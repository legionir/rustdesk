//! Experimental software codec adapter over RustDesk's `scrap` implementation.
//!
//! This API is not hardened for untrusted bitstreams. It does not yet provide
//! all RustDesk codecs, negotiation, hardware acceleration or recovery policy.

mod source_video_qos;
/// Bounded, explicitly configured wrapper for the source video QoS algorithm.
pub mod video_qos;

/// Process-global source codec negotiation adapter.
pub mod negotiation;

/// Optional RustDesk H.264/H.265 RAM-encoder adapter.
#[cfg(feature = "hwcodec")]
pub mod hardware;

use std::io;
use base::message_proto::{video_frame, EncodedVideoFrame, EncodedVideoFrames};
use scrap::{codec::{Decoder, Encoder, EncoderCfg}, aom::AomEncoderConfig, CodecFormat, EncodeInput, ImageFormat, ImageRgb, ImageTexture, VpxEncoderConfig, VpxVideoCodecId};

/// Software video codec used by this prototype.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    /// VP8 via libvpx.
    Vp8,
    /// VP9 via libvpx.
    Vp9,
    /// AV1 via libaom.
    Av1,
}

/// Packed four-byte input format in memory order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackedFormat {
    /// Blue, green, red, alpha bytes.
    Bgra,
    /// Red, green, blue, alpha bytes.
    Rgba,
}

/// Encoder initialization parameters.
#[derive(Clone, Copy, Debug)]
pub struct EncoderConfig {
    /// Codec to use.
    pub codec: Codec,
    /// Even pixel width, between 2 and 4096.
    pub width: u32,
    /// Even pixel height, between 2 and 4096.
    pub height: u32,
    /// RustDesk quality ratio, greater than zero and at most 2.
    pub quality: f32,
    /// Optional maximum keyframe interval, in frames.
    pub keyframe_interval: Option<usize>,
}

/// Encoded packet data and timing from the underlying encoder.
#[derive(Clone)]
pub struct Packet {
    /// Encoded bytes.
    pub data: Vec<u8>,
    /// Whether this packet is a keyframe.
    pub key: bool,
    /// Presentation timestamp in milliseconds.
    pub pts: i64,
}

impl std::fmt::Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Packet").field("bytes", &self.data.len()).field("key", &self.key).field("pts", &self.pts).finish()
    }
}

/// Encoded packets produced by a single encoder invocation.
#[derive(Clone, Debug)]
pub struct EncodedFrame {
    /// Codec used for every packet.
    pub codec: Codec,
    /// Ordered packets, preserving source timestamps and keyframe flags.
    pub packets: Vec<Packet>,
}

/// Explicit source VPX outcome. `VpxNoOutput` means the pinned encoder
/// reported its specific no-output condition; no frame was sent or rendered.
/// This is not interchangeable with arbitrary native failures or AV1 errors.
#[derive(Clone, Debug)]
pub enum EncodeOutcome { Frame(EncodedFrame), VpxNoOutput }

/// Required aligned I420 buffer layout. Offsets and strides include padding.
#[derive(Clone, Copy, Debug)]
pub struct I420Layout {
    /// Offset of U plane in bytes.
    pub u_offset: usize,
    /// Offset of V plane in bytes.
    pub v_offset: usize,
    /// Stride of Y plane in bytes.
    pub y_stride: usize,
    /// Stride of U plane in bytes.
    pub u_stride: usize,
    /// Stride of V plane in bytes.
    pub v_stride: usize,
    /// Minimum required buffer length, including alignment padding.
    pub buffer_len: usize,
}

fn invalid(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidInput, message) }
fn codec_error(error: impl std::fmt::Display) -> io::Error { io::Error::new(io::ErrorKind::Other, error.to_string()) }

/// Explicit acknowledgment that a repeat may resend a previously captured
/// screen image. This is not consent or permission; the caller must recheck
/// current view authorization, desktop identity and retention policy.
#[derive(Clone, Copy, Debug)]
pub struct RepeatFrameOptIn(());
impl RepeatFrameOptIn {
    pub fn acknowledge_cached_screen_pixels() -> Self { Self(()) }
}

/// An I420 software encoder using the original RustDesk encoder implementation.
pub struct SoftwareEncoder {
    native: Encoder,
    codec: Codec,
    layout: I420Layout,
    width: usize,
    height: usize,
    converted: Vec<u8>,
    repeatable: bool,
}

impl SoftwareEncoder {
    /// Initialize an encoder. Recreate it to change resolution or codec.
    pub fn new(config: EncoderConfig) -> io::Result<Self> {
        if !(2..=4096).contains(&config.width) || !(2..=4096).contains(&config.height)
            || config.width % 2 != 0 || config.height % 2 != 0 {
            return Err(invalid("dimensions must be even and between 2 and 4096"));
        }
        if !config.quality.is_finite() || config.quality <= 0.0 || config.quality > 2.0 {
            return Err(invalid("quality must be finite, positive and at most 2"));
        }
        if config.keyframe_interval == Some(0) || config.keyframe_interval.map_or(false, |v| v > u32::MAX as usize) {
            return Err(invalid("invalid keyframe interval"));
        }
        let native_config = match config.codec {
            Codec::Vp8 | Codec::Vp9 => EncoderCfg::VPX(VpxEncoderConfig {
                width: config.width, height: config.height, quality: config.quality,
                codec: if config.codec == Codec::Vp8 { VpxVideoCodecId::VP8 } else { VpxVideoCodecId::VP9 },
                keyframe_interval: config.keyframe_interval,
            }),
            Codec::Av1 => EncoderCfg::AOM(AomEncoderConfig {
                width: config.width, height: config.height, quality: config.quality,
                keyframe_interval: config.keyframe_interval,
            }),
        };
        let native = Encoder::new(native_config, false).map_err(codec_error)?;
        let format = native.yuvfmt();
        let strides = &format.stride;
        if strides.len() < 3 || strides[0] < config.width as usize
            || strides[1] < (config.width / 2) as usize || strides[2] < (config.width / 2) as usize {
            return Err(invalid("invalid backend I420 stride"));
        }
        let y_end = strides[0].checked_mul(format.h).ok_or_else(|| invalid("layout overflow"))?;
        let chroma_rows = format.h.checked_add(1).ok_or_else(|| invalid("layout overflow"))? / 2;
        let u_end = strides[1].checked_mul(chroma_rows).and_then(|n| format.u.checked_add(n)).ok_or_else(|| invalid("layout overflow"))?;
        let v_end = strides[2].checked_mul(chroma_rows).and_then(|n| format.v.checked_add(n)).ok_or_else(|| invalid("layout overflow"))?;
        if format.u < y_end || format.v < u_end || format.h < config.height as usize {
            return Err(invalid("invalid backend I420 plane offsets"));
        }
        let layout = I420Layout { u_offset: format.u, v_offset: format.v, y_stride: strides[0], u_stride: strides[1], v_stride: strides[2], buffer_len: v_end };
        Ok(Self { native, codec: config.codec, layout, width: config.width as usize, height: config.height as usize, converted: vec![0; layout.buffer_len], repeatable: false })
    }

    /// Get the exact padded I420 layout required by this instance.
    pub fn layout(&self) -> I420Layout { self.layout }

    /// Update the quality ratio using the source implementation.
    pub fn set_quality(&mut self, quality: f32) -> io::Result<()> {
        if !quality.is_finite() || quality <= 0.0 || quality > 2.0 {
            return Err(invalid("quality must be finite, positive and at most 2"));
        }
        match self.native.set_quality(quality) {
            Ok(()) => Ok(()),
            Err(error) => { self.repeatable = false; Err(codec_error(error)) },
        }
    }

    /// Current backend-reported target bitrate in kbps, not measured traffic.
    pub fn bitrate(&self) -> u32 { self.native.bitrate() }
    /// Whether the backend reports support for changing quality in place.
    pub fn supports_quality_change(&self) -> bool { self.native.support_changing_quality() }

    /// Convert packed BGRA or RGBA pixels using RustDesk's libyuv conversion and encode.
    /// The source stride and buffer are validated before native code is called.
    /// Dimensions must match the encoder configuration; recreate the encoder on resize.
    pub fn encode_packed(&mut self, data: &[u8], stride: usize, format: PackedFormat, pts_ms: i64) -> io::Result<EncodedFrame> {
        match self.encode_packed_outcome(data, stride, format, pts_ms)? {
            EncodeOutcome::Frame(frame) => Ok(frame),
            EncodeOutcome::VpxNoOutput => { self.repeatable = false; Err(codec_error("no valid frame")) },
        }
    }

    /// Source-aware packed encode. A typed VP8/VP9 no-output result retains the
    /// converted input, as the source static-refresh path does. This does not
    /// prove delivery or permit stale frame disclosure; callers must enforce
    /// authorization, age, repeat limits and decoder synchronization. Native
    /// errors other than the exact VPX marker remain errors and invalidate the
    /// repeat input. This experimental path has not been built or tested.
    pub fn encode_packed_outcome(&mut self, data: &[u8], stride: usize, format: PackedFormat, pts_ms: i64) -> io::Result<EncodeOutcome> {
        self.repeatable = false;
        let row_bytes = self.width.checked_mul(4).ok_or_else(|| invalid("row size overflow"))?;
        let required = stride.checked_mul(self.height).ok_or_else(|| invalid("source size overflow"))?;
        if stride < row_bytes || stride > i32::MAX as usize || data.len() < required {
            return Err(invalid("invalid packed pixel buffer or stride"));
        }
        let l = self.layout;
        let buffer = &mut self.converted;
        // Plane offsets and lengths were checked at construction and the input
        // bounds/strides were checked above. These planes do not overlap.
        let result = unsafe {
            let base = buffer.as_mut_ptr();
            let convert = match format {
                PackedFormat::Bgra => scrap::ARGBToI420,
                PackedFormat::Rgba => scrap::ABGRToI420,
            };
            convert(data.as_ptr(), stride as i32, base, l.y_stride as i32,
                base.add(l.u_offset), l.u_stride as i32, base.add(l.v_offset),
                l.v_stride as i32, self.width as i32, self.height as i32)
        };
        if result != 0 { return Err(codec_error(format!("libyuv conversion failed: {result}"))); }
        let result = self.native.encode_to_message(EncodeInput::YUV(buffer), pts_ms);
        let outcome = Self::classify_native(self.codec, result)?;
        self.repeatable = true;
        Ok(outcome)
    }

    /// Whether this wrapper has a successfully encoded packed input available,
    /// or a source-classified VPX no-output input on the explicit outcome path.
    /// This says nothing about authorization, delivery, or whether the screen
    /// changed since capture. It does not inspect native codec memory.
    pub fn has_repeatable_input(&self) -> bool { self.repeatable }
    /// Forget and zero the wrapper-owned converted image immediately. Native
    /// encoder memory, prior allocations and external copies are unaffected.
    pub fn clear_repeat_input(&mut self) {
        use zeroize::Zeroize;
        self.repeatable = false;
        self.converted.as_mut_slice().zeroize();
    }
    /// Explicitly re-encode the most recent successfully packed input using
    /// its existing wrapper-owned I420 buffer. No screen is sampled. The caller
    /// must authorize each repeat, enforce retention and scheduling limits, and
    /// handle decoder refresh and uncertain delivery. Any encode/packing error
    /// invalidates the cached input; unlike source, VPX no-output is not
    /// distinguished and this conservative API does not continue on that error.
    pub fn repeat_packed(&mut self, pts_ms: i64, _: RepeatFrameOptIn) -> io::Result<EncodedFrame> {
        if !self.repeatable { return Err(invalid("no repeatable packed input")); }
        self.repeatable = false;
        let video = self.native.encode_to_message(EncodeInput::YUV(&self.converted), pts_ms).map_err(codec_error)?;
        let frame = Self::pack(self.codec, video)?;
        self.repeatable = true;
        Ok(frame)
    }

    /// Source-aware repeat of the retained converted input. An exact VPX
    /// no-output retains eligibility; any other error invalidates it. The
    /// returned outcome makes no statement about delivery or freshness.
    pub fn repeat_packed_outcome(&mut self, pts_ms: i64, _: RepeatFrameOptIn) -> io::Result<EncodeOutcome> {
        if !self.repeatable { return Err(invalid("no repeatable packed input")); }
        self.repeatable = false;
        let result = self.native.encode_to_message(EncodeInput::YUV(&self.converted), pts_ms);
        let outcome = Self::classify_native(self.codec, result)?;
        self.repeatable = true;
        Ok(outcome)
    }

    fn classify_native(codec: Codec, result: hbb_common::ResultType<base::message_proto::VideoFrame>) -> io::Result<EncodeOutcome> {
        match result {
            Ok(video) => Ok(EncodeOutcome::Frame(Self::pack(codec, video)?)),
            Err(error) if matches!(codec, Codec::Vp8 | Codec::Vp9) && error.is::<scrap::VpxNoOutput>() => Ok(EncodeOutcome::VpxNoOutput),
            Err(error) => Err(codec_error(error)),
        }
    }

    /// Encode one padded I420 image, with a presentation timestamp in milliseconds.
    /// The backend may return an error when it produces no output.
    pub fn encode(&mut self, i420: &[u8], pts_ms: i64) -> io::Result<EncodedFrame> {
        self.repeatable = false;
        if i420.len() < self.layout.buffer_len { return Err(invalid("I420 buffer too short")); }
        let video = self.native.encode_to_message(EncodeInput::YUV(i420), pts_ms).map_err(codec_error)?;
        Self::pack(self.codec, video)
    }

    fn pack(codec: Codec, video: base::message_proto::VideoFrame) -> io::Result<EncodedFrame> {
        let packets = match video.union {
            Some(video_frame::Union::Vp8s(v)) if codec == Codec::Vp8 => v.frames,
            Some(video_frame::Union::Vp9s(v)) if codec == Codec::Vp9 => v.frames,
            Some(video_frame::Union::Av1s(v)) if codec == Codec::Av1 => v.frames,
            _ => return Err(codec_error("encoder returned unexpected codec")),
        };
        Ok(EncodedFrame { codec, packets: packets.into_iter().map(|p| Packet { data: p.data.to_vec(), key: p.key, pts: p.pts }).collect() })
    }
}

// Best-effort cleanup of this wrapper's retained converted screen pixels.
// Native codecs, capture buffers, packets, allocator copies and crashes remain
// outside this guarantee; this is not secure erasure of all screen content.
impl Drop for SoftwareEncoder {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.converted.as_mut_slice().zeroize();
    }
}

/// Decoded packed pixels owned by the decoder until the next call.
pub struct DecodedFrame<'a> {
    /// Image width in pixels.
    pub width: usize,
    /// Image height in pixels.
    pub height: usize,
    /// Packed ARGB output in the source backend's byte convention.
    pub data: &'a [u8],
}

/// A software decoder. Only feed trusted streams until allocation and bitstream limits are audited.
pub struct SoftwareDecoder {
    native: Decoder,
    codec: Codec,
    rgb: ImageRgb,
    texture: ImageTexture,
}

// Only the current wrapper-owned RGB allocation is scrubbed. Native decoder
// buffers, previous reallocations and caller copies are not controlled here.
impl Drop for SoftwareDecoder {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.rgb.raw.as_mut_slice().zeroize();
    }
}

impl SoftwareDecoder {
    /// Initialize a decoder for a single codec.
    pub fn new(codec: Codec) -> io::Result<Self> {
        let format = match codec { Codec::Vp8 => CodecFormat::VP8, Codec::Vp9 => CodecFormat::VP9, Codec::Av1 => CodecFormat::AV1 };
        let native = Decoder::new(format, None);
        if !native.valid() { return Err(codec_error("decoder unavailable")); }
        Ok(Self { native, codec, rgb: ImageRgb::new(ImageFormat::ARGB, 1), texture: ImageTexture::default() })
    }

    /// Decode an ordered batch; returns `None` when no picture was produced.
    /// A codec mismatch or empty batch is rejected before entering the backend.
    pub fn decode(&mut self, input: &EncodedFrame) -> io::Result<Option<DecodedFrame<'_>>> {
        if input.codec != self.codec { return Err(invalid("codec mismatch")); }
        if input.packets.is_empty() { return Err(invalid("empty packet batch")); }
        let mut total = 0usize;
        let mut packets = Vec::with_capacity(input.packets.len().min(1024));
        if input.packets.len() > 1024 { return Err(invalid("too many packets")); }
        for p in &input.packets {
            total = total.checked_add(p.data.len()).ok_or_else(|| invalid("packet length overflow"))?;
            if p.data.is_empty() || total > 16 * 1024 * 1024 { return Err(invalid("invalid or oversized packet batch")); }
            packets.push(EncodedVideoFrame { data: p.data.clone().into(), key: p.key, pts: p.pts, ..Default::default() });
        }
        let frames = EncodedVideoFrames { frames: packets.into(), ..Default::default() };
        let frame = match self.codec { Codec::Vp8 => video_frame::Union::Vp8s(frames), Codec::Vp9 => video_frame::Union::Vp9s(frames), Codec::Av1 => video_frame::Union::Av1s(frames) };
        let mut pixelbuffer = true;
        let mut chroma = None;
        if !self.native.handle_video_frame(&frame, &mut self.rgb, &mut self.texture, &mut pixelbuffer, &mut chroma).map_err(codec_error)? { return Ok(None); }
        Ok(Some(DecodedFrame { width: self.rgb.w, height: self.rgb.h, data: &self.rgb.raw }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(codec: Codec) -> EncoderConfig { EncoderConfig { codec, width: 64, height: 64, quality: 1.0, keyframe_interval: Some(30) } }

    #[test]
    fn exact_vpx_no_output_is_distinct_from_other_errors() {
        let marker = || Err(hbb_common::anyhow::Error::new(scrap::VpxNoOutput));
        assert!(matches!(SoftwareEncoder::classify_native(Codec::Vp8, marker()), Ok(EncodeOutcome::VpxNoOutput)));
        assert!(matches!(SoftwareEncoder::classify_native(Codec::Vp9, marker()), Ok(EncodeOutcome::VpxNoOutput)));
        assert!(SoftwareEncoder::classify_native(Codec::Av1, marker()).is_err());
        let lookalike = Err(hbb_common::anyhow::anyhow!("no valid frame"));
        assert!(SoftwareEncoder::classify_native(Codec::Vp9, lookalike).is_err());
    }
    #[test]
    fn source_aware_packed_input_is_repeatable_after_frame_or_vpx_no_output() {
        let mut encoder = SoftwareEncoder::new(config(Codec::Vp9)).unwrap();
        let input = vec![100; 64 * 64 * 4];
        let result = encoder.encode_packed_outcome(&input, 256, PackedFormat::Bgra, 0).unwrap();
        assert!(matches!(result, EncodeOutcome::Frame(_) | EncodeOutcome::VpxNoOutput));
        assert!(encoder.has_repeatable_input());
        let result = encoder.repeat_packed_outcome(100, RepeatFrameOptIn::acknowledge_cached_screen_pixels());
        match result {
            Ok(EncodeOutcome::Frame(_)) | Ok(EncodeOutcome::VpxNoOutput) => assert!(encoder.has_repeatable_input()),
            Err(_) => assert!(!encoder.has_repeatable_input()),
        }
        encoder.clear_repeat_input();
        assert!(!encoder.has_repeatable_input());
    }

    #[test]
    fn rejects_invalid_config_and_short_input() {
        let mut bad = config(Codec::Vp8); bad.width = 63;
        assert!(SoftwareEncoder::new(bad).is_err());
        bad.width = 64; bad.quality = f32::NAN;
        assert!(SoftwareEncoder::new(bad).is_err());
        let mut encoder = SoftwareEncoder::new(config(Codec::Vp8)).unwrap();
        assert!(encoder.encode(&[0; 10], 0).is_err());
        assert!(encoder.set_quality(0.0).is_err());
    }

    #[test]
    fn round_trip_software_codecs() {
        for codec in [Codec::Vp8, Codec::Vp9, Codec::Av1] {
            for (width, height) in [(64, 64), (66, 34)] {
                let mut cfg = config(codec);
                cfg.width = width;
                cfg.height = height;
                let mut encoder = SoftwareEncoder::new(cfg).unwrap();
                let layout = encoder.layout();
                let mut pixels = vec![128; layout.buffer_len];
                pixels[..layout.u_offset].fill(80);
                let encoded = encoder.encode(&pixels, 0).unwrap();
                assert!(!encoded.packets.is_empty());
                assert!(encoded.packets.iter().any(|p| p.key));
                let mut decoder = SoftwareDecoder::new(codec).unwrap();
                let decoded = decoder.decode(&encoded).unwrap().expect("decoded picture");
                assert_eq!((decoded.width, decoded.height), (width as usize, height as usize));
                assert_eq!(decoded.data.len(), (width * height * 4) as usize);
            }
        }
    }

    #[test]
    fn packed_round_trip_and_input_validation() {
        for format in [PackedFormat::Bgra, PackedFormat::Rgba] {
            let mut encoder = SoftwareEncoder::new(config(Codec::Vp9)).unwrap();
            assert!(encoder.encode_packed(&[], 256, format, 0).is_err());
            assert!(encoder.encode_packed(&vec![0; 64 * 64 * 4], 3, format, 0).is_err());
            assert!(encoder.encode_packed(&[], usize::MAX, format, 0).is_err());
            let mut input = vec![0; 64 * 64 * 4];
            for pixel in input.chunks_exact_mut(4) { pixel.copy_from_slice(&[100, 100, 100, 255]); }
            let frame = encoder.encode_packed(&input, 256, format, 0).unwrap();
            let mut decoder = SoftwareDecoder::new(Codec::Vp9).unwrap();
            let decoded = decoder.decode(&frame).unwrap().unwrap();
            assert_eq!((decoded.width, decoded.height), (64, 64));
            // Lossy compression and YUV conversion may introduce small rounding differences.
            for value in &decoded.data[..3] { assert!((i32::from(*value) - 100).abs() <= 12); }
        }
    }

    #[test]
    fn repeat_input_is_explicit_and_cleared_without_claiming_native_erasure() {
        let mut encoder = SoftwareEncoder::new(config(Codec::Vp9)).unwrap();
        let opt = RepeatFrameOptIn::acknowledge_cached_screen_pixels();
        assert!(!encoder.has_repeatable_input());
        assert!(encoder.repeat_packed(1, opt).is_err());
        let input = vec![100; 64 * 64 * 4];
        let first = encoder.encode_packed(&input, 256, PackedFormat::Bgra, 0).unwrap();
        assert!(encoder.has_repeatable_input());
        let mut decoder = SoftwareDecoder::new(Codec::Vp9).unwrap();
        assert!(decoder.decode(&first).unwrap().is_some());
        // Source VPX may drop an identical frame; the conservative API disables
        // repeat after any error rather than assuming native state is reusable.
        match encoder.repeat_packed(100, opt) {
            Ok(frame) => { assert!(encoder.has_repeatable_input()); let _ = decoder.decode(&frame).unwrap(); },
            Err(_) => assert!(!encoder.has_repeatable_input()),
        }
        encoder.clear_repeat_input();
        assert!(!encoder.has_repeatable_input());
        assert!(encoder.converted.iter().all(|&byte| byte == 0));
        assert!(encoder.repeat_packed(200, opt).is_err());
        // A rejected later input cannot accidentally repeat an older screen.
        let mut second = SoftwareEncoder::new(config(Codec::Vp9)).unwrap();
        second.encode_packed(&input, 256, PackedFormat::Bgra, 0).unwrap();
        assert!(second.has_repeatable_input());
        assert!(second.encode_packed(&[], 256, PackedFormat::Bgra, 300).is_err());
        assert!(!second.has_repeatable_input());
        assert!(second.repeat_packed(400, opt).is_err());
        second.clear_repeat_input();
    }

    #[test]
    fn rejects_bad_packet_batches() {
        let mut decoder = SoftwareDecoder::new(Codec::Vp8).unwrap();
        assert!(decoder.decode(&EncodedFrame { codec: Codec::Vp9, packets: vec![] }).is_err());
        assert!(decoder.decode(&EncodedFrame { codec: Codec::Vp8, packets: vec![] }).is_err());
        assert!(decoder.decode(&EncodedFrame { codec: Codec::Vp8, packets: vec![Packet { data: vec![], key: false, pts: 0 }] }).is_err());
    }
}

#[cfg(test)]
mod redacted_packet_debug_tests {
    use super::*;
    #[test]
    fn compressed_bytes_are_not_printed_by_debug() {
        let packet = Packet { data: vec![101, 102, 103], key: true, pts: 0 };
        let debug = format!("{packet:?}");
        assert!(debug.contains("bytes: 3")); assert!(!debug.contains("101"));
    }
}
