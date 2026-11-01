//! Experimental software codec adapter over RustDesk's `scrap` implementation.
//!
//! This API is not hardened for untrusted bitstreams. It does not yet provide
//! all RustDesk codecs, negotiation, hardware acceleration or recovery policy.

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
#[derive(Clone, Debug)]
pub struct Packet {
    /// Encoded bytes.
    pub data: Vec<u8>,
    /// Whether this packet is a keyframe.
    pub key: bool,
    /// Presentation timestamp in milliseconds.
    pub pts: i64,
}

/// Encoded packets produced by a single encoder invocation.
#[derive(Clone, Debug)]
pub struct EncodedFrame {
    /// Codec used for every packet.
    pub codec: Codec,
    /// Ordered packets, preserving source timestamps and keyframe flags.
    pub packets: Vec<Packet>,
}

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

/// An I420 software encoder using the original RustDesk encoder implementation.
pub struct SoftwareEncoder {
    native: Encoder,
    codec: Codec,
    layout: I420Layout,
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
        Ok(Self { native, codec: config.codec, layout })
    }

    /// Get the exact padded I420 layout required by this instance.
    pub fn layout(&self) -> I420Layout { self.layout }

    /// Update the quality ratio using the source implementation.
    pub fn set_quality(&mut self, quality: f32) -> io::Result<()> {
        if !quality.is_finite() || quality <= 0.0 || quality > 2.0 {
            return Err(invalid("quality must be finite, positive and at most 2"));
        }
        self.native.set_quality(quality).map_err(codec_error)
    }

    /// Encode one padded I420 image, with a presentation timestamp in milliseconds.
    /// The backend may return an error when it produces no output.
    pub fn encode(&mut self, i420: &[u8], pts_ms: i64) -> io::Result<EncodedFrame> {
        if i420.len() < self.layout.buffer_len { return Err(invalid("I420 buffer too short")); }
        let video = self.native.encode_to_message(EncodeInput::YUV(i420), pts_ms).map_err(codec_error)?;
        let packets = match video.union {
            Some(video_frame::Union::Vp8s(v)) if self.codec == Codec::Vp8 => v.frames,
            Some(video_frame::Union::Vp9s(v)) if self.codec == Codec::Vp9 => v.frames,
            Some(video_frame::Union::Av1s(v)) if self.codec == Codec::Av1 => v.frames,
            _ => return Err(codec_error("encoder returned unexpected codec")),
        };
        Ok(EncodedFrame { codec: self.codec, packets: packets.into_iter().map(|p| Packet { data: p.data.to_vec(), key: p.key, pts: p.pts }).collect() })
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
            let mut encoder = SoftwareEncoder::new(config(codec)).unwrap();
            let layout = encoder.layout();
            let mut pixels = vec![128; layout.buffer_len];
            pixels[..layout.u_offset].fill(80);
            let encoded = encoder.encode(&pixels, 0).unwrap();
            assert!(!encoded.packets.is_empty());
            assert!(encoded.packets.iter().any(|p| p.key));
            let mut decoder = SoftwareDecoder::new(codec).unwrap();
            let decoded = decoder.decode(&encoded).unwrap().expect("decoded picture");
            assert_eq!((decoded.width, decoded.height), (64, 64));
            assert_eq!(decoded.data.len(), 64 * 64 * 4);
        }
    }

    #[test]
    fn rejects_bad_packet_batches() {
        let mut decoder = SoftwareDecoder::new(Codec::Vp8).unwrap();
        assert!(decoder.decode(&EncodedFrame { codec: Codec::Vp9, packets: vec![] }).is_err());
        assert!(decoder.decode(&EncodedFrame { codec: Codec::Vp8, packets: vec![] }).is_err());
        assert!(decoder.decode(&EncodedFrame { codec: Codec::Vp8, packets: vec![Packet { data: vec![], key: false, pts: 0 }] }).is_err());
    }
}
