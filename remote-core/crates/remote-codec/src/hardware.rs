//! Provisional H.264/H.265 RAM encoding through RustDesk's existing hwcodec.
//!
//! Backend selection uses RustDesk's cached global hardware configuration. It
//! may be empty or stale, depends on native FFmpeg/driver setup, and can modify
//! RustDesk global configuration on initialization failure. This adapter does
//! not discover GPUs independently, negotiate codecs, support VRAM textures,
//! decode video or guarantee hardware acceleration for a particular backend.
//! No build or hardware tests have been run. Do not use for untrusted input.

use crate::{codec_error, invalid, DecodedFrame, PackedFormat, Packet};
use base::message_proto::{video_frame, EncodedVideoFrame, EncodedVideoFrames};
use scrap::{codec::{Decoder, Encoder, EncoderCfg}, hwcodec::{HwRamEncoder, HwRamEncoderConfig}, CodecFormat, EncodeInput, EncodeYuvFormat, ImageFormat, ImageRgb, ImageTexture, Pixfmt};
use std::io;

/// Hard ceiling for the adapter-owned NV12 buffer, not driver allocations.
const MAX_NV12_BYTES: usize = 128 * 1024 * 1024;

/// H.264/H.265 codec requested from the source hardware configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareCodec { H264, H265 }
impl HardwareCodec {
    fn source(self) -> CodecFormat { match self { Self::H264 => CodecFormat::H264, Self::H265 => CodecFormat::H265 } }
}

/// Explicit settings for a single source hardware RAM encoder.
pub struct HardwareEncoderConfig {
    pub codec: HardwareCodec,
    pub width: u32,
    pub height: u32,
    pub quality: f32,
    pub keyframe_interval: Option<usize>,
}

/// NV12 layout reported by the chosen native encoder.
#[derive(Debug, Clone, Copy)]
pub struct Nv12Layout {
    pub width: usize,
    pub height: usize,
    pub y_stride: usize,
    pub uv_stride: usize,
    pub uv_offset: usize,
    pub buffer_len: usize,
}

/// A source H.264/H.265 frame and ordered encoded packets.
pub struct HardwareFrame { pub codec: HardwareCodec, pub packets: Vec<Packet> }

fn layout(format: &EncodeYuvFormat, width: usize, height: usize) -> io::Result<Nv12Layout> {
    if format.pixfmt != Pixfmt::NV12 || format.w != width || format.h < height || format.stride.len() < 2 {
        return Err(invalid("hardware encoder did not provide a compatible NV12 layout"));
    }
    let y_stride = format.stride[0]; let uv_stride = format.stride[1];
    if y_stride < width || uv_stride < width || y_stride > i32::MAX as usize || uv_stride > i32::MAX as usize {
        return Err(invalid("invalid NV12 strides"));
    }
    let y_end = y_stride.checked_mul(format.h).ok_or_else(|| invalid("NV12 layout overflow"))?;
    let chroma_rows = format.h.checked_add(1).ok_or_else(|| invalid("NV12 layout overflow"))? / 2;
    let uv_end = uv_stride.checked_mul(chroma_rows).and_then(|n| format.u.checked_add(n)).ok_or_else(|| invalid("NV12 layout overflow"))?;
    // The source backend's fill_frame checks this size independently. Keep the
    // maximum of both calculations and reject plane overlap.
    let backend_min = y_stride.checked_add(uv_stride / 2).and_then(|n| n.checked_mul(format.h)).ok_or_else(|| invalid("NV12 layout overflow"))?;
    let buffer_len = uv_end.max(backend_min);
    if format.u < y_end || buffer_len > MAX_NV12_BYTES || buffer_len > i32::MAX as usize {
        return Err(invalid("unsafe or oversized NV12 layout"));
    }
    Ok(Nv12Layout { width, height, y_stride, uv_stride, uv_offset: format.u, buffer_len })
}

/// Hardware-backed H.264/H.265 encoder using CPU NV12 input.
pub struct HardwareEncoder {
    native: Encoder,
    codec: HardwareCodec,
    backend_name: String,
    layout: Nv12Layout,
    buffer: Vec<u8>,
}
impl HardwareEncoder {
    /// Select an encoder using the source cached hardware configuration.
    /// Failure may update global RustDesk codec state. No fallback is automatic.
    pub fn new(config: HardwareEncoderConfig) -> io::Result<Self> {
        if !(2..=4096).contains(&config.width) || !(2..=4096).contains(&config.height)
            || config.width % 2 != 0 || config.height % 2 != 0
            || !config.quality.is_finite() || config.quality <= 0.0 || config.quality > 2.0
            || config.keyframe_interval == Some(0) || config.keyframe_interval.map_or(false, |n| n > i32::MAX as usize) {
            return Err(invalid("invalid hardware encoder configuration"));
        }
        let info = HwRamEncoder::try_get(config.codec.source()).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no cached RustDesk hardware RAM encoder for codec"))?;
        let backend_name = info.name.clone();
        let native = Encoder::new(EncoderCfg::HWRAM(HwRamEncoderConfig {
            name: info.name, mc_name: info.mc_name, width: config.width as usize, height: config.height as usize,
            quality: config.quality, keyframe_interval: config.keyframe_interval,
        }), false).map_err(codec_error)?;
        let layout = layout(&native.yuvfmt(), config.width as usize, config.height as usize)?;
        Ok(Self { native, codec: config.codec, backend_name, layout, buffer: vec![0; layout.buffer_len] })
    }
    /// Source-selected backend name; this is not proof of actual GPU acceleration.
    pub fn backend_name(&self) -> &str { &self.backend_name }
    /// Required layout for `encode_nv12`.
    pub fn layout(&self) -> Nv12Layout { self.layout }
    /// Encode NV12 data in the layout reported by the chosen backend.
    pub fn encode_nv12(&mut self, data: &[u8], pts_ms: i64) -> io::Result<HardwareFrame> {
        if data.len() < self.layout.buffer_len || data.len() > i32::MAX as usize {
            return Err(invalid("invalid NV12 input length"));
        }
        let frame = self.native.encode_to_message(EncodeInput::YUV(data), pts_ms).map_err(codec_error)?;
        let frames = match frame.union {
            Some(video_frame::Union::H264s(frames)) if self.codec == HardwareCodec::H264 => frames.frames,
            Some(video_frame::Union::H265s(frames)) if self.codec == HardwareCodec::H265 => frames.frames,
            _ => return Err(codec_error("hardware encoder returned unexpected codec")),
        };
        Ok(HardwareFrame { codec: self.codec, packets: frames.into_iter().map(|packet| Packet {
            data: packet.data.to_vec(), key: packet.key, pts: packet.pts,
        }).collect() })
    }
    /// Convert matching-size packed BGRA/RGBA to the backend's NV12 layout and encode.
    pub fn encode_packed(&mut self, data: &[u8], stride: usize, format: PackedFormat, pts_ms: i64) -> io::Result<HardwareFrame> {
        let l = self.layout;
        let row_bytes = l.width.checked_mul(4).ok_or_else(|| invalid("row size overflow"))?;
        let required = stride.checked_mul(l.height).ok_or_else(|| invalid("source size overflow"))?;
        if stride < row_bytes || stride > i32::MAX as usize || data.len() < required { return Err(invalid("invalid packed input")); }
        let convert = match format { PackedFormat::Bgra => scrap::ARGBToNV12, PackedFormat::Rgba => scrap::ABGRToNV12 };
        // Input and output lengths, strides, plane offsets, dimensions and
        // non-overlap were validated. The buffer is reused by this encoder only.
        let result = unsafe {
            let ptr = self.buffer.as_mut_ptr();
            convert(data.as_ptr(), stride as i32, ptr, l.y_stride as i32, ptr.add(l.uv_offset),
                l.uv_stride as i32, l.width as i32, l.height as i32)
        };
        if result != 0 { return Err(codec_error(format!("libyuv NV12 conversion failed: {result}"))); }
        // Temporarily take the buffer to avoid borrowing self both mutably and immutably.
        let mut data = zeroize::Zeroizing::new(std::mem::take(&mut self.buffer));
        let encoded = self.encode_nv12(&data, pts_ms);
        self.buffer = std::mem::take(&mut *data);
        encoded
    }
}

// Best effort only: this wrapper's current NV12 slice is scrubbed. Driver,
// native codec, old allocations, copies and process termination are not.
impl Drop for HardwareEncoder {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.buffer.as_mut_slice().zeroize();
    }
}

/// RAM-backed H.264/H.265 decoder using the RustDesk source backend.
///
/// The native decoder can allocate based on compressed dimensions before this
/// wrapper sees them. Packet limits do **not** make untrusted bitstreams safe;
/// use only trusted synthetic/local inputs until sandboxing and audit exist.
pub struct HardwareDecoder {
    native: Decoder,
    codec: HardwareCodec,
    rgb: ImageRgb,
    texture: ImageTexture,
}
// Does not erase native decoder/driver allocations or prior RGB buffers.
impl Drop for HardwareDecoder {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.rgb.raw.as_mut_slice().zeroize();
    }
}
impl HardwareDecoder {
    /// Create a RAM decoder selected by the source cached hardware config.
    /// Passing no GPU LUID deliberately avoids the source VRAM decoder path.
    pub fn new(codec: HardwareCodec) -> io::Result<Self> {
        let native = Decoder::new(codec.source(), None);
        if !native.valid() { return Err(io::Error::new(io::ErrorKind::NotFound, "source hardware decoder unavailable")); }
        Ok(Self { native, codec, rgb: ImageRgb::new(ImageFormat::ARGB, 1), texture: ImageTexture::default() })
    }
    /// Decode one batch of trusted source-format packets.
    /// The returned pixels borrow the decoder until its next operation.
    pub fn decode(&mut self, input: &HardwareFrame) -> io::Result<Option<DecodedFrame<'_>>> {
        if input.codec != self.codec || input.packets.is_empty() || input.packets.len() > 1024 {
            return Err(invalid("invalid hardware codec or packet count"));
        }
        let mut total = 0usize;
        let mut packets = Vec::with_capacity(input.packets.len());
        for packet in &input.packets {
            total = total.checked_add(packet.data.len()).ok_or_else(|| invalid("packet length overflow"))?;
            if packet.data.is_empty() || total > 16 * 1024 * 1024 { return Err(invalid("invalid or oversized packet batch")); }
            packets.push(EncodedVideoFrame { data: packet.data.clone().into(), key: packet.key, pts: packet.pts, ..Default::default() });
        }
        let frames = EncodedVideoFrames { frames: packets.into(), ..Default::default() };
        let wire = match self.codec { HardwareCodec::H264 => video_frame::Union::H264s(frames), HardwareCodec::H265 => video_frame::Union::H265s(frames) };
        let mut pixelbuffer = true;
        let mut chroma = None;
        if !self.native.handle_video_frame(&wire, &mut self.rgb, &mut self.texture, &mut pixelbuffer, &mut chroma).map_err(codec_error)? { return Ok(None); }
        if !pixelbuffer { return Err(codec_error("unexpected GPU texture from RAM decoder")); }
        Ok(Some(DecodedFrame { width: self.rgb.w, height: self.rgb.h, data: &self.rgb.raw }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_nv12_layout_before_native_conversion() {
        let good = EncodeYuvFormat { pixfmt: Pixfmt::NV12, w: 64, h: 64, stride: vec![64, 64], u: 4096, v: 0 };
        let l = layout(&good, 64, 64).unwrap();
        assert_eq!(l.buffer_len, 6144);
        let bad = EncodeYuvFormat { u: 32, ..good.clone() };
        assert!(layout(&bad, 64, 64).is_err());
        let bad = EncodeYuvFormat { stride: vec![usize::MAX, 64], ..good };
        assert!(layout(&bad, 64, 64).is_err());
    }
    #[test]
    #[ignore = "requires a compatible real GPU, FFmpeg and initialized RustDesk hardware configuration"]
    fn encode_on_real_hardware() {
        let mut encoder = HardwareEncoder::new(HardwareEncoderConfig { codec: HardwareCodec::H264,
            width: 64, height: 64, quality: 1.0, keyframe_interval: Some(30) }).expect("hardware codec available");
        let frame = encoder.encode_packed(&vec![128; 64 * 64 * 4], 64 * 4, PackedFormat::Bgra, 0).unwrap();
        assert!(!frame.packets.is_empty());
        let mut decoder = HardwareDecoder::new(HardwareCodec::H264).expect("hardware RAM decoder available");
        let image = decoder.decode(&frame).unwrap().expect("decoded image");
        assert_eq!((image.width, image.height), (64, 64));
    }
}
