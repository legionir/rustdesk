//! Windows-only experimental DXGI-to-VRAM H.264/H.265 capture and encoding.
//!
//! This combines source `TraitCapturer::device`, `VRamEncoder::try_get`,
//! `set_output_texture` and `EncodeInput::Texture`, keeping the capture device
//! alive longer than the encoder and the borrowed texture until encoding ends.
//! Source hardware probing/configuration is process-global. This API does not
//! negotiate with peers, grant screen permission, perform portable-service/UAC
//! capture, handle rotation, recover device loss, or provide automatic fallback.
//! Native driver allocation/output checks and actual GPU acceleration are not
//! guaranteed. It has not been compiled or tested on Windows.

use super::{Capturer, Display};
use base::message_proto::video_frame;
use scrap::{codec::{Encoder, EncoderCfg}, vram::{VRamEncoder, VRamEncoderConfig}, CodecFormat, EncodeInput, TraitCapturer};
use std::{io, time::Duration};

/// Requested source VRAM format. Runtime availability depends on drivers and
/// RustDesk's cached hardware configuration, not this enum alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VramCodec { H264, H265 }
impl VramCodec {
    fn source(self) -> CodecFormat { match self { Self::H264 => CodecFormat::H264, Self::H265 => CodecFormat::H265 } }
}

/// One packet and the source codec's keyframe/timestamp metadata.
#[derive(Debug)]
pub struct Packet { pub data: Vec<u8>, pub key: bool, pub pts_ms: i64 }
/// Output from one native encode call; native allocations can exceed this cap.
#[derive(Debug)]
pub struct VramFrame { pub codec: VramCodec, pub packets: Vec<Packet> }
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_PACKETS: usize = 1024;
fn invalid(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidInput, message) }
fn backend(error: impl std::fmt::Display) -> io::Error { io::Error::new(io::ErrorKind::Other, error.to_string()) }

fn validate_config(width: usize, height: usize, quality: f32, keyframe_interval: Option<usize>) -> io::Result<()> {
    if width < 2 || height < 2 || width > 4096 || height > 4096 || width % 2 != 0 || height % 2 != 0
        || !quality.is_finite() || quality <= 0.0 || quality > 2.0
        || keyframe_interval == Some(0) || keyframe_interval.map_or(false, |n| n > i32::MAX as usize) {
        return Err(invalid("invalid VRAM capture configuration"));
    }
    Ok(())
}

/// Owned VRAM encoder and the exact capture device from which it was created.
/// The encoder field is deliberately declared first so it is dropped before
/// the capturer and its native device. Do not expose its raw device or frame
/// pointers. A native failure poisons the encoder and requires reconstruction.
pub struct VramCapture {
    encoder: Option<Encoder>,
    capturer: Capturer,
    codec: VramCodec,
    width: usize,
    height: usize,
}
impl VramCapture {
    /// Open an explicitly chosen source display and hardware codec. This may
    /// trigger native device/probe behavior and source-global state changes.
    /// Caller must obtain local screen consent and verify decoder support.
    pub fn open(display: Display, codec: VramCodec, quality: f32, keyframe_interval: Option<usize>) -> io::Result<Self> {
        let info = display.info();
        let (width, height) = (info.width, info.height);
        validate_config(width, height, quality, keyframe_interval)?;
        let mut capturer = display.open()?;
        if capturer.width() != width || capturer.height() != height || capturer.native.is_gdi() {
            return Err(invalid("VRAM requires an unchanged DXGI capture display"));
        }
        let device = capturer.native.device();
        if device.device.is_null() || device.luid == 0 { return Err(invalid("capture device is unavailable")); }
        let feature = VRamEncoder::try_get(&device, codec.source())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no source VRAM encoder for this capture device"))?;
        let encoder = Encoder::new(EncoderCfg::VRAM(VRamEncoderConfig { device, width, height, quality, feature, keyframe_interval }), false).map_err(backend)?;
        if !encoder.input_texture() { return Err(invalid("VRAM backend does not accept textures")); }
        capturer.native.set_output_texture(true);
        Ok(Self { encoder: Some(encoder), capturer, codec, width, height })
    }
    pub fn dimensions(&self) -> (usize, usize) { (self.width, self.height) }
    pub fn codec(&self) -> VramCodec { self.codec }
    pub fn needs_reset(&self) -> bool { self.encoder.is_none() }
    /// Read source-reported target bitrate, not measured network traffic.
    pub fn bitrate(&self) -> io::Result<u32> {
        Ok(self.encoder.as_ref().ok_or_else(|| invalid("VRAM encoder needs recreation"))?.bitrate())
    }
    /// Reconfigure native quality in place. The source VRAM backend may hide
    /// driver failures, so success does not prove the requested bitrate took effect.
    pub fn set_quality(&mut self, quality: f32) -> io::Result<()> {
        if !quality.is_finite() || quality <= 0.0 || quality > 2.0 { return Err(invalid("invalid VRAM quality")); }
        let mut encoder = self.encoder.take().ok_or_else(|| invalid("VRAM encoder needs recreation"))?;
        encoder.set_quality(quality).map_err(backend)?;
        self.encoder = Some(encoder); Ok(())
    }
    /// Capture and encode synchronously. `WouldBlock` comes from capture and
    /// keeps the encoder; native encode/protocol failure poisons it. Buffer size
    /// is checked only after the native encoder has allocated the output.
    pub fn capture_and_encode(&mut self, timeout: Duration, pts_ms: i64) -> io::Result<VramFrame> {
        if timeout.is_zero() { return Err(invalid("capture timeout must be positive")); }
        if self.encoder.is_none() { return Err(invalid("VRAM encoder needs recreation")); }
        // A frame borrows the capturer while the encoder is used. No pointer is
        // retained in this wrapper after the native synchronous encode returns.
        let texture = match self.capturer.native.frame(timeout)? {
            scrap::Frame::Texture((texture, rotation)) if !texture.is_null() && rotation == 0 => (texture, rotation),
            scrap::Frame::Texture(_) => return Err(invalid("null or rotated VRAM texture")),
            scrap::Frame::PixelBuffer(_) => return Err(invalid("capture did not return a GPU texture")),
        };
        let mut encoder = self.encoder.take().ok_or_else(|| invalid("VRAM encoder needs recreation"))?;
        let video = encoder.encode_to_message(EncodeInput::Texture(texture), pts_ms).map_err(backend)?;
        let frames = match video.union {
            Some(video_frame::Union::H264s(v)) if self.codec == VramCodec::H264 => v.frames,
            Some(video_frame::Union::H265s(v)) if self.codec == VramCodec::H265 => v.frames,
            _ => return Err(invalid("unexpected VRAM encoder output")),
        };
        if frames.is_empty() || frames.len() > MAX_PACKETS { return Err(invalid("invalid VRAM packet count")); }
        let mut total = 0usize;
        let mut packets = Vec::with_capacity(frames.len());
        for frame in frames {
            total = total.checked_add(frame.data.len()).ok_or_else(|| invalid("VRAM output overflow"))?;
            if frame.data.is_empty() || total > MAX_OUTPUT_BYTES { return Err(invalid("VRAM output exceeds limit")); }
            packets.push(Packet { data: frame.data.to_vec(), key: frame.key, pts_ms: frame.pts });
        }
        self.encoder = Some(encoder);
        Ok(VramFrame { codec: self.codec, packets })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_config_before_native_allocation() {
        assert!(validate_config(1920, 1080, 1.0, Some(30)).is_ok());
        assert!(validate_config(0, 1080, 1.0, None).is_err());
        assert!(validate_config(1921, 1080, 1.0, None).is_err());
        assert!(validate_config(1920, 1080, f32::NAN, None).is_err());
        assert!(validate_config(1920, 1080, 1.0, Some(0)).is_err());
    }
}
