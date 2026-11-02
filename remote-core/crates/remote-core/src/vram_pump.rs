//! Windows DXGI/VRAM host-session pump. This is an opt-in, synchronous native
//! path without source fallback, GPU/driver validation, recovery or scheduling.
//! The caller must separately negotiate codec support, obtain trusted owner
//! consent, enforce input/output policy, and recreate capture after failures.
//! It has not been built or tested, including on a real Windows desktop.

use crate::{capture_pump::CapturePumpError, video::VideoError, HostInputSession};
use remote_capture::{vram::{VramCapture, VramCodec}, Display};
use remote_input::InputBackend;
use remote_protocol::{Envelope, OwnedVideoPacket, VideoCodec, MAX_ENVELOPE_BYTES};
use remote_session::{SessionId, SessionState};
use remote_transport::NetworkTransport;
use std::{io, time::Duration};

/// A capture device and GPU encoder tied to one already approved session.
/// The capture/encoder pair is taken while a send is in flight, so cancellation
/// discards it and requires recreation plus decoder resynchronization.
pub struct VramVideoPump {
    capture: Option<VramCapture>, session_id: SessionId,
    display_index: i32, max_envelope: usize, stopped: bool,
}
impl VramVideoPump {
    /// Capture the exact enumerated display. This does not negotiate the codec,
    /// provide a hardware fallback, or establish any security properties.
    pub fn open<B: InputBackend>(host: &HostInputSession<B>, display: Display, display_index: i32,
        codec: VramCodec, quality: f32, keyframe_interval: Option<usize>, max_envelope: usize) -> Result<Self, CapturePumpError> {
        if !matches!(host.state(), SessionState::Connected | SessionState::Streaming) || !host.permissions().view_screen {
            return Err(CapturePumpError::NotAuthorized);
        }
        if display_index < 0 || max_envelope == 0 || max_envelope > MAX_ENVELOPE_BYTES {
            return Err(CapturePumpError::InvalidFrame("invalid display index or envelope limit"));
        }
        let capture = VramCapture::open(display, codec, quality, keyframe_interval).map_err(CapturePumpError::Capture)?;
        Ok(Self { capture: Some(capture), session_id: host.id(), display_index, max_envelope, stopped: false })
    }
    pub fn start<B: InputBackend>(&self, host: &mut HostInputSession<B>) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id || self.capture.is_none() { return Err(CapturePumpError::NotAuthorized); }
        host.start_streaming()?; Ok(())
    }
    pub fn needs_reset(&self) -> bool { self.capture.as_ref().map_or(true, VramCapture::needs_reset) }
    pub fn bitrate<B: InputBackend>(&self, host: &HostInputSession<B>) -> Result<u32, CapturePumpError> {
        self.check(host)?;
        self.capture.as_ref().ok_or(CapturePumpError::InvalidFrame("VRAM pump needs recreation"))?.bitrate().map_err(CapturePumpError::Capture)
    }
    pub fn set_quality<B: InputBackend>(&mut self, host: &HostInputSession<B>, quality: f32) -> Result<(), CapturePumpError> {
        self.check(host)?;
        self.capture.as_mut().ok_or(CapturePumpError::InvalidFrame("VRAM pump needs recreation"))?.set_quality(quality).map_err(CapturePumpError::Capture)
    }
    fn check<B: InputBackend>(&self, host: &HostInputSession<B>) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id || host.state() != SessionState::Streaming || !host.permissions().view_screen {
            return Err(CapturePumpError::NotAuthorized);
        }
        Ok(())
    }
    /// Capture and send one packet batch. WouldBlock preserves the encoder;
    /// other capture, encoding, serialization, send or cancellation failures
    /// discard it. A failed network send has an indeterminate outcome.
    pub async fn send_network<B: InputBackend>(&mut self, host: &HostInputSession<B>, transport: &mut dyn NetworkTransport,
        capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<(), CapturePumpError> {
        self.check(host)?;
        if capture_wait.is_zero() || send_wait.is_zero() { return Err(CapturePumpError::InvalidFrame("zero deadline")); }
        let mut capture = self.capture.take().ok_or(CapturePumpError::InvalidFrame("VRAM pump needs recreation"))?;
        let frame = match capture.capture_and_encode(capture_wait, pts_ms) {
            Ok(frame) => frame,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => { self.capture = Some(capture); return Err(CapturePumpError::Capture(error)); },
            Err(error) => return Err(CapturePumpError::Capture(error)),
        };
        let codec = match frame.codec { VramCodec::H264 => VideoCodec::H264, VramCodec::H265 => VideoCodec::H265 };
        let packets: Vec<_> = frame.packets.into_iter().map(|p| OwnedVideoPacket { data: p.data, key: p.key, pts: p.pts_ms }).collect();
        let wire = Envelope::video_event(self.display_index, codec, &packets).map_err(VideoError::from)?.encode(self.max_envelope).map_err(VideoError::from)?;
        transport.send(&wire, send_wait).await.map_err(VideoError::from)?;
        self.capture = Some(capture); Ok(())
    }
    pub fn stop<B: InputBackend>(&mut self, host: &mut HostInputSession<B>) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id { return Err(CapturePumpError::NotAuthorized); }
        crate::capture_pump::finish_streaming(host)?; self.capture = None; self.stopped = true; Ok(())
    }
}
