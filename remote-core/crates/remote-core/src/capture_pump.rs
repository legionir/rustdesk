//! Experimental, caller-driven capture-to-video pump.
//!
//! The host must already be authenticated and authorized. This module creates
//! no task, consent UI, secure transport, codec negotiation, viewer or renderer.
//! Native capture and encoding are synchronous and may block the calling async
//! executor; run on an appropriate dedicated thread/runtime. OS permission,
//! display hotplug, output privacy and multi-session arbitration remain the
//! caller's responsibility. Do not use with untrusted peers.

use crate::{video::{VideoError, VideoSender}, HostInputError, HostInputSession};
use remote_capture::{Capturer, Display, Frame, PixelFormat};
use remote_codec::{EncoderConfig, PackedFormat};
use remote_input::InputBackend;
use remote_session::{SessionId, SessionState};
use remote_transport::{NetworkTransport, Transport};
use std::{error::Error, fmt, io, time::Duration};

/// Capture orchestration error. `Capture` preserves `WouldBlock` from the backend.
#[derive(Debug)]
pub enum CapturePumpError {
    /// Session is not authorized or not in the expected streaming state.
    NotAuthorized,
    /// Encoder dimensions do not match the selected display or changed later.
    DimensionsChanged,
    /// Display index, frame stride, timeout or format is unsupported.
    InvalidFrame(&'static str),
    /// Native display enumeration/open/capture error.
    Capture(io::Error),
    /// Session lifecycle update failed.
    Host(HostInputError),
    /// Encoding, protocol or transport failed.
    Video(VideoError),
}
impl fmt::Display for CapturePumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAuthorized => f.write_str("session is not authorized to view the screen"),
            Self::DimensionsChanged => f.write_str("capture dimensions changed or do not match encoder"),
            Self::InvalidFrame(e) => write!(f, "unsupported capture frame: {e}"),
            Self::Capture(e) => write!(f, "capture: {e}"),
            Self::Host(e) => write!(f, "host session: {e}"),
            Self::Video(e) => write!(f, "video: {e}"),
        }
    }
}
impl Error for CapturePumpError {}
impl From<HostInputError> for CapturePumpError { fn from(e: HostInputError) -> Self { Self::Host(e) } }
impl From<VideoError> for CapturePumpError { fn from(e: VideoError) -> Self { Self::Video(e) } }

enum Output<'a> { Local(&'a mut dyn Transport), Network(&'a mut dyn NetworkTransport) }

/// One capture handle and software encoder, driven by explicit caller steps.
pub struct CapturePump {
    capturer: Capturer,
    sender: VideoSender,
    session_id: SessionId,
    stopped: bool,
    display_index: i32,
    width: usize,
    height: usize,
}
impl CapturePump {
    /// Open the exact previously enumerated display, only after authorization.
    /// The wire display index is supplied by the application and is not a stable
    /// monitor identity. The caller owns codec selection and must ensure it has
    /// negotiated the configured codec with the peer.
    pub fn open<B: InputBackend>(host: &HostInputSession<B>, display: Display, display_index: i32, config: EncoderConfig, max_envelope_bytes: usize) -> Result<Self, CapturePumpError> {
        if !matches!(host.state(), SessionState::Connected | SessionState::Streaming) || !host.permissions().view_screen {
            return Err(CapturePumpError::NotAuthorized);
        }
        if display_index < 0 { return Err(CapturePumpError::InvalidFrame("negative display index")); }
        if display.info().width != config.width as usize || display.info().height != config.height as usize {
            return Err(CapturePumpError::DimensionsChanged);
        }
        let sender = VideoSender::new(config, max_envelope_bytes)?;
        let capturer = display.open().map_err(CapturePumpError::Capture)?;
        if capturer.width() != config.width as usize || capturer.height() != config.height as usize {
            return Err(CapturePumpError::DimensionsChanged);
        }
        Ok(Self { capturer, sender, session_id: host.id(), stopped: false, display_index, width: config.width as usize, height: config.height as usize })
    }
    /// Start the host's streaming state after the pump has been created.
    /// This does not spawn a background task.
    pub fn start<B: InputBackend>(&self, host: &mut HostInputSession<B>) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id { return Err(CapturePumpError::NotAuthorized); }
        host.start_streaming()?;
        Ok(())
    }
    /// Capture, encode and send one frame over an in-process transport.
    pub async fn send_local<B: InputBackend>(&mut self, host: &mut HostInputSession<B>, transport: &mut dyn Transport, capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<(), CapturePumpError> {
        self.send_inner(host, Output::Local(transport), capture_wait, send_wait, pts_ms).await
    }
    /// Capture, encode and send one frame over a network-oriented transport.
    /// Failed sends can have indeterminate delivery; reset and peer resync are required.
    pub async fn send_network<B: InputBackend>(&mut self, host: &mut HostInputSession<B>, transport: &mut dyn NetworkTransport, capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<(), CapturePumpError> {
        self.send_inner(host, Output::Network(transport), capture_wait, send_wait, pts_ms).await
    }
    async fn send_inner<B: InputBackend>(&mut self, host: &mut HostInputSession<B>, output: Output<'_>, capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id || host.state() != SessionState::Streaming || !host.permissions().view_screen { return Err(CapturePumpError::NotAuthorized); }
        if capture_wait.is_zero() || send_wait.is_zero() { return Err(CapturePumpError::InvalidFrame("zero deadline")); }
        let frame = self.capturer.frame(capture_wait).map_err(CapturePumpError::Capture)?;
        let pixels = match frame {
            Frame::Pixels(pixels) => pixels,
            Frame::Texture(_) => return Err(CapturePumpError::InvalidFrame("GPU texture not supported by software encoder")),
        };
        if pixels.width() != self.width || pixels.height() != self.height { return Err(CapturePumpError::DimensionsChanged); }
        let format = match pixels.format() {
            PixelFormat::Bgra => PackedFormat::Bgra, PixelFormat::Rgba => PackedFormat::Rgba,
            _ => return Err(CapturePumpError::InvalidFrame("expected BGRA or RGBA CPU pixels")),
        };
        let stride = *pixels.stride().first().ok_or(CapturePumpError::InvalidFrame("missing stride"))?;
        match output {
            Output::Local(transport) => host.send_video(&mut self.sender, transport, self.display_index, pixels.data(), stride, format, pts_ms, send_wait).await?,
            Output::Network(transport) => host.send_video_network(&mut self.sender, transport, self.display_index, pixels.data(), stride, format, pts_ms, send_wait).await?,
        }
        Ok(())
    }
    /// Read backend-reported bitrate and in-place quality capability for this
    /// pump. The host/session binding and view permission must still be live.
    pub fn encoder_stats<B: InputBackend>(&self, host: &HostInputSession<B>) -> Result<(u32, bool), CapturePumpError> {
        if self.stopped || host.id() != self.session_id || !host.permissions().view_screen || host.state() != SessionState::Streaming {
            return Err(CapturePumpError::NotAuthorized);
        }
        Ok(self.sender.encoder_stats()?)
    }
    /// Apply a locally chosen quality ratio to the existing encoder. A failure
    /// requires encoder recreation and downstream decoder resynchronization.
    pub fn set_quality<B: InputBackend>(&mut self, host: &HostInputSession<B>, quality: f32) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id || !host.permissions().view_screen || host.state() != SessionState::Streaming {
            return Err(CapturePumpError::NotAuthorized);
        }
        self.sender.set_quality(quality)?; Ok(())
    }
    /// Recreate the encoder after an interrupted or failed send. The caller must
    /// coordinate decoder refresh and verify the new config matches the display.
    pub fn reset_encoder(&mut self, config: EncoderConfig) -> Result<(), CapturePumpError> {
        if config.width as usize != self.width || config.height as usize != self.height { return Err(CapturePumpError::DimensionsChanged); }
        self.sender.reset(config)?;
        Ok(())
    }
    /// Whether the sender requires recreation after a failed/cancelled send.
    pub fn needs_reset(&self) -> bool { self.sender.needs_reset() }
    /// Stop this pump and mark its bound session's streaming state stopped.
    /// The capture handle is released when the pump is dropped. The caller must
    /// separately close the transport and session as needed. A failed stop keeps
    /// the pump so the correct session can be supplied or cleanup can be retried.
    pub fn stop<B: InputBackend>(&mut self, host: &mut HostInputSession<B>) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id { return Err(CapturePumpError::NotAuthorized); }
        host.stop_streaming()?;
        self.stopped = true;
        Ok(())
    }
}

/// Caller-driven group of independent software capturers for one session.
///
/// Group creation opens all displays before marking streaming, so an open
/// failure drops already-opened members. This is not an automatic scheduler:
/// the application must choose fair pacing, handle `WouldBlock`, drop/recreate
/// after topology changes, and coordinate client decoder and refresh state.
/// Dropping without `stop` releases native resources but leaves the session's
/// streaming state unchanged. Do not mix with separately managed pumps.
pub struct MultiCapture {
    session_id: SessionId,
    pumps: std::collections::BTreeMap<i32, CapturePump>,
    stopped: bool,
}
impl MultiCapture {
    pub const MAX_STREAMS: usize = 8;
    /// Maximum sum of configured frame areas; not a total native-memory cap.
    pub const MAX_PIXELS: u64 = 32 * 1024 * 1024;
    /// `displays` are actual enumerated handles, with caller-supplied source
    /// wire indices and previously negotiated encoder configurations. The caller
    /// must ensure every selected display is approved. No global memory/CPU/GPU
    /// limit or source subscription semantics are implied by the local caps.
    pub fn start<B: InputBackend>(host: &mut HostInputSession<B>, displays: Vec<(Display, i32, EncoderConfig)>, limit: usize) -> Result<Self, CapturePumpError> {
        if host.state() != SessionState::Connected || !host.permissions().view_screen { return Err(CapturePumpError::NotAuthorized); }
        if displays.is_empty() || displays.len() > Self::MAX_STREAMS { return Err(CapturePumpError::InvalidFrame("invalid capture group size")); }
        let mut indices = std::collections::BTreeSet::new();
        let mut pixels = 0u64;
        for (_, index, config) in &displays {
            if *index < 0 || !indices.insert(*index) { return Err(CapturePumpError::InvalidFrame("invalid or duplicate display index")); }
            pixels = pixels.checked_add(u64::from(config.width) * u64::from(config.height)).ok_or(CapturePumpError::InvalidFrame("pixel budget overflow"))?;
        }
        if pixels > Self::MAX_PIXELS { return Err(CapturePumpError::InvalidFrame("capture group pixel budget exceeded")); }
        let mut pumps = std::collections::BTreeMap::new();
        for (display, index, config) in displays {
            pumps.insert(index, CapturePump::open(host, display, index, config, limit)?);
        }
        host.start_streaming()?;
        Ok(Self { session_id: host.id(), pumps, stopped: false })
    }
    pub fn displays(&self) -> impl Iterator<Item = i32> + '_ { self.pumps.keys().copied() }
    /// Drive one stream. Network send failure/cancellation can make delivery
    /// indeterminate; connection closure and stream resynchronization are the
    /// caller's responsibility. Native work can block the executor.
    pub async fn send_network<B: InputBackend>(&mut self, host: &mut HostInputSession<B>, transport: &mut dyn NetworkTransport,
        display: i32, capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id { return Err(CapturePumpError::NotAuthorized); }
        let pump = self.pumps.get_mut(&display).ok_or(CapturePumpError::InvalidFrame("display not in capture group"))?;
        pump.send_network(host, transport, capture_wait, send_wait, pts_ms).await
    }
    /// Stop the shared streaming state once. Dropping the group afterwards
    /// releases all capture handles; this does not close the connection.
    pub fn stop<B: InputBackend>(&mut self, host: &mut HostInputSession<B>) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id { return Err(CapturePumpError::NotAuthorized); }
        host.stop_streaming()?;
        self.stopped = true;
        for pump in self.pumps.values_mut() { pump.stopped = true; }
        Ok(())
    }
}
