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
    /// A shared, opt-in capture reservation was refused.
    Budget(crate::capture_budget::BudgetError),
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
            Self::Budget(e) => write!(f, "capture budget: {e}"),
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
    // Declared after native fields so accounting is released after them.
    lease: Option<crate::capture_budget::CaptureLease>,
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
        Ok(Self { capturer, sender, lease: None, session_id: host.id(), stopped: false, display_index, width: config.width as usize, height: config.height as usize })
    }
    /// Reserve a cooperative budget before opening the native capturer.
    /// The lease is held until this pump is dropped, including after `stop`.
    /// This excludes other unbudgeted paths and native/GPU allocation sizes.
    pub fn open_budgeted<B: InputBackend>(host: &HostInputSession<B>, display: Display, display_index: i32,
        config: EncoderConfig, max_envelope_bytes: usize, budget: &crate::capture_budget::CaptureBudget) -> Result<Self, CapturePumpError> {
        if !matches!(host.state(), SessionState::Connected | SessionState::Streaming) || !host.permissions().view_screen {
            return Err(CapturePumpError::NotAuthorized);
        }
        let lease = budget.reserve(&[(config.width, config.height)]).map_err(CapturePumpError::Budget)?;
        let mut pump = Self::open(host, display, display_index, config, max_envelope_bytes)?;
        pump.lease = Some(lease);
        Ok(pump)
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
        if self.sender.needs_reset() { return Err(CapturePumpError::Video(VideoError::EncoderResetRequired)); }
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
    /// Source-aware explicit software capture/send. `VpxNoOutput` means no
    /// packet was sent and the encoder/input were retained. This does not
    /// automatically drive source static refresh or ACKs. The old send methods
    /// preserve their conservative error semantics. Native capture/encoding is
    /// synchronous; cancellation/failed I/O require connection cleanup.
    pub async fn send_network_outcome<B: InputBackend>(&mut self, host: &HostInputSession<B>, transport: &mut dyn NetworkTransport,
        capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<crate::video::SendOutcome, CapturePumpError> {
        if self.stopped || host.id() != self.session_id || host.state() != SessionState::Streaming || !host.permissions().view_screen {
            return Err(CapturePumpError::NotAuthorized);
        }
        if capture_wait.is_zero() || send_wait.is_zero() { return Err(CapturePumpError::InvalidFrame("zero deadline")); }
        if self.sender.needs_reset() { return Err(CapturePumpError::Video(VideoError::EncoderResetRequired)); }
        let frame = self.capturer.frame(capture_wait).map_err(CapturePumpError::Capture)?;
        let pixels = match frame { Frame::Pixels(pixels) => pixels, Frame::Texture(_) => return Err(CapturePumpError::InvalidFrame("GPU texture not supported by software encoder")) };
        if pixels.width() != self.width || pixels.height() != self.height { return Err(CapturePumpError::DimensionsChanged); }
        let format = match pixels.format() {
            PixelFormat::Bgra => PackedFormat::Bgra, PixelFormat::Rgba => PackedFormat::Rgba,
            _ => return Err(CapturePumpError::InvalidFrame("expected BGRA or RGBA CPU pixels")),
        };
        let stride = *pixels.stride().first().ok_or(CapturePumpError::InvalidFrame("missing stride"))?;
        Ok(self.sender.send_packed_network_outcome(&host.session, transport, self.display_index, pixels.data(), stride, format, pts_ms, send_wait).await?)
    }
    /// Explicitly repeat the retained source-aware input. A VPX no-output
    /// does not send a frame or release an ACK wait. Caller must authorize,
    /// bound frame age/repeats and service the connection independently.
    pub async fn repeat_network_outcome<B: InputBackend>(&mut self, host: &HostInputSession<B>, transport: &mut dyn NetworkTransport,
        pts_ms: i64, send_wait: Duration, opt_in: remote_codec::RepeatFrameOptIn) -> Result<crate::video::SendOutcome, CapturePumpError> {
        if self.stopped || host.id() != self.session_id || host.state() != SessionState::Streaming || !host.permissions().view_screen {
            return Err(CapturePumpError::NotAuthorized);
        }
        Ok(self.sender.send_repeat_network_outcome(&host.session, transport, self.display_index, pts_ms, send_wait, opt_in).await?)
    }
    /// Whether a successfully converted packed input remains in this pump.
    /// This is not permission to repeat it or evidence that it is still fresh.
    pub fn has_repeatable_input(&self) -> bool { !self.stopped && self.sender.has_repeatable_input() }
    /// Immediately forget/scrub this wrapper's retained input. Native encoder
    /// buffers and other copies remain outside this operation.
    pub fn clear_repeat_input(&mut self) { self.sender.clear_repeat_input(); }
    /// Send one explicitly requested static repeat without sampling a display.
    /// Caller must bound the age/repeats, obtain fresh local consent, maintain
    /// ACK/pacing and handle subscription changes and decoder recovery. This
    /// is not source automatic static refresh. Errors and cancellation have the
    /// same encoder/transport consequences as `send_network`.
    pub async fn repeat_network<B: InputBackend>(&mut self, host: &HostInputSession<B>, transport: &mut dyn NetworkTransport,
        pts_ms: i64, send_wait: Duration, opt_in: remote_codec::RepeatFrameOptIn) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id || host.state() != SessionState::Streaming || !host.permissions().view_screen {
            return Err(CapturePumpError::NotAuthorized);
        }
        self.sender.send_repeat_network(&host.session, transport, self.display_index, pts_ms, send_wait, opt_in).await?;
        Ok(())
    }
    /// Inspect the current native mode while the bound view permission is live.
    #[cfg(target_os = "windows")]
    pub fn is_gdi<B: InputBackend>(&self, host: &HostInputSession<B>) -> Result<bool, CapturePumpError> {
        if self.stopped || host.id() != self.session_id || host.state() != SessionState::Streaming || !host.permissions().view_screen {
            return Err(CapturePumpError::NotAuthorized);
        }
        Ok(self.capturer.is_gdi())
    }
    /// Explicitly switch an authorized software capture to GDI. Before a
    /// requested transition the predictive encoder is discarded even if native
    /// initialization fails. Caller must revalidate local consent and desktop,
    /// coordinate decoder/keyframe recovery, and explicitly reset the encoder.
    /// This is not automatic source fallback or permission to change displays.
    /// If already GDI, returns false but still invalidates the encoder: native
    /// capture may have changed mode independently since its last observation.
    #[cfg(target_os = "windows")]
    pub fn use_gdi<B: InputBackend>(&mut self, host: &HostInputSession<B>, opt_in: remote_capture::GdiFallbackOptIn) -> Result<bool, CapturePumpError> {
        if self.stopped || host.id() != self.session_id || host.state() != SessionState::Streaming || !host.permissions().view_screen {
            return Err(CapturePumpError::NotAuthorized);
        }
        self.sender.invalidate();
        if self.capturer.is_gdi() { return Ok(false); }
        self.capturer.use_gdi(opt_in).map_err(CapturePumpError::Capture)?;
        Ok(true)
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
    /// For the bound session, wrapper-owned cached pixels are scrubbed even if
    /// the subsequent session-state transition fails; native copies remain.
    pub fn stop<B: InputBackend>(&mut self, host: &mut HostInputSession<B>) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id { return Err(CapturePumpError::NotAuthorized); }
        self.sender.clear_repeat_input();
        finish_streaming(host)?;
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
    // The native pumps must be dropped before these reservations.
    leases: std::collections::BTreeMap<i32, crate::capture_budget::CaptureLease>,
    budget: Option<crate::capture_budget::CaptureBudget>,
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
        Self::start_inner(host, displays, limit, None)
    }
    /// Opt into one shared cooperative reservation per stream. All leases are
    /// acquired before native opens and retained until corresponding pumps drop.
    /// This is not an OS-wide, byte, native-allocation, or GPU resource limit.
    pub fn start_budgeted<B: InputBackend>(host: &mut HostInputSession<B>, displays: Vec<(Display, i32, EncoderConfig)>,
        limit: usize, budget: &crate::capture_budget::CaptureBudget) -> Result<Self, CapturePumpError> {
        Self::start_inner(host, displays, limit, Some(budget.clone()))
    }
    fn start_inner<B: InputBackend>(host: &mut HostInputSession<B>, displays: Vec<(Display, i32, EncoderConfig)>,
        limit: usize, budget: Option<crate::capture_budget::CaptureBudget>) -> Result<Self, CapturePumpError> {
        if host.state() != SessionState::Connected || !host.permissions().view_screen { return Err(CapturePumpError::NotAuthorized); }
        if displays.is_empty() || displays.len() > Self::MAX_STREAMS { return Err(CapturePumpError::InvalidFrame("invalid capture group size")); }
        validate_group_specs(displays.iter().map(|(_, index, config)| (*index, config.width, config.height)))?;
        // Declared first so any opened native pumps drop before leases on error.
        let leases = reserve_streams(budget.as_ref(), displays.iter().map(|(_, id, config)| (*id, config.width, config.height)))?;
        let mut pumps = std::collections::BTreeMap::new();
        for (display, index, config) in displays {
            pumps.insert(index, CapturePump::open(host, display, index, config, limit)?);
        }
        host.start_streaming()?;
        Ok(Self { session_id: host.id(), pumps, leases, budget, stopped: false })
    }
    pub fn displays(&self) -> impl Iterator<Item = i32> + '_ { self.pumps.keys().copied() }
    /// Locally allocated session binding, not a peer identity.
    pub fn session_id(&self) -> SessionId { self.session_id }
    /// Atomically replace the group membership from explicitly approved local
    /// handles. New capturers are opened before any old ones are dropped, so
    /// failed native open leaves the existing group intact. Both the final and
    /// temporary combined groups must fit local limits. Replacing an existing
    /// index in one operation is rejected; stop/recreate the group for topology
    /// remaps. Empty groups are not supported; explicitly stop instead.
    /// This is not an atomic OS topology snapshot, global resource cap, remote
    /// subscription handler or consent mechanism. New streams need separately
    /// negotiated decoders, metadata and keyframe/refresh coordination.
    pub fn reconfigure<B: InputBackend>(&mut self, host: &HostInputSession<B>,
        remove: &[i32], add: Vec<(Display, i32, EncoderConfig)>, limit: usize) -> Result<(), CapturePumpError> {
        use std::collections::BTreeMap;
        if self.stopped || host.id() != self.session_id || host.state() != SessionState::Streaming || !host.permissions().view_screen {
            return Err(CapturePumpError::NotAuthorized);
        }
        let existing: Vec<_> = self.pumps.iter().map(|(id, pump)| (*id, pump.width as u32, pump.height as u32)).collect();
        let additions: Vec<_> = add.iter().map(|(_, id, config)| (*id, config.width, config.height)).collect();
        validate_reconfiguration(&existing, remove, &additions)?;
        // The existing reservations remain held throughout temporary opening.
        // If opening fails, drop opened pumps before dropping new reservations.
        let new_leases = reserve_streams(self.budget.as_ref(), additions.into_iter())?;
        let mut opened = BTreeMap::new();
        for (display, index, config) in add {
            opened.insert(index, CapturePump::open(host, display, index, config, limit)?);
        }
        for id in remove { self.pumps.remove(id); self.leases.remove(id); }
        self.pumps.extend(opened);
        self.leases.extend(new_leases);
        Ok(())
    }
    /// Drive one stream. Network send failure/cancellation can make delivery
    /// indeterminate; connection closure and stream resynchronization are the
    /// caller's responsibility. Native work can block the executor.
    pub async fn send_network<B: InputBackend>(&mut self, host: &mut HostInputSession<B>, transport: &mut dyn NetworkTransport,
        display: i32, capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id { return Err(CapturePumpError::NotAuthorized); }
        let pump = self.pumps.get_mut(&display).ok_or(CapturePumpError::InvalidFrame("display not in capture group"))?;
        pump.send_network(host, transport, capture_wait, send_wait, pts_ms).await
    }
    /// Source-aware single-member send; no-output sends nothing. Caller owns
    /// pacing, peer acknowledgements, recovery and frame-retention policy.
    pub async fn send_network_outcome<B: InputBackend>(&mut self, host: &HostInputSession<B>, transport: &mut dyn NetworkTransport,
        display: i32, capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<crate::video::SendOutcome, CapturePumpError> {
        if self.stopped || host.id() != self.session_id { return Err(CapturePumpError::NotAuthorized); }
        self.pumps.get_mut(&display).ok_or(CapturePumpError::InvalidFrame("display not in capture group"))?
            .send_network_outcome(host, transport, capture_wait, send_wait, pts_ms).await
    }
    /// Source-aware explicit cached repeat for one member; no ACK bookkeeping
    /// is performed. The caller must verify consent, age and peer identity.
    pub async fn repeat_network_outcome<B: InputBackend>(&mut self, host: &HostInputSession<B>, transport: &mut dyn NetworkTransport,
        display: i32, pts_ms: i64, send_wait: Duration, opt_in: remote_codec::RepeatFrameOptIn) -> Result<crate::video::SendOutcome, CapturePumpError> {
        if self.stopped || host.id() != self.session_id { return Err(CapturePumpError::NotAuthorized); }
        self.pumps.get_mut(&display).ok_or(CapturePumpError::InvalidFrame("display not in capture group"))?
            .repeat_network_outcome(host, transport, pts_ms, send_wait, opt_in).await
    }
    /// Forget wrapper-owned cached pixels for one member without sending or
    /// acquiring new permission. Native buffers and other copies are unaffected.
    pub fn clear_repeat_input(&mut self, display: i32) -> Result<(), CapturePumpError> {
        self.pumps.get_mut(&display).ok_or(CapturePumpError::InvalidFrame("display not in capture group"))?.clear_repeat_input();
        Ok(())
    }
    /// Read one member's encoder stats for caller-owned QoS bookkeeping.
    /// A successful result is a backend report, not verified bandwidth or proof
    /// of delivery. The host and its view permission must still be active.
    pub fn encoder_stats<B: InputBackend>(&self, host: &HostInputSession<B>, display: i32) -> Result<(u32, bool), CapturePumpError> {
        if self.stopped || host.id() != self.session_id { return Err(CapturePumpError::NotAuthorized); }
        self.pumps.get(&display).ok_or(CapturePumpError::InvalidFrame("display not in capture group"))?.encoder_stats(host)
    }
    /// Explicitly apply a local quality choice to one member. Failure can
    /// require recreation; this is not automatic QoS or viewer negotiation.
    pub fn set_quality<B: InputBackend>(&mut self, host: &HostInputSession<B>, display: i32, quality: f32) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id { return Err(CapturePumpError::NotAuthorized); }
        self.pumps.get_mut(&display).ok_or(CapturePumpError::InvalidFrame("display not in capture group"))?.set_quality(host, quality)
    }
    /// Check whether one encoder needs recreation after a failed send.
    pub fn needs_reset<B: InputBackend>(&self, host: &HostInputSession<B>, display: i32) -> Result<bool, CapturePumpError> {
        if self.stopped || host.id() != self.session_id || !host.permissions().view_screen || host.state() != SessionState::Streaming { return Err(CapturePumpError::NotAuthorized); }
        Ok(self.pumps.get(&display).ok_or(CapturePumpError::InvalidFrame("display not in capture group"))?.needs_reset())
    }
    /// Inspect or explicitly request the source GDI backend for one approved
    /// software stream. No topology, consent or decoder checks are performed.
    #[cfg(target_os = "windows")]
    pub fn is_gdi<B: InputBackend>(&self, host: &HostInputSession<B>, display: i32) -> Result<bool, CapturePumpError> {
        if self.stopped || host.id() != self.session_id { return Err(CapturePumpError::NotAuthorized); }
        self.pumps.get(&display).ok_or(CapturePumpError::InvalidFrame("display not in capture group"))?.is_gdi(host)
    }
    #[cfg(target_os = "windows")]
    pub fn use_gdi<B: InputBackend>(&mut self, host: &HostInputSession<B>, display: i32, opt_in: remote_capture::GdiFallbackOptIn) -> Result<bool, CapturePumpError> {
        if self.stopped || host.id() != self.session_id { return Err(CapturePumpError::NotAuthorized); }
        self.pumps.get_mut(&display).ok_or(CapturePumpError::InvalidFrame("display not in capture group"))?.use_gdi(host, opt_in)
    }
    /// Recreate one member only after external decoder-refresh coordination.
    /// This does not reopen capture or prove topology stability.
    pub fn reset_encoder<B: InputBackend>(&mut self, host: &HostInputSession<B>, display: i32, config: EncoderConfig) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id || !host.permissions().view_screen || host.state() != SessionState::Streaming { return Err(CapturePumpError::NotAuthorized); }
        self.pumps.get_mut(&display).ok_or(CapturePumpError::InvalidFrame("display not in capture group"))?.reset_encoder(config)
    }
    /// Stop the shared streaming state once. Dropping the group afterwards
    /// releases all capture handles; this does not close the connection.
    /// Cached wrapper pixels are scrubbed even if the transition then fails.
    pub fn stop<B: InputBackend>(&mut self, host: &mut HostInputSession<B>) -> Result<(), CapturePumpError> {
        if self.stopped || host.id() != self.session_id { return Err(CapturePumpError::NotAuthorized); }
        for pump in self.pumps.values_mut() { pump.clear_repeat_input(); }
        finish_streaming(host)?;
        self.stopped = true;
        for pump in self.pumps.values_mut() { pump.stopped = true; }
        Ok(())
    }
}

impl Drop for MultiCapture {
    fn drop(&mut self) {
        // Explicit ordering avoids releasing accounting before native resources.
        self.pumps.clear();
        self.leases.clear();
    }
}

fn reserve_streams(budget: Option<&crate::capture_budget::CaptureBudget>,
    specs: impl Iterator<Item = (i32, u32, u32)>)
    -> Result<std::collections::BTreeMap<i32, crate::capture_budget::CaptureLease>, CapturePumpError> {
    let mut leases = std::collections::BTreeMap::new();
    if let Some(budget) = budget {
        for (id, width, height) in specs {
            if leases.contains_key(&id) { return Err(CapturePumpError::InvalidFrame("duplicate display index")); }
            let lease = budget.reserve(&[(width, height)]).map_err(CapturePumpError::Budget)?;
            leases.insert(id, lease);
        }
    }
    Ok(leases)
}

// Validate both final membership and temporary old-plus-new resource limits
// before opening anything. Same-index replacement deliberately fails closed.
fn validate_reconfiguration(existing: &[(i32, u32, u32)], remove: &[i32], add: &[(i32, u32, u32)]) -> Result<(), CapturePumpError> {
    let ids: std::collections::BTreeSet<_> = existing.iter().map(|(id, _, _)| *id).collect();
    let removals: std::collections::BTreeSet<_> = remove.iter().copied().collect();
    if ids.len() != existing.len() || remove.len() > MultiCapture::MAX_STREAMS || removals.len() != remove.len()
        || removals.iter().any(|id| !ids.contains(id)) {
        return Err(CapturePumpError::InvalidFrame("invalid capture removals"));
    }
    if add.len() > MultiCapture::MAX_STREAMS || existing.len() + add.len() > MultiCapture::MAX_STREAMS
        || existing.len() + add.len() == removals.len() {
        return Err(CapturePumpError::InvalidFrame("invalid temporary or final capture group size"));
    }
    validate_group_specs(existing.iter().chain(add.iter()).copied())
}
// Validate before any native capture handle is opened. This ceiling is not a
// substitute for encoder dimension validation or native allocation accounting.
fn validate_group_specs(specs: impl Iterator<Item = (i32, u32, u32)>) -> Result<(), CapturePumpError> {
    let mut indices = std::collections::BTreeSet::new();
    let mut pixels = 0u64;
    for (index, width, height) in specs {
        if index < 0 || !indices.insert(index) { return Err(CapturePumpError::InvalidFrame("invalid or duplicate display index")); }
        pixels = pixels.checked_add(u64::from(width) * u64::from(height)).ok_or(CapturePumpError::InvalidFrame("pixel budget overflow"))?;
    }
    if pixels > MultiCapture::MAX_PIXELS { return Err(CapturePumpError::InvalidFrame("capture group pixel budget exceeded")); }
    Ok(())
}
#[cfg(test)]
mod group_tests {
    use super::*;
    struct NoInput;
    impl remote_input::InputBackend for NoInput {
        fn move_to(&mut self, _: i32, _: i32) -> std::io::Result<()> { Ok(()) }
        fn mouse_down(&mut self, _: remote_input::MouseButton) -> std::io::Result<()> { Ok(()) }
        fn mouse_up(&mut self, _: remote_input::MouseButton) -> std::io::Result<()> { Ok(()) }
        fn scroll(&mut self, _: i32, _: i32) -> std::io::Result<()> { Ok(()) }
        fn key_down(&mut self, _: remote_input::VirtualKey) -> std::io::Result<()> { Ok(()) }
        fn key_up(&mut self, _: remote_input::VirtualKey) -> std::io::Result<()> { Ok(()) }
    }
    #[test]
    fn group_budget_rolls_back_and_preserves_existing_leases() {
        use crate::capture_budget::{BudgetError, BudgetLimits, CaptureBudget};
        let pool = CaptureBudget::new(BudgetLimits { leases: 2, streams: 2, pixels: 200 }).unwrap();
        let existing = reserve_streams(Some(&pool), [(0, 10, 10)].into_iter()).unwrap();
        assert!(matches!(reserve_streams(Some(&pool), [(1, 10, 10), (2, 1, 1)].into_iter()), Err(CapturePumpError::Budget(BudgetError::Capacity))));
        assert_eq!(pool.usage().unwrap(), BudgetLimits { leases: 1, streams: 1, pixels: 100 });
        drop(existing);
        assert!(matches!(reserve_streams(Some(&pool), [(1, 10, 10), (1, 10, 10)].into_iter()), Err(CapturePumpError::InvalidFrame(_))));
        assert_eq!(pool.usage().unwrap(), BudgetLimits { leases: 0, streams: 0, pixels: 0 });
    }
    #[test]
    fn permits_capture_cleanup_after_view_revocation() {
        use remote_security::{password_response, OwnerApproval, PasswordVerifier};
        use remote_session::{Credential, Permissions, Principal};
        let id = SessionId::new([77; 16]).unwrap();
        let principal = Principal::new("test".into()).unwrap();
        let permissions = Permissions { view_screen: true, ..Default::default() };
        let mut verifier = PasswordVerifier::new(id, principal.clone(), "test", "salt", Duration::from_secs(30)).unwrap();
        let response = password_response("test", verifier.challenge()).unwrap();
        let mut approval = OwnerApproval::new(id, principal, Some(permissions));
        let mut host = HostInputSession::new(id, NoInput);
        host.begin_connect().unwrap(); host.transport_connected().unwrap();
        host.authenticate(Credential::new(response.as_bytes()), permissions, &mut verifier, &mut approval).unwrap();
        assert!(finish_streaming(&mut host).is_err());
        host.start_streaming().unwrap();
        host.restrict_permissions(Permissions::default()).unwrap();
        assert_eq!(host.state(), SessionState::Connected);
        assert!(finish_streaming(&mut host).is_ok());
    }
    #[test]
    fn reconfiguration_validates_temporary_resources_before_open() {
        let a = (0, 1920, 1080); let b = (1, 1920, 1080);
        assert!(validate_reconfiguration(&[a], &[0], &[b]).is_ok());
        assert!(validate_reconfiguration(&[a], &[0], &[]).is_err());
        assert!(validate_reconfiguration(&[a], &[0, 0], &[b]).is_err());
        assert!(validate_reconfiguration(&[a], &[1], &[b]).is_err());
        assert!(validate_reconfiguration(&[a], &[0], &[a]).is_err());
        let existing: Vec<_> = (0..8).map(|id| (id, 2, 2)).collect();
        assert!(validate_reconfiguration(&existing, &[0], &[(8, 2, 2)]).is_err());
        assert!(validate_reconfiguration(&[(0, 4096, 4096)], &[0], &[(1, 8192, 4096)]).is_err());
    }
    #[test]
    fn rejects_duplicate_and_excess_pixel_specs_before_native_open() {
        assert!(validate_group_specs([(0, 1920, 1080), (1, 1920, 1080)].into_iter()).is_ok());
        assert!(validate_group_specs([(0, 2, 2), (0, 2, 2)].into_iter()).is_err());
        assert!(validate_group_specs([(-1, 2, 2)].into_iter()).is_err());
        assert!(validate_group_specs([(0, 8192, 8192)].into_iter()).is_err());
        assert!(validate_group_specs([(0, u32::MAX, u32::MAX), (1, u32::MAX, u32::MAX)].into_iter()).is_err());
    }
}

// Revoking view permission already transitions Streaming -> Connected. Native
// handles still need explicit stop/drop even though the session transition ran.
pub(crate) fn finish_streaming<B: InputBackend>(host: &mut HostInputSession<B>) -> Result<(), CapturePumpError> {
    match host.state() {
        SessionState::Streaming => host.stop_streaming().map_err(CapturePumpError::Host),
        SessionState::Connected if !host.permissions().view_screen => Ok(()),
        _ => Err(CapturePumpError::NotAuthorized),
    }
}
