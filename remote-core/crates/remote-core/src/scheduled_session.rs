//! Experimental single-session composition of caller-driven multi-display
//! capture, direct-TCP read-ahead and control event handling. No worker, owner
//! UI, negotiation, renderer, automatic subscriptions or safe untrusted video.
//!
//! The application must alternate event and capture calls fairly, process all
//! returned control requests, and arrange short operation deadlines. Native
//! capture can block and the receive queue is bounded; liveness timeouts count
//! dequeues rather than socket arrivals. This is not the source multi-peer video
//! service and must not be exposed to untrusted peers as a finished server.
use crate::{host_connection::{ConnectionError, HostConnection, HostEvent}, scheduled_capture::{OutcomeStep, ScheduledCapture, ScheduledCaptureError, Step}};
use remote_input::InputBackend;
use remote_session::SessionState;
use remote_transport::UpgradeableDuplexTransport;
use std::{error::Error, fmt, time::{Duration, Instant}};

/// Maximum consecutive inbound events returned by `drive_once` before one
/// capture/pacing attempt. This is local fairness, not source queue semantics.
pub const MAX_EVENT_BURST: u8 = 4;
#[derive(Debug)]
pub enum DriveStep { Event(HostEvent), Capture(Step) }
/// Fair source-aware event or capture outcome; no-output is not a frame ACK.
#[derive(Debug)]
pub enum DriveOutcomeStep { Event(HostEvent), Capture(OutcomeStep) }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry { Idle, Receive }
#[derive(Debug)]
pub enum DriverError {
    InvalidBinding,
    InvalidDeadline,
    Connection(ConnectionError),
    Capture(ScheduledCaptureError),
    Expired(Expiry),
    Cleanup { capture: Option<ScheduledCaptureError>, connection: Option<ConnectionError> },
}
impl fmt::Display for DriverError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "scheduled session: {self:?}") } }
impl Error for DriverError {}
#[derive(Default)]
struct EventFairness { consecutive: u8 }
impl EventFairness {
    fn may_poll(&self) -> bool { self.consecutive < MAX_EVENT_BURST }
    fn event_returned(&mut self) { self.consecutive = self.consecutive.saturating_add(1).min(MAX_EVENT_BURST); }
    fn capture_attempted(&mut self) { self.consecutive = 0; }
}

/// Owns the scheduler and its connection. Dropping drops native captures before
/// the host and its transport. Explicit `close` also attempts lifecycle cleanup.
pub struct ScheduledSession<T: UpgradeableDuplexTransport, B: InputBackend> {
    capture: Option<ScheduledCapture>,
    host: HostConnection<T, B>,
    fairness: EventFairness,
}
impl<T: UpgradeableDuplexTransport, B: InputBackend> ScheduledSession<T, B> {
    /// Consume an already authorized, streaming pair, optionally enabling ACK
    /// pacing only for a peer that requested it. This upgrades the transport;
    /// choose the final framing limit before calling. On error both owned values
    /// are returned so the owner can close/drop them. Session IDs are caller
    /// supplied; the application must ensure uniqueness and must pass the exact
    /// host that opened the group. An equal ID is not proof of that binding or
    /// consent.
    pub fn new(mut host: HostConnection<T, B>, mut capture: ScheduledCapture, ack_timeout: Option<Duration>)
        -> Result<Self, (DriverError, HostConnection<T, B>, ScheduledCapture)> {
        if host.state() != SessionState::Streaming || host.session_id() != capture.group().session_id() {
            return Err((DriverError::InvalidBinding, host, capture));
        }
        if let Some(timeout) = ack_timeout {
            if let Err(e) = capture.enable_ack_wait(&host, timeout) { return Err((DriverError::Capture(e), host, capture)); }
        }
        if let Err(e) = host.enable_duplex_read_ahead() { return Err((DriverError::Connection(e), host, capture)); }
        Ok(Self { capture: Some(capture), host, fairness: EventFairness::default() })
    }
    /// Locally supplied session ID, not proof of connection identity.
    pub fn session_id(&self) -> remote_session::SessionId { self.host.session_id() }
    /// Current local display indices; not stable OS monitor identities.
    pub fn capture_displays(&self) -> Option<Vec<i32>> { self.capture.as_ref().map(|capture| capture.group().displays().collect()) }
    /// Access the bound host for explicit policy changes and control handling.
    /// The caller must not close it, revoke view, or manipulate capture behind
    /// the driver; use `restrict_permissions`, `close` and coordinated methods
    /// to preserve lifecycle and ACK bookkeeping.
    pub fn host_mut(&mut self) -> &mut HostConnection<T, B> { &mut self.host }
    /// Explicit capture reconfiguration/quality decisions remain local policy.
    pub fn capture_mut(&mut self) -> Option<&mut ScheduledCapture> { self.capture.as_mut() }
    /// Restrict locally granted permissions. If view is revoked or cleanup
    /// fails, drop all capture handles/reservations immediately; the caller
    /// may close the remaining host. This never grants new permissions.
    pub fn restrict_permissions(&mut self, permissions: remote_session::Permissions) -> Result<(), DriverError> {
        let result = self.host.restrict_permissions(permissions);
        if result.is_err() || !self.host.permissions().view_screen { self.capture.take(); }
        result.map_err(DriverError::Connection)
    }
    /// Apply a locally approved membership change. This is not automatic
    /// handling of peer subscription requests; the caller must verify consent,
    /// topology and decoder/keyframe coordination. Budgeted groups retain old
    /// reservations while opening additions and drop them after old pumps.
    pub fn reconfigure(&mut self, remove: &[i32], add: Vec<(remote_capture::Display, i32, remote_codec::EncoderConfig)>,
        fps: u32) -> Result<(), DriverError> {
        self.poll_timeouts()?;
        self.capture.as_mut().ok_or(DriverError::InvalidBinding)?
            .reconfigure(&mut self.host, remove, add, fps).map_err(DriverError::Capture)
    }
    /// Change a single existing display's local cadence; no network request is
    /// applied automatically and this does not reconfigure the encoder.
    pub fn set_fps(&mut self, display: u32, fps: u32) -> Result<(), DriverError> {
        self.poll_timeouts()?;
        self.capture.as_mut().ok_or(DriverError::InvalidBinding)?.set_fps(display, fps).map_err(DriverError::Capture)
    }
    /// Apply a separately vetted QoS recommendation. A native quality error
    /// can require encoder recreation and receiver refresh.
    pub fn apply_recommendation(&mut self, display: u32, recommendation: remote_codec::video_qos::Recommendation,
        apply_quality: bool) -> Result<(), DriverError> {
        self.poll_timeouts()?;
        self.capture.as_mut().ok_or(DriverError::InvalidBinding)?
            .apply_recommendation(&mut self.host, display, recommendation, apply_quality).map_err(DriverError::Capture)
    }
    /// Read or explicitly request GDI on one locally approved Windows software
    /// stream. A requested backend switch invalidates the encoder even on
    /// failure. Call `reset_encoder` after explicit viewer synchronization;
    /// that method also clears the stream's outstanding ACK wait. This does not
    /// automate consent, recovery policy, topology checks or switching.
    #[cfg(target_os = "windows")]
    pub fn is_gdi(&mut self, display: i32) -> Result<bool, DriverError> {
        self.poll_timeouts()?;
        let capture = self.capture.as_ref().ok_or(DriverError::InvalidBinding)?;
        self.host.multi_capture_is_gdi(capture.group(), display).map_err(DriverError::Connection)
    }
    #[cfg(target_os = "windows")]
    pub fn use_gdi(&mut self, display: i32, opt_in: remote_capture::GdiFallbackOptIn) -> Result<bool, DriverError> {
        self.poll_timeouts()?;
        let capture = self.capture.as_mut().ok_or(DriverError::InvalidBinding)?;
        self.host.use_multi_capture_gdi(capture.group_mut(), display, opt_in).map_err(DriverError::Connection)
    }
    /// Reset one encoder after explicit peer decoder/keyframe coordination.
    /// A successful reset clears its pending local ACK, but a late ACK can
    /// still be mistaken for a later frame; the source wire has no sequence.
    pub fn reset_encoder(&mut self, display: i32, config: remote_codec::EncoderConfig) -> Result<(), DriverError> {
        self.poll_timeouts()?;
        let capture = self.capture.as_mut().ok_or(DriverError::InvalidBinding)?;
        self.host.reset_multi_capture_encoder(capture.group_mut(), display, config).map_err(DriverError::Connection)?;
        if capture.ack_wait_enabled() {
            let id = u32::try_from(display).map_err(|_| DriverError::InvalidBinding)?;
            capture.clear_ack_for_stream_reset(id).map_err(DriverError::Capture)?;
        }
        Ok(())
    }
    fn poll_timeouts(&mut self) -> Result<(), DriverError> {
        let idle = self.host.poll_idle_timeout();
        match idle {
            Ok(true) => { self.capture.take(); return Err(DriverError::Expired(Expiry::Idle)); },
            Ok(false) => {},
            Err(e) => { self.capture.take(); return Err(DriverError::Connection(e)); },
        }
        match self.host.poll_receive_watchdog() {
            Ok(true) => { self.capture.take(); Err(DriverError::Expired(Expiry::Receive)) },
            Ok(false) => Ok(()),
            Err(e) => { self.capture.take(); Err(DriverError::Connection(e)) },
        }
    }
    /// Process at most one queued event. ACKs update this scheduler before the
    /// event is returned; all other actions remain the caller's responsibility.
    /// `None` means no locally queued event, not that the socket is alive.
    pub async fn poll_event(&mut self, send_deadline: Duration) -> Result<Option<HostEvent>, DriverError> {
        if self.capture.is_none() { return Err(DriverError::InvalidBinding); }
        self.poll_timeouts()?;
        let event = match self.host.try_receive_event(send_deadline).await {
            Ok(event) => event,
            Err(error) => {
                if matches!(self.host.state(), SessionState::Closed | SessionState::Failed | SessionState::Disconnecting) {
                    self.capture.take();
                }
                return Err(DriverError::Connection(error));
            }
        };
        if let Some(ref event) = event {
            let capture = self.capture.as_mut().ok_or(DriverError::InvalidBinding)?;
            if capture.ack_wait_enabled() { capture.observe_event(&self.host, event).map_err(DriverError::Capture)?; }
        }
        Ok(event)
    }
    /// Perform at most one paced capture/send attempt. Poll events regularly;
    /// ACK waits and inbound input do not progress during this operation.
    /// Cancellation requires closing/dropping the entire driver, not retrying.
    pub async fn capture_step(&mut self, now: Instant, capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<Step, DriverError> {
        if self.capture.is_none() { return Err(DriverError::InvalidBinding); }
        self.poll_timeouts()?;
        let result = self.capture.as_mut().ok_or(DriverError::InvalidBinding)?.step(&mut self.host, now, capture_wait, send_wait, pts_ms).await;
        if result.is_err() && matches!(self.host.state(), SessionState::Closed | SessionState::Failed | SessionState::Disconnecting) {
            self.capture.take();
        }
        result.map_err(DriverError::Capture)
    }
    /// Source-aware capture/pacing variant. No-output keeps the encoder and
    /// creates no ACK wait; caller may apply a separately authorized static
    /// repeat policy. Cancellation still requires closing the whole driver.
    pub async fn capture_step_outcome(&mut self, now: Instant, capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<OutcomeStep, DriverError> {
        if self.capture.is_none() { return Err(DriverError::InvalidBinding); }
        self.poll_timeouts()?;
        let result = self.capture.as_mut().ok_or(DriverError::InvalidBinding)?.step_outcome(&mut self.host, now, capture_wait, send_wait, pts_ms).await;
        if result.is_err() && matches!(self.host.state(), SessionState::Closed | SessionState::Failed | SessionState::Disconnecting) { self.capture.take(); }
        result.map_err(DriverError::Capture)
    }
    /// Drop this driver's wrapper-owned retained input for one display without
    /// sending. This remains available after permission revocation if capture
    /// still exists; native memory and external copies are not covered.
    pub fn clear_repeat_input(&mut self, display: i32) -> Result<(), DriverError> {
        self.capture.as_mut().ok_or(DriverError::InvalidBinding)?.clear_repeat_input(display).map_err(DriverError::Capture)
    }
    /// Explicit cached-repeat step with optional ACK pacing. Caller must apply
    /// source static-refresh policy, bound image age, and revalidate local
    /// consent and topology; no background timer or automatic repeat exists.
    pub async fn repeat_outcome(&mut self, display: i32, now: Instant, send_wait: Duration, pts_ms: i64,
        opt_in: remote_codec::RepeatFrameOptIn) -> Result<OutcomeStep, DriverError> {
        if self.capture.is_none() { return Err(DriverError::InvalidBinding); }
        if send_wait.is_zero() { return Err(DriverError::InvalidDeadline); }
        self.poll_timeouts()?;
        let result = self.capture.as_mut().ok_or(DriverError::InvalidBinding)?
            .repeat_outcome(&mut self.host, display, now, send_wait, pts_ms, opt_in).await;
        if result.is_err() && matches!(self.host.state(), SessionState::Closed | SessionState::Failed | SessionState::Disconnecting) { self.capture.take(); }
        result.map_err(DriverError::Capture)
    }
    /// Fair source-aware service step, sharing the same event-burst budget as
    /// `drive_once`. A `VpxNoOutput` outcome is not a transmitted frame. As
    /// with the older helper, direct polling bypasses fairness accounting and
    /// `Wait` is only advisory; no timers or repeat worker are created.
    pub async fn drive_once_outcome(&mut self, capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<DriveOutcomeStep, DriverError> {
        if capture_wait.is_zero() || send_wait.is_zero() { return Err(DriverError::InvalidDeadline); }
        if self.fairness.may_poll() {
            if let Some(event) = self.poll_event(send_wait).await? {
                self.fairness.event_returned();
                return Ok(DriveOutcomeStep::Event(event));
            }
        }
        self.fairness.capture_attempted();
        self.capture_step_outcome(Instant::now(), capture_wait, send_wait, pts_ms).await.map(DriveOutcomeStep::Capture)
    }
    /// Make one fair, caller-driven service step. Up to four immediately
    /// available inbound events are surfaced in succession, then one capture
    /// attempt is reserved even if more input is queued. An empty local queue
    /// also causes a capture attempt. Apply/decline every returned control event
    /// before the next step; no action is automatically authorized. ACKs are
    /// handled by `poll_event`, as usual. This policy is not source parity,
    /// multi-peer fairness, a background loop or a nonblocking native capture.
    ///
    /// `Capture(Wait(delay))` is only a pacing hint: poll again frequently for
    /// incoming events, timeouts and revocation. The caller supplies the media
    /// clock; topology changes and capture reset remain explicit. Cancellation
    /// or indeterminate I/O requires closing/dropping the whole driver. Mixing
    /// this helper with direct `poll_event`/`capture_step` calls bypasses its
    /// event streak accounting. Use a dedicated thread/executor for potentially
    /// blocking native capture, not an application's event-loop thread.
    pub async fn drive_once(&mut self, capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<DriveStep, DriverError> {
        if capture_wait.is_zero() || send_wait.is_zero() { return Err(DriverError::InvalidDeadline); }
        if self.fairness.may_poll() {
            if let Some(event) = self.poll_event(send_wait).await? {
                self.fairness.event_returned();
                return Ok(DriveStep::Event(event));
            }
        }
        self.fairness.capture_attempted();
        self.capture_step(Instant::now(), capture_wait, send_wait, pts_ms).await.map(DriveStep::Capture)
    }
    /// Stop/drop capture and close the host even if either operation fails.
    /// Detectable failures are both returned; OS delivery may still be unknown.
    pub fn close(&mut self) -> Result<(), DriverError> {
        let capture = self.capture.take().and_then(|mut capture| capture.stop(&mut self.host).err());
        let connection = self.host.close().err();
        if capture.is_some() || connection.is_some() { Err(DriverError::Cleanup { capture, connection }) } else { Ok(()) }
    }
}
impl<T: UpgradeableDuplexTransport, B: InputBackend> Drop for ScheduledSession<T, B> {
    fn drop(&mut self) { let _ = self.close(); }
}

#[cfg(test)]
mod fair_tests {
    use super::*;
    #[test]
    fn sustained_events_require_capture_after_bounded_burst() {
        let mut turns = EventFairness::default();
        for _ in 0..MAX_EVENT_BURST { assert!(turns.may_poll()); turns.event_returned(); }
        assert!(!turns.may_poll());
        // Repeated bookkeeping cannot overflow or re-enable event polling.
        for _ in 0..1000 { turns.event_returned(); }
        assert!(!turns.may_poll());
        turns.capture_attempted(); assert!(turns.may_poll());
    }
    #[test]
    fn empty_queue_attempt_resets_partial_burst() {
        let mut turns = EventFairness::default();
        turns.event_returned(); turns.event_returned();
        turns.capture_attempted();
        for _ in 0..MAX_EVENT_BURST { assert!(turns.may_poll()); turns.event_returned(); }
        assert!(!turns.may_poll());
    }
}
