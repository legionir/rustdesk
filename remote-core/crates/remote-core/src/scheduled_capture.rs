//! Caller-driven, single-session multi-display software capture pacing.
//!
//! This intentionally creates no worker or background tasks. The caller owns
//! the connection and must interleave input/control receive calls, handle
//! WouldBlock and errors, enforce per-operation deadlines, protect consent,
//! revalidate topology and coordinate decoder recovery. This serialized path
//! cannot receive input during native capture or network send. It does not
//! implement source probes, multi-peer service queues, cancellation or fairness
//! between sessions. Optional single-session ACK pacing is caller-driven and
//! remains unbuilt and untested.
use crate::{capture_pump::MultiCapture, frame_wait::{FrameWait, WaitError}, host_connection::{ConnectionError, HostConnection, HostEvent}, video_schedule::{DisplayCadences, ScheduleError}};
use remote_input::InputBackend;
use remote_capture::Display;
use remote_codec::EncoderConfig;
use remote_transport::NetworkTransport;
use std::{error::Error, fmt, time::{Duration, Instant}};

#[derive(Debug)]
pub enum ScheduledCaptureError { InvalidGroup, InvalidRecommendation, QualityUnsupported, AckUnavailable, Ack(WaitError), AckClose { ack: WaitError, close: ConnectionError }, Schedule(ScheduleError), Connection(ConnectionError) }
impl fmt::Display for ScheduledCaptureError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "scheduled capture: {self:?}") } }
impl Error for ScheduledCaptureError {}
/// Result of one caller-driven scheduling step. `Wait` is advisory; the owner
/// should still service input/permission changes, not sleep blindly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step { Sent(i32), Wait(Duration) }
/// Source-aware scheduled result; no-output never creates an ACK wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeStep { Sent(i32), VpxNoOutput(i32), Wait(Duration) }
fn record_outcome_ack(wait: &mut Option<FrameWait>, display: u32, outcome: crate::video::SendOutcome, now: Instant) -> Result<(), WaitError> {
    if outcome == crate::video::SendOutcome::Sent {
        if let Some(wait) = wait.as_mut() { wait.sent(display, &[1], now)?; }
    }
    Ok(())
}
/// Owns the capture group so its set of streams cannot be silently replaced.
/// `stop` or dropping is required to release capture resources. Dropping alone
/// does not transition the host out of streaming state.
pub struct ScheduledCapture { group: MultiCapture, cadences: DisplayCadences, ack_wait: Option<FrameWait> }
impl ScheduledCapture {
    /// Bind cadences to an already approved and started group, all at the same
    /// initial frame rate. Failure returns the group to the caller for cleanup.
    pub fn new(group: MultiCapture, fps: u32) -> Result<Self, (ScheduledCaptureError, MultiCapture)> {
        let mut cadences = DisplayCadences::new();
        let displays: Vec<i32> = group.displays().collect();
        for id in displays {
            let id = match u32::try_from(id) { Ok(id) => id, Err(_) => return Err((ScheduledCaptureError::InvalidGroup, group)) };
            if let Err(error) = cadences.add(id, fps) { return Err((ScheduledCaptureError::Schedule(error), group)); }
        }
        Ok(Self { group, cadences, ack_wait: None })
    }
    /// Opt into caller-driven ACK pacing for this exact bound session, only
    /// when its login explicitly requested source `video_ack_required`. A local
    /// timeout is bounded to the source's 3-second ceiling. This is per-session
    /// not a shared multi-peer source service; no queue-dequeue notification is
    /// emulated for peers that did not request ACKs. Once enabled it cannot be
    /// toggled while the scheduler lives; stop/recreate to reset stream state.
    pub fn enable_ack_wait<T: NetworkTransport, B: InputBackend>(&mut self,
        host: &HostConnection<T, B>, timeout: Duration) -> Result<(), ScheduledCaptureError> {
        if self.ack_wait.is_some() || host.session_id() != self.group.session_id()
            || !host.initial_video_ack_required().map_err(ScheduledCaptureError::Connection)? {
            return Err(ScheduledCaptureError::AckUnavailable);
        }
        self.ack_wait = Some(FrameWait::new(timeout).map_err(ScheduledCaptureError::Ack)?); Ok(())
    }
    /// Whether this scheduler was explicitly configured to wait for wire ACKs.
    /// This does not imply the peer has rendered any frame.
    pub fn ack_wait_enabled(&self) -> bool { self.ack_wait.is_some() }
    /// Feed one event obtained from the same bound, authorized host. A source
    /// `VideoReceived` clears this connection's waits across all displays; it
    /// has no frame sequence/display identity and can be late or forged. It is
    /// not proof of decode/render. Other events remain the caller's obligation.
    pub fn observe_event<T: NetworkTransport, B: InputBackend>(&mut self,
        host: &HostConnection<T, B>, event: &HostEvent) -> Result<bool, ScheduledCaptureError> {
        if host.session_id() != self.group.session_id() || !host.initial_video_ack_required().map_err(ScheduledCaptureError::Connection)? {
            return Err(ScheduledCaptureError::AckUnavailable);
        }
        let wait = self.ack_wait.as_mut().ok_or(ScheduledCaptureError::AckUnavailable)?;
        if matches!(event, HostEvent::VideoControl(remote_protocol::video_control::VideoControl::FrameReceived)) {
            wait.acknowledge(1).map_err(ScheduledCaptureError::Ack)?; return Ok(true);
        }
        Ok(false)
    }
    /// Forget a removed/reset display's pending ACK after the caller has
    /// coordinated encoder and decoder refresh. This is not an acknowledgement;
    /// a late ACK can still match a later frame. It does not reset the encoder.
    pub fn clear_ack_for_stream_reset(&mut self, display: u32) -> Result<(), ScheduledCaptureError> {
        if !self.cadences.displays().any(|id| id == display) { return Err(ScheduledCaptureError::InvalidGroup); }
        self.ack_wait.as_mut().ok_or(ScheduledCaptureError::AckUnavailable)?.clear_display(display); Ok(())
    }
    /// Forget wrapper-owned converted pixels for one registered display. This
    /// does not clear a wire ACK, prove native erasure, or send a control frame.
    pub fn clear_repeat_input(&mut self, display: i32) -> Result<(), ScheduledCaptureError> {
        self.group.clear_repeat_input(display).map_err(|e| ScheduledCaptureError::Connection(ConnectionError::Capture(e)))
    }
    /// Updates only local pacing for an existing display. No remote option is
    /// applied unless the caller independently validates and authorizes it.
    pub fn set_fps(&mut self, display: u32, fps: u32) -> Result<(), ScheduledCaptureError> {
        self.cadences.set_fps(display, fps).map_err(ScheduledCaptureError::Schedule)
    }
    /// Explicitly apply one source QoS recommendation to a live display.
    /// The caller decides whether peer-derived QoS input is acceptable, and
    /// supplies the recommendation; nothing is applied automatically. Validate
    /// all local values and prepare the cadence before changing the encoder.
    /// If `apply_quality` is false, only pacing changes. If a native quality
    /// update fails, the encoder may be invalidated and must be reset with
    /// decoder/keyframe coordination; cadence remains unchanged. Neither bitrate
    /// nor delivery is guaranteed, and this has not been tested on a desktop.
    pub fn apply_recommendation<T: NetworkTransport, B: InputBackend>(&mut self,
        host: &mut HostConnection<T, B>, display: u32, recommendation: remote_codec::video_qos::Recommendation,
        apply_quality: bool) -> Result<(), ScheduledCaptureError> {
        let id = i32::try_from(display).map_err(|_| ScheduledCaptureError::InvalidGroup)?;
        if !(1..=120).contains(&recommendation.fps) || (apply_quality && (!recommendation.quality_ratio.is_finite()
            || recommendation.quality_ratio <= 0.0 || recommendation.quality_ratio > 2.0)) {
            return Err(ScheduledCaptureError::InvalidRecommendation);
        }
        let mut next = self.cadences.clone();
        next.set_fps(display, recommendation.fps).map_err(ScheduledCaptureError::Schedule)?;
        if apply_quality {
            let (_, supported) = host.multi_capture_encoder_stats(&self.group, id).map_err(ScheduledCaptureError::Connection)?;
            if !supported { return Err(ScheduledCaptureError::QualityUnsupported); }
            host.set_multi_capture_quality(&mut self.group, id, recommendation.quality_ratio).map_err(ScheduledCaptureError::Connection)?;
        } else {
            // Validate session and group membership even for pacing-only updates.
            host.multi_capture_encoder_stats(&self.group, id).map_err(ScheduledCaptureError::Connection)?;
        }
        self.cadences = next; Ok(())
    }
    /// Reconfigure a locally approved group and its cadence table together.
    /// New cadence state is prepared before native changes; if opening fails,
    /// both the previous group and cadence table remain in place. The caller
    /// remains responsible for consent, fresh topology, decoder refresh and
    /// handling subscriptions that intentionally stop all captures.
    pub fn reconfigure<T: NetworkTransport, B: InputBackend>(&mut self, host: &mut HostConnection<T, B>,
        remove: &[i32], add: Vec<(Display, i32, EncoderConfig)>, fps: u32) -> Result<(), ScheduledCaptureError> {
        let mut next = self.cadences.clone();
        for &id in remove {
            let id = u32::try_from(id).map_err(|_| ScheduledCaptureError::InvalidGroup)?;
            if !next.remove(id) { return Err(ScheduledCaptureError::InvalidGroup); }
        }
        for (_, id, _) in &add {
            let id = u32::try_from(*id).map_err(|_| ScheduledCaptureError::InvalidGroup)?;
            next.add(id, fps).map_err(ScheduledCaptureError::Schedule)?;
        }
        host.reconfigure_multi_capture(&mut self.group, remove, add).map_err(ScheduledCaptureError::Connection)?;
        self.cadences = next;
        if let Some(wait) = self.ack_wait.as_mut() { for id in remove { wait.clear_display(*id as u32); } }
        Ok(())
    }
    /// Reserve one round-robin attempt using caller-supplied monotonic time.
    /// The reservation persists on WouldBlock or other failure to avoid busy
    /// polling. `pts_ms` must come from the caller's consistent media clock.
    /// Cancellation leaves the connection Busy; the owner must close/drop it.
    pub async fn step<T: NetworkTransport, B: InputBackend>(&mut self, host: &mut HostConnection<T, B>, now: Instant,
        capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<Step, ScheduledCaptureError> {
        match self.reserve(host, now)? {
            (Some(display), _) => {
                host.send_multi_capture(&mut self.group, display, capture_wait, send_wait, pts_ms).await.map_err(ScheduledCaptureError::Connection)?;
                self.sent(host, display)?;
                Ok(Step::Sent(display))
            },
            (None, Some(wait)) => Ok(Step::Wait(wait)),
            (None, None) => Err(ScheduledCaptureError::InvalidGroup),
        }
    }
    /// Source-aware capture variant. The exact VPX no-output condition keeps
    /// the encoder and consumes cadence, but emits no message and creates no
    /// ACK wait. This does not automatically repeat cached frames, apply QoS
    /// or guarantee remote rendering. Caller drives events, liveness, consent,
    /// and static-refresh policy; cancellation requires closing the driver.
    pub async fn step_outcome<T: NetworkTransport, B: InputBackend>(&mut self, host: &mut HostConnection<T, B>, now: Instant,
        capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<OutcomeStep, ScheduledCaptureError> {
        match self.reserve(host, now)? {
            (Some(display), _) => {
                let outcome = host.send_multi_capture_outcome(&mut self.group, display, capture_wait, send_wait, pts_ms).await.map_err(ScheduledCaptureError::Connection)?;
                self.finish_outcome(host, display, outcome)
            },
            (None, Some(wait)) => Ok(OutcomeStep::Wait(wait)),
            (None, None) => Err(ScheduledCaptureError::InvalidGroup),
        }
    }
    /// Repeat one previously captured member under explicitly supplied local
    /// privacy/age/scheduling policy. Existing ACK wait blocks this attempt;
    /// a wire send records a new wait and exact VPX no-output does not. Repeat
    /// pacing is deliberately NOT automatic and does not consume capture
    /// cadence. Do not call for stale/unauthorized desktop content; caller must
    /// revalidate consent, session and topology. No nonce or render proof exists.
    pub async fn repeat_outcome<T: NetworkTransport, B: InputBackend>(&mut self, host: &mut HostConnection<T, B>, display: i32,
        now: Instant, send_wait: Duration, pts_ms: i64, opt_in: remote_codec::RepeatFrameOptIn) -> Result<OutcomeStep, ScheduledCaptureError> {
        let id = u32::try_from(display).map_err(|_| ScheduledCaptureError::InvalidGroup)?;
        let actual: std::collections::BTreeSet<_> = self.group.displays().map(|id| id as u32).collect();
        let expected: std::collections::BTreeSet<_> = self.cadences.displays().collect();
        if actual != expected || !actual.contains(&id) { return Err(ScheduledCaptureError::InvalidGroup); }
        if now > Instant::now() { return Err(ScheduledCaptureError::Schedule(ScheduleError::ClockWentBackwards)); }
        if send_wait.is_zero() { return Err(ScheduledCaptureError::Connection(ConnectionError::InvalidState)); }
        if let Some(wait) = self.ack_wait.as_mut() {
            if host.session_id() != self.group.session_id() || !host.initial_video_ack_required().map_err(ScheduledCaptureError::Connection)? {
                return Err(ScheduledCaptureError::AckUnavailable);
            }
            wait.expire(id, now).map_err(ScheduledCaptureError::Ack)?;
            if let Some(delay) = wait.remaining(id, now).map_err(ScheduledCaptureError::Ack)? { return Ok(OutcomeStep::Wait(delay)); }
        }
        let outcome = host.repeat_multi_capture_outcome(&mut self.group, display, pts_ms, send_wait, opt_in).await.map_err(ScheduledCaptureError::Connection)?;
        self.finish_outcome(host, display, outcome)
    }
    fn reserve<T: NetworkTransport, B: InputBackend>(&mut self, host: &HostConnection<T, B>, now: Instant) -> Result<(Option<i32>, Option<Duration>), ScheduledCaptureError> {
        let actual: std::collections::BTreeSet<_> = self.group.displays().map(|id| id as u32).collect();
        let expected: std::collections::BTreeSet<_> = self.cadences.displays().collect();
        if actual != expected { return Err(ScheduledCaptureError::InvalidGroup); }
        if now > Instant::now() { return Err(ScheduledCaptureError::Schedule(ScheduleError::ClockWentBackwards)); }
        let mut blocked = std::collections::HashMap::new();
        if let Some(wait) = self.ack_wait.as_mut() {
            if host.session_id() != self.group.session_id() || !host.initial_video_ack_required().map_err(ScheduledCaptureError::Connection)? {
                return Err(ScheduledCaptureError::AckUnavailable);
            }
            for &id in &actual {
                wait.expire(id, now).map_err(ScheduledCaptureError::Ack)?;
                if let Some(delay) = wait.remaining(id, now).map_err(ScheduledCaptureError::Ack)? { blocked.insert(id, delay); }
            }
        }
        let (display, wait) = self.cadences.next_due_blocked(now, &blocked).map_err(ScheduledCaptureError::Schedule)?;
        let display = display.map(i32::try_from).transpose().map_err(|_| ScheduledCaptureError::InvalidGroup)?;
        Ok((display, wait))
    }
    fn finish_outcome<T: NetworkTransport, B: InputBackend>(&mut self, host: &mut HostConnection<T, B>, display: i32,
        outcome: crate::video::SendOutcome) -> Result<OutcomeStep, ScheduledCaptureError> {
        if let Err(error) = record_outcome_ack(&mut self.ack_wait, display as u32, outcome, Instant::now()) {
            return match host.close() {
                Ok(()) => Err(ScheduledCaptureError::Ack(error)),
                Err(close) => Err(ScheduledCaptureError::AckClose { ack: error, close }),
            };
        }
        Ok(match outcome { crate::video::SendOutcome::Sent => OutcomeStep::Sent(display), crate::video::SendOutcome::VpxNoOutput => OutcomeStep::VpxNoOutput(display) })
    }
    fn sent<T: NetworkTransport, B: InputBackend>(&mut self, host: &mut HostConnection<T, B>, display: i32) -> Result<(), ScheduledCaptureError> {
        self.finish_outcome(host, display, crate::video::SendOutcome::Sent).map(|_| ())
    }
    /// Give the caller explicit access for encoder reset/quality operations.
    /// Reconfigure membership through `ScheduledCapture::reconfigure` instead;
    /// membership index changes are detected on the next step; changing an
    /// index away and back cannot be detected and remains the caller's error.
    pub fn group(&self) -> &MultiCapture { &self.group }
    pub fn group_mut(&mut self) -> &mut MultiCapture { &mut self.group }
    /// Stop session streaming and release the group when this object is dropped.
    /// On failure the caller retains this object and may retry or close the host.
    pub fn stop<T: NetworkTransport, B: InputBackend>(&mut self, host: &mut HostConnection<T, B>) -> Result<(), ScheduledCaptureError> {
        host.stop_multi_capture(&mut self.group).map_err(ScheduledCaptureError::Connection)?;
        if let Some(wait) = self.ack_wait.as_mut() { wait.reset(); }
        Ok(())
    }
}

#[cfg(test)]
mod outcome_ack_tests {
    use super::*;
    use crate::video::SendOutcome;
    #[test]
    fn no_output_never_creates_or_clears_ack_wait() {
        let t = Instant::now(); let mut wait = Some(FrameWait::new(Duration::from_secs(1)).unwrap());
        record_outcome_ack(&mut wait, 0, SendOutcome::VpxNoOutput, t).unwrap();
        assert_eq!(wait.as_ref().unwrap().remaining(0, t).unwrap(), None);
        record_outcome_ack(&mut wait, 0, SendOutcome::Sent, t).unwrap();
        assert_eq!(wait.as_ref().unwrap().remaining(0, t).unwrap(), Some(Duration::from_secs(1)));
        record_outcome_ack(&mut wait, 0, SendOutcome::VpxNoOutput, t).unwrap();
        assert_eq!(wait.as_ref().unwrap().remaining(0, t).unwrap(), Some(Duration::from_secs(1)));
        assert!(matches!(record_outcome_ack(&mut wait, 0, SendOutcome::Sent, t), Err(WaitError::AlreadyPending)));
        wait.as_mut().unwrap().acknowledge(1).unwrap();
        assert_eq!(wait.as_ref().unwrap().remaining(0, t).unwrap(), None);
    }
}
