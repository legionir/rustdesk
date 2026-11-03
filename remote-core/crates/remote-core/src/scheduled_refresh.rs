//! Opt-in caller-driven integration of software static refresh with a single
//! scheduled session. No background task, consent UI or OS-global exclusion is
//! created. The retained I420 image is sensitive; a cooperative age limit is
//! enforced only while the caller drives this object. This is not source
//! multi-peer service parity, secure erasure, proof of rendering, or a safe
//! untrusted decoder. It is unbuilt, untested and requires security review.
use crate::{scheduled_capture::OutcomeStep, scheduled_session::{DriveOutcomeStep, DriverError, ScheduledSession},
    static_refresh::{HardwareBackend, RefreshCodec, RefreshDecision, RefreshError, RepeatOutcome, StaticRefreshPolicy}};
use remote_codec::{Codec, RepeatFrameOptIn};
use remote_input::InputBackend;
use remote_session::SessionId;
use remote_transport::UpgradeableDuplexTransport;
use std::{collections::{BTreeMap, BTreeSet}, error::Error, fmt, time::{Duration, Instant}};

const MAX_DISPLAYS: usize = 8;
/// Local policy cap, not a source limit or guarantee that native memory is gone.
pub const MAX_CACHE_AGE: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum RefreshSessionError { InvalidConfiguration, InvalidBinding, ConsentRequired, Interrupted, Policy(RefreshError), Driver(DriverError) }
impl fmt::Display for RefreshSessionError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "scheduled static refresh: {self:?}") } }
impl Error for RefreshSessionError {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeatStep { NoInput, Expired, NotReady, Wait(Duration), RestartForSubscribers, Sent, VpxNoOutput }

// The exact wrapper position matters: only a capture-side WouldBlock occurs
// before encoding or network I/O. A similarly named codec/network error is
// never classified as safe to retry here.
fn capture_would_block(error: &DriverError) -> bool {
    matches!(error, DriverError::Capture(crate::scheduled_capture::ScheduledCaptureError::Connection(
        crate::host_connection::ConnectionError::Capture(crate::capture_pump::CapturePumpError::Capture(e))
    )) if e.kind() == std::io::ErrorKind::WouldBlock)
}

struct Entry { codec: RefreshCodec, policy: StaticRefreshPolicy, captured_at: Option<Instant> }
impl Entry {
    fn new(codec: RefreshCodec, now: Instant) -> Self {
        Self { codec, policy: StaticRefreshPolicy::new(codec, HardwareBackend::Other, now), captured_at: None }
    }
    fn reset(&mut self, now: Instant) { *self = Self::new(self.codec, now); }
    fn expired(&self, now: Instant, max_age: Duration) -> Result<bool, RefreshError> {
        match self.captured_at {
            None => Ok(false),
            Some(start) => Ok(now.checked_duration_since(start).ok_or(RefreshError::ClockWentBackwards)? >= max_age),
        }
    }
    fn capture_finished(&mut self, started: Instant, finished: Instant) -> Result<(), RefreshError> {
        if finished < started { return Err(RefreshError::ClockWentBackwards); }
        self.policy.new_frame(finished)?;
        self.policy.encoded(true, finished)?;
        self.captured_at = Some(started);
        Ok(())
    }
}

/// Per-session policy state; caller must provide the exact driver, locally
/// established codec for each current display and exclusive serialized access.
/// Equal session IDs are not object identity. Recreate after any reconfigure,
/// encoder reset, desktop/topology change, consent change or uncertain I/O;
/// replacing a display with the same index cannot be detected here.
pub struct ScheduledRefresh {
    session: SessionId,
    entries: BTreeMap<i32, Entry>,
    max_age: Duration,
    interrupted: bool,
}
impl ScheduledRefresh {
    /// Whether an operation was interrupted or failed after it began. This
    /// flag is advisory: regardless of its value, caller must close on uncertain
    /// I/O, external driver mutation or revoked local consent.
    pub fn is_interrupted(&self) -> bool { self.interrupted }
    /// Require an exact display set and locally known software codec. The
    /// codec list is an assertion; it does not negotiate or inspect encoders.
    pub fn new<T: UpgradeableDuplexTransport, B: InputBackend>(driver: &ScheduledSession<T, B>,
        displays: &[(i32, Codec)], max_age: Duration) -> Result<Self, RefreshSessionError> {
        if displays.is_empty() || displays.len() > MAX_DISPLAYS || max_age.is_zero() || max_age > MAX_CACHE_AGE {
            return Err(RefreshSessionError::InvalidConfiguration);
        }
        let now = Instant::now(); let mut entries = BTreeMap::new();
        for &(display, codec) in displays {
            if display < 0 { return Err(RefreshSessionError::InvalidConfiguration); }
            let codec = match codec { Codec::Vp8 => RefreshCodec::Vp8, Codec::Vp9 => RefreshCodec::Vp9, Codec::Av1 => RefreshCodec::Av1 };
            if entries.insert(display, Entry::new(codec, now)).is_some() { return Err(RefreshSessionError::InvalidConfiguration); }
        }
        let manager = Self { session: driver.session_id(), entries, max_age, interrupted: false };
        manager.check(driver)?; Ok(manager)
    }
    fn check<T: UpgradeableDuplexTransport, B: InputBackend>(&self, driver: &ScheduledSession<T, B>) -> Result<(), RefreshSessionError> {
        if self.interrupted { return Err(RefreshSessionError::Interrupted); }
        if self.session != driver.session_id() { return Err(RefreshSessionError::InvalidBinding); }
        let actual: BTreeSet<_> = driver.capture_displays().ok_or(RefreshSessionError::InvalidBinding)?.into_iter().collect();
        let expected: BTreeSet<_> = self.entries.keys().copied().collect();
        if actual != expected { return Err(RefreshSessionError::InvalidBinding); }
        Ok(())
    }
    /// Explicitly erase one wrapper-owned converted image and its policy state.
    /// Native buffers and caller copies are not covered. On a cleanup error,
    /// the manager is poisoned and the caller must close/drop the whole driver.
    pub fn clear<T: UpgradeableDuplexTransport, B: InputBackend>(&mut self, driver: &mut ScheduledSession<T, B>, display: i32) -> Result<(), RefreshSessionError> {
        self.check(driver)?;
        if !self.entries.contains_key(&display) { return Err(RefreshSessionError::InvalidConfiguration); }
        self.interrupted = true;
        driver.clear_repeat_input(display).map_err(RefreshSessionError::Driver)?;
        self.entries.get_mut(&display).ok_or(RefreshSessionError::InvalidConfiguration)?.reset(Instant::now());
        self.interrupted = false; Ok(())
    }
    /// Clear all registered wrapper caches. It does not itself revoke session
    /// permission or prevent future capture. No native erasure is guaranteed.
    pub fn clear_all<T: UpgradeableDuplexTransport, B: InputBackend>(&mut self, driver: &mut ScheduledSession<T, B>) -> Result<(), RefreshSessionError> {
        self.check(driver)?;
        let displays: Vec<_> = self.entries.keys().copied().collect();
        for display in displays { self.clear(driver, display)?; }
        Ok(())
    }
    /// Expire cached inputs at a caller-driven poll. Nothing runs while the
    /// application is idle; an image can remain allocated until the next poll
    /// or drop. The capture start, not completion, is used as the age origin.
    pub fn clear_expired<T: UpgradeableDuplexTransport, B: InputBackend>(&mut self, driver: &mut ScheduledSession<T, B>) -> Result<usize, RefreshSessionError> {
        self.check(driver)?;
        let now = Instant::now(); let mut expired = Vec::new();
        for (&display, entry) in &self.entries {
            if entry.expired(now, self.max_age).map_err(RefreshSessionError::Policy)? { expired.push(display); }
        }
        for &display in &expired { self.clear(driver, display)?; }
        Ok(expired.len())
    }
    /// One fair event-or-capture operation. On a sent frame or typed VPX
    /// no-output, record a new locally retained input. Callers still handle
    /// every returned event and all permission/topology/decoder transitions.
    /// Cancellation poisons this manager: close/drop the driver and manager.
    /// The exact native capture WouldBlock error is returned without poisoning,
    /// since no encode or send started; caller should pace and service events.
    pub async fn drive_once<T: UpgradeableDuplexTransport, B: InputBackend>(&mut self, driver: &mut ScheduledSession<T, B>,
        capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<DriveOutcomeStep, RefreshSessionError> {
        self.clear_expired(driver)?;
        let started = Instant::now(); self.interrupted = true;
        let step = match driver.drive_once_outcome(capture_wait, send_wait, pts_ms).await {
            Ok(step) => step,
            Err(error) if capture_would_block(&error) => { self.interrupted = false; return Err(RefreshSessionError::Driver(error)); },
            Err(error) => return Err(RefreshSessionError::Driver(error)),
        };
        if let DriveOutcomeStep::Capture(OutcomeStep::Sent(display) | OutcomeStep::VpxNoOutput(display)) = &step {
            self.entries.get_mut(display).ok_or(RefreshSessionError::InvalidBinding)?
                .capture_finished(started, Instant::now()).map_err(RefreshSessionError::Policy)?;
        }
        self.interrupted = false; Ok(step)
    }
    /// Evaluate one source-style repeat and perform it if due, respecting the
    /// scheduled driver's ACK wait. `confirm_local_consent` and peer state are
    /// caller assertions, not a trusted UI or authentication. On false, all
    /// wrapper caches are cleared and the manager is poisoned before returning
    /// ConsentRequired; immediately close/drop the driver. This does not itself
    /// revoke host permission or stop other capture paths. `spf`, quality,
    /// subscription-change and display identity must be locally validated.
    /// On send error/cancellation or bookkeeping error close/drop the session;
    /// no retry is safe when delivery is uncertain.
    pub async fn repeat<T: UpgradeableDuplexTransport, B: InputBackend>(&mut self, driver: &mut ScheduledSession<T, B>,
        display: i32, spf: Duration, quality: f32, subscriptions_changed: bool, confirm_local_consent: bool,
        send_wait: Duration, pts_ms: i64) -> Result<RepeatStep, RefreshSessionError> {
        self.check(driver)?;
        if !self.entries.contains_key(&display) || send_wait.is_zero() { return Err(RefreshSessionError::InvalidConfiguration); }
        if !confirm_local_consent { self.clear_all(driver)?; self.interrupted = true; return Err(RefreshSessionError::ConsentRequired); }
        let expired = self.entries.get(&display).ok_or(RefreshSessionError::InvalidConfiguration)?
            .expired(Instant::now(), self.max_age).map_err(RefreshSessionError::Policy)?;
        // A caller repeating only one display must still poll expiry of other
        // cached displays, rather than retaining their pixels indefinitely.
        self.clear_expired(driver)?;
        if expired { return Ok(RepeatStep::Expired); }
        let now = Instant::now();
        let entry = self.entries.get_mut(&display).ok_or(RefreshSessionError::InvalidConfiguration)?;
        if entry.expired(now, self.max_age).map_err(RefreshSessionError::Policy)? {
            self.clear(driver, display)?; return Ok(RepeatStep::Expired);
        }
        if entry.captured_at.is_none() { return Ok(RepeatStep::NoInput); }
        match entry.policy.begin(now, spf, quality, true, true, subscriptions_changed).map_err(RefreshSessionError::Policy)? {
            RefreshDecision::NotReady => return Ok(RepeatStep::NotReady),
            RefreshDecision::Wait(delay) => return Ok(RepeatStep::Wait(delay)),
            RefreshDecision::RestartForSubscribers => return Ok(RepeatStep::RestartForSubscribers),
            RefreshDecision::Repeat => {},
        }
        self.interrupted = true;
        let outcome = driver.repeat_outcome(display, now, send_wait, pts_ms, RepeatFrameOptIn::acknowledge_cached_screen_pixels())
            .await.map_err(RefreshSessionError::Driver)?;
        let entry = self.entries.get_mut(&display).ok_or(RefreshSessionError::InvalidBinding)?;
        let finished = Instant::now();
        let step = match outcome {
            OutcomeStep::Wait(delay) => { entry.policy.cancel_before_encode(finished).map_err(RefreshSessionError::Policy)?; RepeatStep::Wait(delay) },
            OutcomeStep::Sent(id) if id == display => { entry.policy.complete(RepeatOutcome::Output, finished).map_err(RefreshSessionError::Policy)?; RepeatStep::Sent },
            OutcomeStep::VpxNoOutput(id) if id == display => { entry.policy.complete(RepeatOutcome::Failure, finished).map_err(RefreshSessionError::Policy)?; RepeatStep::VpxNoOutput },
            _ => return Err(RefreshSessionError::InvalidBinding),
        };
        self.interrupted = false; Ok(step)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_capture_would_block_is_known_unsent() {
        use crate::{capture_pump::CapturePumpError, host_connection::ConnectionError, scheduled_capture::ScheduledCaptureError};
        let wrap = |kind| DriverError::Capture(ScheduledCaptureError::Connection(ConnectionError::Capture(
            CapturePumpError::Capture(std::io::Error::from(kind)))));
        assert!(capture_would_block(&wrap(std::io::ErrorKind::WouldBlock)));
        assert!(!capture_would_block(&wrap(std::io::ErrorKind::TimedOut)));
        assert!(!capture_would_block(&DriverError::InvalidDeadline));
    }
    #[test]
    fn age_uses_capture_start_and_expires_at_boundary() {
        let t = Instant::now(); let mut entry = Entry::new(RefreshCodec::Vp9, t);
        assert!(!entry.expired(t, Duration::from_secs(1)).unwrap());
        entry.capture_finished(t, t + Duration::from_millis(100)).unwrap();
        assert!(!entry.expired(t + Duration::from_millis(999), Duration::from_secs(1)).unwrap());
        assert!(entry.expired(t + Duration::from_secs(1), Duration::from_secs(1)).unwrap());
        assert!(matches!(entry.expired(t - Duration::from_millis(1), Duration::from_secs(1)), Err(RefreshError::ClockWentBackwards)));
        entry.reset(t + Duration::from_secs(1));
        assert!(!entry.expired(t + Duration::from_secs(2), Duration::from_secs(1)).unwrap());
    }
}
