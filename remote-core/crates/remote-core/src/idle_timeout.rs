//! Caller-driven, opt-in source-style authorized-session idle timeout.
//! RustDesk `Connection::get_auto_disconenct_timer` resets its timer on selected
//! activity and checks it from a one-second tick. This module creates no timer,
//! does not read global config, and never closes sessions on its own.
use std::{error::Error, fmt, time::{Duration, Instant}};
/// Local policy bound; source configuration has no equivalent maximum.
pub const MAX_MINUTES: u32 = 24 * 60;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleError { InvalidTimeout, ClockWentBackwards }
impl fmt::Display for IdleError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "idle timeout: {self:?}") } }
impl Error for IdleError {}
/// One authorized session's activity timestamp. Caller must use a single
/// monotonic clock, drive checks frequently, and enforce closure and cleanup.
pub struct IdleTimeout { last_activity: Instant, threshold_seconds: u64 }
impl IdleTimeout {
    pub fn new(minutes: u32, now: Instant) -> Result<Self, IdleError> {
        if minutes == 0 || minutes > MAX_MINUTES { return Err(IdleError::InvalidTimeout); }
        Ok(Self { last_activity: now, threshold_seconds: u64::from(minutes) * 60 })
    }
    pub fn activity(&mut self, now: Instant) -> Result<(), IdleError> {
        if now < self.last_activity { return Err(IdleError::ClockWentBackwards); }
        self.last_activity = now; Ok(())
    }
    /// Source checks whole seconds strictly greater than configured minutes*60;
    /// with a one-minute threshold this first becomes true at 61 seconds.
    pub fn expired(&self, now: Instant) -> Result<bool, IdleError> {
        let elapsed = now.checked_duration_since(self.last_activity).ok_or(IdleError::ClockWentBackwards)?;
        Ok(elapsed.as_secs() > self.threshold_seconds)
    }
    /// Advisory delay until the source-style threshold is reached. Caller must
    /// still react promptly to I/O, permission revocation and local shutdown.
    pub fn remaining(&self, now: Instant) -> Result<Duration, IdleError> {
        let elapsed = now.checked_duration_since(self.last_activity).ok_or(IdleError::ClockWentBackwards)?;
        Ok(Duration::from_secs(self.threshold_seconds + 1).saturating_sub(elapsed))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_source_whole_second_strict_boundary_and_reset() {
        let now = Instant::now(); let mut idle = IdleTimeout::new(1, now).unwrap();
        assert_eq!(idle.remaining(now).unwrap(), Duration::from_secs(61));
        assert!(!idle.expired(now + Duration::from_millis(60_999)).unwrap());
        assert!(idle.expired(now + Duration::from_secs(61)).unwrap());
        idle.activity(now + Duration::from_secs(30)).unwrap();
        assert!(!idle.expired(now + Duration::from_secs(61)).unwrap());
        assert!(idle.expired(now + Duration::from_secs(91)).unwrap());
        assert_eq!(idle.activity(now), Err(IdleError::ClockWentBackwards));
    }
    #[test]
    fn invalid_bounds_and_clock_regression_are_rejected() {
        let t = Instant::now();
        assert!(matches!(IdleTimeout::new(0, t), Err(IdleError::InvalidTimeout)));
        assert!(matches!(IdleTimeout::new(MAX_MINUTES + 1, t), Err(IdleError::InvalidTimeout)));
        let idle = IdleTimeout::new(1, t).unwrap();
        assert_eq!(idle.expired(t - Duration::from_millis(1)), Err(IdleError::ClockWentBackwards));
    }
}
