//! Caller-driven receive-liveness bookkeeping based on the pinned RustDesk
//! server's 30-second `last_recv_time` check. No socket reads, probes, timers,
//! authentication or automatic closure are performed here.
use std::{error::Error, fmt, time::{Duration, Instant}};
pub const SOURCE_RECEIVE_TIMEOUT: Duration = Duration::from_secs(30);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogError { ClockWentBackwards }
impl fmt::Display for WatchdogError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "receive watchdog: {self:?}") } }
impl Error for WatchdogError {}
/// One local host connection; starts at enable time and uses a monotonic clock.
/// Frame receipt is not identity, proof of activity by a human or an RTT.
pub struct ReceiveWatchdog { last_frame: Instant }
impl ReceiveWatchdog {
    pub fn new(now: Instant) -> Self { Self { last_frame: now } }
    pub fn received(&mut self, now: Instant) -> Result<(), WatchdogError> {
        if now < self.last_frame { return Err(WatchdogError::ClockWentBackwards); }
        self.last_frame = now; Ok(())
    }
    pub fn expired(&self, now: Instant) -> Result<bool, WatchdogError> {
        Ok(now.checked_duration_since(self.last_frame).ok_or(WatchdogError::ClockWentBackwards)? >= SOURCE_RECEIVE_TIMEOUT)
    }
    pub fn remaining(&self, now: Instant) -> Result<Duration, WatchdogError> {
        let elapsed = now.checked_duration_since(self.last_frame).ok_or(WatchdogError::ClockWentBackwards)?;
        Ok(SOURCE_RECEIVE_TIMEOUT.saturating_sub(elapsed))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boundary_and_received_reset() {
        let t = Instant::now(); let mut w = ReceiveWatchdog::new(t);
        assert!(!w.expired(t + Duration::from_millis(29_999)).unwrap());
        assert!(w.expired(t + SOURCE_RECEIVE_TIMEOUT).unwrap());
        w.received(t + Duration::from_secs(1)).unwrap();
        assert!(!w.expired(t + SOURCE_RECEIVE_TIMEOUT).unwrap());
        assert_eq!(w.received(t), Err(WatchdogError::ClockWentBackwards));
        assert_eq!(w.remaining(t + Duration::from_secs(1)).unwrap(), SOURCE_RECEIVE_TIMEOUT);
    }
}
