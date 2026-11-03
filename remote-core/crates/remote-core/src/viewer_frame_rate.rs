//! Caller-driven extraction of source UI-callback frame-rate accounting.
//!
//! `src/client/io_loop.rs` increments frame_count immediately before handing a
//! decoded frame to the UI, then on a status tick of at least one second uses
//! `count * 1000 / elapsed_ms` and resets the count. This helper neither
//! observes frames nor provides a timer or renderer. Callers should use the
//! same actual elapsed interval for every display and align their own ticks.
use std::{error::Error, fmt, time::Duration};
const MAX_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_COUNT: u32 = 1_000_000;
const MAX_FPS: u32 = 1000;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateError { InvalidInterval, CountLimit }
impl fmt::Display for RateError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "viewer frame rate: {self:?}") } }
impl Error for RateError {}
#[derive(Default)]
pub struct ViewerFrameRate { count: u32 }
impl ViewerFrameRate {
    pub fn new() -> Self { Self::default() }
    /// Record a UI-callback frame, not an input packet or confirmed render.
    /// Overflow fails without modifying the count; caller must reset/drop state.
    pub fn record_frame(&mut self) -> Result<(), RateError> {
        if self.count == MAX_COUNT { return Err(RateError::CountLimit); }
        self.count += 1; Ok(())
    }
    pub fn count(&self) -> u32 { self.count }
    pub fn reset(&mut self) { self.count = 0; }
    /// A subsecond tick returns None without resetting the counter. Longer
    /// intervals use integer millisecond division, capped at 1000 FPS for the
    /// RemoteCore planner. Rejecting intervals over 24h and count exhaustion,
    /// and avoiding source's unchecked integer casts, are deliberate changes.
    /// A successful sample resets the count even if no frames were recorded.
    pub fn sample(&mut self, elapsed: Duration) -> Result<Option<u32>, RateError> {
        if elapsed > MAX_INTERVAL { return Err(RateError::InvalidInterval); }
        let millis = elapsed.as_millis();
        if millis < 1000 { return Ok(None); }
        let rate = ((u128::from(self.count) * 1000 / millis).min(u128::from(MAX_FPS))) as u32;
        self.count = 0; Ok(Some(rate))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_timer_correction_and_subsecond_behavior() {
        let mut rate = ViewerFrameRate::new();
        for _ in 0..30 { rate.record_frame().unwrap(); }
        assert_eq!(rate.sample(Duration::from_millis(999)).unwrap(), None);
        assert_eq!(rate.count(), 30);
        assert_eq!(rate.sample(Duration::from_millis(1500)).unwrap(), Some(20));
        assert_eq!(rate.count(), 0);
        assert_eq!(rate.sample(Duration::from_secs(1)).unwrap(), Some(0));
    }
    #[test]
    fn limits_are_atomic_and_caps_rate() {
        let mut rate = ViewerFrameRate { count: MAX_COUNT };
        assert_eq!(rate.record_frame(), Err(RateError::CountLimit));
        assert_eq!(rate.sample(Duration::from_secs(24 * 60 * 60 + 1)), Err(RateError::InvalidInterval));
        assert_eq!(rate.count(), MAX_COUNT);
        assert_eq!(rate.sample(Duration::from_secs(1)).unwrap(), Some(1000));
        assert_eq!(rate.count(), 0);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::viewer_fps::{DisplaySample, ViewerFps};
    use std::time::Instant;
    #[test]
    fn measured_callback_rate_feeds_explicit_planner_tick() {
        let mut meter = ViewerFrameRate::new();
        for _ in 0..30 { meter.record_frame().unwrap(); }
        let delivered = meter.sample(Duration::from_secs(1)).unwrap().unwrap();
        let sample = DisplaySample { display: 0, received_fps: delivered, decode_fps: Some(30), queue_len: 0, queue_capacity: 120 };
        let mut fps = ViewerFps::new(); fps.set_displays(&[0]).unwrap();
        assert_eq!(fps.tick(Instant::now(), true, None, &[sample]).unwrap().custom_fps, Some(27));
    }
}
