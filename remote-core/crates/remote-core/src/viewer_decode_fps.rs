//! Caller-driven extraction of `src/client.rs::fps_calculate` for one decoder.
//! This type does not time work, inspect frames, create a decoder or prove a
//! frame was rendered. Feed only successful displayed-frame measurements as the
//! pinned source does. Use a separate meter per display and reset on reconnect.
use std::{error::Error, fmt, time::Duration};

const SKIP_INITIAL: u32 = 3;
const UPDATE_EVERY: u32 = 10;
const RESET_AFTER: u32 = 30;
const MAX_SAMPLE: Duration = Duration::from_secs(60);
/// Conservative local bound shared with `viewer_fps` samples; the source can
/// report a larger value when measurements round down to one millisecond.
pub const MAX_REPORTED_FPS: u32 = 1000;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeterError { InvalidDuration, Overflow }
impl fmt::Display for MeterError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "decode FPS meter: {self:?}") } }
impl Error for MeterError {}
/// Source retains the last reported FPS across format changes until a new
/// estimate becomes available. This value may therefore be stale; call `reset`
/// if a stricter local policy is needed. No native timing is performed here.
#[derive(Default)]
pub struct DecodeFps { skipped: u32, count: u32, total: Duration, fps: Option<u32> }
impl DecodeFps {
    pub fn new() -> Self { Self::default() }
    pub fn estimate(&self) -> Option<u32> { self.fps }
    pub fn reset(&mut self) { *self = Self::new(); }
    /// Record one locally timed successful displayed frame. Returns a newly
    /// computed estimate only every tenth measured frame; otherwise None.
    /// Zero duration is accepted and does not update FPS until aggregate
    /// milliseconds are nonzero, matching source. Durations over 60 seconds
    /// are rejected without changing state; arithmetic overflow fails closed.
    pub fn record(&mut self, format_changed: bool, elapsed: Duration) -> Result<Option<u32>, MeterError> {
        if elapsed > MAX_SAMPLE { return Err(MeterError::InvalidDuration); }
        let (skipped, count, total) = if format_changed { (0, 0, Duration::ZERO) } else { (self.skipped, self.count, self.total) };
        if skipped < SKIP_INITIAL {
            self.skipped = skipped + 1; self.count = count; self.total = total;
            return Ok(None);
        }
        let total = total.checked_add(elapsed).ok_or(MeterError::Overflow)?;
        let count = count.checked_add(1).ok_or(MeterError::Overflow)?;
        let ms = total.as_millis();
        let updated = if count % UPDATE_EVERY == 0 && ms > 0 {
            let value = (u128::from(count) * 1000 / ms).min(u128::from(MAX_REPORTED_FPS));
            Some(value as u32)
        } else { None };
        if let Some(value) = updated { self.fps = Some(value); }
        self.skipped = skipped;
        if count >= RESET_AFTER { self.count = 0; self.total = Duration::ZERO; }
        else { self.count = count; self.total = total; }
        Ok(updated)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn skips_first_three_and_reports_at_ten_twenty_thirty() {
        let mut meter = DecodeFps::new();
        for _ in 0..3 { assert_eq!(meter.record(false, Duration::from_secs(1)).unwrap(), None); }
        for count in 1..=30 {
            let update = meter.record(false, Duration::from_millis(20)).unwrap();
            assert_eq!(update, if count % 10 == 0 { Some(50) } else { None });
        }
        assert_eq!(meter.estimate(), Some(50));
        assert_eq!(meter.record(false, Duration::from_millis(100)).unwrap(), None);
    }
    #[test]
    fn source_format_change_keeps_stale_estimate_but_resets_window() {
        let mut meter = DecodeFps::new();
        for _ in 0..13 { meter.record(false, Duration::from_millis(10)).unwrap(); }
        assert_eq!(meter.estimate(), Some(100));
        assert_eq!(meter.record(true, Duration::from_millis(10)).unwrap(), None);
        assert_eq!(meter.estimate(), Some(100));
        for _ in 0..2 { meter.record(false, Duration::ZERO).unwrap(); }
        for _ in 0..9 { assert_eq!(meter.record(false, Duration::from_millis(50)).unwrap(), None); }
        assert_eq!(meter.record(false, Duration::from_millis(50)).unwrap(), Some(20));
        meter.reset(); assert_eq!(meter.estimate(), None);
    }
    #[test]
    fn zero_time_and_invalid_sample_are_atomic_and_rate_is_capped() {
        let mut meter = DecodeFps::new();
        for _ in 0..13 { assert_eq!(meter.record(false, Duration::ZERO).unwrap(), None); }
        assert_eq!(meter.estimate(), None);
        assert_eq!(meter.record(true, Duration::from_secs(61)), Err(MeterError::InvalidDuration));
        for _ in 0..9 { assert_eq!(meter.record(false, Duration::from_micros(100)).unwrap(), None); }
        assert_eq!(meter.record(false, Duration::from_micros(100)).unwrap(), Some(MAX_REPORTED_FPS));
    }
}
