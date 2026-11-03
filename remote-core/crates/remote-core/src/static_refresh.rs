//! Side-effect-free policy model of `src/server/video_service/static_refresh.rs`.
//!
//! This tracks *decisions* only: it does not retain pixels/textures, capture,
//! encode, send, create timers, handle subscriptions or grant consent. Cached
//! frames are sensitive and require an independently reviewed lifetime and
//! resource policy. The source integrates with a global video service; this
//! caller-driven model is not a drop-in replacement and has not been tested.
use std::{error::Error, fmt, time::{Duration, Instant}};

const INITIAL_REPEAT_INTERVAL: Duration = Duration::from_millis(100);
const MAX_REPEAT_FAILURES: usize = 3;
const MAX_REPEAT_NO_OUTPUTS: usize = 100;
const SPEED: f32 = 0.5;
const BALANCED: f32 = 0.67;
const BEST: f32 = 1.5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshCodec { Vp8, Vp9, Av1, H264, H265, Unknown }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareBackend { Nvenc, Qsv, Amf, Vaapi, VideoToolbox, MediaCodec, Other }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshError { InvalidQuality, InvalidInterval, ClockWentBackwards, Pending, NoPending }
impl fmt::Display for RefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "static refresh: {self:?}") }
}
impl Error for RefreshError {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshDecision { NotReady, Wait(Duration), RestartForSubscribers, Repeat }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeatOutcome { Output, NoOutput, Failure }

/// Source quality bands and measured per-codec/backend output limits. The
/// caller must identify the *actual* selected backend; strings and peer claims
/// do not prove hardware acceleration. The 0 < quality <= 2 bound is local.
pub fn repeat_limit(codec: RefreshCodec, backend: HardwareBackend, quality: f32) -> Result<usize, RefreshError> {
    if !quality.is_finite() || quality <= 0.0 || quality > 2.0 { return Err(RefreshError::InvalidQuality); }
    use HardwareBackend::*;
    use RefreshCodec::*;
    let (low, speed, balanced, best) = match (codec, backend) {
        (Vp8, _) => (20, 20, 20, 30),
        (Vp9, _) => (40, 20, 20, 20),
        (H264, Nvenc) => (80, 50, 60, 30),
        (H264, Qsv) => (80, 70, 130, 110),
        (H264, Amf) => (150, 150, 170, 110),
        (H264, Vaapi) => (150, 100, 90, 60),
        (H265, Nvenc) => (160, 90, 60, 30),
        (H265, Qsv) => (150, 30, 30, 30),
        (H265, Amf) => (200, 200, 200, 120),
        (H265, VideoToolbox) => (90, 90, 50, 90),
        (H264, MediaCodec) => (50, 20, 20, 10),
        (H265, MediaCodec) => (90, 20, 20, 20),
        (H264 | H265, _) => (90, 60, 60, 30),
        (Av1 | Unknown, _) => (0, 0, 0, 0),
    };
    Ok(if quality >= BEST { best } else if quality >= BALANCED { balanced } else if quality >= SPEED { speed } else { low })
}

/// One current source frame for one display and one actual codec/backend.
/// Recreate the policy on stream replacement, display identity change, reset,
/// revoked view permission or uncertain send. `source_ready` is only caller
/// bookkeeping and never proof of viewer delivery or display identity.
pub struct StaticRefreshPolicy {
    codec: RefreshCodec,
    backend: HardwareBackend,
    last_encode: Instant,
    last_observed: Instant,
    output_count: usize,
    output_limit: usize,
    no_outputs: usize,
    failures: usize,
    source_ready: bool,
    pending: Option<Instant>,
}
impl StaticRefreshPolicy {
    pub fn new(codec: RefreshCodec, backend: HardwareBackend, now: Instant) -> Self {
        Self { codec, backend, last_encode: now, last_observed: now, output_count: 0, output_limit: 0,
            no_outputs: 0, failures: 0, source_ready: false, pending: None }
    }
    fn check_time(&self, now: Instant) -> Result<(), RefreshError> {
        if now < self.last_observed { Err(RefreshError::ClockWentBackwards) } else { Ok(()) }
    }
    fn check_not_pending(&self) -> Result<(), RefreshError> {
        if self.pending.is_some() { Err(RefreshError::Pending) } else { Ok(()) }
    }
    /// New captured frame resets the source per-frame counters. This does not
    /// retain or validate the actual pixels. Source keeps the failure counter
    /// until a successful encode, so this model does too.
    pub fn new_frame(&mut self, now: Instant) -> Result<(), RefreshError> {
        self.check_not_pending()?; self.check_time(now)?;
        self.last_observed = now;
        self.output_count = 0; self.output_limit = 0; self.no_outputs = 0; self.source_ready = false;
        Ok(())
    }
    /// Record a regular encode, including a separately handled latency-drain
    /// encode. `source_ready` must be true only under source's condition: an
    /// source reported at least one send connection, or VP8/VP9 returned its
    /// distinct no-output condition. Neither proves peer receipt or rendering.
    pub fn encoded(&mut self, source_ready: bool, now: Instant) -> Result<(), RefreshError> {
        self.check_not_pending()?; self.check_time(now)?;
        self.last_observed = now; self.last_encode = now;
        if source_ready { self.source_ready = true; self.failures = 0; }
        Ok(())
    }
    /// Decide and reserve at most one repeat attempt. `spf` is caller's frame
    /// interval, clamped to source's 30 FPS maximum. `has_cached_input` and
    /// `is_monitor` are caller assertions, not evidence of privacy or content.
    /// The source's subscription-change branch requires a service restart.
    /// An opened repeat must be completed; on cancellation or an uncertain
    /// send, discard this policy together with the encoder/stream instead.
    pub fn begin(&mut self, now: Instant, spf: Duration, quality: f32,
        is_monitor: bool, has_cached_input: bool, subscriptions_changed: bool) -> Result<RefreshDecision, RefreshError> {
        self.check_not_pending()?; self.check_time(now)?;
        if spf.is_zero() || spf > Duration::from_secs(60) { return Err(RefreshError::InvalidInterval); }
        let limit = repeat_limit(self.codec, self.backend, quality)?;
        self.last_observed = now;
        self.output_limit = self.output_limit.max(limit);
        let is_vpx = matches!(self.codec, RefreshCodec::Vp8 | RefreshCodec::Vp9);
        if !is_monitor || self.codec == RefreshCodec::Av1 || !self.source_ready
            || (!is_vpx && self.failures >= MAX_REPEAT_FAILURES)
            || self.no_outputs >= MAX_REPEAT_NO_OUTPUTS || self.output_count >= self.output_limit {
            return Ok(RefreshDecision::NotReady);
        }
        let spf = spf.max(Duration::from_secs(1) / 30);
        let interval = if is_vpx || (self.output_count == 0 && self.no_outputs == 0) {
            INITIAL_REPEAT_INTERVAL.max(spf)
        } else { spf };
        let elapsed = now.checked_duration_since(self.last_encode).ok_or(RefreshError::ClockWentBackwards)?;
        if elapsed < interval { return Ok(RefreshDecision::Wait(interval - elapsed)); }
        if !has_cached_input { return Ok(RefreshDecision::NotReady); }
        if subscriptions_changed { return Ok(RefreshDecision::RestartForSubscribers); }
        self.pending = Some(now);
        Ok(RefreshDecision::Repeat)
    }
    /// Release a reservation only when the caller knows no native encode or
    /// network send was started (for example, an ACK wait blocked the attempt).
    /// This assertion is local bookkeeping, not evidence. If encode or I/O may
    /// have started, discard this policy and encoder/connection instead; never
    /// use this to retry an uncertain send. `last_encode` remains unchanged.
    pub fn cancel_before_encode(&mut self, now: Instant) -> Result<(), RefreshError> {
        if self.pending.is_none() { return Err(RefreshError::NoPending); }
        self.check_time(now)?;
        self.pending = None; self.last_observed = now;
        Ok(())
    }
    /// Report the native repeat outcome, not render or transport proof. Source
    /// timestamps VP8/VP9 after encoding and other codecs at capture-loop start.
    /// `Failure` increments both failure and no-output counters. Output does
    /// not reset the source no-output counter until a new captured frame.
    pub fn complete(&mut self, outcome: RepeatOutcome, finished: Instant) -> Result<(), RefreshError> {
        let started = self.pending.ok_or(RefreshError::NoPending)?;
        self.check_time(finished)?;
        self.pending = None; self.last_observed = finished;
        self.last_encode = if matches!(self.codec, RefreshCodec::Vp8 | RefreshCodec::Vp9) { finished } else { started };
        match outcome {
            RepeatOutcome::Output => { self.output_count += 1; self.failures = 0; },
            RepeatOutcome::NoOutput => self.no_outputs += 1,
            RepeatOutcome::Failure => { self.no_outputs += 1; self.failures += 1; },
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SPF: Duration = Duration::from_millis(33);
    #[test]
    fn source_quality_bands_and_backend_mapping() {
        use HardwareBackend::*; use RefreshCodec::*;
        let limits = |c, b| [0.1, SPEED, BALANCED, BEST].map(|q| repeat_limit(c, b, q).unwrap());
        assert_eq!(limits(Vp8, Other), [20, 20, 20, 30]);
        assert_eq!(limits(Vp9, Other), [40, 20, 20, 20]);
        assert_eq!(limits(H264, Nvenc), [80, 50, 60, 30]);
        assert_eq!(limits(H265, Qsv), [150, 30, 30, 30]);
        assert_eq!(limits(H264, Vaapi), [150, 100, 90, 60]);
        assert_eq!(limits(H265, MediaCodec), [90, 20, 20, 20]);
        assert_eq!(limits(Av1, Other), [0, 0, 0, 0]);
        assert_eq!(repeat_limit(H264, Other, f32::NAN), Err(RefreshError::InvalidQuality));
        assert_eq!(repeat_limit(H264, Other, 2.1), Err(RefreshError::InvalidQuality));
    }
    #[test]
    fn ready_interval_cache_subscription_and_pending_are_explicit() {
        let t = Instant::now(); let mut policy = StaticRefreshPolicy::new(RefreshCodec::Vp9, HardwareBackend::Other, t);
        assert_eq!(policy.begin(t, SPF, 0.5, true, true, false).unwrap(), RefreshDecision::NotReady);
        policy.new_frame(t).unwrap(); policy.encoded(true, t).unwrap();
        assert_eq!(policy.begin(t, SPF, 0.5, true, true, false).unwrap(), RefreshDecision::Wait(Duration::from_millis(100)));
        let due = t + Duration::from_millis(100);
        assert_eq!(policy.begin(due, SPF, 0.5, true, false, false).unwrap(), RefreshDecision::NotReady);
        assert_eq!(policy.begin(due, SPF, 0.5, true, true, true).unwrap(), RefreshDecision::RestartForSubscribers);
        assert_eq!(policy.begin(due, SPF, 0.5, true, true, false).unwrap(), RefreshDecision::Repeat);
        assert_eq!(policy.new_frame(due), Err(RefreshError::Pending));
        assert_eq!(policy.begin(due, SPF, 0.5, true, true, false), Err(RefreshError::Pending));
        assert_eq!(policy.complete(RepeatOutcome::Output, t), Err(RefreshError::ClockWentBackwards));
        policy.complete(RepeatOutcome::Output, due).unwrap();
        assert_eq!(policy.complete(RepeatOutcome::Output, due), Err(RefreshError::NoPending));
        assert_eq!(policy.begin(due, SPF, 0.5, true, true, false).unwrap(), RefreshDecision::Wait(Duration::from_millis(100)));
    }
    #[test]
    fn known_unsent_reservation_can_be_released_without_counting_output() {
        let t = Instant::now();
        let mut p = StaticRefreshPolicy::new(RefreshCodec::Vp9, HardwareBackend::Other, t);
        p.new_frame(t).unwrap(); p.encoded(true, t).unwrap();
        let due = t + Duration::from_millis(100);
        assert_eq!(p.begin(due, SPF, SPEED, true, true, false).unwrap(), RefreshDecision::Repeat);
        assert_eq!(p.cancel_before_encode(t), Err(RefreshError::ClockWentBackwards));
        p.cancel_before_encode(due).unwrap();
        assert_eq!(p.cancel_before_encode(due), Err(RefreshError::NoPending));
        assert_eq!(p.begin(due, SPF, SPEED, true, true, false).unwrap(), RefreshDecision::Repeat);
    }
    #[test]
    fn output_budget_only_increases_until_the_next_captured_frame() {
        let t = Instant::now(); let mut p = StaticRefreshPolicy::new(RefreshCodec::Vp8, HardwareBackend::Other, t);
        p.new_frame(t).unwrap(); p.encoded(true, t).unwrap();
        for n in 1..=20 {
            let now = t + Duration::from_millis(n * 100);
            assert_eq!(p.begin(now, SPF, SPEED, true, true, false).unwrap(), RefreshDecision::Repeat);
            p.complete(RepeatOutcome::Output, now).unwrap();
        }
        let now = t + Duration::from_millis(2100);
        assert_eq!(p.begin(now, SPF, SPEED, true, true, false).unwrap(), RefreshDecision::NotReady);
        // Quality increases the source's maximum encountered budget.
        for n in 21..=30 {
            let now = t + Duration::from_millis(n * 100);
            assert_eq!(p.begin(now, SPF, BEST, true, true, false).unwrap(), RefreshDecision::Repeat);
            p.complete(RepeatOutcome::Output, now).unwrap();
        }
        let now = t + Duration::from_millis(3100);
        assert_eq!(p.begin(now, SPF, SPEED, true, true, false).unwrap(), RefreshDecision::NotReady);
        p.new_frame(now).unwrap(); p.encoded(true, now).unwrap();
        assert_eq!(p.begin(now + Duration::from_millis(100), SPF, SPEED, true, true, false).unwrap(), RefreshDecision::Repeat);
    }
    #[test]
    fn hardware_failures_stop_at_three_but_vpx_stops_after_100_no_outputs() {
        let t = Instant::now();
        for codec in [RefreshCodec::H264, RefreshCodec::Vp9] {
            let mut p = StaticRefreshPolicy::new(codec, HardwareBackend::Other, t);
            p.new_frame(t).unwrap(); p.encoded(true, t).unwrap();
            let count = if codec == RefreshCodec::Vp9 { 100 } else { 3 };
            for n in 1..=count {
                let now = t + Duration::from_millis(n * 100);
                assert_eq!(p.begin(now, SPF, SPEED, true, true, false).unwrap(), RefreshDecision::Repeat);
                p.complete(RepeatOutcome::Failure, now).unwrap();
            }
            let later = t + Duration::from_millis((count + 1) * 100);
            assert_eq!(p.begin(later, SPF, SPEED, true, true, false).unwrap(), RefreshDecision::NotReady);
            p.new_frame(later).unwrap(); p.encoded(true, later).unwrap();
            assert_eq!(p.begin(later + Duration::from_millis(100), SPF, SPEED, true, true, false).unwrap(), RefreshDecision::Repeat);
        }
    }
    #[test]
    fn successful_repeat_does_not_reset_source_no_output_count() {
        let t = Instant::now();
        let mut p = StaticRefreshPolicy::new(RefreshCodec::Vp9, HardwareBackend::Other, t);
        p.new_frame(t).unwrap(); p.encoded(true, t).unwrap();
        for n in 1..=101 {
            let now = t + Duration::from_millis(n * 100);
            assert_eq!(p.begin(now, SPF, SPEED, true, true, false).unwrap(), RefreshDecision::Repeat);
            p.complete(if n == 51 { RepeatOutcome::Output } else { RepeatOutcome::NoOutput }, now).unwrap();
        }
        let after = t + Duration::from_millis(10200);
        assert_eq!(p.begin(after, SPF, SPEED, true, true, false).unwrap(), RefreshDecision::NotReady);
        p.new_frame(after).unwrap(); p.encoded(true, after).unwrap();
        assert_eq!(p.begin(after + Duration::from_millis(100), SPF, SPEED, true, true, false).unwrap(), RefreshDecision::Repeat);
    }
    #[test]
    fn hardware_repeat_interval_changes_after_output_and_caps_rate() {
        let t = Instant::now();
        let mut p = StaticRefreshPolicy::new(RefreshCodec::H264, HardwareBackend::Nvenc, t);
        p.new_frame(t).unwrap(); p.encoded(true, t).unwrap();
        let spf = Duration::from_millis(1);
        assert_eq!(p.begin(t + Duration::from_millis(99), spf, SPEED, true, true, false).unwrap(), RefreshDecision::Wait(Duration::from_millis(1)));
        let first = t + Duration::from_millis(100);
        assert_eq!(p.begin(first, spf, SPEED, true, true, false).unwrap(), RefreshDecision::Repeat);
        // Hardware uses capture-loop start for the next interval; caller still
        // cannot observe a time earlier than actual completion.
        p.complete(RepeatOutcome::Output, first + Duration::from_millis(10)).unwrap();
        let at = first + Duration::from_millis(10);
        assert_eq!(p.begin(at, spf, SPEED, true, true, false).unwrap(),
            RefreshDecision::Wait(Duration::from_secs(1) / 30 - Duration::from_millis(10)));
        let due = first + Duration::from_secs(1) / 30;
        assert_eq!(p.begin(due, spf, SPEED, true, true, false).unwrap(), RefreshDecision::Repeat);
    }
    #[test]
    fn invalid_inputs_do_not_advance_clock_or_begin_attempt() {
        let t = Instant::now(); let mut p = StaticRefreshPolicy::new(RefreshCodec::Vp9, HardwareBackend::Other, t);
        assert_eq!(p.begin(t + Duration::from_secs(1), Duration::ZERO, SPEED, true, true, false), Err(RefreshError::InvalidInterval));
        assert_eq!(p.begin(t + Duration::from_secs(1), SPF, f32::NAN, true, true, false), Err(RefreshError::InvalidQuality));
        p.new_frame(t).unwrap(); p.encoded(true, t).unwrap();
        assert_eq!(p.begin(t - Duration::from_nanos(1), SPF, SPEED, true, true, false), Err(RefreshError::ClockWentBackwards));
        assert_eq!(p.begin(t + Duration::from_millis(100), SPF, SPEED, false, true, false).unwrap(), RefreshDecision::NotReady);
    }
}
