//! Experimental bounded single-session service loop over an already approved
//! [`ScheduledSession`]. It is not a standalone server, source video service,
//! trusted consent UI, renderer, multi-peer scheduler or security boundary.
//!
//! Input dispatch and heartbeat replies may already have occurred inside the
//! driver before the owner observes an event. The owner must explicitly handle
//! every remaining event, topology and decoder reset, coordinate local permissions
//! and input ownership, and stop the loop
//! immediately when consent changes. Native capture may block past deadlines;
//! cancellation cannot interrupt native calls and cleanup is only best effort.
//! This loop owns and closes the driver rather than reusing it after uncertain
//! I/O. No code in this module creates a runtime or spawns a background task.
use crate::{capture_pump::CapturePumpError, host_connection::{ConnectionError, HostEvent}, scheduled_capture::{OutcomeStep, ScheduledCaptureError}, scheduled_session::{DriveOutcomeStep, DriverError, ScheduledSession}};
use remote_input::InputBackend;
use remote_transport::{close_signal::CloseSignal, UpgradeableDuplexTransport};
use std::{error::Error, fmt, sync::Arc, time::{Duration, Instant}};

const MAX_DURATION: Duration = Duration::from_secs(60);
const MAX_STEPS: u32 = 100_000;
const MAX_CAPTURE_WAIT: Duration = Duration::from_millis(250);
const MAX_SEND_WAIT: Duration = Duration::from_secs(5);
const MAX_POLL_PAUSE: Duration = Duration::from_millis(20);
const MIN_PAUSE: Duration = Duration::from_millis(1);

/// Locally selected limits, not source protocol limits. Capture and send use
/// separate per-operation budgets selected before the step; their combined time
/// can exceed the loop duration even if both obey their budgets. Native calls
/// and owner callbacks can also exceed wall time; `max_steps` bounds attempts.
#[derive(Debug, Clone, Copy)]
pub struct Limits { pub duration: Duration, pub max_steps: u32, pub capture_wait: Duration, pub send_wait: Duration }
impl Limits {
    fn valid(self) -> bool {
        !self.duration.is_zero() && self.duration <= MAX_DURATION && (1..=MAX_STEPS).contains(&self.max_steps)
            && !self.capture_wait.is_zero() && self.capture_wait <= MAX_CAPTURE_WAIT
            && !self.send_wait.is_zero() && self.send_wait <= MAX_SEND_WAIT
    }
}
/// Sticky cooperative stop signal. It wakes cancellable asynchronous I/O and
/// pauses, but cannot interrupt a synchronous native capture or callback. A
/// cancelled send may already be delivered; the driver is always closed and
/// must not be reused. This is not a trusted consent channel.
#[derive(Clone, Default)]
pub struct Stop(Arc<CloseSignal>);
impl Stop {
    pub fn request(&self) { self.0.request(); }
    pub fn requested(&self) -> bool { self.0.is_requested() }
}
/// The owner must explicitly handle every event; continuing is not permission
/// to apply a peer's request. The handler may restrict permissions or stop, but
/// must not close the host, swap the capture group or start overlapping I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventDecision { Continue, Stop }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason { Requested, Owner, Deadline, StepLimit }
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts { pub events: u32, pub sent: u32, pub no_output: u32, pub would_block: u32, pub waits: u32 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report { pub reason: StopReason, pub counts: Counts }
#[derive(Debug)]
pub enum Cause { InvalidLimits, Driver(DriverError), Handler(Box<dyn Error + Send + Sync>) }
/// Error retains the closed/failed driver so a caller can retry detectable
/// connection/input cleanup. `ScheduledSession::close` has already dropped
/// the capture group, so a failed capture-stop transition is not retryable.
/// Never resume streaming or reuse it after an error. Dropping this value
/// performs the driver's best-effort Drop cleanup, which cannot report.
pub struct LoopError<T: UpgradeableDuplexTransport, B: InputBackend> {
    pub cause: Option<Cause>, pub cleanup: Option<DriverError>, driver: ScheduledSession<T, B>,
}
impl<T: UpgradeableDuplexTransport, B: InputBackend> LoopError<T, B> {
    pub fn retry_cleanup(&mut self) -> Result<(), DriverError> { self.driver.close() }
}
impl<T: UpgradeableDuplexTransport, B: InputBackend> fmt::Debug for LoopError<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoopError").field("has_cause", &self.cause.is_some())
            .field("cleanup_failed", &self.cleanup.is_some()).finish_non_exhaustive()
    }
}
impl<T: UpgradeableDuplexTransport, B: InputBackend> fmt::Display for LoopError<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("bounded host loop or cleanup failed") }
}
impl<T: UpgradeableDuplexTransport, B: InputBackend> Error for LoopError<T, B> {}

fn capture_would_block(error: &DriverError) -> bool {
    matches!(error, DriverError::Capture(ScheduledCaptureError::Connection(ConnectionError::Capture(
        CapturePumpError::Capture(error)))) if error.kind() == std::io::ErrorKind::WouldBlock)
}
fn pause(hint: Duration, remaining: Duration) -> Duration {
    hint.max(MIN_PAUSE).min(MAX_POLL_PAUSE).min(remaining)
}

/// Drive one authorized session for a bounded interval. This consumes the
/// driver, closes it on every normal/error return, and drops it on cancellation
/// or panic. An error retains the driver solely for cleanup retry; Drop cannot
/// report failure. No retries occur after an uncertain network/codec error.
/// Capture-side `WouldBlock` alone is treated as known unsent. The handler runs
/// synchronously on the caller's task and must be short and nonblocking.
/// Input and heartbeat events may already have been dispatched by the driver
/// before the callback; the callback cannot approve them retroactively. The
/// existing local permissions and input ownership must be set first.
/// A stop racing a completed step may discard its event or sent count; these
/// counters are local observations and do not prove peer delivery or absence.
/// PTS starts at zero for this loop; caller must coordinate decoder resets and
/// must not assume global monotonicity across loops or streams. Display IDs,
/// frame ACKs and peer events are untrusted/volatile. This is unbuilt/untested.
pub async fn run<T, B, F>(mut driver: ScheduledSession<T, B>, stop: Stop, limits: Limits, mut handle: F) -> Result<Report, LoopError<T, B>>
where T: UpgradeableDuplexTransport, B: InputBackend,
    F: FnMut(HostEvent, &mut ScheduledSession<T, B>) -> Result<EventDecision, Box<dyn Error + Send + Sync>>,
{
    let mut counts = Counts::default();
    let result = async {
        if !limits.valid() { return Err(Cause::InvalidLimits); }
        let start = Instant::now();
        let end = start.checked_add(limits.duration).ok_or(Cause::InvalidLimits)?;
        for _ in 0..limits.max_steps {
            if stop.requested() { return Ok(StopReason::Requested); }
            let now = Instant::now();
            if now >= end { return Ok(StopReason::Deadline); }
            let remaining = end.saturating_duration_since(now);
            let pts = i64::try_from(now.duration_since(start).as_millis()).map_err(|_| Cause::InvalidLimits)?;
            let step = stop.0.race(driver.drive_once_outcome(limits.capture_wait.min(remaining), limits.send_wait.min(remaining), pts)).await;
            let step = match step {
                Some(result) if !stop.requested() => result,
                // An event/input/send may have occurred before this observation;
                // do not resume or retry the driver. `close` runs below.
                _ => return Ok(StopReason::Requested),
            };
            let delay = match step {
                Ok(DriveOutcomeStep::Event(event)) => {
                    counts.events += 1;
                    if handle(event, &mut driver).map_err(Cause::Handler)? == EventDecision::Stop { return Ok(StopReason::Owner); }
                    MIN_PAUSE
                },
                Ok(DriveOutcomeStep::Capture(OutcomeStep::Sent(_))) => { counts.sent += 1; MIN_PAUSE },
                Ok(DriveOutcomeStep::Capture(OutcomeStep::VpxNoOutput(_))) => { counts.no_output += 1; MIN_PAUSE },
                Ok(DriveOutcomeStep::Capture(OutcomeStep::Wait(delay))) => { counts.waits += 1; delay },
                Err(error) if capture_would_block(&error) => { counts.would_block += 1; MIN_PAUSE },
                Err(error) => return Err(Cause::Driver(error)),
            };
            let remaining = end.saturating_duration_since(Instant::now());
            if remaining.is_zero() { return Ok(StopReason::Deadline); }
            if stop.0.race(tokio::time::sleep(pause(delay, remaining))).await.is_none() || stop.requested() {
                return Ok(StopReason::Requested);
            }
        }
        Ok(StopReason::StepLimit)
    }.await;
    let cleanup = driver.close().err();
    match (result, cleanup) {
        (Ok(reason), None) => Ok(Report { reason, counts }),
        (Ok(_), Some(cleanup)) => Err(LoopError { cause: None, cleanup: Some(cleanup), driver }),
        (Err(cause), cleanup) => Err(LoopError { cause: Some(cause), cleanup, driver }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> Limits { Limits { duration: Duration::from_secs(1), max_steps: 3, capture_wait: Duration::from_millis(20), send_wait: Duration::from_secs(1) } }
    #[test]
    fn bounds_and_poll_pause_are_finite() {
        assert!(valid().valid());
        assert!(!Limits { duration: Duration::ZERO, ..valid() }.valid());
        assert!(!Limits { max_steps: MAX_STEPS + 1, ..valid() }.valid());
        assert!(!Limits { capture_wait: MAX_CAPTURE_WAIT + MIN_PAUSE, ..valid() }.valid());
        assert!(!Limits { send_wait: MAX_SEND_WAIT + MIN_PAUSE, ..valid() }.valid());
        assert_eq!(pause(Duration::from_secs(1), Duration::from_secs(1)), MAX_POLL_PAUSE);
        assert_eq!(pause(Duration::ZERO, Duration::from_secs(1)), MIN_PAUSE);
        assert_eq!(pause(Duration::from_secs(1), Duration::from_micros(5)), Duration::from_micros(5));
    }
    #[test]
    fn stop_wakes_pending_cooperative_work_and_drops_it() {
        use std::{future::Future, sync::{atomic::{AtomicBool, Ordering}, Arc}, task::{Context, Poll, Wake, Waker}};
        struct Noop;
        impl Wake for Noop { fn wake(self: Arc<Self>) {} }
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag { fn drop(&mut self) { self.0.store(true, Ordering::Release); } }
        let stop = Stop::default(); let requester = stop.clone();
        let flag = Arc::new(AtomicBool::new(false)); let guard = DropFlag(flag.clone());
        let mut work = Box::pin(stop.0.race(async move { let _guard = guard; std::future::pending::<()>().await }));
        let waker = Waker::from(Arc::new(Noop)); let mut cx = Context::from_waker(&waker);
        assert!(matches!(work.as_mut().poll(&mut cx), Poll::Pending));
        requester.request();
        assert!(matches!(work.as_mut().poll(&mut cx), Poll::Ready(None)));
        assert!(flag.load(Ordering::Acquire));
        assert!(stop.requested());
    }
    #[test]
    fn stop_is_shared_and_would_block_must_be_capture_side() {
        let stop = Stop::default(); let other = stop.clone();
        assert!(!stop.requested()); other.request(); assert!(stop.requested());
        let wrap = |kind| DriverError::Capture(ScheduledCaptureError::Connection(ConnectionError::Capture(CapturePumpError::Capture(std::io::Error::from(kind)))));
        assert!(capture_would_block(&wrap(std::io::ErrorKind::WouldBlock)));
        assert!(!capture_would_block(&wrap(std::io::ErrorKind::TimedOut)));
        assert!(!capture_would_block(&DriverError::InvalidDeadline));
    }
}
