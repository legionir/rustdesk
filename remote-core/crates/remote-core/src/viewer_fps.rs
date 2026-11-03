//! Bounded, caller-driven extraction of `Remote::fps_control` from the pinned
//! RustDesk client (`src/client/io_loop.rs`). This is not a decoder, queue,
//! renderer, timer or automatic network sender. Samples and topology are owned
//! by the application; their validity and authorization are not established.
//!
//! A decision advances local state when returned, just as the source records
//! its attempted FPS and refreshes. It does not prove the peer received or
//! applied anything. Do not retry an uncertain send on the same connection;
//! close/recreate this controller on a failed/cancelled send or reconnect.
use std::{collections::{BTreeMap, BTreeSet}, error::Error, fmt, time::{Duration, Instant}};

const MAX_DISPLAYS: usize = 8;
const MAX_FPS_SAMPLE: u32 = 1000;
const MAX_QUEUE_CAPACITY: u32 = 4096;
const INACTIVE_THRESHOLD: u32 = 15;
const MAX_REFRESHES: u32 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind { InvalidDisplays, InvalidSample, TopologyMismatch, ClockWentBackwards }
impl fmt::Display for ErrorKind { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "viewer fps: {self:?}") } }
impl Error for ErrorKind {}

/// Caller-provided observations for one locally registered display. None of
/// these values are authenticated peer facts or validated decoder performance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplaySample {
    pub display: u32,
    /// Historical name: source counts decoded frames delivered to its UI
    /// callback, not network-received packets or confirmed on-screen renders.
    /// Caller measures/counts and normalizes them over the actual interval.
    pub received_fps: u32,
    pub decode_fps: Option<u32>,
    pub queue_len: u32,
    pub queue_capacity: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Source `OptionMessage.custom_fps` to consider sending, if changed.
    pub custom_fps: Option<u32>,
    /// Displays for which source would request a refresh on this tick.
    pub refresh: Vec<u32>,
    /// The minimum active decode sample; None means no decision is possible.
    pub min_decode_fps: Option<u32>,
}
#[derive(Default)]
struct DisplayState { inactive: u32, idle: u32, refreshes: u32, last_refresh: Option<Instant> }
/// Exactly one locally owned viewer session. Samples must cover all currently
/// registered displays once per tick; no background loop or measurements exist.
pub struct ViewerFps { displays: BTreeMap<u32, DisplayState>, last_auto_fps: Option<u32>, last_tick: Option<Instant> }
impl ViewerFps {
    pub fn new() -> Self { Self { displays: BTreeMap::new(), last_auto_fps: None, last_tick: None } }
    /// Replace volatile display membership; retain counters for unchanged IDs.
    /// Caller must clear/recreate the tracker on identity reuse, topology or
    /// session change. Empty membership is permitted. No remote request occurs.
    pub fn set_displays(&mut self, displays: &[u32]) -> Result<(), ErrorKind> {
        if displays.len() > MAX_DISPLAYS || displays.iter().any(|id| *id > i32::MAX as u32) { return Err(ErrorKind::InvalidDisplays); }
        let ids: BTreeSet<_> = displays.iter().copied().collect();
        if ids.len() != displays.len() { return Err(ErrorKind::InvalidDisplays); }
        self.displays.retain(|id, _| ids.contains(id));
        for id in ids { self.displays.entry(id).or_default(); }
        Ok(())
    }
    /// Forget all local decisions and counters on reconnect or policy reset.
    pub fn reset(&mut self) { *self = Self::new(); }
    /// Mirror the source outbound `Option.custom_fps > 0` and peer-info reset
    /// of `last_auto_fps`, preserving per-display inactivity/refresh history.
    /// The caller must serialize this with manual sends and the next tick. It
    /// does not send anything; failed/uncertain sends require a full reset and
    /// connection recovery instead of treating this as an acknowledgement.
    pub fn note_manual_fps_update(&mut self) { self.last_auto_fps = None; }
    /// Evaluate a single source-style tick. `direct` and `custom_fps` are local
    /// caller inputs, not negotiated facts; invalid custom values follow source
    /// fallback to 30. Limits, saturating counters, exact membership and clock
    /// regression rejection are deliberate safety differences from the source.
    pub fn tick(&mut self, now: Instant, direct: bool, custom_fps: Option<u32>, samples: &[DisplaySample]) -> Result<Decision, ErrorKind> {
        if self.last_tick.map_or(false, |last| now < last) { return Err(ErrorKind::ClockWentBackwards); }
        if samples.len() != self.displays.len() { return Err(ErrorKind::TopologyMismatch); }
        let mut ids = BTreeSet::new();
        for sample in samples {
            if !ids.insert(sample.display) || !self.displays.contains_key(&sample.display) { return Err(ErrorKind::TopologyMismatch); }
            if sample.received_fps > MAX_FPS_SAMPLE || sample.decode_fps.map_or(false, |fps| fps > MAX_FPS_SAMPLE)
                || sample.queue_capacity == 0 || sample.queue_capacity > MAX_QUEUE_CAPACITY || sample.queue_len > sample.queue_capacity {
                return Err(ErrorKind::InvalidSample);
            }
        }
        self.last_tick = Some(now);
        for sample in samples {
            if let Some(state) = self.displays.get_mut(&sample.display) {
                state.inactive = if sample.received_fps == 0 { state.inactive.saturating_add(1) } else { 0 };
            }
        }
        // Source's min over Option values returns None if any active display
        // has no sample, even if another active display has measured FPS.
        let mut min_decode: Option<u32> = None;
        let mut active = false;
        for sample in samples {
            if self.displays.get(&sample.display).map_or(false, |state| state.inactive < INACTIVE_THRESHOLD) {
                active = true;
                let Some(fps) = sample.decode_fps else { return Ok(Decision { custom_fps: None, refresh: vec![], min_decode_fps: None }); };
                min_decode = Some(min_decode.map_or(fps, |old| old.min(fps)));
            }
        }
        let Some(min_decode) = min_decode.filter(|_| active) else { return Ok(Decision { custom_fps: None, refresh: vec![], min_decode_fps: None }); };
        let custom = custom_fps.filter(|fps| (5..=120).contains(fps)).unwrap_or(30);
        let limited = (if direct { min_decode * 9 / 10 } else { min_decode * 4 / 5 }).min(custom);
        let previous = self.last_auto_fps.unwrap_or(custom);
        let mut decrease = false; let mut increase = false;
        let mut max_queue = 0;
        for sample in samples {
            max_queue = max_queue.max(sample.queue_len);
            let Some(state) = self.displays.get_mut(&sample.display) else { continue; };
            let Some(decode) = sample.decode_fps else { continue; };
            if state.inactive > INACTIVE_THRESHOLD { continue; }
            if (sample.queue_len > 1 && previous > limited) || sample.queue_len > (decode / 2).max(1) {
                state.idle = 0; decrease = true;
            } else if sample.queue_len <= 1 {
                state.idle = state.idle.saturating_add(1);
                if state.idle > 3 && previous + 3 <= limited { increase = true; }
            } else { state.idle = 0; }
        }
        let mut fps_decision = None;
        if self.last_auto_fps.is_none() || decrease || increase {
            let candidate = (if decrease && limited < max_queue { limited / 2 } else { limited }).max(1);
            if self.last_auto_fps != Some(candidate) { self.last_auto_fps = Some(candidate); fps_decision = Some(candidate); }
        }
        let mut refresh = Vec::new();
        for sample in samples {
            let Some(state) = self.displays.get_mut(&sample.display) else { continue; };
            let tolerable = min_decode.min(sample.queue_capacity / 2);
            let due = state.refreshes == 0 || state.last_refresh.and_then(|last| now.checked_duration_since(last)).map_or(false, |elapsed| elapsed.as_secs() > 10);
            if state.refreshes < MAX_REFRESHES && sample.queue_len > tolerable && due {
                state.refreshes += 1; state.last_refresh = Some(now); refresh.push(sample.display);
            }
        }
        // Source HashMap iteration order is unspecified. Stable IDs only make
        // our caller's decision deterministic, not network delivery ordering.
        refresh.sort_unstable();
        Ok(Decision { custom_fps: fps_decision, refresh, min_decode_fps: Some(min_decode) })
    }
}
impl Default for ViewerFps { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(display: u32, received_fps: u32, decode_fps: Option<u32>, queue_len: u32, queue_capacity: u32) -> DisplaySample {
        DisplaySample { display, received_fps, decode_fps, queue_len, queue_capacity }
    }
    #[test]
    fn manual_update_resets_auto_fps_but_preserves_refresh_history() {
        let t = Instant::now();
        let s = sample(0, 30, Some(30), 8, 10);
        let mut fps = ViewerFps::new(); fps.set_displays(&[0]).unwrap();
        let first = fps.tick(t, true, Some(30), &[s]).unwrap();
        assert_eq!(first.custom_fps, Some(27)); assert_eq!(first.refresh, vec![0]);
        fps.note_manual_fps_update();
        let second = fps.tick(t + Duration::from_secs(1), true, Some(20), &[s]).unwrap();
        assert_eq!(second.custom_fps, Some(20));
        assert!(second.refresh.is_empty()); // retained 10-second cooldown
    }
    #[test]
    fn direct_and_relay_use_source_ratios_and_custom_fallback() {
        let t = Instant::now(); let s = sample(0, 30, Some(30), 0, 10);
        let mut direct = ViewerFps::new(); direct.set_displays(&[0]).unwrap();
        assert_eq!(direct.tick(t, true, Some(2), &[s]).unwrap().custom_fps, Some(27));
        assert_eq!(direct.tick(t, true, Some(2), &[s]).unwrap().custom_fps, None);
        let mut relay = ViewerFps::new(); relay.set_displays(&[0]).unwrap();
        assert_eq!(relay.tick(t, false, Some(40), &[s]).unwrap().custom_fps, Some(24));
        relay.reset(); relay.set_displays(&[0]).unwrap();
        assert_eq!(relay.tick(t, true, Some(10), &[s]).unwrap().custom_fps, Some(10));
    }
    #[test]
    fn unknown_active_decode_sample_stalls_source_decision() {
        let t = Instant::now(); let mut fps = ViewerFps::new(); fps.set_displays(&[0, 1]).unwrap();
        let known = sample(0, 10, Some(20), 0, 10);
        let unknown = sample(1, 10, None, 0, 10);
        assert_eq!(fps.tick(t, true, None, &[known, unknown]).unwrap(), Decision { custom_fps: None, refresh: vec![], min_decode_fps: None });
        let inactive_unknown = sample(1, 0, None, 0, 10);
        for n in 1..15 { assert!(fps.tick(t + Duration::from_secs(n), true, None, &[known, inactive_unknown]).unwrap().custom_fps.is_none()); }
        assert_eq!(fps.tick(t + Duration::from_secs(15), true, None, &[known, inactive_unknown]).unwrap().custom_fps, Some(18));
    }
    #[test]
    fn refresh_uses_strict_whole_second_delay_and_maximum() {
        let t = Instant::now(); let mut fps = ViewerFps::new(); fps.set_displays(&[2]).unwrap();
        let s = sample(2, 10, Some(10), 6, 10);
        let first = fps.tick(t, true, None, &[s]).unwrap();
        assert_eq!(first.custom_fps, Some(9)); assert_eq!(first.refresh, vec![2]);
        assert!(fps.tick(t + Duration::from_millis(10_999), true, None, &[s]).unwrap().refresh.is_empty());
        assert_eq!(fps.tick(t + Duration::from_secs(11), true, None, &[s]).unwrap().refresh, vec![2]);
        for n in 2..20 { assert_eq!(fps.tick(t + Duration::from_secs(n * 11), true, None, &[s]).unwrap().refresh, vec![2]); }
        assert!(fps.tick(t + Duration::from_secs(20 * 11), true, None, &[s]).unwrap().refresh.is_empty());
    }
    #[test]
    fn idle_increase_and_congested_decrease_follow_source() {
        let t = Instant::now(); let mut fps = ViewerFps::new(); fps.set_displays(&[0]).unwrap();
        let slow = sample(0, 10, Some(10), 0, 100);
        assert_eq!(fps.tick(t, true, Some(30), &[slow]).unwrap().custom_fps, Some(9));
        let fast = sample(0, 30, Some(30), 0, 100);
        // The first tick also increments the idle counter.
        assert_eq!(fps.tick(t + Duration::from_secs(1), true, Some(30), &[fast]).unwrap().custom_fps, None);
        assert_eq!(fps.tick(t + Duration::from_secs(2), true, Some(30), &[fast]).unwrap().custom_fps, None);
        assert_eq!(fps.tick(t + Duration::from_secs(3), true, Some(30), &[fast]).unwrap().custom_fps, Some(27));
        let congested = sample(0, 30, Some(30), 40, 100);
        assert_eq!(fps.tick(t + Duration::from_secs(4), true, Some(30), &[congested]).unwrap().custom_fps, Some(13));
    }
    #[test]
    fn source_inactivity_fifteen_is_excluded_from_minimum_but_still_trends() {
        let t = Instant::now(); let mut fps = ViewerFps::new(); fps.set_displays(&[0, 1]).unwrap();
        let active = sample(0, 30, Some(30), 0, 100);
        let inactive = sample(1, 0, Some(2), 50, 100);
        for n in 0..14 { fps.tick(t + Duration::from_secs(n), true, None, &[active, inactive]).unwrap(); }
        let fifteenth = fps.tick(t + Duration::from_secs(14), true, None, &[active, inactive]).unwrap();
        assert_eq!(fifteenth.min_decode_fps, Some(30));
        assert_eq!(fifteenth.custom_fps, Some(13));
        let sixteenth = fps.tick(t + Duration::from_secs(15), true, None, &[active, inactive]).unwrap();
        assert_eq!(sixteenth.custom_fps, Some(27));
    }
    #[test]
    fn malformed_samples_do_not_advance_the_state_or_clock() {
        let t = Instant::now(); let mut fps = ViewerFps::new(); fps.set_displays(&[0]).unwrap();
        assert_eq!(fps.tick(t + Duration::from_secs(2), true, None, &[sample(0, 1, Some(10), 2, 1)]), Err(ErrorKind::InvalidSample));
        assert_eq!(fps.tick(t, true, None, &[sample(0, 1, Some(10), 0, 1)]).unwrap().custom_fps, Some(9));
        assert_eq!(fps.tick(t, true, None, &[]), Err(ErrorKind::TopologyMismatch));
        assert_eq!(fps.tick(t.checked_sub(Duration::from_millis(1)).unwrap(), true, None, &[sample(0, 1, Some(10), 0, 1)]), Err(ErrorKind::ClockWentBackwards));
        assert_eq!(fps.set_displays(&[0, 0]), Err(ErrorKind::InvalidDisplays));
        assert_eq!(fps.tick(t, true, None, &[sample(0, 1, Some(10), 0, 1)]).unwrap().custom_fps, None);
    }
}

/// Explicit caller policy for the source's refresh compatibility branch.
/// The application must establish peer compatibility; a claimed version alone
/// is not proof. This is separate from local authorization and rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshMode { PerDisplay, All }
#[derive(Debug)]
pub enum DispatchError {
    InvalidDecision,
    Deadline { sent: usize },
    Viewer { sent: usize, error: crate::viewer_connection::ViewerError },
}
impl fmt::Display for DispatchError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "viewer fps dispatch: {self:?}") } }
impl Error for DispatchError {}
/// Explicitly send a previously produced decision. FPS is sent first, followed
/// by one refresh per selected display; `All` sends source refresh-all for each
/// selected display, as the source's old-peer path does. There is no automatic
/// peer compatibility detection or authorization. The peer may ignore requests.
///
/// `sent` counts successful local sends only, never remote receipt or rendering.
/// Failure/cancellation may have uncertain delivery: close the viewer and reset
/// the associated `ViewerFps`; do not retry a partially sent decision. Native
/// work, runtime scheduling and peer behavior are not bounded by this deadline.
pub async fn dispatch<T: remote_transport::NetworkTransport>(
    viewer: &mut crate::viewer_connection::ViewerConnection<T>, decision: &Decision,
    mode: RefreshMode, deadline: Duration,
) -> Result<usize, DispatchError> {
    if deadline.is_zero() || deadline > Duration::from_secs(180)
        || decision.custom_fps.map_or(false, |fps| !(1..=120).contains(&fps))
        || decision.refresh.len() > MAX_DISPLAYS
        || decision.refresh.iter().any(|id| *id > i32::MAX as u32)
        || decision.refresh.iter().copied().collect::<BTreeSet<_>>().len() != decision.refresh.len() {
        return Err(DispatchError::InvalidDecision);
    }
    let end = Instant::now().checked_add(deadline).ok_or(DispatchError::InvalidDecision)?;
    let mut sent = 0;
    if let Some(fps) = decision.custom_fps {
        let remaining = end.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Err(DispatchError::Deadline { sent }); }
        let preferences = remote_protocol::video_preferences::VideoPreferences { quality: None, fps: Some(fps) };
        viewer.send_video_preferences(preferences, remaining).await.map_err(|error| DispatchError::Viewer { sent, error })?;
        sent += 1;
    }
    for display in &decision.refresh {
        let remaining = end.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Err(DispatchError::Deadline { sent }); }
        let control = match mode {
            RefreshMode::PerDisplay => remote_protocol::video_control::VideoControl::RefreshDisplay(*display),
            RefreshMode::All => remote_protocol::video_control::VideoControl::RefreshAll,
        };
        viewer.send_video_control(control, remaining).await.map_err(|error| DispatchError::Viewer { sent, error })?;
        sent += 1;
    }
    Ok(sent)
}
