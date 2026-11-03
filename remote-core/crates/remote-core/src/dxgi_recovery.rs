//! Caller-driven bookkeeping extracted from the Windows video service's DXGI
//! ACCESS_LOST recovery policy. This module does not recreate capturers, switch
//! to GDI, detect errors or authorize capture; it is available on all targets
//! only to allow deterministic policy tests. Keep one state per display service,
//! discard it on identity/topology changes, and serialize access externally.
//!
//! Source: `src/server/video_service.rs` `DxgiRecoveryState` and the
//! `ConnectionReset`/`WouldBlock` branches. The caller's clock is explicit;
//! unlike source `Instant::elapsed`, a backwards timestamp is rejected.
use std::{error::Error, fmt, time::{Duration, Instant}};

pub const RECOVERY_LIMIT: usize = 3;
pub const RECOVERY_WINDOW: Duration = Duration::from_secs(10);
pub const FRAME_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDecision { Restart { attempt: usize }, FallbackToGdi }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockWentBackwards;
impl fmt::Display for ClockWentBackwards {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("DXGI recovery clock went backwards") }
}
impl Error for ClockWentBackwards {}

/// State for source-style restart budgeting, not a capturer or a timer.
#[derive(Default)]
pub struct DxgiRecovery {
    attempts: usize,
    window_started: Option<Instant>,
    last_attempt_time: Option<Instant>,
    restart_pending: bool,
    fallback_pending: bool,
}
impl DxgiRecovery {
    pub fn new() -> Self { Self::default() }
    /// Call only for a non-GDI `ConnectionReset` classified as access lost.
    /// Source starts a fresh window strictly *after* ten seconds, not at the
    /// boundary. Three restarts are proposed; the fourth requests GDI. A
    /// successful frame does not reset the source attempt window. A decision
    /// is advisory: revalidate local consent, current topology, capture budget
    /// and encoder/receiver state before any OS action.
    pub fn access_lost(&mut self, now: Instant) -> Result<RecoveryDecision, ClockWentBackwards> {
        if self.last_attempt_time.map_or(false, |last| now < last) { return Err(ClockWentBackwards); }
        let reset = match self.window_started {
            None => true,
            Some(start) => now.checked_duration_since(start).ok_or(ClockWentBackwards)? > RECOVERY_WINDOW,
        };
        if reset { self.window_started = Some(now); self.attempts = 0; }
        self.last_attempt_time = Some(now);
        if self.attempts >= RECOVERY_LIMIT {
            self.fallback_pending = true;
            Ok(RecoveryDecision::FallbackToGdi)
        } else {
            self.attempts += 1;
            self.restart_pending = true;
            Ok(RecoveryDecision::Restart { attempt: self.attempts })
        }
    }
    /// Consume once after a replacement capturer is successfully created. If
    /// true, the owner may start a two-second grace at creation time; it does
    /// not imply a frame was captured or that GDI is safe on the current desk.
    pub fn take_restart_pending(&mut self) -> bool { std::mem::take(&mut self.restart_pending) }
    /// Consume once when handling a pending fallback, e.g. after a service
    /// restart or when applying GDI immediately. This does not call `set_gdi`.
    pub fn take_fallback_pending(&mut self) -> bool { std::mem::take(&mut self.fallback_pending) }
}

/// In the source, a successfully recreated DXGI capturer is allowed two
/// seconds before ordinary WouldBlock-to-GDI logic resumes. `None` means normal
/// startup and therefore no recovery grace. This does not count WouldBlock
/// errors or promise that fallback will occur at the end of the interval.
pub fn in_frame_grace(restarted_at: Option<Instant>, now: Instant) -> Result<bool, ClockWentBackwards> {
    let Some(started) = restarted_at else { return Ok(false); };
    Ok(now.checked_duration_since(started).ok_or(ClockWentBackwards)? < FRAME_GRACE)
}

/// Per-capturer source `try_gdi` counter. It starts at one, is disabled by a
/// successful frame, and is suppressed while a recovery grace is active. The
/// fallback decision is advisory and does not change the native capture mode.
#[derive(Debug)]
pub struct StartupFallback { counter: u8 }
impl StartupFallback {
    pub fn new() -> Self { Self { counter: 1 } }
    /// Called after a successful capture. `true` corresponds to the source's
    /// optional VRAM `set_fallback_gdi(false)` branch; no VRAM state is changed.
    pub fn frame_captured(&mut self, is_gdi: bool) -> bool {
        let clear_vram_fallback = self.counter == 1 && !is_gdi;
        self.counter = 0;
        clear_vram_fallback
    }
    /// Caller supplies current native mode and the result of `in_frame_grace`.
    /// Returns true on the fourth eligible initial WouldBlock, matching source.
    /// After recommending fallback the counter returns to one, as in the
    /// source; check the actual mode on the next call because a GDI switch may
    /// fail. Never silently retry a failed capture or treat this as consent.
    pub fn would_block(&mut self, is_gdi: bool, in_grace: bool) -> bool {
        if in_grace || is_gdi || self.counter == 0 { return false; }
        let fallback = self.counter > 3;
        if fallback { self.counter = 0; }
        self.counter += 1;
        fallback
    }
}
impl Default for StartupFallback { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_restarts_and_strict_window_boundary() {
        let t = Instant::now(); let mut recovery = DxgiRecovery::new();
        for attempt in 1..=RECOVERY_LIMIT {
            assert_eq!(recovery.access_lost(t).unwrap(), RecoveryDecision::Restart { attempt });
            assert!(recovery.take_restart_pending()); assert!(!recovery.take_restart_pending());
        }
        assert_eq!(recovery.access_lost(t + RECOVERY_WINDOW).unwrap(), RecoveryDecision::FallbackToGdi);
        assert!(recovery.take_fallback_pending()); assert!(!recovery.take_fallback_pending());
        assert_eq!(recovery.access_lost(t + RECOVERY_WINDOW + Duration::from_nanos(1)).unwrap(), RecoveryDecision::Restart { attempt: 1 });
        assert_eq!(recovery.access_lost(t), Err(ClockWentBackwards));
        assert!(recovery.take_restart_pending());
    }
    #[test]
    fn recovery_grace_only_after_restart_creation() {
        let t = Instant::now();
        assert!(!in_frame_grace(None, t).unwrap());
        assert!(in_frame_grace(Some(t), t).unwrap());
        assert!(in_frame_grace(Some(t), t + FRAME_GRACE - Duration::from_nanos(1)).unwrap());
        assert!(!in_frame_grace(Some(t), t + FRAME_GRACE).unwrap());
        assert_eq!(in_frame_grace(Some(t), t - Duration::from_nanos(1)), Err(ClockWentBackwards));
    }
    #[test]
    fn would_block_fallback_is_startup_only_and_grace_is_non_counting() {
        let mut state = StartupFallback::new();
        for _ in 0..100 { assert!(!state.would_block(false, true)); }
        for _ in 0..3 { assert!(!state.would_block(false, false)); }
        assert!(state.would_block(false, false));
        // If the requested mode switch failed, the source restarts its count.
        for _ in 0..3 { assert!(!state.would_block(false, false)); }
        assert!(state.would_block(false, false));
        assert!(!state.would_block(true, false));
        assert!(state.frame_captured(false));
        for _ in 0..10 { assert!(!state.would_block(false, false)); }
    }
    #[test]
    fn first_frame_clears_optional_vram_fallback_only_in_source_branch() {
        let mut initial = StartupFallback::new();
        assert!(initial.frame_captured(false));
        assert!(!initial.frame_captured(false));
        let mut gdi = StartupFallback::new(); assert!(!gdi.frame_captured(true));
        let mut delayed = StartupFallback::new();
        assert!(!delayed.would_block(false, false));
        assert!(!delayed.frame_captured(false));
    }
    #[test]
    fn pending_flags_are_independent_and_do_not_apply_actions() {
        let t = Instant::now(); let mut recovery = DxgiRecovery::new();
        for _ in 0..RECOVERY_LIMIT + 1 { recovery.access_lost(t).unwrap(); }
        assert!(recovery.take_restart_pending());
        assert!(recovery.take_fallback_pending());
        assert!(!recovery.take_restart_pending()); assert!(!recovery.take_fallback_pending());
    }
}
