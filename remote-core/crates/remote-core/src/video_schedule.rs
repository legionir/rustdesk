//! Caller-driven source video pacing, frame-ACK and TestDelay bookkeeping.
//!
//! The wire protocol does not carry an ACK frame sequence or display index,
//! and peers can send arbitrary probe/ACK messages. These helpers mirror the
//! source's broad per-display/per-connection handling, not reliable delivery,
//! authentication, fairness, a task scheduler or the complete source QoS loop.
//! Call only from the owner of an authorized session and trusted display map.
//! No timers or OS capture are created here; cancellation and output privacy
//! remain the caller's responsibility. This module has not been tested.

use remote_protocol::TestDelay;
use std::{collections::{HashMap, HashSet}, error::Error, fmt, time::{Duration, Instant}};

const MAX_DISPLAYS: usize = 32;
const MAX_PEERS: usize = 64;
const MAX_PROBE_AGE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleError { InvalidFps, InvalidDisplay, InvalidPeer, TooManyDisplays, TooManyPeers, AlreadyPending, NoPending, InvalidReply, ClockWentBackwards, ProbeExpired }
impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "video scheduling: {self:?}") }
}
impl Error for ScheduleError {}

/// Single-display monotonic pacing. No catch-up burst is generated after a
/// stall; a new attempt is scheduled from the actual previous attempt time.
pub struct FrameCadence { last_attempt: Option<Instant>, interval: Duration }
impl FrameCadence {
    pub fn new(fps: u32) -> Result<Self, ScheduleError> {
        Ok(Self { last_attempt: None, interval: Self::interval(fps)? })
    }
    fn interval(fps: u32) -> Result<Duration, ScheduleError> {
        if !(1..=120).contains(&fps) { return Err(ScheduleError::InvalidFps); }
        Ok(Duration::from_secs_f64(1.0 / fps as f64))
    }
    pub fn set_fps(&mut self, fps: u32) -> Result<(), ScheduleError> { self.interval = Self::interval(fps)?; Ok(()) }
    /// How long until another capture attempt. `None` means immediately due.
    pub fn remaining(&self, now: Instant) -> Result<Option<Duration>, ScheduleError> {
        let Some(last) = self.last_attempt else { return Ok(None); };
        let elapsed = now.checked_duration_since(last).ok_or(ScheduleError::ClockWentBackwards)?;
        let left = self.interval.saturating_sub(elapsed);
        if left.is_zero() { Ok(None) } else { Ok(Some(left)) }
    }
    /// Reserve an attempt only when due. Record even when capture returns
    /// WouldBlock to avoid a tight polling loop; failures do not reset the codec.
    pub fn begin_attempt(&mut self, now: Instant) -> Result<bool, ScheduleError> {
        if self.remaining(now)?.is_some() { return Ok(false); }
        self.last_attempt = Some(now); Ok(true)
    }
}

struct PendingProbe { sent: Instant, expected: TestDelay, last_tick_second: u64 }
/// One source-format host-origin probe in flight. A reply is untrusted and
/// potentially replayed: the source's default time field is zero and carries
/// no nonce. A peer can forge a matching echo. Do not use this for security.
pub struct DelayProbe { pending: Option<PendingProbe>, expired: bool }
impl DelayProbe {
    pub fn new() -> Self { Self { pending: None, expired: false } }
    /// Mark pending immediately before sending. If the send fails or is
    /// cancelled, close the stream; delivery is indeterminate, so never reuse
    /// this tracker on a different connection.
    pub fn begin(&mut self, now: Instant, last_delay: u32, target_bitrate: u32) -> Result<TestDelay, ScheduleError> {
        if self.expired { return Err(ScheduleError::ProbeExpired); }
        if self.pending.is_some() { return Err(ScheduleError::AlreadyPending); }
        let expected = TestDelay { time: 0, from_client: false, last_delay, target_bitrate };
        self.pending = Some(PendingProbe { sent: now, expected, last_tick_second: 0 }); Ok(expected)
    }
    fn age(pending: &PendingProbe, now: Instant) -> Result<Duration, ScheduleError> {
        now.checked_duration_since(pending.sent).ok_or(ScheduleError::ClockWentBackwards)
    }
    /// Return elapsed time at most once per whole second after two seconds,
    /// for `SourceVideoQos::on_probe_elapsed`. More than 60 seconds is a hard
    /// local bound; close the connection rather than starting a new probe.
    pub fn tick(&mut self, now: Instant) -> Result<Option<Duration>, ScheduleError> {
        if self.expired { return Err(ScheduleError::ProbeExpired); }
        let pending = self.pending.as_mut().ok_or(ScheduleError::NoPending)?;
        let elapsed = Self::age(pending, now)?;
        if elapsed > MAX_PROBE_AGE { self.expired = true; self.pending = None; return Err(ScheduleError::ProbeExpired); }
        let sec = elapsed.as_secs();
        if elapsed <= Duration::from_secs(2) || sec == pending.last_tick_second { return Ok(None); }
        pending.last_tick_second = sec; Ok(Some(elapsed))
    }
    /// Consume an exactly echoed source probe and return local elapsed time.
    /// A mismatch is rejected without clearing the outstanding probe.
    pub fn reply(&mut self, now: Instant, reply: TestDelay) -> Result<Duration, ScheduleError> {
        if self.expired { return Err(ScheduleError::ProbeExpired); }
        let pending = self.pending.as_ref().ok_or(ScheduleError::NoPending)?;
        if reply != pending.expected { return Err(ScheduleError::InvalidReply); }
        let elapsed = Self::age(pending, now)?;
        if elapsed > MAX_PROBE_AGE { self.expired = true; self.pending = None; return Err(ScheduleError::ProbeExpired); }
        self.pending = None; Ok(elapsed)
    }
}
impl Default for DelayProbe { fn default() -> Self { Self::new() } }

/// Tracks a single outstanding generation for each display. Source
/// `VideoReceived` is connection-wide, so an ACK clears that connection from
/// every pending display, as `notify_video_frame_fetched_by_conn_id` does.
/// ACKs do not prove a particular generation was rendered, especially if late.
pub struct FrameAcks { pending: HashMap<u32, HashSet<i32>> }
impl FrameAcks {
    pub fn new() -> Self { Self { pending: HashMap::new() } }
    /// Record a frame sent to a bounded set of positive local connection IDs.
    /// An outstanding generation must finish or be explicitly expired first.
    pub fn sent(&mut self, display: u32, peers: &[i32]) -> Result<(), ScheduleError> {
        if peers.len() > MAX_PEERS { return Err(ScheduleError::TooManyPeers); }
        if peers.iter().any(|id| *id <= 0) { return Err(ScheduleError::InvalidPeer); }
        let set: HashSet<_> = peers.iter().copied().collect();
        if set.len() != peers.len() { return Err(ScheduleError::InvalidPeer); }
        if self.pending.contains_key(&display) { return Err(ScheduleError::AlreadyPending); }
        if !set.is_empty() {
            if self.pending.len() >= MAX_DISPLAYS { return Err(ScheduleError::TooManyDisplays); }
            self.pending.insert(display, set);
        }
        Ok(())
    }
    /// Consume a peer's connection-wide ACK. Returns number of displays updated.
    pub fn acknowledge(&mut self, peer: i32) -> Result<usize, ScheduleError> {
        if peer <= 0 { return Err(ScheduleError::InvalidPeer); }
        let mut count = 0;
        self.pending.retain(|_, peers| { if peers.remove(&peer) { count += 1; } !peers.is_empty() });
        Ok(count)
    }
    /// Disconnect has the same removal effect; it is not an ACK.
    pub fn disconnect(&mut self, peer: i32) -> Result<(), ScheduleError> { self.acknowledge(peer).map(|_| ()) }
    /// Return number of viewers still pending on this display.
    pub fn outstanding(&self, display: u32) -> usize { self.pending.get(&display).map_or(0, HashSet::len) }
    /// Drop local waiting state after a caller-controlled timeout or stream reset.
    /// A late ACK can still be mistaken for a later generation.
    pub fn expire(&mut self, display: u32) { self.pending.remove(&display); }
}
impl Default for FrameAcks { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pace_without_catchup_and_reject_clock_reversal() {
        let t = Instant::now(); let mut cadence = FrameCadence::new(10).unwrap();
        assert!(cadence.begin_attempt(t).unwrap());
        assert!(!cadence.begin_attempt(t + Duration::from_millis(50)).unwrap());
        assert!(cadence.begin_attempt(t + Duration::from_secs(10)).unwrap());
        assert!(!cadence.begin_attempt(t + Duration::from_secs(10)).unwrap());
        assert_eq!(cadence.remaining(t), Err(ScheduleError::ClockWentBackwards));
        assert_eq!(cadence.set_fps(0), Err(ScheduleError::InvalidFps));
    }
    #[test]
    fn source_probe_echo_is_locally_timed_and_bounded() {
        let t = Instant::now(); let mut probe = DelayProbe::new();
        let message = probe.begin(t, 4, 500).unwrap();
        assert!(matches!(probe.begin(t, 0, 0), Err(ScheduleError::AlreadyPending)));
        assert_eq!(probe.tick(t + Duration::from_secs(1)).unwrap(), None);
        assert!(probe.tick(t + Duration::from_secs(3)).unwrap().is_some());
        assert_eq!(probe.tick(t + Duration::from_secs(3)).unwrap(), None);
        let mut wrong = message; wrong.target_bitrate += 1;
        assert_eq!(probe.reply(t + Duration::from_secs(4), wrong), Err(ScheduleError::InvalidReply));
        assert_eq!(probe.reply(t + Duration::from_secs(4), message).unwrap(), Duration::from_secs(4));
        probe.begin(t, 0, 0).unwrap();
        assert_eq!(probe.tick(t + Duration::from_secs(61)), Err(ScheduleError::ProbeExpired));
        assert!(matches!(probe.begin(t, 0, 0), Err(ScheduleError::ProbeExpired)));
    }
    #[test]
    fn connection_ack_releases_all_displays() {
        let mut acks = FrameAcks::new();
        acks.sent(0, &[1, 2]).unwrap(); acks.sent(1, &[1]).unwrap();
        assert_eq!(acks.sent(0, &[1]), Err(ScheduleError::AlreadyPending));
        assert_eq!(acks.acknowledge(1).unwrap(), 2);
        assert_eq!(acks.outstanding(0), 1); assert_eq!(acks.outstanding(1), 0);
        acks.disconnect(2).unwrap(); assert_eq!(acks.outstanding(0), 0);
    }
}
