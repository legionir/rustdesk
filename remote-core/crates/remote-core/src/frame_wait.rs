//! Bounded caller-driven RustDesk-style frame wait bookkeeping.
//!
//! Source video_service waits up to 3000 ms per display for connection-wide
//! fetch notifications, while a connection with `video_ack_required=false`
//! notifies on dequeue, and `true` waits for `VideoReceived`. This helper does
//! not observe source queues; caller decides which successfully sent peers
//! require a wire ACK. A wire ACK has neither display nor sequence identity.
//! A late/forged ACK can release a later frame and is not proof of rendering.
//! There are no timers or background tasks; caller must keep servicing input,
//! connection closure, permission revocation and capture errors.
use std::{collections::{HashMap, HashSet}, error::Error, fmt, time::{Duration, Instant}};

const MAX_DISPLAYS: usize = 32;
const MAX_PEERS: usize = 64;
pub const MAX_WAIT: Duration = Duration::from_millis(3000);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitError { InvalidTimeout, InvalidPeer, TooManyPeers, TooManyDisplays, AlreadyPending, ClockWentBackwards }
impl fmt::Display for WaitError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "frame wait: {self:?}") } }
impl Error for WaitError {}
struct Wait { since: Instant, peers: HashSet<i32> }
/// A fresh tracker must be used for each set of live, uniquely assigned local
/// peer IDs. Never reuse pending entries across reconnections or stream resets.
pub struct FrameWait { waits: HashMap<u32, Wait>, timeout: Duration }
impl FrameWait {
    pub fn new(timeout: Duration) -> Result<Self, WaitError> {
        if timeout.is_zero() || timeout > MAX_WAIT { return Err(WaitError::InvalidTimeout); }
        Ok(Self { waits: HashMap::new(), timeout })
    }
    /// Record ACK-requiring viewers only after successful send. A cancelled or
    /// failed send has indeterminate delivery: close the stream and reset the
    /// tracker; do not infer that the peer did or did not receive the frame.
    pub fn sent(&mut self, display: u32, peers: &[i32], now: Instant) -> Result<(), WaitError> {
        if peers.len() > MAX_PEERS { return Err(WaitError::TooManyPeers); }
        if peers.iter().any(|peer| *peer <= 0) { return Err(WaitError::InvalidPeer); }
        let count = peers.len();
        let peers: HashSet<_> = peers.iter().copied().collect();
        if peers.len() != count { return Err(WaitError::InvalidPeer); }
        if self.waits.contains_key(&display) { return Err(WaitError::AlreadyPending); }
        if peers.is_empty() { return Ok(()); }
        if self.waits.len() >= MAX_DISPLAYS { return Err(WaitError::TooManyDisplays); }
        self.waits.insert(display, Wait { since: now, peers }); Ok(())
    }
    /// Source ACK is connection-wide. It can clear multiple display waits.
    pub fn acknowledge(&mut self, peer: i32) -> Result<usize, WaitError> {
        if peer <= 0 { return Err(WaitError::InvalidPeer); }
        let mut released = 0;
        self.waits.retain(|_, wait| { if wait.peers.remove(&peer) { released += 1; } !wait.peers.is_empty() });
        Ok(released)
    }
    /// Remove a departed peer without treating this as rendered delivery.
    pub fn disconnect(&mut self, peer: i32) -> Result<(), WaitError> { self.acknowledge(peer).map(|_| ()) }
    /// Return time until this display is eligible; `None` means no wait or
    /// locally expired. Expiration is applied only by `expire`.
    pub fn remaining(&self, display: u32, now: Instant) -> Result<Option<Duration>, WaitError> {
        let Some(wait) = self.waits.get(&display) else { return Ok(None); };
        let elapsed = now.checked_duration_since(wait.since).ok_or(WaitError::ClockWentBackwards)?;
        let remaining = self.timeout.saturating_sub(elapsed);
        if remaining.is_zero() { Ok(None) } else { Ok(Some(remaining)) }
    }
    /// Explicitly discard one locally expired wait. Late ACK ambiguity remains.
    pub fn expire(&mut self, display: u32, now: Instant) -> Result<bool, WaitError> {
        if !self.waits.contains_key(&display) || self.remaining(display, now)?.is_some() { return Ok(false); }
        self.waits.remove(&display); Ok(true)
    }
    /// Forget one wait on explicit stream removal/reset, not an ACK.
    pub fn clear_display(&mut self, display: u32) { self.waits.remove(&display); }
    pub fn reset(&mut self) { self.waits.clear(); }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_bad_updates_without_mutating_existing_wait() {
        let t = Instant::now(); let mut waits = FrameWait::new(Duration::from_secs(1)).unwrap();
        assert_eq!(waits.sent(0, &[1, 1], t), Err(WaitError::InvalidPeer));
        assert_eq!(waits.sent(0, &[0], t), Err(WaitError::InvalidPeer));
        assert_eq!(waits.sent(0, &[1; 65], t), Err(WaitError::TooManyPeers));
        waits.sent(0, &[1], t).unwrap();
        assert_eq!(waits.sent(0, &[2], t), Err(WaitError::AlreadyPending));
        assert_eq!(waits.remaining(0, t.checked_sub(Duration::from_millis(1)).unwrap()), Err(WaitError::ClockWentBackwards));
        assert_eq!(waits.acknowledge(2), Ok(0));
        assert_eq!(waits.remaining(0, t), Ok(Some(Duration::from_secs(1))));
        assert_eq!(waits.acknowledge(1), Ok(1));
    }
    #[test]
    fn bounds_display_count_and_expired_wait_needs_explicit_removal() {
        let t = Instant::now(); let mut waits = FrameWait::new(Duration::from_millis(100)).unwrap();
        for display in 0..32 { waits.sent(display, &[1], t).unwrap(); }
        assert_eq!(waits.sent(32, &[1], t), Err(WaitError::TooManyDisplays));
        assert_eq!(waits.remaining(0, t + Duration::from_millis(100)), Ok(None));
        assert_eq!(waits.sent(0, &[1], t + Duration::from_millis(100)), Err(WaitError::AlreadyPending));
        assert!(waits.expire(0, t + Duration::from_millis(100)).unwrap());
        waits.sent(0, &[1], t + Duration::from_millis(100)).unwrap();
        waits.reset(); assert_eq!(waits.remaining(0, t), Ok(None));
    }
    #[test]
    fn waits_combine_with_cadence_and_cleanup_on_removal() {
        use crate::video_schedule::DisplayCadences;
        let t = Instant::now(); let mut waits = FrameWait::new(Duration::from_secs(1)).unwrap();
        let mut cadence = DisplayCadences::new(); cadence.add(0, 10).unwrap(); cadence.add(1, 10).unwrap();
        assert_eq!(cadence.next_due(t).unwrap().0, Some(0)); waits.sent(0, &[1], t).unwrap();
        let mut blocked = HashMap::new(); blocked.insert(0, waits.remaining(0, t).unwrap().unwrap());
        assert_eq!(cadence.next_due_blocked(t, &blocked).unwrap().0, Some(1)); waits.sent(1, &[1], t).unwrap();
        blocked.insert(1, waits.remaining(1, t).unwrap().unwrap());
        assert_eq!(cadence.next_due_blocked(t, &blocked).unwrap().1, Some(Duration::from_secs(1)));
        assert_eq!(waits.acknowledge(1).unwrap(), 2);
        blocked.clear();
        assert_eq!(cadence.next_due_blocked(t, &blocked).unwrap().1, Some(Duration::from_millis(100)));
        waits.sent(0, &[1], t).unwrap(); waits.clear_display(0);
        assert_eq!(waits.remaining(0, t).unwrap(), None);
    }
    #[test]
    fn per_display_waits_connection_ack_timeout_and_disconnect() {
        let t = Instant::now(); let mut waits = FrameWait::new(MAX_WAIT).unwrap();
        waits.sent(0, &[1, 2], t).unwrap(); waits.sent(1, &[1], t).unwrap();
        assert_eq!(waits.acknowledge(1).unwrap(), 2);
        assert_eq!(waits.remaining(1, t).unwrap(), None);
        assert_eq!(waits.remaining(0, t + Duration::from_secs(1)).unwrap(), Some(Duration::from_secs(2)));
        assert!(!waits.expire(0, t + Duration::from_secs(2)).unwrap());
        assert!(waits.expire(0, t + MAX_WAIT).unwrap());
        waits.sent(0, &[2], t).unwrap(); waits.disconnect(2).unwrap();
        assert_eq!(waits.remaining(0, t).unwrap(), None);
        assert_eq!(FrameWait::new(Duration::from_secs(4)).err(), Some(WaitError::InvalidTimeout));
    }
}
