//! Caller-driven bookkeeping for stale pressed-key cleanup, inspired by
//! `fix_key_down_timeout` at the pinned source. No key injection or task.
//!
//! Unlike RustDesk's global map this is an opt-in local tracker: it cannot see
//! keys held by a human, another session, process or alternate input path.
use std::{collections::BTreeMap, error::Error, fmt, time::{Duration, Instant}};
pub const MAX_TRACKED_KEYS: usize = 64;
/// Source's periodic cleanup considers keys held for six minutes stale.
pub const SOURCE_KEY_TIMEOUT: Duration = Duration::from_secs(360);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExpiryError { Capacity, ClockWentBackwards, GenerationExhausted, Stale }
impl fmt::Display for KeyExpiryError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "key expiry: {self:?}") } }
impl Error for KeyExpiryError {}
/// Opaque caller key mapping plus timestamp/generation; not an OS key identity.
/// Snapshots must only be used with the tracker instance that produced them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiredKey { pub key: u64, pub since: Instant, generation: u64 }
#[derive(Default)]
pub struct KeyExpiry { keys: BTreeMap<u64, ExpiredKey>, last_time: Option<Instant>, generation: u64 }
impl KeyExpiry {
    pub fn new() -> Self { Self::default() }
    fn check_time(&self, now: Instant) -> Result<(), KeyExpiryError> {
        if self.last_time.map_or(false, |last| now < last) { Err(KeyExpiryError::ClockWentBackwards) } else { Ok(()) }
    }
    /// Record a successful controller-owned press. Repeated down refreshes the
    /// source timestamp, although individual input controllers may ignore repeat.
    pub fn pressed(&mut self, key: u64, now: Instant) -> Result<(), KeyExpiryError> {
        self.check_time(now)?;
        if !self.keys.contains_key(&key) && self.keys.len() == MAX_TRACKED_KEYS { return Err(KeyExpiryError::Capacity); }
        let generation = self.generation.checked_add(1).ok_or(KeyExpiryError::GenerationExhausted)?;
        self.keys.insert(key, ExpiredKey { key, since: now, generation });
        self.generation = generation; self.last_time = Some(now); Ok(())
    }
    /// Forget an owned key after an explicitly handled key-up. This does not
    /// prove OS delivery. Unknown keys are ignored.
    pub fn released(&mut self, key: u64, now: Instant) -> Result<bool, KeyExpiryError> {
        self.check_time(now)?; self.last_time = Some(now); Ok(self.keys.remove(&key).is_some())
    }
    /// Return expired snapshots without changing the tracked state. The caller
    /// must serialize checks, release and input events, validate ownership, and
    /// decide whether cleanup is safe. No OS event is sent by this method.
    pub fn expired(&mut self, now: Instant) -> Result<Vec<ExpiredKey>, KeyExpiryError> {
        self.check_time(now)?; self.last_time = Some(now);
        Ok(self.keys.values().filter(|key| now.duration_since(key.since) >= SOURCE_KEY_TIMEOUT).copied().collect())
    }
    /// Check whether a snapshot still identifies the current recorded press.
    /// External serialization is still essential: a new press can race any OS
    /// release after this check. Foreign-instance snapshots must not be used.
    pub fn is_current(&self, snapshot: ExpiredKey) -> bool {
        self.keys.get(&snapshot.key) == Some(&snapshot)
    }
    /// Acknowledge a snapshot after locally handled cleanup. A newer press of the
    /// same key invalidates the old generation, but checking *after* injection
    /// cannot undo a wrongly delivered key-up; serialize input externally.
    pub fn acknowledge(&mut self, snapshot: ExpiredKey) -> Result<(), KeyExpiryError> {
        if !self.is_current(snapshot) { return Err(KeyExpiryError::Stale); }
        self.keys.remove(&snapshot.key); Ok(())
    }
    /// Drop bookkeeping only. This does not release any OS key.
    pub fn clear(&mut self) { self.keys.clear(); }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expiry_refresh_and_stale_snapshot_are_bounded() {
        let mut tracker = KeyExpiry::new(); let now = Instant::now();
        tracker.pressed(1, now).unwrap();
        assert!(tracker.expired(now + SOURCE_KEY_TIMEOUT - Duration::from_millis(1)).unwrap().is_empty());
        let old = tracker.expired(now + SOURCE_KEY_TIMEOUT).unwrap()[0];
        assert!(tracker.is_current(old));
        tracker.pressed(1, now + SOURCE_KEY_TIMEOUT).unwrap();
        assert!(!tracker.is_current(old));
        assert_eq!(tracker.acknowledge(old), Err(KeyExpiryError::Stale));
        assert_eq!(tracker.released(1, now), Err(KeyExpiryError::ClockWentBackwards));
        assert!(tracker.released(1, now + SOURCE_KEY_TIMEOUT).unwrap());
    }
    #[test]
    fn clearing_bookkeeping_does_not_reuse_a_generation() {
        let now = Instant::now(); let mut tracker = KeyExpiry::new();
        tracker.pressed(1, now).unwrap();
        let old = tracker.expired(now + SOURCE_KEY_TIMEOUT).unwrap()[0];
        tracker.clear(); tracker.pressed(1, now + SOURCE_KEY_TIMEOUT).unwrap();
        assert!(!tracker.is_current(old));
        assert_eq!(tracker.acknowledge(old), Err(KeyExpiryError::Stale));
    }
    #[test]
    fn exhausted_generations_do_not_replace_an_existing_press() {
        let now = Instant::now(); let mut tracker = KeyExpiry::new();
        tracker.pressed(1, now).unwrap(); let original = tracker.keys[&1];
        tracker.generation = u64::MAX;
        assert_eq!(tracker.pressed(1, now), Err(KeyExpiryError::GenerationExhausted));
        assert!(tracker.is_current(original));
    }
    #[test]
    fn capacity_is_transactional() {
        let mut tracker = KeyExpiry::new(); let now = Instant::now();
        for key in 0..MAX_TRACKED_KEYS { tracker.pressed(key as u64, now).unwrap(); }
        assert_eq!(tracker.pressed(MAX_TRACKED_KEYS as u64, now), Err(KeyExpiryError::Capacity));
        assert_eq!(tracker.expired(now + SOURCE_KEY_TIMEOUT).unwrap().len(), MAX_TRACKED_KEYS);
    }
}
