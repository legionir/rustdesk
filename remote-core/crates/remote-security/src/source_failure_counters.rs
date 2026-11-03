//! Optional in-memory counters derived from RustDesk's default password-login
//! failure policy (`src/server/connection.rs`, not terminal OS credentials).
//! This is bookkeeping only: it is NOT wired into admission or authentication.
//! The embedding application must review policy, derive IPs from a trusted
//! socket or authenticated proxy, serialize check/update, provision memory and
//! audit decisions. Spoofable headers/peer IDs must never be used as addresses.
//! `admission::normalize_socket_ip` is available for explicitly chosen,
//! consistently applied normalization; these counters never normalize by
//! themselves to avoid silently changing source bucket/reset semantics.
//! Shared IPv6 prefix clearing on success follows source behavior and permits
//! one successful login to clear failures for other hosts in that prefix.
use std::{collections::HashMap, error::Error, fmt, net::{IpAddr, Ipv6Addr}};

const SOURCE_IPV4_OR_ADDRESS_TOTAL: u64 = 30;
const SOURCE_ADDRESS_MINUTE: u64 = 6;
const SOURCE_PREFIX_64: u64 = 60;
const SOURCE_PREFIX_56: u64 = 80;
const SOURCE_PREFIX_48: u64 = 100;
const MAX_BUCKETS: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Key { Address(IpAddr), Prefix(Ipv6Addr, u8) }
#[derive(Debug, Clone, Copy)]
struct Counter { minute: u64, minute_failures: u64, total: u64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision { Allowed, AddressTotal, AddressMinute, Prefix64, Prefix56, Prefix48 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterError { InvalidCapacity, Capacity, ClockRegression }
impl fmt::Display for CounterError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "failure counters: {self:?}") } }
impl Error for CounterError {}
fn keys(ip: IpAddr) -> Vec<Key> {
    match ip {
        IpAddr::V4(_) => vec![Key::Address(ip)],
        IpAddr::V6(v6) => {
            let value = u128::from(v6);
            let prefix = |bits: u8| Key::Prefix(Ipv6Addr::from(value & (!0u128 << (128 - bits))), bits);
            vec![prefix(64), prefix(56), prefix(48), Key::Address(ip)]
        }
    }
}
/// Caller-owned counters; synchronize externally, particularly between a check
/// and a concurrently completing authentication attempt. Not a rate-limiter
/// for already-running password guesses and not durable across process restarts.
pub struct SourceFailureCounters { max_buckets: usize, entries: HashMap<Key, Counter> }
impl SourceFailureCounters {
    pub fn new(max_buckets: usize) -> Result<Self, CounterError> {
        if !(4..=MAX_BUCKETS).contains(&max_buckets) { return Err(CounterError::InvalidCapacity); }
        Ok(Self { max_buckets, entries: HashMap::new() })
    }
    /// `minute` is a nondecreasing caller-controlled minute counter, not a
    /// peer-supplied timestamp. Source checks `>` (not `>=`) thresholds. This
    /// helper refuses a clock regression instead of silently resetting a bucket.
    pub fn check(&self, ip: IpAddr, minute: u64) -> Result<Decision, CounterError> {
        let keys = keys(ip);
        for key in &keys {
            if let Some(counter) = self.entries.get(key) {
                if minute < counter.minute { return Err(CounterError::ClockRegression); }
                let decision = match key {
                    Key::Prefix(_, 64) if counter.total > SOURCE_PREFIX_64 => Some(Decision::Prefix64),
                    Key::Prefix(_, 56) if counter.total > SOURCE_PREFIX_56 => Some(Decision::Prefix56),
                    Key::Prefix(_, 48) if counter.total > SOURCE_PREFIX_48 => Some(Decision::Prefix48),
                    Key::Address(_) if counter.total > SOURCE_IPV4_OR_ADDRESS_TOTAL => Some(Decision::AddressTotal),
                    Key::Address(_) if counter.minute == minute && counter.minute_failures > SOURCE_ADDRESS_MINUTE => Some(Decision::AddressMinute),
                    _ => None,
                };
                if let Some(decision) = decision { return Ok(decision); }
            }
        }
        Ok(Decision::Allowed)
    }
    /// Record one actual failed password attempt across all source buckets.
    /// Capacity failure changes none of the buckets; caller must fail closed or
    /// apply an explicitly reviewed alternative, never silently skip recording.
    pub fn record_failure(&mut self, ip: IpAddr, minute: u64) -> Result<(), CounterError> {
        let keys = keys(ip);
        let missing = keys.iter().filter(|key| !self.entries.contains_key(*key)).count();
        if self.entries.len().saturating_add(missing) > self.max_buckets { return Err(CounterError::Capacity); }
        if keys.iter().any(|key| self.entries.get(key).map_or(false, |counter| minute < counter.minute)) {
            return Err(CounterError::ClockRegression);
        }
        for key in keys {
            let counter = self.entries.entry(key).or_insert(Counter { minute, minute_failures: 0, total: 0 });
            if counter.minute != minute { counter.minute = minute; counter.minute_failures = 0; }
            counter.minute_failures = counter.minute_failures.saturating_add(1);
            counter.total = counter.total.saturating_add(1);
        }
        Ok(())
    }
    /// Explicitly reproduce the source's successful-login reset for this IP
    /// and all its IPv6 prefixes, including shared-prefix implications. Source
    /// only clears if the address bucket's last minute is nonzero. Caller must
    /// independently establish success and consent to these semantics.
    pub fn clear_source_on_success(&mut self, ip: IpAddr) {
        if !self.entries.get(&Key::Address(ip)).map_or(false, |entry| entry.minute != 0) { return; }
        for key in keys(ip) { self.entries.remove(&key); }
    }
    /// Explicit administrative reset of every bucket. This weakens lockout and
    /// must be restricted/audited by the embedding application; it is never
    /// called automatically on capacity exhaustion or a peer request.
    pub fn clear_all_by_operator(&mut self) { self.entries.clear(); }
    pub fn bucket_count(&self) -> usize { self.entries.len() }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_threshold_is_strictly_greater_and_resets_on_success() {
        let ip = "192.0.2.1".parse().unwrap(); let mut c = SourceFailureCounters::new(8).unwrap();
        for _ in 0..6 { c.record_failure(ip, 10).unwrap(); }
        assert_eq!(c.check(ip, 10).unwrap(), Decision::Allowed);
        c.record_failure(ip, 10).unwrap(); assert_eq!(c.check(ip, 10).unwrap(), Decision::AddressMinute);
        assert_eq!(c.check(ip, 11).unwrap(), Decision::Allowed);
        c.clear_source_on_success(ip); assert_eq!(c.bucket_count(), 0);
    }
    #[test]
    fn capacity_and_clock_failure_are_atomic() {
        let mut c = SourceFailureCounters::new(4).unwrap();
        let a = "2001:db8::1".parse().unwrap(); let b = "2001:db9::1".parse().unwrap();
        c.record_failure(a, 20).unwrap(); assert_eq!(c.bucket_count(), 4);
        assert_eq!(c.record_failure(b, 20), Err(CounterError::Capacity));
        assert_eq!(c.record_failure(a, 19), Err(CounterError::ClockRegression));
        assert_eq!(c.bucket_count(), 4);
        c.clear_all_by_operator(); assert_eq!(c.bucket_count(), 0);
        assert!(c.record_failure(b, 20).is_ok());
    }
    #[test]
    fn source_success_can_clear_shared_prefixes_without_clearing_other_addresses() {
        let mut c = SourceFailureCounters::new(256).unwrap();
        for n in 0..61u16 {
            c.record_failure(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, n)), 2).unwrap();
        }
        let first = "2001:db8:1:2::".parse().unwrap();
        let second = "2001:db8:1:2::1".parse().unwrap();
        c.clear_source_on_success(first);
        assert_eq!(c.check(second, 2).unwrap(), Decision::Allowed);
        assert_eq!(c.bucket_count(), 60);
    }
    #[test]
    fn shared_ipv6_prefix_is_evaluated_before_address() {
        let mut c = SourceFailureCounters::new(256).unwrap();
        for n in 0..61u16 {
            let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, n));
            c.record_failure(ip, 2).unwrap();
        }
        let fresh = "2001:db8:1:2::aaaa".parse().unwrap();
        assert_eq!(c.check(fresh, 2).unwrap(), Decision::Prefix64);
    }
}
