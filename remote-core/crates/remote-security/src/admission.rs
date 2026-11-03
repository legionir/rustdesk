//! Bounded in-process pre-authorization admission, adapted from limits in
//! `src/server/connection.rs`. This is not a replacement for RustDesk's
//! complete brute-force, 2FA, whitelist, eviction or login logic.
//!
//! All transports must cooperate with one controller, the address must come
//! from a trusted source, and callers must close expired connections themselves.
//! This module does not authenticate peers, prevent distributed attacks, or
//! enforce an I/O/message limit. No tests or security audit have run.

use std::{collections::HashMap, error::Error, fmt, net::IpAddr, sync::{Arc, Mutex}, time::{Duration, Instant}};

/// Source default limit on concurrently unauthorized connections.
pub const SOURCE_GLOBAL_LIMIT: usize = 64;
/// Source default limit on concurrently unauthorized connections per address.
pub const SOURCE_PER_ADDRESS_LIMIT: usize = 16;
/// Source maximum login grace duration.
pub const SOURCE_LOGIN_GRACE: Duration = Duration::from_secs(180);
/// Source pre-authorization message ceiling; transport must enforce separately.
pub const SOURCE_MAX_PREAUTH_MESSAGE: usize = 128 * 1024;

/// Admission policy bounded by the pinned RustDesk defaults.
#[derive(Debug, Clone, Copy)]
pub struct AdmissionLimits {
    pub max_total: usize,
    pub max_per_address: usize,
    pub login_grace: Duration,
}
impl Default for AdmissionLimits {
    fn default() -> Self {
        Self { max_total: SOURCE_GLOBAL_LIMIT, max_per_address: SOURCE_PER_ADDRESS_LIMIT, login_grace: SOURCE_LOGIN_GRACE }
    }
}

/// Admission or state error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    InvalidLimits,
    GlobalLimit,
    AddressLimit,
    Expired,
    Poisoned,
    IdExhausted,
}
impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid pre-authentication admission limits"),
            Self::GlobalLimit => f.write_str("pre-authentication connection limit reached"),
            Self::AddressLimit => f.write_str("pre-authentication per-address limit reached"),
            Self::Expired => f.write_str("pre-authentication grace period expired"),
            Self::Poisoned => f.write_str("admission state is poisoned"),
            Self::IdExhausted => f.write_str("admission identifier space exhausted"),
        }
    }
}
impl Error for AdmissionError {}

struct State { next_id: u64, entries: HashMap<u64, IpAddr> }
struct Inner { limits: AdmissionLimits, state: Mutex<State> }

/// Normalize IPv4-mapped IPv6 socket addresses exactly as this admission
/// controller does. Applications combining this controller with separately
/// owned counters may choose this helper to avoid splitting one address across
/// two buckets, but must consistently apply it to every operation. This is not
/// proxy attribution or authentication, and it changes source counter semantics
/// for mapped IPv6 inputs; that policy must be explicitly reviewed.
pub fn normalize_socket_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

/// A cloneable admission controller shared across cooperating transports.
#[derive(Clone)]
pub struct AdmissionController { inner: Arc<Inner> }
impl AdmissionController {
    /// Reject zero or more permissive limits than the pinned source defaults.
    pub fn new(limits: AdmissionLimits) -> Result<Self, AdmissionError> {
        if limits.max_total == 0 || limits.max_total > SOURCE_GLOBAL_LIMIT
            || limits.max_per_address == 0 || limits.max_per_address > SOURCE_PER_ADDRESS_LIMIT
            || limits.max_per_address > limits.max_total || limits.login_grace.is_zero()
            || limits.login_grace > SOURCE_LOGIN_GRACE {
            return Err(AdmissionError::InvalidLimits);
        }
        Ok(Self { inner: Arc::new(Inner { limits, state: Mutex::new(State { next_id: 1, entries: HashMap::new() }) }) })
    }
    /// Hold a slot until authorization succeeds or the connection is closed.
    ///
    /// Unlike source's eviction policy this adapter simply rejects at capacity;
    /// it never silently makes room while a previous connection remains live.
    /// IPv4-mapped IPv6 addresses are normalized before per-address counting.
    pub fn admit(&self, address: IpAddr) -> Result<AdmissionPermit, AdmissionError> {
        let address = normalize_socket_ip(address);
        let expires = Instant::now().checked_add(self.inner.limits.login_grace).ok_or(AdmissionError::InvalidLimits)?;
        let mut state = self.inner.state.lock().map_err(|_| AdmissionError::Poisoned)?;
        if state.entries.values().filter(|ip| **ip == address).count() >= self.inner.limits.max_per_address { return Err(AdmissionError::AddressLimit); }
        if state.entries.len() >= self.inner.limits.max_total { return Err(AdmissionError::GlobalLimit); }
        let id = state.next_id;
        state.next_id = id.checked_add(1).ok_or(AdmissionError::IdExhausted)?;
        state.entries.insert(id, address);
        Ok(AdmissionPermit { inner: self.inner.clone(), id, expires })
    }
    /// Number of retained slots, including expired connections not yet closed.
    pub fn active(&self) -> Result<usize, AdmissionError> {
        Ok(self.inner.state.lock().map_err(|_| AdmissionError::Poisoned)?.entries.len())
    }
}

/// Unique slot owned by one pending connection. Dropping releases the slot.
///
/// A timeout does not close a socket or release the slot automatically: the
/// connection task must check `check_live`, enforce a timer and close/drop it.
/// Keep this permit until actual authorization, not merely password validation.
pub struct AdmissionPermit { inner: Arc<Inner>, id: u64, expires: Instant }
impl AdmissionPermit {
    /// Refuse work after the fixed login grace deadline.
    pub fn check_live(&self) -> Result<(), AdmissionError> {
        if Instant::now() >= self.expires { Err(AdmissionError::Expired) } else { Ok(()) }
    }
    /// Remaining grace for caller-managed timers, saturating at zero.
    pub fn remaining(&self) -> Duration { self.expires.saturating_duration_since(Instant::now()) }
    /// Release the slot after the trusted caller has completed all required
    /// authentication and authorization. This function does not verify them.
    pub fn authorization_complete(self) { drop(self); }
}
impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        // On poisoning, subsequent admission attempts also fail closed.
        if let Ok(mut state) = self.inner.state.lock() { state.entries.remove(&self.id); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn caps_total_and_normalizes_addresses() {
        let c = AdmissionController::new(AdmissionLimits { max_total: 2, max_per_address: 1, login_grace: Duration::from_secs(5) }).unwrap();
        let a = c.admit("127.0.0.1".parse().unwrap()).unwrap();
        assert!(matches!(c.admit("::ffff:127.0.0.1".parse().unwrap()), Err(AdmissionError::AddressLimit)));
        let b = c.admit("127.0.0.2".parse().unwrap()).unwrap();
        assert!(matches!(c.admit("127.0.0.3".parse().unwrap()), Err(AdmissionError::GlobalLimit)));
        drop(a); assert_eq!(c.active().unwrap(), 1);
        b.authorization_complete(); assert_eq!(c.active().unwrap(), 0);
    }
    #[test]
    fn normalization_only_collapses_v4_mapped_ipv6() {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(normalize_socket_ip("::ffff:192.0.2.1".parse().unwrap()), v4);
        assert_eq!(normalize_socket_ip(v4), v4);
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(normalize_socket_ip(v6), v6);
    }
    #[test]
    fn rejects_invalid_limits_and_holds_slot_until_drop() {
        assert!(matches!(AdmissionController::new(AdmissionLimits { max_total: 65, ..Default::default() }), Err(AdmissionError::InvalidLimits)));
        let c = AdmissionController::new(AdmissionLimits { max_total: 1, max_per_address: 1, login_grace: Duration::from_nanos(1) }).unwrap();
        let permit = c.admit("127.0.0.1".parse().unwrap()).unwrap();
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(permit.check_live(), Err(AdmissionError::Expired));
        assert_eq!(c.active().unwrap(), 1);
        drop(permit); assert_eq!(c.active().unwrap(), 0);
    }
}
