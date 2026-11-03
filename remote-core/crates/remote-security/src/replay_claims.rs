//! In-process, bounded, caller-driven replay claims. This is not a complete
//! TOTP implementation or durable replay store. The application must compute a
//! stable keyed fingerprint of the principal and accepted code, separately
//! verify the code, share this object across all relevant login flows, choose a
//! sufficient window, and protect the fingerprinting key. No network claims,
//! IP headers or raw codes are trusted here. Process restart, multiple processes,
//! clock/system-time changes and caller mistakes can defeat replay protection.
use hmac::{Hmac, Mac};
use remote_session::Principal;
use sha2::Sha256;
use zeroize::Zeroizing;
use std::{collections::HashMap, error::Error, fmt, sync::Mutex, time::{Duration, Instant}};

const MAX_ENTRIES: usize = 4096;
const MAX_WINDOW: Duration = Duration::from_secs(300);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError { InvalidConfiguration, InvalidCode, RandomUnavailable, ClockRegression, Full, Poisoned }
impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "replay claims: {self:?}") }
}
impl Error for ReplayError {}
/// Ephemeral keyed fingerprinting for one shared process-local replay store.
/// A principal must be a stable local identity shared across all flows covered
/// by the same TOTP secret, not an unverified peer label or per-session ID.
/// Changing identity or key bypasses prior claims. No key export/clone/Debug is
/// provided; dropping it wipes only its owned key, not HMAC/allocator copies.
pub struct ReplayFingerprintKey(Zeroizing<[u8; 32]>);
impl ReplayFingerprintKey {
    pub fn random() -> Result<Self, ReplayError> {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut key[..]).map_err(|_| ReplayError::RandomUnavailable)?;
        Ok(Self(key))
    }
    /// Produce an opaque HMAC for a numeric code. This does not verify it.
    /// Call only after verification and do not log or send fingerprints.
    pub fn fingerprint(&self, principal: &Principal, code: &str) -> Result<[u8; 32], ReplayError> {
        if !(6..=8).contains(&code.len()) || !code.bytes().all(|b| b.is_ascii_digit()) { return Err(ReplayError::InvalidCode); }
        let identity = principal.as_str().as_bytes();
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0[..]).map_err(|_| ReplayError::InvalidConfiguration)?;
        mac.update(b"remote-core/totp-replay/v1\0");
        mac.update(&(identity.len() as u32).to_be_bytes());
        mac.update(identity);
        mac.update(code.as_bytes());
        Ok(mac.finalize().into_bytes().into())
    }
}
struct State { last: Option<Instant>, entries: HashMap<[u8; 32], Instant> }
/// A single-process atomic claim set; it neither verifies nor stores raw codes.
/// No Debug/Clone is exposed. Losing the process loses all previous claims.
pub struct ReplayClaims { max_entries: usize, window: Duration, state: Mutex<State> }
impl ReplayClaims {
    /// Configure a bounded store and retention window. For the source TOTP
    /// one-step skew, use at least 90 seconds only when system-time assumptions
    /// are explicitly satisfied; longer may reject legitimate code collisions.
    pub fn new(max_entries: usize, window: Duration) -> Result<Self, ReplayError> {
        if max_entries == 0 || max_entries > MAX_ENTRIES || window.is_zero() || window > MAX_WINDOW { return Err(ReplayError::InvalidConfiguration); }
        Ok(Self { max_entries, window, state: Mutex::new(State { last: None, entries: HashMap::new() }) })
    }
    /// Atomically claim a caller-computed opaque fingerprint after verifying a
    /// code, returning false if it is already retained. Call this inside the
    /// same verification decision before granting any proof. Reject on *any*
    /// error, including Full and Poisoned. Calls must use one shared instance;
    /// an application-provided HMAC must bind principal AND code unambiguously.
    /// A monotonic window alone does not handle wall-clock changes in TOTP.
    pub fn claim(&self, fingerprint: [u8; 32]) -> Result<bool, ReplayError> {
        let mut state = self.state.lock().map_err(|_| ReplayError::Poisoned)?;
        // Sample after acquiring the lock: concurrent callers may acquire it in
        // a different order from their invocation times.
        self.claim_locked(&mut state, fingerprint, Instant::now())
    }
    #[cfg(test)]
    fn claim_at(&self, fingerprint: [u8; 32], now: Instant) -> Result<bool, ReplayError> {
        let mut state = self.state.lock().map_err(|_| ReplayError::Poisoned)?;
        self.claim_locked(&mut state, fingerprint, now)
    }
    fn claim_locked(&self, state: &mut State, fingerprint: [u8; 32], now: Instant) -> Result<bool, ReplayError> {
        if state.last.map_or(false, |last| now < last) { return Err(ReplayError::ClockRegression); }
        let expires = now.checked_add(self.window).ok_or(ReplayError::InvalidConfiguration)?;
        state.last = Some(now);
        state.entries.retain(|_, until| *until > now);
        if state.entries.contains_key(&fingerprint) { return Ok(false); }
        if state.entries.len() >= self.max_entries { return Err(ReplayError::Full); }
        state.entries.insert(fingerprint, expires);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keyed_fingerprints_bind_stable_principal_and_numeric_code() {
        let key = ReplayFingerprintKey(Zeroizing::new([7; 32]));
        let a = Principal::new("local-a".into()).unwrap(); let b = Principal::new("local-b".into()).unwrap();
        let first = key.fingerprint(&a, "123456").unwrap();
        assert_eq!(first, key.fingerprint(&a, "123456").unwrap());
        assert_ne!(first, key.fingerprint(&b, "123456").unwrap());
        assert_ne!(first, key.fingerprint(&a, "123457").unwrap());
        assert_eq!(key.fingerprint(&a, "invalid"), Err(ReplayError::InvalidCode));
    }
    #[test]
    fn duplicate_expiry_full_and_clock_regression_fail_closed() {
        let store = ReplayClaims::new(1, Duration::from_secs(90)).unwrap();
        // Use a synthetic base in the future so regression testing does not
        // depend on whether a platform permits subtracting from its epoch.
        let now = Instant::now().checked_add(Duration::from_secs(1)).unwrap();
        assert_eq!(store.claim_at([1; 32], now), Ok(true));
        assert_eq!(store.claim_at([1; 32], now), Ok(false));
        assert_eq!(store.claim_at([2; 32], now), Err(ReplayError::Full));
        assert_eq!(store.claim_at([3; 32], now - Duration::from_secs(1)), Err(ReplayError::ClockRegression));
        assert_eq!(store.claim_at([2; 32], now + Duration::from_secs(90)), Ok(true));
    }
    #[test]
    fn bad_configuration_and_poisoned_mutex_are_not_bypasses() {
        assert!(matches!(ReplayClaims::new(0, Duration::from_secs(90)), Err(ReplayError::InvalidConfiguration)));
        assert!(matches!(ReplayClaims::new(1, Duration::ZERO), Err(ReplayError::InvalidConfiguration)));
        assert!(matches!(ReplayClaims::new(MAX_ENTRIES + 1, Duration::from_secs(90)), Err(ReplayError::InvalidConfiguration)));
        let claims = ReplayClaims::new(1, Duration::from_secs(90)).unwrap();
        let _ = std::panic::catch_unwind(|| { let _guard = claims.state.lock().unwrap(); panic!("poison for fixture"); });
        assert_eq!(claims.claim([1; 32]), Err(ReplayError::Poisoned));
    }
    #[test]
    fn shared_claim_store_can_gate_two_independent_local_flows() {
        use crate::two_factor_gate::{Attempt, SecondFactorGate};
        use remote_session::SessionId;
        let key = ReplayFingerprintKey(Zeroizing::new([9; 32]));
        let claims = ReplayClaims::new(8, Duration::from_secs(90)).unwrap();
        let principal = Principal::new("stable-local-owner".into()).unwrap();
        let first_id = SessionId::new([1; 16]).unwrap();
        let second_id = SessionId::new([2; 16]).unwrap();
        let mut first = SecondFactorGate::new(first_id, principal.clone(), Duration::from_secs(30), 1).unwrap();
        let mut second = SecondFactorGate::new(second_id, principal.clone(), Duration::from_secs(30), 1).unwrap();
        let decide = |code: &str| {
            if code != "123456" { return Ok(false); } // synthetic verifier, not TOTP
            let token = key.fingerprint(&principal, code).map_err(|_| ())?;
            claims.claim(token).map_err(|_| ())
        };
        assert!(matches!(first.submit(first_id, &principal, "123456", decide), Ok(Attempt::Accepted(_))));
        assert!(matches!(second.submit(second_id, &principal, "123456", decide), Ok(Attempt::Wrong { remaining: 0 })));
    }
    #[test]
    fn concurrently_reused_fingerprint_is_claimed_once() {
        let store = std::sync::Arc::new(ReplayClaims::new(4, Duration::from_secs(90)).unwrap());
        let workers: Vec<_> = (0..8).map(|_| { let store = store.clone(); std::thread::spawn(move || store.claim([7; 32]).unwrap()) }).collect();
        assert_eq!(workers.into_iter().map(|w| w.join().unwrap()).filter(|accepted| *accepted).count(), 1);
    }
}
