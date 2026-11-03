//! Optional bounded, caller-verifier second-factor lifecycle. No TOTP secret,
//! cryptographic implementation, host/login integration, replay store, global
//! rate limit, trusted-device enrollment or consent UI exists here. The
//! embedding application must authenticate the channel and password, obtain
//! owner approval, supply a reviewed verifier and protect/rate-limit it.
//! Session IDs and principals are caller-supplied and not peer authentication.
use remote_session::{Principal, SessionId};
use std::{error::Error, fmt, time::{Duration, Instant}};

const MAX_ATTEMPTS: u8 = 10;
const MAX_LIFETIME: Duration = Duration::from_secs(300);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError { InvalidConfiguration, InvalidBinding, Expired, Exhausted, Finished, VerificationUnavailable }
impl fmt::Display for GateError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "second factor: {self:?}") } }
impl Error for GateError {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State { Pending, Verified, Locked }
/// One unforgeable-by-construction local gate result. It is not a network
/// identity, hardware binding, TOTP replay defense or proof of human approval.
/// Consume before expiry only in the same owner-controlled login flow.
pub struct SecondFactorProof { session: SessionId, principal: Principal, expires: Instant }
impl SecondFactorProof {
    /// Consumes the proof even on mismatch. An equal session ID is not proof
    /// that the same connection owns it; caller must enforce unique bindings.
    pub fn consume(self, session: SessionId, principal: &Principal) -> bool {
        Instant::now() < self.expires && self.session == session && &self.principal == principal
    }
}
/// One attempt result; wrong code does not expose the verifier or submitted
/// credential. Do not log the candidate, tokens, hardware IDs or verifier data.
pub enum Attempt { Wrong { remaining: u8 }, Accepted(SecondFactorProof) }
/// Per-login local gate. Source also has separate global failure counters,
/// trusted devices and click-approval behavior, none of which is modeled here.
pub struct SecondFactorGate { session: SessionId, principal: Principal, expires: Instant, remaining: u8, state: State }
impl SecondFactorGate {
    /// Invoke only after the application has verified password and obtained
    /// required local owner approval. Neither is proved by these arguments.
    /// Lifetime/attempt bounds are deliberately narrower than upstream policy.
    pub fn new(session: SessionId, principal: Principal, lifetime: Duration, attempts: u8) -> Result<Self, GateError> {
        Self::new_at(session, principal, lifetime, attempts, Instant::now())
    }
    fn new_at(session: SessionId, principal: Principal, lifetime: Duration, attempts: u8, now: Instant) -> Result<Self, GateError> {
        if lifetime.is_zero() || lifetime > MAX_LIFETIME || attempts == 0 || attempts > MAX_ATTEMPTS { return Err(GateError::InvalidConfiguration); }
        let expires = now.checked_add(lifetime).ok_or(GateError::InvalidConfiguration)?;
        Ok(Self { session, principal, expires, remaining: attempts, state: State::Pending })
    }
    /// Perform one bounded attempt. `verify` must validate the actual second
    /// factor under an independently reviewed policy; `true` is trusted local
    /// authority, not proof of real verification. Malformed codes count against
    /// the attempt budget. Any verifier error or panic permanently locks this
    /// gate; errors are opaque to avoid exposing secrets. Caller must enforce
    /// rate limits across connections, replay prevention and lifetime of the
    /// verifier's secret. This method is synchronous and must not block a UI.
    pub fn submit<F>(&mut self, session: SessionId, principal: &Principal, code: &str, verify: F) -> Result<Attempt, GateError>
    where F: FnOnce(&str) -> Result<bool, ()> {
        self.submit_at(session, principal, code, verify, Instant::now())
    }
    fn submit_at<F>(&mut self, session: SessionId, principal: &Principal, code: &str, verify: F, now: Instant) -> Result<Attempt, GateError>
    where F: FnOnce(&str) -> Result<bool, ()> {
        match self.state { State::Locked => return Err(GateError::Exhausted), State::Verified => return Err(GateError::Finished), State::Pending => {} }
        if session != self.session || principal != &self.principal { self.state = State::Locked; return Err(GateError::InvalidBinding); }
        if now >= self.expires { self.state = State::Locked; return Err(GateError::Expired); }
        self.remaining -= 1;
        // Set before calling external code so unwinding cannot reopen the gate.
        self.state = State::Locked;
        let valid_format = (6..=8).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_digit());
        let accepted = if valid_format { verify(code).map_err(|_| GateError::VerificationUnavailable)? } else { false };
        // Verification may block past the deadline. Proof must never be issued
        // after it expires, even if the verifier returned true.
        if Instant::now() >= self.expires { return Err(GateError::Expired); }
        if accepted {
            self.state = State::Verified;
            return Ok(Attempt::Accepted(SecondFactorProof { session: self.session, principal: self.principal.clone(), expires: self.expires }));
        }
        if self.remaining > 0 { self.state = State::Pending; }
        Ok(Attempt::Wrong { remaining: self.remaining })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup(t: Instant) -> (SessionId, Principal, SecondFactorGate) {
        let id = SessionId::new([42; 16]).unwrap(); let principal = Principal::new("local-principal".into()).unwrap();
        let gate = SecondFactorGate::new_at(id, principal.clone(), Duration::from_secs(30), 2, t).unwrap();
        (id, principal, gate)
    }
    #[test]
    fn attempts_are_bounded_and_acceptance_is_single_use() {
        let t = Instant::now(); let (id, p, mut gate) = setup(t);
        assert!(matches!(gate.submit_at(id, &p, "invalid", |_| panic!("malformed code reached verifier"), t), Ok(Attempt::Wrong { remaining: 1 })));
        assert!(matches!(gate.submit_at(id, &p, "123456", |_| Ok(false), t), Ok(Attempt::Wrong { remaining: 0 })));
        assert!(matches!(gate.submit_at(id, &p, "123456", |_| Ok(true), t), Err(GateError::Exhausted)));
        let (_, _, mut gate) = setup(t);
        let proof = match gate.submit_at(id, &p, "123456", |_| Ok(true), t).unwrap() { Attempt::Accepted(proof) => proof, _ => panic!("expected proof") };
        assert!(matches!(gate.submit_at(id, &p, "123456", |_| Ok(true), t), Err(GateError::Finished)));
        assert!(proof.consume(id, &p));
    }
    #[test]
    fn mismatch_expiry_and_verifier_error_lock_gate() {
        let t = Instant::now(); let (id, p, mut gate) = setup(t);
        let other = SessionId::new([43; 16]).unwrap();
        assert!(matches!(gate.submit_at(other, &p, "123456", |_| Ok(true), t), Err(GateError::InvalidBinding)));
        assert!(matches!(gate.submit_at(id, &p, "123456", |_| Ok(true), t), Err(GateError::Exhausted)));
        let (_, _, mut gate) = setup(t);
        assert!(matches!(gate.submit_at(id, &p, "123456", |_| Ok(true), t + Duration::from_secs(30)), Err(GateError::Expired)));
        let (_, _, mut gate) = setup(t);
        assert!(matches!(gate.submit_at(id, &p, "123456", |_| Err(()), t), Err(GateError::VerificationUnavailable)));
        assert!(matches!(gate.submit_at(id, &p, "123456", |_| Ok(true), t), Err(GateError::Exhausted)));
    }
    #[cfg(feature = "source-totp")]
    #[test]
    fn optional_source_verifier_composes_without_granting_login() {
        let t = Instant::now(); let (id, p, mut gate) = setup(t);
        let verifier = crate::source_totp::SourceTotp::new(b"12345678901234567890".to_vec(), 8).unwrap();
        let result = gate.submit_at(id, &p, "94287082", |candidate| verifier.check_at(candidate, 59).map_err(|_| ()), t).unwrap();
        let proof = match result { Attempt::Accepted(proof) => proof, _ => panic!("expected RFC example to verify") };
        assert!(proof.consume(id, &p));
        assert!(matches!(gate.submit_at(id, &p, "94287082", |_| Ok(true), t), Err(GateError::Finished)));
    }
    #[test]
    fn proof_is_bound_to_local_session_and_principal() {
        let t = Instant::now(); let (id, p, mut gate) = setup(t);
        let proof = match gate.submit_at(id, &p, "123456", |_| Ok(true), t).unwrap() { Attempt::Accepted(proof) => proof, _ => panic!("expected proof") };
        let other = SessionId::new([44; 16]).unwrap();
        assert!(!proof.consume(other, &p));
        assert!(matches!(gate.submit_at(id, &p, "123456", |_| Ok(true), t), Err(GateError::Finished)));
    }
    #[test]
    fn verifier_panic_does_not_leave_gate_pending() {
        let t = Instant::now(); let (id, p, mut gate) = setup(t);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { let _ = gate.submit_at(id, &p, "123456", |_| -> Result<bool, ()> { panic!("verifier") }, t); }));
        assert!(matches!(gate.submit_at(id, &p, "123456", |_| Ok(true), t), Err(GateError::Exhausted)));
    }
}
