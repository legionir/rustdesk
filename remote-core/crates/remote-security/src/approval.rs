//! Bounded in-process handoff for an embedding application's local owner UI.
//!
//! This is **not** a UI, operating-system consent surface, IPC boundary,
//! authenticator or evidence that a person approved anything. Any code with a
//! broker clone can decide requests. Peer labels are untrusted; a caller must
//! authenticate the endpoint and provision a trusted local approval channel.
//! Connection managers must own the request ticket until authorization or
//! disconnect, enforce admission deadlines and close expired sockets. The source
//! uses connection-manager IPC (`src/server/connection.rs`, `src/ipc.rs`,
//! `src/ui_cm_interface.rs`); this bounded handoff is not that IPC implementation.

use remote_session::{Authorizer, Permissions, Principal, SessionId};
use std::{collections::HashMap, error::Error, fmt, sync::{Arc, Mutex}, time::{Duration, Instant}};

pub const MAX_APPROVAL_REQUESTS: usize = 64;
pub const MAX_APPROVAL_LIFETIME: Duration = Duration::from_secs(180);
pub const MAX_LABEL_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalError { InvalidLimits, InvalidLabel, Full, DuplicateSession, Missing, AlreadyDecided, Expired, Poisoned, IdExhausted }
impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "approval handoff: {self:?}") }
}
impl Error for ApprovalError {}

/// Opaque local routing key; it is not a secret or an authentication token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestKey { session: SessionId, generation: u64 }
impl RequestKey { pub fn session(&self) -> SessionId { self.session } }

/// Information to display alongside a consent prompt. `peer_label` is supplied
/// by the remote endpoint, not proof of identity. Never interpolate it into a
/// shell command or treat it as a trusted OS user.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub key: RequestKey,
    pub principal: Principal,
    pub peer_label: String,
    pub requested: Permissions,
    pub expires_at: Instant,
}
struct Entry { request: ApprovalRequest, decision: Option<Option<Permissions>> }
struct State { next_generation: u64, entries: HashMap<SessionId, Entry> }
struct Inner { maximum: usize, state: Mutex<State> }

/// Cloneable local handoff, bounded across cooperating connection tasks.
#[derive(Clone)]
pub struct ApprovalBroker { inner: Arc<Inner> }
impl ApprovalBroker {
    pub fn new(maximum: usize) -> Result<Self, ApprovalError> {
        if maximum == 0 || maximum > MAX_APPROVAL_REQUESTS { return Err(ApprovalError::InvalidLimits); }
        Ok(Self { inner: Arc::new(Inner { maximum, state: Mutex::new(State { next_generation: 1, entries: HashMap::new() }) }) })
    }
    /// Create a pending request. Its ticket is owned by the session and
    /// removes the request on drop. Deadlines do not close sockets themselves.
    pub fn request(&self, session: SessionId, principal: Principal, peer_label: String, requested: Permissions, lifetime: Duration) -> Result<ApprovalTicket, ApprovalError> {
        self.request_at(session, principal, peer_label, requested, lifetime, Instant::now())
    }
    fn request_at(&self, session: SessionId, principal: Principal, peer_label: String, requested: Permissions, lifetime: Duration, now: Instant) -> Result<ApprovalTicket, ApprovalError> {
        if peer_label.len() > MAX_LABEL_BYTES || peer_label.chars().any(char::is_control) { return Err(ApprovalError::InvalidLabel); }
        if lifetime.is_zero() || lifetime > MAX_APPROVAL_LIFETIME { return Err(ApprovalError::InvalidLimits); }
        let expires_at = now.checked_add(lifetime).ok_or(ApprovalError::InvalidLimits)?;
        let mut state = self.inner.state.lock().map_err(|_| ApprovalError::Poisoned)?;
        if state.entries.contains_key(&session) { return Err(ApprovalError::DuplicateSession); }
        if state.entries.len() >= self.inner.maximum { return Err(ApprovalError::Full); }
        let generation = state.next_generation;
        state.next_generation = generation.checked_add(1).ok_or(ApprovalError::IdExhausted)?;
        let key = RequestKey { session, generation };
        state.entries.insert(session, Entry { request: ApprovalRequest { key, principal, peer_label, requested, expires_at }, decision: None });
        Ok(ApprovalTicket { inner: self.inner.clone(), key })
    }
    /// Snapshot still-undecided, unexpired requests for a trusted local UI.
    /// Stale entries are pruned, but a connection manager must close its socket.
    pub fn pending(&self) -> Result<Vec<ApprovalRequest>, ApprovalError> {
        let now = Instant::now(); let mut state = self.inner.state.lock().map_err(|_| ApprovalError::Poisoned)?;
        state.entries.retain(|_, entry| now < entry.request.expires_at);
        Ok(state.entries.values().filter(|entry| entry.decision.is_none()).map(|entry| entry.request.clone()).collect())
    }
    /// Record one decision from the trusted embedding application. `None`
    /// denies. Grants are intersected with the original request at consumption.
    pub fn decide(&self, key: RequestKey, decision: Option<Permissions>) -> Result<(), ApprovalError> {
        self.decide_at(key, decision, Instant::now())
    }
    fn decide_at(&self, key: RequestKey, decision: Option<Permissions>, now: Instant) -> Result<(), ApprovalError> {
        let mut state = self.inner.state.lock().map_err(|_| ApprovalError::Poisoned)?;
        let entry = state.entries.get_mut(&key.session).filter(|entry| entry.request.key == key).ok_or(ApprovalError::Missing)?;
        if now >= entry.request.expires_at { return Err(ApprovalError::Expired); }
        if entry.decision.is_some() { return Err(ApprovalError::AlreadyDecided); }
        entry.decision = Some(decision); Ok(())
    }
}

/// Unique connection-side registration. Drop cancels only this generation.
pub struct ApprovalTicket { inner: Arc<Inner>, key: RequestKey }
impl ApprovalTicket {
    pub fn key(&self) -> RequestKey { self.key }
    /// Obtain a one-shot expiring policy after a decision. `Ok(None)` means
    /// still pending, not denial. A denied decision returns a policy that denies.
    pub fn take_decision(&mut self) -> Result<Option<BrokerApproval>, ApprovalError> { self.take_at(Instant::now()) }
    fn take_at(&mut self, now: Instant) -> Result<Option<BrokerApproval>, ApprovalError> {
        let mut state = self.inner.state.lock().map_err(|_| ApprovalError::Poisoned)?;
        let entry = state.entries.get(&self.key.session).filter(|entry| entry.request.key == self.key).ok_or(ApprovalError::Missing)?;
        if now >= entry.request.expires_at { return Err(ApprovalError::Expired); }
        if entry.decision.is_none() { return Ok(None); }
        let entry = state.entries.remove(&self.key.session).ok_or(ApprovalError::Missing)?;
        Ok(Some(BrokerApproval { request: entry.request, decision: entry.decision.flatten(), used: false }))
    }
}
impl Drop for ApprovalTicket {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.state.lock() {
            if state.entries.get(&self.key.session).map_or(false, |entry| entry.request.key == self.key) { state.entries.remove(&self.key.session); }
        }
    }
}

/// One-shot decision bound to the original session/principal/deadline. It is
/// not transport authentication and cannot prove a local human was involved.
pub struct BrokerApproval { request: ApprovalRequest, decision: Option<Permissions>, used: bool }
impl Authorizer for BrokerApproval {
    fn authorize(&mut self, session: SessionId, principal: &Principal, requested: Permissions) -> Result<Option<Permissions>, Box<dyn Error + Send + Sync>> {
        if self.used { return Ok(None); }
        self.used = true;
        if session != self.request.key.session || principal != &self.request.principal || Instant::now() >= self.request.expires_at { return Ok(None); }
        let allowed = self.request.requested;
        Ok(self.decision.take().map(|grant| Permissions {
            view_screen: grant.view_screen && allowed.view_screen && requested.view_screen,
            control_mouse: grant.control_mouse && allowed.control_mouse && requested.control_mouse,
            control_keyboard: grant.control_keyboard && allowed.control_keyboard && requested.control_keyboard,
            change_display: grant.change_display && allowed.change_display && requested.change_display,
            disconnect_session: grant.disconnect_session && allowed.disconnect_session && requested.disconnect_session,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (SessionId, Principal, Permissions) {
        (SessionId::new([7; 16]).unwrap(), Principal::new("local-policy-principal".into()).unwrap(), Permissions { view_screen: true, ..Default::default() })
    }
    #[test]
    fn decision_is_one_shot_context_bound_and_restricted() {
        let (id, principal, request) = fixture(); let broker = ApprovalBroker::new(1).unwrap();
        let mut ticket = broker.request(id, principal.clone(), "untrusted viewer".into(), request, Duration::from_secs(10)).unwrap();
        assert!(ticket.take_decision().unwrap().is_none());
        broker.decide(ticket.key(), Some(Permissions { view_screen: true, control_mouse: true, ..Default::default() })).unwrap();
        assert_eq!(broker.decide(ticket.key(), None), Err(ApprovalError::AlreadyDecided));
        let mut policy = ticket.take_decision().unwrap().unwrap();
        let all = Permissions { view_screen: true, control_mouse: true, ..Default::default() };
        assert_eq!(policy.authorize(id, &principal, all).unwrap(), Some(request));
        assert_eq!(policy.authorize(id, &principal, all).unwrap(), None);
    }
    #[test]
    fn ticket_generation_cannot_cancel_a_new_request() {
        let (id, principal, request) = fixture(); let broker = ApprovalBroker::new(1).unwrap();
        let mut old = broker.request(id, principal.clone(), "".into(), request, Duration::from_secs(10)).unwrap();
        broker.decide(old.key(), None).unwrap(); let _ = old.take_decision().unwrap().unwrap();
        let new = broker.request(id, principal, "".into(), request, Duration::from_secs(10)).unwrap();
        drop(old); broker.decide(new.key(), None).unwrap();
    }
    #[test]
    fn taken_policy_still_checks_expiration_and_wrong_principal_consumes_it() {
        let (id, principal, request) = fixture();
        let broker = ApprovalBroker::new(1).unwrap();
        let past = Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
        let mut ticket = broker.request_at(id, principal.clone(), "".into(), request, Duration::from_secs(1), past).unwrap();
        broker.decide_at(ticket.key(), Some(request), past).unwrap();
        let mut expired = ticket.take_at(past).unwrap().unwrap();
        assert_eq!(expired.authorize(id, &principal, request).unwrap(), None);
        let mut ticket = broker.request(id, principal.clone(), "".into(), request, Duration::from_secs(10)).unwrap();
        broker.decide(ticket.key(), Some(request)).unwrap();
        let mut policy = ticket.take_decision().unwrap().unwrap();
        let other = Principal::new("different".into()).unwrap();
        assert_eq!(policy.authorize(id, &other, request).unwrap(), None);
        assert_eq!(policy.authorize(id, &principal, request).unwrap(), None);
    }
    #[test]
    fn expired_requests_and_old_decisions_are_denied() {
        let (id, principal, request) = fixture(); let broker = ApprovalBroker::new(1).unwrap(); let t = Instant::now();
        let mut ticket = broker.request_at(id, principal, "".into(), request, Duration::from_secs(1), t).unwrap();
        assert_eq!(broker.decide_at(ticket.key(), Some(request), t + Duration::from_secs(1)), Err(ApprovalError::Expired));
        assert!(matches!(ticket.take_at(t + Duration::from_secs(1)), Err(ApprovalError::Expired)));
    }
}
