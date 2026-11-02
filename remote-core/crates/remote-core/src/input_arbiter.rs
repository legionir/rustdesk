//! Optional in-process arbitration for a single controlling input session.
//!
//! This is not an OS-wide lock or security boundary. Every OS input path must
//! cooperate with the same arbiter; unguarded `HostInputSession`s, other
//! processes, RustDesk's original input service and human input can bypass it.
//! Some Enigo Windows failures are not observable, even when cleanup succeeds.

use crate::{HostInputError, HostInputSession};
use remote_input::InputBackend;
use remote_session::{SessionId, SessionState};
use std::{error::Error, fmt, sync::{Arc, Mutex}};

#[derive(Default)]
struct State {
    owner: Option<SessionId>,
    quarantine: bool,
}

/// Failure acquiring or recovering the optional controller lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArbitrationError {
    /// Another session still owns the input controller.
    Busy,
    /// Cleanup failed and trusted manual recovery is required.
    Quarantined,
    /// The session is not connected/streaming or has no input permission.
    SessionNotEligible,
    /// The internal mutex was poisoned; refuse further operation.
    Poisoned,
}
impl fmt::Display for ArbitrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => f.write_str("input controller is already owned"),
            Self::Quarantined => f.write_str("input controller requires manual recovery"),
            Self::SessionNotEligible => f.write_str("session is not authorized for input"),
            Self::Poisoned => f.write_str("input arbitration state is poisoned"),
        }
    }
}
impl Error for ArbitrationError {}

/// Shared in-process arbiter for cooperating controlled sessions.
#[derive(Clone, Default)]
pub struct InputArbiter { state: Arc<Mutex<State>> }
impl InputArbiter {
    /// Construct an arbiter with no controller owner.
    pub fn new() -> Self { Self::default() }
    /// Attach an already authorized input session without losing it on failure.
    ///
    /// On failure returns both the error and the original host. This ensures
    /// a failed attach does not accidentally drop an active session. Acquiring
    /// a lease does not authenticate a peer or guarantee global exclusivity.
    pub fn attach<B: InputBackend>(&self, host: HostInputSession<B>) -> Result<ControlledSession<B>, (ArbitrationError, HostInputSession<B>)> {
        let eligible = matches!(host.state(), SessionState::Connected | SessionState::Streaming)
            && (host.permissions().control_mouse || host.permissions().control_keyboard);
        if !eligible { return Err((ArbitrationError::SessionNotEligible, host)); }
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return Err((ArbitrationError::Poisoned, host)),
        };
        if state.quarantine { return Err((ArbitrationError::Quarantined, host)); }
        if state.owner.is_some() { return Err((ArbitrationError::Busy, host)); }
        let id = host.id();
        state.owner = Some(id);
        drop(state);
        Ok(ControlledSession { host, state: self.state.clone(), owns_lease: true, cleanup_failed: false })
    }
    /// Report the current controller, if any.
    pub fn owner(&self) -> Result<Option<SessionId>, ArbitrationError> {
        Ok(self.state.lock().map_err(|_| ArbitrationError::Poisoned)?.owner)
    }
    /// Whether a failed cleanup requires manual recovery.
    pub fn is_quarantined(&self) -> Result<bool, ArbitrationError> {
        Ok(self.state.lock().map_err(|_| ArbitrationError::Poisoned)?.quarantine)
    }
    /// Clear quarantine only after a trusted operator has independently
    /// verified/released OS input. This method cannot perform that verification.
    /// It must not be called while a session still owns the arbiter.
    pub fn acknowledge_manual_recovery(&self) -> Result<(), ArbitrationError> {
        let mut state = self.state.lock().map_err(|_| ArbitrationError::Poisoned)?;
        if state.owner.is_some() { return Err(ArbitrationError::Busy); }
        state.quarantine = false;
        Ok(())
    }
}

/// An input session holding the arbiter until successful close or drop.
///
/// `host_mut` permits normal session operations while ownership remains held.
/// Do not construct any other backend outside the arbiter for this to have
/// meaning. Explicitly call `close` and handle errors; drop is only best effort.
pub struct ControlledSession<B: InputBackend> {
    host: HostInputSession<B>,
    state: Arc<Mutex<State>>,
    owns_lease: bool,
    cleanup_failed: bool,
}
impl<B: InputBackend> ControlledSession<B> {
    /// Access the underlying host while retaining this lease.
    pub fn host(&self) -> &HostInputSession<B> { &self.host }
    /// Mutably access the host while retaining this lease.
    pub fn host_mut(&mut self) -> &mut HostInputSession<B> { &mut self.host }
    /// Close the session and release the lease only after detectable cleanup
    /// succeeds. A failure keeps the lease and can be retried. If the value is
    /// dropped while cleanup is still failing, the arbiter is quarantined.
    pub fn close(&mut self) -> Result<(), HostInputError> {
        if !self.owns_lease { return Ok(()); }
        if let Err(error) = self.host.close() {
            self.cleanup_failed = true;
            return Err(error);
        }
        // A poisoned mutex is intentionally never recovered here: other
        // acquisition attempts also fail closed. The OS cleanup has completed.
        if let Ok(mut state) = self.state.lock() {
            if state.owner == Some(self.host.id()) { state.owner = None; }
        }
        self.owns_lease = false;
        self.cleanup_failed = false;
        Ok(())
    }
}
impl<B: InputBackend> Drop for ControlledSession<B> {
    fn drop(&mut self) {
        if !self.owns_lease { return; }
        if self.host.close().is_err() { self.cleanup_failed = true; }
        if let Ok(mut state) = self.state.lock() {
            if state.owner == Some(self.host.id()) {
                state.owner = None;
                if self.cleanup_failed { state.quarantine = true; }
            }
        }
        self.owns_lease = false;
    }
}
