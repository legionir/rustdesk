//! Experimental, transport-independent session lifecycle and authorization guard.
//!
//! This crate supplies no authenticator, cryptography, networking, persistent
//! session-ID registry, or consent UI. A trusted embedding application must
//! supply those components and bind the authenticated identity to a secure
//! transport. This is not a complete remote desktop session implementation.

use std::{error::Error, fmt};

/// Maximum number of teardown resources attached to a session.
pub const MAX_RESOURCES: usize = 32;
/// Maximum UTF-8 byte length of an authenticated principal name.
pub const MAX_PRINCIPAL_BYTES: usize = 256;

/// Opaque session identifier supplied by the application.
///
/// Identifiers must be generated securely and checked for uniqueness by the
/// session manager. Constructing this value does not provide those properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);
impl SessionId {
    /// Wrap an externally generated identifier. The all-zero identifier is rejected.
    pub fn new(bytes: [u8; 16]) -> Result<Self, SessionError> {
        if bytes.iter().all(|byte| *byte == 0) { return Err(SessionError::InvalidId); }
        Ok(Self(bytes))
    }
    /// Return the identifier bytes.
    pub fn as_bytes(&self) -> &[u8; 16] { &self.0 }
}

/// Session lifecycle state. State changes are explicit and one-way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Constructed but no connection attempt started.
    Created,
    /// Transport connection is being established.
    Connecting,
    /// The peer is awaiting authentication and owner authorization.
    Authenticating,
    /// Authenticated and authorized, but capture has not started.
    Connected,
    /// Screen streaming is active.
    Streaming,
    /// Permissions are revoked and resources are being released.
    Disconnecting,
    /// Resources were released and the session is closed.
    Closed,
    /// Connection or authorization failed; resource cleanup is still required.
    Failed,
}

/// Capabilities approved for a session. Defaults to no access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Permissions {
    /// Receive screen frames.
    pub view_screen: bool,
    /// Send mouse input.
    pub control_mouse: bool,
    /// Send keyboard input.
    pub control_keyboard: bool,
    /// Select a display.
    pub change_display: bool,
    /// Request session termination.
    pub disconnect_session: bool,
}
impl Permissions {
    fn intersect(self, other: Self) -> Self {
        Self {
            view_screen: self.view_screen && other.view_screen,
            control_mouse: self.control_mouse && other.control_mouse,
            control_keyboard: self.control_keyboard && other.control_keyboard,
            change_display: self.change_display && other.change_display,
            disconnect_session: self.disconnect_session && other.disconnect_session,
        }
    }
}

/// Individual action checked against session permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// View the desktop.
    ViewScreen,
    /// Control mouse.
    ControlMouse,
    /// Control keyboard.
    ControlKeyboard,
    /// Change the displayed monitor.
    ChangeDisplay,
    /// Ask to terminate the session.
    DisconnectSession,
}

/// Verified identity returned by the application's trusted authenticator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal(String);
impl Principal {
    /// Validate a non-empty identity returned by the authentication backend.
    pub fn new(identity: String) -> Result<Self, SessionError> {
        if identity.is_empty() || identity.len() > MAX_PRINCIPAL_BYTES || identity.chars().any(char::is_control) {
            return Err(SessionError::InvalidPrincipal);
        }
        Ok(Self(identity))
    }
    /// Access the authenticated identity.
    pub fn as_str(&self) -> &str { &self.0 }
}

/// Sensitive authentication evidence borrowed from the caller.
///
/// The session does not retain a copy. The caller is responsible for secure
/// storage, expiration, replay prevention, and zeroization.
pub struct Credential<'a>(&'a [u8]);
impl<'a> Credential<'a> {
    /// Borrow an authentication credential.
    pub fn new(bytes: &'a [u8]) -> Self { Self(bytes) }
    /// Access evidence for verification by a trusted authenticator.
    pub fn as_bytes(&self) -> &'a [u8] { self.0 }
}

/// Authentication provided by the embedding application.
///
/// Implementations must validate authenticity, expiration, replay and binding
/// to the actual transport as appropriate. Return `None` on refusal. This
/// synchronous interface must not be used for blocking network calls.
pub trait Authenticator {
    /// Verify evidence and return the authenticated principal, or refuse it.
    fn authenticate(&mut self, session: SessionId, evidence: Credential<'_>) -> Result<Option<Principal>, Box<dyn Error + Send + Sync>>;
}

/// Host-side owner approval and policy decision supplied by the application.
///
/// `None` denies the connection. A returned permission set is intersected
/// with the client's requested permissions. This interface is synchronous:
/// obtain user consent before invoking it or use a nonblocking policy cache.
pub trait Authorizer {
    /// Decide whether the principal may connect and which capabilities to grant.
    fn authorize(&mut self, session: SessionId, principal: &Principal, requested: Permissions) -> Result<Option<Permissions>, Box<dyn Error + Send + Sync>>;
}

/// A resource that can be shut down when a session closes.
///
/// Cleanup must be idempotent because failures are retried on subsequent close.
/// Do not rely on this interface for cleanup after process abort or power loss.
pub trait SessionResource: Send {
    /// Release resource ownership and stop any background operations.
    fn shutdown(&mut self) -> Result<(), Box<dyn Error + Send + Sync>>;
}

/// Session operation failed.
#[derive(Debug)]
pub enum SessionError {
    /// The session identifier was invalid.
    InvalidId,
    /// The identity supplied by an authenticator was invalid.
    InvalidPrincipal,
    /// The operation is not allowed in the current state.
    InvalidState { state: SessionState, operation: &'static str },
    /// Required permission has not been granted.
    PermissionDenied,
    /// Authentication was refused.
    AuthenticationDenied,
    /// Owner or policy denied this connection.
    AuthorizationDenied,
    /// Trusted authentication or authorization provider returned an error.
    Provider(Box<dyn Error + Send + Sync>),
    /// Resource count exceeds the session limit.
    ResourceLimit,
    /// Resource cleanup failed. The session remains disconnecting for retry.
    Cleanup(Box<dyn Error + Send + Sync>),
}
impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId => f.write_str("invalid session ID"),
            Self::InvalidPrincipal => f.write_str("invalid authenticated principal"),
            Self::InvalidState { state, operation } => write!(f, "cannot {operation} in state {state:?}"),
            Self::PermissionDenied => f.write_str("session permission denied"),
            Self::AuthenticationDenied => f.write_str("authentication denied"),
            Self::AuthorizationDenied => f.write_str("authorization denied"),
            Self::Provider(_) => f.write_str("authentication or authorization provider failed"),
            Self::ResourceLimit => f.write_str("session resource limit exceeded"),
            Self::Cleanup(_) => f.write_str("session resource cleanup failed"),
        }
    }
}
impl Error for SessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self { Self::Provider(e) | Self::Cleanup(e) => Some(e.as_ref()), _ => None }
    }
}

/// State for one session, independent of transport and platform types.
///
/// A `Session` alone does not start capture or enforce input permissions at the
/// OS boundary. Dispatchers must call [`Session::check`] for every operation,
/// and arrange immediate resource cleanup on disconnect.
pub struct Session {
    id: SessionId,
    state: SessionState,
    principal: Option<Principal>,
    permissions: Permissions,
    resources: Vec<Box<dyn SessionResource>>,
}
impl Session {
    /// Create a session with no permissions and no authenticated identity.
    pub fn new(id: SessionId) -> Self {
        Self { id, state: SessionState::Created, principal: None, permissions: Permissions::default(), resources: Vec::new() }
    }
    /// Session identifier.
    pub fn id(&self) -> SessionId { self.id }
    /// Current lifecycle state.
    pub fn state(&self) -> SessionState { self.state }
    /// Current permissions. They are cleared before cleanup begins.
    pub fn permissions(&self) -> Permissions { self.permissions }
    /// Authenticated principal, if authorization has completed successfully.
    pub fn principal(&self) -> Option<&Principal> { self.principal.as_ref() }

    fn require(&self, state: SessionState, operation: &'static str) -> Result<(), SessionError> {
        if self.state == state { Ok(()) } else { Err(SessionError::InvalidState { state: self.state, operation }) }
    }

    /// Start establishing a connection.
    pub fn begin_connect(&mut self) -> Result<(), SessionError> {
        self.require(SessionState::Created, "begin connecting")?;
        self.state = SessionState::Connecting;
        Ok(())
    }
    /// Record that a transport is connected; the peer remains unauthorized.
    pub fn transport_connected(&mut self) -> Result<(), SessionError> {
        self.require(SessionState::Connecting, "mark transport connected")?;
        self.state = SessionState::Authenticating;
        Ok(())
    }

    /// Authenticate the peer and obtain host approval. Both decisions must succeed.
    ///
    /// Refusal or provider error moves the session to `Failed` with no granted
    /// permissions. Call `close` afterwards to release attached resources.
    pub fn authenticate<A: Authenticator, P: Authorizer>(
        &mut self, evidence: Credential<'_>, requested: Permissions, auth: &mut A, policy: &mut P,
    ) -> Result<(), SessionError> {
        self.require(SessionState::Authenticating, "authenticate")?;
        let principal = match auth.authenticate(self.id, evidence) {
            Ok(Some(principal)) => principal,
            Ok(None) => { self.state = SessionState::Failed; return Err(SessionError::AuthenticationDenied); },
            Err(e) => { self.state = SessionState::Failed; return Err(SessionError::Provider(e)); },
        };
        let granted = match policy.authorize(self.id, &principal, requested) {
            Ok(Some(granted)) => granted,
            Ok(None) => { self.state = SessionState::Failed; return Err(SessionError::AuthorizationDenied); },
            Err(e) => { self.state = SessionState::Failed; return Err(SessionError::Provider(e)); },
        };
        self.permissions = requested.intersect(granted);
        self.principal = Some(principal);
        self.state = SessionState::Connected;
        Ok(())
    }
    /// Mark streaming started after the caller starts its capture pipeline.
    pub fn start_streaming(&mut self) -> Result<(), SessionError> {
        self.require(SessionState::Connected, "start streaming")?;
        self.check(Action::ViewScreen)?;
        self.state = SessionState::Streaming;
        Ok(())
    }
    /// Stop streaming while keeping the authorized session connected.
    pub fn stop_streaming(&mut self) -> Result<(), SessionError> {
        self.require(SessionState::Streaming, "stop streaming")?;
        self.state = SessionState::Connected;
        Ok(())
    }
    /// Check an action before dispatching it to capture or input.
    pub fn check(&self, action: Action) -> Result<(), SessionError> {
        if !matches!(self.state, SessionState::Connected | SessionState::Streaming) { return Err(SessionError::PermissionDenied); }
        let allowed = match action {
            Action::ViewScreen => self.permissions.view_screen,
            Action::ControlMouse => self.permissions.control_mouse,
            Action::ControlKeyboard => self.permissions.control_keyboard,
            Action::ChangeDisplay => self.permissions.change_display,
            Action::DisconnectSession => self.permissions.disconnect_session,
        };
        if allowed { Ok(()) } else { Err(SessionError::PermissionDenied) }
    }
    /// Restrict current permissions. This cannot grant previously denied access.
    ///
    /// When view permission is revoked, this changes `Streaming` to `Connected`;
    /// the caller must also stop any actual capture or delivery tasks immediately.
    pub fn restrict_permissions(&mut self, allowed: Permissions) -> Result<(), SessionError> {
        if !matches!(self.state, SessionState::Connected | SessionState::Streaming) {
            return Err(SessionError::InvalidState { state: self.state, operation: "restrict permissions" });
        }
        self.permissions = self.permissions.intersect(allowed);
        if !self.permissions.view_screen && self.state == SessionState::Streaming { self.state = SessionState::Connected; }
        Ok(())
    }
    /// Attach an owned resource for later cleanup, up to `MAX_RESOURCES`.
    pub fn add_resource(&mut self, resource: Box<dyn SessionResource>) -> Result<(), SessionError> {
        if matches!(self.state, SessionState::Disconnecting | SessionState::Closed | SessionState::Failed) {
            return Err(SessionError::InvalidState { state: self.state, operation: "add resource" });
        }
        if self.resources.len() >= MAX_RESOURCES { return Err(SessionError::ResourceLimit); }
        self.resources.push(resource);
        Ok(())
    }
    /// Mark a nonterminal session failed and revoke its capabilities immediately.
    /// Call `close` to release resources.
    pub fn fail(&mut self) -> Result<(), SessionError> {
        if matches!(self.state, SessionState::Disconnecting | SessionState::Closed | SessionState::Failed) {
            return Err(SessionError::InvalidState { state: self.state, operation: "fail" });
        }
        self.permissions = Permissions::default();
        self.principal = None;
        self.state = SessionState::Failed;
        Ok(())
    }
    /// Revoke access and release resources in reverse registration order.
    ///
    /// All resources are attempted even if one fails. Successfully shut down
    /// resources are removed; failed resources remain for a later retry. This
    /// synchronous method cannot cancel async tasks unless their resource
    /// implementation signals and manages them explicitly.
    pub fn close(&mut self) -> Result<(), SessionError> {
        if self.state == SessionState::Closed { return Ok(()); }
        self.state = SessionState::Disconnecting;
        self.permissions = Permissions::default();
        self.principal = None;
        let mut first_error = None;
        for index in (0..self.resources.len()).rev() {
            match self.resources[index].shutdown() {
                Ok(()) => { self.resources.remove(index); },
                Err(error) => if first_error.is_none() { first_error = Some(error); },
            }
        }
        if let Some(error) = first_error { return Err(SessionError::Cleanup(error)); }
        self.state = SessionState::Closed;
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) { let _ = self.close(); }
}

/// Upper bound on simultaneously retained sessions in one manager.
pub const MAX_MANAGED_SESSIONS: usize = 4096;
/// Upper bound on identifiers remembered by one manager during its lifetime.
pub const MAX_REMEMBERED_IDS: usize = 65536;

/// Errors from the session registry.
#[derive(Debug)]
pub enum ManagerError {
    /// The identifier is already active or has previously been used by this manager.
    DuplicateId,
    /// The active session capacity has been reached.
    ActiveLimit,
    /// The remembered identifier capacity has been reached.
    IdHistoryLimit,
    /// No active session has the requested identifier.
    NotFound,
    /// A session could not release all its resources.
    Session(SessionError),
}
impl fmt::Display for ManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateId => f.write_str("session ID already used"),
            Self::ActiveLimit => f.write_str("active session limit reached"),
            Self::IdHistoryLimit => f.write_str("session ID history limit reached"),
            Self::NotFound => f.write_str("session not found"),
            Self::Session(error) => write!(f, "session: {error}"),
        }
    }
}
impl Error for ManagerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self { Self::Session(error) => Some(error), _ => None }
    }
}

/// Bounded registry of sessions and identifiers used during this manager's lifetime.
///
/// This registry is not durable. A process restart loses its history, so it is
/// not by itself replay protection. Callers must generate unpredictable IDs,
/// enforce persistent anti-replay where required, and serialize access to this
/// value. No background task or global state is created.
pub struct SessionManager {
    active: std::collections::HashMap<SessionId, Session>,
    used: std::collections::HashSet<SessionId>,
    active_limit: usize,
    history_limit: usize,
}
impl SessionManager {
    /// Create a manager with explicit bounds. Zero and excessive limits are refused.
    pub fn new(active_limit: usize, history_limit: usize) -> Result<Self, ManagerError> {
        if active_limit == 0 || active_limit > MAX_MANAGED_SESSIONS { return Err(ManagerError::ActiveLimit); }
        if history_limit == 0 || history_limit > MAX_REMEMBERED_IDS || history_limit < active_limit { return Err(ManagerError::IdHistoryLimit); }
        Ok(Self { active: std::collections::HashMap::new(), used: std::collections::HashSet::new(), active_limit, history_limit })
    }
    /// Create a session using a caller-generated identifier, refusing reuse.
    pub fn create(&mut self, id: SessionId) -> Result<&mut Session, ManagerError> {
        if self.used.contains(&id) { return Err(ManagerError::DuplicateId); }
        if self.active.len() >= self.active_limit { return Err(ManagerError::ActiveLimit); }
        if self.used.len() >= self.history_limit { return Err(ManagerError::IdHistoryLimit); }
        self.used.insert(id);
        Ok(self.active.entry(id).or_insert_with(|| Session::new(id)))
    }
    /// Access an existing session.
    pub fn get(&self, id: SessionId) -> Option<&Session> { self.active.get(&id) }
    /// Mutably access an existing session.
    pub fn get_mut(&mut self, id: SessionId) -> Option<&mut Session> { self.active.get_mut(&id) }
    /// Number of retained sessions, including those awaiting cleanup retry.
    pub fn len(&self) -> usize { self.active.len() }
    /// Whether there are no retained sessions.
    pub fn is_empty(&self) -> bool { self.active.is_empty() }
    /// Close and remove a session only after all its resources have shut down.
    /// If cleanup fails, the session remains in the registry for retry.
    pub fn close(&mut self, id: SessionId) -> Result<(), ManagerError> {
        self.active.get_mut(&id).ok_or(ManagerError::NotFound)?.close().map_err(ManagerError::Session)?;
        self.active.remove(&id);
        Ok(())
    }
    /// Attempt to close all sessions. Returns the first failure after attempting
    /// every session; failed sessions remain registered for later retry.
    pub fn close_all(&mut self) -> Result<(), ManagerError> {
        let ids: Vec<SessionId> = self.active.keys().copied().collect();
        let mut first_error = None;
        for id in ids {
            if let Err(error) = self.close(id) {
                if first_error.is_none() { first_error = Some(error); }
            }
        }
        match first_error { Some(error) => Err(error), None => Ok(()) }
    }
}
