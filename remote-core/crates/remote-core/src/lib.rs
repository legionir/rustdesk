//! Experimental integration of the session guard and input controller.
//!
//! This is not yet the final RemoteCore facade. It does not provide secure
//! networking, credential validation, session-ID generation, a viewer, or
//! capture task orchestration. It must not be exposed to untrusted peers until
//! those layers and OS-level authorization have been reviewed and tested.

use std::{error::Error, fmt};
use remote_input::{InputBackend, InputController, InputError, MouseButton, VirtualKey};
use remote_session::{Action, Authenticator, Authorizer, Credential, Permissions, Session, SessionError, SessionId, SessionState};

/// Error returned by the session guard or input backend.
#[derive(Debug)]
pub enum HostInputError {
    /// Session state, authentication, or permission failure.
    Session(SessionError),
    /// Input permission, state, or backend failure.
    Input(InputError),
    /// Both input and session cleanup failed.
    Cleanup { input: InputError, session: SessionError },
}
impl fmt::Display for HostInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(error) => write!(f, "session: {error}"),
            Self::Input(error) => write!(f, "input: {error}"),
            Self::Cleanup { input, session } => write!(f, "input cleanup: {input}; session cleanup: {session}"),
        }
    }
}
impl Error for HostInputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self { Self::Session(error) => Some(error), Self::Input(error) => Some(error), Self::Cleanup { .. } => None }
    }
}
impl From<SessionError> for HostInputError { fn from(error: SessionError) -> Self { Self::Session(error) } }
impl From<InputError> for HostInputError { fn from(error: InputError) -> Self { Self::Input(error) } }

/// Coordinates an input controller with one session's capability checks.
///
/// Ownership of the backend is exclusive only within this value. The host must
/// still serialize input across sessions and control all other paths that can
/// instantiate an input backend. The wrapped RustDesk Enigo implementation
/// cannot report all OS delivery and release errors.
pub struct HostInputSession<B: InputBackend> {
    session: Session,
    input: InputController<B>,
}
impl<B: InputBackend> HostInputSession<B> {
    /// Construct a session and input controller with all permissions denied.
    pub fn new(id: SessionId, backend: B) -> Self {
        Self { session: Session::new(id), input: InputController::new(backend) }
    }
    /// Current session identifier.
    pub fn id(&self) -> SessionId { self.session.id() }
    /// Current lifecycle state.
    pub fn state(&self) -> SessionState { self.session.state() }
    /// Current session permissions.
    pub fn permissions(&self) -> Permissions { self.session.permissions() }
    /// Mark the beginning of a connection attempt.
    pub fn begin_connect(&mut self) -> Result<(), HostInputError> { self.session.begin_connect()?; Ok(()) }
    /// Mark a transport connected, without granting input privileges.
    pub fn transport_connected(&mut self) -> Result<(), HostInputError> { self.session.transport_connected()?; Ok(()) }
    /// Authenticate and obtain host authorization before activating input.
    ///
    /// `auth` and `policy` are trusted providers; this method implements no
    /// token verification, transport binding, replay protection or UI consent.
    pub fn authenticate<A: Authenticator, P: Authorizer>(
        &mut self, credential: Credential<'_>, requested: Permissions, auth: &mut A, policy: &mut P,
    ) -> Result<(), HostInputError> {
        self.session.authenticate(credential, requested, auth, policy)?;
        let allowed = self.session.permissions();
        if let Err(error) = self.input.set_permissions(remote_input::Permissions {
            mouse: allowed.control_mouse, keyboard: allowed.control_keyboard,
        }) {
            let _ = self.session.fail();
            return Err(HostInputError::Input(error));
        }
        Ok(())
    }
    /// Restrict privileges and release inputs affected by revocation.
    ///
    /// On detectable release failure, the session is marked Failed. Call
    /// `close` to retry cleanup; OS-level releases may still be unverifiable.
    pub fn restrict_permissions(&mut self, permissions: Permissions) -> Result<(), HostInputError> {
        self.session.restrict_permissions(permissions)?;
        let allowed = self.session.permissions();
        if let Err(error) = self.input.set_permissions(remote_input::Permissions {
            mouse: allowed.control_mouse, keyboard: allowed.control_keyboard,
        }) {
            let _ = self.session.fail();
            return Err(HostInputError::Input(error));
        }
        Ok(())
    }
    /// Move the mouse in virtual-desktop coordinates, after authorization.
    pub fn move_to(&mut self, x: i32, y: i32) -> Result<(), HostInputError> {
        self.session.check(Action::ControlMouse)?;
        self.input.move_to(x, y)?;
        Ok(())
    }
    /// Press a mouse button, after authorization.
    pub fn mouse_down(&mut self, button: MouseButton) -> Result<(), HostInputError> {
        self.session.check(Action::ControlMouse)?;
        self.input.mouse_down(button)?;
        Ok(())
    }
    /// Release a mouse button, after authorization.
    pub fn mouse_up(&mut self, button: MouseButton) -> Result<(), HostInputError> {
        self.session.check(Action::ControlMouse)?;
        self.input.mouse_up(button)?;
        Ok(())
    }
    /// Click a mouse button, after authorization.
    pub fn click(&mut self, button: MouseButton) -> Result<(), HostInputError> {
        self.session.check(Action::ControlMouse)?;
        self.input.click(button)?;
        Ok(())
    }
    /// Scroll in backend-defined units, after authorization.
    pub fn scroll(&mut self, x: i32, y: i32) -> Result<(), HostInputError> {
        self.session.check(Action::ControlMouse)?;
        self.input.scroll(x, y)?;
        Ok(())
    }
    /// Press a Windows virtual key, after authorization.
    pub fn key_down(&mut self, key: VirtualKey) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?;
        self.input.key_down(key)?;
        Ok(())
    }
    /// Release a Windows virtual key, after authorization.
    pub fn key_up(&mut self, key: VirtualKey) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?;
        self.input.key_up(key)?;
        Ok(())
    }
    /// Press and release a Windows virtual key, after authorization.
    pub fn key_press(&mut self, key: VirtualKey) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?;
        self.input.key_press(key)?;
        Ok(())
    }
    /// Revoke access and attempt both input and session cleanup.
    ///
    /// Both paths are attempted even when one fails; calling again retries
    /// detectable input or resource cleanup errors.
    pub fn close(&mut self) -> Result<(), HostInputError> {
        let input = self.input.close();
        let session = self.session.close();
        match (input, session) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(input), Ok(())) => Err(HostInputError::Input(input)),
            (Ok(()), Err(session)) => Err(HostInputError::Session(session)),
            (Err(input), Err(session)) => Err(HostInputError::Cleanup { input, session }),
        }
    }
}
