//! Opt-in Windows-style modifier input for cooperating, guarded sessions.
//!
//! This is intentionally narrower than the source service: it never reads or
//! releases the real global OS modifier state, never temporarily synthesizes a
//! missing modifier, and refuses an event if its modifier list disagrees with
//! keys held by this controller. Thus it can reject ordinary RustDesk traffic,
//! especially after lost events, AltGr or human input. It has not been tested.
//! The caller must ensure exclusive OS input and trusted local authorization.

use crate::{windows_keyboard, windows_mouse, HostInputError, HostInputSession};
use remote_input::{InputBackend, VirtualKey};
use remote_protocol::{Envelope, KeyboardPayload, ProtocolError};
use std::{error::Error, fmt};

/// Restricted dispatch failure; no attempt is made to infer missing key state.
#[derive(Debug)]
pub enum ErrorKind {
    Protocol(ProtocolError),
    Host(HostInputError),
    Mouse(windows_mouse::DispatchError),
    Unsupported(&'static str),
    ModifierMismatch,
}
impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "input protocol: {e}"), Self::Host(e) => write!(f, "host input: {e}"),
            Self::Mouse(e) => write!(f, "mouse: {e}"), Self::Unsupported(e) => write!(f, "unsupported input: {e}"),
            Self::ModifierMismatch => f.write_str("wire modifiers do not match tracked input"),
        }
    }
}
impl Error for ErrorKind {}
impl From<ProtocolError> for ErrorKind { fn from(e: ProtocolError) -> Self { Self::Protocol(e) } }
impl From<HostInputError> for ErrorKind { fn from(e: HostInputError) -> Self { Self::Host(e) } }

// Pinned source ControlKey numbers and Windows Enigo key map.
const MODIFIERS: [(i32, u16); 8] = [(1, 0x12), (4, 0xa2), (23, 0x5b), (29, 0x10),
    (64, 0x5c), (73, 0xa1), (74, 0xa3), (75, 0xa5)];
fn modifier(value: i32) -> Option<VirtualKey> {
    MODIFIERS.iter().find(|(id, _)| *id == value).and_then(|(_, code)| VirtualKey::new(*code).ok())
}
/// Verify every listed modifier is held and no tracked modifier was omitted,
/// except the modifier that the current key event itself is changing. This is
/// local bookkeeping, not proof of the OS input device state.
fn check<B: InputBackend>(host: &HostInputSession<B>, values: impl Iterator<Item = i32>, changing: Option<VirtualKey>) -> Result<(), ErrorKind> {
    let mut seen = [false; MODIFIERS.len()];
    for value in values {
        let index = MODIFIERS.iter().position(|(id, _)| *id == value).ok_or(ErrorKind::Unsupported("unknown or lock modifier"))?;
        if seen[index] { return Err(ErrorKind::ModifierMismatch); }
        seen[index] = true;
    }
    for (index, (_, code)) in MODIFIERS.iter().enumerate() {
        let key = VirtualKey::new(*code).map_err(|_| ErrorKind::ModifierMismatch)?;
        if Some(key) == changing { continue; }
        if host.input.is_key_held(key) != seen[index] { return Err(ErrorKind::ModifierMismatch); }
    }
    Ok(())
}

/// Dispatch one legacy control key, including explicitly held modifiers.
/// Character/sequence/scan-code/system actions remain outside this subset.
pub fn keyboard<B: InputBackend>(host: &mut HostInputSession<B>, envelope: &Envelope) -> Result<(), ErrorKind> {
    host.session.check(remote_session::Action::ControlKeyboard).map_err(HostInputError::from)?;
    let event = envelope.keyboard()?;
    if event.mode() != 0 { return Err(ErrorKind::Unsupported("non-legacy keyboard mode")); }
    let value = match event.payload() { Some(KeyboardPayload::ControlKey(value)) => value, _ => return Err(ErrorKind::Unsupported("non-control-key payload")) };
    let changing = modifier(value);
    check(host, event.modifiers(), changing)?;
    let key = match changing {
        Some(key) => key,
        None => VirtualKey::new(windows_keyboard::plain_control_vk(value).ok_or(ErrorKind::Unsupported("unknown or privileged control key"))?)
            .map_err(|_| ErrorKind::Unsupported("invalid virtual key"))?,
    };
    if event.press() { host.key_press(key)?; } else if event.down() { host.key_down(key)?; } else { host.key_up(key)?; }
    Ok(())
}

/// Dispatch a mouse event only if all modifiers are already tracked by this
/// controller and keyboard as well as mouse control is authorized. This does
/// not duplicate the source's temporary modifier synthesis or global fixups.
pub fn mouse<B: InputBackend>(host: &mut HostInputSession<B>, envelope: &Envelope) -> Result<(), ErrorKind> {
    host.session.check(remote_session::Action::ControlMouse).map_err(HostInputError::from)?;
    host.session.check(remote_session::Action::ControlKeyboard).map_err(HostInputError::from)?;
    check(host, envelope.mouse_modifiers()?, None)?;
    let event = envelope.mouse()?;
    // Strip the already-validated modifier list; source bit mask is unchanged.
    windows_mouse::dispatch(host, &Envelope::mouse_event(event)).map_err(ErrorKind::Mouse)
}
