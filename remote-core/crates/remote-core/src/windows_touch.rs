//! Opt-in subset of the source Windows touch-scale behavior.
//!
//! The source holds Control while injecting raw vertical scroll, then releases
//! it on a zero-scale message. This adapter requires *both* local mouse and
//! keyboard permissions, limits deltas, refuses modifier metadata and pan, and
//! refuses to begin with any controller-tracked key held. It does not query or
//! own OS-global keyboard state, handle secure desktop/portable service, or
//! guarantee cleanup after process termination. Caller must serialize ALL input
//! and ensure exclusive OS input ownership while a gesture is active.
use crate::{HostInputError, HostInputSession};
use remote_input::{InputBackend, VirtualKey};
use remote_protocol::{pointer::{PointerError, Touch}, Envelope};
use remote_session::Action;
use std::{error::Error, fmt};

const MAX_SCALE_DELTA: i32 = 12_000;
#[derive(Debug)]
pub enum TouchError { Pointer(PointerError), Host(HostInputError), Unsupported, ConflictingInput, InvalidScale }
impl fmt::Display for TouchError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Windows touch scale: {self:?}") } }
impl Error for TouchError {}
impl From<HostInputError> for TouchError { fn from(e: HostInputError) -> Self { Self::Host(e) } }

/// Gesture state for exactly one controller/session. Do not share across
/// sessions or drop without ending the gesture or closing its input controller.
pub struct TouchScale { active: bool }
impl TouchScale {
    pub fn new() -> Self { Self { active: false } }
    pub fn active(&self) -> bool { self.active }
    /// Apply an existing source touch-scale envelope. A zero ends the tracked
    /// gesture; repeated nonzero messages do not inject repeated Control downs.
    /// A backend failure must cause the owner to close and retry cleanup.
    pub fn dispatch<B: InputBackend>(&mut self, host: &mut HostInputSession<B>, event: &Envelope) -> Result<(), TouchError> {
        host.session.check(Action::ControlMouse).map_err(HostInputError::from)?;
        host.session.check(Action::ControlKeyboard).map_err(HostInputError::from)?;
        let pointer = event.pointer_event().map_err(TouchError::Pointer)?;
        if !pointer.modifiers.is_empty() { return Err(TouchError::Unsupported); }
        let scale = match pointer.touch { Touch::Scale(value) => value, _ => return Err(TouchError::Unsupported) };
        if !(-MAX_SCALE_DELTA..=MAX_SCALE_DELTA).contains(&scale) { return Err(TouchError::InvalidScale); }
        let control = VirtualKey::new(0xa2).map_err(|_| TouchError::Unsupported)?;
        if scale == 0 {
            if self.active { host.key_up(control)?; self.active = false; }
        } else {
            if !self.active {
                if host.input.has_held_keyboard() { return Err(TouchError::ConflictingInput); }
                // Track before injection because a reported failure may still
                // have delivered the key. The caller closes on Host errors.
                self.active = true;
                host.key_down(control)?;
            }
            host.scroll(0, scale)?;
        }
        Ok(())
    }
    /// End before revoking either permission, while both remain authorized.
    /// A failed key-up retains both the tracked key and active flag for retry.
    pub fn end<B: InputBackend>(&mut self, host: &mut HostInputSession<B>) -> Result<(), TouchError> {
        if self.active {
            let control = VirtualKey::new(0xa2).map_err(|_| TouchError::Unsupported)?;
            host.key_up(control)?; self.active = false;
        }
        Ok(())
    }
}
impl Default for TouchScale { fn default() -> Self { Self::new() } }
