//! Experimental per-controller input state and Windows Enigo adapter.
//!
//! This module does not authenticate a caller. Only a trusted session manager
//! may grant permissions or construct a backend. Callers must serialize access
//! to the OS input device and enforce a single controlling session: independent
//! controllers can otherwise release each other's keys. Explicitly call `close`
//! on disconnect; `Drop` only provides best-effort cleanup.

use std::{fmt, io};

/// Input permissions. Default denies all input.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Permissions {
    /// Allow mouse movement, buttons, and scrolling.
    pub mouse: bool,
    /// Allow keyboard events.
    pub keyboard: bool,
}

/// Mouse buttons supported by this adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    /// Primary button.
    Left,
    /// Secondary button.
    Right,
    /// Middle button.
    Middle,
    /// Browser/back extra button.
    Back,
    /// Browser/forward extra button.
    Forward,
}

/// A Windows virtual-key code. This is not a hardware scan code or Unicode text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualKey(u16);

impl VirtualKey {
    /// Validate a Windows virtual-key code, excluding zero and values above 0xfe.
    pub fn new(code: u16) -> io::Result<Self> {
        if !(1..=0xfe).contains(&code) { return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid virtual key")); }
        Ok(Self(code))
    }
    /// The Windows virtual-key code.
    pub fn code(self) -> u16 { self.0 }
}

/// Restricted Windows physical scan code matching the source rdev encoding.
/// Only nonzero one-byte codes with optional E0/E1 prefix are accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanCode(u16);
impl ScanCode {
    pub fn new(code: u32) -> io::Result<Self> {
        let high = code >> 8; let low = code & 0xff;
        if low == 0 || !matches!(high, 0 | 0xe0 | 0xe1) { return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported scan code")); }
        Ok(Self(code as u16))
    }
    pub fn code(self) -> u16 { self.0 }
}

/// Operations required of a local input backend.
///
/// `key_up` and `mouse_up` must return an error when the backend can detect a
/// failure. The RustDesk Enigo adapter cannot detect all release failures.
pub trait InputBackend {
    /// Move to a virtual-desktop coordinate.
    fn move_to(&mut self, x: i32, y: i32) -> io::Result<()>;
    /// Move by relative pixel deltas. Backends may decline this operation.
    fn move_relative(&mut self, _x: i32, _y: i32) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "relative mouse movement not supported"))
    }
    /// Press a mouse button.
    fn mouse_down(&mut self, button: MouseButton) -> io::Result<()>;
    /// Release a mouse button.
    fn mouse_up(&mut self, button: MouseButton) -> io::Result<()>;
    /// Scroll by backend-defined horizontal and vertical units.
    fn scroll(&mut self, x: i32, y: i32) -> io::Result<()>;
    /// Press a Windows virtual key.
    fn key_down(&mut self, key: VirtualKey) -> io::Result<()>;
    /// Release a Windows virtual key.
    fn key_up(&mut self, key: VirtualKey) -> io::Result<()>;
    /// Press/release a source-style physical scan code; unsupported by default.
    fn scan_down(&mut self, _code: ScanCode) -> io::Result<()> { Err(io::Error::new(io::ErrorKind::Unsupported, "scan-code input unsupported")) }
    fn scan_up(&mut self, _code: ScanCode) -> io::Result<()> { Err(io::Error::new(io::ErrorKind::Unsupported, "scan-code input unsupported")) }
    /// Source rdev raw Windows virtual-key path, separate from Enigo keys.
    fn raw_virtual_down(&mut self, _key: VirtualKey) -> io::Result<()> { Err(io::Error::new(io::ErrorKind::Unsupported, "raw virtual-key input unsupported")) }
    fn raw_virtual_up(&mut self, _key: VirtualKey) -> io::Result<()> { Err(io::Error::new(io::ErrorKind::Unsupported, "raw virtual-key input unsupported")) }
    /// Inject a text sequence, if supported by the backend.
    fn type_text(&mut self, _text: &str) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "text input not supported"))
    }
}

/// Errors from permission checks, lifecycle, or the input backend.
#[derive(Debug)]
pub enum InputError {
    /// Input of this type was not authorized.
    PermissionDenied,
    /// The controller has been closed.
    Closed,
    /// A click/press was requested while that button/key is held.
    AlreadyPressed,
    /// Input backend failed.
    Backend(io::Error),
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied => f.write_str("input permission denied"),
            Self::Closed => f.write_str("input controller is closed"),
            Self::AlreadyPressed => f.write_str("input is already pressed"),
            Self::Backend(error) => write!(f, "input backend: {error}"),
        }
    }
}
impl std::error::Error for InputError {}
impl From<io::Error> for InputError { fn from(e: io::Error) -> Self { Self::Backend(e) } }

/// State owned by one controlling session. Not a security or concurrency boundary.
pub struct InputController<B: InputBackend> {
    backend: B,
    permissions: Permissions,
    keys: Vec<VirtualKey>,
    scans: Vec<ScanCode>,
    raw_keys: Vec<VirtualKey>,
    buttons: Vec<MouseButton>,
    closed: bool,
}

impl<B: InputBackend> InputController<B> {
    /// Construct a controller with all permissions denied.
    pub fn new(backend: B) -> Self {
        Self { backend, permissions: Permissions::default(), keys: Vec::new(), scans: Vec::new(), raw_keys: Vec::new(), buttons: Vec::new(), closed: false }
    }

    /// Current permissions.
    pub fn permissions(&self) -> Permissions { self.permissions }

    /// Update permissions. Revocation immediately denies new input and attempts
    /// to release affected held inputs. Failures remain tracked for later retry.
    pub fn set_permissions(&mut self, permissions: Permissions) -> Result<(), InputError> {
        if self.closed { return Err(InputError::Closed); }
        self.permissions = permissions;
        self.release(!permissions.keyboard, !permissions.mouse)
    }

    fn allowed(&self, granted: bool) -> Result<(), InputError> {
        if self.closed { Err(InputError::Closed) } else if !granted { Err(InputError::PermissionDenied) } else { Ok(()) }
    }

    /// Move in virtual desktop coordinates. Monitor-relative mapping is the caller's responsibility.
    pub fn move_to(&mut self, x: i32, y: i32) -> Result<(), InputError> {
        self.allowed(self.permissions.mouse)?;
        self.backend.move_to(x, y)?;
        Ok(())
    }
    /// Move by relative pixel deltas, after checking mouse permission.
    pub fn move_relative(&mut self, x: i32, y: i32) -> Result<(), InputError> {
        self.allowed(self.permissions.mouse)?;
        self.backend.move_relative(x, y)?;
        Ok(())
    }
    /// Send horizontal and vertical scroll deltas in backend units.
    pub fn scroll(&mut self, x: i32, y: i32) -> Result<(), InputError> {
        self.allowed(self.permissions.mouse)?;
        self.backend.scroll(x, y)?;
        Ok(())
    }
    /// Press a button. Repeated downs are ignored to preserve tracked state.
    /// A backend error may have occurred after injection; track first, deny
    /// further input and attempt cleanup instead of assuming no delivery.
    pub fn mouse_down(&mut self, button: MouseButton) -> Result<(), InputError> {
        self.allowed(self.permissions.mouse)?;
        if !self.buttons.contains(&button) {
            self.buttons.push(button);
            if let Err(error) = self.backend.mouse_down(button) {
                self.closed = true; self.permissions = Permissions::default();
                let _ = self.release(true, true);
                return Err(InputError::Backend(error));
            }
        }
        Ok(())
    }
    /// Release a held button; unknown releases are ignored.
    pub fn mouse_up(&mut self, button: MouseButton) -> Result<(), InputError> {
        self.allowed(self.permissions.mouse)?;
        if let Some(index) = self.buttons.iter().position(|b| *b == button) {
            self.backend.mouse_up(button)?;
            self.buttons.remove(index);
        }
        Ok(())
    }
    /// Click a button not currently held by this controller.
    pub fn click(&mut self, button: MouseButton) -> Result<(), InputError> {
        self.allowed(self.permissions.mouse)?;
        if self.buttons.contains(&button) { return Err(InputError::AlreadyPressed); }
        self.mouse_down(button)?;
        self.mouse_up(button)
    }
    /// Whether this controller tracks this key as held. This is not a query of
    /// the real OS keyboard or keys held by other processes or the human user.
    pub fn is_key_held(&self, key: VirtualKey) -> bool { self.keys.contains(&key) }
    /// Press a virtual key. Repeated downs are ignored, so key-repeat is not generated.
    /// On a potentially partial backend failure, deny future input and attempt
    /// cleanup; later `close` retries detectable release failures.
    pub fn key_down(&mut self, key: VirtualKey) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if !self.scans.is_empty() || !self.raw_keys.is_empty() { return Err(InputError::AlreadyPressed); }
        if !self.keys.contains(&key) {
            self.keys.push(key);
            if let Err(error) = self.backend.key_down(key) {
                self.closed = true; self.permissions = Permissions::default();
                let _ = self.release(true, true);
                return Err(InputError::Backend(error));
            }
        }
        Ok(())
    }
    /// Release a held key; unknown releases are ignored.
    pub fn key_up(&mut self, key: VirtualKey) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if let Some(index) = self.keys.iter().position(|k| *k == key) {
            self.backend.key_up(key)?;
            self.keys.remove(index);
        }
        Ok(())
    }
    /// Press and release a key not already held by this controller.
    pub fn key_press(&mut self, key: VirtualKey) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if self.keys.contains(&key) { return Err(InputError::AlreadyPressed); }
        self.key_down(key)?;
        self.key_up(key)
    }
    /// Whether physical scan codes are tracked; not an OS state query.
    pub fn has_held_scans(&self) -> bool { !self.scans.is_empty() }
    /// Whether this controller tracks any physical or virtual key as held.
    pub fn has_held_keyboard(&self) -> bool { !self.keys.is_empty() || !self.scans.is_empty() || !self.raw_keys.is_empty() }
    /// Press a scan code. Mixing physical and virtual tracked keys is refused
    /// to avoid aliasing one OS key into two independent cleanup records.
    pub fn scan_down(&mut self, code: ScanCode) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if !self.keys.is_empty() || !self.raw_keys.is_empty() { return Err(InputError::AlreadyPressed); }
        if !self.scans.contains(&code) {
            if self.scans.len() >= 64 { return Err(InputError::Backend(io::Error::new(io::ErrorKind::InvalidInput, "scan key limit"))); }
            self.scans.push(code);
            if let Err(error) = self.backend.scan_down(code) {
                self.closed = true; self.permissions = Permissions::default();
                let _ = self.release(true, true);
                return Err(InputError::Backend(error));
            }
        }
        Ok(())
    }
    /// Release a tracked scan code; retain it when a detectable failure occurs.
    pub fn scan_up(&mut self, code: ScanCode) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if let Some(index) = self.scans.iter().position(|key| *key == code) {
            self.backend.scan_up(code)?; self.scans.remove(index);
        }
        Ok(())
    }
    /// Press/release a source rdev Windows virtual key. Mixing raw virtual,
    /// scan and Enigo virtual representations is forbidden to prevent aliases.
    pub fn raw_virtual_down(&mut self, key: VirtualKey) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if !self.keys.is_empty() || !self.scans.is_empty() { return Err(InputError::AlreadyPressed); }
        if !self.raw_keys.contains(&key) {
            if self.raw_keys.len() >= 64 { return Err(InputError::Backend(io::Error::new(io::ErrorKind::InvalidInput, "raw virtual key limit"))); }
            self.raw_keys.push(key);
            if let Err(error) = self.backend.raw_virtual_down(key) {
                self.closed = true; self.permissions = Permissions::default();
                let _ = self.release(true, true); return Err(InputError::Backend(error));
            }
        }
        Ok(())
    }
    pub fn raw_virtual_up(&mut self, key: VirtualKey) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if let Some(index) = self.raw_keys.iter().position(|held| *held == key) {
            self.backend.raw_virtual_up(key)?; self.raw_keys.remove(index);
        }
        Ok(())
    }
    /// Inject bounded BMP text only when no keys are tracked as held by this
    /// controller. The source Enigo backend cannot report Windows SendInput
    /// failures, and local-human or other-process modifier state is not checked.
    /// Non-BMP text remains unsupported here pending surrogate/cleanup tests.
    pub fn type_text(&mut self, text: &str) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if self.has_held_keyboard() { return Err(InputError::AlreadyPressed); }
        if text.is_empty() || text.len() > 4096 || text.chars().any(|c| c == '\0' || c as u32 > 0xffff) {
            return Err(InputError::Backend(io::Error::new(io::ErrorKind::InvalidInput, "unsupported text sequence")));
        }
        self.backend.type_text(text)?;
        Ok(())
    }
    /// Deny all future operations and attempt to release every held input.
    /// Repeated calls retry any detectable failed releases.
    pub fn close(&mut self) -> Result<(), InputError> {
        self.closed = true;
        self.permissions = Permissions::default();
        self.release(true, true)
    }

    fn release(&mut self, keys: bool, buttons: bool) -> Result<(), InputError> {
        let mut first_error = None;
        if keys {
            for index in (0..self.raw_keys.len()).rev() {
                match self.backend.raw_virtual_up(self.raw_keys[index]) {
                    Ok(()) => { self.raw_keys.remove(index); },
                    Err(e) => { if first_error.is_none() { first_error = Some(e); } }
                }
            }
            for index in (0..self.scans.len()).rev() {
                match self.backend.scan_up(self.scans[index]) {
                    Ok(()) => { self.scans.remove(index); },
                    Err(e) => { if first_error.is_none() { first_error = Some(e); } }
                }
            }
            for index in (0..self.keys.len()).rev() {
                match self.backend.key_up(self.keys[index]) {
                    Ok(()) => { self.keys.remove(index); },
                    Err(e) => { if first_error.is_none() { first_error = Some(e); } }
                }
            }
        }
        if buttons {
            for index in (0..self.buttons.len()).rev() {
                match self.backend.mouse_up(self.buttons[index]) {
                    Ok(()) => { self.buttons.remove(index); },
                    Err(e) => { if first_error.is_none() { first_error = Some(e); } }
                }
            }
        }
        match first_error { Some(e) => Err(InputError::Backend(e)), None => Ok(()) }
    }
}
impl<B: InputBackend> Drop for InputController<B> {
    fn drop(&mut self) { let _ = self.close(); }
}

/// The Windows adapter reuses RustDesk's Enigo `SendInput` implementation.
#[cfg(windows)]
pub mod windows {
    use super::{InputBackend, MouseButton, ScanCode, VirtualKey};
    use enigo::{Enigo, Key, KeyboardControllable, MouseControllable};
    use std::io;

    /// Windows input backend. Operations affect the interactive desktop.
    /// Enigo does not report every SendInput failure, especially on release,
    /// cursor movement and scroll. Elevated/secure desktops and UIPI can block input.
    pub struct WindowsInput { inner: Enigo }
    impl Default for WindowsInput { fn default() -> Self { Self::new() } }
    impl WindowsInput {
        /// Create the backend. No authentication or authorization is performed.
        pub fn new() -> Self { Self { inner: Enigo::new() } }
    }
    fn button(b: MouseButton) -> enigo::MouseButton {
        match b { MouseButton::Left => enigo::MouseButton::Left, MouseButton::Right => enigo::MouseButton::Right, MouseButton::Middle => enigo::MouseButton::Middle, MouseButton::Back => enigo::MouseButton::Back, MouseButton::Forward => enigo::MouseButton::Forward }
    }
    impl InputBackend for WindowsInput {
        fn move_to(&mut self, x: i32, y: i32) -> io::Result<()> { self.inner.mouse_move_to(x, y); Ok(()) }
        fn move_relative(&mut self, x: i32, y: i32) -> io::Result<()> { self.inner.mouse_move_relative(x, y); Ok(()) }
        fn mouse_down(&mut self, b: MouseButton) -> io::Result<()> { self.inner.mouse_down(button(b)).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())) }
        fn mouse_up(&mut self, b: MouseButton) -> io::Result<()> { self.inner.mouse_up(button(b)); Ok(()) }
        fn scroll(&mut self, x: i32, y: i32) -> io::Result<()> { self.inner.mouse_scroll_x(x); self.inner.mouse_scroll_y(y); Ok(()) }
        fn key_down(&mut self, key: VirtualKey) -> io::Result<()> { self.inner.key_down(Key::Raw(key.code())).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())) }
        fn key_up(&mut self, key: VirtualKey) -> io::Result<()> { self.inner.key_up(Key::Raw(key.code())); Ok(()) }
        fn scan_down(&mut self, code: ScanCode) -> io::Result<()> {
            rdev::simulate(&rdev::EventType::KeyPress(rdev::Key::RawKey(rdev::RawKey::ScanCode(code.code() as u32))))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("rdev scan input: {e:?}")))
        }
        fn scan_up(&mut self, code: ScanCode) -> io::Result<()> {
            rdev::simulate(&rdev::EventType::KeyRelease(rdev::Key::RawKey(rdev::RawKey::ScanCode(code.code() as u32))))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("rdev scan release: {e:?}")))
        }
        fn raw_virtual_down(&mut self, key: VirtualKey) -> io::Result<()> {
            rdev::simulate(&rdev::EventType::KeyPress(rdev::Key::RawKey(rdev::RawKey::WinVirtualKeycode(key.code() as u32))))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("rdev virtual input: {e:?}")))
        }
        fn raw_virtual_up(&mut self, key: VirtualKey) -> io::Result<()> {
            rdev::simulate(&rdev::EventType::KeyRelease(rdev::Key::RawKey(rdev::RawKey::WinVirtualKeycode(key.code() as u32))))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("rdev virtual release: {e:?}")))
        }
        fn type_text(&mut self, text: &str) -> io::Result<()> { self.inner.key_sequence(text); Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    #[derive(Clone, Default)]
    struct Fake { events: Rc<RefCell<Vec<String>>>, fail_release: Rc<RefCell<bool>> }
    impl InputBackend for Fake {
        fn move_to(&mut self, x:i32, y:i32) -> io::Result<()> { self.events.borrow_mut().push(format!("move:{x}:{y}")); Ok(()) }
        fn mouse_down(&mut self, b:MouseButton) -> io::Result<()> { self.events.borrow_mut().push(format!("down:{b:?}")); Ok(()) }
        fn mouse_up(&mut self, b:MouseButton) -> io::Result<()> { self.events.borrow_mut().push(format!("up:{b:?}")); Ok(()) }
        fn scroll(&mut self, _:i32, _:i32) -> io::Result<()> { self.events.borrow_mut().push("scroll".into()); Ok(()) }
        fn key_down(&mut self, k:VirtualKey) -> io::Result<()> { self.events.borrow_mut().push(format!("kd:{}", k.code())); Ok(()) }
        fn key_up(&mut self, k:VirtualKey) -> io::Result<()> {
            self.events.borrow_mut().push(format!("ku:{}", k.code()));
            if *self.fail_release.borrow() { return Err(io::Error::new(io::ErrorKind::Other, "release failed")); }
            Ok(())
        }
    }
    fn key(code:u16) -> VirtualKey { VirtualKey::new(code).unwrap() }

    #[test]
    fn denies_by_default_and_permissions_are_separate() {
        let backend = Fake::default(); let events = backend.events.clone();
        let mut c = InputController::new(backend);
        assert!(matches!(c.key_down(key(65)), Err(InputError::PermissionDenied)));
        assert!(matches!(c.move_to(1, 2), Err(InputError::PermissionDenied)));
        c.set_permissions(Permissions { mouse:true, keyboard:false }).unwrap();
        c.move_to(-20, 30).unwrap();
        assert!(matches!(c.key_down(key(65)), Err(InputError::PermissionDenied)));
        assert_eq!(&*events.borrow(), &["move:-20:30"]);
        assert!(VirtualKey::new(0).is_err());
        assert!(VirtualKey::new(255).is_err());
    }
    #[test]
    fn revoke_and_close_release_held_inputs_once() {
        let backend = Fake::default(); let events = backend.events.clone();
        let mut c = InputController::new(backend);
        c.set_permissions(Permissions { mouse:true, keyboard:true }).unwrap();
        c.key_down(key(17)).unwrap(); c.key_down(key(65)).unwrap(); c.key_down(key(65)).unwrap();
        c.mouse_down(MouseButton::Left).unwrap();
        c.set_permissions(Permissions { mouse:true, keyboard:false }).unwrap();
        assert!(matches!(c.key_down(key(65)), Err(InputError::PermissionDenied)));
        c.close().unwrap(); c.close().unwrap();
        assert!(matches!(c.mouse_down(MouseButton::Left), Err(InputError::Closed)));
        assert_eq!(&*events.borrow(), &["kd:17", "kd:65", "down:Left", "ku:65", "ku:17", "up:Left"]);
    }
    #[test]
    fn failed_release_is_retained_and_retried_on_close() {
        let backend = Fake::default(); let events = backend.events.clone(); let fail = backend.fail_release.clone();
        let mut c = InputController::new(backend);
        c.set_permissions(Permissions { mouse:false, keyboard:true }).unwrap();
        c.key_down(key(65)).unwrap(); *fail.borrow_mut() = true;
        assert!(c.close().is_err()); assert!(matches!(c.key_down(key(66)), Err(InputError::Closed)));
        *fail.borrow_mut() = false; c.close().unwrap();
        assert_eq!(&*events.borrow(), &["kd:65", "ku:65", "ku:65"]);
    }
    #[test]
    fn click_and_drop_cleanup() {
        let backend = Fake::default(); let events = backend.events.clone();
        {
            let mut c = InputController::new(backend);
            c.set_permissions(Permissions { mouse:true, keyboard:true }).unwrap();
            c.click(MouseButton::Left).unwrap(); c.key_press(key(65)).unwrap();
            c.key_down(key(17)).unwrap(); c.mouse_down(MouseButton::Right).unwrap();
            assert!(matches!(c.key_press(key(17)), Err(InputError::AlreadyPressed)));
        }
        assert_eq!(&*events.borrow(), &["down:Left", "up:Left", "kd:65", "ku:65", "kd:17", "down:Right", "ku:17", "up:Right"]);
    }
}

#[cfg(test)]
mod partial_delivery_tests {
    use super::*;
    use std::{cell::{Cell, RefCell}, rc::Rc};
    struct Partial { events: Rc<RefCell<Vec<&'static str>>>, fail_up: Rc<Cell<bool>> }
    impl InputBackend for Partial {
        fn move_to(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
        fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
        fn mouse_up(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
        fn scroll(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
        fn key_down(&mut self, _: VirtualKey) -> io::Result<()> {
            self.events.borrow_mut().push("down-maybe-delivered"); Err(io::Error::new(io::ErrorKind::Other, "partial down"))
        }
        fn key_up(&mut self, _: VirtualKey) -> io::Result<()> {
            self.events.borrow_mut().push("release-attempt");
            if self.fail_up.get() { Err(io::Error::new(io::ErrorKind::Other, "release failed")) } else { Ok(()) }
        }
    }
    #[test]
    fn partial_down_fails_closed_and_retries_release() {
        let events = Rc::new(RefCell::new(Vec::new())); let fail_up = Rc::new(Cell::new(true));
        let mut input = InputController::new(Partial { events: events.clone(), fail_up: fail_up.clone() });
        input.set_permissions(Permissions { keyboard: true, mouse: false }).unwrap();
        assert!(input.key_down(VirtualKey::new(65).unwrap()).is_err());
        assert!(matches!(input.key_down(VirtualKey::new(66).unwrap()), Err(InputError::Closed)));
        fail_up.set(false); input.close().unwrap();
        assert_eq!(&*events.borrow(), &["down-maybe-delivered", "release-attempt", "release-attempt"]);
    }
}

#[cfg(test)]
mod scan_tests {
    use super::*;
    use std::{cell::{Cell, RefCell}, rc::Rc};
    struct Fake { events: Rc<RefCell<Vec<&'static str>>>, fail_up: Rc<Cell<bool>> }
    impl InputBackend for Fake {
        fn move_to(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
        fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
        fn mouse_up(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
        fn scroll(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
        fn key_down(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
        fn key_up(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
        fn scan_down(&mut self, _: ScanCode) -> io::Result<()> { self.events.borrow_mut().push("down"); Ok(()) }
        fn scan_up(&mut self, _: ScanCode) -> io::Result<()> {
            self.events.borrow_mut().push("up");
            if self.fail_up.get() { Err(io::Error::new(io::ErrorKind::Other, "fake release failure")) } else { Ok(()) }
        }
    }
    #[test]
    fn revoke_retains_failed_scan_release_until_close() {
        let events = Rc::new(RefCell::new(Vec::new())); let fail = Rc::new(Cell::new(true));
        let mut input = InputController::new(Fake { events: events.clone(), fail_up: fail.clone() });
        input.set_permissions(Permissions { keyboard: true, mouse: false }).unwrap();
        input.scan_down(ScanCode::new(0xe01d).unwrap()).unwrap();
        assert!(matches!(input.key_down(VirtualKey::new(65).unwrap()), Err(InputError::AlreadyPressed)));
        assert!(matches!(input.type_text("no mixed text"), Err(InputError::AlreadyPressed)));
        assert!(ScanCode::new(0).is_err());
        assert!(ScanCode::new(0x1001).is_err());
        assert!(input.set_permissions(Permissions::default()).is_err());
        assert!(input.has_held_scans());
        fail.set(false); input.close().unwrap();
        assert!(!input.has_held_scans());
        assert_eq!(&*events.borrow(), &["down", "up", "up"]);
    }
}
