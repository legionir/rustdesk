//! Experimental per-controller input state and Windows Enigo adapter.
//!
//! This module does not authenticate a caller. Only a trusted session manager
//! may grant permissions or construct a backend. Callers must serialize access
//! to the OS input device and enforce a single controlling session: independent
//! controllers can otherwise release each other's keys. Explicitly call `close`
//! on disconnect; `Drop` only provides best-effort cleanup.

/// Read-only source Unicode key sequence planning; no native injection.
pub mod windows_unicode_plan;
#[cfg(any(windows, test))]
mod scroll_sequence;

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

/// Explicit acknowledgement of the pinned Windows Enigo Unicode sequence
/// semantics: supplementary characters emit UTF-16 surrogate downs without
/// matching ups, and SendInput failures may be invisible. This token is not
/// consent, OS-wide ownership, a cleanup guarantee or proof the backend is
/// Windows. Only use after local approval on a suitable interactive desktop.
pub struct SourceWindowsUnicodeOptIn(());
impl SourceWindowsUnicodeOptIn {
    pub fn acknowledge_source_surrogate_and_delivery_risks() -> Self { Self(()) }
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

// A failed explicit release is retained for a later owner-driven retry; other
// held inputs can still be released without repeating the uncertain operation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HeldInput { Key(VirtualKey), Scan(ScanCode), RawKey(VirtualKey), Button(MouseButton) }

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
    /// to release affected held inputs. On detectable release failure the
    /// controller is closed and all input denied; unresolved records remain
    /// tracked for explicit `close` retry. Native failures may be invisible.
    pub fn set_permissions(&mut self, permissions: Permissions) -> Result<(), InputError> {
        if self.closed { return Err(InputError::Closed); }
        self.permissions = permissions;
        let release_keys = !permissions.keyboard;
        let release_buttons = !permissions.mouse;
        let result = self.release(release_keys, release_buttons);
        if result.is_err() {
            self.fail_closed();
            // Previously permitted categories were not included in the first
            // cleanup pass. Release them now, without retrying failed releases.
            let _ = self.release(!release_keys, !release_buttons);
        }
        result
    }

    fn fail_closed(&mut self) { self.closed = true; self.permissions = Permissions::default(); }

    fn allowed(&self, granted: bool) -> Result<(), InputError> {
        if self.closed { Err(InputError::Closed) } else if !granted { Err(InputError::PermissionDenied) } else { Ok(()) }
    }

    // A native error can follow partial delivery. Fail closed and attempt
    // release of all tracked input; failed releases remain for explicit retry.
    fn movement_result(&mut self, result: io::Result<()>) -> Result<(), InputError> {
        if let Err(error) = result {
            self.fail_closed();
            let _ = self.release(true, true);
            return Err(InputError::Backend(error));
        }
        Ok(())
    }
    /// Move in virtual desktop coordinates. Monitor-relative mapping is the
    /// caller's responsibility. A detectable backend error closes the
    /// controller; movement may already have occurred and is never retried.
    pub fn move_to(&mut self, x: i32, y: i32) -> Result<(), InputError> {
        self.allowed(self.permissions.mouse)?;
        let result = self.backend.move_to(x, y);
        self.movement_result(result)
    }
    /// Move by relative pixel deltas. Failure is terminal and may be partial.
    pub fn move_relative(&mut self, x: i32, y: i32) -> Result<(), InputError> {
        self.allowed(self.permissions.mouse)?;
        let result = self.backend.move_relative(x, y);
        self.movement_result(result)
    }
    /// Send horizontal and vertical scroll deltas. A detectable partial error
    /// closes input and is not retried; earlier scroll cannot be undone.
    pub fn scroll(&mut self, x: i32, y: i32) -> Result<(), InputError> {
        self.allowed(self.permissions.mouse)?;
        let result = self.backend.scroll(x, y);
        self.movement_result(result)
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
    /// Release a held button; unknown releases are ignored. A detectable
    /// failure closes the controller and keeps the record for `close` retry.
    pub fn mouse_up(&mut self, button: MouseButton) -> Result<(), InputError> {
        self.allowed(self.permissions.mouse)?;
        if let Some(index) = self.buttons.iter().position(|b| *b == button) {
            if let Err(error) = self.backend.mouse_up(button) {
                self.fail_closed();
                let _ = self.release_except(true, true, Some(HeldInput::Button(button)));
                return Err(InputError::Backend(error));
            }
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
    /// Explicit source-style repeated down. Sends a new native down when this
    /// controller already holds the key; it does not start a repeat timer or
    /// inspect global OS state. Requires exclusive input and local consent.
    pub fn key_down_with_repeat(&mut self, key: VirtualKey) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if !self.keys.contains(&key) { return self.key_down(key); }
        if let Err(error) = self.backend.key_down(key) {
            self.closed = true; self.permissions = Permissions::default();
            let _ = self.release(true, true); return Err(InputError::Backend(error));
        }
        Ok(())
    }
    /// Release a held key; unknown releases are ignored. A detectable
    /// failure closes the controller and keeps the record for `close` retry.
    pub fn key_up(&mut self, key: VirtualKey) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if let Some(index) = self.keys.iter().position(|k| *k == key) {
            if let Err(error) = self.backend.key_up(key) {
                self.fail_closed();
                let _ = self.release_except(true, true, Some(HeldInput::Key(key)));
                return Err(InputError::Backend(error));
            }
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
    /// Explicit repeated scan down, with the same partial-failure cleanup as
    /// an initial press. Other input owners and OS repeat timers are not tracked.
    pub fn scan_down_with_repeat(&mut self, code: ScanCode) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if !self.scans.contains(&code) { return self.scan_down(code); }
        if let Err(error) = self.backend.scan_down(code) {
            self.closed = true; self.permissions = Permissions::default();
            let _ = self.release(true, true); return Err(InputError::Backend(error));
        }
        Ok(())
    }
    /// Release a tracked scan code. A detectable failure closes the controller
    /// and retains the record for `close` retry.
    pub fn scan_up(&mut self, code: ScanCode) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if let Some(index) = self.scans.iter().position(|key| *key == code) {
            if let Err(error) = self.backend.scan_up(code) {
                self.fail_closed();
                let _ = self.release_except(true, true, Some(HeldInput::Scan(code)));
                return Err(InputError::Backend(error));
            }
            self.scans.remove(index);
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
    /// Explicit repeated raw virtual down; not a query of global key state.
    pub fn raw_virtual_down_with_repeat(&mut self, key: VirtualKey) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if !self.raw_keys.contains(&key) { return self.raw_virtual_down(key); }
        if let Err(error) = self.backend.raw_virtual_down(key) {
            self.closed = true; self.permissions = Permissions::default();
            let _ = self.release(true, true); return Err(InputError::Backend(error));
        }
        Ok(())
    }
    /// A detectable failed release closes the controller and retains the
    /// record for `close` retry. Unknown releases are ignored.
    pub fn raw_virtual_up(&mut self, key: VirtualKey) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if let Some(index) = self.raw_keys.iter().position(|held| *held == key) {
            if let Err(error) = self.backend.raw_virtual_up(key) {
                self.fail_closed();
                let _ = self.release_except(true, true, Some(HeldInput::RawKey(key)));
                return Err(InputError::Backend(error));
            }
            self.raw_keys.remove(index);
        }
        Ok(())
    }
    /// Inject bounded BMP text only when no keys are tracked as held by this
    /// controller. The Windows fork reports zero-event SendInput results, but
    /// success is not delivery proof and other-process/human modifier state is
    /// not checked. Non-BMP text remains unsupported pending cleanup tests.
    /// A detectable injection failure closes the controller; any partial text
    /// already delivered cannot be undone.
    pub fn type_text(&mut self, text: &str) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if self.has_held_keyboard() { return Err(InputError::AlreadyPressed); }
        if text.is_empty() || text.len() > 4096 || text.chars().any(|c| c == '\0' || c as u32 > 0xffff) {
            return Err(InputError::Backend(io::Error::new(io::ErrorKind::InvalidInput, "unsupported text sequence")));
        }
        if let Err(error) = self.backend.type_text(text) {
            self.fail_closed();
            // Text requires no tracked keys but mouse buttons may still be held.
            // Their failed releases remain tracked for an explicit close retry.
            let _ = self.release(true, true);
            return Err(InputError::Backend(error));
        }
        Ok(())
    }
    /// Explicitly allow the pinned source Windows Enigo sequence behavior,
    /// including supplementary UTF-16 surrogate downs without paired ups.
    /// This bypasses the normal BMP-only rule but still requires keyboard
    /// permission, bounded nonempty text and no locally tracked keys. It is
    /// not an OS-wide input lock and cannot establish delivery or undo output.
    /// A detectable backend error closes this controller; partial output cannot
    /// be undone. The caller must ensure the actual backend is Windows Enigo.
    pub fn type_text_source_windows(&mut self, text: &str, _: SourceWindowsUnicodeOptIn) -> Result<(), InputError> {
        self.allowed(self.permissions.keyboard)?;
        if self.has_held_keyboard() { return Err(InputError::AlreadyPressed); }
        if text.is_empty() || text.len() > windows_unicode_plan::MAX_TEXT_BYTES || text.contains('\0') {
            return Err(InputError::Backend(io::Error::new(io::ErrorKind::InvalidInput, "unsupported text sequence")));
        }
        if let Err(error) = self.backend.type_text(text) {
            self.closed = true; self.permissions = Permissions::default();
            let _ = self.release(true, true); return Err(InputError::Backend(error));
        }
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
        self.release_except(keys, buttons, None)
    }

    fn release_except(&mut self, keys: bool, buttons: bool, skip: Option<HeldInput>) -> Result<(), InputError> {
        let mut first_error = None;
        if keys {
            for index in (0..self.raw_keys.len()).rev() {
                if skip == Some(HeldInput::RawKey(self.raw_keys[index])) { continue; }
                match self.backend.raw_virtual_up(self.raw_keys[index]) {
                    Ok(()) => { self.raw_keys.remove(index); },
                    Err(e) => { if first_error.is_none() { first_error = Some(e); } }
                }
            }
            for index in (0..self.scans.len()).rev() {
                if skip == Some(HeldInput::Scan(self.scans[index])) { continue; }
                match self.backend.scan_up(self.scans[index]) {
                    Ok(()) => { self.scans.remove(index); },
                    Err(e) => { if first_error.is_none() { first_error = Some(e); } }
                }
            }
            for index in (0..self.keys.len()).rev() {
                if skip == Some(HeldInput::Key(self.keys[index])) { continue; }
                match self.backend.key_up(self.keys[index]) {
                    Ok(()) => { self.keys.remove(index); },
                    Err(e) => { if first_error.is_none() { first_error = Some(e); } }
                }
            }
        }
        if buttons {
            for index in (0..self.buttons.len()).rev() {
                if skip == Some(HeldInput::Button(self.buttons[index])) { continue; }
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

/// The Windows adapter uses the source-derived, independently patched Enigo fork.
#[cfg(windows)]
pub mod windows {
    use super::{InputBackend, MouseButton, ScanCode, VirtualKey};
    use enigo::{Enigo, Key, KeyboardControllable, MouseControllable};
    use std::io;

    /// Windows input backend. Operations affect the interactive desktop.
    /// BLOCKED pending independent review and Windows validation. A copied fork
    /// contains candidate fixes for the source error buffer and shared layout
    /// race, but this is not proof of safety. See the Windows safety gate in
    /// docs/analysis; do not enable this backend until that gate is cleared.
    /// The fork reports zero-event SendInput results for tracked releases,
    /// movement/scroll and Unicode sequences, but other failures may be hidden.
    /// Success is not delivery proof; secure desktops and UIPI can block input.
    pub struct WindowsInput { inner: Enigo }
    impl Default for WindowsInput { fn default() -> Self { Self::new() } }
    impl WindowsInput {
        /// Create the backend. No authentication or authorization is performed.
        pub fn new() -> Self { Self { inner: Enigo::new() } }
        /// Read source Enigo's Windows GetKeyState toggle bits for CapsLock and
        /// NumLock without injecting keys. These are transient calling-thread
        /// input-queue observations, not global truth or proof of OS state.
        /// Coordinate the desktop, DPI/session and input ownership externally;
        /// a user or another process may change locks immediately afterward.
        pub fn lock_state(&mut self) -> WindowsLockState {
            WindowsLockState { caps_lock: self.inner.get_key_state(Key::CapsLock), num_lock: self.inner.get_key_state(Key::NumLock) }
        }
    }
    /// Untrusted transient local lock observations, not authorization.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WindowsLockState { pub caps_lock: bool, pub num_lock: bool }
    fn button(b: MouseButton) -> enigo::MouseButton {
        match b { MouseButton::Left => enigo::MouseButton::Left, MouseButton::Right => enigo::MouseButton::Right, MouseButton::Middle => enigo::MouseButton::Middle, MouseButton::Back => enigo::MouseButton::Back, MouseButton::Forward => enigo::MouseButton::Forward }
    }
    impl InputBackend for WindowsInput {
        fn move_to(&mut self, x: i32, y: i32) -> io::Result<()> { self.inner.try_mouse_move_to(x, y).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())) }
        fn move_relative(&mut self, x: i32, y: i32) -> io::Result<()> { self.inner.try_mouse_move_relative(x, y).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())) }
        fn mouse_down(&mut self, b: MouseButton) -> io::Result<()> { self.inner.mouse_down(button(b)).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())) }
        fn mouse_up(&mut self, b: MouseButton) -> io::Result<()> { self.inner.try_mouse_button_up(button(b)).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())) }
        fn scroll(&mut self, x: i32, y: i32) -> io::Result<()> {
            // Source input_service emits vertical first and skips zero deltas.
            super::scroll_sequence::send_scroll(x, y, |axis, delta| {
                let result = match axis {
                    super::scroll_sequence::Axis::Vertical => self.inner.try_mouse_scroll_y(delta),
                    super::scroll_sequence::Axis::Horizontal => self.inner.try_mouse_scroll_x(delta),
                };
                result.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
            })
        }
        fn key_down(&mut self, key: VirtualKey) -> io::Result<()> { self.inner.key_down(Key::Raw(key.code())).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())) }
        fn key_up(&mut self, key: VirtualKey) -> io::Result<()> { self.inner.try_raw_key_up(key.code()).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())) }
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
        fn type_text(&mut self, text: &str) -> io::Result<()> { self.inner.try_source_unicode_sequence(text).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())) }
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
    fn explicit_repeat_keeps_one_cleanup_record() {
        let backend = Fake::default(); let events = backend.events.clone();
        let mut c = InputController::new(backend);
        assert!(matches!(c.key_down_with_repeat(key(65)), Err(InputError::PermissionDenied)));
        c.set_permissions(Permissions { mouse: false, keyboard: true }).unwrap();
        c.key_down(key(65)).unwrap(); c.key_down(key(65)).unwrap();
        c.key_down_with_repeat(key(65)).unwrap(); c.close().unwrap();
        assert_eq!(&*events.borrow(), &["kd:65", "kd:65", "ku:65"]);
        assert!(matches!(c.key_down_with_repeat(key(65)), Err(InputError::Closed)));
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
    struct RepeatPartial { events: Rc<RefCell<Vec<&'static str>>>, count: usize, fail_up: Rc<Cell<bool>> }
    impl InputBackend for RepeatPartial {
        fn move_to(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
        fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
        fn mouse_up(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
        fn scroll(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
        fn key_down(&mut self, _: VirtualKey) -> io::Result<()> {
            self.count += 1; self.events.borrow_mut().push("down");
            if self.count > 1 { Err(io::Error::new(io::ErrorKind::Other, "partial repeat")) } else { Ok(()) }
        }
        fn key_up(&mut self, _: VirtualKey) -> io::Result<()> {
            self.events.borrow_mut().push("release");
            if self.fail_up.get() { Err(io::Error::new(io::ErrorKind::Other, "release failed")) } else { Ok(()) }
        }
    }
    #[test]
    fn partial_repeated_down_fails_closed_and_retries_release() {
        let events = Rc::new(RefCell::new(Vec::new())); let fail_up = Rc::new(Cell::new(true));
        let mut input = InputController::new(RepeatPartial { events: events.clone(), count: 0, fail_up: fail_up.clone() });
        input.set_permissions(Permissions { keyboard: true, mouse: false }).unwrap();
        let key = VirtualKey::new(65).unwrap();
        input.key_down_with_repeat(key).unwrap();
        assert!(input.key_down_with_repeat(key).is_err());
        assert!(matches!(input.key_down_with_repeat(key), Err(InputError::Closed)));
        fail_up.set(false); input.close().unwrap();
        assert_eq!(&*events.borrow(), &["down", "down", "release", "release"]);
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
        fn raw_virtual_down(&mut self, _: VirtualKey) -> io::Result<()> { self.events.borrow_mut().push("raw-down"); Ok(()) }
        fn raw_virtual_up(&mut self, _: VirtualKey) -> io::Result<()> { self.events.borrow_mut().push("raw-up"); Ok(()) }
        fn scan_down(&mut self, _: ScanCode) -> io::Result<()> { self.events.borrow_mut().push("down"); Ok(()) }
        fn scan_up(&mut self, _: ScanCode) -> io::Result<()> {
            self.events.borrow_mut().push("up");
            if self.fail_up.get() { Err(io::Error::new(io::ErrorKind::Other, "fake release failure")) } else { Ok(()) }
        }
    }
    #[test]
    fn repeated_physical_representations_remain_exclusive_and_release_once() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut input = InputController::new(Fake { events: events.clone(), fail_up: Rc::new(Cell::new(false)) });
        input.set_permissions(Permissions { keyboard: true, mouse: false }).unwrap();
        let scan = ScanCode::new(0xe01d).unwrap(); let raw = VirtualKey::new(65).unwrap();
        input.scan_down_with_repeat(scan).unwrap(); input.scan_down_with_repeat(scan).unwrap();
        assert!(matches!(input.raw_virtual_down_with_repeat(raw), Err(InputError::AlreadyPressed)));
        input.scan_up(scan).unwrap();
        input.raw_virtual_down_with_repeat(raw).unwrap(); input.raw_virtual_down_with_repeat(raw).unwrap();
        assert!(matches!(input.scan_down_with_repeat(scan), Err(InputError::AlreadyPressed)));
        input.close().unwrap();
        assert_eq!(&*events.borrow(), &["down", "down", "up", "raw-down", "raw-down", "raw-up"]);
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

#[cfg(test)]
mod source_unicode_opt_in_tests {
    use super::*;
    use std::{cell::{Cell, RefCell}, rc::Rc};
    struct TextBackend { sent: Rc<RefCell<Vec<String>>>, fail: Rc<Cell<bool>> }
    impl InputBackend for TextBackend {
        fn move_to(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
        fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
        fn mouse_up(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
        fn scroll(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
        fn key_down(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
        fn key_up(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
        fn type_text(&mut self, text: &str) -> io::Result<()> {
            self.sent.borrow_mut().push(text.to_owned());
            if self.fail.get() { Err(io::Error::new(io::ErrorKind::Other, "possible partial delivery")) } else { Ok(()) }
        }
    }
    fn opt() -> SourceWindowsUnicodeOptIn { SourceWindowsUnicodeOptIn::acknowledge_source_surrogate_and_delivery_risks() }
    #[test]
    fn only_explicit_path_accepts_bounded_supplementary_text() {
        let sent = Rc::new(RefCell::new(Vec::new())); let fail = Rc::new(Cell::new(false));
        let mut c = InputController::new(TextBackend { sent: sent.clone(), fail: fail.clone() });
        assert!(matches!(c.type_text_source_windows("😀", opt()), Err(InputError::PermissionDenied)));
        c.set_permissions(Permissions { keyboard: true, mouse: false }).unwrap();
        assert!(c.type_text("😀").is_err());
        assert!(c.type_text_source_windows("\0", opt()).is_err());
        assert!(c.type_text_source_windows(&"x".repeat(windows_unicode_plan::MAX_TEXT_BYTES + 1), opt()).is_err());
        c.key_down(VirtualKey::new(65).unwrap()).unwrap();
        assert!(matches!(c.type_text_source_windows("😀", opt()), Err(InputError::AlreadyPressed)));
        c.key_up(VirtualKey::new(65).unwrap()).unwrap();
        c.type_text_source_windows("A😀", opt()).unwrap();
        assert_eq!(&*sent.borrow(), &["A😀"]);
        fail.set(true); assert!(c.type_text_source_windows("B", opt()).is_err());
        assert!(matches!(c.type_text_source_windows("C", opt()), Err(InputError::Closed)));
    }
}

#[cfg(test)]
mod failed_release_policy_tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};
    struct Backend { fail: Rc<Cell<bool>>, releases: Rc<Cell<usize>> }
    impl Backend {
        fn release(&self) -> io::Result<()> {
            self.releases.set(self.releases.get() + 1);
            if self.fail.get() { Err(io::Error::new(io::ErrorKind::Other, "uncertain delivery")) } else { Ok(()) }
        }
    }
    impl InputBackend for Backend {
        fn move_to(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
        fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
        fn mouse_up(&mut self, _: MouseButton) -> io::Result<()> { self.release() }
        fn scroll(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
        fn key_down(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
        fn key_up(&mut self, _: VirtualKey) -> io::Result<()> { self.release() }
        fn scan_down(&mut self, _: ScanCode) -> io::Result<()> { Ok(()) }
        fn scan_up(&mut self, _: ScanCode) -> io::Result<()> { self.release() }
        fn raw_virtual_down(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
        fn raw_virtual_up(&mut self, _: VirtualKey) -> io::Result<()> { self.release() }
        fn type_text(&mut self, _: &str) -> io::Result<()> { Err(io::Error::new(io::ErrorKind::Other, "partial text")) }
    }
    #[test]
    fn failed_up_denies_all_input_and_explicit_close_retries() {
        for kind in 0..4 {
            let fail = Rc::new(Cell::new(false)); let releases = Rc::new(Cell::new(0));
            let mut input = InputController::new(Backend { fail: fail.clone(), releases: releases.clone() });
            input.set_permissions(Permissions { keyboard: true, mouse: true }).unwrap();
            let key = VirtualKey::new(65).unwrap(); let scan = ScanCode::new(0x1e).unwrap();
            match kind { 0 => input.key_down(key).unwrap(), 1 => input.scan_down(scan).unwrap(),
                2 => input.raw_virtual_down(key).unwrap(), _ => input.mouse_down(MouseButton::Left).unwrap() }
            fail.set(true);
            let result = match kind { 0 => input.key_up(key), 1 => input.scan_up(scan),
                2 => input.raw_virtual_up(key), _ => input.mouse_up(MouseButton::Left) };
            assert!(matches!(result, Err(InputError::Backend(_))));
            assert_eq!(releases.get(), 1); // no implicit retry on the failed operation
            assert!(matches!(input.move_to(1, 1), Err(InputError::Closed)));
            assert!(matches!(input.set_permissions(Permissions { keyboard: true, mouse: true }), Err(InputError::Closed)));
            fail.set(false); input.close().unwrap();
            assert_eq!(releases.get(), 2);
            input.close().unwrap(); assert_eq!(releases.get(), 2);
        }
    }
    #[test]
    fn failed_revocation_fails_closed_and_partial_text_is_not_retried() {
        let fail = Rc::new(Cell::new(false)); let releases = Rc::new(Cell::new(0));
        let mut input = InputController::new(Backend { fail: fail.clone(), releases: releases.clone() });
        input.set_permissions(Permissions { keyboard: true, mouse: true }).unwrap();
        input.key_down(VirtualKey::new(65).unwrap()).unwrap();
        fail.set(true);
        assert!(input.set_permissions(Permissions { keyboard: false, mouse: true }).is_err());
        assert!(matches!(input.mouse_down(MouseButton::Left), Err(InputError::Closed)));
        fail.set(false); input.close().unwrap(); assert_eq!(releases.get(), 2);
        let mut text = InputController::new(Backend { fail, releases });
        text.set_permissions(Permissions { keyboard: true, mouse: false }).unwrap();
        assert!(text.type_text("A").is_err());
        assert!(matches!(text.type_text("B"), Err(InputError::Closed)));
    }
    #[test]
    fn text_failure_also_attempts_held_mouse_cleanup() {
        let fail = Rc::new(Cell::new(true)); let releases = Rc::new(Cell::new(0));
        let mut input = InputController::new(Backend { fail: fail.clone(), releases: releases.clone() });
        input.set_permissions(Permissions { keyboard: true, mouse: true }).unwrap();
        input.mouse_down(MouseButton::Left).unwrap();
        assert!(input.type_text("A").is_err());
        assert_eq!(releases.get(), 1);
        fail.set(false); input.close().unwrap();
        assert_eq!(releases.get(), 2);
    }
}

#[cfg(test)]
mod movement_failure_tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};
    struct PartialMove {
        fail_release: Rc<Cell<bool>>,
        moves: Rc<Cell<usize>>,
        releases: Rc<Cell<usize>>,
    }
    impl PartialMove {
        fn move_failure(&self) -> io::Result<()> {
            self.moves.set(self.moves.get() + 1);
            Err(io::Error::new(io::ErrorKind::Other, "possibly partial input"))
        }
        fn release(&self) -> io::Result<()> {
            self.releases.set(self.releases.get() + 1);
            if self.fail_release.get() { Err(io::Error::new(io::ErrorKind::Other, "release failed")) } else { Ok(()) }
        }
    }
    impl InputBackend for PartialMove {
        fn move_to(&mut self, _: i32, _: i32) -> io::Result<()> { self.move_failure() }
        fn move_relative(&mut self, _: i32, _: i32) -> io::Result<()> { self.move_failure() }
        fn scroll(&mut self, _: i32, _: i32) -> io::Result<()> { self.move_failure() }
        fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
        fn mouse_up(&mut self, _: MouseButton) -> io::Result<()> { self.release() }
        fn key_down(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
        fn key_up(&mut self, _: VirtualKey) -> io::Result<()> { self.release() }
    }
    #[test]
    fn every_movement_failure_closes_and_preserves_failed_releases_for_retry() {
        for operation in 0..3 {
            let fail_release = Rc::new(Cell::new(true));
            let moves = Rc::new(Cell::new(0)); let releases = Rc::new(Cell::new(0));
            let mut input = InputController::new(PartialMove { fail_release: fail_release.clone(), moves: moves.clone(), releases: releases.clone() });
            input.set_permissions(Permissions { keyboard: true, mouse: true }).unwrap();
            input.key_down(VirtualKey::new(65).unwrap()).unwrap();
            input.mouse_down(MouseButton::Left).unwrap();
            let result = match operation { 0 => input.move_to(1, 2), 1 => input.move_relative(1, 2), _ => input.scroll(1, 2) };
            assert!(matches!(result, Err(InputError::Backend(_))));
            assert_eq!(moves.get(), 1); assert_eq!(releases.get(), 2);
            assert!(matches!(input.move_to(1, 2), Err(InputError::Closed)));
            assert_eq!(moves.get(), 1); // movement never retried
            fail_release.set(false);
            input.close().unwrap();
            assert_eq!(releases.get(), 4);
            input.close().unwrap(); assert_eq!(releases.get(), 4);
        }
    }
}

// Exercise the exact fork's pure formatter without injecting desktop input.
#[cfg(test)]
#[path = "../../../vendor/enigo/src/win/safe_error.rs"]
mod forked_enigo_error_tests;

// Exercise synchronization with threads without generating any input events.
#[cfg(test)]
#[path = "../../../vendor/enigo/src/win/layout_cache.rs"]
mod forked_enigo_layout_tests;

// Exercise source-derived partial-modifier rollback with a fake backend.
#[cfg(test)]
#[path = "../../../vendor/enigo/src/win/modifier_scope.rs"]
mod forked_enigo_modifier_tests;

#[cfg(test)]
mod partial_release_cleanup_tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    struct Backend { events: Rc<RefCell<Vec<String>>>, failures: Rc<RefCell<Vec<String>>> }
    impl Backend {
        fn up(&self, item: String) -> io::Result<()> {
            self.events.borrow_mut().push(item.clone());
            if self.failures.borrow().contains(&item) {
                Err(io::Error::new(io::ErrorKind::Other, "uncertain release"))
            } else { Ok(()) }
        }
    }
    impl InputBackend for Backend {
        fn move_to(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
        fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
        fn mouse_up(&mut self, button: MouseButton) -> io::Result<()> { self.up(format!("button:{button:?}")) }
        fn scroll(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
        fn key_down(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
        fn key_up(&mut self, key: VirtualKey) -> io::Result<()> { self.up(format!("key:{}", key.code())) }
        fn scan_down(&mut self, _: ScanCode) -> io::Result<()> { Ok(()) }
        fn scan_up(&mut self, key: ScanCode) -> io::Result<()> { self.up(format!("scan:{}", key.code())) }
        fn raw_virtual_down(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
        fn raw_virtual_up(&mut self, key: VirtualKey) -> io::Result<()> { self.up(format!("raw:{}", key.code())) }
    }

    #[test]
    fn failed_explicit_release_cleans_other_records_without_retrying_it() {
        for kind in 0..4 {
            let events = Rc::new(RefCell::new(Vec::new()));
            let failures = Rc::new(RefCell::new(Vec::new()));
            let mut input = InputController::new(Backend { events: events.clone(), failures: failures.clone() });
            input.set_permissions(Permissions { keyboard: true, mouse: true }).unwrap();
            let a = VirtualKey::new(65).unwrap(); let b = VirtualKey::new(66).unwrap();
            let scan_a = ScanCode::new(30).unwrap(); let scan_b = ScanCode::new(31).unwrap();
            match kind {
                0 => { input.key_down(a).unwrap(); input.key_down(b).unwrap(); },
                1 => { input.scan_down(scan_a).unwrap(); input.scan_down(scan_b).unwrap(); },
                2 => { input.raw_virtual_down(a).unwrap(); input.raw_virtual_down(b).unwrap(); },
                _ => { input.key_down(a).unwrap(); },
            }
            input.mouse_down(MouseButton::Left).unwrap();
            input.mouse_down(MouseButton::Right).unwrap();
            let target = match kind { 0 => "key:65", 1 => "scan:30", 2 => "raw:65", _ => "button:Left" };
            let second_failure = if kind == 3 { "key:65" } else { "button:Left" };
            failures.borrow_mut().extend([target.to_owned(), second_failure.to_owned()]);
            let result = match kind {
                0 => input.key_up(a), 1 => input.scan_up(scan_a),
                2 => input.raw_virtual_up(a), _ => input.mouse_up(MouseButton::Left),
            };
            assert!(matches!(result, Err(InputError::Backend(_))));
            assert!(matches!(input.move_to(0, 0), Err(InputError::Closed)));
            let snapshot = events.borrow().clone();
            assert_eq!(snapshot.iter().filter(|event| event.as_str() == target).count(), 1);
            assert_eq!(snapshot.iter().filter(|event| event.as_str() == second_failure).count(), 1);
            assert_eq!(snapshot.iter().filter(|event| event.as_str() == "button:Right").count(), 1);
            failures.borrow_mut().clear();
            input.close().unwrap();
            let snapshot = events.borrow().clone();
            assert_eq!(snapshot.iter().filter(|event| event.as_str() == target).count(), 2);
            assert_eq!(snapshot.iter().filter(|event| event.as_str() == second_failure).count(), 2);
            assert_eq!(snapshot.iter().filter(|event| event.as_str() == "button:Right").count(), 1);
            input.close().unwrap();
            assert_eq!(snapshot, *events.borrow());
        }
    }

    #[test]
    fn failed_permission_revocation_also_cleans_previously_permitted_category() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let failures = Rc::new(RefCell::new(vec!["key:65".to_owned()]));
        let mut input = InputController::new(Backend { events: events.clone(), failures: failures.clone() });
        input.set_permissions(Permissions { keyboard: true, mouse: true }).unwrap();
        input.key_down(VirtualKey::new(65).unwrap()).unwrap();
        input.mouse_down(MouseButton::Left).unwrap();
        assert!(matches!(input.set_permissions(Permissions { keyboard: false, mouse: true }), Err(InputError::Backend(_))));
        assert_eq!(&*events.borrow(), &["key:65", "button:Left"]);
        assert!(matches!(input.mouse_down(MouseButton::Right), Err(InputError::Closed)));
        failures.borrow_mut().clear();
        input.close().unwrap();
        assert_eq!(&*events.borrow(), &["key:65", "button:Left", "key:65"]);
    }
    #[test]
    fn failed_mouse_revocation_cleans_keyboard_and_retains_failed_button() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let failures = Rc::new(RefCell::new(vec!["button:Left".to_owned()]));
        let mut input = InputController::new(Backend { events: events.clone(), failures: failures.clone() });
        input.set_permissions(Permissions { keyboard: true, mouse: true }).unwrap();
        input.key_down(VirtualKey::new(65).unwrap()).unwrap();
        input.mouse_down(MouseButton::Left).unwrap();
        assert!(matches!(input.set_permissions(Permissions { keyboard: true, mouse: false }), Err(InputError::Backend(_))));
        assert_eq!(&*events.borrow(), &["button:Left", "key:65"]);
        failures.borrow_mut().clear(); input.close().unwrap();
        assert_eq!(&*events.borrow(), &["button:Left", "key:65", "button:Left"]);
    }

    #[test]
    fn failed_combined_revocation_does_not_retry_during_same_pass() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let failures = Rc::new(RefCell::new(vec!["key:65".to_owned(), "button:Left".to_owned()]));
        let mut input = InputController::new(Backend { events: events.clone(), failures: failures.clone() });
        input.set_permissions(Permissions { keyboard: true, mouse: true }).unwrap();
        input.key_down(VirtualKey::new(65).unwrap()).unwrap();
        input.mouse_down(MouseButton::Left).unwrap();
        assert!(matches!(input.set_permissions(Permissions::default()), Err(InputError::Backend(_))));
        assert_eq!(&*events.borrow(), &["key:65", "button:Left"]);
        failures.borrow_mut().clear(); input.close().unwrap();
        assert_eq!(&*events.borrow(), &["key:65", "button:Left", "key:65", "button:Left"]);
    }

}

// Pure single-event result classification; no desktop input is injected.
#[cfg(test)]
#[path = "../../../vendor/enigo/src/win/send_result.rs"]
mod forked_enigo_send_result_tests;

// Test source-compatible coordinate math without querying or moving a desktop.
#[cfg(test)]
#[path = "../../../vendor/enigo/src/win/mouse_plan.rs"]
mod forked_enigo_mouse_plan_tests;

// Exercise source-compatible Unicode event ordering with a fake sender.
#[cfg(test)]
#[path = "../../../vendor/enigo/src/win/unicode_sequence.rs"]
mod forked_enigo_unicode_sequence_tests;
