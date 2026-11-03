//! Experimental integration of the session guard and input controller.
//!
//! This is not yet the final RemoteCore facade. Experimental transport,
//! credential, viewer and capture helpers cover only documented subsets;
//! they do not establish production security, trusted consent or full source
//! parity. Applications must generate and bind session identifiers, enforce
//! policy, and review and test OS and network behavior before deployment.

/// Optional single-controller arbitration within a cooperating process.
pub mod input_arbiter;
/// On-demand capture and video delivery for an authorized session.
pub mod capture_pump;
/// Cooperative capture admission accounting, not a native memory cap.
pub mod capture_budget;
/// Experimental, caller-driven host connection; not a secure remote server.
pub mod host_connection;
/// Optional source-key-exchange admission composition.
#[cfg(feature = "source-security")]
pub mod admitted_host;
/// Explicit direct TCP listener with bounded pre-auth admission.
#[cfg(feature = "source-security")]
pub mod direct_host;
/// Explicit WSS listener with pre-TLS admission.
#[cfg(feature = "source-security")]
pub mod wss_host;
/// Experimental caller-driven viewer transport and protocol demultiplexing.
pub mod viewer_connection;
/// Caller-driven bounded viewer FPS and refresh decisions derived from source.
pub mod viewer_fps;
/// Caller-driven source-style decode-speed measurement bookkeeping.
pub mod viewer_decode_fps;
/// Caller-driven source UI-callback frame-rate accounting.
pub mod viewer_frame_rate;
/// Conservative bounded caller-driven compressed viewer frame queue.
pub mod viewer_video_queue;
/// Caller-owned bounded per-peer cursor selection; no renderer.
pub mod viewer_cursor;
/// Optional keyframe/loss bookkeeping for one video stream.
pub mod video_sync;
/// Bounded per-display video synchronization bookkeeping.
pub mod video_streams;
/// Explicitly trusted-only software multi-display video decoding.
pub mod trusted_video_streams;
/// Caller-driven source-style video pacing and probe/ACK bookkeeping.
pub mod video_schedule;
/// Explicit, caller-driven source-style delay probe/QoS bridge.
pub mod probe_qos;
/// Caller-driven bounded frame wait tracking.
pub mod frame_wait;
/// Caller-driven paced multi-display capture, with no background tasks.
pub mod scheduled_capture;
/// Explicit single-session read-ahead and scheduled-capture composition.
pub mod scheduled_session;
/// Opt-in bounded service loop for an already approved scheduled session.
#[cfg(feature = "source-security")]
pub mod bounded_host_loop;
/// Side-effect-free source Windows DXGI access-lost recovery bookkeeping.
pub mod dxgi_recovery;
/// Side-effect-free model of source static-frame refresh scheduling.
pub mod static_refresh;
/// Opt-in, caller-driven source-style scheduled static refresh.
pub mod scheduled_refresh;
/// Explicit caller-driven bridge for source video preference updates.
pub mod video_preferences;
/// Caller-driven planning for source multi-display subscriptions.
pub mod display_selection;
/// Construct bounded metadata from explicitly enumerated display handles.
pub mod display_metadata;
/// Per-session source-style display update bookkeeping; no automatic I/O.
pub mod display_delivery;
/// Source-style cursor-follow display hints, without side effects.
pub mod cursor_follow;
/// Source-style bounded cursor echo exclusion bookkeeping.
pub mod cursor_echo;
/// Explicit per-session source cursor-shape delivery bookkeeping.
pub mod cursor_delivery;
/// Optional local-only stale-key bookkeeping; no input injection.
pub mod key_expiry;
/// Source-style caller-driven authorized-session inactivity accounting.
pub mod idle_timeout;
/// Optional caller-driven source receive-liveness bookkeeping.
pub mod receive_watchdog;
/// Source-style caller-driven foreground window follow hints.
pub mod window_follow;
/// Side-effect-free validation and planning for resolution requests.
pub mod resolution_plan;
/// Convert read-only Windows mode snapshots to bounded wire metadata.
#[cfg(target_os = "windows")]
pub mod windows_mode_metadata;
/// Caller-owned, side-effect-free resolution recovery bookkeeping.
pub mod resolution_history;
/// Experimental Windows DXGI/VRAM session-bound capture.
#[cfg(all(target_os = "windows", feature = "vram"))]
pub mod vram_pump;
/// Opt-in local tracked-modifier input subset.
pub mod tracked_modifiers;
/// Opt-in source-style Windows touch scale handling.
pub mod windows_touch;
pub mod windows_translate_text_plan;
/// Side-effect-free restricted Windows lock synchronization planning.
pub mod windows_lock_plan;
/// Read-only source Windows-to-Windows hotkey branch planning.
pub mod windows_hotkey_plan;
/// Read-only source Windows session eligibility planning; no OS switching.
pub mod windows_session_plan;

use std::{error::Error, fmt};
use remote_input::{InputBackend, InputController, InputError, MouseButton, ScanCode, VirtualKey};
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
    // Separate from locally granted permissions; this never grants input.
    peer_input_disabled: bool,
}
impl<B: InputBackend> HostInputSession<B> {
    /// Construct a session and input controller with all permissions denied.
    pub fn new(id: SessionId, backend: B) -> Self {
        Self { session: Session::new(id), input: InputController::new(backend), peer_input_disabled: false }
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
            mouse: allowed.control_mouse && !self.peer_input_disabled,
            keyboard: allowed.control_keyboard && !self.peer_input_disabled,
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
            mouse: allowed.control_mouse && !self.peer_input_disabled,
            keyboard: allowed.control_keyboard && !self.peer_input_disabled,
        }) {
            let _ = self.session.fail();
            return Err(HostInputError::Input(error));
        }
        Ok(())
    }
    /// Apply a peer input-disable preference after a trusted caller explicitly
    /// accepts it. Both input classes are suppressed, matching the source's
    /// combined keyboard gate. This never changes local authorization. Disabling
    /// denies new input and attempts to release this controller's held inputs;
    /// enabling restores only permissions still locally granted. On detectable
    /// cleanup failure the session fails and must be closed; OS delivery is not
    /// guaranteed. This is not automatic dispatch of untrusted wire options.
    pub(crate) fn set_peer_input_disabled(&mut self, disabled: bool) -> Result<(), HostInputError> {
        if !matches!(self.session.state(), SessionState::Connected | SessionState::Streaming) {
            return Err(HostInputError::Session(SessionError::InvalidState { state: self.session.state(), operation: "change peer input gate" }));
        }
        self.peer_input_disabled = disabled;
        let local = self.session.permissions();
        if let Err(error) = self.input.set_permissions(remote_input::Permissions {
            mouse: local.control_mouse && !disabled, keyboard: local.control_keyboard && !disabled,
        }) {
            let _ = self.session.fail();
            return Err(HostInputError::Input(error));
        }
        Ok(())
    }
    pub(crate) fn peer_input_disabled(&self) -> bool { self.peer_input_disabled }
    /// Mark an authorized session as streaming once the caller has prepared capture.
    /// This does not itself create a capture task or start a transport.
    pub fn start_streaming(&mut self) -> Result<(), HostInputError> {
        self.session.start_streaming()?;
        Ok(())
    }
    /// Mark streaming stopped. The caller must stop actual capture and delivery tasks.
    pub fn stop_streaming(&mut self) -> Result<(), HostInputError> {
        self.session.stop_streaming()?;
        Ok(())
    }
    /// Encode and send one captured frame using this same session's authorization.
    ///
    /// The supplied transport and encoder remain caller-owned. A failed or
    /// cancelled send requires the sender to be reset before another frame.
    /// The caller must coordinate stream cleanup, codec negotiation and input
    /// ownership across sessions; this method does not spawn background tasks.
    pub async fn send_video(
        &mut self,
        sender: &mut video::VideoSender,
        transport: &mut dyn remote_transport::Transport,
        display: i32,
        pixels: &[u8],
        stride: usize,
        format: remote_codec::PackedFormat,
        pts_ms: i64,
        deadline: std::time::Duration,
    ) -> Result<(), video::VideoError> {
        sender.send_packed(&self.session, transport, display, pixels, stride, format, pts_ms, deadline).await
    }
    /// Send a frame over a network-oriented transport using this session.
    /// An interrupted send may have reached the peer and requires encoder reset.
    /// Network authentication and binding remain the caller's responsibility.
    pub async fn send_video_network(
        &mut self,
        sender: &mut video::VideoSender,
        transport: &mut dyn remote_transport::NetworkTransport,
        display: i32,
        pixels: &[u8],
        stride: usize,
        format: remote_codec::PackedFormat,
        pts_ms: i64,
        deadline: std::time::Duration,
    ) -> Result<(), video::VideoError> {
        sender.send_packed_network(&self.session, transport, display, pixels, stride, format, pts_ms, deadline).await
    }
    /// Send one hardware-encoded frame over a network-oriented stream.
    /// Authentication, codec negotiation and peer binding remain external.
    #[cfg(feature = "hwcodec")]
    pub async fn send_hardware_video_network(
        &mut self,
        sender: &mut video::HardwareVideoSender,
        transport: &mut dyn remote_transport::NetworkTransport,
        display: i32,
        pixels: &[u8],
        stride: usize,
        format: remote_codec::PackedFormat,
        pts_ms: i64,
        deadline: std::time::Duration,
    ) -> Result<(), video::VideoError> {
        sender.send_packed_network(&self.session, transport, display, pixels, stride, format, pts_ms, deadline).await
    }
    /// Move the mouse in virtual-desktop coordinates, after authorization.
    pub fn move_to(&mut self, x: i32, y: i32) -> Result<(), HostInputError> {
        self.session.check(Action::ControlMouse)?;
        self.input.move_to(x, y)?;
        Ok(())
    }
    /// Move the mouse by relative pixels, after authorization.
    pub fn move_relative(&mut self, x: i32, y: i32) -> Result<(), HostInputError> {
        self.session.check(Action::ControlMouse)?;
        self.input.move_relative(x, y)?;
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
    /// Authorized explicit repeated virtual-key down. No OS-wide state check.
    pub fn key_down_with_repeat(&mut self, key: VirtualKey) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?; self.input.key_down_with_repeat(key)?; Ok(())
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
    /// Press a restricted physical Windows scan code after keyboard authorization.
    pub fn scan_down(&mut self, code: ScanCode) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?; self.input.scan_down(code)?; Ok(())
    }
    /// Authorized explicit repeated scan-code down.
    pub fn scan_down_with_repeat(&mut self, code: ScanCode) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?; self.input.scan_down_with_repeat(code)?; Ok(())
    }
    /// Release a tracked physical Windows scan code after keyboard authorization.
    pub fn scan_up(&mut self, code: ScanCode) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?; self.input.scan_up(code)?; Ok(())
    }
    /// Inject a source rdev raw Windows virtual key after authorization.
    pub fn raw_virtual_down(&mut self, key: VirtualKey) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?; self.input.raw_virtual_down(key)?; Ok(())
    }
    /// Authorized explicit repeated raw virtual-key down.
    pub fn raw_virtual_down_with_repeat(&mut self, key: VirtualKey) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?; self.input.raw_virtual_down_with_repeat(key)?; Ok(())
    }
    pub fn raw_virtual_up(&mut self, key: VirtualKey) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?; self.input.raw_virtual_up(key)?; Ok(())
    }
    /// Inject a bounded text sequence after keyboard authorization.
    /// Backend/OS limitations and controller-held key restrictions apply.
    pub fn type_text(&mut self, text: &str) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?;
        self.input.type_text(text)?;
        Ok(())
    }
    /// Explicit pinned Windows Enigo supplementary Unicode path. This is not
    /// local consent, complete SendInput error reporting or OS-global exclusion.
    pub fn type_text_source_windows(&mut self, text: &str, opt_in: remote_input::SourceWindowsUnicodeOptIn) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?;
        self.input.type_text_source_windows(text, opt_in)?; Ok(())
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

/// Windows mouse input dispatcher for the supported RustDesk event subset.
///
/// This deliberately refuses modifier-bearing events;
/// it does not silently reinterpret them. Keyboard translation, touch, consent,
/// session-to-transport binding and inter-session input arbitration are not
/// provided. The caller must protect this API from untrusted peers and ensure
/// the backend implements Windows input units and virtual-desktop coordinates.
pub mod windows_mouse {
    use super::{HostInputError, HostInputSession};
    use remote_input::{InputBackend, MouseButton};
    use remote_protocol::{Envelope, ProtocolError};
    use std::{error::Error, fmt};

    /// Failure inspecting or applying a mouse event.
    #[derive(Debug)]
    pub enum DispatchError {
        /// The envelope is not a RustDesk mouse message.
        Protocol(ProtocolError),
        /// This provisional dispatcher does not implement the event form.
        Unsupported(&'static str),
        /// A wheel delta could not be represented safely in Windows units.
        InvalidWheelDelta,
        /// Session authorization or OS backend failed.
        Host(HostInputError),
    }
    impl fmt::Display for DispatchError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Protocol(e) => write!(f, "mouse protocol: {e}"),
                Self::Unsupported(e) => write!(f, "unsupported mouse event: {e}"),
                Self::InvalidWheelDelta => f.write_str("mouse wheel delta exceeds Windows range"),
                Self::Host(e) => write!(f, "mouse dispatch: {e}"),
            }
        }
    }
    impl Error for DispatchError {}
    impl From<ProtocolError> for DispatchError { fn from(e: ProtocolError) -> Self { Self::Protocol(e) } }
    impl From<HostInputError> for DispatchError { fn from(e: HostInputError) -> Self { Self::Host(e) } }

    /// Apply one RustDesk mouse envelope using Windows source semantics.
    ///
    /// Absolute positions use virtual-desktop coordinates; selecting/mapping a
    /// monitor is the caller's responsibility. Relative deltas are clamped to
    /// ±10,000 as in `src/server/input_service.rs`. Ordinary wheel deltas use
    /// `(-x * 120, y * 120)` Windows units; source trackpad events use unscaled
    /// `(-x, y)` Windows wheel units. Modifiers are explicitly rejected. The session
    /// guard checks `control_mouse`, whose policy differs from upstream's
    /// shared `peer_keyboard_enabled()` gate and needs security review.
    pub fn dispatch<B: InputBackend>(host: &mut HostInputSession<B>, envelope: &Envelope) -> Result<(), DispatchError> {
        // Check authorization even for invalid forms before exposing dispatch.
        host.session.check(remote_session::Action::ControlMouse).map_err(HostInputError::from)?;
        let event = envelope.mouse()?;
        if envelope.mouse_modifiers()?.next().is_some() { return Err(DispatchError::Unsupported("modifier-bearing events")); }
        let action = event.mask & 0x7;
        let buttons = event.mask >> 3;
        match action {
            0 => host.move_to(event.x, event.y)?,
            1 | 2 => {
                let button = match buttons {
                    1 => MouseButton::Left, 2 => MouseButton::Right, 4 => MouseButton::Middle,
                    8 => MouseButton::Back, 16 => MouseButton::Forward,
                    _ => return Err(DispatchError::Unsupported("unknown or combined mouse buttons")),
                };
                if action == 1 { host.mouse_down(button)?; } else { host.mouse_up(button)?; }
            }
            3 => {
                let x = event.x.checked_neg().and_then(|n| n.checked_mul(120)).ok_or(DispatchError::InvalidWheelDelta)?;
                let y = event.y.checked_mul(120).ok_or(DispatchError::InvalidWheelDelta)?;
                host.scroll(x, y)?;
            }
            4 => {
                let x = event.x.checked_neg().ok_or(DispatchError::InvalidWheelDelta)?;
                host.scroll(x, event.y)?;
            },
            5 => host.move_relative(event.x.clamp(-10_000, 10_000), event.y.clamp(-10_000, 10_000))?,
            _ => return Err(DispatchError::Unsupported("unknown event type")),
        }
        Ok(())
    }
}

/// Restricted Windows legacy control-key dispatcher.
///
/// Only unmodified control keys and bounded BMP text are handled. The original RustDesk
/// keyboard service has extensive layout, modifier, lock-state, repeat,
/// portable-service and text handling; those paths are not replicated here.
/// This API is not safe to expose without trusted authorization and input
/// arbitration, and is not a complete RustDesk keyboard implementation.
pub mod windows_keyboard {
    use super::{HostInputError, HostInputSession};
    use remote_input::{InputBackend, ScanCode, VirtualKey};
    use remote_protocol::{Envelope, KeyboardPayload, ProtocolError};
    use std::{error::Error, fmt};

    /// Failure inspecting or applying a keyboard message.
    #[derive(Debug)]
    pub enum DispatchError {
        /// Not a keyboard envelope.
        Protocol(ProtocolError),
        /// A keyboard mode, payload or modifier is not implemented here.
        Unsupported(&'static str),
        /// Session authorization or backend failed.
        Host(HostInputError),
    }
    impl fmt::Display for DispatchError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Protocol(e) => write!(f, "keyboard protocol: {e}"),
                Self::Unsupported(e) => write!(f, "unsupported keyboard event: {e}"),
                Self::Host(e) => write!(f, "keyboard dispatch: {e}"),
            }
        }
    }
    impl Error for DispatchError {}
    impl From<ProtocolError> for DispatchError { fn from(e: ProtocolError) -> Self { Self::Protocol(e) } }
    impl From<HostInputError> for DispatchError { fn from(e: HostInputError) -> Self { Self::Host(e) } }

    // ControlKey numeric values are from message.proto. Virtual-key values match
    // src/server/input_service.rs KEY_MAP and libs/enigo/src/win/keycodes.rs.
    // Modifiers, lock keys and system actions are deliberately excluded.
    pub(crate) fn plain_control_vk(value: i32) -> Option<u16> {
        Some(match value {
            2 => 0x08, 5 => 0x2e, 6 => 0x28, 7 => 0x23, 8 => 0x1b,
            9 => 0x70, 10 => 0x79, 11 => 0x7a, 12 => 0x7b,
            13 => 0x71, 14 => 0x72, 15 => 0x73, 16 => 0x74,
            17 => 0x75, 18 => 0x76, 19 => 0x77, 20 => 0x78,
            21 => 0x24, 22 => 0x25, 25 => 0x22, 26 => 0x21,
            27 => 0x0d, 28 => 0x27, 30 => 0x20, 31 => 0x09, 32 => 0x26,
            33..=42 => 0x60 + (value as u16 - 33),
            43 => 0x03, 44 => 0x0c, 46 => 0x13,
            54 => 0x29, 55 => 0x2a, 56 => 0x2b, 57 => 0x2c,
            58 => 0x2d, 59 => 0x2f, 61 => 0x6c,
            65 => 0x5d, 66 => 0x6a, 67 => 0x6b, 68 => 0x6d,
            69 => 0x6e, 70 => 0x6f, 71 => 0x3d, 72 => 0x0d,
            _ => return None,
        })
    }

    /// Restricted source Map-mode dispatch using the pinned rdev Windows raw
    /// scan-code backend. This does not implement source desktop switching,
    /// modifier repair, repeat or translate mode. Caller must explicitly opt in,
    /// bind an authorized Windows peer and ensure exclusive OS input ownership.
    pub fn dispatch_map<B: InputBackend>(host: &mut HostInputSession<B>, envelope: &Envelope) -> Result<(), DispatchError> {
        dispatch_map_with_repeat(host, envelope, false)
    }
    /// Caller explicitly selects whether repeated down messages reach the OS.
    /// This is not OS-wide input arbitration or proof of local consent.
    pub fn dispatch_map_with_repeat<B: InputBackend>(host: &mut HostInputSession<B>, envelope: &Envelope, repeat: bool) -> Result<(), DispatchError> {
        host.session.check(remote_session::Action::ControlKeyboard).map_err(HostInputError::from)?;
        let event = envelope.keyboard()?;
        if event.mode() != 1 || event.press() || event.modifiers().next().is_some() {
            return Err(DispatchError::Unsupported("unsupported map-mode flags or modifiers"));
        }
        let raw = match event.payload() { Some(KeyboardPayload::Position(value)) => value, _ => return Err(DispatchError::Unsupported("map-mode requires a position scan code")) };
        let code = remote_input::ScanCode::new(raw).map_err(|_| DispatchError::Unsupported("invalid Windows scan code"))?;
        if event.down() { if repeat { host.scan_down_with_repeat(code)?; } else { host.scan_down(code)?; } } else { host.scan_up(code)?; }
        Ok(())
    }
    /// Restricted Windows Translate-mode `Chr` handling. Source
    /// `translate_process_code` uses a scan code when the upper 16 bits are
    /// zero, otherwise a raw Windows virtual key from those upper bits. This
    /// subset rejects modifier metadata, press, Unicode, sequences and Windows
    /// hotkeys; it does not synchronize OS state or switch desktops. The input
    /// controller rejects mixed representations while any keys are held.
    pub fn dispatch_translate<B: InputBackend>(host: &mut HostInputSession<B>, envelope: &Envelope) -> Result<(), DispatchError> {
        dispatch_translate_with_repeat(host, envelope, false)
    }
    /// Caller explicitly selects whether repeated down messages reach the OS.
    /// This is not OS-wide input arbitration or proof of local consent.
    pub fn dispatch_translate_with_repeat<B: InputBackend>(host: &mut HostInputSession<B>, envelope: &Envelope, repeat: bool) -> Result<(), DispatchError> {
        host.session.check(remote_session::Action::ControlKeyboard).map_err(HostInputError::from)?;
        let event = envelope.keyboard()?;
        if event.mode() != 2 || event.press() || event.modifiers().next().is_some() {
            return Err(DispatchError::Unsupported("unsupported translate-mode flags or modifiers"));
        }
        let raw = match event.payload() { Some(KeyboardPayload::Position(value)) => value, _ => return Err(DispatchError::Unsupported("translate mode requires a position code")) };
        let vk = raw >> 16;
        if vk == 0 {
            let code = ScanCode::new(raw).map_err(|_| DispatchError::Unsupported("invalid Windows scan code"))?;
            if event.down() { if repeat { host.scan_down_with_repeat(code)?; } else { host.scan_down(code)?; } } else { host.scan_up(code)?; }
        } else {
            let key = u16::try_from(vk).ok().and_then(|value| VirtualKey::new(value).ok()).ok_or(DispatchError::Unsupported("invalid Windows virtual key"))?;
            if event.down() { if repeat { host.raw_virtual_down_with_repeat(key)?; } else { host.raw_virtual_down(key)?; } } else { host.raw_virtual_up(key)?; }
        }
        Ok(())
    }
    /// Explicitly dispatch only source legacy Unicode/sequence text using the
    /// pinned Windows Enigo semantics. It permits non-BMP surrogate downs and
    /// therefore has the token's delivery/cleanup risks. Caller must establish
    /// local consent, desktop and OS-wide exclusive ownership. Other keyboard
    /// paths and peer input cannot be allowed to race this operation.
    pub fn dispatch_source_unicode<B: InputBackend>(host: &mut HostInputSession<B>, envelope: &Envelope,
        opt_in: remote_input::SourceWindowsUnicodeOptIn) -> Result<(), DispatchError> {
        host.session.check(remote_session::Action::ControlKeyboard).map_err(HostInputError::from)?;
        let event = envelope.keyboard()?;
        if event.mode() != 0 || event.modifiers().next().is_some() { return Err(DispatchError::Unsupported("unsupported Unicode flags or modifiers")); }
        match event.payload() {
            Some(KeyboardPayload::Unicode(value)) => {
                let character = char::from_u32(value).ok_or(DispatchError::Unsupported("invalid Unicode scalar"))?;
                host.type_text_source_windows(&character.to_string(), opt_in)?;
            },
            Some(KeyboardPayload::Sequence(text)) => host.type_text_source_windows(text, opt_in)?,
            _ => return Err(DispatchError::Unsupported("requires Unicode or sequence")),
        }
        Ok(())
    }
    /// Apply a non-modifier legacy control-key or Unicode/sequence message to a Windows-style backend.
    ///
    /// A `press` is a down/up pair; otherwise the wire `down` bit determines
    /// state. Repeat downs are suppressed by the input controller. Unlike the
    /// original service this method does not synchronize global modifier state,
    /// switch Windows desktops, support layout/scan codes or non-BMP text, or run the
    /// portable service. Unicode and sequence variants are injected on every
    /// received event as in the source legacy handler, regardless of down/press. Those limitations can affect even accepted keys.
    pub fn dispatch<B: InputBackend>(host: &mut HostInputSession<B>, envelope: &Envelope) -> Result<(), DispatchError> {
        dispatch_with_repeat(host, envelope, false)
    }
    /// Caller explicitly selects whether repeated down messages reach the OS.
    /// This is not OS-wide input arbitration or proof of local consent.
    pub fn dispatch_with_repeat<B: InputBackend>(host: &mut HostInputSession<B>, envelope: &Envelope, repeat: bool) -> Result<(), DispatchError> {
        host.session.check(remote_session::Action::ControlKeyboard).map_err(HostInputError::from)?;
        let event = envelope.keyboard()?;
        if event.mode() != 0 { return Err(DispatchError::Unsupported("non-legacy keyboard mode")); }
        if event.modifiers().next().is_some() { return Err(DispatchError::Unsupported("modifier-bearing keyboard event")); }
        match event.payload() {
            Some(KeyboardPayload::ControlKey(value)) => {
                let code = plain_control_vk(value).ok_or(DispatchError::Unsupported("modifier, system, or unknown control key"))?;
                let key = VirtualKey::new(code).map_err(|_| DispatchError::Unsupported("invalid virtual key"))?;
                if event.press() { host.key_press(key)?; }
                else if event.down() { if repeat { host.key_down_with_repeat(key)?; } else { host.key_down(key)?; } }
                else { host.key_up(key)?; }
            },
            Some(KeyboardPayload::Unicode(value)) => {
                let character = char::from_u32(value).ok_or(DispatchError::Unsupported("invalid Unicode scalar"))?;
                host.type_text(&character.to_string())?;
            },
            Some(KeyboardPayload::Sequence(text)) => host.type_text(text)?,
            _ => return Err(DispatchError::Unsupported("position or Windows hotkey payload")),
        }
        Ok(())
    }
}

/// Capture/codec/protocol/transport integration for a single video stream.
///
/// This module is experimental and must not decode untrusted network data. It
/// does not provide authentication, rendering, negotiation, frame acknowledgments,
/// or a complete host/viewer lifecycle.
pub mod video {
    use remote_codec::{Codec, DecodedFrame, EncodedFrame, EncoderConfig, PackedFormat, Packet, SoftwareDecoder, SoftwareEncoder};
    use remote_protocol::{Envelope, OwnedVideoPacket, ProtocolError, VideoCodec, MAX_ENVELOPE_BYTES};
    use remote_session::{Action, Session, SessionError, SessionState};
    use remote_transport::{Transport, TransportError};
    use std::{error::Error, fmt, io, time::Duration};

    /// An error from the video pipeline.
    #[derive(Debug)]
    pub enum VideoError {
        /// Session state or capability denied the operation.
        Session(SessionError),
        /// Capture conversion or encoder/decoder failed.
        Codec(io::Error),
        /// RustDesk protocol serialization or decoding failed.
        Protocol(ProtocolError),
        /// Message transport failed.
        Transport(TransportError),
        /// Network transport failed; send delivery may be indeterminate.
        Network(remote_transport::NetworkTransportError),
        /// The codec requires resetting before another frame can be sent.
        EncoderResetRequired,
        /// No successful cached packed input is available for repeating.
        NoRepeatableInput,
        /// The wire codec is not supported by this software decoder.
        UnsupportedCodec,
        /// The received codec does not match the configured decoder.
        CodecMismatch,
    }
    impl fmt::Display for VideoError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Session(e) => write!(f, "session: {e}"),
                Self::Codec(e) => write!(f, "codec: {e}"),
                Self::Protocol(e) => write!(f, "protocol: {e}"),
                Self::Transport(e) => write!(f, "transport: {e}"),
                Self::Network(e) => write!(f, "network: {e}"),
                Self::EncoderResetRequired => f.write_str("encoder must be reset"),
                Self::NoRepeatableInput => f.write_str("no repeatable packed input"),
                Self::UnsupportedCodec => f.write_str("unsupported video codec"),
                Self::CodecMismatch => f.write_str("received video codec differs from configured decoder"),
            }
        }
    }
    impl Error for VideoError {}
    impl From<SessionError> for VideoError { fn from(e: SessionError) -> Self { Self::Session(e) } }
    impl From<io::Error> for VideoError { fn from(e: io::Error) -> Self { Self::Codec(e) } }
    impl From<ProtocolError> for VideoError { fn from(e: ProtocolError) -> Self { Self::Protocol(e) } }
    impl From<TransportError> for VideoError { fn from(e: TransportError) -> Self { Self::Transport(e) } }
    impl From<remote_transport::NetworkTransportError> for VideoError { fn from(e: remote_transport::NetworkTransportError) -> Self { Self::Network(e) } }

    fn wire_codec(codec: Codec) -> VideoCodec {
        match codec { Codec::Vp8 => VideoCodec::Vp8, Codec::Vp9 => VideoCodec::Vp9, Codec::Av1 => VideoCodec::Av1 }
    }
    fn software_codec(codec: VideoCodec) -> Result<Codec, VideoError> {
        match codec { VideoCodec::Vp8 => Ok(Codec::Vp8), VideoCodec::Vp9 => Ok(Codec::Vp9), VideoCodec::Av1 => Ok(Codec::Av1), _ => Err(VideoError::UnsupportedCodec) }
    }

    /// Result of an explicit source-aware software encode/send attempt.
    /// `VpxNoOutput` sends nothing and is not an ACK or evidence of rendering.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SendOutcome { Sent, VpxNoOutput }

    fn outcome_wire(codec: Codec, display: i32, outcome: remote_codec::EncodeOutcome, limit: usize) -> Result<Option<Vec<u8>>, VideoError> {
        let encoded = match outcome { remote_codec::EncodeOutcome::Frame(frame) => frame, remote_codec::EncodeOutcome::VpxNoOutput => return Ok(None) };
        let packets: Vec<OwnedVideoPacket> = encoded.packets.into_iter().map(|packet| OwnedVideoPacket {
            data: packet.data, key: packet.key, pts: packet.pts,
        }).collect();
        Ok(Some(Envelope::video_event(display, wire_codec(codec), &packets)?.encode(limit)?))
    }

    /// A single software encoder that writes RustDesk protobuf video envelopes.
    pub struct VideoSender {
        encoder: Option<SoftwareEncoder>,
        config: EncoderConfig,
        max_envelope_bytes: usize,
    }
    impl VideoSender {
        /// Create an encoder with an explicit serialized-envelope limit.
        pub fn new(config: EncoderConfig, max_envelope_bytes: usize) -> Result<Self, VideoError> {
            if max_envelope_bytes == 0 || max_envelope_bytes > MAX_ENVELOPE_BYTES {
                return Err(VideoError::Protocol(ProtocolError::InvalidLimit));
            }
            Ok(Self { encoder: Some(SoftwareEncoder::new(config)?), config, max_envelope_bytes })
        }
        /// Recreate the encoder, for example after a failed or cancelled send.
        /// The caller must negotiate a decoder refresh before sending again.
        pub fn reset(&mut self, config: EncoderConfig) -> Result<(), VideoError> {
            // Never keep a potentially stale encoder when replacement fails.
            self.encoder = None;
            let encoder = SoftwareEncoder::new(config)?;
            self.config = config;
            self.encoder = Some(encoder);
            Ok(())
        }
        /// Discard predictive state before an explicit backend transition.
        #[cfg(target_os = "windows")]
        pub(crate) fn invalidate(&mut self) { self.encoder = None; }
        /// Whether the encoder must be recreated after a failed/cancelled send.
        pub fn needs_reset(&self) -> bool { self.encoder.is_none() }
        /// Source-reported encoder bitrate and dynamic-quality capability.
        pub fn encoder_stats(&self) -> Result<(u32, bool), VideoError> {
            let encoder = self.encoder.as_ref().ok_or(VideoError::EncoderResetRequired)?;
            Ok((encoder.bitrate(), encoder.supports_quality_change()))
        }
        /// Whether a previously converted packed frame can be repeated. This
        /// is local bookkeeping, not current authorization or delivery proof.
        pub fn has_repeatable_input(&self) -> bool { self.encoder.as_ref().map_or(false, |encoder| encoder.has_repeatable_input()) }
        /// Forget the wrapper-owned converted pixels immediately where possible.
        /// Native codec buffers and external copies remain outside this action.
        pub fn clear_repeat_input(&mut self) { if let Some(encoder) = self.encoder.as_mut() { encoder.clear_repeat_input(); } }
        /// Change quality in place. A backend failure discards the encoder,
        /// because its state after a partial native mutation is unknown.
        pub fn set_quality(&mut self, quality: f32) -> Result<(), VideoError> {
            if !quality.is_finite() || quality <= 0.0 || quality > 2.0 {
                return Err(VideoError::Codec(io::Error::new(io::ErrorKind::InvalidInput, "quality must be positive and at most 2")));
            }
            let mut encoder = self.encoder.take().ok_or(VideoError::EncoderResetRequired)?;
            encoder.set_quality(quality)?;
            self.config.quality = quality;
            self.encoder = Some(encoder);
            Ok(())
        }

        /// Convert and encode one packed captured frame, then send its protobuf envelope.
        ///
        /// The session must already be streaming and have screen-view permission.
        /// On conversion, serialization or transport error, or if the returned
        /// future is dropped while a send is in progress, the encoder is dropped
        /// and must be reset. This avoids continuing a predictive stream after a
        /// potentially lost frame; it does not itself request a remote keyframe.
        /// The caller must also stop capture immediately on session revocation.
        pub async fn send_packed(
            &mut self,
            session: &Session,
            transport: &mut dyn Transport,
            display: i32,
            pixels: &[u8],
            stride: usize,
            format: PackedFormat,
            pts_ms: i64,
            deadline: Duration,
        ) -> Result<(), VideoError> {
            if session.state() != SessionState::Streaming {
                return Err(VideoError::Session(SessionError::InvalidState { state: session.state(), operation: "send video" }));
            }
            session.check(Action::ViewScreen)?;
            let mut encoder = self.encoder.take().ok_or(VideoError::EncoderResetRequired)?;
            let encoded = encoder.encode_packed(pixels, stride, format, pts_ms)?;
            let packets: Vec<OwnedVideoPacket> = encoded.packets.into_iter().map(|packet| OwnedVideoPacket {
                data: packet.data, key: packet.key, pts: packet.pts,
            }).collect();
            let wire = Envelope::video_event(display, wire_codec(self.config.codec), &packets)?.encode(self.max_envelope_bytes)?;
            transport.send(&wire, deadline).await?;
            self.encoder = Some(encoder);
            Ok(())
        }
    }

    impl VideoSender {
        /// Send one encoded frame over a network transport with indeterminate
        /// delivery on failure. Failed/cancelled sends require encoder reset and
        /// explicit decoder resynchronization; they must not be replayed blindly.
        pub async fn send_packed_network(
            &mut self,
            session: &Session,
            transport: &mut dyn remote_transport::NetworkTransport,
            display: i32,
            pixels: &[u8],
            stride: usize,
            format: PackedFormat,
            pts_ms: i64,
            deadline: Duration,
        ) -> Result<(), VideoError> {
            if session.state() != SessionState::Streaming {
                return Err(VideoError::Session(SessionError::InvalidState { state: session.state(), operation: "send video" }));
            }
            session.check(Action::ViewScreen)?;
            let mut encoder = self.encoder.take().ok_or(VideoError::EncoderResetRequired)?;
            let encoded = encoder.encode_packed(pixels, stride, format, pts_ms)?;
            let packets: Vec<OwnedVideoPacket> = encoded.packets.into_iter().map(|packet| OwnedVideoPacket {
                data: packet.data, key: packet.key, pts: packet.pts,
            }).collect();
            let wire = Envelope::video_event(display, wire_codec(self.config.codec), &packets)?.encode(self.max_envelope_bytes)?;
            transport.send(&wire, deadline).await?;
            self.encoder = Some(encoder);
            Ok(())
        }
    }

    impl VideoSender {
        /// Explicitly resend cached screen input over network transport after a
        /// fresh local authorization check. The opt-in is an assertion, not a
        /// consent UI; the caller must enforce privacy, age and repeat limits,
        /// service input/ACKs, and coordinate decoder recovery. No capture is
        /// performed and no scheduler is started. Failed or cancelled I/O,
        /// native no-output and serialization errors discard the encoder; never
        /// blindly retry uncertain delivery. This is narrower than source VPX
        /// static refresh because it cannot distinguish native no-output errors.
        pub async fn send_repeat_network(&mut self, session: &Session, transport: &mut dyn remote_transport::NetworkTransport,
            display: i32, pts_ms: i64, deadline: Duration, opt_in: remote_codec::RepeatFrameOptIn) -> Result<(), VideoError> {
            if session.state() != SessionState::Streaming {
                return Err(VideoError::Session(SessionError::InvalidState { state: session.state(), operation: "repeat video" }));
            }
            session.check(Action::ViewScreen)?;
            if deadline.is_zero() { return Err(VideoError::Codec(io::Error::new(io::ErrorKind::InvalidInput, "zero deadline"))); }
            if self.needs_reset() { return Err(VideoError::EncoderResetRequired); }
            if !self.has_repeatable_input() { return Err(VideoError::NoRepeatableInput); }
            let mut encoder = self.encoder.take().ok_or(VideoError::EncoderResetRequired)?;
            let encoded = encoder.repeat_packed(pts_ms, opt_in)?;
            let packets: Vec<OwnedVideoPacket> = encoded.packets.into_iter().map(|packet| OwnedVideoPacket {
                data: packet.data, key: packet.key, pts: packet.pts,
            }).collect();
            let wire = Envelope::video_event(display, wire_codec(self.config.codec), &packets)?.encode(self.max_envelope_bytes)?;
            transport.send(&wire, deadline).await?;
            self.encoder = Some(encoder);
            Ok(())
        }
    }

    impl VideoSender {
        /// Explicit source-aware software encode/send. A typed VPX no-output
        /// retains the encoder and cached input, sends no envelope, and returns
        /// `VpxNoOutput`. Any other native/serialization/send failure or an
        /// in-flight cancellation discards the encoder. The application must
        /// enforce session authorization, input retention, repeat pacing and
        /// decoder recovery; this does not run the source service or prove
        /// delivery. The older `send_packed_network` retains its semantics.
        pub async fn send_packed_network_outcome(&mut self, session: &Session, transport: &mut dyn remote_transport::NetworkTransport,
            display: i32, pixels: &[u8], stride: usize, format: PackedFormat, pts_ms: i64, deadline: Duration) -> Result<SendOutcome, VideoError> {
            if session.state() != SessionState::Streaming {
                return Err(VideoError::Session(SessionError::InvalidState { state: session.state(), operation: "send video" }));
            }
            session.check(Action::ViewScreen)?;
            if deadline.is_zero() || display < 0 { return Err(VideoError::Codec(io::Error::new(io::ErrorKind::InvalidInput, "invalid deadline or display"))); }
            let mut encoder = self.encoder.take().ok_or(VideoError::EncoderResetRequired)?;
            let outcome = encoder.encode_packed_outcome(pixels, stride, format, pts_ms)?;
            let wire = outcome_wire(self.config.codec, display, outcome, self.max_envelope_bytes)?;
            let result = if let Some(wire) = wire {
                transport.send(&wire, deadline).await?;
                SendOutcome::Sent
            } else { SendOutcome::VpxNoOutput };
            self.encoder = Some(encoder);
            Ok(result)
        }
        /// In-process-transport counterpart of `send_packed_network_outcome`.
        /// A no-output result enqueues nothing and retains the encoder. The
        /// local transport's cancellation guarantee does not prove rendering.
        pub async fn send_packed_outcome(&mut self, session: &Session, transport: &mut dyn Transport,
            display: i32, pixels: &[u8], stride: usize, format: PackedFormat, pts_ms: i64, deadline: Duration) -> Result<SendOutcome, VideoError> {
            if session.state() != SessionState::Streaming {
                return Err(VideoError::Session(SessionError::InvalidState { state: session.state(), operation: "send video" }));
            }
            session.check(Action::ViewScreen)?;
            if deadline.is_zero() || display < 0 { return Err(VideoError::Codec(io::Error::new(io::ErrorKind::InvalidInput, "invalid deadline or display"))); }
            let mut encoder = self.encoder.take().ok_or(VideoError::EncoderResetRequired)?;
            let outcome = encoder.encode_packed_outcome(pixels, stride, format, pts_ms)?;
            let wire = outcome_wire(self.config.codec, display, outcome, self.max_envelope_bytes)?;
            let result = if let Some(wire) = wire { transport.send(&wire, deadline).await?; SendOutcome::Sent } else { SendOutcome::VpxNoOutput };
            self.encoder = Some(encoder); Ok(result)
        }
        /// In-process counterpart of `send_repeat_network_outcome`. The caller
        /// remains responsible for consent, freshness, pacing and revocation.
        pub async fn send_repeat_outcome(&mut self, session: &Session, transport: &mut dyn Transport,
            display: i32, pts_ms: i64, deadline: Duration, opt_in: remote_codec::RepeatFrameOptIn) -> Result<SendOutcome, VideoError> {
            if session.state() != SessionState::Streaming {
                return Err(VideoError::Session(SessionError::InvalidState { state: session.state(), operation: "repeat video" }));
            }
            session.check(Action::ViewScreen)?;
            if deadline.is_zero() || display < 0 { return Err(VideoError::Codec(io::Error::new(io::ErrorKind::InvalidInput, "invalid deadline or display"))); }
            if self.needs_reset() { return Err(VideoError::EncoderResetRequired); }
            if !self.has_repeatable_input() { return Err(VideoError::NoRepeatableInput); }
            let mut encoder = self.encoder.take().ok_or(VideoError::EncoderResetRequired)?;
            let outcome = encoder.repeat_packed_outcome(pts_ms, opt_in)?;
            let wire = outcome_wire(self.config.codec, display, outcome, self.max_envelope_bytes)?;
            let result = if let Some(wire) = wire { transport.send(&wire, deadline).await?; SendOutcome::Sent } else { SendOutcome::VpxNoOutput };
            self.encoder = Some(encoder); Ok(result)
        }
        /// Source-aware repeat of a locally retained converted screen frame.
        /// This rechecks view permission but the opt-in is not proof of owner
        /// consent. Caller must bound image age/repeats, apply ACK policy and
        /// ensure the desktop and viewer still correspond to the cached frame.
        /// Failed/cancelled sends are indeterminate and require reset/closure.
        pub async fn send_repeat_network_outcome(&mut self, session: &Session, transport: &mut dyn remote_transport::NetworkTransport,
            display: i32, pts_ms: i64, deadline: Duration, opt_in: remote_codec::RepeatFrameOptIn) -> Result<SendOutcome, VideoError> {
            if session.state() != SessionState::Streaming {
                return Err(VideoError::Session(SessionError::InvalidState { state: session.state(), operation: "repeat video" }));
            }
            session.check(Action::ViewScreen)?;
            if deadline.is_zero() || display < 0 { return Err(VideoError::Codec(io::Error::new(io::ErrorKind::InvalidInput, "invalid deadline or display"))); }
            if self.needs_reset() { return Err(VideoError::EncoderResetRequired); }
            if !self.has_repeatable_input() { return Err(VideoError::NoRepeatableInput); }
            let mut encoder = self.encoder.take().ok_or(VideoError::EncoderResetRequired)?;
            let outcome = encoder.repeat_packed_outcome(pts_ms, opt_in)?;
            let wire = outcome_wire(self.config.codec, display, outcome, self.max_envelope_bytes)?;
            let result = if let Some(wire) = wire {
                transport.send(&wire, deadline).await?;
                SendOutcome::Sent
            } else { SendOutcome::VpxNoOutput };
            self.encoder = Some(encoder);
            Ok(result)
        }
    }

    /// Optional H.264/H.265 RAM video sender using RustDesk's hardware encoder.
    ///
    /// This does not negotiate the codec or implement hardware decoding. On any
    /// failed/cancelled send the encoder is discarded and must be recreated;
    /// the remote decoder also needs an explicit resynchronization strategy.
    #[cfg(feature = "hwcodec")]
    pub struct HardwareVideoSender {
        encoder: Option<remote_codec::hardware::HardwareEncoder>,
        max_envelope_bytes: usize,
    }
    #[cfg(feature = "hwcodec")]
    impl HardwareVideoSender {
        /// Select the source-configured hardware RAM backend.
        pub fn new(config: remote_codec::hardware::HardwareEncoderConfig, max_envelope_bytes: usize) -> Result<Self, VideoError> {
            if max_envelope_bytes == 0 || max_envelope_bytes > MAX_ENVELOPE_BYTES {
                return Err(VideoError::Protocol(ProtocolError::InvalidLimit));
            }
            Ok(Self { encoder: Some(remote_codec::hardware::HardwareEncoder::new(config)?), max_envelope_bytes })
        }
        /// Whether interruption has discarded the encoder.
        pub fn needs_reset(&self) -> bool { self.encoder.is_none() }
        /// Replace an encoder after a stream failure and coordinate peer resynchronization separately.
        pub fn reset(&mut self, config: remote_codec::hardware::HardwareEncoderConfig) -> Result<(), VideoError> {
            self.encoder = None;
            self.encoder = Some(remote_codec::hardware::HardwareEncoder::new(config)?);
            Ok(())
        }
        /// Encode one packed frame and send the original RustDesk video envelope.
        /// Send failure/cancellation can have an indeterminate delivery outcome.
        pub async fn send_packed_network(
            &mut self, session: &Session, transport: &mut dyn remote_transport::NetworkTransport,
            display: i32, pixels: &[u8], stride: usize, format: PackedFormat, pts_ms: i64, deadline: Duration,
        ) -> Result<(), VideoError> {
            if session.state() != SessionState::Streaming {
                return Err(VideoError::Session(SessionError::InvalidState { state: session.state(), operation: "send video" }));
            }
            session.check(Action::ViewScreen)?;
            let mut encoder = self.encoder.take().ok_or(VideoError::EncoderResetRequired)?;
            let encoded = encoder.encode_packed(pixels, stride, format, pts_ms)?;
            let codec = match encoded.codec {
                remote_codec::hardware::HardwareCodec::H264 => VideoCodec::H264,
                remote_codec::hardware::HardwareCodec::H265 => VideoCodec::H265,
            };
            let packets: Vec<OwnedVideoPacket> = encoded.packets.into_iter().map(|packet| OwnedVideoPacket {
                data: packet.data, key: packet.key, pts: packet.pts,
            }).collect();
            let wire = Envelope::video_event(display, codec, &packets)?.encode(self.max_envelope_bytes)?;
            transport.send(&wire, deadline).await?;
            self.encoder = Some(encoder);
            Ok(())
        }
    }

    /// Decoded output together with its source display index.
    pub struct VideoImage<'a> {
        /// Source display index carried by the RustDesk envelope.
        pub display: i32,
        /// Packed decoded image, valid until the next decoder operation.
        pub frame: DecodedFrame<'a>,
    }

    /// H.264/H.265 RAM decoder for trusted RustDesk video envelopes.
    /// Compressed dimensions and driver allocations are not bounded or sandboxed.
    #[cfg(feature = "hwcodec")]
    pub struct HardwareVideoReceiver {
        decoder: remote_codec::hardware::HardwareDecoder,
        codec: remote_codec::hardware::HardwareCodec,
        max_envelope_bytes: usize,
    }
    #[cfg(feature = "hwcodec")]
    impl HardwareVideoReceiver {
        /// Create a source-selected RAM decoder. No capability negotiation is performed.
        pub fn new(codec: remote_codec::hardware::HardwareCodec, max_envelope_bytes: usize) -> Result<Self, VideoError> {
            if max_envelope_bytes == 0 || max_envelope_bytes > MAX_ENVELOPE_BYTES {
                return Err(VideoError::Protocol(ProtocolError::InvalidLimit));
            }
            Ok(Self { decoder: remote_codec::hardware::HardwareDecoder::new(codec)?, codec, max_envelope_bytes })
        }
        /// Decode a trusted H.264/H.265 envelope; untrusted network data is unsafe.
        pub fn decode(&mut self, bytes: &[u8]) -> Result<Option<VideoImage<'_>>, VideoError> {
            let envelope = Envelope::decode(bytes, self.max_envelope_bytes)?;
            let view = envelope.video()?;
            let expected = match self.codec {
                remote_codec::hardware::HardwareCodec::H264 => VideoCodec::H264,
                remote_codec::hardware::HardwareCodec::H265 => VideoCodec::H265,
            };
            if view.codec != expected { return Err(VideoError::CodecMismatch); }
            let display = view.display;
            let packets = view.packets().map(|p| Packet { data: p.data.to_vec(), key: p.key, pts: p.pts }).collect();
            let frame = remote_codec::hardware::HardwareFrame { codec: self.codec, packets };
            Ok(self.decoder.decode(&frame)?.map(|frame| VideoImage { display, frame }))
        }
        /// Receive then decode a trusted envelope from an external stream.
        /// This does not authenticate the sender or harden the native decoder.
        pub async fn receive_network(&mut self, transport: &mut dyn remote_transport::NetworkTransport, deadline: Duration) -> Result<Option<VideoImage<'_>>, VideoError> {
            let bytes = transport.receive(deadline).await?;
            self.decode(&bytes)
        }
    }

    /// Software decoder for RustDesk video envelopes.
    ///
    /// Only use with trusted, authenticated input in a controlled environment.
    /// Length checks do not prevent a compressed frame from demanding excessive
    /// native decoder memory. This is not yet safe for internet-facing peers.
    pub struct VideoReceiver {
        decoder: SoftwareDecoder,
        codec: Codec,
        max_envelope_bytes: usize,
    }
    impl VideoReceiver {
        /// Create a decoder for the negotiated software codec.
        pub fn new(codec: Codec, max_envelope_bytes: usize) -> Result<Self, VideoError> {
            if max_envelope_bytes == 0 || max_envelope_bytes > MAX_ENVELOPE_BYTES {
                return Err(VideoError::Protocol(ProtocolError::InvalidLimit));
            }
            Ok(Self { decoder: SoftwareDecoder::new(codec)?, codec, max_envelope_bytes })
        }
        /// Decode an already-received protobuf envelope.
        /// This does not automatically recover from corruption or lost frames.
        pub fn decode(&mut self, bytes: &[u8]) -> Result<Option<VideoImage<'_>>, VideoError> {
            let envelope = Envelope::decode(bytes, self.max_envelope_bytes)?;
            let view = envelope.video()?;
            let codec = software_codec(view.codec)?;
            if codec != self.codec { return Err(VideoError::CodecMismatch); }
            let display = view.display;
            let packets: Vec<Packet> = view.packets().map(|packet| Packet {
                data: packet.data.to_vec(), key: packet.key, pts: packet.pts,
            }).collect();
            let encoded = EncodedFrame { codec, packets };
            Ok(self.decoder.decode(&encoded)?.map(|frame| VideoImage { display, frame }))
        }
        /// Receive and decode a video envelope from a network-oriented stream.
        /// This does not authenticate the stream or harden the native decoder.
        pub async fn receive_network(&mut self, transport: &mut dyn remote_transport::NetworkTransport, deadline: Duration) -> Result<Option<VideoImage<'_>>, VideoError> {
            let bytes = transport.receive(deadline).await?;
            self.decode(&bytes)
        }
        /// Receive and decode a single video envelope from a transport.
        /// A non-video message returns a protocol error; demultiplexing and
        /// handling other message kinds are the caller's responsibility.
        pub async fn receive(&mut self, transport: &mut dyn Transport, deadline: Duration) -> Result<Option<VideoImage<'_>>, VideoError> {
            let bytes = transport.receive(deadline).await?;
            self.decode(&bytes)
        }
    }
}

/// Read the Windows current-desktop cursor only for an authorized view session.
/// This checks session state but does not bind or authenticate a transport.
/// The result includes no cursor shape and cannot implement source service,
/// secure-desktop, cross-session or portable-service cursor behavior.
#[cfg(target_os = "windows")]
pub fn windows_cursor_snapshot<B: InputBackend>(host: &HostInputSession<B>) -> Result<remote_capture::windows_cursor::CursorSnapshot, cursor_snapshot::Error> {
    if !matches!(host.state(), SessionState::Connected | SessionState::Streaming) || !host.permissions().view_screen {
        return Err(cursor_snapshot::Error::NotAuthorized);
    }
    remote_capture::windows_cursor::snapshot().map_err(cursor_snapshot::Error::Capture)
}

/// Errors sampling a session-bound Windows cursor.
#[cfg(target_os = "windows")]
pub mod cursor_snapshot {
    /// A permission or native sampling failure.
    #[derive(Debug)]
    pub enum Error { NotAuthorized, Capture(std::io::Error) }
    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self { Self::NotAuthorized => f.write_str("screen view is not authorized"), Self::Capture(e) => write!(f, "cursor snapshot: {e}") }
        }
    }
    impl std::error::Error for Error {}
}
