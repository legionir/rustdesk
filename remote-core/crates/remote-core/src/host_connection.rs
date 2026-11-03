//! Experimental ownership bridge between a network stream and host session.
//!
//! This is **not** a secure channel or a complete RustDesk host. It owns a
//! stream through challenge, password verification, local approval, input and
//! capture steps, but cannot cryptographically bind the stream to an end peer.
//! Password challenge transcripts permit offline guessing; TLS at a relay does
//! not protect the desktop peer from that relay. Use only in a controlled,
//! trusted environment pending design review, implementation and tests.
//!
//! This type does not perform the source handshake itself; an optional separate
//! pinned source-v1 transport adapter exists but is unverified. There is no 2FA,
//! trusted-device flow, full login semantics, failure rate limiting, trusted
//! consent UI, automatic codec negotiation, event loop, heartbeat scheduler,
//! reconnect, or cross-process input lock.
//! Untrusted login claims never identify the password holder. A trusted caller
//! supplies the policy and must ensure it is a real local owner decision.

use crate::{capture_pump::{CapturePump, CapturePumpError}, windows_keyboard, windows_mouse, HostInputError, HostInputSession};
use remote_capture::Display;
use remote_codec::EncoderConfig;
use remote_input::InputBackend;
use remote_protocol::{Envelope, MessageKind, ProtocolError, MAX_ENVELOPE_BYTES, MAX_PRE_AUTH_BYTES};
use remote_security::{admission::{AdmissionError, AdmissionPermit}, PasswordVerifier};
use remote_session::{Authorizer, Credential, Permissions, SessionId, SessionState};
use remote_transport::{NetworkTransport, NetworkTransportError};
use std::{error::Error, fmt, time::{Duration, Instant}};
use zeroize::Zeroizing;

/// Unverified peer-supplied labels; none is an authenticated identity.
#[derive(Clone, Debug)]
pub struct LoginClaims {
    pub username: String,
    pub peer_id: String,
    pub peer_name: String,
    pub wire_session_id: u64,
    pub version: String,
}
struct PendingLogin { claims: LoginClaims, response: Zeroizing<Vec<u8>>, decoding: Option<Envelope>, preferences: Option<remote_protocol::video_preferences::VideoPreferences>, cursor_preferences: Option<remote_protocol::cursor_preferences::CursorPreferences>, disable_keyboard: Option<bool>, video_ack_required: bool }

/// A handled event or a video-control request for the host scheduler.
/// Control requests are untrusted, must be rate-limited and validated against
/// the caller's current display list, and do not themselves refresh an encoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostEvent {
    Input,
    /// Input deliberately ignored by the optional peer-disable gate.
    InputSuppressed,
    Heartbeat,
    /// Untrusted echo of a host-origin TestDelay probe, not proof of identity.
    ProbeReply(remote_protocol::TestDelay),
    VideoControl(remote_protocol::video_control::VideoControl),
    /// Untrusted quality/FPS options, optionally with decoder capabilities.
    VideoPreferences { values: remote_protocol::video_preferences::VideoPreferences, decoding: Option<remote_protocol::DecodingCapabilities>, envelope: Box<[u8]> },
    /// Untrusted cursor/follow options, optionally combined with decoding.
    CursorPreferences { values: remote_protocol::cursor_preferences::CursorPreferences, decoding: Option<remote_protocol::DecodingCapabilities>, envelope: Box<[u8]> },
    /// Peer preference, not a grant or an actual OS input state change.
    InputPreference { disable_keyboard: bool, envelope: Box<[u8]> },
    /// Untrusted display-switch request and original wire envelope.
    DisplaySwitchRequest { value: remote_protocol::display_control::DisplaySwitch, envelope: Box<[u8]> },
    /// Untrusted multi-display subscription request and original envelope.
    CaptureDisplaysRequest { value: remote_protocol::display_control::CaptureDisplays, envelope: Box<[u8]> },
    /// Untrusted request; never applies an OS resolution automatically.
    DisplayResolutionRequest(remote_protocol::display_control::DisplayResolution),
    /// Untrusted request for display metadata, requiring local view permission.
    DisplayQuery(u32),
    /// Untrusted Windows session switch request. Never applies an OS change.
    WindowsSessionRequest(u32),
    /// An untrusted request to resend a previously delivered cursor shape.
    CursorShapeRequest(u64),
    /// Untrusted source SupportedDecoding only, serialized as a standalone
    /// option without other fields. Caller controls negotiation and peer IDs.
    DecodingAdvertisement { values: remote_protocol::DecodingCapabilities, envelope: Box<[u8]> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { New, Busy, PendingApproval, Approved, Authorized, Closed }

/// Lifecycle, protocol, admission, or transport error.
pub enum ConnectionError {
    InvalidState,
    /// Peer requested close. The optional diagnostic is untrusted text.
    PeerClosed(Option<String>),
    Expired,
    /// Invalid caller-driven inactivity timer or clock regression.
    Idle(crate::idle_timeout::IdleError),
    /// Invalid caller-driven receive-watchdog clock.
    Watchdog(crate::receive_watchdog::WatchdogError),
    InvalidClaims,
    UnexpectedMessage,
    Admission(AdmissionError),
    /// Local approval handoff failed; this is not proof of trusted UI.
    Approval(remote_security::approval::ApprovalError),
    Protocol(ProtocolError),
    Network(NetworkTransportError),
    Host(HostInputError),
    Capture(CapturePumpError),
    Mouse(windows_mouse::DispatchError),
    Keyboard(windows_keyboard::DispatchError),
    /// Cursor wire validation/compression failed.
    Cursor(remote_protocol::cursor::CursorError),
    /// Explicit per-session cursor delivery bookkeeping failure.
    CursorDelivery(crate::cursor_delivery::DeliveryError),
    /// Opt-in tracked modifier dispatch failed.
    TrackedModifier(crate::tracked_modifiers::ErrorKind),
    /// Optional tracked Windows touch-scale handling failed.
    Touch(crate::windows_touch::TouchError),
    /// Cooperative local input arbitration failed.
    Arbitration(crate::input_arbiter::ArbitrationError),
    /// Desktop metadata or login response validation failed.
    Desktop(remote_protocol::desktop::DesktopError),
    /// Invalid caller-supplied Windows session metadata.
    WindowsSessions(remote_protocol::windows_sessions::WindowsSessionsError),
    DisplayControl(remote_protocol::display_control::DisplayControlError),
    ResolutionMetadata(remote_protocol::resolution_metadata::ResolutionMetadataError),
    /// Local Windows cursor sampling failed.
    CursorCapture(std::io::Error),
    /// Local Windows foreground rectangle sampling failed.
    ForegroundCapture(std::io::Error),
    /// Display enumeration for a local follow operation failed.
    DisplayEnumeration(std::io::Error),
    /// Invalid foreground-follow geometry or display snapshot.
    WindowFollow(crate::window_follow::FocusError),
    /// Invalid cursor-follow geometry or current display.
    CursorFollow(crate::cursor_follow::FollowError),
}
// The close reason is peer-controlled and may contain terminal control codes.
// Other nested errors retain their Display diagnostic; callers must still treat
// those diagnostics as potentially sensitive or untrusted.
impl fmt::Debug for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if matches!(self, Self::PeerClosed(_)) { f.write_str("ConnectionError::PeerClosed(..)") }
        else { write!(f, "ConnectionError({self})") }
    }
}
impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState => f.write_str("host connection is in an invalid state"),
            Self::PeerClosed(_) => f.write_str("peer requested close"),
            Self::Expired => f.write_str("preauthorization deadline expired"),
            Self::Idle(e) => write!(f, "idle timeout: {e}"),
            Self::Watchdog(e) => write!(f, "receive watchdog: {e}"),
            Self::InvalidClaims => f.write_str("invalid untrusted login claims"),
            Self::UnexpectedMessage => f.write_str("unexpected message for this connection state"),
            Self::Admission(e) => write!(f, "admission: {e}"),
            Self::Approval(e) => write!(f, "owner approval: {e}"),
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::Network(e) => write!(f, "network: {e}"),
            Self::Host(e) => write!(f, "host: {e}"),
            Self::Capture(e) => write!(f, "capture: {e}"),
            Self::Mouse(e) => write!(f, "mouse: {e}"),
            Self::Keyboard(e) => write!(f, "keyboard: {e}"),
            Self::Cursor(e) => write!(f, "cursor protocol: {e}"),
            Self::CursorDelivery(e) => write!(f, "cursor delivery: {e}"),
            Self::TrackedModifier(e) => write!(f, "tracked modifier dispatch: {e}"),
            Self::Touch(e) => write!(f, "touch dispatch: {e}"),
            Self::Arbitration(e) => write!(f, "input arbitration: {e}"),
            Self::Desktop(e) => write!(f, "desktop metadata: {e}"),
            Self::WindowsSessions(e) => write!(f, "Windows session metadata: {e}"),
            Self::DisplayControl(e) => write!(f, "display control: {e}"),
            Self::ResolutionMetadata(e) => write!(f, "resolution metadata: {e}"),
            Self::CursorCapture(e) => write!(f, "cursor capture: {e}"),
            Self::ForegroundCapture(e) => write!(f, "foreground capture: {e}"),
            Self::DisplayEnumeration(e) => write!(f, "display enumeration: {e}"),
            Self::WindowFollow(e) => write!(f, "window follow: {e}"),
            Self::CursorFollow(e) => write!(f, "cursor follow: {e}"),
        }
    }
}
impl Error for ConnectionError {}
impl From<AdmissionError> for ConnectionError { fn from(e: AdmissionError) -> Self { Self::Admission(e) } }
impl From<ProtocolError> for ConnectionError { fn from(e: ProtocolError) -> Self { Self::Protocol(e) } }
impl From<NetworkTransportError> for ConnectionError { fn from(e: NetworkTransportError) -> Self { Self::Network(e) } }
impl From<HostInputError> for ConnectionError { fn from(e: HostInputError) -> Self { Self::Host(e) } }
impl From<CapturePumpError> for ConnectionError { fn from(e: CapturePumpError) -> Self { Self::Capture(e) } }

/// A connection owns its transport throughout the limited password workflow.
/// It must not be treated as cryptographically authenticated or production safe.
pub struct HostConnection<T: NetworkTransport, B: InputBackend> {
    transport: T,
    host: HostInputSession<B>,
    verifier: Option<PasswordVerifier>,
    permit: Option<AdmissionPermit>,
    login: Option<PendingLogin>,
    initial_decoding: Option<Envelope>,
    initial_preferences: Option<remote_protocol::video_preferences::VideoPreferences>,
    initial_cursor_preferences: Option<remote_protocol::cursor_preferences::CursorPreferences>,
    initial_disable_keyboard: Option<bool>,
    initial_video_ack_required: Option<bool>,
    cursor_cache: Option<remote_protocol::cursor::CursorCache>,
    phase: Phase,
    max_post_auth_bytes: usize,
    tracked_modifiers: bool,
    key_repeat: bool,
    scan_mode: bool,
    translate_mode: bool,
    source_unicode: bool,
    touch_enabled: bool,
    touch_scale: crate::windows_touch::TouchScale,
    input_lease: Option<crate::input_arbiter::InputLease>,
    idle: Option<crate::idle_timeout::IdleTimeout>,
    receive_watchdog: Option<crate::receive_watchdog::ReceiveWatchdog>,
}
impl<T: NetworkTransport, B: InputBackend> HostConnection<T, B> {
    /// The supplied permit must have been obtained using the actual peer's
    /// address from a trusted source. The verifier must target `id`. This
    /// constructor does not verify TLS, authenticate the peer, or create IDs.
    pub fn new(mut transport: T, id: SessionId, backend: B, verifier: PasswordVerifier, permit: AdmissionPermit, max_post_auth_bytes: usize) -> Result<Self, ConnectionError> {
        if max_post_auth_bytes == 0 || max_post_auth_bytes > MAX_ENVELOPE_BYTES {
            transport.close(); return Err(ConnectionError::InvalidState);
        }
        if let Err(error) = permit.check_live() {
            transport.close(); return Err(ConnectionError::Admission(error));
        }
        let mut host = HostInputSession::new(id, backend);
        if let Err(error) = host.begin_connect().and_then(|_| host.transport_connected()) {
            transport.close(); return Err(ConnectionError::Host(error));
        }
        Ok(Self { transport, host, verifier: Some(verifier), permit: Some(permit), login: None, initial_decoding: None, initial_preferences: None, initial_cursor_preferences: None, initial_disable_keyboard: None, initial_video_ack_required: None, cursor_cache: None, phase: Phase::New, max_post_auth_bytes, tracked_modifiers: false, key_repeat: false, scan_mode: false, translate_mode: false, source_unicode: false, touch_enabled: false, touch_scale: crate::windows_touch::TouchScale::new(), input_lease: None, idle: None, receive_watchdog: None })
    }
    /// ID generated by the embedding application, not a wire identity.
    pub fn session_id(&self) -> SessionId { self.host.id() }
    /// Current local session state.
    pub fn state(&self) -> SessionState { self.host.state() }
    /// Current local authorization; cleared during close.
    pub fn permissions(&self) -> Permissions { self.host.permissions() }
    fn remaining(&self, deadline: Duration) -> Result<Duration, ConnectionError> {
        let permit = self.permit.as_ref().ok_or(ConnectionError::InvalidState)?;
        permit.check_live()?;
        let wait = deadline.min(permit.remaining());
        if wait.is_zero() { return Err(ConnectionError::Expired); }
        Ok(wait)
    }
    fn abort(&mut self) {
        self.phase = Phase::Closed;
        self.source_unicode = false;
        self.login.take();
        self.initial_decoding.take();
        self.initial_preferences.take(); self.initial_cursor_preferences.take(); self.initial_disable_keyboard.take();
        self.initial_video_ack_required.take();
        self.cursor_cache.take();
        self.idle.take(); self.receive_watchdog.take();
        self.verifier.take();
        self.transport.close();
        self.permit.take();
        // Explicit close can retry a detectable error after abort.
        if self.host.close().is_ok() {
            if let Some(lease) = self.input_lease.take() { let _ = lease.finish_clean(); }
        }
    }
    /// Send the source-compatible hash challenge and receive exactly one basic
    /// desktop login. I/O is limited by both deadlines and the admission grace.
    /// On cancellation the connection remains Busy and must be closed/dropped;
    /// the `NetworkTransport` contract requires interrupted I/O to close itself.
    /// The transport's own frame limit should also be set to 128 KiB pre-auth;
    /// this parser's bound is applied after receive and cannot bound its buffers.
    pub async fn receive_password_login(&mut self, deadline: Duration) -> Result<LoginClaims, ConnectionError> {
        if self.phase != Phase::New { return Err(ConnectionError::InvalidState); }
        let wait = self.remaining(deadline)?;
        self.phase = Phase::Busy;
        let result = self.receive_password_login_inner(wait, deadline).await;
        if result.is_err() { self.abort(); }
        result
    }
    async fn receive_password_login_inner(&mut self, first_wait: Duration, deadline: Duration) -> Result<LoginClaims, ConnectionError> {
        let challenge = self.verifier.as_ref().ok_or(ConnectionError::InvalidState)?.challenge();
        let bytes = Envelope::password_challenge_event(&challenge.salt, &challenge.challenge)?.encode(MAX_PRE_AUTH_BYTES)?;
        self.transport.send(&bytes, first_wait).await?;
        let wait = self.remaining(deadline)?;
        let raw = Zeroizing::new(self.transport.receive(wait).await?.into_vec());
        self.remaining(deadline)?;
        let envelope = remote_protocol::sensitive_login::SensitiveIncomingLogin::decode(&raw, MAX_PRE_AUTH_BYTES)?;
        match envelope.close_reason() {
            Ok(reason) => return Err(ConnectionError::PeerClosed(Some(reason.to_owned()))),
            Err(remote_protocol::close_reason::CloseReasonError::TooLong) => return Err(ConnectionError::PeerClosed(None)),
            Err(remote_protocol::close_reason::CloseReasonError::Unexpected) => {},
        }
        let login = envelope.desktop_login()?;
        if login.password_response.len() != 32 || [login.username, login.peer_id, login.peer_name, login.version]
            .iter().any(|s| s.len() > 256 || s.chars().any(char::is_control)) {
            return Err(ConnectionError::InvalidClaims);
        }
        let claims = LoginClaims { username: login.username.to_owned(), peer_id: login.peer_id.to_owned(),
            peer_name: login.peer_name.to_owned(), wire_session_id: login.session_id, version: login.version.to_owned() };
        // Retain only capability data, not the password-bearing login envelope.
        let decoding = match envelope.extract_supported_decoding_event() {
            Ok(event) => Some(event),
            Err(ProtocolError::UnexpectedMessage) => None,
            Err(error) => return Err(ConnectionError::Protocol(error)),
        };
        // Retain only non-secret bounded preferences, never the login bytes.
        // Invalid preferences are ignored rather than discarding valid decoder
        // claims; neither is an instruction until the authorized caller acts.
        let preferences = envelope.video_preferences().ok().filter(|p| !p.is_empty());
        let cursor_preferences = envelope.cursor_preferences().ok().filter(|p| !p.is_empty());
        let disable_keyboard = envelope.disable_keyboard_preference().ok().flatten();
        let video_ack_required = envelope.login_video_ack_required()?;
        self.login = Some(PendingLogin { claims: claims.clone(), response: Zeroizing::new(login.password_response.to_vec()), decoding, preferences, cursor_preferences, disable_keyboard, video_ack_required });
        self.phase = Phase::PendingApproval;
        Ok(claims)
    }
    /// Create an optional in-process owner-decision handoff for this pending
    /// connection. The request label is an untrusted peer claim. The broker is
    /// not a UI or IPC security boundary; the embedding application must secure
    /// that channel and retain/drop the ticket on disconnect.
    pub fn request_owner_approval(&self, broker: &remote_security::approval::ApprovalBroker,
        principal: remote_session::Principal, requested: Permissions, lifetime: Duration)
        -> Result<remote_security::approval::ApprovalTicket, ConnectionError> {
        if self.phase != Phase::PendingApproval { return Err(ConnectionError::InvalidState); }
        let permit = self.permit.as_ref().ok_or(ConnectionError::InvalidState)?;
        permit.check_live()?;
        let label = self.login.as_ref().ok_or(ConnectionError::InvalidState)?.claims.peer_name.clone();
        let lifetime = lifetime.min(permit.remaining());
        broker.request(self.host.id(), principal, label, requested, lifetime).map_err(ConnectionError::Approval)
    }
    /// Poll a broker decision and, when present, consume it along with the
    /// password challenge. No network work or UI is driven by this method.
    /// An expired/missing ticket fails closed and aborts the connection.
    pub fn authorize_with_ticket(&mut self, ticket: &mut remote_security::approval::ApprovalTicket,
        requested: Permissions) -> Result<Option<LoginClaims>, ConnectionError> {
        if self.phase != Phase::PendingApproval || ticket.key().session() != self.host.id() { return Err(ConnectionError::InvalidState); }
        let live = self.permit.as_ref().ok_or(ConnectionError::InvalidState)?.check_live();
        if let Err(error) = live { self.abort(); return Err(ConnectionError::Admission(error)); }
        let policy = match ticket.take_decision() {
            Ok(Some(policy)) => policy,
            Ok(None) => return Ok(None),
            Err(error) => { self.abort(); return Err(ConnectionError::Approval(error)); },
        };
        let mut policy = policy;
        self.authorize(requested, &mut policy).map(Some)
    }
    /// Complete password verification and the trusted caller's local approval.
    /// The policy receives the verifier's configured principal, not proof of a
    /// claimed RustDesk peer ID. `requested` is application policy, not parsed
    /// from wire options. A refusal closes the stream; no retry is supported.
    pub fn authorize<P: Authorizer>(&mut self, requested: Permissions, policy: &mut P) -> Result<LoginClaims, ConnectionError> {
        if self.phase != Phase::PendingApproval { return Err(ConnectionError::InvalidState); }
        let result = (|| {
            self.permit.as_ref().ok_or(ConnectionError::InvalidState)?.check_live()?;
            let login = self.login.take().ok_or(ConnectionError::InvalidState)?;
            // The one-shot verifier is dropped immediately after this attempt,
            // reducing the lifetime of its password-derived hash.
            let mut verifier = self.verifier.take().ok_or(ConnectionError::InvalidState)?;
            self.host.authenticate(Credential::new(&login.response), requested, &mut verifier, policy)?;
            // Approval is synchronous and may take time; expiration still denies.
            self.permit.as_ref().ok_or(ConnectionError::InvalidState)?.check_live()?;
            self.permit.take().ok_or(ConnectionError::InvalidState)?.authorization_complete();
            self.initial_decoding = login.decoding;
            self.initial_preferences = login.preferences;
            self.initial_cursor_preferences = login.cursor_preferences;
            self.initial_disable_keyboard = login.disable_keyboard;
            self.initial_video_ack_required = Some(login.video_ack_required);
            self.phase = Phase::Approved;
            Ok(login.claims)
        })();
        if result.is_err() { self.abort(); }
        result
    }
    /// Take only the login's untrusted decoding advertisement after both
    /// authorization and view permission. It contains no password proof and
    /// can be passed to SourceNegotiator under its global-state restrictions.
    /// Missing abilities must not be silently treated as verified VP9 support.
    pub fn take_initial_decoding_advertisement(&mut self) -> Result<Option<Envelope>, ConnectionError> {
        if !matches!(self.phase, Phase::Approved | Phase::Authorized) || !self.host.permissions().view_screen {
            return Err(ConnectionError::InvalidState);
        }
        Ok(self.initial_decoding.take())
    }
    /// Take bounded, untrusted login quality/FPS preferences after approval.
    /// This never grants capabilities or applies changes to capture/encoder QoS.
    pub fn take_initial_video_preferences(&mut self) -> Result<Option<remote_protocol::video_preferences::VideoPreferences>, ConnectionError> {
        if !matches!(self.phase, Phase::Approved | Phase::Authorized) || !self.host.permissions().view_screen { return Err(ConnectionError::InvalidState); }
        Ok(self.initial_preferences.take())
    }
    /// Take untrusted source cursor/follow preferences after view approval.
    /// This does not subscribe a service, change permissions or prove consent.
    pub fn take_initial_cursor_preferences(&mut self) -> Result<Option<remote_protocol::cursor_preferences::CursorPreferences>, ConnectionError> {
        if !matches!(self.phase, Phase::Approved | Phase::Authorized) || !self.host.permissions().view_screen { return Err(ConnectionError::InvalidState); }
        Ok(self.initial_cursor_preferences.take())
    }
    /// Take the peer's initial source input-disable preference. This does not
    /// alter permissions or release held keys; callers must separately enforce
    /// local policy and cleanup. `false` is never permission to enable input.
    pub fn take_initial_disable_keyboard(&mut self) -> Result<Option<bool>, ConnectionError> {
        if !matches!(self.phase, Phase::Approved | Phase::Authorized) { return Err(ConnectionError::InvalidState); }
        Ok(self.initial_disable_keyboard.take())
    }
    /// Read the peer's untrusted login ACK preference after authorization.
    /// The caller controls actual ACK tracking, deadlines and scheduling. This
    /// flag is connection-wide and does not prove a frame was rendered.
    pub fn initial_video_ack_required(&self) -> Result<bool, ConnectionError> {
        if !matches!(self.phase, Phase::Approved | Phase::Authorized) || !self.host.permissions().view_screen { return Err(ConnectionError::InvalidState); }
        self.initial_video_ack_required.ok_or(ConnectionError::InvalidState)
    }
    /// Send a basic RustDesk success response after password and owner approval.
    /// Callers must supply truthful, consented metadata and only actual runtime
    /// codec abilities. This basic method omits source features and original
    /// resolutions; `send_login_success_with_originals` adds the latter. 2FA and trusted-device fields; it is not full peer compatibility. A
    /// caller without view permission must not expose display metadata here.
    /// Cancellation leaves the connection Busy and requires close/drop.
    pub async fn send_login_success(&mut self, info: &remote_protocol::desktop::PeerInfo, deadline: Duration) -> Result<(), ConnectionError> {
        self.send_login_success_inner(info, None, None, None, deadline).await
    }
    /// Like `send_login_success`, with optional per-display source original
    /// resolutions. Caller must supply trusted, consented current metadata; the
    /// values are claims and are never used to change OS display modes.
    pub async fn send_login_success_with_originals(&mut self, info: &remote_protocol::desktop::PeerInfo,
        originals: &[Option<remote_protocol::desktop::OriginalResolution>], deadline: Duration) -> Result<(), ConnectionError> {
        self.send_login_success_inner(info, Some(originals), None, None, deadline).await
    }
    /// Include caller-supplied original resolutions and supported modes for
    /// PeerInfo's current display, matching the existing source fields. This
    /// neither probes the display nor changes a mode; consent and freshness are
    /// the embedding application's responsibility.
    pub async fn send_login_success_with_display_modes(&mut self, info: &remote_protocol::desktop::PeerInfo,
        originals: &[Option<remote_protocol::desktop::OriginalResolution>],
        modes: Option<&[remote_protocol::resolution_metadata::Resolution]>, deadline: Duration) -> Result<(), ConnectionError> {
        self.send_login_success_inner(info, Some(originals), modes, None, deadline).await
    }
    /// Explicitly disclose caller-supplied, consented Windows session claims.
    /// No OS enumeration or switching is performed. The source's service/RDP
    /// eligibility policy is not implemented; the caller owns policy and must
    /// not assume that advertised sessions remain available or selectable.
    pub async fn send_login_success_with_windows_sessions(&mut self, info: &remote_protocol::desktop::PeerInfo,
        originals: Option<&[Option<remote_protocol::desktop::OriginalResolution>]>,
        modes: Option<&[remote_protocol::resolution_metadata::Resolution]>,
        sessions: &remote_protocol::windows_sessions::WindowsSessions, deadline: Duration) -> Result<(), ConnectionError> {
        self.send_login_success_inner(info, originals, modes, Some(sessions), deadline).await
    }
    async fn send_login_success_inner(&mut self, info: &remote_protocol::desktop::PeerInfo,
        originals: Option<&[Option<remote_protocol::desktop::OriginalResolution>]>,
        modes: Option<&[remote_protocol::resolution_metadata::Resolution]>,
        sessions: Option<&remote_protocol::windows_sessions::WindowsSessions>, deadline: Duration) -> Result<(), ConnectionError> {
        if self.phase != Phase::Approved || deadline.is_zero()
            || (!self.host.permissions().view_screen && (!info.displays.is_empty() || modes.is_some()))
            || (info.displays.is_empty() && modes.is_some())
            || (sessions.is_some() && !(self.host.permissions().view_screen && self.host.permissions().change_display)) {
            return Err(ConnectionError::InvalidState);
        }
        let mut message = Envelope::desktop_login_success(info).map_err(ConnectionError::Desktop)?;
        if let Some(originals) = originals { message.set_display_original_resolutions(originals).map_err(ConnectionError::Desktop)?; }
        if let Some(modes) = modes { message.set_supported_resolutions(Some(modes)).map_err(ConnectionError::ResolutionMetadata)?; }
        if let Some(sessions) = sessions { message.set_windows_sessions(Some(sessions)).map_err(ConnectionError::WindowsSessions)?; }
        let message = message.encode(MAX_PRE_AUTH_BYTES.min(self.max_post_auth_bytes))?;
        self.phase = Phase::Busy;
        if let Err(error) = self.transport.send(&message, deadline).await {
            self.abort(); return Err(ConnectionError::Network(error));
        }
        self.phase = Phase::Authorized;
        Ok(())
    }
    /// Send RustDesk's combined keyboard/mouse permission announcement after
    /// local policy has already been applied. An enabled announcement is
    /// refused unless both local mouse and keyboard permissions are granted;
    /// source has no separate wire bit for this prototype's split permissions.
    /// Sending false does not itself revoke OS input; call restrict_permissions.
    pub async fn send_source_keyboard_permission(&mut self, enabled: bool, deadline: Duration) -> Result<(), ConnectionError> {
        let permissions = self.host.permissions();
        if self.phase != Phase::Authorized || deadline.is_zero() || (enabled && !(permissions.control_mouse && permissions.control_keyboard)) {
            return Err(ConnectionError::InvalidState);
        }
        let wire = Envelope::source_keyboard_permission(enabled).encode(self.max_post_auth_bytes)?;
        self.phase = Phase::Busy;
        if let Err(error) = self.transport.send(&wire, deadline).await { self.abort(); return Err(ConnectionError::Network(error)); }
        self.phase = Phase::Authorized;
        Ok(())
    }
    /// Open and start a software capture pump for this authorized session.
    /// Only one live pump should be used per session; the caller must coordinate
    /// stopping/dropping it, desktop access, negotiation and stream refresh.
    pub fn start_capture(&mut self, display: Display, display_index: i32, config: EncoderConfig, limit: usize) -> Result<CapturePump, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        let pump = CapturePump::open(&self.host, display, display_index, config, limit)?;
        pump.start(&mut self.host)?;
        Ok(pump)
    }
    /// Start a software capture with an opt-in cooperative reservation held
    /// until the pump is dropped. Other unbudgeted paths remain unconstrained.
    pub fn start_capture_budgeted(&mut self, display: Display, display_index: i32, config: EncoderConfig,
        limit: usize, budget: &crate::capture_budget::CaptureBudget) -> Result<CapturePump, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        let pump = CapturePump::open_budgeted(&self.host, display, display_index, config, limit, budget)?;
        pump.start(&mut self.host)?;
        Ok(pump)
    }
    /// Open a caller-approved bounded group of software capture streams. All
    /// handles are opened before entering streaming state; no tasks are spawned.
    pub fn start_multi_capture(&mut self, displays: Vec<(Display, i32, EncoderConfig)>, limit: usize) -> Result<crate::capture_pump::MultiCapture, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        Ok(crate::capture_pump::MultiCapture::start(&mut self.host, displays, limit)?)
    }
    /// Start an opt-in group using a shared cooperative capture budget. All
    /// reservations precede native opening and remain held until handles drop.
    /// Other unbudgeted paths and processes are not constrained by this pool.
    pub fn start_multi_capture_budgeted(&mut self, displays: Vec<(Display, i32, EncoderConfig)>, limit: usize,
        budget: &crate::capture_budget::CaptureBudget) -> Result<crate::capture_pump::MultiCapture, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        Ok(crate::capture_pump::MultiCapture::start_budgeted(&mut self.host, displays, limit, budget)?)
    }
    /// Update group membership from locally approved handles. Opens additions
    /// before dropping removals; see `MultiCapture::reconfigure` for temporary
    /// resource caps and the required topology/decoder coordination. This does
    /// not automatically apply a network CaptureDisplays request.
    pub fn reconfigure_multi_capture(&mut self, group: &mut crate::capture_pump::MultiCapture,
        remove: &[i32], add: Vec<(Display, i32, EncoderConfig)>) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || !self.host.permissions().change_display { return Err(ConnectionError::InvalidState); }
        group.reconfigure(&self.host, remove, add, self.max_post_auth_bytes)?;
        Ok(())
    }
    /// Send one member's frame on the ordered connection. The caller chooses
    /// scheduling and must not drive individual capture pumps at the same time.
    pub async fn send_multi_capture(&mut self, group: &mut crate::capture_pump::MultiCapture, display: i32,
        capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        self.phase = Phase::Busy;
        match group.send_network(&mut self.host, &mut self.transport, display, capture_wait, send_wait, pts_ms).await {
            Ok(()) => { self.phase = Phase::Authorized; Ok(()) },
            Err(CapturePumpError::Video(crate::video::VideoError::Network(error))) => { self.abort(); Err(ConnectionError::Network(error)) },
            Err(error) => { self.phase = Phase::Authorized; Err(ConnectionError::Capture(error)) },
        }
    }
    /// Source-aware group-member capture/send. A VPX no-output retains encoder
    /// state but emits no message; caller must not record an ACK wait for it.
    pub async fn send_multi_capture_outcome(&mut self, group: &mut crate::capture_pump::MultiCapture, display: i32,
        capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<crate::video::SendOutcome, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        self.phase = Phase::Busy;
        match group.send_network_outcome(&self.host, &mut self.transport, display, capture_wait, send_wait, pts_ms).await {
            Ok(outcome) => { self.phase = Phase::Authorized; Ok(outcome) },
            Err(CapturePumpError::Video(crate::video::VideoError::Network(error))) => { self.abort(); Err(ConnectionError::Network(error)) },
            Err(error) => { self.phase = Phase::Authorized; Err(ConnectionError::Capture(error)) },
        }
    }
    /// Explicit cached group-member repeat; no pacing/ACK/consent policy is
    /// automatic. Failure/cancellation requires stream and decoder cleanup.
    pub async fn repeat_multi_capture_outcome(&mut self, group: &mut crate::capture_pump::MultiCapture, display: i32,
        pts_ms: i64, send_wait: Duration, opt_in: remote_codec::RepeatFrameOptIn) -> Result<crate::video::SendOutcome, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        self.phase = Phase::Busy;
        match group.repeat_network_outcome(&self.host, &mut self.transport, display, pts_ms, send_wait, opt_in).await {
            Ok(outcome) => { self.phase = Phase::Authorized; Ok(outcome) },
            Err(CapturePumpError::Video(crate::video::VideoError::Network(error))) => { self.abort(); Err(ConnectionError::Network(error)) },
            Err(error) => { self.phase = Phase::Authorized; Err(ConnectionError::Capture(error)) },
        }
    }
    /// Inspect and explicitly switch a software stream's Windows capture
    /// backend. `use_gdi` invalidates its encoder before a requested switch;
    /// the owner must revalidate consent/topology and coordinate viewer reset.
    #[cfg(target_os = "windows")]
    pub fn multi_capture_is_gdi(&self, group: &crate::capture_pump::MultiCapture, display: i32) -> Result<bool, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        Ok(group.is_gdi(&self.host, display)?)
    }
    #[cfg(target_os = "windows")]
    pub fn use_multi_capture_gdi(&mut self, group: &mut crate::capture_pump::MultiCapture, display: i32,
        opt_in: remote_capture::GdiFallbackOptIn) -> Result<bool, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        Ok(group.use_gdi(&self.host, display, opt_in)?)
    }
    /// Query a group member's backend-reported bitrate and quality support.
    pub fn multi_capture_encoder_stats(&self, group: &crate::capture_pump::MultiCapture, display: i32) -> Result<(u32, bool), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        Ok(group.encoder_stats(&self.host, display)?)
    }
    /// Apply an explicit local quality choice; no remote request is applied
    /// automatically, and the caller owns decoder synchronization.
    pub fn set_multi_capture_quality(&mut self, group: &mut crate::capture_pump::MultiCapture, display: i32, quality: f32) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        Ok(group.set_quality(&self.host, display, quality)?)
    }
    pub fn multi_capture_needs_reset(&self, group: &crate::capture_pump::MultiCapture, display: i32) -> Result<bool, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        Ok(group.needs_reset(&self.host, display)?)
    }
    pub fn reset_multi_capture_encoder(&mut self, group: &mut crate::capture_pump::MultiCapture, display: i32, config: EncoderConfig) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        Ok(group.reset_encoder(&self.host, display, config)?)
    }
    pub fn stop_multi_capture(&mut self, group: &mut crate::capture_pump::MultiCapture) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        group.stop(&mut self.host)?; Ok(())
    }
    /// Open an opt-in Windows GPU capture pump after view authorization.
    /// Codec support and real display consent must be established separately.
    #[cfg(all(target_os = "windows", feature = "vram"))]
    pub fn start_vram_capture(&mut self, display: Display, display_index: i32, codec: remote_capture::vram::VramCodec,
        quality: f32, keyframe_interval: Option<usize>, limit: usize) -> Result<crate::vram_pump::VramVideoPump, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        let pump = crate::vram_pump::VramVideoPump::open(&self.host, display, display_index, codec, quality, keyframe_interval, limit)?;
        pump.start(&mut self.host)?; Ok(pump)
    }
    /// Start the Windows VRAM path with an opt-in cooperative area reservation.
    /// Native GPU memory and unbudgeted capture paths are not bounded by it.
    #[cfg(all(target_os = "windows", feature = "vram"))]
    pub fn start_vram_capture_budgeted(&mut self, display: Display, display_index: i32, codec: remote_capture::vram::VramCodec,
        quality: f32, keyframe_interval: Option<usize>, limit: usize, budget: &crate::capture_budget::CaptureBudget)
        -> Result<crate::vram_pump::VramVideoPump, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        let pump = crate::vram_pump::VramVideoPump::open_budgeted(&self.host, display, display_index, codec, quality, keyframe_interval, limit, budget)?;
        pump.start(&mut self.host)?;
        Ok(pump)
    }
    /// Send one GPU-encoded frame. Native work may block; failed/cancelled
    /// output requires capture/decoder recreation and a new keyframe.
    #[cfg(all(target_os = "windows", feature = "vram"))]
    pub async fn send_vram_capture(&mut self, pump: &mut crate::vram_pump::VramVideoPump,
        capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        self.phase = Phase::Busy;
        let result = pump.send_network(&self.host, &mut self.transport, capture_wait, send_wait, pts_ms).await;
        match result {
            Ok(()) => { self.phase = Phase::Authorized; Ok(()) },
            Err(CapturePumpError::Video(crate::video::VideoError::Network(e))) => { self.abort(); Err(ConnectionError::Network(e)) },
            Err(e) => { self.phase = Phase::Authorized; Err(ConnectionError::Capture(e)) },
        }
    }
    #[cfg(all(target_os = "windows", feature = "vram"))]
    pub fn stop_vram_capture(&mut self, pump: &mut crate::vram_pump::VramVideoPump) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        pump.stop(&mut self.host)?; Ok(())
    }
    /// Explicit source-aware single-capture send. A VPX no-output produces no
    /// wire frame; the caller owns pacing, capture lifetime and peer recovery.
    /// Cancellation leaves this connection Busy and requires close/drop.
    pub async fn send_capture_outcome(&mut self, pump: &mut CapturePump, capture_wait: Duration, send_wait: Duration,
        pts_ms: i64) -> Result<crate::video::SendOutcome, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        self.phase = Phase::Busy;
        match pump.send_network_outcome(&self.host, &mut self.transport, capture_wait, send_wait, pts_ms).await {
            Ok(outcome) => { self.phase = Phase::Authorized; Ok(outcome) },
            Err(CapturePumpError::Video(crate::video::VideoError::Network(error))) => { self.abort(); Err(ConnectionError::Network(error)) },
            Err(error) => { self.phase = Phase::Authorized; Err(ConnectionError::Capture(error)) },
        }
    }
    /// Source-aware explicit repeat; it never creates or clears ACK waits.
    /// Caller must revalidate consent and cached-image freshness every time.
    pub async fn send_capture_repeat_outcome(&mut self, pump: &mut CapturePump, pts_ms: i64, send_wait: Duration,
        opt_in: remote_codec::RepeatFrameOptIn) -> Result<crate::video::SendOutcome, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        self.phase = Phase::Busy;
        match pump.repeat_network_outcome(&self.host, &mut self.transport, pts_ms, send_wait, opt_in).await {
            Ok(outcome) => { self.phase = Phase::Authorized; Ok(outcome) },
            Err(CapturePumpError::Video(crate::video::VideoError::Network(error))) => { self.abort(); Err(ConnectionError::Network(error)) },
            Err(error) => { self.phase = Phase::Authorized; Err(ConnectionError::Capture(error)) },
        }
    }
    /// Send one explicitly authorized cached software frame without capturing.
    /// The caller owns cache age, local consent, source-style repeat policy,
    /// peer decoder synchronization and any ACK pacing. This method does not
    /// integrate with scheduled multi-display capture. Cancellation leaves this
    /// connection Busy and requires close/drop, not replay.
    pub async fn send_capture_repeat(&mut self, pump: &mut CapturePump, pts_ms: i64, send_wait: Duration,
        opt_in: remote_codec::RepeatFrameOptIn) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        self.phase = Phase::Busy;
        match pump.repeat_network(&self.host, &mut self.transport, pts_ms, send_wait, opt_in).await {
            Ok(()) => { self.phase = Phase::Authorized; Ok(()) },
            Err(CapturePumpError::Video(crate::video::VideoError::Network(error))) => { self.abort(); Err(ConnectionError::Network(error)) },
            Err(error) => { self.phase = Phase::Authorized; Err(ConnectionError::Capture(error)) },
        }
    }
    /// Send one frame over this connection. Capture/encode can block the runtime.
    /// Cancellation leaves the connection Busy; close/drop it instead of retrying.
    pub async fn send_capture(&mut self, pump: &mut CapturePump, capture_wait: Duration, send_wait: Duration, pts_ms: i64) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        self.phase = Phase::Busy;
        let result = pump.send_network(&mut self.host, &mut self.transport, capture_wait, send_wait, pts_ms).await;
        match result {
            Ok(()) => { self.phase = Phase::Authorized; Ok(()) },
            Err(CapturePumpError::Video(crate::video::VideoError::Network(e))) => {
                self.abort(); Err(ConnectionError::Network(e))
            },
            Err(e) => { self.phase = Phase::Authorized; Err(ConnectionError::Capture(e)) },
        }
    }
    /// Obtain source encoder statistics for this authorized session's pump.
    pub fn capture_encoder_stats(&self, pump: &CapturePump) -> Result<(u32, bool), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        Ok(pump.encoder_stats(&self.host)?)
    }
    /// Apply a caller-approved quality ratio to this session's pump. No QoS
    /// algorithm or source decoder capability claim is applied automatically.
    pub fn set_capture_quality(&mut self, pump: &mut CapturePump, quality: f32) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        pump.set_quality(&self.host, quality)?; Ok(())
    }
    /// Stop a pump started for this session. Drop it afterwards to release the
    /// native capture handle. This does not close the host connection.
    pub fn stop_capture(&mut self, pump: &mut CapturePump) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        pump.stop(&mut self.host)?; Ok(())
    }
    /// Sample and send one visible current-desktop Windows cursor shape and
    /// position over this connection. Shapes are cached for explicit resend,
    /// but both messages are sent on each sample; there is no deduplication. A hidden cursor returns false without
    /// sending a hide event, since that behavior is not implemented here.
    /// The deadline is a total elapsed budget checked after native sampling and
    /// before each send; synchronous sampling itself cannot be interrupted.
    /// Cursor sampling can block and is not the source portable-service path.
    /// If the handle changes during sampling, the sample is discarded. Handle
    /// reuse and 53-bit content-hash collisions remain possible. Cancellation
    /// leaves the connection Busy and requires close/drop.
    #[cfg(target_os = "windows")]
    pub async fn send_windows_cursor(&mut self, deadline: Duration) -> Result<bool, ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero()
            || !self.host.permissions().view_screen
            || !matches!(self.host.state(), SessionState::Connected | SessionState::Streaming) {
            return Err(ConnectionError::InvalidState);
        }
        let started = Instant::now();
        let shape = match remote_capture::windows_cursor::capture_shape().map_err(ConnectionError::CursorCapture)? {
            Some(shape) => shape, None => return Ok(false),
        };
        let position = remote_capture::windows_cursor::snapshot().map_err(ConnectionError::CursorCapture)?;
        if !position.visible { return Ok(false); }
        if position.handle_id != shape.handle_id {
            return Err(ConnectionError::CursorCapture(std::io::Error::new(std::io::ErrorKind::WouldBlock, "cursor changed while sampling")));
        }
        let mut shape = remote_protocol::cursor::CursorShape { id: 0, hotx: shape.hotx, hoty: shape.hoty,
            width: shape.width, height: shape.height, rgba: shape.rgba };
        shape.id = shape.source_content_id().map_err(ConnectionError::Cursor)?;
        let wire = Envelope::cursor_shape_event(&shape).map_err(ConnectionError::Cursor)?.encode(self.max_post_auth_bytes)?;
        let position = Envelope::cursor_position_event(remote_protocol::cursor::CursorPosition { x: position.x, y: position.y })
            .encode(self.max_post_auth_bytes)?;
        if self.cursor_cache.is_none() {
            self.cursor_cache = Some(remote_protocol::cursor::CursorCache::new(128, remote_protocol::cursor::MAX_CACHE_BYTES).map_err(ConnectionError::Cursor)?);
        }
        let first_wait = deadline.saturating_sub(started.elapsed());
        if first_wait.is_zero() { return Err(ConnectionError::Expired); }
        self.phase = Phase::Busy;
        if let Err(error) = self.transport.send(&wire, first_wait).await {
            self.abort(); return Err(ConnectionError::Network(error));
        }
        if let Some(cache) = self.cursor_cache.as_mut() {
            if let Err(error) = cache.insert(shape) { self.abort(); return Err(ConnectionError::Cursor(error)); }
        }
        let second_wait = deadline.saturating_sub(started.elapsed());
        if second_wait.is_zero() { self.abort(); return Err(ConnectionError::Expired); }
        if let Err(error) = self.transport.send(&position, second_wait).await {
            self.abort(); return Err(ConnectionError::Network(error));
        }
        self.phase = Phase::Authorized;
        Ok(true)
    }
    /// Sample the calling interactive desktop's foreground-window rectangle
    /// after local view approval. The caller must additionally obtain informed
    /// local consent for foreground tracking, ensure desktop/DPI equivalence,
    /// enforce window-follow preferences and rate-limit any peer disclosure.
    /// No window title, process identity, switching or wire send occurs here.
    #[cfg(target_os = "windows")]
    pub fn sample_windows_foreground(&self) -> Result<Option<crate::window_follow::WindowRect>, ConnectionError> {
        if self.phase != Phase::Authorized || !self.host.permissions().view_screen
            || !matches!(self.host.state(), SessionState::Connected | SessionState::Streaming) {
            return Err(ConnectionError::InvalidState);
        }
        remote_capture::windows_foreground::foreground_window_rect()
            .map(|rect| rect.map(Into::into)).map_err(ConnectionError::ForegroundCapture)
    }
    /// Sample Windows foreground focus and send a follow-display hint if it
    /// changes, after explicit application assertions of consent and peer
    /// preference. Compares caller-approved display metadata before and after
    /// sampling, but this is not an atomic desktop snapshot, stable monitor
    /// identity, consent UI or an OS permission. The caller must ensure DPI and
    /// desktop coordinates match, rate-limit polling, and reset `tracker` on
    /// topology, session or preference changes. Native sampling is synchronous
    /// and is not bounded by the send deadline. No capture is switched here.
    /// A send failure may be delivered and closes this connection; do not retry.
    #[cfg(target_os = "windows")]
    pub async fn send_windows_focus_hint(&mut self, tracker: &mut crate::window_follow::FocusTracker,
        approved: &[remote_capture::DisplayInfo], confirm_local_consent: bool, follow_enabled: bool,
        deadline: Duration) -> Result<bool, ConnectionError> {
        if self.phase != Phase::Authorized || !self.host.permissions().view_screen || deadline.is_zero()
            || !confirm_local_consent || !follow_enabled { return Err(ConnectionError::InvalidState); }
        let displays = remote_capture::displays().map_err(ConnectionError::DisplayEnumeration)?;
        let before: Vec<_> = displays.iter().map(|d| d.info().clone()).collect();
        crate::window_follow::validate_capture_snapshot(approved, &before).map_err(ConnectionError::WindowFollow)?;
        let info = crate::display_metadata::windows_source_display_update(&displays, false).map_err(ConnectionError::Desktop)?;
        let rect = self.sample_windows_foreground()?;
        let after: Vec<_> = remote_capture::displays().map_err(ConnectionError::DisplayEnumeration)?.iter().map(|d| d.info().clone()).collect();
        crate::window_follow::validate_capture_snapshot(approved, &after).map_err(ConnectionError::WindowFollow)?;
        let Some(rect) = rect else { return Ok(false); };
        let Some(display) = tracker.observe(&info.displays, rect).map_err(ConnectionError::WindowFollow)? else { return Ok(false); };
        self.send_follow_current_display(display, deadline).await?;
        Ok(true)
    }
    /// Explicitly sample the Windows cursor and send a source-style follow
    /// hint when it lies on a different approved display. No capture is switched
    /// and no background task is started. Both booleans are trusted caller
    /// assertions, not consent UI or proof of peer preferences. The owner must
    /// revalidate desktop/DPI, coordinate multi-UI state and rate-limit samples.
    /// The double topology comparison is not atomic; send delivery is uncertain
    /// on failure and must not be retried. Synchronous native work is not bounded
    /// by the network deadline.
    #[cfg(target_os = "windows")]
    pub async fn send_windows_cursor_follow_hint(&mut self, approved: &[remote_capture::DisplayInfo],
        current_display: u32, multi_ui_session: bool, confirm_local_consent: bool,
        follow_enabled: bool, deadline: Duration) -> Result<bool, ConnectionError> {
        if self.phase != Phase::Authorized || !self.host.permissions().view_screen || deadline.is_zero()
            || !confirm_local_consent || !follow_enabled { return Err(ConnectionError::InvalidState); }
        if multi_ui_session { return Ok(false); }
        let displays = remote_capture::displays().map_err(ConnectionError::DisplayEnumeration)?;
        let before: Vec<_> = displays.iter().map(|d| d.info().clone()).collect();
        crate::window_follow::validate_capture_snapshot(approved, &before).map_err(ConnectionError::WindowFollow)?;
        let info = crate::display_metadata::windows_source_display_update(&displays, false).map_err(ConnectionError::Desktop)?;
        let snapshot = remote_capture::windows_cursor::snapshot().map_err(ConnectionError::CursorCapture)?;
        let after: Vec<_> = remote_capture::displays().map_err(ConnectionError::DisplayEnumeration)?.iter().map(|d| d.info().clone()).collect();
        crate::window_follow::validate_capture_snapshot(approved, &after).map_err(ConnectionError::WindowFollow)?;
        if !snapshot.visible { return Ok(false); }
        let position = remote_protocol::cursor::CursorPosition { x: snapshot.x, y: snapshot.y };
        let hint = crate::cursor_follow::follow_hint(&info.displays, current_display, position, multi_ui_session).map_err(ConnectionError::CursorFollow)?;
        let Some(display) = hint else { return Ok(false); };
        self.send_follow_current_display(display, deadline).await?; Ok(true)
    }
    /// Resend a retained cursor shape after an authorized request. Returns
    /// false for cache misses. Callers must rate-limit requests; this does not
    /// prove peer cache state or handle hash collisions. No sample is taken.
    pub async fn send_cached_cursor(&mut self, id: u64, deadline: Duration) -> Result<bool, ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero() || !self.host.permissions().view_screen { return Err(ConnectionError::InvalidState); }
        let shape = match self.cursor_cache.as_mut().and_then(|cache| cache.get(id)) { Some(shape) => shape, None => return Ok(false) };
        let wire = Envelope::cursor_shape_event(shape).map_err(ConnectionError::Cursor)?.encode(self.max_post_auth_bytes)?;
        self.phase = Phase::Busy;
        if let Err(error) = self.transport.send(&wire, deadline).await { self.abort(); return Err(ConnectionError::Network(error)); }
        self.phase = Phase::Authorized;
        Ok(true)
    }
    /// Send a caller-sampled source cursor shape or ID using an explicit
    /// per-session delivery book. Local view permission, current cursor privacy,
    /// freshness, rate limiting and peer cache recovery remain caller policy.
    /// A matching local session ID is only a guard against accidental reuse, not
    /// peer authentication; callers must enforce uniqueness across reconnects.
    /// A cancelled/failed send poisons the book. Failure aborts the connection;
    /// on cancellation, the caller must close/drop the Busy connection.
    /// successful send is not proof that the peer received or retained it. The
    /// deadline bounds network send only, not native sampling or compression.
    pub async fn send_cursor_announcement(&mut self, book: &mut crate::cursor_delivery::CursorDelivery,
        shape: remote_protocol::cursor::CursorShape, force_shape: bool, deadline: Duration)
        -> Result<crate::cursor_delivery::AnnouncementKind, ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero() || !self.host.permissions().view_screen
            || !matches!(self.host.state(), SessionState::Connected | SessionState::Streaming)
            || book.session_id() != self.session_id() { return Err(ConnectionError::InvalidState); }
        let pending = book.prepare(shape, force_shape).map_err(ConnectionError::CursorDelivery)?;
        self.send_cursor_announcement_inner(pending, deadline).await
    }
    /// Respond to an explicitly handled cursor-shape request using the same
    /// session book. A missing ID returns false and sends nothing. A retained
    /// shape may be stale; caller must revalidate local disclosure permission.
    pub async fn resend_cursor_announcement(&mut self, book: &mut crate::cursor_delivery::CursorDelivery,
        id: u64, deadline: Duration) -> Result<bool, ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero() || !self.host.permissions().view_screen
            || !matches!(self.host.state(), SessionState::Connected | SessionState::Streaming)
            || book.session_id() != self.session_id() { return Err(ConnectionError::InvalidState); }
        let pending = match book.prepare_resend(id).map_err(ConnectionError::CursorDelivery)? {
            Some(pending) => pending, None => return Ok(false),
        };
        self.send_cursor_announcement_inner(pending, deadline).await.map(|_| true)
    }
    async fn send_cursor_announcement_inner(&mut self, pending: crate::cursor_delivery::PendingAnnouncement<'_>,
        deadline: Duration) -> Result<crate::cursor_delivery::AnnouncementKind, ConnectionError> {
        let wire = match pending.encode(self.max_post_auth_bytes) {
            Ok(wire) => Zeroizing::new(wire),
            Err(error) => { pending.discard_before_send(); return Err(ConnectionError::CursorDelivery(error)); },
        };
        let kind = pending.kind();
        self.phase = Phase::Busy;
        if let Err(error) = self.transport.send(&wire, deadline).await {
            self.abort(); return Err(ConnectionError::Network(error));
        }
        pending.sent();
        self.phase = Phase::Authorized;
        Ok(kind)
    }
    /// Send one caller-sampled source cursor position. Coordinates are a
    /// disclosure of local activity; local view permission, informed consent,
    /// rate limiting and desktop/DPI correctness remain caller obligations.
    /// Cancellation leaves this connection Busy and requires close/drop.
    pub async fn send_cursor_position(&mut self, position: remote_protocol::cursor::CursorPosition,
        deadline: Duration) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero() || !self.host.permissions().view_screen
            || !matches!(self.host.state(), SessionState::Connected | SessionState::Streaming) { return Err(ConnectionError::InvalidState); }
        let wire = Envelope::cursor_position_event(position).encode(self.max_post_auth_bytes)?;
        self.phase = Phase::Busy;
        if let Err(error) = self.transport.send(&wire, deadline).await { self.abort(); return Err(ConnectionError::Network(error)); }
        self.phase = Phase::Authorized; Ok(())
    }
    /// Optional caller-driven Windows cursor sample using the source-style
    /// per-session announcement book. This is not the portable-service path,
    /// visibility protocol, consent UI or stable desktop/handle identity.
    /// The caller must exclusively use this book for the peer, route resends,
    /// and reset the connection/book on topology or trust changes. Native
    /// sampling/compression cannot be interrupted and may exceed the budget.
    /// Cancellation leaves the book/connection uncertain; close/drop both.
    #[cfg(target_os = "windows")]
    pub async fn send_windows_cursor_announcement(&mut self, book: &mut crate::cursor_delivery::CursorDelivery,
        force_shape: bool, deadline: Duration) -> Result<bool, ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero() || !self.host.permissions().view_screen
            || !matches!(self.host.state(), SessionState::Connected | SessionState::Streaming)
            || book.session_id() != self.session_id() { return Err(ConnectionError::InvalidState); }
        let start = Instant::now();
        let shape = match remote_capture::windows_cursor::capture_shape().map_err(ConnectionError::CursorCapture)? {
            Some(shape) => shape, None => return Ok(false),
        };
        let position = remote_capture::windows_cursor::snapshot().map_err(ConnectionError::CursorCapture)?;
        if !position.visible { return Ok(false); }
        if position.handle_id != shape.handle_id {
            return Err(ConnectionError::CursorCapture(std::io::Error::new(std::io::ErrorKind::WouldBlock, "cursor changed while sampling")));
        }
        let mut shape = remote_protocol::cursor::CursorShape { id: 0, hotx: shape.hotx, hoty: shape.hoty, width: shape.width, height: shape.height, rgba: shape.rgba };
        shape.id = shape.source_content_id().map_err(ConnectionError::Cursor)?;
        let remaining = deadline.saturating_sub(start.elapsed());
        if remaining.is_zero() { return Err(ConnectionError::Expired); }
        self.send_cursor_announcement(book, shape, force_shape, remaining).await?;
        let remaining = deadline.saturating_sub(start.elapsed());
        if remaining.is_zero() { self.abort(); return Err(ConnectionError::Expired); }
        if let Err(error) = self.send_cursor_position(remote_protocol::cursor::CursorPosition { x: position.x, y: position.y }, remaining).await {
            // The shape/ID may already have reached the peer, so a partially
            // announced pair is not safely retryable on this connection.
            self.abort(); return Err(error);
        }
        Ok(true)
    }
    /// Announce caller-verified source encoder capability changes. This is not
    /// an encoder probe or negotiation, and VP9 has no source flag. Caller
    /// coordinates topology, codec switching and receiver keyframe recovery.
    pub async fn send_supported_encoding(&mut self, value: remote_protocol::EncodingCapabilities, deadline: Duration) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero() || !self.host.permissions().view_screen { return Err(ConnectionError::InvalidState); }
        let wire = Envelope::supported_encoding_event(value).encode(self.max_post_auth_bytes)?;
        self.phase = Phase::Busy;
        if let Err(error) = self.transport.send(&wire, deadline).await { self.abort(); return Err(ConnectionError::Network(error)); }
        self.phase = Phase::Authorized; Ok(())
    }
    /// Send a bounded standalone source PeerInfo update. Caller supplies an
    /// approved current snapshot and coordinates capture/decoder refresh. This
    /// does not guarantee the topology has remained unchanged since enumeration.
    pub async fn send_peer_info_update(&mut self, info: &remote_protocol::desktop::PeerInfo, deadline: Duration) -> Result<(), ConnectionError> {
        self.send_peer_info_update_inner(info, None, None, deadline).await
    }
    /// Include separately supplied source original resolutions. This does not
    /// determine actual original modes, virtual-display status or consent.
    pub async fn send_peer_info_update_with_originals(&mut self, info: &remote_protocol::desktop::PeerInfo,
        originals: &[Option<remote_protocol::desktop::OriginalResolution>], deadline: Duration) -> Result<(), ConnectionError> {
        self.send_peer_info_update_inner(info, Some(originals), None, deadline).await
    }
    /// Disclose an explicitly approved, fresh session snapshot. Like login,
    /// no OS enumeration, session policy or switch is implemented here.
    pub async fn send_peer_info_update_with_windows_sessions(&mut self, info: &remote_protocol::desktop::PeerInfo,
        originals: Option<&[Option<remote_protocol::desktop::OriginalResolution>]>,
        sessions: &remote_protocol::windows_sessions::WindowsSessions, deadline: Duration) -> Result<(), ConnectionError> {
        self.send_peer_info_update_inner(info, originals, Some(sessions), deadline).await
    }
    async fn send_peer_info_update_inner(&mut self, info: &remote_protocol::desktop::PeerInfo,
        originals: Option<&[Option<remote_protocol::desktop::OriginalResolution>]>,
        sessions: Option<&remote_protocol::windows_sessions::WindowsSessions>, deadline: Duration) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero() || !self.host.permissions().view_screen
            || (sessions.is_some() && !self.host.permissions().change_display) { return Err(ConnectionError::InvalidState); }
        let mut message = Envelope::desktop_peer_info_event(info).map_err(ConnectionError::Desktop)?;
        if let Some(originals) = originals { message.set_display_original_resolutions(originals).map_err(ConnectionError::Desktop)?; }
        if let Some(sessions) = sessions { message.set_windows_sessions(Some(sessions)).map_err(ConnectionError::WindowsSessions)?; }
        let wire = message.encode(self.max_post_auth_bytes)?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Authorized; Ok(()) },
            Err(error) => { self.abort(); Err(ConnectionError::Network(error)) },
        }
    }
    /// Send a source display-change notice on this same ordered stream. Caller
    /// must supply current authorized metadata and coordinate capture/decoder
    /// recreation; this method never changes an OS display or resolution.
    pub async fn send_display_change(&mut self, value: &remote_protocol::display_control::DisplaySwitch, deadline: Duration) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero() || !self.host.permissions().view_screen || value.width <= 0 || value.height <= 0 {
            return Err(ConnectionError::InvalidState);
        }
        let wire = Envelope::display_switch_event(value).map_err(ConnectionError::DisplayControl)?.encode(self.max_post_auth_bytes)?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Authorized; Ok(()) },
            Err(error) => { self.abort(); Err(ConnectionError::Network(error)) },
        }
    }
    /// Send a source display announcement with caller-supplied current mode
    /// claims and optional original resolution. These can become stale, do not
    /// authorize a mode change and do not reconfigure capture or the decoder.
    /// The caller must independently obtain consent and verify the actual device.
    pub async fn send_display_change_with_modes(&mut self, value: &remote_protocol::display_control::DisplaySwitch,
        modes: Option<&[remote_protocol::resolution_metadata::Resolution]>,
        original: Option<remote_protocol::resolution_metadata::Resolution>, deadline: Duration) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero() || !self.host.permissions().view_screen || value.width <= 0 || value.height <= 0 {
            return Err(ConnectionError::InvalidState);
        }
        let mut message = Envelope::display_switch_event(value).map_err(ConnectionError::DisplayControl)?;
        message.set_supported_resolutions(modes).map_err(ConnectionError::ResolutionMetadata)?;
        message.set_switch_original_resolution(original).map_err(ConnectionError::ResolutionMetadata)?;
        let wire = message.encode(self.max_post_auth_bytes)?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Authorized; Ok(()) },
            Err(error) => { self.abort(); Err(ConnectionError::Network(error)) },
        }
    }
    /// Send an advisory source cursor-follow display index. Caller validates
    /// actual cursor position, current topology, consent and message frequency.
    pub async fn send_follow_current_display(&mut self, display: u32, deadline: Duration) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero() || !self.host.permissions().view_screen { return Err(ConnectionError::InvalidState); }
        let wire = Envelope::follow_current_display_event(display).map_err(ConnectionError::DisplayControl)?.encode(self.max_post_auth_bytes)?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Authorized; Ok(()) },
            Err(error) => { self.abort(); Err(ConnectionError::Network(error)) },
        }
    }
    /// Send a source host-origin TestDelay message. Caller owns probe
    /// bookkeeping, cadence and validation; it is not an authenticated RTT.
    /// Do not retry after an uncertain send. Cancellation leaves the connection
    /// Busy and requires close/drop.
    pub async fn send_delay_probe(&mut self, last_delay: u32, target_bitrate: u32, deadline: Duration) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero() || !self.host.permissions().view_screen { return Err(ConnectionError::InvalidState); }
        let probe = remote_protocol::TestDelay { time: 0, from_client: false, last_delay, target_bitrate };
        let wire = Envelope::test_delay_event(probe).encode(self.max_post_auth_bytes)?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Authorized; Ok(()) },
            Err(error) => { self.abort(); Err(ConnectionError::Network(error)) },
        }
    }
    /// Enable an optional caller-driven inactivity timeout after login success.
    /// No timer is spawned: the owner must call `poll_idle_timeout` frequently,
    /// including while no network messages arrive, and drop capture resources.
    /// Minutes are a trusted local policy, not a peer setting or security limit.
    pub fn enable_idle_timeout(&mut self, minutes: u32) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || self.idle.is_some() { return Err(ConnectionError::InvalidState); }
        self.idle = Some(crate::idle_timeout::IdleTimeout::new(minutes, Instant::now()).map_err(ConnectionError::Idle)?);
        Ok(())
    }
    /// Advisory time until source-style expiry. `None` means disabled. This
    /// does not schedule I/O or prevent a blocked operation from exceeding it.
    pub fn idle_remaining(&self) -> Result<Option<Duration>, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        self.idle.as_ref().map(|idle| idle.remaining(Instant::now()).map_err(ConnectionError::Idle)).transpose()
    }
    /// Close locally if the optional timeout has expired. Caller must drive
    /// this method, stop/drop all caller-owned captures and handle cleanup
    /// failure. No wire close reason is sent; delivery is not implied.
    pub fn poll_idle_timeout(&mut self) -> Result<bool, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        let expired = match self.idle.as_ref() {
            Some(idle) => idle.expired(Instant::now()).map_err(ConnectionError::Idle)?, None => false,
        };
        if expired { self.close()?; }
        Ok(expired)
    }
    /// Enable a source-style 30-second receive watchdog for an authorized
    /// connection. Caller must drive `poll_receive_watchdog` independently and
    /// service incoming messages promptly; no background timer is started.
    /// Duplex queued frames only count when dequeued by this connection.
    pub fn enable_receive_watchdog(&mut self) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || self.receive_watchdog.is_some() { return Err(ConnectionError::InvalidState); }
        self.receive_watchdog = Some(crate::receive_watchdog::ReceiveWatchdog::new(Instant::now())); Ok(())
    }
    /// Advisory time until receive timeout, or None if disabled.
    pub fn receive_watchdog_remaining(&self) -> Result<Option<Duration>, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        self.receive_watchdog.as_ref().map(|watchdog| watchdog.remaining(Instant::now()).map_err(ConnectionError::Watchdog)).transpose()
    }
    /// Close locally on receive timeout. This is not a heartbeat sender, peer
    /// identity check or proof of delivery; caller retains capture handles.
    /// Blocking I/O and queued duplex frames can delay or distort this check.
    pub fn poll_receive_watchdog(&mut self) -> Result<bool, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        let expired = match self.receive_watchdog.as_ref() {
            Some(watchdog) => watchdog.expired(Instant::now()).map_err(ConnectionError::Watchdog)?, None => false,
        };
        if expired { self.close()?; }
        Ok(expired)
    }
    /// Process one input or TestDelay message as in the original narrow API.
    /// Other control/display/cursor/capability events are consumed but returned
    /// as unexpected; callers that support them must use `receive_event`
    /// consistently instead.
    pub async fn receive_input(&mut self, deadline: Duration) -> Result<(), ConnectionError> {
        match self.receive_event(deadline).await? {
            HostEvent::Input | HostEvent::InputSuppressed | HostEvent::Heartbeat | HostEvent::ProbeReply(_) => Ok(()),
            HostEvent::VideoControl(_) | HostEvent::VideoPreferences { .. } | HostEvent::CursorPreferences { .. } | HostEvent::InputPreference { .. } | HostEvent::DisplaySwitchRequest { .. } | HostEvent::CaptureDisplaysRequest { .. } | HostEvent::DisplayResolutionRequest(_) | HostEvent::DisplayQuery(_) | HostEvent::WindowsSessionRequest(_) | HostEvent::CursorShapeRequest(_) | HostEvent::DecodingAdvertisement { .. } => Err(ConnectionError::UnexpectedMessage),
        }
    }
    /// Receive one authorized input, heartbeat, video or display-control event.
    /// Control requests require local permission but are not acted upon by
    /// this API. The caller must validate display IDs, rate-limit and decide
    /// how/when to refresh or record ACKs. On cancellation close/drop the Busy
    /// connection. This serial interface is not an autonomous host event loop.
    pub async fn receive_event(&mut self, deadline: Duration) -> Result<HostEvent, ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero() { return Err(ConnectionError::InvalidState); }
        self.phase = Phase::Busy;
        let raw = match self.transport.receive(deadline).await {
            Ok(raw) => raw,
            Err(e) => { self.abort(); return Err(ConnectionError::Network(e)); }
        };
        self.phase = Phase::Authorized;
        self.dispatch_received_event(raw, deadline).await
    }
    async fn dispatch_received_event(&mut self, raw: Box<[u8]>, deadline: Duration) -> Result<HostEvent, ConnectionError> {
        // Wipe the owned serialized buffer on all exits, including parse or
        // dispatch errors. Returned control envelopes transfer their bytes to
        // the caller and cannot be wiped here. Transport and parser copies are
        // outside this limited guarantee.
        let mut raw = Zeroizing::new(raw.into_vec());
        // Source refreshes last-receive on every successfully read frame,
        // before protobuf parsing. In duplex mode this is dequeue time, not
        // actual socket arrival; the owner must service the queue promptly.
        if let Some(watchdog) = self.receive_watchdog.as_mut() {
            if let Err(error) = watchdog.received(Instant::now()) { self.abort(); return Err(ConnectionError::Watchdog(error)); }
        }
        let event = remote_protocol::sensitive_input::SensitiveInputEnvelope::decode(&raw, self.max_post_auth_bytes)?;
        match event.close_reason() {
            Ok(reason) => { let reason = reason.to_owned(); self.abort(); return Err(ConnectionError::PeerClosed(Some(reason))); },
            Err(remote_protocol::close_reason::CloseReasonError::TooLong) => { self.abort(); return Err(ConnectionError::PeerClosed(None)); },
            Err(remote_protocol::close_reason::CloseReasonError::Unexpected) => {},
        }
        // RustDesk records input activity even if peer keyboard input is disabled.
        // This limited adapter also counts valid refresh requests, but does not
        // implement source chat, OS-login or false refresh options. The caller
        // must still poll the timeout independently of traffic.
        let activity = idle_activity(&event, self.host.permissions().view_screen);
        if activity {
            if let Some(idle) = self.idle.as_mut() {
                if let Err(error) = idle.activity(Instant::now()) { self.abort(); return Err(ConnectionError::Idle(error)); }
            }
        }
        // An explicitly accepted peer-disable preference suppresses all three
        // input message classes. This never grants input when re-enabled.
        if self.host.peer_input_disabled() && matches!(event.kind(), MessageKind::Mouse | MessageKind::Keyboard | MessageKind::Pointer) {
            return Ok(HostEvent::InputSuppressed);
        }
        // Gesture owns a tracked Control key; disallow other remote input
        // until the gesture ends to avoid aliases and accidental key-up.
        if self.touch_scale.active() && matches!(event.kind(), MessageKind::Mouse | MessageKind::Keyboard) {
            return Err(ConnectionError::InvalidState);
        }
        let result = match event.kind() {
            MessageKind::Pointer if self.touch_enabled => self.touch_scale.dispatch(&mut self.host, &event).map(|_| HostEvent::Input).map_err(ConnectionError::Touch),
            MessageKind::Mouse if self.tracked_modifiers => crate::tracked_modifiers::mouse(&mut self.host, &event).map(|_| HostEvent::Input).map_err(ConnectionError::TrackedModifier),
            MessageKind::Mouse => windows_mouse::dispatch(&mut self.host, &event).map(|_| HostEvent::Input).map_err(ConnectionError::Mouse),
            MessageKind::Keyboard if self.scan_mode && event.keyboard()?.mode() == 1 =>
                windows_keyboard::dispatch_map_with_repeat(&mut self.host, &event, self.key_repeat).map(|_| HostEvent::Input).map_err(ConnectionError::Keyboard),
            MessageKind::Keyboard if self.translate_mode && event.keyboard()?.mode() == 2 =>
                windows_keyboard::dispatch_translate_with_repeat(&mut self.host, &event, self.key_repeat).map(|_| HostEvent::Input).map_err(ConnectionError::Keyboard),
            MessageKind::Keyboard if self.source_unicode && event.keyboard()?.mode() == 0 && matches!(event.keyboard()?.payload(), Some(remote_protocol::KeyboardPayload::Unicode(_) | remote_protocol::KeyboardPayload::Sequence(_))) =>
                windows_keyboard::dispatch_source_unicode(&mut self.host, &event, remote_input::SourceWindowsUnicodeOptIn::acknowledge_source_surrogate_and_delivery_risks()).map(|_| HostEvent::Input).map_err(ConnectionError::Keyboard),
            MessageKind::Keyboard if self.tracked_modifiers && matches!(event.keyboard()?.payload(), Some(remote_protocol::KeyboardPayload::ControlKey(_))) =>
                crate::tracked_modifiers::keyboard(&mut self.host, &event).map(|_| HostEvent::Input).map_err(ConnectionError::TrackedModifier),
            MessageKind::Keyboard => windows_keyboard::dispatch_with_repeat(&mut self.host, &event, self.key_repeat).map(|_| HostEvent::Input).map_err(ConnectionError::Keyboard),
            MessageKind::TestDelay => {
                // The source host echoes client-origin probes unchanged. A
                // host-origin reply is returned to the caller for optional
                // local RTT bookkeeping; all fields remain untrusted.
                let delay = event.test_delay()?;
                if delay.from_client {
                    self.phase = Phase::Busy;
                    if let Err(error) = self.transport.send(&raw, deadline).await {
                        self.abort(); return Err(ConnectionError::Network(error));
                    }
                    self.phase = Phase::Authorized;
                    Ok(HostEvent::Heartbeat)
                } else {
                    Ok(HostEvent::ProbeReply(delay))
                }
            },
            MessageKind::Misc if event.display_switch().is_ok() && self.host.permissions().view_screen && self.host.permissions().change_display => {
                let value = event.display_switch().map_err(ConnectionError::DisplayControl)?;
                Ok(HostEvent::DisplaySwitchRequest { value, envelope: std::mem::take(&mut *raw).into_boxed_slice() })
            },
            MessageKind::Misc if event.capture_displays().is_ok() && self.host.permissions().view_screen && self.host.permissions().change_display => {
                let value = event.capture_displays().map_err(ConnectionError::DisplayControl)?;
                Ok(HostEvent::CaptureDisplaysRequest { value, envelope: std::mem::take(&mut *raw).into_boxed_slice() })
            },
            MessageKind::Misc if event.display_resolution().is_ok() && self.host.permissions().view_screen && self.host.permissions().change_display => {
                Ok(HostEvent::DisplayResolutionRequest(event.display_resolution().map_err(ConnectionError::DisplayControl)?))
            },
            // Conservative local gate; source Windows host has a different,
            // richer installed/RDP/session policy. This never changes sessions.
            MessageKind::Misc if event.selected_windows_session().is_ok() && self.host.permissions().view_screen && self.host.permissions().change_display => {
                Ok(HostEvent::WindowsSessionRequest(event.selected_windows_session().map_err(|_| ConnectionError::UnexpectedMessage)?))
            },
            MessageKind::Misc if event.display_query().is_ok() && self.host.permissions().view_screen => {
                Ok(HostEvent::DisplayQuery(event.display_query().map_err(ConnectionError::DisplayControl)?))
            },
            _ if event.video_control().is_some() && self.host.permissions().view_screen =>
                Ok(HostEvent::VideoControl(event.video_control().ok_or(ConnectionError::UnexpectedMessage)?)),
            MessageKind::Misc if self.host.permissions().view_screen && event.requested_cursor_shape().is_ok() =>
                Ok(HostEvent::CursorShapeRequest(event.requested_cursor_shape().map_err(ConnectionError::Cursor)?)),
            MessageKind::Misc if self.host.permissions().view_screen && event.video_preferences().map_or(false, |value| !value.is_empty()) => {
                let values = event.video_preferences().map_err(|_| ConnectionError::UnexpectedMessage)?;
                let decoding = event.supported_decoding().ok();
                Ok(HostEvent::VideoPreferences { values, decoding, envelope: std::mem::take(&mut *raw).into_boxed_slice() })
            },
            MessageKind::Misc if self.host.permissions().view_screen && event.cursor_preferences().map_or(false, |value| !value.is_empty()) => {
                let values = event.cursor_preferences().map_err(|_| ConnectionError::UnexpectedMessage)?;
                let decoding = event.supported_decoding().ok();
                Ok(HostEvent::CursorPreferences { values, decoding, envelope: std::mem::take(&mut *raw).into_boxed_slice() })
            },
            MessageKind::Misc if event.disable_keyboard_preference().ok().flatten().is_some() => {
                let disable_keyboard = event.disable_keyboard_preference().map_err(|_| ConnectionError::UnexpectedMessage)?.ok_or(ConnectionError::UnexpectedMessage)?;
                Ok(HostEvent::InputPreference { disable_keyboard, envelope: std::mem::take(&mut *raw).into_boxed_slice() })
            },
            MessageKind::Misc if self.host.permissions().view_screen && event.supported_decoding().is_ok() => {
                let values = event.supported_decoding()?;
                let sanitized = event.extract_supported_decoding_event()?.encode(MAX_PRE_AUTH_BYTES)?;
                Ok(HostEvent::DecodingAdvertisement { values, envelope: sanitized.into_boxed_slice() })
            },
            _ => Err(ConnectionError::UnexpectedMessage),
        };
        // A session/input failure may represent partial OS delivery. Close and
        // attempt cleanup; an attached lease remains quarantined if detectable
        // cleanup continues to fail. Unsupported wire forms do not auto-close.
        if matches!(&result,
            Err(ConnectionError::Mouse(windows_mouse::DispatchError::Host(_)))
            | Err(ConnectionError::Keyboard(windows_keyboard::DispatchError::Host(_)))
            | Err(ConnectionError::Touch(crate::windows_touch::TouchError::Host(_)))
            | Err(ConnectionError::TrackedModifier(crate::tracked_modifiers::ErrorKind::Host(_)))
            | Err(ConnectionError::TrackedModifier(crate::tracked_modifiers::ErrorKind::Mouse(windows_mouse::DispatchError::Host(_))))
        ) { self.abort(); }
        result
    }
    /// Reserve a shared cooperative input arbiter for this approved session.
    /// The lease is held until detectable host cleanup succeeds. On unresolved
    /// cleanup failure, dropping this connection quarantines the arbiter.
    /// This is optional and cannot exclude bypassing processes or input paths.
    pub fn attach_input_arbiter(&mut self, arbiter: &crate::input_arbiter::InputArbiter) -> Result<(), ConnectionError> {
        if !matches!(self.phase, Phase::Approved | Phase::Authorized) || self.input_lease.is_some() {
            return Err(ConnectionError::InvalidState);
        }
        self.input_lease = Some(arbiter.acquire(&self.host).map_err(ConnectionError::Arbitration)?);
        Ok(())
    }
    /// Explicitly enable or disable the narrower tracked-modifier dispatch.
    /// The enabled mode requires both mouse and keyboard permissions for mouse
    /// events, does not synchronize OS/global state and may reject normal peer
    /// traffic. Turning it off does not itself release held keys: revoke input
    /// permissions or close the session to perform cleanup.
    pub fn set_tracked_modifiers_enabled(&mut self, enabled: bool) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || self.host.input.has_held_keyboard() || (enabled && (self.scan_mode || self.translate_mode || self.key_repeat)) { return Err(ConnectionError::InvalidState); }
        self.tracked_modifiers = enabled;
        Ok(())
    }
    /// Explicitly enable a restricted Windows Map-mode scan-code path. It is
    /// mutually exclusive with tracked modifier mode and may only be toggled
    /// when this controller has no held keyboard input. Caller must ensure a
    /// matching Windows peer, trusted approval and OS input ownership.
    pub fn set_windows_scan_mode_enabled(&mut self, enabled: bool) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || self.host.input.has_held_keyboard() || (enabled && self.tracked_modifiers) { return Err(ConnectionError::InvalidState); }
        self.scan_mode = enabled; Ok(())
    }
    /// Opt in to source-style repeated key-down injection for the restricted
    /// legacy, map and translate paths. No local repeat timer is created. It
    /// cannot coexist with tracked modifiers and may only change with no held
    /// keys. Caller owns OS input and rate limiting; no consent is implied.
    pub fn set_windows_key_repeat_enabled(&mut self, enabled: bool) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || self.host.input.has_held_keyboard() || (enabled && self.tracked_modifiers) { return Err(ConnectionError::InvalidState); }
        self.key_repeat = enabled; Ok(())
    }
    /// Opt in to the restricted source Windows Translate `Chr` path. This is
    /// not full translation, hotkey, lock-state or desktop-switch support.
    /// It cannot be toggled while any key is held and cannot coexist with the
    /// tracked-modifier policy. The caller must own the interactive input device.
    pub fn set_windows_translate_mode_enabled(&mut self, enabled: bool) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || self.host.input.has_held_keyboard() || (enabled && self.tracked_modifiers) { return Err(ConnectionError::InvalidState); }
        self.translate_mode = enabled; Ok(())
    }
    /// Explicitly enable pinned Windows Enigo supplementary Unicode handling
    /// for subsequent legacy text messages. The token acknowledges unmatched
    /// surrogate downs and potentially invisible delivery failures; it is NOT
    /// owner consent or proof the actual backend is Windows. Caller must own
    /// the interactive desktop, rate-limit input and stop on revocation. This
    /// is disabled by default and may only change with no tracked key held.
    pub fn enable_windows_source_unicode(&mut self, _: remote_input::SourceWindowsUnicodeOptIn) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || !self.host.permissions().control_keyboard || self.host.input.has_held_keyboard() || self.touch_scale.active() {
            return Err(ConnectionError::InvalidState);
        }
        self.source_unicode = true; Ok(())
    }
    /// Disable future source-specific text dispatch; this cannot undo input or
    /// restore unmatched surrogate events that may already have reached the OS.
    pub fn disable_windows_source_unicode(&mut self) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || self.host.input.has_held_keyboard() || self.touch_scale.active() { return Err(ConnectionError::InvalidState); }
        self.source_unicode = false; Ok(())
    }
    /// Opt in to the restricted Windows touch scale path. Caller must ensure
    /// trusted local approval and exclusive input, including non-cooperating
    /// processes/human input. Cannot toggle with any tracked key or gesture held.
    pub fn set_windows_touch_scale_enabled(&mut self, enabled: bool) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || self.host.input.has_held_keyboard() || self.touch_scale.active() {
            return Err(ConnectionError::InvalidState);
        }
        self.touch_enabled = enabled; Ok(())
    }
    /// Explicitly honor a peer's `disable_keyboard` preference. This affects
    /// the source's combined mouse/keyboard gate but does not change local
    /// authorization or automatically act on untrusted option messages. End an
    /// active touch gesture first, and fail closed if tracked cleanup fails.
    /// Re-enabling cannot restore locally revoked capabilities. Input from
    /// non-cooperating processes and OS/human-held keys are not controlled.
    pub fn apply_peer_input_disabled(&mut self, disabled: bool) -> Result<(), ConnectionError> {
        if !matches!(self.phase, Phase::Approved | Phase::Authorized) { return Err(ConnectionError::InvalidState); }
        if disabled && self.touch_scale.active() {
            if let Err(error) = self.touch_scale.end(&mut self.host) { self.abort(); return Err(ConnectionError::Touch(error)); }
        }
        if let Err(error) = self.host.set_peer_input_disabled(disabled) { self.abort(); return Err(ConnectionError::Host(error)); }
        Ok(())
    }
    /// Effective source peer-disable gate; local permissions are reported
    /// separately by `permissions()` and remain authoritative.
    pub fn peer_input_disabled(&self) -> bool { self.host.peer_input_disabled() }
    /// Reduce permissions and release no-longer-authorized held inputs.
    pub fn restrict_permissions(&mut self, permissions: Permissions) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        // End the gesture before either permission is revoked, since the
        // tracked Control release itself requires the old keyboard grant.
        if self.touch_scale.active() && (!permissions.control_mouse || !permissions.control_keyboard) {
            if let Err(error) = self.touch_scale.end(&mut self.host) { self.abort(); return Err(ConnectionError::Touch(error)); }
        }
        match self.host.restrict_permissions(permissions) {
            Ok(()) => {
                if !self.host.permissions().control_keyboard { self.source_unicode = false; }
                if !self.host.permissions().view_screen { self.cursor_cache.take(); self.initial_decoding.take(); self.initial_preferences.take(); self.initial_cursor_preferences.take(); self.initial_video_ack_required.take(); }
                Ok(())
            },
            Err(e) => { self.abort(); Err(ConnectionError::Host(e)) },
        }
    }
    /// Best-effort source close notification followed by local cleanup. A send
    /// failure can have indeterminate delivery and is never retried. Cleanup
    /// still runs; if it fails, its error takes precedence over the send error.
    /// Cancellation requires explicit close/drop by the owner.
    pub async fn send_close_reason(&mut self, reason: &str, deadline: Duration) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero() { return Err(ConnectionError::InvalidState); }
        let wire = Envelope::close_reason_event(reason).map_err(|_| ConnectionError::InvalidClaims)?.encode(self.max_post_auth_bytes)?;
        self.phase = Phase::Busy;
        let sent = self.transport.send(&wire, deadline).await;
        self.close()?;
        sent.map_err(ConnectionError::Network)
    }
    /// Close transport, discard pending proof and retry host input cleanup.
    /// Caller-owned capture handles must be stopped/dropped independently.
    pub fn close(&mut self) -> Result<(), ConnectionError> {
        self.phase = Phase::Closed;
        self.login.take(); self.initial_decoding.take(); self.initial_preferences.take(); self.initial_cursor_preferences.take(); self.initial_disable_keyboard.take(); self.initial_video_ack_required.take(); self.cursor_cache.take(); self.idle.take(); self.receive_watchdog.take(); self.verifier.take(); self.transport.close(); self.permit.take();
        self.host.close()?;
        if let Some(lease) = self.input_lease.take() { lease.finish_clean().map_err(ConnectionError::Arbitration)?; }
        Ok(())
    }
}
impl<T: NetworkTransport, B: InputBackend> Drop for HostConnection<T, B> {
    fn drop(&mut self) { let _ = self.close(); }
}

// Input messages count even if the peer-disable preference suppresses them,
// matching the source activity update. Refresh requires local view permission;
// ACK and heartbeat traffic do not extend this local inactivity window.
fn idle_activity(event: &Envelope, view_screen: bool) -> bool {
    matches!(event.kind(), MessageKind::Mouse | MessageKind::Keyboard | MessageKind::Pointer)
        || (view_screen && matches!(event.video_control(),
            Some(remote_protocol::video_control::VideoControl::RefreshAll | remote_protocol::video_control::VideoControl::RefreshDisplay(_))))
}

#[cfg(test)]
mod idle_activity_tests {
    use super::*;
    use remote_protocol::{MouseEvent, video_control::VideoControl};
    #[test]
    fn input_and_authorized_refresh_count_but_ack_does_not() {
        let mouse = Envelope::mouse_event(MouseEvent { mask: 0, x: 0, y: 0 });
        assert!(idle_activity(&mouse, false));
        let refresh = Envelope::video_control_event(VideoControl::RefreshDisplay(0)).unwrap();
        assert!(idle_activity(&refresh, true));
        assert!(!idle_activity(&refresh, false));
        let ack = Envelope::video_control_event(VideoControl::FrameReceived).unwrap();
        assert!(!idle_activity(&ack, true));
    }
}

impl<T: remote_transport::AdjustableNetworkTransport, B: InputBackend> HostConnection<T, B> {
    /// Adjust the actual transport framing limit after password and owner
    /// approval have both succeeded. Call before requesting larger video frames.
    /// This is not a global allocation limit and does not establish peer trust.
    /// A backend without adjustable framing, such as the current strict WSS
    /// adapter, does not offer this method.
    pub fn set_authorized_message_limit(&mut self, maximum: usize) -> Result<(), ConnectionError> {
        if !matches!(self.phase, Phase::Approved | Phase::Authorized) || maximum == 0 || maximum > MAX_ENVELOPE_BYTES {
            return Err(ConnectionError::InvalidState);
        }
        self.transport.set_max_message_size(maximum)?;
        self.max_post_auth_bytes = maximum;
        Ok(())
    }
}

impl<T: remote_transport::UpgradeableDuplexTransport, B: InputBackend> HostConnection<T, B> {
    /// Opt in after password, owner approval and login response. Set the final
    /// framing limit first; it is frozen during duplex operation. This does not
    /// grant permissions, establish concurrency safety or start capture tasks.
    pub fn enable_duplex_read_ahead(&mut self) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || !self.host.permissions().view_screen { return Err(ConnectionError::InvalidState); }
        match self.transport.upgrade_duplex() {
            Ok(()) => Ok(()),
            Err(error) => { self.abort(); Err(ConnectionError::Network(error)) },
        }
    }
    /// Process one already queued message, or return None without closing an
    /// idle stream. Heartbeat replies can still perform bounded network I/O.
    /// Input dispatch and capture remain caller-serialized and may block.
    pub async fn try_receive_event(&mut self, send_deadline: Duration) -> Result<Option<HostEvent>, ConnectionError> {
        if self.phase != Phase::Authorized || send_deadline.is_zero() { return Err(ConnectionError::InvalidState); }
        match self.transport.try_receive() {
            Ok(Some(raw)) => self.dispatch_received_event(raw, send_deadline).await.map(Some),
            Ok(None) => Ok(None),
            Err(error) => { self.abort(); Err(ConnectionError::Network(error)) },
        }
    }
}
