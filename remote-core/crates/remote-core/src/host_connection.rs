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
use std::{error::Error, fmt, time::Duration};
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
struct PendingLogin { claims: LoginClaims, response: Zeroizing<Vec<u8>>, decoding: Option<Envelope> }

/// A handled event or a video-control request for the host scheduler.
/// Control requests are untrusted, must be rate-limited and validated against
/// the caller's current display list, and do not themselves refresh an encoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostEvent {
    Input,
    Heartbeat,
    /// Untrusted echo of a host-origin TestDelay probe, not proof of identity.
    ProbeReply(remote_protocol::TestDelay),
    VideoControl(remote_protocol::video_control::VideoControl),
    /// Untrusted display-switch request and original wire envelope.
    DisplaySwitchRequest { value: remote_protocol::display_control::DisplaySwitch, envelope: Box<[u8]> },
    /// Untrusted multi-display subscription request and original envelope.
    CaptureDisplaysRequest { value: remote_protocol::display_control::CaptureDisplays, envelope: Box<[u8]> },
    /// An untrusted request to resend a previously delivered cursor shape.
    CursorShapeRequest(u64),
    /// Untrusted source SupportedDecoding only, serialized as a standalone
    /// option without other fields. Caller controls negotiation and peer IDs.
    DecodingAdvertisement { values: remote_protocol::DecodingCapabilities, envelope: Box<[u8]> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { New, Busy, PendingApproval, Approved, Authorized, Closed }

/// Lifecycle, protocol, admission, or transport error.
#[derive(Debug)]
pub enum ConnectionError {
    InvalidState,
    Expired,
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
    /// Opt-in tracked modifier dispatch failed.
    TrackedModifier(crate::tracked_modifiers::ErrorKind),
    /// Cooperative local input arbitration failed.
    Arbitration(crate::input_arbiter::ArbitrationError),
    /// Desktop metadata or login response validation failed.
    Desktop(remote_protocol::desktop::DesktopError),
    DisplayControl(remote_protocol::display_control::DisplayControlError),
    /// Local Windows cursor sampling failed.
    CursorCapture(std::io::Error),
}
impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState => f.write_str("host connection is in an invalid state"),
            Self::Expired => f.write_str("preauthorization deadline expired"),
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
            Self::TrackedModifier(e) => write!(f, "tracked modifier dispatch: {e}"),
            Self::Arbitration(e) => write!(f, "input arbitration: {e}"),
            Self::Desktop(e) => write!(f, "desktop metadata: {e}"),
            Self::DisplayControl(e) => write!(f, "display control: {e}"),
            Self::CursorCapture(e) => write!(f, "cursor capture: {e}"),
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
    cursor_cache: Option<remote_protocol::cursor::CursorCache>,
    phase: Phase,
    max_post_auth_bytes: usize,
    tracked_modifiers: bool,
    scan_mode: bool,
    translate_mode: bool,
    input_lease: Option<crate::input_arbiter::InputLease>,
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
        Ok(Self { transport, host, verifier: Some(verifier), permit: Some(permit), login: None, initial_decoding: None, cursor_cache: None, phase: Phase::New, max_post_auth_bytes, tracked_modifiers: false, scan_mode: false, translate_mode: false, input_lease: None })
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
        self.login.take();
        self.initial_decoding.take();
        self.cursor_cache.take();
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
        let envelope = Envelope::decode(&raw, MAX_PRE_AUTH_BYTES)?;
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
        self.login = Some(PendingLogin { claims: claims.clone(), response: Zeroizing::new(login.password_response.to_vec()), decoding });
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
    /// Send a basic RustDesk success response after password and owner approval.
    /// Callers must supply truthful, consented metadata and only actual runtime
    /// codec abilities. This subset omits source features, original resolutions,
    /// 2FA and trusted-device fields; it is not full peer compatibility. A
    /// caller without view permission must not expose display metadata here.
    /// Cancellation leaves the connection Busy and requires close/drop.
    pub async fn send_login_success(&mut self, info: &remote_protocol::desktop::PeerInfo, deadline: Duration) -> Result<(), ConnectionError> {
        if self.phase != Phase::Approved || deadline.is_zero()
            || (!self.host.permissions().view_screen && !info.displays.is_empty()) {
            return Err(ConnectionError::InvalidState);
        }
        let message = Envelope::desktop_login_success(info).map_err(ConnectionError::Desktop)?
            .encode(MAX_PRE_AUTH_BYTES.min(self.max_post_auth_bytes))?;
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
    /// Open a caller-approved bounded group of software capture streams. All
    /// handles are opened before entering streaming state; no tasks are spawned.
    pub fn start_multi_capture(&mut self, displays: Vec<(Display, i32, EncoderConfig)>, limit: usize) -> Result<crate::capture_pump::MultiCapture, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        Ok(crate::capture_pump::MultiCapture::start(&mut self.host, displays, limit)?)
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
        if let Some(cache) = self.cursor_cache.as_mut() { cache.insert(shape).map_err(ConnectionError::Cursor)?; }
        self.phase = Phase::Busy;
        if let Err(error) = self.transport.send(&wire, deadline).await {
            self.abort(); return Err(ConnectionError::Network(error));
        }
        if let Err(error) = self.transport.send(&position, deadline).await {
            self.abort(); return Err(ConnectionError::Network(error));
        }
        self.phase = Phase::Authorized;
        Ok(true)
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
    /// Process one input or TestDelay message as in the original narrow API.
    /// Video-control events are consumed but returned as unexpected; callers
    /// that support them must use `receive_event` consistently instead.
    pub async fn receive_input(&mut self, deadline: Duration) -> Result<(), ConnectionError> {
        match self.receive_event(deadline).await? {
            HostEvent::Input | HostEvent::Heartbeat | HostEvent::ProbeReply(_) => Ok(()),
            HostEvent::VideoControl(_) | HostEvent::DisplaySwitchRequest { .. } | HostEvent::CaptureDisplaysRequest { .. } | HostEvent::CursorShapeRequest(_) | HostEvent::DecodingAdvertisement { .. } => Err(ConnectionError::UnexpectedMessage),
        }
    }
    /// Receive one authorized input, heartbeat, or video-control request.
    /// Video controls require screen-view permission but are not acted upon by
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
        let event = Envelope::decode(&raw, self.max_post_auth_bytes)?;
        let result = match event.kind() {
            MessageKind::Mouse if self.tracked_modifiers => crate::tracked_modifiers::mouse(&mut self.host, &event).map(|_| HostEvent::Input).map_err(ConnectionError::TrackedModifier),
            MessageKind::Mouse => windows_mouse::dispatch(&mut self.host, &event).map(|_| HostEvent::Input).map_err(ConnectionError::Mouse),
            MessageKind::Keyboard if self.scan_mode && event.keyboard()?.mode() == 1 =>
                windows_keyboard::dispatch_map(&mut self.host, &event).map(|_| HostEvent::Input).map_err(ConnectionError::Keyboard),
            MessageKind::Keyboard if self.translate_mode && event.keyboard()?.mode() == 2 =>
                windows_keyboard::dispatch_translate(&mut self.host, &event).map(|_| HostEvent::Input).map_err(ConnectionError::Keyboard),
            MessageKind::Keyboard if self.tracked_modifiers && matches!(event.keyboard()?.payload(), Some(remote_protocol::KeyboardPayload::ControlKey(_))) =>
                crate::tracked_modifiers::keyboard(&mut self.host, &event).map(|_| HostEvent::Input).map_err(ConnectionError::TrackedModifier),
            MessageKind::Keyboard => windows_keyboard::dispatch(&mut self.host, &event).map(|_| HostEvent::Input).map_err(ConnectionError::Keyboard),
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
                Ok(HostEvent::DisplaySwitchRequest { value, envelope: raw })
            },
            MessageKind::Misc if event.capture_displays().is_ok() && self.host.permissions().view_screen && self.host.permissions().change_display => {
                let value = event.capture_displays().map_err(ConnectionError::DisplayControl)?;
                Ok(HostEvent::CaptureDisplaysRequest { value, envelope: raw })
            },
            _ if event.video_control().is_some() && self.host.permissions().view_screen =>
                Ok(HostEvent::VideoControl(event.video_control().ok_or(ConnectionError::UnexpectedMessage)?)),
            MessageKind::Misc if self.host.permissions().view_screen && event.requested_cursor_shape().is_ok() =>
                Ok(HostEvent::CursorShapeRequest(event.requested_cursor_shape().map_err(ConnectionError::Cursor)?)),
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
        if self.phase != Phase::Authorized || self.host.input.has_held_keyboard() || (enabled && (self.scan_mode || self.translate_mode)) { return Err(ConnectionError::InvalidState); }
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
    /// Opt in to the restricted source Windows Translate `Chr` path. This is
    /// not full translation, hotkey, lock-state or desktop-switch support.
    /// It cannot be toggled while any key is held and cannot coexist with the
    /// tracked-modifier policy. The caller must own the interactive input device.
    pub fn set_windows_translate_mode_enabled(&mut self, enabled: bool) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || self.host.input.has_held_keyboard() || (enabled && self.tracked_modifiers) { return Err(ConnectionError::InvalidState); }
        self.translate_mode = enabled; Ok(())
    }
    /// Reduce permissions and release no-longer-authorized held inputs.
    pub fn restrict_permissions(&mut self, permissions: Permissions) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        match self.host.restrict_permissions(permissions) {
            Ok(()) => {
                if !self.host.permissions().view_screen { self.cursor_cache.take(); self.initial_decoding.take(); }
                Ok(())
            },
            Err(e) => { self.abort(); Err(ConnectionError::Host(e)) },
        }
    }
    /// Close transport, discard pending proof and retry host input cleanup.
    /// Caller-owned capture handles must be stopped/dropped independently.
    pub fn close(&mut self) -> Result<(), ConnectionError> {
        self.phase = Phase::Closed;
        self.login.take(); self.initial_decoding.take(); self.cursor_cache.take(); self.verifier.take(); self.transport.close(); self.permit.take();
        self.host.close()?;
        if let Some(lease) = self.input_lease.take() { lease.finish_clean().map_err(ConnectionError::Arbitration)?; }
        Ok(())
    }
}
impl<T: NetworkTransport, B: InputBackend> Drop for HostConnection<T, B> {
    fn drop(&mut self) { let _ = self.close(); }
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
