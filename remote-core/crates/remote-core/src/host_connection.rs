//! Experimental ownership bridge between a network stream and host session.
//!
//! This is **not** a secure channel or a complete RustDesk host. It owns a
//! stream through challenge, password verification, local approval, input and
//! capture steps, but cannot cryptographically bind the stream to an end peer.
//! Password challenge transcripts permit offline guessing; TLS at a relay does
//! not protect the desktop peer from that relay. Use only in a controlled,
//! trusted environment pending design review, implementation and tests.
//!
//! There is no upstream end-to-end encryption handshake, 2FA, trusted-device
//! flow, full peer-info/login-response semantics, rate limiting, consent UI, codec
//! negotiation, event loop, heartbeat, reconnect, or cross-process input lock.
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
struct PendingLogin { claims: LoginClaims, response: Zeroizing<Vec<u8>> }

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
    Protocol(ProtocolError),
    Network(NetworkTransportError),
    Host(HostInputError),
    Capture(CapturePumpError),
    Mouse(windows_mouse::DispatchError),
    Keyboard(windows_keyboard::DispatchError),
    /// Cursor wire validation/compression failed.
    Cursor(remote_protocol::cursor::CursorError),
    /// Desktop metadata or login response validation failed.
    Desktop(remote_protocol::desktop::DesktopError),
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
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::Network(e) => write!(f, "network: {e}"),
            Self::Host(e) => write!(f, "host: {e}"),
            Self::Capture(e) => write!(f, "capture: {e}"),
            Self::Mouse(e) => write!(f, "mouse: {e}"),
            Self::Keyboard(e) => write!(f, "keyboard: {e}"),
            Self::Cursor(e) => write!(f, "cursor protocol: {e}"),
            Self::Desktop(e) => write!(f, "desktop metadata: {e}"),
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
    verifier: PasswordVerifier,
    permit: Option<AdmissionPermit>,
    login: Option<PendingLogin>,
    phase: Phase,
    max_post_auth_bytes: usize,
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
        Ok(Self { transport, host, verifier, permit: Some(permit), login: None, phase: Phase::New, max_post_auth_bytes })
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
        self.transport.close();
        self.permit.take();
        // Explicit close can retry a detectable error after abort.
        let _ = self.host.close();
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
        let challenge = self.verifier.challenge();
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
        self.login = Some(PendingLogin { claims: claims.clone(), response: Zeroizing::new(login.password_response.to_vec()) });
        self.phase = Phase::PendingApproval;
        Ok(claims)
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
            self.host.authenticate(Credential::new(&login.response), requested, &mut self.verifier, policy)?;
            // Approval is synchronous and may take time; expiration still denies.
            self.permit.as_ref().ok_or(ConnectionError::InvalidState)?.check_live()?;
            self.permit.take().ok_or(ConnectionError::InvalidState)?.authorization_complete();
            self.phase = Phase::Approved;
            Ok(login.claims)
        })();
        if result.is_err() { self.abort(); }
        result
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
    /// Open and start a software capture pump for this authorized session.
    /// Only one live pump should be used per session; the caller must coordinate
    /// stopping/dropping it, desktop access, negotiation and stream refresh.
    pub fn start_capture(&mut self, display: Display, display_index: i32, config: EncoderConfig, limit: usize) -> Result<CapturePump, ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        let pump = CapturePump::open(&self.host, display, display_index, config, limit)?;
        pump.start(&mut self.host)?;
        Ok(pump)
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
    /// Stop a pump started for this session. Drop it afterwards to release the
    /// native capture handle. This does not close the host connection.
    pub fn stop_capture(&mut self, pump: &mut CapturePump) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        pump.stop(&mut self.host)?; Ok(())
    }
    /// Sample and send one visible current-desktop Windows cursor shape and
    /// position over this connection. No caching/deduplication is attempted;
    /// both messages are sent each call. A hidden cursor returns false without
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
        let shape = Envelope::cursor_shape_event(&shape).map_err(ConnectionError::Cursor)?.encode(self.max_post_auth_bytes)?;
        let position = Envelope::cursor_position_event(remote_protocol::cursor::CursorPosition { x: position.x, y: position.y })
            .encode(self.max_post_auth_bytes)?;
        self.phase = Phase::Busy;
        if let Err(error) = self.transport.send(&shape, deadline).await {
            self.abort(); return Err(ConnectionError::Network(error));
        }
        if let Err(error) = self.transport.send(&position, deadline).await {
            self.abort(); return Err(ConnectionError::Network(error));
        }
        self.phase = Phase::Authorized;
        Ok(true)
    }
    /// Process one input or TestDelay message with restricted Windows-style
    /// dispatchers. Other messages are rejected; no full event loop is provided.
    /// On cancelled receive the connection stays Busy and must be closed/dropped.
    pub async fn receive_input(&mut self, deadline: Duration) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized || deadline.is_zero() { return Err(ConnectionError::InvalidState); }
        self.phase = Phase::Busy;
        let raw = match self.transport.receive(deadline).await {
            Ok(raw) => raw,
            Err(e) => { self.abort(); return Err(ConnectionError::Network(e)); }
        };
        self.phase = Phase::Authorized;
        let event = Envelope::decode(&raw, self.max_post_auth_bytes)?;
        match event.kind() {
            MessageKind::Mouse => windows_mouse::dispatch(&mut self.host, &event).map_err(ConnectionError::Mouse),
            MessageKind::Keyboard => windows_keyboard::dispatch(&mut self.host, &event).map_err(ConnectionError::Keyboard),
            MessageKind::TestDelay => {
                // The source host echoes client-origin probes unchanged. Host-
                // origin replies need separate RTT bookkeeping, not provided here.
                if event.test_delay()?.from_client {
                    self.phase = Phase::Busy;
                    if let Err(error) = self.transport.send(&raw, deadline).await {
                        self.abort(); return Err(ConnectionError::Network(error));
                    }
                    self.phase = Phase::Authorized;
                }
                Ok(())
            },
            _ => Err(ConnectionError::UnexpectedMessage),
        }
    }
    /// Reduce permissions and release no-longer-authorized held inputs.
    pub fn restrict_permissions(&mut self, permissions: Permissions) -> Result<(), ConnectionError> {
        if self.phase != Phase::Authorized { return Err(ConnectionError::InvalidState); }
        match self.host.restrict_permissions(permissions) {
            Ok(()) => Ok(()),
            Err(e) => { self.abort(); Err(ConnectionError::Host(e)) },
        }
    }
    /// Close transport, discard pending proof and retry host input cleanup.
    /// Caller-owned capture handles must be stopped/dropped independently.
    pub fn close(&mut self) -> Result<(), ConnectionError> {
        self.phase = Phase::Closed;
        self.login.take(); self.transport.close(); self.permit.take();
        self.host.close()?;
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
