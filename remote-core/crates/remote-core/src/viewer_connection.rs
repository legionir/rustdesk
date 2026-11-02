//! Experimental caller-driven viewer protocol over an owned network stream.
//!
//! `NetworkTransport` alone does not authenticate or encrypt the peer. The
//! source password exchange permits offline guessing and does not authenticate
//! the host or bind to TLS. Never use this with untrusted servers, relays or
//! internet traffic. This module does not implement RustDesk's end-to-end key
//! exchange, 2FA, trusted devices, negotiation, reconnect, rendering, complete
//! multiplexing, or a hardened video decoder. It has not been built or tested.

use remote_protocol::{cursor::{CursorError, CursorPosition, CursorShape}, desktop::{DesktopError, LoginResult, PeerInfo}, DesktopLogin, Envelope, MessageKind, ProtocolError, TestDelay, VideoCodec, MAX_ENVELOPE_BYTES, MAX_PRE_AUTH_BYTES};
use remote_security::{password_response, PasswordChallenge, SecurityError};
use remote_transport::{NetworkTransport, NetworkTransportError};
use std::{error::Error, fmt, time::{Duration, Instant}};
use zeroize::Zeroizing;

/// Labels provided by the viewer, not authenticated by these fields.
#[derive(Debug, Clone)]
pub struct LoginIdentity {
    pub target: String,
    pub viewer_id: String,
    pub viewer_name: String,
    pub wire_session_id: u64,
    pub version: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase { New, Busy, Connected, Closed }
/// Viewer operation failure. No error is proof that a peer is authentic.
#[derive(Debug)]
pub enum ViewerError {
    InvalidState,
    Deadline,
    UnexpectedMessage,
    Denied(String),
    Protocol(ProtocolError),
    Security(SecurityError),
    Desktop(DesktopError),
    Cursor(CursorError),
    Network(NetworkTransportError),
}
impl fmt::Display for ViewerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState => f.write_str("viewer is in an invalid state"),
            Self::Deadline => f.write_str("viewer deadline expired"),
            Self::UnexpectedMessage => f.write_str("unexpected viewer message"),
            Self::Denied(_) => f.write_str("host denied the login"),
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::Security(e) => write!(f, "password challenge: {e}"),
            Self::Desktop(e) => write!(f, "desktop metadata: {e}"),
            Self::Cursor(e) => write!(f, "cursor: {e}"),
            Self::Network(e) => write!(f, "network: {e}"),
        }
    }
}
impl Error for ViewerError {}
impl From<ProtocolError> for ViewerError { fn from(e: ProtocolError) -> Self { Self::Protocol(e) } }
impl From<SecurityError> for ViewerError { fn from(e: SecurityError) -> Self { Self::Security(e) } }
impl From<DesktopError> for ViewerError { fn from(e: DesktopError) -> Self { Self::Desktop(e) } }
impl From<CursorError> for ViewerError { fn from(e: CursorError) -> Self { Self::Cursor(e) } }
impl From<NetworkTransportError> for ViewerError { fn from(e: NetworkTransportError) -> Self { Self::Network(e) } }

/// One incoming message, after basic demultiplexing but before rendering.
pub enum ViewerEvent {
    /// Source video envelope retained as bytes. Native decoding is deliberately
    /// not automatic; its allocation behavior is unsafe for untrusted input.
    Video { display: i32, codec: VideoCodec, envelope: Box<[u8]> },
    CursorShape(CursorShape),
    CursorId(u64),
    CursorPosition(CursorPosition),
    /// A source heartbeat; from-server probes are echoed before returning.
    TestDelay(TestDelay),
    PeerInfo(PeerInfo),
    /// Unknown/non-adapted message. The caller may decode it separately.
    Other(Box<[u8]>),
}

/// Owns one stream throughout the limited login and message workflow.
pub struct ViewerConnection<T: NetworkTransport> { transport: T, phase: Phase, max_bytes: usize }
impl<T: NetworkTransport> ViewerConnection<T> {
    /// The caller must establish and verify an appropriately protected channel
    /// independently. This function cannot verify security properties of `T`.
    pub fn new(mut transport: T, max_bytes: usize) -> Result<Self, ViewerError> {
        if max_bytes == 0 || max_bytes > MAX_ENVELOPE_BYTES { transport.close(); return Err(ViewerError::InvalidState); }
        Ok(Self { transport, phase: Phase::New, max_bytes })
    }
    fn abort(&mut self) { self.phase = Phase::Closed; self.transport.close(); }
    fn remaining(end: Instant) -> Result<Duration, ViewerError> {
        let remaining = end.saturating_duration_since(Instant::now());
        if remaining.is_zero() { Err(ViewerError::Deadline) } else { Ok(remaining) }
    }
    /// Complete a basic source-style password login. `deadline` is an overall
    /// cap on network operations and approval wait, not on blocking native code.
    /// Up to eight source TestDelay probes are echoed while waiting for approval.
    /// Login fields and protobuf buffers may retain copies of password-derived
    /// proof beyond the explicit zeroized wire buffer. The caller owns password
    /// lifetime. Cancellation leaves this object Busy; close/drop it.
    pub async fn login(&mut self, identity: &LoginIdentity, password: &str, deadline: Duration) -> Result<PeerInfo, ViewerError> {
        if self.phase != Phase::New || deadline.is_zero() || deadline > Duration::from_secs(180) { return Err(ViewerError::InvalidState); }
        let end = Instant::now().checked_add(deadline).ok_or(ViewerError::InvalidState)?;
        self.phase = Phase::Busy;
        let result = self.login_inner(identity, password, end).await;
        match result {
            Ok(info) => { self.phase = Phase::Connected; Ok(info) },
            Err(error) => { self.abort(); Err(error) },
        }
    }
    async fn login_inner(&mut self, identity: &LoginIdentity, password: &str, end: Instant) -> Result<PeerInfo, ViewerError> {
        let raw = self.transport.receive(Self::remaining(end)?).await?;
        let challenge = Envelope::decode(&raw, MAX_PRE_AUTH_BYTES)?;
        let hash = challenge.password_challenge()?;
        let hash = PasswordChallenge { salt: hash.salt.to_owned(), challenge: hash.challenge.to_owned() };
        let response = password_response(password, &hash)?;
        let message = Envelope::desktop_login_event(DesktopLogin { username: &identity.target, peer_id: &identity.viewer_id,
            peer_name: &identity.viewer_name, password_response: response.as_bytes(), session_id: identity.wire_session_id, version: &identity.version })?;
        let wire = Zeroizing::new(message.encode(MAX_PRE_AUTH_BYTES)?);
        self.transport.send(&wire, Self::remaining(end)?).await?;
        for _ in 0..=8 {
            let raw = self.transport.receive(Self::remaining(end)?).await?;
            let response = Envelope::decode(&raw, MAX_PRE_AUTH_BYTES)?;
            if response.kind() == MessageKind::TestDelay && !response.test_delay()?.from_client {
                self.transport.send(&raw, Self::remaining(end)?).await?;
                continue;
            }
            return match response.desktop_login_result()? {
                LoginResult::Accepted(info) => Ok(info), LoginResult::Denied(reason) => Err(ViewerError::Denied(reason)),
            };
        }
        Err(ViewerError::UnexpectedMessage)
    }
    /// Send a single existing RustDesk mouse or keyboard message. Host
    /// authorization and interpretation remain the remote host's responsibility.
    /// No automatic retry occurs after an uncertain send.
    pub async fn send_input(&mut self, event: &Envelope, deadline: Duration) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        if !matches!(event.kind(), MessageKind::Mouse | MessageKind::Keyboard) { return Err(ViewerError::UnexpectedMessage); }
        let wire = event.encode(self.max_bytes)?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Connected; Ok(()) },
            Err(e) => { self.abort(); Err(ViewerError::Network(e)) },
        }
    }
    /// Send one existing source video refresh/received notification. This does
    /// not provide codec recovery, flow control or prove the host acted on it.
    /// A peer supplied display index must be validated by the host. Like input,
    /// a failed or cancelled send has indeterminate delivery; do not retry on
    /// the same connection without an application-level recovery policy.
    pub async fn send_video_control(&mut self, control: remote_protocol::video_control::VideoControl, deadline: Duration) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        let event = Envelope::video_control_event(control).ok_or(ViewerError::UnexpectedMessage)?;
        let wire = event.encode(self.max_bytes)?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Connected; Ok(()) },
            Err(error) => { self.abort(); Err(ViewerError::Network(error)) },
        }
    }
    /// Advertise only decoder implementations the embedding application has
    /// actually checked. Source negotiation is host-side and remains untrusted;
    /// this message does not install a decoder or prove compatibility.
    pub async fn send_decoding_advertisement(&mut self, capabilities: remote_protocol::DecodingAdvertisement, deadline: Duration) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        let wire = Envelope::supported_decoding_event(capabilities).encode(MAX_PRE_AUTH_BYTES.min(self.max_bytes))?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Connected; Ok(()) },
            Err(error) => { self.abort(); Err(ViewerError::Network(error)) },
        }
    }
    /// Receive one message. Cursor decoding is bounded but not audited; video
    /// remains compressed. On cancellation close/drop the Busy connection.
    pub async fn receive(&mut self, deadline: Duration) -> Result<ViewerEvent, ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        self.phase = Phase::Busy;
        let result = self.receive_inner(deadline).await;
        match result {
            Ok(event) => { self.phase = Phase::Connected; Ok(event) },
            Err(error) => { self.abort(); Err(error) },
        }
    }
    async fn receive_inner(&mut self, deadline: Duration) -> Result<ViewerEvent, ViewerError> {
        let raw = self.transport.receive(deadline).await?;
        let envelope = Envelope::decode(&raw, self.max_bytes)?;
        match envelope.kind() {
            MessageKind::Video => {
                let frame = envelope.video()?;
                Ok(ViewerEvent::Video { display: frame.display, codec: frame.codec, envelope: raw })
            },
            MessageKind::Cursor => {
                if let Ok(id) = envelope.cursor_id() { return Ok(ViewerEvent::CursorId(id)); }
                if let Ok(position) = envelope.cursor_position() { return Ok(ViewerEvent::CursorPosition(position)); }
                Ok(ViewerEvent::CursorShape(envelope.cursor_shape()?))
            },
            MessageKind::TestDelay => {
                let delay = envelope.test_delay()?;
                if !delay.from_client { self.transport.send(&raw, deadline).await?; }
                Ok(ViewerEvent::TestDelay(delay))
            },
            MessageKind::Other => match envelope.desktop_peer_info() {
                Ok(info) => Ok(ViewerEvent::PeerInfo(info)),
                Err(DesktopError::UnexpectedMessage) => Ok(ViewerEvent::Other(raw)),
                Err(error) => Err(ViewerError::Desktop(error)),
            },
            _ => Ok(ViewerEvent::Other(raw)),
        }
    }
    /// Close the stream. No peer acknowledgement is implied.
    pub fn close(&mut self) { self.phase = Phase::Closed; self.transport.close(); }
}
impl<T: NetworkTransport> Drop for ViewerConnection<T> { fn drop(&mut self) { self.close(); } }

impl<T: remote_transport::AdjustableNetworkTransport> ViewerConnection<T> {
    /// Change the actual framing bound after the basic login has completed.
    /// It is the caller's responsibility to trust the authenticated host and
    /// select a safe limit; native video decoder allocations remain unbounded.
    pub fn set_connected_message_limit(&mut self, maximum: usize) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || maximum == 0 || maximum > MAX_ENVELOPE_BYTES { return Err(ViewerError::InvalidState); }
        self.transport.set_max_message_size(maximum)?;
        self.max_bytes = maximum;
        Ok(())
    }
}
