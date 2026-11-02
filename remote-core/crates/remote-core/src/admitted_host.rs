//! Experimental admission-before-identity-handshake composition.
//!
//! Only available behind `source-security`. This binds the lifetime of an
//! admission permit to an owned stream and uses the existing strict source-v1
//! pinned-host handshake; it does not implement a listener, caller IP trust,
//! viewer authentication, UI consent, 2FA, rate limiting or a security audit.

use crate::host_connection::{ConnectionError, HostConnection};
use hbb_common::sodiumoxide::crypto::sign;
use remote_input::InputBackend;
use remote_protocol::MAX_PRE_AUTH_BYTES;
use remote_rustdesk_websocket::source_crypto::{accept_pinned_host, EncryptedTransport, HandshakeError};
use remote_security::{admission::{AdmissionError, AdmissionPermit}, PasswordVerifier};
use remote_session::SessionId;
use remote_transport::{AdjustableNetworkTransport, NetworkTransportError};
use std::{error::Error, fmt, time::Duration};

/// Admission, framing, key exchange or session initialization failed.
#[derive(Debug)]
pub enum AcceptError { Admission(AdmissionError), Framing(NetworkTransportError), Handshake(HandshakeError), Connection(ConnectionError) }
impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(e) => write!(f, "admission: {e}"), Self::Framing(e) => write!(f, "framing: {e}"),
            Self::Handshake(e) => write!(f, "handshake: {e}"), Self::Connection(e) => write!(f, "connection: {e}"),
        }
    }
}
impl Error for AcceptError {}

/// Initialize one admitted host after accepting a socket and deriving the
/// permit from its *transport-observed* address. The permit is acquired by the
/// caller before this function. Before handshake I/O, the actual framing limit
/// is reduced to `MAX_PRE_AUTH_BYTES + 16` for the secretbox tag. The handshake
/// is limited by both the caller deadline and permit grace. It then returns an
/// unauthenticated `HostConnection`; password verification and local owner
/// approval are still mandatory. Any error/cancellation closes the stream and
/// drops the permit, assuming the provided transport obeys its close contract.
///
/// Other listeners/processes can bypass this admission controller. A proxy or
/// relay address must not be mistaken for authenticated end-peer identity.
/// Pinned key exchange alone authenticates the host to the viewer, not vice
/// versa. This API has not been built, tested or security-reviewed.
pub async fn accept<T: AdjustableNetworkTransport, B: InputBackend>(
    mut transport: T, permit: AdmissionPermit, id: SessionId, backend: B,
    verifier: PasswordVerifier, host_id: &str, signing_key: &sign::SecretKey, deadline: Duration,
) -> Result<HostConnection<EncryptedTransport<T>, B>, AcceptError> {
    if let Err(e) = permit.check_live() { transport.close(); return Err(AcceptError::Admission(e)); }
    if let Err(e) = transport.set_max_message_size(MAX_PRE_AUTH_BYTES + 16) { transport.close(); return Err(AcceptError::Framing(e)); }
    let wait = deadline.min(permit.remaining());
    if wait.is_zero() { transport.close(); return Err(AcceptError::Admission(AdmissionError::Expired)); }
    let secured = accept_pinned_host(transport, host_id, signing_key, MAX_PRE_AUTH_BYTES, wait).await.map_err(AcceptError::Handshake)?;
    HostConnection::new(secured, id, backend, verifier, permit, MAX_PRE_AUTH_BYTES).map_err(AcceptError::Connection)
}

/// Errors in pre-admitted WSS transport setup or the source host handshake.
#[derive(Debug)]
pub enum WssAcceptError {
    Admission(AdmissionError),
    Transport(remote_rustdesk_websocket::wss_server::WssServerError),
    Host(AcceptError),
}
impl fmt::Display for WssAcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(e) => write!(f, "admission: {e}"),
            Self::Transport(e) => write!(f, "WSS setup: {e}"),
            Self::Host(e) => write!(f, "source host setup: {e}"),
        }
    }
}
impl Error for WssAcceptError {}

/// Apply a caller-acquired admission permit *before* the TLS and WebSocket
/// upgrade, then perform the pinned source host handshake. Both upgrades share
/// a total deadline and the admission grace; the returned host still requires
/// password validation and trusted local owner approval. The caller supplies a
/// reviewed TLS certificate/configuration, observed peer IP and listener policy.
/// This adapter performs no HTTP origin/path, relay, client identity, DoS or
/// consent policy. It is unbuilt, untested and not safe to expose publicly.
/// Cancellation drops the socket and permit; a failed setup is not retried.
pub async fn accept_wss<B: InputBackend>(
    stream: tokio::net::TcpStream,
    tls: std::sync::Arc<remote_rustdesk_websocket::wss_server::ServerTlsConfig>,
    permit: AdmissionPermit, id: SessionId, backend: B, verifier: PasswordVerifier,
    host_id: &str, signing_key: &sign::SecretKey, deadline: Duration,
    acknowledge: remote_rustdesk_websocket::wss_server::WssServerOptIn,
) -> Result<HostConnection<EncryptedTransport<remote_rustdesk_websocket::wss_server::StrictWssServer>, B>, WssAcceptError> {
    accept_wss_inner(stream, tls, permit, id, backend, verifier, host_id, signing_key, deadline, None, acknowledge).await
}

/// Pre-admitted WSS host with explicitly selected exact HTTP Host/path/Origin
/// constraints. These headers can be forged by non-browser clients and do not
/// authenticate an endpoint. All `accept_wss` caveats still apply.
pub async fn accept_wss_with_policy<B: InputBackend>(
    stream: tokio::net::TcpStream,
    tls: std::sync::Arc<remote_rustdesk_websocket::wss_server::ServerTlsConfig>,
    permit: AdmissionPermit, id: SessionId, backend: B, verifier: PasswordVerifier,
    host_id: &str, signing_key: &sign::SecretKey, deadline: Duration,
    policy: remote_rustdesk_websocket::wss_server::UpgradePolicy,
    acknowledge: remote_rustdesk_websocket::wss_server::WssServerOptIn,
) -> Result<HostConnection<EncryptedTransport<remote_rustdesk_websocket::wss_server::StrictWssServer>, B>, WssAcceptError> {
    accept_wss_inner(stream, tls, permit, id, backend, verifier, host_id, signing_key, deadline, Some(policy), acknowledge).await
}

async fn accept_wss_inner<B: InputBackend>(
    stream: tokio::net::TcpStream,
    tls: std::sync::Arc<remote_rustdesk_websocket::wss_server::ServerTlsConfig>,
    permit: AdmissionPermit, id: SessionId, backend: B, verifier: PasswordVerifier,
    host_id: &str, signing_key: &sign::SecretKey, deadline: Duration,
    policy: Option<remote_rustdesk_websocket::wss_server::UpgradePolicy>,
    acknowledge: remote_rustdesk_websocket::wss_server::WssServerOptIn,
) -> Result<HostConnection<EncryptedTransport<remote_rustdesk_websocket::wss_server::StrictWssServer>, B>, WssAcceptError> {
    use remote_rustdesk_websocket::wss_server::StrictWssServer;
    permit.check_live().map_err(WssAcceptError::Admission)?;
    let wait = deadline.min(permit.remaining());
    if wait.is_zero() { return Err(WssAcceptError::Admission(AdmissionError::Expired)); }
    let end = std::time::Instant::now().checked_add(wait).ok_or(WssAcceptError::Admission(AdmissionError::Expired))?;
    let transport = match policy {
        Some(policy) => StrictWssServer::accept_with_policy(stream, tls, MAX_PRE_AUTH_BYTES + 16, wait, policy, acknowledge).await,
        None => StrictWssServer::accept(stream, tls, MAX_PRE_AUTH_BYTES + 16, wait, acknowledge).await,
    }.map_err(WssAcceptError::Transport)?;
    let remaining = end.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() { return Err(WssAcceptError::Admission(AdmissionError::Expired)); }
    accept(transport, permit, id, backend, verifier, host_id, signing_key, remaining).await.map_err(WssAcceptError::Host)
}
