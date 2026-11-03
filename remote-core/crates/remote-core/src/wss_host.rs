//! Explicit accepted-socket WSS listener composition, unbuilt and unaudited.
//! Not an Internet-facing service, proxy authentication, secure consent or
//! production listener. The application must provision TLS and host pins,
//! authenticate the viewer, approve screen access, rate-limit failed logins,
//! coordinate all listeners, and handle lifecycle and deployment policy.
use crate::{admitted_host::{self, WssAcceptError}, host_connection::HostConnection};
use hbb_common::sodiumoxide::crypto::sign;
use remote_input::InputBackend;
use remote_rustdesk_websocket::{source_crypto::EncryptedTransport, wss_server::{ServerTlsConfig, StrictWssServer, UpgradePolicy, WssServerOptIn}};
use remote_security::{admission::{AdmissionController, AdmissionError, AdmissionPermit}, PasswordVerifier};
use remote_session::SessionId;
use std::{error::Error, fmt, io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::{TcpListener, TcpStream}, time::timeout};

#[derive(Debug)]
pub enum ListenerError { InvalidDeadline, Timeout, Io(io::Error), Admission(AdmissionError), Setup(WssAcceptError) }
impl fmt::Display for ListenerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { match self {
        Self::InvalidDeadline => f.write_str("invalid WSS listener deadline"), Self::Timeout => f.write_str("WSS listener timed out"),
        Self::Io(error) => write!(f, "WSS listener: {error}"), Self::Admission(error) => write!(f, "admission: {error}"),
        Self::Setup(error) => write!(f, "WSS host setup: {error}"),
    } }
}
impl Error for ListenerError {}
fn valid_deadline(value: Duration) -> bool { !value.is_zero() && value <= Duration::from_secs(180) }
/// Literal bind address, with all admission capacity shared explicitly by the
/// caller. Listening on non-loopback exposes an unauthenticated TCP socket.
pub struct WssHostListener { listener: TcpListener, admission: AdmissionController }
impl WssHostListener {
    pub async fn bind(address: SocketAddr, admission: AdmissionController, deadline: Duration,
        _opt_in: WssServerOptIn) -> Result<Self, ListenerError> {
        if !valid_deadline(deadline) { return Err(ListenerError::InvalidDeadline); }
        let listener = timeout(deadline, TcpListener::bind(address)).await.map_err(|_| ListenerError::Timeout)?.map_err(ListenerError::Io)?;
        Ok(Self { listener, admission })
    }
    pub fn local_addr(&self) -> Result<SocketAddr, ListenerError> { self.listener.local_addr().map_err(ListenerError::Io) }
    /// Reserve admission before TLS/HTTP processing based on the actual socket
    /// peer. A reverse proxy's IP is not the end user's authenticated identity.
    /// A rejected permit drops the accepted socket. Upstream per-IP/prefix rate
    /// limiting, certificate policy and TLS DoS protection are not provided.
    pub async fn accept(&self, deadline: Duration) -> Result<AdmittedWssSocket, ListenerError> {
        if !valid_deadline(deadline) { return Err(ListenerError::InvalidDeadline); }
        let (stream, peer) = timeout(deadline, self.listener.accept()).await.map_err(|_| ListenerError::Timeout)?.map_err(ListenerError::Io)?;
        let permit = self.admission.admit(peer.ip()).map_err(ListenerError::Admission)?;
        Ok(AdmittedWssSocket { stream, peer, permit })
    }
}
/// One accepted socket and permit. Dropping closes the socket and frees the
/// admission slot. It cannot be cloned or reassigned to another connection.
pub struct AdmittedWssSocket { stream: TcpStream, peer: SocketAddr, permit: AdmissionPermit }
impl AdmittedWssSocket {
    pub fn peer_addr(&self) -> SocketAddr { self.peer }
    pub fn remaining_grace(&self) -> Duration { self.permit.remaining() }
    /// Consumes this socket through TLS, a caller-selected HTTP upgrade policy,
    /// and strict source-v1 host key exchange. Header matching is not identity
    /// authentication; password and trusted local owner approval still follow.
    /// Cancellation drops the socket and permit; no automatic retries occur.
    pub async fn secure<B: InputBackend>(self, tls: Arc<ServerTlsConfig>, id: SessionId, backend: B,
        verifier: PasswordVerifier, host_id: &str, signing_key: &sign::SecretKey, deadline: Duration,
        policy: UpgradePolicy, opt_in: WssServerOptIn)
        -> Result<HostConnection<EncryptedTransport<StrictWssServer>, B>, ListenerError> {
        if !valid_deadline(deadline) { return Err(ListenerError::InvalidDeadline); }
        admitted_host::accept_wss_with_policy(self.stream, tls, self.permit, id, backend, verifier, host_id, signing_key, deadline, policy, opt_in)
            .await.map_err(ListenerError::Setup)
    }
}
