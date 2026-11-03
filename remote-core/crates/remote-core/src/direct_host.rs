//! Explicitly opted-in direct TCP host listener and pre-auth composition.
//!
//! This is a low-level experimental building block, not a public server. It
//! binds the exact address selected by the caller, observes the socket peer IP,
//! acquires a bounded admission permit *before* any identity handshake, and
//! holds it through the pending host connection's password and owner approval.
//! Authentication of the viewer, trusted owner consent, online password-failure
//! limits, TLS/proxy policy, pin provisioning, lifecycle and network exposure
//! remain the embedding application's responsibility. No automatic listener,
//! UI, port mapping, relay or Internet exposure is enabled by this module.
use crate::{admitted_host::{self, AcceptError}, host_connection::HostConnection};
use hbb_common::sodiumoxide::crypto::sign;
use remote_input::InputBackend;
use remote_protocol::MAX_PRE_AUTH_BYTES;
use remote_rustdesk_websocket::{direct_tcp::{DirectTcp, DirectTcpError, DirectTcpListener, DirectTcpOptIn}, source_crypto::EncryptedTransport};
use remote_security::{admission::{AdmissionController, AdmissionError, AdmissionPermit}, PasswordVerifier};
use remote_session::SessionId;
use std::{error::Error, fmt, net::SocketAddr, time::Duration};

#[derive(Debug)]
pub enum DirectHostError { Listen(DirectTcpError), Admission(AdmissionError), Handshake(AcceptError) }
impl fmt::Display for DirectHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::Listen(e) => write!(f, "direct TCP: {e}"), Self::Admission(e) => write!(f, "admission: {e}"), Self::Handshake(e) => write!(f, "host handshake: {e}") }
    }
}
impl Error for DirectHostError {}

/// One explicit listener sharing the caller's admission controller. The caller
/// must ensure all listeners/processes cooperate with the same limits.
pub struct DirectHostListener { listener: DirectTcpListener, admission: AdmissionController }
impl DirectHostListener {
    /// Bind a literal address. Non-loopback binds expose the socket to a
    /// network and require a separately reviewed deployment policy. TCP is
    /// initially plaintext until the required source-v1 handshake succeeds.
    pub async fn bind(address: SocketAddr, admission: AdmissionController, deadline: Duration, opt_in: DirectTcpOptIn) -> Result<Self, DirectHostError> {
        let listener = DirectTcpListener::bind(address, MAX_PRE_AUTH_BYTES + 16, deadline, opt_in).await.map_err(DirectHostError::Listen)?;
        Ok(Self { listener, admission })
    }
    pub fn local_addr(&self) -> Result<SocketAddr, DirectHostError> { self.listener.local_addr().map_err(DirectHostError::Listen) }
    /// Accept one connection and reserve capacity using the socket peer IP.
    /// A proxy/NAT address is not the end peer's identity. A rejected permit
    /// causes the accepted socket to be dropped. No handshake has run yet.
    pub async fn accept(&self, deadline: Duration) -> Result<AdmittedSocket, DirectHostError> {
        let (stream, peer) = self.listener.accept(deadline).await.map_err(DirectHostError::Listen)?;
        let permit = self.admission.admit(peer.ip()).map_err(DirectHostError::Admission)?;
        Ok(AdmittedSocket { stream, permit, peer })
    }
}
/// Socket and unique permit. Dropping this value closes the socket and releases
/// the permit. Preparation after accept consumes the permit's login grace.
pub struct AdmittedSocket { stream: DirectTcp, permit: AdmissionPermit, peer: SocketAddr }
impl AdmittedSocket {
    pub fn peer_addr(&self) -> SocketAddr { self.peer }
    pub fn remaining_grace(&self) -> Duration { self.permit.remaining() }
    /// Perform the same admitted handshake but wrap the serial connection so a
    /// caller may explicitly enable read-ahead after password and owner consent.
    /// It starts in serial mode with the pre-authentication framing limit; no
    /// duplex task, input, capture or extra trust is enabled by this method.
    pub async fn secure_upgradeable<B: InputBackend>(self, id: SessionId, backend: B, verifier: PasswordVerifier,
        host_id: &str, signing_key: &sign::SecretKey, deadline: Duration)
        -> Result<HostConnection<remote_rustdesk_websocket::duplex_tcp::UpgradeableEncryptedTcp, B>, DirectHostError> {
        admitted_host::accept_upgradeable_tcp(self.stream, self.permit, id, backend, verifier, host_id, signing_key, deadline)
            .await.map_err(DirectHostError::Handshake)
    }
    /// Perform strict source-v1 host identity exchange. The returned connection
    /// still needs password login and a separate trusted local owner decision;
    /// a peer address or peer-supplied label is not an authenticated identity.
    /// A cancellation or error drops the stream and admission permit.
    pub async fn secure<B: InputBackend>(self, id: SessionId, backend: B, verifier: PasswordVerifier,
        host_id: &str, signing_key: &sign::SecretKey, deadline: Duration) -> Result<HostConnection<EncryptedTransport<DirectTcp>, B>, DirectHostError> {
        admitted_host::accept(self.stream, self.permit, id, backend, verifier, host_id, signing_key, deadline).await.map_err(DirectHostError::Handshake)
    }
}
