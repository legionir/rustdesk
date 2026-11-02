//! Experimental accepted-socket WSS server adapter using the pinned source
//! WebSocket fork. No listener, TLS certificate provisioning, peer admission,
//! HTTP path/origin policy, client authentication, relay or owner consent is
//! provided. TLS alone does not authenticate the desktop controller. This has
//! not been built, tested or security-reviewed. Do not expose it publicly.

use futures_util::{SinkExt, StreamExt};
use remote_transport::{AdjustableNetworkTransport, NetworkTransport, NetworkTransportError, TransportFuture};
use std::{error::Error, fmt, sync::Arc, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{rustls::ServerConfig, server::TlsStream, TlsAcceptor};
use tokio_tungstenite::{accept_async_with_config, tungstenite::{protocol::WebSocketConfig, Message}, WebSocketStream};

const MAX_CONTROL_FRAMES: usize = 32;
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
type Socket = WebSocketStream<TlsStream<TcpStream>>;

/// Explicit recognition that TLS/WebSocket alone is not authorization.
pub struct WssServerOptIn(());
impl WssServerOptIn {
    pub fn acknowledge_missing_admission_and_origin_policy() -> Self { Self(()) }
}
#[derive(Debug)]
pub enum WssServerError { InvalidLimit, InvalidDeadline, HandshakeFailed, Timeout }
impl fmt::Display for WssServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => f.write_str("invalid WSS server limit"),
            Self::InvalidDeadline => f.write_str("invalid WSS server deadline"),
            Self::HandshakeFailed => f.write_str("TLS or WebSocket handshake failed"),
            Self::Timeout => f.write_str("TLS/WebSocket handshake timed out"),
        }
    }
}
impl Error for WssServerError {}

/// One TLS-protected binary WebSocket accepted on a caller-owned TCP socket.
pub struct StrictWssServer { socket: Option<Socket>, maximum: usize }
impl StrictWssServer {
    /// Upgrade a previously accepted socket under a caller-provisioned rustls
    /// server config. The caller must acquire an admission slot from the actual
    /// TCP peer **before** calling and hold it through all approval. HTTP path,
    /// origin, subprotocol and headers are not checked. No handshake CPU or
    /// aggregate connection bounds beyond the caller's policy are supplied.
    /// Cancellation, timeout or error drops the owned socket.
    pub async fn accept(stream: TcpStream, tls: Arc<ServerConfig>, maximum: usize, deadline: Duration, _ack: WssServerOptIn) -> Result<Self, WssServerError> {
        if maximum == 0 || maximum > MAX_MESSAGE_BYTES { return Err(WssServerError::InvalidLimit); }
        if deadline.is_zero() { return Err(WssServerError::InvalidDeadline); }
        let config = WebSocketConfig::default().read_buffer_size(16 * 1024).write_buffer_size(0)
            .max_write_buffer_size(maximum + 64 * 1024).max_message_size(Some(maximum)).max_frame_size(Some(maximum));
        let socket = timeout(deadline, async move {
            let tls = TlsAcceptor::from(tls).accept(stream).await.map_err(|_| WssServerError::HandshakeFailed)?;
            accept_async_with_config(tls, Some(config)).await.map_err(|_| WssServerError::HandshakeFailed)
        }).await.map_err(|_| WssServerError::Timeout)??;
        Ok(Self { socket: Some(socket), maximum })
    }
    pub fn is_open(&self) -> bool { self.socket.is_some() }
}
impl NetworkTransport for StrictWssServer {
    fn send<'a>(&'a mut self, bytes: &'a [u8], deadline: Duration) -> TransportFuture<'a, Result<(), NetworkTransportError>> {
        Box::pin(async move {
            if deadline.is_zero() || bytes.len() > self.maximum { return Err(NetworkTransportError::InvalidRequest("invalid WSS deadline or size".into())); }
            let mut socket = self.socket.take().ok_or(NetworkTransportError::Closed)?;
            match timeout(deadline, socket.send(Message::Binary(bytes.to_vec().into()))).await {
                Ok(Ok(())) => { self.socket = Some(socket); Ok(()) },
                _ => Err(NetworkTransportError::SendOutcomeUnknown("WSS server send failed".into())),
            }
        })
    }
    fn receive(&mut self, deadline: Duration) -> TransportFuture<'_, Result<Box<[u8]>, NetworkTransportError>> {
        Box::pin(async move {
            if deadline.is_zero() { return Err(NetworkTransportError::InvalidRequest("invalid WSS deadline".into())); }
            let mut socket = self.socket.take().ok_or(NetworkTransportError::Closed)?;
            let read = async {
                let mut controls = 0;
                loop {
                    match socket.next().await {
                        Some(Ok(Message::Binary(bytes))) if bytes.len() <= self.maximum => return Ok(bytes.to_vec().into_boxed_slice()),
                        Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                            controls += 1; if controls > MAX_CONTROL_FRAMES { return Err(()); }
                        },
                        _ => return Err(()),
                    }
                }
            };
            match timeout(deadline, read).await {
                Ok(Ok(bytes)) => { self.socket = Some(socket); Ok(bytes) },
                _ => Err(NetworkTransportError::ReceiveFailed("WSS server receive failed".into())),
            }
        })
    }
    fn close(&mut self) { self.socket.take(); }
}
impl AdjustableNetworkTransport for StrictWssServer {
    fn set_max_message_size(&mut self, maximum: usize) -> Result<(), NetworkTransportError> {
        if maximum == 0 || maximum > MAX_MESSAGE_BYTES { return Err(NetworkTransportError::InvalidRequest("invalid WSS server frame limit".into())); }
        let socket = self.socket.as_mut().ok_or(NetworkTransportError::Closed)?;
        socket.set_config(|config| { config.max_message_size = Some(maximum); config.max_frame_size = Some(maximum); config.max_write_buffer_size = maximum + 64 * 1024; });
        self.maximum = maximum;
        Ok(())
    }
}
impl Drop for StrictWssServer { fn drop(&mut self) { self.close(); } }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{source_crypto::{accept_pinned_host, connect_pinned_host}, strict_wss::{client_config, StrictWss}};
    use hbb_common::sodiumoxide::{self, crypto::sign};
    use tokio::{net::TcpListener, time::timeout};
    use tokio_rustls::rustls::{self, pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer}, RootCertStore};
    const WAIT: Duration = Duration::from_secs(5);
    const CA: &[u8] = include_bytes!("../fixtures/test-ca.der");
    const CERT: &[u8] = include_bytes!("../fixtures/test-server.der");
    const KEY: &[u8] = include_bytes!("../fixtures/test-server-key.der");
    fn configs() -> (Arc<ServerConfig>, Arc<rustls::ClientConfig>) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap()
            .with_no_client_auth().with_single_cert(vec![CertificateDer::from(CERT.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec()))).unwrap();
        let mut roots = RootCertStore::empty(); roots.add(CertificateDer::from(CA.to_vec())).unwrap();
        (Arc::new(server), client_config(roots).unwrap())
    }
    #[tokio::test]
    async fn tls_websocket_and_source_encryption_exchange_binary() {
        sodiumoxide::init().unwrap();
        let (server_config, client_config) = configs();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (public, secret) = sign::gen_keypair();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let ws = StrictWssServer::accept(stream, server_config, 128 * 1024, WAIT, WssServerOptIn::acknowledge_missing_admission_and_origin_policy()).await.unwrap();
            let mut secured = accept_pinned_host(ws, "test-host", &secret, 128 * 1024 - 16, WAIT).await.unwrap();
            secured.set_max_message_size(4096).unwrap();
            assert_eq!(&*secured.receive(WAIT).await.unwrap(), b"hello");
            secured.send(b"response", WAIT).await.unwrap();
        });
        let url = url::Url::parse(&format!("wss://localhost:{port}/")).unwrap();
        let ws = StrictWss::connect_with_config(url, 128 * 1024, WAIT, client_config).await.unwrap();
        let mut secured = connect_pinned_host(ws, "test-host", &public, 128 * 1024 - 16, WAIT).await.unwrap();
        secured.set_max_message_size(4096).unwrap();
        secured.send(b"hello", WAIT).await.unwrap();
        assert_eq!(&*secured.receive(WAIT).await.unwrap(), b"response");
        timeout(WAIT, task).await.unwrap().unwrap();
    }
}
