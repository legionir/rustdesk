//! Experimental accepted-socket WSS server adapter using the pinned source
//! WebSocket fork. No listener, TLS certificate provisioning, peer admission,
//! HTTP path/origin policy, client authentication, relay or owner consent is
//! provided. TLS alone does not authenticate the desktop controller. This has
//! not been built, tested or security-reviewed. Do not expose it publicly.

use futures_util::{SinkExt, StreamExt};
use remote_transport::{AdjustableNetworkTransport, NetworkTransport, NetworkTransportError, TransportFuture};
use std::{error::Error, fmt, sync::Arc, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
/// Caller-provisioned rustls server policy; certificates and authorization are external.
pub use tokio_rustls::rustls::ServerConfig as ServerTlsConfig;
use tokio_tungstenite::{accept_async_with_config, accept_hdr_async_with_config,
    tungstenite::{handshake::server::{Request, Response, ErrorResponse}, http::{header::{HOST, ORIGIN}, StatusCode}, protocol::WebSocketConfig, Message}, WebSocketStream};

const MAX_CONTROL_FRAMES: usize = 32;
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
type Socket = WebSocketStream<TlsStream<TcpStream>>;

/// Explicit recognition that TLS/WebSocket alone is not authorization.
pub struct WssServerOptIn(());
impl WssServerOptIn {
    pub fn acknowledge_missing_admission_and_origin_policy() -> Self { Self(()) }
    /// Origin/path checks are not peer authentication or consent.
    pub fn acknowledge_tls_and_origin_are_not_authentication() -> Self { Self(()) }
}
/// Exact HTTP upgrade constraints supplied by a trusted application.
/// Origin checks mitigate accidental browser access but are not authentication:
/// non-browser clients can forge Origin and Host. Reverse proxies must preserve
/// expected headers; forwarded headers are never trusted here.
#[derive(Clone, Debug)]
pub struct UpgradePolicy { path: String, host: String, origin: Option<String>, allow_no_origin: bool }
impl UpgradePolicy {
    pub fn new(path: String, host: String, origin: Option<String>, allow_no_origin: bool) -> Result<Self, WssServerError> {
        let valid = |s: &str, max: usize| !s.is_empty() && s.len() <= max && s.is_ascii() && !s.bytes().any(|c| c.is_ascii_control() || c == b' ');
        if !valid(&path, 2048) || !path.starts_with('/') || path.contains('?') || path.contains('#')
            || !valid(&host, 512) || origin.as_ref().map_or(false, |o| !valid(o, 2048))
            || (origin.is_none() && !allow_no_origin) { return Err(WssServerError::InvalidPolicy); }
        Ok(Self { path, host, origin, allow_no_origin })
    }
    fn matches(&self, request: &Request) -> bool {
        if request.uri().path() != self.path || request.uri().query().is_some()
            || request.uri().scheme().is_some() || request.uri().authority().is_some() { return false; }
        let mut hosts = request.headers().get_all(HOST).iter();
        let host_ok = hosts.next().and_then(|h| h.to_str().ok()).map_or(false, |h| h.eq_ignore_ascii_case(&self.host)) && hosts.next().is_none();
        if !host_ok { return false; }
        let mut origins = request.headers().get_all(ORIGIN).iter();
        let first = origins.next();
        if origins.next().is_some() { return false; }
        match first {
            None => self.allow_no_origin,
            Some(value) => value.to_str().ok().zip(self.origin.as_deref()).map_or(false, |(value, expected)| value == expected),
        }
    }
    fn respond(&self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        if self.matches(request) { Ok(response) } else {
            let mut denied = ErrorResponse::new(Some("upgrade denied".into()));
            *denied.status_mut() = StatusCode::FORBIDDEN;
            Err(denied)
        }
    }
}
#[derive(Debug)]
pub enum WssServerError { InvalidLimit, InvalidDeadline, InvalidPolicy, HandshakeFailed, Timeout }
impl fmt::Display for WssServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => f.write_str("invalid WSS server limit"),
            Self::InvalidDeadline => f.write_str("invalid WSS server deadline"),
            Self::InvalidPolicy => f.write_str("invalid WSS upgrade policy"),
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
    pub async fn accept(stream: TcpStream, tls: Arc<ServerTlsConfig>, maximum: usize, deadline: Duration, _ack: WssServerOptIn) -> Result<Self, WssServerError> {
        Self::accept_inner(stream, tls, maximum, deadline, None).await
    }
    /// Like `accept`, but enforce an exact Host/path and explicitly configured
    /// Origin policy during the WebSocket upgrade. This is not authentication.
    pub async fn accept_with_policy(stream: TcpStream, tls: Arc<ServerTlsConfig>, maximum: usize, deadline: Duration, policy: UpgradePolicy, _ack: WssServerOptIn) -> Result<Self, WssServerError> {
        Self::accept_inner(stream, tls, maximum, deadline, Some(policy)).await
    }
    async fn accept_inner(stream: TcpStream, tls: Arc<ServerTlsConfig>, maximum: usize, deadline: Duration, policy: Option<UpgradePolicy>) -> Result<Self, WssServerError> {
        if maximum == 0 || maximum > MAX_MESSAGE_BYTES { return Err(WssServerError::InvalidLimit); }
        if deadline.is_zero() { return Err(WssServerError::InvalidDeadline); }
        let config = WebSocketConfig::default().read_buffer_size(16 * 1024).write_buffer_size(0)
            .max_write_buffer_size(maximum + 64 * 1024).max_message_size(Some(maximum)).max_frame_size(Some(maximum));
        let socket = timeout(deadline, async move {
            let tls = TlsAcceptor::from(tls).accept(stream).await.map_err(|_| WssServerError::HandshakeFailed)?;
            match policy {
                Some(policy) => accept_hdr_async_with_config(tls, move |req: &Request, response: Response| policy.respond(req, response), Some(config)).await,
                None => accept_async_with_config(tls, Some(config)).await,
            }.map_err(|_| WssServerError::HandshakeFailed)
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
    fn configs() -> (Arc<ServerTlsConfig>, Arc<rustls::ClientConfig>) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = ServerTlsConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap()
            .with_no_client_auth().with_single_cert(vec![CertificateDer::from(CERT.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec()))).unwrap();
        let mut roots = RootCertStore::empty(); roots.add(CertificateDer::from(CA.to_vec())).unwrap();
        (Arc::new(server), client_config(roots).unwrap())
    }
    #[test]
    fn upgrade_policy_checks_path_host_and_origin() {
        use tokio_tungstenite::tungstenite::http::Request as HttpRequest;
        let policy = UpgradePolicy::new("/remote".into(), "localhost:443".into(), Some("https://desktop.example".into()), false).unwrap();
        let good = HttpRequest::builder().uri("/remote").header("host", "localhost:443").header("origin", "https://desktop.example").body(()).unwrap();
        assert!(policy.matches(&good));
        let query = HttpRequest::builder().uri("/remote?token=x").header("host", "localhost:443").header("origin", "https://desktop.example").body(()).unwrap();
        assert!(!policy.matches(&query));
        let absent = HttpRequest::builder().uri("/remote").header("host", "localhost:443").body(()).unwrap();
        assert!(!policy.matches(&absent));
        let duplicate = HttpRequest::builder().uri("/remote").header("host", "localhost:443").header("origin", "https://desktop.example").header("origin", "https://evil.example").body(()).unwrap();
        assert!(!policy.matches(&duplicate));
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
