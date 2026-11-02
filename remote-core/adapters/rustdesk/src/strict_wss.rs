//! Experimental client-only WSS transport using RustDesk's pinned WebSocket fork.
//!
//! TLS validates the server certificate and hostname using bundled WebPKI and
//! system roots, without consulting RustDesk's global proxy or TLS-fallback
//! settings. A WSS server (or relay) can read the WebSocket payloads: this is
//! not end-to-end peer encryption, RustDesk's signed key exchange, or client
//! authentication. Do not expose input or decode untrusted video based on WSS
//! alone. This module has not been built, tested, or security-audited.

use futures_util::{SinkExt, StreamExt};
use remote_transport::{NetworkTransport, NetworkTransportError, TransportFuture};
use std::{error::Error, fmt, sync::Arc, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::{protocol::WebSocketConfig, Message}, Connector, MaybeTlsStream, WebSocketStream};
use url::Url;

/// Maximum accepted single message and frame size.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of control frames handled during one receive operation.
const MAX_CONTROL_FRAMES_PER_RECEIVE: usize = 32;
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// WSS validation, connection or I/O error. It never contains the endpoint URL.
#[derive(Debug)]
pub enum WssError {
    /// Only WSS URLs with a host and without credentials, query or fragment are accepted.
    InvalidEndpoint,
    /// Invalid message limit.
    InvalidLimit,
    /// Deadline must be nonzero.
    InvalidTimeout,
    /// Local input exceeds the configured bound and was not sent.
    MessageTooLarge { size: usize, limit: usize },
    /// TLS configuration could not be created.
    TlsConfiguration,
    /// DNS, TCP, TLS, certificate verification or WebSocket handshake failed.
    ConnectionFailed,
    /// Deadline elapsed. For sends, delivery can be indeterminate.
    Timeout,
    /// Socket was closed or an in-flight operation was cancelled.
    Closed,
    /// A text or unexpected frame was received on this binary-only stream.
    UnexpectedFrame,
    /// Control-frame flood during a single receive.
    TooManyControlFrames,
    /// A WebSocket or underlying I/O operation failed.
    Io,
}
impl fmt::Display for WssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint => f.write_str("expected a WSS URL without credentials, query or fragment"),
            Self::InvalidLimit => f.write_str("invalid WSS message limit"),
            Self::InvalidTimeout => f.write_str("WSS deadline must be nonzero"),
            Self::MessageTooLarge { size, limit } => write!(f, "message size {size} exceeds limit {limit}"),
            Self::TlsConfiguration => f.write_str("cannot initialize strict TLS configuration"),
            Self::ConnectionFailed => f.write_str("WSS connection or certificate validation failed"),
            Self::Timeout => f.write_str("WSS deadline exceeded; socket dropped"),
            Self::Closed => f.write_str("WSS socket is closed"),
            Self::UnexpectedFrame => f.write_str("expected binary WebSocket message"),
            Self::TooManyControlFrames => f.write_str("too many WebSocket control frames"),
            Self::Io => f.write_str("WSS I/O failed"),
        }
    }
}
impl Error for WssError {}

fn endpoint(raw: &str) -> Result<Url, WssError> {
    let url = Url::parse(raw).map_err(|_| WssError::InvalidEndpoint)?;
    if url.scheme() != "wss" || url.host().is_none() || !url.username().is_empty()
        || url.password().is_some() || url.query().is_some() || url.fragment().is_some()
        || url.port() == Some(0) {
        return Err(WssError::InvalidEndpoint);
    }
    Ok(url)
}
fn validate_limit(max_message_size: usize, deadline: Duration) -> Result<(), WssError> {
    if max_message_size == 0 || max_message_size > MAX_MESSAGE_BYTES { return Err(WssError::InvalidLimit); }
    if deadline.is_zero() { return Err(WssError::InvalidTimeout); }
    Ok(())
}

fn client_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, WssError> {
    // An explicitly chosen provider avoids relying on Rustls's process-global
    // provider selection when other parts of the application use Rustls too.
    if roots.is_empty() { return Err(WssError::TlsConfiguration); }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions()
        .map_err(|_| WssError::TlsConfiguration)?;
    Ok(Arc::new(builder.with_root_certificates(roots).with_no_client_auth()))
}
fn system_client_config() -> Result<Arc<ClientConfig>, WssError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // RustDesk likewise combines bundled and native roots. The bundled store
    // remains usable if the platform store cannot be loaded; invalid roots are
    // ignored, never treated as valid leaf certificates.
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    client_config(roots)
}

/// A binary-only WSS client with a per-connection strict TLS policy.
pub struct StrictWss {
    socket: Option<Socket>,
    max_message_size: usize,
}
impl StrictWss {
    /// Connect with validated TLS server identity and no insecure fallback.
    ///
    /// Only a trusted application should choose the endpoint: the URL can
    /// point to any network host (SSRF protections are not implemented).
    /// Query strings, authentication headers, client certificates, proxies,
    /// certificate pinning and custom roots are not supported. This validates
    /// the WSS server, not a remote desktop peer behind a relay.
    pub async fn connect(raw: &str, max_message_size: usize, deadline: Duration) -> Result<Self, WssError> {
        let url = endpoint(raw)?;
        validate_limit(max_message_size, deadline)?;
        let config = system_client_config()?;
        Self::connect_with_config(url, max_message_size, deadline, config).await
    }
    async fn connect_with_config(url: Url, max_message_size: usize, deadline: Duration, config: Arc<ClientConfig>) -> Result<Self, WssError> {
        validate_limit(max_message_size, deadline)?;
        let ws_config = WebSocketConfig::default()
            .read_buffer_size(16 * 1024)
            .write_buffer_size(0)
            .max_write_buffer_size(max_message_size + 64 * 1024)
            .max_message_size(Some(max_message_size))
            .max_frame_size(Some(max_message_size));
        // Outer deadline covers DNS, TCP, TLS and HTTP upgrade. Passing an
        // explicit connector avoids process-global fallback and proxy settings.
        let (socket, _) = timeout(deadline, connect_async_tls_with_config(
            url.as_str(), Some(ws_config), true, Some(Connector::Rustls(config)),
        )).await.map_err(|_| WssError::Timeout)?.map_err(|_| WssError::ConnectionFailed)?;
        Ok(Self { socket: Some(socket), max_message_size })
    }
    /// Whether the connection is still held by this adapter.
    pub fn is_open(&self) -> bool { self.socket.is_some() }
    /// Send a binary message. A failed or cancelled send may have reached the server.
    pub async fn send(&mut self, bytes: &[u8], deadline: Duration) -> Result<(), WssError> {
        validate_limit(self.max_message_size, deadline)?;
        if bytes.len() > self.max_message_size {
            return Err(WssError::MessageTooLarge { size: bytes.len(), limit: self.max_message_size });
        }
        let mut socket = self.socket.take().ok_or(WssError::Closed)?;
        timeout(deadline, socket.send(Message::Binary(bytes.to_vec().into()))).await
            .map_err(|_| WssError::Timeout)?.map_err(|_| WssError::Io)?;
        self.socket = Some(socket);
        Ok(())
    }
    /// Receive a binary message. Text frames and excessive control frames close the socket.
    pub async fn receive(&mut self, deadline: Duration) -> Result<Vec<u8>, WssError> {
        validate_limit(self.max_message_size, deadline)?;
        let mut socket = self.socket.take().ok_or(WssError::Closed)?;
        let read = async {
            let mut controls = 0;
            loop {
                match socket.next().await {
                    Some(Ok(Message::Binary(bytes))) => return Ok(bytes.to_vec()),
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                        controls += 1;
                        if controls > MAX_CONTROL_FRAMES_PER_RECEIVE { return Err(WssError::TooManyControlFrames); }
                    }
                    Some(Ok(Message::Close(_))) | None => return Err(WssError::Closed),
                    Some(Ok(_)) => return Err(WssError::UnexpectedFrame),
                    Some(Err(_)) => return Err(WssError::Io),
                }
            }
        };
        let bytes = timeout(deadline, read).await.map_err(|_| WssError::Timeout)??;
        if bytes.len() > self.max_message_size {
            return Err(WssError::MessageTooLarge { size: bytes.len(), limit: self.max_message_size });
        }
        self.socket = Some(socket);
        Ok(bytes)
    }
    /// Drop without waiting for a close handshake or delivery acknowledgement.
    pub fn close(&mut self) { self.socket.take(); }
}
impl NetworkTransport for StrictWss {
    fn send<'a>(&'a mut self, bytes: &'a [u8], deadline: Duration) -> TransportFuture<'a, Result<(), NetworkTransportError>> {
        Box::pin(async move {
            StrictWss::send(self, bytes, deadline).await.map_err(|e| match e {
                WssError::Closed => NetworkTransportError::Closed,
                WssError::InvalidTimeout | WssError::InvalidLimit | WssError::MessageTooLarge { .. } => NetworkTransportError::InvalidRequest(e.to_string()),
                _ => NetworkTransportError::SendOutcomeUnknown(e.to_string()),
            })
        })
    }
    fn receive(&mut self, deadline: Duration) -> TransportFuture<'_, Result<Box<[u8]>, NetworkTransportError>> {
        Box::pin(async move {
            StrictWss::receive(self, deadline).await.map(Vec::into_boxed_slice).map_err(|e| match e {
                WssError::Closed => NetworkTransportError::Closed,
                WssError::InvalidTimeout | WssError::InvalidLimit => NetworkTransportError::InvalidRequest(e.to_string()),
                _ => NetworkTransportError::ReceiveFailed(e.to_string()),
            })
        })
    }
    fn close(&mut self) { StrictWss::close(self); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{net::TcpListener, task::JoinHandle};
    use tokio_rustls::{rustls::{pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer}, ServerConfig}, TlsAcceptor};
    use tokio_tungstenite::accept_async;
    const WAIT: Duration = Duration::from_secs(5);
    const CA: &[u8] = include_bytes!("../fixtures/test-ca.der");
    const CERT: &[u8] = include_bytes!("../fixtures/test-server.der");
    const KEY: &[u8] = include_bytes!("../fixtures/test-server-key.der");

    fn test_roots() -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(CA.to_vec())).unwrap();
        client_config(roots).unwrap()
    }
    async fn test_server(text: bool) -> (u16, JoinHandle<()>) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = CertificateDer::from(CERT.to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec()));
        let config = ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap()
            .with_no_client_auth().with_single_cert(vec![cert], key).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else { return };
            let Ok(tls) = TlsAcceptor::from(Arc::new(config)).accept(stream).await else { return };
            let Ok(mut ws) = accept_async(tls).await else { return };
            if text {
                let _ = ws.send(Message::Text("not binary".into())).await;
            } else if let Some(Ok(Message::Binary(data))) = ws.next().await {
                let _ = ws.send(Message::Binary(data)).await;
            }
        });
        (port, task)
    }
    async fn finish(task: JoinHandle<()>) { timeout(WAIT, task).await.unwrap().unwrap(); }
    #[test]
    fn endpoint_policy_refuses_plaintext_and_url_secrets() {
        assert!(endpoint("wss://example.com/path").is_ok());
        for value in ["ws://example.com/", "https://example.com/", "wss://user:pass@example.com/", "wss://example.com/?token=x", "wss://example.com/#x", "wss://example.com:0/"] {
            assert!(matches!(endpoint(value), Err(WssError::InvalidEndpoint)));
        }
    }
    #[tokio::test]
    async fn validates_test_ca_and_transfers_binary() {
        let (port, task) = test_server(false).await;
        let url = endpoint(&format!("wss://localhost:{port}/")).unwrap();
        let mut client = StrictWss::connect_with_config(url, 1024, WAIT, test_roots()).await.unwrap();
        client.send(b"synthetic", WAIT).await.unwrap();
        assert_eq!(client.receive(WAIT).await.unwrap(), b"synthetic");
        finish(task).await;
    }
    #[tokio::test]
    async fn refuses_wrong_hostname_even_for_trusted_ca() {
        let (port, task) = test_server(false).await;
        // The fixture has only DNS:localhost, not the 127.0.0.1 IP SAN.
        let url = endpoint(&format!("wss://127.0.0.1:{port}/")).unwrap();
        assert!(matches!(StrictWss::connect_with_config(url, 1024, WAIT, test_roots()).await, Err(WssError::ConnectionFailed)));
        finish(task).await;
    }
    #[tokio::test]
    async fn refuses_untrusted_ca_and_closes_on_text() {
        let (port, task) = test_server(false).await;
        assert!(matches!(StrictWss::connect(&format!("wss://localhost:{port}/"), 1024, WAIT).await, Err(WssError::ConnectionFailed)));
        finish(task).await;
        let (port, task) = test_server(true).await;
        let url = endpoint(&format!("wss://localhost:{port}/")).unwrap();
        let mut client = StrictWss::connect_with_config(url, 1024, WAIT, test_roots()).await.unwrap();
        assert!(matches!(client.receive(WAIT).await, Err(WssError::UnexpectedFrame)));
        assert!(!client.is_open());
        finish(task).await;
    }
}
