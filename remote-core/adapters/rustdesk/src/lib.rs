//! Experimental, loopback-only adapter for RustDesk's WebSocket client.
//!
//! This is deliberately not a remote WSS implementation. The source client
//! uses process-global TLS/proxy configuration and its unsecured receive path
//! accepts text frames. Those behaviors need isolation and security review
//! before use with remote peers. This adapter is suitable only for controlled
//! local development; it provides no authentication or encryption.

use hbb_common::{config::Config, websocket::WsFramedStream};
use std::{error::Error, fmt, time::Duration};
use tokio::time::timeout;
use url::{Host, Url};

/// Maximum payload accepted or sent by this adapter.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Error from the legacy WebSocket adapter.
#[derive(Debug)]
pub enum WebSocketError {
    /// URL is not an explicitly allowed loopback WebSocket endpoint.
    InvalidEndpoint,
    /// Configuration would route the connection through a proxy.
    ProxyNotAllowed,
    /// Message limit is zero or exceeds the adapter ceiling.
    InvalidLimit,
    /// Timeout must be nonzero and fit the source client's millisecond API.
    InvalidTimeout,
    /// Message exceeds the configured limit.
    MessageTooLarge { size: usize, limit: usize },
    /// Deadline elapsed; the socket has been dropped.
    Timeout,
    /// Connection was closed, aborted, or cancelled.
    Closed,
    /// Underlying WebSocket or I/O failure.
    Transport(String),
}
impl fmt::Display for WebSocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint => f.write_str("only literal loopback ws endpoints without credentials, query or fragment are allowed"),
            Self::ProxyNotAllowed => f.write_str("proxy configuration is not allowed for this loopback adapter"),
            Self::InvalidLimit => f.write_str("invalid message limit"),
            Self::InvalidTimeout => f.write_str("invalid timeout"),
            Self::MessageTooLarge { size, limit } => write!(f, "message size {size} exceeds limit {limit}"),
            Self::Timeout => f.write_str("WebSocket deadline exceeded; connection closed"),
            Self::Closed => f.write_str("WebSocket is closed"),
            Self::Transport(error) => write!(f, "WebSocket transport: {error}"),
        }
    }
}
impl Error for WebSocketError {}

fn timeout_ms(deadline: Duration) -> Result<u64, WebSocketError> {
    let millis = deadline.as_millis();
    if millis == 0 || millis > u64::MAX as u128 { return Err(WebSocketError::InvalidTimeout); }
    Ok(millis as u64)
}

fn validate_endpoint(endpoint: &str) -> Result<Url, WebSocketError> {
    let url = Url::parse(endpoint).map_err(|_| WebSocketError::InvalidEndpoint)?;
    let loopback = match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    };
    if url.scheme() != "ws" || !loopback || !url.username().is_empty() || url.password().is_some()
        || url.query().is_some() || url.fragment().is_some() {
        return Err(WebSocketError::InvalidEndpoint);
    }
    Ok(url)
}

/// A WebSocket backed by the pinned RustDesk `WsFramedStream`.
///
/// Sending is binary, but the underlying source accepts text frames before its
/// optional encryption is enabled. The adapter returns those bytes unchanged;
/// it does not promise binary-only receive. A cancelled or timed-out operation
/// drops its socket to avoid continuing on an unknown partial-send state. A
/// failed send may still have reached the peer, so callers must not blindly
/// replay sensitive messages. This type intentionally does not implement the
/// stricter local `Transport` trait's cancellation guarantee.
pub struct LoopbackWebSocket {
    stream: Option<WsFramedStream>,
    max_message_size: usize,
}
impl LoopbackWebSocket {
    /// Connect to an explicit `ws://127.0.0.1:port/path` or `ws://[::1]:port/path`.
    ///
    /// No DNS hostname, `wss`, proxy, userinfo, query, or fragment is accepted.
    /// Loopback does not authenticate a peer; use only a controlled test setup.
    /// Global RustDesk proxy configuration can change concurrently, so the
    /// embedding process must also ensure it remains disabled during connect.
    pub async fn connect(endpoint: &str, max_message_size: usize, deadline: Duration) -> Result<Self, WebSocketError> {
        let url = validate_endpoint(endpoint)?;
        if max_message_size == 0 || max_message_size > MAX_MESSAGE_BYTES { return Err(WebSocketError::InvalidLimit); }
        let ms = timeout_ms(deadline)?;
        if Config::get_socks().is_some() { return Err(WebSocketError::ProxyNotAllowed); }
        let mut stream = timeout(deadline, WsFramedStream::new(url.as_str(), None, ms))
            .await.map_err(|_| WebSocketError::Timeout)?
            .map_err(|error| WebSocketError::Transport(error.to_string()))?;
        // Set both WebSocket frame and reassembled message limits before reading.
        stream.set_max_packet_length(max_message_size);
        // Deadlines below govern the whole operation; zero disables the nested timeout.
        stream.set_send_timeout(0);
        Ok(Self { stream: Some(stream), max_message_size })
    }

    /// Whether an active socket is retained by the adapter.
    pub fn is_open(&self) -> bool { self.stream.is_some() }

    /// Send one binary WebSocket message.
    ///
    /// Once the operation starts, an error, timeout or cancellation drops the
    /// connection. Delivery to the peer is indeterminate on such a failure.
    pub async fn send(&mut self, bytes: &[u8], deadline: Duration) -> Result<(), WebSocketError> {
        timeout_ms(deadline)?;
        if bytes.len() > self.max_message_size {
            return Err(WebSocketError::MessageTooLarge { size: bytes.len(), limit: self.max_message_size });
        }
        // Taking ownership ensures cancelling the future drops the socket rather
        // than exposing a possibly half-written stream for subsequent use.
        let mut stream = self.stream.take().ok_or(WebSocketError::Closed)?;
        timeout(deadline, stream.send_raw(bytes.to_vec())).await
            .map_err(|_| WebSocketError::Timeout)?
            .map_err(|error| WebSocketError::Transport(error.to_string()))?;
        self.stream = Some(stream);
        Ok(())
    }

    /// Receive one message. Unencrypted text frames are also accepted by the
    /// underlying RustDesk implementation. Timeout closes the socket.
    pub async fn receive(&mut self, deadline: Duration) -> Result<Vec<u8>, WebSocketError> {
        timeout_ms(deadline)?;
        let mut stream = self.stream.take().ok_or(WebSocketError::Closed)?;
        let bytes = timeout(deadline, stream.next()).await.map_err(|_| WebSocketError::Timeout)?
            .ok_or(WebSocketError::Closed)?
            .map_err(|error| WebSocketError::Transport(error.to_string()))?;
        if bytes.len() > self.max_message_size {
            return Err(WebSocketError::MessageTooLarge { size: bytes.len(), limit: self.max_message_size });
        }
        self.stream = Some(stream);
        Ok(bytes.to_vec())
    }

    /// Drop the socket. This does not wait for a WebSocket close handshake.
    pub fn close(&mut self) { self.stream.take(); }
}
