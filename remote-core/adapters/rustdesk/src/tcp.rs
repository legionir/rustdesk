//! Experimental loopback-only TCP using the pinned RustDesk framing codec.
//!
//! Connections are plaintext and unauthenticated. Loopback is not a security
//! boundary against local users or processes; do not use this for remote input
//! or sensitive content. No proxy, TLS, secretbox key exchange, peer identity,
//! owner consent or rate limiting is provided here.

use hbb_common::tcp::FramedStream;
use std::{error::Error, fmt, net::SocketAddr, time::Duration};
use tokio::{net::{TcpListener, TcpStream}, time::timeout};

/// Maximum RustDesk framed payload accepted by this adapter.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Errors from the loopback TCP adapter.
#[derive(Debug)]
pub enum TcpError {
    /// Only literal loopback IP addresses are accepted.
    InvalidEndpoint,
    /// The message cap must be nonzero and within the adapter limit.
    InvalidLimit,
    /// The deadline must be nonzero.
    InvalidTimeout,
    /// Payload exceeds the configured per-message limit.
    MessageTooLarge { size: usize, limit: usize },
    /// An operation timed out. For send, delivery may have occurred.
    Timeout,
    /// The stream is closed or was abandoned during an operation.
    Closed,
    /// A native socket or framed protocol operation failed.
    Transport(String),
}
impl fmt::Display for TcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint => f.write_str("only literal loopback TCP endpoints are allowed"),
            Self::InvalidLimit => f.write_str("invalid TCP message limit"),
            Self::InvalidTimeout => f.write_str("TCP deadline must be nonzero"),
            Self::MessageTooLarge { size, limit } => write!(f, "message size {size} exceeds limit {limit}"),
            Self::Timeout => f.write_str("TCP deadline exceeded; connection dropped"),
            Self::Closed => f.write_str("TCP stream is closed"),
            Self::Transport(e) => write!(f, "TCP transport: {e}"),
        }
    }
}
impl Error for TcpError {}

fn validate(addr: SocketAddr, max_message_size: usize, deadline: Duration) -> Result<(), TcpError> {
    if !addr.ip().is_loopback() { return Err(TcpError::InvalidEndpoint); }
    if max_message_size == 0 || max_message_size > MAX_MESSAGE_BYTES { return Err(TcpError::InvalidLimit); }
    if deadline.is_zero() { return Err(TcpError::InvalidTimeout); }
    Ok(())
}

/// A listener bound exclusively to an explicitly supplied loopback address.
pub struct LoopbackTcpListener {
    listener: TcpListener,
    max_message_size: usize,
}
impl LoopbackTcpListener {
    /// Bind to a literal loopback IP and port; port zero requests an ephemeral port.
    /// This does not authenticate peers or protect from other local processes.
    pub async fn bind(addr: SocketAddr, max_message_size: usize, deadline: Duration) -> Result<Self, TcpError> {
        validate(addr, max_message_size, deadline)?;
        let listener = timeout(deadline, TcpListener::bind(addr)).await.map_err(|_| TcpError::Timeout)?
            .map_err(|e| TcpError::Transport(e.to_string()))?;
        Ok(Self { listener, max_message_size })
    }
    /// Actual local address, useful when the listener was bound to port zero.
    pub fn local_addr(&self) -> Result<SocketAddr, TcpError> {
        self.listener.local_addr().map_err(|e| TcpError::Transport(e.to_string()))
    }
    /// Accept one loopback peer with a bounded wait.
    pub async fn accept(&self, deadline: Duration) -> Result<LoopbackTcp, TcpError> {
        if deadline.is_zero() { return Err(TcpError::InvalidTimeout); }
        let (stream, peer) = timeout(deadline, self.listener.accept()).await.map_err(|_| TcpError::Timeout)?
            .map_err(|e| TcpError::Transport(e.to_string()))?;
        if !peer.ip().is_loopback() { return Err(TcpError::InvalidEndpoint); }
        LoopbackTcp::wrap(stream, self.max_message_size)
    }
}

/// An unencrypted RustDesk-framed loopback TCP socket.
///
/// Cancellation, timeout or I/O failure during send or receive drops the
/// socket; the outcome of a failed send is indeterminate. This type therefore
/// intentionally does not implement the in-process `Transport` trait, whose
/// cancellation contract says a cancelled send is never enqueued.
pub struct LoopbackTcp {
    stream: Option<FramedStream>,
    max_message_size: usize,
}
impl LoopbackTcp {
    fn wrap(stream: TcpStream, max_message_size: usize) -> Result<Self, TcpError> {
        let local = stream.local_addr().map_err(|e| TcpError::Transport(e.to_string()))?;
        let peer = stream.peer_addr().map_err(|e| TcpError::Transport(e.to_string()))?;
        if !local.ip().is_loopback() || !peer.ip().is_loopback() { return Err(TcpError::InvalidEndpoint); }
        stream.set_nodelay(true).map_err(|e| TcpError::Transport(e.to_string()))?;
        let mut stream = FramedStream::from(stream, local);
        stream.codec_mut().set_max_packet_length(max_message_size);
        stream.set_send_timeout(0);
        Ok(Self { stream: Some(stream), max_message_size })
    }
    /// Connect to a literal loopback address. No DNS or proxy is used.
    pub async fn connect(addr: SocketAddr, max_message_size: usize, deadline: Duration) -> Result<Self, TcpError> {
        validate(addr, max_message_size, deadline)?;
        if addr.port() == 0 { return Err(TcpError::InvalidEndpoint); }
        let stream = timeout(deadline, TcpStream::connect(addr)).await.map_err(|_| TcpError::Timeout)?
            .map_err(|e| TcpError::Transport(e.to_string()))?;
        Self::wrap(stream, max_message_size)
    }
    /// Whether the adapter still retains a socket.
    pub fn is_open(&self) -> bool { self.stream.is_some() }
    /// Send a framed binary message. Any in-flight failure may have delivered it.
    pub async fn send(&mut self, bytes: &[u8], deadline: Duration) -> Result<(), TcpError> {
        if deadline.is_zero() { return Err(TcpError::InvalidTimeout); }
        if bytes.len() > self.max_message_size {
            return Err(TcpError::MessageTooLarge { size: bytes.len(), limit: self.max_message_size });
        }
        // Ownership moves into the future. Dropping it closes a potentially
        // partially written stream instead of making it available for reuse.
        let mut stream = self.stream.take().ok_or(TcpError::Closed)?;
        timeout(deadline, stream.send_raw(bytes.to_vec())).await.map_err(|_| TcpError::Timeout)?
            .map_err(|e| TcpError::Transport(e.to_string()))?;
        self.stream = Some(stream);
        Ok(())
    }
    /// Receive one framed message; a timeout or partial read closes the socket.
    pub async fn receive(&mut self, deadline: Duration) -> Result<Vec<u8>, TcpError> {
        if deadline.is_zero() { return Err(TcpError::InvalidTimeout); }
        let mut stream = self.stream.take().ok_or(TcpError::Closed)?;
        let bytes = timeout(deadline, stream.next()).await.map_err(|_| TcpError::Timeout)?
            .ok_or(TcpError::Closed)?.map_err(|e| TcpError::Transport(e.to_string()))?;
        if bytes.len() > self.max_message_size {
            return Err(TcpError::MessageTooLarge { size: bytes.len(), limit: self.max_message_size });
        }
        self.stream = Some(stream);
        Ok(bytes.to_vec())
    }
    /// Drop the socket without waiting for peer acknowledgement.
    pub fn close(&mut self) { self.stream.take(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    const WAIT: Duration = Duration::from_secs(3);
    #[tokio::test]
    async fn uses_rustdesk_frames_and_respects_limits() {
        let listener = LoopbackTcpListener::bind("127.0.0.1:0".parse().unwrap(), 8, WAIT).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = LoopbackTcp::connect(addr, 8, WAIT).await.unwrap();
        let mut server = listener.accept(WAIT).await.unwrap();
        client.send(&[0, 255, 2], WAIT).await.unwrap();
        assert_eq!(server.receive(WAIT).await.unwrap(), [0, 255, 2]);
        server.send(b"ok", WAIT).await.unwrap();
        assert_eq!(client.receive(WAIT).await.unwrap(), b"ok");
        assert!(matches!(client.send(&[0; 9], WAIT).await, Err(TcpError::MessageTooLarge { .. })));
        assert!(client.is_open());
        client.close();
        assert!(!client.is_open());
    }
    #[tokio::test]
    async fn refuses_non_loopback_and_invalid_limits() {
        assert!(matches!(LoopbackTcpListener::bind("0.0.0.0:0".parse().unwrap(), 8, WAIT).await, Err(TcpError::InvalidEndpoint)));
        assert!(matches!(LoopbackTcp::connect("192.0.2.1:42".parse().unwrap(), 8, WAIT).await, Err(TcpError::InvalidEndpoint)));
        assert!(matches!(LoopbackTcpListener::bind("127.0.0.1:0".parse().unwrap(), 0, WAIT).await, Err(TcpError::InvalidLimit)));
    }
    #[tokio::test]
    async fn receive_timeout_drops_socket() {
        let listener = LoopbackTcpListener::bind("127.0.0.1:0".parse().unwrap(), 8, WAIT).await.unwrap();
        let mut client = LoopbackTcp::connect(listener.local_addr().unwrap(), 8, WAIT).await.unwrap();
        let _server = listener.accept(WAIT).await.unwrap();
        assert!(matches!(client.receive(Duration::from_millis(10)).await, Err(TcpError::Timeout)));
        assert!(!client.is_open());
    }
}
