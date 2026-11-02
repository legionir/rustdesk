//! Explicitly opted-in direct TCP using RustDesk's source `BytesCodec` framing.
//!
//! This transport does **not** encrypt or authenticate connections, enforce
//! owner consent, perform admission/rate limiting, or choose safe bind/target
//! addresses. Use the separate source_crypto adapter and trusted policy only
//! after review. Exposing a plaintext listener is unsafe. This code has not
//! been built, tested, or audited; it is not a production remote desktop server.

use hbb_common::tcp::FramedStream;
use remote_transport::{AdjustableNetworkTransport, NetworkTransport, NetworkTransportError, TransportFuture};
use std::{error::Error, fmt, net::SocketAddr, time::Duration};
use tokio::{net::{TcpListener, TcpStream}, time::timeout};

/// Hard maximum source frame size, excluding allocations/overhead.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Explicit acknowledgment that the TCP transport is plaintext until the
/// caller successfully applies separate security. This is not a security gate.
#[derive(Clone, Copy)]
pub struct DirectTcpOptIn(());
impl DirectTcpOptIn {
    /// Construct only after the application has explicitly informed the local
    /// operator and chosen the network exposure and authentication policy.
    pub fn acknowledge_plaintext_transport() -> Self { Self(()) }
}
#[derive(Debug)]
pub enum DirectTcpError { InvalidLimit, InvalidDeadline, Closed, Timeout, Io }
impl fmt::Display for DirectTcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => f.write_str("invalid TCP frame limit"),
            Self::InvalidDeadline => f.write_str("invalid TCP deadline"),
            Self::Closed => f.write_str("TCP stream is closed"),
            Self::Timeout => f.write_str("TCP operation timed out"),
            Self::Io => f.write_str("TCP operation failed"),
        }
    }
}
impl Error for DirectTcpError {}
fn valid(limit: usize, deadline: Duration) -> Result<(), DirectTcpError> {
    if limit == 0 || limit > MAX_FRAME_BYTES { return Err(DirectTcpError::InvalidLimit); }
    if deadline.is_zero() { return Err(DirectTcpError::InvalidDeadline); }
    Ok(())
}

/// Plaintext direct listener. Accepted IP addresses are transport-observed,
/// not identities; NAT, proxies and distributed attacks complicate admission.
pub struct DirectTcpListener { listener: TcpListener, frame_limit: usize }
impl DirectTcpListener {
    /// Bind exactly the explicitly supplied literal IP address and port. No
    /// automatic interface selection, authentication, TLS or admission occurs.
    pub async fn bind(address: SocketAddr, frame_limit: usize, deadline: Duration, _ack: DirectTcpOptIn) -> Result<Self, DirectTcpError> {
        valid(frame_limit, deadline)?;
        let listener = timeout(deadline, TcpListener::bind(address)).await.map_err(|_| DirectTcpError::Timeout)?
            .map_err(|_| DirectTcpError::Io)?;
        Ok(Self { listener, frame_limit })
    }
    pub fn local_addr(&self) -> Result<SocketAddr, DirectTcpError> { self.listener.local_addr().map_err(|_| DirectTcpError::Io) }
    /// Accept exactly one socket. The application must immediately apply its
    /// bounded pre-auth admission policy before beginning any handshake.
    pub async fn accept(&self, deadline: Duration) -> Result<(DirectTcp, SocketAddr), DirectTcpError> {
        valid(self.frame_limit, deadline)?;
        let (stream, peer) = timeout(deadline, self.listener.accept()).await.map_err(|_| DirectTcpError::Timeout)?
            .map_err(|_| DirectTcpError::Io)?;
        Ok((DirectTcp::wrap(stream, self.frame_limit)?, peer))
    }
}

/// One explicit plaintext TCP connection with cancellation-safe socket closure.
pub struct DirectTcp { stream: Option<FramedStream>, frame_limit: usize }
impl DirectTcp {
    /// Connect to a literal address only; no DNS, proxy or SSRF policy is
    /// applied. The caller must constrain which addresses may be selected.
    pub async fn connect(address: SocketAddr, frame_limit: usize, deadline: Duration, _ack: DirectTcpOptIn) -> Result<Self, DirectTcpError> {
        valid(frame_limit, deadline)?;
        let stream = timeout(deadline, TcpStream::connect(address)).await.map_err(|_| DirectTcpError::Timeout)?
            .map_err(|_| DirectTcpError::Io)?;
        Self::wrap(stream, frame_limit)
    }
    fn wrap(stream: TcpStream, frame_limit: usize) -> Result<Self, DirectTcpError> {
        let local = stream.local_addr().map_err(|_| DirectTcpError::Io)?;
        stream.set_nodelay(true).map_err(|_| DirectTcpError::Io)?;
        let mut stream = FramedStream::from(stream, local);
        stream.codec_mut().set_max_packet_length(frame_limit);
        Ok(Self { stream: Some(stream), frame_limit })
    }
    pub fn is_open(&self) -> bool { self.stream.is_some() }
}
impl NetworkTransport for DirectTcp {
    fn send<'a>(&'a mut self, data: &'a [u8], deadline: Duration) -> TransportFuture<'a, Result<(), NetworkTransportError>> {
        Box::pin(async move {
            if deadline.is_zero() || data.len() > self.frame_limit { return Err(NetworkTransportError::InvalidRequest("invalid deadline or frame size".into())); }
            let mut stream = self.stream.take().ok_or(NetworkTransportError::Closed)?;
            match timeout(deadline, stream.send_raw(data.to_vec())).await {
                Ok(Ok(())) => { self.stream = Some(stream); Ok(()) },
                _ => Err(NetworkTransportError::SendOutcomeUnknown("direct TCP send failed".into())),
            }
        })
    }
    fn receive(&mut self, deadline: Duration) -> TransportFuture<'_, Result<Box<[u8]>, NetworkTransportError>> {
        Box::pin(async move {
            if deadline.is_zero() { return Err(NetworkTransportError::InvalidRequest("invalid deadline".into())); }
            let mut stream = self.stream.take().ok_or(NetworkTransportError::Closed)?;
            let bytes = match timeout(deadline, stream.next()).await {
                Ok(Some(Ok(bytes))) if bytes.len() <= self.frame_limit => bytes,
                _ => return Err(NetworkTransportError::ReceiveFailed("direct TCP receive failed".into())),
            };
            self.stream = Some(stream);
            Ok(bytes.to_vec().into_boxed_slice())
        })
    }
    fn close(&mut self) { self.stream.take(); }
}
impl AdjustableNetworkTransport for DirectTcp {
    fn set_max_message_size(&mut self, maximum: usize) -> Result<(), NetworkTransportError> {
        if maximum == 0 || maximum > MAX_FRAME_BYTES { return Err(NetworkTransportError::InvalidRequest("invalid TCP frame limit".into())); }
        let stream = self.stream.as_mut().ok_or(NetworkTransportError::Closed)?;
        stream.codec_mut().set_max_packet_length(maximum);
        self.frame_limit = maximum;
        Ok(())
    }
}
impl Drop for DirectTcp { fn drop(&mut self) { self.close(); } }
