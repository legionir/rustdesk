//! Experimental, ordered, bounded, in-process transport.
//!
//! Local transport is for trusted in-process endpoints, not for crossing a
//! security boundary. It does not authenticate peers, encrypt data, implement
//! a heartbeat, or provide reconnection. It requires an existing Tokio runtime.

use std::{fmt, future::Future, pin::Pin, time::Duration};
use tokio::{sync::mpsc, time::timeout};

/// Maximum payload bytes held in one direction's queue, excluding allocator and
/// channel overhead and the message a receiver has already taken out.
pub const MAX_QUEUED_BYTES_PER_DIRECTION: usize = 32 * 1024 * 1024;
/// Maximum permitted individual message length.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of messages in either directional queue.
pub const MAX_QUEUE_CAPACITY: usize = 1024;

/// Error returned by a transport operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The message exceeds the configured maximum.
    MessageTooLarge { size: usize, maximum: usize },
    /// The endpoint or its peer was closed.
    Closed,
    /// The operation did not complete within its deadline.
    Timeout,
    /// Invalid queue capacity, message bound, or total memory budget.
    InvalidLimits,
}
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLarge { size, maximum } => write!(f, "message of {size} bytes exceeds limit {maximum}"),
            Self::Closed => f.write_str("transport is closed"),
            Self::Timeout => f.write_str("transport timed out"),
            Self::InvalidLimits => f.write_str("invalid transport limits"),
        }
    }
}
impl std::error::Error for TransportError {}

/// Configuration for each direction of a local pair.
#[derive(Debug, Clone, Copy)]
pub struct LocalConfig {
    /// Number of messages that can wait in one directional queue.
    pub queue_capacity: usize,
    /// Maximum bytes in a message sent in either direction.
    pub max_message_size: usize,
}

impl LocalConfig {
    fn validate(self) -> Result<(), TransportError> {
        if self.queue_capacity == 0 || self.queue_capacity > MAX_QUEUE_CAPACITY
            || self.max_message_size == 0 || self.max_message_size > MAX_MESSAGE_BYTES
            || self.queue_capacity.checked_mul(self.max_message_size)
                .map_or(true, |bytes| bytes > MAX_QUEUED_BYTES_PER_DIRECTION)
        { return Err(TransportError::InvalidLimits); }
        Ok(())
    }
}

/// Future returned by the object-safe transport interface.
pub type TransportFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Ordered binary message transport, independent of protocol and session types.
///
/// Calls on a given endpoint are serialized by its mutable borrow. A send
/// returning success means accepted by the local transport, not processed by
/// the peer. Cancelling a send before it completes must not enqueue a message.
pub trait Transport: Send {
    /// Send a binary message, waiting at most `deadline` for capacity.
    fn send<'a>(&'a mut self, bytes: &'a [u8], deadline: Duration) -> TransportFuture<'a, Result<(), TransportError>>;
    /// Receive the next binary message, waiting at most `deadline`.
    fn receive(&mut self, deadline: Duration) -> TransportFuture<'_, Result<Box<[u8]>, TransportError>>;
    /// Close this endpoint and discard its locally queued incoming messages.
    fn close(&mut self);
}

/// One endpoint of a bounded in-process duplex channel.
pub struct LocalTransport {
    sender: Option<mpsc::Sender<Box<[u8]>>>,
    receiver: mpsc::Receiver<Box<[u8]>>,
    max_message_size: usize,
    closed: bool,
}

/// Create a pair of independent, ordered local endpoints.
///
/// At most `queue_capacity * max_message_size` payload bytes per direction
/// are retained by the channel. User-owned input, received messages, allocator
/// overhead and other pairs are not included in this bound.
pub fn local_pair(config: LocalConfig) -> Result<(LocalTransport, LocalTransport), TransportError> {
    config.validate()?;
    let (a_tx, a_rx) = mpsc::channel(config.queue_capacity);
    let (b_tx, b_rx) = mpsc::channel(config.queue_capacity);
    Ok((
        LocalTransport { sender: Some(a_tx), receiver: b_rx, max_message_size: config.max_message_size, closed: false },
        LocalTransport { sender: Some(b_tx), receiver: a_rx, max_message_size: config.max_message_size, closed: false },
    ))
}

impl Transport for LocalTransport {
    fn send<'a>(&'a mut self, bytes: &'a [u8], deadline: Duration) -> TransportFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            if self.closed { return Err(TransportError::Closed); }
            if bytes.len() > self.max_message_size {
                return Err(TransportError::MessageTooLarge { size: bytes.len(), maximum: self.max_message_size });
            }
            let sender = self.sender.as_ref().ok_or(TransportError::Closed)?;
            // Reserve before allocating so a full queue does not retain another copy.
            let permit = timeout(deadline, sender.reserve()).await.map_err(|_| TransportError::Timeout)?
                .map_err(|_| TransportError::Closed)?;
            permit.send(Box::from(bytes));
            Ok(())
        })
    }

    fn receive(&mut self, deadline: Duration) -> TransportFuture<'_, Result<Box<[u8]>, TransportError>> {
        Box::pin(async move {
            if self.closed { return Err(TransportError::Closed); }
            timeout(deadline, self.receiver.recv()).await.map_err(|_| TransportError::Timeout)?
                .ok_or(TransportError::Closed)
        })
    }

    fn close(&mut self) {
        if self.closed { return; }
        self.closed = true;
        self.sender.take();
        self.receiver.close();
        while self.receiver.try_recv().is_ok() {}
    }
}

impl Drop for LocalTransport {
    fn drop(&mut self) { self.close(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    const WAIT: Duration = Duration::from_secs(1);
    fn config() -> LocalConfig { LocalConfig { queue_capacity: 1, max_message_size: 8 } }

    #[test]
    fn invalid_configs_are_rejected() {
        assert!(matches!(local_pair(LocalConfig { queue_capacity: 0, max_message_size: 1 }), Err(TransportError::InvalidLimits)));
        assert!(matches!(local_pair(LocalConfig { queue_capacity: 1, max_message_size: 0 }), Err(TransportError::InvalidLimits)));
        assert!(matches!(local_pair(LocalConfig { queue_capacity: MAX_QUEUE_CAPACITY + 1, max_message_size: 1 }), Err(TransportError::InvalidLimits)));
        assert!(matches!(local_pair(LocalConfig { queue_capacity: 3, max_message_size: MAX_MESSAGE_BYTES }), Err(TransportError::InvalidLimits)));
        assert!(matches!(local_pair(LocalConfig { queue_capacity: usize::MAX, max_message_size: usize::MAX }), Err(TransportError::InvalidLimits)));
    }

    #[tokio::test]
    async fn binary_bidirectional_order_and_size() {
        let (mut a, mut b) = local_pair(LocalConfig { queue_capacity: 2, max_message_size: 8 }).unwrap();
        a.send(&[0, 255, 1], WAIT).await.unwrap();
        a.send(b"second", WAIT).await.unwrap();
        b.send(b"reply", WAIT).await.unwrap();
        assert_eq!(&*b.receive(WAIT).await.unwrap(), &[0, 255, 1]);
        assert_eq!(&*b.receive(WAIT).await.unwrap(), b"second");
        assert_eq!(&*a.receive(WAIT).await.unwrap(), b"reply");
        assert_eq!(a.send(&[0; 9], WAIT).await, Err(TransportError::MessageTooLarge { size: 9, maximum: 8 }));
        a.send(&[], WAIT).await.unwrap();
        assert_eq!(&*b.receive(WAIT).await.unwrap(), b"");
    }

    #[tokio::test]
    async fn backpressure_timeout_does_not_enqueue() {
        let (mut a, mut b) = local_pair(config()).unwrap();
        a.send(b"first", WAIT).await.unwrap();
        assert_eq!(a.send(b"second", Duration::from_millis(10)).await, Err(TransportError::Timeout));
        assert_eq!(&*b.receive(WAIT).await.unwrap(), b"first");
        assert_eq!(b.receive(Duration::from_millis(10)).await, Err(TransportError::Timeout));
        a.send(b"third", WAIT).await.unwrap();
        assert_eq!(&*b.receive(WAIT).await.unwrap(), b"third");
    }

    #[tokio::test]
    async fn cancelling_send_releases_reservation_and_does_not_enqueue() {
        let (mut a, mut b) = local_pair(config()).unwrap();
        a.send(b"first", WAIT).await.unwrap();
        let pending = a.send(b"lost", WAIT);
        tokio::pin!(pending);
        tokio::select! { result = &mut pending => panic!("send unexpectedly completed: {result:?}"), _ = tokio::time::sleep(Duration::from_millis(10)) => {} }
        drop(pending);
        assert_eq!(&*b.receive(WAIT).await.unwrap(), b"first");
        assert_eq!(b.receive(Duration::from_millis(10)).await, Err(TransportError::Timeout));
    }

    #[tokio::test]
    async fn close_and_drop_notify_peer_and_preserve_already_sent_data() {
        let (mut a, mut b) = local_pair(config()).unwrap();
        a.send(b"queued", WAIT).await.unwrap();
        a.close(); a.close();
        assert_eq!(a.send(b"x", WAIT).await, Err(TransportError::Closed));
        assert_eq!(&*b.receive(WAIT).await.unwrap(), b"queued");
        assert_eq!(b.receive(WAIT).await, Err(TransportError::Closed));
        assert_eq!(b.send(b"x", WAIT).await, Err(TransportError::Closed));
        let (a, mut b) = local_pair(config()).unwrap();
        drop(a);
        assert_eq!(b.receive(WAIT).await, Err(TransportError::Closed));
    }

    #[tokio::test]
    async fn trait_object_can_be_used() {
        let (a, mut b) = local_pair(config()).unwrap();
        let mut transport: Box<dyn Transport> = Box::new(a);
        transport.send(b"hello", WAIT).await.unwrap();
        assert_eq!(&*b.receive(WAIT).await.unwrap(), b"hello");
        transport.close();
    }
}
