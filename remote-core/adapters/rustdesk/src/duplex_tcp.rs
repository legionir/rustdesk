//! Experimental bounded full-duplex driver for an *already established*
//! strict source-v1 encrypted direct TCP stream. Not a host, consent boundary,
//! production transport or security claim. This is opt-in and untested.
//!
//! The handshake's existing framed socket (including buffered bytes) is split;
//! exactly one task owns each ordered direction and each direction uses only its
//! counter in a cloned source Encrypt state. Sender clones are not exposed. One
//! inbound and one outbound message may queue; framing and plaintext limits are
//! fixed at handoff. Cancellation, timeout, failed I/O, invalid ciphertext,
//! counter exhaustion or dropping either half requests closure of both tasks.
//! Async task scheduling means socket release is not instantaneous. The caller
//! must run inside a live Tokio runtime and keep it running through cleanup.
//! Backpressure, cancellation races, nonce handling, interop, teardown, native
//! allocation bounds and adversarial behavior require independent testing and
//! security review. No transport authentication or local authorization is added.
use crate::direct_tcp::DirectTcp;
use futures_util::{SinkExt, StreamExt};
use hbb_common::{bytes::{Bytes, BytesMut}, sodiumoxide::crypto::secretbox, tcp::Encrypt};
use remote_transport::NetworkTransportError;
use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};
use tokio::{sync::{mpsc, oneshot, watch}, time::timeout};
use zeroize::{Zeroize, Zeroizing};

struct Shared { closed: AtomicBool, signal: watch::Sender<bool> }
impl Shared {
    fn close(&self) { if !self.closed.swap(true, Ordering::AcqRel) { self.signal.send_replace(true); } }
    fn is_closed(&self) -> bool { self.closed.load(Ordering::Acquire) }
}
async fn stopped(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow() { return; }
        if rx.changed().await.is_err() { return; }
    }
}
struct OnCancel { shared: Arc<Shared>, armed: bool }
impl OnCancel { fn new(shared: &Arc<Shared>) -> Self { Self { shared: shared.clone(), armed: true } } }
impl Drop for OnCancel { fn drop(&mut self) { if self.armed { self.shared.close(); } } }
// These wrappers scrub queue-owned plaintext on drop, including cancellation.
// Source cipher internals, caller buffers, allocator copies and crashes are not
// covered. Once returned, the received bytes are owned by the caller.
struct Outbound { plain: Zeroizing<Vec<u8>>, done: oneshot::Sender<()> }

/// Holds a single writer and reader. Dropping either closes the whole duplex
/// connection; they must not outlive the runtime or the owning session.
pub struct DuplexTcp { writer: DuplexWriter, reader: DuplexReader }
impl DuplexTcp {
    pub(crate) fn start(socket: DirectTcp, cipher: Encrypt, max_plaintext: usize) -> Result<Self, NetworkTransportError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| NetworkTransportError::InvalidRequest("duplex driver requires an active Tokio runtime".into()))?;
        let (framed, frame_limit) = socket.into_framed()?;
        if max_plaintext == 0 || max_plaintext.checked_add(secretbox::MACBYTES).map_or(true, |n| n > frame_limit) {
            return Err(NetworkTransportError::InvalidRequest("incompatible duplex framing limit".into()));
        }
        // Framed owns any read/write buffers accumulated during the handshake.
        let (mut sink, mut source) = framed.0.split();
        let (signal, stop_read) = watch::channel(false);
        let stop_write = signal.subscribe();
        let shared = Arc::new(Shared { closed: AtomicBool::new(false), signal });
        let (out_tx, mut out_rx) = mpsc::channel::<Outbound>(1);
        let (in_tx, in_rx) = mpsc::channel::<Zeroizing<Vec<u8>>>(1);
        let mut write_cipher = cipher.clone();
        let mut read_cipher = cipher;
        let write_shared = shared.clone();
        handle.spawn(async move {
            let mut stop = stop_write;
            loop {
                let req = tokio::select! { biased; _ = stopped(&mut stop) => break, req = out_rx.recv() => match req { Some(req) => req, None => break } };
                if write_shared.is_closed() || write_cipher.1 == u64::MAX { break; }
                let bytes = Bytes::from(write_cipher.enc(&req.plain));
                let sent = tokio::select! { biased; _ = stopped(&mut stop) => false, result = sink.send(bytes) => result.is_ok() };
                if !sent { break; }
                // If the waiter disappeared, outcome is unknown; close instead
                // of continuing after a potentially cancelled operation.
                if req.done.send(()).is_err() { break; }
            }
            write_shared.close();
        });
        let read_shared = shared.clone();
        handle.spawn(async move {
            let mut stop = stop_read;
            loop {
                // Reserve before reading: a slow consumer cannot accumulate
                // unbounded plaintext. The framed backend can still buffer data.
                let permit = tokio::select! { biased; _ = stopped(&mut stop) => break, p = in_tx.reserve() => match p { Ok(p) => p, Err(_) => break } };
                let frame = tokio::select! { biased; _ = stopped(&mut stop) => break, frame = source.next() => frame };
                let mut bytes: BytesMut = match frame { Some(Ok(bytes)) => bytes, _ => break };
                if read_shared.is_closed() || read_cipher.2 == u64::MAX || bytes.len() < secretbox::MACBYTES
                    || bytes.len() > max_plaintext + secretbox::MACBYTES || read_cipher.dec(&mut bytes).is_err() { break; }
                let plain = Zeroizing::new(bytes.to_vec());
                bytes[..].zeroize();
                permit.send(plain);
            }
            read_shared.close();
        });
        Ok(Self { writer: DuplexWriter { tx: out_tx, shared: shared.clone(), maximum: max_plaintext },
            reader: DuplexReader { rx: in_rx, shared } })
    }
    /// Consume the owner into exactly one writer and one reader.
    pub fn split(self) -> (DuplexWriter, DuplexReader) { (self.writer, self.reader) }
}
/// Ordered sender, not clonable. Success means the local framed writer completed,
/// not that the peer processed the message. Never retry an uncertain send.
pub struct DuplexWriter { tx: mpsc::Sender<Outbound>, shared: Arc<Shared>, maximum: usize }
impl DuplexWriter {
    pub async fn send(&mut self, bytes: &[u8], deadline: Duration) -> Result<(), NetworkTransportError> {
        if deadline.is_zero() || bytes.len() > self.maximum { return Err(NetworkTransportError::InvalidRequest("invalid deadline or message size".into())); }
        if self.shared.is_closed() { return Err(NetworkTransportError::Closed); }
        let mut guard = OnCancel::new(&self.shared);
        let (done, wait) = oneshot::channel();
        let operation = async {
            self.tx.send(Outbound { plain: Zeroizing::new(bytes.to_vec()), done }).await.map_err(|_| ())?;
            wait.await.map_err(|_| ())
        };
        match timeout(deadline, operation).await {
            Ok(Ok(())) if !self.shared.is_closed() => { guard.armed = false; Ok(()) },
            _ => Err(NetworkTransportError::SendOutcomeUnknown("duplex send failed or timed out".into())),
        }
    }
    pub fn close(&mut self) { self.shared.close(); }
}
impl Drop for DuplexWriter { fn drop(&mut self) { self.close(); } }
/// Ordered receiver, not clonable. One read-ahead plaintext frame may be queued.
pub struct DuplexReader { rx: mpsc::Receiver<Zeroizing<Vec<u8>>>, shared: Arc<Shared> }
impl DuplexReader {
    // Drop and scrub currently queued plaintext as soon as a caller notices
    // closure. A background sender with an already reserved permit may still
    // race this drain; receiver drop remains the final cleanup point.
    fn discard_pending(&mut self) {
        self.rx.close();
        while self.rx.try_recv().is_ok() {}
    }
    /// Poll without waiting. Unlike an interrupted network receive, observing an
    /// empty local queue does not close or cancel the background socket read.
    pub fn try_receive(&mut self) -> Result<Option<Box<[u8]>>, NetworkTransportError> {
        if self.shared.is_closed() { self.discard_pending(); return Err(NetworkTransportError::Closed); }
        match self.rx.try_recv() {
            Ok(mut bytes) => Ok(Some(std::mem::take(&mut *bytes).into_boxed_slice())),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => { self.shared.close(); Err(NetworkTransportError::Closed) },
        }
    }
    /// Wait for one message. Timeout/cancellation closes both directions;
    /// use `try_receive` for a non-destructive idle poll.
    pub async fn receive(&mut self, deadline: Duration) -> Result<Box<[u8]>, NetworkTransportError> {
        if deadline.is_zero() { return Err(NetworkTransportError::InvalidRequest("invalid deadline".into())); }
        if self.shared.is_closed() { self.discard_pending(); return Err(NetworkTransportError::Closed); }
        let mut guard = OnCancel::new(&self.shared);
        match timeout(deadline, self.rx.recv()).await {
            Ok(Some(mut bytes)) if !self.shared.is_closed() => {
                guard.armed = false; Ok(std::mem::take(&mut *bytes).into_boxed_slice())
            },
            _ => Err(NetworkTransportError::ReceiveFailed("duplex receive failed or timed out".into())),
        }
    }
    pub fn close(&mut self) { self.shared.close(); self.discard_pending(); }
}
impl Drop for DuplexReader { fn drop(&mut self) { self.close(); } }

impl remote_transport::NetworkTransport for DuplexTcp {
    fn send<'a>(&'a mut self, bytes: &'a [u8], deadline: Duration) -> remote_transport::TransportFuture<'a, Result<(), NetworkTransportError>> {
        Box::pin(async move { self.writer.send(bytes, deadline).await })
    }
    fn receive(&mut self, deadline: Duration) -> remote_transport::TransportFuture<'_, Result<Box<[u8]>, NetworkTransportError>> {
        Box::pin(async move { self.reader.receive(deadline).await })
    }
    fn close(&mut self) { self.writer.close(); self.reader.close(); }
}

/// Explicitly selected wrapper: initially serial, later convertible exactly
/// once to the experimental bounded duplex driver. Raising the actual framing
/// limit is possible only while serial; authorized owners must choose the final
/// bound before upgrading. This type does not authorize the transition itself.
pub struct UpgradeableEncryptedTcp { state: Option<UpgradeState> }
enum UpgradeState { Serial(crate::source_crypto::EncryptedTransport<DirectTcp>), Duplex(DuplexTcp) }
impl UpgradeableEncryptedTcp {
    pub fn new(transport: crate::source_crypto::EncryptedTransport<DirectTcp>) -> Self { Self { state: Some(UpgradeState::Serial(transport)) } }
}
impl remote_transport::NetworkTransport for UpgradeableEncryptedTcp {
    fn send<'a>(&'a mut self, bytes: &'a [u8], deadline: Duration) -> remote_transport::TransportFuture<'a, Result<(), NetworkTransportError>> {
        Box::pin(async move { match self.state.as_mut().ok_or(NetworkTransportError::Closed)? {
            UpgradeState::Serial(t) => remote_transport::NetworkTransport::send(t, bytes, deadline).await,
            UpgradeState::Duplex(t) => remote_transport::NetworkTransport::send(t, bytes, deadline).await,
        } })
    }
    fn receive(&mut self, deadline: Duration) -> remote_transport::TransportFuture<'_, Result<Box<[u8]>, NetworkTransportError>> {
        Box::pin(async move { match self.state.as_mut().ok_or(NetworkTransportError::Closed)? {
            UpgradeState::Serial(t) => remote_transport::NetworkTransport::receive(t, deadline).await,
            UpgradeState::Duplex(t) => remote_transport::NetworkTransport::receive(t, deadline).await,
        } })
    }
    fn close(&mut self) {
        if let Some(state) = self.state.take() { match state {
            UpgradeState::Serial(mut t) => remote_transport::NetworkTransport::close(&mut t),
            UpgradeState::Duplex(mut t) => remote_transport::NetworkTransport::close(&mut t),
        } }
    }
}
impl Drop for UpgradeableEncryptedTcp { fn drop(&mut self) { remote_transport::NetworkTransport::close(self); } }
impl remote_transport::AdjustableNetworkTransport for UpgradeableEncryptedTcp {
    fn set_max_message_size(&mut self, maximum: usize) -> Result<(), NetworkTransportError> {
        match self.state.as_mut().ok_or(NetworkTransportError::Closed)? {
            UpgradeState::Serial(t) => remote_transport::AdjustableNetworkTransport::set_max_message_size(t, maximum),
            UpgradeState::Duplex(_) => Err(NetworkTransportError::InvalidRequest("frame limit is fixed after duplex upgrade".into())),
        }
    }
}
impl remote_transport::UpgradeableDuplexTransport for UpgradeableEncryptedTcp {
    fn upgrade_duplex(&mut self) -> Result<(), NetworkTransportError> {
        match self.state.take().ok_or(NetworkTransportError::Closed)? {
            UpgradeState::Serial(t) => { self.state = Some(UpgradeState::Duplex(t.into_experimental_duplex()?)); Ok(()) },
            UpgradeState::Duplex(t) => { self.state = Some(UpgradeState::Duplex(t)); Err(NetworkTransportError::InvalidRequest("already upgraded".into())) },
        }
    }
    fn try_receive(&mut self) -> Result<Option<Box<[u8]>>, NetworkTransportError> {
        match self.state.as_mut().ok_or(NetworkTransportError::Closed)? {
            UpgradeState::Duplex(t) => t.reader.try_receive(),
            UpgradeState::Serial(_) => Err(NetworkTransportError::InvalidRequest("duplex not enabled".into())),
        }
    }
}
