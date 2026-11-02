//! Deferred synthetic cases: no tests run, no production-security claim.
use hbb_common::sodiumoxide::{self, crypto::sign};
use remote_rustdesk_websocket::{source_crypto::{accept_pinned_host, connect_pinned_host}, tcp::{LoopbackTcp, LoopbackTcpListener}};
use remote_transport::{NetworkTransport, NetworkTransportError, TransportFuture};
use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};
const WAIT: Duration = Duration::from_secs(5);
const LIMIT: usize = 128 * 1024;
async fn sockets() -> (LoopbackTcp, LoopbackTcp) {
    let listener = LoopbackTcpListener::bind("127.0.0.1:0".parse().unwrap(), LIMIT, WAIT).await.unwrap();
    let viewer = LoopbackTcp::connect(listener.local_addr().unwrap(), LIMIT, WAIT).await.unwrap();
    (listener.accept(WAIT).await.unwrap(), viewer)
}
struct Tamper<T> { inner: T, enabled: Arc<AtomicBool> }
impl<T: NetworkTransport> NetworkTransport for Tamper<T> {
    fn send<'a>(&'a mut self, bytes: &'a [u8], deadline: Duration) -> TransportFuture<'a, Result<(), NetworkTransportError>> {
        Box::pin(async move {
            let mut output = bytes.to_vec();
            if self.enabled.load(Ordering::SeqCst) && !output.is_empty() { output[0] ^= 1; }
            self.inner.send(&output, deadline).await
        })
    }
    fn receive(&mut self, deadline: Duration) -> TransportFuture<'_, Result<Box<[u8]>, NetworkTransportError>> { self.inner.receive(deadline) }
    fn close(&mut self) { self.inner.close(); }
}
#[tokio::test]
async fn pinned_split_keys_exchange_both_directions_and_reject_tampering() {
    sodiumoxide::init().unwrap();
    let (host_socket, viewer_socket) = sockets().await;
    let (public, secret) = sign::gen_keypair();
    let toggle = Arc::new(AtomicBool::new(false));
    let viewer_socket = Tamper { inner: viewer_socket, enabled: toggle.clone() };
    let (host, viewer) = tokio::join!(accept_pinned_host(host_socket, "host-1", &secret, LIMIT - 16, WAIT),
        connect_pinned_host(viewer_socket, "host-1", &public, LIMIT - 16, WAIT));
    let mut host = host.unwrap(); let mut viewer = viewer.unwrap();
    viewer.send(b"viewer-message", WAIT).await.unwrap();
    assert_eq!(&*host.receive(WAIT).await.unwrap(), b"viewer-message");
    host.send(b"host-message", WAIT).await.unwrap();
    assert_eq!(&*viewer.receive(WAIT).await.unwrap(), b"host-message");
    toggle.store(true, Ordering::SeqCst);
    viewer.send(b"tampered", WAIT).await.unwrap();
    assert!(host.receive(WAIT).await.is_err());
    assert!(host.receive(WAIT).await.is_err());
}
#[tokio::test]
async fn wrong_pin_and_wrong_host_id_fail_closed() {
    sodiumoxide::init().unwrap();
    for wrong_id in [false, true] {
        let (host_socket, viewer_socket) = sockets().await;
        let (public, secret) = sign::gen_keypair();
        let (other, _) = sign::gen_keypair();
        let (host, viewer) = tokio::join!(accept_pinned_host(host_socket, "host-1", &secret, LIMIT - 16, WAIT),
            connect_pinned_host(viewer_socket, if wrong_id { "other-host" } else { "host-1" }, if wrong_id { &public } else { &other }, LIMIT - 16, WAIT));
        assert!(viewer.is_err());
        assert!(host.is_err());
    }
}
