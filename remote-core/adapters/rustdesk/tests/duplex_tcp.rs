//! Synthetic local tests written for later execution; not a security audit.
use hbb_common::sodiumoxide::{self, crypto::sign};
use remote_rustdesk_websocket::{direct_tcp::{DirectTcp, DirectTcpListener, DirectTcpOptIn}, source_crypto::{accept_pinned_host, connect_pinned_host}};
use remote_transport::NetworkTransport;
use std::time::Duration;
const WAIT: Duration = Duration::from_secs(5);
const LIMIT: usize = 128 * 1024;

async fn encrypted_pair() -> (remote_rustdesk_websocket::source_crypto::EncryptedTransport<DirectTcp>, remote_rustdesk_websocket::source_crypto::EncryptedTransport<DirectTcp>) {
    sodiumoxide::init().unwrap();
    let opt = DirectTcpOptIn::acknowledge_plaintext_transport();
    let listener = DirectTcpListener::bind("127.0.0.1:0".parse().unwrap(), LIMIT, WAIT, opt).await.unwrap();
    let viewer = DirectTcp::connect(listener.local_addr().unwrap(), LIMIT, WAIT, opt).await.unwrap();
    let (host, _) = listener.accept(WAIT).await.unwrap();
    let (public, secret) = sign::gen_keypair();
    let (host, viewer) = tokio::join!(accept_pinned_host(host, "test-host", &secret, LIMIT - 16, WAIT), connect_pinned_host(viewer, "test-host", &public, LIMIT - 16, WAIT));
    (host.unwrap(), viewer.unwrap())
}
#[tokio::test]
async fn preserved_nonces_and_bidirectional_order() {
    let (mut host, mut viewer) = encrypted_pair().await;
    host.send(b"before-split-h", WAIT).await.unwrap();
    assert_eq!(&*viewer.receive(WAIT).await.unwrap(), b"before-split-h");
    viewer.send(b"before-split-v", WAIT).await.unwrap();
    assert_eq!(&*host.receive(WAIT).await.unwrap(), b"before-split-v");
    let (mut hw, mut hr) = host.into_experimental_duplex().unwrap().split();
    let (mut vw, mut vr) = viewer.into_experimental_duplex().unwrap().split();
    assert!(hr.try_receive().unwrap().is_none());
    let (a, b, c, d) = tokio::join!(async { for n in 0..20 { hw.send(&[n], WAIT).await.unwrap(); } },
        async { for n in 0..20 { assert_eq!(&*vr.receive(WAIT).await.unwrap(), &[n]); } },
        async { for n in 20..40 { vw.send(&[n], WAIT).await.unwrap(); } },
        async { for n in 20..40 { assert_eq!(&*hr.receive(WAIT).await.unwrap(), &[n]); } });
    let _ = (a, b, c, d);
}
#[tokio::test]
async fn timeout_or_cancellation_closes_both_local_halves() {
    let (host, viewer) = encrypted_pair().await;
    let (mut writer, mut reader) = host.into_experimental_duplex().unwrap().split();
    let (_vw, _vr) = viewer.into_experimental_duplex().unwrap().split();
    assert!(reader.receive(Duration::from_millis(10)).await.is_err());
    assert!(writer.send(b"after-timeout", WAIT).await.is_err());
    assert!(reader.try_receive().is_err());
}
#[tokio::test]
async fn invalid_local_size_does_not_close_and_drop_propagates() {
    let (host, viewer) = encrypted_pair().await;
    let (mut writer, mut reader) = host.into_experimental_duplex().unwrap().split();
    let (mut vw, mut vr) = viewer.into_experimental_duplex().unwrap().split();
    assert!(writer.send(&vec![1; LIMIT], WAIT).await.is_err());
    writer.send(b"ok", WAIT).await.unwrap();
    assert_eq!(&*vr.receive(WAIT).await.unwrap(), b"ok");
    drop(writer);
    assert!(reader.receive(WAIT).await.is_err());
    // Peer-visible closure is asynchronous; do not assert an immediate send failure.
    vw.close();
}

#[tokio::test]
async fn cancelling_an_inflight_receive_closes_both_halves() {
    let (host, viewer) = encrypted_pair().await;
    let (mut writer, mut reader) = host.into_experimental_duplex().unwrap().split();
    let (_vw, _vr) = viewer.into_experimental_duplex().unwrap().split();
    {
        let mut receive = Box::pin(reader.receive(WAIT));
        tokio::select! {
            result = &mut receive => panic!("unexpected receive completion: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(10)) => {},
        }
    }
    assert!(writer.send(b"after-cancel", WAIT).await.is_err());
    assert!(reader.try_receive().is_err());
}

#[tokio::test]
async fn handoff_preserves_frames_already_accepted_by_the_framed_reader() {
    let (mut host, mut viewer) = encrypted_pair().await;
    viewer.send(b"first", WAIT).await.unwrap();
    viewer.send(b"second", WAIT).await.unwrap();
    assert_eq!(&*host.receive(WAIT).await.unwrap(), b"first");
    // Whether the second frame was already in Framed's internal read buffer or
    // still in the socket is scheduler-dependent; either way it must survive.
    let (_hw, mut hr) = host.into_experimental_duplex().unwrap().split();
    assert_eq!(&*hr.receive(WAIT).await.unwrap(), b"second");
}
