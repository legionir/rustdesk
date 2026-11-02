//! Deferred local synthetic cases; no public listener is opened here.
use remote_rustdesk_websocket::direct_tcp::{DirectTcp, DirectTcpListener, DirectTcpOptIn};
use remote_transport::{AdjustableNetworkTransport, NetworkTransport};
use std::time::Duration;
const WAIT: Duration = Duration::from_secs(3);
#[tokio::test]
async fn explicit_direct_tcp_framing_and_limit_transition() {
    let opt = DirectTcpOptIn::acknowledge_plaintext_transport();
    let listener = DirectTcpListener::bind("127.0.0.1:0".parse().unwrap(), 32, WAIT, opt).await.unwrap();
    let mut client = DirectTcp::connect(listener.local_addr().unwrap(), 32, WAIT, opt).await.unwrap();
    let (mut server, address) = listener.accept(WAIT).await.unwrap();
    assert!(address.ip().is_loopback());
    client.send(b"hello", WAIT).await.unwrap();
    assert_eq!(&*server.receive(WAIT).await.unwrap(), b"hello");
    assert!(client.send(&[3; 33], WAIT).await.is_err());
    client.set_max_message_size(64).unwrap(); server.set_max_message_size(64).unwrap();
    client.send(&[3; 33], WAIT).await.unwrap();
    assert_eq!(server.receive(WAIT).await.unwrap().len(), 33);
    server.close(); client.close();
}
