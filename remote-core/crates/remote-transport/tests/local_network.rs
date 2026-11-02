//! Deferred synthetic cases for the network contract over local queues.
use remote_transport::{local_network_pair, LocalConfig, NetworkTransport, NetworkTransportError};
use std::time::Duration;
const WAIT: Duration = Duration::from_secs(1);
#[tokio::test]
async fn exchanges_and_rejects_oversize_without_closing() {
    let (mut a, mut b) = local_network_pair(LocalConfig { queue_capacity: 2, max_message_size: 8 }).unwrap();
    assert!(matches!(a.send(&[0; 9], WAIT).await, Err(NetworkTransportError::InvalidRequest(_))));
    a.send(b"hello", WAIT).await.unwrap();
    assert_eq!(&*b.receive(WAIT).await.unwrap(), b"hello");
}
#[tokio::test]
async fn cancelled_receive_closes_endpoint() {
    let (mut a, mut b) = local_network_pair(LocalConfig { queue_capacity: 1, max_message_size: 8 }).unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(1), a.receive(WAIT)).await;
    assert!(a.receive(WAIT).await.is_err());
    assert!(b.send(b"x", WAIT).await.is_err());
}
