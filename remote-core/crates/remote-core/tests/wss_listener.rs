#![cfg(feature = "source-security")]
//! Synthetic TCP admission only; does not exercise TLS, capture or real input.
//! Written for later execution and not yet run.
use remote_core::wss_host::WssHostListener;
use remote_rustdesk_websocket::wss_server::WssServerOptIn;
use remote_security::admission::{AdmissionController, AdmissionLimits};
use std::time::Duration;
use tokio::net::TcpStream;
const WAIT: Duration = Duration::from_secs(5);
#[tokio::test]
async fn socket_admission_is_held_before_any_tls_and_released_on_drop() {
    let admission = AdmissionController::new(AdmissionLimits { max_total: 1, max_per_address: 1, login_grace: WAIT }).unwrap();
    let listener = WssHostListener::bind("127.0.0.1:0".parse().unwrap(), admission.clone(), WAIT,
        WssServerOptIn::acknowledge_tls_and_origin_are_not_authentication()).await.unwrap();
    let _client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let socket = listener.accept(WAIT).await.unwrap();
    assert!(socket.peer_addr().ip().is_loopback()); assert_eq!(admission.active().unwrap(), 1);
    drop(socket); assert_eq!(admission.active().unwrap(), 0);
    assert!(listener.accept(Duration::ZERO).await.is_err());
}
