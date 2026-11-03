//! Synthetic pixels only. No desktop capture, real consent, or remote security.
use remote_codec::{Codec, EncoderConfig, PackedFormat, RepeatFrameOptIn};
use remote_core::video::{VideoError, VideoReceiver, VideoSender};
use remote_rustdesk_websocket::tcp::{LoopbackTcp, LoopbackTcpListener};
use remote_security::{password_response, OwnerApproval, PasswordVerifier};
use remote_session::{Credential, Permissions, Principal, Session, SessionId};
use std::time::Duration;

#[tokio::test]
async fn authorized_synthetic_video_over_rustdesk_tcp_framing() {
    const LIMIT: usize = 1024 * 1024;
    const WAIT: Duration = Duration::from_secs(5);
    let listener = LoopbackTcpListener::bind("127.0.0.1:0".parse().unwrap(), LIMIT, WAIT).await.unwrap();
    let mut sender_socket = LoopbackTcp::connect(listener.local_addr().unwrap(), LIMIT, WAIT).await.unwrap();
    let mut receiver_socket = listener.accept(WAIT).await.unwrap();

    // Authentication and approval happen inside this process, not across TCP.
    let id = SessionId::new([4; 16]).unwrap();
    let principal = Principal::new("test-viewer".into()).unwrap();
    let permissions = Permissions { view_screen: true, ..Default::default() };
    let mut verifier = PasswordVerifier::new(id, principal.clone(), "test-only", "test-salt", WAIT).unwrap();
    let proof = password_response("test-only", verifier.challenge()).unwrap();
    let mut approval = OwnerApproval::new(id, principal, Some(permissions));
    let mut session = Session::new(id);
    session.begin_connect().unwrap();
    session.transport_connected().unwrap();
    session.authenticate(Credential::new(proof.as_bytes()), permissions, &mut verifier, &mut approval).unwrap();
    session.start_streaming().unwrap();

    let config = EncoderConfig { codec: Codec::Vp9, width: 64, height: 64, quality: 1.0, keyframe_interval: Some(30) };
    let mut sender = VideoSender::new(config, LIMIT).unwrap();
    let mut receiver = VideoReceiver::new(Codec::Vp9, LIMIT).unwrap();
    let repeat = RepeatFrameOptIn::acknowledge_cached_screen_pixels();
    assert!(matches!(sender.send_repeat_network(&session, &mut sender_socket, 2, 0, WAIT, repeat).await, Err(VideoError::NoRepeatableInput)));
    assert!(!sender.needs_reset());
    let pixels = vec![0x80; 64 * 64 * 4];
    let (sent, received) = tokio::join!(
        sender.send_packed_network(&session, &mut sender_socket, 2, &pixels, 64 * 4, PackedFormat::Bgra, 0, WAIT),
        receiver.receive_network(&mut receiver_socket, WAIT)
    );
    sent.unwrap();
    let image = received.unwrap().expect("decoded frame");
    assert_eq!(image.display, 2);
    assert_eq!((image.frame.width, image.frame.height), (64, 64));
    assert!(!image.frame.data.is_empty());
    assert!(sender.has_repeatable_input());
    assert!(sender.send_repeat_network(&session, &mut sender_socket, 2, 100, Duration::ZERO, repeat).await.is_err());
    assert!(sender.has_repeatable_input());
    // VP9 may drop an identical frame. Either a repeat was sent, or a native
    // no-output/error conservatively invalidated the encoder; no retry occurs.
    match sender.send_repeat_network(&session, &mut sender_socket, 2, 100, WAIT, repeat).await {
        Ok(()) => { let _ = receiver.receive_network(&mut receiver_socket, WAIT).await.unwrap(); },
        Err(_) => assert!(sender.needs_reset()),
    }
    session.restrict_permissions(Permissions::default()).unwrap();
    assert!(matches!(sender.send_repeat_network(&session, &mut sender_socket, 2, 200, WAIT, repeat).await, Err(VideoError::Session(_))));
    sender.clear_repeat_input();
    assert!(!sender.has_repeatable_input());
}

/// Deterministic artificial send cancellation, not a real network test.
struct NeverSend { closed: std::sync::Arc<std::sync::atomic::AtomicBool> }
struct CloseOnDrop(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl Drop for CloseOnDrop {
    fn drop(&mut self) { self.0.store(true, std::sync::atomic::Ordering::SeqCst); }
}
impl remote_transport::NetworkTransport for NeverSend {
    fn send<'a>(&'a mut self, _: &'a [u8], _: Duration) -> remote_transport::TransportFuture<'a, Result<(), remote_transport::NetworkTransportError>> {
        Box::pin(async move {
            let _close = CloseOnDrop(self.closed.clone());
            std::future::pending().await
        })
    }
    fn receive(&mut self, _: Duration) -> remote_transport::TransportFuture<'_, Result<Box<[u8]>, remote_transport::NetworkTransportError>> {
        Box::pin(async { Err(remote_transport::NetworkTransportError::Closed) })
    }
    fn close(&mut self) { self.closed.store(true, std::sync::atomic::Ordering::SeqCst); }
}

#[tokio::test]
async fn cancel_inflight_video_send_invalidates_encoder_and_repeat_cache() {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    const WAIT: Duration = Duration::from_secs(5);
    let id = SessionId::new([17; 16]).unwrap();
    let principal = Principal::new("local-test".into()).unwrap();
    let permissions = Permissions { view_screen: true, ..Default::default() };
    let mut verifier = PasswordVerifier::new(id, principal.clone(), "test", "salt", WAIT).unwrap();
    let proof = password_response("test", verifier.challenge()).unwrap();
    let mut approval = OwnerApproval::new(id, principal, Some(permissions));
    let mut session = Session::new(id); session.begin_connect().unwrap(); session.transport_connected().unwrap();
    session.authenticate(Credential::new(proof.as_bytes()), permissions, &mut verifier, &mut approval).unwrap();
    session.start_streaming().unwrap();
    let config = EncoderConfig { codec: Codec::Vp9, width: 64, height: 64, quality: 1.0, keyframe_interval: Some(30) };
    let mut sender = VideoSender::new(config, 1024 * 1024).unwrap();
    let closed = Arc::new(AtomicBool::new(false));
    let mut transport = NeverSend { closed: closed.clone() };
    let pixels = vec![128; 64 * 64 * 4];
    assert!(tokio::time::timeout(Duration::from_millis(100), sender.send_packed_network(
        &session, &mut transport, 0, &pixels, 256, PackedFormat::Bgra, 0, WAIT)).await.is_err());
    assert!(closed.load(Ordering::SeqCst));
    assert!(sender.needs_reset()); assert!(!sender.has_repeatable_input());
}
