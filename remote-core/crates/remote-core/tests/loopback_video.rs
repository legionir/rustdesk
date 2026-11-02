//! Synthetic pixels only. No desktop capture, real consent, or remote security.
use remote_codec::{Codec, EncoderConfig, PackedFormat};
use remote_core::video::{VideoReceiver, VideoSender};
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
}
