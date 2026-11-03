//! Synthetic pixels and a recording fake transport. No real desktop/network.
use remote_codec::{Codec, EncoderConfig, PackedFormat, RepeatFrameOptIn};
use remote_core::video::{SendOutcome, VideoError, VideoSender};
use remote_security::{password_response, OwnerApproval, PasswordVerifier};
use remote_session::{Credential, Permissions, Principal, Session, SessionId};
use remote_transport::{NetworkTransport, NetworkTransportError, TransportFuture};
use std::{sync::{Arc, Mutex}, time::Duration};

struct Recording(Arc<Mutex<Vec<Vec<u8>>>>);
impl NetworkTransport for Recording {
    fn send<'a>(&'a mut self, bytes: &'a [u8], _: Duration) -> TransportFuture<'a, Result<(), NetworkTransportError>> {
        Box::pin(async move { self.0.lock().map_err(|_| NetworkTransportError::Closed)?.push(bytes.to_vec()); Ok(()) })
    }
    fn receive(&mut self, _: Duration) -> TransportFuture<'_, Result<Box<[u8]>, NetworkTransportError>> {
        Box::pin(async { Err(NetworkTransportError::Closed) })
    }
    fn close(&mut self) {}
}
fn session() -> Session {
    let id = SessionId::new([42; 16]).unwrap(); let p = Principal::new("fixture".into()).unwrap();
    let permissions = Permissions { view_screen: true, ..Default::default() };
    let mut verifier = PasswordVerifier::new(id, p.clone(), "test-only", "salt", Duration::from_secs(5)).unwrap();
    let proof = password_response("test-only", verifier.challenge()).unwrap();
    let mut approval = OwnerApproval::new(id, p, Some(permissions));
    let mut session = Session::new(id); session.begin_connect().unwrap(); session.transport_connected().unwrap();
    session.authenticate(Credential::new(proof.as_bytes()), permissions, &mut verifier, &mut approval).unwrap();
    session.start_streaming().unwrap(); session
}
#[tokio::test]
async fn source_outcomes_preserve_encoder_and_only_send_when_output_exists() {
    let mut session = session();
    let config = EncoderConfig { codec: Codec::Vp9, width: 64, height: 64, quality: 1.0, keyframe_interval: Some(30) };
    let mut sender = VideoSender::new(config, 1024 * 1024).unwrap();
    let messages = Arc::new(Mutex::new(Vec::new())); let mut network = Recording(messages.clone());
    let pixels = vec![128; 64 * 64 * 4]; let wait = Duration::from_secs(1);
    let first = sender.send_packed_network_outcome(&session, &mut network, 0, &pixels, 256, PackedFormat::Bgra, 0, wait).await.unwrap();
    assert_eq!(messages.lock().unwrap().len(), if first == SendOutcome::Sent { 1 } else { 0 });
    assert!(!sender.needs_reset()); assert!(sender.has_repeatable_input());
    let before = messages.lock().unwrap().len();
    match sender.send_repeat_network_outcome(&session, &mut network, 0, 100, wait, RepeatFrameOptIn::acknowledge_cached_screen_pixels()).await {
        Ok(outcome) => {
            assert_eq!(messages.lock().unwrap().len(), before + if outcome == SendOutcome::Sent { 1 } else { 0 });
            assert!(!sender.needs_reset()); assert!(sender.has_repeatable_input());
        },
        Err(_) => assert!(sender.needs_reset()),
    }
    session.restrict_permissions(Permissions::default()).unwrap();
    assert!(matches!(sender.send_repeat_network_outcome(&session, &mut network, 0, 200, wait,
        RepeatFrameOptIn::acknowledge_cached_screen_pixels()).await, Err(VideoError::Session(_))));
    sender.clear_repeat_input(); assert!(!sender.has_repeatable_input());
}

#[tokio::test]
async fn source_outcomes_work_with_bounded_in_process_transport() {
    use remote_transport::{local_pair, LocalConfig, Transport, TransportError};
    let session = session();
    let config = EncoderConfig { codec: Codec::Vp8, width: 64, height: 64, quality: 1.0, keyframe_interval: Some(30) };
    let mut sender = VideoSender::new(config, 1024 * 1024).unwrap();
    let (mut tx, mut rx) = local_pair(LocalConfig { queue_capacity: 1, max_message_size: 1024 * 1024 }).unwrap();
    let pixels = vec![64; 64 * 64 * 4]; let wait = Duration::from_secs(1);
    let outcome = sender.send_packed_outcome(&session, &mut tx, 0, &pixels, 256, PackedFormat::Bgra, 0, wait).await.unwrap();
    match outcome {
        SendOutcome::Sent => assert!(!rx.receive(wait).await.unwrap().is_empty()),
        SendOutcome::VpxNoOutput => assert_eq!(rx.receive(Duration::from_millis(5)).await, Err(TransportError::Timeout)),
    }
    assert!(!sender.needs_reset()); assert!(sender.has_repeatable_input());
    let result = sender.send_repeat_outcome(&session, &mut tx, 0, 100, wait, RepeatFrameOptIn::acknowledge_cached_screen_pixels()).await;
    match result {
        Ok(SendOutcome::Sent) => assert!(!rx.receive(wait).await.unwrap().is_empty()),
        Ok(SendOutcome::VpxNoOutput) => assert_eq!(rx.receive(Duration::from_millis(5)).await, Err(TransportError::Timeout)),
        Err(_) => assert!(sender.needs_reset()),
    }
    sender.clear_repeat_input();
}
