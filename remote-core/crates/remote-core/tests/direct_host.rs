#![cfg(feature = "source-security")]
//! Synthetic loopback only. Does not capture screens or inject OS input.
use hbb_common::sodiumoxide::{self, crypto::sign};
use remote_core::{direct_host::DirectHostListener, viewer_connection::{LoginIdentity, ViewerConnection}};
use remote_input::{InputBackend, MouseButton, VirtualKey};
use remote_protocol::desktop::PeerInfo;
use remote_rustdesk_websocket::{direct_tcp::{DirectTcp, DirectTcpOptIn}, source_crypto::connect_pinned_host};
use remote_security::{admission::{AdmissionController, AdmissionLimits}, OwnerApproval, PasswordVerifier};
use remote_session::{Permissions, Principal, SessionId};
use remote_transport::NetworkTransport;
use std::{io, time::Duration};
const WAIT: Duration = Duration::from_secs(10);
const LIMIT: usize = 128 * 1024;
struct NoInput;
impl InputBackend for NoInput {
    fn move_to(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
    fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
    fn mouse_up(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
    fn scroll(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
    fn key_down(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
    fn key_up(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
}
#[tokio::test]
async fn holds_admission_before_handshake_and_releases_on_drop() {
    let admission = AdmissionController::new(AdmissionLimits { max_total: 1, max_per_address: 1, login_grace: WAIT }).unwrap();
    let opt = DirectTcpOptIn::acknowledge_plaintext_transport();
    let listener = DirectHostListener::bind("127.0.0.1:0".parse().unwrap(), admission.clone(), WAIT, opt).await.unwrap();
    let mut client = DirectTcp::connect(listener.local_addr().unwrap(), LIMIT, WAIT, opt).await.unwrap();
    let accepted = listener.accept(WAIT).await.unwrap();
    assert!(accepted.peer_addr().ip().is_loopback()); assert_eq!(admission.active().unwrap(), 1);
    drop(accepted); assert_eq!(admission.active().unwrap(), 0);
    assert!(client.receive(WAIT).await.is_err());
}
#[tokio::test]
async fn direct_admitted_handshake_still_requires_password_and_owner_approval() {
    sodiumoxide::init().unwrap();
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let opt = DirectTcpOptIn::acknowledge_plaintext_transport();
    let listener = DirectHostListener::bind("127.0.0.1:0".parse().unwrap(), admission.clone(), WAIT, opt).await.unwrap();
    let client = DirectTcp::connect(listener.local_addr().unwrap(), LIMIT, WAIT, opt).await.unwrap();
    let accepted = listener.accept(WAIT).await.unwrap();
    let id = SessionId::new([99; 16]).unwrap(); let principal = Principal::new("holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test-secret", "test-salt", WAIT).unwrap();
    let (pin, secret) = sign::gen_keypair();
    let (server, client) = tokio::join!(accepted.secure(id, NoInput, verifier, "host", &secret, WAIT),
        connect_pinned_host(client, "host", &pin, LIMIT - 16, WAIT));
    let mut server = server.unwrap(); let mut viewer = ViewerConnection::new(client.unwrap(), LIMIT - 16).unwrap();
    assert_eq!(admission.active().unwrap(), 1);
    let perms = Permissions { view_screen: true, ..Default::default() };
    let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "Windows".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let identity = LoginIdentity { target: "host".into(), viewer_id: "v".into(), viewer_name: "v".into(), wire_session_id: 1, version: "test".into() };
    let ((), result) = tokio::join!(async {
        server.receive_password_login(WAIT).await.unwrap();
        let mut approval = OwnerApproval::new(id, principal, Some(perms));
        server.authorize(perms, &mut approval).unwrap();
        server.send_login_success(&info, WAIT).await.unwrap();
    }, viewer.login(&identity, "test-secret", WAIT));
    result.unwrap(); assert_eq!(admission.active().unwrap(), 0);
    viewer.close(); server.close().unwrap();
}

#[tokio::test]
async fn explicit_duplex_upgrade_only_after_login_and_preserves_frames() {
    use remote_core::host_connection::HostEvent;
    use remote_protocol::video_control::VideoControl;
    use remote_rustdesk_websocket::duplex_tcp::UpgradeableEncryptedTcp;
    sodiumoxide::init().unwrap();
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let opt = DirectTcpOptIn::acknowledge_plaintext_transport();
    let listener = DirectHostListener::bind("127.0.0.1:0".parse().unwrap(), admission, WAIT, opt).await.unwrap();
    let client = DirectTcp::connect(listener.local_addr().unwrap(), LIMIT, WAIT, opt).await.unwrap();
    let pending = listener.accept(WAIT).await.unwrap();
    let id = SessionId::new([100; 16]).unwrap(); let principal = Principal::new("holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test-secret", "test-salt", WAIT).unwrap();
    let (pin, secret) = sign::gen_keypair();
    let (server, client) = tokio::join!(pending.secure_upgradeable(id, NoInput, verifier, "host", &secret, WAIT),
        connect_pinned_host(client, "host", &pin, LIMIT - 16, WAIT));
    let mut server = server.unwrap();
    let mut viewer = ViewerConnection::new(UpgradeableEncryptedTcp::new(client.unwrap()), LIMIT - 16).unwrap();
    assert!(server.enable_duplex_read_ahead().is_err());
    assert!(viewer.enable_duplex_read_ahead().is_err());
    let perms = Permissions { view_screen: true, ..Default::default() };
    let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "Windows".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let identity = LoginIdentity { target: "host".into(), viewer_id: "v".into(), viewer_name: "v".into(), wire_session_id: 1, version: "test".into() };
    let ((), result) = tokio::join!(async {
        server.receive_password_login(WAIT).await.unwrap();
        server.authorize(perms, &mut OwnerApproval::new(id, principal, Some(perms))).unwrap();
        server.set_authorized_message_limit(LIMIT - 16).unwrap();
        server.send_login_success(&info, WAIT).await.unwrap();
    }, viewer.login(&identity, "test-secret", WAIT));
    result.unwrap(); viewer.set_connected_message_limit(LIMIT - 16).unwrap();
    server.enable_duplex_read_ahead().unwrap(); viewer.enable_duplex_read_ahead().unwrap();
    assert!(server.try_receive_event(WAIT).await.unwrap().is_none());
    let (sent, received) = tokio::join!(viewer.send_video_control(VideoControl::RefreshAll, WAIT), server.receive_event(WAIT));
    sent.unwrap(); assert_eq!(received.unwrap(), HostEvent::VideoControl(VideoControl::RefreshAll));
    let preferences = remote_protocol::cursor_preferences::CursorPreferences { show_remote_cursor: Some(true), follow_remote_cursor: Some(false), ..Default::default() };
    let (sent, received) = tokio::join!(viewer.send_cursor_preferences(preferences, WAIT), server.receive_event(WAIT));
    sent.unwrap();
    match received.unwrap() {
        HostEvent::CursorPreferences { values, .. } => assert_eq!(values, preferences),
        _ => panic!("expected cursor preferences"),
    }
    let (sent, received) = tokio::join!(viewer.send_disable_keyboard(true, WAIT), server.receive_event(WAIT));
    sent.unwrap(); assert!(matches!(received.unwrap(), HostEvent::InputPreference { disable_keyboard: true, .. }));
    assert!(!server.permissions().control_keyboard);
    let capabilities = remote_protocol::EncodingCapabilities { vp8: true, av1: false, h264: false, h265: false, i444: None };
    let (sent, received) = tokio::join!(server.send_supported_encoding(capabilities, WAIT), viewer.receive(WAIT));
    sent.unwrap(); assert!(matches!(received.unwrap(), remote_core::viewer_connection::ViewerEvent::EncodingCapabilities(c) if c == capabilities));
    let (sent, received) = tokio::join!(server.send_delay_probe(0, 0, WAIT), viewer.receive(WAIT));
    sent.unwrap(); assert!(matches!(received.unwrap(), remote_core::viewer_connection::ViewerEvent::TestDelay(_)));
    assert!(matches!(server.receive_event(WAIT).await.unwrap(), HostEvent::ProbeReply(_)));
    viewer.close(); server.close().unwrap();
}
