//! Written for later execution. Synthetic input over loopback, no real desktop.
use remote_core::host_connection::HostConnection;
use remote_input::{InputBackend, MouseButton, VirtualKey};
use remote_protocol::{DesktopLogin, Envelope, MouseEvent};
use remote_rustdesk_websocket::tcp::{LoopbackTcp, LoopbackTcpListener};
use remote_security::{admission::{AdmissionController, AdmissionLimits}, password_response, OwnerApproval, PasswordChallenge, PasswordVerifier};
use remote_session::{Permissions, Principal, SessionId, SessionState};
use remote_transport::NetworkTransport;
use std::{io, sync::{Arc, Mutex}, time::Duration};

const WAIT: Duration = Duration::from_secs(5);
const LIMIT: usize = 128 * 1024;
#[derive(Clone, Default)]
struct Fake(Arc<Mutex<Vec<String>>>);
impl InputBackend for Fake {
    fn move_to(&mut self, x: i32, y: i32) -> io::Result<()> { self.0.lock().unwrap().push(format!("move:{x},{y}")); Ok(()) }
    fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
    fn mouse_up(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
    fn scroll(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
    fn key_down(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
    fn key_up(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
}
async fn sockets() -> (LoopbackTcp, LoopbackTcp) {
    let listener = LoopbackTcpListener::bind("127.0.0.1:0".parse().unwrap(), LIMIT, WAIT).await.unwrap();
    let viewer = LoopbackTcp::connect(listener.local_addr().unwrap(), LIMIT, WAIT).await.unwrap();
    let host = listener.accept(WAIT).await.unwrap();
    (host, viewer)
}
async fn respond(viewer: &mut LoopbackTcp, password: &str) {
    let raw = viewer.receive(WAIT).await.unwrap();
    let envelope = Envelope::decode(&raw, LIMIT).unwrap();
    let challenge = envelope.password_challenge().unwrap();
    let challenge = PasswordChallenge { salt: challenge.salt.to_owned(), challenge: challenge.challenge.to_owned() };
    let response = password_response(password, &challenge).unwrap();
    let login = Envelope::desktop_login_event(DesktopLogin { username: "host", peer_id: "unverified-peer", peer_name: "unverified-name", password_response: response.as_bytes(), session_id: 4, version: "test" }).unwrap();
    viewer.send(&login.encode(LIMIT).unwrap(), WAIT).await.unwrap();
}
#[tokio::test]
async fn password_owner_approval_and_input_share_owned_stream() {
    let (socket, mut viewer) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([3; 16]).unwrap();
    let principal = Principal::new("shared-password-holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test-only", "salt", WAIT).unwrap();
    let fake = Fake::default(); let calls = fake.0.clone();
    let mut host = HostConnection::new(socket, id, fake, verifier, permit, LIMIT).unwrap();
    let (claims, ()) = tokio::join!(host.receive_password_login(WAIT), respond(&mut viewer, "test-only"));
    assert_eq!(claims.unwrap().peer_id, "unverified-peer");
    assert_eq!(admission.active().unwrap(), 1);
    let permissions = Permissions { control_mouse: true, ..Default::default() };
    let mut approval = OwnerApproval::new(id, principal, Some(permissions));
    host.authorize(permissions, &mut approval).unwrap();
    assert_eq!(host.state(), SessionState::Connected);
    assert_eq!(admission.active().unwrap(), 0);
    let peer = remote_protocol::desktop::PeerInfo { username: "".into(), hostname: "".into(), platform: "Windows".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    host.send_login_success(&peer, WAIT).await.unwrap();
    let reply = viewer.receive(WAIT).await.unwrap();
    assert!(matches!(Envelope::decode(&reply, LIMIT).unwrap().desktop_login_result().unwrap(), remote_protocol::desktop::LoginResult::Accepted(_)));
    let event = Envelope::mouse_event(MouseEvent { mask: 0, x: -12, y: 18 }).encode(LIMIT).unwrap();
    viewer.send(&event, WAIT).await.unwrap();
    host.receive_input(WAIT).await.unwrap();
    assert_eq!(&*calls.lock().unwrap(), &["move:-12,18"]);
    host.close().unwrap(); assert_eq!(host.state(), SessionState::Closed);
}
#[tokio::test]
async fn wrong_password_denies_and_releases_admission() {
    let (socket, mut viewer) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([5; 16]).unwrap();
    let principal = Principal::new("holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "right", "salt", WAIT).unwrap();
    let mut host = HostConnection::new(socket, id, Fake::default(), verifier, permit, LIMIT).unwrap();
    let (claims, ()) = tokio::join!(host.receive_password_login(WAIT), respond(&mut viewer, "wrong"));
    claims.unwrap();
    let permissions = Permissions { control_mouse: true, ..Default::default() };
    let mut approval = OwnerApproval::new(id, principal, Some(permissions));
    assert!(host.authorize(permissions, &mut approval).is_err());
    assert_eq!(admission.active().unwrap(), 0);
    assert_eq!(host.permissions(), Permissions::default());
    assert!(host.receive_input(WAIT).await.is_err());
}

#[tokio::test]
async fn provisional_host_and_viewer_login_then_mouse() {
    use remote_core::viewer_connection::{LoginIdentity, ViewerConnection};
    use remote_protocol::desktop::PeerInfo;
    let (socket, viewer_socket) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([9; 16]).unwrap();
    let principal = Principal::new("password-holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "shared-test-secret", "salt", WAIT).unwrap();
    let fake = Fake::default(); let calls = fake.0.clone();
    let mut host = HostConnection::new(socket, id, fake, verifier, permit, LIMIT).unwrap();
    let mut viewer = ViewerConnection::new(viewer_socket, LIMIT).unwrap();
    let identity = LoginIdentity { target: "host".into(), viewer_id: "unverified".into(), viewer_name: "viewer".into(), wire_session_id: 9, version: "test".into() };
    let perms = Permissions { control_mouse: true, ..Default::default() };
    let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "Windows".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let (server, client) = tokio::join!(async {
        let claims = host.receive_password_login(WAIT).await.unwrap();
        assert_eq!(claims.peer_id, "unverified");
        let mut policy = OwnerApproval::new(id, principal, Some(perms));
        host.authorize(perms, &mut policy).unwrap();
        host.send_login_success(&info, WAIT).await.unwrap();
    }, viewer.login(&identity, "shared-test-secret", WAIT));
    let _ = server; assert_eq!(client.unwrap(), info);
    let mouse = Envelope::mouse_event(MouseEvent { mask: 0, x: 7, y: -4 });
    let (sent, received) = tokio::join!(viewer.send_input(&mouse, WAIT), host.receive_input(WAIT));
    sent.unwrap(); received.unwrap();
    assert_eq!(&*calls.lock().unwrap(), &["move:7,-4"]);
    viewer.close(); host.close().unwrap();
}

#[tokio::test]
async fn strict_pinned_exchange_then_password_approval_and_input() {
    use hbb_common::sodiumoxide::{self, crypto::sign};
    use remote_core::viewer_connection::{LoginIdentity, ViewerConnection};
    use remote_protocol::desktop::PeerInfo;
    use remote_rustdesk_websocket::source_crypto::{accept_pinned_host, connect_pinned_host};
    sodiumoxide::init().unwrap();
    let (socket, viewer_socket) = sockets().await;
    let (host_public, host_secret) = sign::gen_keypair();
    let (host_socket, viewer_socket) = tokio::join!(
        accept_pinned_host(socket, "expected-host", &host_secret, LIMIT - 16, WAIT),
        connect_pinned_host(viewer_socket, "expected-host", &host_public, LIMIT - 16, WAIT));
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([10; 16]).unwrap();
    let principal = Principal::new("password-holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "shared-test-secret", "salt", WAIT).unwrap();
    let fake = Fake::default(); let calls = fake.0.clone();
    let mut host = HostConnection::new(host_socket.unwrap(), id, fake, verifier, permit, LIMIT - 16).unwrap();
    let mut viewer = ViewerConnection::new(viewer_socket.unwrap(), LIMIT - 16).unwrap();
    let identity = LoginIdentity { target: "expected-host".into(), viewer_id: "unverified".into(), viewer_name: "viewer".into(), wire_session_id: 10, version: "test".into() };
    let perms = Permissions { control_mouse: true, ..Default::default() };
    let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "Windows".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    assert!(host.set_authorized_message_limit(256 * 1024).is_err());
    let (server, client) = tokio::join!(async {
        host.receive_password_login(WAIT).await.unwrap();
        let mut policy = OwnerApproval::new(id, principal, Some(perms));
        host.authorize(perms, &mut policy).unwrap();
        host.set_authorized_message_limit(256 * 1024).unwrap();
        host.send_login_success(&info, WAIT).await.unwrap();
    }, viewer.login(&identity, "shared-test-secret", WAIT));
    let _ = server; assert_eq!(client.unwrap(), info);
    viewer.set_connected_message_limit(256 * 1024).unwrap();
    let mouse = Envelope::mouse_event(MouseEvent { mask: 0, x: 7, y: -4 });
    let (sent, received) = tokio::join!(viewer.send_input(&mouse, WAIT), host.receive_input(WAIT));
    sent.unwrap(); received.unwrap();
    assert_eq!(&*calls.lock().unwrap(), &["move:7,-4"]);
    viewer.close(); host.close().unwrap();
}

#[cfg(feature = "source-security")]
#[tokio::test]
async fn preauth_admission_is_retained_during_pinned_identity_handshake() {
    use hbb_common::sodiumoxide::{self, crypto::sign};
    use remote_rustdesk_websocket::source_crypto::connect_pinned_host;
    sodiumoxide::init().unwrap();
    let (socket, viewer_socket) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([11; 16]).unwrap();
    let principal = Principal::new("viewer".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal, "test", "salt", WAIT).unwrap();
    let (host_public, host_secret) = sign::gen_keypair();
    let (host, viewer) = tokio::join!(
        remote_core::admitted_host::accept(socket, permit, id, Fake::default(), verifier, "host", &host_secret, WAIT),
        connect_pinned_host(viewer_socket, "host", &host_public, LIMIT - 16, WAIT));
    let mut host = host.unwrap(); let mut viewer = viewer.unwrap();
    assert_eq!(admission.active().unwrap(), 1);
    assert_eq!(host.state(), SessionState::Authenticating);
    host.close().unwrap(); viewer.close();
    assert_eq!(admission.active().unwrap(), 0);
}

#[cfg(feature = "source-security")]
#[tokio::test]
async fn cancelled_pre_auth_handshake_closes_socket_and_releases_permit() {
    use hbb_common::sodiumoxide::{self, crypto::sign};
    sodiumoxide::init().unwrap();
    let (socket, mut viewer_socket) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([12; 16]).unwrap();
    let principal = Principal::new("viewer".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal, "test", "salt", WAIT).unwrap();
    let (_, host_secret) = sign::gen_keypair();
    let result = tokio::time::timeout(Duration::from_millis(20),
        remote_core::admitted_host::accept(socket, permit, id, Fake::default(), verifier, "host", &host_secret, WAIT)).await;
    assert!(result.is_err());
    assert_eq!(admission.active().unwrap(), 0);
    // The signed challenge may already have been queued; the next receive must
    // fail after it has been consumed. No credentials were exchanged.
    let _ = viewer_socket.receive(WAIT).await;
    assert!(viewer_socket.receive(WAIT).await.is_err());
}

#[tokio::test]
async fn video_controls_reach_authorized_scheduler_but_are_not_executed() {
    use remote_core::host_connection::HostEvent;
    use remote_core::viewer_connection::{LoginIdentity, ViewerConnection};
    use remote_protocol::{desktop::PeerInfo, video_control::VideoControl};
    let (socket, viewer_socket) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([13; 16]).unwrap();
    let principal = Principal::new("holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test", "salt", WAIT).unwrap();
    let mut host = HostConnection::new(socket, id, Fake::default(), verifier, permit, LIMIT).unwrap();
    let mut viewer = ViewerConnection::new(viewer_socket, LIMIT).unwrap();
    let identity = LoginIdentity { target: "host".into(), viewer_id: "v".into(), viewer_name: "v".into(), wire_session_id: 13, version: "test".into() };
    let permissions = Permissions { view_screen: true, ..Default::default() };
    let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "Windows".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let (_, login) = tokio::join!(async {
        host.receive_password_login(WAIT).await.unwrap();
        host.authorize(permissions, &mut OwnerApproval::new(id, principal, Some(permissions))).unwrap();
        host.send_login_success(&info, WAIT).await.unwrap();
    }, viewer.login(&identity, "test", WAIT));
    login.unwrap();
    for control in [VideoControl::RefreshAll, VideoControl::RefreshDisplay(3), VideoControl::FrameReceived] {
        let (sent, received) = tokio::join!(viewer.send_video_control(control, WAIT), host.receive_event(WAIT));
        sent.unwrap(); assert_eq!(received.unwrap(), HostEvent::VideoControl(control));
    }
    host.restrict_permissions(Permissions::default()).unwrap();
    let (sent, received) = tokio::join!(viewer.send_video_control(VideoControl::RefreshAll, WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert!(received.is_err());
    viewer.close(); host.close().unwrap();
}
