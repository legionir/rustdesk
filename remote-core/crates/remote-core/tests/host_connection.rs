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
