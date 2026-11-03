//! Written for later execution. Synthetic input over loopback, no real desktop.
use remote_core::host_connection::HostConnection;
use remote_input::{InputBackend, MouseButton, ScanCode, VirtualKey};
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
    fn scroll(&mut self, x: i32, y: i32) -> io::Result<()> { self.0.lock().unwrap().push(format!("scroll:{x},{y}")); Ok(()) }
    fn key_down(&mut self, key: VirtualKey) -> io::Result<()> { self.0.lock().unwrap().push(format!("key-down:{}", key.code())); Ok(()) }
    fn key_up(&mut self, key: VirtualKey) -> io::Result<()> { self.0.lock().unwrap().push(format!("key-up:{}", key.code())); Ok(()) }
    fn type_text(&mut self, text: &str) -> io::Result<()> { self.0.lock().unwrap().push(format!("text:{text}")); Ok(()) }
    fn scan_down(&mut self, key: ScanCode) -> io::Result<()> { self.0.lock().unwrap().push(format!("scan-down:{}", key.code())); Ok(()) }
    fn scan_up(&mut self, key: ScanCode) -> io::Result<()> { self.0.lock().unwrap().push(format!("scan-up:{}", key.code())); Ok(()) }
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
    let broker = remote_security::approval::ApprovalBroker::new(1).unwrap();
    let mut ticket = host.request_owner_approval(&broker, principal, permissions, WAIT).unwrap();
    assert!(host.authorize_with_ticket(&mut ticket, permissions).unwrap().is_none());
    let visible = broker.pending().unwrap(); assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].peer_label, "unverified-name");
    broker.decide(ticket.key(), Some(permissions)).unwrap();
    assert!(host.authorize_with_ticket(&mut ticket, permissions).unwrap().is_some());
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
    // Check unsupported sensitive messages produce an error and no fake input.
    // This fixture cannot observe direct native OS side effects.
    use remote_protocol::sensitive_display::{SensitiveOptions, VirtualDisplayRequest};
    let requests = [
        Envelope::privacy_request_event("", true).unwrap(),
        Envelope::virtual_display_request_event(VirtualDisplayRequest { display: 0, on: true }),
        Envelope::sensitive_options_event(SensitiveOptions { block_input: Some(true), ..Default::default() }),
    ];
    for request in requests {
        viewer.send(&request.encode(LIMIT).unwrap(), WAIT).await.unwrap();
        assert!(matches!(host.receive_event(WAIT).await, Err(remote_core::host_connection::ConnectionError::UnexpectedMessage)));
        assert_eq!(&*calls.lock().unwrap(), &["move:-12,18"]);
    }
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
    assert!(host.send_source_keyboard_permission(true, WAIT).await.is_err());
    let (notice_sent, notice) = tokio::join!(host.send_source_keyboard_permission(false, WAIT), viewer.receive(WAIT));
    notice_sent.unwrap();
    match notice.unwrap() {
        remote_core::viewer_connection::ViewerEvent::Permission(n) => assert_eq!((n.permission, n.enabled), (0, false)),
        _ => panic!("expected source permission notice"),
    }
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
    let perms = Permissions { view_screen: true, control_mouse: true, control_keyboard: true, ..Default::default() };
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
    let mut probe = remote_core::video_schedule::DelayProbe::new();
    let started = std::time::Instant::now();
    let expected = probe.begin(started, 12, 400).unwrap();
    let (sent, received) = tokio::join!(host.send_delay_probe(12, 400, WAIT), viewer.receive(WAIT));
    sent.unwrap(); assert!(matches!(received.unwrap(), remote_core::viewer_connection::ViewerEvent::TestDelay(_)));
    let reply = match host.receive_event(WAIT).await.unwrap() {
        remote_core::host_connection::HostEvent::ProbeReply(reply) => reply,
        _ => panic!("expected source probe echo"),
    };
    assert_eq!(reply, expected);
    probe.reply(std::time::Instant::now(), reply).unwrap();
    // Translate Seq wire is accepted by the viewer but the current host must
    // not accidentally inject it, even with restricted Translate mode enabled.
    host.set_windows_translate_mode_enabled(true).unwrap();
    let text = Envelope::windows_translate_sequence_event("sample").unwrap();
    let (sent, rejected) = tokio::join!(viewer.send_input(&text, WAIT), host.receive_event(WAIT));
    sent.unwrap();
    assert!(matches!(rejected, Err(remote_core::host_connection::ConnectionError::Keyboard(_))));
    assert_eq!(&*calls.lock().unwrap(), &["move:7,-4"]);
    host.set_windows_translate_mode_enabled(false).unwrap();
    host.set_windows_scan_mode_enabled(true).unwrap();
    host.set_windows_key_repeat_enabled(true).unwrap();
    assert!(host.set_tracked_modifiers_enabled(true).is_err());
    let scan = Envelope::windows_scan_event(0xe01d, true).unwrap();
    let (sent, received) = tokio::join!(viewer.send_input(&scan, WAIT), host.receive_event(WAIT));
    sent.unwrap(); received.unwrap();
    let (sent, received) = tokio::join!(viewer.send_input(&scan, WAIT), host.receive_event(WAIT));
    sent.unwrap(); received.unwrap();
    assert!(host.set_windows_key_repeat_enabled(false).is_err());
    assert!(host.set_windows_scan_mode_enabled(false).is_err());
    viewer.close(); host.close().unwrap();
    assert_eq!(&*calls.lock().unwrap(), &["move:7,-4", "scan-down:57373", "scan-down:57373", "scan-up:57373"]);
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
    use remote_protocol::{desktop::PeerInfo, video_control::VideoControl, CodecPreference, DecodingAdvertisement};
    let (socket, viewer_socket) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([13; 16]).unwrap();
    let principal = Principal::new("holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test", "salt", WAIT).unwrap();
    let mut host = HostConnection::new(socket, id, Fake::default(), verifier, permit, LIMIT).unwrap();
    let mut viewer = ViewerConnection::new(viewer_socket, LIMIT).unwrap();
    let identity = LoginIdentity { target: "host".into(), viewer_id: "v".into(), viewer_name: "v".into(), wire_session_id: 13, version: "test".into() };
    let permissions = Permissions { view_screen: true, change_display: true, ..Default::default() };
    let capabilities = DecodingAdvertisement { vp8: true, vp9: false, av1: false, h264: false, h265: false, preference: CodecPreference::Vp8 };
    assert!(host.take_initial_decoding_advertisement().is_err());
    let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "Windows".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let windows_claims = remote_protocol::windows_sessions::WindowsSessions { current_sid: 1,
        sessions: vec![remote_protocol::windows_sessions::WindowsSession { sid: 1, name: "console".into() }] };
    let (_, login) = tokio::join!(async {
        host.receive_password_login(WAIT).await.unwrap();
        host.authorize(permissions, &mut OwnerApproval::new(id, principal, Some(permissions))).unwrap();
        let initial = host.take_initial_decoding_advertisement().unwrap().unwrap();
        assert_eq!(initial.supported_decoding().unwrap().vp8, 1);
        assert!(initial.desktop_login().is_err());
        assert!(host.take_initial_decoding_advertisement().unwrap().is_none());
        host.send_login_success_with_windows_sessions(&info, None, None, &windows_claims, WAIT).await.unwrap();
    }, viewer.login_with_decoding(&identity, "test", capabilities, WAIT));
    login.unwrap();
    assert_eq!(viewer.windows_sessions(), Some(&windows_claims));
    let (sent, update) = tokio::join!(host.send_peer_info_update_with_windows_sessions(&info, None, &windows_claims, WAIT), viewer.receive(WAIT));
    sent.unwrap(); assert!(matches!(update.unwrap(), remote_core::viewer_connection::ViewerEvent::PeerInfo(_)));
    assert_eq!(viewer.windows_sessions(), Some(&windows_claims));
    // The local host only reports this request; it never switches OS sessions.
    let (sent, event) = tokio::join!(viewer.select_windows_session(7,
        remote_protocol::windows_sessions::SessionSwitchOptIn::acknowledge_remote_session_switch_risk(), WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert_eq!(event.unwrap(), HostEvent::WindowsSessionRequest(7));
    for control in [VideoControl::RefreshAll, VideoControl::RefreshDisplay(3), VideoControl::FrameReceived, VideoControl::AutoAdjustFps(30), VideoControl::ClientRecording(false), VideoControl::ClientRecording(true)] {
        let (sent, received) = tokio::join!(viewer.send_video_control(control, WAIT), host.receive_event(WAIT));
        sent.unwrap(); assert_eq!(received.unwrap(), HostEvent::VideoControl(control));
    }
    // Caller-driven source FPS plan: dispatch merely sends requests, while the
    // host returns them as untrusted controls rather than applying them.
    {
        use remote_core::viewer_fps::{self, Decision, DispatchError, RefreshMode};
        let invalid = Decision { custom_fps: Some(121), refresh: vec![0], min_decode_fps: Some(1) };
        assert!(matches!(viewer_fps::dispatch(&mut viewer, &invalid, RefreshMode::PerDisplay, WAIT).await, Err(DispatchError::InvalidDecision)));
        let duplicate = Decision { custom_fps: None, refresh: vec![0, 0], min_decode_fps: Some(1) };
        assert!(matches!(viewer_fps::dispatch(&mut viewer, &duplicate, RefreshMode::PerDisplay, WAIT).await, Err(DispatchError::InvalidDecision)));
        let decision = Decision { custom_fps: Some(27), refresh: vec![0, 1], min_decode_fps: Some(30) };
        let (sent, events) = tokio::join!(viewer_fps::dispatch(&mut viewer, &decision, RefreshMode::PerDisplay, WAIT), async {
            let first = host.receive_event(WAIT).await.unwrap();
            let second = host.receive_event(WAIT).await.unwrap();
            let third = host.receive_event(WAIT).await.unwrap();
            (first, second, third)
        });
        assert_eq!(sent.unwrap(), 3);
        assert!(matches!(events.0, HostEvent::VideoPreferences { values, .. } if values.fps == Some(27) && values.quality.is_none()));
        assert_eq!(events.1, HostEvent::VideoControl(VideoControl::RefreshDisplay(0)));
        assert_eq!(events.2, HostEvent::VideoControl(VideoControl::RefreshDisplay(1)));
        let old_peer = Decision { custom_fps: None, refresh: vec![0, 1], min_decode_fps: Some(30) };
        let (sent, events) = tokio::join!(viewer_fps::dispatch(&mut viewer, &old_peer, RefreshMode::All, WAIT), async {
            (host.receive_event(WAIT).await.unwrap(), host.receive_event(WAIT).await.unwrap())
        });
        assert_eq!(sent.unwrap(), 2);
        assert_eq!(events.0, HostEvent::VideoControl(VideoControl::RefreshAll));
        assert_eq!(events.1, HostEvent::VideoControl(VideoControl::RefreshAll));
    }
    let (sent, received) = tokio::join!(viewer.send_decoding_advertisement(capabilities, WAIT), host.receive_event(WAIT));
    sent.unwrap();
    match received.unwrap() {
        HostEvent::DecodingAdvertisement { values, envelope } => {
            assert_eq!(values.vp8, 1);
            assert_eq!(Envelope::decode(&envelope, LIMIT).unwrap().supported_decoding().unwrap(), values);
        },
        _ => panic!("expected decoding advertisement"),
    }
    let (sent, received) = tokio::join!(viewer.request_cursor_shape(u64::MAX, WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert_eq!(received.unwrap(), HostEvent::CursorShapeRequest(u64::MAX));
    assert!(!host.send_cached_cursor(u64::MAX, WAIT).await.unwrap());
    use remote_protocol::display_control::{CaptureDisplays, DisplaySwitch};
    use remote_core::viewer_connection::ViewerEvent;
    let switch = DisplaySwitch { display: 1, x: 0, y: 0, width: 0, height: 0, cursor_embedded: false };
    let event = Envelope::display_switch_event(&switch).unwrap();
    let (sent, received) = tokio::join!(viewer.send_display_control(&event, WAIT), host.receive_event(WAIT));
    sent.unwrap(); match received.unwrap() {
        HostEvent::DisplaySwitchRequest { value, envelope } => {
            assert_eq!(value, switch); assert_eq!(Envelope::decode(&envelope, LIMIT).unwrap().display_switch().unwrap(), switch);
        }, _ => panic!("expected switch request"),
    }
    let request = CaptureDisplays { add: vec![0, 1], sub: vec![], set: vec![] };
    let event = Envelope::capture_displays_event(&request).unwrap();
    let (sent, received) = tokio::join!(viewer.send_display_control(&event, WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert!(matches!(received.unwrap(), HostEvent::CaptureDisplaysRequest { value, .. } if value == request));
    let update = PeerInfo { username: "".into(), hostname: "".into(), platform: "".into(), version: "".into(),
        displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let (sent, received) = tokio::join!(host.send_peer_info_update(&update, WAIT), viewer.receive(WAIT));
    sent.unwrap(); assert!(matches!(received.unwrap(), ViewerEvent::PeerInfo(value) if value == update));
    let notice = DisplaySwitch { display: 1, x: -1920, y: 0, width: 1920, height: 1080, cursor_embedded: false };
    let (sent, received) = tokio::join!(host.send_display_change(&notice, WAIT), viewer.receive(WAIT));
    sent.unwrap(); assert!(matches!(received.unwrap(), ViewerEvent::DisplayChanged { value, .. } if value == notice));
    let mode = remote_protocol::display_control::DisplayResolution { display: 1, width: 1280, height: 720 };
    let mode_event = Envelope::display_resolution_event(mode).unwrap();
    let (sent, received) = tokio::join!(viewer.send_display_control(&mode_event, WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert_eq!(received.unwrap(), HostEvent::DisplayResolutionRequest(mode));
    let query = Envelope::display_query_event(1).unwrap();
    let (sent, received) = tokio::join!(viewer.send_display_control(&query, WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert_eq!(received.unwrap(), HostEvent::DisplayQuery(1));
    let (sent, received) = tokio::join!(host.send_follow_current_display(1, WAIT), viewer.receive(WAIT));
    sent.unwrap(); assert!(matches!(received.unwrap(), ViewerEvent::FollowCurrentDisplay(1)));
    host.restrict_permissions(Permissions { view_screen: true, ..Default::default() }).unwrap();
    assert!(host.send_peer_info_update_with_windows_sessions(&info, None, &windows_claims, WAIT).await.is_err());
    let (sent, selection) = tokio::join!(viewer.select_windows_session(7,
        remote_protocol::windows_sessions::SessionSwitchOptIn::acknowledge_remote_session_switch_risk(), WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert!(selection.is_err());
    let (sent, received) = tokio::join!(viewer.send_display_control(&event, WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert!(received.is_err());
    let (sent, received) = tokio::join!(viewer.send_display_control(&mode_event, WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert!(received.is_err());
    let (sent, received) = tokio::join!(viewer.send_display_control(&query, WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert_eq!(received.unwrap(), HostEvent::DisplayQuery(1));
    host.restrict_permissions(Permissions::default()).unwrap();
    let (sent, received) = tokio::join!(viewer.send_video_control(VideoControl::RefreshAll, WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert!(received.is_err());
    assert!(host.send_cached_cursor(u64::MAX, WAIT).await.is_err());
    viewer.close(); host.close().unwrap();
}

#[tokio::test]
async fn opt_in_touch_blocks_other_input_and_cleans_up_on_mouse_revoke() {
    use remote_core::{host_connection::HostEvent, viewer_connection::{LoginIdentity, ViewerConnection}};
    use remote_protocol::{desktop::PeerInfo, pointer::Touch};
    let (socket, viewer_socket) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([55; 16]).unwrap(); let principal = Principal::new("holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test", "salt", WAIT).unwrap();
    let fake = Fake::default(); let calls = fake.0.clone();
    let mut host = HostConnection::new(socket, id, fake, verifier, permit, LIMIT).unwrap();
    let mut viewer = ViewerConnection::new(viewer_socket, LIMIT).unwrap();
    let identity = LoginIdentity { target: "host".into(), viewer_id: "v".into(), viewer_name: "v".into(), wire_session_id: 55, version: "test".into() };
    let perms = Permissions { control_mouse: true, control_keyboard: true, ..Default::default() };
    let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "Windows".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let (_, login) = tokio::join!(async {
        host.receive_password_login(WAIT).await.unwrap();
        host.authorize(perms, &mut OwnerApproval::new(id, principal, Some(perms))).unwrap();
        host.send_login_success(&info, WAIT).await.unwrap();
    }, viewer.login(&identity, "test", WAIT)); login.unwrap();
    let touch = Envelope::touch_event(Touch::Scale(120));
    let (sent, received) = tokio::join!(viewer.send_input(&touch, WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert!(received.is_err());
    host.set_windows_touch_scale_enabled(true).unwrap();
    let (sent, received) = tokio::join!(viewer.send_input(&touch, WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert_eq!(received.unwrap(), HostEvent::Input);
    let mouse = Envelope::mouse_event(MouseEvent { mask: 0, x: 1, y: 2 });
    let (sent, received) = tokio::join!(viewer.send_input(&mouse, WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert!(received.is_err());
    assert!(host.set_windows_touch_scale_enabled(false).is_err());
    host.restrict_permissions(Permissions { control_keyboard: true, ..Default::default() }).unwrap();
    assert_eq!(&*calls.lock().unwrap(), &["key-down:162", "scroll:0,120", "key-up:162"]);
    host.set_windows_touch_scale_enabled(false).unwrap(); viewer.close(); host.close().unwrap();
}

#[tokio::test]
async fn login_preferences_are_held_until_approval_and_updates_are_caller_driven() {
    use remote_core::{host_connection::HostEvent, viewer_connection::{LoginIdentity, ViewerConnection}};
    use remote_protocol::{CodecPreference, DecodingAdvertisement, desktop::PeerInfo, video_preferences::{Quality, VideoPreferences}};
    let (socket, viewer_socket) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([19; 16]).unwrap();
    let principal = Principal::new("password-holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test-password", "salt", WAIT).unwrap();
    let mut host = HostConnection::new(socket, id, Fake::default(), verifier, permit, LIMIT).unwrap();
    let mut viewer = ViewerConnection::new(viewer_socket, LIMIT).unwrap();
    let identity = LoginIdentity { target: "host".into(), viewer_id: "viewer".into(), viewer_name: "viewer".into(), wire_session_id: 19, version: "test".into() };
    let perms = Permissions { view_screen: true, ..Default::default() };
    let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "Windows".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let ad = DecodingAdvertisement { vp8: false, vp9: true, av1: false, h264: false, h265: false, preference: CodecPreference::Vp9 };
    let options = VideoPreferences { quality: Some(Quality::Best), fps: Some(30) };
    let ((), result) = tokio::join!(async {
        host.receive_password_login(WAIT).await.unwrap();
        assert!(host.take_initial_video_preferences().is_err());
        let mut approval = OwnerApproval::new(id, principal, Some(perms));
        host.authorize(perms, &mut approval).unwrap();
        assert!(host.initial_video_ack_required().unwrap());
        assert_eq!(host.take_initial_video_preferences().unwrap(), Some(options));
        assert_eq!(host.take_initial_video_preferences().unwrap(), None);
        assert_eq!(host.take_initial_decoding_advertisement().unwrap().unwrap().supported_decoding().unwrap().vp9, 1);
        host.send_login_success(&info, WAIT).await.unwrap();
    }, viewer.login_with_ack(&identity, "test-password", Some(ad), Some(options), WAIT));
    result.unwrap();
    let (send, event) = tokio::join!(viewer.send_video_preferences(options, WAIT), host.receive_event(WAIT));
    send.unwrap();
    match event.unwrap() { HostEvent::VideoPreferences { values, decoding, .. } => { assert_eq!(values, options); assert!(decoding.is_none()); }, _ => panic!("expected video preferences") }
    viewer.close(); host.close().unwrap();
}

#[tokio::test]
async fn peer_close_during_login_releases_admission() {
    use remote_core::host_connection::ConnectionError;
    let (socket, mut viewer) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([20; 16]).unwrap();
    let principal = Principal::new("password-holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal, "test-password", "salt", WAIT).unwrap();
    let mut host = HostConnection::new(socket, id, Fake::default(), verifier, permit, LIMIT).unwrap();
    let (result, ()) = tokio::join!(host.receive_password_login(WAIT), async {
        viewer.receive(WAIT).await.unwrap();
        viewer.send(&Envelope::close_reason_event("cancelled").unwrap().encode(LIMIT).unwrap(), WAIT).await.unwrap();
    });
    assert!(matches!(result, Err(ConnectionError::PeerClosed(Some(reason))) if reason == "cancelled"));
    assert_eq!(admission.active().unwrap(), 0);
    assert_eq!(host.state(), SessionState::Closed);
}

#[tokio::test]
async fn peer_close_releases_held_input_after_approval() {
    use remote_core::host_connection::ConnectionError;
    let (socket, mut viewer) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([21; 16]).unwrap();
    let principal = Principal::new("password-holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test-password", "salt", WAIT).unwrap();
    let fake = Fake::default(); let calls = fake.0.clone();
    let mut host = HostConnection::new(socket, id, fake, verifier, permit, LIMIT).unwrap();
    let (login, ()) = tokio::join!(host.receive_password_login(WAIT), respond(&mut viewer, "test-password"));
    login.unwrap();
    let perms = Permissions { control_keyboard: true, ..Default::default() };
    host.authorize(perms, &mut OwnerApproval::new(id, principal, Some(perms))).unwrap();
    let peer = remote_protocol::desktop::PeerInfo { username: "".into(), hostname: "".into(), platform: "Windows".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    host.send_login_success(&peer, WAIT).await.unwrap(); viewer.receive(WAIT).await.unwrap();
    let key = Envelope::legacy_keyboard_event(remote_protocol::input::LegacyKey::ControlKey(2), true, false, &[]).unwrap().encode(LIMIT).unwrap();
    viewer.send(&key, WAIT).await.unwrap(); host.receive_input(WAIT).await.unwrap();
    viewer.send(&Envelope::close_reason_event("done").unwrap().encode(LIMIT).unwrap(), WAIT).await.unwrap();
    assert!(matches!(host.receive_event(WAIT).await, Err(ConnectionError::PeerClosed(Some(reason))) if reason == "done"));
    assert_eq!(host.state(), SessionState::Closed);
    assert_eq!(&*calls.lock().unwrap(), &["key-down:8", "key-up:8"]);
}

#[tokio::test]
async fn accepted_peer_input_gate_releases_keys_without_expanding_local_permissions() {
    use remote_core::{host_connection::HostEvent, viewer_connection::{LoginIdentity, ViewerConnection}};
    use remote_protocol::{desktop::PeerInfo, input::LegacyKey};
    let (socket, viewer_socket) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([111; 16]).unwrap();
    let principal = Principal::new("holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test", "salt", WAIT).unwrap();
    let fake = Fake::default(); let calls = fake.0.clone();
    let mut host = HostConnection::new(socket, id, fake, verifier, permit, LIMIT).unwrap();
    let mut viewer = ViewerConnection::new(viewer_socket, LIMIT).unwrap();
    assert!(host.enable_idle_timeout(1).is_err());
    assert!(host.enable_receive_watchdog().is_err());
    assert!(host.set_windows_key_repeat_enabled(true).is_err());
    assert!(host.set_windows_scan_mode_enabled(true).is_err());
    assert!(host.set_windows_translate_mode_enabled(true).is_err());
    let identity = LoginIdentity { target: "host".into(), viewer_id: "viewer".into(), viewer_name: "viewer".into(), wire_session_id: 1, version: "test".into() };
    let perms = Permissions { control_keyboard: true, control_mouse: true, ..Default::default() };
    let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "test".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let ((), result) = tokio::join!(async {
        host.receive_password_login(WAIT).await.unwrap();
        host.authorize(perms, &mut OwnerApproval::new(id, principal, Some(perms))).unwrap();
        let mode = remote_protocol::resolution_metadata::Resolution { width: 1920, height: 1080 };
        assert!(host.send_login_success_with_display_modes(&info, &[], Some(&[mode]), WAIT).await.is_err());
        host.send_login_success(&info, WAIT).await.unwrap();
    }, viewer.login(&identity, "test", WAIT)); result.unwrap();
    assert!(host.idle_remaining().unwrap().is_none());
    assert!(host.enable_idle_timeout(0).is_err());
    host.enable_idle_timeout(1).unwrap();
    assert!(host.enable_idle_timeout(1).is_err());
    assert!(!host.poll_idle_timeout().unwrap());
    assert!(host.receive_watchdog_remaining().unwrap().is_none());
    host.enable_receive_watchdog().unwrap();
    assert!(host.enable_receive_watchdog().is_err());
    assert!(!host.poll_receive_watchdog().unwrap());
    let key = Envelope::legacy_keyboard_event(LegacyKey::ControlKey(2), true, false, &[]).unwrap();
    let (sent, event) = tokio::join!(viewer.send_input(&key, WAIT), host.receive_event(WAIT)); sent.unwrap(); assert_eq!(event.unwrap(), HostEvent::Input);
    assert!(host.idle_remaining().unwrap().is_some());
    assert!(host.receive_watchdog_remaining().unwrap().is_some());
    host.apply_peer_input_disabled(true).unwrap(); assert!(host.peer_input_disabled());
    assert_eq!(&*calls.lock().unwrap(), &["key-down:8", "key-up:8"]);
    let (sent, event) = tokio::join!(viewer.send_input(&key, WAIT), host.receive_event(WAIT)); sent.unwrap(); assert_eq!(event.unwrap(), HostEvent::InputSuppressed);
    assert_eq!(calls.lock().unwrap().len(), 2);
    host.restrict_permissions(Permissions { control_mouse: true, ..Default::default() }).unwrap();
    host.apply_peer_input_disabled(false).unwrap(); assert!(!host.peer_input_disabled());
    assert!(!host.permissions().control_keyboard && host.permissions().control_mouse);
    let mouse = Envelope::mouse_event(MouseEvent { mask: 0, x: 4, y: 6 });
    let (sent, event) = tokio::join!(viewer.send_input(&mouse, WAIT), host.receive_event(WAIT)); sent.unwrap(); assert_eq!(event.unwrap(), HostEvent::Input);
    assert_eq!(calls.lock().unwrap().last().unwrap(), "move:4,6");
    viewer.close(); host.close().unwrap();
}

#[tokio::test]
async fn original_display_resolution_claims_survive_login_and_update() {
    use remote_core::viewer_connection::{LoginIdentity, ViewerConnection, ViewerEvent};
    use remote_protocol::desktop::{DisplayInfo, OriginalResolution, PeerInfo};
    let (socket, viewer_socket) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([112; 16]).unwrap();
    let principal = Principal::new("holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test", "salt", WAIT).unwrap();
    let mut host = HostConnection::new(socket, id, Fake::default(), verifier, permit, LIMIT).unwrap();
    let mut viewer = ViewerConnection::new(viewer_socket, LIMIT).unwrap();
    let identity = LoginIdentity { target: "host".into(), viewer_id: "viewer".into(), viewer_name: "viewer".into(), wire_session_id: 1, version: "test".into() };
    let perms = Permissions { view_screen: true, ..Default::default() };
    let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "Windows".into(), version: "test".into(),
        displays: vec![DisplayInfo { x: 0, y: 0, width: 1280, height: 720, name: "display".into(), online: true, cursor_embedded: false, scale: 0.0 }],
        current_display: 0, sas_enabled: false, encoding: None };
    let original = Some(OriginalResolution { width: 1920, height: 1080 });
    let mode = remote_protocol::resolution_metadata::Resolution { width: 1920, height: 1080 };
    let ((), result) = tokio::join!(async {
        host.receive_password_login(WAIT).await.unwrap();
        host.authorize(perms, &mut OwnerApproval::new(id, principal, Some(perms))).unwrap();
        host.send_login_success_with_display_modes(&info, &[original], Some(&[mode]), WAIT).await.unwrap();
    }, viewer.login(&identity, "test", WAIT));
    assert_eq!(result.unwrap(), info);
    assert_eq!(viewer.original_resolutions().unwrap(), &[original]);
    assert_eq!(viewer.supported_modes(), Some((0, &[mode][..])));
    let (sent, event) = tokio::join!(host.send_peer_info_update_with_originals(&info, &[None], WAIT), viewer.receive(WAIT));
    sent.unwrap(); assert!(matches!(event.unwrap(), ViewerEvent::PeerInfo(_)));
    assert_eq!(viewer.original_resolutions().unwrap(), &[None]);
    assert!(viewer.supported_modes().is_none());
    let change = remote_protocol::display_control::DisplaySwitch { display: 0, x: 0, y: 0, width: 1280, height: 720, cursor_embedded: false };
    let (sent, event) = tokio::join!(host.send_display_change_with_modes(&change, Some(&[mode]), Some(mode), WAIT), viewer.receive(WAIT));
    sent.unwrap();
    match event.unwrap() {
        ViewerEvent::DisplayChanged { envelope, .. } => {
            let decoded = Envelope::decode(&envelope, LIMIT).unwrap();
            assert_eq!(decoded.supported_resolutions().unwrap(), Some(vec![mode]));
            assert_eq!(decoded.switch_original_resolution().unwrap(), Some(mode));
        },
        _ => panic!("expected display-change metadata"),
    }
    assert_eq!(viewer.supported_modes(), Some((0, &[mode][..])));
    viewer.close(); assert!(viewer.original_resolutions().is_none()); assert!(viewer.supported_modes().is_none()); host.close().unwrap();
}

#[tokio::test]
async fn source_two_factor_responses_do_not_bypass_basic_viewer_login() {
    use remote_core::viewer_connection::{LoginIdentity, ViewerConnection, ViewerError};
    for reason in ["2FA Required", "Wrong 2FA Code"] {
        let (mut source, socket) = sockets().await;
        let mut viewer = ViewerConnection::new(socket, LIMIT).unwrap();
        let identity = LoginIdentity { target: "host".into(), viewer_id: "viewer".into(),
            viewer_name: "viewer".into(), wire_session_id: 1, version: "test".into() };
        let ((), result) = tokio::join!(async {
            source.send(&Envelope::password_challenge_event("salt", "challenge").unwrap().encode(LIMIT).unwrap(), WAIT).await.unwrap();
            let login = source.receive(WAIT).await.unwrap();
            assert!(Envelope::decode(&login, LIMIT).unwrap().desktop_login().is_ok());
            source.send(&Envelope::desktop_login_error(reason).unwrap().encode(LIMIT).unwrap(), WAIT).await.unwrap();
        }, viewer.login(&identity, "password", WAIT));
        assert!(matches!(result, Err(ViewerError::Denied(text)) if text == reason));
        // Unsupported 2FA must not become a connected/input-capable session.
        assert!(matches!(viewer.send_input(&Envelope::mouse_event(MouseEvent { mask: 0, x: 0, y: 0 }), WAIT).await,
            Err(ViewerError::InvalidState)));
    }
}

#[tokio::test]
async fn caller_driven_delay_probe_reaches_source_qos() {
    use remote_core::{host_connection::HostEvent, probe_qos::{ProbeQos, ProbeQosError}, viewer_connection::{LoginIdentity, ViewerConnection, ViewerEvent}};
    use remote_codec::video_qos::{QosError, SourceVideoQos};
    let (socket, viewer_socket) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([23; 16]).unwrap();
    let principal = Principal::new("holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test", "salt", WAIT).unwrap();
    let mut host = HostConnection::new(socket, id, Fake::default(), verifier, permit, LIMIT).unwrap();
    let mut viewer = ViewerConnection::new(viewer_socket, LIMIT).unwrap();
    let identity = LoginIdentity { target: "host".into(), viewer_id: "v".into(), viewer_name: "v".into(), wire_session_id: 23, version: "test".into() };
    let permissions = Permissions { view_screen: true, ..Default::default() };
    let info = remote_protocol::desktop::PeerInfo { username: "".into(), hostname: "".into(), platform: "Windows".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let (_, logged_in) = tokio::join!(async {
        host.receive_password_login(WAIT).await.unwrap();
        host.authorize(permissions, &mut OwnerApproval::new(id, principal, Some(permissions))).unwrap();
        host.send_login_success(&info, WAIT).await.unwrap();
    }, viewer.login(&identity, "test", WAIT));
    logged_in.unwrap();
    let mut qos = SourceVideoQos::new(false);
    assert!(matches!(ProbeQos::new(id, 8, &qos), Err(ProbeQosError::Qos(QosError::InvalidPeer))));
    qos.add_peer(8).unwrap();
    let mut probe = ProbeQos::new(id, 8, &qos).unwrap();
    assert!(matches!(probe.send(&mut host, u32::MAX, WAIT).await, Err(ProbeQosError::InvalidBitrate)));
    assert!(matches!(probe.send(&mut host, 0, Duration::ZERO).await, Err(ProbeQosError::InvalidDeadline)));
    let (sent, seen) = tokio::join!(probe.send(&mut host, 1234, WAIT), viewer.receive(WAIT));
    sent.unwrap();
    let reply = match seen.unwrap() {
        ViewerEvent::TestDelay(value) => { assert!(!value.from_client); assert_eq!(value.last_delay, 0); assert_eq!(value.target_bitrate, 1234); value },
        _ => panic!("expected host TestDelay"),
    };
    assert!(matches!(probe.send(&mut host, 1234, WAIT).await, Err(ProbeQosError::Probe(remote_core::video_schedule::ScheduleError::AlreadyPending))));
    assert!(!probe.observe(&host, &mut qos, &HostEvent::Heartbeat, std::time::Instant::now()).unwrap());
    let mut wrong = reply; wrong.target_bitrate += 1;
    assert!(matches!(probe.observe(&host, &mut qos, &HostEvent::ProbeReply(wrong), std::time::Instant::now()), Err(ProbeQosError::Probe(remote_core::video_schedule::ScheduleError::InvalidReply))));
    // Simulated monotonic clock allows the source elapsed-QoS path without
    // waiting for a real network; no timer runs in the helper.
    let sample_at = std::time::Instant::now() + Duration::from_secs(3);
    assert!(probe.tick(&host, &mut qos, sample_at).unwrap());
    assert!(!probe.tick(&host, &mut qos, sample_at).unwrap());
    let event = host.receive_event(WAIT).await.unwrap();
    assert!(probe.observe(&host, &mut qos, &event, sample_at).unwrap());
    assert!(probe.last_delay_ms() >= 3000);
    assert!(matches!(probe.observe(&host, &mut qos, &event, sample_at), Err(ProbeQosError::Probe(remote_core::video_schedule::ScheduleError::NoPending))));
    probe.send(&mut host, 2000, WAIT).await.unwrap();
    let expired = std::time::Instant::now() + Duration::from_secs(61);
    assert!(matches!(probe.tick(&host, &mut qos, expired), Err(ProbeQosError::Probe(remote_core::video_schedule::ScheduleError::ProbeExpired))));
    assert!(matches!(probe.send(&mut host, 0, WAIT).await, Err(ProbeQosError::Probe(remote_core::video_schedule::ScheduleError::ProbeExpired))));
    qos.remove_peer(8).unwrap();
    assert!(matches!(probe.tick(&host, &mut qos, std::time::Instant::now()), Err(ProbeQosError::Qos(QosError::InvalidPeer))));
    viewer.close(); host.close().unwrap();
}

// Synthetic cancellation fixture: toggling the flag makes the next network
// send permanently pending without sending anything. No native desktop access.
struct PausableTcp {
    inner: LoopbackTcp,
    pause: Arc<std::sync::atomic::AtomicBool>,
}
struct ClosePaused<'a>(&'a mut LoopbackTcp);
impl Drop for ClosePaused<'_> { fn drop(&mut self) { self.0.close(); } }
impl NetworkTransport for PausableTcp {
    fn send<'a>(&'a mut self, bytes: &'a [u8], deadline: Duration) -> remote_transport::TransportFuture<'a, Result<(), remote_transport::NetworkTransportError>> {
        Box::pin(async move {
            if self.pause.load(std::sync::atomic::Ordering::SeqCst) {
                let _close_on_cancel = ClosePaused(&mut self.inner);
                std::future::pending::<Result<(), remote_transport::NetworkTransportError>>().await
            } else { NetworkTransport::send(&mut self.inner, bytes, deadline).await }
        })
    }
    fn receive(&mut self, deadline: Duration) -> remote_transport::TransportFuture<'_, Result<Box<[u8]>, remote_transport::NetworkTransportError>> {
        NetworkTransport::receive(&mut self.inner, deadline)
    }
    fn close(&mut self) { self.inner.close(); }
}

#[tokio::test]
async fn cancelled_probe_poisoning_requires_host_cleanup() {
    use remote_core::{probe_qos::{ProbeQos, ProbeQosError}, viewer_connection::{LoginIdentity, ViewerConnection}};
    use remote_codec::video_qos::SourceVideoQos;
    use std::sync::atomic::{AtomicBool, Ordering};
    let (socket, viewer_socket) = sockets().await;
    let paused = Arc::new(AtomicBool::new(false));
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([24; 16]).unwrap();
    let principal = Principal::new("holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test", "salt", WAIT).unwrap();
    let mut host = HostConnection::new(PausableTcp { inner: socket, pause: paused.clone() }, id, Fake::default(), verifier, permit, LIMIT).unwrap();
    let mut viewer = ViewerConnection::new(viewer_socket, LIMIT).unwrap();
    let identity = LoginIdentity { target: "host".into(), viewer_id: "v".into(), viewer_name: "v".into(), wire_session_id: 24, version: "test".into() };
    let permissions = Permissions { view_screen: true, ..Default::default() };
    let info = remote_protocol::desktop::PeerInfo { username: "".into(), hostname: "".into(), platform: "Windows".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let (_, logged_in) = tokio::join!(async {
        host.receive_password_login(WAIT).await.unwrap();
        host.authorize(permissions, &mut OwnerApproval::new(id, principal, Some(permissions))).unwrap();
        host.send_login_success(&info, WAIT).await.unwrap();
    }, viewer.login(&identity, "test", WAIT));
    logged_in.unwrap();
    let mut qos = SourceVideoQos::new(false); qos.add_peer(1).unwrap();
    let mut probe = ProbeQos::new(id, 1, &qos).unwrap();
    paused.store(true, Ordering::SeqCst);
    assert!(tokio::time::timeout(Duration::from_millis(20), probe.send(&mut host, 0, WAIT)).await.is_err());
    assert!(matches!(probe.tick(&host, &mut qos, std::time::Instant::now()), Err(ProbeQosError::Interrupted)));
    assert!(matches!(probe.send(&mut host, 0, WAIT).await, Err(ProbeQosError::Interrupted)));
    host.close().unwrap(); viewer.close();
}

#[tokio::test]
async fn explicit_viewer_factor_is_sent_only_after_prompt_and_never_retried() {
    use remote_core::viewer_connection::{LoginIdentity, TwoFactorSendOptIn, ViewerConnection, ViewerError};
    use remote_protocol::{desktop::PeerInfo, two_factor::{REQUIRE_2FA, WRONG_2FA_CODE}};
    for case in 0..5 {
        let (mut peer, socket) = sockets().await;
        let mut viewer = ViewerConnection::new(socket, LIMIT).unwrap();
        let identity = LoginIdentity { target: "host".into(), viewer_id: "viewer".into(), viewer_name: "viewer".into(), wire_session_id: 1, version: "test".into() };
        let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "test".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
        let ((), result) = tokio::join!(async {
            peer.send(&Envelope::password_challenge_event("salt", "challenge").unwrap().encode(LIMIT).unwrap(), WAIT).await.unwrap();
            let login = peer.receive(WAIT).await.unwrap();
            assert!(Envelope::decode(&login, LIMIT).unwrap().desktop_login().is_ok());
            if case != 3 {
                peer.send(&Envelope::desktop_login_error(REQUIRE_2FA).unwrap().encode(LIMIT).unwrap(), WAIT).await.unwrap();
                let factor = peer.receive(WAIT).await.unwrap();
                let factor = Envelope::decode(&factor, LIMIT).unwrap(); let request = factor.two_factor_request().unwrap();
                assert_eq!(request.code, "123456"); assert!(request.hardware_id.is_empty()); assert!(!request.trust_this_device);
            }
            if case == 4 {
                let probe = Envelope::test_delay_event(remote_protocol::TestDelay { time: 10, from_client: false, last_delay: 0, target_bitrate: 0 }).encode(LIMIT).unwrap();
                peer.send(&probe, WAIT).await.unwrap();
                assert_eq!(peer.receive(WAIT).await.unwrap(), probe);
            }
            let response = match case {
                0 | 3 | 4 => Envelope::desktop_login_success(&info).unwrap(),
                1 => Envelope::desktop_login_error(WRONG_2FA_CODE).unwrap(),
                _ => Envelope::desktop_login_error(REQUIRE_2FA).unwrap(),
            };
            peer.send(&response.encode(LIMIT).unwrap(), WAIT).await.unwrap();
        }, viewer.login_with_two_factor_code(&identity, "password", "123456", TwoFactorSendOptIn::acknowledge_code_disclosure_to_peer(), WAIT));
        match case {
            0 | 4 => assert!(result.is_ok()),
            1 => assert!(matches!(result, Err(ViewerError::Denied(reason)) if reason == WRONG_2FA_CODE)),
            2 => assert!(matches!(result, Err(ViewerError::Denied(reason)) if reason == REQUIRE_2FA)),
            _ => assert!(matches!(result, Err(ViewerError::TwoFactorNotRequested))),
        }
        viewer.close();
    }
}

#[tokio::test]
async fn source_unicode_host_opt_in_requires_permission_and_can_be_disabled() {
    use remote_core::viewer_connection::{LoginIdentity, ViewerConnection};
    use remote_input::SourceWindowsUnicodeOptIn;
    use remote_protocol::{desktop::PeerInfo, input::LegacyKey};
    let (socket, viewer_socket) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([125; 16]).unwrap(); let principal = Principal::new("holder".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test", "salt", WAIT).unwrap();
    let fake = Fake::default(); let calls = fake.0.clone();
    let mut host = HostConnection::new(socket, id, fake, verifier, permit, LIMIT).unwrap();
    let token = SourceWindowsUnicodeOptIn::acknowledge_source_surrogate_and_delivery_risks;
    assert!(host.enable_windows_source_unicode(token()).is_err());
    let mut viewer = ViewerConnection::new(viewer_socket, LIMIT).unwrap();
    let identity = LoginIdentity { target: "host".into(), viewer_id: "viewer".into(), viewer_name: "viewer".into(), wire_session_id: 1, version: "test".into() };
    let perms = Permissions { control_keyboard: true, ..Default::default() };
    let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "test".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let ((), result) = tokio::join!(async {
        host.receive_password_login(WAIT).await.unwrap();
        host.authorize(perms, &mut OwnerApproval::new(id, principal, Some(perms))).unwrap();
        host.send_login_success(&info, WAIT).await.unwrap();
    }, viewer.login(&identity, "test", WAIT)); result.unwrap();
    host.enable_windows_source_unicode(token()).unwrap();
    let text = Envelope::legacy_keyboard_event(LegacyKey::Sequence("😀"), true, false, &[]).unwrap();
    let (sent, received) = tokio::join!(viewer.send_input(&text, WAIT), host.receive_event(WAIT));
    sent.unwrap(); assert_eq!(received.unwrap(), remote_core::host_connection::HostEvent::Input);
    assert_eq!(&*calls.lock().unwrap(), &["text:😀"]);
    host.disable_windows_source_unicode().unwrap();
    host.restrict_permissions(Permissions::default()).unwrap();
    assert!(host.enable_windows_source_unicode(token()).is_err());
    viewer.close(); host.close().unwrap();
}

#[tokio::test]
async fn invalid_second_factor_is_rejected_before_login_io() {
    use remote_core::viewer_connection::{LoginIdentity, TwoFactorSendOptIn, ViewerConnection, ViewerError};
    let (mut peer, socket) = sockets().await;
    let mut viewer = ViewerConnection::new(socket, LIMIT).unwrap();
    let identity = LoginIdentity { target: "host".into(), viewer_id: "viewer".into(), viewer_name: "viewer".into(), wire_session_id: 1, version: "test".into() };
    assert!(matches!(viewer.login_with_two_factor_code(&identity, "password", "12345x", TwoFactorSendOptIn::acknowledge_code_disclosure_to_peer(), WAIT).await,
        Err(ViewerError::Protocol(remote_protocol::ProtocolError::InvalidAuthenticationField))));
    // Peer can still send its challenge and a subsequent basic login proceeds;
    // the invalid candidate did not start the viewer workflow or emit code.
    let info = remote_protocol::desktop::PeerInfo { username: "".into(), hostname: "".into(), platform: "test".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let ((), result) = tokio::join!(async {
        peer.send(&Envelope::password_challenge_event("salt", "challenge").unwrap().encode(LIMIT).unwrap(), WAIT).await.unwrap();
        let login = peer.receive(WAIT).await.unwrap(); assert!(Envelope::decode(&login, LIMIT).unwrap().desktop_login().is_ok());
        peer.send(&Envelope::desktop_login_success(&info).unwrap().encode(LIMIT).unwrap(), WAIT).await.unwrap();
    }, viewer.login(&identity, "password", WAIT));
    assert!(result.is_ok()); viewer.close();
}

#[test]
fn peer_error_strings_are_not_in_default_debug() {
    use remote_core::{host_connection::ConnectionError, viewer_connection::ViewerError};
    let text = "untrusted-secret\x1b[31m".to_owned();
    assert!(!format!("{:?}", ConnectionError::PeerClosed(Some(text.clone()))).contains("untrusted-secret"));
    assert!(!format!("{:?}", ViewerError::PeerClosed(Some(text.clone()))).contains("untrusted-secret"));
    assert!(!format!("{:?}", ViewerError::Denied(text.clone())).contains("untrusted-secret"));
}

#[tokio::test]
async fn explicit_cursor_delivery_uses_shape_id_and_resend_in_one_session() {
    use remote_core::{cursor_delivery::{AnnouncementKind, CursorDelivery}, viewer_connection::{LoginIdentity, ViewerConnection, ViewerEvent}};
    use remote_protocol::{cursor::CursorShape, desktop::PeerInfo};
    let (socket, viewer_socket) = sockets().await;
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([91; 16]).unwrap();
    let principal = Principal::new("local-owner".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test-only", "salt", WAIT).unwrap();
    let mut host = HostConnection::new(socket, id, Fake::default(), verifier, permit, LIMIT).unwrap();
    let mut viewer = ViewerConnection::new(viewer_socket, LIMIT).unwrap();
    let identity = LoginIdentity { target: "host".into(), viewer_id: "viewer".into(), viewer_name: "viewer".into(), wire_session_id: 91, version: "test".into() };
    let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "test".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let permissions = Permissions { view_screen: true, ..Default::default() };
    let (_, login) = tokio::join!(async {
        host.receive_password_login(WAIT).await.unwrap();
        host.authorize(permissions, &mut OwnerApproval::new(id, principal, Some(permissions))).unwrap();
        host.send_login_success(&info, WAIT).await.unwrap();
    }, viewer.login(&identity, "test-only", WAIT));
    login.unwrap();
    let mut shape = CursorShape { id: 0, hotx: 0, hoty: 0, width: 1, height: 1, rgba: vec![1, 2, 3, 4] };
    shape.id = shape.source_content_id().unwrap();
    let mut wrong = CursorDelivery::new(SessionId::new([92; 16]).unwrap(), 2, 8).unwrap();
    assert!(host.send_cursor_announcement(&mut wrong, shape.clone(), false, WAIT).await.is_err());
    assert!(wrong.is_empty());
    let mut book = CursorDelivery::new(id, 2, 8).unwrap();
    let (sent, received) = tokio::join!(host.send_cursor_announcement(&mut book, shape.clone(), false, WAIT), viewer.receive(WAIT));
    assert_eq!(sent.unwrap(), AnnouncementKind::Shape);
    assert!(matches!(received.unwrap(), ViewerEvent::CursorShape(value) if value == shape));
    let (sent, received) = tokio::join!(host.send_cursor_announcement(&mut book, shape.clone(), false, WAIT), viewer.receive(WAIT));
    assert_eq!(sent.unwrap(), AnnouncementKind::Id);
    assert!(matches!(received.unwrap(), ViewerEvent::CursorId(value) if value == shape.id));
    assert!(!host.resend_cursor_announcement(&mut book, u64::MAX, WAIT).await.unwrap());
    let (requested, event) = tokio::join!(viewer.request_cursor_shape(shape.id, WAIT), host.receive_event(WAIT));
    requested.unwrap();
    assert!(matches!(event.unwrap(), remote_core::host_connection::HostEvent::CursorShapeRequest(id) if id == shape.id));
    let (sent, received) = tokio::join!(host.resend_cursor_announcement(&mut book, shape.id, WAIT), viewer.receive(WAIT));
    assert!(sent.unwrap());
    assert!(matches!(received.unwrap(), ViewerEvent::CursorShape(value) if value == shape));
    host.close().unwrap(); viewer.close();
}

// Synthetic wrapper: closes before an injected uncertain result/stall. It does
// not emulate partial TCP writes or prove remote delivery/cancellation safety.
struct CursorFaultTransport {
    inner: LoopbackTcp,
    action: Arc<std::sync::atomic::AtomicU8>,
}
impl NetworkTransport for CursorFaultTransport {
    fn send<'a>(&'a mut self, bytes: &'a [u8], deadline: Duration)
        -> remote_transport::TransportFuture<'a, Result<(), remote_transport::NetworkTransportError>> {
        use std::sync::atomic::Ordering;
        let action = self.action.swap(0, Ordering::AcqRel);
        if action == 0 { return NetworkTransport::send(&mut self.inner, bytes, deadline); }
        self.inner.close();
        Box::pin(async move {
            if action == 2 { std::future::pending::<()>().await; }
            Err(remote_transport::NetworkTransportError::SendOutcomeUnknown("synthetic fault".into()))
        })
    }
    fn receive(&mut self, deadline: Duration)
        -> remote_transport::TransportFuture<'_, Result<Box<[u8]>, remote_transport::NetworkTransportError>> {
        NetworkTransport::receive(&mut self.inner, deadline)
    }
    fn close(&mut self) { self.inner.close(); }
}
async fn cursor_fault_session() -> (HostConnection<CursorFaultTransport, Fake>, remote_core::viewer_connection::ViewerConnection<LoopbackTcp>, Arc<std::sync::atomic::AtomicU8>, SessionId) {
    use remote_core::viewer_connection::{LoginIdentity, ViewerConnection};
    use remote_protocol::desktop::PeerInfo;
    let (socket, viewer_socket) = sockets().await;
    let action = Arc::new(std::sync::atomic::AtomicU8::new(0));
    let transport = CursorFaultTransport { inner: socket, action: action.clone() };
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let id = SessionId::new([93; 16]).unwrap();
    let principal = Principal::new("local-owner".into()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test-only", "salt", WAIT).unwrap();
    let mut host = HostConnection::new(transport, id, Fake::default(), verifier, permit, LIMIT).unwrap();
    let mut viewer = ViewerConnection::new(viewer_socket, LIMIT).unwrap();
    let identity = LoginIdentity { target: "host".into(), viewer_id: "viewer".into(), viewer_name: "viewer".into(), wire_session_id: 93, version: "test".into() };
    let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "test".into(), version: "test".into(), displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let permissions = Permissions { view_screen: true, ..Default::default() };
    let (_, login) = tokio::join!(async {
        host.receive_password_login(WAIT).await.unwrap();
        host.authorize(permissions, &mut OwnerApproval::new(id, principal, Some(permissions))).unwrap();
        host.send_login_success(&info, WAIT).await.unwrap();
    }, viewer.login(&identity, "test-only", WAIT));
    login.unwrap();
    (host, viewer, action, id)
}
#[tokio::test]
async fn cursor_send_failure_and_cancellation_poison_the_delivery_book() {
    use remote_core::cursor_delivery::CursorDelivery;
    use remote_protocol::cursor::CursorShape;
    use std::sync::atomic::Ordering;
    let mut shape = CursorShape { id: 0, hotx: 0, hoty: 0, width: 1, height: 1, rgba: vec![1, 2, 3, 4] };
    shape.id = shape.source_content_id().unwrap();
    let (mut host, mut viewer, action, id) = cursor_fault_session().await;
    let mut book = CursorDelivery::new(id, 2, 8).unwrap();
    action.store(1, Ordering::Release);
    assert!(host.send_cursor_announcement(&mut book, shape.clone(), false, WAIT).await.is_err());
    assert!(book.is_poisoned()); assert_eq!(host.state(), SessionState::Closed);
    viewer.close();
    let (mut host, mut viewer, action, id) = cursor_fault_session().await;
    let mut book = CursorDelivery::new(id, 2, 8).unwrap();
    action.store(2, Ordering::Release);
    assert!(tokio::time::timeout(Duration::from_millis(10), host.send_cursor_announcement(&mut book, shape, false, WAIT)).await.is_err());
    assert!(book.is_poisoned());
    // Cancellation leaves the host Busy; the embedding application must close.
    host.close().unwrap(); viewer.close();
}

#[tokio::test]
async fn windows_session_claims_are_bounded_and_selection_is_wire_only() {
    use remote_core::viewer_connection::{LoginIdentity, ViewerConnection, ViewerEvent};
    use remote_protocol::{desktop::PeerInfo, windows_sessions::{SessionSwitchOptIn, WindowsSession, WindowsSessions}};
    let (mut source, socket) = sockets().await;
    let mut viewer = ViewerConnection::new(socket, LIMIT).unwrap();
    let identity = LoginIdentity { target: "host".into(), viewer_id: "v".into(), viewer_name: "v".into(), wire_session_id: 1, version: "test".into() };
    let info = PeerInfo { username: "".into(), hostname: "".into(), platform: "Windows".into(), version: "test".into(),
        displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
    let claims = WindowsSessions { current_sid: 2, sessions: vec![WindowsSession { sid: 1, name: "console".into() }, WindowsSession { sid: 2, name: "RDP".into() }] };
    let (_, result) = tokio::join!(async {
        source.send(&Envelope::password_challenge_event("salt", "challenge").unwrap().encode(LIMIT).unwrap(), WAIT).await.unwrap();
        source.receive(WAIT).await.unwrap();
        let mut login = Envelope::desktop_login_success(&info).unwrap();
        login.set_windows_sessions(Some(&claims)).unwrap();
        login.set_feature_claims(Some(remote_protocol::platform_metadata::FeatureClaims { privacy_mode: true, terminal: false, port_forward_mux: false })).unwrap();
        login.set_platform_additions(r#"{"is_installed":true}"#).unwrap();
        source.send(&login.encode(LIMIT).unwrap(), WAIT).await.unwrap();
    }, viewer.login(&identity, "test", WAIT));
    result.unwrap();
    assert_eq!(viewer.windows_sessions(), Some(&claims));
    assert!(viewer.feature_claims().unwrap().privacy_mode);
    assert_eq!(viewer.platform_additions(), Some(r#"{"is_installed":true}"#));
    let (sent, raw) = tokio::join!(viewer.select_windows_session(1, SessionSwitchOptIn::acknowledge_remote_session_switch_risk(), WAIT), source.receive(WAIT));
    sent.unwrap();
    assert_eq!(Envelope::decode(&raw.unwrap(), LIMIT).unwrap().selected_windows_session().unwrap(), 1);
    // A full PeerInfo update without the optional field clears stale claims.
    let update = Envelope::desktop_peer_info_event(&info).unwrap().encode(LIMIT).unwrap();
    let (sent, received) = tokio::join!(source.send(&update, WAIT), viewer.receive(WAIT));
    sent.unwrap(); assert!(matches!(received.unwrap(), ViewerEvent::PeerInfo(_)));
    assert!(viewer.windows_sessions().is_none());
    assert!(viewer.feature_claims().is_none());
    assert_eq!(viewer.platform_additions(), Some(""));
    viewer.close(); assert!(viewer.windows_sessions().is_none());
    assert!(viewer.platform_additions().is_none());
}
