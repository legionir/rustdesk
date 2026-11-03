//! Opt-in disposable desktop test. Reads local screen content; no images logged.
//! This exercises an experimental loopback stack, not authentication or privacy.
use remote_codec::{Codec, EncoderConfig, RepeatFrameOptIn};
use remote_core::{capture_pump::CapturePumpError, host_connection::{ConnectionError, HostConnection}, viewer_connection::{LoginIdentity, ViewerConnection, ViewerEvent}};
use remote_input::{InputBackend, MouseButton, VirtualKey};
use remote_protocol::desktop::{DisplayInfo, PeerInfo};
use remote_rustdesk_websocket::tcp::{LoopbackTcp, LoopbackTcpListener};
use remote_security::{admission::{AdmissionController, AdmissionLimits}, OwnerApproval, PasswordVerifier};
use remote_session::{Permissions, Principal, SessionId};
use std::{io, time::Duration};

struct NoInput;
impl InputBackend for NoInput {
    fn move_to(&mut self, _: i32, _: i32) -> io::Result<()> { Err(io::ErrorKind::PermissionDenied.into()) }
    fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { Err(io::ErrorKind::PermissionDenied.into()) }
    fn mouse_up(&mut self, _: MouseButton) -> io::Result<()> { Err(io::ErrorKind::PermissionDenied.into()) }
    fn scroll(&mut self, _: i32, _: i32) -> io::Result<()> { Err(io::ErrorKind::PermissionDenied.into()) }
    fn key_down(&mut self, _: VirtualKey) -> io::Result<()> { Err(io::ErrorKind::PermissionDenied.into()) }
    fn key_up(&mut self, _: VirtualKey) -> io::Result<()> { Err(io::ErrorKind::PermissionDenied.into()) }
}

#[tokio::test]
async fn explicit_repeat_requires_owned_authorized_capture() {
    if std::env::var_os("REMOTE_CORE_TEST_DISPLAY").as_deref() != Some(std::ffi::OsStr::new("1")) { return; }
    const LIMIT: usize = 8 * 1024 * 1024; const WAIT: Duration = Duration::from_secs(15);
    let display = remote_capture::displays().unwrap().into_iter().next().expect("authorized test display");
    let meta = display.info().clone();
    let width = u32::try_from(meta.width).unwrap(); let height = u32::try_from(meta.height).unwrap();
    assert!(width >= 2 && height >= 2 && width <= 4096 && height <= 4096 && width % 2 == 0 && height % 2 == 0);
    let listener = LoopbackTcpListener::bind("127.0.0.1:0".parse().unwrap(), LIMIT, WAIT).await.unwrap();
    let (viewer_socket, host_socket) = tokio::join!(LoopbackTcp::connect(listener.local_addr().unwrap(), LIMIT, WAIT), listener.accept(WAIT));
    let id = SessionId::new([72; 16]).unwrap(); let principal = Principal::new("repeat-test".into()).unwrap();
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test-only", "test-salt", WAIT).unwrap();
    let mut host = HostConnection::new(host_socket.unwrap(), id, NoInput, verifier, permit, LIMIT).unwrap();
    let mut viewer = ViewerConnection::new(viewer_socket.unwrap(), LIMIT).unwrap();
    let permissions = Permissions { view_screen: true, ..Default::default() };
    let info = PeerInfo { username: String::new(), hostname: String::new(), platform: "test".into(), version: "test".into(),
        displays: vec![DisplayInfo { x: meta.x, y: meta.y, width: width as i32, height: height as i32,
            name: String::new(), online: meta.online, cursor_embedded: false, scale: 0.0 }], current_display: 0, sas_enabled: false, encoding: None };
    let identity = LoginIdentity { target: "host".into(), viewer_id: "viewer".into(), viewer_name: "viewer".into(), wire_session_id: 1, version: "test".into() };
    let ((), login) = tokio::join!(async {
        host.receive_password_login(WAIT).await.unwrap();
        host.authorize(permissions, &mut OwnerApproval::new(id, principal, Some(permissions))).unwrap();
        host.send_login_success(&info, WAIT).await.unwrap();
    }, viewer.login(&identity, "test-only", WAIT));
    login.unwrap();
    let config = EncoderConfig { codec: Codec::Vp9, width, height, quality: 1.0, keyframe_interval: Some(30) };
    let mut pump = host.start_capture(display, 0, config, LIMIT).unwrap();
    assert!(!pump.has_repeatable_input());
    let ((), received) = tokio::join!(async {
        for n in 0..100 {
            match host.send_capture(&mut pump, Duration::from_millis(100), WAIT, n * 100).await {
                Ok(()) => return,
                Err(ConnectionError::Capture(CapturePumpError::Capture(e))) if e.kind() == io::ErrorKind::WouldBlock => tokio::time::sleep(Duration::from_millis(20)).await,
                other => panic!("capture: {other:?}"),
            }
        }
        panic!("no initial frame");
    }, viewer.receive(WAIT));
    assert!(matches!(received.unwrap(), ViewerEvent::Video { display: 0, .. }));
    assert!(pump.has_repeatable_input());
    let (result, received) = tokio::join!(
        host.send_capture_repeat_outcome(&mut pump, 10000, WAIT, RepeatFrameOptIn::acknowledge_cached_screen_pixels()),
        viewer.receive(WAIT)
    );
    match result {
        Ok(remote_core::video::SendOutcome::Sent) => assert!(matches!(received.unwrap(), ViewerEvent::Video { display: 0, .. })),
        Ok(remote_core::video::SendOutcome::VpxNoOutput) => {
            assert!(received.is_err()); assert!(!pump.needs_reset()); assert!(pump.has_repeatable_input());
        },
        Err(ConnectionError::Capture(CapturePumpError::Video(_))) => assert!(pump.needs_reset()),
        other => panic!("repeat: {other:?}"),
    }
    host.stop_capture(&mut pump).unwrap();
    assert!(!pump.has_repeatable_input());
    host.close().unwrap(); viewer.close();
}
