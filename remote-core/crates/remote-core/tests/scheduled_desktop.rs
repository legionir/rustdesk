//! Deferred opt-in desktop integration, not a security or interoperability test.
//! It captures private display content; run only on a disposable Xvfb desktop or
//! explicitly consented interactive desktop with REMOTE_CORE_TEST_DISPLAY=1.
use hbb_common::sodiumoxide::{self, crypto::sign};
use remote_codec::{Codec, EncoderConfig};
use remote_core::{capture_budget::{BudgetLimits, CaptureBudget}, capture_pump::CapturePumpError,
    host_connection::{ConnectionError, HostConnection, HostEvent},
    scheduled_capture::{OutcomeStep, ScheduledCapture, ScheduledCaptureError}, scheduled_refresh::{RepeatStep, RefreshSessionError, ScheduledRefresh}, scheduled_session::{DriveOutcomeStep, DriverError, ScheduledSession},
    video::VideoReceiver, viewer_connection::{LoginIdentity, ViewerConnection, ViewerEvent}};
use remote_input::{InputBackend, MouseButton, VirtualKey};
use remote_protocol::{desktop::{DisplayInfo, PeerInfo}, video_control::VideoControl};
use remote_rustdesk_websocket::{direct_tcp::{DirectTcp, DirectTcpListener, DirectTcpOptIn}, duplex_tcp::UpgradeableEncryptedTcp,
    source_crypto::{accept_pinned_host, connect_pinned_host}};
use remote_security::{admission::{AdmissionController, AdmissionLimits}, OwnerApproval, PasswordVerifier};
use remote_session::{Permissions, Principal, SessionId};
use std::{io, time::{Duration, Instant}};

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
async fn budgeted_session_captures_one_local_frame_and_routes_control() {
    if std::env::var_os("REMOTE_CORE_TEST_DISPLAY").as_deref() != Some(std::ffi::OsStr::new("1")) { return; }
    const PRE: usize = 128 * 1024; const LIMIT: usize = 8 * 1024 * 1024; const WAIT: Duration = Duration::from_secs(15);
    sodiumoxide::init().unwrap();
    let display = remote_capture::displays().unwrap().into_iter().next().expect("authorized test display");
    let metadata = display.info().clone();
    let width = u32::try_from(metadata.width).unwrap(); let height = u32::try_from(metadata.height).unwrap();
    assert!(width >= 2 && height >= 2 && width <= 4096 && height <= 4096 && width % 2 == 0 && height % 2 == 0);
    let config = EncoderConfig { codec: Codec::Vp9, width, height, quality: 1.0, keyframe_interval: Some(30) };
    let listener = DirectTcpListener::bind("127.0.0.1:0".parse().unwrap(), PRE, WAIT, DirectTcpOptIn::acknowledge_plaintext_transport()).await.unwrap();
    let address = listener.local_addr().unwrap(); let (pin, secret) = sign::gen_keypair();
    let (host_socket, viewer_socket) = tokio::join!(async {
        let (socket, _) = listener.accept(WAIT).await.unwrap();
        UpgradeableEncryptedTcp::new(accept_pinned_host(socket, "test-host", &secret, PRE - 16, WAIT).await.unwrap())
    }, async {
        let socket = DirectTcp::connect(address, PRE, WAIT, DirectTcpOptIn::acknowledge_plaintext_transport()).await.unwrap();
        connect_pinned_host(socket, "test-host", &pin, PRE - 16, WAIT).await.unwrap()
    });
    let id = SessionId::new([61; 16]).unwrap(); let principal = Principal::new("local-test".into()).unwrap();
    let admission = AdmissionController::new(AdmissionLimits::default()).unwrap();
    let permit = admission.admit("127.0.0.1".parse().unwrap()).unwrap();
    let verifier = PasswordVerifier::new(id, principal.clone(), "test-only", "test-salt", WAIT).unwrap();
    let mut host = HostConnection::new(host_socket, id, NoInput, verifier, permit, PRE - 16).unwrap();
    let mut viewer = ViewerConnection::new(viewer_socket, PRE - 16).unwrap();
    let identity = LoginIdentity { target: "test-host".into(), viewer_id: "viewer".into(), viewer_name: "viewer".into(), wire_session_id: 1, version: "test".into() };
    let perms = Permissions { view_screen: true, ..Default::default() };
    let peer = PeerInfo { username: String::new(), hostname: String::new(), platform: "test".into(), version: "test".into(),
        displays: vec![DisplayInfo { x: metadata.x, y: metadata.y, width: width as i32, height: height as i32,
            name: String::new(), online: true, cursor_embedded: false, scale: 0.0 }], current_display: 0, sas_enabled: false, encoding: None };
    let ((), login) = tokio::join!(async {
        host.receive_password_login(WAIT).await.unwrap();
        host.authorize(perms, &mut OwnerApproval::new(id, principal, Some(perms))).unwrap();
        host.set_authorized_message_limit(LIMIT).unwrap(); host.send_login_success(&peer, WAIT).await.unwrap();
    }, viewer.login(&identity, "test-only", WAIT));
    login.unwrap(); viewer.set_connected_message_limit(LIMIT).unwrap();
    let budget = CaptureBudget::new(BudgetLimits { leases: 1, streams: 1, pixels: u64::from(width) * u64::from(height) }).unwrap();
    let group = host.start_multi_capture_budgeted(vec![(display, 0, config)], LIMIT, &budget).unwrap();
    let scheduler = match ScheduledCapture::new(group, 10) { Ok(value) => value, Err((e, _)) => panic!("scheduler: {e}") };
    let mut driver = match ScheduledSession::new(host, scheduler, None) { Ok(value) => value, Err((e, _, _)) => panic!("session: {e}") };
    viewer.send_video_control(VideoControl::RefreshAll, WAIT).await.unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(event) = driver.poll_event(WAIT).await.unwrap() {
            assert_eq!(event, HostEvent::VideoControl(VideoControl::RefreshAll)); break;
        }
        assert!(Instant::now() < until, "control message was not received");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut refresh = ScheduledRefresh::new(&driver, &[(0, Codec::Vp9)], Duration::from_secs(30)).unwrap();
    assert!(matches!(ScheduledRefresh::new(&driver, &[(0, Codec::Vp9), (0, Codec::Vp9)], Duration::from_secs(1)), Err(RefreshSessionError::InvalidConfiguration)));
    assert_eq!(refresh.repeat(&mut driver, 0, Duration::from_millis(100), 1.0, false, true, WAIT, 0).await.unwrap(), RepeatStep::NoInput);
    let (sent, received) = tokio::join!(async {
        let mut repeat_cached = false;
        for attempt in 0..100 {
            if repeat_cached {
                match refresh.repeat(&mut driver, 0, Duration::from_millis(100), 1.0, false, true, WAIT, attempt * 100).await {
                    Ok(RepeatStep::Sent) => return,
                    Ok(RepeatStep::VpxNoOutput) => tokio::time::sleep(Duration::from_millis(100)).await,
                    Ok(RepeatStep::Wait(delay)) => tokio::time::sleep(delay.min(Duration::from_millis(50))).await,
                    other => panic!("unexpected repeat step: {other:?}"),
                }
                continue;
            }
            match refresh.drive_once(&mut driver, Duration::from_millis(100), WAIT, attempt * 100).await {
                Ok(DriveOutcomeStep::Capture(OutcomeStep::Sent(0))) => return,
                Ok(DriveOutcomeStep::Capture(OutcomeStep::VpxNoOutput(0))) => repeat_cached = true,
                Ok(DriveOutcomeStep::Capture(OutcomeStep::Wait(delay))) => tokio::time::sleep(delay.min(Duration::from_millis(50))).await,
                Ok(DriveOutcomeStep::Event(event)) => panic!("unexpected queued event: {event:?}"),
                Err(RefreshSessionError::Driver(DriverError::Capture(ScheduledCaptureError::Connection(ConnectionError::Capture(CapturePumpError::Capture(e))))))
                    if e.kind() == io::ErrorKind::WouldBlock => tokio::time::sleep(Duration::from_millis(20)).await,
                other => panic!("unexpected capture step: {other:?}"),
            }
        }
        panic!("display did not produce a frame");
    }, viewer.receive(WAIT));
    let _ = sent;
    let envelope = match received.unwrap() { ViewerEvent::Video { display: 0, envelope, .. } => envelope, _ => panic!("expected video") };
    let mut decoder = VideoReceiver::new(Codec::Vp9, LIMIT).unwrap();
    let frame = decoder.decode(&envelope).unwrap().expect("first local frame");
    assert_eq!((frame.frame.width, frame.frame.height), (width as usize, height as usize));
    assert!(matches!(refresh.repeat(&mut driver, 0, Duration::from_millis(100), 1.0, false, false, WAIT, 0).await,
        Err(RefreshSessionError::ConsentRequired)));
    assert!(matches!(refresh.repeat(&mut driver, 0, Duration::from_millis(100), 1.0, false, true, WAIT, 0).await, Err(RefreshSessionError::Interrupted)));
    // Fixture continues below only to exercise cleanup and GDI behavior; a real
    // consent denial requires the caller to close/drop the session immediately.
    // Reconfiguration, GDI and revocation below require a new manager.
    drop(refresh);
    #[cfg(target_os = "windows")]
    if std::env::var_os("REMOTE_CORE_TEST_GDI").as_deref() == Some(std::ffi::OsStr::new("1")) {
        // Separately opted-in: a backend switch may change desktop behavior.
        if !driver.is_gdi(0).unwrap() {
            assert!(driver.use_gdi(0, remote_capture::GdiFallbackOptIn::acknowledge_backend_change()).unwrap());
            assert!(driver.is_gdi(0).unwrap());
            tokio::time::sleep(Duration::from_millis(120)).await;
            assert!(matches!(driver.capture_step(Instant::now(), Duration::from_millis(100), WAIT, 0).await,
                Err(DriverError::Capture(ScheduledCaptureError::Connection(ConnectionError::Capture(CapturePumpError::Video(remote_core::video::VideoError::EncoderResetRequired)))))));
            // A reset explicitly follows local viewer/decoder coordination.
            driver.reset_encoder(0, config).unwrap();
            assert!(!driver.use_gdi(0, remote_capture::GdiFallbackOptIn::acknowledge_backend_change()).unwrap());
            tokio::time::sleep(Duration::from_millis(120)).await;
            assert!(matches!(driver.capture_step(Instant::now(), Duration::from_millis(100), WAIT, 0).await,
                Err(DriverError::Capture(ScheduledCaptureError::Connection(ConnectionError::Capture(CapturePumpError::Video(remote_core::video::VideoError::EncoderResetRequired)))))));
        }
    }
    driver.restrict_permissions(Permissions::default()).unwrap();
    assert_eq!(budget.usage().unwrap(), BudgetLimits { leases: 0, streams: 0, pixels: 0 });
    driver.close().unwrap(); drop(driver); viewer.close();
}
