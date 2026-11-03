#![cfg(feature = "source-security")]
//! Deferred bounded service-loop integration; not an interop/security test.
//! It captures private display content; run only on a disposable Xvfb desktop or
//! explicitly consented interactive desktop with REMOTE_CORE_TEST_DISPLAY=1.
use hbb_common::sodiumoxide::{self, crypto::sign};
use remote_codec::{Codec, EncoderConfig};
use remote_core::{capture_budget::{BudgetLimits, CaptureBudget}, host_connection::{HostConnection, HostEvent},
    scheduled_capture::ScheduledCapture, scheduled_session::ScheduledSession,
    viewer_connection::{LoginIdentity, ViewerConnection, ViewerEvent}};
use remote_input::{InputBackend, MouseButton, VirtualKey};
use remote_protocol::{desktop::{DisplayInfo, PeerInfo}, video_control::VideoControl};
use remote_rustdesk_websocket::{direct_tcp::{DirectTcp, DirectTcpListener, DirectTcpOptIn}, duplex_tcp::UpgradeableEncryptedTcp,
    source_crypto::{accept_pinned_host, connect_pinned_host}};
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
async fn bounded_loop_services_a_local_viewer_and_stops() {
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
    let driver = match ScheduledSession::new(host, scheduler, None) { Ok(value) => value, Err((e, _, _)) => panic!("session: {e}") };
    use remote_core::bounded_host_loop::{self, EventDecision, Limits, Stop, StopReason};
    let stop = Stop::default();
    let viewer_stop = stop.clone();
    viewer.send_video_control(VideoControl::RefreshAll, WAIT).await.unwrap();
    let service = bounded_host_loop::run(driver, stop, Limits {
        duration: Duration::from_secs(10), max_steps: 10000,
        capture_wait: Duration::from_millis(100), send_wait: Duration::from_secs(1),
    }, |event, _| {
        match event {
            HostEvent::VideoControl(VideoControl::RefreshAll) | HostEvent::Heartbeat => Ok(EventDecision::Continue),
            _ => Err(std::io::Error::new(io::ErrorKind::Other, "unexpected local event").into()),
        }
    });
    let receive = async {
        let event = viewer.receive(WAIT).await.unwrap();
        assert!(matches!(event, ViewerEvent::Video { display: 0, .. }));
        viewer_stop.request();
        // Keep the serial viewer alive until the service observes the stop,
        // so EOF cannot race against read-ahead and hide the received frame.
    };
    let (result, ()) = tokio::join!(service, receive);
    match result {
        Ok(report) => assert_eq!(report.reason, StopReason::Requested),
        Err(mut error) => {
            // A stop can cancel while the host phase is Busy. Capture-stop
            // bookkeeping then reports InvalidState even though host close runs.
            // Require that exact cleanup error; do not hide unrelated failures.
            assert!(error.cause.is_none());
            assert!(matches!(&error.cleanup,
                Some(remote_core::scheduled_session::DriverError::Cleanup {
                    capture: Some(remote_core::scheduled_capture::ScheduledCaptureError::Connection(
                        remote_core::host_connection::ConnectionError::InvalidState)), connection: None,
                })));
            error.retry_cleanup().unwrap();
        },
    }
    // A stop may win after the frame was delivered but before the sender
    // records its completed step. Counts are observations, not receipts.
    assert_eq!(budget.usage().unwrap(), BudgetLimits { leases: 0, streams: 0, pixels: 0 });
    viewer.close();
}
