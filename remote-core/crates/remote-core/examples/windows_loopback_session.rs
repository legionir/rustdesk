//! Manual, untested integration example: one interactive Windows desktop,
//! one process, encrypted loopback TCP and one captured VP9 frame. It captures
//! private screen contents. Do not run without local user consent.
//!
//! This is a demo of provisional adapters, NOT a production server or security
//! assurance. It uses an ephemeral host signing key and a fixed demo password;
//! no remote access, input injection, rendering, owner UI or key persistence.

#[cfg(not(windows))]
fn main() { eprintln!("This example requires an interactive Windows desktop."); }

#[cfg(windows)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use hbb_common::sodiumoxide::{self, crypto::sign};
    use remote_capture::displays;
    use remote_codec::{Codec, EncoderConfig};
    use remote_core::{host_connection::HostConnection, video::VideoReceiver,
        viewer_connection::{LoginIdentity, ViewerConnection, ViewerEvent}};
    use remote_input::windows::WindowsInput;
    use remote_protocol::desktop::{DisplayInfo, PeerInfo};
    use remote_rustdesk_websocket::{direct_tcp::{DirectTcp, DirectTcpListener, DirectTcpOptIn},
        source_crypto::{accept_pinned_host, connect_pinned_host}};
    use remote_security::{admission::{AdmissionController, AdmissionLimits}, OwnerApproval, PasswordVerifier};
    use remote_session::{Permissions, Principal, SessionId};
    use std::{io, time::Duration};

    if std::env::args().nth(1).as_deref() != Some("--confirm-local-screen-capture") {
        return Err("Pass --confirm-local-screen-capture only on a disposable interactive desktop".into());
    }
    sodiumoxide::init().map_err(|_| io::Error::new(io::ErrorKind::Other, "sodium initialization failed"))?;
    let displays = displays()?;
    let display = displays.into_iter().next().ok_or("no display available")?;
    let metadata = display.info().clone();
    let width = u32::try_from(metadata.width)?;
    let height = u32::try_from(metadata.height)?;
    if width < 2 || height < 2 || width > 4096 || height > 4096 || width % 2 != 0 || height % 2 != 0 {
        return Err("display dimensions unsupported by this demo's software encoder".into());
    }
    const WAIT: Duration = Duration::from_secs(30);
    const PREAUTH_FRAME: usize = 128 * 1024;
    const VIDEO_FRAME: usize = 8 * 1024 * 1024;
    const HOST_ID: &str = "temporary-loopback-host";
    const PASSWORD: &str = "loopback-demo-only";
    let config = EncoderConfig { codec: Codec::Vp9, width, height, quality: 1.0, keyframe_interval: Some(30) };
    let opt = DirectTcpOptIn::acknowledge_plaintext_transport();
    let listener = DirectTcpListener::bind("127.0.0.1:0".parse()?, PREAUTH_FRAME, WAIT, opt).await?;
    let address = listener.local_addr()?;
    let (pin, secret) = sign::gen_keypair();
    let admission = AdmissionController::new(AdmissionLimits::default())?;
    let mut id_bytes = [0; 16];
    getrandom::getrandom(&mut id_bytes).map_err(|_| io::Error::new(io::ErrorKind::Other, "random ID unavailable"))?;
    let id = SessionId::new(id_bytes)?;
    let principal = Principal::new("loopback-demo".into())?;
    let permissions = Permissions { view_screen: true, ..Default::default() };

    let host = async {
        let (socket, peer) = listener.accept(WAIT).await?;
        // Admission is obtained before the identity handshake, and retained
        // through password validation and explicit local approval.
        let permit = admission.admit(peer.ip())?;
        let socket = accept_pinned_host(socket, HOST_ID, &secret, PREAUTH_FRAME - 16, WAIT).await?;
        let verifier = PasswordVerifier::new(id, principal.clone(), PASSWORD, "loopback-demo-salt", WAIT)?;
        let mut host = HostConnection::new(socket, id, WindowsInput::new(), verifier, permit, PREAUTH_FRAME - 16)?;
        host.receive_password_login(WAIT).await?;
        // The command-line confirmation is demo consent only, not a trusted UI.
        let mut policy = OwnerApproval::new(id, principal, Some(permissions));
        host.authorize(permissions, &mut policy)?;
        host.set_authorized_message_limit(VIDEO_FRAME)?;
        let info = PeerInfo { username: String::new(), hostname: String::new(), platform: "Windows".into(), version: "demo".into(),
            displays: vec![DisplayInfo { x: metadata.x, y: metadata.y, width: width as i32, height: height as i32,
                name: String::new(), online: metadata.online, cursor_embedded: false, scale: 0.0 }],
            current_display: 0, sas_enabled: false, encoding: None };
        host.send_login_success(&info, WAIT).await?;
        let mut pump = host.start_capture(display, 0, config, VIDEO_FRAME)?;
        let mut sent = false;
        for attempt in 0..50 {
            match host.send_capture(&mut pump, Duration::from_millis(100), WAIT, attempt * 100).await {
                Ok(()) => { sent = true; break; },
                Err(remote_core::host_connection::ConnectionError::Capture(remote_core::capture_pump::CapturePumpError::Capture(error)))
                    if error.kind() == io::ErrorKind::WouldBlock => tokio::time::sleep(Duration::from_millis(50)).await,
                Err(error) => return Err(Box::<dyn std::error::Error>::from(error)),
            }
        }
        if !sent { return Err(Box::<dyn std::error::Error>::from("capture did not produce a frame")); }
        host.stop_capture(&mut pump)?; drop(pump); host.close()?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let viewer = async {
        let socket = DirectTcp::connect(address, PREAUTH_FRAME, WAIT, opt).await?;
        let socket = connect_pinned_host(socket, HOST_ID, &pin, PREAUTH_FRAME - 16, WAIT).await?;
        let mut viewer = ViewerConnection::new(socket, PREAUTH_FRAME - 16)?;
        let identity = LoginIdentity { target: HOST_ID.into(), viewer_id: "local-viewer".into(), viewer_name: "demo".into(), wire_session_id: 1, version: "demo".into() };
        viewer.login(&identity, PASSWORD, WAIT).await?;
        viewer.set_connected_message_limit(VIDEO_FRAME)?;
        let envelope = match viewer.receive(WAIT).await? {
            ViewerEvent::Video { envelope, .. } => envelope,
            _ => return Err(Box::<dyn std::error::Error>::from("unexpected demo message")),
        };
        // The bitstream is from this same local demo. Native decoding is not
        // safe for untrusted streams and has no hardened allocation limit.
        let mut decoder = VideoReceiver::new(Codec::Vp9, VIDEO_FRAME)?;
        let frame = decoder.decode(&envelope)?.ok_or("no decoded frame")?;
        println!("Decoded local frame: {}x{}, {} bytes", frame.frame.width, frame.frame.height, frame.frame.data.len());
        viewer.close();
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let (host_result, viewer_result) = tokio::join!(host, viewer);
    host_result?; viewer_result?;
    Ok(())
}
