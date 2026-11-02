//! Experimental single-process pipeline on a disposable Windows desktop.
//! No network, renderer, owner-consent UI, or real remote peer is involved.

#[cfg(windows)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use remote_capture::{Frame, PixelFormat};
    use remote_codec::{Codec, EncoderConfig, PackedFormat};
    use remote_core::{video::{VideoReceiver, VideoSender}, HostInputSession};
    use remote_input::windows::WindowsInput;
    use remote_security::{password_response, OwnerApproval, PasswordVerifier};
    use remote_session::{Credential, Permissions, Principal, SessionId};
    use remote_transport::{local_pair, LocalConfig};
    use std::{io, time::Duration};
    use zeroize::Zeroizing;

    if std::env::args().nth(1).as_deref() != Some("--confirm-capture") {
        eprintln!("This example captures the first available desktop display. Run on a disposable interactive Windows desktop with --confirm-capture.");
        return Ok(());
    }
    let password = Zeroizing::new(std::env::var("REMOTE_CORE_EXAMPLE_PASSWORD")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "set REMOTE_CORE_EXAMPLE_PASSWORD for this local example"))?);
    let mut id_bytes = [0u8; 16];
    getrandom::getrandom(&mut id_bytes).map_err(|_| io::Error::new(io::ErrorKind::Other, "secure randomness unavailable"))?;
    let id = SessionId::new(id_bytes)?;
    let mut salt_bytes = [0u8; 16];
    getrandom::getrandom(&mut salt_bytes).map_err(|_| io::Error::new(io::ErrorKind::Other, "secure randomness unavailable"))?;
    let salt: String = salt_bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let principal = Principal::new("local-example-viewer".into())?;
    let mut verifier = PasswordVerifier::new(id, principal.clone(), &password, &salt, Duration::from_secs(30))?;
    let proof = password_response(&password, verifier.challenge())?;
    // This consent is intentionally local to a single-process example. A real
    // host must obtain owner consent through a trusted UI and bind authentication
    // to a separately secured transport before accepting a remote viewer.
    let permissions = Permissions { view_screen: true, ..Default::default() };
    let mut approval = OwnerApproval::new(id, principal, Some(permissions));
    let mut host = HostInputSession::new(id, WindowsInput::new());
    host.begin_connect()?;
    host.transport_connected()?;
    host.authenticate(Credential::new(proof.as_bytes()), permissions, &mut verifier, &mut approval)?;
    host.start_streaming()?;

    let display = remote_capture::displays()?.into_iter().next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no display available"))?;
    let mut capturer = display.open()?;
    let frame = capturer.frame(Duration::from_secs(3))?;
    let pixels = match frame {
        Frame::Pixels(pixels) => pixels,
        Frame::Texture(_) => return Err(io::Error::new(io::ErrorKind::Unsupported, "example requires CPU pixels").into()),
    };
    let format = match pixels.format() {
        PixelFormat::Bgra => PackedFormat::Bgra,
        PixelFormat::Rgba => PackedFormat::Rgba,
        _ => return Err(io::Error::new(io::ErrorKind::Unsupported, "example requires BGRA or RGBA pixels").into()),
    };
    let width = u32::try_from(pixels.width())?;
    let height = u32::try_from(pixels.height())?;
    let stride = *pixels.stride().first().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing capture stride"))?;
    let max_bytes = 16 * 1024 * 1024;
    let (mut host_transport, mut viewer_transport) = local_pair(LocalConfig { queue_capacity: 1, max_message_size: max_bytes })?;
    let mut sender = VideoSender::new(EncoderConfig { codec: Codec::Vp9, width, height, quality: 1.0, keyframe_interval: Some(30) }, max_bytes)?;
    host.send_video(&mut sender, &mut host_transport, 0, pixels.data(), stride, format, 0, Duration::from_secs(5)).await?;
    let mut receiver = VideoReceiver::new(Codec::Vp9, max_bytes)?;
    let image = receiver.receive(&mut viewer_transport, Duration::from_secs(5)).await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "decoder produced no frame"))?;
    println!("Decoded display {}: {}×{}, {} bytes", image.display, image.frame.width, image.frame.height, image.frame.data.len());
    host.stop_streaming()?;
    host.close()?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This example requires an interactive Windows desktop.");
}
