//! Experimental integration of the session guard and input controller.
//!
//! This is not yet the final RemoteCore facade. It does not provide secure
//! networking, credential validation, session-ID generation, a viewer, or
//! capture task orchestration. It must not be exposed to untrusted peers until
//! those layers and OS-level authorization have been reviewed and tested.

use std::{error::Error, fmt};
use remote_input::{InputBackend, InputController, InputError, MouseButton, VirtualKey};
use remote_session::{Action, Authenticator, Authorizer, Credential, Permissions, Session, SessionError, SessionId, SessionState};

/// Error returned by the session guard or input backend.
#[derive(Debug)]
pub enum HostInputError {
    /// Session state, authentication, or permission failure.
    Session(SessionError),
    /// Input permission, state, or backend failure.
    Input(InputError),
    /// Both input and session cleanup failed.
    Cleanup { input: InputError, session: SessionError },
}
impl fmt::Display for HostInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(error) => write!(f, "session: {error}"),
            Self::Input(error) => write!(f, "input: {error}"),
            Self::Cleanup { input, session } => write!(f, "input cleanup: {input}; session cleanup: {session}"),
        }
    }
}
impl Error for HostInputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self { Self::Session(error) => Some(error), Self::Input(error) => Some(error), Self::Cleanup { .. } => None }
    }
}
impl From<SessionError> for HostInputError { fn from(error: SessionError) -> Self { Self::Session(error) } }
impl From<InputError> for HostInputError { fn from(error: InputError) -> Self { Self::Input(error) } }

/// Coordinates an input controller with one session's capability checks.
///
/// Ownership of the backend is exclusive only within this value. The host must
/// still serialize input across sessions and control all other paths that can
/// instantiate an input backend. The wrapped RustDesk Enigo implementation
/// cannot report all OS delivery and release errors.
pub struct HostInputSession<B: InputBackend> {
    session: Session,
    input: InputController<B>,
}
impl<B: InputBackend> HostInputSession<B> {
    /// Construct a session and input controller with all permissions denied.
    pub fn new(id: SessionId, backend: B) -> Self {
        Self { session: Session::new(id), input: InputController::new(backend) }
    }
    /// Current session identifier.
    pub fn id(&self) -> SessionId { self.session.id() }
    /// Current lifecycle state.
    pub fn state(&self) -> SessionState { self.session.state() }
    /// Current session permissions.
    pub fn permissions(&self) -> Permissions { self.session.permissions() }
    /// Mark the beginning of a connection attempt.
    pub fn begin_connect(&mut self) -> Result<(), HostInputError> { self.session.begin_connect()?; Ok(()) }
    /// Mark a transport connected, without granting input privileges.
    pub fn transport_connected(&mut self) -> Result<(), HostInputError> { self.session.transport_connected()?; Ok(()) }
    /// Authenticate and obtain host authorization before activating input.
    ///
    /// `auth` and `policy` are trusted providers; this method implements no
    /// token verification, transport binding, replay protection or UI consent.
    pub fn authenticate<A: Authenticator, P: Authorizer>(
        &mut self, credential: Credential<'_>, requested: Permissions, auth: &mut A, policy: &mut P,
    ) -> Result<(), HostInputError> {
        self.session.authenticate(credential, requested, auth, policy)?;
        let allowed = self.session.permissions();
        if let Err(error) = self.input.set_permissions(remote_input::Permissions {
            mouse: allowed.control_mouse, keyboard: allowed.control_keyboard,
        }) {
            let _ = self.session.fail();
            return Err(HostInputError::Input(error));
        }
        Ok(())
    }
    /// Restrict privileges and release inputs affected by revocation.
    ///
    /// On detectable release failure, the session is marked Failed. Call
    /// `close` to retry cleanup; OS-level releases may still be unverifiable.
    pub fn restrict_permissions(&mut self, permissions: Permissions) -> Result<(), HostInputError> {
        self.session.restrict_permissions(permissions)?;
        let allowed = self.session.permissions();
        if let Err(error) = self.input.set_permissions(remote_input::Permissions {
            mouse: allowed.control_mouse, keyboard: allowed.control_keyboard,
        }) {
            let _ = self.session.fail();
            return Err(HostInputError::Input(error));
        }
        Ok(())
    }
    /// Move the mouse in virtual-desktop coordinates, after authorization.
    pub fn move_to(&mut self, x: i32, y: i32) -> Result<(), HostInputError> {
        self.session.check(Action::ControlMouse)?;
        self.input.move_to(x, y)?;
        Ok(())
    }
    /// Press a mouse button, after authorization.
    pub fn mouse_down(&mut self, button: MouseButton) -> Result<(), HostInputError> {
        self.session.check(Action::ControlMouse)?;
        self.input.mouse_down(button)?;
        Ok(())
    }
    /// Release a mouse button, after authorization.
    pub fn mouse_up(&mut self, button: MouseButton) -> Result<(), HostInputError> {
        self.session.check(Action::ControlMouse)?;
        self.input.mouse_up(button)?;
        Ok(())
    }
    /// Click a mouse button, after authorization.
    pub fn click(&mut self, button: MouseButton) -> Result<(), HostInputError> {
        self.session.check(Action::ControlMouse)?;
        self.input.click(button)?;
        Ok(())
    }
    /// Scroll in backend-defined units, after authorization.
    pub fn scroll(&mut self, x: i32, y: i32) -> Result<(), HostInputError> {
        self.session.check(Action::ControlMouse)?;
        self.input.scroll(x, y)?;
        Ok(())
    }
    /// Press a Windows virtual key, after authorization.
    pub fn key_down(&mut self, key: VirtualKey) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?;
        self.input.key_down(key)?;
        Ok(())
    }
    /// Release a Windows virtual key, after authorization.
    pub fn key_up(&mut self, key: VirtualKey) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?;
        self.input.key_up(key)?;
        Ok(())
    }
    /// Press and release a Windows virtual key, after authorization.
    pub fn key_press(&mut self, key: VirtualKey) -> Result<(), HostInputError> {
        self.session.check(Action::ControlKeyboard)?;
        self.input.key_press(key)?;
        Ok(())
    }
    /// Revoke access and attempt both input and session cleanup.
    ///
    /// Both paths are attempted even when one fails; calling again retries
    /// detectable input or resource cleanup errors.
    pub fn close(&mut self) -> Result<(), HostInputError> {
        let input = self.input.close();
        let session = self.session.close();
        match (input, session) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(input), Ok(())) => Err(HostInputError::Input(input)),
            (Ok(()), Err(session)) => Err(HostInputError::Session(session)),
            (Err(input), Err(session)) => Err(HostInputError::Cleanup { input, session }),
        }
    }
}

/// Capture/codec/protocol/transport integration for a single video stream.
///
/// This module is experimental and must not decode untrusted network data. It
/// does not provide authentication, rendering, negotiation, frame acknowledgments,
/// or a complete host/viewer lifecycle.
pub mod video {
    use remote_codec::{Codec, DecodedFrame, EncodedFrame, EncoderConfig, PackedFormat, Packet, SoftwareDecoder, SoftwareEncoder};
    use remote_protocol::{Envelope, OwnedVideoPacket, ProtocolError, VideoCodec, MAX_ENVELOPE_BYTES};
    use remote_session::{Action, Session, SessionError, SessionState};
    use remote_transport::{Transport, TransportError};
    use std::{error::Error, fmt, io, time::Duration};

    /// An error from the video pipeline.
    #[derive(Debug)]
    pub enum VideoError {
        /// Session state or capability denied the operation.
        Session(SessionError),
        /// Capture conversion or encoder/decoder failed.
        Codec(io::Error),
        /// RustDesk protocol serialization or decoding failed.
        Protocol(ProtocolError),
        /// Message transport failed.
        Transport(TransportError),
        /// The codec requires resetting before another frame can be sent.
        EncoderResetRequired,
        /// The wire codec is not supported by this software decoder.
        UnsupportedCodec,
        /// The received codec does not match the configured decoder.
        CodecMismatch,
    }
    impl fmt::Display for VideoError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Session(e) => write!(f, "session: {e}"),
                Self::Codec(e) => write!(f, "codec: {e}"),
                Self::Protocol(e) => write!(f, "protocol: {e}"),
                Self::Transport(e) => write!(f, "transport: {e}"),
                Self::EncoderResetRequired => f.write_str("encoder must be reset"),
                Self::UnsupportedCodec => f.write_str("unsupported video codec"),
                Self::CodecMismatch => f.write_str("received video codec differs from configured decoder"),
            }
        }
    }
    impl Error for VideoError {}
    impl From<SessionError> for VideoError { fn from(e: SessionError) -> Self { Self::Session(e) } }
    impl From<io::Error> for VideoError { fn from(e: io::Error) -> Self { Self::Codec(e) } }
    impl From<ProtocolError> for VideoError { fn from(e: ProtocolError) -> Self { Self::Protocol(e) } }
    impl From<TransportError> for VideoError { fn from(e: TransportError) -> Self { Self::Transport(e) } }

    fn wire_codec(codec: Codec) -> VideoCodec {
        match codec { Codec::Vp8 => VideoCodec::Vp8, Codec::Vp9 => VideoCodec::Vp9, Codec::Av1 => VideoCodec::Av1 }
    }
    fn software_codec(codec: VideoCodec) -> Result<Codec, VideoError> {
        match codec { VideoCodec::Vp8 => Ok(Codec::Vp8), VideoCodec::Vp9 => Ok(Codec::Vp9), VideoCodec::Av1 => Ok(Codec::Av1), _ => Err(VideoError::UnsupportedCodec) }
    }

    /// A single software encoder that writes RustDesk protobuf video envelopes.
    pub struct VideoSender {
        encoder: Option<SoftwareEncoder>,
        config: EncoderConfig,
        max_envelope_bytes: usize,
    }
    impl VideoSender {
        /// Create an encoder with an explicit serialized-envelope limit.
        pub fn new(config: EncoderConfig, max_envelope_bytes: usize) -> Result<Self, VideoError> {
            if max_envelope_bytes == 0 || max_envelope_bytes > MAX_ENVELOPE_BYTES {
                return Err(VideoError::Protocol(ProtocolError::InvalidLimit));
            }
            Ok(Self { encoder: Some(SoftwareEncoder::new(config)?), config, max_envelope_bytes })
        }
        /// Recreate the encoder, for example after a failed or cancelled send.
        /// The caller must negotiate a decoder refresh before sending again.
        pub fn reset(&mut self, config: EncoderConfig) -> Result<(), VideoError> {
            // Never keep a potentially stale encoder when replacement fails.
            self.encoder = None;
            let encoder = SoftwareEncoder::new(config)?;
            self.config = config;
            self.encoder = Some(encoder);
            Ok(())
        }
        /// Whether the encoder must be recreated after a failed/cancelled send.
        pub fn needs_reset(&self) -> bool { self.encoder.is_none() }

        /// Convert and encode one packed captured frame, then send its protobuf envelope.
        ///
        /// The session must already be streaming and have screen-view permission.
        /// On conversion, serialization or transport error, or if the returned
        /// future is dropped while a send is in progress, the encoder is dropped
        /// and must be reset. This avoids continuing a predictive stream after a
        /// potentially lost frame; it does not itself request a remote keyframe.
        /// The caller must also stop capture immediately on session revocation.
        pub async fn send_packed(
            &mut self,
            session: &Session,
            transport: &mut dyn Transport,
            display: i32,
            pixels: &[u8],
            stride: usize,
            format: PackedFormat,
            pts_ms: i64,
            deadline: Duration,
        ) -> Result<(), VideoError> {
            if session.state() != SessionState::Streaming {
                return Err(VideoError::Session(SessionError::InvalidState { state: session.state(), operation: "send video" }));
            }
            session.check(Action::ViewScreen)?;
            let mut encoder = self.encoder.take().ok_or(VideoError::EncoderResetRequired)?;
            let encoded = encoder.encode_packed(pixels, stride, format, pts_ms)?;
            let packets: Vec<OwnedVideoPacket> = encoded.packets.into_iter().map(|packet| OwnedVideoPacket {
                data: packet.data, key: packet.key, pts: packet.pts,
            }).collect();
            let wire = Envelope::video_event(display, wire_codec(self.config.codec), &packets)?.encode(self.max_envelope_bytes)?;
            transport.send(&wire, deadline).await?;
            self.encoder = Some(encoder);
            Ok(())
        }
    }

    /// Decoded output together with its source display index.
    pub struct VideoImage<'a> {
        /// Source display index carried by the RustDesk envelope.
        pub display: i32,
        /// Packed decoded image, valid until the next decoder operation.
        pub frame: DecodedFrame<'a>,
    }

    /// Software decoder for RustDesk video envelopes.
    ///
    /// Only use with trusted, authenticated input in a controlled environment.
    /// Length checks do not prevent a compressed frame from demanding excessive
    /// native decoder memory. This is not yet safe for internet-facing peers.
    pub struct VideoReceiver {
        decoder: SoftwareDecoder,
        codec: Codec,
        max_envelope_bytes: usize,
    }
    impl VideoReceiver {
        /// Create a decoder for the negotiated software codec.
        pub fn new(codec: Codec, max_envelope_bytes: usize) -> Result<Self, VideoError> {
            if max_envelope_bytes == 0 || max_envelope_bytes > MAX_ENVELOPE_BYTES {
                return Err(VideoError::Protocol(ProtocolError::InvalidLimit));
            }
            Ok(Self { decoder: SoftwareDecoder::new(codec)?, codec, max_envelope_bytes })
        }
        /// Decode an already-received protobuf envelope.
        /// This does not automatically recover from corruption or lost frames.
        pub fn decode(&mut self, bytes: &[u8]) -> Result<Option<VideoImage<'_>>, VideoError> {
            let envelope = Envelope::decode(bytes, self.max_envelope_bytes)?;
            let view = envelope.video()?;
            let codec = software_codec(view.codec)?;
            if codec != self.codec { return Err(VideoError::CodecMismatch); }
            let display = view.display;
            let packets: Vec<Packet> = view.packets().map(|packet| Packet {
                data: packet.data.to_vec(), key: packet.key, pts: packet.pts,
            }).collect();
            let encoded = EncodedFrame { codec, packets };
            Ok(self.decoder.decode(&encoded)?.map(|frame| VideoImage { display, frame }))
        }
        /// Receive and decode a single video envelope from a transport.
        /// A non-video message returns a protocol error; demultiplexing and
        /// handling other message kinds are the caller's responsibility.
        pub async fn receive(&mut self, transport: &mut dyn Transport, deadline: Duration) -> Result<Option<VideoImage<'_>>, VideoError> {
            let bytes = transport.receive(deadline).await?;
            self.decode(&bytes)
        }
    }
}
