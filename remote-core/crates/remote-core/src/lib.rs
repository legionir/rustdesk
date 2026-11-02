//! Experimental integration of the session guard and input controller.
//!
//! This is not yet the final RemoteCore facade. It does not provide secure
//! networking, credential validation, session-ID generation, a viewer, or
//! capture task orchestration. It must not be exposed to untrusted peers until
//! those layers and OS-level authorization have been reviewed and tested.

/// Optional single-controller arbitration within a cooperating process.
pub mod input_arbiter;

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
    /// Mark an authorized session as streaming once the caller has prepared capture.
    /// This does not itself create a capture task or start a transport.
    pub fn start_streaming(&mut self) -> Result<(), HostInputError> {
        self.session.start_streaming()?;
        Ok(())
    }
    /// Mark streaming stopped. The caller must stop actual capture and delivery tasks.
    pub fn stop_streaming(&mut self) -> Result<(), HostInputError> {
        self.session.stop_streaming()?;
        Ok(())
    }
    /// Encode and send one captured frame using this same session's authorization.
    ///
    /// The supplied transport and encoder remain caller-owned. A failed or
    /// cancelled send requires the sender to be reset before another frame.
    /// The caller must coordinate stream cleanup, codec negotiation and input
    /// ownership across sessions; this method does not spawn background tasks.
    pub async fn send_video(
        &mut self,
        sender: &mut video::VideoSender,
        transport: &mut dyn remote_transport::Transport,
        display: i32,
        pixels: &[u8],
        stride: usize,
        format: remote_codec::PackedFormat,
        pts_ms: i64,
        deadline: std::time::Duration,
    ) -> Result<(), video::VideoError> {
        sender.send_packed(&self.session, transport, display, pixels, stride, format, pts_ms, deadline).await
    }
    /// Send a frame over a network-oriented transport using this session.
    /// An interrupted send may have reached the peer and requires encoder reset.
    /// Network authentication and binding remain the caller's responsibility.
    pub async fn send_video_network(
        &mut self,
        sender: &mut video::VideoSender,
        transport: &mut dyn remote_transport::NetworkTransport,
        display: i32,
        pixels: &[u8],
        stride: usize,
        format: remote_codec::PackedFormat,
        pts_ms: i64,
        deadline: std::time::Duration,
    ) -> Result<(), video::VideoError> {
        sender.send_packed_network(&self.session, transport, display, pixels, stride, format, pts_ms, deadline).await
    }
    /// Move the mouse in virtual-desktop coordinates, after authorization.
    pub fn move_to(&mut self, x: i32, y: i32) -> Result<(), HostInputError> {
        self.session.check(Action::ControlMouse)?;
        self.input.move_to(x, y)?;
        Ok(())
    }
    /// Move the mouse by relative pixels, after authorization.
    pub fn move_relative(&mut self, x: i32, y: i32) -> Result<(), HostInputError> {
        self.session.check(Action::ControlMouse)?;
        self.input.move_relative(x, y)?;
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

/// Windows mouse input dispatcher for the supported RustDesk event subset.
///
/// This deliberately refuses modifier-bearing events and trackpad messages;
/// it does not silently reinterpret them. Keyboard translation, touch, consent,
/// session-to-transport binding and inter-session input arbitration are not
/// provided. The caller must protect this API from untrusted peers and ensure
/// the backend implements Windows input units and virtual-desktop coordinates.
pub mod windows_mouse {
    use super::{HostInputError, HostInputSession};
    use remote_input::{InputBackend, MouseButton};
    use remote_protocol::{Envelope, ProtocolError};
    use std::{error::Error, fmt};

    /// Failure inspecting or applying a mouse event.
    #[derive(Debug)]
    pub enum DispatchError {
        /// The envelope is not a RustDesk mouse message.
        Protocol(ProtocolError),
        /// This provisional dispatcher does not implement the event form.
        Unsupported(&'static str),
        /// A wheel delta could not be represented safely in Windows units.
        InvalidWheelDelta,
        /// Session authorization or OS backend failed.
        Host(HostInputError),
    }
    impl fmt::Display for DispatchError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Protocol(e) => write!(f, "mouse protocol: {e}"),
                Self::Unsupported(e) => write!(f, "unsupported mouse event: {e}"),
                Self::InvalidWheelDelta => f.write_str("mouse wheel delta exceeds Windows range"),
                Self::Host(e) => write!(f, "mouse dispatch: {e}"),
            }
        }
    }
    impl Error for DispatchError {}
    impl From<ProtocolError> for DispatchError { fn from(e: ProtocolError) -> Self { Self::Protocol(e) } }
    impl From<HostInputError> for DispatchError { fn from(e: HostInputError) -> Self { Self::Host(e) } }

    /// Apply one RustDesk mouse envelope using Windows source semantics.
    ///
    /// Absolute positions use virtual-desktop coordinates; selecting/mapping a
    /// monitor is the caller's responsibility. Relative deltas are clamped to
    /// ±10,000 as in `src/server/input_service.rs`. Ordinary wheel deltas use
    /// `(-x * 120, y * 120)` Windows units. Modifiers and trackpad events are
    /// explicitly rejected until their source behavior is extracted. The session
    /// guard checks `control_mouse`, whose policy differs from upstream's
    /// shared `peer_keyboard_enabled()` gate and needs security review.
    pub fn dispatch<B: InputBackend>(host: &mut HostInputSession<B>, envelope: &Envelope) -> Result<(), DispatchError> {
        // Check authorization even for invalid forms before exposing dispatch.
        host.session.check(remote_session::Action::ControlMouse).map_err(HostInputError::from)?;
        let event = envelope.mouse()?;
        if envelope.mouse_modifiers()?.next().is_some() { return Err(DispatchError::Unsupported("modifier-bearing events")); }
        let action = event.mask & 0x7;
        let buttons = event.mask >> 3;
        match action {
            0 => host.move_to(event.x, event.y)?,
            1 | 2 => {
                let button = match buttons {
                    1 => MouseButton::Left, 2 => MouseButton::Right, 4 => MouseButton::Middle,
                    8 => MouseButton::Back, 16 => MouseButton::Forward,
                    _ => return Err(DispatchError::Unsupported("unknown or combined mouse buttons")),
                };
                if action == 1 { host.mouse_down(button)?; } else { host.mouse_up(button)?; }
            }
            3 => {
                let x = event.x.checked_neg().and_then(|n| n.checked_mul(120)).ok_or(DispatchError::InvalidWheelDelta)?;
                let y = event.y.checked_mul(120).ok_or(DispatchError::InvalidWheelDelta)?;
                host.scroll(x, y)?;
            }
            4 => return Err(DispatchError::Unsupported("trackpad")),
            5 => host.move_relative(event.x.clamp(-10_000, 10_000), event.y.clamp(-10_000, 10_000))?,
            _ => return Err(DispatchError::Unsupported("unknown event type")),
        }
        Ok(())
    }
}

/// Restricted Windows legacy control-key dispatcher.
///
/// Only control keys without modifiers are handled. The original RustDesk
/// keyboard service has extensive layout, modifier, lock-state, repeat,
/// portable-service and text handling; those paths are not replicated here.
/// This API is not safe to expose without trusted authorization and input
/// arbitration, and is not a complete RustDesk keyboard implementation.
pub mod windows_keyboard {
    use super::{HostInputError, HostInputSession};
    use remote_input::{InputBackend, VirtualKey};
    use remote_protocol::{Envelope, KeyboardPayload, ProtocolError};
    use std::{error::Error, fmt};

    /// Failure inspecting or applying a keyboard message.
    #[derive(Debug)]
    pub enum DispatchError {
        /// Not a keyboard envelope.
        Protocol(ProtocolError),
        /// A keyboard mode, payload or modifier is not implemented here.
        Unsupported(&'static str),
        /// Session authorization or backend failed.
        Host(HostInputError),
    }
    impl fmt::Display for DispatchError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Protocol(e) => write!(f, "keyboard protocol: {e}"),
                Self::Unsupported(e) => write!(f, "unsupported keyboard event: {e}"),
                Self::Host(e) => write!(f, "keyboard dispatch: {e}"),
            }
        }
    }
    impl Error for DispatchError {}
    impl From<ProtocolError> for DispatchError { fn from(e: ProtocolError) -> Self { Self::Protocol(e) } }
    impl From<HostInputError> for DispatchError { fn from(e: HostInputError) -> Self { Self::Host(e) } }

    // ControlKey numeric values are from message.proto. Virtual-key values match
    // src/server/input_service.rs KEY_MAP and libs/enigo/src/win/keycodes.rs.
    // Modifiers, lock keys and system actions are deliberately excluded.
    fn plain_control_vk(value: i32) -> Option<u16> {
        Some(match value {
            2 => 0x08, 5 => 0x2e, 6 => 0x28, 7 => 0x23, 8 => 0x1b,
            9 => 0x70, 10 => 0x79, 11 => 0x7a, 12 => 0x7b,
            13 => 0x71, 14 => 0x72, 15 => 0x73, 16 => 0x74,
            17 => 0x75, 18 => 0x76, 19 => 0x77, 20 => 0x78,
            21 => 0x24, 22 => 0x25, 25 => 0x22, 26 => 0x21,
            27 => 0x0d, 28 => 0x27, 30 => 0x20, 31 => 0x09, 32 => 0x26,
            33..=42 => 0x60 + (value as u16 - 33),
            43 => 0x03, 44 => 0x0c, 46 => 0x13,
            54 => 0x29, 55 => 0x2a, 56 => 0x2b, 57 => 0x2c,
            58 => 0x2d, 59 => 0x2f, 61 => 0x6c,
            65 => 0x5d, 66 => 0x6a, 67 => 0x6b, 68 => 0x6d,
            69 => 0x6e, 70 => 0x6f, 71 => 0x3d, 72 => 0x0d,
            _ => return None,
        })
    }

    /// Apply a non-modifier legacy control-key message to a Windows-style backend.
    ///
    /// A `press` is a down/up pair; otherwise the wire `down` bit determines
    /// state. Repeat downs are suppressed by the input controller. Unlike the
    /// original service this method does not synchronize global modifier state,
    /// switch Windows desktops, support layout/text/scan codes, or run the
    /// portable service. Those limitations can affect even accepted keys.
    pub fn dispatch<B: InputBackend>(host: &mut HostInputSession<B>, envelope: &Envelope) -> Result<(), DispatchError> {
        host.session.check(remote_session::Action::ControlKeyboard).map_err(HostInputError::from)?;
        let event = envelope.keyboard()?;
        if event.mode() != 0 { return Err(DispatchError::Unsupported("non-legacy keyboard mode")); }
        if event.modifiers().next().is_some() { return Err(DispatchError::Unsupported("modifier-bearing keyboard event")); }
        let value = match event.payload() {
            Some(KeyboardPayload::ControlKey(value)) => value,
            _ => return Err(DispatchError::Unsupported("non-control-key payload")),
        };
        let code = plain_control_vk(value).ok_or(DispatchError::Unsupported("modifier, system, or unknown control key"))?;
        let key = VirtualKey::new(code).map_err(|_| DispatchError::Unsupported("invalid virtual key"))?;
        if event.press() { host.key_press(key)?; }
        else if event.down() { host.key_down(key)?; }
        else { host.key_up(key)?; }
        Ok(())
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
        /// Network transport failed; send delivery may be indeterminate.
        Network(remote_transport::NetworkTransportError),
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
                Self::Network(e) => write!(f, "network: {e}"),
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
    impl From<remote_transport::NetworkTransportError> for VideoError { fn from(e: remote_transport::NetworkTransportError) -> Self { Self::Network(e) } }

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

    impl VideoSender {
        /// Send one encoded frame over a network transport with indeterminate
        /// delivery on failure. Failed/cancelled sends require encoder reset and
        /// explicit decoder resynchronization; they must not be replayed blindly.
        pub async fn send_packed_network(
            &mut self,
            session: &Session,
            transport: &mut dyn remote_transport::NetworkTransport,
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
        /// Receive and decode a video envelope from a network-oriented stream.
        /// This does not authenticate the stream or harden the native decoder.
        pub async fn receive_network(&mut self, transport: &mut dyn remote_transport::NetworkTransport, deadline: Duration) -> Result<Option<VideoImage<'_>>, VideoError> {
            let bytes = transport.receive(deadline).await?;
            self.decode(&bytes)
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
