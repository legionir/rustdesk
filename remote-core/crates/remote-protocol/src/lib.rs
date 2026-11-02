//! Experimental adapter for RustDesk's existing desktop protobuf schema.
//!
//! This is not a new protocol or a full security boundary. It preserves all
//! recognized and unknown fields on envelopes with a recognized payload when
//! decoded and re-encoded, but callers must still authorize each message and validate its
//! fields before acting. Parsing does not authenticate the sender, prevent
//! replay, or enforce all semantic and memory-allocation limits.

/// Cursor wire messages and bounded decoded-shape cache.
pub mod cursor;
/// Existing desktop login response and display metadata.
pub mod desktop;

use base::message_proto::{self, message, misc, video_frame, Message};
use hbb_common::protobuf::Message as ProtobufMessage;
use std::{error::Error, fmt};

/// Largest accepted serialized desktop protobuf envelope, in bytes.
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024 * 1024;
/// Suggested maximum before authentication. Use this explicitly on untrusted peers.
pub const MAX_PRE_AUTH_BYTES: usize = 128 * 1024;
/// Largest number of individual encoded packets exposed from one video message.
pub const MAX_VIDEO_PACKETS: usize = 1024;

/// Error returned when decoding, inspecting or encoding an envelope.
#[derive(Debug)]
pub enum ProtocolError {
    /// The configured size limit is zero or exceeds the hard ceiling.
    InvalidLimit,
    /// The serialized envelope exceeds the configured limit.
    TooLarge { size: usize, limit: usize },
    /// Protobuf decoding or encoding failed.
    Protobuf(String),
    /// The parsed envelope contains no recognized message variant.
    MissingMessage,
    /// The operation requires a different message kind.
    UnexpectedMessage,
    /// The encoded video frame contains too many packets.
    TooManyVideoPackets,
    /// An authentication field has an unsupported size or value.
    InvalidAuthenticationField,
}
impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => f.write_str("invalid envelope size limit"),
            Self::TooLarge { size, limit } => write!(f, "envelope size {size} exceeds limit {limit}"),
            Self::Protobuf(error) => write!(f, "protobuf: {error}"),
            Self::MissingMessage => f.write_str("message has no recognized payload"),
            Self::UnexpectedMessage => f.write_str("unexpected message kind"),
            Self::TooManyVideoPackets => f.write_str("too many encoded video packets"),
            Self::InvalidAuthenticationField => f.write_str("invalid authentication field"),
        }
    }
}
impl Error for ProtocolError {}

/// Broad categories for dispatch; unlisted RustDesk payloads remain intact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// Video data.
    Video,
    /// Mouse input.
    Mouse,
    /// Cursor shape, selected cursor ID or position.
    Cursor,
    /// Keyboard input.
    Keyboard,
    /// Login and related authorization messages.
    Authentication,
    /// Latency/liveness probe.
    TestDelay,
    /// Display, capability, permission, or other control message.
    Misc,
    /// Other existing RustDesk message kinds, such as clipboard or file transfer.
    Other,
}

/// A decoded RustDesk envelope. The source protobuf type remains private.
pub struct Envelope {
    inner: Message,
}
impl Envelope {
    /// Decode an existing RustDesk protobuf envelope under an explicit bound.
    ///
    /// The caller should use a strict pre-authorization limit before accepting
    /// trusted peers. The byte bound does not guarantee a fixed allocation bound
    /// for protobuf internals; additional validation and resource controls are required.
    pub fn decode(bytes: &[u8], max_bytes: usize) -> Result<Self, ProtocolError> {
        validate_limit(max_bytes)?;
        if bytes.len() > max_bytes { return Err(ProtocolError::TooLarge { size: bytes.len(), limit: max_bytes }); }
        let inner = Message::parse_from_bytes(bytes).map_err(|error| ProtocolError::Protobuf(error.to_string()))?;
        if inner.union.is_none() { return Err(ProtocolError::MissingMessage); }
        Ok(Self { inner })
    }
    /// Serialize the complete preserved RustDesk envelope under an explicit bound.
    pub fn encode(&self, max_bytes: usize) -> Result<Vec<u8>, ProtocolError> {
        validate_limit(max_bytes)?;
        let size = self.inner.compute_size();
        if size > max_bytes as u64 { return Err(ProtocolError::TooLarge { size: usize::try_from(size).unwrap_or(usize::MAX), limit: max_bytes }); }
        self.inner.write_to_bytes().map_err(|error| ProtocolError::Protobuf(error.to_string()))
    }
    /// Classify the existing message without changing its contents.
    pub fn kind(&self) -> MessageKind {
        match self.inner.union.as_ref() {
            Some(message::Union::VideoFrame(_)) => MessageKind::Video,
            Some(message::Union::MouseEvent(_)) => MessageKind::Mouse,
            Some(message::Union::CursorData(_)) | Some(message::Union::CursorPosition(_)) | Some(message::Union::CursorId(_)) => MessageKind::Cursor,
            Some(message::Union::KeyEvent(_)) => MessageKind::Keyboard,
            Some(message::Union::LoginRequest(_)) | Some(message::Union::LoginResponse(_))
            | Some(message::Union::Hash(_)) | Some(message::Union::Auth2fa(_))
            | Some(message::Union::PublicKey(_)) | Some(message::Union::SignedId(_)) => MessageKind::Authentication,
            Some(message::Union::TestDelay(_)) => MessageKind::TestDelay,
            Some(message::Union::Misc(_)) => MessageKind::Misc,
            _ => MessageKind::Other,
        }
    }
    /// Inspect an existing TestDelay message. The values are untrusted and do
    /// not by themselves establish a heartbeat or network-quality estimate.
    pub fn test_delay(&self) -> Result<TestDelay, ProtocolError> {
        match self.inner.union.as_ref() {
            Some(message::Union::TestDelay(delay)) => Ok(TestDelay { time: delay.time, from_client: delay.from_client,
                last_delay: delay.last_delay, target_bitrate: delay.target_bitrate }),
            _ => Err(ProtocolError::UnexpectedMessage),
        }
    }
    /// Construct the original RustDesk TestDelay message.
    pub fn test_delay_event(delay: TestDelay) -> Self {
        let mut inner = Message::new();
        inner.set_test_delay(message_proto::TestDelay { time: delay.time, from_client: delay.from_client,
            last_delay: delay.last_delay, target_bitrate: delay.target_bitrate, ..Default::default() });
        Self { inner }
    }
    /// Inspect a mouse event. Coordinates and mask retain RustDesk semantics;
    /// they are not automatically mapped to a local monitor or authorized.
    pub fn mouse(&self) -> Result<MouseEvent, ProtocolError> {
        match self.inner.union.as_ref() {
            Some(message::Union::MouseEvent(event)) => Ok(MouseEvent { mask: event.mask, x: event.x, y: event.y }),
            _ => Err(ProtocolError::UnexpectedMessage),
        }
    }
    /// Read an existing SupportedDecoding payload from a login or Misc option.
    /// Values are claims supplied by a peer, not proof a decoder works.
    pub fn supported_decoding(&self) -> Result<DecodingCapabilities, ProtocolError> {
        let source = self.source_supported_decoding()?;
        Ok(DecodingCapabilities {
            vp8: source.ability_vp8, vp9: source.ability_vp9, av1: source.ability_av1,
            h264: source.ability_h264, h265: source.ability_h265,
            preference: source.prefer.value(), preferred_chroma: source.prefer_chroma.value(),
            i444: source.i444.as_ref().map(|c| ChromaCapabilities { vp8: c.vp8, vp9: c.vp9, av1: c.av1, h264: c.h264, h265: c.h265 }),
        })
    }
    /// Access the source protobuf for source-compatible negotiation adapters.
    /// It remains untrusted and can carry unknown fields; do not treat this
    /// as a stable independent public API.
    pub fn source_supported_decoding(&self) -> Result<&message_proto::SupportedDecoding, ProtocolError> {
        let option = match self.inner.union.as_ref() {
            Some(message::Union::LoginRequest(login)) => login.option.as_ref(),
            Some(message::Union::Misc(misc)) => match misc.union.as_ref() {
                Some(misc::Union::Option(option)) => Some(option),
                _ => None,
            },
            _ => None,
        };
        option.and_then(|o| o.supported_decoding.as_ref()).ok_or(ProtocolError::UnexpectedMessage)
    }
    /// Construct the same Misc→Option→SupportedDecoding update used by the
    /// RustDesk client. Only explicitly declared abilities are advertised;
    /// the caller must verify runtime support and authorization separately.
    pub fn supported_decoding_event(ad: DecodingAdvertisement) -> Self {
        use message_proto::supported_decoding::PreferCodec;
        let preference = match ad.preference {
            CodecPreference::Auto => PreferCodec::Auto, CodecPreference::Vp8 => PreferCodec::VP8,
            CodecPreference::Vp9 => PreferCodec::VP9, CodecPreference::Av1 => PreferCodec::AV1,
            CodecPreference::H264 => PreferCodec::H264, CodecPreference::H265 => PreferCodec::H265,
        };
        let decoding = message_proto::SupportedDecoding {
            ability_vp8: ad.vp8 as i32, ability_vp9: ad.vp9 as i32, ability_av1: ad.av1 as i32,
            ability_h264: ad.h264 as i32, ability_h265: ad.h265 as i32, prefer: preference.into(),
            ..Default::default()
        };
        let option = message_proto::OptionMessage {
            supported_decoding: Some(decoding).into(), ..Default::default()
        };
        let mut misc = message_proto::Misc::new();
        misc.set_option(option);
        let mut inner = Message::new(); inner.set_misc(misc);
        Self { inner }
    }
    /// Inspect the source SupportedEncoding advertisement in a Misc message,
    /// PeerInfo message, or successful LoginResponse. VP9 is implicit in the
    /// source schema and must not be inferred as operational without probing.
    pub fn supported_encoding(&self) -> Result<EncodingCapabilities, ProtocolError> {
        let source = match self.inner.union.as_ref() {
            Some(message::Union::Misc(m)) => match m.union.as_ref() {
                Some(misc::Union::SupportedEncoding(e)) => Some(e),
                _ => None,
            },
            Some(message::Union::PeerInfo(p)) => p.encoding.as_ref(),
            Some(message::Union::LoginResponse(r)) => match r.union.as_ref() {
                Some(message_proto::login_response::Union::PeerInfo(p)) => p.encoding.as_ref(),
                _ => None,
            },
            _ => None,
        }.ok_or(ProtocolError::UnexpectedMessage)?;
        Ok(EncodingCapabilities { vp8: source.vp8, av1: source.av1, h264: source.h264, h265: source.h265,
            i444: source.i444.as_ref().map(|c| ChromaCapabilities { vp8: c.vp8, vp9: c.vp9, av1: c.av1, h264: c.h264, h265: c.h265 }) })
    }
    /// Inspect the existing RustDesk password challenge fields.
    pub fn password_challenge(&self) -> Result<PasswordChallenge<'_>, ProtocolError> {
        match self.inner.union.as_ref() {
            Some(message::Union::Hash(hash)) => Ok(PasswordChallenge { salt: &hash.salt, challenge: &hash.challenge }),
            _ => Err(ProtocolError::UnexpectedMessage),
        }
    }
    /// Construct a RustDesk password challenge envelope.
    /// The supplied fields are not generated or validated as cryptographic nonces here.
    pub fn password_challenge_event(salt: &str, challenge: &str) -> Result<Self, ProtocolError> {
        if salt.is_empty() || salt.len() > 256 || challenge.is_empty() || challenge.len() > 256 {
            return Err(ProtocolError::InvalidAuthenticationField);
        }
        let hash = message_proto::Hash { salt: salt.to_owned(), challenge: challenge.to_owned(), ..Default::default() };
        let mut inner = Message::new();
        inner.set_hash(hash);
        Ok(Self { inner })
    }
    /// Inspect fields of a desktop login request. Requests for other RustDesk
    /// modes are refused by this view but remain intact in the envelope.
    pub fn desktop_login(&self) -> Result<DesktopLogin<'_>, ProtocolError> {
        match self.inner.union.as_ref() {
            Some(message::Union::LoginRequest(login)) if login.union.is_none() => Ok(DesktopLogin {
                username: &login.username, peer_id: &login.my_id, peer_name: &login.my_name,
                password_response: &login.password, session_id: login.session_id, version: &login.version,
            }),
            _ => Err(ProtocolError::UnexpectedMessage),
        }
    }
    /// Construct a basic desktop login request. Additional RustDesk options,
    /// trusted-device tokens, OS login and 2FA are not represented here.
    /// No identity or authorization is established by constructing this message.
    pub fn desktop_login_event(login: DesktopLogin<'_>) -> Result<Self, ProtocolError> {
        if login.username.len() > 256 || login.peer_id.len() > 256 || login.peer_name.len() > 256
            || login.version.len() > 256 || !(login.password_response.is_empty() || login.password_response.len() == 32) {
            return Err(ProtocolError::InvalidAuthenticationField);
        }
        let request = message_proto::LoginRequest {
            username: login.username.to_owned(), my_id: login.peer_id.to_owned(), my_name: login.peer_name.to_owned(),
            password: login.password_response.to_vec().into(), session_id: login.session_id, version: login.version.to_owned(),
            ..Default::default()
        };
        let mut inner = Message::new();
        inner.set_login_request(request);
        Ok(Self { inner })
    }
    /// Inspect every modifier in a mouse event as its original protobuf enum value.
    pub fn mouse_modifiers(&self) -> Result<impl Iterator<Item = i32> + '_, ProtocolError> {
        match self.inner.union.as_ref() {
            Some(message::Union::MouseEvent(event)) => Ok(event.modifiers.iter().map(|value| value.value())),
            _ => Err(ProtocolError::UnexpectedMessage),
        }
    }
    /// Inspect a keyboard event without translating its layout or key values.
    pub fn keyboard(&self) -> Result<KeyboardEvent<'_>, ProtocolError> {
        match self.inner.union.as_ref() {
            Some(message::Union::KeyEvent(event)) => Ok(KeyboardEvent { event }),
            _ => Err(ProtocolError::UnexpectedMessage),
        }
    }
    /// Construct a RustDesk mouse event without modifiers.
    ///
    /// The mask uses the original wire encoding. This does not authorize or
    /// validate any OS action; dispatchers must apply their own policy.
    pub fn mouse_event(event: MouseEvent) -> Self {
        let mut mouse = message_proto::MouseEvent::new();
        mouse.mask = event.mask;
        mouse.x = event.x;
        mouse.y = event.y;
        let mut inner = Message::new();
        inner.set_mouse_event(mouse);
        Self { inner }
    }
    /// Construct an encoded RustDesk video envelope without changing the wire schema.
    /// Raw RGB/YUV descriptors are not accepted by this packet constructor.
    /// Packet metadata is preserved; the caller is responsible for codec
    /// negotiation, timestamps, keyframe ordering and source authorization.
    pub fn video_event(display: i32, codec: VideoCodec, packets: &[OwnedVideoPacket]) -> Result<Self, ProtocolError> {
        if packets.is_empty() { return Err(ProtocolError::MissingMessage); }
        if packets.len() > MAX_VIDEO_PACKETS { return Err(ProtocolError::TooManyVideoPackets); }
        let mut bytes = 0usize;
        let mut frames = Vec::with_capacity(packets.len());
        for packet in packets {
            bytes = bytes.checked_add(packet.data.len()).ok_or(ProtocolError::TooLarge { size: usize::MAX, limit: MAX_ENVELOPE_BYTES })?;
            if bytes > MAX_ENVELOPE_BYTES { return Err(ProtocolError::TooLarge { size: bytes, limit: MAX_ENVELOPE_BYTES }); }
            frames.push(message_proto::EncodedVideoFrame {
                data: packet.data.clone().into(), key: packet.key, pts: packet.pts, ..Default::default()
            });
        }
        let frames = message_proto::EncodedVideoFrames { frames: frames.into(), ..Default::default() };
        let union = match codec {
            VideoCodec::Vp8 => video_frame::Union::Vp8s(frames),
            VideoCodec::Vp9 => video_frame::Union::Vp9s(frames),
            VideoCodec::Av1 => video_frame::Union::Av1s(frames),
            VideoCodec::H264 => video_frame::Union::H264s(frames),
            VideoCodec::H265 => video_frame::Union::H265s(frames),
            VideoCodec::Rgb | VideoCodec::Yuv => return Err(ProtocolError::UnexpectedMessage),
        };
        let mut frame = message_proto::VideoFrame::new();
        frame.display = display;
        frame.union = Some(union);
        let mut inner = Message::new();
        inner.set_video_frame(frame);
        Ok(Self { inner })
    }
    /// Inspect the video payload without copying packet bytes.
    pub fn video(&self) -> Result<VideoFrame<'_>, ProtocolError> {
        let frame = match self.inner.union.as_ref() {
            Some(message::Union::VideoFrame(frame)) => frame,
            _ => return Err(ProtocolError::UnexpectedMessage),
        };
        let (codec, packets) = match frame.union.as_ref() {
            Some(video_frame::Union::Vp8s(packets)) => (VideoCodec::Vp8, Some(packets)),
            Some(video_frame::Union::Vp9s(packets)) => (VideoCodec::Vp9, Some(packets)),
            Some(video_frame::Union::Av1s(packets)) => (VideoCodec::Av1, Some(packets)),
            Some(video_frame::Union::H264s(packets)) => (VideoCodec::H264, Some(packets)),
            Some(video_frame::Union::H265s(packets)) => (VideoCodec::H265, Some(packets)),
            Some(video_frame::Union::Rgb(_)) => (VideoCodec::Rgb, None),
            Some(video_frame::Union::Yuv(_)) => (VideoCodec::Yuv, None),
            None => return Err(ProtocolError::MissingMessage),
        };
        if packets.map_or(false, |p| p.frames.len() > MAX_VIDEO_PACKETS) { return Err(ProtocolError::TooManyVideoPackets); }
        Ok(VideoFrame { display: frame.display, codec, packets })
    }
}

fn validate_limit(max_bytes: usize) -> Result<(), ProtocolError> {
    if max_bytes == 0 || max_bytes > MAX_ENVELOPE_BYTES { Err(ProtocolError::InvalidLimit) } else { Ok(()) }
}

/// Optional source I444 codec ability flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChromaCapabilities { pub vp8: bool, pub vp9: bool, pub av1: bool, pub h264: bool, pub h265: bool }
/// Untrusted decoder capability values preserved from RustDesk's wire schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodingCapabilities {
    pub vp8: i32, pub vp9: i32, pub av1: i32, pub h264: i32, pub h265: i32,
    /// Raw source enum value, including unrecognized values.
    pub preference: i32,
    /// Raw source chroma enum value, including unrecognized values.
    pub preferred_chroma: i32,
    pub i444: Option<ChromaCapabilities>,
}
/// Encoder claims from RustDesk's schema. VP9 has no explicit flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodingCapabilities {
    pub vp8: bool, pub av1: bool, pub h264: bool, pub h265: bool,
    pub i444: Option<ChromaCapabilities>,
}
/// Preference in the existing RustDesk SupportedDecoding message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecPreference { Auto, Vp8, Vp9, Av1, H264, H265 }
/// Explicit decoder abilities to send in a RustDesk option message.
/// I444 and non-default chroma are not advertised by this constructor.
#[derive(Debug, Clone, Copy)]
pub struct DecodingAdvertisement {
    pub vp8: bool, pub vp9: bool, pub av1: bool, pub h264: bool, pub h265: bool,
    pub preference: CodecPreference,
}

/// Existing source latency-probe fields. The peer controls all values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestDelay { pub time: i64, pub from_client: bool, pub last_delay: u32, pub target_bitrate: u32 }

/// Borrowed RustDesk password challenge fields.
pub struct PasswordChallenge<'a> {
    /// Public password salt.
    pub salt: &'a str,
    /// Public one-time challenge string.
    pub challenge: &'a str,
}

/// Borrowed basic desktop login fields.
///
/// These are untrusted peer-supplied values until separately authenticated.
/// `session_id` is RustDesk's wire ID, not the core's `SessionId` type.
pub struct DesktopLogin<'a> {
    /// Target login identity.
    pub username: &'a str,
    /// Claimed peer ID (not authenticated by itself).
    pub peer_id: &'a str,
    /// Claimed peer display name.
    pub peer_name: &'a str,
    /// Password challenge response; an empty response may request owner approval.
    pub password_response: &'a [u8],
    /// RustDesk wire-level session ID.
    pub session_id: u64,
    /// Peer version string.
    pub version: &'a str,
}

/// A RustDesk mouse event without its modifier list.
/// Use this view only when modifier information is not needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseEvent {
    /// Encoded mouse action and button mask.
    pub mask: i32,
    /// Desktop horizontal coordinate.
    pub x: i32,
    /// Desktop vertical coordinate.
    pub y: i32,
}

/// A borrowed keyboard event in the original RustDesk wire representation.
pub struct KeyboardEvent<'a> {
    event: &'a message_proto::KeyEvent,
}
impl<'a> KeyboardEvent<'a> {
    /// Whether the event indicates key down.
    pub fn down(&self) -> bool { self.event.down }
    /// Whether the event requests a press rather than a held key.
    pub fn press(&self) -> bool { self.event.press }
    /// Raw source keyboard mode enum value, including unknown values.
    pub fn mode(&self) -> i32 { self.event.mode.value() }
    /// Raw source control-key enum values for modifiers, including unknown values.
    pub fn modifiers(&self) -> impl Iterator<Item = i32> + '_ {
        self.event.modifiers.iter().map(|value| value.value())
    }
    /// View the key payload. An absent payload is not a valid input operation.
    pub fn payload(&self) -> Option<KeyboardPayload<'_>> {
        use message_proto::key_event::Union;
        match self.event.union.as_ref()? {
            Union::ControlKey(value) => Some(KeyboardPayload::ControlKey(value.value())),
            Union::Chr(value) => Some(KeyboardPayload::Position(*value)),
            Union::Unicode(value) => Some(KeyboardPayload::Unicode(*value)),
            Union::Seq(value) => Some(KeyboardPayload::Sequence(value.as_str())),
            Union::Win2winHotkey(value) => Some(KeyboardPayload::WindowsHotkey(*value)),
        }
    }
}

/// Key payload before platform- and layout-specific interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboardPayload<'a> {
    /// Raw source control-key enum value, which may be unknown.
    ControlKey(i32),
    /// Position key code; its platform meaning depends on keyboard mode.
    Position(u32),
    /// Unicode scalar or code as supplied by the peer; validate before use.
    Unicode(u32),
    /// UTF-8 text sequence supplied by the peer.
    Sequence(&'a str),
    /// RustDesk Windows-to-Windows hotkey encoding.
    WindowsHotkey(u32),
}

/// Video wire variants supported by the source schema, not a runtime support guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    /// VP8-encoded data.
    Vp8,
    /// VP9-encoded data.
    Vp9,
    /// AV1-encoded data.
    Av1,
    /// H.264-encoded data.
    H264,
    /// H.265-encoded data.
    H265,
    /// Raw RGB descriptor.
    Rgb,
    /// Raw YUV descriptor.
    Yuv,
}

/// Borrowed view of an existing RustDesk video payload.
pub struct VideoFrame<'a> {
    /// Source display index.
    pub display: i32,
    /// Encoded codec or raw pixel descriptor.
    pub codec: VideoCodec,
    packets: Option<&'a message_proto::EncodedVideoFrames>,
}
impl<'a> VideoFrame<'a> {
    /// Iterate over encoded packets in wire order. Raw descriptors have none.
    pub fn packets(&self) -> impl Iterator<Item = VideoPacket<'a>> + '_ {
        self.packets.into_iter().flat_map(|packets| packets.frames.iter()).map(|packet| VideoPacket {
            data: &packet.data, key: packet.key, pts: packet.pts,
        })
    }
}

/// Owned compressed packet supplied to a RustDesk video envelope.
#[derive(Clone, Debug)]
pub struct OwnedVideoPacket {
    /// Compressed bytes.
    pub data: Vec<u8>,
    /// Keyframe marker.
    pub key: bool,
    /// Presentation timestamp in the source protocol's units.
    pub pts: i64,
}

/// Borrowed encoded packet and its RustDesk timing metadata.
pub struct VideoPacket<'a> {
    /// Compressed bytes.
    pub data: &'a [u8],
    /// Keyframe marker.
    pub key: bool,
    /// Presentation timestamp in the source protocol's units.
    pub pts: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decoder_advertisement_round_trips_existing_schema() {
        let envelope = Envelope::supported_decoding_event(DecodingAdvertisement {
            vp8: true, vp9: true, av1: false, h264: true, h265: false, preference: CodecPreference::H264,
        });
        let bytes = envelope.encode(4096).unwrap();
        let parsed = Envelope::decode(&bytes, 4096).unwrap();
        let caps = parsed.supported_decoding().unwrap();
        assert_eq!((caps.vp8, caps.vp9, caps.av1, caps.h264, caps.h265), (1, 1, 0, 1, 0));
        assert_eq!(caps.preference, 2);
        assert!(caps.i444.is_none());
        assert_eq!(parsed.encode(4096).unwrap(), bytes);
    }
    #[test]
    fn source_supported_encoding_and_chroma_are_preserved() {
        let mut misc = message_proto::Misc::new();
        misc.set_supported_encoding(message_proto::SupportedEncoding {
            vp8: true, h264: true, h265: false, av1: false,
            i444: Some(message_proto::CodecAbility { h264: true, ..Default::default() }).into(),
            ..Default::default()
        });
        let mut message = Message::new(); message.set_misc(misc);
        let parsed = Envelope::decode(&message.write_to_bytes().unwrap(), 4096).unwrap();
        let caps = parsed.supported_encoding().unwrap();
        assert!(caps.vp8 && caps.h264 && !caps.h265);
        assert!(caps.i444.unwrap().h264);
    }
    #[test]
    fn password_challenge_and_basic_login_round_trip() {
        let challenge = Envelope::password_challenge_event("public-salt", "one-time-challenge").unwrap();
        let wire = challenge.encode(4096).unwrap();
        let parsed = Envelope::decode(&wire, 4096).unwrap();
        let view = parsed.password_challenge().unwrap();
        assert_eq!((view.salt, view.challenge), ("public-salt", "one-time-challenge"));
        let response = [9u8; 32];
        let login = Envelope::desktop_login_event(DesktopLogin { username: "host", peer_id: "viewer", peer_name: "display", password_response: &response, session_id: 42, version: "1" }).unwrap();
        let wire = login.encode(4096).unwrap();
        let parsed = Envelope::decode(&wire, 4096).unwrap();
        let view = parsed.desktop_login().unwrap();
        assert_eq!((view.username, view.peer_id, view.session_id), ("host", "viewer", 42));
        assert_eq!(view.password_response, &response);
    }
    #[test]
    fn rejects_oversize_and_non_video_inspection() {
        let mouse = Envelope::mouse_event(MouseEvent { mask: 0, x: -1, y: 1 });
        assert!(matches!(mouse.video(), Err(ProtocolError::UnexpectedMessage)));
        assert!(matches!(mouse.encode(1), Err(ProtocolError::TooLarge { .. })));
        assert!(matches!(Envelope::decode(&[0; 4097], 4096), Err(ProtocolError::TooLarge { .. })));
    }
}
