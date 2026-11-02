//! Experimental adapter for RustDesk's existing desktop protobuf schema.
//!
//! This is not a new protocol or a full security boundary. It preserves all
//! recognized and unknown fields on envelopes with a recognized payload when
//! decoded and re-encoded, but callers must still authorize each message and validate its
//! fields before acting. Parsing does not authenticate the sender, prevent
//! replay, or enforce all semantic and memory-allocation limits.

use base::message_proto::{self, message, video_frame, Message};
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
            Some(message::Union::KeyEvent(_)) => MessageKind::Keyboard,
            Some(message::Union::LoginRequest(_)) | Some(message::Union::LoginResponse(_))
            | Some(message::Union::Hash(_)) | Some(message::Union::Auth2fa(_))
            | Some(message::Union::PublicKey(_)) | Some(message::Union::SignedId(_)) => MessageKind::Authentication,
            Some(message::Union::TestDelay(_)) => MessageKind::TestDelay,
            Some(message::Union::Misc(_)) => MessageKind::Misc,
            _ => MessageKind::Other,
        }
    }
    /// Inspect a mouse event. Coordinates and mask retain RustDesk semantics;
    /// they are not automatically mapped to a local monitor or authorized.
    pub fn mouse(&self) -> Result<MouseEvent, ProtocolError> {
        match self.inner.union.as_ref() {
            Some(message::Union::MouseEvent(event)) => Ok(MouseEvent { mask: event.mask, x: event.x, y: event.y }),
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
