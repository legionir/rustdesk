//! Existing `Misc` video control fields; no new wire protocol.
//! Constructing/parsing a request does not authorize, handle or rate-limit it.
use crate::{message, message_proto, Envelope};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoControl {
    RefreshAll,
    RefreshDisplay(u32),
    FrameReceived,
}
impl Envelope {
    /// Construct an existing source video refresh or received notification.
    /// Display indices are bounded to the signed protobuf field's range.
    pub fn video_control_event(control: VideoControl) -> Option<Self> {
        let mut misc = message_proto::Misc::new();
        match control {
            VideoControl::RefreshAll => misc.set_refresh_video(true),
            VideoControl::RefreshDisplay(index) => misc.set_refresh_video_display(i32::try_from(index).ok()?),
            VideoControl::FrameReceived => misc.set_video_received(true),
        }
        let mut inner = message_proto::Message::new(); inner.set_misc(misc); Some(Self { inner })
    }
    /// Inspect only these known variants. Negative display IDs and a false
    /// refresh-all are ignored rather than cast into large display indices.
    pub fn video_control(&self) -> Option<VideoControl> {
        match self.inner.union.as_ref()? {
            message::Union::Misc(misc) => match misc.union.as_ref()? {
                message_proto::misc::Union::RefreshVideo(true) => Some(VideoControl::RefreshAll),
                message_proto::misc::Union::RefreshVideoDisplay(index) if *index >= 0 => Some(VideoControl::RefreshDisplay(*index as u32)),
                message_proto::misc::Union::VideoReceived(_) => Some(VideoControl::FrameReceived),
                _ => None,
            },
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_controls_round_trip_without_altering_unknown_fields() {
        for event in [VideoControl::RefreshAll, VideoControl::RefreshDisplay(3), VideoControl::FrameReceived] {
            let bytes = Envelope::video_control_event(event).unwrap().encode(128).unwrap();
            assert_eq!(Envelope::decode(&bytes, 128).unwrap().video_control(), Some(event));
        }
        assert!(Envelope::video_control_event(VideoControl::RefreshDisplay(u32::MAX)).is_none());
    }
}
