//! Existing `Misc` video control fields; no new wire protocol.
//! Constructing/parsing a request does not authorize, handle or rate-limit it.
use crate::{message, message_proto, Envelope};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoControl {
    RefreshAll,
    RefreshDisplay(u32),
    FrameReceived,
    /// Legacy peer-reported auto-adjust cap; source accepts 1..=120.
    AutoAdjustFps(u32),
    /// Untrusted peer recording claim. This neither starts nor stops recording.
    ClientRecording(bool),
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
            VideoControl::AutoAdjustFps(fps) if (1..=120).contains(&fps) => misc.set_auto_adjust_fps(fps),
            VideoControl::AutoAdjustFps(_) => return None,
            VideoControl::ClientRecording(active) => misc.set_client_record_status(active),
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
                message_proto::misc::Union::AutoAdjustFps(fps) if (1..=120).contains(fps) => Some(VideoControl::AutoAdjustFps(*fps)),
                message_proto::misc::Union::ClientRecordStatus(active) => Some(VideoControl::ClientRecording(*active)),
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
    fn source_controls_round_trip_with_bounded_display_index() {
        for event in [VideoControl::RefreshAll, VideoControl::RefreshDisplay(3), VideoControl::FrameReceived, VideoControl::AutoAdjustFps(30), VideoControl::ClientRecording(false), VideoControl::ClientRecording(true)] {
            let bytes = Envelope::video_control_event(event).unwrap().encode(128).unwrap();
            assert_eq!(Envelope::decode(&bytes, 128).unwrap().video_control(), Some(event));
        }
        assert!(Envelope::video_control_event(VideoControl::RefreshDisplay(u32::MAX)).is_none());
        assert!(Envelope::video_control_event(VideoControl::AutoAdjustFps(0)).is_none());
        assert!(Envelope::video_control_event(VideoControl::AutoAdjustFps(121)).is_none());
    }
}
