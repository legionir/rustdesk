//! Optional conservative software-stream recovery bookkeeping.
//!
//! This is not the source QoS implementation, a decoder, a security boundary,
//! or proof that a keyframe flag is truthful. One instance tracks exactly one
//! logical display/codec; the caller owns decoder creation, refresh requests,
//! render acknowledgements and any ordering guarantees.

use remote_protocol::{Envelope, ProtocolError, VideoCodec};
use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Ignore this predictive message until a keyframe arrives.
    AwaitKeyframe,
    /// The caller may try to decode this message, then must report the outcome.
    Decode,
}
#[derive(Debug)]
pub enum SyncError { InvalidDisplay, PendingDecode, NoPendingDecode, MismatchedStream, Protocol(ProtocolError) }
impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDisplay => f.write_str("display index must be nonnegative"),
            Self::PendingDecode => f.write_str("previous decode outcome not reported"),
            Self::NoPendingDecode => f.write_str("no decode awaiting an outcome"),
            Self::MismatchedStream => f.write_str("display or codec changed"),
            Self::Protocol(e) => write!(f, "video protocol: {e}"),
        }
    }
}
impl Error for SyncError {}
impl From<ProtocolError> for SyncError { fn from(e: ProtocolError) -> Self { Self::Protocol(e) } }

/// Ordered caller-driven tracking for one independently decoded video stream.
pub struct VideoSync { display: i32, codec: VideoCodec, synced: bool, pending: bool }
impl VideoSync {
    /// Construct a tracker. Initially a keyframe is required.
    pub fn new(display: i32, codec: VideoCodec) -> Result<Self, SyncError> {
        if display < 0 { return Err(SyncError::InvalidDisplay); }
        Ok(Self { display, codec, synced: false, pending: false })
    }
    /// Inspect an already size-bounded envelope before decoding. A known loss,
    /// decode error or transport interruption must be reported through `reset`.
    /// The first encoded packet's wire key flag is only a hint supplied by the
    /// peer; it does not validate the bitstream or bound decoder allocations.
    pub fn begin(&mut self, envelope: &Envelope) -> Result<Decision, SyncError> {
        if self.pending { return Err(SyncError::PendingDecode); }
        let frame = envelope.video()?;
        if frame.display != self.display || frame.codec != self.codec { return Err(SyncError::MismatchedStream); }
        let first = frame.packets().next().ok_or(SyncError::MismatchedStream)?;
        if !self.synced && !first.key { return Ok(Decision::AwaitKeyframe); }
        self.pending = true;
        Ok(Decision::Decode)
    }
    /// Report whether decoding succeeded. `true` means the decoder accepted the
    /// message, not necessarily that a frame was rendered or an ACK is due.
    /// A failure requires the caller to discard/recreate the actual decoder.
    pub fn complete(&mut self, succeeded: bool) -> Result<(), SyncError> {
        if !self.pending { return Err(SyncError::NoPendingDecode); }
        self.pending = false;
        self.synced = succeeded;
        Ok(())
    }
    /// Mark a loss, reconnect, decoder replacement or cancelled decode. Caller
    /// must recreate its decoder and request a refresh separately as appropriate.
    pub fn reset(&mut self) { self.synced = false; self.pending = false; }
    pub fn awaiting_keyframe(&self) -> bool { !self.synced }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_protocol::OwnedVideoPacket;
    fn frame(key: bool, display: i32) -> Envelope {
        Envelope::video_event(display, VideoCodec::Vp9, &[OwnedVideoPacket { data: vec![1], key, pts: 1 }]).unwrap()
    }
    #[test]
    fn tracks_keyframe_failure_and_explicit_recovery() {
        let mut sync = VideoSync::new(0, VideoCodec::Vp9).unwrap();
        assert_eq!(sync.begin(&frame(false, 0)).unwrap(), Decision::AwaitKeyframe);
        assert_eq!(sync.begin(&frame(true, 0)).unwrap(), Decision::Decode);
        assert!(matches!(sync.begin(&frame(true, 0)), Err(SyncError::PendingDecode)));
        sync.complete(true).unwrap();
        assert_eq!(sync.begin(&frame(false, 0)).unwrap(), Decision::Decode);
        sync.complete(false).unwrap();
        assert!(sync.awaiting_keyframe());
        assert_eq!(sync.begin(&frame(false, 0)).unwrap(), Decision::AwaitKeyframe);
        assert!(matches!(sync.begin(&frame(true, 1)), Err(SyncError::MismatchedStream)));
        sync.reset();
    }
}
