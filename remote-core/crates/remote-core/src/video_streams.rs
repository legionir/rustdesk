//! Explicit per-display decoder synchronization for multiple streams.
//!
//! This is bookkeeping only: no native decoder, buffering, rendering, refresh,
//! ACK or scheduling is performed. Display indices are volatile untrusted wire
//! values; callers must bind them to an approved, current topology. A changed
//! codec or topology requires the caller to replace the decoder and tracker.
use crate::video_sync::{Decision, SyncError, VideoSync};
use remote_protocol::{Envelope, ProtocolError, VideoCodec};
use std::{collections::BTreeMap, error::Error, fmt};

const MAX_STREAMS: usize = 8;
#[derive(Debug)]
pub enum StreamError { InvalidDisplay, Capacity, Duplicate, Unknown, Protocol(ProtocolError), Sync(SyncError) }
impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "video streams: {self:?}") }
}
impl Error for StreamError {}
impl From<ProtocolError> for StreamError { fn from(error: ProtocolError) -> Self { Self::Protocol(error) } }
impl From<SyncError> for StreamError { fn from(error: SyncError) -> Self { Self::Sync(error) } }
/// Bounded independent recovery trackers; ownership of actual decoders remains
/// external. No thread or memory isolation for native decoders is provided.
pub struct VideoStreams { streams: BTreeMap<i32, VideoSync> }
impl VideoStreams {
    pub fn new() -> Self { Self { streams: BTreeMap::new() } }
    /// Register only after external authorization and codec selection. Newly
    /// registered streams require a keyframe before a decode is allowed.
    pub fn register(&mut self, display: i32, codec: VideoCodec) -> Result<(), StreamError> {
        if display < 0 { return Err(StreamError::InvalidDisplay); }
        if self.streams.contains_key(&display) { return Err(StreamError::Duplicate); }
        if self.streams.len() >= MAX_STREAMS { return Err(StreamError::Capacity); }
        self.streams.insert(display, VideoSync::new(display, codec)?); Ok(())
    }
    /// Validate one frame against an existing tracker and mark a decode pending.
    /// The returned display identifies which decoder the caller must use.
    pub fn begin(&mut self, envelope: &Envelope) -> Result<(i32, Decision), StreamError> {
        let display = envelope.video()?.display;
        let stream = self.streams.get_mut(&display).ok_or(StreamError::Unknown)?;
        Ok((display, stream.begin(envelope)?))
    }
    /// Complete exactly one pending decode for the selected display. Failure
    /// resets the tracker; the caller must discard/recreate its actual decoder.
    pub fn complete(&mut self, display: i32, succeeded: bool) -> Result<(), StreamError> {
        self.streams.get_mut(&display).ok_or(StreamError::Unknown)?.complete(succeeded)?; Ok(())
    }
    pub fn reset(&mut self, display: i32) -> Result<(), StreamError> {
        self.streams.get_mut(&display).ok_or(StreamError::Unknown)?.reset(); Ok(())
    }
    /// Remove a tracker when the caller has stopped/discarded its decoder.
    pub fn remove(&mut self, display: i32) -> bool { self.streams.remove(&display).is_some() }
    pub fn len(&self) -> usize { self.streams.len() }
    pub fn is_empty(&self) -> bool { self.streams.is_empty() }
}
impl Default for VideoStreams { fn default() -> Self { Self::new() } }
#[cfg(test)]
mod tests {
    use super::*;
    use remote_protocol::OwnedVideoPacket;
    fn frame(display: i32, key: bool) -> Envelope {
        Envelope::video_event(display, VideoCodec::Vp9, &[OwnedVideoPacket { data: vec![1], key, pts: 0 }]).unwrap()
    }
    #[test]
    fn independent_displays_recover_separately() {
        let mut streams = VideoStreams::new();
        streams.register(0, VideoCodec::Vp9).unwrap(); streams.register(1, VideoCodec::Vp9).unwrap();
        assert!(matches!(streams.register(0, VideoCodec::Vp9), Err(StreamError::Duplicate)));
        assert_eq!(streams.begin(&frame(0, true)).unwrap(), (0, Decision::Decode));
        streams.complete(0, true).unwrap();
        assert_eq!(streams.begin(&frame(1, false)).unwrap(), (1, Decision::AwaitKeyframe));
        assert_eq!(streams.begin(&frame(0, false)).unwrap(), (0, Decision::Decode));
        streams.complete(0, false).unwrap();
        assert_eq!(streams.begin(&frame(0, false)).unwrap(), (0, Decision::AwaitKeyframe));
        assert!(matches!(streams.begin(&frame(2, true)), Err(StreamError::Unknown)));
    }
    #[test]
    fn stream_capacity_is_bounded() {
        let mut streams = VideoStreams::new();
        for display in 0..8 { streams.register(display, VideoCodec::Vp9).unwrap(); }
        assert!(matches!(streams.register(8, VideoCodec::Vp9), Err(StreamError::Capacity)));
        assert!(streams.remove(4)); streams.register(8, VideoCodec::Vp9).unwrap();
    }
}
