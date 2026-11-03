//! Bounded, caller-driven compressed-frame queue for one viewer/display/codec.
//!
//! Inspired by the pinned source's 120-entry predictive queue and keyframe
//! bypass (`src/client/io_loop.rs::handle_msg_from_peer`), but deliberately not
//! a drop-in copy: source force-pushes a predictive frame on overflow, requests
//! refresh, and sends keyframes through a separate unbounded channel. Here we
//! retain at most the caller's finite number/byte limit, clear queued data on
//! loss or a new keyframe, and require explicit decode completion. Only the
//! first packet's untrusted key flag is accepted as a restart hint. These rules
//! trade source throughput/behavior for bounded, conservative bookkeeping.
//!
//! No native decoder, network I/O, timer, renderer or OS permission is provided.
//! Protobuf parsing itself can allocate; byte caps do not bound native decoder
//! allocations, malicious bitstreams, queues elsewhere or memory held by callers.
//! Use actual native decoders only with locally produced trusted input.
use remote_protocol::{Envelope, ProtocolError, VideoCodec, MAX_ENVELOPE_BYTES};
use std::{collections::VecDeque, error::Error, fmt};
use zeroize::Zeroizing;

const MAX_FRAMES: usize = 120;
const MAX_QUEUED_BYTES: usize = 32 * 1024 * 1024;
#[derive(Debug)]
pub enum QueueError { InvalidLimit, InvalidStream, FrameTooLarge, Protocol(ProtocolError), MissingPackets, WrongStream, Busy, InvalidTicket, CounterExhausted }
impl fmt::Display for QueueError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "viewer video queue: {self:?}") } }
impl Error for QueueError {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult {
    Queued,
    /// A new key-marked message cleared older queued frames; caller must
    /// recreate/coordinate decoder and confirm actual decoding before sync.
    Keyframe { discarded: usize },
    /// Predictive input was dropped while waiting for a restart.
    AwaitKeyframe,
    /// Capacity was exceeded, queue cleared and refresh should be considered.
    NeedRefresh { discarded: usize },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion { Applied, Stale, DecodeFailed }
// Scrub queue-owned compressed screen data on discard/drop. Returned frames,
// parser/native copies, allocator copies and crash dumps are outside this scope.
struct Entry { bytes: Zeroizing<Vec<u8>>, keyframe: bool }
struct Pending { id: u64, generation: u64, bytes: usize, keyframe: bool }
/// One ownership-transferred message. Its data remains untrusted and may be
/// retained outside queue accounting; `complete` does not prove it was freed.
pub struct QueuedFrame { pub token: u64, pub generation: u64, pub keyframe: bool, pub bytes: Box<[u8]> }
/// A single-threaded queue. Wrap externally if needed; do not hold a mutex
/// across decoder work. Only one decode is in flight; finish before popping
/// another. Frame/ticket IDs and generation are process-local, not wire IDs.
pub struct ViewerVideoQueue {
    display: i32, codec: VideoCodec, frame_limit: usize, byte_limit: usize, message_limit: usize,
    entries: VecDeque<Entry>, queued_bytes: usize, in_flight: Option<Pending>,
    generation: u64, next_token: u64, synced: bool,
}
impl ViewerVideoQueue {
    pub fn new(display: i32, codec: VideoCodec, frame_limit: usize, byte_limit: usize, message_limit: usize) -> Result<Self, QueueError> {
        if display < 0 || matches!(codec, VideoCodec::Rgb | VideoCodec::Yuv) { return Err(QueueError::InvalidStream); }
        if frame_limit == 0 || frame_limit > MAX_FRAMES || byte_limit == 0 || byte_limit > MAX_QUEUED_BYTES
            || message_limit == 0 || message_limit > MAX_ENVELOPE_BYTES || message_limit > byte_limit { return Err(QueueError::InvalidLimit); }
        Ok(Self { display, codec, frame_limit, byte_limit, message_limit, entries: VecDeque::new(), queued_bytes: 0,
            in_flight: None, generation: 0, next_token: 0, synced: false })
    }
    /// Number of queued messages, excluding the in-flight ticket.
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    /// Locally accounted bytes, including the one in-flight ticket. Buffers
    /// retained by callers after completion are not included.
    pub fn accounted_bytes(&self) -> usize { self.queued_bytes + self.in_flight.as_ref().map_or(0, |pending| pending.bytes) }
    pub fn generation(&self) -> u64 { self.generation }
    pub fn synced(&self) -> bool { self.synced }
    fn next_generation(&self) -> Result<u64, QueueError> { self.generation.checked_add(1).ok_or(QueueError::CounterExhausted) }
    fn clear_entries(&mut self) -> usize {
        let count = self.entries.len(); self.entries.clear(); self.queued_bytes = 0; count
    }
    /// Forget queued frames and invalidate in-flight results on reconnect,
    /// topology change, decoder reset or explicit loss. An in-flight ticket
    /// still occupies its slot/bytes until `complete` or the queue is dropped.
    pub fn reset(&mut self) -> Result<usize, QueueError> {
        let generation = self.next_generation()?;
        let count = self.clear_entries(); self.synced = false; self.generation = generation; Ok(count)
    }
    /// Validate and retain a bounded envelope. A first-packet key flag is only
    /// a peer claim and does not prove a valid/independent keyframe. Input is
    /// consumed on every outcome. Any error leaves the queue unchanged: the
    /// caller must stop consuming, invalidate it with `reset`, coordinate a
    /// decoder reset and request a new keyframe before continuing. This also
    /// applies to incorrect topology/codec, malformed and oversized frames;
    /// never silently skip a possibly predictive frame. If reset fails, discard
    /// the queue. Rejected/overlapping input outside this object needs the same
    /// policy. A failed input must not be retried as if it had not arrived.
    pub fn push(&mut self, bytes: Box<[u8]>) -> Result<PushResult, QueueError> {
        // Ownership has transferred even on rejection; scrub this wrapper's
        // input on all paths where it is not retained or popped to the caller.
        let bytes = Zeroizing::new(bytes.into_vec());
        if bytes.is_empty() || bytes.len() > self.message_limit { return Err(QueueError::FrameTooLarge); }
        let envelope = Envelope::decode(&bytes, self.message_limit).map_err(QueueError::Protocol)?;
        let frame = envelope.video().map_err(QueueError::Protocol)?;
        if frame.display != self.display || frame.codec != self.codec { return Err(QueueError::WrongStream); }
        let keyframe = frame.packets().next().ok_or(QueueError::MissingPackets)?.key;
        if keyframe {
            let generation = self.next_generation()?;
            let discarded = self.clear_entries(); self.synced = false; self.generation = generation;
            let in_flight_bytes = self.in_flight.as_ref().map_or(0, |pending| pending.bytes);
            if self.frame_limit <= usize::from(self.in_flight.is_some()) || in_flight_bytes + bytes.len() > self.byte_limit {
                return Ok(PushResult::NeedRefresh { discarded: discarded + 1 });
            }
            self.queued_bytes = bytes.len(); self.entries.push_back(Entry { bytes, keyframe: true });
            return Ok(PushResult::Keyframe { discarded });
        }
        let pending_keyframe = self.entries.front().map_or(false, |entry| entry.keyframe)
            || self.in_flight.as_ref().map_or(false, |pending| pending.keyframe && pending.generation == self.generation);
        if !self.synced && !pending_keyframe { return Ok(PushResult::AwaitKeyframe); }
        if self.entries.len() + usize::from(self.in_flight.is_some()) >= self.frame_limit
            || self.accounted_bytes() + bytes.len() > self.byte_limit {
            let generation = self.next_generation()?;
            let discarded = self.clear_entries(); self.synced = false; self.generation = generation;
            return Ok(PushResult::NeedRefresh { discarded: discarded + 1 });
        }
        self.queued_bytes += bytes.len(); self.entries.push_back(Entry { bytes, keyframe: false });
        Ok(PushResult::Queued)
    }
    /// Transfer one ordered message for decode. The caller must subsequently
    /// report completion; neither popping nor a key flag is proof of decode.
    pub fn pop(&mut self) -> Result<Option<QueuedFrame>, QueueError> {
        if self.in_flight.is_some() { return Err(QueueError::Busy); }
        if self.entries.is_empty() { return Ok(None); }
        let token = self.next_token.checked_add(1).ok_or(QueueError::CounterExhausted)?;
        let Some(mut entry) = self.entries.pop_front() else { return Ok(None); };
        self.next_token = token; self.queued_bytes -= entry.bytes.len();
        self.in_flight = Some(Pending { id: token, generation: self.generation, bytes: entry.bytes.len(), keyframe: entry.keyframe });
        let bytes = std::mem::take(&mut *entry.bytes).into_boxed_slice();
        Ok(Some(QueuedFrame { token, generation: self.generation, keyframe: entry.keyframe, bytes }))
    }
    /// Check immediately before a caller-owned render; this check cannot be
    /// atomic with external rendering or concurrent topology/queue changes.
    pub fn is_current(&self, token: u64) -> bool {
        self.in_flight.as_ref().map_or(false, |pending| pending.id == token && pending.generation == self.generation)
    }
    /// Report one decode result. A failed decode invalidates all queued frames;
    /// recreate the actual decoder and request refresh separately. Old tickets
    /// release their accounting but cannot mark the new generation synchronized.
    pub fn complete(&mut self, token: u64, succeeded: bool) -> Result<Completion, QueueError> {
        let pending = self.in_flight.as_ref().ok_or(QueueError::InvalidTicket)?;
        if pending.id != token { return Err(QueueError::InvalidTicket); }
        if pending.generation != self.generation { self.in_flight.take(); return Ok(Completion::Stale); }
        if !succeeded {
            let generation = self.next_generation()?;
            self.in_flight.take(); self.clear_entries(); self.synced = false; self.generation = generation;
            return Ok(Completion::DecodeFailed);
        }
        let keyframe = pending.keyframe;
        self.in_flight.take();
        if keyframe { self.synced = true; }
        Ok(Completion::Applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_protocol::OwnedVideoPacket;
    fn wire(display: i32, codec: VideoCodec, key: bool, payload: usize) -> Box<[u8]> {
        Envelope::video_event(display, codec, &[OwnedVideoPacket { data: vec![7; payload], key, pts: 1 }])
            .unwrap().encode(1024 * 1024).unwrap().into_boxed_slice()
    }
    fn queue(frames: usize, bytes: usize, message: usize) -> ViewerVideoQueue {
        ViewerVideoQueue::new(0, VideoCodec::Vp9, frames, bytes, message).unwrap()
    }
    #[test]
    fn ordered_keyframe_completion_gates_predictive_input() {
        let mut q = queue(4, 4096, 1024);
        assert_eq!(q.push(wire(0, VideoCodec::Vp9, false, 4)).unwrap(), PushResult::AwaitKeyframe);
        assert_eq!(q.push(wire(0, VideoCodec::Vp9, true, 4)).unwrap(), PushResult::Keyframe { discarded: 0 });
        assert_eq!(q.push(wire(0, VideoCodec::Vp9, false, 4)).unwrap(), PushResult::Queued);
        let frame = q.pop().unwrap().unwrap(); assert!(frame.keyframe); assert!(q.is_current(frame.token));
        assert!(matches!(q.pop(), Err(QueueError::Busy)));
        assert!(matches!(q.complete(frame.token + 1, true), Err(QueueError::InvalidTicket)));
        assert_eq!(q.complete(frame.token, true).unwrap(), Completion::Applied); assert!(q.synced());
        let frame = q.pop().unwrap().unwrap(); assert!(!frame.keyframe);
        assert_eq!(q.complete(frame.token, true).unwrap(), Completion::Applied);
        assert!(q.is_empty()); assert_eq!(q.accounted_bytes(), 0);
    }
    #[test]
    fn overflow_invalidates_inflight_and_refuses_deltas_until_fresh_key() {
        let mut q = queue(2, 4096, 1024);
        q.push(wire(0, VideoCodec::Vp9, true, 4)).unwrap();
        let old = q.pop().unwrap().unwrap();
        q.push(wire(0, VideoCodec::Vp9, false, 4)).unwrap();
        assert_eq!(q.push(wire(0, VideoCodec::Vp9, false, 4)).unwrap(), PushResult::NeedRefresh { discarded: 2 });
        assert!(!q.is_current(old.token));
        assert_eq!(q.complete(old.token, true).unwrap(), Completion::Stale);
        assert!(!q.synced()); assert_eq!(q.accounted_bytes(), 0);
        assert_eq!(q.push(wire(0, VideoCodec::Vp9, false, 4)).unwrap(), PushResult::AwaitKeyframe);
        assert_eq!(q.push(wire(0, VideoCodec::Vp9, true, 4)).unwrap(), PushResult::Keyframe { discarded: 0 });
        let fresh = q.pop().unwrap().unwrap(); assert_eq!(q.complete(fresh.token, true).unwrap(), Completion::Applied);
        assert!(q.synced());
    }
    #[test]
    fn new_key_replaces_queued_frames_and_invalidates_old_ticket() {
        let mut q = queue(3, 4096, 1024);
        q.push(wire(0, VideoCodec::Vp9, true, 4)).unwrap();
        let old = q.pop().unwrap().unwrap();
        q.push(wire(0, VideoCodec::Vp9, false, 4)).unwrap();
        assert_eq!(q.push(wire(0, VideoCodec::Vp9, true, 4)).unwrap(), PushResult::Keyframe { discarded: 1 });
        assert_eq!(q.complete(old.token, false).unwrap(), Completion::Stale);
        let fresh = q.pop().unwrap().unwrap(); assert!(fresh.keyframe);
        assert_eq!(q.complete(fresh.token, true).unwrap(), Completion::Applied);
        assert!(q.synced());
    }
    #[test]
    fn failure_reset_and_invalid_data_keep_bounds() {
        let mut q = queue(2, 2048, 1024);
        q.push(wire(0, VideoCodec::Vp9, true, 4)).unwrap();
        let old = q.pop().unwrap().unwrap();
        assert!(matches!(q.push(wire(1, VideoCodec::Vp9, true, 4)), Err(QueueError::WrongStream)));
        assert!(matches!(q.push(wire(0, VideoCodec::Vp8, true, 4)), Err(QueueError::WrongStream)));
        assert!(matches!(q.push(vec![0u8; 1025].into_boxed_slice()), Err(QueueError::FrameTooLarge)));
        assert!(q.is_current(old.token));
        assert_eq!(q.complete(old.token, false).unwrap(), Completion::DecodeFailed);
        assert!(!q.synced()); assert_eq!(q.accounted_bytes(), 0);
        q.push(wire(0, VideoCodec::Vp9, true, 4)).unwrap();
        let old = q.pop().unwrap().unwrap(); q.reset().unwrap();
        assert!(!q.is_current(old.token)); assert_eq!(q.complete(old.token, true).unwrap(), Completion::Stale);
        assert_eq!(q.accounted_bytes(), 0);
    }
    #[test]
    fn keyframe_cannot_exceed_limits_while_previous_ticket_is_held() {
        let frame = wire(0, VideoCodec::Vp9, true, 20); let len = frame.len();
        let mut q = queue(2, len + 1, len);
        q.push(frame).unwrap(); let old = q.pop().unwrap().unwrap();
        assert_eq!(q.push(wire(0, VideoCodec::Vp9, true, 20)).unwrap(), PushResult::NeedRefresh { discarded: 1 });
        assert_eq!(q.complete(old.token, true).unwrap(), Completion::Stale);
        assert_eq!(q.accounted_bytes(), 0);
    }
}
