//! Caller-driven, per-connection cursor announcement bookkeeping inspired by
//! `MouseCursorSub::send` in the pinned `src/server/input_service.rs`.
//! This does not sample the OS, send messages, render a cursor, grant consent,
//! know the peer's cache, or resolve source content-ID collisions. There is no
//! automatic integration with HostConnection; all of that remains caller-owned.
use remote_protocol::{cursor::{CursorError, CursorShape, MAX_CACHE_BYTES, MAX_CACHE_ITEMS}, Envelope, ProtocolError};
use remote_session::SessionId;
use std::{collections::HashMap, error::Error, fmt};
use zeroize::Zeroize;

#[derive(Debug)]
pub enum DeliveryError { InvalidLimits, InvalidShape(CursorError), InvalidId, Collision, Full, Poisoned, Protocol(ProtocolError) }
impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid cursor delivery limits"),
            Self::InvalidShape(e) => write!(f, "invalid cursor shape: {e}"),
            Self::InvalidId => f.write_str("cursor ID does not match source content ID"),
            Self::Collision => f.write_str("different cursor shape has an existing ID"),
            Self::Full => f.write_str("cursor delivery cache full; close or restart the session"),
            Self::Poisoned => f.write_str("cursor delivery state is indeterminate"),
            Self::Protocol(e) => write!(f, "cursor wire: {e}"),
        }
    }
}
impl Error for DeliveryError {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnouncementKind { Shape, Id }
struct OwnedShape(CursorShape);
impl Drop for OwnedShape { fn drop(&mut self) { self.0.rgba.zeroize(); } }

/// Exactly one peer/session. This retains exact sent shapes, does not evict,
/// and fails on capacity instead of forgetting a possible content-ID collision.
/// Never reuse it across a reconnect or another viewer. Limits exclude wire,
/// native compression, caller copies and map/allocator overhead.
pub struct CursorDelivery {
    session: SessionId, sent: HashMap<u64, OwnedShape>, bytes: usize, max_items: usize, max_bytes: usize, poisoned: bool,
}
impl CursorDelivery {
    /// Bind to the application's unique local session ID; IDs are not peer
    /// authentication and can be reused accidentally by the caller.
    pub fn new(session: SessionId, max_items: usize, max_bytes: usize) -> Result<Self, DeliveryError> {
        if max_items == 0 || max_items > MAX_CACHE_ITEMS || max_bytes == 0 || max_bytes > MAX_CACHE_BYTES { return Err(DeliveryError::InvalidLimits); }
        Ok(Self { session, sent: HashMap::new(), bytes: 0, max_items, max_bytes, poisoned: false })
    }
    /// Build a source wire announcement but do not send it. Shape ID must be
    /// the existing source 53-bit content hash. A recorded ID with nonidentical
    /// geometry/pixels is rejected, not silently aliased. Local capacity must
    /// be selected before the connection; a full cache requires session reset.
    /// `force_shape` sends full data again when the peer may have evicted it.
    /// An ID announcement assumes peer retention and can still miss. Keep the
    /// returned pending object until send completes; dropping it without an
    /// explicit outcome permanently poisons this book for the current session.
    pub fn prepare(&mut self, shape: CursorShape, force_shape: bool) -> Result<PendingAnnouncement<'_>, DeliveryError> {
        let shape = OwnedShape(shape);
        if self.poisoned { return Err(DeliveryError::Poisoned); }
        let id = shape.0.id;
        if shape.0.source_content_id().map_err(DeliveryError::InvalidShape)? != id { return Err(DeliveryError::InvalidId); }
        let known = if let Some(previous) = self.sent.get(&id) {
            if previous.0 != shape.0 { return Err(DeliveryError::Collision); }
            true
        } else {
            if self.sent.len() >= self.max_items || shape.0.rgba.len() > self.max_bytes.saturating_sub(self.bytes) {
                return Err(DeliveryError::Full);
            }
            false
        };
        let kind = if known && !force_shape { AnnouncementKind::Id } else { AnnouncementKind::Shape };
        let wire = match kind {
            AnnouncementKind::Shape => Envelope::cursor_shape_event(&shape.0).map_err(DeliveryError::InvalidShape)?,
            AnnouncementKind::Id => Envelope::cursor_id_event(id),
        };
        let new_shape = if known { None } else { Some(shape) };
        Ok(PendingAnnouncement { book: self, id, kind, wire, new_shape, finished: false })
    }
    /// Prepare a full retained shape for a peer's explicit resend request.
    /// `None` means the ID was not sent/retained by this book. Caller still
    /// verifies current view permission and freshness before sending.
    pub fn prepare_resend(&mut self, id: u64) -> Result<Option<PendingAnnouncement<'_>>, DeliveryError> {
        if self.poisoned { return Err(DeliveryError::Poisoned); }
        let shape = match self.sent.get(&id) { Some(shape) => shape, None => return Ok(None) };
        let wire = Envelope::cursor_shape_event(&shape.0).map_err(DeliveryError::InvalidShape)?;
        Ok(Some(PendingAnnouncement { book: self, id, kind: AnnouncementKind::Shape, wire, new_shape: None, finished: false }))
    }
    pub fn session_id(&self) -> SessionId { self.session }
    pub fn retained_bytes(&self) -> usize { self.bytes }
    pub fn len(&self) -> usize { self.sent.len() }
    pub fn is_empty(&self) -> bool { self.sent.is_empty() }
    pub fn is_poisoned(&self) -> bool { self.poisoned }
}
/// Owns the bookkeeping transaction, not a transport. Committing is a trusted
/// caller assertion, not proof the peer received, decoded or retained the shape.
/// The encoded Vec must be handled separately and may retain private pixels.
pub struct PendingAnnouncement<'a> {
    book: &'a mut CursorDelivery, id: u64, kind: AnnouncementKind, wire: Envelope,
    new_shape: Option<OwnedShape>, finished: bool,
}
impl PendingAnnouncement<'_> {
    pub fn kind(&self) -> AnnouncementKind { self.kind }
    pub fn encode(&self, limit: usize) -> Result<Vec<u8>, DeliveryError> { self.wire.encode(limit).map_err(DeliveryError::Protocol) }
    /// Call only when the complete send returned success. An ACK is not proof
    /// of a peer cache. If send fails or is cancelled, drop to poison instead.
    pub fn sent(mut self) {
        if let Some(shape) = self.new_shape.take() {
            self.book.bytes += shape.0.rgba.len();
            self.book.sent.insert(self.id, shape);
        }
        self.finished = true;
    }
    /// Call only if no send was started, e.g. local encoding failed. The caller
    /// is responsible for ensuring no bytes escaped and no task is in flight.
    pub fn discard_before_send(mut self) { self.finished = true; }
}
impl Drop for PendingAnnouncement<'_> {
    fn drop(&mut self) { if !self.finished { self.book.poisoned = true; } }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn shape(rgba: [u8; 4]) -> CursorShape {
        let mut shape = CursorShape { id: 0, hotx: 0, hoty: 0, width: 1, height: 1, rgba: rgba.to_vec() };
        shape.id = shape.source_content_id().unwrap(); shape
    }
    #[test]
    fn shape_then_id_with_explicit_resend_and_capacity() {
        let first = shape([1, 2, 3, 4]);
        let mut book = CursorDelivery::new(SessionId::new([1; 16]).unwrap(), 1, 4).unwrap();
        let pending = book.prepare(first.clone(), false).unwrap();
        assert_eq!(pending.kind(), AnnouncementKind::Shape);
        assert_eq!(Envelope::decode(&pending.encode(4096).unwrap(), 4096).unwrap().cursor_shape().unwrap(), first);
        pending.sent();
        assert_eq!((book.len(), book.retained_bytes()), (1, 4));
        assert!(book.prepare_resend(first.id + 1).unwrap().is_none());
        let resend = book.prepare_resend(first.id).unwrap().unwrap();
        assert_eq!(resend.kind(), AnnouncementKind::Shape);
        assert_eq!(Envelope::decode(&resend.encode(4096).unwrap(), 4096).unwrap().cursor_shape().unwrap(), first);
        resend.sent();
        let pending = book.prepare(first.clone(), false).unwrap();
        assert_eq!(pending.kind(), AnnouncementKind::Id);
        assert_eq!(Envelope::decode(&pending.encode(4096).unwrap(), 4096).unwrap().cursor_id().unwrap(), first.id);
        pending.sent();
        let pending = book.prepare(first, true).unwrap();
        assert_eq!(pending.kind(), AnnouncementKind::Shape); pending.sent();
        assert!(matches!(book.prepare(shape([4, 3, 2, 1]), false), Err(DeliveryError::Full)));
        assert_eq!(book.len(), 1);
    }
    #[test]
    fn bytes_limit_and_peer_session_books_are_independent() {
        let first = shape([1, 2, 3, 4]); let second = shape([4, 3, 2, 1]);
        let mut left = CursorDelivery::new(SessionId::new([1; 16]).unwrap(), 2, 4).unwrap();
        let mut right = CursorDelivery::new(SessionId::new([2; 16]).unwrap(), 2, 4).unwrap();
        assert_ne!(left.session_id(), right.session_id());
        left.prepare(first.clone(), false).unwrap().sent();
        assert!(matches!(left.prepare(second, false), Err(DeliveryError::Full)));
        assert_eq!(left.retained_bytes(), 4);
        let pending = right.prepare(first, false).unwrap();
        assert_eq!(pending.kind(), AnnouncementKind::Shape);
        pending.discard_before_send();
        assert!(right.is_empty());
    }
    #[test]
    fn never_commit_undelivered_shape_and_poison_unknown_outcome() {
        let mut book = CursorDelivery::new(SessionId::new([1; 16]).unwrap(), 2, 8).unwrap();
        let first = shape([1, 2, 3, 4]);
        let pending = book.prepare(first.clone(), false).unwrap();
        assert!(pending.encode(0).is_err());
        pending.discard_before_send();
        assert!(book.is_empty()); assert!(!book.is_poisoned());
        { let _unknown = book.prepare(first.clone(), false).unwrap(); }
        assert!(book.is_poisoned());
        assert!(matches!(book.prepare_resend(first.id), Err(DeliveryError::Poisoned)));
        assert!(matches!(book.prepare(first, false), Err(DeliveryError::Poisoned)));
    }
    #[test]
    fn rejects_invalid_limits_and_shapes_before_any_delivery() {
        let id = SessionId::new([1; 16]).unwrap();
        assert!(matches!(CursorDelivery::new(id, 0, 4), Err(DeliveryError::InvalidLimits)));
        assert!(matches!(CursorDelivery::new(id, MAX_CACHE_ITEMS + 1, 4), Err(DeliveryError::InvalidLimits)));
        assert!(matches!(CursorDelivery::new(id, 1, 0), Err(DeliveryError::InvalidLimits)));
        assert!(matches!(CursorDelivery::new(id, 1, MAX_CACHE_BYTES + 1), Err(DeliveryError::InvalidLimits)));
        let mut book = CursorDelivery::new(id, 1, 4).unwrap();
        let mut invalid = shape([1, 2, 3, 4]); invalid.hotx = 1;
        assert!(matches!(book.prepare(invalid, false), Err(DeliveryError::InvalidShape(_))));
        assert!(book.is_empty()); assert!(!book.is_poisoned());
    }
    #[test]
    fn mismatched_id_and_recorded_collision_are_rejected() {
        let mut book = CursorDelivery::new(SessionId::new([1; 16]).unwrap(), 2, 8).unwrap();
        let first = shape([1, 2, 3, 4]);
        let mut wrong = first.clone(); wrong.id ^= 1;
        assert!(matches!(book.prepare(wrong, false), Err(DeliveryError::InvalidId)));
        // Inject a conflicting stored entry to exercise a collision without
        // attempting to brute-force the 53-bit source content hash.
        let mut conflicting = first.clone(); conflicting.rgba[0] ^= 1;
        book.bytes = 4; book.sent.insert(first.id, OwnedShape(conflicting));
        assert!(matches!(book.prepare(first, false), Err(DeliveryError::Collision)));
    }
}
