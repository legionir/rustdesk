//! RustDesk cursor wire compatibility and bounded RGBA shape cache.
//!
//! The source server compresses cursor RGBA using zstd; the source client
//! validates 1..=512 dimensions, hotspot and exact decoded RGBA length. This
//! module follows those limits but is untested and not a general decompression
//! sandbox. Cursor content is untrusted until the session is authenticated.

use super::{message, message_proto, Envelope};
use std::{collections::{HashMap, VecDeque}, error::Error, fmt};

/// Source client maximum dimension; maximum decoded shape is 1 MiB.
pub const MAX_CURSOR_DIMENSION: i32 = 512;
/// Hard ceiling for one cache's retained RGBA bytes, excluding overhead.
pub const MAX_CACHE_BYTES: usize = 8 * 1024 * 1024;
/// Hard ceiling for retained cursor shape IDs.
pub const MAX_CACHE_ITEMS: usize = 512;

/// Cursor shape data as decoded RGBA. IDs are 64-bit and should be exposed to
/// JavaScript as decimal strings, not numbers, to avoid precision loss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorShape {
    pub id: u64,
    pub hotx: i32,
    pub hoty: i32,
    pub width: i32,
    pub height: i32,
    pub rgba: Vec<u8>,
}
/// A position in the coordinates supplied by the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorPosition { pub x: i32, pub y: i32 }

/// Invalid cursor content, cache limits or message kind.
#[derive(Debug)]
pub enum CursorError {
    UnexpectedMessage,
    InvalidDimensions,
    InvalidHotspot,
    InvalidLength,
    CompressedTooLarge,
    Compression(String),
    InvalidCacheLimits,
    ShapeTooLargeForCache,
}
impl fmt::Display for CursorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedMessage => f.write_str("unexpected cursor message"),
            Self::InvalidDimensions => f.write_str("invalid cursor dimensions"),
            Self::InvalidHotspot => f.write_str("cursor hotspot is outside the image"),
            Self::InvalidLength => f.write_str("invalid decoded cursor length"),
            Self::CompressedTooLarge => f.write_str("compressed cursor exceeds source bound"),
            Self::Compression(e) => write!(f, "cursor zstd: {e}"),
            Self::InvalidCacheLimits => f.write_str("invalid cursor cache limits"),
            Self::ShapeTooLargeForCache => f.write_str("cursor is larger than cache capacity"),
        }
    }
}
impl Error for CursorError {}

fn expected_len(width: i32, height: i32, hotx: i32, hoty: i32) -> Result<usize, CursorError> {
    if !(1..=MAX_CURSOR_DIMENSION).contains(&width) || !(1..=MAX_CURSOR_DIMENSION).contains(&height) { return Err(CursorError::InvalidDimensions); }
    if !(0..width).contains(&hotx) || !(0..height).contains(&hoty) { return Err(CursorError::InvalidHotspot); }
    (width as usize).checked_mul(height as usize).and_then(|n| n.checked_mul(4)).ok_or(CursorError::InvalidDimensions)
}
impl CursorShape {
    /// Validate dimensions, hotspot and exact packed RGBA length.
    pub fn validate(&self) -> Result<(), CursorError> {
        if self.rgba.len() != expected_len(self.width, self.height, self.hotx, self.hoty)? { return Err(CursorError::InvalidLength); }
        Ok(())
    }
}

impl Envelope {
    /// Decode one RustDesk zstd-compressed cursor shape with source bounds.
    pub fn cursor_shape(&self) -> Result<CursorShape, CursorError> {
        let data = match self.inner.union.as_ref() {
            Some(message::Union::CursorData(data)) => data,
            _ => return Err(CursorError::UnexpectedMessage),
        };
        let expected = expected_len(data.width, data.height, data.hotx, data.hoty)?;
        if data.colors.len() > zstd::zstd_safe::compress_bound(expected) { return Err(CursorError::CompressedTooLarge); }
        let rgba = zstd::bulk::decompress(&data.colors, expected).map_err(|e| CursorError::Compression(e.to_string()))?;
        if rgba.len() != expected { return Err(CursorError::InvalidLength); }
        Ok(CursorShape { id: data.id, hotx: data.hotx, hoty: data.hoty, width: data.width, height: data.height, rgba })
    }
    /// Compress a validated RGBA shape into the original RustDesk schema.
    pub fn cursor_shape_event(shape: &CursorShape) -> Result<Self, CursorError> {
        shape.validate()?;
        let colors = zstd::bulk::compress(&shape.rgba, 3).map_err(|e| CursorError::Compression(e.to_string()))?;
        let data = message_proto::CursorData { id: shape.id, hotx: shape.hotx, hoty: shape.hoty,
            width: shape.width, height: shape.height, colors: colors.into(), ..Default::default() };
        let mut inner = message_proto::Message::new(); inner.set_cursor_data(data);
        Ok(Self { inner })
    }
    /// Inspect a RustDesk cursor ID message.
    pub fn cursor_id(&self) -> Result<u64, CursorError> {
        match self.inner.union.as_ref() { Some(message::Union::CursorId(id)) => Ok(*id), _ => Err(CursorError::UnexpectedMessage) }
    }
    /// Construct a RustDesk cursor ID selection message.
    pub fn cursor_id_event(id: u64) -> Self {
        let mut inner = message_proto::Message::new(); inner.set_cursor_id(id); Self { inner }
    }
    /// Inspect a RustDesk cursor-position message.
    pub fn cursor_position(&self) -> Result<CursorPosition, CursorError> {
        match self.inner.union.as_ref() {
            Some(message::Union::CursorPosition(p)) => Ok(CursorPosition { x: p.x, y: p.y }),
            _ => Err(CursorError::UnexpectedMessage),
        }
    }
    /// Construct a cursor-position message in peer-provided coordinates.
    pub fn cursor_position_event(position: CursorPosition) -> Self {
        let mut inner = message_proto::Message::new();
        inner.set_cursor_position(message_proto::CursorPosition { x: position.x, y: position.y, ..Default::default() });
        Self { inner }
    }
    /// Ask a supporting RustDesk host to resend a cached shape by ID.
    /// Availability depends on peer version and is not guaranteed.
    pub fn request_cursor_shape_event(id: u64) -> Self {
        let mut misc = message_proto::Misc::new(); misc.set_request_cursor_data(id);
        let mut inner = message_proto::Message::new(); inner.set_misc(misc); Self { inner }
    }
}

/// Small LRU cache bounded by entry count and retained RGBA bytes.
///
/// This excludes map/allocator overhead and shapes borrowed or cloned by the
/// application. No deduplication by content or automatic network requests are
/// performed. The caller owns selected-ID state and handles eviction/misses.
pub struct CursorCache {
    shapes: HashMap<u64, CursorShape>,
    order: VecDeque<u64>,
    bytes: usize,
    max_items: usize,
    max_bytes: usize,
}
impl CursorCache {
    /// Create a cache with explicit limits within the hard ceilings.
    pub fn new(max_items: usize, max_bytes: usize) -> Result<Self, CursorError> {
        if max_items == 0 || max_items > MAX_CACHE_ITEMS || max_bytes == 0 || max_bytes > MAX_CACHE_BYTES {
            return Err(CursorError::InvalidCacheLimits);
        }
        Ok(Self { shapes: HashMap::new(), order: VecDeque::new(), bytes: 0, max_items, max_bytes })
    }
    /// Store a validated shape, replacing the same ID and evicting oldest IDs.
    pub fn insert(&mut self, shape: CursorShape) -> Result<(), CursorError> {
        shape.validate()?;
        let size = shape.rgba.len();
        if size > self.max_bytes { return Err(CursorError::ShapeTooLargeForCache); }
        if let Some(old) = self.shapes.remove(&shape.id) {
            self.bytes -= old.rgba.len();
            self.order.retain(|id| *id != shape.id);
        }
        while self.shapes.len() >= self.max_items || self.bytes + size > self.max_bytes {
            if let Some(id) = self.order.pop_front() {
                if let Some(old) = self.shapes.remove(&id) { self.bytes -= old.rgba.len(); }
            } else { break; }
        }
        self.bytes += size;
        self.order.push_back(shape.id);
        self.shapes.insert(shape.id, shape);
        Ok(())
    }
    /// Retrieve and mark a shape recently used. A miss may require a source
    /// `request_cursor_data` message if the remote peer supports it.
    pub fn get(&mut self, id: u64) -> Option<&CursorShape> {
        if self.shapes.contains_key(&id) {
            self.order.retain(|old| *old != id);
            self.order.push_back(id);
        }
        self.shapes.get(&id)
    }
    /// Remove all cached shapes.
    pub fn clear(&mut self) { self.shapes.clear(); self.order.clear(); self.bytes = 0; }
    /// Current retained RGBA bytes (excludes allocation overhead).
    pub fn retained_bytes(&self) -> usize { self.bytes }
    /// Number of retained IDs.
    pub fn len(&self) -> usize { self.shapes.len() }
    /// Whether the cache has no shapes.
    pub fn is_empty(&self) -> bool { self.shapes.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn shape(id: u64) -> CursorShape { CursorShape { id, hotx: 0, hoty: 1, width: 2, height: 2, rgba: vec![42; 16] } }
    #[test]
    fn round_trips_cursor_and_large_wire_id() {
        let input = shape(u64::MAX - 5);
        let envelope = Envelope::cursor_shape_event(&input).unwrap();
        let wire = envelope.encode(4096).unwrap();
        let decoded = Envelope::decode(&wire, 4096).unwrap().cursor_shape().unwrap();
        assert_eq!(decoded, input);
        assert_eq!(Envelope::cursor_id_event(input.id).cursor_id().unwrap(), input.id);
        let pos = CursorPosition { x: -20, y: 10 };
        assert_eq!(Envelope::cursor_position_event(pos).cursor_position().unwrap(), pos);
    }
    #[test]
    fn validates_shapes_and_evicts_lru() {
        let mut bad = shape(1); bad.hotx = 2;
        assert!(matches!(Envelope::cursor_shape_event(&bad), Err(CursorError::InvalidHotspot)));
        let mut cache = CursorCache::new(2, 32).unwrap();
        cache.insert(shape(1)).unwrap(); cache.insert(shape(2)).unwrap();
        assert!(cache.get(1).is_some()); cache.insert(shape(3)).unwrap();
        assert!(cache.get(2).is_none()); assert_eq!(cache.retained_bytes(), 32);
        cache.clear(); assert!(cache.is_empty());
    }
}
