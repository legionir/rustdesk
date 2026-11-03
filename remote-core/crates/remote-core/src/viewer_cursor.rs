//! Caller-driven cursor selection using the bounded source wire cache.
//!
//! The pinned receive loop selects a CursorData shape on receipt and selects
//! CursorId directly. This helper does not implement old-peer content dedupe,
//! visibility/embedded-cursor policy, rendering, network requests or sessions.
//! IDs, positions and shape pixels are peer claims, not authenticated identity.
//! Resend responses lack correlation and can race later selections. The caller
//! must explicitly decide whether a delayed shape should change selection.
use remote_protocol::cursor::{CursorCache, CursorError, CursorPosition, CursorShape};

/// Isolated to one peer/session. Clear on reconnect and topology/security
/// changes; do not share shape IDs between peers. Capacity excludes caller-held
/// copies, allocator overhead and previously decoded/decompressed messages.
pub struct ViewerCursor {
    cache: CursorCache,
    selected: Option<u64>,
    position: Option<CursorPosition>,
}
impl ViewerCursor {
    pub fn new(max_items: usize, max_bytes: usize) -> Result<Self, CursorError> {
        Ok(Self { cache: CursorCache::new(max_items, max_bytes)?, selected: None, position: None })
    }
    /// Store an already decoded shape. Set `select` for an ordinary CursorData
    /// event; choose carefully for asynchronous resends, which have no request
    /// identifier and might be stale. Even `select = false` can replace the
    /// cached pixels for the selected ID; it is not a freshness check. On error
    /// state is unchanged; caller must stop using any stale selection or clear
    /// it according to its UI policy.
    pub fn observe_shape(&mut self, shape: CursorShape, select: bool) -> Result<(), CursorError> {
        let id = shape.id;
        self.cache.insert(shape)?;
        if select { self.selected = Some(id); }
        Ok(())
    }
    /// Select a peer-provided ID even on cache miss. Return whether a shape is
    /// present; a miss is not a hidden cursor and does not itself send a request.
    pub fn select(&mut self, id: u64) -> bool {
        self.selected = Some(id); self.cache.get(id).is_some()
    }
    pub fn selected_id(&self) -> Option<u64> { self.selected }
    /// Access current data if cached; absence may be initial state or eviction.
    /// No guarantee exists that this is the host's current visual cursor.
    pub fn selected_shape(&mut self) -> Option<&CursorShape> { let id = self.selected?; self.cache.get(id) }
    pub fn observe_position(&mut self, position: CursorPosition) { self.position = Some(position); }
    pub fn position(&self) -> Option<CursorPosition> { self.position }
    pub fn retained_bytes(&self) -> usize { self.cache.retained_bytes() }
    pub fn len(&self) -> usize { self.cache.len() }
    pub fn clear(&mut self) { self.cache.clear(); self.selected = None; self.position = None; }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn shape(id: u64) -> CursorShape { CursorShape { id, hotx: 0, hoty: 0, width: 1, height: 1, rgba: vec![1, 2, 3, 4] } }
    #[test]
    fn selection_eviction_and_late_resend_are_explicit() {
        let mut c = ViewerCursor::new(2, 8).unwrap();
        assert!(!c.select(u64::MAX)); assert_eq!(c.selected_id(), Some(u64::MAX));
        c.observe_shape(shape(u64::MAX), true).unwrap();
        assert_eq!(c.selected_shape().unwrap().rgba, [1, 2, 3, 4]);
        c.observe_shape(shape(2), true).unwrap();
        c.observe_shape(shape(3), true).unwrap();
        assert!(!c.select(u64::MAX));
        assert_eq!(c.selected_id(), Some(u64::MAX)); assert!(c.selected_shape().is_none());
        assert!(c.select(3));
        c.observe_shape(shape(u64::MAX), false).unwrap();
        assert_eq!(c.selected_id(), Some(3));
        c.observe_position(CursorPosition { x: -10, y: 20 });
        assert_eq!(c.position(), Some(CursorPosition { x: -10, y: 20 }));
        assert_eq!(c.retained_bytes(), 8); c.clear();
        assert!(c.selected_id().is_none()); assert!(c.position().is_none()); assert_eq!(c.len(), 0);
    }
    #[test]
    fn nonselecting_same_id_can_replace_selected_pixels() {
        let mut c = ViewerCursor::new(1, 4).unwrap();
        c.observe_shape(shape(1), true).unwrap();
        let mut replacement = shape(1); replacement.rgba[0] = 9;
        c.observe_shape(replacement, false).unwrap();
        assert_eq!(c.selected_id(), Some(1));
        assert_eq!(c.selected_shape().unwrap().rgba[0], 9);
    }
    #[test]
    fn invalid_shape_does_not_change_selection_or_cache() {
        let mut c = ViewerCursor::new(1, 4).unwrap(); c.observe_shape(shape(1), true).unwrap();
        let mut bad = shape(2); bad.rgba.clear();
        assert!(c.observe_shape(bad, true).is_err());
        assert_eq!(c.selected_id(), Some(1)); assert_eq!(c.selected_shape().unwrap().id, 1);
    }
}
