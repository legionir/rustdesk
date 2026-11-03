//! Caller-driven bounded per-session cursor selection. Not a renderer.
use crate::{cursor_id, js_error, CursorMetadata, DecodedCursorShape, MAX_CURSOR_RGBA_BYTES};
use napi::{bindgen_prelude::Buffer, Error, Result};
use napi_derive::napi;
use remote_core::viewer_cursor::ViewerCursor;
use remote_protocol::cursor::{CursorPosition, CursorShape};
use std::sync::Mutex;

#[napi(object)]
pub struct ViewerCursorPosition { pub x: i32, pub y: i32 }
#[napi(object)]
pub struct ViewerCursorStats { pub selected_id: Option<String>, pub cached: u32, pub retained_bytes: u32 }
#[napi]
pub struct ViewerCursorHandle { cursor: Mutex<ViewerCursor> }
#[napi]
impl ViewerCursorHandle {
    /// Copy a decoded shape into the bounded cache; only select it when the
    /// caller determines the event is still relevant to current UI state.
    #[napi]
    pub fn observe_shape(&self, metadata: CursorMetadata, rgba: Buffer, select: bool) -> Result<()> {
        if rgba.len() > MAX_CURSOR_RGBA_BYTES { return Err(Error::from_reason("cursor RGBA exceeds 1 MiB")); }
        let shape = CursorShape { id: cursor_id(&metadata.id)?, hotx: metadata.hotx, hoty: metadata.hoty,
            width: metadata.width, height: metadata.height, rgba: rgba.to_vec() };
        self.cursor.lock().map_err(|_| Error::from_reason("cursor state poisoned"))?.observe_shape(shape, select).map_err(js_error)
    }
    /// A cache miss is returned as false; no request is sent automatically.
    #[napi]
    pub fn select(&self, id: String) -> Result<bool> {
        let id = cursor_id(&id)?;
        Ok(self.cursor.lock().map_err(|_| Error::from_reason("cursor state poisoned"))?.select(id))
    }
    /// Copy the selected shape into JavaScript, if present. Repeated calls
    /// allocate independent JS buffers outside cache accounting.
    #[napi]
    pub fn selected_shape(&self) -> Result<Option<DecodedCursorShape>> {
        let mut state = self.cursor.lock().map_err(|_| Error::from_reason("cursor state poisoned"))?;
        Ok(state.selected_shape().map(|shape| DecodedCursorShape { id: shape.id.to_string(), hotx: shape.hotx, hoty: shape.hoty,
            width: shape.width, height: shape.height, rgba: shape.rgba.clone().into() }))
    }
    #[napi]
    pub fn observe_position(&self, x: i32, y: i32) -> Result<()> {
        self.cursor.lock().map_err(|_| Error::from_reason("cursor state poisoned"))?.observe_position(CursorPosition { x, y }); Ok(())
    }
    #[napi]
    pub fn position(&self) -> Result<Option<ViewerCursorPosition>> {
        Ok(self.cursor.lock().map_err(|_| Error::from_reason("cursor state poisoned"))?.position().map(|p| ViewerCursorPosition { x: p.x, y: p.y }))
    }
    #[napi]
    pub fn stats(&self) -> Result<ViewerCursorStats> {
        let state = self.cursor.lock().map_err(|_| Error::from_reason("cursor state poisoned"))?;
        Ok(ViewerCursorStats { selected_id: state.selected_id().map(|id| id.to_string()), cached: u32::try_from(state.len()).map_err(js_error)?,
            retained_bytes: u32::try_from(state.retained_bytes()).map_err(js_error)? })
    }
    /// Clear all state when changing connection/peer; old JS copies persist.
    #[napi]
    pub fn clear(&self) -> Result<()> {
        self.cursor.lock().map_err(|_| Error::from_reason("cursor state poisoned"))?.clear(); Ok(())
    }
}
#[napi]
pub fn create_viewer_cursor(max_items: u32, max_bytes: u32) -> Result<ViewerCursorHandle> {
    let cursor = ViewerCursor::new(usize::try_from(max_items).map_err(js_error)?, usize::try_from(max_bytes).map_err(js_error)?).map_err(js_error)?;
    Ok(ViewerCursorHandle { cursor: Mutex::new(cursor) })
}
