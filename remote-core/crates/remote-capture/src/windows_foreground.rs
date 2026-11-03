//! Read-only foreground window rectangle, adapted from
//! `src/platform/windows.rs::get_focused_display` at the pinned baseline.
//! Does not expose titles, process IDs or handles. This is a transient sample
//! of the calling thread's current desktop and not a security boundary.
use std::{io, mem};
use winapi::{shared::{minwindef::FALSE, windef::RECT}, um::winuser::{GetForegroundWindow, GetWindowRect}};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowRect { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }
/// Sample only on an explicitly authorized interactive desktop. A foreground
/// window/rectangle may be stale immediately, may straddle monitors, and may
/// use a different coordinate/DPI awareness context from the capture snapshot.
/// This does not switch sessions/desktops, follow focus or signal a peer.
pub fn foreground_window_rect() -> io::Result<Option<WindowRect>> {
    unsafe {
        let window = GetForegroundWindow();
        if window.is_null() { return Ok(None); }
        let mut rect: RECT = mem::zeroed();
        if GetWindowRect(window, &mut rect) == FALSE { return Err(io::Error::last_os_error()); }
        Ok(Some(WindowRect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }))
    }
}
