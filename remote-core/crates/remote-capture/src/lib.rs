//! Experimental adapter for RustDesk's `scrap` capture backend.
//!
//! The underlying display is consumed when capture starts, preventing a stale
//! enumeration index from silently selecting a different display. A frame
//! borrows the capturer until it is dropped. This crate currently depends on the
//! RustDesk checkout and is not yet an independently distributable extraction.

/// Experimental combined Windows DXGI capture and VRAM encoding.
#[cfg(all(target_os = "windows", feature = "vram"))]
pub mod vram;

/// Read-only foreground-window geometry; explicit local consent required.
#[cfg(target_os = "windows")]
pub mod windows_foreground;

/// Read-only current-thread/input desktop name comparison; no switching.
#[cfg(target_os = "windows")]
pub mod windows_desktop;

/// Read-only bounded Windows display-mode inspection.
#[cfg(target_os = "windows")]
pub mod windows_resolution;

#[cfg(any(target_os = "windows", test))]
mod cursor_pixels;
#[cfg(target_os = "windows")]
mod windows_cursor_shape;

use std::{ffi::c_void, io, time::Duration};
use scrap::{TraitCapturer, TraitPixelBuffer};

/// Information observed when a display was enumerated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayInfo {
    /// Platform-provided display name; not guaranteed to be globally unique.
    pub name: String,
    /// Horizontal origin in the virtual desktop coordinate space.
    pub x: i32,
    /// Vertical origin in the virtual desktop coordinate space.
    pub y: i32,
    /// Capture width in pixels.
    pub width: usize,
    /// Capture height in pixels.
    pub height: usize,
    /// Whether the source reports the display as online.
    pub online: bool,
    /// Whether the source reports the display as primary.
    pub primary: bool,
}

/// An enumerated native display. The handle is not a stable cross-enumeration ID.
pub struct Display {
    native: scrap::Display,
    info: DisplayInfo,
}

impl Display {
    /// Snapshot display metadata without exposing the RustDesk type.
    pub fn info(&self) -> &DisplayInfo {
        &self.info
    }

    /// Consume this exact display handle and open its capture backend.
    pub fn open(self) -> io::Result<Capturer> {
        Ok(Capturer { native: scrap::Capturer::new(self.native)? })
    }
}

/// Enumerate displays using the original backend's errors and ordering.
pub fn displays() -> io::Result<Vec<Display>> {
    Ok(scrap::Display::all()?.into_iter().map(|native| {
        let (x, y) = native.origin();
        let info = DisplayInfo {
            name: native.name(), x, y, width: native.width(), height: native.height(),
            online: native.is_online(), primary: native.is_primary(),
        };
        Display { native, info }
    }).collect())
}

/// Pixel format reported by the native capture backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// Packed blue, green, red, alpha.
    Bgra,
    /// Packed red, green, blue, alpha.
    Rgba,
    /// Packed little-endian RGB 5:6:5.
    Rgb565Le,
    /// Planar YUV 4:2:0.
    I420,
    /// Semi-planar YUV 4:2:0.
    Nv12,
    /// Planar YUV 4:4:4.
    I444,
}

impl From<scrap::Pixfmt> for PixelFormat {
    fn from(format: scrap::Pixfmt) -> Self {
        match format {
            scrap::Pixfmt::BGRA => Self::Bgra,
            scrap::Pixfmt::RGBA => Self::Rgba,
            scrap::Pixfmt::RGB565LE => Self::Rgb565Le,
            scrap::Pixfmt::I420 => Self::I420,
            scrap::Pixfmt::NV12 => Self::Nv12,
            scrap::Pixfmt::I444 => Self::I444,
        }
    }
}

/// A frame tied to the lifetime of the capture backend.
pub enum Frame<'a> {
    /// CPU-accessible pixels and native stride information.
    Pixels(Pixels<'a>),
    /// Backend-specific texture. Its pointer must not outlive this frame.
    /// Interpreting the handle requires the corresponding platform backend.
    Texture(Texture<'a>),
}

/// A borrowed CPU frame; its data remains valid only while this value lives.
pub struct Pixels<'a> {
    native: scrap::PixelBuffer<'a>,
}

impl Pixels<'_> {
    /// Raw native-format bytes, including any padding.
    pub fn data(&self) -> &[u8] { self.native.data() }
    /// Frame width in pixels.
    pub fn width(&self) -> usize { self.native.width() }
    /// Frame height in pixels.
    pub fn height(&self) -> usize { self.native.height() }
    /// Per-plane strides as reported by the backend.
    pub fn stride(&self) -> Vec<usize> { self.native.stride() }
    /// Pixel format reported by the backend.
    pub fn format(&self) -> PixelFormat { self.native.pixfmt().into() }
}

/// Borrowed platform texture handle and backend-provided auxiliary value.
pub struct Texture<'a> {
    handle: *mut c_void,
    auxiliary: usize,
    _capture: std::marker::PhantomData<&'a mut Capturer>,
}

impl Texture<'_> {
    /// Return the backend handle. Consumers must obey platform-specific rules.
    pub fn handle(&self) -> *mut c_void { self.handle }
    /// Return the backend-provided auxiliary value without interpreting it.
    pub fn auxiliary(&self) -> usize { self.auxiliary }
}

/// Explicit acknowledgment that a caller may change the backend of an already
/// locally authorized Windows capture. This token is not proof of consent or
/// permission, and never authorizes opening or streaming another display.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy)]
pub struct GdiFallbackOptIn(());
#[cfg(target_os = "windows")]
impl GdiFallbackOptIn {
    pub fn acknowledge_backend_change() -> Self { Self(()) }
}

/// Capture instance backed by the original RustDesk implementation.
pub struct Capturer {
    native: scrap::Capturer,
}

impl Capturer {
    /// Capture width in pixels at backend initialization.
    pub fn width(&self) -> usize { self.native.width() }
    /// Capture height in pixels at backend initialization.
    pub fn height(&self) -> usize { self.native.height() }
    /// Read the source backend's current GDI flag. The backend may switch
    /// internally after a failed DXGI/HDR operation; this is a momentary local
    /// observation, not proof of display identity, consent or a usable frame.
    #[cfg(target_os = "windows")]
    pub fn is_gdi(&self) -> bool { self.native.is_gdi() }
    /// Explicitly ask the source backend to create GDI capture for this exact
    /// opened display. This does not check current local consent, topology,
    /// privacy/secure desktop or resource policy; the caller must do so and
    /// coordinate encoder/keyframe recovery. Switching can change pixel/texture
    /// behavior and must not be used by the VRAM path. The source reports only
    /// success/failure, not a detailed error. Already-GDI is a no-op to avoid
    /// replacing a working GDI instance. There is no automatic retry/reversal.
    #[cfg(target_os = "windows")]
    pub fn use_gdi(&mut self, _: GdiFallbackOptIn) -> io::Result<()> {
        if self.native.is_gdi() || self.native.set_gdi() { Ok(()) }
        else { Err(io::Error::new(io::ErrorKind::Other, "GDI capture initialization failed")) }
    }
    /// Obtain a frame. `WouldBlock` and other errors retain backend semantics.
    /// Timeout handling differs between native platforms.
    pub fn frame(&mut self, timeout: Duration) -> io::Result<Frame<'_>> {
        Ok(match self.native.frame(timeout)? {
            scrap::Frame::PixelBuffer(native) => Frame::Pixels(Pixels { native }),
            scrap::Frame::Texture((handle, auxiliary)) => Frame::Texture(Texture {
                handle, auxiliary, _capture: std::marker::PhantomData,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::PixelFormat;

    #[test]
    fn maps_every_source_pixel_format() {
        for (source, expected) in [
            (scrap::Pixfmt::BGRA, PixelFormat::Bgra),
            (scrap::Pixfmt::RGBA, PixelFormat::Rgba),
            (scrap::Pixfmt::RGB565LE, PixelFormat::Rgb565Le),
            (scrap::Pixfmt::I420, PixelFormat::I420),
            (scrap::Pixfmt::NV12, PixelFormat::Nv12),
            (scrap::Pixfmt::I444, PixelFormat::I444),
        ] {
            assert_eq!(PixelFormat::from(source), expected);
        }
    }
}

/// Native cursor visibility and coordinates for the current Windows desktop.
/// This is not the RustDesk portable-service implementation. Shape sampling is
/// experimental; service/UAC/secure-desktop and multi-session behavior differ.
#[cfg(target_os = "windows")]
pub mod windows_cursor {
    pub use crate::windows_cursor_shape::{capture_shape, WindowsCursorShape};
    use std::{io, mem};
    use winapi::{shared::minwindef::FALSE, um::winuser::{GetCursorInfo, CURSORINFO, CURSOR_SHOWING}};

    /// One snapshot. The handle-derived ID is process/desktop specific, may be
    /// reused and must not be treated as a durable cursor-shape identity.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CursorSnapshot {
        pub visible: bool,
        pub x: i32,
        pub y: i32,
        pub handle_id: u64,
    }

    /// Sample the current desktop cursor. No authentication, authorization or
    /// shape extraction is performed here; host callers must enforce consent.
    pub fn snapshot() -> io::Result<CursorSnapshot> {
        unsafe {
            // CURSORINFO is a Win32 C POD and requires cbSize before the call.
            let mut info: CURSORINFO = mem::zeroed();
            info.cbSize = mem::size_of::<CURSORINFO>() as u32;
            if GetCursorInfo(&mut info) == FALSE { return Err(io::Error::last_os_error()); }
            Ok(CursorSnapshot {
                visible: info.flags & CURSOR_SHOWING != 0,
                x: info.ptScreenPos.x,
                y: info.ptScreenPos.y,
                handle_id: info.hCursor as usize as u64,
            })
        }
    }
}
