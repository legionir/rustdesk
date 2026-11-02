//! Windows cursor bitmap sampling, adapted from RustDesk's Windows platform
//! implementation at the pinned baseline. This is intentionally separate
//! from the portable-service/UAC desktop switching paths and is not tested.

use crate::cursor_pixels;
use std::{io, mem, ptr};
use winapi::{
    shared::{minwindef::FALSE, windef::{HBITMAP, HDC, HICON}},
    um::{
        wingdi::{BITMAP, BITMAPINFO, BITMAPV5HEADER, BI_BITFIELDS, DIB_RGB_COLORS,
            DeleteObject, GetBitmapBits, GetDIBits, GetObjectA},
        winuser::{CopyIcon, DestroyIcon, GetCursorInfo, GetDC, GetIconInfo, ReleaseDC,
            CURSORINFO, CURSOR_SHOWING, ICONINFO},
    },
};

fn invalid(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, message) }

/// Raw RGBA shape of the current visible cursor. `handle_id` is transient and
/// may be reused; derive a content ID before using it as a remote cache key.
#[derive(Debug, Clone)]
pub struct WindowsCursorShape {
    pub handle_id: u64,
    pub hotx: i32,
    pub hoty: i32,
    pub width: i32,
    pub height: i32,
    pub rgba: Vec<u8>,
}
struct OwnedIcon(HICON);
impl Drop for OwnedIcon { fn drop(&mut self) { unsafe { if !self.0.is_null() { DestroyIcon(self.0); } } } }
struct IconBitmaps(ICONINFO);
impl Drop for IconBitmaps {
    fn drop(&mut self) {
        unsafe {
            if !self.0.hbmMask.is_null() { DeleteObject(self.0.hbmMask as _); }
            if !self.0.hbmColor.is_null() { DeleteObject(self.0.hbmColor as _); }
        }
    }
}
struct ScreenDc(HDC);
impl Drop for ScreenDc { fn drop(&mut self) { unsafe { if !self.0.is_null() { ReleaseDC(ptr::null_mut(), self.0); } } } }

unsafe fn bitmap(mask: HBITMAP) -> io::Result<BITMAP> {
    let mut out: BITMAP = mem::zeroed();
    let copied = GetObjectA(mask as _, mem::size_of::<BITMAP>() as i32, &mut out as *mut _ as _);
    if copied == 0 { return Err(io::Error::last_os_error()); }
    if copied as usize != mem::size_of::<BITMAP>() || out.bmPlanes != 1 || out.bmBitsPixel != 1 {
        return Err(invalid("unsupported Windows cursor mask bitmap"));
    }
    Ok(out)
}
unsafe fn color_rgba(bitmap: HBITMAP, width: usize, height: usize) -> io::Result<Vec<u8>> {
    let dc = ScreenDc(GetDC(ptr::null_mut()));
    if dc.0.is_null() { return Err(io::Error::last_os_error()); }
    let mut header: BITMAPV5HEADER = mem::zeroed();
    header.bV5Size = mem::size_of::<BITMAPV5HEADER>() as u32;
    header.bV5Width = width as i32;
    header.bV5Height = -(height as i32);
    header.bV5Planes = 1;
    header.bV5BitCount = 32;
    header.bV5Compression = BI_BITFIELDS;
    header.bV5RedMask = 0x000000ff;
    header.bV5GreenMask = 0x0000ff00;
    header.bV5BlueMask = 0x00ff0000;
    header.bV5AlphaMask = 0xff000000;
    let mut rgba = vec![0; width * height * 4];
    // Win32 documents that the bitmap must not be selected into a DC here;
    // the source selects it first. This implementation avoids selecting it.
    let rows = GetDIBits(dc.0, bitmap, 0, height as u32, rgba.as_mut_ptr() as _,
        &mut header as *mut BITMAPV5HEADER as *mut BITMAPINFO, DIB_RGB_COLORS);
    if rows != height as i32 { return Err(invalid("GetDIBits returned an incomplete cursor bitmap")); }
    let masks = [header.bV5RedMask, header.bV5GreenMask, header.bV5BlueMask];
    let mut indexes = [0usize; 4];
    for (index, mask) in masks.into_iter().enumerate() {
        if mask == 0 { return Err(invalid("missing cursor color mask")); }
        let shift = mask.trailing_zeros();
        if shift % 8 != 0 || shift > 24 || mask != 0xffu32 << shift { return Err(invalid("unsupported cursor color mask")); }
        indexes[index] = (shift / 8) as usize;
    }
    if indexes[0] == indexes[1] || indexes[0] == indexes[2] || indexes[1] == indexes[2] { return Err(invalid("overlapping cursor color masks")); }
    indexes[3] = 6usize.checked_sub(indexes[0] + indexes[1] + indexes[2]).ok_or_else(|| invalid("invalid cursor alpha mask"))?;
    if indexes[3] > 3 { return Err(invalid("invalid cursor alpha channel")); }
    for pixel in rgba.chunks_exact_mut(4) {
        let source = [pixel[0], pixel[1], pixel[2], pixel[3]];
        for channel in 0..4 { pixel[channel] = source[indexes[channel]]; }
    }
    Ok(rgba)
}

/// Capture a copy of the currently visible Windows cursor shape.
///
/// `None` means Windows reported it hidden. The shape is captured separately
/// from position and can change between calls. There is no authorization or
/// trusted consent here; the host must guard this operation. Desktop/service,
/// hotplug, animation, scaling, color/alpha, monochrome and secure-desktop
/// behavior have not been built or tested. This code is not the upstream
/// portable-service path and must not be advertised as equivalent to it.
pub fn capture_shape() -> io::Result<Option<WindowsCursorShape>> {
    unsafe {
        let mut cursor: CURSORINFO = mem::zeroed();
        cursor.cbSize = mem::size_of::<CURSORINFO>() as u32;
        if GetCursorInfo(&mut cursor) == FALSE { return Err(io::Error::last_os_error()); }
        if cursor.flags & CURSOR_SHOWING == 0 { return Ok(None); }
        if cursor.hCursor.is_null() { return Err(invalid("visible cursor has null handle")); }
        let handle_id = cursor.hCursor as usize as u64;
        let icon = OwnedIcon(CopyIcon(cursor.hCursor as HICON));
        if icon.0.is_null() { return Err(io::Error::last_os_error()); }
        let mut raw: ICONINFO = mem::zeroed();
        if GetIconInfo(icon.0, &mut raw) == FALSE { return Err(io::Error::last_os_error()); }
        let info = IconBitmaps(raw);
        if info.0.hbmMask.is_null() { return Err(invalid("cursor mask is null")); }
        let mask_bitmap = bitmap(info.0.hbmMask)?;
        let width = usize::try_from(mask_bitmap.bmWidth).map_err(|_| invalid("invalid cursor width"))?;
        let bitmap_height = usize::try_from(mask_bitmap.bmHeight).map_err(|_| invalid("invalid cursor height"))?;
        let stride = usize::try_from(mask_bitmap.bmWidthBytes).map_err(|_| invalid("invalid cursor stride"))?;
        let color = !info.0.hbmColor.is_null();
        if width == 0 || width > 512 || bitmap_height == 0 || bitmap_height > 1024 || stride == 0 || stride > 4096 {
            return Err(invalid("cursor bitmap dimensions exceed limits"));
        }
        let height = if color { bitmap_height } else {
            if bitmap_height % 2 != 0 { return Err(invalid("invalid monochrome cursor mask height")); }
            bitmap_height / 2
        };
        if height == 0 || height > 512 || stride < (width + 7) / 8 { return Err(invalid("invalid cursor mask layout")); }
        let mask_size = stride.checked_mul(bitmap_height).ok_or_else(|| invalid("cursor mask size overflow"))?;
        if mask_size > 1024 * 1024 { return Err(invalid("cursor mask exceeds 1 MiB")); }
        let mut mask = vec![0; mask_size];
        let copied = GetBitmapBits(info.0.hbmMask, mask_size as i32, mask.as_mut_ptr() as _);
        if copied != mask_size as i32 { return Err(invalid("GetBitmapBits returned an incomplete mask")); }
        let (mut rgba, outline) = if color {
            let mut data = color_rgba(info.0.hbmColor, width, height)?;
            let outline = cursor_pixels::color_mask(&mut data, &mask, width, height, stride)?;
            (data, outline)
        } else { cursor_pixels::monochrome(&mask, width, height, stride)? };
        let (mut out_width, mut out_height) = (width, height);
        let (mut hotx, mut hoty) = (usize::try_from(info.0.xHotspot).map_err(|_| invalid("invalid hotspot"))?, usize::try_from(info.0.yHotspot).map_err(|_| invalid("invalid hotspot"))?);
        if hotx >= width || hoty >= height { return Err(invalid("cursor hotspot outside image")); }
        if outline {
            rgba = cursor_pixels::source_outline(&rgba, width, height)?;
            out_width += 2; out_height += 2; hotx += 1; hoty += 1;
        }
        Ok(Some(WindowsCursorShape { handle_id, hotx: hotx as i32, hoty: hoty as i32,
            width: out_width as i32, height: out_height as i32, rgba }))
    }
}
