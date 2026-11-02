//! Bounds-checked cursor bitmap conversion adapted from RustDesk's Windows
//! `src/platform/windows.rs` and `src/platform/windows.cc` at the pinned source.
//! Kept platform-independent so synthetic inputs can later be checked without
//! invoking Windows. It has not been built, compared or tested yet.
use std::io;

const MAX_DIMENSION: usize = 512;
fn invalid(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, message) }
fn layout(width: usize, height: usize, mask_stride: usize, mask_len: usize, planes: usize) -> io::Result<usize> {
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION { return Err(invalid("invalid cursor dimensions")); }
    let packed = width.checked_add(7).ok_or_else(|| invalid("cursor width overflow"))? / 8;
    if mask_stride < packed || mask_stride > 4096 { return Err(invalid("invalid cursor mask stride")); }
    let needed = mask_stride.checked_mul(height).and_then(|v| v.checked_mul(planes)).ok_or_else(|| invalid("cursor mask size overflow"))?;
    if mask_len < needed { return Err(invalid("truncated cursor mask")); }
    width.checked_mul(height).and_then(|v| v.checked_mul(4)).ok_or_else(|| invalid("cursor RGBA size overflow"))
}
fn bit(mask: &[u8], stride: usize, x: usize, y: usize) -> bool {
    mask[y * stride + x / 8] & (0x80 >> (x & 7)) != 0
}

/// Convert an AND/XOR monochrome cursor to RGBA. The source replaces XOR
/// inversion with black and requests a white outline when inversion is present.
pub(crate) fn monochrome(mask: &[u8], width: usize, height: usize, stride: usize) -> io::Result<(Vec<u8>, bool)> {
    let rgba_len = layout(width, height, stride, mask.len(), 2)?;
    let (and_mask, xor_mask) = mask.split_at(stride * height);
    let mut rgba = vec![0; rgba_len];
    let mut outline = false;
    for y in 0..height {
        for x in 0..width {
            let and = bit(and_mask, stride, x, y);
            let xor = bit(xor_mask, stride, x, y);
            let dst = &mut rgba[(y * width + x) * 4..][..4];
            match (and, xor) {
                (false, false) => dst.copy_from_slice(&[0, 0, 0, 255]),
                (false, true) => dst.copy_from_slice(&[255, 255, 255, 255]),
                (true, true) => { dst.copy_from_slice(&[0, 0, 0, 255]); outline = true; },
                (true, false) => {},
            }
        }
    }
    Ok((rgba, outline))
}

/// Apply the source's mask fallback when a color bitmap supplies zero alpha.
/// Returns whether the source would add an outline. The source swaps red/blue
/// in this fallback even though normal nonzero-alpha pixels are left alone.
pub(crate) fn color_mask(rgba: &mut [u8], mask: &[u8], width: usize, height: usize, stride: usize) -> io::Result<bool> {
    let rgba_len = layout(width, height, stride, mask.len(), 1)?;
    if rgba.len() != rgba_len { return Err(invalid("invalid color cursor RGBA length")); }
    if rgba.chunks_exact(4).any(|pixel| pixel[3] != 0) { return Ok(false); }
    for y in 0..height {
        for x in 0..width {
            let pix = &mut rgba[(y * width + x) * 4..][..4];
            let mut visible = !bit(mask, stride, x, y);
            if !visible && pix.iter().any(|v| *v != 0) { visible = true; pix.fill(0); }
            pix.swap(0, 2);
            pix[3] = if visible { 255 } else { 0 };
        }
    }
    Ok(true)
}

/// Add the same bounded linear-index outline as the pinned source C helper.
/// Its initial offset is `(width + 1) * 4`, not `(width + 3) * 4`; this may
/// shift pixels relative to the enlarged hotspot and needs real-peer comparison.
pub(crate) fn source_outline(rgba: &[u8], width: usize, height: usize) -> io::Result<Vec<u8>> {
    if width == 0 || height == 0 || width > MAX_DIMENSION - 2 || height > MAX_DIMENSION - 2 { return Err(invalid("outlined cursor exceeds limit")); }
    let size = width.checked_mul(height).and_then(|v| v.checked_mul(4)).ok_or_else(|| invalid("cursor overflow"))?;
    if rgba.len() != size { return Err(invalid("invalid cursor RGBA length")); }
    let row = (width + 2) * 4;
    let mut out = vec![0; row * (height + 2)];
    let initial = (width + 1) * 4;
    for y in 0..height {
        for x in 0..width {
            if rgba[(y * width + x) * 4 + 3] == 0 { continue; }
            let dest = initial + y * row + x * 4;
            for start in [dest.checked_sub(row + 4), dest.checked_sub(4), dest.checked_add(row).and_then(|n| n.checked_sub(4))].into_iter().flatten() {
                if start.checked_add(12).map_or(false, |end| end <= out.len()) { out[start..start + 12].fill(255); }
            }
        }
    }
    for y in 0..height {
        for x in 0..width {
            let src = (y * width + x) * 4;
            let dest = initial + y * row + x * 4;
            if rgba[src + 3] != 0 && dest + 4 <= out.len() { out[dest..dest + 4].copy_from_slice(&rgba[src..src + 4]); }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn monochrome_and_xor_values() {
        // Four bits: black, white, transparent, inverted black.
        let (pixels, outline) = monochrome(&[0b0011_0000, 0b0101_0000], 4, 1, 1).unwrap();
        assert!(outline);
        assert_eq!(pixels, vec![0,0,0,255, 255,255,255,255, 0,0,0,0, 0,0,0,255]);
    }
    #[test]
    fn color_mask_fallback_and_validation() {
        let mut rgba = vec![1,2,3,0, 0,0,0,0];
        assert!(color_mask(&mut rgba, &[0b0100_0000], 2, 1, 1).unwrap());
        assert_eq!(rgba, vec![3,2,1,255, 0,0,0,0]);
        assert!(monochrome(&[0], 9, 1, 1).is_err());
        assert!(source_outline(&vec![0; 512 * 4], 512, 1).is_err());
    }
}
