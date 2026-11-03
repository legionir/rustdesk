//! Arithmetic for the source Windows absolute virtual-desktop mapping.

/// Preserve the source formula using widened arithmetic and clamp to the
/// documented 0..=65535 SendInput range. An unavailable extent is rejected.
pub(crate) fn to_absolute(value: i32, origin: i32, extent: i32) -> Option<i32> {
    if extent <= 0 { return None; }
    let absolute = (i64::from(value) - i64::from(origin)) * 65535 / i64::from(extent);
    Some(absolute.clamp(0, 65535) as i32)
}

#[cfg(test)]
mod tests {
    use super::to_absolute;

    #[test]
    fn virtual_desktop_origins_extents_and_clamps_follow_source() {
        assert_eq!(to_absolute(-1920, -1920, 3840), Some(0));
        assert_eq!(to_absolute(0, -1920, 3840), Some(32767));
        assert_eq!(to_absolute(1920, -1920, 3840), Some(65535));
        assert_eq!(to_absolute(-9999, -1920, 3840), Some(0));
        assert_eq!(to_absolute(9999, -1920, 3840), Some(65535));
        assert_eq!(to_absolute(0, 0, 0), None);
        assert_eq!(to_absolute(0, 0, -1), None);
    }

    #[test]
    fn extreme_untrusted_coordinates_do_not_overflow() {
        assert_eq!(to_absolute(i32::MAX, i32::MIN, 1), Some(65535));
        assert_eq!(to_absolute(i32::MIN, i32::MAX, 1), Some(0));
        assert_eq!(to_absolute(i32::MAX, i32::MIN, i32::MAX), Some(65535));
    }
}
