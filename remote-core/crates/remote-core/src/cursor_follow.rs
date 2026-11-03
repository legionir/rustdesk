//! Side-effect-free cursor-follow display calculation adapted from
//! `src/server/connection.rs::handle_cursor_switch_display` at the pinned source.
//!
//! Coordinates and display geometry must be from the same local desktop and
//! coordinate space. This neither samples the cursor nor authorizes disclosure,
//! switches capture, sends a message or validates topology stability. The caller
//! must obtain consent, enforce view permission, apply follow preferences, and
//! independently handle multi-UI sessions, scaling and display changes.
use remote_protocol::{cursor::CursorPosition, desktop::{DisplayInfo, MAX_DISPLAYS, MAX_DISPLAY_DIMENSION}};
use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowError { InvalidDisplays, InvalidCurrentDisplay }
impl fmt::Display for FollowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "cursor follow: {self:?}") }
}
impl Error for FollowError {}

/// Compute the first matching display and return a hint only when it differs
/// from the current index, as in source. Input snapshots with absent/unknown
/// scale (0), invalid dimensions or nonfinite scale are rejected, unlike the
/// source. The whole list is checked first to avoid partially trusting a broken
/// snapshot. Overlaps retain source first-match behavior, not physical identity.
/// Integer subtraction is widened to avoid overflow for extreme coordinates.
pub fn follow_hint(displays: &[DisplayInfo], current_display: u32, position: CursorPosition,
    multi_ui_session: bool) -> Result<Option<u32>, FollowError> {
    if displays.is_empty() || displays.len() > MAX_DISPLAYS { return Err(FollowError::InvalidDisplays); }
    if current_display as usize >= displays.len() { return Err(FollowError::InvalidCurrentDisplay); }
    if displays.iter().any(|d| !(1..=MAX_DISPLAY_DIMENSION).contains(&d.width)
        || !(1..=MAX_DISPLAY_DIMENSION).contains(&d.height) || !d.scale.is_finite()
        || !(0.01..=16.0).contains(&d.scale)) { return Err(FollowError::InvalidDisplays); }
    if multi_ui_session { return Ok(None); }
    let matched = displays.iter().position(|d| {
        let dx = i64::from(position.x) - i64::from(d.x);
        let dy = i64::from(position.y) - i64::from(d.y);
        dx >= 0 && dy >= 0 && (dx as f64) * d.scale < f64::from(d.width)
            && (dy as f64) * d.scale < f64::from(d.height)
    });
    Ok(matched.and_then(|index| (index as u32 != current_display).then_some(index as u32)))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn display(x: i32, width: i32, scale: f64) -> DisplayInfo {
        DisplayInfo { x, y: 0, width, height: 100, name: String::new(), online: true, cursor_embedded: false, scale }
    }
    #[test]
    fn matches_scaled_half_open_rectangles_and_multi_ui_suppression() {
        let displays = [display(-100, 100, 1.0), display(0, 100, 2.0)];
        let pos = CursorPosition { x: 49, y: 10 };
        assert_eq!(follow_hint(&displays, 0, pos, false), Ok(Some(1)));
        assert_eq!(follow_hint(&displays, 1, pos, false), Ok(None));
        assert_eq!(follow_hint(&displays, 0, CursorPosition { x: 50, y: 10 }, false), Ok(None));
        assert_eq!(follow_hint(&displays, 0, pos, true), Ok(None));
    }
    #[test]
    fn rejects_unknown_scale_and_widens_arithmetic() {
        let displays = [display(i32::MIN, 100, 1.0), display(0, 100, 0.0)];
        let p = CursorPosition { x: i32::MAX, y: 0 };
        assert_eq!(follow_hint(&displays, 0, p, false), Err(FollowError::InvalidDisplays));
        assert_eq!(follow_hint(&displays[..1], 0, p, false), Ok(None));
        assert_eq!(follow_hint(&displays[..1], 1, p, false), Err(FollowError::InvalidCurrentDisplay));
    }
}
