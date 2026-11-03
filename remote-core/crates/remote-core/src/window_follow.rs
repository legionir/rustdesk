//! Caller-driven source-style foreground-window follow calculation.
//! Adapted from Windows `platform::get_focused_display` and
//! `input_service::run_window_focus`. No native samples, tasks, consent,
//! topology coordination or wire messages are created here.
use remote_protocol::desktop::{DisplayInfo, MAX_DISPLAYS, MAX_DISPLAY_DIMENSION};
use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowRect { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusError { InvalidDisplays, InvalidRect, TopologyChanged, AmbiguousDisplay }
impl fmt::Display for FocusError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "window follow: {self:?}") } }
impl Error for FocusError {}
/// Validate an approved capture topology against a later observation before
/// exposing a focus hint. Names and indices are volatile; equality is not proof
/// of physical identity or atomicity. Reject duplicate, offline and lossy names
/// conservatively, including a legitimate literal replacement character.
pub fn validate_capture_snapshot(approved: &[remote_capture::DisplayInfo], observed: &[remote_capture::DisplayInfo]) -> Result<(), FocusError> {
    if approved.len() < 2 || approved.len() > MAX_DISPLAYS || observed.len() > MAX_DISPLAYS { return Err(FocusError::InvalidDisplays); }
    if approved != observed { return Err(FocusError::TopologyChanged); }
    let mut names = std::collections::BTreeSet::new();
    if approved.iter().any(|d| !d.online || d.name.is_empty() || d.name.len() > 256
        || d.name.chars().any(|ch| ch.is_control() || ch == '\u{fffd}') || !names.insert(&d.name)) {
        return Err(FocusError::AmbiguousDisplay);
    }
    Ok(())
}
/// Return first rectangle containing the source-style window center. Uses
/// widened arithmetic to avoid overflow and rejects empty/reversed window
/// bounds and invalid display dimensions. No physical identity is established.
/// Coordinate spaces and scaling must be verified by the owner.
pub fn focused_display(displays: &[DisplayInfo], rect: WindowRect) -> Result<Option<u32>, FocusError> {
    if displays.is_empty() || displays.len() > MAX_DISPLAYS || displays.iter().any(|d|
        !(1..=MAX_DISPLAY_DIMENSION).contains(&d.width) || !(1..=MAX_DISPLAY_DIMENSION).contains(&d.height)) {
        return Err(FocusError::InvalidDisplays);
    }
    if rect.right <= rect.left || rect.bottom <= rect.top { return Err(FocusError::InvalidRect); }
    let x = i64::from(rect.left) + (i64::from(rect.right) - i64::from(rect.left)) / 2;
    let y = i64::from(rect.top) + (i64::from(rect.bottom) - i64::from(rect.top)) / 2;
    Ok(displays.iter().position(|d| x >= i64::from(d.x) && y >= i64::from(d.y)
        && x < i64::from(d.x) + i64::from(d.width) && y < i64::from(d.y) + i64::from(d.height)).map(|i| i as u32))
}
/// One caller-owned subscription tracker. Mirrors source: no notification for
/// the first valid sample, no update on an unmatched sample, and notifications
/// only on subsequent changes while at least two displays are available.
/// Reset when the desktop/topology/subscription changes; identities are indices.
#[derive(Default)]
pub struct FocusTracker { previous: Option<u32> }
impl FocusTracker {
    pub fn new() -> Self { Self::default() }
    pub fn reset(&mut self) { self.previous = None; }
    pub fn observe(&mut self, displays: &[DisplayInfo], rect: WindowRect) -> Result<Option<u32>, FocusError> {
        if displays.len() <= 1 { return Ok(None); }
        let Some(current) = focused_display(displays, rect)? else { return Ok(None); };
        let changed = self.previous.map_or(false, |previous| previous != current);
        self.previous = Some(current);
        Ok(changed.then_some(current))
    }
}
#[cfg(target_os = "windows")]
impl From<remote_capture::windows_foreground::WindowRect> for WindowRect {
    fn from(r: remote_capture::windows_foreground::WindowRect) -> Self { Self { left: r.left, top: r.top, right: r.right, bottom: r.bottom } }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn display(x: i32) -> DisplayInfo { DisplayInfo { x, y: 0, width: 100, height: 100, name: "screen".into(), online: true, cursor_embedded: false, scale: 1.0 } }
    fn rect(x: i32) -> WindowRect { WindowRect { left: x, top: 0, right: x + 20, bottom: 20 } }
    #[test]
    fn approved_topology_must_match_and_have_unambiguous_online_names() {
        let display = |name: &str, x| remote_capture::DisplayInfo { name: name.into(), x, y: 0, width: 100, height: 100, online: true, primary: x == 0 };
        let approved = [display("a", 0), display("b", 100)];
        assert_eq!(validate_capture_snapshot(&approved, &approved), Ok(()));
        let mut changed = approved.clone(); changed[1].x = 101;
        assert_eq!(validate_capture_snapshot(&approved, &changed), Err(FocusError::TopologyChanged));
        let mut duplicate = approved.clone(); duplicate[1].name = "a".into();
        assert_eq!(validate_capture_snapshot(&duplicate, &duplicate), Err(FocusError::AmbiguousDisplay));
        let mut lossy = approved.clone(); lossy[1].name = "b\u{fffd}".into();
        assert_eq!(validate_capture_snapshot(&lossy, &lossy), Err(FocusError::AmbiguousDisplay));
    }
    #[test]
    fn emits_only_subsequent_changes_and_resets() {
        let displays = [display(0), display(100)]; let mut tracker = FocusTracker::new();
        assert_eq!(tracker.observe(&displays, rect(0)), Ok(None));
        assert_eq!(tracker.observe(&displays, rect(500)), Ok(None));
        assert_eq!(tracker.observe(&displays, rect(100)), Ok(Some(1)));
        assert_eq!(tracker.observe(&displays, rect(100)), Ok(None));
        tracker.reset(); assert_eq!(tracker.observe(&displays, rect(0)), Ok(None));
    }
    #[test]
    fn rejects_invalid_rect_and_avoids_integer_overflow() {
        let displays = [display(i32::MAX - 1)];
        assert_eq!(focused_display(&displays, WindowRect { left: i32::MAX - 1, right: i32::MAX, top: 0, bottom: 1 }), Ok(Some(0)));
        assert_eq!(focused_display(&displays, WindowRect { left: 0, right: 0, top: 0, bottom: 1 }), Err(FocusError::InvalidRect));
    }
}
