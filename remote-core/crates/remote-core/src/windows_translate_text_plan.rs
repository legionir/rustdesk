//! Side-effect-free model of the Windows Translate-mode `Seq` branch in
//! `src/server/input_service.rs::translate_keyboard_mode`, and the pinned
//! rdev `windows/simulate.rs` at 0904f23ce496e255461a98848b85c11fa5a62eab.
//!
//! This is NOT an input dispatcher: it makes no desktop/foreground selection,
//! key-state observation, authorization, injection, cleanup or error recovery.
//! The upstream path can release locally held Shift keys, and its hotkey route
//! can synthesize temporary modifiers based on the foreground layout. Those
//! are OS-global effects; do not execute this plan without input arbitration,
//! informed local approval and a separate security/compatibility review.

use std::{error::Error, fmt};

/// Local limit, not a source protocol limit.
pub const MAX_TEXT_BYTES: usize = 4096;

/// Transient caller-supplied state corresponding to the six separate
/// `GetKeyState` checks in `is_hot_key_modifiers_down`. It can already be stale
/// and does not establish the active desktop, focus, layout or key ownership.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotkeyState {
    pub control: bool,
    pub right_control: bool,
    pub alt: bool,
    pub right_alt: bool,
    pub meta: bool,
    pub right_meta: bool,
}
impl HotkeyState {
    pub fn any(self) -> bool {
        self.control || self.right_control || self.alt || self.right_alt || self.meta || self.right_meta
    }
}

/// The source routes each scalar through one of two rdev functions. Both
/// paths truncate the scalar to the low 16 bits, not UTF-16 encoding. The
/// layout route may inject temporary modifier presses/releases and uses
/// Unicode as a fallback if VkKeyScanExW cannot map the unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextRoute { UnicodeDirect, LayoutThenUnicodeFallback }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError { Empty, TooLong, ContainsNul }
impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Windows translated text: {self:?}") }
}
impl Error for PlanError {}

/// A borrowed plan deliberately has no Debug implementation: it contains text
/// that can include secrets. It owns no copy, but neither it nor the underlying
/// source string is zeroized; the caller controls both lifetimes and logging.
pub struct TextPlan<'a> { text: &'a str, route: TextRoute }
impl<'a> TextPlan<'a> {
    pub fn route(&self) -> TextRoute { self.route }
    /// Direct Unicode route queries/release-checks ShiftLeft then ShiftRight.
    /// Each check re-observes the OS after any preceding release; this boolean
    /// is not evidence that either key is held or that release will succeed.
    pub fn checks_shift_release(&self) -> bool { self.route == TextRoute::UnicodeDirect }
    /// Return low 16 bits of each Unicode scalar, as the pinned rdev receives
    /// it. These are sensitive text data; never log or retain them unnecessarily.
    pub fn units(&self) -> impl Iterator<Item = u16> + '_ { self.text.chars().map(|scalar| scalar as u32 as u16) }
}

/// Describe only the source branch decision. The local nonempty/NUL/size
/// restrictions deliberately differ from the source. Route selection occurs
/// once before iterating text, and the reported OS observations can be stale.
pub fn plan(text: &str, hotkey: HotkeyState) -> Result<TextPlan<'_>, PlanError> {
    if text.is_empty() { return Err(PlanError::Empty); }
    if text.len() > MAX_TEXT_BYTES { return Err(PlanError::TooLong); }
    if text.contains('\0') { return Err(PlanError::ContainsNul); }
    Ok(TextPlan { text, route: if hotkey.any() { TextRoute::LayoutThenUnicodeFallback } else { TextRoute::UnicodeDirect } })
}

/// Source `get_modifier_state` checks either side for either Shift key. Call
/// this independently with a fresh observation for each of its two checks;
/// a prior release or human input can change the second result. This merely
/// reports the branch, not authorization to release a key.
pub fn source_shift_check(left: bool, right: bool) -> bool { left || right }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_route_preserves_source_truncation_not_utf16_encoding() {
        let plan = plan("A😀\u{10ffff}", HotkeyState::default()).unwrap();
        assert_eq!(plan.route(), TextRoute::UnicodeDirect);
        assert!(plan.checks_shift_release());
        assert_eq!(plan.units().collect::<Vec<_>>(), vec![0x41, 0xf600, 0xffff]);
        assert!(source_shift_check(false, true));
        assert!(!source_shift_check(false, false));
    }
    #[test]
    fn each_hotkey_selects_layout_route_without_shift_checks() {
        let states = [
            HotkeyState { control: true, ..Default::default() },
            HotkeyState { right_control: true, ..Default::default() },
            HotkeyState { alt: true, ..Default::default() },
            HotkeyState { right_alt: true, ..Default::default() },
            HotkeyState { meta: true, ..Default::default() },
            HotkeyState { right_meta: true, ..Default::default() },
        ];
        for state in states {
            let p = plan("é😀", state).unwrap();
            assert_eq!(p.route(), TextRoute::LayoutThenUnicodeFallback);
            assert!(!p.checks_shift_release());
            assert_eq!(p.units().collect::<Vec<_>>(), vec![0xe9, 0xf600]);
        }
    }
    #[test]
    fn bounds_are_local_and_fail_before_plan() {
        assert!(matches!(plan("", HotkeyState::default()), Err(PlanError::Empty)));
        assert!(matches!(plan("a\0b", HotkeyState::default()), Err(PlanError::ContainsNul)));
        assert!(matches!(plan(&"x".repeat(MAX_TEXT_BYTES + 1), HotkeyState::default()), Err(PlanError::TooLong)));
    }
}
