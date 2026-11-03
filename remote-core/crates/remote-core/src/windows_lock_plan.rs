//! Side-effect-free Windows legacy keyboard lock-mode decision, adapted from
//! `input_service.rs::{LockModesHandler,skip_led_sync_control_key,
//! is_numpad_control_key,should_disable_numlock}`. This is a deliberately
//! restricted planner, not native lock-state synchronization or input dispatch.
//!
//! The caller must supply freshly sampled OS lock states and explicitly decide
//! whether to trust peer modifier claims. Lock toggles affect the local desktop
//! and can race local users, other sessions, desktop switches and other apps.
//! There is no automatic key injection, restoration, exclusive ownership or
//! guarantee that lock state is observed correctly. Never use as authorization.
use remote_protocol::{Envelope, KeyboardPayload};
use std::{error::Error, fmt};

const MAX_MODIFIERS: usize = 32;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockPlan { Skip, Toggle { caps_lock: bool, num_lock: bool } }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockPlanError { Unexpected, Unsupported, TooManyModifiers }
impl fmt::Display for LockPlanError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Windows lock plan: {self:?}") } }
impl Error for LockPlanError {}
/// Decide which temporary lock toggles the pinned source would use for a
/// supported legacy event on Windows. Source toggles them back on handler drop;
/// this function neither makes nor restores those changes. Unknown modes,
/// payloads, and lock/system control keys are rejected rather than guessed.
pub fn legacy_lock_plan(event: &Envelope, local_caps: bool, local_num: bool) -> Result<LockPlan, LockPlanError> {
    let event = event.keyboard().map_err(|_| LockPlanError::Unexpected)?;
    if event.mode() != 0 { return Err(LockPlanError::Unsupported); }
    let mut caps = false; let mut num = false; let mut count = 0;
    for modifier in event.modifiers() {
        count += 1; if count > MAX_MODIFIERS { return Err(LockPlanError::TooManyModifiers); }
        caps |= modifier == 3; num |= modifier == 63;
    }
    let (numpad, navigation) = match event.payload() {
        Some(KeyboardPayload::ControlKey(k)) => {
            // Source skips synchronization for modifier, Return and Tab keys.
            if matches!(k, 1 | 4 | 23 | 27 | 29 | 31 | 73 | 74 | 75) { return Ok(LockPlan::Skip); }
            // Our limited dispatcher does not support system and lock keys.
            if crate::windows_keyboard::plain_control_vk(k).is_none() { return Err(LockPlanError::Unsupported); }
            (matches!(k, 33..=42 | 72), matches!(k, 5 | 6 | 7 | 21 | 22 | 25 | 26 | 28 | 32 | 58))
        },
        Some(KeyboardPayload::Unicode(_) | KeyboardPayload::Sequence(_)) => (false, false),
        _ => return Err(LockPlanError::Unsupported),
    };
    let toggle_num = if numpad { num != local_num } else { navigation && local_num };
    Ok(LockPlan::Toggle { caps_lock: caps != local_caps, num_lock: toggle_num })
}
#[cfg(test)]
mod tests {
    use super::*;
    use remote_protocol::input::LegacyKey;
    fn key(code: i32, modifiers: &[i32]) -> Envelope { Envelope::legacy_keyboard_event(LegacyKey::ControlKey(code), true, false, modifiers).unwrap() }
    #[test]
    fn all_source_navigation_and_numpad_lock_decisions() {
        // Values from ControlKey and NUMPAD_KEY_MAP in the pinned source.
        for code in [5, 6, 7, 21, 22, 25, 26, 28, 32, 58] {
            for local_num in [false, true] {
                for local_caps in [false, true] {
                    let decision = legacy_lock_plan(&key(code, &[3, 63]), local_caps, local_num).unwrap();
                    assert_eq!(decision, LockPlan::Toggle { caps_lock: !local_caps, num_lock: local_num }, "navigation key {code}");
                }
            }
        }
        for code in (33..=42).chain(std::iter::once(72)) {
            for local_num in [false, true] {
                for peer_num in [false, true] {
                    let modifiers = if peer_num { vec![63] } else { vec![] };
                    let decision = legacy_lock_plan(&key(code, &modifiers), false, local_num).unwrap();
                    assert_eq!(decision, LockPlan::Toggle { caps_lock: false, num_lock: local_num != peer_num }, "numpad key {code}");
                }
            }
        }
        for code in [1, 4, 23, 27, 29, 31, 73, 74, 75] {
            assert_eq!(legacy_lock_plan(&key(code, &[3, 63]), false, false), Ok(LockPlan::Skip));
        }
    }
    #[test]
    fn source_navigation_numpad_and_skipped_keys() {
        assert_eq!(legacy_lock_plan(&key(21, &[]), false, true), Ok(LockPlan::Toggle { caps_lock: false, num_lock: true }));
        assert_eq!(legacy_lock_plan(&key(33, &[3, 63]), false, false), Ok(LockPlan::Toggle { caps_lock: true, num_lock: true }));
        assert_eq!(legacy_lock_plan(&key(33, &[63]), false, true), Ok(LockPlan::Toggle { caps_lock: false, num_lock: false }));
        assert_eq!(legacy_lock_plan(&key(31, &[3]), false, true), Ok(LockPlan::Skip));
        assert_eq!(legacy_lock_plan(&key(63, &[]), false, true), Err(LockPlanError::Unsupported));
    }
}
