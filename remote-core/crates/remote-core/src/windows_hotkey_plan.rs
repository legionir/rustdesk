//! Read-only extraction of the pinned Windows `Win2winHotkey` branch in
//! `src/server/input_service.rs::simulate_win2win_hotkey`. No keyboard state,
//! platform layout, SendInput, authorization, cleanup or retry is performed.
//! The source falls back to a scan-code event when `simulate_key_unicode`
//! returns an error; that error can follow partial native input. Blindly
//! executing both branches can duplicate input or leave modifiers held.
use remote_protocol::{Envelope, KeyboardPayload};
use std::{error::Error, fmt};

const MAX_MODIFIERS: usize = 16;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotkeyPlanError { UnexpectedMessage, UnsupportedMode, UnsupportedPayload, TooManyModifiers }
impl fmt::Display for HotkeyPlanError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Windows hotkey plan: {self:?}") } }
impl Error for HotkeyPlanError {}
/// Source branch decision. Values are untrusted peer claims and can contain
/// zero, surrogates, reserved or invalid Windows key values. A scan is determined
/// by current native layout later, not by this plan. No state is tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotkeyAction {
    /// Source attempts a layout-dependent Unicode key click; *any* error
    /// triggers fallback to a separately computed VK scan-down event.
    TryUnicodeClick { utf16_unit: u16, fallback_virtual_key: u16 },
    /// Source maps the virtual key to a scan and issues an up event.
    ScanRelease { virtual_key: u16 },
}
/// The original flags are retained for the caller's policy analysis. Source's
/// specific hotkey branch uses `down` and the two words; this adapter does not
/// assert the rest of the input service or OS modifier state is equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotkeyPlan { pub action: HotkeyAction, pub press_flag: bool, pub modifier_count: usize }
/// Inspect an existing Translate-mode payload, with a local bound on modifier
/// count. Does not prove Windows-to-Windows origin or permit injection.
pub fn plan(event: &Envelope) -> Result<HotkeyPlan, HotkeyPlanError> {
    let event = event.keyboard().map_err(|_| HotkeyPlanError::UnexpectedMessage)?;
    if event.mode() != 2 { return Err(HotkeyPlanError::UnsupportedMode); }
    let raw = match event.payload() { Some(KeyboardPayload::WindowsHotkey(raw)) => raw, _ => return Err(HotkeyPlanError::UnsupportedPayload) };
    let mut modifier_count = 0usize;
    for _ in event.modifiers() {
        modifier_count += 1; if modifier_count > MAX_MODIFIERS { return Err(HotkeyPlanError::TooManyModifiers); }
    }
    let virtual_key = (raw >> 16) as u16;
    let unicode = raw as u16;
    let action = if event.down() {
        HotkeyAction::TryUnicodeClick { utf16_unit: unicode, fallback_virtual_key: virtual_key }
    } else {
        HotkeyAction::ScanRelease { virtual_key }
    };
    Ok(HotkeyPlan { action, press_flag: event.press(), modifier_count })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_high_low_word_and_down_up_branches() {
        let down = Envelope::windows_hotkey_event(0x41, 0x00e9, true, &[4, 29]).unwrap();
        let up = Envelope::windows_hotkey_event(0x41, 0xffff, false, &[]).unwrap();
        assert_eq!(plan(&down), Ok(HotkeyPlan { action: HotkeyAction::TryUnicodeClick { utf16_unit: 0x00e9, fallback_virtual_key: 0x41 }, press_flag: false, modifier_count: 2 }));
        assert_eq!(plan(&up), Ok(HotkeyPlan { action: HotkeyAction::ScanRelease { virtual_key: 0x41 }, press_flag: false, modifier_count: 0 }));
    }
    #[test]
    fn malformed_context_and_untrusted_words_are_not_os_actions() {
        let surrogate = Envelope::windows_hotkey_event(0xffff, 0xd800, true, &[]).unwrap();
        assert_eq!(plan(&surrogate).unwrap().action, HotkeyAction::TryUnicodeClick { utf16_unit: 0xd800, fallback_virtual_key: 0xffff });
        let legacy = Envelope::legacy_keyboard_event(remote_protocol::input::LegacyKey::ControlKey(2), true, false, &[]).unwrap();
        assert_eq!(plan(&legacy), Err(HotkeyPlanError::UnsupportedMode));
        let scan = Envelope::windows_translate_event(0x1e, true).unwrap();
        assert_eq!(plan(&scan), Err(HotkeyPlanError::UnsupportedPayload));
        let mouse = Envelope::mouse_event(remote_protocol::MouseEvent { mask: 0, x: 0, y: 0 });
        assert_eq!(plan(&mouse), Err(HotkeyPlanError::UnexpectedMessage));
    }
}
