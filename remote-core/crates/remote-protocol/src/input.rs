//! Constructors for the existing RustDesk mouse/legacy keyboard schema.
//! They validate basic resource bounds but do not authorize input, interpret
//! keyboard layouts or prove that a target supports the requested event.
use super::{message_proto, Envelope, MouseEvent};
use hbb_common::protobuf::{Enum, EnumOrUnknown};
use std::{error::Error, fmt};

/// Wire payload supported by this constructor, without layout translation.
pub enum LegacyKey<'a> { ControlKey(i32), Unicode(u32), Sequence(&'a str) }
/// Bounded keyboard/mouse construction error.
#[derive(Debug)]
pub enum InputWireError { InvalidControlKey, InvalidModifier, TooManyModifiers, InvalidText, InvalidScanCode }
impl fmt::Display for InputWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidControlKey => f.write_str("unrecognized source control key"),
            Self::InvalidModifier => f.write_str("unrecognized modifier"),
            Self::TooManyModifiers => f.write_str("too many modifiers"),
            Self::InvalidText => f.write_str("invalid input text"),
            Self::InvalidScanCode => f.write_str("invalid Windows scan code"),
        }
    }
}
impl Error for InputWireError {}
fn modifiers(values: &[i32]) -> Result<Vec<EnumOrUnknown<message_proto::ControlKey>>, InputWireError> {
    if values.len() > 16 { return Err(InputWireError::TooManyModifiers); }
    values.iter().map(|value| message_proto::ControlKey::from_i32(*value)
        .map(EnumOrUnknown::new).ok_or(InputWireError::InvalidModifier)).collect()
}
impl Envelope {
    /// Construct a source mouse envelope with its original modifier values.
    /// The receiver still validates action, coordinates and permissions.
    pub fn mouse_event_with_modifiers(event: MouseEvent, values: &[i32]) -> Result<Self, InputWireError> {
        let mut mouse = message_proto::MouseEvent::new(); mouse.mask = event.mask; mouse.x = event.x; mouse.y = event.y;
        mouse.modifiers = modifiers(values)?;
        let mut inner = message_proto::Message::new(); inner.set_mouse_event(mouse); Ok(Self { inner })
    }
    /// Construct a restricted source Map-mode scan-code event. The caller
    /// must know that the host is Windows and accepts this opt-in mode.
    pub fn windows_scan_event(code: u32, down: bool) -> Result<Self, InputWireError> {
        let high = code >> 8; let low = code & 0xff;
        if low == 0 || !matches!(high, 0 | 0xe0 | 0xe1) { return Err(InputWireError::InvalidScanCode); }
        let mut keyboard = message_proto::KeyEvent::new(); keyboard.mode = message_proto::KeyboardMode::Map.into();
        keyboard.down = down; keyboard.set_chr(code);
        let mut inner = message_proto::Message::new(); inner.set_key_event(keyboard); Ok(Self { inner })
    }
    /// Construct a restricted source Translate-mode Windows position event.
    /// Upper 16 bits encode a Windows virtual key when nonzero; otherwise the
    /// low bits encode a physical scan code. Compatibility is caller-owned.
    pub fn windows_translate_event(code: u32, down: bool) -> Result<Self, InputWireError> {
        let vk = code >> 16;
        if vk == 0 {
            let high = code >> 8; let low = code & 0xff;
            if low == 0 || !matches!(high, 0 | 0xe0 | 0xe1) { return Err(InputWireError::InvalidScanCode); }
        } else if vk > 0xfe { return Err(InputWireError::InvalidControlKey); }
        let mut keyboard = message_proto::KeyEvent::new(); keyboard.mode = message_proto::KeyboardMode::Translate.into();
        keyboard.down = down; keyboard.set_chr(code);
        let mut inner = message_proto::Message::new(); inner.set_key_event(keyboard); Ok(Self { inner })
    }
    /// Construct a bounded source Translate-mode sequence. A real Windows
    /// peer can inject text into the focused application. This does not grant
    /// authorization, prove consent, choose a safe desktop, or guarantee Unicode
    /// fidelity. Source Windows/rdev truncates non-BMP scalars in this path.
    pub fn windows_translate_sequence_event(text: &str) -> Result<Self, InputWireError> {
        if text.is_empty() || text.len() > 4096 || text.contains('\0') { return Err(InputWireError::InvalidText); }
        let mut keyboard = message_proto::KeyEvent::new(); keyboard.mode = message_proto::KeyboardMode::Translate.into();
        keyboard.set_seq(text.to_owned());
        let mut inner = message_proto::Message::new(); inner.set_key_event(keyboard); Ok(Self { inner })
    }
    /// Construct RustDesk's existing Windows-to-Windows Translate-mode hotkey
    /// payload: upper 16 bits are a source virtual-key code, lower 16 bits a
    /// UTF-16 code unit. No layout conversion, OS event, consent or authorization
    /// occurs. Modifier values are untrusted peer claims. This reproduces the
    /// wire shape, not proof that the host safely supports the event.
    pub fn windows_hotkey_event(virtual_key: u16, unicode: u16, down: bool, values: &[i32]) -> Result<Self, InputWireError> {
        let mut keyboard = message_proto::KeyEvent::new();
        keyboard.mode = message_proto::KeyboardMode::Translate.into(); keyboard.down = down;
        keyboard.modifiers = modifiers(values)?;
        keyboard.set_win2win_hotkey((u32::from(virtual_key) << 16) | u32::from(unicode));
        let mut inner = message_proto::Message::new(); inner.set_key_event(keyboard); Ok(Self { inner })
    }
    /// Construct a legacy-mode source keyboard message. The receiver determines
    /// semantics and permission; position/translate/map modes are not covered.
    pub fn legacy_keyboard_event(key: LegacyKey<'_>, down: bool, press: bool, values: &[i32]) -> Result<Self, InputWireError> {
        let mut keyboard = message_proto::KeyEvent::new();
        keyboard.down = down; keyboard.press = press; keyboard.modifiers = modifiers(values)?;
        match key {
            LegacyKey::ControlKey(value) => keyboard.set_control_key(message_proto::ControlKey::from_i32(value).ok_or(InputWireError::InvalidControlKey)?),
            LegacyKey::Unicode(value) => {
                if char::from_u32(value).map_or(true, |c| c == '\0') { return Err(InputWireError::InvalidText); }
                keyboard.set_unicode(value);
            },
            LegacyKey::Sequence(text) => {
                if text.is_empty() || text.len() > 4096 || text.contains('\0') { return Err(InputWireError::InvalidText); }
                keyboard.set_seq(text.to_owned());
            },
        }
        let mut inner = message_proto::Message::new(); inner.set_key_event(keyboard); Ok(Self { inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyboardPayload;
    #[test]
    fn windows_translate_sequence_uses_source_wire_mode_and_bounds() {
        let message = Envelope::windows_translate_sequence_event("A😀").unwrap();
        let decoded = Envelope::decode(&message.encode(8192).unwrap(), 8192).unwrap();
        let key = decoded.keyboard().unwrap();
        assert_eq!(key.mode(), 2);
        assert_eq!(key.payload(), Some(KeyboardPayload::Sequence("A😀")));
        assert!(Envelope::windows_translate_sequence_event("").is_err());
        assert!(Envelope::windows_translate_sequence_event("a\0b").is_err());
        assert!(Envelope::windows_translate_sequence_event(&"x".repeat(4097)).is_err());
    }
    #[test]
    fn windows_hotkey_preserves_both_wire_words() {
        let message = Envelope::windows_hotkey_event(0x41, 0x00e9, true, &[4]).unwrap();
        let bytes = message.encode(4096).unwrap(); let decoded = Envelope::decode(&bytes, 4096).unwrap();
        let event = decoded.keyboard().unwrap();
        assert_eq!(event.mode(), 2); assert!(event.down());
        assert_eq!(event.modifiers().collect::<Vec<_>>(), vec![4]);
        assert_eq!(event.payload(), Some(KeyboardPayload::WindowsHotkey(0x0041_00e9)));
        assert!(Envelope::windows_hotkey_event(0, 0, false, &[4; 17]).is_err());
    }
    #[test]
    fn legacy_key_and_mouse_modifiers_round_trip() {
        let message = Envelope::legacy_keyboard_event(LegacyKey::ControlKey(13), true, false, &[4]).unwrap();
        let wire = message.encode(4096).unwrap();
        let parsed = Envelope::decode(&wire, 4096).unwrap();
        let key = parsed.keyboard().unwrap();
        assert_eq!(key.payload(), Some(KeyboardPayload::ControlKey(13)));
        assert_eq!(key.modifiers().collect::<Vec<_>>(), vec![4]);
        let mouse = Envelope::mouse_event_with_modifiers(MouseEvent { mask: 0, x: -4, y: 8 }, &[29]).unwrap();
        assert_eq!(mouse.mouse_modifiers().unwrap().collect::<Vec<_>>(), vec![29]);
        let scan = Envelope::windows_scan_event(0xe01d, true).unwrap();
        let wire = scan.encode(4096).unwrap(); let parsed = Envelope::decode(&wire, 4096).unwrap();
        assert_eq!(parsed.keyboard().unwrap().mode(), 1);
        assert_eq!(parsed.keyboard().unwrap().payload(), Some(KeyboardPayload::Position(0xe01d)));
        assert!(Envelope::windows_scan_event(0, true).is_err());
    }
}

#[cfg(test)]
mod redacted_debug_tests {
    use crate::{KeyboardPayload, OwnedVideoPacket};
    #[test]
    fn debug_never_prints_sequence_or_key_payload_values() {
        let payloads = [KeyboardPayload::Sequence("confidential-test-value"), KeyboardPayload::Unicode(12345),
            KeyboardPayload::ControlKey(12345), KeyboardPayload::Position(12345), KeyboardPayload::WindowsHotkey(12345)];
        for payload in payloads {
            let formatted = format!("{payload:?}");
            assert!(formatted.contains("REDACTED"));
            assert!(!formatted.contains("confidential-test-value")); assert!(!formatted.contains("12345"));
        }
        let packet = OwnedVideoPacket { data: vec![101, 102, 103], key: true, pts: 0 };
        let formatted = format!("{packet:?}");
        assert!(!formatted.contains("101")); assert!(formatted.contains("bytes: 3"));
    }
}
