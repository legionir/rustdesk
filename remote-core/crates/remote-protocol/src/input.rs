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
pub enum InputWireError { InvalidControlKey, InvalidModifier, TooManyModifiers, InvalidText }
impl fmt::Display for InputWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidControlKey => f.write_str("unrecognized source control key"),
            Self::InvalidModifier => f.write_str("unrecognized modifier"),
            Self::TooManyModifiers => f.write_str("too many modifiers"),
            Self::InvalidText => f.write_str("invalid input text"),
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
    fn legacy_key_and_mouse_modifiers_round_trip() {
        let message = Envelope::legacy_keyboard_event(LegacyKey::ControlKey(13), true, false, &[4]).unwrap();
        let wire = message.encode(4096).unwrap();
        let parsed = Envelope::decode(&wire, 4096).unwrap();
        let key = parsed.keyboard().unwrap();
        assert_eq!(key.payload(), Some(KeyboardPayload::ControlKey(13)));
        assert_eq!(key.modifiers().collect::<Vec<_>>(), vec![4]);
        let mouse = Envelope::mouse_event_with_modifiers(MouseEvent { mask: 0, x: -4, y: 8 }, &[29]).unwrap();
        assert_eq!(mouse.mouse_modifiers().unwrap().collect::<Vec<_>>(), vec![29]);
    }
}
