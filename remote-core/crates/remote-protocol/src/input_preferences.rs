//! Existing RustDesk `OptionMessage.disable_keyboard` tri-state. In the source
//! it gates the combined keyboard/mouse permission; it cannot grant permission.
//! Parsing or constructing this value does not change input authorization,
//! release held input, subscribe cursor services or modify OS state.
use crate::{message, message_proto, Envelope};
use std::{error::Error, fmt};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputPreferenceError { Unexpected, UnknownValue }
impl fmt::Display for InputPreferenceError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "input preference: {self:?}") } }
impl Error for InputPreferenceError {}
impl Envelope {
    /// A `None` value means NotSet/unchanged, not enabled or authorized.
    pub fn input_preference_event(disable_keyboard: Option<bool>) -> Self {
        use message_proto::option_message::BoolOption;
        let mut option = message_proto::OptionMessage::new();
        option.disable_keyboard = match disable_keyboard { None => BoolOption::NotSet, Some(true) => BoolOption::Yes, Some(false) => BoolOption::No }.into();
        let mut misc = message_proto::Misc::new(); misc.set_option(option);
        let mut inner = message_proto::Message::new(); inner.set_misc(misc); Self { inner }
    }
    /// Set the field on a desktop login or standalone source option without
    /// replacing other options, decoder claims or the password response.
    pub fn set_disable_keyboard_preference(&mut self, value: Option<bool>) -> Result<(), InputPreferenceError> {
        use message_proto::option_message::BoolOption;
        let option = match self.inner.union.as_mut() {
            Some(message::Union::LoginRequest(login)) if login.union.is_none() => {
                if login.option.is_none() { login.option = Some(message_proto::OptionMessage::new()).into(); }
                login.option.as_mut().ok_or(InputPreferenceError::Unexpected)?
            },
            Some(message::Union::Misc(misc)) => match misc.union.as_mut() {
                Some(message_proto::misc::Union::Option(option)) => option, _ => return Err(InputPreferenceError::Unexpected),
            },
            _ => return Err(InputPreferenceError::Unexpected),
        };
        option.disable_keyboard = match value { None => BoolOption::NotSet, Some(false) => BoolOption::No, Some(true) => BoolOption::Yes }.into();
        Ok(())
    }
    /// Read only the disable flag from a source login or option message. Other
    /// fields remain available separately and must not be implicitly discarded.
    pub fn disable_keyboard_preference(&self) -> Result<Option<bool>, InputPreferenceError> {
        let option = match self.inner.union.as_ref() {
            Some(message::Union::LoginRequest(login)) => login.option.as_ref(),
            Some(message::Union::Misc(misc)) => match misc.union.as_ref() { Some(message_proto::misc::Union::Option(option)) => Some(option), _ => None },
            _ => None,
        }.ok_or(InputPreferenceError::Unexpected)?;
        match option.disable_keyboard.value() { 0 => Ok(None), 1 => Ok(Some(false)), 2 => Ok(Some(true)), _ => Err(InputPreferenceError::UnknownValue) }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_other_login_and_option_fields() {
        use crate::{DesktopLogin, video_preferences::{Quality, VideoPreferences}};
        let value = VideoPreferences { quality: Some(Quality::Balanced), fps: Some(30) };
        let mut option = Envelope::video_preferences_event(value).unwrap();
        option.set_disable_keyboard_preference(Some(true)).unwrap();
        assert_eq!(option.video_preferences().unwrap(), value);
        assert_eq!(option.disable_keyboard_preference().unwrap(), Some(true));
        let mut login = Envelope::desktop_login_event(DesktopLogin { username: "host", peer_id: "viewer", peer_name: "viewer", password_response: &[7; 32], session_id: 2, version: "test" }).unwrap();
        login.set_disable_keyboard_preference(Some(false)).unwrap();
        assert_eq!(login.disable_keyboard_preference().unwrap(), Some(false));
        assert_eq!(login.desktop_login().unwrap().password_response, &[7; 32]);
    }
    #[test]
    fn source_tristate_roundtrips_without_authorizing_input() {
        for value in [None, Some(false), Some(true)] {
            let raw = Envelope::input_preference_event(value).encode(1024).unwrap();
            assert_eq!(Envelope::decode(&raw, 1024).unwrap().disable_keyboard_preference().unwrap(), value);
        }
    }
}
