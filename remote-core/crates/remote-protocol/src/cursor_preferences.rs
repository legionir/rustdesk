//! Existing source cursor/window following options. These are untrusted
//! preferences, not permissions, proof of cursor visibility, or instructions
//! to subscribe a service or expose local geometry automatically.
use crate::{message, message_proto, Envelope};
use std::{error::Error, fmt};

/// `None` means unchanged (source NotSet), not false.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CursorPreferences {
    pub show_remote_cursor: Option<bool>, pub follow_remote_cursor: Option<bool>,
    pub follow_remote_window: Option<bool>, pub show_my_cursor: Option<bool>,
}
impl CursorPreferences {
    pub fn is_empty(self) -> bool { self.show_remote_cursor.is_none() && self.follow_remote_cursor.is_none() && self.follow_remote_window.is_none() && self.show_my_cursor.is_none() }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorPreferenceError { Unexpected, UnknownValue }
impl fmt::Display for CursorPreferenceError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "cursor preferences: {self:?}") } }
impl Error for CursorPreferenceError {}
fn read(value: i32) -> Result<Option<bool>, CursorPreferenceError> {
    match value { 0 => Ok(None), 1 => Ok(Some(false)), 2 => Ok(Some(true)), _ => Err(CursorPreferenceError::UnknownValue) }
}
fn write(value: Option<bool>) -> message_proto::option_message::BoolOption {
    use message_proto::option_message::BoolOption;
    match value { None => BoolOption::NotSet, Some(false) => BoolOption::No, Some(true) => BoolOption::Yes }
}
fn update(option: &mut message_proto::OptionMessage, value: CursorPreferences) {
    option.show_remote_cursor = write(value.show_remote_cursor).into();
    option.follow_remote_cursor = write(value.follow_remote_cursor).into();
    option.follow_remote_window = write(value.follow_remote_window).into();
    option.show_my_cursor = write(value.show_my_cursor).into();
}
impl Envelope {
    pub fn cursor_preferences_event(value: CursorPreferences) -> Self {
        let mut option = message_proto::OptionMessage::new(); update(&mut option, value);
        let mut misc = message_proto::Misc::new(); misc.set_option(option);
        let mut inner = message_proto::Message::new(); inner.set_misc(misc); Self { inner }
    }
    /// Inspect source login or standalone option without applying anything.
    /// Unknown values reject this preference group without altering other fields.
    pub fn cursor_preferences(&self) -> Result<CursorPreferences, CursorPreferenceError> {
        let option = match self.inner.union.as_ref() {
            Some(message::Union::LoginRequest(login)) => login.option.as_ref(),
            Some(message::Union::Misc(misc)) => match misc.union.as_ref() { Some(message_proto::misc::Union::Option(option)) => Some(option), _ => None },
            _ => None,
        }.ok_or(CursorPreferenceError::Unexpected)?;
        Ok(CursorPreferences { show_remote_cursor: read(option.show_remote_cursor.value())?,
            follow_remote_cursor: read(option.follow_remote_cursor.value())?, follow_remote_window: read(option.follow_remote_window.value())?,
            show_my_cursor: read(option.show_my_cursor.value())? })
    }
    /// Update only these four fields on an existing source option or desktop
    /// login; other options, capabilities and login proof are preserved.
    pub fn set_cursor_preferences(&mut self, value: CursorPreferences) -> Result<(), CursorPreferenceError> {
        let option = match self.inner.union.as_mut() {
            Some(message::Union::LoginRequest(login)) if login.union.is_none() => {
                if login.option.is_none() { login.option = Some(message_proto::OptionMessage::new()).into(); }
                login.option.as_mut().ok_or(CursorPreferenceError::Unexpected)?
            },
            Some(message::Union::Misc(misc)) => match misc.union.as_mut() {
                Some(message_proto::misc::Union::Option(option)) => option, _ => return Err(CursorPreferenceError::Unexpected),
            },
            _ => return Err(CursorPreferenceError::Unexpected),
        };
        update(option, value); Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_three_state_and_unrelated_options() {
        use crate::video_preferences::{Quality, VideoPreferences};
        let video = VideoPreferences { quality: Some(Quality::Best), fps: Some(30) };
        let cursor = CursorPreferences { show_remote_cursor: Some(true), follow_remote_cursor: Some(false), ..Default::default() };
        let mut option = Envelope::video_preferences_event(video).unwrap(); option.set_cursor_preferences(cursor).unwrap();
        let decoded = Envelope::decode(&option.encode(1024).unwrap(), 1024).unwrap();
        assert_eq!(decoded.video_preferences().unwrap(), video); assert_eq!(decoded.cursor_preferences().unwrap(), cursor);
        assert_eq!(read(3), Err(CursorPreferenceError::UnknownValue));
        assert!(CursorPreferences::default().is_empty());
    }
}
