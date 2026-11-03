//! RustDesk's existing OptionMessage image-quality and FPS fields.
//!
//! These are untrusted preferences, not permissions, measured capabilities or
//! instructions to change a local encoder automatically. Other source options
//! are deliberately not applied by this adapter. The original envelope remains
//! available to a caller who needs to inspect additional source fields.
use crate::{message, message_proto, Envelope};
use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quality { Low, Balanced, Best, Custom(i32) }
impl Quality {
    /// Value expected by the source video-QoS `user_image_quality` function.
    pub fn source_value(self) -> i32 { match self { Self::Low => 2, Self::Balanced => 3, Self::Best => 4, Self::Custom(value) => value } }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VideoPreferences { pub quality: Option<Quality>, pub fps: Option<u32> }
impl VideoPreferences { pub fn is_empty(&self) -> bool { self.quality.is_none() && self.fps.is_none() } }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferenceError { Unexpected, InvalidQuality, InvalidFps }
impl fmt::Display for PreferenceError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "video preferences: {self:?}") } }
impl Error for PreferenceError {}
fn validate(value: VideoPreferences) -> Result<(), PreferenceError> {
    if let Some(Quality::Custom(value)) = value.quality {
        if value <= 0 { return Err(PreferenceError::InvalidQuality); }
    }
    if value.fps.map_or(false, |fps| !(1..=120).contains(&fps)) { return Err(PreferenceError::InvalidFps); }
    Ok(())
}
fn write_option(option: &mut message_proto::OptionMessage, value: VideoPreferences) -> Result<(), PreferenceError> {
    validate(value)?;
    option.image_quality = match value.quality {
        Some(Quality::Low) => message_proto::ImageQuality::Low,
        Some(Quality::Balanced) => message_proto::ImageQuality::Balanced,
        Some(Quality::Best) => message_proto::ImageQuality::Best,
        _ => message_proto::ImageQuality::NotSet,
    }.into();
    option.custom_image_quality = match value.quality { Some(Quality::Custom(v)) => v, _ => 0 };
    option.custom_fps = value.fps.unwrap_or(0) as i32;
    Ok(())
}
impl Envelope {
    /// Construct only the source video preference fields, never unrelated
    /// privacy, input, recording, clipboard, or decoder options.
    pub fn video_preferences_event(value: VideoPreferences) -> Result<Self, PreferenceError> {
        let mut option = message_proto::OptionMessage::new(); write_option(&mut option, value)?;
        let mut misc = message_proto::Misc::new(); misc.set_option(option);
        let mut inner = message_proto::Message::new(); inner.set_misc(misc); Ok(Self { inner })
    }
    /// Add preferences to an existing standalone option, preserving decoder
    /// claims and all other fields. The caller is responsible for any unrelated
    /// fields already present; this function neither authorizes nor applies them.
    pub fn set_option_video_preferences(&mut self, value: VideoPreferences) -> Result<(), PreferenceError> {
        validate(value)?;
        let option = match self.inner.union.as_mut() {
            Some(message::Union::Misc(misc)) => match misc.union.as_mut() {
                Some(message_proto::misc::Union::Option(option)) => option,
                _ => return Err(PreferenceError::Unexpected),
            },
            _ => return Err(PreferenceError::Unexpected),
        };
        write_option(option, value)
    }
    /// Add preferences to a constructed desktop login, preserving any other
    /// fields already present. Validation does not prove peer support.
    pub fn set_login_video_preferences(&mut self, value: VideoPreferences) -> Result<(), PreferenceError> {
        validate(value)?;
        let login = match self.inner.union.as_mut() {
            Some(message::Union::LoginRequest(login)) if login.union.is_none() => login,
            _ => return Err(PreferenceError::Unexpected),
        };
        if login.option.is_none() { login.option = Some(message_proto::OptionMessage::new()).into(); }
        write_option(login.option.as_mut().ok_or(PreferenceError::Unexpected)?, value)
    }
    /// Read only bounded quality/FPS from a source login or standalone option.
    /// Unlike the source's ignore behavior, invalid positive FPS and unknown
    /// image-quality enums are rejected, never cast or applied automatically.
    pub fn video_preferences(&self) -> Result<VideoPreferences, PreferenceError> {
        let option = match self.inner.union.as_ref() {
            Some(message::Union::LoginRequest(login)) => login.option.as_ref(),
            Some(message::Union::Misc(misc)) => match misc.union.as_ref() {
                Some(message_proto::misc::Union::Option(option)) => Some(option), _ => None,
            }, _ => None,
        }.ok_or(PreferenceError::Unexpected)?;
        let quality = match option.image_quality.value() {
            0 if option.custom_image_quality > 0 => Some(Quality::Custom(option.custom_image_quality)),
            0 => None, 2 => Some(Quality::Low), 3 => Some(Quality::Balanced), 4 => Some(Quality::Best),
            _ => return Err(PreferenceError::InvalidQuality),
        };
        let fps = if option.custom_fps > 0 {
            Some(u32::try_from(option.custom_fps).map_err(|_| PreferenceError::InvalidFps)?)
        } else { None };
        let result = VideoPreferences { quality, fps }; validate(result)?; Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::DesktopLogin;
    #[test]
    fn source_option_and_login_preferences_roundtrip() {
        for quality in [Quality::Low, Quality::Balanced, Quality::Best, Quality::Custom(0x6400)] {
            let preferences = VideoPreferences { quality: Some(quality), fps: Some(30) };
            let bytes = Envelope::video_preferences_event(preferences).unwrap().encode(4096).unwrap();
            assert_eq!(Envelope::decode(&bytes, 4096).unwrap().video_preferences().unwrap(), preferences);
            let mut login = Envelope::desktop_login_event(DesktopLogin { username: "host", peer_id: "v", peer_name: "v", password_response: &[1; 32], session_id: 1, version: "t" }).unwrap();
            login.set_login_video_preferences(preferences).unwrap();
            assert_eq!(login.video_preferences().unwrap(), preferences);
        }
    }
    #[test]
    fn login_combines_decoder_and_preferences_without_exposing_proof() {
        use crate::{CodecPreference, DecodingAdvertisement};
        let ad = DecodingAdvertisement { vp8: false, vp9: true, av1: false, h264: false, h265: false, preference: CodecPreference::Vp9 };
        let value = VideoPreferences { quality: Some(Quality::Best), fps: Some(60) };
        let mut login = Envelope::desktop_login_event(DesktopLogin { username: "host", peer_id: "v", peer_name: "v", password_response: &[7; 32], session_id: 1, version: "t" }).unwrap();
        login.set_login_decoding(ad).unwrap(); login.set_login_video_preferences(value).unwrap();
        let decoded = Envelope::decode(&login.encode(4096).unwrap(), 4096).unwrap();
        assert_eq!(decoded.video_preferences().unwrap(), value);
        assert_eq!(decoded.supported_decoding().unwrap().vp9, 1);
        let isolated = decoded.extract_supported_decoding_event().unwrap();
        assert!(!isolated.encode(4096).unwrap().windows(32).any(|bytes| bytes == [7; 32]));
        assert!(isolated.video_preferences().unwrap().is_empty());
    }
    #[test]
    fn standalone_option_preserves_simultaneous_decoding() {
        use crate::{CodecPreference, DecodingAdvertisement};
        let ad = DecodingAdvertisement { vp8: false, vp9: true, av1: false, h264: false, h265: false, preference: CodecPreference::Vp9 };
        let preferences = VideoPreferences { quality: Some(Quality::Balanced), fps: Some(24) };
        let mut msg = Envelope::supported_decoding_event(ad);
        msg.set_option_video_preferences(preferences).unwrap();
        let decoded = Envelope::decode(&msg.encode(4096).unwrap(), 4096).unwrap();
        assert_eq!(decoded.supported_decoding().unwrap().vp9, 1);
        assert_eq!(decoded.video_preferences().unwrap(), preferences);
    }
    #[test]
    fn enum_precedes_custom_and_invalid_fps_does_not_erase_decoding() {
        use crate::{CodecPreference, DecodingAdvertisement};
        let ad = DecodingAdvertisement { vp8: false, vp9: true, av1: false, h264: false, h265: false, preference: CodecPreference::Vp9 };
        let mut msg = Envelope::supported_decoding_event(ad);
        let option = match msg.inner.union.as_mut().unwrap() { message::Union::Misc(m) => match m.union.as_mut().unwrap() { message_proto::misc::Union::Option(o) => o, _ => unreachable!() }, _ => unreachable!() };
        option.image_quality = message_proto::ImageQuality::Low.into(); option.custom_image_quality = 0x6400; option.custom_fps = 121;
        assert_eq!(msg.video_preferences(), Err(PreferenceError::InvalidFps));
        assert_eq!(msg.supported_decoding().unwrap().vp9, 1);
        let option = match msg.inner.union.as_mut().unwrap() { message::Union::Misc(m) => match m.union.as_mut().unwrap() { message_proto::misc::Union::Option(o) => o, _ => unreachable!() }, _ => unreachable!() };
        option.custom_fps = 30;
        assert_eq!(msg.video_preferences().unwrap().quality, Some(Quality::Low));
    }
    #[test]
    fn rejects_invalid_local_values() {
        assert_eq!(Envelope::video_preferences_event(VideoPreferences { quality: None, fps: Some(121) }).err(), Some(PreferenceError::InvalidFps));
        assert_eq!(Envelope::video_preferences_event(VideoPreferences { quality: Some(Quality::Custom(0)), fps: None }).err(), Some(PreferenceError::InvalidQuality));
    }
}
