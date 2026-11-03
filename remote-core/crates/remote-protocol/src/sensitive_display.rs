//! Wire-only extraction of source `Misc.TogglePrivacyMode` and
//! `Misc.ToggleVirtualDisplay`. These are sensitive OS-affecting requests,
//! not authorization or proof of a valid device, implementation, session,
//! privacy guarantee or local consent. No request is sent or executed here.
//! Unrecognized or unsupported requests must not be silently applied.
use crate::{message, message_proto, Envelope};
use hbb_common::protobuf::Enum;
use std::{error::Error, fmt};

const MAX_IMPL_KEY_BYTES: usize = 256;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveDisplayError { Unexpected, InvalidImplementationKey, InvalidNotice, InvalidOption }
impl fmt::Display for SensitiveDisplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "sensitive display request: {self:?}") }
}
impl Error for SensitiveDisplayError {}
#[derive(Clone, PartialEq, Eq)]
pub struct PrivacyRequest { pub impl_key: String, pub on: bool }
// A peer-controlled implementation key must not become a terminal/log injection.
impl fmt::Debug for PrivacyRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("PrivacyRequest").field("on", &self.on).finish_non_exhaustive() }
}
/// Raw signed index is retained exactly. Source supports platform-specific
/// meanings; this type neither validates a monitor nor permits plug/unplug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualDisplayRequest { pub display: i32, pub on: bool }
/// An untrusted peer report, not proof of OS privacy or input-blocking state.
/// Unknown numeric enum values are retained on read for forward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayNoticeKind { Privacy(i32), BlockInput(i32) }
#[derive(Clone, PartialEq, Eq)]
pub struct DisplayNotice { pub kind: DisplayNoticeKind, pub details: String, pub impl_key: String }
impl fmt::Debug for DisplayNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("DisplayNotice").field("kind", &self.kind).finish_non_exhaustive() }
}
/// Existing tri-state source options. `None` means no request, not false.
/// Sending these options to a real peer can change its OS/input behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SensitiveOptions { pub legacy_privacy: Option<bool>, pub block_input: Option<bool>, pub lock_after_session: Option<bool> }
fn option_value(value: i32) -> Result<Option<bool>, SensitiveDisplayError> {
    match value { 0 => Ok(None), 1 => Ok(Some(false)), 2 => Ok(Some(true)), _ => Err(SensitiveDisplayError::InvalidOption) }
}
fn bool_option(value: Option<bool>) -> message_proto::option_message::BoolOption {
    use message_proto::option_message::BoolOption;
    match value { None => BoolOption::NotSet, Some(false) => BoolOption::No, Some(true) => BoolOption::Yes }
}
fn valid_key(key: &str) -> bool { key.len() <= MAX_IMPL_KEY_BYTES && !key.chars().any(char::is_control) }
impl Envelope {
    /// Construct the isolated source OptionMessage without applying it. Legacy
    /// privacy is only used by older RustDesk peers; block-input and session
    /// locking require separate local policy and cleanup on the receiver.
    pub fn sensitive_options_event(value: SensitiveOptions) -> Self {
        let mut option = message_proto::OptionMessage::new();
        option.privacy_mode = bool_option(value.legacy_privacy).into();
        option.block_input = bool_option(value.block_input).into();
        option.lock_after_session_end = bool_option(value.lock_after_session).into();
        let mut misc = message_proto::Misc::new(); misc.set_option(option);
        let mut message = message_proto::Message::new(); message.set_misc(misc); Self { inner: message }
    }
    /// Inspect these three fields in login or standalone source options. Other
    /// fields are intentionally left untouched. Invalid enum values fail closed.
    pub fn sensitive_options(&self) -> Result<SensitiveOptions, SensitiveDisplayError> {
        let option = match self.inner.union.as_ref() {
            Some(message::Union::LoginRequest(login)) => login.option.as_ref(),
            Some(message::Union::Misc(misc)) => match misc.union.as_ref() { Some(message_proto::misc::Union::Option(option)) => Some(option), _ => None },
            _ => None,
        }.ok_or(SensitiveDisplayError::Unexpected)?;
        Ok(SensitiveOptions { legacy_privacy: option_value(option.privacy_mode.value())?, block_input: option_value(option.block_input.value())?, lock_after_session: option_value(option.lock_after_session_end.value())? })
    }
    /// Construct an existing source wire request. Empty key is preserved because
    /// source callers use it. The receiving peer may actually change its OS.
    pub fn privacy_request_event(key: &str, on: bool) -> Result<Self, SensitiveDisplayError> {
        if !valid_key(key) { return Err(SensitiveDisplayError::InvalidImplementationKey); }
        let mut misc = message_proto::Misc::new();
        misc.set_toggle_privacy_mode(message_proto::TogglePrivacyMode { impl_key: key.to_owned(), on, ..Default::default() });
        let mut message = message_proto::Message::new(); message.set_misc(misc); Ok(Self { inner: message })
    }
    /// Read only bounded, untrusted request fields; no policy is applied.
    pub fn privacy_request(&self) -> Result<PrivacyRequest, SensitiveDisplayError> {
        let request = match self.inner.union.as_ref() {
            Some(message::Union::Misc(misc)) => match misc.union.as_ref() {
                Some(message_proto::misc::Union::TogglePrivacyMode(value)) => value,
                _ => return Err(SensitiveDisplayError::Unexpected),
            }, _ => return Err(SensitiveDisplayError::Unexpected),
        };
        if !valid_key(&request.impl_key) { return Err(SensitiveDisplayError::InvalidImplementationKey); }
        Ok(PrivacyRequest { impl_key: request.impl_key.clone(), on: request.on })
    }
    /// Build a known source back-notification state. This is a peer claim, not
    /// proof of privacy. Reject unknown enum numbers when constructing; reading
    /// retains them. Details can be untrusted text and must never be logged raw.
    pub fn sensitive_display_notice_event(notice: &DisplayNotice) -> Result<Self, SensitiveDisplayError> {
        if !valid_key(&notice.impl_key) || notice.details.len() > 4096 { return Err(SensitiveDisplayError::InvalidNotice); }
        let mut back = message_proto::BackNotification { details: notice.details.clone(), impl_key: notice.impl_key.clone(), ..Default::default() };
        match notice.kind {
            DisplayNoticeKind::Privacy(value) => back.set_privacy_mode_state(message_proto::back_notification::PrivacyModeState::from_i32(value).ok_or(SensitiveDisplayError::InvalidNotice)?),
            DisplayNoticeKind::BlockInput(value) => back.set_block_input_state(message_proto::back_notification::BlockInputState::from_i32(value).ok_or(SensitiveDisplayError::InvalidNotice)?),
        }
        let mut misc = message_proto::Misc::new(); misc.set_back_notification(back);
        let mut message = message_proto::Message::new(); message.set_misc(misc); Ok(Self { inner: message })
    }
    /// Inspect a bounded back-notification without applying it. No returned
    /// field is an authenticated fact or authorization to change local state.
    pub fn sensitive_display_notice(&self) -> Result<DisplayNotice, SensitiveDisplayError> {
        let back = match self.inner.union.as_ref() {
            Some(message::Union::Misc(misc)) => match misc.union.as_ref() {
                Some(message_proto::misc::Union::BackNotification(value)) => value,
                _ => return Err(SensitiveDisplayError::Unexpected),
            }, _ => return Err(SensitiveDisplayError::Unexpected),
        };
        if !valid_key(&back.impl_key) || back.details.len() > 4096 { return Err(SensitiveDisplayError::InvalidNotice); }
        let kind = match back.union.as_ref() {
            Some(message_proto::back_notification::Union::PrivacyModeState(value)) => DisplayNoticeKind::Privacy(value.value()),
            Some(message_proto::back_notification::Union::BlockInputState(value)) => DisplayNoticeKind::BlockInput(value.value()),
            _ => return Err(SensitiveDisplayError::Unexpected),
        };
        Ok(DisplayNotice { kind, details: back.details.clone(), impl_key: back.impl_key.clone() })
    }
    /// Construct the original virtual-display request without asserting that the
    /// raw index is valid; do not expose this to a peer without local policy.
    pub fn virtual_display_request_event(request: VirtualDisplayRequest) -> Self {
        let mut misc = message_proto::Misc::new();
        misc.set_toggle_virtual_display(message_proto::ToggleVirtualDisplay { display: request.display, on: request.on, ..Default::default() });
        let mut message = message_proto::Message::new(); message.set_misc(misc); Self { inner: message }
    }
    /// Preserve the original signed index for later platform-specific review.
    pub fn virtual_display_request(&self) -> Result<VirtualDisplayRequest, SensitiveDisplayError> {
        let request = match self.inner.union.as_ref() {
            Some(message::Union::Misc(misc)) => match misc.union.as_ref() {
                Some(message_proto::misc::Union::ToggleVirtualDisplay(value)) => value,
                _ => return Err(SensitiveDisplayError::Unexpected),
            }, _ => return Err(SensitiveDisplayError::Unexpected),
        };
        Ok(VirtualDisplayRequest { display: request.display, on: request.on })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip_without_executing_display_operations() {
        let options = SensitiveOptions { legacy_privacy: None, block_input: Some(true), lock_after_session: Some(false) };
        let wire = Envelope::sensitive_options_event(options).encode(4096).unwrap();
        assert_eq!(Envelope::decode(&wire, 4096).unwrap().sensitive_options().unwrap(), options);
        assert_eq!(option_value(3), Err(SensitiveDisplayError::InvalidOption));
        for key in ["", "magnifier"] {
            let msg = Envelope::privacy_request_event(key, true).unwrap();
            let wire = msg.encode(4096).unwrap(); let decoded = Envelope::decode(&wire, 4096).unwrap();
            assert_eq!(decoded.privacy_request().unwrap(), PrivacyRequest { impl_key: key.into(), on: true });
            assert!(matches!(decoded.virtual_display_request(), Err(SensitiveDisplayError::Unexpected)));
        }
        for request in [VirtualDisplayRequest { display: -1, on: false }, VirtualDisplayRequest { display: i32::MAX, on: true }] {
            let wire = Envelope::virtual_display_request_event(request).encode(4096).unwrap();
            assert_eq!(Envelope::decode(&wire, 4096).unwrap().virtual_display_request().unwrap(), request);
        }
        assert!(Envelope::privacy_request_event("bad\nkey", true).is_err());
        assert!(Envelope::privacy_request_event(&"x".repeat(257), true).is_err());
        for kind in [DisplayNoticeKind::Privacy(4), DisplayNoticeKind::BlockInput(2)] {
            let notice = DisplayNotice { kind, details: "diagnostic".into(), impl_key: "".into() };
            let wire = Envelope::sensitive_display_notice_event(&notice).unwrap().encode(4096).unwrap();
            assert_eq!(Envelope::decode(&wire, 4096).unwrap().sensitive_display_notice().unwrap(), notice);
            assert!(!format!("{:?}", notice).contains("diagnostic"));
        }
        assert!(Envelope::sensitive_display_notice_event(&DisplayNotice { kind: DisplayNoticeKind::Privacy(999), details: String::new(), impl_key: String::new() }).is_err());
        assert!(!format!("{:?}", PrivacyRequest { impl_key: "secret-key".into(), on: true }).contains("secret-key"));
    }
}
