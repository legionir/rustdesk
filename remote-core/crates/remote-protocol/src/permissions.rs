//! RustDesk's existing `Misc::PermissionInfo` wire notification.
//! Values are untrusted claims and do not authorize local operations.
use crate::{message, message_proto, Envelope, ProtocolError};

/// An untrusted raw source permission enum value and its announced state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionNotice { pub permission: i32, pub enabled: bool }
/// `PermissionInfo::Keyboard` covers source keyboard *and* mouse access.
pub const SOURCE_KEYBOARD_PERMISSION: i32 = 0;

impl Envelope {
    /// Inspect a source permission notification without mapping unknown values.
    pub fn permission_notice(&self) -> Result<PermissionNotice, ProtocolError> {
        match self.inner.union.as_ref() {
            Some(message::Union::Misc(m)) => match m.union.as_ref() {
                Some(message_proto::misc::Union::PermissionInfo(p)) => Ok(PermissionNotice { permission: p.permission.value(), enabled: p.enabled }),
                _ => Err(ProtocolError::UnexpectedMessage),
            },
            _ => Err(ProtocolError::UnexpectedMessage),
        }
    }
    /// Construct only the existing source keyboard/mouse permission notice.
    /// This does not change local session authorization.
    pub fn source_keyboard_permission(enabled: bool) -> Self {
        let info = message_proto::PermissionInfo { permission: message_proto::permission_info::Permission::Keyboard.into(), enabled, ..Default::default() };
        let mut misc = message_proto::Misc::new(); misc.set_permission_info(info);
        let mut inner = message_proto::Message::new(); inner.set_misc(misc); Self { inner }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keyboard_permission_uses_existing_source_envelope() {
        for enabled in [false, true] {
            let wire = Envelope::source_keyboard_permission(enabled).encode(128).unwrap();
            let parsed = Envelope::decode(&wire, 128).unwrap().permission_notice().unwrap();
            assert_eq!(parsed, PermissionNotice { permission: SOURCE_KEYBOARD_PERMISSION, enabled });
        }
        assert!(Envelope::source_keyboard_permission(true).video().is_err());
    }
}
