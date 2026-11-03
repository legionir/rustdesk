//! Bounded source supported/original resolution metadata in login PeerInfo and
//! Misc.SwitchDisplay. These values are untrusted claims, not a mode probe,
//! permission grant, OS change or proof of a stable display identity.
use crate::{message, message_proto, Envelope};
use hbb_common::protobuf::MessageField;
use std::{error::Error, fmt};

/// Local bound, not a source protocol guarantee.
pub const MAX_RESOLUTION_ENTRIES: usize = 512;
const MAX_DIMENSION: i32 = 32768;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolution { pub width: i32, pub height: i32 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionMetadataError { UnexpectedMessage, Invalid }
impl fmt::Display for ResolutionMetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "resolution metadata: {self:?}") }
}
impl Error for ResolutionMetadataError {}
fn valid_mode(v: Resolution) -> bool { (1..=MAX_DIMENSION).contains(&v.width) && (1..=MAX_DIMENSION).contains(&v.height) }
fn valid_original(v: Resolution) -> bool { (v.width == 0 && v.height == 0) || valid_mode(v) }
fn modes_field(e: &Envelope) -> Result<&MessageField<message_proto::SupportedResolutions>, ResolutionMetadataError> {
    match e.inner.union.as_ref() {
        Some(message::Union::PeerInfo(p)) => Ok(&p.resolutions),
        Some(message::Union::LoginResponse(r)) => match r.union.as_ref() {
            Some(message_proto::login_response::Union::PeerInfo(p)) => Ok(&p.resolutions),
            _ => Err(ResolutionMetadataError::UnexpectedMessage),
        },
        Some(message::Union::Misc(m)) => match m.union.as_ref() {
            Some(message_proto::misc::Union::SwitchDisplay(s)) => Ok(&s.resolutions),
            _ => Err(ResolutionMetadataError::UnexpectedMessage),
        },
        _ => Err(ResolutionMetadataError::UnexpectedMessage),
    }
}
fn modes_field_mut(e: &mut Envelope) -> Result<&mut MessageField<message_proto::SupportedResolutions>, ResolutionMetadataError> {
    match e.inner.union.as_mut() {
        Some(message::Union::PeerInfo(p)) => Ok(&mut p.resolutions),
        Some(message::Union::LoginResponse(r)) => match r.union.as_mut() {
            Some(message_proto::login_response::Union::PeerInfo(p)) => Ok(&mut p.resolutions),
            _ => Err(ResolutionMetadataError::UnexpectedMessage),
        },
        Some(message::Union::Misc(m)) => match m.union.as_mut() {
            Some(message_proto::misc::Union::SwitchDisplay(s)) => Ok(&mut s.resolutions),
            _ => Err(ResolutionMetadataError::UnexpectedMessage),
        },
        _ => Err(ResolutionMetadataError::UnexpectedMessage),
    }
}
impl Envelope {
    /// Preserve absent vs present-empty lists. PeerInfo values concern its
    /// current display; SwitchDisplay values concern the indicated display.
    pub fn supported_resolutions(&self) -> Result<Option<Vec<Resolution>>, ResolutionMetadataError> {
        let Some(list) = modes_field(self)?.as_ref() else { return Ok(None); };
        if list.resolutions.len() > MAX_RESOLUTION_ENTRIES { return Err(ResolutionMetadataError::Invalid); }
        let mut values = Vec::with_capacity(list.resolutions.len());
        for entry in &list.resolutions {
            let v = Resolution { width: entry.width, height: entry.height };
            if !valid_mode(v) { return Err(ResolutionMetadataError::Invalid); }
            values.push(v);
        }
        Ok(Some(values))
    }
    /// Attach caller-supplied, consented supported-mode claims, transactionally.
    /// This does not enumerate modes or verify OS support. Unrelated fields of
    /// the outer envelope are retained, but this setter replaces this field.
    pub fn set_supported_resolutions(&mut self, values: Option<&[Resolution]>) -> Result<(), ResolutionMetadataError> {
        if let Some(values) = values {
            if values.len() > MAX_RESOLUTION_ENTRIES || values.iter().any(|v| !valid_mode(*v)) { return Err(ResolutionMetadataError::Invalid); }
        }
        let field = modes_field_mut(self)?;
        *field = values.map(|values| message_proto::SupportedResolutions {
            resolutions: values.iter().map(|v| message_proto::Resolution { width: v.width, height: v.height, ..Default::default() }).collect(),
            ..Default::default()
        }).into();
        Ok(())
    }
    /// Read a SwitchDisplay original-resolution claim. Zero by zero is a
    /// source virtual-display sentinel; other values must be positive pairs.
    pub fn switch_original_resolution(&self) -> Result<Option<Resolution>, ResolutionMetadataError> {
        let Some(message::Union::Misc(m)) = self.inner.union.as_ref() else { return Err(ResolutionMetadataError::UnexpectedMessage); };
        let Some(message_proto::misc::Union::SwitchDisplay(s)) = m.union.as_ref() else { return Err(ResolutionMetadataError::UnexpectedMessage); };
        let value = s.original_resolution.as_ref().map(|r| Resolution { width: r.width, height: r.height });
        if value.map_or(false, |v| !valid_original(v)) { return Err(ResolutionMetadataError::Invalid); }
        Ok(value)
    }
    /// Set only SwitchDisplay's optional original-resolution field; never
    /// changes a local or remote display mode.
    pub fn set_switch_original_resolution(&mut self, value: Option<Resolution>) -> Result<(), ResolutionMetadataError> {
        if value.map_or(false, |v| !valid_original(v)) { return Err(ResolutionMetadataError::Invalid); }
        let Some(message::Union::Misc(m)) = self.inner.union.as_mut() else { return Err(ResolutionMetadataError::UnexpectedMessage); };
        let Some(message_proto::misc::Union::SwitchDisplay(s)) = m.union.as_mut() else { return Err(ResolutionMetadataError::UnexpectedMessage); };
        s.original_resolution = value.map(|v| message_proto::Resolution { width: v.width, height: v.height, ..Default::default() }).into();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display_control::DisplaySwitch;
    #[test]
    fn peer_info_mode_bounds_and_absence_are_preserved() {
        use crate::desktop::PeerInfo;
        let peer = PeerInfo { username: String::new(), hostname: String::new(), platform: String::new(), version: String::new(),
            displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
        let mut login = Envelope::desktop_login_success(&peer).unwrap();
        let mode = Resolution { width: 1920, height: 1080 };
        assert_eq!(login.supported_resolutions().unwrap(), None);
        login.set_supported_resolutions(Some(&[mode])).unwrap();
        assert!(login.set_supported_resolutions(Some(&vec![mode; MAX_RESOLUTION_ENTRIES + 1])).is_err());
        let parsed = Envelope::decode(&login.encode(8192).unwrap(), 8192).unwrap();
        assert_eq!(parsed.supported_resolutions().unwrap(), Some(vec![mode]));
        assert_eq!(parsed.desktop_login_result().unwrap(), crate::desktop::LoginResult::Accepted(peer));
        assert!(parsed.switch_original_resolution().is_err());
        let err = Envelope::desktop_login_error("denied").unwrap();
        assert!(err.supported_resolutions().is_err());
    }
    #[test]
    fn switch_metadata_round_trip_and_rejection_are_transactional() {
        let mut msg = Envelope::display_switch_event(&DisplaySwitch { display: 0, x: -10, y: 0, width: 1280, height: 720, cursor_embedded: false }).unwrap();
        assert_eq!(msg.supported_resolutions().unwrap(), None);
        let modes = [Resolution { width: 1280, height: 720 }, Resolution { width: 1920, height: 1080 }];
        msg.set_supported_resolutions(Some(&modes)).unwrap();
        msg.set_switch_original_resolution(Some(modes[1])).unwrap();
        assert_eq!(msg.set_supported_resolutions(Some(&[Resolution { width: 0, height: 1 }])), Err(ResolutionMetadataError::Invalid));
        assert_eq!(msg.set_switch_original_resolution(Some(Resolution { width: 0, height: 2 })), Err(ResolutionMetadataError::Invalid));
        let decoded = Envelope::decode(&msg.encode(8192).unwrap(), 8192).unwrap();
        assert_eq!(decoded.supported_resolutions().unwrap(), Some(modes.to_vec()));
        assert_eq!(decoded.switch_original_resolution().unwrap(), Some(modes[1]));
        msg.set_supported_resolutions(Some(&[])).unwrap(); assert_eq!(msg.supported_resolutions().unwrap(), Some(vec![]));
        msg.set_supported_resolutions(None).unwrap(); assert_eq!(msg.supported_resolutions().unwrap(), None);
    }
}
