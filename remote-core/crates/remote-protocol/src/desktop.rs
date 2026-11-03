//! RustDesk's existing desktop login response and display metadata.
//!
//! This is a bounded subset of the source schema, not a new protocol. Incoming
//! peer labels, display geometry, flags and login results are untrusted claims.
//! Re-encoding a full envelope through `Envelope` preserves omitted fields;
//! constructing a fresh response from this subset intentionally leaves source
//! features, resolutions, OS-session metadata and trusted-device fields unset.
use super::{message, message_proto, Envelope};
use std::{error::Error, fmt};

/// Maximum displays exposed by this adapter, not an upstream wire limit.
pub const MAX_DISPLAYS: usize = 64;
/// Maximum width/height accepted by this adapter; not an allocation guarantee.
pub const MAX_DISPLAY_DIMENSION: i32 = 32768;
/// One current display entry from RustDesk `PeerInfo`.
#[derive(Debug, Clone, PartialEq)]
pub struct DisplayInfo {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub name: String,
    pub online: bool,
    pub cursor_embedded: bool,
    /// `0.0` means unknown as in the source's default protobuf value.
    pub scale: f64,
}
/// Basic peer and display metadata. A claimed platform or user is not identity.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerInfo {
    pub username: String,
    pub hostname: String,
    pub platform: String,
    pub version: String,
    pub displays: Vec<DisplayInfo>,
    pub current_display: i32,
    pub sas_enabled: bool,
    /// Source SupportedEncoding flags, if supplied. No VP9 flag exists there.
    pub encoding: Option<super::EncodingCapabilities>,
}
/// A wire-level response; `Accepted` alone is not proof of host identity.
#[derive(Debug, Clone, PartialEq)]
pub enum LoginResult { Accepted(PeerInfo), Denied(String) }
/// Invalid metadata or unexpected message variant.
#[derive(Debug)]
pub enum DesktopError { UnexpectedMessage, InvalidMetadata }
impl fmt::Display for DesktopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::UnexpectedMessage => f.write_str("not a desktop login response"), Self::InvalidMetadata => f.write_str("invalid desktop metadata") }
    }
}
impl Error for DesktopError {}
fn valid_text(s: &str) -> bool { s.len() <= 256 && !s.chars().any(char::is_control) }
impl PeerInfo {
    /// Apply this adapter's resource/geometry bounds. Does not prove support,
    /// availability, authenticity or safe decoder behavior.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if [&self.username, &self.hostname, &self.platform, &self.version].into_iter().any(|s| !valid_text(s))
            || self.displays.len() > MAX_DISPLAYS || self.current_display < 0
            || (!self.displays.is_empty() && self.current_display as usize >= self.displays.len()) {
            return Err(DesktopError::InvalidMetadata);
        }
        for display in &self.displays {
            if !valid_text(&display.name) || !(1..=MAX_DISPLAY_DIMENSION).contains(&display.width)
                || !(1..=MAX_DISPLAY_DIMENSION).contains(&display.height)
                || !display.scale.is_finite() || !(0.0..=16.0).contains(&display.scale) {
                return Err(DesktopError::InvalidMetadata);
            }
        }
        Ok(())
    }
}
fn decode_peer(peer: &message_proto::PeerInfo) -> Result<PeerInfo, DesktopError> {
    if peer.displays.len() > MAX_DISPLAYS { return Err(DesktopError::InvalidMetadata); }
    let displays = peer.displays.iter().map(|d| DisplayInfo {
        x: d.x, y: d.y, width: d.width, height: d.height, name: d.name.clone(),
        online: d.online, cursor_embedded: d.cursor_embedded, scale: d.scale,
    }).collect();
    let encoding = peer.encoding.as_ref().map(|e| super::EncodingCapabilities {
        vp8: e.vp8, av1: e.av1, h264: e.h264, h265: e.h265,
        i444: e.i444.as_ref().map(|c| super::ChromaCapabilities { vp8: c.vp8, vp9: c.vp9, av1: c.av1, h264: c.h264, h265: c.h265 }),
    });
    let info = PeerInfo { username: peer.username.clone(), hostname: peer.hostname.clone(), platform: peer.platform.clone(),
        version: peer.version.clone(), displays, current_display: peer.current_display, sas_enabled: peer.sas_enabled, encoding };
    info.validate()?; Ok(info)
}
fn encode_peer(info: &PeerInfo) -> Result<message_proto::PeerInfo, DesktopError> {
    info.validate()?;
    let displays = info.displays.iter().map(|d| message_proto::DisplayInfo {
        x: d.x, y: d.y, width: d.width, height: d.height, name: d.name.clone(),
        online: d.online, cursor_embedded: d.cursor_embedded, scale: d.scale, ..Default::default()
    }).collect();
    let encoding = info.encoding.map(|e| message_proto::SupportedEncoding {
        vp8: e.vp8, av1: e.av1, h264: e.h264, h265: e.h265,
        i444: e.i444.map(|c| message_proto::CodecAbility { vp8: c.vp8, vp9: c.vp9, av1: c.av1, h264: c.h264, h265: c.h265, ..Default::default() }).into(),
        ..Default::default()
    }).into();
    Ok(message_proto::PeerInfo { username: info.username.clone(), hostname: info.hostname.clone(), platform: info.platform.clone(),
        version: info.version.clone(), displays, current_display: info.current_display, sas_enabled: info.sas_enabled,
        encoding, ..Default::default() })
}
/// Source display original-resolution claim. Zero by zero is used for
/// RustDesk virtual displays; absence and zero are distinct wire values. This
/// is untrusted metadata, not proof of a physical mode or permission to change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginalResolution { pub width: i32, pub height: i32 }
fn valid_original(value: OriginalResolution) -> bool {
    (value.width == 0 && value.height == 0) || ((1..=MAX_DISPLAY_DIMENSION).contains(&value.width) && (1..=MAX_DISPLAY_DIMENSION).contains(&value.height))
}
pub(crate) fn peer_ref(envelope: &Envelope) -> Result<&message_proto::PeerInfo, DesktopError> {
    match envelope.inner.union.as_ref() {
        Some(message::Union::PeerInfo(peer)) => Ok(peer),
        Some(message::Union::LoginResponse(response)) => match response.union.as_ref() {
            Some(message_proto::login_response::Union::PeerInfo(peer)) => Ok(peer),
            _ => Err(DesktopError::UnexpectedMessage),
        },
        _ => Err(DesktopError::UnexpectedMessage),
    }
}
pub(crate) fn peer_mut(envelope: &mut Envelope) -> Result<&mut message_proto::PeerInfo, DesktopError> {
    match envelope.inner.union.as_mut() {
        Some(message::Union::PeerInfo(peer)) => Ok(peer),
        Some(message::Union::LoginResponse(response)) => match response.union.as_mut() {
            Some(message_proto::login_response::Union::PeerInfo(peer)) => Ok(peer),
            _ => Err(DesktopError::UnexpectedMessage),
        },
        _ => Err(DesktopError::UnexpectedMessage),
    }
}
impl Envelope {
    /// Read bounded source `original_resolution` claims for each display from
    /// a login response or standalone PeerInfo. The complete original envelope
    /// retains other protobuf fields. A nonzero pair must have both dimensions.
    pub fn display_original_resolutions(&self) -> Result<Vec<Option<OriginalResolution>>, DesktopError> {
        let peer = peer_ref(self)?;
        if peer.displays.len() > MAX_DISPLAYS { return Err(DesktopError::InvalidMetadata); }
        peer.displays.iter().map(|display| {
            let value = display.original_resolution.as_ref().map(|r| OriginalResolution { width: r.width, height: r.height });
            if value.map_or(false, |v| !valid_original(v)) { return Err(DesktopError::InvalidMetadata); }
            Ok(value)
        }).collect()
    }
    /// Set original-resolution claims without rebuilding the peer info or
    /// dropping unrelated fields. Validate the entire list before mutating;
    /// the trusted caller supplies actual consented metadata. No OS changes.
    pub fn set_display_original_resolutions(&mut self, values: &[Option<OriginalResolution>]) -> Result<(), DesktopError> {
        let peer = peer_mut(self)?;
        if peer.displays.len() > MAX_DISPLAYS || values.len() != peer.displays.len()
            || values.iter().flatten().any(|v| !valid_original(*v)) { return Err(DesktopError::InvalidMetadata); }
        for (display, value) in peer.displays.iter_mut().zip(values) {
            display.original_resolution = value.map(|v| message_proto::Resolution { width: v.width, height: v.height, ..Default::default() }).into();
        }
        Ok(())
    }
    /// Inspect an existing login response. Metadata remains an untrusted claim.
    pub fn desktop_login_result(&self) -> Result<LoginResult, DesktopError> {
        let response = match self.inner.union.as_ref() { Some(message::Union::LoginResponse(response)) => response, _ => return Err(DesktopError::UnexpectedMessage) };
        match response.union.as_ref() {
            Some(message_proto::login_response::Union::PeerInfo(info)) => Ok(LoginResult::Accepted(decode_peer(info)?)),
            Some(message_proto::login_response::Union::Error(error)) if valid_text(error) => Ok(LoginResult::Denied(error.clone())),
            Some(message_proto::login_response::Union::Error(_)) => Err(DesktopError::InvalidMetadata),
            _ => Err(DesktopError::UnexpectedMessage),
        }
    }
    /// Inspect an existing standalone PeerInfo update.
    pub fn desktop_peer_info(&self) -> Result<PeerInfo, DesktopError> {
        match self.inner.union.as_ref() { Some(message::Union::PeerInfo(info)) => decode_peer(info), _ => Err(DesktopError::UnexpectedMessage) }
    }
    /// Construct an existing login success response; only use actual, approved
    /// display metadata and runtime-probed capability flags.
    pub fn desktop_login_success(info: &PeerInfo) -> Result<Self, DesktopError> {
        let mut response = message_proto::LoginResponse::new(); response.set_peer_info(encode_peer(info)?);
        let mut inner = message_proto::Message::new(); inner.set_login_response(response); Ok(Self { inner })
    }
    /// Construct a source login error without exposing internal diagnostics.
    pub fn desktop_login_error(error: &str) -> Result<Self, DesktopError> {
        if error.is_empty() || !valid_text(error) { return Err(DesktopError::InvalidMetadata); }
        let mut response = message_proto::LoginResponse::new(); response.set_error(error.to_owned());
        let mut inner = message_proto::Message::new(); inner.set_login_response(response); Ok(Self { inner })
    }
    /// Construct an existing standalone PeerInfo update from this subset.
    pub fn desktop_peer_info_event(info: &PeerInfo) -> Result<Self, DesktopError> {
        let mut inner = message_proto::Message::new(); inner.set_peer_info(encode_peer(info)?); Ok(Self { inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn info() -> PeerInfo { PeerInfo { username: "local-user".into(), hostname: "test".into(), platform: "Windows".into(),
        version: "test".into(), displays: vec![DisplayInfo { x: -1920, y: 0, width: 1920, height: 1080, name: "display".into(), online: true, cursor_embedded: false, scale: 1.0 }],
        current_display: 0, sas_enabled: false, encoding: None } }
    #[test]
    fn response_round_trip_and_error() {
        let original = info();
        let encoded = Envelope::desktop_login_success(&original).unwrap().encode(4096).unwrap();
        assert_eq!(Envelope::decode(&encoded, 4096).unwrap().desktop_login_result().unwrap(), LoginResult::Accepted(original));
        let denied = Envelope::desktop_login_error("denied").unwrap();
        assert_eq!(denied.desktop_login_result().unwrap(), LoginResult::Denied("denied".into()));
    }
    #[test]
    fn original_resolution_round_trip_and_atomic_rejection() {
        let peer = info(); let mut message = Envelope::desktop_login_success(&peer).unwrap();
        assert_eq!(message.display_original_resolutions().unwrap(), vec![None]);
        let original = OriginalResolution { width: 1920, height: 1080 };
        message.set_display_original_resolutions(&[Some(original)]).unwrap();
        assert!(message.set_display_original_resolutions(&[Some(OriginalResolution { width: 1, height: 0 })]).is_err());
        assert!(message.set_display_original_resolutions(&[]).is_err());
        let wire = message.encode(4096).unwrap(); let mut decoded = Envelope::decode(&wire, 4096).unwrap();
        assert_eq!(decoded.display_original_resolutions().unwrap(), vec![Some(original)]);
        assert_eq!(decoded.desktop_login_result().unwrap(), LoginResult::Accepted(peer));
        decoded.set_display_original_resolutions(&[Some(OriginalResolution { width: 0, height: 0 })]).unwrap();
        assert_eq!(decoded.display_original_resolutions().unwrap()[0].unwrap().width, 0);
        assert!(Envelope::desktop_login_error("denied").unwrap().display_original_resolutions().is_err());
    }
    #[test]
    fn validates_geometry_and_untrusted_strings() {
        let mut v = info(); v.displays[0].width = 0; assert!(v.validate().is_err());
        v = info(); v.displays[0].scale = f64::NAN; assert!(v.validate().is_err());
        v = info(); v.current_display = 1; assert!(v.validate().is_err());
        v = info(); v.hostname = "a\nb".into(); assert!(v.validate().is_err());
    }
}
