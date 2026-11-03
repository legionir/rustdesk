//! Existing source PeerInfo feature flags and opaque platform additions.
//! These are untrusted claims, never a capability probe or permission grant.
//! Terminal and forwarding remain outside this prototype's initial scope.
use super::{desktop::{peer_mut, peer_ref}, message_proto, Envelope};
use std::{error::Error, fmt};

/// Local bound on the UTF-8 wire string, not an upstream schema limit.
pub const MAX_ADDITIONS_BYTES: usize = 16 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureClaims { pub privacy_mode: bool, pub terminal: bool, pub port_forward_mux: bool }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformMetadataError { UnexpectedMessage, AdditionsTooLarge }
impl fmt::Display for PlatformMetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::UnexpectedMessage => f.write_str("not peer metadata"), Self::AdditionsTooLarge => f.write_str("platform additions exceed local bound") }
    }
}
impl Error for PlatformMetadataError {}
impl Envelope {
    /// The optional source Features submessage; presence is not authorization.
    pub fn feature_claims(&self) -> Result<Option<FeatureClaims>, PlatformMetadataError> {
        let peer = peer_ref(self).map_err(|_| PlatformMetadataError::UnexpectedMessage)?;
        Ok(peer.features.as_ref().map(|f| FeatureClaims { privacy_mode: f.privacy_mode, terminal: f.terminal, port_forward_mux: f.port_forward_mux }))
    }
    /// Replace caller-approved claims. This does not enable the named features.
    /// Unknown fields within the replaced submessage are not preserved.
    pub fn set_feature_claims(&mut self, value: Option<FeatureClaims>) -> Result<(), PlatformMetadataError> {
        let peer = peer_mut(self).map_err(|_| PlatformMetadataError::UnexpectedMessage)?;
        peer.features = value.map(|v| message_proto::Features { privacy_mode: v.privacy_mode, terminal: v.terminal,
            port_forward_mux: v.port_forward_mux, ..Default::default() }).into();
        Ok(())
    }
    /// Return a bounded opaque string. Source convention is a JSON object, but
    /// this method neither parses JSON nor verifies its schema; empty is the
    /// protobuf default. Never trust it for security or execute its contents.
    pub fn platform_additions(&self) -> Result<&str, PlatformMetadataError> {
        let peer = peer_ref(self).map_err(|_| PlatformMetadataError::UnexpectedMessage)?;
        if peer.platform_additions.len() > MAX_ADDITIONS_BYTES { return Err(PlatformMetadataError::AdditionsTooLarge); }
        Ok(&peer.platform_additions)
    }
    /// Set a bounded opaque source field. Caller must ensure JSON compatibility,
    /// consent and correct escaping, and avoid leaking sensitive OS details.
    pub fn set_platform_additions(&mut self, value: &str) -> Result<(), PlatformMetadataError> {
        if value.len() > MAX_ADDITIONS_BYTES { return Err(PlatformMetadataError::AdditionsTooLarge); }
        let peer = peer_mut(self).map_err(|_| PlatformMetadataError::UnexpectedMessage)?;
        peer.platform_additions = value.to_owned();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop::PeerInfo;
    #[test]
    fn preserves_unrelated_metadata_and_bounds_opaque_additions() {
        let peer = PeerInfo { username: "test".into(), hostname: "host".into(), platform: "Windows".into(), version: "v".into(),
            displays: vec![], current_display: 0, sas_enabled: false, encoding: None };
        let mut envelope = Envelope::desktop_login_success(&peer).unwrap();
        assert_eq!(envelope.feature_claims().unwrap(), None);
        assert_eq!(envelope.platform_additions().unwrap(), "");
        let features = FeatureClaims { privacy_mode: true, terminal: false, port_forward_mux: false };
        envelope.set_feature_claims(Some(features)).unwrap();
        envelope.set_platform_additions(r#"{"is_installed":true}"#).unwrap();
        let wire = envelope.encode(65536).unwrap();
        let mut decoded = Envelope::decode(&wire, 65536).unwrap();
        assert_eq!(decoded.feature_claims().unwrap(), Some(features));
        assert_eq!(decoded.platform_additions().unwrap(), r#"{"is_installed":true}"#);
        assert!(decoded.set_platform_additions(&"x".repeat(MAX_ADDITIONS_BYTES + 1)).is_err());
        assert_eq!(decoded.platform_additions().unwrap(), r#"{"is_installed":true}"#);
        assert_eq!(decoded.desktop_login_result().unwrap(), crate::desktop::LoginResult::Accepted(peer));
        decoded.set_feature_claims(None).unwrap();
        assert_eq!(decoded.feature_claims().unwrap(), None);
    }
}
