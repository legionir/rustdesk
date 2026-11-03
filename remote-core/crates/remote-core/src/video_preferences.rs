//! Optional bridge from untrusted wire preferences into caller-owned QoS state.
//!
//! The caller must separately check view authorization, associate a local peer
//! ID with the correct session and decide whether to honor the request. This
//! modifies only source QoS state; it does not update an encoder or scheduler.
use remote_codec::video_qos::{QosError, SourceVideoQos};
use remote_protocol::video_preferences::{PreferenceError, Quality, VideoPreferences};
use std::{error::Error, fmt};

#[derive(Debug)]
pub enum ApplyError { Invalid(PreferenceError), Qos(QosError) }
impl fmt::Display for ApplyError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { match self { Self::Invalid(e) => write!(f, "{e}"), Self::Qos(e) => write!(f, "{e}") } } }
impl Error for ApplyError {}
/// Explicitly apply bounded preferences for a registered, locally allocated
/// peer ID. Validate all supplied fields before changing either setting.
pub fn apply(qos: &mut SourceVideoQos, peer: i32, preferences: VideoPreferences) -> Result<(), ApplyError> {
    if matches!(preferences.quality, Some(Quality::Custom(n)) if n <= 0) { return Err(ApplyError::Invalid(PreferenceError::InvalidQuality)); }
    if preferences.fps.map_or(false, |fps| !(1..=120).contains(&fps)) { return Err(ApplyError::Invalid(PreferenceError::InvalidFps)); }
    qos.require_peer(peer).map_err(ApplyError::Qos)?;
    if let Some(fps) = preferences.fps { qos.set_peer_fps(peer, fps).map_err(ApplyError::Qos)?; }
    if let Some(quality) = preferences.quality { qos.set_peer_image_quality(peer, quality.source_value()).map_err(ApplyError::Qos)?; }
    Ok(())
}

/// Explicitly apply only source QoS-related controls to a registered peer.
/// Recording is an untrusted claim; this does not start or stop recording.
/// Refresh and frame ACK controls are not consumed here and return false.
pub fn apply_control(qos: &mut SourceVideoQos, peer: i32, control: remote_protocol::video_control::VideoControl) -> Result<bool, ApplyError> {
    use remote_protocol::video_control::VideoControl;
    qos.require_peer(peer).map_err(ApplyError::Qos)?;
    match control {
        VideoControl::AutoAdjustFps(fps) => qos.set_peer_auto_fps(peer, fps).map_err(ApplyError::Qos)?,
        VideoControl::ClientRecording(active) => qos.set_peer_recording_claim(peer, active).map_err(ApplyError::Qos)?,
        _ => return Ok(false),
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn require_registered_peer_and_validate_before_mutation() {
        let mut qos = SourceVideoQos::new(false);
        let empty = VideoPreferences::default();
        assert!(matches!(apply(&mut qos, 1, empty), Err(ApplyError::Qos(QosError::InvalidPeer))));
        qos.add_peer(1).unwrap();
        assert!(apply(&mut qos, 1, empty).is_ok());
        assert!(matches!(apply(&mut qos, 1, VideoPreferences { quality: Some(Quality::Best), fps: Some(121) }), Err(ApplyError::Invalid(PreferenceError::InvalidFps))));
        assert!(matches!(apply(&mut qos, 1, VideoPreferences { quality: Some(Quality::Custom(-1)), fps: Some(30) }), Err(ApplyError::Invalid(PreferenceError::InvalidQuality))));
        assert!(apply(&mut qos, 1, VideoPreferences { quality: Some(Quality::Low), fps: Some(30) }).is_ok());
        qos.remove_peer(1).unwrap();
        assert!(matches!(apply(&mut qos, 1, empty), Err(ApplyError::Qos(QosError::InvalidPeer))));
    }
}
