//! Bounded, caller-driven adapter around the pinned RustDesk video QoS logic.
//!
//! This adapter has no timers, network probes, scheduler, frame ACK handling or
//! encoder ownership. Input observations and peer/display IDs must be supplied
//! by a trusted embedding session manager; remote values must not be treated as
//! verified network measurements. The source algorithm was copied from
//! `src/server/video_qos.rs` at the recorded baseline and adjusted only as
//! described in the extraction report. It has not been built or tested.

use crate::source_video_qos::VideoQoS;
use std::{collections::HashSet, error::Error, fmt, time::Duration};

/// Limit the per-instance state held by the source algorithm.
pub const MAX_PEERS: usize = 64;
pub const MAX_DISPLAYS: usize = 32;
/// Bounds avoid arithmetic overflow inside the original delay history logic.
pub const MAX_DELAY_MS: u32 = 60_000;
/// Largest accepted reported bitrate (kilobits/second); not a bandwidth cap.
pub const MAX_BITRATE_KBPS: u32 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QosError { InvalidPeer, DuplicatePeer, PeerLimit, InvalidDisplay, DuplicateDisplay, DisplayLimit, InvalidMeasurement, InvalidFps }
impl fmt::Display for QosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "video QoS: {self:?}") }
}
impl Error for QosError {}

/// A snapshot of source recommendations, not proof that they were applied.
#[derive(Debug, Clone, Copy)]
pub struct Recommendation {
    pub fps: u32,
    pub frame_interval: Duration,
    /// Source bitrate ratio. Some source ratios exceed the current prototype
    /// software encoder's accepted range; callers must check compatibility.
    pub quality_ratio: f32,
    pub bitrate_kbps: u32,
    pub variable_bitrate_active: bool,
}

/// Independent QoS state for one cooperating group of source video services.
/// It has no process-global registration. Do not mix its IDs across unrelated
/// sessions or treat it as the original global server's full orchestration.
pub struct SourceVideoQos {
    qos: VideoQoS,
    peers: HashSet<i32>,
    displays: HashSet<u32>,
}
impl SourceVideoQos {
    /// `adaptive_bitrate` explicitly replaces the source global config lookup.
    pub fn new(adaptive_bitrate: bool) -> Self {
        let mut qos = VideoQoS::default();
        qos.set_abr_config(adaptive_bitrate);
        Self { qos, peers: HashSet::new(), displays: HashSet::new() }
    }
    fn name(display: u32) -> String { format!("display:{display}") }
    fn has_peer(&self, id: i32) -> Result<(), QosError> {
        if self.peers.contains(&id) { Ok(()) } else { Err(QosError::InvalidPeer) }
    }
    fn has_display(&self, id: u32) -> Result<(), QosError> {
        if self.displays.contains(&id) { Ok(()) } else { Err(QosError::InvalidDisplay) }
    }
    /// Register a unique, locally allocated positive connection ID.
    pub fn add_peer(&mut self, id: i32) -> Result<(), QosError> {
        if id <= 0 { return Err(QosError::InvalidPeer); }
        if self.peers.contains(&id) { return Err(QosError::DuplicatePeer); }
        if self.peers.len() >= MAX_PEERS { return Err(QosError::PeerLimit); }
        self.peers.insert(id); self.qos.on_connection_open(id); Ok(())
    }
    /// Remove a connection and its adaptation state.
    pub fn remove_peer(&mut self, id: i32) -> Result<(), QosError> {
        self.has_peer(id)?; self.peers.remove(&id); self.qos.on_connection_close(id);
        // Source resets all state after the final connection departs, including
        // display registrations. Keep the wrapper and underlying maps aligned.
        if self.peers.is_empty() { self.displays.clear(); }
        Ok(())
    }
    /// Register a local display index. Index identity and hotplug are caller-owned.
    pub fn add_display(&mut self, id: u32, quality_change_supported: bool) -> Result<(), QosError> {
        if self.displays.contains(&id) { return Err(QosError::DuplicateDisplay); }
        if self.displays.len() >= MAX_DISPLAYS { return Err(QosError::DisplayLimit); }
        let name = Self::name(id); self.qos.new_display(name.clone());
        self.qos.set_support_changing_quality(&name, quality_change_supported);
        self.displays.insert(id); Ok(())
    }
    pub fn remove_display(&mut self, id: u32) -> Result<(), QosError> {
        self.has_display(id)?; self.displays.remove(&id); self.qos.remove_display(&Self::name(id)); Ok(())
    }
    /// Apply the source's 1..=120 viewer FPS cap; adjustment occurs on a later
    /// source update, not necessarily synchronously with this call.
    pub fn set_peer_fps(&mut self, id: i32, fps: u32) -> Result<(), QosError> {
        self.has_peer(id)?;
        if !(1..=120).contains(&fps) { return Err(QosError::InvalidFps); }
        self.qos.user_custom_fps(id, fps); Ok(())
    }
    /// Pass the existing source ImageQuality enum/custom packed value.
    pub fn set_peer_image_quality(&mut self, id: i32, source_value: i32) -> Result<(), QosError> {
        self.has_peer(id)?; self.qos.user_image_quality(id, source_value); Ok(())
    }
    /// Feed a locally matched probe round trip, in milliseconds. A peer can
    /// influence observations; the caller must correlate probes and rate-limit.
    pub fn on_delay_reply(&mut self, id: i32, delay_ms: u32) -> Result<(), QosError> {
        self.has_peer(id)?;
        if delay_ms > MAX_DELAY_MS { return Err(QosError::InvalidMeasurement); }
        self.qos.user_network_delay(id, delay_ms); Ok(())
    }
    /// Feed elapsed time for an outstanding locally tracked probe. Repeated
    /// calls must follow the source scheduler's cadence; this type has no timer.
    pub fn on_probe_elapsed(&mut self, id: i32, elapsed: Duration) -> Result<(), QosError> {
        self.has_peer(id)?;
        if elapsed > Duration::from_millis(MAX_DELAY_MS as u64) { return Err(QosError::InvalidMeasurement); }
        self.qos.user_delay_response_elapsed(id, elapsed.as_millis()); Ok(())
    }
    pub fn set_encoder_bitrate(&mut self, kbps: u32) -> Result<(), QosError> {
        if kbps > MAX_BITRATE_KBPS { return Err(QosError::InvalidMeasurement); }
        self.qos.store_bitrate(kbps); Ok(())
    }
    /// Run the source display update with one frame count. Call even with no
    /// frame at the source's scheduling cadence to permit timeout adaptation.
    pub fn update_display(&mut self, id: u32, frame_encoded: bool) -> Result<(), QosError> {
        self.has_display(id)?;
        self.qos.update_display_data(&Self::name(id), if frame_encoded { 1 } else { 0 }); Ok(())
    }
    pub fn recommendation(&mut self) -> Recommendation {
        Recommendation { fps: self.qos.fps(), frame_interval: self.qos.spf(), quality_ratio: self.qos.ratio(),
            bitrate_kbps: self.qos.bitrate(), variable_bitrate_active: self.qos.in_vbr_state() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_registration_and_measurements() {
        let mut q = SourceVideoQos::new(false);
        assert_eq!(q.add_peer(0), Err(QosError::InvalidPeer));
        q.add_peer(1).unwrap();
        assert_eq!(q.add_peer(1), Err(QosError::DuplicatePeer));
        q.add_display(0, true).unwrap();
        assert_eq!(q.add_display(0, true), Err(QosError::DuplicateDisplay));
        assert_eq!(q.set_peer_fps(1, 121), Err(QosError::InvalidFps));
        assert_eq!(q.on_delay_reply(1, u32::MAX), Err(QosError::InvalidMeasurement));
        assert_eq!(q.on_probe_elapsed(1, Duration::from_secs(61)), Err(QosError::InvalidMeasurement));
        q.set_peer_fps(1, 10).unwrap(); q.on_delay_reply(1, 20).unwrap();
        q.update_display(0, true).unwrap();
        assert!((1..=10).contains(&q.recommendation().fps));
        assert!(!q.recommendation().variable_bitrate_active);
        q.remove_peer(1).unwrap();
        assert_eq!(q.update_display(0, false), Err(QosError::InvalidDisplay));
    }
}
