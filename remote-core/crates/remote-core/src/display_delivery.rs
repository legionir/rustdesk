//! Per-session, caller-driven subset of the source display-change notification.
//!
//! Inspired by `SyncDisplaysInfo::{check_changed,get_update_sync_displays}` in
//! `src/server/display_service.rs`. Unlike the source's process-global flag,
//! this book is per subscriber and commits only after a local send succeeds.
//! It covers only the bounded `desktop::DisplayInfo` fields, not source
//! original resolutions or platform additions. No sampling, timer, network,
//! consent, topology lock, capture restart, or decoder refresh happens here.

use remote_protocol::desktop::{DesktopError, DisplayInfo, PeerInfo, MAX_DISPLAYS};
use remote_session::SessionId;
use std::{error::Error, fmt};

#[derive(Debug)]
pub enum DisplayDeliveryError { InvalidSnapshot, Poisoned }
impl fmt::Display for DisplayDeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSnapshot => f.write_str("invalid display snapshot"),
            Self::Poisoned => f.write_str("display update outcome is unknown; close the session"),
        }
    }
}
impl Error for DisplayDeliveryError {}

/// State belongs to exactly one approved local session. Never reuse after a
/// reconnect or permission/desktop boundary. Snapshots and display names may
/// disclose private information and remain in memory until replaced or dropped.
/// Equality and successful send do not prove stable physical monitor identity,
/// freshness, peer receipt, rendering, or consent. The caller must enforce all
/// of these separately and rebuild capture/decoder state when needed.
pub struct DisplayDelivery {
    session: SessionId,
    latest: Option<PeerInfo>,
    sent: Option<PeerInfo>,
    poisoned: bool,
}
impl DisplayDelivery {
    pub fn new(session: SessionId) -> Self { Self { session, latest: None, sent: None, poisoned: false } }
    pub fn session_id(&self) -> SessionId { self.session }
    pub fn is_poisoned(&self) -> bool { self.poisoned }

    /// Replace the locally observed snapshot. Empty lists are allowed; the
    /// first observation always needs a notification. Validation happens
    /// before mutation or cloning unbounded caller-owned names. Observations
    /// coalesce, so a change that reverts before sending is not announced.
    pub fn observe(&mut self, displays: &[DisplayInfo]) -> Result<(), DisplayDeliveryError> {
        if self.poisoned { return Err(DisplayDeliveryError::Poisoned); }
        if displays.len() > MAX_DISPLAYS || displays.iter().any(|d| d.name.len() > 256) {
            return Err(DisplayDeliveryError::InvalidSnapshot);
        }
        let info = PeerInfo { username: String::new(), hostname: String::new(), platform: String::new(), version: String::new(),
            displays: displays.to_vec(), current_display: 0, sas_enabled: false, encoding: None };
        info.validate().map_err(|_: DesktopError| DisplayDeliveryError::InvalidSnapshot)?;
        self.latest = Some(info);
        Ok(())
    }
    /// Prepare a notification only if the observed subset differs from the
    /// last successful local send. Dropping an unresolved transaction poisons
    /// the book, including when an async send future is cancelled. Explicit
    /// `discard_before_send` is allowed only before *any* network I/O starts.
    /// Caller must recheck view permission, local consent and snapshot validity
    /// immediately before sending; a concurrent topology change can still race.
    pub fn prepare(&mut self) -> Result<Option<PendingDisplayUpdate<'_>>, DisplayDeliveryError> {
        if self.poisoned { return Err(DisplayDeliveryError::Poisoned); }
        if self.latest.is_none() || self.latest == self.sent { return Ok(None); }
        Ok(Some(PendingDisplayUpdate { book: self, finished: false }))
    }
}

/// A single borrowed send transaction. Local send success is not peer ACK.
/// This owns no transport; callers must close the connection on uncertain I/O.
pub struct PendingDisplayUpdate<'a> { book: &'a mut DisplayDelivery, finished: bool }
impl PendingDisplayUpdate<'_> {
    /// The source-style standalone `PeerInfo` subset to pass to the existing
    /// host send API. Its fields are untrusted metadata to a receiving peer.
    pub fn info(&self) -> &PeerInfo { self.book.latest.as_ref().expect("pending snapshot exists") }
    /// Only call after the complete send returned success. No receipt is proven.
    pub fn sent(mut self) { self.book.sent = self.book.latest.clone(); self.finished = true; }
    /// Call only if the caller guarantees no send or other I/O was initiated.
    pub fn discard_before_send(mut self) { self.finished = true; }
}
impl Drop for PendingDisplayUpdate<'_> {
    fn drop(&mut self) { if !self.finished { self.book.poisoned = true; } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_protocol::Envelope;
    fn id(n: u8) -> SessionId { SessionId::new([n; 16]).unwrap() }
    fn display(x: i32) -> DisplayInfo { DisplayInfo { x, y: 0, width: 1920, height: 1080, name: "screen".into(), online: true, cursor_embedded: false, scale: 1.0 } }
    #[test]
    fn first_empty_snapshot_then_coalesced_changes_and_source_wire() {
        let mut b = DisplayDelivery::new(id(1));
        assert!(b.prepare().unwrap().is_none());
        b.observe(&[]).unwrap();
        b.prepare().unwrap().unwrap().sent();
        assert!(b.prepare().unwrap().is_none());
        b.observe(&[display(0)]).unwrap();
        b.observe(&[display(20)]).unwrap();
        let p = b.prepare().unwrap().unwrap();
        let encoded = Envelope::desktop_peer_info_event(p.info()).unwrap().encode(4096).unwrap();
        let received = Envelope::decode(&encoded, 4096).unwrap().desktop_peer_info().unwrap();
        assert_eq!(received.displays, vec![display(20)]);
        assert_eq!(received.current_display, 0);
        p.sent();
        b.observe(&[display(0)]).unwrap();
        b.observe(&[display(20)]).unwrap();
        assert!(b.prepare().unwrap().is_none());
    }
    #[test]
    fn failed_validation_does_not_mutate_and_discard_is_explicit() {
        let mut b = DisplayDelivery::new(id(1)); b.observe(&[display(0)]).unwrap();
        let mut invalid = display(1); invalid.width = 0;
        assert!(matches!(b.observe(&[invalid]), Err(DisplayDeliveryError::InvalidSnapshot)));
        let p = b.prepare().unwrap().unwrap(); assert_eq!(p.info().displays[0].x, 0); p.discard_before_send();
        assert!(!b.is_poisoned()); b.prepare().unwrap().unwrap().sent();
        let mut oversized = display(1); oversized.name = "x".repeat(257);
        assert!(matches!(b.observe(&[oversized]), Err(DisplayDeliveryError::InvalidSnapshot)));
        assert!(b.prepare().unwrap().is_none());
    }
    #[test]
    fn unknown_outcome_poison_is_session_local_and_sticky() {
        let mut a = DisplayDelivery::new(id(1)); let mut b = DisplayDelivery::new(id(2));
        assert_ne!(a.session_id(), b.session_id());
        a.observe(&[display(0)]).unwrap(); b.observe(&[display(0)]).unwrap();
        drop(a.prepare().unwrap().unwrap());
        assert!(a.is_poisoned());
        assert!(matches!(a.prepare(), Err(DisplayDeliveryError::Poisoned)));
        assert!(matches!(a.observe(&[]), Err(DisplayDeliveryError::Poisoned)));
        b.prepare().unwrap().unwrap().sent(); assert!(!b.is_poisoned());
    }
}
