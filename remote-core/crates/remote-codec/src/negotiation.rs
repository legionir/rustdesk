//! Adapter over RustDesk's **process-global** codec negotiation state.
//!
//! RustDesk's `Encoder::update` maintains a global peer map and may query
//! process-global configuration, cached hardware state and host memory.
//! Run this adapter only in a dedicated process that owns those globals; it
//! cannot isolate unrelated RustDesk code or prevent ID collisions with it.
//! The algorithm is the pinned source algorithm, including its VP9 default,
//! not a new protocol or a guarantee any advertised codec is actually usable.
//! This module has not been built, tested or validated with real peers.

use crate::{invalid, Codec};
use remote_protocol::{Envelope, MAX_PRE_AUTH_BYTES};
use scrap::{codec::{Encoder, EncodingUpdate}, CodecFormat};
use std::{collections::HashSet, io, sync::atomic::{AtomicBool, Ordering}};

/// Upper bound on peer registrations owned by this adapter instance.
pub const MAX_PEERS: usize = 64;
static NEGOTIATOR_BUSY: AtomicBool = AtomicBool::new(false);

/// Codec selected by the original RustDesk source negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiatedCodec { Vp8, Vp9, Av1, H264, H265, Unknown }
impl NegotiatedCodec {
    /// Map source software selections to this prototype's software encoder API.
    /// Hardware, unknown or unavailable selections are not silently downgraded.
    pub fn software(self) -> Option<Codec> {
        match self { Self::Vp8 => Some(Codec::Vp8), Self::Vp9 => Some(Codec::Vp9), Self::Av1 => Some(Codec::Av1), _ => None }
    }
}
fn selected() -> NegotiatedCodec {
    match Encoder::negotiated_codec() {
        CodecFormat::VP8 => NegotiatedCodec::Vp8, CodecFormat::VP9 => NegotiatedCodec::Vp9,
        CodecFormat::AV1 => NegotiatedCodec::Av1, CodecFormat::H264 => NegotiatedCodec::H264,
        CodecFormat::H265 => NegotiatedCodec::H265, _ => NegotiatedCodec::Unknown,
    }
}

/// Explicit acknowledgement of the upstream legacy VP9 assumption.
/// Missing capability data does not demonstrate decoder support. Use only when
/// the embedding application deliberately accepts the compatibility risk.
pub struct LegacyVp9OptIn(());
impl LegacyVp9OptIn {
    pub fn acknowledge_unverified_peer_decoder() -> Self { Self(()) }
}

/// Cooperatively owns a subset of RustDesk's process-global negotiation map.
///
/// Only one instance from this module may exist at a time. Other users of the
/// original `scrap::codec::Encoder` globals can still collide and bypass this
/// guard. The embedding application must ensure exclusive process ownership and
/// use globally unique positive peer IDs. Drop removes this instance's IDs but
/// cannot restore state changed by unrelated code.
pub struct SourceNegotiator { peers: HashSet<i32> }
impl SourceNegotiator {
    /// Acquire the module-local guard. Refuses concurrent instances.
    pub fn new() -> io::Result<Self> {
        NEGOTIATOR_BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "source negotiation already in use"))?;
        Ok(Self { peers: HashSet::new() })
    }
    /// Apply a peer's existing RustDesk SupportedDecoding option or login data.
    ///
    /// This is a source-compatible global operation, not a security decision.
    /// A peer's capabilities must be authenticated and verified by the caller.
    /// A 128 KiB serialized envelope limit and peer-count bound apply here;
    /// upstream's own global state and allocations may exceed these bounds.
    pub fn update(&mut self, peer_id: i32, envelope: &Envelope) -> io::Result<NegotiatedCodec> {
        if peer_id <= 0 { return Err(invalid("peer ID must be positive")); }
        if !self.peers.contains(&peer_id) && self.peers.len() >= MAX_PEERS { return Err(invalid("negotiation peer limit reached")); }
        envelope.encode(MAX_PRE_AUTH_BYTES).map_err(|e| invalid_protocol(e.to_string()))?;
        let decoding = envelope.source_supported_decoding().map_err(|e| invalid_protocol(e.to_string()))?.clone();
        Encoder::update(EncodingUpdate::Update(peer_id, decoding));
        self.peers.insert(peer_id);
        Ok(selected())
    }
    /// Match the pinned source's `NewOnlyVP9` behavior for a peer whose login
    /// carried no decoding advertisement. This is intentionally opt-in: a
    /// missing claim does not prove VP9 is present or safe. Uses the same
    /// process-global state and ownership caveats as `update`.
    pub fn register_legacy_vp9(&mut self, peer_id: i32, _opt_in: LegacyVp9OptIn) -> io::Result<NegotiatedCodec> {
        if peer_id <= 0 { return Err(invalid("peer ID must be positive")); }
        if !self.peers.contains(&peer_id) && self.peers.len() >= MAX_PEERS { return Err(invalid("negotiation peer limit reached")); }
        Encoder::update(EncodingUpdate::NewOnlyVP9(peer_id));
        self.peers.insert(peer_id);
        Ok(selected())
    }
    /// Remove a peer registered by this instance. Unknown IDs are rejected so
    /// this wrapper does not intentionally remove unrelated source state.
    pub fn remove(&mut self, peer_id: i32) -> io::Result<NegotiatedCodec> {
        if !self.peers.remove(&peer_id) { return Err(io::Error::new(io::ErrorKind::NotFound, "peer not registered")); }
        Encoder::update(EncodingUpdate::Remove(peer_id));
        Ok(selected())
    }
    /// Current source-global choice; it can change outside this wrapper.
    pub fn selected(&self) -> NegotiatedCodec { selected() }
    /// Number of peer IDs owned by this instance.
    pub fn peer_count(&self) -> usize { self.peers.len() }
}
impl Drop for SourceNegotiator {
    fn drop(&mut self) {
        for id in self.peers.drain() { Encoder::update(EncodingUpdate::Remove(id)); }
        NEGOTIATOR_BUSY.store(false, Ordering::Release);
    }
}
fn invalid_protocol(message: String) -> io::Error { io::Error::new(io::ErrorKind::InvalidInput, message) }

#[cfg(test)]
mod tests {
    use super::*;
    use remote_protocol::{CodecPreference, DecodingAdvertisement};
    #[test]
    fn source_accepts_existing_capability_envelope() {
        let mut n = SourceNegotiator::new().unwrap();
        assert!(matches!(SourceNegotiator::new(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
        let msg = Envelope::supported_decoding_event(DecodingAdvertisement {
            vp8: true, vp9: true, av1: false, h264: false, h265: false, preference: CodecPreference::Vp9,
        });
        assert_eq!(n.update(1, &msg).unwrap(), NegotiatedCodec::Vp9);
        assert_eq!(n.peer_count(), 1);
        n.remove(1).unwrap();
        assert_eq!(n.peer_count(), 0);
        assert!(n.register_legacy_vp9(0, LegacyVp9OptIn::acknowledge_unverified_peer_decoder()).is_err());
        assert_eq!(n.register_legacy_vp9(2, LegacyVp9OptIn::acknowledge_unverified_peer_decoder()).unwrap(), NegotiatedCodec::Vp9);
        assert_eq!(n.peer_count(), 1);
        n.remove(2).unwrap();
    }
}
