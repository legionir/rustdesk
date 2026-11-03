//! Narrow, best-effort wiping for a RustDesk keyboard sequence envelope.
//! Text, typed key codes, unknown protobuf fields, JS strings, serialization,
//! peer buffers, allocator copies and native/transport memory are not generally
//! protected. Failed parsing may leave allocations outside this guard. A crash,
//! process kill or leak can skip Drop. Do not log or clone input messages.
use crate::{message, message_proto, Envelope, ProtocolError};
use std::ops::Deref;
use zeroize::Zeroize;

/// Own an envelope and erase the current protobuf `KeyEvent.seq` String on
/// drop. This does not erase other sensitive key-event representations or
/// strings in other variants. The caller must wipe any encoded bytes separately.
pub struct SensitiveInputEnvelope(Envelope);
impl SensitiveInputEnvelope {
    pub fn new(envelope: Envelope) -> Self { Self(envelope) }
    pub fn decode(bytes: &[u8], max_bytes: usize) -> Result<Self, ProtocolError> {
        Envelope::decode(bytes, max_bytes).map(Self)
    }
    fn scrub(&mut self) {
        if let Some(message::Union::KeyEvent(event)) = self.0.inner.union.as_mut() {
            if let Some(message_proto::key_event::Union::Seq(text)) = event.union.as_mut() { text.zeroize(); }
        }
    }
}
impl Deref for SensitiveInputEnvelope {
    type Target = Envelope;
    fn deref(&self) -> &Envelope { &self.0 }
}
impl Drop for SensitiveInputEnvelope { fn drop(&mut self) { self.scrub(); } }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{input::LegacyKey, KeyboardPayload};
    #[test]
    fn scrubs_recognized_sequence_and_preserves_non_text_shape() {
        let event = Envelope::legacy_keyboard_event(LegacyKey::Sequence("secret"), false, false, &[]).unwrap();
        let mut guarded = SensitiveInputEnvelope::new(event);
        guarded.scrub();
        assert_eq!(guarded.keyboard().unwrap().payload(), Some(KeyboardPayload::Sequence("")));
        let mut other = SensitiveInputEnvelope::new(Envelope::legacy_keyboard_event(LegacyKey::ControlKey(13), true, false, &[]).unwrap());
        other.scrub();
        assert_eq!(other.keyboard().unwrap().payload(), Some(KeyboardPayload::ControlKey(13)));
    }
    #[test]
    fn decoded_translate_sequence_is_guarded() {
        let envelope = Envelope::windows_translate_sequence_event("sample").unwrap();
        let wire = zeroize::Zeroizing::new(envelope.encode(1024).unwrap());
        let mut decoded = SensitiveInputEnvelope::decode(&wire, 1024).unwrap();
        decoded.scrub();
        assert_eq!(decoded.keyboard().unwrap().payload(), Some(KeyboardPayload::Sequence("")));
    }
}
