//! Bounded adapters for the pinned RustDesk `Auth2FA` protobuf and its two
//! login-error strings. This does not verify TOTP, approve, enroll a device,
//! rate-limit, authenticate a peer, or implement a login state machine. All
//! fields are untrusted and credentials can remain in protobuf/allocator copies.
use crate::{message, message_proto, Envelope, ProtocolError};
use std::fmt;

/// The exact source login-error sent after password/owner authorization.
pub const REQUIRE_2FA: &str = "2FA Required";
/// The exact source login-error on an incorrect second-factor code.
pub const WRONG_2FA_CODE: &str = "Wrong 2FA Code";
/// Local limit on an untrusted device identifier, not an upstream wire limit.
pub const MAX_HARDWARE_ID_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoFactorPrompt { Required, WrongCode }
/// Only classifies exact protocol strings. A prompt is unauthenticated and is
/// not proof a host is genuine or that password verification succeeded.
pub fn classify_login_error(reason: &str) -> Option<TwoFactorPrompt> {
    match reason { REQUIRE_2FA => Some(TwoFactorPrompt::Required), WRONG_2FA_CODE => Some(TwoFactorPrompt::WrongCode), _ => None }
}
/// Borrowed untrusted request. Debug is redacted; protobuf, network buffers,
/// caller copies and hardware IDs may nonetheless remain in memory or logs.
pub struct TwoFactorRequest<'a> { pub code: &'a str, pub hardware_id: &'a [u8], pub trust_this_device: bool }
impl fmt::Debug for TwoFactorRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TwoFactorRequest").field("code", &"[REDACTED]").field("hardware_id", &"[REDACTED]")
            .field("trust_this_device", &self.trust_this_device).finish()
    }
}
/// Outbound-only guard that scrubs the protobuf's current code String on drop,
/// including encoding errors and Rust unwinding. Hardware ID, wire bytes,
/// intermediate protobuf/native buffers, reallocations, caller copies and
/// process termination remain outside this best-effort guarantee. No Debug or
/// Clone implementation is provided. The caller must scrub the returned bytes.
pub struct SensitiveTwoFactorEnvelope(Envelope);
impl SensitiveTwoFactorEnvelope {
    pub fn new(code: &str, hardware_id: &[u8], trust_this_device: bool) -> Result<Self, ProtocolError> {
        Envelope::two_factor_event(code, hardware_id, trust_this_device).map(Self)
    }
    pub fn encode(&self, max_bytes: usize) -> Result<Vec<u8>, ProtocolError> { self.0.encode(max_bytes) }
    fn scrub(&mut self) {
        use zeroize::Zeroize;
        if let Some(message::Union::Auth2fa(auth)) = self.0.inner.union.as_mut() {
            auth.code.zeroize();
            if let Ok(mut bytes) = std::mem::take(&mut auth.hwid).try_into_mut() { bytes.as_mut().zeroize(); }
        }
    }
}
impl Drop for SensitiveTwoFactorEnvelope { fn drop(&mut self) { self.scrub(); } }
fn valid(code: &str, hardware_id: &[u8]) -> bool {
    (6..=8).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_digit()) && hardware_id.len() <= MAX_HARDWARE_ID_BYTES
}
impl Envelope {
    /// Construct the existing message only. Choosing `trust_this_device` is a
    /// peer request, not consent to enrollment; this adapter does not enroll.
    /// The source currently generates six-digit TOTP and supports configured
    /// digits; the bounded 6..=8 numeric rule is a local compatibility policy.
    pub fn two_factor_event(code: &str, hardware_id: &[u8], trust_this_device: bool) -> Result<Self, ProtocolError> {
        if !valid(code, hardware_id) { return Err(ProtocolError::InvalidAuthenticationField); }
        let mut inner = message_proto::Message::new();
        inner.set_auth_2fa(message_proto::Auth2FA { code: code.to_owned(), hwid: hardware_id.to_vec().into(), trust_this_device, ..Default::default() });
        Ok(Self { inner })
    }
    /// Inspect without copying code or identifier. Do not retain or log these
    /// values; validate authorization, attempt caps and replay separately.
    pub fn two_factor_request(&self) -> Result<TwoFactorRequest<'_>, ProtocolError> {
        let auth = match self.inner.union.as_ref() { Some(message::Union::Auth2fa(auth)) => auth, _ => return Err(ProtocolError::UnexpectedMessage) };
        if !valid(&auth.code, &auth.hwid) { return Err(ProtocolError::InvalidAuthenticationField); }
        Ok(TwoFactorRequest { code: &auth.code, hardware_id: &auth.hwid, trust_this_device: auth.trust_this_device })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_fields_round_trip_without_enrollment() {
        let wire = Envelope::two_factor_event("012345", &[1, 2, 3], true).unwrap().encode(4096).unwrap();
        let envelope = Envelope::decode(&wire, 4096).unwrap();
        let request = envelope.two_factor_request().unwrap();
        assert_eq!(request.code, "012345"); assert_eq!(request.hardware_id, &[1, 2, 3]); assert!(request.trust_this_device);
        let debug = format!("{request:?}"); assert!(!debug.contains("012345")); assert!(!debug.contains("[1, 2, 3]"));
    }
    #[test]
    fn guarded_code_scrub_invalidates_retained_protobuf_field() {
        let mut secret = SensitiveTwoFactorEnvelope::new("123456", &[], false).unwrap();
        assert!(secret.encode(4096).is_ok());
        secret.scrub();
        assert!(matches!(secret.0.two_factor_request(), Err(ProtocolError::InvalidAuthenticationField)));
        // Repeated cleanup is safe; bytes already returned by encode are not wiped here.
        secret.scrub();
    }
    #[test]
    fn untrusted_incoming_values_are_checked_after_protobuf_decode() {
        for (code, hwid) in [("bad".to_owned(), vec![]), ("123456".to_owned(), vec![7; MAX_HARDWARE_ID_BYTES + 1])] {
            let mut message = message_proto::Message::new();
            message.set_auth_2fa(message_proto::Auth2FA { code, hwid: hwid.into(), trust_this_device: true, ..Default::default() });
            let envelope = Envelope { inner: message };
            let raw = envelope.encode(4096).unwrap();
            let parsed = Envelope::decode(&raw, 4096).unwrap();
            assert!(matches!(parsed.two_factor_request(), Err(ProtocolError::InvalidAuthenticationField)));
        }
        let other = Envelope::test_delay_event(crate::TestDelay { time: 0, from_client: true, last_delay: 0, target_bitrate: 0 });
        assert!(matches!(other.two_factor_request(), Err(ProtocolError::UnexpectedMessage)));
    }
    #[test]
    fn local_bounds_and_exact_prompt_classification() {
        assert!(Envelope::two_factor_event("12345", &[], false).is_err());
        assert!(Envelope::two_factor_event("12345x", &[], false).is_err());
        assert!(Envelope::two_factor_event("123456789", &[], false).is_err());
        assert!(Envelope::two_factor_event("123456", &vec![1; MAX_HARDWARE_ID_BYTES + 1], false).is_err());
        assert_eq!(classify_login_error(REQUIRE_2FA), Some(TwoFactorPrompt::Required));
        assert_eq!(classify_login_error(WRONG_2FA_CODE), Some(TwoFactorPrompt::WrongCode));
        assert_eq!(classify_login_error("2fa required"), None);
    }
}
