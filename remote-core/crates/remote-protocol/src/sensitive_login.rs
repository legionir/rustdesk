//! Limited-lifetime wrapper for the locally constructed source desktop login.
//! This is not secure memory: protobuf serialization, transport, password, SHA
//! implementation and allocator may hold copies. Aborts/crashes cannot be
//! erased reliably. Only the uniquely owned protobuf password buffer is wiped.
use crate::{message, DesktopLogin, DecodingAdvertisement, Envelope, ProtocolError};
use crate::video_preferences::{PreferenceError, VideoPreferences};
use zeroize::Zeroize;

pub struct SensitiveDesktopLogin(Envelope);
impl SensitiveDesktopLogin {
    pub fn new(login: DesktopLogin<'_>) -> Result<Self, ProtocolError> { Envelope::desktop_login_event(login).map(Self) }
    pub fn set_video_ack_required(&mut self, required: bool) -> Result<(), ProtocolError> { self.0.set_login_video_ack_required(required) }
    pub fn set_decoding(&mut self, value: DecodingAdvertisement) -> Result<(), ProtocolError> { self.0.set_login_decoding(value) }
    pub fn set_video_preferences(&mut self, value: VideoPreferences) -> Result<(), PreferenceError> { self.0.set_login_video_preferences(value) }
    /// Attach source cursor preferences; these are untrusted requests, not
    /// consent or evidence that the peer can or will provide cursor data.
    pub fn set_cursor_preferences(&mut self, value: crate::cursor_preferences::CursorPreferences) -> Result<(), crate::cursor_preferences::CursorPreferenceError> { self.0.set_cursor_preferences(value) }
    /// Attach a source peer input-disable request, not a grant of permission.
    pub fn set_disable_keyboard(&mut self, value: Option<bool>) -> Result<(), crate::input_preferences::InputPreferenceError> { self.0.set_disable_keyboard_preference(value) }
    /// The caller must wipe the returned serialized buffer separately.
    pub fn encode(&self, max_bytes: usize) -> Result<Vec<u8>, ProtocolError> { self.0.encode(max_bytes) }
    fn scrub(&mut self) { scrub_login(&mut self.0); }
}
impl Drop for SensitiveDesktopLogin { fn drop(&mut self) { self.scrub(); } }

/// Guard a pre-auth decoded message while inspecting it. Only fields of a
/// LoginRequest (including a switch-sides response), Auth2FA and elevation
/// logon are scrubbed where accessible;
/// other message variants and unknown fields can still contain secrets. Encoded
/// input and parse-failure allocations are the caller's responsibility. A copied or shared `Bytes` buffer cannot be wiped.
pub struct SensitiveIncomingLogin(Envelope);
impl SensitiveIncomingLogin {
    pub fn decode(bytes: &[u8], max_bytes: usize) -> Result<Self, ProtocolError> { Envelope::decode(bytes, max_bytes).map(Self) }
}
impl std::ops::Deref for SensitiveIncomingLogin {
    type Target = Envelope;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl Drop for SensitiveIncomingLogin { fn drop(&mut self) { scrub_login(&mut self.0); } }
fn scrub_login(envelope: &mut Envelope) {
    match envelope.inner.union.as_mut() {
        Some(message::Union::LoginRequest(login)) => scrub_request(login),
        Some(message::Union::SwitchSidesResponse(response)) => {
            if let Some(login) = response.lr.as_mut() { scrub_request(login); }
        },
        Some(message::Union::Auth2fa(auth)) => {
            auth.code.zeroize();
            if let Ok(mut bytes) = std::mem::take(&mut auth.hwid).try_into_mut() { bytes.as_mut().zeroize(); }
        },
        Some(message::Union::Misc(misc)) => {
            if let Some(crate::message_proto::misc::Union::ElevationRequest(request)) = misc.union.as_mut() {
                if let Some(crate::message_proto::elevation_request::Union::Logon(logon)) = request.union.as_mut() { logon.password.zeroize(); }
            }
        },
        _ => {},
    }
}


fn scrub_request(login: &mut crate::message_proto::LoginRequest) {
    // `Bytes` can be erased only when uniquely owned. If uniqueness is lost,
    // drop without claiming erasure, rather than wiping a copy.
    if let Ok(mut bytes) = std::mem::take(&mut login.password).try_into_mut() { bytes.as_mut().zeroize(); }
    if let Ok(mut bytes) = std::mem::take(&mut login.trusted_device_v2_token).try_into_mut() { bytes.as_mut().zeroize(); }
    if let Ok(mut bytes) = std::mem::take(&mut login.hwid).try_into_mut() { bytes.as_mut().zeroize(); }
    if let Some(os_login) = login.os_login.as_mut() { os_login.password.zeroize(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incoming_login_fields_are_removed_without_cloning() {
        let mut request = crate::message_proto::LoginRequest::new();
        request.password = vec![1; 32].into();
        request.hwid = vec![2; 8].into();
        request.trusted_device_v2_token = vec![3; 8].into();
        request.os_login = Some(crate::message_proto::OSLogin { username: "user".into(), password: "password".into(), ..Default::default() }).into();
        let mut message = crate::message_proto::Message::new(); message.set_login_request(request);
        let raw = Envelope { inner: message }.encode(4096).unwrap();
        let mut incoming = SensitiveIncomingLogin::decode(&raw, 4096).unwrap();
        scrub_login(&mut incoming.0);
        match incoming.0.inner.union.as_ref() {
            Some(message::Union::LoginRequest(value)) => {
                assert!(value.password.is_empty()); assert!(value.hwid.is_empty());
                assert!(value.trusted_device_v2_token.is_empty());
                assert!(value.os_login.as_ref().unwrap().password.is_empty());
            }, _ => panic!("not login"),
        }
    }
    #[test]
    fn switch_sides_nested_login_fields_are_removed() {
        let mut request = crate::message_proto::LoginRequest::new();
        request.password = vec![5; 32].into();
        request.os_login = Some(crate::message_proto::OSLogin { username: "user".into(), password: "secret".into(), ..Default::default() }).into();
        let mut message = crate::message_proto::Message::new();
        message.set_switch_sides_response(crate::message_proto::SwitchSidesResponse { lr: Some(request).into(), ..Default::default() });
        let mut envelope = Envelope { inner: message }; scrub_login(&mut envelope);
        match envelope.inner.union.as_ref() {
            Some(message::Union::SwitchSidesResponse(value)) => {
                let login = value.lr.as_ref().unwrap();
                assert!(login.password.is_empty()); assert!(login.os_login.as_ref().unwrap().password.is_empty());
            }, _ => panic!("not switch-sides"),
        }
    }
    #[test]
    fn other_recognized_pre_auth_credentials_are_scrubbed() {
        let mut auth = crate::message_proto::Message::new();
        auth.set_auth_2fa(crate::message_proto::Auth2FA { code: "123456".into(), hwid: vec![4; 8].into(), ..Default::default() });
        let mut envelope = Envelope { inner: auth }; scrub_login(&mut envelope);
        match envelope.inner.union.as_ref() {
            Some(message::Union::Auth2fa(value)) => { assert!(value.code.is_empty()); assert!(value.hwid.is_empty()); },
            _ => panic!("not 2fa"),
        }
        let mut request = crate::message_proto::ElevationRequest::new();
        request.set_logon(crate::message_proto::ElevationRequestWithLogon { username: "user".into(), password: "secret".into(), ..Default::default() });
        let mut misc = crate::message_proto::Misc::new(); misc.set_elevation_request(request);
        let mut message = crate::message_proto::Message::new(); message.set_misc(misc);
        let mut envelope = Envelope { inner: message }; scrub_login(&mut envelope);
        if let Some(message::Union::Misc(misc)) = envelope.inner.union.as_ref() {
            if let Some(crate::message_proto::misc::Union::ElevationRequest(request)) = misc.union.as_ref() {
                if let Some(crate::message_proto::elevation_request::Union::Logon(logon)) = request.union.as_ref() {
                    assert!(logon.password.is_empty()); return;
                }
            }
        }
        panic!("not elevation logon");
    }
    #[test]
    fn guard_removes_original_password_field_and_is_idempotent() {
        let proof = [42; 32];
        let mut login = SensitiveDesktopLogin::new(DesktopLogin { username: "host", peer_id: "viewer", peer_name: "name", password_response: &proof, session_id: 0, version: "1" }).unwrap();
        let cursor = crate::cursor_preferences::CursorPreferences { show_remote_cursor: Some(true), ..Default::default() };
        login.set_cursor_preferences(cursor).unwrap(); login.set_disable_keyboard(Some(true)).unwrap();
        let wire = login.encode(4096).unwrap();
        let parsed = Envelope::decode(&wire, 4096).unwrap();
        assert_eq!(parsed.cursor_preferences().unwrap(), cursor);
        assert_eq!(parsed.disable_keyboard_preference().unwrap(), Some(true));
        login.scrub();
        match login.0.inner.union.as_ref() { Some(message::Union::LoginRequest(value)) => assert!(value.password.is_empty()), _ => panic!("not login") }
        login.scrub();
    }
}
