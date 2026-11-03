//! Bounded wire-only adapter for source `PeerInfo.windows_sessions` and
//! `Misc.selected_sid`. Selection may make a real RustDesk host switch its
//! service to another Windows login session. Nothing here enumerates, validates
//! availability, authorizes or performs an OS session change.
use super::{desktop::{peer_mut, peer_ref}, message, message_proto, Envelope};
use std::{collections::HashSet, error::Error, fmt};

/// Local resource ceilings, not source protocol limits.
pub const MAX_SESSIONS: usize = 64;
pub const MAX_NAME_BYTES: usize = 256;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSession { pub sid: u32, pub name: String }
/// All values are untrusted claims; a session ID is not a stable identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSessions { pub sessions: Vec<WindowsSession>, pub current_sid: u32 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsSessionsError { UnexpectedMessage, InvalidSessions }
impl fmt::Display for WindowsSessionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::UnexpectedMessage => f.write_str("not a Windows session message"), Self::InvalidSessions => f.write_str("invalid Windows session claims") }
    }
}
impl Error for WindowsSessionsError {}
impl WindowsSessions {
    /// Reject ambiguous duplicate IDs and a missing current ID when nonempty.
    /// This is a local defensive policy, not proof the source has that session.
    pub fn validate(&self) -> Result<(), WindowsSessionsError> {
        if self.sessions.len() > MAX_SESSIONS { return Err(WindowsSessionsError::InvalidSessions); }
        let mut ids = HashSet::with_capacity(self.sessions.len());
        for s in &self.sessions {
            if s.name.len() > MAX_NAME_BYTES || s.name.chars().any(char::is_control) || !ids.insert(s.sid) {
                return Err(WindowsSessionsError::InvalidSessions);
            }
        }
        if !self.sessions.is_empty() && !ids.contains(&self.current_sid) { return Err(WindowsSessionsError::InvalidSessions); }
        Ok(())
    }
}
/// Explicit acknowledgement of a potentially disruptive remote session switch;
/// this marker is not authorization and cannot enforce consent in other paths.
#[derive(Debug, Clone, Copy)]
pub struct SessionSwitchOptIn(());
impl SessionSwitchOptIn {
    pub fn acknowledge_remote_session_switch_risk() -> Self { Self(()) }
}
impl Envelope {
    /// Inspect optional source login/update claims. `None` means field absent;
    /// an explicitly present empty list remains distinguishable.
    pub fn windows_sessions(&self) -> Result<Option<WindowsSessions>, WindowsSessionsError> {
        let peer = peer_ref(self).map_err(|_| WindowsSessionsError::UnexpectedMessage)?;
        let Some(raw) = peer.windows_sessions.as_ref() else { return Ok(None); };
        if raw.sessions.len() > MAX_SESSIONS { return Err(WindowsSessionsError::InvalidSessions); }
        let value = WindowsSessions { current_sid: raw.current_sid,
            sessions: raw.sessions.iter().map(|s| WindowsSession { sid: s.sid, name: s.name.clone() }).collect() };
        value.validate()?; Ok(Some(value))
    }
    /// Replace optional session claims after validating the complete input.
    /// Other PeerInfo fields are preserved, but unknown fields *inside* the
    /// replaced WindowsSessions submessage are discarded. This emits claims only.
    pub fn set_windows_sessions(&mut self, value: Option<&WindowsSessions>) -> Result<(), WindowsSessionsError> {
        if let Some(value) = value { value.validate()?; }
        let peer = peer_mut(self).map_err(|_| WindowsSessionsError::UnexpectedMessage)?;
        peer.windows_sessions = value.map(|value| message_proto::WindowsSessions {
            sessions: value.sessions.iter().map(|s| message_proto::WindowsSession { sid: s.sid, name: s.name.clone(), ..Default::default() }).collect(),
            current_sid: value.current_sid, ..Default::default()
        }).into();
        Ok(())
    }
    /// Inspect a peer's untrusted selection request; this never switches OS sessions.
    pub fn selected_windows_session(&self) -> Result<u32, WindowsSessionsError> {
        match self.inner.union.as_ref() {
            Some(message::Union::Misc(misc)) => match misc.union.as_ref() {
                Some(message_proto::misc::Union::SelectedSid(sid)) => Ok(*sid),
                _ => Err(WindowsSessionsError::UnexpectedMessage),
            },
            _ => Err(WindowsSessionsError::UnexpectedMessage),
        }
    }
    /// Construct the original source selection message; sending it to a real
    /// host can trigger an OS session switch. Caller owns fresh owner consent,
    /// actual session enumeration, peer compatibility and all side effects.
    pub fn select_windows_session_event(sid: u32, _opt_in: SessionSwitchOptIn) -> Self {
        let mut misc = message_proto::Misc::new(); misc.set_selected_sid(sid);
        let mut inner = message_proto::Message::new(); inner.set_misc(misc); Self { inner }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop::{LoginResult, PeerInfo};
    fn peer() -> PeerInfo {
        PeerInfo { username: "user".into(), hostname: "host".into(), platform: "Windows".into(), version: "test".into(),
            displays: vec![], current_display: 0, sas_enabled: false, encoding: None }
    }
    #[test]
    fn absent_empty_and_selected_sid_roundtrip() {
        let expected = peer();
        let mut message = Envelope::desktop_login_success(&expected).unwrap();
        assert_eq!(message.windows_sessions().unwrap(), None);
        let empty = WindowsSessions { sessions: vec![], current_sid: 0 };
        message.set_windows_sessions(Some(&empty)).unwrap();
        assert_eq!(message.windows_sessions().unwrap(), Some(empty));
        let value = WindowsSessions { current_sid: 2, sessions: vec![
            WindowsSession { sid: 1, name: "console".into() }, WindowsSession { sid: 2, name: "remote".into() },
        ] };
        message.set_windows_sessions(Some(&value)).unwrap();
        let bytes = message.encode(8192).unwrap();
        let mut decoded = Envelope::decode(&bytes, 8192).unwrap();
        assert_eq!(decoded.windows_sessions().unwrap(), Some(value));
        assert_eq!(decoded.desktop_login_result().unwrap(), LoginResult::Accepted(expected));
        decoded.set_windows_sessions(None).unwrap();
        assert_eq!(decoded.windows_sessions().unwrap(), None);
        let selected = Envelope::select_windows_session_event(u32::MAX, SessionSwitchOptIn::acknowledge_remote_session_switch_risk());
        let selected = Envelope::decode(&selected.encode(8192).unwrap(), 8192).unwrap();
        assert_eq!(selected.selected_windows_session().unwrap(), u32::MAX);
        assert_eq!(selected.windows_sessions().unwrap_err(), WindowsSessionsError::UnexpectedMessage);
    }
    #[test]
    fn invalid_replacement_does_not_mutate_message() {
        let mut message = Envelope::desktop_login_success(&peer()).unwrap();
        let valid = WindowsSessions { current_sid: 1, sessions: vec![WindowsSession { sid: 1, name: "a".into() }] };
        message.set_windows_sessions(Some(&valid)).unwrap();
        let invalid = [
            WindowsSessions { current_sid: 1, sessions: vec![WindowsSession { sid: 1, name: "a".into() }, WindowsSession { sid: 1, name: "b".into() }] },
            WindowsSessions { current_sid: 2, sessions: valid.sessions.clone() },
            WindowsSessions { current_sid: 1, sessions: vec![WindowsSession { sid: 1, name: "x\n".into() }] },
            WindowsSessions { current_sid: 1, sessions: vec![WindowsSession { sid: 1, name: "x".repeat(MAX_NAME_BYTES + 1) }] },
            WindowsSessions { current_sid: 1, sessions: (0..=MAX_SESSIONS).map(|i| WindowsSession { sid: i as u32, name: "".into() }).collect() },
        ];
        for bad in invalid {
            assert_eq!(message.set_windows_sessions(Some(&bad)).unwrap_err(), WindowsSessionsError::InvalidSessions);
            assert_eq!(message.windows_sessions().unwrap(), Some(valid.clone()));
        }
        assert_eq!(message.selected_windows_session().unwrap_err(), WindowsSessionsError::UnexpectedMessage);
    }
}
