//! Read-only planner for two branches in pinned `src/server/connection.rs`:
//! `handle_windows_specific_session` and `Misc::SelectedSid`. No OS enumeration,
//! IPC, authentication, policy, consent or session switching is performed.
//! Conditions are snapshots and can change before any attempted action; never
//! treat a positive result as permission, proof or a stable OS session identity.
use std::{collections::HashSet, error::Error, fmt};

/// Local maximum, not a source limit.
pub const MAX_SESSIONS: usize = 64;
/// Source get_version_number("1.2.4") using the pinned calculation.
pub const SOURCE_MIN_ADVERTISEMENT_VERSION: i64 = 1_002_040;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError { TooManySessions, DuplicateSession }
impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Windows session plan: {self:?}") }
}
impl Error for PlanError {}
/// All inputs are supplied by the owner. The count must use the source's
/// authorized non-port-forward connection scope, not all sockets. Version is
/// the pinned `hbb_common::get_version_number` result; parsing untrusted strings
/// and arithmetic overflow policy are deliberately not reproduced here.
#[derive(Debug, Clone, Copy)]
pub struct Snapshot<'a> {
    pub installed: bool,
    pub share_rdp: bool,
    /// The source does not advertise Windows sessions for terminal logins.
    pub terminal_login: bool,
    pub authorized_non_forward_connections: usize,
    pub current_sid: Option<u32>,
    pub sessions: &'a [u32],
    pub peer_version_number: i64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advertisement { Omit, Offer { current_sid: u32 } }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection { NoSwitch, SwitchCandidate { sid: u32 } }
impl Snapshot<'_> {
    fn validate(&self) -> Result<(), PlanError> {
        if self.sessions.len() > MAX_SESSIONS { return Err(PlanError::TooManySessions); }
        let mut ids = HashSet::with_capacity(self.sessions.len());
        if self.sessions.iter().any(|sid| !ids.insert(*sid)) { return Err(PlanError::DuplicateSession); }
        Ok(())
    }
    fn common(&self) -> bool {
        self.installed && self.share_rdp && self.authorized_non_forward_connections == 1 && self.sessions.len() > 1
    }
    /// Whether the pinned branch would advertise these IDs; names and login
    /// response construction remain the caller's responsibility.
    pub fn advertisement(&self) -> Result<Advertisement, PlanError> {
        self.validate()?;
        match self.current_sid {
            Some(current_sid) if !self.terminal_login && self.common() && self.sessions.contains(&current_sid)
                && self.peer_version_number >= SOURCE_MIN_ADVERTISEMENT_VERSION => Ok(Advertisement::Offer { current_sid }),
            _ => Ok(Advertisement::Omit),
        }
    }
    /// The selected-ID branch re-enumerates IDs and does not repeat the version
    /// or current-ID-membership checks from advertisement. `NoSwitch` covers
    /// multiple source fallback branches, none of which are executed here.
    /// Outer connection-type scoping is also not modeled for this branch.
    pub fn selection(&self, selected_sid: u32) -> Result<Selection, PlanError> {
        self.validate()?;
        match self.current_sid {
            Some(current_sid) if self.common() && current_sid != selected_sid && self.sessions.contains(&selected_sid) => Ok(Selection::SwitchCandidate { sid: selected_sid }),
            _ => Ok(Selection::NoSwitch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ready<'a>(sessions: &'a [u32]) -> Snapshot<'a> {
        Snapshot { installed: true, share_rdp: true, terminal_login: false, authorized_non_forward_connections: 1,
            current_sid: Some(1), sessions, peer_version_number: SOURCE_MIN_ADVERTISEMENT_VERSION }
    }
    #[test]
    fn source_branches_differ_on_version_and_current_membership() {
        let ids = [1, 2]; let snapshot = ready(&ids);
        assert_eq!(snapshot.advertisement().unwrap(), Advertisement::Offer { current_sid: 1 });
        assert_eq!(snapshot.selection(2).unwrap(), Selection::SwitchCandidate { sid: 2 });
        assert_eq!(snapshot.selection(1).unwrap(), Selection::NoSwitch);
        assert_eq!(snapshot.selection(3).unwrap(), Selection::NoSwitch);
        let terminal = Snapshot { terminal_login: true, ..snapshot };
        assert_eq!(terminal.advertisement().unwrap(), Advertisement::Omit);
        // Selection is only the branch guard, not outer connection-type scoping.
        assert_eq!(terminal.selection(2).unwrap(), Selection::SwitchCandidate { sid: 2 });
        let older = Snapshot { peer_version_number: SOURCE_MIN_ADVERTISEMENT_VERSION - 1, ..snapshot };
        assert_eq!(older.advertisement().unwrap(), Advertisement::Omit);
        assert_eq!(older.selection(2).unwrap(), Selection::SwitchCandidate { sid: 2 });
        let missing = Snapshot { current_sid: Some(99), ..snapshot };
        assert_eq!(missing.advertisement().unwrap(), Advertisement::Omit);
        assert_eq!(missing.selection(2).unwrap(), Selection::SwitchCandidate { sid: 2 });
        let one = [1]; let single = ready(&one);
        assert_eq!(single.advertisement().unwrap(), Advertisement::Omit);
        assert_eq!(single.selection(1).unwrap(), Selection::NoSwitch);
        let empty: [u32; 0] = []; let none = ready(&empty);
        assert_eq!(none.advertisement().unwrap(), Advertisement::Omit);
        assert_eq!(none.selection(2).unwrap(), Selection::NoSwitch);
        let zero_ids = [0, 2]; let zero = Snapshot { current_sid: Some(0), sessions: &zero_ids, ..snapshot };
        assert_eq!(zero.advertisement().unwrap(), Advertisement::Offer { current_sid: 0 });
        assert_eq!(zero.selection(2).unwrap(), Selection::SwitchCandidate { sid: 2 });
    }
    #[test]
    fn conservative_rejection_of_ambiguous_snapshots() {
        assert_eq!(ready(&[1, 1]).advertisement(), Err(PlanError::DuplicateSession));
        assert_eq!(ready(&[1, 1]).selection(1), Err(PlanError::DuplicateSession));
        let many: Vec<u32> = (0..=MAX_SESSIONS as u32).collect();
        assert_eq!(ready(&many).selection(1), Err(PlanError::TooManySessions));
        let ids = [1, 2]; let snapshot = ready(&ids);
        for disallowed in [Snapshot { installed: false, ..snapshot }, Snapshot { share_rdp: false, ..snapshot },
            Snapshot { authorized_non_forward_connections: 2, ..snapshot }, Snapshot { current_sid: None, ..snapshot }] {
            assert_eq!(disallowed.advertisement().unwrap(), Advertisement::Omit);
            assert_eq!(disallowed.selection(2).unwrap(), Selection::NoSwitch);
        }
    }
}
