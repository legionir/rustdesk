//! Side-effect-free planning of a source display-resolution request.
//!
//! This does not change the OS mode, grant permission, freeze topology or
//! restore a previous resolution. A trusted host must authorize view and display
//! control plus separately obtain informed local consent, re-enumerate just
//! before acting, serialize display mutations and handle restoration/failure.
use remote_capture::DisplayInfo;
use remote_protocol::display_control::DisplayResolution;
use std::{error::Error, fmt};

const MAX_DISPLAYS: usize = 64;
const MAX_MODES: usize = 512;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Resolution { pub width: u32, pub height: u32 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionPlan {
    pub display: u32,
    /// Ephemeral OS device name; never use as a durable authenticated identity.
    pub device_name: String,
    pub previous: Resolution,
    pub requested: Resolution,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError { InvalidSnapshot, TopologyChanged, InvalidDisplay, InvalidMode, UnsupportedMode }
impl fmt::Display for PlanError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "resolution plan: {self:?}") } }
impl Error for PlanError {}
/// Validate against an owner-approved snapshot and a fresh observed snapshot.
/// Equality cannot prove stable physical identity, and a topology can change
/// immediately after this call. Caller provides the fresh native mode list and
/// must treat truncated/incomplete enumeration as unsuitable for mutation.
pub fn plan(approved: &[DisplayInfo], observed: &[DisplayInfo], request: DisplayResolution, modes: &[Resolution]) -> Result<ResolutionPlan, PlanError> {
    if approved.is_empty() || approved.len() > MAX_DISPLAYS || observed.len() > MAX_DISPLAYS || modes.is_empty() || modes.len() > MAX_MODES {
        return Err(PlanError::InvalidSnapshot);
    }
    if approved != observed { return Err(PlanError::TopologyChanged); }
    let display = observed.get(request.display as usize).ok_or(PlanError::InvalidDisplay)?;
    if !display.online || display.name.is_empty() || display.name.len() > 256 || display.name.chars().any(|ch| ch.is_control() || ch == '\u{fffd}')
        || observed.iter().filter(|candidate| candidate.name == display.name).count() != 1 {
        return Err(PlanError::InvalidDisplay);
    }
    let width = u32::try_from(request.width).map_err(|_| PlanError::InvalidMode)?;
    let height = u32::try_from(request.height).map_err(|_| PlanError::InvalidMode)?;
    let previous = Resolution { width: u32::try_from(display.width).map_err(|_| PlanError::InvalidMode)?,
        height: u32::try_from(display.height).map_err(|_| PlanError::InvalidMode)? };
    let requested = Resolution { width, height };
    let valid = |mode: Resolution| (1..=32768).contains(&mode.width) && (1..=32768).contains(&mode.height);
    if !valid(previous) || !valid(requested) || modes.iter().any(|mode| !valid(*mode)) { return Err(PlanError::InvalidMode); }
    if !modes.contains(&requested) { return Err(PlanError::UnsupportedMode); }
    Ok(ResolutionPlan { display: request.display, device_name: display.name.clone(), previous, requested })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn display(name: &str) -> DisplayInfo { DisplayInfo { name: name.into(), x: 0, y: 0, width: 1920, height: 1080, online: true, primary: true } }
    #[test]
    fn refuses_stale_duplicate_and_unsupported() {
        let original = vec![display("one")]; let mut changed = original.clone(); changed[0].x = -1;
        let req = DisplayResolution { display: 0, width: 1280, height: 720 };
        let modes = [Resolution { width: 1280, height: 720 }];
        assert_eq!(plan(&original, &changed, req, &modes), Err(PlanError::TopologyChanged));
        let lossy = vec![display("one\u{fffd}")];
        assert_eq!(plan(&lossy, &lossy, req, &modes), Err(PlanError::InvalidDisplay));
        assert_eq!(plan(&original, &original, req, &[Resolution { width: 1920, height: 1080 }]), Err(PlanError::UnsupportedMode));
        assert_eq!(plan(&[display("one"), display("one")], &[display("one"), display("one")], req, &modes), Err(PlanError::InvalidDisplay));
        let value = plan(&original, &original, req, &modes).unwrap();
        assert_eq!(value.previous, Resolution { width: 1920, height: 1080 });
        assert_eq!(value.requested, modes[0]);
    }
}

/// Errors while collecting an approved Windows resolution plan.
#[cfg(windows)]
#[derive(Debug)]
pub enum WindowsPlanError { NotAuthorized, Capture(std::io::Error), ModeQuery(std::io::Error), Truncated, CurrentModeChanged, Plan(PlanError) }
#[cfg(windows)]
impl fmt::Display for WindowsPlanError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Windows resolution planning: {self:?}") } }
#[cfg(windows)]
impl Error for WindowsPlanError {}
/// Re-enumerate current Windows displays and supported modes for an approved
/// request. This is a read-only plan, not trusted consent to alter OS settings.
/// The operation is synchronous and can block the caller. Windows topology can
/// still change immediately after the final snapshot; the application must
/// coordinate revalidation, permission, restoration and actual mode change.
#[cfg(windows)]
pub fn plan_windows<T: remote_transport::NetworkTransport, B: remote_input::InputBackend>(
    host: &crate::host_connection::HostConnection<T, B>, approved: &[DisplayInfo], request: DisplayResolution,
) -> Result<ResolutionPlan, WindowsPlanError> {
    if !matches!(host.state(), remote_session::SessionState::Connected | remote_session::SessionState::Streaming)
        || !host.permissions().view_screen || !host.permissions().change_display { return Err(WindowsPlanError::NotAuthorized); }
    let observed: Vec<_> = remote_capture::displays().map_err(WindowsPlanError::Capture)?.into_iter().map(|display| display.info().clone()).collect();
    if observed != approved { return Err(WindowsPlanError::Plan(PlanError::TopologyChanged)); }
    let display = observed.get(request.display as usize).ok_or(WindowsPlanError::Plan(PlanError::InvalidDisplay))?;
    let snapshot = remote_capture::windows_resolution::enumerate_modes(&display.name).map_err(WindowsPlanError::ModeQuery)?;
    if snapshot.truncated { return Err(WindowsPlanError::Truncated); }
    if snapshot.current.width as usize != display.width || snapshot.current.height as usize != display.height { return Err(WindowsPlanError::CurrentModeChanged); }
    let modes: Vec<Resolution> = snapshot.modes.into_iter().map(|mode| Resolution { width: mode.width, height: mode.height }).collect();
    let result = plan(approved, &observed, request, &modes).map_err(WindowsPlanError::Plan)?;
    let after: Vec<_> = remote_capture::displays().map_err(WindowsPlanError::Capture)?.into_iter().map(|display| display.info().clone()).collect();
    if after != observed { return Err(WindowsPlanError::Plan(PlanError::TopologyChanged)); }
    Ok(result)
}
