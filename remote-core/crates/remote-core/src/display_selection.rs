//! Caller-driven planning for source CaptureDisplays requests.
//!
//! This does not acquire or stop capture, send frames, or change any OS state.
//! Indices are volatile positions in a caller-provided current display snapshot,
//! not durable monitor identities. Revalidate/recreate on hotplug or permission
//! changes. Apply a plan only after all required capture operations succeed.
use remote_protocol::display_control::{CaptureDisplays, MAX_DISPLAY_ENTRIES};
use std::{collections::BTreeSet, error::Error, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayPlan { pub active: Vec<u32>, pub start: Vec<u32>, pub stop: Vec<u32> }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayPlanError { InvalidLimit, InvalidIndex, DuplicateCurrent, Capacity, TopologyChanged, AmbiguousDisplay }
impl fmt::Display for DisplayPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "display plan: {self:?}") }
}
impl Error for DisplayPlanError {}
/// Source precedence is nonempty add, otherwise nonempty sub, otherwise set.
/// Despite its name, source `sub` uses `include=false, exclude=true` in
/// `Server::capture_displays`: it *retains* listed active displays and removes
/// other active displays, rather than subtracting the listed IDs.
/// Unlike upstream's partial filtering, this adapter rejects the entire request
/// if *any* supplied index is unavailable. Empty set deliberately stops all.
/// Caller must authorize view/change-display and bound concurrent encoder memory.
pub fn plan(current: &[u32], request: &CaptureDisplays, available: &[bool], max_active: usize) -> Result<DisplayPlan, DisplayPlanError> {
    if available.len() > MAX_DISPLAY_ENTRIES || max_active == 0 || max_active > MAX_DISPLAY_ENTRIES
        || current.len() > MAX_DISPLAY_ENTRIES || request.add.len() > MAX_DISPLAY_ENTRIES
        || request.sub.len() > MAX_DISPLAY_ENTRIES || request.set.len() > MAX_DISPLAY_ENTRIES {
        return Err(DisplayPlanError::InvalidLimit);
    }
    let validate = |index: &u32| available.get(*index as usize).copied().unwrap_or(false);
    if current.iter().chain(request.add.iter()).chain(request.sub.iter()).chain(request.set.iter()).any(|n| !validate(n)) {
        return Err(DisplayPlanError::InvalidIndex);
    }
    let before: BTreeSet<u32> = current.iter().copied().collect();
    if before.len() != current.len() { return Err(DisplayPlanError::DuplicateCurrent); }
    let mut after = before.clone();
    if !request.add.is_empty() { after.extend(request.add.iter().copied()); }
    else if !request.sub.is_empty() { after.retain(|index| request.sub.contains(index)); }
    else { after = request.set.iter().copied().collect(); }
    if after.len() > max_active { return Err(DisplayPlanError::Capacity); }
    Ok(DisplayPlan { active: after.iter().copied().collect(), start: after.difference(&before).copied().collect(), stop: before.difference(&after).copied().collect() })
}
/// Plan a request against an owner-approved and freshly enumerated snapshot.
/// Exact equality is a conservative stale-topology check, not proof of a
/// durable physical display identity. Online names must be nonempty, unique
/// and free of control characters. No handle is acquired and the topology can
/// still change after this call. Revalidate before opening any display; the
/// application owns permission, consent, decoder synchronization and rollback.
pub fn plan_for_snapshot(current: &[u32], request: &CaptureDisplays,
    approved: &[remote_capture::DisplayInfo], observed: &[remote_capture::DisplayInfo], max_active: usize)
    -> Result<DisplayPlan, DisplayPlanError> {
    if approved.is_empty() || approved.len() > MAX_DISPLAY_ENTRIES || observed.len() > MAX_DISPLAY_ENTRIES {
        return Err(DisplayPlanError::InvalidLimit);
    }
    if approved != observed { return Err(DisplayPlanError::TopologyChanged); }
    let mut names = BTreeSet::new();
    for d in observed.iter().filter(|d| d.online) {
        if d.name.is_empty() || d.name.len() > 256 || d.name.chars().any(|ch| ch.is_control() || ch == '\u{fffd}') || !names.insert(&d.name) {
            return Err(DisplayPlanError::AmbiguousDisplay);
        }
    }
    let available: Vec<bool> = observed.iter().map(|d| d.online).collect();
    plan(current, request, &available, max_active)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(add: &[u32], sub: &[u32], set: &[u32]) -> CaptureDisplays {
        CaptureDisplays { add: add.to_vec(), sub: sub.to_vec(), set: set.to_vec() }
    }
    #[test]
    fn snapshot_must_match_and_devices_must_be_unambiguous() {
        let display = remote_capture::DisplayInfo { name: "display-1".into(), x: 0, y: 0, width: 1920, height: 1080, online: true, primary: true };
        let mut changed = display.clone(); changed.width = 1280;
        let req = request(&[], &[], &[0]);
        let mut lossy = display.clone(); lossy.name = "display-\u{fffd}".into();
        assert_eq!(plan_for_snapshot(&[], &req, &[lossy.clone()], &[lossy], 1), Err(DisplayPlanError::AmbiguousDisplay));
        assert_eq!(plan_for_snapshot(&[], &req, &[display.clone()], &[changed], 1), Err(DisplayPlanError::TopologyChanged));
        assert_eq!(plan_for_snapshot(&[], &req, &[display.clone(), display.clone()], &[display.clone(), display.clone()], 2), Err(DisplayPlanError::AmbiguousDisplay));
        assert_eq!(plan_for_snapshot(&[], &req, &[display.clone()], &[display], 1).unwrap().active, vec![0]);
    }
    #[test]
    fn source_precedence_and_empty_set_are_explicit() {
        let displays = [true, true, true];
        assert_eq!(plan(&[0], &request(&[1], &[0], &[2]), &displays, 3).unwrap().active, vec![0, 1]);
        assert_eq!(plan(&[0, 1], &request(&[], &[0], &[2]), &displays, 3).unwrap().active, vec![0]);
        // Source sub is an inclusion filter, not subtraction or an add: a
        // valid but inactive listed display can leave no subscriptions.
        assert!(plan(&[0, 1], &request(&[], &[2], &[]), &displays, 3).unwrap().active.is_empty());
        let result = plan(&[0, 1], &request(&[], &[], &[]), &displays, 3).unwrap();
        assert_eq!(result.stop, vec![0, 1]); assert!(result.active.is_empty());
    }
    #[test]
    fn rejects_invalid_indices_instead_of_filtering_to_empty_set() {
        assert_eq!(plan(&[0], &request(&[], &[4], &[]), &[true], 1), Err(DisplayPlanError::InvalidIndex));
        assert_eq!(plan(&[0], &request(&[1], &[], &[]), &[true, true], 1), Err(DisplayPlanError::Capacity));
        assert_eq!(plan(&[0, 0], &request(&[], &[], &[]), &[true], 2), Err(DisplayPlanError::DuplicateCurrent));
    }
}
