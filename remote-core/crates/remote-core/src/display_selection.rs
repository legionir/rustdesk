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
pub enum DisplayPlanError { InvalidLimit, InvalidIndex, DuplicateCurrent, Capacity }
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
#[cfg(test)]
mod tests {
    use super::*;
    fn request(add: &[u32], sub: &[u32], set: &[u32]) -> CaptureDisplays {
        CaptureDisplays { add: add.to_vec(), sub: sub.to_vec(), set: set.to_vec() }
    }
    #[test]
    fn source_precedence_and_empty_set_are_explicit() {
        let displays = [true, true, true];
        assert_eq!(plan(&[0], &request(&[1], &[0], &[2]), &displays, 3).unwrap().active, vec![0, 1]);
        assert_eq!(plan(&[0, 1], &request(&[], &[0], &[2]), &displays, 3).unwrap().active, vec![0]);
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
