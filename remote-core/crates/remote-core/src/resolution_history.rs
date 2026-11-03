//! Explicit, side-effect-free resolution-change bookkeeping inspired by
//! `src/server/display_service.rs::{set_last_changed_resolution,restore_resolutions}`.
//!
//! The source keeps the first original size and last attempted size per device,
//! restores when no clients remain and clears even when restore fails. This
//! bounded helper deliberately never calls Win32, restores automatically or
//! clears on failure. It cannot identify a physical monitor: device names are
//! volatile and can be reused. The owner must serialize operations, independently
//! obtain consent, re-enumerate/revalidate before each native change or restore,
//! handle uncertainty/third-party changes, and persist recovery if required.
use crate::resolution_plan::{Resolution, ResolutionPlan};
use std::{collections::BTreeMap, error::Error, fmt};

const MAX_RECORDS: usize = 64;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionRecord { pub device_name: String, pub original: Resolution, pub last_attempted: Resolution, pub generation: u64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryError { Invalid, Capacity, ConflictingCurrent, StaleRecord, UnknownDevice, GenerationExhausted }
impl fmt::Display for HistoryError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "resolution history: {self:?}") } }
impl Error for HistoryError {}
fn valid(mode: Resolution) -> bool { (1..=32768).contains(&mode.width) && (1..=32768).contains(&mode.height) }
fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 256 && !name.contains('\u{fffd}') && !name.chars().any(char::is_control)
}
/// Caller-owned, in-memory records for one explicitly coordinated application.
/// Not process-global, durable, authenticated or shared across instances.
#[derive(Default)]
pub struct ResolutionHistory { records: BTreeMap<String, ResolutionRecord>, next_generation: u64 }
impl ResolutionHistory {
    pub fn new() -> Self { Self::default() }
    /// Record an intended, already locally authorized plan BEFORE the native
    /// call, because failure/cancellation may leave actual OS state uncertain.
    /// Subsequent plans must observe our last attempted size; this conservative
    /// rule differs from source and rejects divergent/unfinished changes rather
    /// than overwriting evidence. Matching dimensions do not prove identity.
    pub fn record_attempt(&mut self, plan: &ResolutionPlan) -> Result<(), HistoryError> {
        if !valid_name(&plan.device_name) || !valid(plan.previous) || !valid(plan.requested) { return Err(HistoryError::Invalid); }
        if let Some(record) = self.records.get(&plan.device_name) {
            if record.last_attempted != plan.previous { return Err(HistoryError::ConflictingCurrent); }
        } else if self.records.len() >= MAX_RECORDS { return Err(HistoryError::Capacity); }
        let generation = self.next_generation.checked_add(1).ok_or(HistoryError::GenerationExhausted)?;
        if let Some(record) = self.records.get_mut(&plan.device_name) {
            record.last_attempted = plan.requested; record.generation = generation;
        } else {
            self.records.insert(plan.device_name.clone(), ResolutionRecord { device_name: plan.device_name.clone(), original: plan.previous, last_attempted: plan.requested, generation });
        }
        self.next_generation = generation;
        Ok(())
    }
    /// Snapshot intended recovery records in deterministic order. This does not
    /// assert that a device still exists, that our change took effect, or that
    /// restoring it will not override a local user's later change.
    pub fn recovery_records(&self) -> Vec<ResolutionRecord> { self.records.values().cloned().collect() }
    /// Forget one record only after a trusted local operator has independently
    /// verified safe recovery or chosen to accept the current mode. Matching
    /// the exact snapshot and its monotonic generation prevents ABA removal of
    /// a newer recorded attempt only when the snapshot belongs to this same
    /// history instance. Generations restart in a new instance, so never import
    /// records across instances or restarts. This is not proof of successful
    /// restoration or OS identity. Errors retain the record.
    pub fn acknowledge_recovery(&mut self, expected: &ResolutionRecord) -> Result<(), HistoryError> {
        match self.records.get(&expected.device_name) {
            None => return Err(HistoryError::UnknownDevice),
            Some(current) if current != expected => return Err(HistoryError::StaleRecord),
            Some(_) => {},
        }
        self.records.remove(&expected.device_name); Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn mode(width: u32, height: u32) -> Resolution { Resolution { width, height } }
    fn plan(name: &str, previous: Resolution, requested: Resolution) -> ResolutionPlan {
        ResolutionPlan { display: 0, device_name: name.into(), previous, requested }
    }
    #[test]
    fn keeps_first_original_and_rejects_stale_or_divergent_attempts() {
        let mut history = ResolutionHistory::new();
        let (a, b, c) = (mode(1920, 1080), mode(1280, 720), mode(1024, 768));
        history.record_attempt(&plan("display", a, b)).unwrap();
        let old = history.recovery_records().remove(0);
        assert_eq!(history.record_attempt(&plan("display", a, c)), Err(HistoryError::ConflictingCurrent));
        history.record_attempt(&plan("display", b, c)).unwrap();
        assert_eq!(history.acknowledge_recovery(&old), Err(HistoryError::StaleRecord));
        let current = history.recovery_records().remove(0);
        assert_eq!((current.original, current.last_attempted), (a, c));
        history.acknowledge_recovery(&current).unwrap();
        assert_eq!(history.acknowledge_recovery(&current), Err(HistoryError::UnknownDevice));
    }
    #[test]
    fn stale_snapshot_is_rejected_even_when_sizes_return_to_same_values() {
        let mut history = ResolutionHistory::new();
        let (a, b, c) = (mode(1920, 1080), mode(1280, 720), mode(1024, 768));
        history.record_attempt(&plan("display", a, b)).unwrap();
        let old = history.recovery_records().remove(0);
        history.record_attempt(&plan("display", b, c)).unwrap();
        history.record_attempt(&plan("display", c, b)).unwrap();
        assert_eq!(history.acknowledge_recovery(&old), Err(HistoryError::StaleRecord));
        let current = history.recovery_records().remove(0);
        assert_ne!(current.generation, old.generation);
        history.acknowledge_recovery(&current).unwrap();
    }
    #[test]
    fn exhausted_generations_leave_existing_records_unchanged() {
        let mut history = ResolutionHistory::new();
        let (a, b, c) = (mode(1920, 1080), mode(1280, 720), mode(1024, 768));
        history.record_attempt(&plan("display", a, b)).unwrap();
        let old = history.recovery_records().remove(0);
        history.next_generation = u64::MAX;
        assert_eq!(history.record_attempt(&plan("display", b, c)), Err(HistoryError::GenerationExhausted));
        assert_eq!(history.recovery_records(), vec![old]);
    }
    #[test]
    fn validates_before_inserting_and_bounds_records() {
        let mut history = ResolutionHistory::new(); let a = mode(1, 1);
        assert_eq!(history.record_attempt(&plan("a\0b", a, a)), Err(HistoryError::Invalid));
        for id in 0..MAX_RECORDS { history.record_attempt(&plan(&format!("display{id}"), a, a)).unwrap(); }
        assert_eq!(history.record_attempt(&plan("extra", a, a)), Err(HistoryError::Capacity));
        assert_eq!(history.recovery_records().len(), MAX_RECORDS);
    }
}
