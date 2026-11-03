//! Optional cooperative capture admission accounting. No native resources are
//! acquired here. This is not an OS/process-wide limit: every capture path must
//! hold leases from the same instance, and pixels are not a byte/CPU/GPU bound.
//! Reserve temporary additions before opening replacement streams and retain
//! old leases until old native handles are dropped; rollback by dropping the
//! new lease. Crashes, unrelated processes, native buffering and stale topology
//! are outside its scope. There is no queue, fairness or automatic scheduling.
use std::{error::Error, fmt, sync::{Arc, Mutex}};

const MAX_LEASES: usize = 64;
const MAX_STREAMS: usize = 256;
const MAX_PIXELS: u64 = 1 << 32;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetLimits { pub leases: usize, pub streams: usize, pub pixels: u64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetError { InvalidLimits, InvalidRequest, Capacity, Poisoned }
impl fmt::Display for BudgetError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "capture budget: {self:?}") } }
impl Error for BudgetError {}
#[derive(Default)]
struct Usage { leases: usize, streams: usize, pixels: u64 }
struct Inner { limits: BudgetLimits, usage: Mutex<Usage> }
/// Cloneable pool for cooperating capture owners. The application chooses
/// reviewed local limits; a lease is only accounting, not native ownership.
#[derive(Clone)]
pub struct CaptureBudget { inner: Arc<Inner> }
impl CaptureBudget {
    pub fn new(limits: BudgetLimits) -> Result<Self, BudgetError> {
        if limits.leases == 0 || limits.leases > MAX_LEASES || limits.streams == 0 || limits.streams > MAX_STREAMS
            || limits.pixels == 0 || limits.pixels > MAX_PIXELS { return Err(BudgetError::InvalidLimits); }
        Ok(Self { inner: Arc::new(Inner { limits, usage: Mutex::new(Usage::default()) }) })
    }
    /// Reserve one to eight bounded nonzero frame areas before opening native
    /// resources. Sum is checked before mutation; no partial reservation on
    /// failure. Native allocations and encoder buffering may be much larger.
    pub fn reserve(&self, dimensions: &[(u32, u32)]) -> Result<CaptureLease, BudgetError> {
        if dimensions.is_empty() || dimensions.len() > 8 { return Err(BudgetError::InvalidRequest); }
        let mut pixels = 0u64;
        for &(width, height) in dimensions {
            if width == 0 || height == 0 || width > 32768 || height > 32768 { return Err(BudgetError::InvalidRequest); }
            pixels = pixels.checked_add(u64::from(width) * u64::from(height)).ok_or(BudgetError::InvalidRequest)?;
        }
        let mut state = self.inner.usage.lock().map_err(|_| BudgetError::Poisoned)?;
        let streams = state.streams.checked_add(dimensions.len()).ok_or(BudgetError::Capacity)?;
        let total_pixels = state.pixels.checked_add(pixels).ok_or(BudgetError::Capacity)?;
        if state.leases >= self.inner.limits.leases || streams > self.inner.limits.streams || total_pixels > self.inner.limits.pixels {
            return Err(BudgetError::Capacity);
        }
        state.leases += 1; state.streams = streams; state.pixels = total_pixels;
        Ok(CaptureLease { inner: self.inner.clone(), streams: dimensions.len(), pixels })
    }
    pub fn usage(&self) -> Result<BudgetLimits, BudgetError> {
        let state = self.inner.usage.lock().map_err(|_| BudgetError::Poisoned)?;
        Ok(BudgetLimits { leases: state.leases, streams: state.streams, pixels: state.pixels })
    }
}
/// Release accounting when dropped. The owner must drop native handles first;
/// this type does not own them and cannot verify that they have closed.
pub struct CaptureLease { inner: Arc<Inner>, streams: usize, pixels: u64 }
impl Drop for CaptureLease {
    fn drop(&mut self) {
        // A poisoned mutex makes future reserve/usage fail closed.
        if let Ok(mut state) = self.inner.usage.lock() {
            state.leases -= 1; state.streams -= self.streams; state.pixels -= self.pixels;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacity_failures_do_not_change_live_reservations() {
        let budget = CaptureBudget::new(BudgetLimits { leases: 2, streams: 2, pixels: 200 }).unwrap();
        let first = budget.reserve(&[(10, 10)]).unwrap();
        assert!(matches!(budget.reserve(&[(11, 10)]), Err(BudgetError::Capacity)));
        assert_eq!(budget.usage().unwrap(), BudgetLimits { leases: 1, streams: 1, pixels: 100 });
        let second = budget.reserve(&[(10, 10)]).unwrap();
        assert!(matches!(budget.reserve(&[(1, 1)]), Err(BudgetError::Capacity)));
        drop(first); assert_eq!(budget.usage().unwrap().pixels, 100);
        drop(second); assert_eq!(budget.usage().unwrap().streams, 0);
    }
    #[test]
    fn concurrent_reservations_never_exceed_the_shared_limit() {
        use std::sync::{Arc, Barrier};
        let pool = CaptureBudget::new(BudgetLimits { leases: 4, streams: 4, pixels: 400 }).unwrap();
        let start = Arc::new(Barrier::new(12)); let finish = Arc::new(Barrier::new(12));
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..12).map(|_| {
                let pool = pool.clone(); let start = start.clone(); let finish = finish.clone();
                scope.spawn(move || {
                    start.wait(); let lease = pool.reserve(&[(10, 10)]);
                    finish.wait(); lease.is_ok()
                })
            }).collect();
            let successes = handles.into_iter().map(|handle| handle.join().unwrap()).filter(|ok| *ok).count();
            assert_eq!(successes, 4);
        });
        assert_eq!(pool.usage().unwrap(), BudgetLimits { leases: 0, streams: 0, pixels: 0 });
    }
    #[test]
    fn refuses_invalid_dimensions_and_limits() {
        assert!(matches!(CaptureBudget::new(BudgetLimits { leases: 0, streams: 1, pixels: 1 }), Err(BudgetError::InvalidLimits)));
        let pool = CaptureBudget::new(BudgetLimits { leases: 1, streams: 8, pixels: 500 }).unwrap();
        assert!(matches!(pool.reserve(&[]), Err(BudgetError::InvalidRequest)));
        assert!(matches!(pool.reserve(&[(0, 1)]), Err(BudgetError::InvalidRequest)));
        assert_eq!(pool.usage().unwrap().leases, 0);
    }
}
