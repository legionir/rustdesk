//! Synchronization for the source-derived process-wide keyboard-layout cache.
use std::sync::Mutex;

/// Protect an opaque Windows handle represented as an integer. Access always
/// happens under the same lock; the handle remains owned by Windows.
pub(crate) struct LayoutCache(Mutex<usize>);
impl LayoutCache {
    pub(crate) const fn new() -> Self { Self(Mutex::new(0)) }

    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut usize) -> R) -> R {
        let mut value = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut value)
    }
}

#[cfg(test)]
mod tests {
    use super::LayoutCache;
    use std::sync::Arc;

    #[test]
    fn multiple_callers_share_serialized_state() {
        let cache = Arc::new(LayoutCache::new());
        let mut workers = Vec::new();
        for _ in 0..8 {
            let cache = cache.clone();
            workers.push(std::thread::spawn(move || {
                for _ in 0..1000 { cache.with(|value| *value += 1); }
            }));
        }
        for worker in workers { worker.join().unwrap(); }
        assert_eq!(cache.with(|value| *value), 8000);
    }

    #[test]
    fn poisoned_lock_remains_usable() {
        let cache = Arc::new(LayoutCache::new());
        let other = cache.clone();
        assert!(std::thread::spawn(move || other.with(|value| {
            *value = 17;
            panic!("intentional poison");
        })).join().is_err());
        assert_eq!(cache.with(|value| *value), 17);
        cache.with(|value| *value = 19);
        assert_eq!(cache.with(|value| *value), 19);
    }
}
