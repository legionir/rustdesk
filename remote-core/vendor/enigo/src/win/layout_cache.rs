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

    /// Source-style cached-layout scan mapping; no input event is sent.
    #[cfg(windows)]
    pub(crate) fn map_scan(&self, vk: u16) -> u16 {
        use winapi::shared::windef::HKL;
        use winapi::um::winuser::{GetForegroundWindow, GetKeyboardLayout, GetWindowThreadProcessId, MapVirtualKeyExW};
        self.with(|layout| unsafe {
            if *layout == 0 {
                let thread = GetWindowThreadProcessId(GetForegroundWindow(), std::ptr::null_mut());
                *layout = GetKeyboardLayout(thread) as usize;
            }
            MapVirtualKeyExW(vk as _, 0, *layout as HKL) as _
        })
    }

    /// Source-style layout refresh and character mapping; no input event is sent.
    #[cfg(windows)]
    pub(crate) fn map_character(&self, chr: char) -> u16 {
        use winapi::shared::windef::HKL;
        use winapi::um::winuser::{GetForegroundWindow, GetKeyboardLayout, GetWindowThreadProcessId, VkKeyScanExW};
        self.with(|layout| unsafe {
            let thread = GetWindowThreadProcessId(GetForegroundWindow(), std::ptr::null_mut());
            *layout = GetKeyboardLayout(thread) as usize;
            VkKeyScanExW(chr as _, *layout as HKL) as _
        })
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
    #[cfg(windows)]
    #[test]
    fn concurrent_native_layout_queries_do_not_inject_input() {
        let cache = Arc::new(LayoutCache::new());
        let mut workers = Vec::new();
        for _ in 0..8 {
            let cache = cache.clone();
            workers.push(std::thread::spawn(move || {
                for _ in 0..500 {
                    // Result depends on the current desktop/layout; this only
                    // exercises the synchronization and native lookup paths.
                    let _ = cache.map_scan(0x41);
                    let _ = cache.map_character('a');
                }
            }));
        }
        for worker in workers { worker.join().unwrap(); }
    }

}
