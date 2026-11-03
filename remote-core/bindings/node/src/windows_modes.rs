//! Experimental read-only Windows mode enumeration; no OS state mutation.
//! It exposes display topology and is not a trusted local consent UI.
use napi::{bindgen_prelude::AsyncTask, Env, Error, Result, Task};
use napi_derive::napi;
use std::sync::atomic::{AtomicBool, Ordering};
static MODE_QUERY_IN_USE: AtomicBool = AtomicBool::new(false);
struct ModeLease;
impl ModeLease {
    fn acquire() -> Result<Self> {
        MODE_QUERY_IN_USE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self).map_err(|_| Error::from_reason("display mode inspection already in progress"))
    }
}
impl Drop for ModeLease { fn drop(&mut self) { MODE_QUERY_IN_USE.store(false, Ordering::Release); } }

#[napi(object)]
pub struct WindowsDisplayMode { pub width: u32, pub height: u32, pub bits_per_pixel: u32, pub refresh_hz: u32 }
#[napi(object)]
pub struct WindowsModeSnapshot {
    pub display_index: u32, pub device_name: String, pub current: WindowsDisplayMode,
    pub modes: Vec<WindowsDisplayMode>, pub truncated: bool,
}
pub struct WindowsModesTask { display_index: u32, _lease: ModeLease }
impl Task for WindowsModesTask {
    type Output = WindowsModeSnapshot; type JsValue = WindowsModeSnapshot;
    fn compute(&mut self) -> Result<Self::Output> {
        #[cfg(windows)]
        {
            use crate::js_error;
            use remote_capture::windows_resolution::{enumerate_modes, DisplayMode};
            let before: Vec<_> = remote_capture::displays().map_err(js_error)?.into_iter().map(|d| d.info().clone()).collect();
            if before.len() > 64 { return Err(Error::from_reason("too many displays")); }
            let display = before.get(self.display_index as usize).ok_or_else(|| Error::from_reason("display index is unavailable"))?;
            if !display.online || display.name.is_empty() || before.iter().filter(|other| other.name == display.name).count() != 1 {
                return Err(Error::from_reason("display name is offline, empty or ambiguous"));
            }
            let snapshot = enumerate_modes(&display.name).map_err(js_error)?;
            if snapshot.current.width as usize != display.width || snapshot.current.height as usize != display.height {
                return Err(Error::from_reason("display mode changed during enumeration"));
            }
            let after: Vec<_> = remote_capture::displays().map_err(js_error)?.into_iter().map(|d| d.info().clone()).collect();
            if before != after { return Err(Error::from_reason("display topology changed during enumeration")); }
            let convert = |mode: DisplayMode| WindowsDisplayMode { width: mode.width, height: mode.height, bits_per_pixel: mode.bits_per_pixel, refresh_hz: mode.refresh_hz };
            Ok(WindowsModeSnapshot { display_index: self.display_index, device_name: display.name.clone(), current: convert(snapshot.current), modes: snapshot.modes.into_iter().map(convert).collect(), truncated: snapshot.truncated })
        }
        #[cfg(not(windows))]
        { let _ = self.display_index; Err(Error::from_reason("Windows display modes are unavailable on this platform")) }
    }
    fn resolve(&mut self, _: Env, value: Self::Output) -> Result<Self::JsValue> { Ok(value) }
}
/// Read-only local topology query, not a resolution-setting operation.
/// Local application must obtain trusted consent before exposing the result.
#[napi]
pub fn inspect_windows_display_modes(display_index: u32, confirm_local_consent: bool) -> Result<AsyncTask<WindowsModesTask>> {
    if !confirm_local_consent { return Err(Error::from_reason("explicit local consent is required")); }
    if display_index >= 64 { return Err(Error::from_reason("display index exceeds local bound")); }
    let lease = ModeLease::acquire()?;
    Ok(AsyncTask::new(WindowsModesTask { display_index, _lease: lease }))
}
