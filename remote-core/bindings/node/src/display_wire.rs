//! Unverified Node inspection of bounded source display-change metadata.
//! Inspection never changes an OS mode and does not authenticate the sender.
use crate::js_error;
use napi::{bindgen_prelude::{AsyncTask, Buffer}, Env, Error, Result, Task};
use napi_derive::napi;
use remote_protocol::{resolution_metadata::Resolution, Envelope};
use std::sync::atomic::{AtomicBool, Ordering};

const LIMIT: usize = 128 * 1024;
static BUSY: AtomicBool = AtomicBool::new(false);
struct Lease;
impl Lease {
    fn acquire() -> Result<Self> {
        BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self).map_err(|_| Error::from_reason("display inspection already running"))
    }
}
impl Drop for Lease { fn drop(&mut self) { BUSY.store(false, Ordering::Release); } }
#[napi(object)]
pub struct WireResolution { pub width: i32, pub height: i32 }
#[napi(object)]
pub struct DisplayChangeMetadata {
    pub display: u32, pub x: i32, pub y: i32, pub width: i32, pub height: i32,
    pub cursor_embedded: bool, pub supported_modes: Option<Vec<WireResolution>>,
    pub original: Option<WireResolution>,
}
fn js_resolution(v: Resolution) -> WireResolution { WireResolution { width: v.width, height: v.height } }
pub struct InspectDisplayChangeTask { _lease: Lease, wire: Vec<u8> }
impl Task for InspectDisplayChangeTask {
    type Output = DisplayChangeMetadata;
    type JsValue = DisplayChangeMetadata;
    fn compute(&mut self) -> Result<Self::Output> {
        let event = Envelope::decode(&self.wire, LIMIT).map_err(js_error)?;
        let display = event.display_switch().map_err(js_error)?;
        let modes = event.supported_resolutions().map_err(js_error)?;
        let original = event.switch_original_resolution().map_err(js_error)?;
        Ok(DisplayChangeMetadata { display: display.display, x: display.x, y: display.y,
            width: display.width, height: display.height, cursor_embedded: display.cursor_embedded,
            supported_modes: modes.map(|modes| modes.into_iter().map(js_resolution).collect()), original: original.map(js_resolution) })
    }
    fn resolve(&mut self, _: Env, value: Self::Output) -> Result<Self::JsValue> { Ok(value) }
}
/// Inspect a `displayChanged` event's original envelope on a worker. Rejects
/// inputs over 128 KiB before copying and permits only one task at a time.
/// Peer claims remain untrusted and can be stale; mode count is locally capped.
#[napi]
pub fn inspect_display_change(wire: Buffer) -> Result<AsyncTask<InspectDisplayChangeTask>> {
    if wire.is_empty() || wire.len() > LIMIT { return Err(Error::from_reason("display envelope must be 1..131072 bytes")); }
    let lease = Lease::acquire()?;
    Ok(AsyncTask::new(InspectDisplayChangeTask { _lease: lease, wire: wire.to_vec() }))
}
