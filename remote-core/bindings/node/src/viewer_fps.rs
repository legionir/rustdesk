//! Synchronous bookkeeping only; no remote policy, decoder or I/O.
use crate::js_error;
use napi::{Error, Result};
use napi_derive::napi;
use remote_core::viewer_fps::{DisplaySample, ViewerFps};
use std::{sync::Mutex, time::Instant};

#[napi(object)]
pub struct ViewerFpsSample {
    pub display: u32,
    pub received_fps: u32,
    pub decode_fps: Option<u32>,
    pub queue_len: u32,
    pub queue_capacity: u32,
}
#[napi(object)]
pub struct ViewerFpsDecision {
    pub custom_fps: Option<u32>,
    pub refresh: Vec<u32>,
    pub min_decode_fps: Option<u32>,
}
/// Independent caller-owned state, not implicitly bound to a Viewer object.
/// Create a new tracker on reconnect or display identity change.
#[napi]
pub struct ViewerFpsController { inner: Mutex<ViewerFps> }
#[napi]
impl ViewerFpsController {
    #[napi]
    pub fn set_displays(&self, displays: Vec<u32>) -> Result<()> {
        self.inner.lock().map_err(|_| Error::from_reason("viewer FPS state poisoned"))?.set_displays(&displays).map_err(js_error)
    }
    #[napi]
    pub fn reset(&self) -> Result<()> {
        self.inner.lock().map_err(|_| Error::from_reason("viewer FPS state poisoned"))?.reset(); Ok(())
    }
    /// Explicit source-style reset of last auto FPS after a manual change.
    /// Serialize with manual sends/ticks; failed sends still require full reset.
    #[napi]
    pub fn note_manual_fps_update(&self) -> Result<()> {
        self.inner.lock().map_err(|_| Error::from_reason("viewer FPS state poisoned"))?.note_manual_fps_update(); Ok(())
    }
    /// Advances local decisions, not actual peer state. Caller supplies local
    /// measurements and decides if/how to send; a failed send requires reset.
    #[napi]
    pub fn tick(&self, direct: bool, custom_fps: Option<u32>, samples: Vec<ViewerFpsSample>) -> Result<ViewerFpsDecision> {
        if samples.len() > 8 { return Err(Error::from_reason("at most eight display samples")); }
        let values: Vec<_> = samples.into_iter().map(|s| DisplaySample { display: s.display, received_fps: s.received_fps,
            decode_fps: s.decode_fps, queue_len: s.queue_len, queue_capacity: s.queue_capacity }).collect();
        let value = self.inner.lock().map_err(|_| Error::from_reason("viewer FPS state poisoned"))?
            .tick(Instant::now(), direct, custom_fps, &values).map_err(js_error)?;
        Ok(ViewerFpsDecision { custom_fps: value.custom_fps, refresh: value.refresh, min_decode_fps: value.min_decode_fps })
    }
}
/// Explicitly create a fresh isolated FPS state. No peer is contacted.
#[napi]
pub fn create_viewer_fps_controller() -> ViewerFpsController { ViewerFpsController { inner: Mutex::new(ViewerFps::new()) } }

/// Independent one-display decode-speed meter. Timing and successful rendering
/// are caller assertions, not performed or verified by this object.
#[napi]
pub struct ViewerDecodeFps { inner: Mutex<remote_core::viewer_decode_fps::DecodeFps> }
#[napi]
impl ViewerDecodeFps {
    /// `elapsedMicros` is a caller measurement, capped at 60 seconds.
    #[napi]
    pub fn record(&self, format_changed: bool, elapsed_micros: u32) -> Result<Option<u32>> {
        self.inner.lock().map_err(|_| Error::from_reason("decode FPS state poisoned"))?
            .record(format_changed, std::time::Duration::from_micros(u64::from(elapsed_micros))).map_err(js_error)
    }
    #[napi]
    pub fn estimate(&self) -> Result<Option<u32>> {
        Ok(self.inner.lock().map_err(|_| Error::from_reason("decode FPS state poisoned"))?.estimate())
    }
    #[napi]
    pub fn reset(&self) -> Result<()> {
        self.inner.lock().map_err(|_| Error::from_reason("decode FPS state poisoned"))?.reset(); Ok(())
    }
}
#[napi]
pub fn create_viewer_decode_fps() -> ViewerDecodeFps {
    ViewerDecodeFps { inner: Mutex::new(remote_core::viewer_decode_fps::DecodeFps::new()) }
}

/// One caller-counted UI-callback rate meter. No timer or render verification.
#[napi]
pub struct ViewerFrameRate { inner: Mutex<remote_core::viewer_frame_rate::ViewerFrameRate> }
#[napi]
impl ViewerFrameRate {
    #[napi]
    pub fn record_frame(&self) -> Result<()> {
        self.inner.lock().map_err(|_| Error::from_reason("frame-rate state poisoned"))?.record_frame().map_err(js_error)
    }
    /// Supply actual elapsed milliseconds shared across displays. Under one
    /// second returns no sample and retains counts; successful samples reset.
    #[napi]
    pub fn sample(&self, elapsed_ms: u32) -> Result<Option<u32>> {
        self.inner.lock().map_err(|_| Error::from_reason("frame-rate state poisoned"))?
            .sample(std::time::Duration::from_millis(u64::from(elapsed_ms))).map_err(js_error)
    }
    #[napi]
    pub fn reset(&self) -> Result<()> {
        self.inner.lock().map_err(|_| Error::from_reason("frame-rate state poisoned"))?.reset(); Ok(())
    }
}
#[napi]
pub fn create_viewer_frame_rate() -> ViewerFrameRate {
    ViewerFrameRate { inner: Mutex::new(remote_core::viewer_frame_rate::ViewerFrameRate::new()) }
}
