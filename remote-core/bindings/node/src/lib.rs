//! Experimental Node-API bindings for local, explicit display capture only.
//! This addon does not expose input control, networking, or authentication.

use napi::{bindgen_prelude::{AsyncTask, Buffer}, Env, Error, Result, Task};
use napi_derive::napi;
use remote_capture::{Frame, PixelFormat};
use std::{sync::atomic::{AtomicBool, Ordering}, time::Duration};

// Reject concurrent native capture tasks rather than multiplying copied frame
// buffers without bound. This does not limit queued JS promises or native
// allocations made internally by the capture backend.
static CAPTURE_BUSY: AtomicBool = AtomicBool::new(false);
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_TIMEOUT_MS: u32 = 2000;

struct CaptureLease;
impl CaptureLease {
    fn acquire() -> Result<Self> {
        CAPTURE_BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self).map_err(|_| Error::from_reason("another native capture is in progress"))
    }
}
impl Drop for CaptureLease {
    fn drop(&mut self) { CAPTURE_BUSY.store(false, Ordering::Release); }
}

fn js_error(error: impl std::fmt::Display) -> Error { Error::from_reason(error.to_string()) }
fn dimension(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::from_reason("capture dimension or stride exceeds Node API limit"))
}

/// A snapshot, not a persistent display identifier. Display ordering may
/// change between enumeration and capture due to hotplug or desktop changes.
#[napi(object)]
pub struct DisplayMetadata {
    pub index: u32,
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub online: bool,
    pub primary: bool,
}

#[napi(object)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub strides: Vec<u32>,
    /// Native pixel format, not necessarily packed RGBA.
    pub format: String,
    /// Owned copy, including any native row/plane padding.
    pub data: Buffer,
}

pub struct EnumerateTask;
impl Task for EnumerateTask {
    type Output = Vec<DisplayMetadata>;
    type JsValue = Vec<DisplayMetadata>;
    fn compute(&mut self) -> Result<Self::Output> {
        remote_capture::displays().map_err(js_error)?.into_iter().enumerate().map(|(index, display)| {
            let info = display.info();
            Ok(DisplayMetadata { index: dimension(index)?, name: info.name.clone(), x: info.x, y: info.y,
                width: dimension(info.width)?, height: dimension(info.height)?, online: info.online, primary: info.primary })
        }).collect()
    }
    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> { Ok(output) }
}

/// Owned worker result before conversion into a Node buffer.
pub struct RawFrame { width: u32, height: u32, strides: Vec<u32>, format: String, data: Vec<u8> }
pub struct CaptureTask { display_index: u32, timeout_ms: u32 }
impl Task for CaptureTask {
    type Output = RawFrame;
    type JsValue = CapturedFrame;
    fn compute(&mut self) -> Result<Self::Output> {
        let _lease = CaptureLease::acquire()?;
        let display = remote_capture::displays().map_err(js_error)?.into_iter().nth(self.display_index as usize)
            .ok_or_else(|| Error::from_reason("display index is no longer available"))?;
        let mut capture = display.open().map_err(js_error)?;
        let pixels = match capture.frame(Duration::from_millis(self.timeout_ms.into())).map_err(js_error)? {
            Frame::Pixels(pixels) => pixels,
            Frame::Texture(_) => return Err(Error::from_reason("GPU texture frames are not supported by this Node API")),
        };
        if pixels.data().len() > MAX_FRAME_BYTES {
            return Err(Error::from_reason("captured frame exceeds the 64 MiB Node copy limit"));
        }
        let format = match pixels.format() {
            PixelFormat::Bgra => "bgra", PixelFormat::Rgba => "rgba", PixelFormat::Rgb565Le => "rgb565le",
            PixelFormat::I420 => "i420", PixelFormat::Nv12 => "nv12", PixelFormat::I444 => "i444",
        };
        Ok(RawFrame { width: dimension(pixels.width())?, height: dimension(pixels.height())?,
            strides: pixels.stride().into_iter().map(dimension).collect::<Result<Vec<_>>>()?,
            format: format.to_owned(), data: pixels.data().to_vec() })
    }
    fn resolve(&mut self, _env: Env, frame: Self::Output) -> Result<Self::JsValue> {
        Ok(CapturedFrame { width: frame.width, height: frame.height, strides: frame.strides,
            format: frame.format, data: frame.data.into() })
    }
}

/// Enumerate the current desktop displays on a libuv worker.
#[napi]
pub fn list_displays() -> AsyncTask<EnumerateTask> { AsyncTask::new(EnumerateTask) }

/// Capture one current display on a libuv worker. Re-enumerates before opening;
/// the index is not guaranteed to still refer to the same physical display.
/// `timeout_ms` is a native-backend hint, not a guaranteed operation deadline.
#[napi]
pub fn capture_display(display_index: u32, timeout_ms: u32) -> Result<AsyncTask<CaptureTask>> {
    if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
        return Err(Error::from_reason("timeoutMs must be between 1 and 2000"));
    }
    Ok(AsyncTask::new(CaptureTask { display_index, timeout_ms }))
}
