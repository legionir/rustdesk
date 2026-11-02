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

// Single outstanding encoder task, acquired before copying the JS buffer.
// This bounds prototype-owned pending copies; the caller can still retain
// arbitrary buffers/results, and native codec allocations are not bounded here.
static ENCODER_BUSY: AtomicBool = AtomicBool::new(false);
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENCODED_BYTES: usize = 16 * 1024 * 1024;

struct EncodeLease;
impl EncodeLease {
    fn acquire() -> Result<Self> {
        ENCODER_BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self).map_err(|_| Error::from_reason("another encode operation is in progress"))
    }
}
impl Drop for EncodeLease {
    fn drop(&mut self) { ENCODER_BUSY.store(false, Ordering::Release); }
}

/// Settings for a single, independent software encode operation.
#[napi(object)]
pub struct EncodeOptions {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    /// `vp8`, `vp9` or `av1`.
    pub codec: String,
    /// `bgra` or `rgba`.
    pub pixel_format: String,
    /// Finite RustDesk quality ratio in the range (0, 2].
    pub quality: f64,
    /// Presentation time in milliseconds (32-bit unsigned for JS precision).
    pub pts_ms: u32,
}

#[napi(object)]
pub struct EncodedPacket {
    pub data: Buffer,
    pub key: bool,
    /// Native packet presentation time, represented as a JS number.
    pub pts_ms: f64,
}
#[napi(object)]
pub struct EncodedFrame {
    pub codec: String,
    pub packets: Vec<EncodedPacket>,
}

/// Owned data transferred from an encoder worker to the JS runtime.
pub struct RawEncoded { codec: String, packets: Vec<remote_codec::Packet> }
/// A single isolated encoder invocation executed on a libuv worker.
pub struct EncodeTask {
    _lease: EncodeLease,
    data: Vec<u8>,
    options: EncodeOptions,
    codec: remote_codec::Codec,
    pixel_format: remote_codec::PackedFormat,
}
impl Task for EncodeTask {
    type Output = RawEncoded;
    type JsValue = EncodedFrame;
    fn compute(&mut self) -> Result<Self::Output> {
        let mut encoder = remote_codec::SoftwareEncoder::new(remote_codec::EncoderConfig {
            codec: self.codec, width: self.options.width, height: self.options.height,
            quality: self.options.quality as f32, keyframe_interval: None,
        }).map_err(js_error)?;
        let encoded = encoder.encode_packed(&self.data, self.options.stride as usize, self.pixel_format, self.options.pts_ms as i64).map_err(js_error)?;
        let total = encoded.packets.iter().try_fold(0usize, |sum, packet| sum.checked_add(packet.data.len()))
            .ok_or_else(|| Error::from_reason("encoded frame size overflow"))?;
        if total > MAX_ENCODED_BYTES { return Err(Error::from_reason("encoded frame exceeds 16 MiB copy limit")); }
        Ok(RawEncoded { codec: self.options.codec.clone(), packets: encoded.packets })
    }
    fn resolve(&mut self, _env: Env, result: Self::Output) -> Result<Self::JsValue> {
        Ok(EncodedFrame { codec: result.codec, packets: result.packets.into_iter().map(|packet| EncodedPacket {
            data: packet.data.into(), key: packet.key, pts_ms: packet.pts as f64,
        }).collect() })
    }
}

/// Encode one packed raw frame with a fresh encoder on a libuv worker.
///
/// This is not a streaming encoder: every call creates a new encoder and must
/// be treated as an independent stream. It does not produce a RustDesk envelope
/// or negotiate a codec. The input buffer is copied before this call returns.
#[napi]
pub fn encode_frame(data: Buffer, options: EncodeOptions) -> Result<AsyncTask<EncodeTask>> {
    use remote_codec::{Codec, PackedFormat};
    if !(2..=4096).contains(&options.width) || !(2..=4096).contains(&options.height)
        || options.width % 2 != 0 || options.height % 2 != 0
        || !options.quality.is_finite() || options.quality <= 0.0 || options.quality > 2.0 {
        return Err(Error::from_reason("invalid encoder dimensions or quality"));
    }
    let codec = match options.codec.as_str() {
        "vp8" => Codec::Vp8, "vp9" => Codec::Vp9, "av1" => Codec::Av1,
        _ => return Err(Error::from_reason("codec must be vp8, vp9 or av1")),
    };
    let pixel_format = match options.pixel_format.as_str() {
        "bgra" => PackedFormat::Bgra, "rgba" => PackedFormat::Rgba,
        _ => return Err(Error::from_reason("pixelFormat must be bgra or rgba")),
    };
    let row_bytes = (options.width as usize).checked_mul(4).ok_or_else(|| Error::from_reason("row size overflow"))?;
    let stride = options.stride as usize;
    // Match SoftwareEncoder::encode_packed: every row, including the last,
    // must have the full stride available before native conversion.
    let required = (options.height as usize).checked_mul(stride)
        .ok_or_else(|| Error::from_reason("pixel buffer size overflow"))?;
    if stride < row_bytes || data.len() < required || data.len() > MAX_INPUT_BYTES {
        return Err(Error::from_reason("invalid stride or pixel buffer size"));
    }
    let lease = EncodeLease::acquire()?;
    Ok(AsyncTask::new(EncodeTask { _lease: lease, data: data.to_vec(), options, codec, pixel_format }))
}

// Cursor data is compressed/decompressed on a libuv worker. This is a wire
// utility, not a screen capturer, renderer, transport, or authenticated session.
static CURSOR_BUSY: AtomicBool = AtomicBool::new(false);
const MAX_CURSOR_RGBA_BYTES: usize = 512 * 512 * 4;
const MAX_CURSOR_WIRE_BYTES: usize = 2 * 1024 * 1024;
struct CursorLease;
impl CursorLease {
    fn acquire() -> Result<Self> {
        CURSOR_BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self).map_err(|_| Error::from_reason("another cursor operation is in progress"))
    }
}
impl Drop for CursorLease {
    fn drop(&mut self) { CURSOR_BUSY.store(false, Ordering::Release); }
}
fn cursor_id(id: &str) -> Result<u64> {
    let parsed = id.parse::<u64>().map_err(|_| Error::from_reason("cursor id must be a decimal u64 string"))?;
    if parsed.to_string() != id { return Err(Error::from_reason("cursor id must use canonical decimal notation")); }
    Ok(parsed)
}

/// Cursor metadata. ID is a string because RustDesk uses a 64-bit identifier.
#[napi(object)]
pub struct CursorMetadata {
    pub id: String,
    pub hotx: i32,
    pub hoty: i32,
    pub width: i32,
    pub height: i32,
}
/// A decoded RustDesk shape; `rgba` is an owned packed RGBA buffer.
#[napi(object)]
pub struct DecodedCursorShape {
    pub id: String,
    pub hotx: i32,
    pub hoty: i32,
    pub width: i32,
    pub height: i32,
    pub rgba: Buffer,
}
pub struct EncodeCursorTask { _lease: CursorLease, shape: remote_protocol::cursor::CursorShape }
impl Task for EncodeCursorTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;
    fn compute(&mut self) -> Result<Self::Output> {
        remote_protocol::Envelope::cursor_shape_event(&self.shape).map_err(js_error)?
            .encode(MAX_CURSOR_WIRE_BYTES).map_err(js_error)
    }
    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> { Ok(output.into()) }
}
/// Serialize one validated RGBA cursor shape using RustDesk's existing schema.
/// This copies the input; only one encode/decode task may be outstanding.
#[napi]
pub fn encode_cursor_shape(rgba: Buffer, metadata: CursorMetadata) -> Result<AsyncTask<EncodeCursorTask>> {
    if rgba.len() > MAX_CURSOR_RGBA_BYTES { return Err(Error::from_reason("cursor RGBA exceeds 1 MiB")); }
    let id = cursor_id(&metadata.id)?;
    let lease = CursorLease::acquire()?;
    let shape = remote_protocol::cursor::CursorShape { id, hotx: metadata.hotx, hoty: metadata.hoty,
        width: metadata.width, height: metadata.height, rgba: rgba.to_vec() };
    shape.validate().map_err(js_error)?;
    Ok(AsyncTask::new(EncodeCursorTask { _lease: lease, shape }))
}
pub struct DecodeCursorTask { _lease: CursorLease, wire: Vec<u8> }
impl Task for DecodeCursorTask {
    type Output = remote_protocol::cursor::CursorShape;
    type JsValue = DecodedCursorShape;
    fn compute(&mut self) -> Result<Self::Output> {
        remote_protocol::Envelope::decode(&self.wire, MAX_CURSOR_WIRE_BYTES).map_err(js_error)?
            .cursor_shape().map_err(js_error)
    }
    fn resolve(&mut self, _: Env, shape: Self::Output) -> Result<Self::JsValue> {
        Ok(DecodedCursorShape { id: shape.id.to_string(), hotx: shape.hotx, hoty: shape.hoty,
            width: shape.width, height: shape.height, rgba: shape.rgba.into() })
    }
}
/// Parse a cursor-shape envelope and decompress it under the source limits.
/// This is untested and is not an audited native decompression sandbox.
#[napi]
pub fn decode_cursor_shape(wire: Buffer) -> Result<AsyncTask<DecodeCursorTask>> {
    if wire.len() > MAX_CURSOR_WIRE_BYTES { return Err(Error::from_reason("cursor envelope exceeds 2 MiB")); }
    let lease = CursorLease::acquire()?;
    Ok(AsyncTask::new(DecodeCursorTask { _lease: lease, wire: wire.to_vec() }))
}

/// Create a cursor-position envelope using the existing wire schema.
#[napi]
pub fn encode_cursor_position(x: i32, y: i32) -> Result<Buffer> {
    remote_protocol::Envelope::cursor_position_event(remote_protocol::cursor::CursorPosition { x, y })
        .encode(4096).map(Into::into).map_err(js_error)
}
/// Create a cursor-ID envelope. Decimal string IDs preserve all 64 bits.
#[napi]
pub fn encode_cursor_id(id: String) -> Result<Buffer> {
    remote_protocol::Envelope::cursor_id_event(cursor_id(&id)?)
        .encode(4096).map(Into::into).map_err(js_error)
}
