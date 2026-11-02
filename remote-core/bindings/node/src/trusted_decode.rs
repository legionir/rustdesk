//! Explicitly opt-in, bounded-batch *trusted input only* software decoding.
//! This is not a hardened decoder or an automatic network renderer: a malicious
//! compressed bitstream can allocate excessive native memory or exploit codec
//! libraries before any output bound is checked. Do not pass untrusted peers.

use crate::js_error;
use napi::{bindgen_prelude::{AsyncTask, Buffer}, Env, Error, Result, Task};
use napi_derive::napi;
use remote_codec::Codec;
use remote_core::{video::VideoReceiver, video_sync::{Decision, VideoSync}};
use remote_protocol::{Envelope, VideoCodec};
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_MESSAGES: usize = 32;
const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
static DECODE_BUSY: AtomicBool = AtomicBool::new(false);
struct DecodeLease;
impl DecodeLease {
    fn acquire() -> Result<Self> {
        DECODE_BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self).map_err(|_| Error::from_reason("another trusted decode is in progress"))
    }
}
impl Drop for DecodeLease { fn drop(&mut self) { DECODE_BUSY.store(false, Ordering::Release); } }

/// Packed libyuv ARGB output in the source byte convention. `data` is copied,
/// with `stride = width * 4`; it is not an HTML canvas RGBA format promise.
#[napi(object)]
pub struct TrustedDecodedImage { pub input_index: u32, pub display: i32, pub width: u32, pub height: u32, pub stride: u32, pub data: Buffer }
pub struct Image { input_index: u32, display: i32, width: u32, height: u32, stride: u32, data: Vec<u8> }
pub struct TrustedDecodeTask { _lease: DecodeLease, messages: Vec<Vec<u8>> }
impl Task for TrustedDecodeTask {
    type Output = Vec<Image>;
    type JsValue = Vec<TrustedDecodedImage>;
    fn compute(&mut self) -> Result<Self::Output> {
        let first = Envelope::decode(&self.messages[0], MAX_INPUT_BYTES).map_err(js_error)?;
        let initial = first.video().map_err(js_error)?;
        let display = initial.display;
        let wire_codec = initial.codec;
        let codec = match wire_codec {
            VideoCodec::Vp8 => Codec::Vp8, VideoCodec::Vp9 => Codec::Vp9, VideoCodec::Av1 => Codec::Av1,
            _ => return Err(Error::from_reason("trusted batch supports only VP8, VP9 and AV1")),
        };
        let mut sync = VideoSync::new(display, wire_codec).map_err(js_error)?;
        let mut decoder = VideoReceiver::new(codec, MAX_INPUT_BYTES).map_err(js_error)?;
        let mut images = Vec::new();
        let mut output_bytes = 0usize;
        for (index, wire) in self.messages.iter().enumerate() {
            let envelope = Envelope::decode(wire, MAX_INPUT_BYTES).map_err(js_error)?;
            if sync.begin(&envelope).map_err(js_error)? != Decision::Decode {
                return Err(Error::from_reason("trusted batch must start with a keyframe"));
            }
            let decoded = decoder.decode(wire).map_err(js_error)?;
            if let Some(image) = decoded {
                let w = image.frame.width; let h = image.frame.height;
                let stride = w.checked_mul(4).ok_or_else(|| Error::from_reason("decoded stride overflow"))?;
                let required = stride.checked_mul(h).ok_or_else(|| Error::from_reason("decoded size overflow"))?;
                if w == 0 || h == 0 || w > 4096 || h > 4096 || required != image.frame.data.len() {
                    return Err(Error::from_reason("unexpected decoded dimensions or layout"));
                }
                output_bytes = output_bytes.checked_add(required).ok_or_else(|| Error::from_reason("decoded output overflow"))?;
                if output_bytes > MAX_OUTPUT_BYTES { return Err(Error::from_reason("decoded batch exceeds 64 MiB copy limit")); }
                images.push(Image { input_index: index as u32, display: image.display, width: w as u32, height: h as u32,
                    stride: stride as u32, data: image.frame.data.to_vec() });
            }
            sync.complete(true).map_err(js_error)?;
        }
        Ok(images)
    }
    fn resolve(&mut self, _: Env, images: Self::Output) -> Result<Self::JsValue> {
        Ok(images.into_iter().map(|image| TrustedDecodedImage { input_index: image.input_index, display: image.display,
            width: image.width, height: image.height, stride: image.stride, data: image.data.into() }).collect())
    }
}

/// Decode one ordered, independent source video batch on a worker. Requires an
/// explicit trusted-input acknowledgement, starts a new decoder for each call,
/// and never automatically consumes a Viewer or network message. Limits apply
/// only to copied input/output, not native decoding or JS-retained memory.
#[napi]
pub fn decode_trusted_video_batch(messages: Vec<Buffer>, acknowledge_trusted_input_only: bool) -> Result<AsyncTask<TrustedDecodeTask>> {
    if !acknowledge_trusted_input_only { return Err(Error::from_reason("explicit trusted-input acknowledgement required")); }
    if messages.is_empty() || messages.len() > MAX_MESSAGES { return Err(Error::from_reason("invalid trusted batch length")); }
    let total = messages.iter().try_fold(0usize, |sum, message| sum.checked_add(message.len()))
        .ok_or_else(|| Error::from_reason("trusted batch input overflow"))?;
    if total == 0 || total > MAX_INPUT_BYTES || messages.iter().any(|message| message.is_empty()) {
        return Err(Error::from_reason("invalid trusted batch size"));
    }
    let lease = DecodeLease::acquire()?;
    Ok(AsyncTask::new(TrustedDecodeTask { _lease: lease, messages: messages.into_iter().map(|message| message.to_vec()).collect() }))
}
