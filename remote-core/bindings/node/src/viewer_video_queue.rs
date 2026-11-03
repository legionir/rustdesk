//! Explicit per-display compressed frame queue; no decoder or viewer ownership.
use crate::js_error;
use napi::{bindgen_prelude::{AsyncTask, Buffer}, Env, Error, Result, Task};
use napi_derive::napi;
use remote_core::viewer_video_queue::{Completion, PushResult, ViewerVideoQueue};
use remote_protocol::VideoCodec;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};

struct State { queue: Mutex<ViewerVideoQueue>, busy: AtomicBool, message_limit: usize }
struct Busy(Arc<State>);
impl Busy {
    fn acquire(state: &Arc<State>) -> Result<Self> {
        state.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::from_reason("video queue already has an operation in progress"))?;
        Ok(Self(state.clone()))
    }
}
impl Drop for Busy { fn drop(&mut self) { self.0.busy.store(false, Ordering::Release); } }
fn token(value: &str) -> Result<u64> {
    let id = value.parse::<u64>().map_err(|_| Error::from_reason("ticket must be a canonical decimal u64"))?;
    if id.to_string() != value { return Err(Error::from_reason("ticket must be a canonical decimal u64")); }
    Ok(id)
}
#[napi(object)]
pub struct QueuePushResult { pub kind: String, pub discarded: u32 }
#[napi(object)]
pub struct QueueFrame { pub token: String, pub generation: String, pub keyframe: bool, pub data: Buffer }
#[napi(object)]
pub struct QueueStats { pub queued: u32, pub accounted_bytes: u32, pub generation: String, pub synced: bool }

/// Queue memory excludes JS buffers retained after completion, protobuf
/// parsing allocations and native decoders. No input is made safe by queuing.
#[napi]
pub struct ViewerVideoQueueHandle { state: Arc<State> }
#[napi]
impl ViewerVideoQueueHandle {
    /// Copy one encoded envelope and inspect it on a worker. Only one queue
    /// operation is allowed at a time; overlaps are rejected, not reordered.
    #[napi]
    pub fn push(&self, data: Buffer) -> Result<AsyncTask<QueuePushTask>> {
        if data.is_empty() || data.len() > self.state.message_limit { return Err(Error::from_reason("invalid video envelope length")); }
        let busy = Busy::acquire(&self.state)?;
        Ok(AsyncTask::new(QueuePushTask { state: self.state.clone(), _busy: busy, data: Some(data.to_vec().into_boxed_slice()) }))
    }
    /// Transfer the next buffer. The application must call `complete` with the
    /// ticket after attempting decode, or explicitly dispose of this queue.
    #[napi]
    pub fn pop(&self) -> Result<Option<QueueFrame>> {
        let _busy = Busy::acquire(&self.state)?;
        let mut queue = self.state.queue.lock().map_err(|_| Error::from_reason("video queue poisoned"))?;
        Ok(queue.pop().map_err(js_error)?.map(|frame| QueueFrame { token: frame.token.to_string(), generation: frame.generation.to_string(),
            keyframe: frame.keyframe, data: frame.bytes.into_vec().into() }))
    }
    #[napi]
    pub fn is_current(&self, value: String) -> Result<bool> {
        let id = token(&value)?; let _busy = Busy::acquire(&self.state)?;
        Ok(self.state.queue.lock().map_err(|_| Error::from_reason("video queue poisoned"))?.is_current(id))
    }
    /// Caller-reported result; it does not prove decoder success or rendering.
    #[napi]
    pub fn complete(&self, value: String, succeeded: bool) -> Result<String> {
        let id = token(&value)?; let _busy = Busy::acquire(&self.state)?;
        let completion = self.state.queue.lock().map_err(|_| Error::from_reason("video queue poisoned"))?.complete(id, succeeded).map_err(js_error)?;
        Ok(match completion { Completion::Applied => "applied", Completion::Stale => "stale", Completion::DecodeFailed => "decodeFailed" }.into())
    }
    /// Invalidates outstanding tickets and drops queued buffers. It cannot
    /// interrupt a decode or reclaim buffers already handed to JavaScript.
    #[napi]
    pub fn reset(&self) -> Result<u32> {
        let _busy = Busy::acquire(&self.state)?;
        let count = self.state.queue.lock().map_err(|_| Error::from_reason("video queue poisoned"))?.reset().map_err(js_error)?;
        u32::try_from(count).map_err(js_error)
    }
    #[napi]
    pub fn stats(&self) -> Result<QueueStats> {
        let _busy = Busy::acquire(&self.state)?;
        let queue = self.state.queue.lock().map_err(|_| Error::from_reason("video queue poisoned"))?;
        Ok(QueueStats { queued: u32::try_from(queue.len()).map_err(js_error)?, accounted_bytes: u32::try_from(queue.accounted_bytes()).map_err(js_error)?,
            generation: queue.generation().to_string(), synced: queue.synced() })
    }
}
pub struct QueuePushTask { state: Arc<State>, _busy: Busy, data: Option<Box<[u8]>> }
impl Task for QueuePushTask {
    type Output = PushResult; type JsValue = QueuePushResult;
    fn compute(&mut self) -> Result<PushResult> {
        let data = self.data.take().ok_or_else(|| Error::from_reason("video queue task already consumed"))?;
        self.state.queue.lock().map_err(|_| Error::from_reason("video queue poisoned"))?.push(data).map_err(js_error)
    }
    fn resolve(&mut self, _: Env, value: PushResult) -> Result<QueuePushResult> {
        let (kind, discarded) = match value {
            PushResult::Queued => ("queued", 0), PushResult::Keyframe { discarded } => ("keyframe", discarded),
            PushResult::AwaitKeyframe => ("awaitKeyframe", 0), PushResult::NeedRefresh { discarded } => ("needRefresh", discarded),
        };
        Ok(QueuePushResult { kind: kind.into(), discarded: u32::try_from(discarded).map_err(js_error)? })
    }
}
/// Create an isolated local queue for one negotiated display and codec. This
/// does not bind the queue to a viewer, prove support or authenticate a peer.
#[napi]
pub fn create_viewer_video_queue(display: i32, codec: String, max_frames: u32, max_bytes: u32, max_message_bytes: u32) -> Result<ViewerVideoQueueHandle> {
    let codec = match codec.as_str() {
        "vp8" => VideoCodec::Vp8, "vp9" => VideoCodec::Vp9, "av1" => VideoCodec::Av1,
        "h264" => VideoCodec::H264, "h265" => VideoCodec::H265,
        _ => return Err(Error::from_reason("unsupported encoded video variant")),
    };
    let message_limit = usize::try_from(max_message_bytes).map_err(js_error)?;
    let queue = ViewerVideoQueue::new(display, codec, usize::try_from(max_frames).map_err(js_error)?,
        usize::try_from(max_bytes).map_err(js_error)?, message_limit).map_err(js_error)?;
    Ok(ViewerVideoQueueHandle { state: Arc::new(State { queue: Mutex::new(queue), busy: AtomicBool::new(false), message_limit }) })
}
