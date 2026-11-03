//! Persistent trusted-input-only video decoding. The native decoder and its
//! non-Send texture pointer stay on one dedicated thread until shutdown.
//! Native bitstream parsing is not hardened; this is NOT safe for a network
//! peer merely because it is pinned or password-authenticated.
use crate::js_error;
use napi::{bindgen_prelude::{AsyncTask, Buffer}, Env, Error, Result, Task};
use napi_derive::napi;
use remote_codec::Codec;
use remote_core::trusted_video_streams::{DecodeResult, TrustedOnly, TrustedVideoStreams};
use std::{sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, mpsc::{self, SyncSender}, Arc, Mutex}, thread};
use zeroize::Zeroizing;

const MAX_WORKERS: usize = 2;
const MAX_INPUT: usize = 16 * 1024 * 1024;
const MAX_OUTPUT: usize = 32 * 1024 * 1024;
static WORKERS: AtomicUsize = AtomicUsize::new(0);
struct WorkerLease;
impl WorkerLease {
    fn acquire() -> Result<Self> {
        WORKERS.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |n| (n < MAX_WORKERS).then_some(n + 1))
            .map(|_| Self).map_err(|_| Error::from_reason("maximum trusted decoder workers reached"))
    }
}
impl Drop for WorkerLease { fn drop(&mut self) { WORKERS.fetch_sub(1, Ordering::AcqRel); } }
struct State { sender: Mutex<Option<SyncSender<Command>>>, busy: AtomicBool, max_input: usize }
struct Busy(Arc<State>);
impl Busy {
    fn acquire(state: &Arc<State>) -> Result<Self> {
        state.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::from_reason("trusted decoder already has an operation in progress"))?;
        Ok(Self(state.clone()))
    }
}
impl Drop for Busy { fn drop(&mut self) { self.0.busy.store(false, Ordering::Release); } }

enum Operation { Register { display: i32, codec: Codec }, Decode(Zeroizing<Vec<u8>>), Reset(i32), Invalidate(i32), InvalidateAll, Remove(i32) }
struct Command { operation: Operation, reply: SyncSender<std::result::Result<Response, String>> }
pub enum Response { Ok, Removed(bool), AwaitKeyframe(i32), NoImage(i32), Image { display: i32, width: u32, height: u32, pixels: Zeroizing<Vec<u8>> } }

/// Dedicated worker owns all native state. The bounded request and reply
/// channels contain at most one operation/image each. When the last sender is
/// dropped it destroys the decoder on this thread and releases the lease.
fn run_worker(receiver: mpsc::Receiver<Command>, max_input: usize, max_output: usize, _lease: WorkerLease) {
    let trusted = TrustedOnly::acknowledge_native_decoder_is_not_safe_for_untrusted_input();
    let mut streams = match TrustedVideoStreams::new(max_input, max_output, trusted) { Ok(value) => value, Err(_) => return };
    while let Ok(command) = receiver.recv() {
        let (response, fatal) = match command.operation {
            Operation::Register { display, codec } => (streams.register(display, codec).map(|_| Response::Ok).map_err(|e| e.to_string()), false),
            Operation::Reset(display) => (streams.reset(display).map(|_| Response::Ok).map_err(|e| e.to_string()), false),
            Operation::Invalidate(display) => (streams.invalidate(display).map(|_| Response::Ok).map_err(|e| e.to_string()), false),
            Operation::InvalidateAll => { streams.invalidate_all(); (Ok(Response::Ok), false) },
            Operation::Remove(display) => (Ok(Response::Removed(streams.remove(display))), false),
            Operation::Decode(bytes) => match streams.decode(&bytes) {
                Ok(DecodeResult::AwaitKeyframe { display }) => (Ok(Response::AwaitKeyframe(display)), false),
                Ok(DecodeResult::NoImage { display }) => (Ok(Response::NoImage(display)), false),
                Ok(DecodeResult::Image(image)) => {
                    // Scrub worker-owned output on errors/cancelled replies;
                    // JavaScript Buffers and native decoder copies are outside
                    // this limited best-effort guarantee.
                    let pixels = Zeroizing::new(image.pixels);
                    if image.width > 4096 || image.height > 4096 {
                        (Err("decoded dimensions exceed Node limits".into()), true)
                    } else {
                        match (u32::try_from(image.width), u32::try_from(image.height)) {
                            (Ok(width), Ok(height)) => (Ok(Response::Image { display: image.display, width, height, pixels }), false),
                            _ => (Err("decoded dimensions exceed Node limits".into()), true),
                        }
                    }
                },
                // After any failed decode, close the whole worker: decoder state
                // and message loss may be uncertain. No retry on this instance.
                Err(error) => (Err(error.to_string()), true),
            },
        };
        // A dropped receiver means the consumer no longer owns the result; do
        // not continue decoding with unobserved state or retained screen data.
        if command.reply.send(response).is_err() || fatal { break; }
    }
}

#[napi(object)]
pub struct TrustedStreamResult {
    pub kind: String, pub display: Option<i32>, pub width: Option<u32>, pub height: Option<u32>,
    pub stride: Option<u32>, pub data: Option<Buffer>,
}
/// An independent thread-confined trusted decoder collection, not bound to a
/// Viewer or actual local consent. Close when unused; no OS/network cancellation.
#[napi]
pub struct TrustedVideoWorker { state: Arc<State> }
#[napi]
impl TrustedVideoWorker {
    /// Register one explicit software codec for a volatile display index.
    #[napi]
    pub fn register(&self, display: i32, codec: String) -> Result<AsyncTask<TrustedOperationTask>> {
        let codec = match codec.as_str() { "vp8" => Codec::Vp8, "vp9" => Codec::Vp9, "av1" => Codec::Av1,
            _ => return Err(Error::from_reason("trusted worker supports vp8, vp9 or av1")) };
        if display < 0 { return Err(Error::from_reason("display must be nonnegative")); }
        self.task(Operation::Register { display, codec })
    }
    /// Decode a locally produced trusted envelope in order. A decode error
    /// after the command reaches the thread closes the worker. Length/overlap
    /// errors are rejected before dispatch and do not close it; if input was
    /// lost, stop, close and recreate it before a fresh keyframe. No retries.
    #[napi]
    pub fn decode(&self, data: Buffer) -> Result<AsyncTask<TrustedOperationTask>> {
        if data.is_empty() || data.len() > self.state.max_input { return Err(Error::from_reason("invalid trusted video envelope size")); }
        let busy = Busy::acquire(&self.state)?;
        Ok(AsyncTask::new(TrustedOperationTask { state: self.state.clone(), _busy: busy,
            operation: Some(Operation::Decode(Zeroizing::new(data.to_vec()))) }))
    }
    /// Recreate one decoder; peer refresh/keyframe coordination is separate.
    #[napi]
    pub fn reset(&self, display: i32) -> Result<AsyncTask<TrustedOperationTask>> {
        if display < 0 { return Err(Error::from_reason("display must be nonnegative")); }
        self.task(Operation::Reset(display))
    }
    /// Discard one decoder after a known lost frame; call reset before reuse.
    /// Native memory/caller copies are not guaranteed erased. Trusted local
    /// input restriction remains unchanged.
    #[napi]
    pub fn invalidate(&self, display: i32) -> Result<AsyncTask<TrustedOperationTask>> {
        if display < 0 { return Err(Error::from_reason("display must be nonnegative")); }
        self.task(Operation::Invalidate(display))
    }
    /// Discard all decoders when a lost frame's display is unknown. Registered
    /// streams must each be explicitly reset and obtain a fresh keyframe.
    #[napi]
    pub fn invalidate_all(&self) -> Result<AsyncTask<TrustedOperationTask>> { self.task(Operation::InvalidateAll) }
    #[napi]
    pub fn remove(&self, display: i32) -> Result<AsyncTask<TrustedOperationTask>> {
        if display < 0 { return Err(Error::from_reason("display must be nonnegative")); }
        self.task(Operation::Remove(display))
    }
    /// Close the channel when no operation is in flight. The decoder is dropped
    /// asynchronously on its thread; this cannot interrupt a blocked native call.
    #[napi]
    pub fn close(&self) -> Result<()> {
        let _busy = Busy::acquire(&self.state)?;
        self.state.sender.lock().map_err(|_| Error::from_reason("trusted decoder state poisoned"))?.take(); Ok(())
    }
}
impl TrustedVideoWorker {
    fn task(&self, operation: Operation) -> Result<AsyncTask<TrustedOperationTask>> {
        let busy = Busy::acquire(&self.state)?;
        Ok(AsyncTask::new(TrustedOperationTask { state: self.state.clone(), _busy: busy, operation: Some(operation) }))
    }
}
pub struct TrustedOperationTask { state: Arc<State>, _busy: Busy, operation: Option<Operation> }
impl Task for TrustedOperationTask {
    type Output = Response; type JsValue = TrustedStreamResult;
    fn compute(&mut self) -> Result<Response> {
        let operation = self.operation.take().ok_or_else(|| Error::from_reason("trusted decoder task already consumed"))?;
        let sender = self.state.sender.lock().map_err(|_| Error::from_reason("trusted decoder state poisoned"))?
            .as_ref().cloned().ok_or_else(|| Error::from_reason("trusted decoder is closed"))?;
        let (reply, receiver) = mpsc::sync_channel(1);
        sender.try_send(Command { operation, reply }).map_err(|_| Error::from_reason("trusted decoder is closed or busy"))?;
        receiver.recv().map_err(|_| Error::from_reason("trusted decoder worker stopped"))?.map_err(Error::from_reason)
    }
    fn resolve(&mut self, _: Env, response: Response) -> Result<TrustedStreamResult> {
        let mut result = TrustedStreamResult { kind: String::new(), display: None, width: None, height: None, stride: None, data: None };
        match response {
            Response::Ok => result.kind = "ok".into(),
            Response::Removed(removed) => result.kind = if removed { "removed" } else { "notFound" }.into(),
            Response::AwaitKeyframe(display) => { result.kind = "awaitKeyframe".into(); result.display = Some(display); },
            Response::NoImage(display) => { result.kind = "noImage".into(); result.display = Some(display); },
            Response::Image { display, width, height, mut pixels } => {
                result.kind = "image".into(); result.display = Some(display); result.width = Some(width); result.height = Some(height);
                result.stride = Some(width.checked_mul(4).ok_or_else(|| Error::from_reason("decoded stride overflow"))?); result.data = Some(std::mem::take(&mut *pixels).into());
            },
        }
        Ok(result)
    }
}

/// Explicit trusted-only opt-in. The acknowledgement is not a security check.
/// The thread/decoder cap is process-local and does not bound native memory.
#[napi]
pub fn create_trusted_video_worker(max_input_bytes: u32, max_output_bytes: u32, acknowledge_local_trusted_input: bool) -> Result<TrustedVideoWorker> {
    if !acknowledge_local_trusted_input { return Err(Error::from_reason("explicit trusted local input acknowledgement required")); }
    let max_input = usize::try_from(max_input_bytes).map_err(js_error)?;
    let max_output = usize::try_from(max_output_bytes).map_err(js_error)?;
    if max_input == 0 || max_input > MAX_INPUT || max_output == 0 || max_output > MAX_OUTPUT {
        return Err(Error::from_reason("invalid trusted decoder limits"));
    }
    let lease = WorkerLease::acquire()?;
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new().name("remote-core-trusted-video".into()).spawn(move || run_worker(receiver, max_input, max_output, lease)).map_err(js_error)?;
    Ok(TrustedVideoWorker { state: Arc::new(State { sender: Mutex::new(Some(sender)), busy: AtomicBool::new(false), max_input }) })
}
