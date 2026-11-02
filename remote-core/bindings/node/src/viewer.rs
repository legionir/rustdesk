//! Unverified Node binding for one strict pinned-source direct TCP viewer.
//! Not a complete SDK or audited security boundary. Passwords also remain in
//! JS memory outside Rust's zeroization control. All network and codec work is
//! experimental; never expose this to untrusted peers before review/testing.

use crate::js_error;
use hbb_common::sodiumoxide::{self, crypto::sign};
use napi::{bindgen_prelude::{AsyncTask, Buffer}, Env, Error, Result, Task};
use napi_derive::napi;
use remote_core::viewer_connection::{LoginIdentity, ViewerConnection, ViewerEvent};
use remote_protocol::{desktop::PeerInfo, Envelope, MouseEvent};
use remote_rustdesk_websocket::{direct_tcp::{DirectTcp, DirectTcpOptIn}, source_crypto::{connect_pinned_host, EncryptedTransport}};
use std::{net::SocketAddr, sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, Arc, Mutex, OnceLock}, time::{Duration, Instant}};
use zeroize::Zeroizing;

type NativeViewer = ViewerConnection<EncryptedTransport<DirectTcp>>;
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static VIEWERS: AtomicUsize = AtomicUsize::new(0);
const MAX_VIEWERS: usize = 8;
const PRE_AUTH_FRAME: usize = 128 * 1024;
const MAX_FRAME: usize = 16 * 1024 * 1024 - 16;

pub(crate) fn runtime() -> Result<&'static tokio::runtime::Runtime> {
    if let Some(rt) = RUNTIME.get() { return Ok(rt); }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().map_err(js_error)?;
    let _ = RUNTIME.set(rt); // Another worker may have installed a runtime first.
    RUNTIME.get().ok_or_else(|| Error::from_reason("cannot initialize network runtime"))
}
pub(crate) fn wait(ms: u32) -> Result<Duration> {
    if ms == 0 || ms > 180_000 { return Err(Error::from_reason("timeoutMs must be 1..180000")); }
    Ok(Duration::from_millis(ms.into()))
}
pub(crate) fn remaining(end: Instant) -> Result<Duration> {
    let value = end.saturating_duration_since(Instant::now());
    if value.is_zero() { Err(Error::from_reason("connection deadline expired")) } else { Ok(value) }
}
struct ViewerLease;
impl ViewerLease {
    fn acquire() -> Result<Self> {
        VIEWERS.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |n| (n < MAX_VIEWERS).then_some(n + 1))
            .map(|_| Self).map_err(|_| Error::from_reason("maximum viewer connections reached"))
    }
}
impl Drop for ViewerLease { fn drop(&mut self) { VIEWERS.fetch_sub(1, Ordering::AcqRel); } }
struct BusyLease(Arc<ViewerState>);
impl BusyLease {
    fn acquire(state: &Arc<ViewerState>) -> Result<Self> {
        state.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::from_reason("viewer already has an operation in progress"))?;
        Ok(Self(state.clone()))
    }
}
impl Drop for BusyLease { fn drop(&mut self) { self.0.busy.store(false, Ordering::Release); } }
struct ViewerState {
    viewer: Mutex<Option<NativeViewer>>,
    busy: AtomicBool,
    // Conservative capacity accounting: released only after the JS object and
    // any tasks referencing it are all dropped, even after explicit close.
    _lease: ViewerLease,
    info: PeerInfo,
}

/// Direct literal address and trusted host pin supplied by the application.
/// `password` remains in JavaScript memory; do not log options or reuse weak
/// passwords. The addon cannot verify that pin provisioning or consent is safe.
#[napi(object)]
pub struct ViewerOptions {
    pub address: String,
    pub expected_host_id: String,
    pub host_signing_key: Buffer,
    pub viewer_id: String,
    pub viewer_name: String,
    pub wire_session_id: String,
    pub version: String,
    pub password: String,
    pub timeout_ms: u32,
    pub max_message_bytes: u32,
}

/// Bounded metadata from a peer; still untrusted until verified by the caller.
#[napi(object)]
pub struct ViewerDisplayInfo {
    pub x: i32, pub y: i32, pub width: i32, pub height: i32,
    pub name: String, pub online: bool, pub cursor_embedded: bool, pub scale: f64,
}
#[napi(object)]
pub struct ViewerPeerInfo {
    pub username: String, pub hostname: String, pub platform: String, pub version: String,
    pub current_display: i32, pub displays: Vec<ViewerDisplayInfo>,
}
fn to_js_peer(info: &PeerInfo) -> ViewerPeerInfo {
    ViewerPeerInfo { username: info.username.clone(), hostname: info.hostname.clone(), platform: info.platform.clone(),
        version: info.version.clone(), current_display: info.current_display,
        displays: info.displays.iter().map(|d| ViewerDisplayInfo { x: d.x, y: d.y, width: d.width, height: d.height,
            name: d.name.clone(), online: d.online, cursor_embedded: d.cursor_embedded, scale: d.scale }).collect() }
}

/// Node handle around one viewer. Operations are serialized: there is no
/// simultaneous receive/send, queue, reconnect, renderer, decoder or host API.
#[napi]
pub struct Viewer { state: Arc<ViewerState> }
#[napi]
impl Viewer {
    /// Metadata from the initial login response; not a live display list.
    #[napi]
    pub fn peer_info(&self) -> ViewerPeerInfo { to_js_peer(&self.state.info) }
    /// Queue one restricted RustDesk mouse message on a worker.
    #[napi]
    pub fn send_mouse(&self, mask: i32, x: i32, y: i32, timeout_ms: u32) -> Result<AsyncTask<SendMouseTask>> {
        let deadline = wait(timeout_ms)?;
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(SendMouseTask { state: self.state.clone(), _busy: lease, event: MouseEvent { mask, x, y }, deadline }))
    }
    /// Send a legacy source control-key message. The host must independently
    /// authorize and support this key and the supplied source modifier values.
    #[napi]
    pub fn send_control_key(&self, control_key: i32, down: bool, press: bool, modifiers: Vec<i32>, timeout_ms: u32) -> Result<AsyncTask<SendWireInputTask>> {
        let deadline = wait(timeout_ms)?;
        let event = Envelope::legacy_keyboard_event(remote_protocol::input::LegacyKey::ControlKey(control_key), down, press, &modifiers).map_err(js_error)?;
        let wire = event.encode(8192).map_err(js_error)?;
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(SendWireInputTask { state: self.state.clone(), _busy: lease, wire, deadline }))
    }
    /// Send bounded legacy text. JS and protobuf may retain copies of the text.
    #[napi]
    pub fn send_text(&self, text: String, timeout_ms: u32) -> Result<AsyncTask<SendWireInputTask>> {
        let deadline = wait(timeout_ms)?;
        let event = Envelope::legacy_keyboard_event(remote_protocol::input::LegacyKey::Sequence(&text), false, false, &[]).map_err(js_error)?;
        let wire = event.encode(8192).map_err(js_error)?;
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(SendWireInputTask { state: self.state.clone(), _busy: lease, wire, deadline }))
    }
    /// Send a source mouse event with explicitly supplied source modifier values.
    #[napi]
    pub fn send_mouse_with_modifiers(&self, mask: i32, x: i32, y: i32, modifiers: Vec<i32>, timeout_ms: u32) -> Result<AsyncTask<SendWireInputTask>> {
        let deadline = wait(timeout_ms)?;
        let event = Envelope::mouse_event_with_modifiers(MouseEvent { mask, x, y }, &modifiers).map_err(js_error)?;
        let wire = event.encode(8192).map_err(js_error)?;
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(SendWireInputTask { state: self.state.clone(), _busy: lease, wire, deadline }))
    }
    /// Request a refresh of all displays; host support/rate limits vary.
    #[napi]
    pub fn request_refresh_all(&self, timeout_ms: u32) -> Result<AsyncTask<VideoControlTask>> {
        self.video_control_task(remote_protocol::video_control::VideoControl::RefreshAll, timeout_ms)
    }
    /// Request refresh for a current peer-reported display index.
    #[napi]
    pub fn request_refresh_display(&self, display: u32, timeout_ms: u32) -> Result<AsyncTask<VideoControlTask>> {
        if display > i32::MAX as u32 { return Err(Error::from_reason("display index exceeds wire range")); }
        self.video_control_task(remote_protocol::video_control::VideoControl::RefreshDisplay(display), timeout_ms)
    }
    /// Notify the host that a frame was processed; this is not automatic.
    #[napi]
    pub fn notify_video_received(&self, timeout_ms: u32) -> Result<AsyncTask<VideoControlTask>> {
        self.video_control_task(remote_protocol::video_control::VideoControl::FrameReceived, timeout_ms)
    }
    /// Receive one message on a worker. Receive timeout closes the connection.
    #[napi]
    pub fn receive(&self, timeout_ms: u32) -> Result<AsyncTask<ReceiveTask>> {
        let deadline = wait(timeout_ms)?;
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(ReceiveTask { state: self.state.clone(), _busy: lease, deadline }))
    }
    /// Close only when no operation is in flight. Dropping the last reference
    /// also closes it; explicit close is preferred. This does not wait for peer.
    #[napi]
    pub fn close(&self) -> Result<()> {
        let _busy = BusyLease::acquire(&self.state)?;
        let mut state = self.state.viewer.lock().map_err(|_| Error::from_reason("viewer state poisoned"))?;
        if let Some(mut viewer) = state.take() { viewer.close(); }
        Ok(())
    }
}

impl Viewer {
    fn video_control_task(&self, control: remote_protocol::video_control::VideoControl, timeout_ms: u32) -> Result<AsyncTask<VideoControlTask>> {
        let deadline = wait(timeout_ms)?;
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(VideoControlTask { state: self.state.clone(), _busy: lease, control, deadline }))
    }
}

pub struct VideoControlTask {
    state: Arc<ViewerState>, _busy: BusyLease,
    control: remote_protocol::video_control::VideoControl, deadline: Duration,
}
impl Task for VideoControlTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut lock = self.state.viewer.lock().map_err(|_| Error::from_reason("viewer state poisoned"))?;
        let viewer = lock.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        runtime()?.block_on(viewer.send_video_control(self.control, self.deadline)).map_err(js_error)
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { Ok(()) }
}

pub struct ConnectTask {
    _lease: Option<ViewerLease>, address: SocketAddr, host_id: String, host_key: [u8; 32],
    identity: LoginIdentity, password: Zeroizing<String>, deadline: Duration, max_message: usize,
}
impl Task for ConnectTask {
    type Output = (NativeViewer, PeerInfo);
    type JsValue = Viewer;
    fn compute(&mut self) -> Result<Self::Output> {
        sodiumoxide::init().map_err(|_| Error::from_reason("crypto initialization failed"))?;
        let pin = sign::PublicKey::from_slice(&self.host_key).ok_or_else(|| Error::from_reason("invalid host signing key"))?;
        let end = Instant::now().checked_add(self.deadline).ok_or_else(|| Error::from_reason("invalid deadline"))?;
        runtime()?.block_on(async {
            let socket = DirectTcp::connect(self.address, PRE_AUTH_FRAME, remaining(end)?, DirectTcpOptIn::acknowledge_plaintext_transport()).await.map_err(js_error)?;
            let secured = connect_pinned_host(socket, &self.host_id, &pin, PRE_AUTH_FRAME - 16, remaining(end)?).await.map_err(js_error)?;
            let mut viewer = ViewerConnection::new(secured, PRE_AUTH_FRAME - 16).map_err(js_error)?;
            let info = viewer.login(&self.identity, &self.password, remaining(end)?).await.map_err(js_error)?;
            viewer.set_connected_message_limit(self.max_message).map_err(js_error)?;
            Ok((viewer, info))
        })
    }
    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
        let lease = self._lease.take().ok_or_else(|| Error::from_reason("viewer lease unavailable"))?;
        Ok(Viewer { state: Arc::new(ViewerState { viewer: Mutex::new(Some(output.0)), busy: AtomicBool::new(false), _lease: lease, info: output.1 }) })
    }
}
/// Connect to a literal IP:port, pin the host's source Ed25519 public key, run
/// the source-compatible strict v1 exchange and basic password login. Requires
/// trusted key distribution and actual local host approval. Untested.
#[napi]
pub fn connect_viewer(mut options: ViewerOptions) -> Result<AsyncTask<ConnectTask>> {
    let deadline = wait(options.timeout_ms)?;
    let address = options.address.parse::<SocketAddr>().map_err(|_| Error::from_reason("address must be literal IP:port"))?;
    if options.host_signing_key.len() != 32 { return Err(Error::from_reason("hostSigningKey must be 32 bytes")); }
    if options.max_message_bytes == 0 || options.max_message_bytes as usize > MAX_FRAME { return Err(Error::from_reason("invalid maxMessageBytes")); }
    let wire_session_id = options.wire_session_id.parse::<u64>().map_err(|_| Error::from_reason("wireSessionId must be a decimal u64 string"))?;
    if wire_session_id.to_string() != options.wire_session_id { return Err(Error::from_reason("wireSessionId must be canonical decimal")); }
    if options.password.is_empty() || options.password.len() > 1024 { return Err(Error::from_reason("invalid password length")); }
    let lease = ViewerLease::acquire()?;
    let mut host_key = [0u8; 32]; host_key.copy_from_slice(&options.host_signing_key);
    let identity = LoginIdentity { target: options.expected_host_id.clone(), viewer_id: options.viewer_id,
        viewer_name: options.viewer_name, wire_session_id, version: options.version };
    Ok(AsyncTask::new(ConnectTask { _lease: Some(lease), address, host_id: options.expected_host_id, host_key,
        identity, password: Zeroizing::new(std::mem::take(&mut options.password)), deadline, max_message: options.max_message_bytes as usize }))
}

pub struct SendMouseTask { state: Arc<ViewerState>, _busy: BusyLease, event: MouseEvent, deadline: Duration }
impl Task for SendMouseTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut lock = self.state.viewer.lock().map_err(|_| Error::from_reason("viewer state poisoned"))?;
        let viewer = lock.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        runtime()?.block_on(viewer.send_input(&Envelope::mouse_event(self.event), self.deadline)).map_err(js_error)
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { Ok(()) }
}
pub struct SendWireInputTask { state: Arc<ViewerState>, _busy: BusyLease, wire: Vec<u8>, deadline: Duration }
impl Task for SendWireInputTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let event = Envelope::decode(&self.wire, 8192).map_err(js_error)?;
        let mut lock = self.state.viewer.lock().map_err(|_| Error::from_reason("viewer state poisoned"))?;
        let viewer = lock.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        runtime()?.block_on(viewer.send_input(&event, self.deadline)).map_err(js_error)
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { Ok(()) }
}
/// Incoming wire message. Video is compressed, `data` is not a decoded image.
#[napi(object)]
pub struct ViewerMessage {
    pub kind: String,
    pub data: Option<Buffer>,
    pub display: Option<i32>,
    pub codec: Option<String>,
    pub cursor_id: Option<String>,
    pub x: Option<i32>, pub y: Option<i32>,
    pub hotx: Option<i32>, pub hoty: Option<i32>,
    pub width: Option<i32>, pub height: Option<i32>,
    pub peer: Option<ViewerPeerInfo>,
}
pub struct ReceiveTask { state: Arc<ViewerState>, _busy: BusyLease, deadline: Duration }
impl Task for ReceiveTask {
    type Output = ViewerEvent;
    type JsValue = ViewerMessage;
    fn compute(&mut self) -> Result<ViewerEvent> {
        let mut lock = self.state.viewer.lock().map_err(|_| Error::from_reason("viewer state poisoned"))?;
        let viewer = lock.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        runtime()?.block_on(viewer.receive(self.deadline)).map_err(js_error)
    }
    fn resolve(&mut self, _: Env, event: ViewerEvent) -> Result<ViewerMessage> {
        let mut msg = ViewerMessage { kind: String::new(), data: None, display: None, codec: None, cursor_id: None,
            x: None, y: None, hotx: None, hoty: None, width: None, height: None, peer: None };
        match event {
            ViewerEvent::Video { display, codec, envelope } => {
                msg.kind = "video".into(); msg.data = Some(envelope.into_vec().into()); msg.display = Some(display);
                msg.codec = Some(format!("{codec:?}").to_ascii_lowercase());
            },
            ViewerEvent::CursorShape(shape) => {
                msg.kind = "cursorShape".into(); msg.cursor_id = Some(shape.id.to_string());
                msg.hotx = Some(shape.hotx); msg.hoty = Some(shape.hoty); msg.width = Some(shape.width); msg.height = Some(shape.height); msg.data = Some(shape.rgba.into());
            },
            ViewerEvent::CursorId(id) => { msg.kind = "cursorId".into(); msg.cursor_id = Some(id.to_string()); },
            ViewerEvent::CursorPosition(pos) => { msg.kind = "cursorPosition".into(); msg.x = Some(pos.x); msg.y = Some(pos.y); },
            ViewerEvent::TestDelay(_) => { msg.kind = "testDelay".into(); },
            ViewerEvent::PeerInfo(info) => { msg.kind = "peerInfo".into(); msg.peer = Some(to_js_peer(&info)); },
            ViewerEvent::Other(raw) => { msg.kind = "other".into(); msg.data = Some(raw.into_vec().into()); },
        }
        Ok(msg)
    }
}
