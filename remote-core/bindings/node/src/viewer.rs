//! Unverified Node binding for one strict pinned-source direct TCP viewer.
//! Not a complete SDK or audited security boundary. Passwords also remain in
//! JS memory outside Rust's zeroization control. All network and codec work is
//! experimental; never expose this to untrusted peers before review/testing.

use crate::js_error;
use hbb_common::sodiumoxide::{self, crypto::sign};
use napi::{bindgen_prelude::{AsyncTask, Buffer}, Env, Error, Result, Task};
use napi_derive::napi;
use remote_core::viewer_connection::{LoginIdentity, TwoFactorSendOptIn, ViewerConnection, ViewerError, ViewerEvent};
use remote_protocol::{desktop::PeerInfo, Envelope, MouseEvent};
use remote_rustdesk_websocket::{direct_tcp::{DirectTcp, DirectTcpOptIn}, duplex_tcp::UpgradeableEncryptedTcp, source_crypto::{connect_pinned_host, EncryptedTransport}, strict_wss::StrictWss};
use std::{net::SocketAddr, sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, Arc, Mutex, OnceLock}, time::{Duration, Instant}};
use zeroize::{Zeroize, Zeroizing};

pub enum NativeViewer {
    Tcp(ViewerConnection<UpgradeableEncryptedTcp>),
    Wss(ViewerConnection<EncryptedTransport<StrictWss>>),
}
impl NativeViewer {
    async fn send_input(&mut self, event: &Envelope, wait: Duration) -> std::result::Result<(), ViewerError> {
        match self { Self::Tcp(v) => v.send_input(event, wait).await, Self::Wss(v) => v.send_input(event, wait).await }
    }
    async fn send_display_control(&mut self, event: &Envelope, wait: Duration) -> std::result::Result<(), ViewerError> {
        match self { Self::Tcp(v) => v.send_display_control(event, wait).await, Self::Wss(v) => v.send_display_control(event, wait).await }
    }
    async fn send_video_control(&mut self, event: remote_protocol::video_control::VideoControl, wait: Duration) -> std::result::Result<(), ViewerError> {
        match self { Self::Tcp(v) => v.send_video_control(event, wait).await, Self::Wss(v) => v.send_video_control(event, wait).await }
    }
    async fn send_video_preferences(&mut self, event: remote_protocol::video_preferences::VideoPreferences, wait: Duration) -> std::result::Result<(), ViewerError> {
        match self { Self::Tcp(v) => v.send_video_preferences(event, wait).await, Self::Wss(v) => v.send_video_preferences(event, wait).await }
    }
    async fn send_disable_keyboard(&mut self, disabled: bool, wait: Duration) -> std::result::Result<(), ViewerError> {
        match self { Self::Tcp(v) => v.send_disable_keyboard(disabled, wait).await, Self::Wss(v) => v.send_disable_keyboard(disabled, wait).await }
    }
    async fn send_cursor_preferences(&mut self, event: remote_protocol::cursor_preferences::CursorPreferences, wait: Duration) -> std::result::Result<(), ViewerError> {
        match self { Self::Tcp(v) => v.send_cursor_preferences(event, wait).await, Self::Wss(v) => v.send_cursor_preferences(event, wait).await }
    }
    async fn send_decoding_advertisement(&mut self, event: remote_protocol::DecodingAdvertisement, wait: Duration) -> std::result::Result<(), ViewerError> {
        match self { Self::Tcp(v) => v.send_decoding_advertisement(event, wait).await, Self::Wss(v) => v.send_decoding_advertisement(event, wait).await }
    }
    fn enable_duplex(&mut self) -> std::result::Result<(), ViewerError> {
        match self { Self::Tcp(v) => v.enable_duplex_read_ahead(), Self::Wss(_) => Err(ViewerError::InvalidState) }
    }
    async fn try_receive(&mut self, wait: Duration) -> std::result::Result<Option<ViewerEvent>, ViewerError> {
        match self { Self::Tcp(v) => v.try_receive(wait).await, Self::Wss(_) => Err(ViewerError::InvalidState) }
    }
    async fn request_cursor_shape(&mut self, id: u64, wait: Duration) -> std::result::Result<(), ViewerError> {
        match self { Self::Tcp(v) => v.request_cursor_shape(id, wait).await, Self::Wss(v) => v.request_cursor_shape(id, wait).await }
    }
    async fn receive(&mut self, wait: Duration) -> std::result::Result<ViewerEvent, ViewerError> {
        match self { Self::Tcp(v) => v.receive(wait).await, Self::Wss(v) => v.receive(wait).await }
    }
    fn original_resolutions(&self) -> Option<Vec<Option<remote_protocol::desktop::OriginalResolution>>> {
        match self { Self::Tcp(v) => v.original_resolutions().map(|values| values.to_vec()), Self::Wss(v) => v.original_resolutions().map(|values| values.to_vec()) }
    }
    fn windows_sessions(&self) -> Option<remote_protocol::windows_sessions::WindowsSessions> {
        match self { Self::Tcp(v) => v.windows_sessions().cloned(), Self::Wss(v) => v.windows_sessions().cloned() }
    }
    fn supported_modes(&self) -> Option<(u32, Vec<remote_protocol::resolution_metadata::Resolution>)> {
        match self {
            Self::Tcp(v) => v.supported_modes().map(|(display, modes)| (display, modes.to_vec())),
            Self::Wss(v) => v.supported_modes().map(|(display, modes)| (display, modes.to_vec())),
        }
    }
    async fn dispatch_fps(&mut self, decision: &remote_core::viewer_fps::Decision, mode: remote_core::viewer_fps::RefreshMode, wait: Duration) -> std::result::Result<usize, remote_core::viewer_fps::DispatchError> {
        match self { Self::Tcp(v) => remote_core::viewer_fps::dispatch(v, decision, mode, wait).await, Self::Wss(v) => remote_core::viewer_fps::dispatch(v, decision, mode, wait).await }
    }
    async fn send_close_reason(&mut self, reason: &str, wait: Duration) -> std::result::Result<(), ViewerError> {
        match self { Self::Tcp(v) => v.send_close_reason(reason, wait).await, Self::Wss(v) => v.send_close_reason(reason, wait).await }
    }
    fn close(&mut self) { match self { Self::Tcp(v) => v.close(), Self::Wss(v) => v.close() } }
}
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
    fn acquire_raw(state: &Arc<ViewerState>) -> Result<Self> {
        state.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::from_reason("viewer already has an operation in progress"))?;
        Ok(Self(state.clone()))
    }
    fn acquire(state: &Arc<ViewerState>) -> Result<Self> {
        if state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested")); }
        let lease = Self::acquire_raw(state)?;
        if state.close_signal.is_requested() { drop(lease); return Err(Error::from_reason("viewer close requested")); }
        Ok(lease)
    }
}
impl Drop for BusyLease {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
        // Drop cannot return an error. A poisoned slot remains unavailable;
        // its viewer is eventually dropped with the state as a last resort.
        let _ = finish_requested_close(&self.0);
    }
}
struct ViewerState {
    viewer: Mutex<Option<NativeViewer>>,
    busy: AtomicBool,
    close_signal: remote_transport::close_signal::CloseSignal,
    // Conservative capacity accounting: released only after the JS object and
    // any tasks referencing it are all dropped, even after explicit close.
    _lease: ViewerLease,
    info: PeerInfo,
}

// Close without waiting for the active worker. Recheck after releasing the
// busy flag in BusyLease::drop so a request racing that release is not lost.
fn finish_requested_close(state: &ViewerState) -> Result<()> {
    if !state.close_signal.is_requested() { return Ok(()); }
    if state.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { return Ok(()); }
    // This internal lease is deliberately not BusyLease: its Drop must not
    // recursively try to finish the same close request.
    struct BusyReset<'a>(&'a AtomicBool);
    impl Drop for BusyReset<'_> { fn drop(&mut self) { self.0.store(false, Ordering::Release); } }
    let _reset = BusyReset(&state.busy);
    let viewer = match state.viewer.lock() {
        Ok(mut slot) => Ok(slot.take()),
        Err(_) => Err(Error::from_reason("viewer state poisoned during close request")),
    };
    let result = match viewer { Ok(Some(mut viewer)) => { viewer.close(); Ok(()) }, Ok(None) => Ok(()), Err(error) => Err(error) };
    result
}

// This clears the Rust-owned option on all local validation failures. Copies in
// JavaScript, N-API, protobuf and transport allocations remain outside control.
fn take_two_factor(code: &mut Option<String>, acknowledged: Option<bool>) -> Result<Option<Zeroizing<String>>> {
    let code = code.take().map(Zeroizing::new);
    if code.is_some() != acknowledged.unwrap_or(false) { return Err(Error::from_reason("twoFactorCode requires explicit disclosure acknowledgement")); }
    if let Some(value) = code.as_ref() {
        if !(6..=8).contains(&value.len()) || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::from_reason("invalid two-factor code"));
        }
    }
    Ok(code)
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
    /// Explicitly request source ACK pacing; caller must send VideoReceived.
    pub video_ack_required: Option<bool>,
    /// Pre-obtained secret code; enabling requires explicit disclosure acknowledgement.
    pub two_factor_code: Option<String>,
    pub acknowledge_two_factor_disclosure: Option<bool>,
}

/// Bounded metadata from a peer; still untrusted until verified by the caller.
#[napi(object)]
pub struct ViewerDisplayInfo {
    pub x: i32, pub y: i32, pub width: i32, pub height: i32,
    pub name: String, pub online: bool, pub cursor_embedded: bool, pub scale: f64,
}
/// Peer-provided encoder claims, not a runtime probe.
#[napi(object)]
pub struct ViewerEncodingCapabilities {
    pub vp8: bool, pub av1: bool, pub h264: bool, pub h265: bool,
    pub i444_vp8: Option<bool>, pub i444_vp9: Option<bool>, pub i444_av1: Option<bool>, pub i444_h264: Option<bool>, pub i444_h265: Option<bool>,
}
fn to_js_encoding(value: remote_protocol::EncodingCapabilities) -> ViewerEncodingCapabilities {
    ViewerEncodingCapabilities { vp8: value.vp8, av1: value.av1, h264: value.h264, h265: value.h265,
        i444_vp8: value.i444.map(|c| c.vp8), i444_vp9: value.i444.map(|c| c.vp9), i444_av1: value.i444.map(|c| c.av1),
        i444_h264: value.i444.map(|c| c.h264), i444_h265: value.i444.map(|c| c.h265) }
}
#[napi(object)]
pub struct ViewerPeerInfo {
    pub username: String, pub hostname: String, pub platform: String, pub version: String,
    pub current_display: i32, pub displays: Vec<ViewerDisplayInfo>,
    pub sas_enabled: bool, pub encoding: Option<ViewerEncodingCapabilities>,
}
fn to_js_peer(info: &PeerInfo) -> ViewerPeerInfo {
    ViewerPeerInfo { username: info.username.clone(), hostname: info.hostname.clone(), platform: info.platform.clone(),
        version: info.version.clone(), current_display: info.current_display,
        displays: info.displays.iter().map(|d| ViewerDisplayInfo { x: d.x, y: d.y, width: d.width, height: d.height,
            name: d.name.clone(), online: d.online, cursor_embedded: d.cursor_embedded, scale: d.scale }).collect(),
        sas_enabled: info.sas_enabled, encoding: info.encoding.map(to_js_encoding) }
}

/// Explicit external decoder claims. The addon does not probe or install any
/// decoders, so only advertise implementations the application actually has.
#[napi(object)]
pub struct ViewerDecodingOptions {
    pub vp8: bool, pub vp9: bool, pub av1: bool, pub h264: bool, pub h265: bool,
    /// One of auto, vp8, vp9, av1, h264 or h265.
    pub preference: String,
}
fn decoding_options(options: ViewerDecodingOptions) -> Result<remote_protocol::DecodingAdvertisement> {
    use remote_protocol::CodecPreference;
    let preference = match options.preference.as_str() {
        "auto" => CodecPreference::Auto, "vp8" => CodecPreference::Vp8, "vp9" => CodecPreference::Vp9,
        "av1" => CodecPreference::Av1, "h264" => CodecPreference::H264, "h265" => CodecPreference::H265,
        _ => return Err(Error::from_reason("invalid decoding preference")),
    };
    Ok(remote_protocol::DecodingAdvertisement { vp8: options.vp8, vp9: options.vp9, av1: options.av1,
        h264: options.h264, h265: options.h265, preference })
}

/// Source tri-state cursor preferences. Missing fields mean unchanged.
#[napi(object)]
pub struct CursorPreferences {
    pub show_remote_cursor: Option<bool>, pub follow_remote_cursor: Option<bool>,
    pub follow_remote_window: Option<bool>, pub show_my_cursor: Option<bool>,
}
impl From<CursorPreferences> for remote_protocol::cursor_preferences::CursorPreferences {
    fn from(value: CursorPreferences) -> Self { Self { show_remote_cursor: value.show_remote_cursor, follow_remote_cursor: value.follow_remote_cursor,
        follow_remote_window: value.follow_remote_window, show_my_cursor: value.show_my_cursor } }
}
impl From<remote_protocol::cursor_preferences::CursorPreferences> for CursorPreferences {
    fn from(value: remote_protocol::cursor_preferences::CursorPreferences) -> Self { Self { show_remote_cursor: value.show_remote_cursor, follow_remote_cursor: value.follow_remote_cursor,
        follow_remote_window: value.follow_remote_window, show_my_cursor: value.show_my_cursor } }
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
    /// Latest untrusted original-resolution claims from login or the latest
    /// PeerInfo event, read on a worker. A null result means unavailable or
    /// invalid metadata. This does not measure DPI or authorize mode changes.
    #[napi]
    pub fn original_resolutions(&self) -> Result<AsyncTask<OriginalResolutionsTask>> {
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(OriginalResolutionsTask { state: self.state.clone(), _busy: lease }))
    }
    /// Latest supported-mode claims and their volatile display index, if any.
    /// This is not a mode probe or permission to change OS settings.
    #[napi]
    pub fn supported_modes(&self) -> Result<AsyncTask<SupportedModesTask>> {
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(SupportedModesTask { state: self.state.clone(), _busy: lease }))
    }
    /// Untrusted Windows login-session claims; this is not OS enumeration,
    /// consent or authorization to select a session.
    #[napi]
    pub fn windows_sessions(&self) -> Result<AsyncTask<ViewerWindowsSessionsTask>> {
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(ViewerWindowsSessionsTask { state: self.state.clone(), _busy: lease }))
    }
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
        let wire = Zeroizing::new(event.encode(8192).map_err(js_error)?);
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(SendWireInputTask { state: self.state.clone(), _busy: lease, wire, deadline }))
    }
    /// Send bounded legacy text. JS and protobuf may retain copies of the text.
    #[napi]
    pub fn send_text(&self, text: String, timeout_ms: u32) -> Result<AsyncTask<SendWireInputTask>> {
        let text = Zeroizing::new(text);
        let deadline = wait(timeout_ms)?;
        let event = remote_protocol::sensitive_input::SensitiveInputEnvelope::new(
            Envelope::legacy_keyboard_event(remote_protocol::input::LegacyKey::Sequence(&text), false, false, &[]).map_err(js_error)?);
        let wire = Zeroizing::new(event.encode(8192).map_err(js_error)?);
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(SendWireInputTask { state: self.state.clone(), _busy: lease, wire, deadline }))
    }
    /// Opt-in source Translate-mode text message, which may inject into the
    /// peer's focused application. The peer independently controls permission,
    /// focus and input state. Windows source truncates supplementary scalars,
    /// can release local Shift keys and can synthesize layout modifiers. This
    /// opt-in is not local or remote consent and delivery may be indeterminate.
    #[napi]
    pub fn send_windows_translate_text(&self, text: String, acknowledge_source_effects: bool, timeout_ms: u32) -> Result<AsyncTask<SendWireInputTask>> {
        let text = Zeroizing::new(text);
        if !acknowledge_source_effects { return Err(Error::from_reason("source Translate text effects must be acknowledged")); }
        let deadline = wait(timeout_ms)?;
        let event = remote_protocol::sensitive_input::SensitiveInputEnvelope::new(
            Envelope::windows_translate_sequence_event(&text).map_err(js_error)?);
        let wire = Zeroizing::new(event.encode(8192).map_err(js_error)?);
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(SendWireInputTask { state: self.state.clone(), _busy: lease, wire, deadline }))
    }
    /// Send a restricted Windows source Map-mode physical scan code. The
    /// remote host must explicitly authorize and support this mode.
    #[napi]
    pub fn send_windows_scan_code(&self, code: u32, down: bool, timeout_ms: u32) -> Result<AsyncTask<SendWireInputTask>> {
        let deadline = wait(timeout_ms)?;
        let event = Envelope::windows_scan_event(code, down).map_err(js_error)?;
        let wire = Zeroizing::new(event.encode(8192).map_err(js_error)?);
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(SendWireInputTask { state: self.state.clone(), _busy: lease, wire, deadline }))
    }
    /// Send a restricted Windows source Translate-mode position code. The
    /// remote host must explicitly authorize and support this mode.
    #[napi]
    pub fn send_windows_translate_code(&self, code: u32, down: bool, timeout_ms: u32) -> Result<AsyncTask<SendWireInputTask>> {
        let deadline = wait(timeout_ms)?;
        let event = Envelope::windows_translate_event(code, down).map_err(js_error)?;
        let wire = Zeroizing::new(event.encode(8192).map_err(js_error)?);
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(SendWireInputTask { state: self.state.clone(), _busy: lease, wire, deadline }))
    }
    /// Send source touch-scale input; zero ends the gesture. The target must
    /// independently grant mouse/keyboard access and enable this Windows path.
    #[napi]
    pub fn send_touch_scale(&self, scale: i32, timeout_ms: u32) -> Result<AsyncTask<SendWireInputTask>> {
        if !(-12_000..=12_000).contains(&scale) { return Err(Error::from_reason("touch scale delta is out of range")); }
        let event = Envelope::touch_event(remote_protocol::pointer::Touch::Scale(scale));
        let wire = Zeroizing::new(event.encode(8192).map_err(js_error)?);
        let deadline = wait(timeout_ms)?;
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(SendWireInputTask { state: self.state.clone(), _busy: lease, wire, deadline }))
    }
    /// Send a source mouse event with explicitly supplied source modifier values.
    #[napi]
    pub fn send_mouse_with_modifiers(&self, mask: i32, x: i32, y: i32, modifiers: Vec<i32>, timeout_ms: u32) -> Result<AsyncTask<SendWireInputTask>> {
        let deadline = wait(timeout_ms)?;
        let event = Envelope::mouse_event_with_modifiers(MouseEvent { mask, x, y }, &modifiers).map_err(js_error)?;
        let wire = Zeroizing::new(event.encode(8192).map_err(js_error)?);
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(SendWireInputTask { state: self.state.clone(), _busy: lease, wire, deadline }))
    }
    /// Request a display switch without changing host resolution. The host may
    /// refuse or ignore it; its display indices may have changed since login.
    #[napi]
    pub fn request_display(&self, display: u32, timeout_ms: u32) -> Result<AsyncTask<DisplayControlTask>> {
        let value = remote_protocol::display_control::DisplaySwitch { display, x: 0, y: 0, width: 0, height: 0, cursor_embedded: false };
        let event = Envelope::display_switch_event(&value).map_err(js_error)?;
        self.display_control_task(event, timeout_ms)
    }
    /// Send existing subscription lists. Empty lists request an empty set, which
    /// may unsubscribe every display. No capture or OS state is changed locally.
    #[napi]
    pub fn request_capture_displays(&self, add: Vec<u32>, sub: Vec<u32>, set: Vec<u32>, timeout_ms: u32) -> Result<AsyncTask<DisplayControlTask>> {
        let value = remote_protocol::display_control::CaptureDisplays { add, sub, set };
        let event = Envelope::capture_displays_event(&value).map_err(js_error)?;
        self.display_control_task(event, timeout_ms)
    }
    /// Ask the peer to change its OS resolution. This can affect the local
    /// user on that machine and requires explicit informed consent; the peer
    /// must independently authorize, validate and decide whether to apply it.
    #[napi]
    pub fn request_display_resolution(&self, display: u32, width: i32, height: i32,
        confirm_remote_resolution_change: bool, timeout_ms: u32) -> Result<AsyncTask<DisplayControlTask>> {
        if !confirm_remote_resolution_change { return Err(Error::from_reason("explicit remote resolution change confirmation required")); }
        let value = remote_protocol::display_control::DisplayResolution { display, width, height };
        self.display_control_task(Envelope::display_resolution_event(value).map_err(js_error)?, timeout_ms)
    }
    /// Request source display metadata. This does not switch a display.
    #[napi]
    pub fn query_display(&self, display: u32, timeout_ms: u32) -> Result<AsyncTask<DisplayControlTask>> {
        self.display_control_task(Envelope::display_query_event(display).map_err(js_error)?, timeout_ms)
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
    /// Send a source legacy auto-adjust frame-rate cap (1..120).
    #[napi]
    pub fn send_auto_adjust_fps(&self, fps: u32, timeout_ms: u32) -> Result<AsyncTask<VideoControlTask>> {
        if !(1..=120).contains(&fps) { return Err(Error::from_reason("fps must be 1..120")); }
        self.video_control_task(remote_protocol::video_control::VideoControl::AutoAdjustFps(fps), timeout_ms)
    }
    /// Report local recording state to the host. This does not record frames,
    /// and the host cannot verify this assertion from the protocol.
    #[napi]
    pub fn report_recording(&self, recording: bool, timeout_ms: u32) -> Result<AsyncTask<VideoControlTask>> {
        self.video_control_task(remote_protocol::video_control::VideoControl::ClientRecording(recording), timeout_ms)
    }
    /// Advertise externally verified decoder support using the existing source
    /// option message. This addon does not provide a network video decoder.
    #[napi]
    pub fn advertise_decoding(&self, options: ViewerDecodingOptions, timeout_ms: u32) -> Result<AsyncTask<AdvertiseDecodingTask>> {
        let capabilities = decoding_options(options)?;
        let deadline = wait(timeout_ms)?;
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(AdvertiseDecodingTask { state: self.state.clone(), _busy: lease, capabilities, deadline }))
    }
    /// Send untrusted source QoS preferences; zero means unchanged. Quality is
    /// the existing source value (2 low, 3 balanced, 4 best, otherwise packed
    /// custom). This does not cause automatic host encoder adaptation.
    #[napi]
    pub fn send_video_preferences(&self, image_quality: i32, fps: u32, timeout_ms: u32) -> Result<AsyncTask<VideoPreferencesTask>> {
        use remote_protocol::video_preferences::{Quality, VideoPreferences};
        let quality = match image_quality { 0 => None, 2 => Some(Quality::Low), 3 => Some(Quality::Balanced), 4 => Some(Quality::Best), n if n > 0 => Some(Quality::Custom(n)), _ => return Err(Error::from_reason("imageQuality must be nonnegative")) };
        if fps > 120 { return Err(Error::from_reason("fps must be 0..120")); }
        let preferences = VideoPreferences { quality, fps: if fps == 0 { None } else { Some(fps) } };
        let deadline = wait(timeout_ms)?; let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(VideoPreferencesTask { state: self.state.clone(), _busy: lease, preferences, deadline }))
    }
    /// Request source input disable/enable. False is not an authorization grant.
    #[napi]
    pub fn send_disable_keyboard(&self, disabled: bool, timeout_ms: u32) -> Result<AsyncTask<DisableKeyboardTask>> {
        let deadline = wait(timeout_ms)?; let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(DisableKeyboardTask { state: self.state.clone(), _busy: lease, disabled, deadline }))
    }
    /// Send cursor/follow requests. The host may ignore them; no permission is granted.
    #[napi]
    pub fn send_cursor_preferences(&self, preferences: CursorPreferences, timeout_ms: u32) -> Result<AsyncTask<CursorPreferencesTask>> {
        let deadline = wait(timeout_ms)?; let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(CursorPreferencesTask { state: self.state.clone(), _busy: lease, preferences: preferences.into(), deadline }))
    }
    /// Ask the host for a previously sent cursor shape; it may have been evicted.
    #[napi]
    pub fn request_cursor_shape(&self, id: String, timeout_ms: u32) -> Result<AsyncTask<RequestCursorTask>> {
        let value = id.parse::<u64>().map_err(|_| Error::from_reason("cursor ID must be a decimal u64 string"))?;
        if value.to_string() != id { return Err(Error::from_reason("cursor ID must be canonical decimal")); }
        let deadline = wait(timeout_ms)?;
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(RequestCursorTask { state: self.state.clone(), _busy: lease, id: value, deadline }))
    }
    /// Receive one message on a worker. Receive timeout closes the connection.
    #[napi]
    pub fn receive(&self, timeout_ms: u32) -> Result<AsyncTask<ReceiveTask>> {
        let deadline = wait(timeout_ms)?;
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(ReceiveTask { state: self.state.clone(), _busy: lease, deadline }))
    }
    /// Send a caller-approved FPS plan as existing source messages. Select the
    /// refresh compatibility mode explicitly; the peer may ignore all requests.
    /// This is not a measurement, consent decision or delivery acknowledgement.
    #[napi]
    pub fn dispatch_fps_decision(&self, decision: crate::viewer_fps::ViewerFpsDecision, per_display_refresh: bool,
        timeout_ms: u32) -> Result<AsyncTask<DispatchFpsTask>> {
        if decision.custom_fps.map_or(false, |fps| !(1..=120).contains(&fps)) || decision.refresh.len() > 8
            || decision.refresh.iter().any(|display| *display > i32::MAX as u32)
            || decision.refresh.iter().copied().collect::<std::collections::BTreeSet<_>>().len() != decision.refresh.len() {
            return Err(Error::from_reason("invalid FPS decision"));
        }
        let deadline = wait(timeout_ms)?; let lease = BusyLease::acquire(&self.state)?;
        let plan = remote_core::viewer_fps::Decision { custom_fps: decision.custom_fps, refresh: decision.refresh, min_decode_fps: decision.min_decode_fps };
        let mode = if per_display_refresh { remote_core::viewer_fps::RefreshMode::PerDisplay } else { remote_core::viewer_fps::RefreshMode::All };
        Ok(AsyncTask::new(DispatchFpsTask { state: self.state.clone(), _busy: lease, decision: plan, mode, deadline }))
    }
    /// Enable experimental direct-TCP read-ahead after successful login.
    /// WSS is not supported; this does not make decoder input safe.
    #[napi]
    pub fn enable_duplex_read_ahead(&self, acknowledge_experimental: bool) -> Result<AsyncTask<EnableViewerDuplexTask>> {
        if !acknowledge_experimental { return Err(Error::from_reason("explicit experimental duplex acknowledgement required")); }
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(EnableViewerDuplexTask { state: self.state.clone(), _busy: lease }))
    }
    /// Non-destructive local queue poll after enabling direct-TCP read-ahead.
    /// Returning null means no queued message, not a network timeout.
    #[napi]
    pub fn try_receive(&self, send_timeout_ms: u32) -> Result<AsyncTask<TryViewerReceiveTask>> {
        let deadline = wait(send_timeout_ms)?; let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(TryViewerReceiveTask { state: self.state.clone(), _busy: lease, deadline }))
    }
    /// Request terminal local closure without waiting for a worker. Network
    /// cancellation may already have delivered a message; no retries are safe.
    /// Native synchronous work and runtime stalls cannot be interrupted. The
    /// viewer count remains reserved until the JS handle/tasks are dropped.
    #[napi]
    pub fn request_close(&self) -> Result<()> {
        self.state.close_signal.request();
        finish_requested_close(&self.state)
    }
    /// Send one best-effort source CloseReason and close locally. Delivery is
    /// not acknowledged and an indeterminate failure must not be retried.
    #[napi]
    pub fn send_close_reason(&self, reason: String, timeout_ms: u32) -> Result<AsyncTask<ViewerCloseReasonTask>> {
        let reason = Zeroizing::new(reason);
        Envelope::close_reason_event(&reason).map_err(js_error)?;
        let deadline = wait(timeout_ms)?;
        let busy = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(ViewerCloseReasonTask { state: self.state.clone(), _busy: busy, reason, deadline }))
    }
    /// Close only when no operation is in flight. Dropping the last reference
    /// also closes it; explicit close is preferred. This does not wait for peer.
    #[napi]
    pub fn close(&self) -> Result<()> {
        let _busy = BusyLease::acquire_raw(&self.state)?;
        let mut state = self.state.viewer.lock().map_err(|_| Error::from_reason("viewer state poisoned"))?;
        if let Some(mut viewer) = state.take() { viewer.close(); }
        Ok(())
    }
}

impl Viewer {
    fn display_control_task(&self, event: Envelope, timeout_ms: u32) -> Result<AsyncTask<DisplayControlTask>> {
        let deadline = wait(timeout_ms)?;
        let wire = event.encode(8192).map_err(js_error)?;
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(DisplayControlTask { state: self.state.clone(), _busy: lease, wire, deadline }))
    }
    fn video_control_task(&self, control: remote_protocol::video_control::VideoControl, timeout_ms: u32) -> Result<AsyncTask<VideoControlTask>> {
        let deadline = wait(timeout_ms)?;
        let lease = BusyLease::acquire(&self.state)?;
        Ok(AsyncTask::new(VideoControlTask { state: self.state.clone(), _busy: lease, control, deadline }))
    }
}

// A close request drops the network future; delivery is indeterminate.
async fn until_close<T>(state: &ViewerState, future: impl std::future::Future<Output = T>) -> Option<T> {
    state.close_signal.race(future).await
}
macro_rules! viewer_io {
    ($state:expr, $viewer:ident, $future:expr) => {{
        let state = $state;
        let result = runtime()?.block_on(until_close(state, $future));
        match result {
            Some(result) if !state.close_signal.is_requested() => result.map_err(js_error),
            _ => { $viewer.close(); Err(Error::from_reason("viewer close requested; delivery may be indeterminate")) },
        }
    }};
}

// BusyLease excludes other viewer operations. The mutex is never held while
// network futures run; on panic/drop the native viewer is restored or closed.
struct ViewerCheckout { state: Arc<ViewerState>, viewer: Option<NativeViewer> }
impl ViewerCheckout {
    fn take(state: &Arc<ViewerState>) -> Result<Self> {
        let viewer = state.viewer.lock().map_err(|_| Error::from_reason("viewer state poisoned"))?.take()
            .ok_or_else(|| Error::from_reason("viewer is closed"))?;
        Ok(Self { state: state.clone(), viewer: Some(viewer) })
    }
}
impl Drop for ViewerCheckout {
    fn drop(&mut self) {
        // A panic may leave an in-flight send or receive indeterminate. Do not
        // restore a potentially live connection in a half-completed phase.
        if std::thread::panicking() { self.state.close_signal.request(); }
        if self.state.close_signal.is_requested() {
            if let Some(mut viewer) = self.viewer.take() { viewer.close(); }
        }
        if let Ok(mut slot) = self.state.viewer.lock() {
            if slot.is_none() { *slot = self.viewer.take(); }
        }
        // Poison or an unexpected occupied slot drops the remaining viewer;
        // ViewerConnection's Drop performs best-effort transport cleanup.
    }
}
pub struct ViewerCloseReasonTask { state: Arc<ViewerState>, _busy: BusyLease, reason: Zeroizing<String>, deadline: Duration }
impl Task for ViewerCloseReasonTask {
    type Output = (); type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut checkout = ViewerCheckout::take(&self.state)?;
        let viewer = checkout.viewer.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        let result = (|| viewer_io!(&self.state, viewer, viewer.send_close_reason(&self.reason, self.deadline)))();
        self.state.close_signal.request();
        result
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { Ok(()) }
}

pub struct DispatchFpsTask { state: Arc<ViewerState>, _busy: BusyLease, decision: remote_core::viewer_fps::Decision,
    mode: remote_core::viewer_fps::RefreshMode, deadline: Duration }
impl Task for DispatchFpsTask {
    type Output = u32; type JsValue = u32;
    fn compute(&mut self) -> Result<u32> {
        let mut checkout = ViewerCheckout::take(&self.state)?;
        let result = {
            let viewer = checkout.viewer.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
            viewer_io!(&self.state, viewer, viewer.dispatch_fps(&self.decision, self.mode, self.deadline))
        };
        match result {
            Ok(sent) => u32::try_from(sent).map_err(js_error),
            Err(error) => {
                // A failed batch can be partially delivered. Close rather than
                // let JS retry on an ambiguous connection; tracker reset is separate.
                if let Some(mut viewer) = checkout.viewer.take() { viewer.close(); }
                Err(error)
            },
        }
    }
    fn resolve(&mut self, _: Env, sent: u32) -> Result<u32> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested; delivery may be indeterminate")); } Ok(sent) }
}

pub struct EnableViewerDuplexTask { state: Arc<ViewerState>, _busy: BusyLease }
impl Task for EnableViewerDuplexTask {
    type Output = (); type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut checkout = ViewerCheckout::take(&self.state)?;
        let viewer = checkout.viewer.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        viewer_io!(&self.state, viewer, async { viewer.enable_duplex() })
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested; delivery may be indeterminate")); } Ok(()) }
}

pub struct DisplayControlTask { state: Arc<ViewerState>, _busy: BusyLease, wire: Vec<u8>, deadline: Duration }
impl Task for DisplayControlTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let event = Envelope::decode(&self.wire, 8192).map_err(js_error)?;
        let mut checkout = ViewerCheckout::take(&self.state)?;
        let viewer = checkout.viewer.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        viewer_io!(&self.state, viewer, viewer.send_display_control(&event, self.deadline))
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested; delivery may be indeterminate")); } Ok(()) }
}

pub struct VideoControlTask {
    state: Arc<ViewerState>, _busy: BusyLease,
    control: remote_protocol::video_control::VideoControl, deadline: Duration,
}
impl Task for VideoControlTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut checkout = ViewerCheckout::take(&self.state)?;
        let viewer = checkout.viewer.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        viewer_io!(&self.state, viewer, viewer.send_video_control(self.control, self.deadline))
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested; delivery may be indeterminate")); } Ok(()) }
}

pub struct AdvertiseDecodingTask {
    state: Arc<ViewerState>, _busy: BusyLease,
    capabilities: remote_protocol::DecodingAdvertisement, deadline: Duration,
}
impl Task for AdvertiseDecodingTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut checkout = ViewerCheckout::take(&self.state)?;
        let viewer = checkout.viewer.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        viewer_io!(&self.state, viewer, viewer.send_decoding_advertisement(self.capabilities, self.deadline))
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested; delivery may be indeterminate")); } Ok(()) }
}

pub struct VideoPreferencesTask { state: Arc<ViewerState>, _busy: BusyLease, preferences: remote_protocol::video_preferences::VideoPreferences, deadline: Duration }
impl Task for VideoPreferencesTask {
    type Output = (); type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut checkout = ViewerCheckout::take(&self.state)?;
        let viewer = checkout.viewer.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        viewer_io!(&self.state, viewer, viewer.send_video_preferences(self.preferences, self.deadline))
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested; delivery may be indeterminate")); } Ok(()) }
}

pub struct DisableKeyboardTask { state: Arc<ViewerState>, _busy: BusyLease, disabled: bool, deadline: Duration }
impl Task for DisableKeyboardTask {
    type Output = (); type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut checkout = ViewerCheckout::take(&self.state)?;
        let viewer = checkout.viewer.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        viewer_io!(&self.state, viewer, viewer.send_disable_keyboard(self.disabled, self.deadline))
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested; delivery may be indeterminate")); } Ok(()) }
}

pub struct CursorPreferencesTask { state: Arc<ViewerState>, _busy: BusyLease, preferences: remote_protocol::cursor_preferences::CursorPreferences, deadline: Duration }
impl Task for CursorPreferencesTask {
    type Output = (); type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut checkout = ViewerCheckout::take(&self.state)?;
        let viewer = checkout.viewer.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        viewer_io!(&self.state, viewer, viewer.send_cursor_preferences(self.preferences, self.deadline))
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested; delivery may be indeterminate")); } Ok(()) }
}

pub struct RequestCursorTask { state: Arc<ViewerState>, _busy: BusyLease, id: u64, deadline: Duration }
impl Task for RequestCursorTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut checkout = ViewerCheckout::take(&self.state)?;
        let viewer = checkout.viewer.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        viewer_io!(&self.state, viewer, viewer.request_cursor_shape(self.id, self.deadline))
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested; delivery may be indeterminate")); } Ok(()) }
}

pub struct ConnectTask {
    cancel: Arc<remote_transport::close_signal::CloseSignal>,
    _lease: Option<ViewerLease>, address: SocketAddr, host_id: String, host_key: [u8; 32],
    identity: LoginIdentity, password: Zeroizing<String>, two_factor_code: Option<Zeroizing<String>>, deadline: Duration, max_message: usize, video_ack_required: bool,
}
impl Task for ConnectTask {
    type Output = (NativeViewer, PeerInfo);
    type JsValue = Viewer;
    fn compute(&mut self) -> Result<Self::Output> {
        if self.cancel.is_requested() { return Err(Error::from_reason("viewer connection cancelled")); }
        sodiumoxide::init().map_err(|_| Error::from_reason("crypto initialization failed"))?;
        let pin = sign::PublicKey::from_slice(&self.host_key).ok_or_else(|| Error::from_reason("invalid host signing key"))?;
        let end = Instant::now().checked_add(self.deadline).ok_or_else(|| Error::from_reason("invalid deadline"))?;
        let cancel = self.cancel.clone();
        let result = runtime()?.block_on(cancel.race(async {
            let socket = DirectTcp::connect(self.address, PRE_AUTH_FRAME, remaining(end)?, DirectTcpOptIn::acknowledge_plaintext_transport()).await.map_err(js_error)?;
            let secured = connect_pinned_host(socket, &self.host_id, &pin, PRE_AUTH_FRAME - 16, remaining(end)?).await.map_err(js_error)?;
            let mut viewer = ViewerConnection::new(UpgradeableEncryptedTcp::new(secured), PRE_AUTH_FRAME - 16).map_err(js_error)?;
            let info = if let Some(code) = self.two_factor_code.as_ref() {
                viewer.login_with_two_factor_options(&self.identity, &self.password, code, None, None, self.video_ack_required,
                    TwoFactorSendOptIn::acknowledge_code_disclosure_to_peer(), remaining(end)?).await
            } else if self.video_ack_required {
                viewer.login_with_ack(&self.identity, &self.password, None, None, remaining(end)?).await
            } else { viewer.login(&self.identity, &self.password, remaining(end)?).await }.map_err(js_error)?;
            viewer.set_connected_message_limit(self.max_message).map_err(js_error)?;
            Ok((NativeViewer::Tcp(viewer), info))
        }));
        drop(self.two_factor_code.take());
        match result {
            Some(result) if !cancel.is_requested() => result,
            _ => Err(Error::from_reason("viewer connection cancelled; peer may have received data")),
        }
    }
    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
        if self.cancel.is_requested() { return Err(Error::from_reason("viewer connection cancelled; peer may have received data")); }
        let lease = self._lease.take().ok_or_else(|| Error::from_reason("viewer lease unavailable"))?;
        Ok(Viewer { state: Arc::new(ViewerState { viewer: Mutex::new(Some(output.0)), busy: AtomicBool::new(false), close_signal: remote_transport::close_signal::CloseSignal::new(), _lease: lease, info: output.1 }) })
    }
}
/// Connect to a literal IP:port, pin the host's source Ed25519 public key, run
/// the source-compatible strict v1 exchange and basic password login. Requires
/// trusted key distribution and actual local host approval. Untested.
#[napi]
pub fn connect_viewer(options: ViewerOptions) -> Result<AsyncTask<ConnectTask>> {
    connect_viewer_with_signal(options, Arc::new(remote_transport::close_signal::CloseSignal::new()))
}
fn connect_viewer_with_signal(mut options: ViewerOptions, cancel: Arc<remote_transport::close_signal::CloseSignal>) -> Result<AsyncTask<ConnectTask>> {
    let password = Zeroizing::new(std::mem::take(&mut options.password));
    let two_factor_code = take_two_factor(&mut options.two_factor_code, options.acknowledge_two_factor_disclosure)?;
    let deadline = wait(options.timeout_ms)?;
    let address = options.address.parse::<SocketAddr>().map_err(|_| Error::from_reason("address must be literal IP:port"))?;
    if options.host_signing_key.len() != 32 { return Err(Error::from_reason("hostSigningKey must be 32 bytes")); }
    if options.max_message_bytes == 0 || options.max_message_bytes as usize > MAX_FRAME { return Err(Error::from_reason("invalid maxMessageBytes")); }
    let wire_session_id = options.wire_session_id.parse::<u64>().map_err(|_| Error::from_reason("wireSessionId must be a decimal u64 string"))?;
    if wire_session_id.to_string() != options.wire_session_id { return Err(Error::from_reason("wireSessionId must be canonical decimal")); }
    if password.is_empty() || password.len() > 1024 { return Err(Error::from_reason("invalid password length")); }
    let lease = ViewerLease::acquire()?;
    let mut host_key = [0u8; 32]; host_key.copy_from_slice(&options.host_signing_key);
    let identity = LoginIdentity { target: options.expected_host_id.clone(), viewer_id: options.viewer_id,
        viewer_name: options.viewer_name, wire_session_id, version: options.version };
    Ok(AsyncTask::new(ConnectTask { cancel, _lease: Some(lease), address, host_id: options.expected_host_id, host_key,
        identity, password, two_factor_code, deadline, max_message: options.max_message_bytes as usize, video_ack_required: options.video_ack_required.unwrap_or(false) }))
}

/// WSS endpoint and independently pinned desktop host identity. The WSS
/// server can observe traffic metadata and is not itself the desktop identity.
/// Only trusted applications should choose endpoint URLs; SSRF is not prevented.
#[napi(object)]
pub struct WssViewerOptions {
    pub endpoint: String, pub expected_host_id: String, pub host_signing_key: Buffer,
    pub viewer_id: String, pub viewer_name: String, pub wire_session_id: String, pub version: String,
    pub password: String, pub timeout_ms: u32, pub max_message_bytes: u32,
    /// Explicitly request source ACK pacing; caller must send VideoReceived.
    pub video_ack_required: Option<bool>,
    /// Pre-obtained secret code; enabling requires explicit disclosure acknowledgement.
    pub two_factor_code: Option<String>,
    pub acknowledge_two_factor_disclosure: Option<bool>,
}
pub struct WssConnectTask {
    cancel: Arc<remote_transport::close_signal::CloseSignal>,
    lease: Option<ViewerLease>, endpoint: String, host_id: String, host_key: [u8; 32],
    identity: LoginIdentity, password: Zeroizing<String>, two_factor_code: Option<Zeroizing<String>>, deadline: Duration, max_message: usize, video_ack_required: bool,
}
impl Task for WssConnectTask {
    type Output = (NativeViewer, PeerInfo);
    type JsValue = Viewer;
    fn compute(&mut self) -> Result<Self::Output> {
        if self.cancel.is_requested() { return Err(Error::from_reason("viewer connection cancelled")); }
        sodiumoxide::init().map_err(|_| Error::from_reason("crypto initialization failed"))?;
        let pin = sign::PublicKey::from_slice(&self.host_key).ok_or_else(|| Error::from_reason("invalid host signing key"))?;
        let end = Instant::now().checked_add(self.deadline).ok_or_else(|| Error::from_reason("invalid deadline"))?;
        let cancel = self.cancel.clone();
        let result = runtime()?.block_on(cancel.race(async {
            let socket = StrictWss::connect(&self.endpoint, PRE_AUTH_FRAME, remaining(end)?).await.map_err(js_error)?;
            let secured = connect_pinned_host(socket, &self.host_id, &pin, PRE_AUTH_FRAME - 16, remaining(end)?).await.map_err(js_error)?;
            let mut viewer = ViewerConnection::new(secured, PRE_AUTH_FRAME - 16).map_err(js_error)?;
            let info = if let Some(code) = self.two_factor_code.as_ref() {
                viewer.login_with_two_factor_options(&self.identity, &self.password, code, None, None, self.video_ack_required,
                    TwoFactorSendOptIn::acknowledge_code_disclosure_to_peer(), remaining(end)?).await
            } else if self.video_ack_required {
                viewer.login_with_ack(&self.identity, &self.password, None, None, remaining(end)?).await
            } else { viewer.login(&self.identity, &self.password, remaining(end)?).await }.map_err(js_error)?;
            viewer.set_connected_message_limit(self.max_message).map_err(js_error)?;
            Ok((NativeViewer::Wss(viewer), info))
        }));
        drop(self.two_factor_code.take());
        match result {
            Some(result) if !cancel.is_requested() => result,
            _ => Err(Error::from_reason("viewer connection cancelled; peer may have received data")),
        }
    }
    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Viewer> {
        if self.cancel.is_requested() { return Err(Error::from_reason("viewer connection cancelled; peer may have received data")); }
        let lease = self.lease.take().ok_or_else(|| Error::from_reason("viewer lease unavailable"))?;
        Ok(Viewer { state: Arc::new(ViewerState { viewer: Mutex::new(Some(output.0)), busy: AtomicBool::new(false), close_signal: remote_transport::close_signal::CloseSignal::new(), _lease: lease, info: output.1 }) })
    }
}
/// Strict TLS WSS with a separate pinned RustDesk host exchange. Does not
/// configure a relay, authenticate a relay route, prevent SSRF, or prove that a
/// Cloudflare deployment is compatible. This interface is unbuilt and untested.
#[napi]
pub fn connect_wss_viewer(options: WssViewerOptions) -> Result<AsyncTask<WssConnectTask>> {
    connect_wss_viewer_with_signal(options, Arc::new(remote_transport::close_signal::CloseSignal::new()))
}
fn connect_wss_viewer_with_signal(mut options: WssViewerOptions, cancel: Arc<remote_transport::close_signal::CloseSignal>) -> Result<AsyncTask<WssConnectTask>> {
    let password = Zeroizing::new(std::mem::take(&mut options.password));
    let two_factor_code = take_two_factor(&mut options.two_factor_code, options.acknowledge_two_factor_disclosure)?;
    let deadline = wait(options.timeout_ms)?;
    StrictWss::validate_endpoint(&options.endpoint).map_err(|_| Error::from_reason("invalid WSS endpoint"))?;
    if options.host_signing_key.len() != 32 { return Err(Error::from_reason("hostSigningKey must be 32 bytes")); }
    if options.max_message_bytes == 0 || options.max_message_bytes as usize > MAX_FRAME { return Err(Error::from_reason("invalid maxMessageBytes")); }
    let wire_session_id = options.wire_session_id.parse::<u64>().map_err(|_| Error::from_reason("wireSessionId must be a decimal u64 string"))?;
    if wire_session_id.to_string() != options.wire_session_id { return Err(Error::from_reason("wireSessionId must be canonical decimal")); }
    if password.is_empty() || password.len() > 1024 { return Err(Error::from_reason("invalid password length")); }
    let lease = ViewerLease::acquire()?;
    let mut host_key = [0u8; 32]; host_key.copy_from_slice(&options.host_signing_key);
    let identity = LoginIdentity { target: options.expected_host_id.clone(), viewer_id: options.viewer_id,
        viewer_name: options.viewer_name, wire_session_id, version: options.version };
    Ok(AsyncTask::new(WssConnectTask { cancel, lease: Some(lease), endpoint: options.endpoint, host_id: options.expected_host_id, host_key,
        identity, password, two_factor_code, deadline, max_message: options.max_message_bytes as usize, video_ack_required: options.video_ack_required.unwrap_or(false) }))
}

/// One-shot cancellation handle for a viewer connection attempt. It must not
/// be reused for a second attempt; cancellation after delivery does not close
/// the returned Viewer, which has its own terminal close request.
#[napi]
pub struct ViewerConnectRequest {
    cancel: Arc<remote_transport::close_signal::CloseSignal>,
    started: AtomicBool,
}
#[napi]
impl ViewerConnectRequest {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self { cancel: Arc::new(remote_transport::close_signal::CloseSignal::new()), started: AtomicBool::new(false) }
    }
    /// Record a sticky cancellation and wake any pending async I/O. The remote
    /// peer may already have received credentials or a successful login.
    #[napi]
    pub fn cancel(&self) { self.cancel.request(); }
    /// Validation errors also consume the handle. A new attempt needs a new
    /// handle; the cancellation signal is never reset.
    #[napi]
    pub fn connect_tcp(&self, mut options: ViewerOptions) -> Result<AsyncTask<ConnectTask>> {
        if let Err(error) = self.claim() {
            options.password.zeroize(); options.two_factor_code.zeroize();
            return Err(error);
        }
        connect_viewer_with_signal(options, self.cancel.clone())
    }
    #[napi]
    pub fn connect_wss(&self, mut options: WssViewerOptions) -> Result<AsyncTask<WssConnectTask>> {
        if let Err(error) = self.claim() {
            options.password.zeroize(); options.two_factor_code.zeroize();
            return Err(error);
        }
        connect_wss_viewer_with_signal(options, self.cancel.clone())
    }
}
impl ViewerConnectRequest {
    fn claim(&self) -> Result<()> {
        if self.cancel.is_requested() { return Err(Error::from_reason("viewer connection cancelled")); }
        self.started.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::from_reason("viewer connect request already used"))?;
        if self.cancel.is_requested() { return Err(Error::from_reason("viewer connection cancelled")); }
        Ok(())
    }
}

/// One indexed optional original-resolution claim.
#[napi(object)]
pub struct ViewerOriginalResolution { pub present: bool, pub width: Option<i32>, pub height: Option<i32> }
pub struct OriginalResolutionsTask { state: Arc<ViewerState>, _busy: BusyLease }
impl Task for OriginalResolutionsTask {
    type Output = Option<Vec<Option<remote_protocol::desktop::OriginalResolution>>>;
    type JsValue = Option<Vec<ViewerOriginalResolution>>;
    fn compute(&mut self) -> Result<Self::Output> {
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested")); }
        let lock = self.state.viewer.lock().map_err(|_| Error::from_reason("viewer state poisoned"))?;
        let viewer = lock.as_ref().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        let result = viewer.original_resolutions();
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested")); }
        Ok(result)
    }
    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested")); }
        Ok(output.map(|values| values.into_iter().map(|value| ViewerOriginalResolution {
            present: value.is_some(), width: value.map(|v| v.width), height: value.map(|v| v.height),
        }).collect()))
    }
}

#[napi(object)]
pub struct ViewerSupportedModes { pub display: u32, pub modes: Vec<crate::display_wire::WireResolution> }
pub struct SupportedModesTask { state: Arc<ViewerState>, _busy: BusyLease }
impl Task for SupportedModesTask {
    type Output = Option<(u32, Vec<remote_protocol::resolution_metadata::Resolution>)>;
    type JsValue = Option<ViewerSupportedModes>;
    fn compute(&mut self) -> Result<Self::Output> {
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested")); }
        let lock = self.state.viewer.lock().map_err(|_| Error::from_reason("viewer state poisoned"))?;
        let viewer = lock.as_ref().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        let result = viewer.supported_modes();
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested")); }
        Ok(result)
    }
    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested")); }
        Ok(output.map(|(display, modes)| ViewerSupportedModes { display,
            modes: modes.into_iter().map(|mode| crate::display_wire::WireResolution { width: mode.width, height: mode.height }).collect() }))
    }
}

#[napi(object)]
pub struct ViewerWindowsSession { pub sid: u32, pub name: String }
#[napi(object)]
pub struct ViewerWindowsSessions { pub current_sid: u32, pub sessions: Vec<ViewerWindowsSession> }
pub struct ViewerWindowsSessionsTask { state: Arc<ViewerState>, _busy: BusyLease }
impl Task for ViewerWindowsSessionsTask {
    type Output = Option<remote_protocol::windows_sessions::WindowsSessions>;
    type JsValue = Option<ViewerWindowsSessions>;
    fn compute(&mut self) -> Result<Self::Output> {
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested")); }
        let lock = self.state.viewer.lock().map_err(|_| Error::from_reason("viewer state poisoned"))?;
        let viewer = lock.as_ref().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        let result = viewer.windows_sessions();
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested")); }
        Ok(result)
    }
    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested")); }
        Ok(output.map(|value| ViewerWindowsSessions { current_sid: value.current_sid,
            sessions: value.sessions.into_iter().map(|s| ViewerWindowsSession { sid: s.sid, name: s.name }).collect() }))
    }
}

pub struct SendMouseTask { state: Arc<ViewerState>, _busy: BusyLease, event: MouseEvent, deadline: Duration }
impl Task for SendMouseTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut checkout = ViewerCheckout::take(&self.state)?;
        let viewer = checkout.viewer.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        viewer_io!(&self.state, viewer, viewer.send_input(&Envelope::mouse_event(self.event), self.deadline))
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested; delivery may be indeterminate")); } Ok(()) }
}
pub struct SendWireInputTask { state: Arc<ViewerState>, _busy: BusyLease, wire: Zeroizing<Vec<u8>>, deadline: Duration }
impl Task for SendWireInputTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let event = remote_protocol::sensitive_input::SensitiveInputEnvelope::decode(&self.wire, 8192).map_err(js_error)?;
        let mut checkout = ViewerCheckout::take(&self.state)?;
        let viewer = checkout.viewer.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        viewer_io!(&self.state, viewer, viewer.send_input(&event, self.deadline))
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested; delivery may be indeterminate")); } Ok(()) }
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
    pub width: Option<i32>, pub height: Option<i32>, pub cursor_embedded: Option<bool>,
    pub peer: Option<ViewerPeerInfo>,
    pub permission: Option<i32>, pub enabled: Option<bool>,
    pub encoding_vp8: Option<bool>, pub encoding_av1: Option<bool>, pub encoding_h264: Option<bool>, pub encoding_h265: Option<bool>,
    pub i444_vp8: Option<bool>, pub i444_vp9: Option<bool>, pub i444_av1: Option<bool>, pub i444_h264: Option<bool>, pub i444_h265: Option<bool>,
    pub probe_time: Option<String>, pub probe_from_client: Option<bool>, pub probe_last_delay: Option<u32>, pub probe_target_bitrate: Option<u32>,
}
pub struct ReceiveTask { state: Arc<ViewerState>, _busy: BusyLease, deadline: Duration }
impl Task for ReceiveTask {
    type Output = ViewerEvent;
    type JsValue = ViewerMessage;
    fn compute(&mut self) -> Result<ViewerEvent> {
        let mut checkout = ViewerCheckout::take(&self.state)?;
        let viewer = checkout.viewer.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        viewer_io!(&self.state, viewer, viewer.receive(self.deadline))
    }
    fn resolve(&mut self, _: Env, event: ViewerEvent) -> Result<ViewerMessage> {
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested")); }
        viewer_event_to_js(event)
    }
}
fn viewer_event_to_js(event: ViewerEvent) -> Result<ViewerMessage> {
        let mut msg = ViewerMessage { kind: String::new(), data: None, display: None, codec: None, cursor_id: None,
            x: None, y: None, hotx: None, hoty: None, width: None, height: None, cursor_embedded: None, peer: None, permission: None, enabled: None, encoding_vp8: None, encoding_av1: None, encoding_h264: None, encoding_h265: None,
            i444_vp8: None, i444_vp9: None, i444_av1: None, i444_h264: None, i444_h265: None,
            probe_time: None, probe_from_client: None, probe_last_delay: None, probe_target_bitrate: None };
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
            ViewerEvent::TestDelay(value) => {
                msg.kind = "testDelay".into(); msg.probe_time = Some(value.time.to_string());
                msg.probe_from_client = Some(value.from_client); msg.probe_last_delay = Some(value.last_delay);
                msg.probe_target_bitrate = Some(value.target_bitrate);
            },
            ViewerEvent::PeerInfo(info) => { msg.kind = "peerInfo".into(); msg.peer = Some(to_js_peer(&info)); },
            ViewerEvent::FollowCurrentDisplay(display) => { msg.kind = "followCurrentDisplay".into(); msg.display = Some(display as i32); },
            ViewerEvent::DisplayChanged { value, envelope } => { msg.kind = "displayChanged".into(); msg.display = Some(value.display as i32); msg.x = Some(value.x); msg.y = Some(value.y); msg.width = Some(value.width); msg.height = Some(value.height); msg.cursor_embedded = Some(value.cursor_embedded); msg.data = Some(envelope.into_vec().into()); },
            ViewerEvent::EncodingCapabilities(value) => {
                msg.kind = "encodingCapabilities".into(); msg.encoding_vp8 = Some(value.vp8); msg.encoding_av1 = Some(value.av1);
                msg.encoding_h264 = Some(value.h264); msg.encoding_h265 = Some(value.h265);
                if let Some(c) = value.i444 { msg.i444_vp8 = Some(c.vp8); msg.i444_vp9 = Some(c.vp9); msg.i444_av1 = Some(c.av1); msg.i444_h264 = Some(c.h264); msg.i444_h265 = Some(c.h265); }
            },
            ViewerEvent::Permission(notice) => { msg.kind = "permission".into(); msg.permission = Some(notice.permission); msg.enabled = Some(notice.enabled); },
            ViewerEvent::Other(raw) => { msg.kind = "other".into(); msg.data = Some(raw.into_vec().into()); },
        }
        Ok(msg)
}
pub struct TryViewerReceiveTask { state: Arc<ViewerState>, _busy: BusyLease, deadline: Duration }
impl Task for TryViewerReceiveTask {
    type Output = Option<ViewerEvent>; type JsValue = Option<ViewerMessage>;
    fn compute(&mut self) -> Result<Self::Output> {
        let mut checkout = ViewerCheckout::take(&self.state)?;
        let viewer = checkout.viewer.as_mut().ok_or_else(|| Error::from_reason("viewer is closed"))?;
        viewer_io!(&self.state, viewer, viewer.try_receive(self.deadline))
    }
    fn resolve(&mut self, _: Env, event: Self::Output) -> Result<Self::JsValue> {
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("viewer close requested")); }
        event.map(viewer_event_to_js).transpose()
    }
}
