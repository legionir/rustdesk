//! Experimental *loopback only*, view-only Node host admission and approval.
//! Not a product, security boundary, consent UI, full RustDesk host, or public
//! network server. Code, Node-API types and native backends are unbuilt and
//! untested. The application must show trusted local consent, provision the
//! ephemeral key, time out abandoned pending sessions, and protect passwords.

use crate::{js_error, viewer::{remaining, runtime, wait}};
use hbb_common::sodiumoxide::{self, crypto::sign};
use napi::{bindgen_prelude::{AsyncTask, Buffer}, Env, Error, Result, Task};
use napi_derive::napi;
use remote_core::{admitted_host, host_connection::{HostConnection, HostEvent, LoginClaims}};
use remote_input::{InputBackend, MouseButton, VirtualKey};
use remote_protocol::desktop::{DisplayInfo, PeerInfo};
use remote_rustdesk_websocket::{direct_tcp::{DirectTcp, DirectTcpListener, DirectTcpOptIn}, source_crypto::EncryptedTransport};
use remote_security::{admission::{AdmissionController, AdmissionLimits}, OwnerApproval, PasswordVerifier};
use remote_session::{Permissions, Principal, SessionId};
use std::{io, sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex}, time::{Duration, Instant}};
use zeroize::Zeroizing;

const PREAUTH: usize = 128 * 1024;
const POSTAUTH: usize = 8 * 1024 * 1024;
static LISTENER_IN_USE: AtomicBool = AtomicBool::new(false);
static SESSION_IN_USE: AtomicBool = AtomicBool::new(false);

// View-only backend: even if a programming error grants input later, it cannot
// inject OS events. A production host needs real consent and input ownership.
struct NoInput;
impl NoInput { fn denied() -> io::Result<()> { Err(io::Error::new(io::ErrorKind::PermissionDenied, "input is disabled")) } }
impl InputBackend for NoInput {
    fn move_to(&mut self, _: i32, _: i32) -> io::Result<()> { Self::denied() }
    fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { Self::denied() }
    fn mouse_up(&mut self, _: MouseButton) -> io::Result<()> { Self::denied() }
    fn scroll(&mut self, _: i32, _: i32) -> io::Result<()> { Self::denied() }
    fn key_down(&mut self, _: VirtualKey) -> io::Result<()> { Self::denied() }
    fn key_up(&mut self, _: VirtualKey) -> io::Result<()> { Self::denied() }
}
type NativeHost = HostConnection<EncryptedTransport<DirectTcp>, NoInput>;

struct Lease(&'static AtomicBool);
impl Lease {
    fn acquire(flag: &'static AtomicBool, description: &'static str) -> Result<Self> {
        flag.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self(flag)).map_err(|_| Error::from_reason(description))
    }
}
impl Drop for Lease { fn drop(&mut self) { self.0.store(false, Ordering::Release); } }
pub struct ListenerData {
    listener: DirectTcpListener,
    host_id: String,
    secret: sign::SecretKey,
    password: Zeroizing<String>,
    admission: AdmissionController,
}
struct ListenerState {
    data: Mutex<Option<ListenerData>>,
    busy: AtomicBool,
    // Released on explicit close or when the last object/task is dropped.
    lease: Mutex<Option<Lease>>,
    address: String,
    pin: [u8; 32],
}
struct ListenerBusy(Arc<ListenerState>);
impl ListenerBusy {
    fn acquire(state: &Arc<ListenerState>) -> Result<Self> {
        state.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::from_reason("host listener already has an operation in progress"))?;
        Ok(Self(state.clone()))
    }
}
impl Drop for ListenerBusy { fn drop(&mut self) { self.0.busy.store(false, Ordering::Release); } }
pub struct SessionData { host: NativeHost, id: SessionId, principal: Principal, claims: LoginClaims, approved_displays: Option<Vec<remote_capture::DisplayInfo>>, approval_deadline: Instant }
struct SessionState {
    data: Mutex<Option<SessionData>>, busy: AtomicBool, lease: Mutex<Option<Lease>>,
    expiration: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl Drop for SessionState {
    fn drop(&mut self) {
        if let Ok(expiration) = self.expiration.get_mut() {
            if let Some(task) = expiration.take() { task.abort(); }
        }
    }
}
struct SessionBusy(Arc<SessionState>);
impl SessionBusy {
    fn acquire(state: &Arc<SessionState>) -> Result<Self> {
        state.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::from_reason("host session already has an operation in progress"))?;
        Ok(Self(state.clone()))
    }
}
impl Drop for SessionBusy { fn drop(&mut self) { self.0.busy.store(false, Ordering::Release); } }

#[napi(object)]
pub struct LocalHostOptions { pub host_id: String, pub password: String, pub timeout_ms: u32 }

pub struct ListenTask { host_id: String, password: Zeroizing<String>, deadline: Duration, lease: Option<Lease> }
impl Task for ListenTask {
    type Output = (ListenerData, String, [u8; 32]);
    type JsValue = LocalHost;
    fn compute(&mut self) -> Result<Self::Output> {
        sodiumoxide::init().map_err(|_| Error::from_reason("crypto initialization failed"))?;
        let (public, secret) = sign::gen_keypair();
        let listener = runtime()?.block_on(DirectTcpListener::bind("127.0.0.1:0".parse().map_err(js_error)?, PREAUTH, self.deadline, DirectTcpOptIn::acknowledge_plaintext_transport())).map_err(js_error)?;
        let address = listener.local_addr().map_err(js_error)?.to_string();
        let admission = AdmissionController::new(AdmissionLimits { max_total: 1, max_per_address: 1, login_grace: Duration::from_secs(180) }).map_err(js_error)?;
        let mut pin = [0; 32]; pin.copy_from_slice(&public.0);
        Ok((ListenerData { listener, host_id: self.host_id.clone(), secret, password: Zeroizing::new(std::mem::take(&mut *self.password)), admission }, address, pin))
    }
    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<LocalHost> {
        let lease = self.lease.take().ok_or_else(|| Error::from_reason("host listener lease unavailable"))?;
        Ok(LocalHost { state: Arc::new(ListenerState { data: Mutex::new(Some(output.0)), busy: AtomicBool::new(false), lease: Mutex::new(Some(lease)), address: output.1, pin: output.2 }) })
    }
}

/// Bind to 127.0.0.1 on an ephemeral port and generate a temporary host key.
/// JS strings and process memory can retain password copies; this is not secure
/// credential storage or a production key-management interface.
#[napi]
pub fn listen_local_host(mut options: LocalHostOptions) -> Result<AsyncTask<ListenTask>> {
    let deadline = wait(options.timeout_ms)?;
    if options.host_id.is_empty() || options.host_id.len() > 256 || options.host_id.chars().any(char::is_control) {
        return Err(Error::from_reason("invalid hostId"));
    }
    if options.password.is_empty() || options.password.len() > 1024 { return Err(Error::from_reason("invalid password length")); }
    let lease = Lease::acquire(&LISTENER_IN_USE, "a local host listener already exists")?;
    Ok(AsyncTask::new(ListenTask { host_id: options.host_id, password: Zeroizing::new(std::mem::take(&mut options.password)), deadline, lease: Some(lease) }))
}

#[napi]
pub struct LocalHost { state: Arc<ListenerState> }
#[napi]
impl LocalHost {
    #[napi]
    pub fn address(&self) -> String { self.state.address.clone() }
    /// Raw temporary Ed25519 public key. Its authenticity still depends on how
    /// the application provides it to the trusted local viewer.
    #[napi]
    pub fn signing_public_key(&self) -> Buffer { self.state.pin.to_vec().into() }
    /// Receive one pending login. The connection is NOT approved yet. Only one
    /// session is admitted per addon process. Explicitly close finished
    /// sessions; a timeout or failure closes the candidate stream.
    #[napi]
    pub fn accept(&self, timeout_ms: u32) -> Result<AsyncTask<AcceptTask>> {
        let deadline = wait(timeout_ms)?;
        let busy = ListenerBusy::acquire(&self.state)?;
        let lease = Lease::acquire(&SESSION_IN_USE, "a local host session already exists")?;
        Ok(AsyncTask::new(AcceptTask { state: self.state.clone(), _busy: busy, lease: Some(lease), deadline }))
    }
    /// Close the listener when no accept is active. Existing sessions remain
    /// caller-owned and must be closed separately.
    #[napi]
    pub fn close(&self) -> Result<()> {
        let _busy = ListenerBusy::acquire(&self.state)?;
        self.state.data.lock().map_err(|_| Error::from_reason("host listener state poisoned"))?.take();
        self.state.lease.lock().map_err(|_| Error::from_reason("host listener lease poisoned"))?.take();
        Ok(())
    }
}

pub struct AcceptTask { state: Arc<ListenerState>, _busy: ListenerBusy, lease: Option<Lease>, deadline: Duration }
impl Task for AcceptTask {
    type Output = SessionData;
    type JsValue = LocalHostSession;
    fn compute(&mut self) -> Result<Self::Output> {
        let lock = self.state.data.lock().map_err(|_| Error::from_reason("host listener state poisoned"))?;
        let data = lock.as_ref().ok_or_else(|| Error::from_reason("host listener closed"))?;
        let end = Instant::now().checked_add(self.deadline).ok_or_else(|| Error::from_reason("invalid deadline"))?;
        runtime()?.block_on(async {
            let (socket, peer) = data.listener.accept(remaining(end)?).await.map_err(js_error)?;
            if !peer.ip().is_loopback() { return Err(Error::from_reason("loopback peer required")); }
            let permit = data.admission.admit(peer.ip()).map_err(js_error)?;
            let mut id_bytes = [0u8; 16]; let mut salt_bytes = [0u8; 32];
            getrandom::getrandom(&mut id_bytes).map_err(js_error)?;
            getrandom::getrandom(&mut salt_bytes).map_err(js_error)?;
            let salt: String = salt_bytes.iter().map(|b| format!("{b:02x}")).collect();
            let id = SessionId::new(id_bytes).map_err(js_error)?;
            let principal = Principal::new("local-shared-password-holder".into()).map_err(js_error)?;
            let verifier = PasswordVerifier::new(id, principal.clone(), &data.password, &salt, remaining(end)?).map_err(js_error)?;
            let mut host = admitted_host::accept(socket, permit, id, NoInput, verifier, &data.host_id, &data.secret, remaining(end)?).await.map_err(js_error)?;
            let claims = host.receive_password_login(remaining(end)?).await.map_err(js_error)?;
            Ok(SessionData { host, id, principal, claims, approved_displays: None, approval_deadline: end })
        })
    }
    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<LocalHostSession> {
        let lease = self.lease.take().ok_or_else(|| Error::from_reason("host session lease unavailable"))?;
        let deadline = output.approval_deadline;
        let state = Arc::new(SessionState { data: Mutex::new(Some(output)), busy: AtomicBool::new(false), lease: Mutex::new(Some(lease)), expiration: Mutex::new(None) });
        let weak = Arc::downgrade(&state);
        let task = runtime()?.spawn(async move {
            tokio::time::sleep(deadline.saturating_duration_since(Instant::now())).await;
            loop {
                // Scope all synchronous lock guards before the next await, so
                // the timer never blocks a Tokio worker or carries a guard.
                let retry = {
                    let Some(state) = weak.upgrade() else { return; };
                    let result = match state.data.try_lock() {
                        Ok(mut data) => {
                            let pending = data.as_ref().map_or(false, |session| matches!(session.host.state(), remote_session::SessionState::Authenticating | remote_session::SessionState::Closed | remote_session::SessionState::Failed));
                            if pending {
                                if let Some(mut session) = data.take() { let _ = session.host.close(); }
                                if let Ok(mut lease) = state.lease.lock() { lease.take(); }
                            }
                            false
                        },
                        Err(std::sync::TryLockError::Poisoned(_)) => false,
                        Err(std::sync::TryLockError::WouldBlock) => true,
                    };
                    result
                };
                if !retry { return; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        *state.expiration.lock().map_err(|_| Error::from_reason("host expiration state poisoned"))? = Some(task);
        Ok(LocalHostSession { state })
    }
}

/// All claims are supplied by the connecting process and are not its identity.
#[napi(object)]
pub struct LocalLoginClaims { pub username: String, pub peer_id: String, pub peer_name: String, pub wire_session_id: String, pub version: String }
#[napi]
pub struct LocalHostSession { state: Arc<SessionState> }
#[napi]
impl LocalHostSession {
    #[napi]
    pub fn claims(&self) -> Result<LocalLoginClaims> {
        let _busy = SessionBusy::acquire(&self.state)?;
        let lock = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let claims = &lock.as_ref().ok_or_else(|| Error::from_reason("host session closed"))?.claims;
        Ok(LocalLoginClaims { username: claims.username.clone(), peer_id: claims.peer_id.clone(), peer_name: claims.peer_name.clone(), wire_session_id: claims.wire_session_id.to_string(), version: claims.version.clone() })
    }
    /// Complete password verification and grant VIEW ONLY after a separate,
    /// trusted local consent decision. The boolean is an application assertion,
    /// not a consent UI. No keyboard/mouse permissions can be granted here.
    #[napi]
    pub fn approve_view(&self, confirm_local_consent: bool, timeout_ms: u32) -> Result<AsyncTask<ApproveTask>> {
        if !confirm_local_consent { return Err(Error::from_reason("explicit local consent is required")); }
        let deadline = wait(timeout_ms)?;
        let busy = SessionBusy::acquire(&self.state)?;
        Ok(AsyncTask::new(ApproveTask { state: self.state.clone(), _busy: busy, deadline }))
    }
    /// Capture and send one independently encoded VP9 frame for an approved
    /// display. The caller must separately confirm the viewer supports VP9.
    /// Reopens capture and creates an encoder on each call; this is not an
    /// efficient continuous video stream. Metadata comparisons do not prove a
    /// stable display identity when hardware or desktops change. A changed
    /// enumeration is rejected and the session must be re-approved.
    #[napi]
    pub fn send_one_vp9_frame(&self, display_index: u32, confirm_viewer_vp9: bool, capture_timeout_ms: u32, send_timeout_ms: u32) -> Result<AsyncTask<SendFrameTask>> {
        if !confirm_viewer_vp9 { return Err(Error::from_reason("viewer VP9 support must be explicitly confirmed")); }
        if capture_timeout_ms == 0 || capture_timeout_ms > 2000 { return Err(Error::from_reason("captureTimeoutMs must be 1..2000")); }
        let send_wait = wait(send_timeout_ms)?;
        let busy = SessionBusy::acquire(&self.state)?;
        Ok(AsyncTask::new(SendFrameTask { state: self.state.clone(), _busy: busy, display_index, capture_wait: Duration::from_millis(capture_timeout_ms.into()), send_wait }))
    }
    /// Sample the current Windows cursor after consent and send shape/position.
    /// Returns false if hidden/unavailable. Non-Windows platforms reject this
    /// method. Does not support secure desktop or portable-service capture.
    #[napi]
    pub fn sample_windows_cursor(&self, timeout_ms: u32) -> Result<AsyncTask<SampleCursorTask>> {
        let deadline = wait(timeout_ms)?;
        let busy = SessionBusy::acquire(&self.state)?;
        Ok(AsyncTask::new(SampleCursorTask { state: self.state.clone(), _busy: busy, deadline }))
    }
    /// Resend a retained cursor shape, or return false for a cache miss.
    #[napi]
    pub fn resend_cursor_shape(&self, id: String, timeout_ms: u32) -> Result<AsyncTask<ResendCursorTask>> {
        let value = id.parse::<u64>().map_err(|_| Error::from_reason("cursor ID must be a decimal u64 string"))?;
        if value.to_string() != id { return Err(Error::from_reason("cursor ID must be canonical decimal")); }
        let deadline = wait(timeout_ms)?;
        let busy = SessionBusy::acquire(&self.state)?;
        Ok(AsyncTask::new(ResendCursorTask { state: self.state.clone(), _busy: busy, id: value, deadline }))
    }
    /// Receive one source control/heartbeat message. This serial API cannot
    /// receive concurrently with frame sends. Timeouts close the connection.
    /// Peer requests are untrusted and are not acted on automatically.
    #[napi]
    pub fn receive_event(&self, timeout_ms: u32) -> Result<AsyncTask<HostEventTask>> {
        let deadline = wait(timeout_ms)?;
        let busy = SessionBusy::acquire(&self.state)?;
        Ok(AsyncTask::new(HostEventTask { state: self.state.clone(), _busy: busy, deadline }))
    }
    /// Close/reject the session. Must not overlap another session operation.
    #[napi]
    pub fn close(&self) -> Result<()> {
        let _busy = SessionBusy::acquire(&self.state)?;
        let mut data = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        if let Some(session) = data.as_mut() { session.host.close().map_err(js_error)?; }
        data.take();
        self.state.lease.lock().map_err(|_| Error::from_reason("host session lease poisoned"))?.take();
        if let Some(task) = self.state.expiration.lock().map_err(|_| Error::from_reason("host expiration state poisoned"))?.take() { task.abort(); }
        Ok(())
    }
}

pub struct ApproveTask { state: Arc<SessionState>, _busy: SessionBusy, deadline: Duration }
impl Task for ApproveTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut lock = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let session = lock.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?;
        // Enumeration may reveal screen geometry; it happens only on explicit
        // local approval and is not a stable identity across hotplug.
        let displays = remote_capture::displays().map_err(js_error)?;
        if displays.is_empty() || displays.len() > remote_protocol::desktop::MAX_DISPLAYS { return Err(Error::from_reason("invalid display count")); }
        let mut infos = Vec::with_capacity(displays.len());
        let mut approved_displays = Vec::with_capacity(displays.len());
        for display in displays {
            let d = display.info();
            approved_displays.push(d.clone());
            let width = i32::try_from(d.width).map_err(js_error)?;
            let height = i32::try_from(d.height).map_err(js_error)?;
            infos.push(DisplayInfo { x: d.x, y: d.y, width, height, name: String::new(), online: d.online, cursor_embedded: false, scale: 0.0 });
        }
        let info = PeerInfo { username: String::new(), hostname: String::new(), platform: std::env::consts::OS.into(), version: "experimental".into(), displays: infos, current_display: 0, sas_enabled: false, encoding: None };
        let end = Instant::now().checked_add(self.deadline).ok_or_else(|| Error::from_reason("invalid approval deadline"))?;
        let permissions = Permissions { view_screen: true, ..Default::default() };
        let mut approval = OwnerApproval::new(session.id, session.principal.clone(), Some(permissions));
        let rt = runtime()?;
        let result = (|| -> Result<()> {
            session.host.authorize(permissions, &mut approval).map_err(js_error)?;
            session.host.set_authorized_message_limit(POSTAUTH).map_err(js_error)?;
            rt.block_on(async {
                session.host.send_login_success(&info, remaining(end)?).await.map_err(js_error)?;
                session.host.send_source_keyboard_permission(false, remaining(end)?).await.map_err(js_error)
            })
        })();
        if let Err(error) = result {
            // Do not retain an approved-but-unannounced session on any setup
            // failure, including an expired deadline before either send.
            let _ = session.host.close();
            return Err(error);
        }
        session.approved_displays = Some(approved_displays);
        Ok(())
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { Ok(()) }
}

/// A one-shot local capture/encoder operation, run on a Node worker.
pub struct SendFrameTask { state: Arc<SessionState>, _busy: SessionBusy, display_index: u32, capture_wait: Duration, send_wait: Duration }
impl Task for SendFrameTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        use remote_codec::{Codec, EncoderConfig};
        let mut lock = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let session = lock.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?;
        let index = usize::try_from(self.display_index).map_err(js_error)?;
        let approved = session.approved_displays.as_ref().and_then(|items| items.get(index)).ok_or_else(|| Error::from_reason("display was not approved"))?;
        let display = remote_capture::displays().map_err(js_error)?.into_iter().nth(index).ok_or_else(|| Error::from_reason("display is no longer available"))?;
        if display.info() != approved { return Err(Error::from_reason("display enumeration changed; re-approval required")); }
        let width = u32::try_from(approved.width).map_err(js_error)?;
        let height = u32::try_from(approved.height).map_err(js_error)?;
        let display_wire = i32::try_from(self.display_index).map_err(js_error)?;
        let config = EncoderConfig { codec: Codec::Vp9, width, height, quality: 1.0, keyframe_interval: Some(30) };
        let rt = runtime()?;
        let mut pump = session.host.start_capture(display, display_wire, config, POSTAUTH).map_err(js_error)?;
        let result = rt.block_on(session.host.send_capture(&mut pump, self.capture_wait, self.send_wait, 0));
        let stop = session.host.stop_capture(&mut pump);
        drop(pump);
        result.map_err(js_error)?;
        stop.map_err(js_error)?;
        Ok(())
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { Ok(()) }
}

/// Untrusted host-side event. Capabilities are serialized as an isolated
/// existing source option, with login proof and other options removed.
#[napi(object)]
pub struct LocalHostEvent {
    pub kind: String,
    pub display: Option<u32>, pub cursor_id: Option<String>,
    pub data: Option<Buffer>,
    pub vp8: Option<i32>, pub vp9: Option<i32>, pub av1: Option<i32>,
    pub h264: Option<i32>, pub h265: Option<i32>, pub preference: Option<i32>,
}
pub struct HostEventTask { state: Arc<SessionState>, _busy: SessionBusy, deadline: Duration }
impl Task for HostEventTask {
    type Output = HostEvent;
    type JsValue = LocalHostEvent;
    fn compute(&mut self) -> Result<HostEvent> {
        let mut lock = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let session = lock.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?;
        runtime()?.block_on(session.host.receive_event(self.deadline)).map_err(js_error)
    }
    fn resolve(&mut self, _: Env, event: HostEvent) -> Result<LocalHostEvent> {
        use remote_protocol::video_control::VideoControl;
        let mut output = LocalHostEvent { kind: String::new(), display: None, cursor_id: None, data: None, vp8: None, vp9: None, av1: None, h264: None, h265: None, preference: None };
        match event {
            HostEvent::Input => output.kind = "input".into(),
            HostEvent::Heartbeat => output.kind = "heartbeat".into(),
            HostEvent::VideoControl(VideoControl::RefreshAll) => output.kind = "refreshAll".into(),
            HostEvent::VideoControl(VideoControl::RefreshDisplay(index)) => { output.kind = "refreshDisplay".into(); output.display = Some(index); },
            HostEvent::VideoControl(VideoControl::FrameReceived) => output.kind = "frameReceived".into(),
            HostEvent::CursorShapeRequest(id) => { output.kind = "cursorShapeRequest".into(); output.cursor_id = Some(id.to_string()); },
            HostEvent::DecodingAdvertisement { values, envelope } => {
                output.kind = "decodingAdvertisement".into(); output.data = Some(envelope.into_vec().into());
                output.vp8 = Some(values.vp8); output.vp9 = Some(values.vp9); output.av1 = Some(values.av1);
                output.h264 = Some(values.h264); output.h265 = Some(values.h265); output.preference = Some(values.preference);
            },
        }
        Ok(output)
    }
}

/// Windows-only on-demand shape sampling. OS behavior remains unverified.
pub struct SampleCursorTask { state: Arc<SessionState>, _busy: SessionBusy, deadline: Duration }
impl Task for SampleCursorTask {
    type Output = bool;
    type JsValue = bool;
    fn compute(&mut self) -> Result<bool> {
        #[cfg(target_os = "windows")]
        {
            let mut lock = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
            let session = lock.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?;
            runtime()?.block_on(session.host.send_windows_cursor(self.deadline)).map_err(js_error)
        }
        #[cfg(not(target_os = "windows"))]
        { Err(Error::from_reason("Windows cursor sampling is unavailable on this platform")) }
    }
    fn resolve(&mut self, _: Env, value: bool) -> Result<bool> { Ok(value) }
}
pub struct ResendCursorTask { state: Arc<SessionState>, _busy: SessionBusy, id: u64, deadline: Duration }
impl Task for ResendCursorTask {
    type Output = bool;
    type JsValue = bool;
    fn compute(&mut self) -> Result<bool> {
        let mut lock = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let session = lock.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?;
        runtime()?.block_on(session.host.send_cached_cursor(self.id, self.deadline)).map_err(js_error)
    }
    fn resolve(&mut self, _: Env, value: bool) -> Result<bool> { Ok(value) }
}
