//! Experimental view-only Node host admission and approval. The original
//! listener is loopback-only; a separate explicit network opt-in is restricted
//! to an exact observed peer IP. Neither is a product, security boundary, consent
//! UI, full RustDesk host, or public network server. Code, Node-API types and native backends are unbuilt and
//! untested. The application must show trusted local consent, provision the
//! ephemeral key, time out abandoned pending sessions, and protect passwords.

use crate::{js_error, viewer::{remaining, runtime, wait}};
use hbb_common::sodiumoxide::{self, crypto::sign};
use napi::{bindgen_prelude::{AsyncTask, Buffer}, Env, Error, Result, Task};
use napi_derive::napi;
use remote_core::{admitted_host, host_connection::{HostConnection, HostEvent, LoginClaims}};
use remote_input::{InputBackend, MouseButton, VirtualKey};
use remote_protocol::desktop::{DisplayInfo, PeerInfo};
use remote_rustdesk_websocket::{direct_tcp::{DirectTcp, DirectTcpListener, DirectTcpOptIn}, duplex_tcp::UpgradeableEncryptedTcp};
use remote_security::{admission::{AdmissionController, AdmissionLimits}, OwnerApproval, PasswordVerifier};
use remote_session::{Permissions, Principal, SessionId};
use std::{io, net::{IpAddr, SocketAddr}, sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex}, time::{Duration, Instant}};
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
type NativeHost = HostConnection<UpgradeableEncryptedTcp, NoInput>;

struct Lease(&'static AtomicBool);
impl Lease {
    fn acquire(flag: &'static AtomicBool, description: &'static str) -> Result<Self> {
        flag.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self(flag)).map_err(|_| Error::from_reason(description))
    }
}
impl Drop for Lease { fn drop(&mut self) { self.0.store(false, Ordering::Release); } }
#[derive(Clone, Copy)]
enum PeerPolicy { Loopback, Exact(IpAddr) }
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip { IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip), _ => ip }
}
impl PeerPolicy {
    fn permits(self, address: IpAddr) -> bool {
        let address = normalize_ip(address);
        match self { Self::Loopback => address.is_loopback(), Self::Exact(expected) => address == normalize_ip(expected) }
    }
}
pub struct ListenerData {
    listener: DirectTcpListener,
    peer_policy: PeerPolicy,
    host_id: String,
    secret: sign::SecretKey,
    password: Zeroizing<String>,
    admission: AdmissionController,
}
struct ListenerState {
    data: Mutex<Option<ListenerData>>,
    busy: AtomicBool,
    close_signal: remote_transport::close_signal::CloseSignal,
    // Released on explicit close or when the last object/task is dropped.
    lease: Mutex<Option<Lease>>,
    address: String,
    pin: [u8; 32],
}
struct ListenerBusy(Arc<ListenerState>);
impl ListenerBusy {
    fn acquire_raw(state: &Arc<ListenerState>) -> Result<Self> {
        state.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::from_reason("host listener already has an operation in progress"))?;
        Ok(Self(state.clone()))
    }
    fn acquire(state: &Arc<ListenerState>) -> Result<Self> {
        if state.close_signal.is_requested() { return Err(Error::from_reason("host listener close requested")); }
        let busy = Self::acquire_raw(state)?;
        if state.close_signal.is_requested() { drop(busy); return Err(Error::from_reason("host listener close requested")); }
        Ok(busy)
    }
}
impl Drop for ListenerBusy {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
        let _ = finish_requested_listener_close(&self.0);
    }
}
// Drop only the listener, not its lease. Existing accepted sessions are owned
// separately. Explicit close releases the lease after the active accept ends.
fn finish_requested_listener_close(state: &ListenerState) -> Result<()> {
    if !state.close_signal.is_requested() { return Ok(()); }
    if state.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { return Ok(()); }
    struct BusyReset<'a>(&'a AtomicBool);
    impl Drop for BusyReset<'_> { fn drop(&mut self) { self.0.store(false, Ordering::Release); } }
    let _busy = BusyReset(&state.busy);
    let mut data = state.data.try_lock().map_err(|error| match error {
        std::sync::TryLockError::WouldBlock => Error::from_reason("host listener cleanup is busy; retry close"),
        std::sync::TryLockError::Poisoned(_) => Error::from_reason("host listener state poisoned"),
    })?;
    data.take();
    Ok(())
}
enum CursorDeliveryMode { Unset, AlwaysShape, PerSession(remote_core::cursor_delivery::CursorDelivery) }
pub struct SessionData { host: NativeHost, id: SessionId, principal: Principal, claims: LoginClaims, approved_displays: Option<Vec<remote_capture::DisplayInfo>>, approval_deadline: Instant, focus: remote_core::window_follow::FocusTracker, cursor_mode: CursorDeliveryMode, duplex_enabled: bool }
struct SessionState {
    data: Mutex<Option<SessionData>>, busy: AtomicBool, lease: Mutex<Option<Lease>>,
    expiration: Mutex<Option<tokio::task::JoinHandle<()>>>, burst_cancel: AtomicBool,
    close_signal: remote_transport::close_signal::CloseSignal,
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
    fn acquire_raw(state: &Arc<SessionState>) -> Result<Self> {
        state.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::from_reason("host session already has an operation in progress"))?;
        Ok(Self(state.clone()))
    }
    fn acquire(state: &Arc<SessionState>) -> Result<Self> {
        if state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested")); }
        let busy = Self::acquire_raw(state)?;
        if state.close_signal.is_requested() { drop(busy); return Err(Error::from_reason("host session close requested")); }
        Ok(busy)
    }
}
impl Drop for SessionBusy {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
        // Drop cannot report cleanup failure. Explicit close can retry it.
        let _ = finish_requested_session_close(&self.0);
    }
}
// A close request never releases the session lease by itself: explicit close
// remains the retryable cleanup/lease-release operation. Try-lock avoids waiting
// for a concurrent expiration callback. Host cleanup is synchronous and can
// still block; this prototype's backend is view-only and has no input to release.
fn finish_requested_session_close(state: &SessionState) -> Result<()> {
    if !state.close_signal.is_requested() { return Ok(()); }
    if state.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { return Ok(()); }
    struct BusyReset<'a>(&'a AtomicBool);
    impl Drop for BusyReset<'_> { fn drop(&mut self) { self.0.store(false, Ordering::Release); } }
    let _busy = BusyReset(&state.busy);
    let mut slot = state.data.try_lock().map_err(|error| match error {
        std::sync::TryLockError::WouldBlock => Error::from_reason("host session cleanup is busy; retry close"),
        std::sync::TryLockError::Poisoned(_) => Error::from_reason("host session state poisoned"),
    })?;
    match slot.as_mut() {
        Some(session) => {
            // Forget wrapper-owned cursor shapes promptly; copies in native,
            // transport or JavaScript memory remain outside this operation.
            session.cursor_mode = CursorDeliveryMode::Unset;
            session.host.close().map_err(js_error)
        },
        None => Ok(()),
    }
}

#[napi(object)]
pub struct LocalHostOptions { pub host_id: String, pub password: String, pub timeout_ms: u32 }

pub struct ListenTask { host_id: String, password: Zeroizing<String>, deadline: Duration, lease: Option<Lease>, bind: SocketAddr, peer_policy: PeerPolicy }
impl Task for ListenTask {
    type Output = (ListenerData, String, [u8; 32]);
    type JsValue = LocalHost;
    fn compute(&mut self) -> Result<Self::Output> {
        sodiumoxide::init().map_err(|_| Error::from_reason("crypto initialization failed"))?;
        let (public, secret) = sign::gen_keypair();
        let listener = runtime()?.block_on(DirectTcpListener::bind(self.bind, PREAUTH, self.deadline, DirectTcpOptIn::acknowledge_plaintext_transport())).map_err(js_error)?;
        let address = listener.local_addr().map_err(js_error)?.to_string();
        let admission = AdmissionController::new(AdmissionLimits { max_total: 1, max_per_address: 1, login_grace: Duration::from_secs(180) }).map_err(js_error)?;
        let mut pin = [0; 32]; pin.copy_from_slice(&public.0);
        Ok((ListenerData { listener, peer_policy: self.peer_policy, host_id: self.host_id.clone(), secret, password: Zeroizing::new(std::mem::take(&mut *self.password)), admission }, address, pin))
    }
    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<LocalHost> {
        let lease = self.lease.take().ok_or_else(|| Error::from_reason("host listener lease unavailable"))?;
        Ok(LocalHost { state: Arc::new(ListenerState { data: Mutex::new(Some(output.0)), busy: AtomicBool::new(false), close_signal: remote_transport::close_signal::CloseSignal::new(), lease: Mutex::new(Some(lease)), address: output.1, pin: output.2 }) })
    }
}

/// Bind to 127.0.0.1 on an ephemeral port and generate a temporary host key.
/// JS strings and process memory can retain password copies; this is not secure
/// credential storage or a production key-management interface.
#[napi]
pub fn listen_local_host(mut options: LocalHostOptions) -> Result<AsyncTask<ListenTask>> {
    // Cover validation and listener-lease failures as well as worker lifetime.
    // JS/N-API copies and allocator history remain outside this guarantee.
    let password = Zeroizing::new(std::mem::take(&mut options.password));
    let deadline = wait(options.timeout_ms)?;
    if options.host_id.is_empty() || options.host_id.len() > 256 || options.host_id.chars().any(char::is_control) {
        return Err(Error::from_reason("invalid hostId"));
    }
    if password.is_empty() || password.len() > 1024 { return Err(Error::from_reason("invalid password length")); }
    let lease = Lease::acquire(&LISTENER_IN_USE, "a local host listener already exists")?;
    Ok(AsyncTask::new(ListenTask { host_id: options.host_id, password, deadline, lease: Some(lease), bind: "127.0.0.1:0".parse().map_err(js_error)?, peer_policy: PeerPolicy::Loopback }))
}

/// Explicit, network-exposed experimental host options. Both the bind address
/// and the one permitted transport-observed client IP are literals. A NAT or
/// proxy may share/obscure that address; it is never an authenticated identity.
#[napi(object)]
pub struct NetworkHostOptions {
    pub address: String,
    pub allowed_peer_ip: String,
    pub host_id: String,
    pub password: String,
    pub timeout_ms: u32,
    pub acknowledge_network_exposure: bool,
}
pub struct NetworkListenTask { inner: ListenTask }
impl Task for NetworkListenTask {
    type Output = (ListenerData, String, [u8; 32]);
    type JsValue = NetworkHost;
    fn compute(&mut self) -> Result<Self::Output> { self.inner.compute() }
    fn resolve(&mut self, env: Env, output: Self::Output) -> Result<Self::JsValue> {
        let local = self.inner.resolve(env, output)?;
        Ok(NetworkHost { state: local.state.clone() })
    }
}
/// Controlled-network-only prototype: password transcripts allow offline
/// guessing, rate limiting and secure pin provisioning are absent, owner
/// consent is caller-supplied, and screen data is private. Never expose to an
/// untrusted network or use as a production server. No input is enabled.
#[napi]
pub fn listen_network_host(mut options: NetworkHostOptions) -> Result<AsyncTask<NetworkListenTask>> {
    let password = Zeroizing::new(std::mem::take(&mut options.password));
    if !options.acknowledge_network_exposure { return Err(Error::from_reason("explicit network exposure acknowledgement required")); }
    let deadline = wait(options.timeout_ms)?;
    let address: SocketAddr = options.address.parse().map_err(|_| Error::from_reason("address must be a literal IP and port"))?;
    let peer: IpAddr = options.allowed_peer_ip.parse().map_err(|_| Error::from_reason("allowedPeerIp must be a literal IP"))?;
    let peer = normalize_ip(peer);
    if peer.is_unspecified() || peer.is_multicast() { return Err(Error::from_reason("invalid allowed peer address")); }
    if options.host_id.is_empty() || options.host_id.len() > 256 || options.host_id.chars().any(char::is_control) {
        return Err(Error::from_reason("invalid hostId"));
    }
    if password.is_empty() || password.len() > 1024 { return Err(Error::from_reason("invalid password length")); }
    let lease = Lease::acquire(&LISTENER_IN_USE, "a host listener already exists")?;
    Ok(AsyncTask::new(NetworkListenTask { inner: ListenTask { host_id: options.host_id,
        password, deadline, lease: Some(lease), bind: address, peer_policy: PeerPolicy::Exact(peer) } }))
}

/// Network-exposed view-only host; approval and secure pin delivery are external.
#[napi]
pub struct NetworkHost { state: Arc<ListenerState> }
#[napi]
impl NetworkHost {
    #[napi]
    pub fn address(&self) -> String { self.state.address.clone() }
    #[napi]
    pub fn signing_public_key(&self) -> Buffer { self.state.pin.to_vec().into() }
    #[napi]
    pub fn accept(&self, timeout_ms: u32) -> Result<AsyncTask<AcceptTask>> {
        LocalHost { state: self.state.clone() }.accept(timeout_ms)
    }
    #[napi]
    pub fn request_close(&self) -> Result<()> { LocalHost { state: self.state.clone() }.request_close() }
    #[napi]
    pub fn close(&self) -> Result<()> { LocalHost { state: self.state.clone() }.close() }
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
    /// Request cancellation of an active accept; the lease remains reserved
    /// until explicit close. Already delivered sessions are not affected.
    #[napi]
    pub fn request_close(&self) -> Result<()> {
        self.state.close_signal.request();
        finish_requested_listener_close(&self.state)
    }
    /// Close the listener when no accept is active. Existing sessions remain
    /// caller-owned and must be closed separately.
    #[napi]
    pub fn close(&self) -> Result<()> {
        let _busy = ListenerBusy::acquire_raw(&self.state)?;
        self.state.data.lock().map_err(|_| Error::from_reason("host listener state poisoned"))?.take();
        self.state.lease.lock().map_err(|_| Error::from_reason("host listener lease poisoned"))?.take();
        Ok(())
    }
}

/// The listener is checked out only while `ListenerBusy` is held. This avoids
/// holding a JS-facing mutex while accept, handshake and login perform I/O.
/// Other operations fail busy; a terminal request drops the checked-out listener.
struct ListenerCheckout { state: Arc<ListenerState>, data: Option<ListenerData> }
impl ListenerCheckout {
    fn take(state: &Arc<ListenerState>) -> Result<Self> {
        let data = state.data.lock().map_err(|_| Error::from_reason("host listener state poisoned"))?
            .take().ok_or_else(|| Error::from_reason("host listener closed"))?;
        Ok(Self { state: state.clone(), data: Some(data) })
    }
}
impl Drop for ListenerCheckout {
    fn drop(&mut self) {
        // A panic can interrupt a native or network operation in an unknown
        // state. Drop the listener rather than returning it for another accept.
        if std::thread::panicking() { self.state.close_signal.request(); }
        if self.state.close_signal.is_requested() { self.data.take(); return; }
        if let Ok(mut slot) = self.state.data.lock() {
            if slot.is_none() { *slot = self.data.take(); }
        }
        // A poisoned slot drops the listener; it is not safe to reuse.
    }
}

pub struct AcceptTask { state: Arc<ListenerState>, _busy: ListenerBusy, lease: Option<Lease>, deadline: Duration }
impl Task for AcceptTask {
    type Output = SessionData;
    type JsValue = LocalHostSession;
    fn compute(&mut self) -> Result<Self::Output> {
        let checkout = ListenerCheckout::take(&self.state)?;
        let data = checkout.data.as_ref().ok_or_else(|| Error::from_reason("host listener unavailable"))?;
        let end = Instant::now().checked_add(self.deadline).ok_or_else(|| Error::from_reason("invalid deadline"))?;
        let result = runtime()?.block_on(self.state.close_signal.race(async {
            let (socket, peer) = data.listener.accept(remaining(end)?).await.map_err(js_error)?;
            if !data.peer_policy.permits(peer.ip()) { return Err(Error::from_reason("peer address not permitted")); }
            let permit = data.admission.admit(peer.ip()).map_err(js_error)?;
            let mut id_bytes = [0u8; 16]; let mut salt_bytes = [0u8; 32];
            getrandom::getrandom(&mut id_bytes).map_err(js_error)?;
            getrandom::getrandom(&mut salt_bytes).map_err(js_error)?;
            let salt: String = salt_bytes.iter().map(|b| format!("{b:02x}")).collect();
            let id = SessionId::new(id_bytes).map_err(js_error)?;
            let principal = Principal::new("local-shared-password-holder".into()).map_err(js_error)?;
            let verifier = PasswordVerifier::new(id, principal.clone(), &data.password, &salt, remaining(end)?).map_err(js_error)?;
            let mut host = admitted_host::accept_upgradeable_tcp(socket, permit, id, NoInput, verifier, &data.host_id, &data.secret, remaining(end)?).await.map_err(js_error)?;
            let claims = host.receive_password_login(remaining(end)?).await.map_err(js_error)?;
            Ok(SessionData { host, id, principal, claims, approved_displays: None, approval_deadline: end, focus: remote_core::window_follow::FocusTracker::new(), cursor_mode: CursorDeliveryMode::Unset, duplex_enabled: false })
        }));
        match result {
            Some(result) if !self.state.close_signal.is_requested() => result,
            _ => Err(Error::from_reason("host listener close requested; candidate connection dropped")),
        }
    }
    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<LocalHostSession> {
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("host listener close requested; candidate connection dropped")); }
        let lease = self.lease.take().ok_or_else(|| Error::from_reason("host session lease unavailable"))?;
        let deadline = output.approval_deadline;
        let state = Arc::new(SessionState { data: Mutex::new(Some(output)), busy: AtomicBool::new(false), lease: Mutex::new(Some(lease)), expiration: Mutex::new(None), burst_cancel: AtomicBool::new(false), close_signal: remote_transport::close_signal::CloseSignal::new() });
        let weak = Arc::downgrade(&state);
        let task = runtime()?.spawn(async move {
            tokio::time::sleep(deadline.saturating_duration_since(Instant::now())).await;
            loop {
                // Scope all synchronous lock guards before the next await, so
                // the timer never blocks a Tokio worker or carries a guard.
                let retry = {
                    let Some(state) = weak.upgrade() else { return; };
                    // Reserve the same gate as user operations so expiration
                    // cannot mistake a checkout for a closed slot or overlap
                    // explicit close. Dropping the gate also finishes any close
                    // request that arrived while the timer was working.
                    match SessionBusy::acquire_raw(&state) {
                        Err(_) => true,
                        Ok(_busy) => {
                            if state.close_signal.is_requested() { false }
                            else { match state.data.try_lock() {
                                Ok(mut data) => {
                                    let pending = data.as_ref().map_or(false, |session| matches!(session.host.state(), remote_session::SessionState::Authenticating | remote_session::SessionState::Closed | remote_session::SessionState::Failed));
                                    if pending {
                                        // Keep the lease and object for explicit
                                        // retry after a detectable failure or a
                                        // concurrent terminal close request.
                                        let clean = data.as_mut().map_or(true, |session| session.host.close().is_ok());
                                        if clean && !state.close_signal.is_requested() {
                                            data.take();
                                            if let Ok(mut lease) = state.lease.lock() { lease.take(); }
                                        } else if !clean {
                                            state.close_signal.request();
                                        }
                                    }
                                    false
                                },
                                Err(std::sync::TryLockError::Poisoned(_)) => false,
                                Err(std::sync::TryLockError::WouldBlock) => true,
                            }}
                        },
                    }
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
/// Untrusted initial or updated source video preferences; absent fields mean
/// no preference, not reset. Values never cause automatic encoder changes.
#[napi(object)]
pub struct HostVideoPreferences { pub image_quality: Option<i32>, pub custom_fps: Option<u32> }
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
    /// Take the login's bounded video preferences once, only after approval.
    /// This does not apply the request, expose the login proof, or prove the
    /// viewer is able to decode any particular codec.
    #[napi]
    pub fn take_initial_video_preferences(&self) -> Result<Option<HostVideoPreferences>> {
        let _busy = SessionBusy::acquire(&self.state)?;
        let mut lock = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let session = lock.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?;
        let value = session.host.take_initial_video_preferences().map_err(js_error)?;
        Ok(value.map(|p| HostVideoPreferences { image_quality: p.quality.map(|q| q.source_value()), custom_fps: p.fps }))
    }
    /// Take the untrusted login cursor/follow preferences after view approval.
    #[napi]
    pub fn take_initial_cursor_preferences(&self) -> Result<Option<crate::viewer::CursorPreferences>> {
        let _busy = SessionBusy::acquire(&self.state)?;
        let mut lock = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let session = lock.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?;
        Ok(session.host.take_initial_cursor_preferences().map_err(js_error)?.map(Into::into))
    }
    /// Take the peer's initial input-disable preference after approval. This
    /// view-only Node host never grants OS input, regardless of the value.
    #[napi]
    pub fn take_initial_disable_keyboard(&self) -> Result<Option<bool>> {
        let _busy = SessionBusy::acquire(&self.state)?;
        let mut lock = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let session = lock.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?;
        session.host.take_initial_disable_keyboard().map_err(js_error)
    }
    /// Peer-requested source ACK pacing after view approval. This is an
    /// untrusted preference, not evidence of actual rendering. The application
    /// must implement bounded pacing and process `frameReceived` itself.
    #[napi]
    pub fn initial_video_ack_required(&self) -> Result<bool> {
        let _busy = SessionBusy::acquire(&self.state)?;
        let lock = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let session = lock.as_ref().ok_or_else(|| Error::from_reason("host session closed"))?;
        session.host.initial_video_ack_required().map_err(js_error)
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
    /// Send one VP9 wire envelope to a trusted, non-decoding diagnostic sink.
    /// The explicit flag acknowledges that decoder capability is NOT checked;
    /// this is not suitable for an ordinary viewer expecting usable video.
    /// Local consent, exposure, per-frame privacy and uncertain-delivery rules
    /// remain the caller's responsibility. This method is unbuilt/untested.
    #[napi]
    pub fn send_one_vp9_envelope_to_trusted_sink(&self, display_index: u32, acknowledge_no_decoder: bool,
        capture_timeout_ms: u32, send_timeout_ms: u32) -> Result<AsyncTask<SendFrameTask>> {
        if !acknowledge_no_decoder { return Err(Error::from_reason("explicit non-decoding sink acknowledgement required")); }
        if capture_timeout_ms == 0 || capture_timeout_ms > 2000 { return Err(Error::from_reason("captureTimeoutMs must be 1..2000")); }
        let send_wait = wait(send_timeout_ms)?;
        let busy = SessionBusy::acquire(&self.state)?;
        Ok(AsyncTask::new(SendFrameTask { state: self.state.clone(), _busy: busy, display_index, capture_wait: Duration::from_millis(capture_timeout_ms.into()), send_wait }))
    }
    /// Send a bounded VP9 burst using one capture and encoder instance. This
    /// holds a libuv worker and serializes all host operations for the burst;
    /// it is not an autonomous session server. Viewer support and local owner
    /// consent are separate caller responsibilities.
    #[napi]
    pub fn send_vp9_burst(&self, display_index: u32, confirm_viewer_vp9: bool, fps: u32, max_frames: u32,
        max_duration_ms: u32, capture_timeout_ms: u32, send_timeout_ms: u32) -> Result<AsyncTask<SendBurstTask>> {
        if !confirm_viewer_vp9 { return Err(Error::from_reason("viewer VP9 support must be explicitly confirmed")); }
        if !(1..=30).contains(&fps) || !(1..=120).contains(&max_frames) || !(250..=5000).contains(&max_duration_ms)
            || !(1..=2000).contains(&capture_timeout_ms) {
            return Err(Error::from_reason("invalid bounded burst settings"));
        }
        let send_wait = wait(send_timeout_ms)?;
        let busy = SessionBusy::acquire(&self.state)?;
        self.state.burst_cancel.store(false, Ordering::Release);
        Ok(AsyncTask::new(SendBurstTask { state: self.state.clone(), _busy: busy, display_index, fps, max_frames,
            max_duration: Duration::from_millis(max_duration_ms.into()), capture_wait: Duration::from_millis(capture_timeout_ms.into()), send_wait }))
    }
    /// Opt-in VP9 burst with source `VideoReceived` pacing. Requires explicit
    /// duplex read-ahead and a peer that requested ACKs. The ACK is an untrusted
    /// unsequenced claim, not proof of decode/render or frame identity. Control
    /// events stop the burst; an event while waiting for ACK closes the session.
    /// Native capture/encode cannot be interrupted and may exceed deadlines.
    #[napi]
    pub fn send_vp9_ack_burst(&self, display_index: u32, confirm_viewer_vp9: bool, acknowledge_untrusted_ack: bool,
        fps: u32, max_frames: u32, max_duration_ms: u32, capture_timeout_ms: u32, send_timeout_ms: u32)
        -> Result<AsyncTask<AckBurstTask>> {
        if !confirm_viewer_vp9 || !acknowledge_untrusted_ack { return Err(Error::from_reason("explicit codec and ACK limitations acknowledgement required")); }
        if !(1..=30).contains(&fps) || !(1..=120).contains(&max_frames) || !(250..=5000).contains(&max_duration_ms)
            || !(1..=2000).contains(&capture_timeout_ms) { return Err(Error::from_reason("invalid bounded ACK burst settings")); }
        let send_wait = wait(send_timeout_ms)?;
        let busy = SessionBusy::acquire(&self.state)?;
        self.state.burst_cancel.store(false, Ordering::Release);
        Ok(AsyncTask::new(AckBurstTask { state: self.state.clone(), _busy: busy, display_index, fps, max_frames,
            max_duration: Duration::from_millis(max_duration_ms.into()), capture_wait: Duration::from_millis(capture_timeout_ms.into()), send_wait }))
    }
    /// Same bounded ACK-paced burst for an explicit trusted, non-decoding
    /// diagnostic sink. This does not assert viewer decoder capability.
    #[napi]
    pub fn send_vp9_ack_burst_to_trusted_sink(&self, display_index: u32, acknowledge_no_decoder: bool,
        acknowledge_untrusted_ack: bool, fps: u32, max_frames: u32, max_duration_ms: u32,
        capture_timeout_ms: u32, send_timeout_ms: u32) -> Result<AsyncTask<AckBurstTask>> {
        if !acknowledge_no_decoder { return Err(Error::from_reason("explicit non-decoding sink acknowledgement required")); }
        self.send_vp9_ack_burst(display_index, true, acknowledge_untrusted_ack, fps, max_frames, max_duration_ms, capture_timeout_ms, send_timeout_ms)
    }
    /// Cooperatively stop a running/queued VP9 burst. This never blocks and
    /// can be called while another operation is active; it cannot interrupt a
    /// native capture or in-flight send. Await the burst before closing.
    #[napi]
    pub fn request_stop_burst(&self) { self.state.burst_cancel.store(true, Ordering::Release); }
    /// Sample and optionally disclose a foreground-display change on Windows.
    /// Both booleans are local application assertions, not a trusted consent UI.
    /// No background tracking or capture switch is started. Caller must handle
    /// topology changes, DPI/desktop context, rate limits and tracker resets.
    #[napi]
    pub fn send_windows_focus_hint(&self, confirm_local_consent: bool, follow_enabled: bool, timeout_ms: u32) -> Result<AsyncTask<FocusHintTask>> {
        if !confirm_local_consent || !follow_enabled { return Err(Error::from_reason("local consent and follow preference are required")); }
        let deadline = wait(timeout_ms)?;
        let busy = SessionBusy::acquire(&self.state)?;
        Ok(AsyncTask::new(FocusHintTask { state: self.state.clone(), _busy: busy, deadline }))
    }
    /// Explicit cursor-follow sample. The current display and multi-UI state
    /// are caller claims; consent/preference booleans are not a trusted UI.
    #[napi]
    pub fn send_windows_cursor_follow_hint(&self, current_display: u32, multi_ui_session: bool,
        confirm_local_consent: bool, follow_enabled: bool, timeout_ms: u32) -> Result<AsyncTask<CursorFollowTask>> {
        if !confirm_local_consent || !follow_enabled { return Err(Error::from_reason("local consent and follow preference are required")); }
        let deadline = wait(timeout_ms)?;
        let busy = SessionBusy::acquire(&self.state)?;
        Ok(AsyncTask::new(CursorFollowTask { state: self.state.clone(), _busy: busy, current_display, multi_ui_session, deadline }))
    }
    /// Forget focus history on a policy or topology change; sends nothing.
    #[napi]
    pub fn reset_window_focus(&self) -> Result<()> {
        let _busy = SessionBusy::acquire(&self.state)?;
        let mut data = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let session = data.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?;
        if session.approved_displays.is_none() { return Err(Error::from_reason("host session is not approved")); }
        session.focus.reset(); Ok(())
    }
    /// Sample the current Windows cursor after caller-asserted view approval and
    /// send shape/position. This is not proof of informed local consent.
    /// Returns false if hidden/unavailable. Non-Windows platforms reject this
    /// method. Does not support secure desktop or portable-service capture.
    #[napi]
    pub fn sample_windows_cursor(&self, timeout_ms: u32) -> Result<AsyncTask<SampleCursorTask>> {
        let deadline = wait(timeout_ms)?;
        let busy = SessionBusy::acquire(&self.state)?;
        Ok(AsyncTask::new(SampleCursorTask { state: self.state.clone(), _busy: busy, deadline }))
    }
    /// Explicitly select the bounded per-session cursor announcement mode.
    /// The application must handle peer cache misses and resend requests; the
    /// peer may not retain shapes even after a successful send. This does not
    /// grant view permission or sample a cursor. It cannot be mixed with the
    /// always-shape mode or reset within a live session.
    #[napi]
    pub fn enable_cursor_announcements(&self, acknowledge_peer_cache_misses: bool) -> Result<()> {
        if !acknowledge_peer_cache_misses { return Err(Error::from_reason("peer cache misses must be explicitly acknowledged")); }
        let _busy = SessionBusy::acquire(&self.state)?;
        let mut data = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let session = data.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?;
        if session.approved_displays.is_none() { return Err(Error::from_reason("host session is not approved")); }
        if !matches!(&session.cursor_mode, CursorDeliveryMode::Unset) { return Err(Error::from_reason("cursor delivery mode already selected")); }
        let book = remote_core::cursor_delivery::CursorDelivery::new(session.id, 128, remote_protocol::cursor::MAX_CACHE_BYTES).map_err(js_error)?;
        session.cursor_mode = CursorDeliveryMode::PerSession(book);
        Ok(())
    }
    /// Explicitly sample the Windows cursor in per-session announcement mode.
    /// Local consent and peer cache recovery are caller responsibilities; this
    /// is not a background service and does not handle hidden cursors.
    #[napi]
    pub fn sample_windows_cursor_announcement(&self, force_shape: bool, timeout_ms: u32) -> Result<AsyncTask<SampleCursorAnnouncementTask>> {
        let deadline = wait(timeout_ms)?;
        let busy = SessionBusy::acquire(&self.state)?;
        Ok(AsyncTask::new(SampleCursorAnnouncementTask { state: self.state.clone(), _busy: busy, force_shape, deadline }))
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
    /// Send one caller-driven host TestDelay probe after asserted view approval.
    /// No timer, source QoS loop or correlation is provided; replies are
    /// untrusted and may be forged/replayed. Failed/cancelled sends require
    /// closing this session rather than retrying uncertain delivery.
    #[napi]
    pub fn send_delay_probe(&self, last_delay_ms: u32, target_bitrate_kbps: u32, timeout_ms: u32) -> Result<AsyncTask<SendDelayProbeTask>> {
        if last_delay_ms > remote_codec::video_qos::MAX_DELAY_MS || target_bitrate_kbps > remote_codec::video_qos::MAX_BITRATE_KBPS {
            return Err(Error::from_reason("invalid probe delay or bitrate"));
        }
        let deadline = wait(timeout_ms)?;
        let busy = SessionBusy::acquire(&self.state)?;
        Ok(AsyncTask::new(SendDelayProbeTask { state: self.state.clone(), _busy: busy, last_delay_ms, target_bitrate_kbps, deadline }))
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
    /// Enable experimental direct-TCP read-ahead after view approval. The
    /// method does not create a parallel capture or input dispatcher.
    #[napi]
    pub fn enable_duplex_read_ahead(&self, acknowledge_experimental: bool) -> Result<AsyncTask<EnableHostDuplexTask>> {
        if !acknowledge_experimental { return Err(Error::from_reason("explicit experimental duplex acknowledgement required")); }
        let busy = SessionBusy::acquire(&self.state)?;
        Ok(AsyncTask::new(EnableHostDuplexTask { state: self.state.clone(), _busy: busy }))
    }
    /// Poll one queued event; unlike receiveEvent an empty queue is not a
    /// timeout and does not close the connection. TestDelay may require a send.
    #[napi]
    pub fn try_receive_event(&self, send_timeout_ms: u32) -> Result<AsyncTask<TryHostEventTask>> {
        let deadline = wait(send_timeout_ms)?; let busy = SessionBusy::acquire(&self.state)?;
        Ok(AsyncTask::new(TryHostEventTask { state: self.state.clone(), _busy: busy, deadline }))
    }
    /// Enable caller-driven inactivity accounting after approval. This does not
    /// start a timer; the embedding application must poll and clean up promptly.
    #[napi]
    pub fn enable_idle_timeout(&self, minutes: u32) -> Result<()> {
        let _busy = SessionBusy::acquire(&self.state)?;
        let mut data = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        data.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?.host.enable_idle_timeout(minutes).map_err(js_error)
    }
    /// Approximate time until timeout, rounded up to milliseconds. Null means
    /// disabled. The application is still responsible for driving the check.
    #[napi]
    pub fn idle_remaining_ms(&self) -> Result<Option<u32>> {
        let _busy = SessionBusy::acquire(&self.state)?;
        let data = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let remaining = data.as_ref().ok_or_else(|| Error::from_reason("host session closed"))?.host.idle_remaining().map_err(js_error)?;
        remaining.map(|value| {
            let millis = value.as_millis() + if value.subsec_nanos() % 1_000_000 != 0 { 1 } else { 0 };
            u32::try_from(millis).map_err(|_| Error::from_reason("idle timeout overflow"))
        }).transpose()
    }
    /// Perform one local inactivity check. If expired, close and release the
    /// Node session slot. No peer close reason or capture interruption is sent.
    /// This cannot overlap capture, receive, or another operation.
    #[napi]
    pub fn poll_idle_timeout(&self) -> Result<bool> {
        let _busy = SessionBusy::acquire(&self.state)?;
        let mut data = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let expired = data.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?.host.poll_idle_timeout().map_err(js_error)?;
        if expired {
            data.take();
            self.state.lease.lock().map_err(|_| Error::from_reason("host session lease poisoned"))?.take();
            if let Some(task) = self.state.expiration.lock().map_err(|_| Error::from_reason("host expiration state poisoned"))?.take() { task.abort(); }
        }
        Ok(expired)
    }
    /// Enable the restricted source Windows scan-mode dispatcher. The boolean
    /// is only the application's assertion; it is not proof of OS consent.
    #[napi]
    pub fn set_windows_scan_mode_enabled(&self, enabled: bool, confirm_local_consent: bool) -> Result<()> {
        if enabled && !confirm_local_consent { return Err(Error::from_reason("local consent is required")); }
        let _busy = SessionBusy::acquire(&self.state)?;
        #[cfg(target_os = "windows")]
        {
            let mut data = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
            data.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?.host.set_windows_scan_mode_enabled(enabled).map_err(js_error)
        }
        #[cfg(not(target_os = "windows"))]
        { Err(Error::from_reason("Windows keyboard mode is unavailable on this platform")) }
    }
    /// Enable the restricted Windows Translate `Chr` dispatcher, not complete
    /// layout translation. The caller must own the OS input device.
    #[napi]
    pub fn set_windows_translate_mode_enabled(&self, enabled: bool, confirm_local_consent: bool) -> Result<()> {
        if enabled && !confirm_local_consent { return Err(Error::from_reason("local consent is required")); }
        let _busy = SessionBusy::acquire(&self.state)?;
        #[cfg(target_os = "windows")]
        {
            let mut data = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
            data.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?.host.set_windows_translate_mode_enabled(enabled).map_err(js_error)
        }
        #[cfg(not(target_os = "windows"))]
        { Err(Error::from_reason("Windows keyboard mode is unavailable on this platform")) }
    }
    /// Enable repeated downs for supported Windows keyboard modes. No timer,
    /// rate limiter or global input arbitration is supplied by this method.
    #[napi]
    pub fn set_windows_key_repeat_enabled(&self, enabled: bool, confirm_local_consent: bool) -> Result<()> {
        if enabled && !confirm_local_consent { return Err(Error::from_reason("local consent is required")); }
        let _busy = SessionBusy::acquire(&self.state)?;
        #[cfg(target_os = "windows")]
        {
            let mut data = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
            data.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?.host.set_windows_key_repeat_enabled(enabled).map_err(js_error)
        }
        #[cfg(not(target_os = "windows"))]
        { Err(Error::from_reason("Windows key repeat is unavailable on this platform")) }
    }
    /// Enable caller-driven 30-second receive liveness accounting after approval.
    /// This creates no timer or probes and does not establish identity.
    #[napi]
    pub fn enable_receive_watchdog(&self) -> Result<()> {
        let _busy = SessionBusy::acquire(&self.state)?;
        let mut data = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        data.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?.host.enable_receive_watchdog().map_err(js_error)
    }
    /// Approximate receive deadline, rounded up. Dequeue time may differ from
    /// actual arrival with the experimental duplex driver.
    #[napi]
    pub fn receive_watchdog_remaining_ms(&self) -> Result<Option<u32>> {
        let _busy = SessionBusy::acquire(&self.state)?;
        let data = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let remaining = data.as_ref().ok_or_else(|| Error::from_reason("host session closed"))?.host.receive_watchdog_remaining().map_err(js_error)?;
        remaining.map(|value| {
            let millis = value.as_millis() + if value.subsec_nanos() % 1_000_000 != 0 { 1 } else { 0 };
            u32::try_from(millis).map_err(|_| Error::from_reason("receive watchdog timeout overflow"))
        }).transpose()
    }
    /// Explicitly close and release the local session slot on timeout. Cannot
    /// overlap another operation and cannot interrupt native work or a send.
    #[napi]
    pub fn poll_receive_watchdog(&self) -> Result<bool> {
        let _busy = SessionBusy::acquire(&self.state)?;
        let mut data = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        let expired = data.as_mut().ok_or_else(|| Error::from_reason("host session closed"))?.host.poll_receive_watchdog().map_err(js_error)?;
        if expired {
            data.take();
            self.state.lease.lock().map_err(|_| Error::from_reason("host session lease poisoned"))?.take();
            if let Some(task) = self.state.expiration.lock().map_err(|_| Error::from_reason("host expiration state poisoned"))?.take() { task.abort(); }
        }
        Ok(expired)
    }
    /// Send a best-effort source close notification on an approved session,
    /// then close locally. Explicit close remains necessary to release the slot.
    #[napi]
    pub fn send_close_reason(&self, reason: String, timeout_ms: u32) -> Result<AsyncTask<HostCloseReasonTask>> {
        let reason = Zeroizing::new(reason);
        remote_protocol::Envelope::close_reason_event(&reason).map_err(js_error)?;
        let deadline = wait(timeout_ms)?;
        let busy = SessionBusy::acquire(&self.state)?;
        Ok(AsyncTask::new(HostCloseReasonTask { state: self.state.clone(), _busy: busy, reason, deadline }))
    }
    /// Request terminal close without waiting for an active worker. In-flight
    /// delivery can be indeterminate and native calls may not be interruptible.
    /// Await active work and call `close` to release the session lease/retry any
    /// detectable cleanup. This is not a trusted consent or cancellation UI.
    #[napi]
    pub fn request_close(&self) -> Result<()> {
        self.state.close_signal.request();
        self.state.burst_cancel.store(true, Ordering::Release);
        finish_requested_session_close(&self.state)
    }
    /// Close/reject the session. Must not overlap another session operation.
    #[napi]
    pub fn close(&self) -> Result<()> {
        let _busy = SessionBusy::acquire_raw(&self.state)?;
        let mut data = self.state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
        if let Some(session) = data.as_mut() { session.host.close().map_err(js_error)?; }
        data.take();
        self.state.lease.lock().map_err(|_| Error::from_reason("host session lease poisoned"))?.take();
        if let Some(task) = self.state.expiration.lock().map_err(|_| Error::from_reason("host expiration state poisoned"))?.take() { task.abort(); }
        Ok(())
    }
}

// `None` cancels the in-flight future, never proving non-delivery. The checked
// out session is subsequently closed by the sticky close gate; no retry is safe.
macro_rules! host_io {
    ($state:expr, $future:expr) => {{
        let state = $state;
        let result = runtime()?.block_on(state.close_signal.race($future));
        match result {
            Some(result) if !state.close_signal.is_requested() => result.map_err(js_error),
            _ => Err(Error::from_reason("host session close requested; delivery may be indeterminate")),
        }
    }};
}

pub struct HostCloseReasonTask { state: Arc<SessionState>, _busy: SessionBusy, reason: Zeroizing<String>, deadline: Duration }
impl Task for HostCloseReasonTask {
    type Output = (); type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut checkout = SessionCheckout::approved(&self.state)?;
        let session = checkout.data.as_mut().ok_or_else(|| Error::from_reason("host session unavailable"))?;
        let result = (|| host_io!(&self.state, session.host.send_close_reason(&self.reason, self.deadline)))();
        self.state.close_signal.request();
        result
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { Ok(()) }
}

pub struct EnableHostDuplexTask { state: Arc<SessionState>, _busy: SessionBusy }
impl Task for EnableHostDuplexTask {
    type Output = (); type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut checkout = SessionCheckout::approved(&self.state)?;
        let session = checkout.data.as_mut().ok_or_else(|| Error::from_reason("host session unavailable"))?;
        host_io!(&self.state, async { session.host.enable_duplex_read_ahead() })?;
        session.duplex_enabled = true;
        Ok(())
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested; delivery may be indeterminate")); } Ok(()) }
}
pub struct ApproveTask { state: Arc<SessionState>, _busy: SessionBusy, deadline: Duration }
impl Task for ApproveTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut checkout = SessionCheckout::pending(&self.state)?;
        let session = checkout.data.as_mut().ok_or_else(|| Error::from_reason("host session unavailable"))?;
        if Instant::now() >= session.approval_deadline {
            let _ = session.host.close();
            return Err(Error::from_reason("local owner approval expired"));
        }
        // Enumeration may reveal screen geometry; it happens only on explicit
        // local approval and is not a stable identity across hotplug.
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested")); }
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
        // Enumeration is blocking and can finish after expiry. Do not let the
        // expiration timer's mutex contention authorize a stale approval.
        if Instant::now() >= session.approval_deadline {
            let _ = session.host.close();
            return Err(Error::from_reason("local owner approval expired"));
        }
        let end = Instant::now().checked_add(self.deadline).ok_or_else(|| Error::from_reason("invalid approval deadline"))?.min(session.approval_deadline);
        let permissions = Permissions { view_screen: true, ..Default::default() };
        let mut approval = OwnerApproval::new(session.id, session.principal.clone(), Some(permissions));
        let result = (|| -> Result<()> {
            if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested")); }
            session.host.authorize(permissions, &mut approval).map_err(js_error)?;
            session.host.set_authorized_message_limit(POSTAUTH).map_err(js_error)?;
            host_io!(&self.state, async {
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
        // A transport implementation may finish just after its deadline. A
        // success message may already have reached the peer, but this host must
        // not retain an approved session past the owner's approval deadline.
        if Instant::now() >= end {
            let _ = session.host.close();
            return Err(Error::from_reason("local owner approval expired"));
        }
        session.approved_displays = Some(approved_displays);
        Ok(())
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested; delivery may be indeterminate")); } Ok(()) }
}

/// RAII checkout ensures no session mutex guard is held during network I/O.
/// SessionBusy excludes ordinary concurrent operations while the state is out.
struct SessionCheckout { state: Arc<SessionState>, data: Option<SessionData> }
impl SessionCheckout {
    /// Checkout a pending login while the approval task owns SessionBusy.
    /// The deadline task must retry while checked out, including on failure.
    fn pending(state: &Arc<SessionState>) -> Result<Self> {
        let data = {
            let mut slot = state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
            let session = slot.as_ref().ok_or_else(|| Error::from_reason("host session closed"))?;
            if session.approved_displays.is_some() { return Err(Error::from_reason("host session already approved")); }
            slot.take().ok_or_else(|| Error::from_reason("host session closed"))?
        };
        Ok(Self { state: state.clone(), data: Some(data) })
    }
    fn approved(state: &Arc<SessionState>) -> Result<Self> {
        let data = {
            let mut slot = state.data.lock().map_err(|_| Error::from_reason("host session state poisoned"))?;
            let session = slot.as_ref().ok_or_else(|| Error::from_reason("host session closed"))?;
            if session.approved_displays.is_none() { return Err(Error::from_reason("host session is not approved")); }
            slot.take().ok_or_else(|| Error::from_reason("host session closed"))?
        };
        Ok(Self { state: state.clone(), data: Some(data) })
    }
}
impl Drop for SessionCheckout {
    fn drop(&mut self) {
        // Unwinding may interrupt a network/encoder operation after side
        // effects. Do not return a live uncertain session for reuse.
        if std::thread::panicking() { self.state.close_signal.request(); }
        if self.state.close_signal.is_requested() {
            if let Some(session) = self.data.as_mut() {
                session.cursor_mode = CursorDeliveryMode::Unset;
                // Retain the session for explicit cleanup retry on failure.
                let _ = session.host.close();
            }
        }
        if let Ok(mut slot) = self.state.data.lock() {
            if slot.is_none() { *slot = self.data.take(); }
        }
        // If the mutex is poisoned, any remaining data is dropped/closed and
        // the application must treat this session slot as failed, not retry it.
    }
}
pub struct SendDelayProbeTask { state: Arc<SessionState>, _busy: SessionBusy, last_delay_ms: u32, target_bitrate_kbps: u32, deadline: Duration }
impl Task for SendDelayProbeTask {
    type Output = (); type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        let mut checkout = SessionCheckout::approved(&self.state)?;
        let session = checkout.data.as_mut().ok_or_else(|| Error::from_reason("host session unavailable"))?;
        host_io!(&self.state, session.host.send_delay_probe(self.last_delay_ms, self.target_bitrate_kbps, self.deadline))
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested; delivery may be indeterminate")); } Ok(()) }
}

pub struct FocusHintTask { state: Arc<SessionState>, _busy: SessionBusy, deadline: Duration }
impl Task for FocusHintTask {
    type Output = bool; type JsValue = bool;
    fn compute(&mut self) -> Result<bool> {
        #[cfg(target_os = "windows")]
        {
            let mut checkout = SessionCheckout::approved(&self.state)?;
            let session = checkout.data.as_mut().ok_or_else(|| Error::from_reason("host session unavailable"))?;
            let approved = session.approved_displays.as_deref().ok_or_else(|| Error::from_reason("host session is not approved"))?;
            host_io!(&self.state, session.host.send_windows_focus_hint(&mut session.focus, approved, true, true, self.deadline))
        }
        #[cfg(not(target_os = "windows"))]
        { Err(Error::from_reason("Windows focus tracking is unavailable on this platform")) }
    }
    fn resolve(&mut self, _: Env, value: bool) -> Result<bool> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested; delivery may be indeterminate")); } Ok(value) }
}

pub struct CursorFollowTask { state: Arc<SessionState>, _busy: SessionBusy, current_display: u32, multi_ui_session: bool, deadline: Duration }
impl Task for CursorFollowTask {
    type Output = bool; type JsValue = bool;
    fn compute(&mut self) -> Result<bool> {
        #[cfg(target_os = "windows")]
        {
            let mut checkout = SessionCheckout::approved(&self.state)?;
            let session = checkout.data.as_mut().ok_or_else(|| Error::from_reason("host session unavailable"))?;
            let approved = session.approved_displays.as_deref().ok_or_else(|| Error::from_reason("host session is not approved"))?;
            host_io!(&self.state, session.host.send_windows_cursor_follow_hint(approved, self.current_display, self.multi_ui_session, true, true, self.deadline))
        }
        #[cfg(not(target_os = "windows"))]
        { Err(Error::from_reason("Windows cursor follow is unavailable on this platform")) }
    }
    fn resolve(&mut self, _: Env, value: bool) -> Result<bool> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested; delivery may be indeterminate")); } Ok(value) }
}

/// A one-shot local capture/encoder operation, run on a Node worker.
pub struct SendFrameTask { state: Arc<SessionState>, _busy: SessionBusy, display_index: u32, capture_wait: Duration, send_wait: Duration }
impl Task for SendFrameTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        use remote_codec::{Codec, EncoderConfig};
        let mut checkout = SessionCheckout::approved(&self.state)?;
        let session = checkout.data.as_mut().ok_or_else(|| Error::from_reason("host session unavailable"))?;
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested")); }
        let index = usize::try_from(self.display_index).map_err(js_error)?;
        let approved = session.approved_displays.as_ref().and_then(|items| items.get(index)).ok_or_else(|| Error::from_reason("display was not approved"))?;
        let display = remote_capture::displays().map_err(js_error)?.into_iter().nth(index).ok_or_else(|| Error::from_reason("display is no longer available"))?;
        if display.info() != approved { return Err(Error::from_reason("display enumeration changed; re-approval required")); }
        let width = u32::try_from(approved.width).map_err(js_error)?;
        let height = u32::try_from(approved.height).map_err(js_error)?;
        let display_wire = i32::try_from(self.display_index).map_err(js_error)?;
        let config = EncoderConfig { codec: Codec::Vp9, width, height, quality: 1.0, keyframe_interval: Some(30) };
        let rt = runtime()?;
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested")); }
        let mut pump = session.host.start_capture(display, display_wire, config, POSTAUTH).map_err(js_error)?;
        let result = rt.block_on(self.state.close_signal.race(session.host.send_capture(&mut pump, self.capture_wait, self.send_wait, 0)));
        let stop = session.host.stop_capture(&mut pump);
        drop(pump);
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested; delivery may be indeterminate")); }
        match result {
            Some(result) => result.map_err(js_error)?,
            None => return Err(Error::from_reason("host session close requested; delivery may be indeterminate")),
        }
        stop.map_err(js_error)?;
        Ok(())
    }
    fn resolve(&mut self, _: Env, _: ()) -> Result<()> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested; delivery may be indeterminate")); } Ok(()) }
}

/// One bounded burst; a single native capture/encoder is created and destroyed
/// on the same libuv worker. No raw texture or capturer crosses worker threads.
pub struct SendBurstTask { state: Arc<SessionState>, _busy: SessionBusy, display_index: u32, fps: u32, max_frames: u32,
    max_duration: Duration, capture_wait: Duration, send_wait: Duration }
impl Task for SendBurstTask {
    type Output = u32;
    type JsValue = u32;
    fn compute(&mut self) -> Result<u32> {
        use remote_codec::{Codec, EncoderConfig};
        use remote_core::{capture_pump::CapturePumpError, video_schedule::FrameCadence};
        let mut checkout = SessionCheckout::approved(&self.state)?;
        let session = checkout.data.as_mut().ok_or_else(|| Error::from_reason("host session unavailable"))?;
        // A burst serializes all host operations, so it cannot consume ACKs or
        // safely preserve other events while running. Do not promise peer ACK
        // pacing and then silently emit multiple frames without waiting.
        if session.host.initial_video_ack_required().map_err(js_error)? {
            return Err(Error::from_reason("ACK-paced bursts require the separate explicit sendVp9AckBurst API"));
        }
        let index = usize::try_from(self.display_index).map_err(js_error)?;
        let approved = session.approved_displays.as_ref().and_then(|items| items.get(index)).ok_or_else(|| Error::from_reason("display was not approved"))?.clone();
        let display = remote_capture::displays().map_err(js_error)?.into_iter().nth(index).ok_or_else(|| Error::from_reason("display is no longer available"))?;
        if display.info() != &approved { return Err(Error::from_reason("display enumeration changed; re-approval required")); }
        let config = EncoderConfig { codec: Codec::Vp9, width: u32::try_from(approved.width).map_err(js_error)?,
            height: u32::try_from(approved.height).map_err(js_error)?, quality: 1.0, keyframe_interval: Some(30) };
        let display_wire = i32::try_from(self.display_index).map_err(js_error)?;
        let rt = runtime()?;
        let mut cadence = FrameCadence::new(self.fps).map_err(js_error)?;
        let started = Instant::now();
        let end = started.checked_add(self.max_duration).ok_or_else(|| Error::from_reason("invalid burst deadline"))?;
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested")); }
        if self.state.burst_cancel.load(Ordering::Acquire) { return Ok(0); }
        let mut pump = session.host.start_capture(display, display_wire, config, POSTAUTH).map_err(js_error)?;
        let result = (|| -> Result<u32> {
            let mut sent = 0;
            while sent < self.max_frames {
                if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested")); }
                if self.state.burst_cancel.load(Ordering::Acquire) { break; }
                let now = Instant::now();
                if now >= end { break; }
                if let Some(delay) = cadence.remaining(now).map_err(js_error)? {
                    std::thread::sleep(delay.min(end.saturating_duration_since(now)).min(Duration::from_millis(50)));
                    continue;
                }
                cadence.begin_attempt(now).map_err(js_error)?;
                // The exact display handle is retained by the pump. Recheck the
                // approved snapshot too; metadata equality is not a stable ID.
                let current = remote_capture::displays().map_err(js_error)?.into_iter().nth(index).ok_or_else(|| Error::from_reason("display is no longer available"))?;
                if current.info() != &approved { return Err(Error::from_reason("display enumeration changed; re-approval required")); }
                let remaining = end.saturating_duration_since(Instant::now());
                if remaining.is_zero() || self.state.burst_cancel.load(Ordering::Acquire) { break; }
                let pts = i64::try_from(started.elapsed().as_millis()).map_err(js_error)?;
                let outcome = rt.block_on(self.state.close_signal.race(session.host.send_capture(&mut pump, self.capture_wait.min(remaining), self.send_wait.min(remaining), pts)));
                if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested; delivery may be indeterminate")); }
                match outcome {
                    Some(Ok(())) => sent += 1,
                    Some(Err(remote_core::host_connection::ConnectionError::Capture(CapturePumpError::Capture(e)))) if e.kind() == io::ErrorKind::WouldBlock => {},
                    Some(Err(error)) => return Err(js_error(error)),
                    None => return Err(Error::from_reason("host session close requested; delivery may be indeterminate")),
                }
            }
            if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested")); }
            Ok(sent)
        })();
        // Always attempt to leave the streaming lifecycle, including when
        // enumeration/encoding fails. Network abort may already close it.
        let stop = session.host.stop_capture(&mut pump);
        drop(pump);
        match result { Err(error) => Err(error), Ok(sent) => { stop.map_err(js_error)?; Ok(sent) } }
    }
    fn resolve(&mut self, _: Env, sent: u32) -> Result<u32> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested; delivery may be indeterminate")); } Ok(sent) }
}

/// Untrusted host-side event. Post-login raw options may contain unrelated
/// fields; never apply them without local validation and authorization.
#[napi(object)]
pub struct LocalHostEvent {
    pub kind: String,
    pub display: Option<u32>, pub cursor_id: Option<String>, pub windows_session_id: Option<u32>,
    pub data: Option<Buffer>,
    pub vp8: Option<i32>, pub vp9: Option<i32>, pub av1: Option<i32>,
    pub h264: Option<i32>, pub h265: Option<i32>, pub preference: Option<i32>,
    pub image_quality: Option<i32>, pub custom_fps: Option<u32>, pub recording: Option<bool>,
    pub show_remote_cursor: Option<bool>, pub follow_remote_cursor: Option<bool>, pub follow_remote_window: Option<bool>, pub show_my_cursor: Option<bool>,
    pub disable_keyboard: Option<bool>,
    pub probe_time: Option<String>, pub probe_last_delay: Option<u32>, pub probe_target_bitrate: Option<u32>,
}
pub struct HostEventTask { state: Arc<SessionState>, _busy: SessionBusy, deadline: Duration }
impl Task for HostEventTask {
    type Output = HostEvent;
    type JsValue = LocalHostEvent;
    fn compute(&mut self) -> Result<HostEvent> {
        let mut checkout = SessionCheckout::approved(&self.state)?;
        let session = checkout.data.as_mut().ok_or_else(|| Error::from_reason("host session unavailable"))?;
        host_io!(&self.state, session.host.receive_event(self.deadline))
    }
    fn resolve(&mut self, _: Env, event: HostEvent) -> Result<LocalHostEvent> {
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested")); }
        host_event_to_js(event)
    }
}
/// One bounded ACK-paced burst. Any returned event remains untrusted and must
/// be handled by the application. The host's normal dispatch may already echo
/// heartbeats or attempt input according to local permissions; the Node host's
/// backend remains view-only and denies OS input.
#[napi(object)]
pub struct AckBurstResult { pub sent: u32, pub reason: String, pub event: Option<LocalHostEvent>, pub connection_closed: bool }
pub struct AckBurstOutput { sent: u32, reason: &'static str, event: Option<HostEvent>, close: bool }
pub struct AckBurstTask { state: Arc<SessionState>, _busy: SessionBusy, display_index: u32, fps: u32, max_frames: u32,
    max_duration: Duration, capture_wait: Duration, send_wait: Duration }
impl Task for AckBurstTask {
    type Output = AckBurstOutput;
    type JsValue = AckBurstResult;
    fn compute(&mut self) -> Result<AckBurstOutput> {
        use remote_codec::{Codec, EncoderConfig};
        use remote_core::{capture_pump::CapturePumpError, host_connection::ConnectionError, video::SendOutcome, video_schedule::FrameCadence};
        use remote_protocol::video_control::VideoControl;
        let mut checkout = SessionCheckout::approved(&self.state)?;
        let session = checkout.data.as_mut().ok_or_else(|| Error::from_reason("host session unavailable"))?;
        if !session.duplex_enabled { return Err(Error::from_reason("duplex read-ahead must be enabled")); }
        if !session.host.initial_video_ack_required().map_err(js_error)? { return Err(Error::from_reason("peer did not request video ACK pacing")); }
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested")); }
        if self.state.burst_cancel.load(Ordering::Acquire) { return Ok(AckBurstOutput { sent: 0, reason: "requested", event: None, close: false }); }
        let index = usize::try_from(self.display_index).map_err(js_error)?;
        let approved = session.approved_displays.as_ref().and_then(|items| items.get(index))
            .ok_or_else(|| Error::from_reason("display not approved"))?.clone();
        let display = remote_capture::displays().map_err(js_error)?.into_iter().nth(index)
            .ok_or_else(|| Error::from_reason("display is no longer available"))?;
        if display.info() != &approved { return Err(Error::from_reason("display topology changed; reapproval required")); }
        let config = EncoderConfig { codec: Codec::Vp9, width: u32::try_from(approved.width).map_err(js_error)?,
            height: u32::try_from(approved.height).map_err(js_error)?, quality: 1.0, keyframe_interval: Some(30) };
        let wire_index = i32::try_from(self.display_index).map_err(js_error)?;
        let rt = runtime()?;
        let start = Instant::now();
        let end = start.checked_add(self.max_duration).ok_or_else(|| Error::from_reason("invalid burst deadline"))?;
        let mut cadence = FrameCadence::new(self.fps).map_err(js_error)?;
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested")); }
        if self.state.burst_cancel.load(Ordering::Acquire) { return Ok(AckBurstOutput { sent: 0, reason: "requested", event: None, close: false }); }
        let mut pump = match session.host.start_capture(display, wire_index, config, POSTAUTH) {
            Ok(pump) => pump,
            Err(error) => { let _ = session.host.close(); return Err(js_error(error)); },
        };
        let raced = rt.block_on(self.state.close_signal.race(async {
            let mut sent = 0u32;
            loop {
                if self.state.burst_cancel.load(Ordering::Acquire) { return Ok(AckBurstOutput { sent, reason: "requested", event: None, close: false }); }
                if session.host.poll_idle_timeout().map_err(js_error)? || session.host.poll_receive_watchdog().map_err(js_error)? {
                    return Err(Error::from_reason("host session liveness timeout"));
                }
                let now = Instant::now();
                if sent >= self.max_frames { return Ok(AckBurstOutput { sent, reason: "frameLimit", event: None, close: false }); }
                if now >= end { return Ok(AckBurstOutput { sent, reason: "deadline", event: None, close: false }); }
                // Drain one control event before attempting a frame. A stray ACK
                // cannot be attributed to a future frame and is fatal.
                let remaining = end.saturating_duration_since(now);
                if let Some(event) = session.host.try_receive_event(self.send_wait.min(remaining)).await.map_err(js_error)? {
                    if matches!(&event, HostEvent::VideoControl(VideoControl::FrameReceived)) { return Err(Error::from_reason("unsolicited or stale video ACK")); }
                    return Ok(AckBurstOutput { sent, reason: "event", event: Some(event), close: false });
                }
                let now = Instant::now();
                let remaining = end.saturating_duration_since(now);
                if remaining.is_zero() { continue; }
                if let Some(delay) = cadence.remaining(now).map_err(js_error)? {
                    tokio::time::sleep(delay.min(Duration::from_millis(20)).min(remaining)).await;
                    continue;
                }
                // Like the existing burst, treat topology metadata as a volatile
                // guard, not a stable display identity or proof of consent.
                let current = remote_capture::displays().map_err(js_error)?.into_iter().nth(index)
                    .ok_or_else(|| Error::from_reason("display is no longer available"))?;
                if current.info() != &approved { return Err(Error::from_reason("display topology changed; reapproval required")); }
                let now = Instant::now();
                let remaining = end.saturating_duration_since(now);
                if remaining.is_zero() || self.state.burst_cancel.load(Ordering::Acquire) { continue; }
                if !cadence.begin_attempt(now).map_err(js_error)? { continue; }
                let pts = i64::try_from(now.duration_since(start).as_millis()).map_err(js_error)?;
                match session.host.send_capture_outcome(&mut pump, self.capture_wait.min(remaining), self.send_wait.min(remaining), pts).await {
                    Ok(SendOutcome::VpxNoOutput) => continue,
                    Err(ConnectionError::Capture(CapturePumpError::Capture(error))) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(10).min(end.saturating_duration_since(Instant::now()))).await; continue;
                    },
                    Ok(SendOutcome::Sent) => {},
                    Err(error) => return Err(js_error(error)),
                }
                sent += 1;
                let ack_end = Instant::now().checked_add(self.send_wait).unwrap_or(end).min(end);
                loop {
                    if self.state.burst_cancel.load(Ordering::Acquire) { return Err(Error::from_reason("burst stopped with video ACK outstanding")); }
                    if session.host.poll_idle_timeout().map_err(js_error)? || session.host.poll_receive_watchdog().map_err(js_error)? {
                        return Err(Error::from_reason("host session liveness timeout"));
                    }
                    let remaining = ack_end.saturating_duration_since(Instant::now());
                    if remaining.is_zero() { return Err(Error::from_reason("video ACK deadline expired; delivery remains uncertain")); }
                    match session.host.try_receive_event(self.send_wait.min(remaining)).await.map_err(js_error)? {
                        Some(HostEvent::VideoControl(VideoControl::FrameReceived)) => break,
                        Some(event) => return Ok(AckBurstOutput { sent, reason: "eventWithAckOutstanding", event: Some(event), close: true }),
                        None => tokio::time::sleep(Duration::from_millis(10).min(remaining)).await,
                    }
                }
            }
        }));
        let result = match raced {
            Some(result) if !self.state.close_signal.is_requested() => result,
            _ => Err(Error::from_reason("host session close requested; delivery may be indeterminate")),
        };
        let stopped = session.host.stop_capture(&mut pump).map_err(js_error);
        match result {
            Err(error) => { let _ = session.host.close(); Err(error) },
            Ok(output) => {
                if let Err(error) = stopped { let _ = session.host.close(); return Err(error); }
                if output.close { session.host.close().map_err(js_error)?; }
                Ok(output)
            },
        }
    }
    fn resolve(&mut self, _: Env, output: AckBurstOutput) -> Result<AckBurstResult> {
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested; delivery may be indeterminate")); }
        Ok(AckBurstResult { sent: output.sent, reason: output.reason.into(), event: output.event.map(host_event_to_js).transpose()?, connection_closed: output.close })
    }
}

fn host_event_to_js(event: HostEvent) -> Result<LocalHostEvent> {
        use remote_protocol::video_control::VideoControl;
        let mut output = LocalHostEvent { kind: String::new(), display: None, cursor_id: None, windows_session_id: None, data: None, vp8: None, vp9: None, av1: None, h264: None, h265: None, preference: None, image_quality: None, custom_fps: None, recording: None, show_remote_cursor: None, follow_remote_cursor: None, follow_remote_window: None, show_my_cursor: None, disable_keyboard: None, probe_time: None, probe_last_delay: None, probe_target_bitrate: None };
        match event {
            HostEvent::Input => output.kind = "input".into(),
            HostEvent::InputSuppressed => output.kind = "inputSuppressed".into(),
            HostEvent::Heartbeat => output.kind = "heartbeat".into(),
            HostEvent::ProbeReply(value) => { output.kind = "heartbeat".into(); output.probe_time = Some(value.time.to_string());
                output.probe_last_delay = Some(value.last_delay); output.probe_target_bitrate = Some(value.target_bitrate); },
            HostEvent::DisplayResolutionRequest(value) => { output.kind = "displayResolution".into(); output.display = Some(value.display); },
            HostEvent::DisplayQuery(display) => { output.kind = "displayQuery".into(); output.display = Some(display); },
            HostEvent::WindowsSessionRequest(sid) => { output.kind = "windowsSessionRequest".into(); output.windows_session_id = Some(sid); },
            HostEvent::DisplaySwitchRequest { value, envelope } => { output.kind = "displaySwitch".into(); output.display = Some(value.display); output.data = Some(envelope.into_vec().into()); },
            HostEvent::CaptureDisplaysRequest { envelope, .. } => { output.kind = "captureDisplays".into(); output.data = Some(envelope.into_vec().into()); },
            HostEvent::VideoControl(VideoControl::RefreshAll) => output.kind = "refreshAll".into(),
            HostEvent::VideoControl(VideoControl::RefreshDisplay(index)) => { output.kind = "refreshDisplay".into(); output.display = Some(index); },
            HostEvent::VideoControl(VideoControl::FrameReceived) => output.kind = "frameReceived".into(),
            HostEvent::VideoControl(VideoControl::AutoAdjustFps(fps)) => { output.kind = "autoAdjustFps".into(); output.custom_fps = Some(fps); },
            HostEvent::VideoControl(VideoControl::ClientRecording(active)) => { output.kind = "clientRecording".into(); output.recording = Some(active); },
            HostEvent::CursorShapeRequest(id) => { output.kind = "cursorShapeRequest".into(); output.cursor_id = Some(id.to_string()); },
            HostEvent::VideoPreferences { values, decoding, envelope } => {
                output.kind = "videoPreferences".into();
                if let Ok(parsed) = remote_protocol::Envelope::decode(&envelope, remote_protocol::MAX_ENVELOPE_BYTES) {
                    output.disable_keyboard = parsed.disable_keyboard_preference().ok().flatten();
                    if let Ok(cursor) = parsed.cursor_preferences() {
                        output.show_remote_cursor = cursor.show_remote_cursor; output.follow_remote_cursor = cursor.follow_remote_cursor;
                        output.follow_remote_window = cursor.follow_remote_window; output.show_my_cursor = cursor.show_my_cursor;
                    }
                }
                output.data = Some(envelope.into_vec().into());
                output.image_quality = values.quality.map(|quality| quality.source_value()); output.custom_fps = values.fps;
                if let Some(values) = decoding {
                    output.vp8 = Some(values.vp8); output.vp9 = Some(values.vp9); output.av1 = Some(values.av1);
                    output.h264 = Some(values.h264); output.h265 = Some(values.h265); output.preference = Some(values.preference);
                }
            },
            HostEvent::CursorPreferences { values, decoding, envelope } => {
                output.kind = "cursorPreferences".into();
                output.disable_keyboard = remote_protocol::Envelope::decode(&envelope, remote_protocol::MAX_ENVELOPE_BYTES).ok().and_then(|e| e.disable_keyboard_preference().ok().flatten());
                output.data = Some(envelope.into_vec().into());
                output.show_remote_cursor = values.show_remote_cursor; output.follow_remote_cursor = values.follow_remote_cursor;
                output.follow_remote_window = values.follow_remote_window; output.show_my_cursor = values.show_my_cursor;
                if let Some(values) = decoding {
                    output.vp8 = Some(values.vp8); output.vp9 = Some(values.vp9); output.av1 = Some(values.av1);
                    output.h264 = Some(values.h264); output.h265 = Some(values.h265); output.preference = Some(values.preference);
                }
            },
            HostEvent::InputPreference { disable_keyboard, envelope } => {
                output.kind = "inputPreference".into(); output.disable_keyboard = Some(disable_keyboard); output.data = Some(envelope.into_vec().into());
            },
            HostEvent::DecodingAdvertisement { values, envelope } => {
                output.kind = "decodingAdvertisement".into(); output.data = Some(envelope.into_vec().into());
                output.vp8 = Some(values.vp8); output.vp9 = Some(values.vp9); output.av1 = Some(values.av1);
                output.h264 = Some(values.h264); output.h265 = Some(values.h265); output.preference = Some(values.preference);
            },
        }
        Ok(output)
}
pub struct TryHostEventTask { state: Arc<SessionState>, _busy: SessionBusy, deadline: Duration }
impl Task for TryHostEventTask {
    type Output = Option<HostEvent>; type JsValue = Option<LocalHostEvent>;
    fn compute(&mut self) -> Result<Self::Output> {
        let mut checkout = SessionCheckout::approved(&self.state)?;
        let session = checkout.data.as_mut().ok_or_else(|| Error::from_reason("host session unavailable"))?;
        host_io!(&self.state, session.host.try_receive_event(self.deadline))
    }
    fn resolve(&mut self, _: Env, event: Self::Output) -> Result<Self::JsValue> {
        if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested")); }
        event.map(host_event_to_js).transpose()
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
            let mut checkout = SessionCheckout::approved(&self.state)?;
            let session = checkout.data.as_mut().ok_or_else(|| Error::from_reason("host session unavailable"))?;
            if matches!(&session.cursor_mode, CursorDeliveryMode::Unset) { session.cursor_mode = CursorDeliveryMode::AlwaysShape; }
            else if !matches!(&session.cursor_mode, CursorDeliveryMode::AlwaysShape) { return Err(Error::from_reason("cursor delivery mode already selected")); }
            host_io!(&self.state, session.host.send_windows_cursor(self.deadline))
        }
        #[cfg(not(target_os = "windows"))]
        { Err(Error::from_reason("Windows cursor sampling is unavailable on this platform")) }
    }
    fn resolve(&mut self, _: Env, value: bool) -> Result<bool> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested; delivery may be indeterminate")); } Ok(value) }
}
/// Opt-in source-style cursor announcement; does not create a service loop.
pub struct SampleCursorAnnouncementTask { state: Arc<SessionState>, _busy: SessionBusy, force_shape: bool, deadline: Duration }
impl Task for SampleCursorAnnouncementTask {
    type Output = bool;
    type JsValue = bool;
    fn compute(&mut self) -> Result<bool> {
        #[cfg(target_os = "windows")]
        {
            let mut checkout = SessionCheckout::approved(&self.state)?;
            let session = checkout.data.as_mut().ok_or_else(|| Error::from_reason("host session unavailable"))?;
            let (host, mode) = (&mut session.host, &mut session.cursor_mode);
            let book = match mode { CursorDeliveryMode::PerSession(book) => book, _ => return Err(Error::from_reason("cursor announcements are not enabled")) };
            host_io!(&self.state, host.send_windows_cursor_announcement(book, self.force_shape, self.deadline))
        }
        #[cfg(not(target_os = "windows"))]
        { Err(Error::from_reason("Windows cursor sampling is unavailable on this platform")) }
    }
    fn resolve(&mut self, _: Env, value: bool) -> Result<bool> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested; delivery may be indeterminate")); } Ok(value) }
}
pub struct ResendCursorTask { state: Arc<SessionState>, _busy: SessionBusy, id: u64, deadline: Duration }
impl Task for ResendCursorTask {
    type Output = bool;
    type JsValue = bool;
    fn compute(&mut self) -> Result<bool> {
        let mut checkout = SessionCheckout::approved(&self.state)?;
        let session = checkout.data.as_mut().ok_or_else(|| Error::from_reason("host session unavailable"))?;
        if matches!(&session.cursor_mode, CursorDeliveryMode::Unset) { session.cursor_mode = CursorDeliveryMode::AlwaysShape; }
        let (host, mode) = (&mut session.host, &mut session.cursor_mode);
        match mode {
            CursorDeliveryMode::AlwaysShape => host_io!(&self.state, host.send_cached_cursor(self.id, self.deadline)),
            CursorDeliveryMode::PerSession(book) => host_io!(&self.state, host.resend_cursor_announcement(book, self.id, self.deadline)),
            CursorDeliveryMode::Unset => Err(Error::from_reason("cursor delivery mode unavailable")),
        }
    }
    fn resolve(&mut self, _: Env, value: bool) -> Result<bool> { if self.state.close_signal.is_requested() { return Err(Error::from_reason("host session close requested; delivery may be indeterminate")); } Ok(value) }
}
