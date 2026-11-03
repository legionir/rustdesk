//! Experimental caller-driven viewer protocol over an owned network stream.
//!
//! `NetworkTransport` alone does not authenticate or encrypt the peer. The
//! source password exchange permits offline guessing and does not authenticate
//! the host or bind to TLS. Never use this with untrusted servers, relays or
//! internet traffic. This module does not implement RustDesk's end-to-end key
//! exchange, host-side 2FA enforcement, trusted devices, negotiation, reconnect, rendering, complete
//! multiplexing, or a hardened video decoder. It has not been built or tested.

use remote_protocol::{cursor::{CursorError, CursorPosition, CursorShape}, desktop::{DesktopError, LoginResult, PeerInfo}, DesktopLogin, Envelope, MessageKind, ProtocolError, TestDelay, VideoCodec, MAX_ENVELOPE_BYTES, MAX_PRE_AUTH_BYTES};
use remote_security::{password_response, PasswordChallenge, SecurityError};
use remote_transport::{NetworkTransport, NetworkTransportError};
use std::{error::Error, fmt, time::{Duration, Instant}};
use zeroize::Zeroizing;

/// Labels provided by the viewer, not authenticated by these fields.
#[derive(Debug, Clone)]
pub struct LoginIdentity {
    pub target: String,
    pub viewer_id: String,
    pub viewer_name: String,
    pub wire_session_id: u64,
    pub version: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase { New, Busy, Connected, Closed }
/// Viewer operation failure. No error is proof that a peer is authentic.
pub enum ViewerError {
    InvalidState,
    /// Peer requested close; reason is untrusted and may be absent if oversized.
    PeerClosed(Option<String>),
    Deadline,
    UnexpectedMessage,
    /// Explicit second-factor flow was accepted without a prompt; rejected.
    TwoFactorNotRequested,
    Denied(String),
    Protocol(ProtocolError),
    Security(SecurityError),
    Desktop(DesktopError),
    DisplayControl(remote_protocol::display_control::DisplayControlError),
    Preferences(remote_protocol::video_preferences::PreferenceError),
    Cursor(CursorError),
    Network(NetworkTransportError),
}
// Never implicitly log peer-provided denial/close strings. Nested diagnostics
// may still contain untrusted or sensitive information and need caller review.
impl fmt::Debug for ViewerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerClosed(_) => f.write_str("ViewerError::PeerClosed(..)"),
            Self::Denied(_) => f.write_str("ViewerError::Denied(..)"),
            _ => write!(f, "ViewerError({self})"),
        }
    }
}
impl fmt::Display for ViewerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState => f.write_str("viewer is in an invalid state"),
            Self::PeerClosed(_) => f.write_str("peer requested close"),
            Self::Deadline => f.write_str("viewer deadline expired"),
            Self::UnexpectedMessage => f.write_str("unexpected viewer message"),
            Self::TwoFactorNotRequested => f.write_str("host did not request the required second factor"),
            Self::Denied(_) => f.write_str("host denied the login"),
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::Security(e) => write!(f, "password challenge: {e}"),
            Self::Desktop(e) => write!(f, "desktop metadata: {e}"),
            Self::DisplayControl(e) => write!(f, "display control: {e}"),
            Self::Preferences(e) => write!(f, "video preferences: {e}"),
            Self::Cursor(e) => write!(f, "cursor: {e}"),
            Self::Network(e) => write!(f, "network: {e}"),
        }
    }
}
impl Error for ViewerError {}
impl From<ProtocolError> for ViewerError { fn from(e: ProtocolError) -> Self { Self::Protocol(e) } }
impl From<SecurityError> for ViewerError { fn from(e: SecurityError) -> Self { Self::Security(e) } }
impl From<DesktopError> for ViewerError { fn from(e: DesktopError) -> Self { Self::Desktop(e) } }
impl From<CursorError> for ViewerError { fn from(e: CursorError) -> Self { Self::Cursor(e) } }
impl From<NetworkTransportError> for ViewerError { fn from(e: NetworkTransportError) -> Self { Self::Network(e) } }

/// One incoming message, after basic demultiplexing but before rendering.
pub enum ViewerEvent {
    /// Source video envelope retained as bytes. Native decoding is deliberately
    /// not automatic; its allocation behavior is unsafe for untrusted input.
    Video { display: i32, codec: VideoCodec, envelope: Box<[u8]> },
    CursorShape(CursorShape),
    CursorId(u64),
    CursorPosition(CursorPosition),
    /// A source heartbeat; from-server probes are echoed before returning.
    TestDelay(TestDelay),
    PeerInfo(PeerInfo),
    /// Peer-provided encoder capabilities, not proof of available codecs.
    EncodingCapabilities(remote_protocol::EncodingCapabilities),
    /// Untrusted source display announcement, including the original envelope.
    DisplayChanged { value: remote_protocol::display_control::DisplaySwitch, envelope: Box<[u8]> },
    /// Untrusted cursor-follow display hint; it is not authorization.
    FollowCurrentDisplay(u32),
    /// Untrusted source permission announcement; not a local authorization grant.
    Permission(remote_protocol::permissions::PermissionNotice),
    /// Unknown/non-adapted message. The caller may decode it separately.
    Other(Box<[u8]>),
}

/// Explicit acknowledgement that a 2FA code will be disclosed to the remote
/// peer, which can lie or relay it. This token does not verify the channel.
pub struct TwoFactorSendOptIn(());
impl TwoFactorSendOptIn {
    pub fn acknowledge_code_disclosure_to_peer() -> Self { Self(()) }
}

/// Owns one stream throughout the limited login and message workflow.
pub struct ViewerConnection<T: NetworkTransport> {
    transport: T, phase: Phase, max_bytes: usize,
    original_resolutions: Option<Vec<Option<remote_protocol::desktop::OriginalResolution>>>,
    supported_modes: Option<(u32, Vec<remote_protocol::resolution_metadata::Resolution>)>,
    windows_sessions: Option<remote_protocol::windows_sessions::WindowsSessions>,
    feature_claims: Option<remote_protocol::platform_metadata::FeatureClaims>,
    platform_additions: Option<String>,
}
impl<T: NetworkTransport> ViewerConnection<T> {
    /// The caller must establish and verify an appropriately protected channel
    /// independently. This function cannot verify security properties of `T`.
    pub fn new(mut transport: T, max_bytes: usize) -> Result<Self, ViewerError> {
        if max_bytes == 0 || max_bytes > MAX_ENVELOPE_BYTES { transport.close(); return Err(ViewerError::InvalidState); }
        Ok(Self { transport, phase: Phase::New, max_bytes, original_resolutions: None, supported_modes: None, windows_sessions: None, feature_claims: None, platform_additions: None })
    }
    fn abort(&mut self) { self.phase = Phase::Closed; self.original_resolutions = None; self.supported_modes = None; self.windows_sessions = None; self.feature_claims = None; self.platform_additions = None; self.transport.close(); }
    /// Latest bounded, untrusted original-resolution claims from login or the
    /// latest PeerInfo update. `None` also means missing/invalid metadata or a
    /// closed connection. A zero pair can mean a virtual display. These values
    /// do not authenticate topology or authorize resolution changes.
    pub fn original_resolutions(&self) -> Option<&[Option<remote_protocol::desktop::OriginalResolution>]> {
        self.original_resolutions.as_deref()
    }
    /// Most recent bounded supported-mode claims and their volatile display
    /// index. Absent/invalid metadata and topology updates clear this value.
    /// These are untrusted peer claims, not a mode probe or permission to act.
    pub fn supported_modes(&self) -> Option<(u32, &[remote_protocol::resolution_metadata::Resolution])> {
        self.supported_modes.as_ref().map(|(display, modes)| (*display, modes.as_slice()))
    }
    /// Latest bounded Windows session claims from login or PeerInfo update.
    /// `None` includes absent, invalid and closed; entries are not verified OS
    /// sessions or permission to switch. No session is selected automatically.
    pub fn windows_sessions(&self) -> Option<&remote_protocol::windows_sessions::WindowsSessions> {
        self.windows_sessions.as_ref()
    }
    /// Optional untrusted peer feature flags; they do not enable any feature.
    pub fn feature_claims(&self) -> Option<remote_protocol::platform_metadata::FeatureClaims> { self.feature_claims }
    /// Bounded opaque peer string (conventionally JSON), not parsed or trusted.
    /// `None` includes invalid/unavailable/closed; empty is the wire default.
    pub fn platform_additions(&self) -> Option<&str> { self.platform_additions.as_deref() }
    fn remaining(end: Instant) -> Result<Duration, ViewerError> {
        let remaining = end.saturating_duration_since(Instant::now());
        if remaining.is_zero() { Err(ViewerError::Deadline) } else { Ok(remaining) }
    }
    /// Complete a basic source-style password login. `deadline` is an overall
    /// cap on network operations and approval wait, not on blocking native code.
    /// Up to eight source TestDelay probes are echoed while waiting for approval.
    /// Serialization, transport and allocator may retain password-derived proof
    /// copies beyond guarded buffers. The caller owns password
    /// lifetime. Cancellation leaves this object Busy; close/drop it.
    pub async fn login(&mut self, identity: &LoginIdentity, password: &str, deadline: Duration) -> Result<PeerInfo, ViewerError> {
        self.login_with_options(identity, password, None, None, false, None, deadline).await
    }
    /// Login with explicit locally-verified decoder claims attached to the
    /// source login message. This does not install decoders or guarantee the
    /// host's encoder selection and remains an untrusted wire claim.
    pub async fn login_with_decoding(&mut self, identity: &LoginIdentity, password: &str, capabilities: remote_protocol::DecodingAdvertisement, deadline: Duration) -> Result<PeerInfo, ViewerError> {
        self.login_with_options(identity, password, Some(capabilities), None, false, None, deadline).await
    }
    /// Include bounded quality/FPS preferences and optional decoder claims in
    /// source login. Peer support and actual encoder adaptation are not assured.
    pub async fn login_with_video_options(&mut self, identity: &LoginIdentity, password: &str, capabilities: Option<remote_protocol::DecodingAdvertisement>, preferences: remote_protocol::video_preferences::VideoPreferences, deadline: Duration) -> Result<PeerInfo, ViewerError> {
        self.login_with_options(identity, password, capabilities, Some(preferences), false, None, deadline).await
    }
    /// Explicitly request source video acknowledgements at login. The viewer
    /// must independently emit VideoReceived at the appropriate time; this
    /// method does not verify a frame was decoded or rendered.
    pub async fn login_with_ack(&mut self, identity: &LoginIdentity, password: &str, capabilities: Option<remote_protocol::DecodingAdvertisement>, preferences: Option<remote_protocol::video_preferences::VideoPreferences>, deadline: Duration) -> Result<PeerInfo, ViewerError> {
        self.login_with_options(identity, password, capabilities, preferences, true, None, deadline).await
    }
    /// Submit one already-obtained source TOTP only if the peer sends the exact
    /// 2FA prompt. A malicious peer can request and relay it; this generic
    /// transport does not authenticate or encrypt itself. Use only after the
    /// caller verifies the actual host and channel, and only with local consent.
    /// Reject acceptance if no prompt occurred; acceptance after the prompt is
    /// still only a peer claim, not proof the peer verified the factor.
    /// Never enroll a trusted device here. Wrong/repeated prompts, unexpected
    /// messages, failed/cancelled sends and timeout close the connection; there
    /// is no retry, interactive prompt, replay protection or host-side 2FA.
    /// The caller owns the code and memory/logging hygiene; protobuf and network
    /// copies can remain even though the immediate wire Vec is zeroized.
    pub async fn login_with_two_factor_code(&mut self, identity: &LoginIdentity, password: &str, code: &str,
        opt_in: TwoFactorSendOptIn, deadline: Duration) -> Result<PeerInfo, ViewerError> {
        self.login_with_two_factor_options(identity, password, code, None, None, false, opt_in, deadline).await
    }
    /// The same explicit one-code flow with caller-supplied video options.
    /// ACKs and decoder capability claims are not automated or verified. All
    /// channel, consent, disclosure and peer-verification caveats above apply.
    pub async fn login_with_two_factor_options(&mut self, identity: &LoginIdentity, password: &str, code: &str,
        capabilities: Option<remote_protocol::DecodingAdvertisement>, preferences: Option<remote_protocol::video_preferences::VideoPreferences>,
        video_ack_required: bool, opt_in: TwoFactorSendOptIn, deadline: Duration) -> Result<PeerInfo, ViewerError> {
        let _ = opt_in;
        if !(6..=8).contains(&code.len()) || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ViewerError::Protocol(ProtocolError::InvalidAuthenticationField));
        }
        self.login_with_options(identity, password, capabilities, preferences, video_ack_required, Some(code), deadline).await
    }
    async fn login_with_options(&mut self, identity: &LoginIdentity, password: &str, capabilities: Option<remote_protocol::DecodingAdvertisement>, preferences: Option<remote_protocol::video_preferences::VideoPreferences>, video_ack_required: bool, two_factor_code: Option<&str>, deadline: Duration) -> Result<PeerInfo, ViewerError> {
        if self.phase != Phase::New || deadline.is_zero() || deadline > Duration::from_secs(180) { return Err(ViewerError::InvalidState); }
        let end = Instant::now().checked_add(deadline).ok_or(ViewerError::InvalidState)?;
        self.phase = Phase::Busy;
        let result = self.login_inner(identity, password, capabilities, preferences, video_ack_required, two_factor_code, end).await;
        match result {
            Ok(info) => { self.phase = Phase::Connected; Ok(info) },
            Err(error) => { self.abort(); Err(error) },
        }
    }
    async fn login_inner(&mut self, identity: &LoginIdentity, password: &str, capabilities: Option<remote_protocol::DecodingAdvertisement>, preferences: Option<remote_protocol::video_preferences::VideoPreferences>, video_ack_required: bool, two_factor_code: Option<&str>, end: Instant) -> Result<PeerInfo, ViewerError> {
        let raw = self.transport.receive(Self::remaining(end)?).await?;
        let challenge = Envelope::decode(&raw, MAX_PRE_AUTH_BYTES)?;
        let hash = challenge.password_challenge()?;
        let hash = PasswordChallenge { salt: hash.salt.to_owned(), challenge: hash.challenge.to_owned() };
        {
            let response = password_response(password, &hash)?;
            let mut message = remote_protocol::sensitive_login::SensitiveDesktopLogin::new(DesktopLogin { username: &identity.target, peer_id: &identity.viewer_id,
                peer_name: &identity.viewer_name, password_response: response.as_bytes(), session_id: identity.wire_session_id, version: &identity.version })?;
            message.set_video_ack_required(video_ack_required)?;
            if let Some(capabilities) = capabilities { message.set_decoding(capabilities)?; }
            if let Some(preferences) = preferences { message.set_video_preferences(preferences).map_err(ViewerError::Preferences)?; }
            let wire = Zeroizing::new(message.encode(MAX_PRE_AUTH_BYTES)?);
            self.transport.send(&wire, Self::remaining(end)?).await?;
        }
        let mut two_factor_sent = false;
        // Preserve the legacy eight-heartbeat allowance; a 2FA flow needs one
        // additional response slot for the prompt before the final result.
        let response_budget = if two_factor_code.is_some() { 10 } else { 9 };
        for _ in 0..response_budget {
            let raw = self.transport.receive(Self::remaining(end)?).await?;
            let response = Envelope::decode(&raw, MAX_PRE_AUTH_BYTES)?;
            if response.kind() == MessageKind::TestDelay && !response.test_delay()?.from_client {
                self.transport.send(&raw, Self::remaining(end)?).await?;
                continue;
            }
            match response.close_reason() {
                Ok(reason) => return Err(ViewerError::PeerClosed(Some(reason.to_owned()))),
                Err(remote_protocol::close_reason::CloseReasonError::TooLong) => return Err(ViewerError::PeerClosed(None)),
                Err(remote_protocol::close_reason::CloseReasonError::Unexpected) => {},
            }
            return match response.desktop_login_result()? {
                LoginResult::Accepted(info) => {
                    if two_factor_code.is_some() && !two_factor_sent { return Err(ViewerError::TwoFactorNotRequested); }
                    self.original_resolutions = response.display_original_resolutions().ok();
                    self.windows_sessions = response.windows_sessions().ok().flatten();
                    self.feature_claims = response.feature_claims().ok().flatten();
                    self.platform_additions = response.platform_additions().ok().map(str::to_owned);
                    self.supported_modes = if info.displays.is_empty() { None } else { response.supported_resolutions().ok().flatten().map(|modes| (info.current_display as u32, modes)) };
                    Ok(info)
                },
                LoginResult::Denied(reason) if reason == remote_protocol::two_factor::REQUIRE_2FA && !two_factor_sent && two_factor_code.is_some() => {
                    let code = two_factor_code.ok_or(ViewerError::InvalidState)?;
                    let wire = {
                        let message = remote_protocol::two_factor::SensitiveTwoFactorEnvelope::new(code, &[], false)?;
                        Zeroizing::new(message.encode(MAX_PRE_AUTH_BYTES)?)
                    };
                    self.transport.send(&wire, Self::remaining(end)?).await?;
                    two_factor_sent = true;
                    continue;
                },
                LoginResult::Denied(reason) => Err(ViewerError::Denied(reason)),
            };
        }
        Err(ViewerError::UnexpectedMessage)
    }
    /// Send a single existing RustDesk mouse or keyboard message. Host
    /// authorization and interpretation remain the remote host's responsibility.
    /// No automatic retry occurs after an uncertain send.
    pub async fn send_input(&mut self, event: &Envelope, deadline: Duration) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        if !matches!(event.kind(), MessageKind::Mouse | MessageKind::Keyboard | MessageKind::Pointer) { return Err(ViewerError::UnexpectedMessage); }
        let wire = Zeroizing::new(event.encode(self.max_bytes)?);
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Connected; Ok(()) },
            Err(e) => { self.abort(); Err(ViewerError::Network(e)) },
        }
    }
    /// Send an existing bounded source display-switch/subscription request.
    /// The host must authorize, validate current displays and decide whether to
    /// act. A nonzero requested resolution may change OS settings at a peer.
    pub async fn send_display_control(&mut self, event: &Envelope, deadline: Duration) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        if event.display_switch().is_err() && event.capture_displays().is_err()
            && event.display_resolution().is_err() && event.display_query().is_err() { return Err(ViewerError::UnexpectedMessage); }
        let wire = event.encode(self.max_bytes)?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Connected; Ok(()) },
            Err(error) => { self.abort(); Err(ViewerError::Network(error)) },
        }
    }
    /// Send a source Windows session selection to the peer. A real host may
    /// switch its service/session, with disruptive OS effects. The untrusted
    /// cached list is not authorization; caller must secure fresh local consent
    /// and verify that the requested session is appropriate. A failed/cancelled
    /// send is indeterminate and must never be blindly retried.
    pub async fn select_windows_session(&mut self, sid: u32, opt_in: remote_protocol::windows_sessions::SessionSwitchOptIn,
        deadline: Duration) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        let wire = Envelope::select_windows_session_event(sid, opt_in).encode(self.max_bytes)?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Connected; Ok(()) },
            Err(error) => { self.abort(); Err(ViewerError::Network(error)) },
        }
    }
    /// Send one existing source video refresh/received notification. This does
    /// not provide codec recovery, flow control or prove the host acted on it.
    /// A peer supplied display index must be validated by the host. Like input,
    /// a failed or cancelled send has indeterminate delivery; do not retry on
    /// the same connection without an application-level recovery policy.
    pub async fn send_video_control(&mut self, control: remote_protocol::video_control::VideoControl, deadline: Duration) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        let event = Envelope::video_control_event(control).ok_or(ViewerError::UnexpectedMessage)?;
        let wire = event.encode(self.max_bytes)?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Connected; Ok(()) },
            Err(error) => { self.abort(); Err(ViewerError::Network(error)) },
        }
    }
    /// Send source quality/FPS preferences. The host decides whether and how
    /// to act; no encoder adaptation occurs on the viewer.
    pub async fn send_video_preferences(&mut self, preferences: remote_protocol::video_preferences::VideoPreferences, deadline: Duration) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        let event = Envelope::video_preferences_event(preferences).map_err(ViewerError::Preferences)?;
        let wire = event.encode(self.max_bytes)?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Connected; Ok(()) },
            Err(error) => { self.abort(); Err(ViewerError::Network(error)) },
        }
    }
    /// Send existing source cursor/follow preferences. The host controls all
    /// subscriptions and permissions; no cursor is captured by this call.
    pub async fn send_cursor_preferences(&mut self, preferences: remote_protocol::cursor_preferences::CursorPreferences, deadline: Duration) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        let wire = Envelope::cursor_preferences_event(preferences).encode(self.max_bytes)?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Connected; Ok(()) },
            Err(error) => { self.abort(); Err(ViewerError::Network(error)) },
        }
    }
    /// Request the source input-disable preference. The host may ignore it and
    /// `false` is never a permission grant. Caller handles local input state.
    pub async fn send_disable_keyboard(&mut self, disabled: bool, deadline: Duration) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        let wire = Envelope::input_preference_event(Some(disabled)).encode(self.max_bytes)?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Connected; Ok(()) },
            Err(error) => { self.abort(); Err(ViewerError::Network(error)) },
        }
    }
    /// Advertise only decoder implementations the embedding application has
    /// actually checked. Source negotiation is host-side and remains untrusted;
    /// this message does not install a decoder or prove compatibility.
    pub async fn send_decoding_advertisement(&mut self, capabilities: remote_protocol::DecodingAdvertisement, deadline: Duration) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        let wire = Envelope::supported_decoding_event(capabilities).encode(MAX_PRE_AUTH_BYTES.min(self.max_bytes))?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Connected; Ok(()) },
            Err(error) => { self.abort(); Err(ViewerError::Network(error)) },
        }
    }
    /// Ask a supporting host to resend a cursor shape evicted by the viewer.
    /// The host may have evicted it too; this is not guaranteed to get a reply.
    pub async fn request_cursor_shape(&mut self, id: u64, deadline: Duration) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        let wire = Envelope::request_cursor_shape_event(id).encode(self.max_bytes)?;
        self.phase = Phase::Busy;
        match self.transport.send(&wire, deadline).await {
            Ok(()) => { self.phase = Phase::Connected; Ok(()) },
            Err(error) => { self.abort(); Err(ViewerError::Network(error)) },
        }
    }
    /// Receive one message. Cursor decoding is bounded but not audited; video
    /// remains compressed. On cancellation close/drop the Busy connection.
    pub async fn receive(&mut self, deadline: Duration) -> Result<ViewerEvent, ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        self.phase = Phase::Busy;
        let result = self.receive_inner(deadline).await;
        match result {
            Ok(event) => { self.phase = Phase::Connected; Ok(event) },
            Err(error) => { self.abort(); Err(error) },
        }
    }
    async fn receive_inner(&mut self, deadline: Duration) -> Result<ViewerEvent, ViewerError> {
        let raw = self.transport.receive(deadline).await?;
        self.dispatch_received(raw, deadline).await
    }
    async fn dispatch_received(&mut self, raw: Box<[u8]>, deadline: Duration) -> Result<ViewerEvent, ViewerError> {
        let envelope = Envelope::decode(&raw, self.max_bytes)?;
        match envelope.close_reason() {
            Ok(reason) => return Err(ViewerError::PeerClosed(Some(reason.to_owned()))),
            Err(remote_protocol::close_reason::CloseReasonError::TooLong) => return Err(ViewerError::PeerClosed(None)),
            Err(remote_protocol::close_reason::CloseReasonError::Unexpected) => {},
        }
        match envelope.kind() {
            MessageKind::Video => {
                let frame = envelope.video()?;
                Ok(ViewerEvent::Video { display: frame.display, codec: frame.codec, envelope: raw })
            },
            MessageKind::Cursor => {
                if let Ok(id) = envelope.cursor_id() { return Ok(ViewerEvent::CursorId(id)); }
                if let Ok(position) = envelope.cursor_position() { return Ok(ViewerEvent::CursorPosition(position)); }
                Ok(ViewerEvent::CursorShape(envelope.cursor_shape()?))
            },
            MessageKind::TestDelay => {
                let delay = envelope.test_delay()?;
                if !delay.from_client { self.transport.send(&raw, deadline).await?; }
                Ok(ViewerEvent::TestDelay(delay))
            },
            MessageKind::Misc => match envelope.display_switch() {
                Ok(value) => {
                    self.supported_modes = envelope.supported_resolutions().ok().flatten().map(|modes| (value.display, modes));
                    Ok(ViewerEvent::DisplayChanged { value, envelope: raw })
                },
                Err(remote_protocol::display_control::DisplayControlError::Invalid) => Err(ViewerError::DisplayControl(remote_protocol::display_control::DisplayControlError::Invalid)),
                Err(remote_protocol::display_control::DisplayControlError::Unexpected) => match envelope.follow_current_display() {
                    Ok(display) => Ok(ViewerEvent::FollowCurrentDisplay(display)),
                    Err(remote_protocol::display_control::DisplayControlError::Invalid) => Err(ViewerError::DisplayControl(remote_protocol::display_control::DisplayControlError::Invalid)),
                    Err(remote_protocol::display_control::DisplayControlError::Unexpected) => match envelope.permission_notice() {
                        Ok(notice) => Ok(ViewerEvent::Permission(notice)),
                        Err(ProtocolError::UnexpectedMessage) => match envelope.supported_encoding() {
                            Ok(value) => Ok(ViewerEvent::EncodingCapabilities(value)),
                            Err(ProtocolError::UnexpectedMessage) => Ok(ViewerEvent::Other(raw)),
                            Err(error) => Err(ViewerError::Protocol(error)),
                        },
                        Err(error) => Err(ViewerError::Protocol(error)),
                    },
                },
            },
            MessageKind::Other => match envelope.desktop_peer_info() {
                Ok(info) => {
                    self.original_resolutions = envelope.display_original_resolutions().ok();
                    self.windows_sessions = envelope.windows_sessions().ok().flatten();
                    self.feature_claims = envelope.feature_claims().ok().flatten();
                    self.platform_additions = envelope.platform_additions().ok().map(str::to_owned);
                    self.supported_modes = if info.displays.is_empty() { None } else { envelope.supported_resolutions().ok().flatten().map(|modes| (info.current_display as u32, modes)) };
                    Ok(ViewerEvent::PeerInfo(info))
                },
                Err(DesktopError::UnexpectedMessage) => Ok(ViewerEvent::Other(raw)),
                Err(error) => Err(ViewerError::Desktop(error)),
            },
            _ => Ok(ViewerEvent::Other(raw)),
        }
    }
    /// Send one source close notification and then close locally, even if the
    /// send fails. Delivery is indeterminate on failure; never retry it.
    /// Cancellation leaves Busy; caller must close/drop the connection.
    pub async fn send_close_reason(&mut self, reason: &str, deadline: Duration) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        let wire = Envelope::close_reason_event(reason).map_err(|_| ViewerError::InvalidState)?.encode(self.max_bytes)?;
        self.phase = Phase::Busy;
        let result = self.transport.send(&wire, deadline).await;
        self.close();
        result.map_err(ViewerError::Network)
    }
    /// Close the stream. No peer acknowledgement is implied.
    pub fn close(&mut self) { self.phase = Phase::Closed; self.original_resolutions = None; self.supported_modes = None; self.windows_sessions = None; self.feature_claims = None; self.platform_additions = None; self.transport.close(); }
}
impl<T: NetworkTransport> Drop for ViewerConnection<T> { fn drop(&mut self) { self.close(); } }

impl<T: remote_transport::AdjustableNetworkTransport> ViewerConnection<T> {
    /// Change the actual framing bound after the basic login has completed.
    /// It is the caller's responsibility to trust the authenticated host and
    /// select a safe limit; native video decoder allocations remain unbounded.
    pub fn set_connected_message_limit(&mut self, maximum: usize) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected || maximum == 0 || maximum > MAX_ENVELOPE_BYTES { return Err(ViewerError::InvalidState); }
        self.transport.set_max_message_size(maximum)?;
        self.max_bytes = maximum;
        Ok(())
    }
}

impl<T: remote_transport::UpgradeableDuplexTransport> ViewerConnection<T> {
    /// Explicitly enable experimental read-ahead after successful login. The
    /// message limit must be set before upgrading and is then fixed.
    pub fn enable_duplex_read_ahead(&mut self) -> Result<(), ViewerError> {
        if self.phase != Phase::Connected { return Err(ViewerError::InvalidState); }
        match self.transport.upgrade_duplex() {
            Ok(()) => Ok(()),
            Err(error) => { self.abort(); Err(ViewerError::Network(error)) },
        }
    }
    /// Consume a queued message without timing out an idle socket read. Echoing
    /// a TestDelay probe may still send and block for the supplied deadline.
    pub async fn try_receive(&mut self, deadline: Duration) -> Result<Option<ViewerEvent>, ViewerError> {
        if self.phase != Phase::Connected || deadline.is_zero() { return Err(ViewerError::InvalidState); }
        let raw = match self.transport.try_receive() {
            Ok(Some(raw)) => raw, Ok(None) => return Ok(None),
            Err(error) => { self.abort(); return Err(ViewerError::Network(error)); },
        };
        self.phase = Phase::Busy;
        match self.dispatch_received(raw, deadline).await {
            Ok(event) => { self.phase = Phase::Connected; Ok(Some(event)) },
            Err(error) => { self.abort(); Err(error) },
        }
    }
}
