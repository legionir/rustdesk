//! Caller-driven bridge between a host TestDelay probe and source video QoS.
//!
//! The original `src/server/connection.rs` sends a host probe on a timer,
//! updates QoS while awaiting it, and records the elapsed time on reply. This
//! bridge only joins already-extracted primitives; it starts no timer or worker
//! and never grants permissions. The caller must fairly service host events,
//! call `tick` at the desired cadence, and handle errors and cleanup. Unlike
//! source, `DelayProbe` requires an exact echo and limits its lifetime to 60s.
//! This is a compatibility difference, not authentication: source probes have
//! no nonce and a peer can forge or replay matching replies. Measurements and
//! bitrate are advisory; do not use them for identity, authorization or billing.
//!
//! This module is provisional, unbuilt and untested. Input/session IDs and
//! their association with QoS state remain trusted caller responsibilities.
use crate::{host_connection::{ConnectionError, HostConnection, HostEvent}, video_schedule::{DelayProbe, ScheduleError}};
use remote_codec::video_qos::{QosError, SourceVideoQos, MAX_BITRATE_KBPS};
use remote_input::InputBackend;
use remote_session::{SessionId, SessionState};
use remote_transport::NetworkTransport;
use std::{error::Error, fmt, time::{Duration, Instant}};

#[derive(Debug)]
pub enum ProbeQosError { InvalidBinding, InvalidBitrate, InvalidDeadline, Interrupted, Probe(ScheduleError), Qos(QosError), Connection(ConnectionError) }
impl fmt::Display for ProbeQosError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "probe QoS: {self:?}") } }
impl Error for ProbeQosError {}

/// Per-session, single-outstanding-probe state. An equal caller-provided
/// session ID is not proof of connection identity; never reuse IDs across
/// sessions. Drop this tracker on disconnect, uncertain send or policy change.
pub struct ProbeQos { session: SessionId, peer: i32, probe: DelayProbe, last_delay_ms: u32, interrupted: bool }
impl ProbeQos {
    /// Register only a locally allocated, positive QoS connection ID already
    /// associated with this exact session. This does not register or own it.
    pub fn new(session: SessionId, peer: i32, qos: &SourceVideoQos) -> Result<Self, ProbeQosError> {
        qos.require_peer(peer).map_err(ProbeQosError::Qos)?;
        Ok(Self { session, peer, probe: DelayProbe::new(), last_delay_ms: 0, interrupted: false })
    }
    fn check<T: NetworkTransport, B: InputBackend>(&self, host: &HostConnection<T, B>) -> Result<(), ProbeQosError> {
        if self.interrupted { return Err(ProbeQosError::Interrupted); }
        if host.session_id() != self.session || !host.permissions().view_screen
            || !matches!(host.state(), SessionState::Connected | SessionState::Streaming) { return Err(ProbeQosError::InvalidBinding); }
        Ok(())
    }
    /// Last locally timed matching reply; zero also represents no measurement.
    /// This is not a trusted network measurement or remote delivery proof.
    pub fn last_delay_ms(&self) -> u32 { self.last_delay_ms }
    /// Start a probe and send it over the bound host. `target_bitrate` is an
    /// explicit caller-supplied local QoS snapshot, not a peer limit. A failed
    /// or cancelled send permanently invalidates this tracker; close/drop the
    /// host and tracker rather than retrying an indeterminate message.
    pub async fn send<T: NetworkTransport, B: InputBackend>(&mut self, host: &mut HostConnection<T, B>, target_bitrate: u32, deadline: Duration) -> Result<(), ProbeQosError> {
        self.check(host)?;
        if target_bitrate > MAX_BITRATE_KBPS { return Err(ProbeQosError::InvalidBitrate); }
        if deadline.is_zero() { return Err(ProbeQosError::InvalidDeadline); }
        let probe = self.probe.begin(Instant::now(), self.last_delay_ms, target_bitrate).map_err(ProbeQosError::Probe)?;
        // This flag remains true if the future is dropped during the await.
        self.interrupted = true;
        host.send_delay_probe(probe.last_delay, probe.target_bitrate, deadline).await.map_err(ProbeQosError::Connection)?;
        self.interrupted = false;
        Ok(())
    }
    /// Feed an elapsed observation into the registered QoS peer at most once
    /// per eligible whole second. Returns false if no update was due. The host
    /// session owner provides monotonic time and continues servicing events.
    pub fn tick<T: NetworkTransport, B: InputBackend>(&mut self, host: &HostConnection<T, B>, qos: &mut SourceVideoQos, now: Instant) -> Result<bool, ProbeQosError> {
        self.check(host)?; qos.require_peer(self.peer).map_err(ProbeQosError::Qos)?;
        match self.probe.tick(now).map_err(ProbeQosError::Probe)? {
            Some(elapsed) => { qos.on_probe_elapsed(self.peer, elapsed).map_err(ProbeQosError::Qos)?; Ok(true) },
            None => Ok(false),
        }
    }
    /// Feed a host event from the exact bound connection. Only a host-origin
    /// matching echo is consumed; unrelated events return `Ok(false)` and must
    /// still be processed by the caller. A mismatched echo does not clear the
    /// pending probe. Milliseconds are truncated as in source; late/forged
    /// replies are not distinguishable from legitimate ones on this wire.
    pub fn observe<T: NetworkTransport, B: InputBackend>(&mut self, host: &HostConnection<T, B>, qos: &mut SourceVideoQos,
        event: &HostEvent, now: Instant) -> Result<bool, ProbeQosError> {
        self.check(host)?;
        let HostEvent::ProbeReply(reply) = event else { return Ok(false); };
        qos.require_peer(self.peer).map_err(ProbeQosError::Qos)?;
        let elapsed = self.probe.reply(now, *reply).map_err(ProbeQosError::Probe)?;
        // DelayProbe bounds elapsed to <= 60s, so conversion is exact.
        let ms = u32::try_from(elapsed.as_millis()).map_err(|_| ProbeQosError::Probe(ScheduleError::ProbeExpired))?;
        qos.on_delay_reply(self.peer, ms).map_err(ProbeQosError::Qos)?;
        self.last_delay_ms = ms;
        Ok(true)
    }
}
