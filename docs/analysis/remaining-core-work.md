# Remaining RemoteCore extraction work — provisional

This is a working gap list, not an acceptance or security review. The source
baseline and licenses are recorded in `source-baseline.md`. The original
RustDesk source remains intact. Everything after the local transport CI run is
unbuilt and untested by request; do not use the current prototype as a product.

## Windows-first host and viewer

- `src/server/connection.rs::Connection::start`, `on_message`, and `on_close`
  orchestrate many source behaviors; `remote-core::host_connection` is only a
  caller-driven subset. Remaining work includes full message routing, timers,
  disconnect reasons, permissions synchronization, source rate limiting,
  configuration, secure ownership/approval and resource shutdown.
- `src/server/input_service.rs` implements keyboard modes, modifiers, lock
  state, key-repeat/fixup, desktop switching, pointer/touch and session routing.
  `windows_keyboard`, `windows_mouse`, `tracked_modifiers`, the Enigo adapter
  and opt-in pinned-rdev scan path cover only documented subsets. The opt-in
  modifier and Map-mode policies are intentionally narrower than source and
  require compatibility, cleanup and security review on real Windows.
- `src/platform/windows.rs::get_cursor_data` and `src/platform/windows.cc` have
  an experimental shape adapter, not verified against color masks, animation,
  scaling, UAC, secure desktop or portable service. Source portable-service
  cursor/input paths are not extracted.
- `remote-core::capture_pump` is synchronous, caller driven, software-only and
  accepts BGRA/RGBA CPU frames. Capture tasks, hotplug/resize, zero-copy,
  reliable multi-monitor behavior, VRAM transport and source fallback policy
  are not completed. `hwcodec` RAM paths exist but are unbuilt and untested.
- `viewer_connection` demultiplexes a small set of existing protobuf variants;
  it does not render, automatically negotiate codecs, perform recovery or
  implement video ACK/QoS scheduling or all display/permission updates. Basic
  control and capability messages can be sent/returned to the caller, but are
  not automatically scheduled. Native video decoders are not hardened against
  hostile compressed streams.

## Security and transport

- `admitted_host` plus `source_crypto` optionally composes pre-auth admission,
  explicit pinned host identity and source-v1 split-key encryption. The code
  rejects legacy fallback, which is a deliberate compatibility/security policy
  difference requiring review. It does not implement rendezvous signature
  chains, secure pin lifecycle, 2FA/trusted devices, complete failure policy,
  a local owner-consent UI, or audited replay/DoS protection.
- `DirectTcp` can expose an unencrypted listener; secure composition is the
  application caller's responsibility. The strict WSS adapter validates relay
  TLS; an accepted-socket WSS host adapter now exists, but there is no complete
  WSS listener policy, authenticated routing, SSRF control or proven
  Cloudflare interoperability. Source encryption can wrap binary transports but
  the complete hosted relay setup has not been tested.
- `InputArbiter` coordinates only cooperating sessions in one process and is
  optional; it cannot exclude other processes, direct unguarded input paths or
  human input. Enigo does not report all Windows SendInput failures.

## Node, packaging and validation

- Node exposes local single-frame capture/encode, cursor wire conversion and a
  narrow pinned TCP/WSS viewer and a loopback-only, view-only single-frame host
  with serialized operations. It has no general network host API, decoded video
  renderer, complete keyboard/input semantics, durable credentials or
  production-safe consent. Native decoder allocation is
  not bounded by compressed message size.
- `tools/export-source.py` makes a provenance-recorded candidate tree, not a
  separate versioned release, resolved lockfile, license clearance or verified
  independent build. It deliberately includes upstream shared libraries rather
  than deleting unexamined dependencies.
- After extraction is actually complete, prepare Rust and native dependencies,
  run workspace and addon builds/tests (including feature matrix), then debug
  failures. Real interactive Windows capture/input/UAC/multi-monitor and GPU
  work require an authorized disposable machine; CI results must not be
  substituted for those checks. Interoperability, network adversarial and
  security review remain separate acceptance gates.

### Source login-failure policy still missing

The pinned `src/server/connection.rs::{check_failure_with_scope,
update_failure_with_scope,get_ipv6_prefixes}` maintains process-global,
per-address failure counters and, for IPv6, /64, /56 and /48 counters. It
checks both one-minute and cumulative thresholds, removes relevant entries on
success and emits audit alarms. The terminal OS-credential path delegates to
`src/server/login_failure_check.rs` for process-wide exponential backoff and a
Windows login gate; terminal/OS login is outside the current prototype. The
current RemoteCore admission permit caps concurrent pre-auth work but is **not**
an equivalent failed-login rate limiter, and a password transcript permits
offline guessing. `remote_security::source_failure_counters` now exposes an
opt-in, bounded, caller-driven extraction of the default source address/prefix
counter thresholds. It is not integrated into login or transport and cannot
limit concurrent already-admitted attempts. It differs by rejecting clock
regression, saturating counters and failing on bounded storage exhaustion. It
retains the source's shared-prefix reset behavior (which needs policy review). Before integrating a policy, resolve trusted peer-address
attribution through proxies/WSS, shared-prefix reset semantics, bounded storage,
concurrent attempts, persistence, lockout/DoS risk and auditing with the owner;
do not silently treat self-reported IDs or HTTP headers as authenticated IPs.

### Video QoS and Windows VRAM increment (unverified)

`remote-codec::video_qos` now wraps a copy of the baseline
`src/server/video_qos.rs` and its source test fixtures. The copy replaces the
source global `enable-abr` option read with explicit caller configuration,
preserves that setting when the final peer leaves, and saturates display-counter
and bitrate additions. The wrapper bounds peer/display counts and untrusted
measurement values. It does not provide the upstream service, timers, security
or scheduling; its result may exceed the current software encoder's allowed
quality range. Source `VideoReceived` is connection-wide, with no frame or
monitor ID: the bounded helper in `remote-core::video_schedule` tracks pending
viewers across displays but cannot distinguish late ACKs. `DelayProbe` uses the
existing source `TestDelay` fields with `time = 0`; matching replies are neither
nonce-protected nor authenticated. Pacing, probes, frame ACKs and application
of QoS recommendations are all explicit caller responsibilities.

On Windows with `vram`, `remote-capture::vram` now combines the source DXGI
device and source VRAM encoder, with the encoder dropped before the capturer;
`remote-core::vram_pump` connects it to an authorized caller-driven host session.
Both retain the existing H.264/H.265 wire format. GPU/driver behavior, pointer
lifetimes across native calls, capture consent, device loss, UAC/secure desktop,
rotation, software fallback, decoding, interoperability and performance remain
unverified; native allocations precede output-size checks. The source encoder's
VRAM quality setter can hide driver errors. This is not a complete source video
service, a tested Windows implementation, or a safe untrusted decoder.

### Display switch and multi-display subscription increment (unverified)

The source uses `Misc.SwitchDisplay` in both directions and
`Misc.CaptureDisplays` for subscription changes (`connection.rs` and
`video_service.rs`). The prototype now reads/writes bounded subsets, exposes
request events only with both local view and change-display permissions, and
preserves the original bounded wire envelope. The viewer exposes display
announcements and can send requests; the Node host remains view-only and does
not accept these requests. A caller-driven planner follows source add > sub >
set precedence, but rejects any invalid/offline index rather than silently
filtering, and treats an empty set as unsubscribe all. It returns start/stop
plans without performing them. Applications must supply actual current display
state, authorize each change, coordinate capturers/encoders and enforce resource
limits. Indices are not stable identities and hotplug requires revalidation.
OS resolution changes, multi-stream scheduling, atomic rollback, virtual
monitors, source resolution metadata construction, source compatibility and
real Windows multi-monitor capture remain incomplete and untested.

The unverified `MultiCapture` group opens up to eight explicitly approved
software capture handles and starts session streaming once; it caps the sum of
frame areas at 32 Mi pixels, which is not a native-memory bound. It supports
caller-driven per-display sends and shared stop. It does not auto-apply the
subscription planner, dynamically reconfigure a group, schedule frames, recover
from native failure/hotplug or coordinate refresh/decoder state. Do not mix it
with separately managed pumps for the same session. The Windows two-monitor
loopback example requires explicit screen-capture confirmation; it has not been
built or run and must be used only on an authorized disposable desktop.
