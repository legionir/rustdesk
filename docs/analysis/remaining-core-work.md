# Remaining RemoteCore extraction work — provisional

This is a working gap list, not an acceptance or security review. The source
baseline and licenses are recorded in `source-baseline.md`. The original
RustDesk source remains intact. GitHub Actions run `41442854621` built and tested
the default workspace at commit `229987e` on Linux and Windows, including Linux
Xvfb capture. Later work is not covered by that run. Optional native features,
real interactive Windows desktop/input and end-to-end interoperability remain
unverified; do not use the current prototype as a product.

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
  narrow pinned TCP/WSS viewer and a view-only host with serialized single-frame
  or short bounded bursts. An explicitly opted-in direct network host accepts a
  single exact observed peer IP but lacks security review, durable keys, rate
  limiting and trusted consent; it is not a general production host. There is no decoded video
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
set precedence. Source `sub` keeps the listed already-active displays and removes
other subscriptions (`src/server.rs::capture_displays`), despite its name. The
planner rejects any invalid/offline index rather than silently filtering, and
treats an empty set as unsubscribe all. It returns start/stop
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
subscription planner, recover from native failure/hotplug or coordinate
refresh/decoder state. Explicit group reconfiguration and a separate caller-driven
scheduler are available, subject to their documented limits. Do not mix it
with separately managed pumps for the same session. The Windows two-monitor
loopback example requires explicit screen-capture confirmation; it has not been
built or run and must be used only on an authorized disposable desktop.

A separate bounded `DisplayCadences` helper can reserve round-robin capture
attempts at caller-specified rates and `VideoStreams` tracks keyframe recovery
per display. Neither spawns tasks or creates decoders or subscriptions. The
separate `ScheduledCapture` composes MultiCapture with cadence and opt-in ACK
waiting and can explicitly apply QoS recommendations; it is not autonomous.
These helpers do not establish fairness across separate connections or enforce
global CPU, decoder allocation or bandwidth budgets.

`display_metadata::display_update` builds a bounded standalone `PeerInfo` from
handles enumerated by the caller, and the authorized host can send the update.
Unlike `src/server/display_service.rs::displays_to_msg`, this subset omits the
Windows virtual-display `platform_additions` JSON and original resolution;
scale is unknown. Handle order and metadata can become stale immediately after
enumeration. Refresh, secure desktop switching, actual mode changes and stream
recreation are not automatic.

Explicit `stop` now accepts the session's already-connected state after view
permission was revoked, so capture resources can be marked stopped and dropped
without a second streaming-state transition. This is not an asynchronous
cancellation mechanism: a capture handle and any blocked native call remain
the owner's responsibility, and software handles are released on drop.

### Windows touch-scale increment and gap

The source `PointerDeviceEvent` carries `TouchEvent` scale and pan variants.
`src/server/input_service.rs::handle_pointer_` processes only scale on Windows:
`handle_scale` holds Control and scrolls the raw scale until a zero scale
releases Control. Windows routes pointer events through
`src/server/portable_service.rs::handle_pointer`. An experimental opt-in host
path now exposes bounded scale events, requires both mouse and keyboard grants,
tracks and releases the Control key, denies mixing other input while active, and
cleans up before a permission downgrade. It intentionally differs from source:
there is a local delta limit, no repeat downs, no modifier metadata, no pan and
no global OS key-state reconciliation. Enigo can hide SendInput failures;
exclusive OS input and correct cleanup on crash are not guaranteed. The wire
adapter preserves pan messages without executing them. Real Windows behavior,
secure desktop, portable-service IPC, local-user interference, and new tests
are unverified. The trackpad wheel mapping is a different source message.

### Direct TCP listener composition

The `source-security` feature now has `direct_host::DirectHostListener`, which
accepts a literal bind address and shares a caller-supplied admission controller.
It obtains a permit from the actual socket peer before the source-v1 handshake;
password and owner approval remain separate. Dropping the pending socket releases
the permit. The Node addon has an independently opted-in network listener with
exact observed IP filtering, a temporary pin and a view-only backend. Neither
endpoint is safe for untrusted networks: addresses do not authenticate users,
password transcripts permit offline guessing, and failure lockout, durable key
management, audit, secure UI and a full concurrent event loop are still missing.
The network path and new tests have not been built or run.

### Source quality and FPS preferences (unverified)

The existing `OptionMessage` can carry decoder support and quality/FPS in the
same message (`src/server/connection.rs::update_options`). The experimental
protocol adapter extracts only bounded source quality and FPS fields, and the
host retains sanitized login preferences only after password and owner approval.
Post-login preference events retain decoder claims when both are present. The
caller may explicitly feed validated preferences into registered source QoS
state; nothing changes a capture pump, scheduler or encoder automatically. Node
exposes the untrusted initial values and event values, and a viewer can request
updates. Invalid preferences are ignored on login without discarding valid
decoder claims; invalid positive FPS/unknown quality enum are not accepted as
preferences. Packed custom values and their source interpretation are not a
stable application API. Interoperability, abuse limits, fairness, adaptation,
Node and synthetic tests remain unverified. Raw post-login event bytes can
contain unrelated options and must not be applied indiscriminately.

### Peer close reason (unverified)

The source handles `Misc.CloseReason` before authorization
(`src/server/connection.rs::on_message`). The experimental host now handles it
while waiting for the login and after authorization, closes the transport and
attempts input cleanup; the viewer handles it while awaiting a login result and
when receiving post-login messages. Long reasons are discarded and still close;
other text is untrusted and must be escaped before display. Sending a close
reason is best-effort and uncertain delivery is not retried. This does not
observe a peer disconnect while synchronous owner approval or another operation
is in progress, nor does it release caller-owned capture handles. Cleanup,
interoperability and new synthetic tests have not been run.

### Caller-driven multi-display capture pacing (unverified)

`scheduled_capture::ScheduledCapture` composes the existing bounded
`MultiCapture` and `DisplayCadences` without starting threads or timers. The
embedding application explicitly starts a capture group, drives one frame
attempt at a time and can change per-display cadence. Per-display encoder
statistics, quality, reset status and reset are available through the
session-bound host API. This is not the RustDesk video service: it serializes
receive and capture, cannot interrupt a blocking capture, does not independently
honor subscriptions, ACKs or QoS, and cannot establish topology stability.
Interleaving with receive, consent revocation and cleanup remain caller-owned;
real Windows behavior and all new code remain unbuilt and untested.

The existing `Misc.AutoAdjustFps` and `Misc.ClientRecordStatus` can now be
returned as view-authorized source controls. FPS is locally bounded to the
source's 1–120 range. The caller may explicitly feed them to `SourceVideoQos`;
recording status is a peer assertion, not recording permission, a privacy
indicator or proof of recording. No recording is started or stopped. These
changes and their Node surfaces have not been built or tested.

### Trusted-only multi-display decoding (unverified)

`trusted_video_streams` now owns up to eight independent software decoders and
keyframe trackers. Each stream must be registered explicitly; decode/output
validation failure discards the decoder and requires an explicit reset plus
peer refresh. The Rust API demands a trusted-input acknowledgement. The output
copy has a local bound, but native decoder allocations happen **before** that
check; a compromised authenticated peer can still exhaust memory or exploit
native codecs. It is therefore not an untrusted-network decoder or a security
boundary. Renderer, hardware decode orchestration, color/stride conventions,
stream renegotiation, async isolation and actual end-to-end sessions are not
completed. Synthetic local encode/decode tests are written but not executed.

The prototype also exposes the existing desktop-login `video_ack_required`
flag. Hosts can read the untrusted flag only after view approval; viewers must
explicitly request it and independently send `VideoReceived`. In source,
connections without the flag notify the video service when a frame is dequeued
for sending; connections with it wait for the connection-wide peer message.
The prototype does not yet implement the source service's sender queue,
deadlines or multi-peer ACK scheduler, and an ACK cannot prove render. The new
path is unbuilt and untested.

### Experimental TCP read-ahead and duplex driver

The strict source-v1 direct TCP path now has an opt-in, bounded duplex driver.
It moves the existing framed connection including buffered bytes into one reader
and one writer task, retaining the source direction keys and counters. It has
one queued input and one queued output message, does not retry uncertain sends,
and requests task/socket closure on cancellation, failure or dropping a half.
The optional `UpgradeableEncryptedTcp` stays serial through login and allows an
explicit post-authorization upgrade after choosing the final frame limit. Host
and viewer can then poll queued messages without cancelling an idle socket read.
This does **not** make host input dispatch concurrent with blocking capture,
provide a scheduler or secure owner consent, or apply rate limits. TLS/WSS are
not covered. Task shutdown is asynchronous; runtime lifetime, byte/allocation
bounds, ordering, cancellation races, framing buffers, source interop and
nonce safety require comprehensive testing and independent security review. The
code and synthetic tests have not been built or run. Do not use for production
or untrusted networks.

### Read-only Windows resolution planning (unverified)

The source `src/platform/windows.rs` enumerates modes via
`EnumDisplaySettingsW` and changes them with `ChangeDisplaySettingsExW`, while
`src/server/connection.rs::change_resolution` also handles virtual displays and
tracks prior resolution for restoration. The prototype now adds bounded,
read-only Windows mode enumeration and a separate side-effect-free request
planner. The latter checks local view/change-display permissions, approved and
fresh snapshots, unique device names, a supported mode and a second topology
snapshot. Enumeration is not atomic, Win32 end/failure distinction is limited,
and a device name/snapshot is not a durable physical identity. No API here
changes, persists or restores any mode; source virtual-display handling,
recovery, informed consent and inter-process coordination remain missing. All
new code and synthetic tests are unbuilt and untested, including real Windows.

The source exporter now produces `SOURCE_MANIFEST.sha256` over every exported
file other than the manifest itself, in deterministic path order. This supports
local integrity comparison but is unsigned and does not establish provenance,
reproducible builds, completeness or licensing clearance. The source archive
hashes remain recorded separately in `SOURCE_PROVENANCE.md`.

The Node TCP/WSS viewer can optionally request source video acknowledgements at
login (`videoAckRequired`); the application must send `notifyVideoReceived`
after processing video. `frame_wait::FrameWait` is a bounded caller-driven
per-display timeout/connection-ACK helper, but is not yet wired to capture,
transport, subscriptions, actual send queues or the source's complete service.
Neither ACKs nor timeout imply rendering. All of these additions are untested.

### Transactional multi-display membership (unverified)

The experimental `MultiCapture::reconfigure` and host wrapper accept explicit
locally approved handles; they validate old-plus-new temporary stream/pixel
limits, open all additions before removing old streams, and leave the old group
intact if a native open fails. `ScheduledCapture::reconfigure` stages the
cadence table first and updates it only after membership succeeds. Same-index
replacement and an empty resulting group are deliberately rejected; stop and
recreate for these cases. The caller must handle decoder/keyframe and metadata
coordination, OS topology races, consent and network subscription requests.
Native allocations are not globally bounded and open/cleanup can have OS side
effects; this is not an atomic system transaction. It is unbuilt and untested.

`ScheduledCapture::apply_recommendation` now provides an explicit, caller-driven
bridge from a source QoS recommendation to one stream's pacing and optionally
its encoder quality. It validates bounds and backend support; failed native
quality changes may invalidate the encoder and require explicit decoder refresh.
No automatic QoS loop, delivery guarantees or untrusted-peer approval is added.

### Cursor/follow options (unverified)

The pinned `OptionMessage` has tri-state `show_remote_cursor`,
`follow_remote_cursor`, `follow_remote_window` and `show_my_cursor` fields.
The prototype preserves NotSet/No/Yes, rejects unknown values, and routes these
untrusted requests after view approval. Other options and decoder claims in the
same source message are retained; video preferences take event precedence and
Node exposes any accompanying cursor values. No cursor subscription, window
tracking, policy, rendering or OS action is applied automatically. Source
semantics also depend on keyboard permission and service subscriptions, which
remain the embedding application's responsibility. Tests are written but not
run.

`Misc.SupportedEncoding` now has a RustDesk-schema constructor, an explicit
host send method, viewer event and Node viewer representation including optional
I444 claims. These values are claims only, VP9 has no top-level source flag,
and no capability probing, automatic stream switch, decoder reset or negotiation
is performed. The route and synthetic cases are unbuilt and untested.

`display_selection::plan_for_snapshot` additionally compares a locally approved
snapshot with a newly observed one and rejects ambiguous online device names
before applying the existing subscription planning rules. Equality is not
physical identity, and topology may still change after planning; callers must
revalidate before opening handles. Manual read-only inspection examples now
exist for Rust and Node on Windows; neither has been built or run.

### Explicit WSS listener composition (unverified)

`wss_host::WssHostListener` binds an application-selected literal address and
holds a socket-derived admission permit before TLS and WebSocket negotiation.
A caller-supplied TLS configuration, exact HTTP upgrade policy and explicit
opt-in are required before the source-v1 handshake; password and local owner
approval still follow. Source IP behind a proxy is not the end-user identity,
HTTP headers are forgeable, and global rate limiting, PKI/pin provisioning,
viewer identity and consent remain unimplemented. A synthetic admission test
was written, but this listener, TLS interoperability, proxy and Cloudflare
behavior are unbuilt and untested; never expose it as a production service.

`disable_keyboard` is now exposed as a source tri-state preference in protocol,
host and viewer APIs (including Node). Upstream gates both keyboard and mouse
with this flag; the prototype returns an untrusted request and does not yet
apply that gate or release held input. `false` never grants local permission.
Combined options remain available in their original envelope. This is an
incomplete compatibility path, not a security boundary, and is untested.

The Linux workflow is prepared to export a committed candidate outside the
checkout, verify its unsigned file manifest and build/test that exported tree
when the branch is eventually pushed. This job step has not been run and does
not imply the candidate is a reproducible, licensed or security-reviewed
release. The inherited lockfile is intentionally not enforced with `--locked`.

The Windows device name comes from `scrap::common::dxgi::Display::name`, which
converts the DXGI/GDI UTF-16 name lossily. The mode query refuses replacement
characters rather than silently querying a potentially different device. This
is conservative and can reject an unusual name; it is not a stable-ID solution.

Before integrating failure counters, address normalization needs a policy
review: `AdmissionController::admit` normalizes IPv4-mapped IPv6 to IPv4,
whereas `SourceFailureCounters::keys` currently treats a supplied mapped value
as IPv6 and also creates prefix buckets. Callers must normalize consistently
from a trusted socket or risk inconsistent counting. This unconnected helper is
not a production login rate limiter.

### Optional source input-disable gate (unverified)

An explicit host API can now honor the peer's `disable_keyboard` preference
without changing locally granted permissions. It suppresses keyboard, mouse and
pointer input and attempts to release this controller's held keys/buttons; an
active touch-scale gesture is ended first. Re-enabling restores only capabilities
still locally granted. The wire option is still **not applied automatically**:
trusted application policy must opt in and decide what to do with combined
options. Release failure closes the host and attempts cleanup, but native OS
success is not always observable. This is not global input arbitration, and
source cursor/clipboard subscription behavior is not reproduced. Synthetic
cases are written but unbuilt and untested; independent security/API review and
real Windows cleanup validation remain required.

### Optional single-session capture ACK pacing (unverified)

`ScheduledCapture` can explicitly enable a bounded, caller-driven wait after a
peer requested `video_ack_required`. Successful sends register a per-display
wait, source connection-wide ACK events can clear all pending displays, and
other displays can proceed while one waits. The owner must call `observe_event`
for events read from the same session, service all other control/input messages,
and explicitly handle timeouts, reconfiguration and decoder refresh. Peer ACKs
carry no sequence/display and can be late or forged; they are not render proof.
There is no shared multi-viewer broadcast queue, source dequeue notification for
ACK-disabled peers, autonomous task, rate limiting or concurrent OS capture.
The helper and its deferred tests are unbuilt, untested and unaudited.

### Source original display resolution metadata (unverified)

The source sets `DisplayInfo.original_resolution`, including `0,0` for its own
virtual displays, from a global change-history map. Protocol methods now retain
this optional field for login and standalone PeerInfo, and Rust host methods
can send caller-supplied values; the Rust viewer retains the most recent bounded
claims. Invalid metadata is not treated as permission, and all values are
untrusted and may be stale. This does not implement the source global change
history, virtual-display detection, mode switching/restoration or topology
coordination. The Node viewer exposes the latest claims asynchronously. Tests
are written but not executed.

### Cursor-follow hint (unverified)

`cursor_follow::follow_hint` adapts the source's first matching scaled rectangle
and suppresses a hint when the cursor remains on the current display or the
connection uses multiple UI sessions. It widens coordinate arithmetic and rejects
unknown/invalid scales rather than assuming one. `windows_source_display_update`
can explicitly report the pinned source's Windows scale policy of 1.0; it is not
a DPI probe. The embedding host must confirm cursor/display coordinate spaces,
consent and topology, decide whether follow is enabled and explicitly send the
hint. The explicit Windows `send_windows_cursor_follow_hint` now composes an
opt-in sample, checked snapshots and hint send; the Node binding exposes it
with caller-asserted consent and follow policy. Neither path switches capture,
handles desktop transitions or resolves overlapping monitor identity. Tests are
written but not run.

### Supported modes and switch metadata (unverified)

`resolution_metadata` now reads and constructs bounded source
`SupportedResolutions` in PeerInfo or `Misc.SwitchDisplay`, and the latter's
optional original resolution. An authorized Rust host may explicitly send the
switch metadata, and a Rust viewer retains the original bounded switch envelope
for application inspection. These are untrusted claims, not a complete or atomic
Windows enumeration, a mode change, topology proof or permission. Node can
inspect a bounded original display-change envelope on a worker and query the
viewer's latest untrusted login/switch mode claims. No corresponding integration
or real desktop test has run.

### Resolution recovery intent (unverified)

The source records each changed display's original and last-requested
resolution and calls native restore when the last client leaves; it clears the
map even after restore errors (`src/server/display_service.rs`). The new
caller-owned `resolution_history` retains the first original, the most recent
attempt and a bounded set of recovery records, without calling the OS. Unlike
source it rejects a new attempt if the observed previous size differs from the
last attempted size, and only drops an exact record after an explicit trusted
acknowledgement; a local generation distinguishes successive attempts in one
instance, not across restarts. It is neither durable nor process-global;
size/name equality does not prove physical identity, and a crash, hotplug or external display
change may make restoration unsafe. Actual mode change/restoration, exclusive
coordination, consent, and tests remain outstanding.

### Foreground-window follow (unverified)

The Windows platform uses `GetForegroundWindow` and `GetWindowRect`, choosing
which display contains the window center; the source service emits a hint only
when an already-known focus display changes and at least two displays exist.
The new opt-in read-only `windows_foreground` sample and `window_follow` tracker
expose these pieces without window titles, processes or handles. An explicit
Windows-only `send_windows_focus_hint` now composes approved snapshot checks,
foreground sampling, tracking and a hint send when a caller asserts local
consent and follow policy. It does not subscribe or run automatically, and the
boolean assertion is not trusted consent. Applications must enforce local consent/view
permission, follow-window policy, matching DPI/desktop coordinate contexts,
reset on topology change, and rate-limit disclosure; a transient rectangle is
not a stable identity. UAC, secure desktop, Windows DPI virtualization, real
multi-monitor use and all new tests remain unverified.

### Cursor echo exclusion (unverified)

Source cursor-position service suppresses an update to the most recent peer
input connection for strictly less than 300 ms. `cursor_echo` provides bounded,
caller-owned monotonic bookkeeping for the same exclusion window, including
explicit disconnect/reset and checks against the last input timestamp (not a
global clock-regression guard). It is not wired to the input or cursor services: the application must consistently track all eligible
input, use unique local IDs and coordinate broadcasts. It does not suppress
messages by itself, establish exclusive input, or prove delivery. Synthetic
cases are written but have not run.

### Windows legacy lock-state planning (unverified)

The source Windows input service temporarily synchronizes CapsLock and, for
numpad or navigation keys, NumLock from the peer's modifier bits, then attempts
to toggle them back on handler drop. `windows_lock_plan` reproduces a restricted
legacy decision without OS side effects, excluding unsupported/system keys;
`WindowsInput::lock_state` reads the same Enigo GetKeyState toggle bits. These
are transient thread/input-queue observations. No automatic injection or
restore is implemented: global lock changes can race the local user, other
processes and desktop switches, and the Enigo adapter cannot prove delivery.
Security/compatibility review, actual Windows behavior, exclusive ownership and
all synthetic cases remain outstanding.

### 2FA remains an explicit security gate

At the pinned source `send_logon_response_and_keep_alive` sends the login error
`2FA Required` and keeps the pre-authorized connection alive. The server
accepts `Auth2FA` only while awaiting it, checks a separate failure scope, then
validates the TOTP; wrong codes return `Wrong 2FA Code`. Trusted-device handling,
recent-session exceptions, approval, token enrollment and revocation affect the
outcome (`src/server/connection.rs`, `src/auth_2fa.rs`). TOTP generation uses
SHA-1, a 30-second step and configured digits in that source. The prototype's
basic viewer treats this response as denial; an explicit separate viewer flow
can respond once, but its host does not implement this state machine. Merely forwarding `Auth2FA` or accepting a boolean callback would not
reproduce the protections. Secret storage/zeroization, replay and rate limits,
trusted-device policy, independent security review and an approved API are
required before enabling host-side 2FA enforcement; absence must never be
represented as successful full RustDesk authentication.

### Cooperative capture budget (unverified)

`capture_budget` supplies an opt-in in-process lease pool for counts of
reservations, streams and configured pixel areas. The opt-in
`HostConnection::start_multi_capture_budgeted` and `MultiCapture::start_budgeted`
reserve one lease per stream before native opening; reconfiguration retains old
leases during temporary additions and releases each after its native pump drops.
The opt-in single software and Windows VRAM capture paths also hold a lease
until pump drop. Unbudgeted constructors remain available for each path.
The pool is not an OS-wide arbiter or a byte/GPU/CPU limit and cannot account
for uncooperative paths, native allocations or other processes. No fairness,
rate limiting, native capture lifecycle tests or build have been demonstrated.

`windows_mode_metadata` converts the experimental Windows mode snapshot into
bounded, deduplicated source mode claims after rejecting a locally truncated
snapshot. Unlike source it sorts dimensions; `truncated=false` still cannot
prove exhaustive enumeration because Win32 also returns zero on some errors.
The caller must revalidate topology and authorize disclosure. No desktop test
has verified this bridge.

### Stale key bookkeeping (unverified)

RustDesk's global key map timestamps each recorded down, removes on up and its
10-second loop releases keys at least 360 seconds old (`fix_key_down_timeout`).
`key_expiry` provides an opt-in bounded per-instance map and returns snapshots;
it does not start a loop, observe `InputController`, or inject releases. The
caller must coordinate a single local input owner, distinguish key representations,
serialize snapshot validation and release with concurrent input, handle failed
or uncertain delivery, and preserve OS/user state. Repeated source downs refresh
expiry, whereas the controller suppresses repeat by default and optionally
injects explicit repeated downs; the caller must also refresh the separate
bookkeeping on the correct successful/possibly delivered events. The pieces
must not be wired together without reconciling failure and ordering semantics. Generation prevents stale
acknowledgement only within one instance, not a wrong key-up already delivered.
Synthetic tests are written but have not run.

Topology and resolution planners conservatively reject device names containing
U+FFFD, since DXGI names may have been lossily decoded. This also rejects a
legitimate literal U+FFFD and requires an explicit identity-policy decision; it
must not be described as a complete or lossless device-name implementation.

### Inactivity timeout (unverified)

The source can enable an authorized connection's auto-disconnect from local
configuration. It checks once per second, closes when elapsed whole seconds are
strictly greater than the configured minutes multiplied by 60, and resets on
input, certain refresh requests and other source features. `idle_timeout` and
`HostConnection::enable_idle_timeout` now expose an opt-in bounded subset. The
host records mouse/keyboard/pointer and valid authorized video-refresh activity,
including peer-disabled input; it does not include source chat, OS login or
false refresh messages. Heartbeat and video ACK do not reset the timer. The
trusted owner must call `poll_idle_timeout` regularly; this does not schedule a
task, interrupt blocked capture or network I/O, send the source close reason,
or drop caller-owned capture handles. An active peer can deliberately keep the
timeout alive. The 1..1440 minute range is a local restriction unlike source.
This is not a transport liveness timeout or security control. No new tests have
been run and source compatibility remains unverified.

### Receive liveness (unverified)

RustDesk's server records successful received frames before protobuf parsing
and checks a 30-second receive timeout on its delay-probe tick. An opt-in
`HostConnection` watchdog now records dequeued frames and exposes remaining time
and a caller-driven close check. It sends no TestDelay probes, has no timer, and
starts only after explicit enabling on an authorized connection. With the TCP
read-ahead driver, dequeue time is not socket-arrival time; a busy or stalled
owner may incorrectly time out or postpone expiry. Raw malformed frames also
refresh the source timer. Owners must service reads, probe cadence and cleanup
independently, without treating this as identity or DoS protection. This does
not reproduce source session startup, timer scheduling or close reason and has
not been built or tested.

### Scheduled single-session composition (unverified)

`ScheduledSession` now owns a bound host and `ScheduledCapture`, upgrades an
eligible transport to experimental read-ahead, checks optional caller-driven
idle/receive watchdogs, and passes received ACKs to optional per-session frame
pacing. The application must alternate `poll_event` and `capture_step` fairly,
process all returned controls, choose deadlines, provide consent/authorization,
coordinate topology and decoder refresh, and call `close`; it does not create
an autonomous loop or source multi-peer broadcast service. On timeout it drops
capture handles and reservations but cannot interrupt in-flight native work.
The Windows multi-display loopback example has been adapted to this composition;
none of it has been built or tested. TCP read-ahead, ACK ambiguity, queue
saturation, cancellation and cleanup require adversarial validation.

### Restricted keyboard repeat and Node mode opt-ins (unverified)

Source `process_control_key` and raw rdev map/translate send each repeated down
while its pressed-key record remains one entry. The controller now offers an
explicit repeat-down path, with a single retained cleanup record and fail-closed
handling for detectable backend errors. `HostConnection` may opt in to this for
its restricted legacy/map/translate subsets; tracked modifiers cannot coexist.
Node exposes those restricted mode toggles with caller-asserted local consent.
No OS timer, rate limit, physical input ownership, complete modifier/lock state,
desktop switching or reliable Enigo error detection is provided. Tests are
written but none has run; real Windows keyboard semantics require validation.

The source Windows Enigo `key_sequence` in `libs/enigo/src/win/win_impl.rs`
encodes supplementary Unicode as two `unicode_key_down` calls with no paired
key-up (the source contains a commented question about key-up). The provisional
controller still rejects non-BMP input rather than silently invent different
OS semantics or claiming parity. This restriction is a documented open gap,
not an approved permanent removal; it needs Windows target-app and cleanup
validation, a deliberate security/API decision, and a compatible implementation.
`remote_input::windows_unicode_plan::source_windows_sequence` now exposes a
bounded, side-effect-free representation of that source sequence (rejecting NUL
and empty strings locally). Its tests are written but not run; it must not be
mistaken for an approved or safe native injector.

`ScheduledSession` compares caller-supplied session IDs, not unforgeable object
identity: the embedding application must guarantee unique IDs and pass the exact
host that opened the capture group. A matching ID does not prove consent or
prevent cross-session resource use if an embedding violates that contract.

### Viewer-side adaptive FPS extraction (unverified)

The pinned `src/client/io_loop.rs::fps_control` estimates a shared FPS cap from
active display decode rates, direct/relay ratios, queue pressure and idle
trends; it also requests refresh when per-display backlog exceeds a tolerance.
`remote_core::viewer_fps` now extracts bounded caller-fed bookkeeping for that
logic, including the source's `Option` minimum behavior, inactive threshold,
strict whole-second refresh timing, cap of 20 refresh requests per display and
`ui_session_interface.rs::refresh_video` old-peer refresh-all choice. It does
not create decoder threads, measure FPS, authenticate the direct/relay claim,
detect peer compatibility, or apply decisions automatically. The caller must
supply accurate local samples, serialize decisions with manual FPS changes,
clear state on topology/reconnect, decide whether to send, and treat late or
failed delivery as unknown. `dispatch` sends existing source messages only;
its counter is local send completion, not proof of peer receipt or rendering.
Bounded samples, stable display order, rejected clock regression, saturation,
and explicit caller policy are deliberate differences from source. Decoder
queues, capture, real network adaptation and tests have not been exercised.

The related source `src/client.rs::fps_calculate` measurement logic is now a
separate caller-driven `viewer_decode_fps::DecodeFps` meter, also exposed to
Node. It skips three warmup frames, reports at ten-frame intervals, resets its
window after thirty and preserves the old estimate on format change. It adds a
60-second sample bound and a 1000 FPS output cap; it never times native work or
verifies rendering. Cancellation, frame drops, codec changes and meter lifetime
remain application responsibilities. Its new synthetic tests have not run.

### Viewer queue and Node persistent decoder increments (unverified)

The source `handle_msg_from_peer` sends a video message containing any keyframe
through a separate media channel and force-pushes non-keyframes into a 120-slot
queue, requesting refresh on overflow; its keyframe channel is not bounded by
that queue. `viewer_video_queue` is an explicit conservative alternative, not
wire or algorithm parity: first-packet key flags, bounded frame/byte counts,
clearing backlog on overflow/keyframe and caller-completed generation tickets.
A ticket limits only locally accounted bytes and cannot reclaim JS/native memory
or atomically protect external rendering. The Node queue is likewise isolated
from the Viewer, with worker-side protobuf parsing and explicit refresh policy.

The Node `TrustedVideoWorker` pins `TrustedVideoStreams` to a dedicated thread
because `scrap::ImageTexture` contains a raw pointer. Commands are bounded and
serialized, and any decode failure terminates the worker. The worker cap is not
an OS/native-memory sandbox; it cannot interrupt a stuck decoder, authenticate
input, verify consent, synchronize peer codec changes or render. Tests and Node
build have not run. This does not establish safe decoding of remote video.

### Viewer cursor selection increment (unverified)

`viewer_cursor::ViewerCursor` composes the existing bounded decoded-shape cache
with selected ID and last position; a miss is observable and shape selection is
caller-controlled. It mirrors the broad source distinction between CursorData
and CursorId, not the old-peer content-deduplication in
`src/client/io_loop.rs::{dedupes_cursors,set_cursor_data_by_content}` or the UI
rendering/visibility policy. Source's `RequestCursorData` response does not
correlate to a request and source host may return nothing, so delayed response
selection and retries require application policy. Node exposes a local helper,
not an automatic viewer integration. Cache IDs and pixels are untrusted, the
cache excludes returned copies, and state must be cleared between peers.

### Viewer frame-rate and manual FPS reset (unverified)

At `src/client/io_loop.rs` status tick, source computes FPS from the number of
frames delivered to its UI callback divided by actual elapsed milliseconds and
then resets each count; it does not count received network packets or guarantee
render completion. `ViewerFrameRate` models that callback accounting with a
caller-supplied interval, finite count, 24-hour interval limit, non-overflowing
integer math and a 1000-FPS cap. Multiple per-display meters must share the same
caller-managed sampling interval. Counts are serialized by the helper; source's
separate read/reset locks can race a callback. The `received_fps` field name in
`ViewerFps` remains for API compatibility but means this UI-callback estimate.
`note_manual_fps_update` mirrors source resetting last-auto FPS on a positive
outbound manual option or peer-info update without clearing refresh history;
the embedding app must invoke and serialize it, and no delivery is implied.
Neither path is wired into a renderer or background timer; tests are deferred.

The source handles a rejected CursorData decode by logging and still selecting
the untrusted peer ID (`src/client/io_loop.rs`), so its UI may try recovery.
The current `ViewerConnection::dispatch_received` instead returns a cursor error
and its receive path closes the connection. This fail-closed prototype
behavior differs from source and has not been reviewed for parity; changing it needs an agreed recovery
policy, decompression review, bounded request policy and interop tests. Neither
cursor IDs nor content hashes authenticate pixels.

### Source host probe/QoS bridge (unverified)

`src/server/connection.rs` owns a periodic TestDelay task, stores the last RTT,
sends the source QoS bitrate and calls `user_delay_response_elapsed` and
`user_network_delay` on the global source QoS object. `probe_qos::ProbeQos`
now connects the already-extracted host probe and QoS primitives for one
caller-bound authorized view session. The caller still registers a local peer
ID, supplies a locally observed bitrate and timer ticks, polls host events and
performs cleanup. No timer, multi-peer/global source QoS service, trustworthy
peer identity or automatic adaptation is provided. The bridge rejects mismatched
TestDelay echoes and expiry after 60 seconds, unlike source's broad matching;
probe fields contain no nonce and a malicious peer can forge/replay a match.
Any cancellation while sending marks the tracker unusable and requires the host
to be closed; equality of caller-supplied session IDs does not establish object
identity. Time regression is rejected during one probe. The Rust QoS bridge is not wired to Node or `ScheduledSession`; Node exposes
only explicit probe send and untrusted reply fields. All of this is unbuilt and
untested.

`dxgi_recovery` now models the source Windows access-lost restart counter (three
attempts within a strict ten-second window), pending restart/fallback flags and
two-second replacement-capturer grace. It is purely caller-driven bookkeeping;
it does not restart DXGI, switch to GDI, retain/transfer budgets, reset codecs,
notify peers, detect display identity changes, or preserve privacy mode. It is
not connected to `ScheduledSession` and has not been built or tested. Automatic
fallback remains a separately reviewed and consent-sensitive OS operation.
The same module models the source's initial WouldBlock-to-GDI counter: it
only counts before a first successful frame, ignores attempts during recovery
grace, and advises fallback on the fourth eligible WouldBlock. It does not call
`set_gdi` or alter VRAM flags. Real capture may itself switch backend and must
be revalidated; the model must not be treated as proof of source parity.

For an already opened, caller-authorized Windows `remote_capture::Capturer`,
`use_gdi(GdiFallbackOptIn::acknowledge_backend_change())` now delegates to the
source `set_gdi` and checks its boolean result. It is exposed through the software capture pump, host and scheduled session;
it is not wired to the VRAM pump or recovery state above. No automatic fallback
exists. A requested transition invalidates the software encoder even on failure;
the caller must explicitly coordinate a reset with the viewer.
The token is an assertion, not consent. The caller must revalidate desktop,
privacy and display identity and coordinate stream/encoder recovery. The
Windows-only interactive GDI fixture is opt-in and has not been run.

`static_refresh` models the source static-frame refinement quality bands,
codec/backend output caps, initial repeat interval, no-output/failure limits,
subscriber restart hint and caller-reported encode outcomes. It retains no frame,
does not call the encoder or transport and is not connected to the capture pump.
Source latency-drain repeats, native cached YUV/texture ownership, predictive
stream failure, subscriber reconfiguration, frame privacy and actual bitrate
remain unimplemented/unverified. Repeating sensitive screen content requires a
separately reviewed bounded lifetime and authorization. Fixtures are unrun.

The software encoder already retains a converted I420 buffer between frames;
the static-refresh policy itself does not retain pixels or read that buffer.
The current wrapper-owned converted and decoded RGB slices are now zeroized on
encoder/decoder drop. This is only best-effort: codec/native/OS buffers, earlier
reallocations, serialized packets, clones, swap, GPU memory and process crashes
are not covered. It is not a secure-deletion or privacy guarantee and has not
been compiled or benchmarked.

An explicit software-only primitive can now re-encode a successfully packed
input already retained in the encoder's converted buffer. `VideoSender` exposes
one network repeat after checking session view permission, with an opt-in token;
the single software capture pump and host expose an explicit repeat as well.
The legacy primitive does not automatically invoke the policy or integrate with
scheduled group capture, ACK pacing, Node, hardware/VRAM or the source service.
Separate source-aware scheduled variants are described below. The caller must enforce
cache age, privacy, scheduling, revocation cleanup and decoder synchronization.
Unlike source, this conservative path discards the encoder on any repeat error,
including a VPX no-output error, and cannot retry it. It is unbuilt/untested and
must not be presented as full source static-refresh behavior.
The optional hardware RAM encoder/decoder also scrub their current wrapper-owned
NV12/RGB slices on drop; an in-flight NV12 temporary is zeroized on Rust unwind.
Driver/codec buffers, GPU memory, reallocations, abrupt termination and external
copies remain outside that narrow best-effort cleanup. Hardware features and
performance have not been built or tested.

Source-aware opt-in software encode/send variants now recognize the exact
`scrap::VpxNoOutput` error only for VP8/VP9. They retain the encoder and last
converted input while returning `VpxNoOutput` without sending a packet; other
errors still fail conservatively. These paths are available for local and
network `VideoSender`, host capture pumps and the scheduled multi-display/ACK
driver, but not Node, hardware or VRAM. Legacy methods keep their
previous error/reset behavior. The caller must bound and authorize cached-frame
retention, handle local pacing and restart on uncertain sends. This is not the
full source static-refresh loop. The new tests and desktop fixture are unrun.

The source-aware VPX variant is now also available through multi-capture and
`ScheduledSession`, with explicit repeat and bounded ACK bookkeeping. No-output
reserves capture cadence but never creates an ACK wait; repeat returns a pacing
wait while an ACK is pending. It does not automatically connect the static
refresh policy, provide a worker, bound cache age, prove rendering or handle
multiple peers. The deterministic ACK-bookkeeping and Xvfb desktop fixtures
are written but unrun; this is not verified source-service equivalence.

`scheduled_refresh` provisionally composes the source-aware scheduler with the
pure static-refresh policy for one session and up to eight caller-supplied
software display/codec bindings. It checks exact current index membership,
requires a per-repeat consent assertion, applies ACK waits, and clears retained
wrapper pixels when polled at/after a caller-selected age (at most 60 seconds).
Age starts before the capture step, which is conservative. This is cooperative:
no timer clears idle sessions, native encode/send may continue past the age or
consent check, native and external pixel copies are not erased, equal session or
display IDs are not stable identity, and reconfiguration/reset requires a new
manager. Any cancellation or error while the manager drives the session poisons
it and requires close/drop; delivery can be indeterminate. This code and tests
are unrun and require security, privacy and real Windows review.

The existing `Auth2FA` message now has a bounded, redacted-inspection wire
adapter, and `remote_security::two_factor_gate` offers a single-login, bounded,
caller-verified second-factor lifecycle. The basic viewer still fails closed on a 2FA prompt; an explicitly opted-in
viewer method can now send one pre-obtained code after an exact prompt, while
rejecting success without a prompt. This does not prove that the peer verified
the code or authenticated the channel. The host does not enforce 2FA. The optional `source-totp` feature now wraps the source's locked `totp-rs`
verifier with SHA-1, 30-second steps and one-step skew, but remains disconnected
from login and untested. The gate has no global attempt limiting, shared replay defense, trusted-device enrollment, trusted local consent UI or
channel binding. The injected verifier is local authority, not evidence that
verification occurred. Source shared counters/lockout, trusted-device policy,
secret provisioning and the protocol/API decisions need security review before
connection. No new fixture has been built or run.

The Node direct TCP/WSS viewers expose the same pre-obtained-code flow only
with an explicit disclosure acknowledgment; it can be combined with video ACK.
The supplied JavaScript and N-API strings cannot be reliably erased, the code
can expire while waiting for approval, and the pinned peer can still lie or
relay it. This is not an interactive 2FA UX or a host-side 2FA requirement.
Argument-validation fixtures are written but unrun.

For Windows, an explicit `SourceWindowsUnicodeOptIn` now allows the existing
Enigo backend to receive bounded supplementary text through a separate input
controller/legacy dispatcher. Default text dispatch remains BMP-only. This
reuses the source's unmatched surrogate-down behavior; it cannot reliably detect
partial `SendInput`, restore OS state or exclude other sessions/processes. The
opt-in token is not consent. `HostConnection` exposes a separate local
per-session opt-in after keyboard authorization; it is off by default. Synthetic fake-backend fixtures are written but unrun; real
interactive Windows, desktop switching, IME, cleanup and security review remain
required before enabling it in an application.

The source Windows-to-Windows Translate hotkey payload (`Win2winHotkey`) now
has a wire constructor and a side-effect-free branch planner. In the pinned
`src/server/input_service.rs::simulate_win2win_hotkey`, a down attempts
`rdev::simulate_key_unicode(utf16, false)`, then on *any* error falls back to a
scan-code down computed from the upper-word virtual key; up always emits a
scan-code release. Inspection of pinned rdev `0904f23...` shows that its
Unicode helper may already have emitted modifier and key events before
returning an error and ignores some release errors. Therefore an error is not
proof that fallback is safe. The planner does not simulate, validate actual
Windows key/layout values, maintain held-key/OS state, authorize or perform
fallback. Dispatch, partial-delivery policy, modifier synchronization,
desktop switching and security approval remain open. Fixtures are unrun.

The provisional `InputController` now denies all further operations when a
backend reports a key/button/scan/raw-key release failure, a permission-revoke
cleanup failure, or a text-injection failure. This is a deliberate fail-closed
policy change for direct callers, not a claim of upstream parity. The failed
release remains tracked for explicit `close()` retry (and best-effort `Drop`),
which can itself interact with a human or another process after uncertain OS
delivery. Caller-managed exclusive ownership remains mandatory. No callback can
detect the Windows Enigo errors it does not report; a successful release is
not proof of OS state. Fixtures are written but not run, and real Windows input
and cleanup must be validated on an authorized interactive machine.

An opt-in `bounded_host_loop::run` now consumes one already-authorized
`ScheduledSession` and alternates its existing event/capture steps for at most
60 seconds or 100,000 steps. It never creates its own runtime or spawns a task;
the embedding application owns the Tokio context and must secure local consent,
permissions, topology, cursor/control handling and decoder recovery. The loop
returns untrusted control events to a synchronous handler, but input dispatch
and heartbeat replies can already occur inside the driver before that handler.
A cooperative stop cannot interrupt a native capture/send/callback; cancellation
requires dropping the owning future and cannot report cleanup failure. Only a
capture-side WouldBlock is retried; other errors close the driver and return it
inside the error only for detectable cleanup retry, never for resuming. No static
repeat, capture recovery, per-peer policy or multi-session orchestration is
automated. Time bounds are cooperative, not hard deadlines. This implementation
and its fixtures have not been built or run and are not a production host.

The trusted-only multi-display decoder collection and Node worker now expose
explicit per-display/all-display invalidation to drop decoder instances after
known or unrouteable frame loss without immediately allocating replacements.
The caller must separately invalidate queued/in-flight work, reset each decoder,
request a fresh keyframe and coordinate renderer state. On decode errors the
Node worker still terminates; pre-dispatch rejection requires explicit caller
recovery. This is not hostile-bitstream hardening, memory-erasure assurance or
permission to decode network data, including data from a pinned peer. New
fixtures are unrun.

The source's privacy-mode and virtual-display wire requests are now preserved
by `remote_protocol::sensitive_display`, without host dispatch or OS execution.
At the pinned baseline, `src/server/connection.rs::turn_on_privacy` checks an
authorized remote connection and `privacy_mode` permission, interacts with the
selected platform backend, performs a post-change check and may close other
remote connections. Turning it off uses connection ownership checks. Windows
`toggle_virtual_display` delegates to the installed virtual display manager;
its raw signed display index has backend-specific semantics (including special
values). Request parsing and this local 256-byte/control-character key bound do
not implement those policies, restoration, isolation, consent, IPC, the driver,
or a guarantee that a display is private. These capabilities remain missing,
not removed or considered accepted; host routing stays disabled pending
security and API decisions. Sending such requests to a real RustDesk peer can
change its OS. Fixtures are written but unrun.

The same protocol module now also reads/writes bounded `BackNotification`
privacy/block-input status messages from the baseline schema, preserving unknown
numeric values when reading and redacting peer-provided text in its `Debug`.
These are unauthenticated claims and are not proof of any actual privacy or input
state; the active viewer does not yet route them automatically. Construction
rejects unknown enum values and oversized details as a deliberate local bound.
No native privacy/blocking behavior has been implemented or tested here.

Host and viewer login now use scoped guards for selected protobuf login fields:
unique owned password-proof/token/hardware-ID byte buffers and the OS-login
password string are wiped when possible, including early returns. The host's
raw received buffer and copied pending proof remain separately zeroized; viewer
proof and encoded wire are scoped through send. Shared immutable `Bytes`,
protobuf unknown fields, other message variants, decode/encode failures,
transport copies, allocator memory, the original password and process crashes
are not covered. Fixtures do not prove physical memory erasure; all new code and
fixtures remain unbuilt and unrun.

An optional in-process `ReplayClaims` set and random HMAC fingerprint key can
atomically reject reuse across cooperating verifier flows without retaining raw
codes. This is an unbuilt/unrun primitive, **not integrated into host login or
2FA**. The caller must first verify the code, bind the same stable local
principal to the same secret, share one key/store across every flow, fail
closed on saturation or errors and select an adequate retention window. The
90-second suggestion matches at most the source's normal 30-second step and
one-step skew under stable wall-clock assumptions; a wall-clock rollback,
restarts, other processes, key/identity changes, missing persistence, code
collisions and global rate limiting remain unresolved. Fingerprint generation
requires the newly declared `hmac` dependency; an independent lockfile and
build have not been generated.
The pre-auth decoded-message guard additionally scrubs visible 2FA code and
hardware ID and elevation-logon password fields on rejection where they occur;
other variants and unknown fields remain outside this limited cleanup. The
outgoing 2FA guard also attempts to scrub its uniquely owned hardware ID.

Wire-only `SensitiveOptions` additionally preserves the source tri-state
`lock_after_session_end`, `block_input`, and legacy `privacy_mode` fields;
unknown values are rejected and no OS action is dispatched. At baseline,
`Connection::update_options` handles legacy privacy only for peers older than
1.2.4 (with a keyboard check), and block input requires keyboard and block-input
permissions. The actual block/unblock, locking, disconnect restoration and
portable-service behavior remain unimplemented. Sending options to an existing
RustDesk peer can have real side effects; fixtures are unrun.

Strict WSS URL validation is shared with the Node entry point and rejects raw
whitespace/control characters and endpoints longer than 4096 bytes. This is a
local restriction, not source parity, DNS validation, SSRF protection, or
Cloudflare verification. The Node crate's direct `url` dependency was removed
only after its sole source use moved to the RustDesk adapter; the adapter still
depends on `url` for actual parsing. This change is unbuilt and untested.
The same guard also covers selected nested login fields in a switch-sides
response; switch-sides itself is not implemented. This does not protect unknown
protobuf fields or any unlisted secret-bearing message type.

Host/viewer connection error `Debug` now redacts direct peer close and denial
strings; they remain accessible through enum variants and must still be escaped
or omitted in any UI/log. Nested diagnostics are not universally sanitized.
The redaction fixture is synthetic and unrun.

Node listener admission now checks out its listener state before blocking
accept, key exchange and login, so it does not hold its JS-facing data mutex
across those operations. The existing busy gate still rejects concurrent close
and accept: this is not cancellation or nonblocking native I/O. On panic the
checked-out listener is dropped rather than returned; a poisoned slot also
drops it. The loopback rejection/retry fixture is written but unrun; listener
lease cleanup, Node task destruction and cancellation still require validation.

Node pending approval, frame/burst, cursor and duplex workers now use session
checkout rather than holding the JS-facing session data mutex across native
capture, enumeration or network operations. The public busy lease still
serializes operations and explicitly rejects close while work is in flight;
cooperative burst stop cannot interrupt capture/send. The expiration timer now
retries while a session is checked out instead of treating an empty slot as a
finished session. Approval rechecks its deadline after the last send and closes
if it elapsed; a success may already have reached the peer before that close.
Unwind best-effort closes a checked-out host; crashes and native hangs remain
outside the guarantee. Real-display concurrency and lifecycle fixtures were
updated but remain unbuilt/unrun; no proof of timely revocation is implied.

`remote_capture::windows_desktop::compare_current_thread_to_input` now exposes
only a read-only name comparison inspired by `inputDesktopSelected` in the
pinned `src/platform/windows.cc`. It opens the input desktop with read access,
uses the current OS thread's borrowed desktop handle and explicitly checks close
of its owned input handle on success. Failure is an error, never interpreted as
a match; error-path Drop cleanup is best effort and can fail silently. Names
are not returned. This is not `try_change_desktop`, portable service, UAC handling,
object identity, consent, or proof that capture/input is safe; races, name reuse,
window stations, desktop permissions and thread migration matter. The original
source attempts desktop switching in `input_service.rs`, `service.rs` and
`portable_service.rs`; these side effects remain unextracted and require an
owner-approved security design. A read-only local example and bounded parser
fixture are written but unbuilt/unrun on Windows.

`cursor_delivery` is a separate per-peer, caller-driven bookkeeping extraction
inspired by `MouseCursorSub::send`: the first successful send uses full shape,
later matching shapes can use the existing cursor-ID message, and an explicit
force flag resends full data. It compares retained pixels/geometry on a repeated
source 53-bit ID and refuses a collision, never evicts IDs silently, and fails
closed on capacity or a dropped/uncertain send transaction. Opt-in host methods
can send announcements, resend retained shapes, and sample a Windows cursor;
the book is not connected to the default always-shape host path. The Node host
exposes it through a separate explicit mode. The caller must coordinate a fresh
per-session instance, authorization and peer cache recovery. Successful
send does not prove reception, retention, display, or freshness. Shape copies,
compressed/native buffers and caller/transport memory are not covered by the
limited wipe of owned retained RGBA. Synthetic fixtures are written but unrun.

The experimental host's opt-in cursor announcement is checked against local
view permission, session state and the book's caller-assigned local session
ID. It can resend retained IDs and send a separately sampled position. The
Windows path keeps the source-style full-shape/ID behavior but uses a separate
book from the existing cursor cache; mixing them or reusing an ID/session across
reconnects can break recovery. Sampling, compression and native code cannot be
interrupted, hidden cursors still emit no hide event, and successful send is
not proof of viewer display. The synthetic host/viewer loopback fixture and
Windows path are unbuilt and unrun.

The Node host can explicitly opt into the per-session cursor announcement book
with `enableCursorAnnouncements`, sample a Windows cursor and answer explicit
resend requests. It refuses switching between that mode and the prior
always-shape mode in one session; enabling requires view approval and an
acknowledgement that a peer cache can miss. There is no automatic event routing,
background polling, hide event or independent trusted consent UI. The path,
mode handling and JS fixture are unbuilt/unrun.

The Node host also has an explicit, bounded VP9 ACK-paced burst requiring a
prior duplex upgrade and peer ACK preference. It stops on unhandled control
requests and closes if a request arrives while an ACK is outstanding; no-output
creates no ACK wait. Source `VideoReceived` has no sequence or authentication,
so a delayed or malicious ACK can still be attributed to a later frame and
never proves rendering. No independent consent, automatic QoS/subscription,
continuous service or hard native deadline is provided. This new path and its
local fixture are unbuilt/unrun and do not establish two-system behavior.

### Cooperative Node close requests (unverified)

Viewer operations now check out the native viewer rather than holding its data
mutex through network I/O. `requestClose()` uses a sticky transport close signal
and races viewer I/O against it. A host session has a separate terminal close
request and can race approval sends, event receives, cursor sends and frame/burst
work. Host native capture/encoding is synchronous and cannot be interrupted;
close is not proof of delivery, revocation timing or remote receipt. `close()`
remains necessary to release the host lease and retry detectable cleanup;
viewer capacity remains reserved until the JS object/tasks are dropped. An
expiration cleanup failure retains the host session/lease for explicit retry.
Listener close requests also cancel pending accept/handshake candidates, but
a one-shot Node `ViewerConnectRequest` can also cancel pending TCP/WSS login.
The original connect functions remain non-cancellable. These APIs do not add a trusted consent UI or input permissions. Shutdown, race,
poisoning and Node fixtures are unbuilt/unrun.

### Hidden cursor behavior at the pinned source

`src/platform/windows.rs::get_cursor` returns `None` when `CURSOR_SHOWING` is
not set. `src/server/input_service.rs::run_cursor` only updates the current
shape inside `if let Some(hcursor)` and otherwise retains the last shape; its
snapshot sends that retained message. Thus the current RemoteCore Windows
sampling path's `false` on hidden cursor is not evidence of a missing source
hide message, and no new wire variant should be invented. Position, snapshot,
visibility, portable-service and viewer rendering behavior still require
end-to-end source interoperability testing; last retained shape is not proof
that the UI hides the cursor.

### Windows session wire metadata (unverified)

`message.proto` carries `PeerInfo.windows_sessions` and `Misc.selected_sid`.
At the pinned `src/server/connection.rs::handle_windows_specific_session`, the
source advertises sessions only for installed/share-RDP configuration, one
authorized non-port-forward connection, multiple sessions, current SID present,
and a sufficiently new peer. `SelectedSid` checks installation, configuration,
connection count and fresh OS enumeration before asking IPC to connect to another
session. It may end the existing connection. RemoteCore now has bounded wire
inspection/construction and viewer retention; a typed viewer send requires an
explicit switch-risk marker, and host routing merely reports an untrusted
request behind its local view/change-display permission gate. Node exposes only
read-only session claims, not switching. No OS enumeration, portable service,
IPC switch, fresh consent, source policy equivalence or peer compatibility is
implemented. The local bounds and duplicate/current-ID validation intentionally
reject some possible source messages. Metadata names may be sensitive. Fixtures
are written, not built/run; any full session-switch API requires policy review.

### Peer feature and platform metadata (wire only)

`PeerInfo.features` and `platform_additions` are now inspectable and replaceable
as bounded source fields; the viewer retains the latest claims. The additions
string is opaque (source convention is JSON), not parsed or validated as a
schema. Features are claims only: privacy mode, terminal and port forwarding are
not thereby implemented, authorized or enabled. A local 16 KiB string limit is
not an upstream protocol limit and protobuf parsing occurs before this semantic
bound. Replacing the Features submessage discards unknown fields inside it.
`src/server/connection.rs` derives additions from platform installation, privacy,
clipboard and display conditions; this extraction does not probe or recreate
those policies. Metadata can be sensitive; no comprehensive zeroization is
promised. Unbuilt/unrun.

`windows_session_plan` additionally mirrors the source's two distinct eligibility
branches as read-only caller-supplied snapshots. Advertisement checks the pinned
numeric version threshold and current SID membership; selection re-enumerates
and checks neither. The planner rejects duplicate IDs and more than 64 sessions,
which are local restrictions; it neither parses untrusted version strings nor
runs IPC. Snapshots are stale immediately and a positive result is not consent,
OS authorization, policy equivalence or proof that a later switch is safe.
This is not wired into the view-only Node host and has not been built or tested.

### Windows Translate sequence observation (provisional)

`src/server/input_service.rs::translate_keyboard_mode` routes `Seq` through
`is_hot_key_modifiers_down` once. Without those modifiers it probes left and
right Shift sequentially and may release them; with them it calls rdev's
layout-based `simulate_char(..., true)`. Pinned rdev revision
`0904f23ce496e255461a98848b85c11fa5a62eab`,
`src/windows/simulate.rs`, casts each scalar to `u16` on both paths; it does
not produce a supplementary UTF-16 pair. Its layout path may press/release
modifiers and may report only the principal down result. Source ignores
simulation errors. `windows_translate_text_plan` and the opt-in viewer wire
constructor model/expose this behavior without claiming safe local injection.
The prototype host has no Translate-Seq dispatcher. Global ownership, real
interactive Windows verification and security review remain open. Guards wipe
some Rust-owned sequence/serialized buffers, not JS, transport, parsing errors,
unknown fields or all allocator/native copies. None of this increment was built
or tested.

### Input failure behavior update (unverified)

The experimental `InputController` now denies further input after a detectable
absolute/relative movement or scroll backend failure and attempts to release
all tracked keys/buttons. Failed releases remain tracked for explicit `close()`
retry. A detectable text failure likewise attempts cleanup of any held mouse
buttons; no failed movement, scroll or text is replayed. This local policy is
intentionally fail-closed and not a claim of exact source behavior. Enigo's
Windows movement, scrolling and some release methods can report success without
revealing a native injection failure, and cleanup cannot undo partial input.
The new fake-backend fixtures are written but not run; review this policy and
verify actual Windows behavior before enabling input.

### Wakeable host-loop stop (unverified)

The bounded experimental host loop now races asynchronous driver work and
pacing sleeps against its sticky stop signal. It still cannot interrupt native
synchronous capture/input or owner callbacks. If stop races a send or event,
that side effect may already have happened and its counter/event can be lost;
the loop closes the whole driver instead of retrying. Cancellation can leave
its host in a busy phase, so capture-stop bookkeeping can report a cleanup error
even as the host/transport are closed; the retained error allows only applicable
cleanup retry, not resumption. This local behavior, race and associated
fixtures have not been built or run.

### Candidate path audit (not a build)

The local v41 candidate exported from `bf4ea87` has 433 manifest-hashed
files. Its unsigned hash/membership verifier and the new static local Cargo
path auditor reported 16 manifests and 44 path edges. This is not proof of
authenticity, dependency resolution, feature coverage, native file closure,
licensing or buildability. The audit fixtures and all newer Cargo/Node builds
and tests remain deferred; later commits are not included in v41.

### Blocking Windows Enigo error-buffer review

Static inspection of pinned source `libs/enigo/src/win/win_impl.rs::get_error`
found a potential out-of-bounds write: it initializes a `Vec<u16>` with length
256 but passes `buff_size + 1` (257 UTF-16 code units) to `FormatMessageW` as
its buffer capacity. A sufficiently long formatted system error could therefore
cause Windows to write beyond the initialized buffer/allocation. In addition,
`buff[chars_copied]` can be out of range when the returned count reaches 256.
This path is reachable when source `SendInput` fails in `mouse_down` or
`key_down`, both used by `remote-input::windows::WindowsInput` before the
candidate fork was selected. Whether a particular Windows error triggers either condition has not been
experimentally verified; the mismatch itself is visible in the source. The
Windows input adapter must not be considered safe or production-ready.

Do not alter the RustDesk baseline in place. Before using this path, agree on
and review a narrowly scoped fix in an independently maintained Enigo fork or
extracted copy, make the advertised `FormatMessageW` capacity match the actual
buffer and fix returned-length indexing/terminator handling, then audit the
other unsafe/native paths. Rebuild and exercise success and deliberately failed
SendInput/error-formatting cases on a disposable Windows system with suitable
memory-safety tooling, alongside input cleanup tests. A mock backend or passing
CI compilation would not prove the OS-dependent path safe. This is a blocking
validation/security gate, not a removed RustDesk feature or a verified fix.

Related to this gate, the same source Enigo Windows file contains an
unsynchronized mutable process-global keyboard-layout handle used by key
injection. Multiple extracted backend instances can access it concurrently;
optional per-application arbitration does not cover all paths. See
`windows-enigo-error-gate.md` for the evidence and required concurrency review.

**Candidate mitigation:** `remote-core/vendor/enigo` now contains an
independent source-derived patch for these two findings and is selected by the
Windows adapter. The source tree is unchanged. The patch is not a completed
security review or real-Windows validation; the input gate remains in force.
See `windows-enigo-error-gate.md` for provenance, changed error behavior,
limitations and required tests.
