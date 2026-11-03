# Deferred validation plan — extraction is not complete

This is a plan, not a report of successful execution. Do not treat any command
below as already run. Earlier CI at `229987e` does not cover later changes.
Follow the owner's instruction to execute tests and debugging after the agreed
extraction scope is complete; real desktop/input tests require explicit local
consent and a disposable environment.

## 1. Source and build provenance

- Record the full RustDesk baseline, `hbb_common` submodule object, extraction
  revision, Rust toolchain, native dependency versions and platform/arch.
- Export committed objects to a fresh directory outside the checkout with
  `remote-core/tools/export-source.py`. The exporter does not create a Git
  repository, resolve a lockfile or establish licensing/security clearance.
- Run `python remote-core/tools/verify-export.py <export-root>` and its Python
  unittest fixtures on Linux and Windows; it checks membership and hashes but
  assumes a trusted, quiescent directory and unsigned manifest. Review every
  copied source license and notice before proposing a separate repository.
- Resolve and commit an appropriate standalone lockfile only after reviewing
  dependency resolution and policy. Build without network access is a separate
  reproducibility gate; no such guarantee is currently made.

## 2. Synthetic and native builds

- Prepare pinned Rust/native dependencies from the workflow. Run the workspace
  checks and tests on Linux and Windows with documented toolchain versions,
  including `source-security`; validate an exported tree separately. Exercise
  feature combinations (`wayland`, `drm`, `hwcodec`, `vram`, `mediacodec`) only
  on appropriate platforms with explicit prerequisites; mark unsupported
  combinations and retain failure logs rather than claiming all features pass.
- Build the Node addon on each supported target and run the non-interactive
  Node tests. Check API/type exports and resource cleanup under cancellation,
  garbage collection, process shutdown, oversized inputs and error paths.
- Exercise `DirectTcp`, strict WSS and duplex handoff with slow peers, framing
  fragmentation, corrupted ciphertext, queue saturation, repeated cancellation,
  write/read interruption, nonce exhaustion, task shutdown and reconnection.
  Tests must not mistake ACK or successful send for remote rendering.
- Compare protocol messages and behavior against the pinned source, including
  login with/without video ACK, combined options, permission revocation,
  display subscriptions and keyframe recovery. Exercise optional peer-disable
  cleanup, ACK timeouts/late ACKs, cross-display pacing, supported/original mode
  claims, stale recovery generations, cursor focus/echo, budget contention and
  per-key timeout generation/repeat behavior. For budgeted captures, test native
  open failure rollback, reconfiguration failure with old streams still alive,
  temporary capacity limits, stop-before-drop and close/disconnect ownership;
  verify resources drop before their reservations under failure and cancellation.
  Exercise `ScheduledSession` with receive bursts, per-display WouldBlock,
  ACK-required versus non-ACK login, queue-full backpressure, permission revoke,
  timeout during idle and in-flight capture, malformed frames and close failures.
  The opt-in `scheduled_desktop` integration is prepared for Xvfb but has not
  run; without `REMOTE_CORE_TEST_DISPLAY=1` it returns early and a passing
  test result does not mean that capture was exercised. The manual Windows
  multi-display example is not a substitute for these tests. Before wiring stale-key cleanup,
  validate ownership and concurrently repeated key-down/cleanup semantics against
  source and real Windows, including partial delivery and local-human input.
  Exercise inactivity at whole-second boundaries, disabled input, refresh/ACK,
  blocked I/O, timer scheduling, disconnect cleanup and capture handle release.
  Check receive watchdog behavior on raw malformed frames, queued read-ahead,
  long native operations, genuine probes, timeout and cleanup under cancellation.
  The Node `display-wire.test.cjs` fixture includes source protobuf field tags;
  independently compare it with source serialization. Legacy fallback, 2FA and
  missing source behavior require explicit compatibility decisions, not silent
  removal.

## 3. Windows and interoperability (authorized operator)

- On a disposable interactive Windows desktop, manually verify DXGI/GDI capture,
  multiple monitors, mixed DPI/rotation, hotplug, modes, cursor shapes and hidden
  state; test input translation, modifier/gesture cleanup and permission
  revocation only where injection is expressly authorized. The read-only
  `windows_foreground_follow` example still discloses local activity and needs
  explicit informed consent; compare foreground/cursor coordinates against DPI
  awareness and topology changes. Secure desktop/UAC,
  portable service, global input arbitration and OS recovery require separate
  design and must not be inferred from ordinary desktop results.
- Verify software and hardware codecs and actual GPU/device-loss/fallback paths
  on representative machines. Native decoder libraries are not sandboxed;
  do not feed untrusted compressed data until a reviewed isolation strategy is
  implemented and independently validated.
- Test source host/viewer compatibility and independently configured WSS/TLS
  endpoints. Cloudflare behavior is an operational transport test, not a trust
  mechanism; document limits and failures without blocking unrelated core work.

## 4. Release gate

Security review must cover credential derivation/offline guessing, peer identity,
key provisioning and rotation, rate limiting, local owner approval, trusted
proxy address attribution, resource bounds, failure cleanup and the deliberate
source-v1-only policy. Review the final public API, protocol compatibility and
licenses with the owner. Any failed build, test or review remains an explicit
blocker; do not claim a complete independent SDK until all agreed gates pass.

### Deferred viewer FPS coverage

Run the `viewer_fps` synthetic tests and `host_connection` FPS dispatch tests
with the full workspace after extraction. Compare scripted multi-display traces
against `src/client/io_loop.rs::fps_control`, especially missing samples,
source inactivity boundaries (the filter uses `< 15`, trend uses `> 15`),
refresh timing/count, relay ratios, custom FPS precedence, membership churn,
and send failure/cancellation. Exercise real decoder queues and mixed desktop
sizes only with a trusted local producer; a pinned host does not make compressed
bitstreams safe. Validate per-display/legacy refresh compatibility separately.

The Node `viewer-fps.test.cjs` and opt-in local-host dispatch cases are also
written but unrun. Check TypeScript/Node-API object conversion, worker cleanup,
viewer cancellation/close races, zero/oversize values, reconnect/topology reset,
and JS exceptions; ensure no libuv/network operation holds a JS-facing mutex.

Test `viewer_video_queue` limits, keyframe supersession, failed decode,
malformed/wrong-stream packets, exhausted generations, in-flight reset and
caller-retained buffers. Exercise Node worker startup, shutdown, cap reuse,
thread panic, blocked decode, dropped promise/results, concurrent operations,
round-trip owned buffers, codec switch and teardown. Test with locally generated
trusted bitstreams only; untrusted codec fuzzing belongs in an isolated native
sandbox and requires a separate security plan. Compare documented queue policy
differences with source before accepting compatibility.

Verify viewer cursor cache selection, peer-ID collisions, maximum dimensions and
item/byte eviction, stale/missing IDs, failed insert, delayed resend races,
embedded/visible cursors, reconnect and cache isolation, and Node-owned buffer
copies. Compare old-peer content dedupe, source UI behavior and cursor resend
interoperability separately; do not claim this helper implements those paths.

The RemoteCore workflow now includes deferred Node 20 addon build and synthetic
Node test steps on Linux and Windows; Linux also runs the opt-in local-host
capture cases inside Xvfb. These steps do not run until a relevant branch push.
Xvfb is not an interactive Windows desktop, and successful Node synthetic tests
would not validate security, real screen permissions, WSS relays or hardware
paths. The Node crate sets `test = false`, so Cargo workspace tests alone do not
execute its JS binding tests; the explicit npm steps are required.

Run the synthetic `source_two_factor_responses_do_not_bypass_basic_viewer_login`
case for both source error strings. It asserts denial/closed state only; passing
it would not implement or validate 2FA, trusted devices, TOTP, code replay
prevention or the source server's failure counters. Those remain security gates.
For frame rates, cross-check UI-callback counts versus true packet arrivals,
subsecond/long intervals, source integer boundaries, shared display tick timing,
manual FPS resets and explicit dispatch ordering.

Exercise `ProbeQos` with a responsive source viewer, forged/mismatched and late
replies, regressing caller time, elapsed/RTT boundary truncation, peer removal,
view revocation, mid-send cancellation, timeouts, source session-ID reuse and
QoS sharing. Confirm teardown after an interrupted send and no pending borrow
or network operation survives the session. The synthetic loopback fixtures do
not authenticate replies or prove any end-to-end bandwidth measurement.

The Node local-host fixture also sends an explicit TestDelay after view approval
and expects a heartbeat carrying the source reply fields. Check missing fields
on ordinary heartbeat, i64 string boundaries, mismatched/forged replies,
concurrent and cancelled sends, checkout/cleanup and JS exceptions. It exercises
only a synthetic local peer/Xvfb when opted in, not a secure network RTT.

Run `ScheduledSession::drive_once` with sustained untrusted event bursts,
queue starvation, zero/invalid deadlines, pause/WouldBlock, ACK wait and
revocation while traffic continues. Confirm the local four-event limit, capture
attempt reset on error, caller handling of every returned event, no busy loop on
`Wait`, duplex queue backpressure, timer polling and shutdown. The Xvfb desktop
fixture now exercises a basic fair capture step but remains unrun and cannot
establish production fairness, low latency or Windows desktop behavior.

Validate DXGI access-lost recovery on a disposable interactive Windows desktop,
including reset at the ten-second boundary, replacement capturer creation failure,
mode/topology/identity changes, the two-second WouldBlock grace, GDI fallback,
encoder reset/keyframe and viewer synchronization, budget ownership, privacy
mode, secure desktop and consent revocation. The pure recovery state tests do
not perform any of these actions and have not been run.

The Windows scheduled-desktop fixture can additionally exercise an explicit GDI
transition with both `REMOTE_CORE_TEST_DISPLAY=1` and `REMOTE_CORE_TEST_GDI=1`.
It checks encoder invalidation and explicit recreation if the original backend
is DXGI; if already GDI it does not cover that branch. This captures a real
screen and is not enabled in unattended CI. Validate failed `set_gdi`, automatic
backend changes, revocation, display identity, resource cleanup and peer
keyframe coordination separately before use.

Compare `static_refresh` against pinned `video_service/static_refresh.rs` across
quality boundaries, backend identification, no-output versus codec errors,
source-ready transitions, capture-loop/encode timestamps, subscription changes,
and changing frame rates. Integration must also validate secure frame disposal,
revocation, stale frame retention, encoder reset on failed/cancelled send, ACK
flow and multi-viewer behavior. Policy fixtures are not native encoder tests.

For the explicit cached-frame repeat, validate local permission revocation,
retention expiry, future cancellation at encode/send boundaries, source VPX
no-output behavior, zero deadline, decoder/keyframe reset, and failed or
indeterminate network sends. Inspect wrapper, native codec and allocator memory
separately; zeroization of one owned slice is not whole-process erasure. Existing
synthetic loopback and codec fixtures remain unrun.

The single-host capture pump also exposes an explicit repeat without capture.
Test its bound session/view checks, stop/revocation cleanup, source VPX
no-output, pending send cancellation and native buffer retention. Scheduled
multi-display capture has no repeat integration or ACK coordination here.

`host_repeat_desktop` adds an opt-in Xvfb/desktop capture-and-repeat fixture and
is scheduled in the unrun Linux workflow. Its loopback TCP is plaintext and
local processes are not excluded, so use a disposable isolated display/host;
it is not a network-security or interactive-Windows test.

Validate exact typed `scrap::VpxNoOutput` classification (including wrapped
errors, both VP8/VP9, and excluding AV1/lookalike failures), native state after
no-output, retained image expiry, no packet/ACK on no-output, repeated encode,
wire delivery, zero deadline, cancellation, permissions, cleanup and decoder
synchronization. Run both fake transport fixtures and isolated Xvfb/Windows
capture fixtures. The actual frequency and semantics depend on native libvpx;
none of the new paths has been compiled or executed.

For `ScheduledRefresh`, validate caller-provided codec/display binding, capture
start versus completion age, no-output and output budgets, ACK block without a
native attempt, cancellation at every await, consent refusal/cleanup, idle
sessions without polls, slow native encode after expiry, reconfiguration/reset,
identity reuse, topology changes and concurrent input/event fairness. Check that
`VpxNoOutput` increments source repeat-failure accounting without ACK and that
other failures poison/close rather than retry. The TTL is a cooperative policy,
not a strict privacy or erasure guarantee.

For optional `source-totp`, build the feature matrix with the locked source
crate, run RFC SHA-1 vectors and skew/clock-boundary cases, fuzz field bounds,
inspect transient secret copies and zeroization, and review credential storage,
clock rollback, repeated same-step codes, concurrent sessions, trusted-device
policy and global lockout before any login integration. Source compatibility
is not a substitute for security review.

Test the explicit viewer 2FA flow against a trusted source peer, including no
prompt, repeated prompt, wrong code, interleaved TestDelay, timeout/cancellation,
malformed fields, empty hardware ID and no trusted-device request. Verify the
default viewer still closes on 2FA and never sends codes. A malicious host can
request or relay codes; the API cannot establish channel security and server
acceptance is not proof of verification.

Node's new second-factor options need addon build and validation tests on both
platforms plus an explicitly trusted, pinned source loopback peer for success,
wrong code, no prompt, timeout and ACK-required cases. Confirm neither error
messages nor diagnostics log the code and examine N-API/task cleanup. Existing
Node host does not enforce 2FA and cannot serve as proof of a verified flow.

On a disposable Windows desktop, compare opt-in supplementary Unicode event
order and target application behavior with pinned Enigo, including surrogate
boundaries, held modifiers, focus/desktop changes, UIPI, partial SendInput,
revocation and process crash. The backend does not report all failures and the
source sends unmatched surrogate downs; synthetic tests cannot prove cleanup.

Windows-to-Windows hotkey tests must cover the high/low-word wire payload,
layout-specific mapping, no mapping, zero/reserved VKs, UTF-16 surrogates,
modifier and `press` flags, map/translate mode differences, repeated down/up,
partial Unicode key-click failures, ignored native modifier-up errors, and
cleanup/revocation/desktop switching. Do not turn the source's fallback on after
an uncertain partial injection without an explicit reviewed policy and real
Windows validation.

The experimental duplex TCP handoff now clears queue-owned plaintext on drop,
including queued/cancelled outbound messages and queued inbound messages; its
current read buffer is cleared after copying. This does not clear the pinned
source cipher's temporary decrypted allocation, framing buffers, returned
caller-owned data, native crypto copies, or crash dumps. The read-ahead driver
fails closed when it observes EOF/error: a concurrently queued final frame may
be discarded even if the peer's local send completed. Check that ordering and
close/cancellation races behave as documented; never interpret a successful
local send or close as proof that the application processed a message.

The candidate exporter now retains the baseline `.cargo/config.toml`, including
Windows CRT settings. The deferred CI definition separately builds/tests the
exported workspace and Node addon on Windows as well as Linux; it has not run
for this increment. Static config preservation does not establish that native
dependencies, the inherited lockfile, licenses, or an independent build work.

For `bounded_host_loop`, verify event/capture fairness under sustained input,
consent revocation while capture or send is blocked, immediate and delayed
stop, deadline/step budget, callbacks that return errors or panic, loss and
partial writes, native WouldBlock versus codec WouldBlock, drop/cleanup errors,
per-display ACK behavior, dynamic topology changes and timestamp resets. An
interactive two-system Windows test is separate from synthetic timing fixtures.

Compressed entries retained by `ViewerVideoQueue` and the Node trusted decoder
worker's owned request/output buffers now use best-effort zeroization when
discarded. A frame popped to a caller and an image handed to JavaScript are no
longer owned by those wrappers. Protobuf, native codec, allocator, external
copies, already-transferred buffers and process crashes remain outside the
guarantee. Validate invalidation, in-flight tickets, dropped replies, close races
and native decoder lifetime without treating successful tests as secure erasure.

### Deferred sensitive wire, replay and credential-lifetime coverage

Run `remote-protocol` sensitive-display and login-guard fixtures on both targets,
then compare source privacy/block-input/lock/disconnect semantics against the
pinned connection and Windows service implementations. Test unsupported messages
and combined options without invoking any native OS action; a synthetic backend
cannot observe direct platform side effects. Any actual privacy, virtual-display
or block-input execution needs an owner-approved policy and a separate isolated
Windows test plan, including partial failure and recovery.

Run `remote-security` replay-claim concurrency, expiration, capacity, clock
regression and poison fixtures; review the HMAC domain separation, principal/key
lifecycle and time-step assumptions independently. Test process restart,
multi-process operation, wall-clock jumps, replay races and persistent/shared
rate limits only after implementing the missing policy. A passing in-process
fixture does not enforce 2FA in host login. Inspect login-guard cancellation,
protobuf unknown/other variants, shared `Bytes`, serialization and transport
copies; the fixtures verify field state, not physical memory erasure. Validate
the WSS endpoint policy and Node synchronous rejection alongside certificates,
DNS/SSRF policy and relay interoperation. All these fixtures are currently unrun.

For `windows_desktop`, independently inspect handle ownership, access rights,
UTF-16 length/termination and error propagation on a disposable interactive
Windows system. Compare same-thread behavior against the pinned source across
normal, locked, disconnected and UAC/secure-desktop transitions without
switching or injecting input. Names alone do not identify window stations or
prove safety; a task migration invalidates a result sampled on another thread.
Any future desktop switch or service integration requires its own policy and
restoration/cleanup tests. The local example and fixture have not run.

Validate `cursor_delivery` shape/ID ordering, force-resend, cache exhaustion,
collision rejection, incomplete transaction poisoning, failed/partial writes,
cancellation, reconnect isolation and zeroization limits before considering
integration. Compare peer cache eviction and older/newer source viewer behavior;
ID references assume remote retention and do not prove delivery or rendering.

The opt-in Node ACK-paced VP9 burst needs synthetic transport-level coverage for
ACK before send, duplicate/late/forged ACK, no-output, event before and during
ACK wait, deadline and stop with/without an outstanding frame, decoder reset
between bursts, host slot cleanup, queue saturation and transport cancellation.
Verify capture cadence on WouldBlock, display hotplug, privacy revocation and
liveness timeout while native calls block. A single-frame local Node fixture and
optional two-system non-decoding diagnostic are written, not run; neither is a
substitute for these failure tests or Windows interactive interoperability.

For the source-style cursor book, compare peers below and at the source 1.5.0
cursor-content naming boundary in `src/common.rs::is_peer_naming_cursors_by_content`
and `src/client/io_loop.rs::{dedupes_cursors,set_cursor_data_by_content}`. Check
same-handle shape changes, content-hash collisions, animation, cache misses,
`CursorId` after eviction, delayed resend and embedded or hidden cursor paths.
The current book always uses content IDs and does not claim complete older-peer
compatibility. Do not rely on the synthetic collision injection as evidence of
collision resistance or on matching OS handles as stable shape identity.

Exercise the sticky `close_signal` race with request before registration, while
pending, concurrent completion/request, multiple waiters and dropped futures.
For Node host and viewer, test closure while operations are queued, read/write
is pending, approval sends are partially delivered, native capture/encode blocks,
ACK is outstanding, state mutex is contended/poisoned, worker unwinds and cleanup
fails. Verify no reuse after an uncertain send, no session-lease release before
successful cleanup, and explicit close/GC behavior. A pending-login fixture and
interactive local fixtures are written but have not been run. These local tests
cannot prove OS revocation timing, remote non-delivery, or two-system security.

For Windows session interoperability, use disposable authorized Windows
machines and record the source version, installed/service state, share-RDP
setting, process session and active-session list. Verify login/update claims,
selection of current vs another session, peer-version conditions, timeout,
service reconnect and consent independently; no OS switching is implemented by
this prototype. Exercise absent/present-empty/malformed/oversized/duplicate
claims, stale lists and send failure without replay. Ensure the local permission
gate is not confused with source policy. For platform additions, separately
validate untrusted JSON handling, feature omissions and unknown protobuf fields;
wire helpers do not authenticate or parse JSON. New fixtures are unrun.

For the updated bounded host loop, cover stop arriving during an active duplex
receive, partially delivered send, completed-but-unobserved event, native
capture, pacing sleep, callback and cleanup; check whether a busy-phase capture
stop reports an error while host close still runs. Do not assert that `sent`
counts exactly match peer receipt when stop races a completed send. Run both
loopback fake I/O and the separately authorized interactive desktop fixture.

Run the `sensitive_input` field-scrub, Debug-redaction and input-backend partial
movement/text fixtures. Verify invalid option paths and task cancellation on the
Node host/viewer; Rust-owned text guards cannot erase JS strings, unknown
fields, parser failures, transport/native copies, dropped raw control events or
allocator history. Compare Translate/Seq wire mode with the pinned RustDesk
source and test the model's non-BMP truncation only in a disposable test setup;
the experimental host intentionally rejects this input form. Do not use native
input or decoding in unattended CI.

After exporting a fresh candidate, inspect its manifest, run the static Cargo
path auditor and its synthetic fixtures, then separately run actual Cargo
metadata/build/test with the intended toolchain and feature matrix. The auditor
cannot evaluate external crate resolution, conditional cfg/features, build.rs,
macro includes, native files or license closure. Also validate diagnostic
approval prompt abort/setup-failure and host/viewer Ctrl+C races; a CLI signal
is not a trusted consent channel and cannot interrupt blocking native calls.

**Blocking Windows input gate:** Before enabling `WindowsInput`, address and
review the pinned Enigo `get_error` buffer-size mismatch described in
`remaining-core-work.md`. Test returned-length boundaries and error formatting
under a memory checker on disposable Windows, plus both mouse/key SendInput
failure paths. No source edit or runtime confirmation has been made here.
