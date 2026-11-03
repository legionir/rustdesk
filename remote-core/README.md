# RemoteCore — experimental extraction prototype

This is an **experimental partial extraction**, not a standalone RemoteCore release.
The latest local work is not covered by the historical CI runs linked below;
no current independent build, two-system interoperability, security review or
Windows interactive-desktop verification has been completed. The working gap
list and deferred validation plan live in `../docs/analysis/remaining-core-work.md`
and `../docs/analysis/deferred-validation-plan.md`. In particular, privacy,
virtual-display and block-input wire helpers do not execute those operations;
the experimental replay helper is not connected to host 2FA. Do not deploy this
prototype as a secure remote-access service.
It uses the RustDesk checkout's `libs/scrap`, `base`, and `hbb_common` by path;
those crates also bring native libraries and other dependencies. The source
commit is `23e5bb471a040d62f0a6ad52591fb30784265b73`, and the hbb_common
submodule is `fae47e024dd83cef6aaecde0aa7d11731df11649`.

The capture adapter enumerates displays and exposes borrowed CPU frames or a native
texture handle. Input, codecs, session/security, loopback networking, provisional
strict WSS, experimental pinned source encryption and a partial Node binding are described below. They are incomplete,
not yet integrated into a secure remote desktop, and do not establish a complete
multi-platform support contract.
Texture interpretation remains platform-specific. `WouldBlock` and timeouts
retain the original backend's semantics. No guarantees about hotplug, scaling,
concurrent sessions or stable monitor IDs have yet been established.

For Linux with the native dependencies installed:

```sh
cargo test --manifest-path remote-core/Cargo.toml --workspace --features linux-pkg-config
REMOTE_CORE_TEST_DISPLAY=1 xvfb-run -a cargo test --manifest-path remote-core/Cargo.toml --workspace --features linux-pkg-config --test x11_capture -- --nocapture
```

The display test is opt-in because it accesses a real display. CI runs it on an
isolated virtual X11 display. Wayland, Windows and macOS require independent
validation. Review `../LICENCE` and the licenses and provenance of all source
and dependencies before distribution; the final licensing decision is pending.

## Software codec prototype

`remote-codec` adapts the source VP8/VP9/libaom AV1 encoder/decoder for padded
I420 input and packed CPU output. An opt-in H.264/H.265 RAM hardware adapter
and a bounded wrapper around the source's global codec negotiation have since
been added, but are not tested or integrated into a complete session. A separate
Windows `vram` prototype exists; packet-loss recovery, production fallback and
in-place resolution changes remain incomplete. None of the source capabilities has been removed from RustDesk. The decoder must not be used with untrusted streams: packet size checks
do not limit dimensions or native decoder allocations. No security audit has
been performed.

A Linux CI run on commit `2fd23de` passed workspace `cargo check`, software
codec unit round trips, and an Xvfb display capture test:
https://github.com/legionir/rustdesk/actions/runs/41342856512. It does not
validate the full RustDesk baseline, other platforms, hardware codecs, or
security. The prototype does not yet commit a standalone lockfile; dependency
resolution may therefore change between runs.


`SoftwareEncoder::encode_packed` connects a matching-size BGRA/RGBA capture
buffer to the source libyuv I420 conversion and encoder. An opt-in integration
test captures, encodes and decodes a display. The Linux workflow runs this on
Xvfb. The Windows CI job builds and runs software tests on a Windows runner;
it does **not** claim a DXGI capture test because a hosted runner may not have
an interactive desktop. On a disposable interactive Windows machine, set
`REMOTE_CORE_TEST_DISPLAY=1` and run the `capture_pipeline` integration test;
ensure screen capture is authorized. Recreate the encoder when resolution
changes; pixel formats other than packed BGRA/RGBA are not supported by this
bridge yet.

## Windows input prototype

**Blocking safety concern:** the pinned source Enigo Windows `get_error`
passes a 257-code-unit capacity to a 256-unit buffer and can index at the
buffer length on certain long system error messages. The experimental Windows
input backend reaches that path after failed mouse/key `SendInput` calls.
The risk is based on static source inspection and has not been reproduced.
The adapter now uses a source-derived fork with candidate fixes for this buffer
and the layout race. Those fixes have not cleared independent review or native
validation. Do not enable the backend until the gate is cleared. See
`../docs/analysis/remaining-core-work.md` for the exact scope and next steps.
The Windows local-pipeline, loopback-session and multi-display examples also
construct this backend, even though their current policies grant view only;
defer running them until the gate has been reviewed.

`remote-input` wraps a source-derived Enigo Windows fork and tracks held virtual
keys and mouse buttons per controller. Permissions default to denied; revocation
and `close()` attempt cleanup. Windows Enigo does not report all `SendInput`
failures, so a successful release is not proof that Windows accepted it. Drop
is best-effort and cannot handle process crash or power loss. This module is not
an authenticator or a sandbox. Only use it under an authenticated, authorized
session manager that serializes access to the OS input device; concurrent
controllers can otherwise interfere with each other's keys. Layout conversion,
full scan-code/layout translation, text/IME, automatic repeat timing and
monitor-relative mapping are not implemented. Limited legacy BMP text, explicit
repeat-down injection, opt-in tracked modifiers and restricted Windows Map and
Translate paths do not reproduce full source behavior.
Experimental mouse and unmodified legacy-control-key protocol translation covers
only a subset and is documented in `../docs/api/protocol.md`.

Only **after the blocking safety gate above is fixed and reviewed**, on an
interactive, disposable Windows desktop, focus a test editor and run:

```powershell
cargo run --manifest-path remote-core/Cargo.toml -p remote-input --example windows_input -- --confirm-inject-input
```

This deliberately injects the A key into the focused window. Never run it on a
production desktop. CI uses a fake input backend and does not inject keys.

To manually test the capture-to-codec bridge in an interactive Windows session
with the documented native dependencies installed:

```powershell
$env:REMOTE_CORE_TEST_DISPLAY = "1"
cargo test --manifest-path remote-core/Cargo.toml -p remote-codec --test capture_pipeline -- --nocapture
Remove-Item Env:REMOTE_CORE_TEST_DISPLAY
```

The test expects a capturable display with even dimensions no larger than
4096×4096 and BGRA/RGBA pixels; it may fail on a locked or unavailable desktop.
It does not transmit or render frames. Explicitly inspect the desktop and
permissions before running it.

## Local transport prototype

`remote-transport` adds an async in-process binary transport with bounded
per-direction queues, size limits, backpressure, deadlines and close handling.
It is not a network transport and provides no authentication, encryption,
heartbeat or reconnect. The Linux display integration test now sends encoded
packet bytes through the local transport before decoding. Packet metadata is
passed in-process by the test; it is **not** a wire protocol or a complete
host/viewer session. Separate experimental loopback TCP/WS adapters and a strict WSS client now exist;
they are not yet security-reviewed or verified as a complete host/viewer.

## Session lifecycle prototype

`remote-session` adds a bounded in-memory session registry, lifecycle states,
explicit authentication and owner-authorization interfaces, per-action
permission checks, and retryable resource shutdown. A separate experimental
password-challenge verifier exists, but the session crate does **not** implement
credential storage, owner approval UI, secure ID generation,
transport binding, heartbeat, timers or actual streaming orchestration. The
session manager remembers used IDs only for its process lifetime and is not a
replay defense. Dispatchers must enforce `Session::check` at every input and
screen action and integrate resource shutdown, not assume the state machine
stops already-running work. This code is new and has not yet been tested.

`remote-core::HostInputSession` is an experimental integration between the
session authorization guard and the Windows-input abstraction. Every exposed
input action checks the session capability and the input controller also checks
its own permissions. Revocation attempts to release held inputs; close attempts
both input and session cleanup. This is not the final facade or a full remote
host: trusted authentication/consent providers, transport binding, global
exclusive input arbitration, capture/streaming orchestration, and validation
remain required. A cooperative input arbiter is available but cannot exclude unguarded input
paths or other processes. This integration has not yet been built or tested.

## RustDesk protocol adapter

`remote-protocol` wraps the source `base` protobuf schema, with explicit
serialized message bounds, mouse inspection/construction, and video packet
inspection/construction for VP8, VP9, AV1, H.264 and H.265 wire variants.
Recognition of a wire variant is not a claim that its codec is usable on the
host. Unrecognized supported RustDesk message kinds remain available for
round-trip encoding rather than being silently removed, but their semantic
handlers are not implemented. The adapter does not authenticate messages or
validate every field; the pre-authorization limit is a caller responsibility.
This code has not yet been built, tested or security-audited.

`remote-core::video` adds an experimental capture-buffer → software encoder →
RustDesk protobuf → generic transport sender and a matching receiver. The
sender checks an externally owned streaming session and view permission, and
requires an encoder reset after failure or cancellation. An experimental wrapper
now invokes the source's process-global codec negotiation; it is not yet wired
into a complete host or viewer. Renderer, authenticated transport,
reconnection, bounded native decoder allocations and live task cancellation
are not implemented. The receiver must not be exposed to untrusted peers. This
pipeline has not been built or tested.

`remote-rustdesk-websocket` is an experimental wrapper around the original
RustDesk WebSocket client, limited to literal loopback `ws://` addresses. It
is unauthenticated and accepts upstream plaintext text frames; it is not a secure
network transport. A separate strict WSS client now isolates TLS policy but still
requires review and peer authentication. Neither adapter has been built or tested.

`remote-security` adds an experimental implementation of RustDesk's existing
password challenge calculation and a single-use expiring verifier; owner
approval remains a separate embedding-application decision. This legacy scheme
is vulnerable to offline password guessing from captured transcripts and does
not authenticate the server or bind to TLS. It must not be exposed to remote
peers without a separately authenticated encrypted channel, rate limits,
trusted consent and security review. It has not yet been built or tested and
does not implement RustDesk 2FA or the complete login flow.

### Experimental Windows local pipeline

`windows_local_pipeline` exercises password-challenge calculation and a locally
recorded approval, display capture, VP9 encode, RustDesk protobuf, local
transport and decode in one process. It is **not** a remote viewer, does not
render, does not test mouse/keyboard, and its approval is not a human-consent
UI. It captures a real display. Run only on a disposable, interactive Windows
desktop after reviewing the source and native prerequisites:

```powershell
$env:REMOTE_CORE_EXAMPLE_PASSWORD = "a strong example-only password"
cargo run --manifest-path remote-core/Cargo.toml -p remote-core --example windows_local_pipeline -- --confirm-capture
Remove-Item Env:REMOTE_CORE_EXAMPLE_PASSWORD
```

Environment variables may be visible to local processes; do not use a real
credential. Dimensions must satisfy the prototype encoder's even 2–4096 pixel
bounds, and the first capture may return `WouldBlock`. The example is not yet
built or tested.

The experimental `bindings/node` Node-API addon covers local display enumeration,
raw capture and software-frame encoding, plus partial host/viewer APIs. It is
not a complete remote desktop SDK; see its README for prerequisites, privacy
constraints and limitations. Later Node changes have not been built or tested.

### Exporting a candidate independent source tree

`python3 remote-core/tools/export-source.py /path/to/new-directory` exports the
committed prototype, pinned RustDesk library paths, exact `hbb_common` submodule
commit, root license and an inherited lockfile into a new directory outside the
checkout. It does not modify the RustDesk source or initialize a Git repository.
The exporter uses Git objects, so uncommitted changes are excluded. It records
commits and archive hashes in `SOURCE_PROVENANCE.md` and an unsigned file hash
manifest in `SOURCE_MANIFEST.sha256`. The baseline `.cargo/config.toml` is
also included to retain its Windows CRT and other target settings; it has not
been validated as a standalone build configuration. The inherited lockfile is
only a resolution starting point: a locked independent build and license review
are still outstanding. A focused generated root `.gitignore` excludes common
build artifacts but cannot protect custom targets, secrets or user data. Before
building or creating a repository, run
`python remote-core/tools/verify-export.py /path/to/new-directory` on a trusted,
quiescent tree. It detects file hash/membership changes, not authorship or
provenance authenticity; build products and a new `.git` directory count as
unlisted files. The exported tree is experimental and untested.

`python3 remote-core/tools/audit-path-dependencies.py /path/to/new-directory`
(Python 3.11+) additionally inspects explicit workspace members and local
Cargo path dependencies, including target, development and build dependencies.
It rejects unsupported workspace inheritance/globs, escaping/absolute paths
and missing manifests instead of guessing. It does not invoke Cargo, interpret
features, resolve remote crates, inspect build scripts/includes/native files,
prove portability, verify hashes or replace a build. Candidate v41 at commit
`bf4ea87` was inspected (16 manifests, 44 edges). The auditor's synthetic
fixtures subsequently passed; current Rust and addon builds remain unverified.
See `../docs/analysis/validation-results-20261103.md` for the limited results.

The RustDesk adapter also contains experimental loopback-only TCP client and
listener wrappers using RustDesk's existing `FramedStream` codec. These are
plaintext and do not authenticate local peers; never use them for credentials,
remote input or private screen contents. Send failures have indeterminate
delivery, and the wrapper does not implement the in-process transport's
stronger cancellation contract. TCP adapter tests are written but unrun.

`strict_wss::StrictWss` is a provisional binary-only WSS **client** built on the
pinned RustDesk WebSocket fork with its own validating TLS configuration and no
insecure fallback. It authenticates the WSS endpoint, not the desktop peer, and
is not end-to-end encrypted through a relay. It does not yet provide a secure
host/viewer, trusted consent or a hardened video decoder. It has not been built,
tested or audited; see `docs/architecture/transport-design.md`.

### Source backend features

The workspace forwards the source `scrap` features `wayland`, `drm`,
`hwcodec`, `vram`, and `mediacodec` as opt-in features where relevant. This
preserves access to upstream build paths; it **does not** implement or verify
all hardware codecs, GPU texture handling, Wayland portal setup or mobile
capture through the current public adapters. Feature combinations, extra native
prerequisites and platform behavior remain untested. The software encoder API
still supports only VP8, VP9 and AV1.

With the opt-in `hwcodec` feature, `remote-codec::hardware` wraps RustDesk's
cached H.264/H.265 RAM encoder selection and NV12/packed conversion. It does
not automatically fall back, negotiate codecs, decode, handle VRAM textures or
prove a backend is truly GPU accelerated. It uses the source's process-global
hardware config and can mutate it on encoder failure; Windows native FFmpeg,
driver and configuration prerequisites remain. This code and its ignored
real-hardware test have not been built or run.

`remote-core::capture_pump` connects an already authorized session to an exact
capture display and software video sender, one caller-driven frame at a time.
It is synchronous around native capture/encoding and can block the executor;
run on an appropriate dedicated thread. It is not a host server, renderer,
consent UI or authenticated transport. It has not been built or tested.

The Node addon includes experimental pinned direct TCP/WSS viewers and a
view-only host with single-frame and bounded burst sends. Its default listener
is loopback-only; a separate restricted network listener is explicitly opt-in.
It does not render video or provide a complete input or general host API. Its security and build are unverified; see `bindings/node/README.md`.

A further manual `windows_loopback_session` example composes the provisional
direct TCP framing, pinned source-v1 key exchange, password/owner approval,
capture pump with an opt-in cooperative reservation and trusted local VP9 decode.
The budget accounts for configured pixel area/stream counts, not actual native
allocations or unbudgeted capture paths. It binds loopback only and captures a
real screen; it requires an explicit command-line confirmation, an interactive
disposable Windows desktop and native dependencies. It is written but **not
built or run**; it is not a production security demonstration. Command after
extraction and review:

```powershell
cargo run --manifest-path remote-core/Cargo.toml -p remote-core --example windows_loopback_session -- --confirm-local-screen-capture
```

### Experimental multi-display example (not built or run)

On an authorized disposable Windows desktop with at least two displays, the
following manual example drives a provisional scheduled duplex session and
locally decodes the first VP9 frame from each of the first two displays, using
per-stream budget reservations. The scheduler may send extra frames. It uses a temporary loopback-only key and demo
password and reads real private screen contents; do not run without the local
user's consent. Successful compilation would not prove GPU, hotplug, secure
Desktop/UAC, production security or RustDesk interoperability.

```sh
cargo run --manifest-path remote-core/Cargo.toml -p remote-core --example windows_multi_display -- --confirm-local-screen-capture
```

`MultiCapture`, display subscription planning and per-display timing/recovery
are separate caller-driven experimental pieces. They do not automatically
follow display changes, schedule captures, coordinate decoder recreation or
provide an owner-consent UI. See `../docs/analysis/remaining-core-work.md`.

### Status of newer increments

The latest successful CI run applies only to commit `229987e`:
https://github.com/legionir/rustdesk/actions/runs/41442854621. Later changes,
including the opt-in direct TCP read-ahead driver, read-only Windows display
mode planning, WSS listener composition and recent Node additions, have not
been built, tested or security reviewed. See `../docs/analysis/remaining-core-work.md`
for current gaps, caveats and deferred validation. The prototype is not a
replacement for RustDesk and must not be exposed to untrusted peers.

### Manual Windows foreground-follow inspection (unverified)

Only after informed local consent on a disposable interactive desktop:

```powershell
cargo run --manifest-path remote-core/Cargo.toml -p remote-core --example windows_foreground_follow -- --confirm-local-foreground-inspection
```

The example samples foreground window geometry for ten seconds and prints only
changes in the matching display index. It does not send data, inject input or
capture pixels. Focus/geometry still reveal activity; topology and DPI contexts
may change, and the example has not been built or tested.
