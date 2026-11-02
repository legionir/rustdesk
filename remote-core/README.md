# RemoteCore — capture extraction prototype

This is an **experimental first adapter**, not a standalone RemoteCore release.
It uses the RustDesk checkout's `libs/scrap`, `base`, and `hbb_common` by path;
those crates also bring native libraries and other dependencies. The source
commit is `23e5bb471a040d62f0a6ad52591fb30784265b73`, and the hbb_common
submodule is `fae47e024dd83cef6aaecde0aa7d11731df11649`.

The capture adapter enumerates displays and exposes borrowed CPU frames or a native
texture handle. Input, codecs, session/security, loopback networking, provisional
strict WSS and a partial Node binding are described below. They are incomplete,
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
I420 input and packed CPU output. The implementation is experimental: it does
not yet offer H.264/H.265, hardware codecs,
packet-loss recovery, codec negotiation or resolution changes in-place. These
capabilities have not been removed from RustDesk; they have not yet been
adapted. The decoder must not be used with untrusted streams: packet size checks
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

`remote-input` wraps the source Enigo Windows backend and tracks held virtual
keys and mouse buttons per controller. Permissions default to denied; revocation
and `close()` attempt cleanup. Windows Enigo does not report all `SendInput`
failures, so a successful release is not proof that Windows accepted it. Drop
is best-effort and cannot handle process crash or power loss. This module is not
an authenticator or a sandbox. Only use it under an authenticated, authorized
session manager that serializes access to the OS input device; concurrent
controllers can otherwise interfere with each other's keys. Layout conversion,
scan-code modes, text/IME, repeat and monitor-relative mapping are not implemented.
Experimental mouse and unmodified legacy-control-key protocol translation covers
only a subset and is documented in `../docs/api/protocol.md`.

For an **interactive, disposable Windows desktop**, focus a test editor and run:

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
permission checks, and retryable resource shutdown. It does **not** implement
an authenticator, credential storage, owner approval UI, secure ID generation,
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
remain required. This integration has not yet been built or tested.

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
requires an encoder reset after failure or cancellation. This is not yet a
complete host or viewer; codec negotiation, renderer, authenticated transport,
reconnection, bounded native decoder allocations and live task cancellation
are not implemented. The receiver must not be exposed to untrusted peers. This
pipeline has not been built or tested.

`remote-rustdesk-websocket` is an experimental wrapper around the original
RustDesk WebSocket client, limited to literal loopback `ws://` addresses. It
is unauthenticated and accepts upstream plaintext text frames; it is not a WSS
adapter or a secure network transport. WSS remains blocked on isolation of the
source's global TLS/proxy configuration and a reviewed security design. This
adapter has not yet been built or tested.

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
one raw frame capture and independent software-frame encoding only. It is not a remote desktop SDK; see its README
for prerequisites, privacy constraints and limitations. It has not been built
or tested.

### Exporting a candidate independent source tree

`python3 remote-core/tools/export-source.py /path/to/new-directory` exports the
committed prototype, pinned RustDesk library paths, exact `hbb_common` submodule
commit, root license and an inherited lockfile into a new directory outside the
checkout. It does not modify the RustDesk source or initialize a Git repository.
The exporter uses Git objects, so uncommitted changes are excluded. It records
commits and archive hashes in `SOURCE_PROVENANCE.md`. The inherited lockfile is
only a resolution starting point: a locked independent build and license review
are still outstanding. The exported tree is experimental and untested.

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
