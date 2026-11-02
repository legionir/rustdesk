# RemoteCore progress

> Current status: extraction is incomplete. The increments below are historical;
> later sections supersede earlier statements about features. The latest local
> code adds a caller-driven session-bound capture pump, cursor wire/cache APIs
> and Windows cursor-position sampling. These additions, along with all work
> after local transport CI run 41395071344, have not been built or tested. No
> secure host/viewer, peer-bound authorization, standalone verified build,
> complete Windows input/cursor shape support, or Node network/session API is
> available. No post-deferral CI has been run.

## Windows-first capture and codec increment

Commit `b869d83` adds a packed BGRA/RGBA-to-I420 bridge using the same libyuv calls as `libs/scrap/src/common/convert.rs`, with stride/buffer validation before calling native code. The existing software codec adapters provide VP8, VP9 and AV1. H.264/H.265 and hardware paths remain unadapted; none of RustDesk's existing functionality has been removed. Recreate the encoder when a display changes size; other pixel formats and capture-to-encoder zero-copy are not implemented.

[CI run 41345298622](https://github.com/legionir/rustdesk/actions/runs/41345298622) passed on the above commit. Windows Server 2022 executed workspace cargo check and tests, including synthetic software codec round trips and packed pixel conversion. Its real-display test was not enabled: GitHub-hosted Windows runners do not establish an interactive DXGI desktop in this workflow. Therefore Windows screen capture, multi-monitor behavior, permission handling and hotplug are **not validated**. Linux CI also passed an Xvfb capture → VP9 encode → decode integration test. These are not network, rendering, performance or security tests.

The workspace remains an adapter inside the RustDesk checkout, dependent on `scrap`, `base` and `hbb_common`; it is not yet independently distributable. The decoder is not safe to expose to untrusted peers: encoded payload length alone does not bound decoder allocations. Session, input, transport, authorization, Windows real-desktop testing and Node.js bindings are not implemented. No v0.1.0 acceptance gate is complete. Full source baseline and license/provenance review are still outstanding.

## Windows input increment

Commit `a72fbcb` introduces an experimental controller and Windows adapter over the RustDesk Enigo backend. Mouse and keyboard permissions default to denied and are checked independently. Held keys and buttons are tracked; revocation, explicit `close`, and best-effort drop attempt release. Fake-backend tests cover permission denial, revoke, idempotent close, release retry and drop cleanup. CI on [run 41371622106](https://github.com/legionir/rustdesk/actions/runs/41371622106) passed Linux and Windows workspace checks and tests; no input was injected on CI.

This is not RustDesk's complete input service: the adapter accepts Windows virtual-key codes, does not implement scan-code translation, text/IME, hotkey layout processing, key repeat, or monitor-relative mapping. The existing Enigo Windows methods do not return success/failure for release/move/scroll, so successful cleanup does not prove OS acceptance. The caller must provide authentication, owner consent, authorization and exclusive coordination across sessions. A crashed process cannot run cleanup; user-facing control must not rely solely on Drop. Actual Windows interactive-desktop, keyboard layout, UAC and multi-monitor tests remain outstanding.

## Bounded local transport increment

Commits `cf9abaa` and `c3180dd` add `remote-transport`, an object-safe async binary transport interface and an in-process Tokio channel implementation. Each direction bounds both message count and message size, reserves queue capacity before copying, applies deadlines, and handles cancellation and close. Limits exclude application-owned messages, allocator/channel overhead, and the receiver's already-dequeued messages; they are not a global process memory cap.

[CI run 41395071344](https://github.com/legionir/rustdesk/actions/runs/41395071344) passed Windows and Linux transport tests, workspace checks/tests, and the Linux Xvfb capture → VP9 encode → local byte transport → decode test. The integration test retains codec metadata in process; it is not a wire protocol or real host/viewer session. Real Windows capture remains untested in CI. Local transport has no authentication, encryption, heartbeat or reconnection. WebSocket/WSS, session orchestration, security audit and network tests remain outstanding; this increment does not make the project production-ready.

## Experimental Node binding and source export (not tested)

The `remote-core/bindings/node` crate exposes asynchronous Node-API display
enumeration and one-frame local capture, with a 64 MiB copied-frame limit and
one native capture at a time. It is not a remote desktop SDK and provides no
input, network, authentication, or trusted-consent UI. Native timeout behavior,
monitor hotplug identity, privacy and remaining memory risks are documented in
its README. Neither the addon nor its build script has been run.

`remote-core/tools/export-source.py` exports committed objects from the pinned
RustDesk baseline, the exact hbb_common submodule commit and the selected
prototype commit into a new directory, without altering the original checkout.
An experimental tree was materialized at `/home/user/remote-core`; it is not a
separate Git repository, release, license clearance, or independently verified
build. Its inherited upstream lockfile does not establish a locked build of
new prototype packages. Security transport, full RustDesk functionality,
Windows real-desktop tests, standalone builds and final debugging remain open.

## Loopback TCP and explicit network delivery contract (not tested)

The RustDesk adapter now wraps its source `FramedStream` for loopback-only TCP
client/listener use. A separate `NetworkTransport` interface records uncertain
send delivery, rather than weakening local-channel cancellation guarantees.
Experimental video sender/receiver methods use that interface. Security-adapter
unit cases and a synthetic VP9→RustDesk protobuf→loopback TCP→decode integration
case have been added but not built or run. The test's authentication occurs
in-process, not over the TCP socket. Neither TCP nor the existing loopback WS is
an authenticated/encrypted transport; the prototype is not safe to expose to
untrusted peers. Production WSS, peer binding, consent, a complete host/viewer
and secure bitstream handling remain open.

## Provisional Windows input dispatch (not tested)

`windows_mouse::dispatch` routes absolute and bounded relative motion, five
mouse buttons and ordinary wheel events through the session guard. Modifier
lists, trackpad, touch and other event forms are explicitly unsupported. A
separate `windows_keyboard::dispatch` covers only unmodified legacy control
keys; it does not translate text, scan codes or modifiers, sync OS state or
support Windows portable-service desktop switching. The gate for mouse is an
independent `control_mouse` permission, unlike RustDesk's shared
`peer_keyboard_enabled()` gate; that decision remains subject to review. Both
have fake-backend tests, written but not run, and neither demonstrates actual
Windows input. There is still no input arbitration across sessions or secure
network-to-session binding. These APIs must not be exposed to untrusted peers.

## Strict WSS, arbitration, Node encode and feature forwarding (not tested)

A provisional strict WSS client uses the pinned RustDesk WebSocket fork and an
isolated Rustls configuration; certificate failure and binary-frame cases are
written with disposable local test certificates but not run. TLS terminates at
the WSS endpoint and does not authenticate an end desktop peer or protect the
payload from the relay. Cloudflare interoperability is not established.

Optional in-process input arbitration keeps one cooperating controller and
quarantines detectable cleanup failures; it can be bypassed by unguarded input
paths and is not an OS lock. The Node addon now includes a single-frame software
encoder and a capture-to-encode example, plus unrun synthetic tests. The source
`wayland`, `drm`, `hwcodec`, `vram` and `mediacodec` feature flags are forwarded,
but the feature-specific public integrations, native builds and tests remain
incomplete. No new build, test or CI was run.

A provisional `hwcodec`-gated adapter now uses RustDesk's cached H.264/H.265
RAM encoder and accepts validated NV12 or BGRA/RGBA input. Source encoder init
can change process-global codec state; source discovery/cache and driver/FFmpeg
prerequisites remain. The adapter does not implement negotiation, hardware
decode or VRAM texture encoding. Its layout and opt-in real-GPU tests are
written but not run, and no hardware availability or safety is claimed.

The opt-in source features preserve prerequisite relationships (`drm` enables
`wayland`; `vram` enables `hwcodec`). `mediacodec` follows an Android-specific
source path and is not a promise of desktop compilation. Feature combinations
remain unbuilt and require real native-dependency and platform verification.

## Caller-driven capture and cursor increment (not tested)

`CapturePump` ties an authorized session ID, exact display handle and software
encoder together; it checks permissions before capture and sends one frame per
caller invocation over the existing local or network interface. It performs
blocking native work and does not create a server, authenticate a peer, or
automatically clean up the session when dropped. Hotplug, cancellation,
concurrency, real desktop and resource behavior remain to be tested.

`remote-protocol::cursor` implements the source cursor data, ID, position and
request messages, with source-compatible zstd limits and a bounded decoded
shape LRU. Windows current-desktop cursor position/visibility sampling is
available separately, but source portable-service capture and actual cursor
shapes are not extracted. A temporary Windows handle is not the upstream
content-derived ID. Node cannot yet consume cursor events. All of this is
unbuilt, untested, and not security audited.

## Current host/viewer, cursor and Node extraction (not tested)

This increment adds an explicit opt-in direct framed TCP adapter, source-v1
signed key exchange with a caller-provided host signing-key pin, an encrypted
transport wrapper, and caller-driven host/viewer password, authorization and
message flows. Version 0/plaintext fallback is rejected by this new wrapper,
a deliberate policy change requiring security review. This does not implement
rendezvous trust, key provisioning, 2FA, complete peer compatibility or an
audited internet-facing server. Synthetic host/viewer and tamper cases have
been written but not run.

Windows cursor shape capture and bounded BMP legacy text input were adapted
from source paths; UAC/portable service, complete keyboard/IME, permissions and
real input/cursor behavior remain unverified. The Node addon now exposes
cursor-wire utilities and a narrow pinned direct-TCP viewer with compressed
video events and mouse sends; it is not a complete SDK. All additions since
local-transport CI remain unbuilt, untested and unaudited. No CI was triggered.
