# RemoteCore — capture extraction prototype

This is an **experimental first adapter**, not a standalone RemoteCore release.
It uses the RustDesk checkout's `libs/scrap`, `base`, and `hbb_common` by path;
those crates also bring native libraries and other dependencies. The source
commit is `23e5bb471a040d62f0a6ad52591fb30784265b73`, and the hbb_common
submodule is `fae47e024dd83cef6aaecde0aa7d11731df11649`.

The adapter enumerates displays and exposes borrowed CPU frames or a native
texture handle. It does not implement streaming, input, authentication, codec
abstraction, a Node.js binding, or a complete multi-platform support contract.
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
does not yet offer H.264/H.265, hardware codecs,
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
scan-code modes, text/IME, repeat, monitor-relative mapping, and RustDesk
protocol translation are not implemented.

For an **interactive, disposable Windows desktop**, focus a test editor and run:

```powershell
cargo run --manifest-path remote-core/Cargo.toml -p remote-input --example windows_input -- --confirm-inject-input
```

This deliberately injects the A key into the focused window. Never run it on a
production desktop. CI uses a fake input backend and does not inject keys.
