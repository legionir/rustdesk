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
