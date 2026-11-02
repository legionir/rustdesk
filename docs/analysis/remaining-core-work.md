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
  `windows_keyboard`, `windows_mouse`, `tracked_modifiers` and the Enigo adapter
  cover only documented subsets. The opt-in modifier policy is intentionally
  narrower than source behavior and requires compatibility and security review.
- `src/platform/windows.rs::get_cursor_data` and `src/platform/windows.cc` have
  an experimental shape adapter, not verified against color masks, animation,
  scaling, UAC, secure desktop or portable service. Source portable-service
  cursor/input paths are not extracted.
- `remote-core::capture_pump` is synchronous, caller driven, software-only and
  accepts BGRA/RGBA CPU frames. Capture tasks, hotplug/resize, zero-copy,
  reliable multi-monitor behavior, VRAM transport and source fallback policy
  are not completed. `hwcodec` RAM paths exist but are unbuilt and untested.
- `viewer_connection` demultiplexes a small set of existing protobuf variants;
  it does not render or negotiate codecs, request video refresh on recovery,
  support video ACK/QoS or handle all display/permission updates. Native video
  decoders are not hardened against hostile compressed streams.

## Security and transport

- `admitted_host` plus `source_crypto` optionally composes pre-auth admission,
  explicit pinned host identity and source-v1 split-key encryption. The code
  rejects legacy fallback, which is a deliberate compatibility/security policy
  difference requiring review. It does not implement rendezvous signature
  chains, secure pin lifecycle, 2FA/trusted devices, complete failure policy,
  a local owner-consent UI, or audited replay/DoS protection.
- `DirectTcp` can expose an unencrypted listener; secure composition is the
  application caller's responsibility. The strict WSS adapter validates relay
  TLS but has no server, authenticated routing headers, SSRF control or proven
  Cloudflare interoperability. Source encryption can wrap binary transports but
  the complete hosted relay setup has not been tested.
- `InputArbiter` coordinates only cooperating sessions in one process and is
  optional; it cannot exclude other processes, direct unguarded input paths or
  human input. Enigo does not report all Windows SendInput failures.

## Node, packaging and validation

- Node exposes local single-frame capture/encode, cursor wire conversion and a
  narrow pinned direct-TCP viewer with serialized operations. It has no host
  API, WSS binding, decoded video renderer, complete keyboard/input semantics,
  durable credentials or production-safe consent. Native decoder allocation is
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
