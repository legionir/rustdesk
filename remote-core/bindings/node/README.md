# Experimental Node-API capture binding

This is a partial binding, not a Node remote desktop SDK. It currently exposes
display enumeration, a single raw capture and single-frame software encoding
using RustDesk adapters. It does not expose input injection, a session, networking,
codec negotiation, secure transport or authentication. No binary is shipped.
The API and build have not been tested.

Install the same Rust/native dependencies needed by the Rust workspace, then:

```powershell
cd remote-core/bindings/node
npm run build
node -e "require('./').listDisplays().then(console.log).catch(console.error)"
```

`listDisplays()` and `captureDisplay(index, timeoutMs)` return promises and run
on a libuv worker, but a native backend may block beyond the timeout hint.
Only one capture operation runs at a time; concurrent operations are rejected.
Display indices are snapshots and may refer to different monitors after
hotplug; callers must not use them as stable identifiers. The copied frame is
limited to 64 MiB, but backend allocations, JS-held frames and libuv work queues
are not included in this limit. Frame bytes may include padding; inspect the
format and per-plane strides rather than assuming RGBA. `WouldBlock`, permission
errors, desktop changes and unsupported texture frames reject the promise.

Capture contains private screen data. Invoke only with the local user's
permission and avoid logging or transmitting frame buffers. This binding is not
an OS security boundary and has no trusted-consent UI. Use a disposable
interactive Windows desktop for manual verification.

`encodeFrame(data, options)` adds single-frame software VP8/VP9/AV1 encoding for
packed BGRA or RGBA input. It copies the JS input before returning, then
executes on a libuv worker; the 64 MiB copy may block the event loop briefly.
Only one encode can be outstanding; others are rejected until it finishes.
Each call uses a fresh encoder and represents a separate stream, not continuous
video, protocol framing or codec negotiation. The 16 MiB output check happens
after native encoding and does not bound native allocations or JS-held buffers.
There is deliberately no Node decoder for untrusted bitstreams. This API is
experimental and untested.

A real capture-to-VP9 example (captures the screen, but does not send or save
its contents) is available after building:

```powershell
node examples/capture-encode.cjs --confirm-capture
```

The native backend may return `WouldBlock`; the example has no retry loop.
`npm test` contains synthetic encoder cases and requires a built addon. Neither
example nor tests have been run. On Linux, set
`REMOTE_CORE_LINUX_PKG_CONFIG=1` before `npm run build` to enable the workspace's
pkg-config feature when native libraries are installed accordingly.

Experimental cursor utilities `encodeCursorShape`, `decodeCursorShape`,
`encodeCursorId` and `encodeCursorPosition` convert the existing RustDesk wire
messages. Shape conversions run on a worker, use a single shared concurrency
lease and copy inputs; they do not capture, render or transmit a cursor. IDs are
canonical decimal strings, since JS numbers cannot represent all RustDesk u64
IDs. The 1 MiB raw and 2 MiB serialized checks exclude native zstd allocations,
protobuf overhead, JS-held buffers and other callers. These additions and the
synthetic cursor cases have not been built, tested or security audited.
