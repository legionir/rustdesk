# Experimental Node-API capture binding

This is a partial binding, not a Node remote desktop SDK. It currently exposes
display enumeration, a single raw capture and single-frame software encoding
using RustDesk adapters. It also has an experimental, limited direct-TCP viewer
with pinned source key exchange and basic password login. It does not expose a
host server, trusted consent, codec negotiation, decoded video rendering or a
complete input API. No binary is shipped. The API and build have not been tested
or security-audited.

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

## Experimental direct TCP viewer

`connectViewer(options)` connects to a literal IP:port, checks a caller-supplied
32-byte host signing-key pin and host ID, runs the source version-1 split-key
exchange and the basic password/login flow, then returns a `Viewer`. The host
requires an independently configured owner policy. The caller must securely
obtain and rotate the pin and ensure the remote end is trusted. This code is
not audited; no rendezvous trust chain, WSS Node binding, TLS, 2FA, complete
RustDesk compatibility, rate limiting or replay audit is provided. Do not use
it with untrusted peers.

`peerInfo()` returns a login snapshot; `sendMouse()` sends a limited wire event;
`receive()` returns one event (video remains compressed in a RustDesk envelope).
`sendControlKey`, `sendText` and `sendMouseWithModifiers` construct source
legacy wire events, but the host may reject them; its tracked-modifier mode is
opt-in and its text support is restricted. Control-key numbers are RustDesk
schema values, not Windows virtual-key codes. There is no video decoder or
renderer yet. A viewer permits only
one active operation at a time; therefore a long receive blocks input sends and
a receive timeout closes the connection. Close explicitly when idle. At most
eight viewer objects/tasks are retained by this addon, including explicitly
closed objects until garbage collection. Other Node buffers, queued libuv tasks,
native allocations and process resources are not bounded by this count. Password
strings remain in JS memory and may have additional copies; do not log them.
None of these APIs or their security guarantees has been built or tested.

`examples/pinned-viewer.cjs` demonstrates a manually confirmed connection to a
trusted test peer using a raw 32-byte public-key file. It prints only event
kind and length and does not decode or save screen data. The example requires a
password in an environment variable for convenience; that is **not** secure
credential storage. It has not been run. Do not use it for production access.
