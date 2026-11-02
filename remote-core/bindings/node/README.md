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

The viewer's `requestRefreshAll`, `requestRefreshDisplay`, and
`notifyVideoReceived` send existing RustDesk video-control messages. They do
not perform decoding, schedule recovery or guarantee peer behavior. The caller
must coordinate them with `receive`; operations cannot overlap. These methods
have not been built or tested.

### Experimental loopback-only view host

`listenLocalHost` binds **only 127.0.0.1**, generates a temporary signing key,
accepts one pending connection and exposes its unverified claims. The embedding
application must obtain an independent local owner's explicit decision before
calling `approveView(true, ...)`, or close/reject the session. Approval grants
screen viewing only. An always-denying backend prevents OS input even if an
input message is received. The password and ephemeral key must not be logged;
JS strings and process memory can retain sensitive copies. A loopback address
is not proof that another local process is trusted. There is no trusted consent
UI, controller authentication, production key provisioning, brute-force
policy or security audit. An experimental timer closes an abandoned pending
session at the original accept deadline; approval also checks expiration.
Explicit close is still required, and timer/cancellation behavior is untested.

After approval, `sendOneVp9Frame` explicitly opts into a single software VP9
capture/send, opens a fresh capture handle and encoder, and stops them after the
call. The application must know the viewer supports VP9, limit calls, manage
capture timeouts and explicitly close both the session and listener. The addon
checks current display metadata against the approval snapshot, but hotplug,
desktop switching or an identical replacement can still defeat that check.
Capture can reveal private screen content. No continuous stream, input API,
server event loop, WSS listener, multi-controller support or hardened native
decoder is supplied. Calls on a handle cannot overlap; close cannot interrupt
an in-flight call. Native capture may block longer than its requested timeout.
All of this is **unbuilt and untested**.

`examples/local-host-viewer.cjs` is a manual demonstration that requires
explicit confirmation and an interactive desktop. It is not an automated test
or production reference.

`viewer.advertiseDecoding` sends explicit external decoder claims; the addon
does not provide or probe a network decoder. The local host's `receiveEvent`
can return these claims, refresh requests and frame-received notifications to
the caller. They are untrusted, not acted on automatically, and must be
validated/rate-limited. Calls are serialized, so receiving cannot overlap a
capture/send on the same host session. A receive timeout closes the session.

`connectWssViewer` uses strict certificate-validated WSS plus the separate
pinned source host exchange, and returns the same serialized viewer API. The
configured WSS endpoint can target arbitrary network hosts: **SSRF filtering is
not implemented**. Credentials, query strings, fragments, proxies and custom
root stores are not supported. This does not provide a WSS server, configure or
authenticate a relay route, or verify Cloudflare compatibility. TLS validates
the WSS endpoint; the separately pinned exchange is intended to identify the
host behind it. This code and its validation cases have not been built or run.

A Windows host may explicitly call `sampleWindowsCursor` after view approval,
and the viewer may request a previously sent shape with `requestCursorShape`.
Host requests are surfaced as events; the application may explicitly call
`resendCursorShape` and must rate-limit requests. Shape caching is bounded but
content IDs can collide, cache entries can be evicted, and hidden cursor,
UAC/secure desktop, animation and portable-service behavior remain incomplete.
These methods and native Win32 sampling are unbuilt and untested.
