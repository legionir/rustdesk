# Experimental Node-API capture binding

This is a partial binding, not a Node remote desktop SDK. It currently exposes
display enumeration, a single raw capture and single-frame software encoding
using RustDesk adapters. It also has limited pinned TCP/WSS viewers and an
experimental view-only host with single-frame and bounded burst sends; the default
listener is loopback-only and a separate restricted network opt-in exists. It does not provide a
general host server, trusted consent, automatic codec negotiation, network
video rendering or a complete input API. An explicit trusted-only local batch
decoder is available but is not safe for untrusted compressed streams. No binary is shipped. The API and build have not been tested
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
The Node trusted-only decoder described below is not safe for untrusted bitstreams. This API is
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

**Windows input safety gate:** static review found a potential out-of-bounds
error-formatting path in the pinned Enigo Windows backend when mouse/key
`SendInput` fails. The experimental local host is view-only, but viewer input
messages can affect a separate remote host whose implementation and safety are
outside this binding. Do not enable or exercise Windows input until the gate in
`../../../docs/analysis/windows-enigo-error-gate.md` is resolved and reviewed.

`connectViewer(options)` connects to a literal IP:port, checks a caller-supplied
32-byte host signing-key pin and host ID, runs the source version-1 split-key
exchange and the basic password/login flow, then returns a `Viewer`. The host
requires an independently configured owner policy. The caller must securely
obtain and rotate the pin and ensure the remote end is trusted. This code is
not audited; this direct TCP path has no rendezvous trust chain, TLS, host-side
2FA enforcement, complete RustDesk compatibility, rate limiting or replay audit. A separate WSS
viewer is described below. Do not use
it with untrusted peers.

`peerInfo()` returns a login snapshot; `sendMouse()` sends a limited wire event;
`receive()` returns one event (video remains compressed in a RustDesk envelope).
`sendControlKey`, `sendText` and `sendMouseWithModifiers` construct source
legacy wire events, but the host may reject them; its tracked-modifier mode is
opt-in and its text support is restricted. Control-key numbers are RustDesk
schema values, not Windows virtual-key codes. There is no network-safe decoder, renderer or automatic decoding. A viewer permits only
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
Capture can reveal private screen content. There is no autonomous continuous
stream, input API, server event loop, WSS listener, multi-controller support or
hardened native decoder. Short caller-driven bursts are available separately.
Calls on a handle cannot overlap; `close()` cannot interrupt an in-flight call,
and the cooperative `requestClose()` cannot interrupt native capture/encoding.
Native work may block longer than its requested timeout.
All of this is **unbuilt and untested**.

`examples/local-host-viewer.cjs` is a manual demonstration that requires
`--confirm-local-screen-capture` and an authorized interactive desktop. An
additional `--decode-trusted-local-frame` opts into native decoding of only the
frame generated by that same local process; neither flag supplies real consent,
a renderer or security isolation. It is not an automated test or production
reference, and has not been run.

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

`sendWindowsScanCode` constructs a restricted source Map-mode event. It does
not grant input or establish peer platform compatibility. The experimental
loopback host is view-only and will reject input; a separate trusted host must
explicitly enable scan-mode dispatch. Windows scan-code behavior, cleanup and
Node bindings have not been built or tested.

For the experimental loopback host, the pre-authorization accept deadline also
bounds owner approval and its initial response. Display enumeration is blocking;
the approval worker rechecks expiry afterward, even if the expiration timer was
waiting on the same session mutex. This behavior is untested, and it does not
turn caller-provided approval into a trusted OS consent prompt.

### Bounded local VP9 burst (experimental)

After view approval, `sendVp9Burst(displayIndex, confirmViewerVp9, fps,
maxFrames, maxDurationMs, captureTimeoutMs, sendTimeoutMs)` sends up to 120
frames over a single software VP9 encoder at up to 30 FPS and for at most five
seconds of scheduled work. It returns the number actually sent; unchanged
screen capture may produce `WouldBlock` instead. Each burst creates a new stream
and encoder, so the viewer must handle stream/keyframe changes. It checks the
approved display metadata on every attempt, but that does not establish stable
monitor identity. This is view-only, not continuous production
streaming, codec negotiation or a trusted consent UI.

`requestStopBurst()` sets a cooperative stop flag without waiting for the host
lock. Await the burst before closing the session. It cannot interrupt a native
capture, encoder, display enumeration or in-flight send; native calls may
exceed their timeout hints, so the duration is not a hard privacy deadline. The
burst occupies a libuv worker and excludes all other operations on this host
session. The viewer must read messages concurrently; `Viewer.receive()` and
input/control operations are themselves mutually exclusive. No test, build,
performance, privacy or interoperability validation has been performed.

### Trusted-input-only video batch decoding

`decodeTrustedVideoBatch(messages, true)` optionally decodes up to 32 ordered
existing source VP8/VP9/AV1 envelopes in one fresh software decoder on a worker.
The first message must be flagged as a keyframe and the display/codec must remain
unchanged. It returns packed source-libyuv ARGB buffers with width, height and
stride; byte order is not promised to match HTML canvas RGBA. The caller handles
rendering, ACKs and decoder recreation across batches.

**Do not feed untrusted network bitstreams to this function.** The boolean is an
explicit acknowledgement, not a security check. Input (16 MiB) and copied-output
(64 MiB) limits are checked around native calls but do not limit codec allocation,
CPU or vulnerabilities while decoding. Use only authenticated, independently
trusted local test data in an isolated environment; the decoder and API have not
been built, tested, hardened or audited. At most one such task runs concurrently.

### Experimental display control

The viewer can request a display switch, request subscription lists, query
metadata, and explicitly confirm a remote resolution-change request. These
messages may affect another machine when handled by a RustDesk-compatible
peer; the peer must independently authorize them. The local loopback host is
view-only and does not implement switching or resolution changes. The source
`sub` subscription list retains listed existing streams rather than subtracting
them, and an empty set can unsubscribe all streams. Display indices may change
on hotplug. `displayChanged` and `followCurrentDisplay` events are untrusted
peer claims; `displayChanged.data` retains the original bounded protobuf.
The methods and types have not been built or tested.

The viewer can send a source touch-scale value with `sendTouchScale`, where zero
ends the gesture. A Windows host must independently opt in and grant both mouse
and keyboard control. The Node loopback host intentionally has no input backend.
The scale path is not verified on a real desktop and does not provide consent or
exclusive OS input ownership.

### Restricted network host (experimental, not for public networks)

`listenNetworkHost` binds an explicitly supplied literal address and port and
accepts only one explicitly supplied socket-observed peer IP. The call requires
`acknowledgeNetworkExposure: true`. IP allowlisting is not authentication: NAT,
proxies and hosts on the same network can invalidate the assumption. This is
view-only, shares the one-listener/one-session caps, and returns the same
`LocalHostSession` type as the loopback listener. Owner approval, password
strength and trusted delivery of the ephemeral host public key remain external.
There is no password failure rate limiting, durable key provisioning, trusted
consent UI, hardened decoder, production session loop, or security review. Do not
expose it to an untrusted or public network. The listener can receive attempts
before approval; a malicious peer can consume its capacity or probe passwords.
The address/pin returned by `address()`/`signingPublicKey()` are not proof of a
remote identity and must be provided over a trusted channel. The new network
path has not been built or tested.

The experimental viewer can call `sendVideoPreferences(imageQuality, fps,
timeoutMs)`. Quality is 0 (unchanged), 2 (low), 3 (balanced), 4 (best), or a
positive source-packed custom value; FPS is 0 (unchanged) or 1–120. The host
may read untrusted login preferences once after approval with
`takeInitialVideoPreferences()` and receive `videoPreferences` events. These
values do not automatically configure a capture, encoder, or scheduler.
Event `data` is an untrusted raw post-login option and may include other fields;
do not apply it indiscriminately. This path has not been built or tested.

The optional `enableDuplexReadAhead(true)` and `tryReceive` /
`tryReceiveEvent` methods use an experimental direct-TCP-only read-ahead queue
after approval/login. They do not allow concurrent Node session operations:
frame capture/sending and input dispatch remain serialized, and long native
calls can block progress. Empty polls do not cancel the socket; failed sends,
receive timeouts, closure or dropping a half close both sides asynchronously.
WSS is not supported. This is unaudited, unbuilt and untested; it is not safe
for production, untrusted networks or hostile video bitstreams.

## Read-only Windows modes and source preferences

`inspectWindowsDisplayModes(index, true)` performs a read-only, bounded mode
query after application-supplied local consent; it never changes resolution.
Indices/names and snapshots can become stale, enumeration can be incomplete,
and the boolean is not a trusted consent UI. `examples/windows-display-modes.cjs`
requires an explicit confirmation argument. This code is unbuilt and untested.

The viewer can opt into `videoAckRequired`, send source cursor/follow and
input-disable preferences, and receive encoding claims. These are untrusted
requests/claims and never grant local permissions or trigger rendering. An
ACK-required session must be paced by the application; serialized VP9 bursts
reject it because they cannot service ACKs concurrently. The host can inspect
initial preferences after approval and receive request events, but does not
apply them automatically. Cursor/keyboard policy and cleanup remain incomplete.

After the addon is built and the owner explicitly approves disclosing display
mode metadata, the read-only example can be invoked on a disposable interactive
Windows desktop as follows (this command has not been run):

```powershell
node examples/windows-display-modes.cjs --confirm-local-display-inspection
```

The separate Rust example is `windows_display_modes`; both examples can fail on
locked desktops or topology changes. They do not apply a requested resolution
or implement restoration. Mode enumeration failure is not proof that no modes
exist, and a non-truncated result is not proof that Windows returned every mode.

### Optional host inactivity accounting (unverified)

After view approval, `LocalHostSession.enableIdleTimeout(minutes)` configures a
caller-driven timeout. The application must call `pollIdleTimeout()` regularly
and arrange capture/operation cleanup; no timer or wire close notification is
started. `idleRemainingMs()` is advisory, and long native or network operations
can delay polling. Input and some refresh messages reset it; peer activity can
keep it alive. It is not liveness, trusted consent, or security enforcement.
Node integration and real-desktop behavior have not been built or tested.

A separate opt-in `enableReceiveWatchdog()` tracks time since the last frame
processed by the host; `pollReceiveWatchdog()` must be called explicitly. It
uses 30 seconds and sends no probes. With read-ahead, frame arrival and dequeue
times differ, so delayed servicing can cause premature or delayed closure. It
is not peer authentication, a security timeout, or an autonomous background
service. The Node API and its tests have not been built or run.

### Explicit Windows foreground hint (unverified)

After view approval, `sendWindowsFocusHint(true, true, timeoutMs)` can inspect
the foreground window and send a display hint only when the tracked focus
changes. Both booleans are application assertions, not an actual consent UI
or proof that the viewer requested following. Call only after independently
obtaining informed local consent, enforce policy and rate limits, and reset via
`resetWindowFocus()` after preference or topology changes. There is no automatic
tracking, capture switch or title/process disclosure. Foreground geometry itself
is sensitive; the double topology check is not atomic, and Windows DPI/UAC/
secure-desktop and error cleanup are unverified. Unsupported on non-Windows.

`sendWindowsCursorFollowHint(currentDisplay, multiUiSession, true, true, timeoutMs)`
likewise samples the local Windows cursor and may send an advisory display
index. The current display and multi-UI state are caller claims, not peer
identity. The same separate consent, follow policy, rate limit, topology and
DPI caveats apply. Neither API switches capture or starts a background task.

The Windows-only `setWindowsScanModeEnabled`, `setWindowsTranslateModeEnabled`
and `setWindowsKeyRepeatEnabled` are opt-in restricted input subsets. The Node
host is currently view-only, so these toggles do not grant keyboard permission or
make keyboard injection available. Enabling
requires the caller to assert local consent and own/rate-limit OS input; this
assertion is not a consent mechanism. Modes cannot change with tracked keys
held, and repeat cannot coexist with tracked-modifier mode. The backend may not
report all OS injection failures. They are not full source desktop switching,
layout translation, modifier synchronization, or a repeat timer, and have not
been tested on Windows. Disabling does not synthesize key-up; release/revoke or
close first.

### Caller-driven viewer FPS decisions (experimental)

`createViewerFpsController()` creates per-caller, bounded bookkeeping derived
from the pinned RustDesk viewer. `setDisplays` supplies locally tracked volatile
indices; `tick(direct, customFps, samples)` returns optional `customFps` and
`refresh` requests based on caller-provided local decoder FPS and queue samples.
It measures nothing, schedules nothing, and is not tied to a `Viewer`. Recreate
or reset it on reconnect, topology/identity changes, cancelled operations or
uncertain sends; coordinate manual FPS changes separately. A returned decision
advances bookkeeping even if the caller elects not to send it.

After locally reviewing the decision and peer compatibility, an application may
call `viewer.dispatchFpsDecision(decision, perDisplayRefresh, timeoutMs)`. This
uses the existing source preference and refresh messages, not a new protocol;
`false` selects legacy refresh-all for each requested display. It returns the
number of locally completed sends, not proof that a peer received, decoded or
rendered anything. On batch failure the Node viewer is closed; reset its FPS
controller and do not retry ambiguous delivery. The feature does not harden
native decoding or make untrusted compressed video safe. It is unbuilt and all
Node tests are deferred.

`createViewerDecodeFps()` supplies separate per-display measurement
bookkeeping. Call `record(formatChanged, elapsedMicros)` only for a locally
measured successfully displayed frame. The source skips three warm-up frames,
updates every ten measured frames and clears its accumulated window at thirty.
As in source, a format change retains the previous estimate until a new one is
computed; call `reset()` when stale data is unsuitable. Duration is locally
bounded to 60 seconds and reported FPS to 1000, unlike the source. The meter
neither times a decoder nor proves rendering; its tests are written but unrun.

### Persistent trusted video worker and bounded local queue

`createTrustedVideoWorker(maxInputBytes, maxOutputBytes, true)` starts an
independent dedicated native-decoder thread. Register a locally selected display
and `vp8`, `vp9` or `av1`, then feed ordered, **locally produced trusted** video
envelopes using `decode`. Results can be `awaitKeyframe`, `noImage` or `image`;
image bytes are packed libyuv ARGB in the source byte convention, not a canvas
RGBA promise. `reset` and `remove` are explicit. The worker owns the decoder on
one thread because the source texture state contains a raw pointer. Errors after
a decode reaches the thread terminate the worker. Length/overlap errors rejected
before dispatch do not close it: if a frame was lost, stop delivery and close and
recreate the worker after outstanding operations finish. In either case request
a new keyframe separately and never retry uncertain decoder state. Waiting for
a native result occupies a Node/libuv task thread as well as the decoder thread.
A hung native call cannot be interrupted;
`close` is rejected while an operation is in flight and does not synchronously
join the worker. The process-local cap is two workers, each with up to eight
streams; slots are released when the thread exits, not merely when `close` is
called. This does not count separate batch decoders, native allocations, JS
buffers, other processes or GPU memory.

`createViewerVideoQueue(display, codec, maxFrames, maxBytes, maxMessageBytes)`
is an independent bounded compressed-buffer queue, not attached to a Viewer or
decoder. `push` copies and parses on a worker; only one operation may be active.
`keyframe` requires the caller to coordinate decoder reset. `needRefresh` means
queued data was dropped and the application must decide whether to request a
new keyframe. **Any push error, including invalid length, parse failure or a
rejected overlapping call, leaves the queue unchanged**: stop delivery, wait
for any active operation, reset the queue and actual decoder, and request a
keyframe. If reset fails, discard the queue. Silently dropping such an input can
break predictive decoding. `pop` transfers a ticket and buffer to JS; check `isCurrent`
before rendering and `complete` exactly once. Reset invalidates in-flight
results but does not interrupt decoding or reclaim JS-held buffers. Generation
checks are not atomic with external rendering. Unlike source's force-push and
unbounded keyframe channel, this conservative queue drops backlog and rejects
predictive frames until a first-packet keyframe hint. Key flags are untrusted.
Both features are unbuilt, untested and **not safe for untrusted bitstreams**;
input/frame caps do not bound allocations or vulnerabilities inside codecs.

### Cursor selection helper

`createViewerCursor(maxItems, maxBytes)` is a caller-driven per-peer cache for
already decoded RGBA cursor events. For an ordinary `cursorShape` event, pass
its metadata and `data` to `observeShape(..., true)`; for `cursorId`, call
`select(id)` and inspect its boolean result. A cache miss does not imply a
hidden cursor. A supporting peer may answer `viewer.requestCursorShape(id, ...)`,
but requests, rate limiting and retries are entirely application policy. A
resend response has no request correlation and may arrive after a new cursor
selection: decide whether to store without selecting, and do not infer freshness
from its ID. Storing a delayed response can replace cached pixels even when the
ID is currently selected and `select` is false; discard ambiguous responses if
that matters to the application's policy. Track `cursorPosition` with `observePosition`. The helper does not
render, handle visibility, old-peer content dedupe or embedded cursor policy.
Use a separate instance per connection and `clear` on reconnect. Copies handed
to JavaScript, allocator overhead and decompression allocations are outside its
byte cap. On a rejected shape, prior selection remains; the caller must avoid
drawing stale state or clear it. This API and its tests have not been run.

`ViewerFpsController`'s `receivedFps` is a historical API name: the pinned
source counts decoded frames at the UI callback and divides by the actual status
timer interval, rather than counting network arrivals or confirmed renders. The
application supplies this measurement. On a manually queued positive FPS
preference or peer-info reset, call `noteManualFpsUpdate` in serialized order to
forget the previous automatic decision while retaining refresh/inactivity state.
This only updates local bookkeeping and never proves that a preference arrived.
`createViewerFrameRate()` can count caller-observed UI callbacks and calculate
this source-style sample using the actual elapsed milliseconds. The caller must
use a common interval across displays. Sampling below one second retains counts;
accepted samples reset them. Counts/intervals and reported rate have finite caps;
this meter cannot prove drawing, time itself, or automatically drive the FPS
controller. This helper is unbuilt and untested.

The test script uses Node's built-in test runner (`node --test`), which Node's
16.20.2 CLI documentation says was added in 16.17.0. The declared runtime range
is not an assurance that every Node 16 release can run the tests; the deferred
workflow currently targets Node 20. Neither runtime compatibility range has
been validated for this addon.

A view-approved `LocalHostSession` can explicitly send `sendDelayProbe` with
locally supplied last-delay and bitrate values. The caller must limit to one
outstanding probe, measure elapsed monotonic time, service `receiveEvent` and
apply any QoS policy separately. A host-origin reply still has event kind
`heartbeat` for compatibility but includes `probeTime` (decimal i64 string),
`probeLastDelay` and `probeTargetBitrate`; ordinary client-origin heartbeats do
not include them. Fields are untrusted and matching them is not authentication:
the source probe has no nonce and can be replayed/forged. No timer, QoS state,
rate limiting or rendering guarantee is provided. Close the session on a failed
or cancelled send rather than retrying uncertain delivery. View approval is a
caller assertion, not proof of consent. This binding has not been built/tested.
On the viewer, `testDelay` events also expose `probeTime`, `probeFromClient`,
`probeLastDelay`, and `probeTargetBitrate` as untrusted wire values. Host-origin
probes are echoed by the underlying viewer before the event is returned; that
send can fail and close the connection. This is not a verified speed test or
proof that the remote desktop host is authentic.

### Explicit viewer second-factor response (experimental)

An optional `twoFactorCode` may be supplied to either connect function only with
`acknowledgeTwoFactorDisclosure: true`. It must be 6–8 ASCII digits. The viewer
sends it at most once, only after the exact source prompt; it fails if the host
accepts without prompting. This can be combined with `videoAckRequired`. There
is no interactive prompt, retry, trusted-device enrollment or host-side 2FA. The
peer can lie about verification or relay the code. Pin provisioning and local
consent remain the caller's responsibility. JavaScript and N-API retain copies
outside Rust zeroization; never log options. A pre-obtained TOTP may expire while
waiting for approval. The new flow and Node fixtures have not been built/tested.

## Two-system diagnostic (not run)

A view-only, bounded-envelope manual LAN diagnostic and explicit safety/setup
limits are described in [`../../docs/two-system-diagnostic.md`](../../docs/two-system-diagnostic.md).
It has not been built or run. It cannot render or control the remote desktop,
and is not suitable for untrusted networks or production use.

### Experimental Windows cursor announcements

After view approval, `enableCursorAnnouncements(true)` explicitly selects a
bounded per-session cursor book. `sampleWindowsCursorAnnouncement(forceShape,
timeoutMs)` samples and sends either full cursor data or a source cursor ID,
then position. `resendCursorShape(id, timeoutMs)` uses the selected book for
an explicitly handled peer request. A peer can evict a shape or fail to decode
it; a successful send proves neither receipt nor rendering. The application
must process misses, revalidate disclosure/consent, rate-limit sampling and
close/recreate the session on cache exhaustion or uncertain sends. This mode
cannot be mixed with `sampleWindowsCursor`'s always-shape cache within the same
session. It has no background service, cursor hide event, trusted consent UI,
portable-service desktop handling, or stable Windows handle identity. The
Windows path and Node fixtures have not been built or run.

### Experimental ACK-paced VP9 burst

For a peer that requested video ACKs, the caller may first enable explicit
duplex read-ahead, then opt into `sendVp9AckBurst`. It reuses one encoder for a
bounded, caller-driven burst, polls the receive queue and waits for a source
`VideoReceived` claim after each sent frame. The peer must receive concurrently
and call `notifyVideoReceived` under its own policy. VPX no-output does not
create an ACK wait. The source ACK has no frame ID, can be stale or forged, and
cannot prove decode or rendering. This feature is not a production streaming
service or decoder negotiation. It must not be mixed with other in-flight frame
producers; caller coordinates keyframe/decoder resets between bursts.

A non-ACK control event before a send stops the burst and is returned to the
caller; the host's normal dispatcher may already echo heartbeats before the
caller sees them. An event while an ACK is outstanding stops and closes the session so
that an uncertain ACK is not silently reused. ACK timeout, stop with an ACK
outstanding, unexpected ACK, transport error or topology change during capture
also closes the connection. A topology error detected before capture rejects the
request; callers should close and obtain fresh approval before retrying. The application must still call `session.close()` to release
the Node host's session slot and retry any detectable cleanup. Native
capture/encode and synchronous display enumeration cannot be interrupted and can exceed the requested time bounds. No independent trusted
consent, topology identity, rate limit, or untrusted-codec safety is supplied.
This API and its single-frame local fixture are unbuilt and unrun.

### Viewer cooperative close request (experimental)

`viewer.requestClose()` requests terminal closure even while one serialized
viewer operation is running. The worker races network futures against the
request and closes the viewer instead of reusing an indeterminate connection.
It does not prove a send was delivered or cancelled, interrupt synchronous
native work, cancel a connection attempt before a viewer handle exists, or
release the process-local viewer-capacity lease while the JS handle remains
reachable. Completion can race the request; do not retry ambiguous operations.
The existing `close()` still rejects overlap. Node and Rust fixtures for this
path are written but not built or run.

`LocalHostSession.requestClose()` similarly makes a terminal host close request,
sets the burst stop flag and races active network operations against the request.
It cannot interrupt synchronous screen enumeration, capture or codec calls and
may run synchronous cleanup when the session is idle. An operation completing
at the same time as the request may have delivered data or even login success;
the connection must never be reused or a send blindly retried. If the state
mutex is contended or poisoned the request can return an error even though its
sticky signal was recorded; await active work and retry explicit `close()`.
`requestClose` does **not** release the host session lease: explicit `close()`
remains required after the task completes, including on errors. It does not
cancel an outstanding listener accept or connection attempt by itself. It is not a trusted
consent UI or proof of timely capture termination. Code and fixtures are unrun.

`LocalHost.requestClose()` and `NetworkHost.requestClose()` request terminal
closure of that listener and cancel a pending accept, including the handshake
and login candidate. An accepted result racing the request may be discarded
before JS receives it. Existing sessions already delivered to JS are independent
and must be closed separately. Await the pending accept before `close()`; the
listener lease remains reserved until explicit close. As with session requests,
a contended or poisoned state can report an error after the sticky signal was
recorded. This does not cancel a viewer connection attempt, interrupt synchronous
native code, guarantee peer non-delivery, or establish a security boundary.
Code and fixtures are unrun.

`Viewer.sendCloseReason(reason, timeoutMs)` and the approved host session's
`sendCloseReason` send at most one source `Misc.CloseReason` (local limit 512
UTF-8 bytes), then close locally. The reason is disclosed to the peer and may
persist in JavaScript, protobuf or transport copies; do not put secrets in it.
A failed/cancelled send has indeterminate delivery and must not be retried;
success is not an acknowledgement. A concurrent `requestClose()` may cancel
the notification. Host callers must still call `close()` to release the lease.
Incoming close reasons are untrusted and current Node errors deliberately do
not expose their text. Code and fixtures are unrun.

`viewer.windowsSessions()` returns optional peer-provided Windows session names
and IDs from login or the latest PeerInfo update. Absent and invalid metadata
both appear as null/undefined. Values may be sensitive, stale or malicious; they
are not OS enumeration, identity or authorization. This Node prototype does not
switch Windows sessions. The Rust-only explicit selection wire API can trigger
real remote host behavior and requires separate consent/policy review. Unrun.

The approval-expiration timer uses the session busy gate. If a close request is
already recorded, the timer leaves the slot reserved for explicit `close()`;
a timeout that has already completed its cleanup may win a concurrent race.
A detectable timer cleanup failure also retains the session for retry. Drop and
process termination remain best effort and cannot report cleanup failure. Unrun.

When a terminal close request is observed before Promise resolution, queued
viewer/host event and viewer metadata results are discarded instead of handed
newly to JavaScript. This is best effort: data already returned to JS remains
there, dispatch or heartbeat side effects may already have occurred, and dropping
buffers is not a guarantee of memory wiping. Delivery and native timing remain
uncertain. Unrun.

If a terminal close is observed before resolution, ordinary pending host/viewer
send, capture and approval Promises reject even if native work or a wire send
completed; the peer may still have received data. A successful explicit
`sendCloseReason` is the exception: it intentionally closes its own connection
and reports its send result. None of these outcomes acknowledges peer receipt.

A `ViewerConnectRequest` provides a one-shot cooperative cancellation handle
for `connectTcp` or `connectWss`. A call consumes the handle even if local
validation fails. Cancellation races the entire TCP/WSS connection, pinned
exchange and login, and drops a candidate viewer if cancellation wins before JS
resolution. It cannot retract a proof, 2FA code, or other bytes the peer already
received, interrupt synchronous crypto/native work, or prove remote cleanup.
Once a Viewer has been delivered, the request's cancellation is independent;
call that viewer's `requestClose()` instead. The original `connectViewer` and
`connectWssViewer` remain available but have no externally cancellable handle.
Cancellation does not validate identity provisioning or make WSS safe for
untrusted endpoints. Node/transport copies of secrets can remain. Unbuilt/unrun.
