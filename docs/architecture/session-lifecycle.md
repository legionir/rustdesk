# Session lifecycle prototype — pending verification

> Historical sections below describe successive increments; later sections
> supersede earlier statements about integration. Current host/viewer glue,
> source encryption and Node viewer remain partial, unbuilt and untested.

The new `remote-session` crate models Created → Connecting → Authenticating →
Connected ↔ Streaming → Disconnecting → Closed, plus Failed. Only a successful
caller-supplied authenticator and authorizer grant capabilities, and grants are
intersected with requested permissions. A denied authentication or consent
moves the session to Failed. Explicit permission restriction can only reduce
capabilities; close revokes them before attempting bounded, retryable resource
cleanup. No access is authorized in Created, Connecting, Authenticating,
Disconnecting, Closed, or Failed.

The state machine is not yet connected to `remote-input`, capture, codecs or
transport. It cannot by itself stop tasks or clear a held key when permission
is revoked. Resources are synchronous, must be idempotent, and must arrange
cancellation and joining of any async task themselves. The caller owns secure
ID creation, persistent replay prevention, token lifecycle, TLS/peer binding,
timeouts, heartbeat, consent UX, cross-session device coordination and
failure logging. ID history is bounded, in-memory, and lost on restart. The
traits are dependency-inversion seams, not security implementations; accepting
all credentials or automatically approving a session would be insecure.

As requested, no build or tests were run for this increment. It is neither an
acceptance-gate result nor a security audit. Before connecting it to real input,
review the authorization contract, add adversarial lifecycle tests and verify
resource shutdown and revocation under cancellation.

`HostInputSession` can mark streaming and pass a frame through `VideoSender`
using the same session and view-screen capability used for input checks. It
does not start capture itself, own the transport/encoder, or cancel separate
tasks when permissions are revoked. The integration is experimental and has
not yet been built or tested.

`input_arbiter::InputArbiter` optionally serializes cooperating in-process
controllers. It attaches only connected sessions with input permission, keeps
the lease while cleanup is retried, and quarantines the arbiter after an
unrecoverable detectable cleanup failure until a trusted operator acknowledges
manual OS recovery. It is not a global or cross-process lock: other input
paths, unguarded sessions, upstream RustDesk, processes and human input bypass
it. Windows Enigo cannot report every SendInput failure. The arbiter has fake
backend tests, not yet run, and is not a security boundary or production proof.

`capture_pump::CapturePump` is a caller-driven bridge from an authorized
`HostInputSession` and an exact enumerated display handle to the software video
sender, for local or network-oriented transport. The caller creates and starts
it, sends frames one at a time and stops it; it creates no background task.
It refuses capture before view authorization, remembers the supplied session ID,
and checks the ID and state again each frame. Session IDs still require secure
generation and uniqueness; an ID is not proof of transport binding.
Capture and codec operations can synchronously block the calling executor, the
capture timeout is only a backend hint, hotplug needs recreation, and failed
sends require encoder reset plus peer resync. Dropping the pump does not change
the session state or close transport; call `stop`, drop the pump to release
capture, and perform session cleanup explicitly.
This code is new, untested, and does not authenticate the transport.

`host_connection::HostConnection` now owns one network transport and guarded
session during a narrow caller-driven password challenge, trusted approval,
restricted input and software capture workflow. It retains a pre-auth admission
permit until authorization, checks the grace period at transitions, clears
pending evidence on close, and never hands out its transport or host session.
Cancellation leaves its operation phase unusable: the caller must close/drop
it. Capture handles remain caller-owned and must also be dropped. The receive
bound is after transport receive, so the transport must independently enforce a
128 KiB pre-auth frame cap. This partial glue is untested and cannot establish
cryptographic peer binding, E2E encryption, secure identity, owner consent, 2FA,
full RustDesk interoperability or cross-session input exclusivity. In
particular a relay can observe the password challenge transcript. It is not a
safe internet-facing server.

A separate `viewer_connection::ViewerConnection` now owns a transport for a
basic password login and caller-driven message demultiplexing. The host sends
an existing-schema login response only after explicit approval; both sides can
process a limited source TestDelay path. The viewer leaves video compressed for
explicit trusted decoding and surfaces cursor/peer metadata. This is still not
an end-to-end-authenticated or encrypted session, not a complete RustDesk
host/viewer, and is not safe against untrusted peers/relays. Network login and
synthetic input cases have been written but not run. Actual display rendering,
video negotiation/refresh, full message multiplexing, permissions synchronization,
secure key exchange, 2FA and consent UX remain incomplete.

A deferred synthetic case additionally composes the strict pinned-source
version-1 key exchange, owned host/viewer password login, local approval and
fake mouse dispatch. It has not been executed. This composition is an
experiment, not proof of interoperability or a security boundary; no UI, real
input, codec stream, pinned-key provisioning or untrusted-client tests are
included. Admission should be taken *before* beginning the identity handshake;
the case is only a composition sketch and does not model that ordering.

An approved `HostConnection` can optionally acquire the existing cooperative
`InputArbiter` without exposing its host or transport. The lease remains held
until detectable session/input cleanup succeeds; unresolved drop quarantines
the arbiter. This remains optional, local-process coordination only: unguarded
connections, other processes and human input bypass it, and Windows Enigo does
not report every release failure. These changes are not built or tested.

Input down events now record the intended held key/button before calling the
backend. If a backend reports a failure after a potentially partial injection,
the controller denies further input and attempts releases; explicit close can
retry detectable cleanup failures. This policy assumes exclusive input
ownership and may itself release a key held by another actor if that assumption
is false. Windows Enigo still hides some OS failures. The new fake case has not
been run or validated on a desktop.

`ViewerConnection::send_video_control` and `HostConnection::receive_event` now
carry the existing source refresh/received variants. The host requires local
screen-view permission and returns a request to its caller rather than changing
a capture/encoder itself. The caller must validate display indices against its
current display list, rate-limit requests and implement refresh/ACK scheduling.
The legacy `receive_input` method consumes but rejects these controls; do not
mix the two receive styles if video controls matter. These additions and the
synthetic test are unbuilt and untested.

Decoder capabilities may optionally be included in a viewer login or sent as
an existing option after login. The host retains only a separate
SupportedDecoding message—not the login's password-bearing envelope—and exposes
it only after owner approval with screen-view permission. Later option updates
are similarly returned to the caller as sanitized capability-only messages.
This does not automatically invoke the process-global `SourceNegotiator`, prove
any codec works, negotiate every source option, or start capture. Peer IDs,
cleanup and exclusive ownership of upstream globals remain the caller's
responsibility. The capability cases have not been built or run.

For peers that omit decoder capability data, RustDesk source registers
`EncodingUpdate::NewOnlyVP9`. `SourceNegotiator::register_legacy_vp9` now
exposes that exact fallback only with an explicit acknowledgement token. It is
not a decoder probe and inherits the process-global collision and cleanup
limitations of the source negotiator. The fallback test is deferred.

`VideoSync` is optional caller-driven bookkeeping for a single display and
codec. After a reported loss or decode failure it waits for the source wire
keyframe marker and requires the caller to report decode outcome. This marker
is peer-supplied and not validation; callers must recreate the native decoder,
request refresh and decide render/ACK policy themselves. The tracker neither
bounds native decoder allocation nor makes untrusted bitstreams safe. Its fake
unit test has not been run.
