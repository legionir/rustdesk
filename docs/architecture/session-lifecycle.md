# Session lifecycle prototype — pending verification

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
