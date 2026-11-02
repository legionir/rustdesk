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
