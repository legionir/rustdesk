# Security implementation status — provisional, not audited

`remote-security` contains an experimental compatibility adapter for the
password challenge used by the pinned source: `src/client.rs::handle_hash`
computes SHA256(password || salt), then SHA256(h1 || challenge), and
`src/server/connection.rs::verify_h1` verifies the latter with a constant-time
comparison. The adapter generates a random challenge, expires and consumes it
on the first attempt, uses a constant-time comparison, and implements the
existing `remote-session::Authenticator` interface. The corresponding
`OwnerApproval` only represents a decision made elsewhere; it does not present
a UI or prove a human consented.

This compatibility password scheme is **not** a modern PAKE. A captured
challenge and response allow offline guessing, and it does not authenticate
the server or cryptographically bind to a TLS channel. The verifier keeps a
password-derived secret in memory and uses best-effort zeroization, not a
proof all copies or SHA internals are wiped. Use only strong passwords over an
authenticated encrypted channel. The existing RustDesk WebSocket wrapper is
loopback-only and is not that channel. A separate experimental strict WSS client
validates its endpoint, but does not authenticate a desktop peer behind a relay
or implement RustDesk's end-to-end handshake. Do not expose this prototype to
the internet or enable remote input based on these adapters alone.

Missing: verified and audited end-to-end secure transport and peer binding; trusted consent UX; permission
revocation across running tasks; session-ID generation and persistent replay
controls; brute-force/connection limits; credentials storage and rotation;
expiry policy across process restarts; RustDesk 2FA and trusted-device behavior;
security tests and audit. The adapter has not been built or tested. It is not a
claim of authentication compatibility for the whole RustDesk login flow.

`remote-security::admission` adds an optional bounded in-process pre-auth slot
controller using the source defaults (64 total, 16 per address, 180 seconds,
128 KiB suggested message cap). The caller must enforce the message cap, run
timers, close expired sockets, and retain permits until *all* authorization
succeeds. Unlike upstream, this provisional version refuses new connections at
capacity rather than evicting the oldest. It does not implement rate limiting,
2FA, ID whitelist, secure identity or distributed-attack prevention, and cannot
trust relay-provided client IPs without separate validation. Bypass paths and
multiple processes are outside its scope. It has not been built or tested; the
policy difference requires security review before deployment.

A new **experimental and untested** `source_crypto` adapter reuses the pinned
source's signed `IdPk`, `PublicKey`, secretbox framing and version-1 split-key
implementation on an owned ordered binary transport. Its viewer explicitly
pins the host signing key and exact host ID; the host still needs password and
local owner approval to authorize a viewer. Unlike source fallback behavior it
rejects unsigned peers, v0 and malformed/short encrypted frames, and closes on
failure or cancellation. It does not implement a rendezvous signature chain,
key provisioning/rotation/revocation, WebRTC fingerprint binding, 2FA, complete
RustDesk compatibility or an audited replay/DoS defense. These policy choices
are provisional and require human security review. They do not make this
prototype production-ready or safe for untrusted traffic. No tests were run.

Behind the opt-in `remote-core/source-security` feature, `admitted_host::accept`
composes a caller-acquired admission permit with a framing-level pre-auth cap
and the pinned source-v1 host handshake, before creating the still-unauthorized
host session. The caller must acquire the permit using a trusted observed socket
address *before* calling it. Separate password verification and owner approval
are still mandatory. The cap includes 16 bytes for secretbox overhead and is
not a whole-process memory limit. This integration remains unbuilt, untested,
and subject to security-policy review.

The Node prototype also has a view-only listener restricted to loopback. It
uses a one-listener/one-session cooperative limit, a temporary signing key,
pre-auth framing/admission, password verification and a separate explicit
approval call. It denies OS input. A timer attempts to close abandoned pending
sessions at the accept deadline; the decision API checks expiry independently.
Local process identity, secure key provisioning, OS-wide exclusivity, UI
consent, cancellation under all races and decoder/desktop safety are not
established. The implementation and deferred loopback cases are unbuilt,
untested and unaudited; never treat loopback as an authentication boundary.

### Local approval handoff (experimental, not a consent UI)

`remote-security::approval::ApprovalBroker` and the optional
`HostConnection::request_owner_approval` / `authorize_with_ticket` methods
provide a bounded in-process handoff. Tickets are session/generation scoped,
expire, and are removed on drop; a consumed decision remains one-shot, checks
its original principal and deadline, and intersects requested permissions. Peer
labels are unverified and must not be displayed as authenticated identities.
This is not RustDesk's connection-manager IPC or an OS-authenticated channel:
any code with a broker clone can approve. The embedding application must present
a trusted owner prompt, secure any cross-process communication, close expired
connections and provision identities. Races, revocation and behavior on real
Windows have not been built, tested or reviewed.

An **unwired, untested** `source_failure_counters` module records source-style
password-failure totals and IPv6 /64, /56 and /48 buckets with explicit bounded
capacity. It does not block login, attribute connections, provide an atomic
check-and-attempt gate, persist state or emit audit events. Capacity exhaustion
is an error (it must not be ignored). Its explicit source-compatible success
reset clears shared IPv6 prefix counters and can enable bypass by one successful
peer; default integration and policy require human security review. Proxy and
WSS endpoints must not use unauthenticated headers as trusted client IPs.

The optional counter's operator reset intentionally clears all lockout state;
it is not triggered automatically by capacity exhaustion and must not be
exposed to a remote peer. With no expiry or persistence, a full table can
block new address tracking and a restart loses counters. Applications need an
explicit reviewed operational policy rather than treating this module as a
complete password-guessing defense.
