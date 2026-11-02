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
loopback-only and is not that channel. Do not expose this prototype to the
internet or enable remote input based on this adapter alone.

Missing: secure transport and peer binding; trusted consent UX; permission
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
