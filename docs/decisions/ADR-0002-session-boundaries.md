# ADR 0002: Session lifecycle guard without embedded authentication (provisional)

## Context and evidence
`src/server/connection.rs::Connection::start`, `on_message` and `on_close`
combine login, connection-manager approval, service dispatch and cleanup. A
network adapter cannot safely treat a connected stream as an authorized
session. `libs/hbb_common/src/websocket.rs` also reads process-global TLS
configuration and can accept invalid certificates if insecure fallback is
enabled. Its plaintext receive path accepts text frames as bytes.

## Options
1. Copy RustDesk's application connection manager wholesale: highest immediate
   behavioral reuse but couples application UI, configuration and other services.
2. Invent a new token/approval scheme: superficially standalone but unsafe to
   freeze before security and compatibility review.
3. Provide a fail-closed lifecycle and trusted policy interfaces while keeping
   actual authorization, transport binding and source adapters explicit.

## Decision
Implement option 3 as an **experimental, untested** scaffold. It does not
replace RustDesk authentication or guarantee authorization at the OS input
boundary. The final authentication, replay, session protocol and approval
mechanisms require review and implementation; this ADR does not approve them.
Do not plug in an allow-all provider or publish it as a secure server.

## Consequences
The design is small and transport-independent, but it cannot reproduce all
RustDesk behavior alone. Cleanup requires explicit integration, ID history is
not durable, and synchronous providers cannot directly perform async I/O.
Before WS/WSS integration, isolate TLS policy, prohibit insecure fallback by
default, define binary-frame behavior and cancellation semantics, and validate
real certificate failure scenarios. Compatibility and security remain open.
