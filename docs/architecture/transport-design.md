# Transport status — provisional

`remote-transport` supplies a bounded in-process transport and an object-safe
interface. `remote-rustdesk-websocket` wraps the existing pinned
`hbb_common::websocket::WsFramedStream`, not a new WebSocket implementation.
It intentionally accepts only literal loopback `ws://` endpoints for local
experimentation and refuses configured proxies. Because process-global proxy
configuration can change concurrently, the embedding process must keep it
disabled during the connection attempt. It does not support WSS or remote
networking, and loopback access does not authenticate the peer.

The wrapper sets both upstream frame and message limits before reading, applies
operation deadlines and drops the connection if an operation fails or is
cancelled. A send that times out or is cancelled may already have reached the
peer; no automatic replay is attempted. The upstream unsecured receive path
returns text frames as bytes, so binary-only receive is not guaranteed.

This adapter cannot safely implement the local `Transport` cancellation
contract, which promises that a cancelled send is not enqueued: a network send
may have an indeterminate outcome. Do not weaken that contract silently. A
future network-facing interface needs explicit delivery and cancellation
semantics, isolated TLS policy with certificate verification, authorization,
end-to-end or authenticated transport, message bounds, denial-of-service tests,
heartbeat/reconnect behavior, and actual WSS interoperability testing.

This code has not yet been built or tested.
