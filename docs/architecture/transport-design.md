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

The adapter also has an experimental `LoopbackTcpListener`/`LoopbackTcp`
using the original `hbb_common::tcp::FramedStream` and its `BytesCodec` framing,
without changing RustDesk's wire protocol. It binds and connects only literal
loopback IP addresses. This is plaintext, unauthenticated, and unsuitable for
credentials, remote input or private screen contents: other local processes may
connect. Per-message limits are set before reading. A timed-out or cancelled
I/O operation drops the socket; send delivery is indeterminate. It deliberately
does not implement the in-process `Transport` cancellation contract. No
handshake, TLS, real session binding or Internet-facing TCP is provided. Tests
have been written but not run.

`NetworkTransport` is a separate object-safe contract from the in-process
`Transport`: a failed or cancelled network send has an indeterminate delivery
outcome and the stream must close if an in-flight operation fails or is
cancelled. The existing loopback WebSocket and TCP wrappers implement it, and
the video sender/receiver have a corresponding network path. Encoder reset and
explicit decoder resynchronization remain necessary after interruption. This
interface provides no authentication, confidentiality, server identity, or
proof that a peer processed a message. Current implementations remain loopback
only, plaintext, untested, and unsafe for private desktop content or input.

## Experimental strict WSS client

`strict_wss::StrictWss` is a client-only adapter using the same pinned
`tokio-tungstenite` fork as `hbb_common`, but constructs a separate Rustls
configuration with the ring provider and WebPKI plus native roots. It does not
read the global TLS/proxy cache or use insecure-certificate fallback. It
requires `wss://`, rejects userinfo, query and fragment, configures frame/message
bounds before the HTTP upgrade, accepts only binary messages, and closes on
failed/cancelled in-flight I/O. It does not support proxies, custom roots,
client certificates, authentication headers or URL queries; these limitations
can block real deployments. A configured URL must be trusted: arbitrary URLs
can cause SSRF. The adapter is not a server and does not implement RustDesk's
signed key exchange or provide end-to-end encryption through a relay. TLS
validates the WSS server, not a desktop peer behind it. The policy is
provisional and needs human security/API review and real certificate,
interoperability and Cloudflare tests before use. No build or tests have run.
