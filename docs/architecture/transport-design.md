# Transport status — provisional

> This document records successive increments. Later sections supersede early
> statements that all adapters are loopback-only or lack WSS; none is verified.

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

Codec capability messages are the original RustDesk protobuf messages. The
optional `remote-codec::negotiation::SourceNegotiator` delegates to RustDesk's
original process-global `Encoder::update` algorithm and bounds the peer IDs it
owns; it does not implement an alternative selection policy. Because other
RustDesk code can mutate the same global state and reuse IDs, run this adapter
only in a dedicated process that exclusively owns that state. Its module-local
guard cannot prevent unrelated code from bypassing it. Capability claims are
not authenticated or runtime proof, hardware initialization can fail, and the
source's VP9 fallback is not a capability guarantee. Adapter and tests are
unbuilt and unrun.

A provisional `AdjustableNetworkTransport` capability can change a real
framing-layer message bound. Loopback TCP implements it using the source
`BytesCodec`, and `EncryptedTransport` adds secretbox tag overhead. The host
connection exposes raising the bound only after its password and owner-policy
steps succeed. This is not a process memory bound, cannot clear already
buffered data and is untested. Strict WSS now adjusts tungstenite frame,
message and write-buffer limits while idle; this has not been built or tested.
Callers must apply a pre-auth framing cap before the identity handshake and
retain admission until all approval completes. A separate direct TCP adapter described below can bind non-loopback addresses.

`direct_tcp` is an additional explicit-opt-in direct TCP listener/connector
using the same RustDesk frame codec and dynamic frame limit; unlike the earlier
loopback adapter it can bind/connect non-loopback literal addresses. It is
plaintext, unauthenticated and dangerous if exposed by itself. It does not
implement DNS, proxy or SSRF policy. The caller must admit the transport-observed
peer address before handshake, apply reviewed encryption and trusted owner
policy, and control address exposure. Neither its local synthetic case nor a
real network deployment has been tested.

The Node prototype can also use strict WSS with a separately pinned source host
key. It has no relay/server configuration, endpoint SSRF policy, WSS host API
or Cloudflare interoperability proof. Dynamic WSS framing, Node binding and
all associated synthetic cases are unbuilt and untested.
