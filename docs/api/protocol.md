# RustDesk protocol adapter — experimental

The `remote-protocol` crate uses `libs/base/protos/message.proto` through the
source `base` crate. It does not introduce a replacement wire protocol. It
provides bounded protobuf envelope decode/encode, a broad dispatch category,
mouse events, and borrowed or owned encoded video packets. The source schema
contains many additional event types which are retained during round trips but
not yet exposed as a stable high-level API.

The `max_bytes` argument is mandatory; use `MAX_PRE_AUTH_BYTES` or a stricter
policy before authentication and enforce a matching transport-level bound
*before* reading data. `MAX_ENVELOPE_BYTES` is a hard adapter ceiling, not a
recommendation for unauthenticated peers. A serialized size limit does not
limit all protobuf or codec allocations. Video data is untrusted and the
current `remote-codec` decoder has not been hardened for hostile streams.
Envelopes neither authenticate the peer nor bind messages to a session, reject
replays, validate permission changes, or provide encryption. Callers must not
route them to input or an exposed decoder until a complete security layer exists.

Mouse inspection omits modifier details, and construction creates an empty
modifier list. Do not use it as a replacement for the original input service
until layout, modifiers, coordinates and platform behavior are preserved.
The encoded-video constructor preserves packet ordering and keyframe/PTS
metadata but does not validate sequence, codec compatibility or timestamps.
The crate currently depends on the RustDesk checkout and has not been built or
tested.
