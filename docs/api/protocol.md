# RustDesk protocol adapter — experimental

The `remote-protocol` crate uses `libs/base/protos/message.proto` through the
source `base` crate. It does not introduce a replacement wire protocol. It
provides bounded protobuf envelope decode/encode, a broad dispatch category,
mouse and keyboard inspection, and borrowed or owned encoded video packets. The source schema
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

Mouse modifier values can be inspected separately, while construction creates
an empty modifier list. Keyboard payloads retain their original mode and values;
they are not translated into Windows virtual keys. Do not use it as a replacement for the original input service
until layout, modifiers, coordinates and platform behavior are preserved.
The encoded-video constructor preserves packet ordering and keyframe/PTS
metadata but does not validate sequence, codec compatibility or timestamps.
The crate currently depends on the RustDesk checkout and has not been built or
tested.

`password_challenge_event`/`password_challenge` and
`desktop_login_event`/`desktop_login` expose a basic subset of RustDesk's Hash
and LoginRequest messages without replacing the schema. Non-desktop request
modes remain intact but are not handled by the desktop view. The fields are
untrusted, and the adapter does not enforce 2FA, token validation, owner
approval, peer identity, or message replay protection.

The experimental `windows_mouse::dispatch` handles a limited subset of mouse
messages through the session guard: absolute/relative movement, five buttons,
and ordinary Windows wheel events. Its constants and Windows wheel signs/units
come from `src/common.rs::input` and `src/server/input_service.rs`; relative
deltas are clamped to ±10,000. It rejects modifier-bearing mouse events,
trackpad and unknown event forms; their protobuf remains unchanged. It does not
implement keyboard/touch dispatch, display mapping, input arbitration, transport
binding or a trusted consent flow. Its distinct mouse permission differs from
upstream's shared keyboard gate and must be reviewed. Tests use a fake backend
and have not been run; real Windows desktop behavior is unverified.

`windows_keyboard::dispatch` accepts only a restricted set of unmodified
legacy `ControlKey` messages, using the source's Windows virtual-key mappings.
It rejects modifier keys/lists, lock and system actions, text, scan codes and
other modes. Unlike RustDesk it does not synchronize OS modifier state, perform
portable-service/desktop switching or generate repeats, so even supported keys
are not a claim of complete compatibility. Its fake-backend tests are written
but not run; real input delivery is unverified.

With the `hwcodec` feature, `HardwareVideoSender` can pack H.264/H.265 RAM
encoder output into the existing RustDesk VideoFrame oneof and send it through
`NetworkTransport` under a view-screen session check. It discards the encoder
after an interrupted send; the application must renegotiate/resynchronize the
peer. This path does not implement hardware decoding, codec negotiation, secure
peer binding, or native driver isolation, and has not been built or tested.

`remote-protocol` can inspect SupportedDecoding in login/Misc option messages,
and SupportedEncoding in Misc, PeerInfo or successful LoginResponse, preserving
raw decoder ability/preference values. Its explicit advertisement constructor
emits the source Misc→Option→SupportedDecoding layout, with no I444 claims.
Claims are untrusted and are not runtime probes. RustDesk's SupportedEncoding
has no VP9 flag; do not infer a working encoder solely from the schema. The
source protobuf remains the wire format, not a new protocol. These adapters are
not built or tested.

The optional `HardwareVideoReceiver` can pass H.264/H.265 wire packets to the
source RAM decoder when a configured backend is available. Packet count/size
limits do not stop native decoder or driver allocations determined by the
bitstream. It must only process trusted data until the decoder is sandboxed and
reviewed. No real-GPU, compatibility or adversarial tests have run.

`remote-protocol::cursor` exposes RustDesk cursor ID, position, zstd-compressed
shape and request-shape messages. It mirrors the source client's 512×512,
hotspot and exact RGBA length checks, and provides an explicitly bounded LRU
cache. Cursor IDs are 64-bit; Node/JS callers must use strings to avoid loss of
precision. The cache excludes allocator/application-held memory and does not
draw a cursor or implement source content-based deduplication. Neither its
wire compatibility nor adversarial decompression behavior has been tested.
