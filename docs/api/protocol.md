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
