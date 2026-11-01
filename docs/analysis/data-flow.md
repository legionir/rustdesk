# Data flow: traced portions, not a complete proof

Static inspection at the pinned commit; line/function references are evidence, not executed behavior. `ResultType` is the project's `anyhow`-based result alias. Paths not yet proven are marked open.

## Video

| Stage | Input → output | Execution and error handling |
|---|---|---|
| `src/server.rs::new`, `Server` | Registers display/cursor/other services; video services added on demand around `src/server.rs:440` | Server-wide service lifecycle; exact init and subscriber ordering still to trace. |
| `src/server/video_service.rs::new`, `run` | `VideoSource`/display index → service loop; `Capturer::new(display)`, then `c.frame(spf)` | `run` returns `ResultType<()>`; Linux invokes Wayland `ensure_inited()?`. Capture backend selected by `libs/scrap/src/common/linux.rs::Capturer::new`. Exact frame retry and timeout cases need a complete audit. |
| `src/server/video_service.rs::handle_one_frame` | `EncodeInput`, timestamp and display index → `Encoder::encode_to_message` → `VideoFrame` → `Message::set_video_frame` → `GenericService::send_video_frame` | Encoder failure is counted, logged and handled by service policy; new subscribers can cause `SWITCH`. Recording uses the same message. Ownership and all switch/recreate cases need further audit. |
| `src/server/connection.rs::Connection::start` | Service broadcast → per-connection video receiver → network stream | Tokio select loop; `tx_video` is a Tokio **unbounded** channel. Awaited network send alone does not prove bounded total buffering. Inspect upstream subscriber and drain policies before claiming exhaustion resistance. |
| `src/client/io_loop.rs::handle_msg_from_peer` | Received bytes → `Message::parse_from_bytes` → `VideoFrame` | Async message handling creates per-display video thread; keyframes go to `std::sync::mpsc::channel`; non-key frames go to `ArrayQueue` (capacity `VIDEO_QUEUE_SIZE=120`) and overflow requests refresh. The notification/keyframe channel itself is unbounded; this is not an end-to-end memory bound. Invalid protobuf is not dispatched; exact peer handling/limits still require audit. |
| `src/client.rs::start_video_thread`, `VideoHandler::handle_frame` | `VideoFrame` → `Decoder::handle_video_frame` → `ImageRgb` or texture → callback | Dedicated `std::thread`; decoder resets on codec format change. Decode errors request `session.refresh_video`; unsupported decoder is advertised after failure/invalidity. |
| `src/client/io_loop.rs::new_video_thread` callback | image/texture → `ui_handler.on_rgba` or feature-gated `on_texture` | UI-specific render and frame ownership not yet fully traced. |

## Input

1. `src/client.rs::send_mouse` constructs mouse protocol messages; keyboard producers exist in several UI/input paths and require complete enumeration.
2. Stream transports serialized `base::message_proto::Message`. `src/server/connection.rs::on_message` checks authorization and dispatches `MouseEvent`/`KeyEvent`. On desktop both simulated mouse and keyboard paths use `peer_keyboard_enabled()`; camera connections are rejected. This differs from separate proposed mouse/keyboard capabilities. Mobile branches differ.
3. `Connection::start` spawns `Connection::handle_input` on a standard thread. That loop receives `MessageInput`, invokes `input_service::handle_mouse` or `handle_key`; a press is expanded to down/up. `input_service` invokes platform-specific Enigo/rdev/uinput code; mapping and error handling need further tracing.
4. Input state includes process-wide `ENIGO`, `KEYS_DOWN` and other locks in `input_service.rs`. Its timeout loop checks every 10 seconds and force-releases on process exit. `reset_input_ondisconn` exists only for macOS and is invoked at input-thread start, not proof of universal per-session key cleanup. Trace all RAII/disconnect paths and test with concurrent sessions before promising stuck-key safety.

Open: complete source-to-renderer and keyboard producer paths, mapping and monitor coordinates, queue ownership on cancellation, OS behavior, dynamic resolution/hotplug, and error propagation. No runtime tests have been performed.
