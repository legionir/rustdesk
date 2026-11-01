# Repository map and initial tracing — incomplete

This is a starting map, not a comprehensive architecture or verified end-to-end trace. Paths refer to the pinned source in source-baseline.md.

| Area | Evidence | Initial observation |
|---|---|---|
| Entry/server | `src/main.rs`, `src/core_main.rs`, `src/server.rs::start_server`, `src/rendezvous_mediator.rs::RendezvousMediator::start_all` | App/server and rendezvous are coupled; identify all init and shutdown paths before extraction. |
| Capture/send | `src/server/video_service.rs::run`, `Capturer::new`, `c.frame(spf)`, `handle_one_frame` | A service performs capture, encoding and broadcasts; display and QoS logic are mixed in. |
| Encode | `libs/scrap/src/common/codec.rs::EncoderApi` and `Encoder::new` | Trait emits RustDesk `VideoFrame`; feature-gated hardware backends. |
| Viewer | `src/client.rs::VideoHandler::handle_frame`, `start_video_thread` | Decode/renderer handoff exists; full dispatch, threading and error path still need tracing. |
| Input | `src/client.rs::send_mouse`; `src/server/connection.rs` match on `MouseEvent`/`KeyEvent`; `src/server/input_service.rs::handle_mouse`, `handle_key` | Authorized connection handles input; existing desktop mouse path checks `peer_keyboard_enabled()`. Proposed distinct mouse/keyboard permissions are not assumed to match upstream semantics. |
| Protocol | `libs/base/protos/message.proto`; `libs/hbb_common/protos/rendezvous.proto` | Protobuf schema separates desktop and rendezvous messages but desktop envelope includes excluded services too. |
| Network | `libs/hbb_common/src/websocket.rs::WsFramedStream`, `src/rendezvous_mediator.rs` | WS/WSS client code coupled to config, TLS and encryption. `/ws/id` and `/ws/relay` in endpoint mapping are not proof of a standalone routing server. |
| State | `libs/scrap/src/common/codec.rs` static `USABLE_ENCODING`; `src/server/input_service.rs` globals | Extraction requires explicit ownership/concurrency analysis. |

Remaining: enumerate all handlers, task boundaries, error propagation, session state transitions, display hotplug, authentication/permission and cleanup paths; generate full graph and confirm actual renderer and input behavior on each platform. Existing code does not establish the proposed lifecycle state machine.
