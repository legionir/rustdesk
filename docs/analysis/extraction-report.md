# Preliminary extraction assessment — no approval requested yet

No component is certified transferable without changes or tests. Strategies below are hypotheses backed by code references; no removals or rewrites are approved.

| Component | Evidence | Initial strategy | Risk |
|---|---|---|---|
| Capture | `libs/scrap/src/common/linux.rs`, `src/server/video_service.rs::run` | Reuse platform backends with adapter; separate service/ownership | Native build and permissions, display changes and lifetime behavior. |
| Codec | `libs/scrap/src/common/codec.rs::EncoderApi`, `Decoder` | Reuse implementations; adapt protocol types and global negotiation | Feature gating, native dependencies, hardware availability, format and buffer lifetime. |
| Input | `libs/enigo/Cargo.toml`, `src/server/input_service.rs::reset_input_ondisconn` | Reuse OS implementations, isolate dispatch/state | Layout, stuck keys, OS permissions, clipboard-assisted input. |
| Protocol | `libs/base/protos/message.proto` | Preserve schema initially in compatibility adapter; decide after full audit | Wire compatibility and security; no new schema is approved. |
| Transport | `libs/hbb_common/src/websocket.rs::WsFramedStream` | Investigate adapting existing implementation before any new transport | Config, TLS and encryption coupling; server-side handling and backpressure still unaudited. |
| Session/security | `src/server/connection.rs::start` and message dispatch; `src/client.rs::Client::start` | Likely extract behavior through adapters or selectively refactor | Authorization, resource lifetime, authentication and reconnect are deeply application-coupled; no rewrite decision yet. |

Codec evidence: `EncoderCfg` has VPX and AOM paths; `Decoder` has VP8, VP9 and AV1 implementations, while H.264/H.265 RAM, VRAM and Android MediaCodec decoding are feature gated. `EncoderCfg` hardware paths are conditional. `Decoder::supported_decodings` probes H.264/H.265 hardware availability. Thus code paths are present, not proof any particular platform can build or run them. H.264 software encoding is not established. VP8/VP9/AV1 runtime behavior also remains untested.

Keep `base`, `hbb_common`, the source codec/native stack and relevant platform backends until the real graph proves a narrower alternative preserves behavior. No dependency is currently proven safe to delete. Separate mouse/keyboard permission changes, auth model, protocol compatibility, source license compliance and standalone repository placement require human review. Time estimates would be speculative until the baseline and full dependency analysis are complete.
