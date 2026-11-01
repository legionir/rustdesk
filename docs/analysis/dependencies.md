# Dependency inventory — preliminary

Cargo metadata could not run; this is a manifest-level inventory, **not** a resolved transitive graph. `Cargo.lock` records pinned resolution; repeat `cargo metadata --locked` on a prepared machine and analyze target-specific features and native dependencies before removal.

Root workspace lists `libs/scrap`, `libs/hbb_common`, `libs/base`, `libs/enigo`, `libs/clipboard`, `libs/virtual_display`, `libs/virtual_display/dylib`, `libs/portable`, `libs/remote_printer`, plus the root package. `libs/libxdo-sys-stub` is a local crates.io patch, not an explicit member. Root patches tungstenite and WebRTC to RustDesk forks; these patches must be accounted for in a standalone consumer's root manifest, not assumed to propagate.

- `scrap` directly depends on `base`, `hbb_common`, rust-webm; optionally hwcodec, GStreamer and D-Bus. `scrap/src/common/codec.rs` directly uses `base::message_proto`: capture and codec are not currently protocol-independent.
- `enigo` directly depends on `base`, `hbb_common`, RustDesk forks of rdev and tfc; Linux uses libxdo-sys (patched at root).
- `hbb_common` includes protobuf, Tokio, sodiumoxide, TLS, tokio-tungstenite, configuration and platform dependencies. `base` holds desktop message schema. These are broader than transport and protocol alone.
- Root includes Flutter as an optional feature, but root services, configuration, UI and platform code share dependencies. A non-Flutter build does not by itself prove independent extraction.
- Clipboard is excluded from the desired product surface, but `src/server/input_service.rs` contains clipboard-assisted text input (`input_text_via_clipboard_server`); do not remove this dependency before identifying an equivalent behavior and testing it.
