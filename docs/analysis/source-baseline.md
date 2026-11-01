# Source baseline — work in progress

Recorded 2026-11-01. This is not Gate A approval. No application code has been changed.

- Requested upstream: https://github.com/rustdesk/rustdesk; `git ls-remote ... HEAD` returned `23e5bb471a040d62f0a6ad52591fb30784265b73` at inspection time. The supplied checkout has that same commit; its configured origin is the fork `https://github.com/legionir/rustdesk.git`, not the official remote. This verifies the advertised HEAD hash, not a full provenance or signature audit.
- Initial branch: `arena/d2b8eee8-rustdesk`; initially clean. Commit message: `finish translations`.
- `.gitmodules`: one submodule, `libs/hbb_common`, https://github.com/rustdesk/hbb_common, pinned at `fae47e024dd83cef6aaecde0aa7d11731df11649`. It was initially uninitialized and was initialized at the recorded gitlink, without changing it.
- Host: Linux x86_64, kernel 6.1.158+. `rustc` and `cargo` are absent from PATH. Root manifest declares `rust-version = "1.75"`; this is a requirement, not a detected compiler version. No repository rust-toolchain file was found.
- Desktop target source paths include Windows, macOS, Linux (X11 and Wayland); Android/iOS code also exists. This is source presence, not a tested support matrix.
- License: root `LICENCE` and individual crate manifests require legal review, including dependency and distribution obligations; no conclusion has been made.
