# Local manifest dependency graph (static, incomplete)

This graph is mechanically read from local manifest `path` dependencies, including build dependencies and target-specific manifest sections. It is not Cargo's resolved graph: Cargo metadata could not run, features are not resolved, patch edges and transitive external packages are not fully enumerated. `Cargo.lock` and target-specific dependencies must be audited with the real toolchain before drawing removal conclusions.

```text
rustdesk -> scrap, base, hbb_common [also build], enigo [desktop], clipboard [desktop]
rustdesk -> virtual_display, remote_printer [Windows]
scrap -> base -> hbb_common
scrap -> hbb_common
enigo -> base, hbb_common
clipboard -> base, hbb_common
virtual_display -> hbb_common
dylib_virtual_display -> hbb_common
remote_printer -> hbb_common [Windows]
libxdo-sys-stub -> hbb_common [root crates.io patch]
rustdesk-portable-packer -> no local path dependency
```

RustDesk root patches tungstenite and several WebRTC packages to pinned Git revisions, and libxdo-sys to the local stub; the standalone root would need intentional equivalent resolution if behavior depends on them. External dependencies, native libraries, protobuf generation, feature unification, target conditions, shared globals and service-level coupling are not represented by the diagram. Manifest edges do not mean every module in a crate needs every dependency; use source-level tracing and tests to determine safe boundaries.
