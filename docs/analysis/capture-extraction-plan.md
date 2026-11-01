# First extraction increment: capture — blocked at Gate A

The user has selected a Rust core with a Node.js adapter and requested that extraction begin. That is approval of a direction, not proof that Gate A has passed or acceptance of an untested security/lifecycle design. No production source is copied or changed in this increment.

## Source boundary and evidence

- `libs/scrap/src/common/mod.rs` exposes `TraitCapturer`, `TraitPixelBuffer`, `Frame`, and platform-selected modules. `libs/scrap/src/common/linux.rs` dispatches `Capturer::new` and `frame` to X11/Wayland and exposes display enumeration and metadata.
- `src/server/video_service.rs::run` and `handle_one_frame` mix capture ownership, encode, service subscriptions, frame delivery, QoS, recording and switching. Moving that service wholesale would not produce an independent capture crate.
- `libs/scrap/Cargo.toml` directly depends on `base` and `hbb_common`; `libs/scrap/src/common/codec.rs` uses the desktop protobuf types from `base`. `base` itself depends on `hbb_common` and includes other application code. It is not yet a minimal capture dependency.
- Root `LICENCE` is AGPL-3.0; the `scrap` manifest reports MIT. This is not a conclusion that all files under `scrap` can be redistributed under MIT. Audit per-file provenance, notices and dependency licenses, especially modified files, before distributing extracted source.

## Smallest defensible next change after Gate A

1. Prepare a standalone workspace with recorded source and submodule pins, license/notice inventory, and reproducible target-specific prerequisites. Do not silently change the selected source revision or delete shared dependencies.
2. Start with an adapter around the existing capture types and retain the original crate and its current dependency closure initially. Define an owned display descriptor and explicit borrowed frame lifetime, without promising zero-copy across threads. Retain original errors and metadata.
3. Add independent tests around enumeration and frame contracts, including no-display, dropped/reconfigured display, cancellation and resource cleanup. Hardware/desktop-dependent integration tests must report skipped when unavailable, not success.
4. Run build and tests on a prepared Linux desktop; separately validate Windows and macOS. Only after a passing baseline compare behavior before and after each separation step. Keep codec and global-state disentangling in separately reviewable changes.
5. Only once native Rust API and lifecycle are stable should an N-API adapter be considered; the adapter cannot replace platform validation.

## Stop conditions and open decisions

`cargo`/`rustc` are absent, metadata/build/tests cannot run, and platform/permission/session/security tracing remains incomplete. In particular the existing desktop mouse path uses keyboard permission, and some video channels are unbounded. The design has not been reviewed against these behaviors. Existing requirements explicitly stop at a fundamental problem at each gate and require build/test after each step. Beginning to copy or rewrite source now would bypass those checks and could not meet the acceptance criteria.

Required next action: provide a Linux environment with toolchain compatible with the manifest and documented native dependencies, or enable access to a trusted pre-provisioned toolchain. Run the baseline described in `build-baseline.md`, complete Gate A and request review of protocol/security/permission and public API decisions. Do not treat the choice of Rust + Node.js binding as approval of those separate decisions.

## Prototype started on user request

A limited capture adapter now lives under `remote-core/` and a dedicated GitHub Actions workflow runs Linux unit and virtual-X11 capture tests. This proceeds before Gate A and baseline completion at the user's explicit request to use CI; it does not approve the architecture or waive the remaining gates. The prototype is not independent, not released, and does not implement the rest of the core. Its compile/test outcome must be taken from actual CI, not assumed.
