# RemoteCore progress

## Windows-first capture and codec increment

Commit `b869d83` adds a packed BGRA/RGBA-to-I420 bridge using the same libyuv calls as `libs/scrap/src/common/convert.rs`, with stride/buffer validation before calling native code. The existing software codec adapters provide VP8, VP9 and AV1. H.264/H.265 and hardware paths remain unadapted; none of RustDesk's existing functionality has been removed. Recreate the encoder when a display changes size; other pixel formats and capture-to-encoder zero-copy are not implemented.

[CI run 41345298622](https://github.com/legionir/rustdesk/actions/runs/41345298622) passed on the above commit. Windows Server 2022 executed workspace cargo check and tests, including synthetic software codec round trips and packed pixel conversion. Its real-display test was not enabled: GitHub-hosted Windows runners do not establish an interactive DXGI desktop in this workflow. Therefore Windows screen capture, multi-monitor behavior, permission handling and hotplug are **not validated**. Linux CI also passed an Xvfb capture → VP9 encode → decode integration test. These are not network, rendering, performance or security tests.

The workspace remains an adapter inside the RustDesk checkout, dependent on `scrap`, `base` and `hbb_common`; it is not yet independently distributable. The decoder is not safe to expose to untrusted peers: encoded payload length alone does not bound decoder allocations. Session, input, transport, authorization, Windows real-desktop testing and Node.js bindings are not implemented. No v0.1.0 acceptance gate is complete. Full source baseline and license/provenance review are still outstanding.
