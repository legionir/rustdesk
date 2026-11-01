# Platform observations — untested

- Linux: `libs/scrap/src/common/linux.rs` selects X11/Wayland capturers. `libs/scrap` has optional Wayland/GStreamer and DRM features; DRM dynamically loads its native library according to the manifest. Input includes Enigo, rdev and uinput paths (`src/server/input_service.rs`). Source comments in `video_service.rs::run` say Wayland supports only one video capturer and does not support multi-screen capture there; verify against the rest of the current implementation and real compositors before stating a definitive support matrix. Wayland portal/compositor permissions and display hotplug need real tests.
- Windows: `libs/scrap/src/dxgi` and `libs/scrap/src/common/dxgi.rs` implement capture; Enigo/rdev and Windows-specific input branches exist. Hardware encoder/decoder are feature and hardware dependent. Desktop isolation, secure desktop and elevation behavior remain to audit.
- macOS: `libs/scrap/src/quartz` is a capture backend; input uses CoreGraphics/Objective-C and macOS-specific virtual state. `Connection::on_message` applies Retina coordinate handling. Screen recording and accessibility permissions require real platform verification.
- Android/iOS have separate branches; they are not evidence of desktop feature parity. iOS `KeyEvent` branch in connection handling is empty.

None of the above platforms was built or run; no FPS, hardware availability, permission behavior or compatibility claim is made.
