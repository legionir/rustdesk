//! Explicit opt-in only: this captures a real local screen. Use a disposable
//! interactive Windows desktop with REMOTE_CORE_TEST_DISPLAY=1 and consent.
#![cfg(target_os = "windows")]
use remote_capture::{displays, Frame, GdiFallbackOptIn};
use std::{io, time::Duration};

#[test]
fn explicitly_switches_authorized_local_capture_to_gdi() {
    if std::env::var_os("REMOTE_CORE_TEST_DISPLAY").as_deref() != Some(std::ffi::OsStr::new("1")) { return; }
    let display = displays().unwrap().into_iter().next().expect("authorized interactive display");
    let mut capture = display.open().unwrap();
    capture.use_gdi(GdiFallbackOptIn::acknowledge_backend_change()).unwrap();
    assert!(capture.is_gdi());
    // Idempotence avoids replacing the existing GDI handle.
    capture.use_gdi(GdiFallbackOptIn::acknowledge_backend_change()).unwrap();
    for _ in 0..10 {
        match capture.frame(Duration::from_millis(250)) {
            Ok(Frame::Pixels(frame)) => { assert!(frame.width() > 0 && frame.height() > 0 && !frame.data().is_empty()); return; },
            Ok(Frame::Texture(_)) => panic!("GDI unexpectedly returned a texture"),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => panic!("capture failed: {error}"),
        }
    }
    panic!("GDI did not produce an initial frame");
}
