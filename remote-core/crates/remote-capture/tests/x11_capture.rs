//! Run explicitly with `REMOTE_CORE_TEST_DISPLAY=1` on a disposable X11 display.
#[test]
fn captures_a_real_x11_display_when_requested() {
    if std::env::var_os("REMOTE_CORE_TEST_DISPLAY").is_none() {
        eprintln!("SKIP: REMOTE_CORE_TEST_DISPLAY is not set");
        return;
    }
    let displays = remote_capture::displays().expect("enumerate displays");
    assert!(!displays.is_empty(), "X11 test display must exist");
    let display = displays.into_iter().next().unwrap();
    assert!(display.info().width > 0 && display.info().height > 0);
    let mut capturer = display.open().expect("open display");
    let frame = capturer.frame(std::time::Duration::from_secs(1)).expect("capture frame");
    match frame {
        remote_capture::Frame::Pixels(pixels) => {
            assert!(pixels.width() > 0 && pixels.height() > 0);
            assert!(!pixels.data().is_empty());
            assert!(!pixels.stride().is_empty());
        }
        remote_capture::Frame::Texture(_) => panic!("X11 test expected CPU pixels"),
    }
}
