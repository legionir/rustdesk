//! Requires an explicitly selected disposable desktop session.
use remote_capture::{Frame, PixelFormat};
use remote_codec::{Codec, EncoderConfig, PackedFormat, SoftwareDecoder, SoftwareEncoder};
use std::time::Duration;

#[test]
fn capture_encode_decode_on_requested_desktop() {
    if std::env::var_os("REMOTE_CORE_TEST_DISPLAY").is_none() {
        eprintln!("SKIP: REMOTE_CORE_TEST_DISPLAY is not set");
        return;
    }
    let display = remote_capture::displays().expect("enumerate displays").into_iter().next().expect("test display");
    let mut capture = display.open().expect("open display");
    let frame = capture.frame(Duration::from_secs(3)).expect("capture frame");
    let pixels = match frame { Frame::Pixels(pixels) => pixels, Frame::Texture(_) => panic!("expected CPU pixels") };
    let format = match pixels.format() { PixelFormat::Bgra => PackedFormat::Bgra, PixelFormat::Rgba => PackedFormat::Rgba, other => panic!("unsupported test format: {other:?}") };
    let (width, height) = (pixels.width() as u32, pixels.height() as u32);
    let mut encoder = SoftwareEncoder::new(EncoderConfig { codec: Codec::Vp9, width, height, quality: 1.0, keyframe_interval: Some(30) }).expect("create encoder");
    let encoded = encoder.encode_packed(pixels.data(), pixels.stride()[0], format, 0).expect("encode captured frame");
    let mut decoder = SoftwareDecoder::new(Codec::Vp9).expect("create decoder");
    let decoded = decoder.decode(&encoded).expect("decode frame").expect("decoded image");
    assert_eq!((decoded.width, decoded.height), (width as usize, height as usize));
    assert!(!decoded.data.is_empty());
}
