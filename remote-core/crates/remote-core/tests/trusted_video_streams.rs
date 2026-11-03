//! Synthetic local codec fixtures, written for execution after extraction.
//! No network, real display or external/untrusted bitstream is used.
use remote_codec::{Codec, EncoderConfig, PackedFormat, SoftwareEncoder};
use remote_core::trusted_video_streams::{DecodeError, DecodeResult, TrustedOnly, TrustedVideoStreams};
use remote_protocol::{Envelope, OwnedVideoPacket, VideoCodec};

fn trusted() -> TrustedOnly { TrustedOnly::acknowledge_native_decoder_is_not_safe_for_untrusted_input() }
fn frame(codec: Codec, display: i32) -> Vec<u8> {
    let cfg = EncoderConfig { codec, width: 64, height: 64, quality: 1.0, keyframe_interval: Some(30) };
    let mut encoder = SoftwareEncoder::new(cfg).unwrap();
    let pixels = vec![128u8; 64 * 64 * 4];
    let encoded = encoder.encode_packed(&pixels, 64 * 4, PackedFormat::Bgra, 1).unwrap();
    let packets: Vec<_> = encoded.packets.into_iter().map(|p| OwnedVideoPacket { data: p.data, key: p.key, pts: p.pts }).collect();
    let codec = match codec { Codec::Vp8 => VideoCodec::Vp8, Codec::Vp9 => VideoCodec::Vp9, Codec::Av1 => VideoCodec::Av1 };
    Envelope::video_event(display, codec, &packets).unwrap().encode(1024 * 1024).unwrap()
}
#[test]
fn independent_local_displays_and_explicit_loss_reset() {
    let mut streams = TrustedVideoStreams::new(1024 * 1024, 64 * 64 * 4, trusted()).unwrap();
    streams.register(0, Codec::Vp9).unwrap(); streams.register(1, Codec::Vp9).unwrap();
    assert!(matches!(streams.register(1, Codec::Vp9), Err(DecodeError::Duplicate)));
    for display in [1, 0] {
        match streams.decode(&frame(Codec::Vp9, display)).unwrap() {
            DecodeResult::Image(image) => { assert_eq!(image.display, display); assert_eq!((image.width, image.height, image.pixels.len()), (64, 64, 64 * 64 * 4)); },
            _ => panic!("local keyframe should produce image"),
        }
    }
    assert!(matches!(streams.invalidate(7), Err(DecodeError::UnknownDisplay)));
    streams.invalidate(0).unwrap();
    assert!(matches!(streams.decode(&frame(Codec::Vp9, 0)), Err(DecodeError::ResetRequired)));
    streams.reset(0).unwrap();
    assert!(matches!(streams.decode(&frame(Codec::Vp9, 0)).unwrap(), DecodeResult::Image(_)));
    assert_eq!(streams.invalidate_all(), 2);
    assert!(matches!(streams.decode(&frame(Codec::Vp9, 0)), Err(DecodeError::ResetRequired)));
    assert!(matches!(streams.decode(&frame(Codec::Vp9, 1)), Err(DecodeError::ResetRequired)));
    streams.reset(0).unwrap();
    assert!(matches!(streams.decode(&frame(Codec::Vp9, 0)).unwrap(), DecodeResult::Image(_)));
    assert!(streams.remove(1)); assert!(!streams.remove(1));
    assert!(matches!(streams.decode(&frame(Codec::Vp9, 1)), Err(DecodeError::UnknownDisplay)));
}
#[test]
fn output_copy_limit_poison_requires_explicit_reset() {
    let mut streams = TrustedVideoStreams::new(1024 * 1024, 1, trusted()).unwrap();
    streams.register(0, Codec::Vp9).unwrap();
    let encoded = frame(Codec::Vp9, 0);
    assert!(matches!(streams.decode(&encoded), Err(DecodeError::InvalidOutput)));
    assert!(matches!(streams.decode(&encoded), Err(DecodeError::ResetRequired)));
    streams.reset(0).unwrap();
    assert!(matches!(streams.decode(&encoded), Err(DecodeError::InvalidOutput)));
}

#[test]
fn bounded_queue_and_local_decoder_coordinate_keyframe_reset() {
    use remote_core::viewer_video_queue::{Completion, PushResult, ViewerVideoQueue};
    let mut streams = TrustedVideoStreams::new(1024 * 1024, 64 * 64 * 4, trusted()).unwrap();
    streams.register(0, Codec::Vp9).unwrap();
    let mut queue = ViewerVideoQueue::new(0, VideoCodec::Vp9, 4, 2 * 1024 * 1024, 1024 * 1024).unwrap();
    let first = frame(Codec::Vp9, 0).into_boxed_slice();
    assert_eq!(queue.push(first).unwrap(), PushResult::Keyframe { discarded: 0 });
    let first = queue.pop().unwrap().unwrap();
    assert!(queue.is_current(first.token));
    assert!(matches!(streams.decode(&first.bytes).unwrap(), DecodeResult::Image(_)));
    assert_eq!(queue.complete(first.token, true).unwrap(), Completion::Applied);
    assert!(queue.synced());
    // A fresh independently produced encoder emits a new keyframe. The queue
    // invalidates older work; caller must reset the actual decoder separately.
    let next = frame(Codec::Vp9, 0).into_boxed_slice();
    assert_eq!(queue.push(next).unwrap(), PushResult::Keyframe { discarded: 0 });
    streams.reset(0).unwrap();
    let next = queue.pop().unwrap().unwrap();
    assert!(matches!(streams.decode(&next.bytes).unwrap(), DecodeResult::Image(_)));
    assert_eq!(queue.complete(next.token, true).unwrap(), Completion::Applied);
    assert_eq!(queue.accounted_bytes(), 0);
}
