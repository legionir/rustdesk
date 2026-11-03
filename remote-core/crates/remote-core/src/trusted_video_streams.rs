//! Explicitly opted-in, caller-driven multi-display software decoding.
//!
//! Native codec libraries are not sandboxed and compressed data can cause
//! native allocations before dimensions are checked. A pinned host, password,
//! wire-size limit or keyframe flag does not make a bitstream safe. Use ONLY
//! with trusted locally produced input in a controlled environment. This module
//! is not an Internet-facing decoder, renderer, codec negotiator or ACK loop.
//! It has not been built, tested, audited or validated on an interactive desktop.

use crate::{video::{VideoError, VideoReceiver}, video_sync::{Decision, SyncError, VideoSync}};
use remote_codec::Codec;
use remote_protocol::{Envelope, ProtocolError, VideoCodec, MAX_ENVELOPE_BYTES};
use std::{collections::BTreeMap, error::Error, fmt};

const MAX_STREAMS: usize = 8;
const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;

/// Explicit acknowledgment, not a security mechanism. The caller is responsible
/// for determining whether every input is safe to pass to native decoders.
pub struct TrustedOnly(());
impl TrustedOnly { pub fn acknowledge_native_decoder_is_not_safe_for_untrusted_input() -> Self { Self(()) } }
#[derive(Debug)]
pub enum DecodeError { InvalidLimit, InvalidDisplay, Duplicate, Capacity, UnknownDisplay, ResetRequired, Protocol(ProtocolError), Sync(SyncError), Video(VideoError), InvalidOutput }
impl fmt::Display for DecodeError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "trusted video streams: {self:?}") } }
impl Error for DecodeError {}
struct Stream { sync: VideoSync, decoder: Option<VideoReceiver>, codec: Codec }
/// Bounded-copy decoded image. Width/height and format are from the source
/// software decoder; image bytes are owned and independent of future decodes.
pub struct Image { pub display: i32, pub width: usize, pub height: usize, pub pixels: Vec<u8> }
impl fmt::Debug for Image {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Image").field("display", &self.display).field("width", &self.width)
            .field("height", &self.height).field("pixel_bytes", &self.pixels.len()).finish()
    }
}
#[derive(Debug)]
pub enum DecodeResult { AwaitKeyframe { display: i32 }, NoImage { display: i32 }, Image(Image) }
/// Separate decoder and recovery state per approved display; codec and topology
/// changes require explicit removal/re-registration. Neither display IDs nor
/// key flags are authenticated or validated by this structure.
pub struct TrustedVideoStreams { streams: BTreeMap<i32, Stream>, max_input: usize, max_output: usize }
impl TrustedVideoStreams {
    pub fn new(max_input: usize, max_output: usize, _trusted: TrustedOnly) -> Result<Self, DecodeError> {
        if max_input == 0 || max_input > MAX_ENVELOPE_BYTES || max_output == 0 || max_output > MAX_OUTPUT_BYTES { return Err(DecodeError::InvalidLimit); }
        Ok(Self { streams: BTreeMap::new(), max_input, max_output })
    }
    /// Register an explicitly selected source software codec. This initializes a
    /// native decoder and does not establish permission or actual codec support.
    pub fn register(&mut self, display: i32, codec: Codec) -> Result<(), DecodeError> {
        if display < 0 { return Err(DecodeError::InvalidDisplay); }
        if self.streams.contains_key(&display) { return Err(DecodeError::Duplicate); }
        if self.streams.len() >= MAX_STREAMS { return Err(DecodeError::Capacity); }
        let wire_codec = match codec { Codec::Vp8 => VideoCodec::Vp8, Codec::Vp9 => VideoCodec::Vp9, Codec::Av1 => VideoCodec::Av1 };
        let sync = VideoSync::new(display, wire_codec).map_err(DecodeError::Sync)?;
        let decoder = VideoReceiver::new(codec, self.max_input).map_err(DecodeError::Video)?;
        self.streams.insert(display, Stream { sync, decoder: Some(decoder), codec }); Ok(())
    }
    /// Parse and decode one ordered, trusted source video envelope. On decode or
    /// output validation failure the decoder is discarded; explicitly reset and
    /// request a fresh keyframe. Unknown/mismatched streams are not decoded.
    /// If an input is lost or rejected before its display can be identified,
    /// invalidate all streams before any further decode: a predictive frame
    /// may have been skipped. These helpers still accept only trusted local input.
    pub fn decode(&mut self, bytes: &[u8]) -> Result<DecodeResult, DecodeError> {
        let envelope = Envelope::decode(bytes, self.max_input).map_err(DecodeError::Protocol)?;
        let display = envelope.video().map_err(DecodeError::Protocol)?.display;
        let stream = self.streams.get_mut(&display).ok_or(DecodeError::UnknownDisplay)?;
        if stream.decoder.is_none() { return Err(DecodeError::ResetRequired); }
        match stream.sync.begin(&envelope).map_err(DecodeError::Sync)? {
            Decision::AwaitKeyframe => return Ok(DecodeResult::AwaitKeyframe { display }),
            Decision::Decode => {},
        }
        let result = (|| {
            let decoder = stream.decoder.as_mut().ok_or(DecodeError::ResetRequired)?;
            let image = decoder.decode(bytes).map_err(DecodeError::Video)?;
            match image {
                None => Ok(DecodeResult::NoImage { display }),
                Some(image) => {
                    let frame = image.frame;
                    let expected = frame.width.checked_mul(frame.height).and_then(|n| n.checked_mul(4)).ok_or(DecodeError::InvalidOutput)?;
                    if image.display != display || expected == 0 || expected > self.max_output || frame.data.len() != expected { return Err(DecodeError::InvalidOutput); }
                    Ok(DecodeResult::Image(Image { display, width: frame.width, height: frame.height, pixels: frame.data.to_vec() }))
                },
            }
        })();
        match result {
            Ok(result) => { stream.sync.complete(true).map_err(DecodeError::Sync)?; Ok(result) },
            Err(error) => { stream.decoder.take(); stream.sync.reset(); Err(error) },
        }
    }
    /// Drop a registered decoder without constructing a replacement. Use
    /// after a known per-display loss before accepting more data. The caller
    /// must reset it and obtain a new keyframe; native copies or caller-owned
    /// images are not securely erased. Does not grant input or network trust.
    pub fn invalidate(&mut self, display: i32) -> Result<(), DecodeError> {
        let stream = self.streams.get_mut(&display).ok_or(DecodeError::UnknownDisplay)?;
        stream.decoder.take(); stream.sync.reset(); Ok(())
    }
    /// Discard all decoder instances after a loss with unknown stream identity.
    /// Registrations remain so each display can be explicitly reset later.
    /// This does not prove native erasure, coordinate rendering or send refresh.
    pub fn invalidate_all(&mut self) -> usize {
        for stream in self.streams.values_mut() { stream.decoder.take(); stream.sync.reset(); }
        self.streams.len()
    }
    /// Discard and reconstruct a decoder after loss, failure or topology reset.
    /// The next frame must have a wire key flag; request refresh separately.
    pub fn reset(&mut self, display: i32) -> Result<(), DecodeError> {
        let stream = self.streams.get_mut(&display).ok_or(DecodeError::UnknownDisplay)?;
        stream.decoder.take(); stream.sync.reset();
        stream.decoder = Some(VideoReceiver::new(stream.codec, self.max_input).map_err(DecodeError::Video)?);
        Ok(())
    }
    pub fn remove(&mut self, display: i32) -> bool { self.streams.remove(&display).is_some() }
    pub fn len(&self) -> usize { self.streams.len() }
    pub fn is_empty(&self) -> bool { self.streams.is_empty() }
}

#[cfg(test)]
mod redacted_debug_tests {
    use super::*;
    #[test]
    fn decoded_pixels_are_not_printed_by_debug() {
        let image = Image { display: 0, width: 1, height: 1, pixels: vec![101, 102, 103, 104] };
        let result = DecodeResult::Image(image);
        let formatted = format!("{result:?}");
        assert!(formatted.contains("pixel_bytes: 4"));
        assert!(!formatted.contains("101")); assert!(!formatted.contains("104"));
    }
}
