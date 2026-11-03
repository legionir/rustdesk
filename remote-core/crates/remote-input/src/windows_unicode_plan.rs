//! Side-effect-free description of the pinned Enigo Windows `key_sequence`.
//! In particular, supplementary scalars produce two down events with no
//! corresponding ups in that source. Do not blindly inject this plan: target
//! applications, OS state, partial SendInput delivery and cleanup need a Windows
//! security/compatibility decision and real desktop tests first.
use std::{error::Error, fmt};

/// Local allocation limit, not a source protocol limit.
pub const MAX_TEXT_BYTES: usize = 4096;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnicodeEvent { Down(u16), Up(u16) }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError { Empty, TooLong, ContainsNul }
impl fmt::Display for PlanError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Unicode plan: {self:?}") } }
impl Error for PlanError {}
/// Reproduce event order, not delivery or security. UTF-8 is guaranteed by
/// `str`. NUL and empty strings are conservatively refused, even though the
/// source does not impose these same constraints. Results contain typed text;
/// callers should avoid logging or retaining them.
pub fn source_windows_sequence(text: &str) -> Result<Vec<UnicodeEvent>, PlanError> {
    if text.is_empty() { return Err(PlanError::Empty); }
    if text.len() > MAX_TEXT_BYTES { return Err(PlanError::TooLong); }
    if text.contains('\0') { return Err(PlanError::ContainsNul); }
    let mut result = Vec::with_capacity(text.len().saturating_mul(2));
    for scalar in text.chars() {
        let mut units = [0; 2];
        let encoded = scalar.encode_utf16(&mut units);
        if encoded.len() == 1 {
            result.push(UnicodeEvent::Down(encoded[0]));
            result.push(UnicodeEvent::Up(encoded[0]));
        } else {
            result.push(UnicodeEvent::Down(encoded[0]));
            result.push(UnicodeEvent::Down(encoded[1]));
        }
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_bmp_and_surrogate_order_without_injection() {
        assert_eq!(source_windows_sequence("A😀").unwrap(), vec![UnicodeEvent::Down(65), UnicodeEvent::Up(65),
            UnicodeEvent::Down(0xd83d), UnicodeEvent::Down(0xde00)]);
        assert_eq!(source_windows_sequence(""), Err(PlanError::Empty));
        assert_eq!(source_windows_sequence("a\0b"), Err(PlanError::ContainsNul));
        assert_eq!(source_windows_sequence(&"x".repeat(MAX_TEXT_BYTES + 1)), Err(PlanError::TooLong));
    }
    #[test]
    fn supplementary_boundaries_are_source_down_only() {
        assert_eq!(source_windows_sequence("\u{10000}\u{10ffff}").unwrap(), vec![
            UnicodeEvent::Down(0xd800), UnicodeEvent::Down(0xdc00),
            UnicodeEvent::Down(0xdbff), UnicodeEvent::Down(0xdfff),
        ]);
        assert_eq!(source_windows_sequence("\u{ffff}").unwrap(), vec![UnicodeEvent::Down(0xffff), UnicodeEvent::Up(0xffff)]);
    }
}
