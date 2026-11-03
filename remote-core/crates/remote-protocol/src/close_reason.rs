//! Source `Misc.CloseReason`, a peer-controlled diagnostic, not an identity.
use crate::{message, message_proto, Envelope};
use std::{error::Error, fmt};

/// Local bound, not an upstream protocol limit. Text is untrusted; escape it
/// before displaying or logging and never interpret it as a policy decision.
pub const MAX_REASON_BYTES: usize = 512;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReasonError { Unexpected, TooLong }
impl fmt::Display for CloseReasonError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "close reason: {self:?}") } }
impl Error for CloseReasonError {}
impl Envelope {
    pub fn close_reason_event(reason: &str) -> Result<Self, CloseReasonError> {
        if reason.len() > MAX_REASON_BYTES { return Err(CloseReasonError::TooLong); }
        let mut misc = message_proto::Misc::new(); misc.set_close_reason(reason.to_owned());
        let mut inner = message_proto::Message::new(); inner.set_misc(misc); Ok(Self { inner })
    }
    pub fn close_reason(&self) -> Result<&str, CloseReasonError> {
        let reason = match self.inner.union.as_ref() {
            Some(message::Union::Misc(misc)) => match misc.union.as_ref() {
                Some(message_proto::misc::Union::CloseReason(reason)) => reason.as_str(),
                _ => return Err(CloseReasonError::Unexpected),
            }, _ => return Err(CloseReasonError::Unexpected),
        };
        if reason.len() > MAX_REASON_BYTES { return Err(CloseReasonError::TooLong); }
        Ok(reason)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_source_roundtrip() {
        for text in ["", "Closed by peer", "متوقف"] {
            let msg = Envelope::close_reason_event(text).unwrap().encode(4096).unwrap();
            assert_eq!(Envelope::decode(&msg, 4096).unwrap().close_reason().unwrap(), text);
        }
        assert_eq!(Envelope::close_reason_event(&"x".repeat(MAX_REASON_BYTES + 1)).err(), Some(CloseReasonError::TooLong));
    }
}
