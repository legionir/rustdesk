//! Existing RustDesk SwitchDisplay and CaptureDisplays messages. These are
//! untrusted requests/announcements, not authorization or proof of monitor
//! identity. The caller must validate against a current approved display list.
use crate::{message, message_proto, Envelope};
use std::{error::Error, fmt};

pub const MAX_DISPLAY_ENTRIES: usize = 64;
pub const MAX_DISPLAY_DIMENSION: i32 = 32768;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplaySwitch {
    pub display: u32, pub x: i32, pub y: i32, pub width: i32, pub height: i32, pub cursor_embedded: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureDisplays { pub add: Vec<u32>, pub sub: Vec<u32>, pub set: Vec<u32> }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayControlError { Unexpected, Invalid }
impl fmt::Display for DisplayControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "display control: {self:?}") }
}
impl Error for DisplayControlError {}
fn valid_switch(value: &DisplaySwitch) -> bool {
    value.display <= i32::MAX as u32 && ((value.width == 0 && value.height == 0)
        || ((1..=MAX_DISPLAY_DIMENSION).contains(&value.width) && (1..=MAX_DISPLAY_DIMENSION).contains(&value.height)))
}
fn decode_indices(values: &[i32]) -> Result<Vec<u32>, DisplayControlError> {
    if values.len() > MAX_DISPLAY_ENTRIES || values.iter().any(|value| *value < 0) { return Err(DisplayControlError::Invalid); }
    Ok(values.iter().map(|value| *value as u32).collect())
}
fn encode_indices(values: &[u32]) -> Result<Vec<i32>, DisplayControlError> {
    if values.len() > MAX_DISPLAY_ENTRIES { return Err(DisplayControlError::Invalid); }
    values.iter().map(|value| i32::try_from(*value).map_err(|_| DisplayControlError::Invalid)).collect()
}
impl Envelope {
    /// Construct a source switch request or notice. Zero dimensions mean no
    /// resolution request. Nonzero values must not automatically change the OS.
    pub fn display_switch_event(value: &DisplaySwitch) -> Result<Self, DisplayControlError> {
        if !valid_switch(value) { return Err(DisplayControlError::Invalid); }
        let mut misc = message_proto::Misc::new();
        misc.set_switch_display(message_proto::SwitchDisplay { display: value.display as i32, x: value.x, y: value.y,
            width: value.width, height: value.height, cursor_embedded: value.cursor_embedded, ..Default::default() });
        let mut inner = message_proto::Message::new(); inner.set_misc(misc); Ok(Self { inner })
    }
    /// Read bounded switch fields. Additional source resolution fields are not
    /// represented here; retaining the original envelope preserves them.
    pub fn display_switch(&self) -> Result<DisplaySwitch, DisplayControlError> {
        let value = match self.inner.union.as_ref() {
            Some(message::Union::Misc(misc)) => match misc.union.as_ref() {
                Some(message_proto::misc::Union::SwitchDisplay(value)) => value,
                _ => return Err(DisplayControlError::Unexpected),
            },
            _ => return Err(DisplayControlError::Unexpected),
        };
        if value.display < 0 { return Err(DisplayControlError::Invalid); }
        let result = DisplaySwitch { display: value.display as u32, x: value.x, y: value.y, width: value.width,
            height: value.height, cursor_embedded: value.cursor_embedded };
        if !valid_switch(&result) { return Err(DisplayControlError::Invalid); }
        Ok(result)
    }
    /// Construct the original subscription request. Empty `set` can mean
    /// unsubscribe all; the caller must explicitly handle this sensitive case.
    pub fn capture_displays_event(value: &CaptureDisplays) -> Result<Self, DisplayControlError> {
        let mut misc = message_proto::Misc::new();
        misc.set_capture_displays(message_proto::CaptureDisplays { add: encode_indices(&value.add)?, sub: encode_indices(&value.sub)?, set: encode_indices(&value.set)?, ..Default::default() });
        let mut inner = message_proto::Message::new(); inner.set_misc(misc); Ok(Self { inner })
    }
    /// Read the three existing lists without applying source precedence or
    /// starting capture. Never cast negative indices or treat invalid filtered
    /// input as an empty set (which may unsubscribe everything).
    pub fn capture_displays(&self) -> Result<CaptureDisplays, DisplayControlError> {
        let value = match self.inner.union.as_ref() {
            Some(message::Union::Misc(misc)) => match misc.union.as_ref() {
                Some(message_proto::misc::Union::CaptureDisplays(value)) => value,
                _ => return Err(DisplayControlError::Unexpected),
            },
            _ => return Err(DisplayControlError::Unexpected),
        };
        Ok(CaptureDisplays { add: decode_indices(&value.add)?, sub: decode_indices(&value.sub)?, set: decode_indices(&value.set)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn switch_and_subscriptions_round_trip_without_applying_them() {
        let request = DisplaySwitch { display: 2, x: -1920, y: 0, width: 1920, height: 1080, cursor_embedded: false };
        let wire = Envelope::display_switch_event(&request).unwrap().encode(4096).unwrap();
        assert_eq!(Envelope::decode(&wire, 4096).unwrap().display_switch().unwrap(), request);
        let subscriptions = CaptureDisplays { add: vec![1, 2], sub: vec![], set: vec![] };
        let wire = Envelope::capture_displays_event(&subscriptions).unwrap().encode(4096).unwrap();
        assert_eq!(Envelope::decode(&wire, 4096).unwrap().capture_displays().unwrap(), subscriptions);
        assert!(Envelope::capture_displays_event(&CaptureDisplays { add: vec![u32::MAX], sub: vec![], set: vec![] }).is_err());
        let mut invalid = request; invalid.height = 0; assert!(Envelope::display_switch_event(&invalid).is_err());
    }
}
