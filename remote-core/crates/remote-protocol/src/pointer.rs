//! Existing RustDesk PointerDeviceEvent / TouchEvent protobuf variants.
//! These are untrusted wire values, not authorization or evidence of a local
//! touch device. Platform dispatch and lifecycle remain caller responsibilities.
use super::{message, message_proto, Envelope};
use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Touch {
    /// Delta scale multiplied by 1000; zero signals end of the gesture.
    Scale(i32),
    PanStart { x: i32, y: i32 },
    PanUpdate { x: i32, y: i32 },
    PanEnd { x: i32, y: i32 },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerEvent { pub touch: Touch, pub modifiers: Vec<i32> }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerError { Unexpected, Invalid, TooManyModifiers }
impl fmt::Display for PointerError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "pointer event: {self:?}") } }
impl Error for PointerError {}
/// A small adapter bound, not an upstream protobuf or OS limit.
pub const MAX_MODIFIERS: usize = 16;
impl Envelope {
    /// Build an unmodified source pointer gesture. This does not inject input.
    pub fn touch_event(touch: Touch) -> Self {
        let mut event = message_proto::TouchEvent::new();
        match touch {
            Touch::Scale(scale) => event.set_scale_update(message_proto::TouchScaleUpdate { scale, ..Default::default() }),
            Touch::PanStart { x, y } => event.set_pan_start(message_proto::TouchPanStart { x, y, ..Default::default() }),
            Touch::PanUpdate { x, y } => event.set_pan_update(message_proto::TouchPanUpdate { x, y, ..Default::default() }),
            Touch::PanEnd { x, y } => event.set_pan_end(message_proto::TouchPanEnd { x, y, ..Default::default() }),
        }
        let mut pointer = message_proto::PointerDeviceEvent::new(); pointer.set_touch_event(event);
        let mut inner = message_proto::Message::new(); inner.set_pointer_device_event(pointer); Self { inner }
    }
    /// Parse bounded modifier values without interpreting them. Pan variants
    /// are represented even when the Windows source ignores them.
    pub fn pointer_event(&self) -> Result<PointerEvent, PointerError> {
        let pointer = match self.inner.union.as_ref() {
            Some(message::Union::PointerDeviceEvent(event)) => event,
            _ => return Err(PointerError::Unexpected),
        };
        if pointer.modifiers.len() > MAX_MODIFIERS { return Err(PointerError::TooManyModifiers); }
        let touch = match pointer.union.as_ref() {
            Some(message_proto::pointer_device_event::Union::TouchEvent(touch)) => touch,
            _ => return Err(PointerError::Invalid),
        };
        let touch = match touch.union.as_ref() {
            Some(message_proto::touch_event::Union::ScaleUpdate(value)) => Touch::Scale(value.scale),
            Some(message_proto::touch_event::Union::PanStart(value)) => Touch::PanStart { x: value.x, y: value.y },
            Some(message_proto::touch_event::Union::PanUpdate(value)) => Touch::PanUpdate { x: value.x, y: value.y },
            Some(message_proto::touch_event::Union::PanEnd(value)) => Touch::PanEnd { x: value.x, y: value.y },
            _ => return Err(PointerError::Invalid),
        };
        Ok(PointerEvent { touch, modifiers: pointer.modifiers.iter().map(|v| v.value()).collect() })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip_source_touch_variants() {
        for touch in [Touch::Scale(200), Touch::Scale(0), Touch::PanStart { x: -1, y: 2 }, Touch::PanUpdate { x: 4, y: -6 }, Touch::PanEnd { x: 0, y: 0 }] {
            let event = Envelope::touch_event(touch);
            let wire = event.encode(4096).unwrap();
            assert_eq!(Envelope::decode(&wire, 4096).unwrap().pointer_event().unwrap(), PointerEvent { touch, modifiers: vec![] });
        }
    }
}
