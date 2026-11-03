//! Source-compatible ordering for two-axis wheel input, with partial failures.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Axis { Vertical, Horizontal }

/// Send nonzero vertical then horizontal deltas once each. A failure stops the
/// sequence; an earlier event may have been delivered and must not be retried.
pub(crate) fn send_scroll<E>(x: i32, y: i32, mut send: impl FnMut(Axis, i32) -> Result<(), E>) -> Result<(), E> {
    if y != 0 { send(Axis::Vertical, y)?; }
    if x != 0 { send(Axis::Horizontal, x)?; }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{send_scroll, Axis};
    #[test]
    fn vertical_precedes_horizontal_and_zero_is_not_sent() {
        let mut events = Vec::new();
        let result: Result<(), ()> = send_scroll(-2, 3, |axis, delta| { events.push((axis, delta)); Ok(()) });
        assert_eq!(result, Ok(()));
        assert_eq!(events, [(Axis::Vertical, 3), (Axis::Horizontal, -2)]);
        events.clear();
        let result: Result<(), ()> = send_scroll(0, 0, |axis, delta| { events.push((axis, delta)); Ok(()) });
        assert_eq!(result, Ok(())); assert!(events.is_empty());
    }
    #[test]
    fn partial_failure_never_retries_or_sends_later_axis() {
        for failing in [Axis::Vertical, Axis::Horizontal] {
            let mut events = Vec::new();
            let result = send_scroll(2, 3, |axis, delta| {
                events.push((axis, delta));
                if axis == failing { Err("uncertain") } else { Ok(()) }
            });
            assert_eq!(result, Err("uncertain"));
            if failing == Axis::Vertical { assert_eq!(events, [(Axis::Vertical, 3)]); }
            else { assert_eq!(events, [(Axis::Vertical, 3), (Axis::Horizontal, 2)]); }
        }
    }
}
