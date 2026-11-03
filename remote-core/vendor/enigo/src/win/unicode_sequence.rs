//! Source-compatible Unicode event ordering with explicit partial failure.

/// Emit the pinned source's UTF-16 event order without allocating a copy of the
/// text. `is_up` is false for downs. BMP units have down/up; supplementary
/// scalars have two downs and no ups, matching the source's documented risk.
/// Stop at the first error without retry or implicit release. Successful events
/// may already have affected an application; callers must not retry blindly.
pub(crate) fn send_sequence<E>(text: &str, mut send: impl FnMut(u16, bool) -> Result<(), E>) -> Result<(), E> {
    for scalar in text.chars() {
        let mut buffer = [0u16; 2];
        let encoded = scalar.encode_utf16(&mut buffer);
        if encoded.len() == 1 {
            send(encoded[0], false)?;
            send(encoded[0], true)?;
        } else {
            send(encoded[0], false)?;
            send(encoded[1], false)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::send_sequence;

    #[test]
    fn preserves_source_bmp_and_supplementary_order() {
        let mut events = Vec::new();
        let result: Result<(), ()> = send_sequence("A😀B", |unit, up| { events.push((unit, up)); Ok(()) });
        assert_eq!(result, Ok(()));
        assert_eq!(events, [(65, false), (65, true), (0xD83D, false), (0xDE00, false), (66, false), (66, true)]);
    }

    #[test]
    fn failure_at_any_stage_stops_without_retry() {
        let expected = [(65, false), (65, true), (0xD83D, false), (0xDE00, false), (66, false), (66, true)];
        for failure in 0..expected.len() {
            let mut events = Vec::new();
            let result = send_sequence("A😀B", |unit, up| {
                events.push((unit, up));
                if events.len() - 1 == failure { Err("uncertain") } else { Ok(()) }
            });
            assert_eq!(result, Err("uncertain"));
            assert_eq!(events, expected[..=failure]);
        }
    }
}
