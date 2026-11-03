//! Pure formatting for SendInput errors; performs no Windows calls.

/// Format a captured error code and an optional FormatMessageW result.
/// Windows returns a count excluding the terminator; a valid nonzero count
/// must therefore be strictly below the buffer capacity.
pub(crate) fn format_error(code: u32, buffer: &[u16], count: usize) -> String {
    let message = if count > 0 && count < buffer.len() {
        let mut end = count;
        while end > 0 && buffer[end - 1] < u16::from(b' ') { end -= 1; }
        String::from_utf16(&buffer[..end]).ok().filter(|text| !text.is_empty())
    } else {
        None
    };
    match message {
        Some(text) => format!("SendInput failed: {text} (Windows error {code})"),
        None => format!("SendInput failed (Windows error {code}; message unavailable)"),
    }
}

#[cfg(test)]
mod tests {
    use super::format_error;

    #[test]
    fn zero_and_invalid_counts_return_numeric_error() {
        let buffer = [65, 66, 0];
        for count in [0, 3, 4, usize::MAX] {
            assert_eq!(format_error(5, &buffer, count), "SendInput failed (Windows error 5; message unavailable)");
        }
        assert!(format_error(0, &[], 0).contains("Windows error 0"));
    }

    #[test]
    fn normal_and_maximum_fitting_messages_exclude_terminator() {
        let buffer = [65, 66, 67, 0];
        assert_eq!(format_error(5, &buffer, 3), "SendInput failed: ABC (Windows error 5)");
        assert_eq!(format_error(5, &[65, 13, 10, 0], 3), "SendInput failed: A (Windows error 5)");
        assert_eq!(format_error(5, &[65, 32, 0], 2), "SendInput failed: A  (Windows error 5)");
    }

    #[test]
    fn invalid_or_empty_utf16_falls_back_to_error_code() {
        assert!(format_error(7, &[0xD800, 0], 1).contains("message unavailable"));
        assert!(format_error(7, &[10, 13, 0], 2).contains("message unavailable"));
        assert_eq!(format_error(7, &[0xD83D, 0xDE00, 0], 2), "SendInput failed: 😀 (Windows error 7)");
    }
}
