//! Bounds-checked Windows error formatting, with pure decoding helpers.

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

/// Capture the thread's last OS error immediately, then format it using a
/// bounded initialized buffer. A failure or malformed message still returns
/// the numeric code. This function performs no input injection.
#[cfg(windows)]
pub(crate) fn last_input_error() -> String {
    use winapi::um::winbase::{FormatMessageW, FORMAT_MESSAGE_ARGUMENT_ARRAY,
        FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS};
    extern "system" { fn GetLastError() -> u32; }
    // No allocations or intervening OS calls before reading the thread error.
    let code = unsafe { GetLastError() };
    let mut buffer = [0u16; 256];
    let count = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY,
            std::ptr::null(), code, 0, buffer.as_mut_ptr(), buffer.len() as u32,
            std::ptr::null_mut(),
        )
    };
    format_error(code, &buffer, count as usize)
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
    #[cfg(windows)]
    #[test]
    fn native_system_error_is_captured_and_formatted_without_input() {
        extern "system" { fn SetLastError(code: u32); }
        // ERROR_ACCESS_DENIED is a stable numeric Windows system error. Do
        // not assert localized system message text or foreground desktop state.
        unsafe { SetLastError(5); }
        let text = super::last_input_error();
        assert!(text.starts_with("SendInput failed"));
        assert!(text.contains("Windows error 5"), "{text}");

        // Unknown codes must still be surfaced when FormatMessageW fails.
        unsafe { SetLastError(0xEFFFFFFF); }
        let text = super::last_input_error();
        assert!(text.contains("Windows error 4026531839"), "{text}");
    }

    #[cfg(windows)]
    #[test]
    fn native_format_message_respects_supplied_buffer_capacity() {
        use winapi::um::winbase::{FormatMessageW, FORMAT_MESSAGE_FROM_STRING, FORMAT_MESSAGE_IGNORE_INSERTS};
        use std::ffi::c_void;
        for (message, expected_count) in [("1234567", 7), ("12345678", 0)] {
            let source: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
            let mut guarded = [0xBEEFu16; 10];
            let count = unsafe {
                FormatMessageW(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_IGNORE_INSERTS,
                    source.as_ptr() as *const c_void, 0, 0, guarded.as_mut_ptr().add(1), 8,
                    std::ptr::null_mut())
            };
            assert_eq!(count, expected_count);
            assert_eq!(guarded[0], 0xBEEF);
            assert_eq!(guarded[9], 0xBEEF);
            if count > 0 {
                assert_eq!(&guarded[1..8], &source[..7]);
                assert_eq!(guarded[8], 0);
            }
        }
    }

}
