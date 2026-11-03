//! Check a single-event SendInput result without changing error capture order.

/// Invoke one sender once; call the error producer immediately and only if
/// SendInput reports zero events. This cannot detect a later delivery failure.
pub(crate) fn check_send<E>(send: impl FnOnce() -> u32, error: impl FnOnce() -> E) -> Result<(), E> {
    if send() == 0 { Err(error()) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::check_send;
    use std::cell::Cell;

    #[test]
    fn failure_reads_error_once_and_never_retries_send() {
        let sends = Cell::new(0);
        let reads = Cell::new(0);
        let result = check_send(|| { sends.set(sends.get() + 1); 0 }, || { reads.set(reads.get() + 1); 5 });
        assert_eq!(result, Err(5));
        assert_eq!((sends.get(), reads.get()), (1, 1));
    }

    #[test]
    fn success_does_not_consult_stale_thread_error() {
        let sends = Cell::new(0);
        let result: Result<(), ()> = check_send(|| { sends.set(sends.get() + 1); 1 }, || panic!("stale error queried"));
        assert_eq!(result, Ok(()));
        assert_eq!(sends.get(), 1);
    }
}
