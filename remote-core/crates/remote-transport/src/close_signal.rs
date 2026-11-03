//! Sticky local close-request signal for owner-controlled asynchronous work.
//!
//! This is only a wakeup/bookkeeping primitive. It does not close a transport,
//! authenticate anyone, interrupt synchronous native code, or prove that an
//! in-flight message was not delivered. After an ambiguous cancellation the
//! caller must close/drop the affected connection rather than retry it.
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

/// A one-way signal. A fresh connection requires a fresh instance.
#[derive(Default)]
pub struct CloseSignal { requested: AtomicBool, notify: Notify }
impl CloseSignal {
    pub fn new() -> Self { Self::default() }
    /// Mark permanently requested and wake registered waiters. `true` means
    /// this call changed local state; it is not an acknowledgement of cleanup.
    pub fn request(&self) -> bool {
        let changed = !self.requested.swap(true, Ordering::AcqRel);
        self.notify.notify_waiters();
        changed
    }
    pub fn is_requested(&self) -> bool { self.requested.load(Ordering::Acquire) }
    /// Resolve once requested, including when requested before registration.
    /// Register before rechecking the flag so a racing `notify_waiters` is not
    /// lost. Dropping this waiter does not consume or reset the signal.
    pub async fn wait(&self) {
        if self.is_requested() { return; }
        let notification = self.notify.notified();
        tokio::pin!(notification);
        notification.as_mut().enable();
        if self.is_requested() { return; }
        notification.await;
    }
    /// Race a future against this signal, preferring an already-observed close.
    /// `None` drops the in-flight future and is not proof that I/O was unsent.
    /// A request can race a `Some` result; callers must check again and close
    /// the connection before reuse when delivery or ownership is uncertain.
    pub async fn race<F: std::future::Future>(&self, future: F) -> Option<F::Output> {
        tokio::select! { biased; _ = self.wait() => None, result = future => Some(result) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, sync::Arc, task::{Context, Poll, Wake, Waker}};
    struct Noop;
    impl Wake for Noop { fn wake(self: Arc<Self>) {} }
    #[test]
    fn request_wakes_all_and_remains_sticky() {
        let signal = CloseSignal::new();
        let waker = Waker::from(Arc::new(Noop)); let mut cx = Context::from_waker(&waker);
        let mut first = Box::pin(signal.wait()); let mut second = Box::pin(signal.wait());
        assert!(matches!(first.as_mut().poll(&mut cx), Poll::Pending));
        assert!(matches!(second.as_mut().poll(&mut cx), Poll::Pending));
        assert!(signal.request()); assert!(!signal.request()); assert!(signal.is_requested());
        assert!(matches!(first.as_mut().poll(&mut cx), Poll::Ready(())));
        assert!(matches!(second.as_mut().poll(&mut cx), Poll::Ready(())));
        let mut late = Box::pin(signal.wait());
        assert!(matches!(late.as_mut().poll(&mut cx), Poll::Ready(())));
    }
    #[test]
    fn race_cancels_pending_future_and_prefers_sticky_close() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped { fn drop(&mut self) { self.0.store(true, Ordering::Release); } }
        let signal = CloseSignal::new(); let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(dropped.clone());
        let mut race = Box::pin(signal.race(async move { let _guard = guard; std::future::pending::<()>().await }));
        let waker = Waker::from(Arc::new(Noop)); let mut cx = Context::from_waker(&waker);
        assert!(matches!(race.as_mut().poll(&mut cx), Poll::Pending));
        signal.request();
        assert!(matches!(race.as_mut().poll(&mut cx), Poll::Ready(None)));
        assert!(dropped.load(Ordering::Acquire));
        let mut ready = Box::pin(signal.race(async { 7 }));
        assert!(matches!(ready.as_mut().poll(&mut cx), Poll::Ready(None)));
    }
    #[test]
    fn dropped_waiter_does_not_consume_a_request() {
        let signal = CloseSignal::new();
        let waker = Waker::from(Arc::new(Noop)); let mut cx = Context::from_waker(&waker);
        let mut abandoned = Box::pin(signal.wait());
        assert!(matches!(abandoned.as_mut().poll(&mut cx), Poll::Pending));
        drop(abandoned); signal.request();
        let mut later = Box::pin(signal.wait());
        assert!(matches!(later.as_mut().poll(&mut cx), Poll::Ready(())));
    }
}
