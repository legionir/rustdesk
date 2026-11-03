//! Caller-driven source-style cursor-position echo suppression bookkeeping.
//! Source `input_service::run_pos` excludes the last controlling connection
//! for 300 ms after peer pointer input. This helper neither observes input nor
//! broadcasts cursor positions; all sessions must share one owner and verified,
//! non-reused local IDs. It is not authentication, a privacy boundary, a remote
//! cursor visibility policy or proof that OS input was delivered.
use std::{error::Error, fmt, time::{Duration, Instant}};

pub const SOURCE_ECHO_WINDOW: Duration = Duration::from_millis(300);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoError { InvalidConnection, ClockWentBackwards }
impl fmt::Display for EchoError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "cursor echo: {self:?}") } }
impl Error for EchoError {}
#[derive(Default)]
pub struct CursorEcho { last: Option<(i32, Instant)> }
impl CursorEcho {
    pub fn new() -> Self { Self::default() }
    /// Record one accepted peer-origin pointer action using a positive, unique
    /// local connection ID. Caller decides which actions actually match source;
    /// an input dispatch error does not prove whether the OS saw the input.
    pub fn record(&mut self, connection: i32, now: Instant) -> Result<(), EchoError> {
        if connection <= 0 { return Err(EchoError::InvalidConnection); }
        if self.last.map_or(false, |(_, previous)| now < previous) { return Err(EchoError::ClockWentBackwards); }
        self.last = Some((connection, now)); Ok(())
    }
    /// The last locally recorded connection within the strict 300 ms window,
    /// or None. Other viewers can still receive the cursor position. Checks
    /// only against the last recorded input timestamp, not previous queries;
    /// callers must still supply globally monotonic observations. A new
    /// connection ID must not inherit an old connection's exclusion.
    pub fn excluded(&self, now: Instant) -> Result<Option<i32>, EchoError> {
        let Some((connection, previous)) = self.last else { return Ok(None); };
        let elapsed = now.checked_duration_since(previous).ok_or(EchoError::ClockWentBackwards)?;
        Ok((elapsed < SOURCE_ECHO_WINDOW).then_some(connection))
    }
    /// Clear an old association at disconnect, desktop replacement or shutdown.
    pub fn disconnect(&mut self, connection: i32) -> Result<(), EchoError> {
        if connection <= 0 { return Err(EchoError::InvalidConnection); }
        if self.last.map_or(false, |(last, _)| last == connection) { self.last = None; }
        Ok(())
    }
    pub fn reset(&mut self) { self.last = None; }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn excludes_only_last_controller_and_strict_source_window() {
        let t = Instant::now(); let mut echo = CursorEcho::new();
        assert_eq!(echo.excluded(t), Ok(None));
        echo.record(1, t).unwrap(); assert_eq!(echo.excluded(t + Duration::from_millis(299)), Ok(Some(1)));
        assert_eq!(echo.excluded(t + SOURCE_ECHO_WINDOW), Ok(None));
        echo.record(2, t + Duration::from_millis(1)).unwrap();
        echo.disconnect(1).unwrap(); assert_eq!(echo.excluded(t + Duration::from_millis(1)), Ok(Some(2)));
        echo.disconnect(2).unwrap(); assert_eq!(echo.excluded(t + Duration::from_millis(1)), Ok(None));
    }
    #[test]
    fn rejected_updates_leave_previous_state_intact() {
        let t = Instant::now(); let mut echo = CursorEcho::new(); echo.record(1, t).unwrap();
        assert_eq!(echo.record(0, t), Err(EchoError::InvalidConnection));
        assert_eq!(echo.record(2, t - Duration::from_millis(1)), Err(EchoError::ClockWentBackwards));
        assert_eq!(echo.excluded(t - Duration::from_millis(1)), Err(EchoError::ClockWentBackwards));
        assert_eq!(echo.excluded(t), Ok(Some(1)));
    }
}
