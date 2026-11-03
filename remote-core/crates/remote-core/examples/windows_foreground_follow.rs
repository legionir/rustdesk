//! Manual, read-only Windows foreground/display hint example. No titles,
//! screenshots, input injection, network or display mode changes occur.
//! Obtain informed local consent on a disposable interactive desktop before
//! running. Focus and geometry still disclose private activity. DPI awareness,
//! UAC/secure desktop and hotplug are not validated. Not built or tested.
#[cfg(not(windows))]
fn main() { eprintln!("Foreground follow example is Windows-only."); }

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use remote_core::{display_metadata::windows_source_display_update, window_follow::FocusTracker};
    if std::env::args().nth(1).as_deref() != Some("--confirm-local-foreground-inspection") {
        return Err("obtain local consent and pass --confirm-local-foreground-inspection".into());
    }
    let displays = remote_capture::displays()?;
    let approved = windows_source_display_update(&displays, false)?;
    if approved.displays.len() < 2 { return Err("at least two displays are required".into()); }
    let mut tracker = FocusTracker::new();
    for _ in 0..40 {
        let fresh = remote_capture::displays()?;
        let observed = windows_source_display_update(&fresh, false)?;
        if observed.displays != approved.displays { return Err("topology changed; stop and reauthorize".into()); }
        if let Some(rect) = remote_capture::windows_foreground::foreground_window_rect()? {
            if let Some(display) = tracker.observe(&observed.displays, rect.into())? {
                println!("foreground display changed to snapshot index {display}");
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Ok(())
}
