//! Manual local Windows observation only: no desktop switch, input, screen
//! capture or network I/O. A comparison is not consent or a security decision.
//! Unbuilt and unrun; use on a disposable interactive desktop with approval.
#[cfg(not(windows))]
fn main() { eprintln!("Windows desktop observation is available only on Windows."); }

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use remote_capture::windows_desktop::compare_current_thread_to_input;
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("--confirm-local-desktop-observation") || args.next().is_some() {
        return Err("obtain local consent and pass --confirm-local-desktop-observation".into());
    }
    // Observe on this OS thread; this says nothing about other threads or
    // processes. No names are printed. Failure must not be interpreted as
    // either a matching or a secure desktop.
    println!("Calling thread/input desktop name relation: {:?}", compare_current_thread_to_input()?);
    Ok(())
}
