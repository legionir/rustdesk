//! Manual read-only Windows display-mode inspection. Does not change modes.
//! Requires an interactive desktop and explicit local user consent. Device
//! names and mode lists may be stale immediately; no identity is authenticated.
//!
//! Written for later manual execution; this example has not been built/tested.
#[cfg(not(windows))]
fn main() { eprintln!("Windows display mode inspection is unavailable on this platform."); }

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use remote_capture::{displays, windows_resolution::enumerate_modes};
    if std::env::args().nth(1).as_deref() != Some("--confirm-local-display-inspection") {
        return Err("pass --confirm-local-display-inspection only after local consent".into());
    }
    let handles = displays()?;
    if handles.is_empty() || handles.len() > 64 { return Err("invalid display count".into()); }
    let snapshot: Vec<_> = handles.iter().map(|d| d.info().clone()).collect();
    let mut observations = Vec::new();
    for (index, info) in snapshot.iter().enumerate() {
        if !info.online || info.name.is_empty() || snapshot.iter().filter(|d| d.name == info.name).count() != 1 {
            eprintln!("display {index} is offline or ambiguous; skipped"); continue;
        }
        let modes = enumerate_modes(&info.name)?;
        if modes.current.width as usize != info.width || modes.current.height as usize != info.height {
            return Err("display mode changed during inspection".into());
        }
        let wire_modes = remote_core::windows_mode_metadata::supported_modes(&modes)?;
        observations.push((index, &info.name, modes, wire_modes));
    }
    let after: Vec<_> = displays()?.iter().map(|d| d.info().clone()).collect();
    if after != snapshot { return Err("display topology changed during inspection".into()); }
    // This recheck is not atomic; topology and modes may change immediately.
    for (index, name, modes, wire_modes) in observations {
        println!("display {index}: {name:?}, current={}x{}@{}Hz, native modes={}, distinct wire sizes={}",
            modes.current.width, modes.current.height, modes.current.refresh_hz, modes.modes.len(), wire_modes.len());
    }
    Ok(())
}
