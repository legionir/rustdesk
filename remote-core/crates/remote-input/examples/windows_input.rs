//! Manual test for a disposable, interactive Windows desktop.
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use remote_input::{windows::WindowsInput, InputController, Permissions, VirtualKey};
    if std::env::args().nth(1).as_deref() != Some("--confirm-inject-input") {
        eprintln!("This test injects the A key into the active window. Focus a disposable text editor, then pass --confirm-inject-input.");
        return Ok(());
    }
    let mut input = InputController::new(WindowsInput::new());
    input.set_permissions(Permissions { mouse: false, keyboard: true })?;
    input.key_press(VirtualKey::new(0x41)?)?;
    input.close()?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This example is only available on Windows.");
}
