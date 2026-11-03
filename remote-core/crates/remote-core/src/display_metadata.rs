//! Construct bounded display metadata from an already-enumerated snapshot.
//! Enumeration and screen disclosure still require trusted local consent.
//! Names and indices are not stable identities; scale is unavailable through
//! this capture adapter and is intentionally reported as unknown (zero).
use remote_capture::Display;
use remote_protocol::desktop::{DesktopError, DisplayInfo, PeerInfo, MAX_DISPLAYS};

/// Build the source-style standalone PeerInfo display update. The supplied
/// cursor embedding claim must match the chosen capture backend. This is not
/// an atomic topology snapshot or capability advertisement; caller must
/// re-enumerate/recreate streams after hotplug and obtain permission to send.
pub fn display_update(displays: &[Display], cursor_embedded: bool) -> Result<PeerInfo, DesktopError> {
    if displays.len() > MAX_DISPLAYS { return Err(DesktopError::InvalidMetadata); }
    let mut values = Vec::with_capacity(displays.len());
    for display in displays {
        let info = display.info();
        let width = i32::try_from(info.width).map_err(|_| DesktopError::InvalidMetadata)?;
        let height = i32::try_from(info.height).map_err(|_| DesktopError::InvalidMetadata)?;
        values.push(DisplayInfo { x: info.x, y: info.y, width, height, name: info.name.clone(),
            online: info.online, cursor_embedded, scale: 0.0 });
    }
    let result = PeerInfo { username: String::new(), hostname: String::new(), platform: String::new(), version: String::new(),
        displays: values, current_display: 0, sas_enabled: false, encoding: None };
    result.validate()?; Ok(result)
}

/// Windows-only display update using the pinned source's `update_sync_displays`
/// input-coordinate scale of 1.0. This is a source policy for Windows, not an
/// actual per-monitor DPI measurement. The caller must verify that enumeration,
/// cursor and input coordinates refer to the same desktop/DPI-awareness context;
/// UAC, virtual displays, hotplug and OS scaling remain unverified. Original
/// resolutions and virtual-display platform additions are still omitted.
#[cfg(target_os = "windows")]
pub fn windows_source_display_update(displays: &[Display], cursor_embedded: bool) -> Result<PeerInfo, DesktopError> {
    let mut info = display_update(displays, cursor_embedded)?;
    for display in &mut info.displays { display.scale = 1.0; }
    info.validate()?; Ok(info)
}
