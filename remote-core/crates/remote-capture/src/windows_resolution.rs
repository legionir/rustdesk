//! Read-only Windows display-mode enumeration, adapted from
//! `src/platform/windows.rs::{resolutions,current_resolution}` at the pinned
//! baseline. This module deliberately performs no resolution change.
//!
//! Device names are volatile and can be reused after hotplug or desktop
//! switching; monitor enumeration and mode queries are not an atomic snapshot.
//! Returned dimensions/refresh rates are OS claims, not guaranteed usable
//! capture modes. The caller must obtain consent before exposing topology and
//! revalidate it immediately before any separately authorized operation.
use std::{collections::BTreeSet, io, mem};
use winapi::{shared::minwindef::FALSE, um::{wingdi::DEVMODEW, winuser::{EnumDisplaySettingsW, ENUM_CURRENT_SETTINGS}}};

/// Local cap on the number of native mode records inspected, not an upstream cap.
pub const MAX_MODE_RECORDS: u32 = 512;
/// One Windows device mode. Source `resolutions` deduplicates by width/height;
/// this adapter also retains bit depth and refresh rate for local inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DisplayMode { pub width: u32, pub height: u32, pub bits_per_pixel: u32, pub refresh_hz: u32 }
#[derive(Debug, Clone)]
pub struct ModeSnapshot { pub current: DisplayMode, pub modes: Vec<DisplayMode>, pub truncated: bool }
fn invalid(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidInput, message) }
fn device_name(name: &str) -> io::Result<Vec<u16>> {
    // DEVMODEW device names have 32 UTF-16 code units including NUL. Unlike
    // the source helper, refuse truncation which could select another device.
    // scrap::common::dxgi::Display::name uses lossy UTF-16 conversion. Refuse
    // replacement characters rather than querying a potentially different name.
    if name.is_empty() || name.contains('\u{fffd}') || name.chars().any(char::is_control) { return Err(invalid("invalid or lossy device name")); }
    let mut value: Vec<u16> = name.encode_utf16().collect();
    if value.len() >= 32 || value.contains(&0) { return Err(invalid("device name exceeds Windows limit")); }
    value.push(0); Ok(value)
}
fn mode(dm: &DEVMODEW) -> io::Result<DisplayMode> {
    if dm.dmPelsWidth == 0 || dm.dmPelsHeight == 0 || dm.dmPelsWidth > 32768 || dm.dmPelsHeight > 32768 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid display dimensions"));
    }
    Ok(DisplayMode { width: dm.dmPelsWidth, height: dm.dmPelsHeight, bits_per_pixel: dm.dmBitsPerPel, refresh_hz: dm.dmDisplayFrequency })
}
fn query(device: &[u16], index: u32) -> Option<DEVMODEW> {
    // DEVMODEW is a Win32 C POD. `dmSize` must be initialized for each call.
    let mut dm: DEVMODEW = unsafe { mem::zeroed() };
    dm.dmSize = mem::size_of::<DEVMODEW>() as u16;
    let result = unsafe { EnumDisplaySettingsW(device.as_ptr(), index, &mut dm) };
    (result != FALSE).then_some(dm)
}
/// Enumerate the current mode and a locally bounded set of device modes.
/// No OS setting is changed and no capture handle is acquired. Win32 uses the
/// same zero result for end-of-enumeration and some failures; `truncated` only
/// indicates the local cap, not proof that enumeration was exhaustive.
pub fn enumerate_modes(name: &str) -> io::Result<ModeSnapshot> {
    let device = device_name(name)?;
    let current = mode(&query(&device, ENUM_CURRENT_SETTINGS).ok_or_else(|| io::Error::last_os_error())?)?;
    let mut modes = BTreeSet::new();
    for index in 0..MAX_MODE_RECORDS {
        let Some(entry) = query(&device, index) else { return Ok(ModeSnapshot { current, modes: modes.into_iter().collect(), truncated: false }); };
        modes.insert(mode(&entry)?);
    }
    Ok(ModeSnapshot { current, modes: modes.into_iter().collect(), truncated: query(&device, MAX_MODE_RECORDS).is_some() })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_and_truncated_device_names_without_os_calls() {
        assert!(device_name("").is_err()); assert!(device_name("a\0b").is_err());
        assert!(device_name("\u{fffd}").is_err());
        assert!(device_name(&"a".repeat(32)).is_err());
        assert!(device_name("\\\\.\\DISPLAY1").is_ok());
    }
}
