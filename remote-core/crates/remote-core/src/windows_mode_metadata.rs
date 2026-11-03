//! Read-only conversion of a locally inspected Windows mode snapshot into
//! bounded source wire metadata. Does not authorize disclosure or mutate modes.
//! Enumeration is not atomic or guaranteed complete, even if `truncated=false`.
use remote_capture::windows_resolution::ModeSnapshot;
use remote_protocol::resolution_metadata::{Resolution, MAX_RESOLUTION_ENTRIES};
use std::{collections::BTreeSet, error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsModeMetadataError { Truncated, Invalid, Capacity }
impl fmt::Display for WindowsModeMetadataError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Windows mode metadata: {self:?}") } }
impl Error for WindowsModeMetadataError {}
/// Deduplicate dimensions as source `platform::resolutions` does. This helper
/// sorts dimensions; source preserves native enumeration order, while the mode
/// snapshot itself is already deduplicated/sorted. Reject a locally truncated snapshot, invalid dimensions or excess entries. Absence of
/// truncation does not prove exhaustive Win32 enumeration or stable topology;
/// the owner must independently approve disclosure and revalidate the device.
pub fn supported_modes(snapshot: &ModeSnapshot) -> Result<Vec<Resolution>, WindowsModeMetadataError> {
    if snapshot.truncated { return Err(WindowsModeMetadataError::Truncated); }
    if snapshot.modes.len() > MAX_RESOLUTION_ENTRIES { return Err(WindowsModeMetadataError::Capacity); }
    if !(1..=32768).contains(&snapshot.current.width) || !(1..=32768).contains(&snapshot.current.height) {
        return Err(WindowsModeMetadataError::Invalid);
    }
    let mut dimensions = BTreeSet::new();
    for mode in &snapshot.modes {
        if !(1..=32768).contains(&mode.width) || !(1..=32768).contains(&mode.height) { return Err(WindowsModeMetadataError::Invalid); }
        dimensions.insert((mode.width, mode.height));
    }
    Ok(dimensions.into_iter().map(|(width, height)| Resolution { width: width as i32, height: height as i32 }).collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    use remote_capture::windows_resolution::DisplayMode;
    #[test]
    fn rejects_truncation_and_deduplicates_dimensions() {
        let current = DisplayMode { width: 1920, height: 1080, bits_per_pixel: 32, refresh_hz: 60 };
        let other = DisplayMode { refresh_hz: 144, ..current };
        let smaller = DisplayMode { width: 1280, height: 720, ..current };
        let mut snapshot = ModeSnapshot { current, modes: vec![current, other, smaller], truncated: false };
        assert_eq!(supported_modes(&snapshot).unwrap(), vec![Resolution { width: 1280, height: 720 }, Resolution { width: 1920, height: 1080 }]);
        snapshot.truncated = true; assert_eq!(supported_modes(&snapshot), Err(WindowsModeMetadataError::Truncated));
        snapshot.truncated = false; snapshot.modes[0].width = 0;
        assert_eq!(supported_modes(&snapshot), Err(WindowsModeMetadataError::Invalid));
        snapshot.modes[0] = current; snapshot.current.width = 0;
        assert_eq!(supported_modes(&snapshot), Err(WindowsModeMetadataError::Invalid));
    }
}
