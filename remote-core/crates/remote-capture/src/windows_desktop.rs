//! Read-only subset of RustDesk's `inputDesktopSelected` in
//! `src/platform/windows.cc`. This samples only the calling OS thread and
//! compares names. It does not switch desktops, authorize capture/input, detect
//! a secure desktop reliably, or reproduce the source service's UAC behavior.
//! Run on the same OS thread that owns the relevant desktop/capture resources;
//! an async task can migrate between threads. Results can be stale immediately.
use std::{io, mem};
use winapi::{
    shared::{minwindef::FALSE, windef::HDESK},
    um::{processthreadsapi::GetCurrentThreadId, winuser::{CloseDesktop, GetThreadDesktop,
        GetUserObjectInformationW, OpenInputDesktop, DESKTOP_READOBJECTS, UOI_NAME}},
};

const NAME_UNITS: usize = 256;
/// Name equality is not an OS desktop identity, permission, or security proof.
/// Desktop names can recur and there is a race between both observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopRelation { SameName, DifferentName }
struct OwnedDesktop(HDESK);
impl OwnedDesktop {
    fn close(mut self) -> io::Result<()> {
        if unsafe { CloseDesktop(self.0) } == FALSE { return Err(io::Error::last_os_error()); }
        self.0 = std::ptr::null_mut();
        Ok(())
    }
}
impl Drop for OwnedDesktop {
    fn drop(&mut self) { unsafe { if !self.0.is_null() { CloseDesktop(self.0); } } }
}
fn invalid(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, message) }
/// Interpret the bounded UTF-16 buffer without disclosing desktop names.
fn terminated_name(buffer: &[u16]) -> io::Result<&[u16]> {
    let end = buffer.iter().position(|unit| *unit == 0).ok_or_else(|| invalid("unterminated desktop name"))?;
    if end == 0 { return Err(invalid("empty desktop name")); }
    Ok(&buffer[..end])
}
unsafe fn name(handle: HDESK) -> io::Result<[u16; NAME_UNITS]> {
    let mut value = [0u16; NAME_UNITS];
    let mut needed = 0u32;
    let capacity = u32::try_from(mem::size_of_val(&value)).map_err(|_| invalid("desktop name buffer too large"))?;
    if GetUserObjectInformationW(handle as _, UOI_NAME as i32, value.as_mut_ptr() as _, capacity, &mut needed) == FALSE {
        return Err(io::Error::last_os_error());
    }
    if needed == 0 || needed > capacity || needed % 2 != 0 { return Err(invalid("invalid desktop name length")); }
    // Only consider the bytes Windows reported, not zero-filled spare capacity.
    terminated_name(&value[..(needed / 2) as usize])?;
    Ok(value)
}
/// Compare names of the current thread's desktop and the current input desktop.
/// The input handle is opened with read-only access. Successful observations
/// explicitly check CloseDesktop; error paths attempt best-effort Drop cleanup.
/// The borrowed thread-desktop handle is not closed. Access failure is returned as
/// an error, never interpreted as a safe or changed desktop. Equal names do not
/// prove that two handles denote the same object/window station, nor that the
/// input desktop remains selected. No consent or privilege is provided.
/// This Windows-only adapter has not been built, run or security reviewed.
pub fn compare_current_thread_to_input() -> io::Result<DesktopRelation> {
    unsafe {
        let current = GetThreadDesktop(GetCurrentThreadId());
        if current.is_null() { return Err(io::Error::last_os_error()); }
        let input = OwnedDesktop(OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS));
        if input.0.is_null() { return Err(io::Error::last_os_error()); }
        let current_name = name(current)?;
        let input_name = name(input.0)?;
        let relation = if terminated_name(&current_name)? == terminated_name(&input_name)? {
            DesktopRelation::SameName
        } else { DesktopRelation::DifferentName };
        input.close()?;
        Ok(relation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_name_parser_rejects_empty_and_missing_terminator() {
        assert_eq!(terminated_name(&[65, 66, 0, 67]).unwrap(), &[65, 66]);
        assert!(terminated_name(&[0]).is_err());
        assert!(terminated_name(&[65, 66]).is_err());
    }
}
