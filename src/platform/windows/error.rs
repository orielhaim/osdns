//! Structured Windows status → osdns [`Error`] translation.
//!
//! Prefer Win32 / NTSTATUS / HRESULT numeric codes and `std::io::ErrorKind`.
//! Never classify failures by scanning Display text.

use std::io::{Error as IoError, ErrorKind};

use windows_result::{Error as WinError, HRESULT, NTSTATUS, WIN32_ERROR};

use crate::capability::BackendKind;
use crate::error::{Error, Result};

use super::ffi::ERROR_FILE_NOT_FOUND;

/// Success is `0` for Win32, LSTATUS, and the IP Helper APIs typed as NTSTATUS.
///
/// Learn documents several IP Helper calls as returning `NO_ERROR`. Real builds
/// still surface classic Win32 values such as `ERROR_ACCESS_DENIED` (5), so
/// small codes are mapped as Win32 and only large values use NTSTATUS.
pub(crate) fn check_status(status: i32, operation: &str) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(from_status(status, operation))
    }
}

pub(crate) fn check_hresult(status: i32, operation: &str) -> Result<()> {
    let hr = HRESULT(status);
    if hr.is_ok() {
        Ok(())
    } else {
        Err(map_error(WinError::from_hresult(hr), operation))
    }
}

pub(crate) fn from_status(status: i32, operation: &str) -> Error {
    if (0..0x1_0000).contains(&status) {
        map_error(WinError::from(WIN32_ERROR(status as u32)), operation)
    } else {
        map_error(WinError::from(NTSTATUS(status)), operation)
    }
}

pub(crate) fn map_error(error: WinError, operation: &str) -> Error {
    let io = IoError::from(error.clone());
    match io.kind() {
        ErrorKind::PermissionDenied => Error::RequiresPrivilege(format!(
            "{operation} requires administrator privileges (windows status {})",
            format_status(&error)
        )),
        ErrorKind::NotFound => Error::Platform {
            backend: BackendKind::WindowsIpHelper,
            message: format!(
                "{operation} not found (windows status {})",
                format_status(&error)
            ),
        },
        _ => Error::Platform {
            backend: BackendKind::WindowsIpHelper,
            message: format!(
                "{operation} failed with windows status {} ({})",
                format_status(&error),
                io
            ),
        },
    }
}

pub(crate) fn registry_not_found(error: &WinError) -> bool {
    IoError::from(error.clone()).kind() == ErrorKind::NotFound
        || win32_code(error) == Some(ERROR_FILE_NOT_FOUND as u32)
}

fn format_status(error: &WinError) -> String {
    if let Some(code) = win32_code(error) {
        format!("0x{:08X} / win32 {code}", error.code().0 as u32)
    } else {
        format!("0x{:08X}", error.code().0 as u32)
    }
}

fn win32_code(error: &WinError) -> Option<u32> {
    let hr = error.code().0 as u32;
    // HRESULT_FROM_WIN32 packs facility Win32 as 0x8007xxxx.
    if hr & 0xFFFF_0000 == 0x8007_0000 {
        return Some(hr & 0xFFFF);
    }
    if hr < 0x1_0000 {
        return Some(hr);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::windows::ffi::ERROR_ACCESS_DENIED;

    #[test]
    fn access_denied_is_privilege_without_string_matching() {
        let error = from_status(ERROR_ACCESS_DENIED, "SetInterfaceDnsSettings");
        assert!(matches!(error, Error::RequiresPrivilege(_)));
        let Error::RequiresPrivilege(message) = error else {
            unreachable!();
        };
        assert!(message.contains("0x"), "{message}");
        assert!(message.contains("privileges"), "{message}");
    }

    #[test]
    fn file_not_found_kind_is_detectable() {
        let error = WinError::from(WIN32_ERROR(ERROR_FILE_NOT_FOUND as u32));
        assert!(registry_not_found(&error));
    }

    #[test]
    fn success_codes_pass() {
        check_status(0, "x").unwrap();
        check_hresult(0, "x").unwrap();
    }
}
