//! Machine-wide ProgramData resolution for the global lock namespace.

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::platform::windows::error::check_hresult;
use crate::platform::windows::ffi::{
    self, CSIDL_COMMON_APPDATA, FOLDERID_PROGRAM_DATA, HANDLE, HWND, KF_FLAG_DEFAULT, MAX_PATH,
    PWSTR, wide_to_path,
};

/// Resolves the machine ProgramData directory.
///
/// Prefers `SHGetKnownFolderPath(FOLDERID_ProgramData)`. If that fails (some
/// restricted hosts return `ERROR_FILE_NOT_FOUND` for known-folder ids), falls
/// back to `SHGetFolderPathW(CSIDL_COMMON_APPDATA)`. Never reads environment
/// variables, which can silently convert the global lock namespace into a
/// per-user path.
pub(crate) fn program_data_dir() -> Result<PathBuf> {
    match known_folder_program_data() {
        Ok(path) => Ok(path),
        Err(known_error) => match sh_get_folder_program_data() {
            Ok(path) => Ok(path),
            Err(folder_error) => Err(Error::RequiresPrivilege(format!(
                "cannot resolve the machine ProgramData folder for the global lock namespace: known-folder={known_error}; csidl={folder_error}"
            ))),
        },
    }
}

fn known_folder_program_data() -> Result<PathBuf> {
    let mut path_ptr: PWSTR = std::ptr::null_mut();
    // SAFETY: known-folder id is static; output is CoTaskMem-owned and freed below.
    let status = unsafe {
        ffi::SHGetKnownFolderPath(
            &FOLDERID_PROGRAM_DATA,
            KF_FLAG_DEFAULT,
            std::ptr::null_mut::<core::ffi::c_void>() as HANDLE,
            &mut path_ptr,
        )
    };
    if let Err(error) = check_hresult(status, "SHGetKnownFolderPath(ProgramData)") {
        free_known_folder(path_ptr);
        return Err(error);
    }
    if path_ptr.is_null() {
        return Err(Error::RequiresPrivilege(
            "SHGetKnownFolderPath returned a null ProgramData path".to_string(),
        ));
    }
    // SAFETY: non-null path from SHGetKnownFolderPath.
    let path = unsafe { wide_to_path(path_ptr) };
    free_known_folder(path_ptr);
    if path.as_os_str().is_empty() {
        return Err(Error::RequiresPrivilege(
            "the machine ProgramData folder resolved empty; refusing a per-user lock namespace"
                .to_string(),
        ));
    }
    Ok(path)
}

fn sh_get_folder_program_data() -> Result<PathBuf> {
    let mut buffer = vec![0u16; MAX_PATH as usize + 1];
    // SAFETY: buffer is writable MAX_PATH+NUL wide storage for the API.
    let status = unsafe {
        ffi::SHGetFolderPathW(
            std::ptr::null_mut::<core::ffi::c_void>() as HWND,
            CSIDL_COMMON_APPDATA,
            std::ptr::null_mut::<core::ffi::c_void>() as HANDLE,
            0,
            buffer.as_mut_ptr(),
        )
    };
    check_hresult(status, "SHGetFolderPathW(CSIDL_COMMON_APPDATA)")?;
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    let path = PathBuf::from(String::from_utf16_lossy(&buffer[..len]));
    if path.as_os_str().is_empty() {
        return Err(Error::RequiresPrivilege(
            "the machine ProgramData folder resolved empty; refusing a per-user lock namespace"
                .to_string(),
        ));
    }
    Ok(path)
}

fn free_known_folder(pointer: PWSTR) {
    if !pointer.is_null() {
        // SAFETY: pointer came from SHGetKnownFolderPath / CoTaskMemAlloc.
        unsafe { ffi::CoTaskMemFree(pointer.cast()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_data_resolves_non_empty() {
        let path = program_data_dir().unwrap();
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn program_data_ignores_env_overrides() {
        let original_programdata = std::env::var_os("PROGRAMDATA");
        let original_local = std::env::var_os("LOCALAPPDATA");
        // SAFETY: this test owns the process env for its duration and restores it.
        unsafe {
            std::env::set_var("PROGRAMDATA", r"C:\osdns-test-programdata-not-real");
            std::env::set_var("LOCALAPPDATA", r"C:\osdns-test-localappdata-not-real");
        }
        let path = program_data_dir();
        // SAFETY: restore previous values.
        unsafe {
            match original_programdata {
                Some(value) => std::env::set_var("PROGRAMDATA", value),
                None => std::env::remove_var("PROGRAMDATA"),
            }
            match original_local {
                Some(value) => std::env::set_var("LOCALAPPDATA", value),
                None => std::env::remove_var("LOCALAPPDATA"),
            }
        }
        let path = path.unwrap();
        assert!(!path.starts_with(r"C:\osdns-test-programdata-not-real"));
        assert!(!path.starts_with(r"C:\osdns-test-localappdata-not-real"));
    }
}
