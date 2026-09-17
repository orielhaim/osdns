//! DNS cache flushing. Best-effort only: flushing never defines correctness,
//! and DNS Client (Dnscache) service failures are reported separately from
//! configuration failures.

use crate::error::Result;
use crate::platform::windows::error::map_error;
use windows_result::{Error as WinError, WIN32_ERROR};

// DnsFlushResolverCache is exported by dnsapi.dll but is absent from the
// public Win32 metadata consumed by windows-bindgen 0.100.
windows_link::link!("dnsapi.dll" "system" fn DnsFlushResolverCache() -> i32);

pub(crate) fn flush_succeeded(status: i32) -> bool {
    status != 0
}

pub(crate) fn flush() -> Result<()> {
    // SAFETY: the function takes no parameters and touches no caller memory.
    let status = unsafe { DnsFlushResolverCache() };
    if flush_succeeded(status) {
        return Ok(());
    }
    let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(1) as u32;
    match map_error(WinError::from(WIN32_ERROR(code)), "DnsFlushResolverCache") {
        crate::error::Error::Platform { backend, message } => Err(crate::error::Error::Platform {
            backend,
            message: format!("{message} (is the DNS Client service running?)"),
        }),
        other => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::flush_succeeded;

    #[test]
    fn bool_true_is_success() {
        assert!(flush_succeeded(1));
        assert!(flush_succeeded(-1));
        assert!(!flush_succeeded(0));
    }
}
