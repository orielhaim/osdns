//! DNS cache flushing. Best-effort only: flushing never defines correctness,
//! and DNS Client (Dnscache) service failures are reported separately from
//! configuration failures.

use crate::error::Result;
use crate::platform::windows::error::check_status;

// DnsFlushResolverCache is exported by dnsapi.dll but is absent from the
// public Win32 metadata consumed by windows-bindgen 0.100.
windows_link::link!("dnsapi.dll" "system" fn DnsFlushResolverCache() -> u32);

pub(crate) fn flush() -> Result<()> {
    // SAFETY: the function takes no parameters and touches no caller memory.
    let result = unsafe { DnsFlushResolverCache() };
    check_status(result as i32, "DnsFlushResolverCache").map_err(|error| match error {
        crate::error::Error::Platform { backend, message } => crate::error::Error::Platform {
            backend,
            message: format!("{message} (is the DNS Client service running?)"),
        },
        other => other,
    })
}
