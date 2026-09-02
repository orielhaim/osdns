//! DNS cache flushing. Best-effort only: flushing never defines correctness,
//! and DNS Client (Dnscache) service failures are reported separately from
//! configuration failures.

use crate::capability::BackendKind;
use crate::error::{Error, Result};

// DnsFlushResolverCache is exported by dnsapi.dll but is not part of the
// windows crate metadata, so it is declared here directly.
#[link(name = "dnsapi")]
unsafe extern "system" {
    fn DnsFlushResolverCache() -> u32;
}

pub(crate) fn flush() -> Result<()> {
    // SAFETY: the function takes no parameters and touches no caller memory.
    let result = unsafe { DnsFlushResolverCache() };
    if result != 0 {
        return Err(Error::Platform {
            backend: BackendKind::WindowsIpHelper,
            message: format!(
                "DnsFlushResolverCache failed with win32 error {result} (is the DNS Client service running?)"
            ),
        });
    }
    Ok(())
}
