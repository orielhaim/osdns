#[cfg(feature = "test-util")]
pub(crate) use crate::platform::unix::openresolv::probe_for_test;
pub(crate) use crate::platform::unix::openresolv::{Probe, Resolvconf, probe};

use crate::error::Result;
use crate::normalize::NormalizedConfig;
use crate::platform::linux;
use crate::platform::unix::openresolv::ResolvconfPlatform;

pub(crate) fn new(probe: Probe, owner: &str) -> Resolvconf {
    Resolvconf::new(
        probe,
        owner,
        ResolvconfPlatform {
            resource_prefix: "linux",
            list_interfaces: linux::list_interfaces,
            watch_directory: linux::watch::watch_directories,
            validate_plan,
        },
    )
}

fn validate_plan(_plan: &NormalizedConfig) -> Result<()> {
    Ok(())
}
