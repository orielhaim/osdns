pub(crate) mod direct;
pub(crate) mod watch;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::Arc;

use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;

use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::NormalizedConfig;
use crate::platform::Backend;
use crate::platform::unix::detect::{self, ResolvConfState};
use crate::platform::unix::openresolv::{self as shared_openresolv, ResolvconfPlatform};

pub(crate) fn resource_prefix() -> &'static str {
    std::env::consts::OS
}

pub(crate) fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    let mut interfaces = BTreeMap::<String, (u32, InterfaceFlags)>::new();
    for address in getifaddrs().map_err(std::io::Error::from)? {
        let index = nix::net::if_::if_nametoindex(address.interface_name.as_str())
            .map_err(std::io::Error::from)?;
        interfaces
            .entry(address.interface_name)
            .and_modify(|(_, flags)| *flags |= address.flags)
            .or_insert((index, address.flags));
    }
    Ok(interfaces
        .into_iter()
        .map(|(name, (index, flags))| InterfaceInfo {
            index,
            name: OsString::from(name),
            friendly_name: None,
            guid: None,
            is_up: interface_is_up(flags),
        })
        .collect())
}

fn interface_is_up(flags: InterfaceFlags) -> bool {
    flags.contains(InterfaceFlags::IFF_UP | InterfaceFlags::IFF_RUNNING)
}

pub(crate) fn validate_resolver_limits(plan: &NormalizedConfig) -> Result<()> {
    const MAX_NAMESERVERS: usize = 3;
    const MAX_SEARCH_DOMAINS: usize = 6;
    #[cfg(target_os = "freebsd")]
    const MAX_SEARCH_CHARACTERS: usize = 256;
    #[cfg(target_os = "netbsd")]
    const MAX_SEARCH_CHARACTERS: usize = 1024;
    if plan.nameservers.len() > MAX_NAMESERVERS {
        return Err(Error::invalid_config(format_args!(
            "the BSD libc resolver accepts at most {MAX_NAMESERVERS} nameservers"
        )));
    }
    let search = plan
        .search_domains
        .iter()
        .filter(|domain| !domain.is_root())
        .map(|domain| domain.to_string())
        .collect::<Vec<_>>();
    if search.len() > MAX_SEARCH_DOMAINS {
        return Err(Error::invalid_config(format_args!(
            "the BSD libc resolver accepts at most {MAX_SEARCH_DOMAINS} search domains"
        )));
    }
    let characters = search.iter().map(String::len).sum::<usize>() + search.len().saturating_sub(1);
    if characters > MAX_SEARCH_CHARACTERS {
        return Err(Error::invalid_config(format_args!(
            "the BSD libc resolver accepts at most {MAX_SEARCH_CHARACTERS} search-list characters"
        )));
    }
    Ok(())
}

pub(crate) fn new_resolvconf(owner: &str) -> Result<shared_openresolv::Resolvconf> {
    let probe = shared_openresolv::probe().ok_or_else(|| {
        Error::BackendUnavailable(
            "openresolv owns /etc/resolv.conf, but a verified openresolv backend was not found"
                .to_string(),
        )
    })?;
    Ok(shared_openresolv::Resolvconf::new(
        probe,
        owner,
        ResolvconfPlatform {
            resource_prefix: resource_prefix(),
            list_interfaces,
            watch_directory: watch::watch_directories,
            validate_plan: validate_resolver_limits,
        },
    ))
}

pub(crate) fn select(owner: &str) -> Result<Arc<dyn Backend>> {
    match detect::classify(std::path::Path::new(detect::RESOLV_CONF_PATH)) {
        ResolvConfState::OpenResolv => Ok(Arc::new(new_resolvconf(owner)?)),
        ResolvConfState::Unmanaged | ResolvConfState::Missing => {
            if shared_openresolv::configuration_blocks_direct(std::path::Path::new(
                detect::RESOLV_CONF_PATH,
            )) {
                Err(Error::BackendUnavailable(
                    "an Openresolv configuration is present but cannot be verified; refusing direct resolv.conf mutation"
                        .to_string(),
                ))
            } else {
                Ok(Arc::new(direct::new()))
            }
        }
        ResolvConfState::Foreign => Err(Error::BackendUnavailable(
            "/etc/resolv.conf has an unknown or foreign DNS manager signature".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_up_requires_administrative_and_running_flags() {
        assert!(!interface_is_up(InterfaceFlags::empty()));
        assert!(!interface_is_up(InterfaceFlags::IFF_UP));
        assert!(!interface_is_up(InterfaceFlags::IFF_RUNNING));
        assert!(interface_is_up(
            InterfaceFlags::IFF_UP | InterfaceFlags::IFF_RUNNING
        ));
    }
}
