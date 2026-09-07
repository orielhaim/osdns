pub(crate) mod detect;
pub(crate) mod direct;
pub(crate) mod network_manager;
pub(crate) mod resolvconf;
pub(crate) mod resolved;
mod route;
pub(crate) mod watch;

use std::path::PathBuf;

use crate::config::DnsScope;
use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;

pub(crate) const SYS_CLASS_NET: &str = "/sys/class/net";
pub(crate) const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

pub(crate) fn interface_names() -> Result<Vec<String>> {
    let mut names = Vec::new();
    let entries = std::fs::read_dir(SYS_CLASS_NET)?;
    for entry in entries {
        let entry = entry?;
        names.push(entry.file_name().to_string_lossy().to_string());
    }
    names.sort();
    Ok(names)
}

pub(crate) fn ifindex_for_name(name: &str) -> Result<u32> {
    let path = PathBuf::from(SYS_CLASS_NET).join(name).join("ifindex");
    let text = std::fs::read_to_string(&path)
        .map_err(|_| Error::invalid_config(format_args!("interface {name:?} does not exist")))?;
    text.trim().parse::<u32>().map_err(|_| {
        Error::platform(
            crate::capability::BackendKind::SystemdResolved,
            format_args!("unparseable ifindex for {name:?}"),
        )
    })
}

pub(crate) fn name_for_ifindex(ifindex: u32) -> Result<String> {
    for name in interface_names()? {
        if matches!(ifindex_for_name(&name), Ok(found) if found == ifindex) {
            return Ok(name);
        }
    }
    Err(Error::invalid_config(format_args!(
        "interface with index {ifindex} does not exist"
    )))
}

pub(crate) fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    let mut out = Vec::new();
    for name in interface_names()? {
        let index = match ifindex_for_name(&name) {
            Ok(index) => index,
            Err(_) => continue,
        };
        let operstate =
            std::fs::read_to_string(PathBuf::from(SYS_CLASS_NET).join(&name).join("operstate"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
        out.push(InterfaceInfo {
            index,
            name: name.into(),
            friendly_name: None,
            guid: None,
            is_up: operstate == "up" || operstate == "unknown",
        });
    }
    Ok(out)
}

pub(crate) fn default_route_ifindex() -> Result<u32> {
    route::default_interface()
}

pub(crate) fn resolve_interface_selector(scope: &DnsScope) -> Result<(u32, String)> {
    match scope {
        DnsScope::Global => unreachable!("global scope handled by caller"),
        DnsScope::Interface(selector) => match selector {
            crate::config::InterfaceSelector::Default => {
                let index = default_route_ifindex()?;
                let name = name_for_ifindex(index)?;
                Ok((index, name))
            }
            crate::config::InterfaceSelector::Index(index) => {
                let name = name_for_ifindex(*index)?;
                Ok((*index, name))
            }
            crate::config::InterfaceSelector::Name(name) => {
                let name = name.to_string_lossy().to_string();
                let index = ifindex_for_name(&name)?;
                Ok((index, name))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_route_lookup_returns_a_live_interface() {
        let index = default_route_ifindex().unwrap();
        let name = name_for_ifindex(index).unwrap();
        assert_eq!(ifindex_for_name(&name).unwrap(), index);
    }
}
