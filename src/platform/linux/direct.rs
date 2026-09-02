use serde::{Deserialize, Serialize};

use crate::capability::{BackendKind, Capabilities};
use crate::config::{DnsConfig, DnsScope};
use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::NormalizedConfig;
use crate::ownership::ResourceId;
use crate::platform::linux;
use crate::platform::text_config::{build_resolv_conf_content, parse_resolv_conf_content};
use crate::platform::{ApplyReceipt, Backend, PlatformSnapshot};
use crate::watch::{WatchCallback, WatchHandle};

const RESOLV_CONF: &str = linux::RESOLV_CONF_PATH;

fn capabilities() -> Capabilities {
    Capabilities::new(BackendKind::ResolvConfFile)
        .with_read(true)
        .with_global_dns(true)
        .with_per_interface_dns(false)
        .with_search_domains(true)
        .with_split_dns(false)
        .with_watch(true)
        .with_cache_flush(false)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DirectSnapshot {
    pub(crate) content: Option<Vec<u8>>,
    #[cfg(unix)]
    pub(crate) mode: Option<u32>,
    #[cfg(not(unix))]
    pub(crate) mode: Option<()>,
}

/// Direct `/etc/resolv.conf` backend: the last resort, used only when no
/// manager owns the file.
///
/// The whole file content is the managed resource. That is deliberately
/// conservative: any byte change made by another actor while a lease is held
/// is an external modification and is never overwritten. The written content
/// is a deterministic function of the desired configuration, so read-back
/// verification and journal recovery compare exact bytes.
pub(crate) struct DirectResolvConf {
    caps: Capabilities,
}

impl DirectResolvConf {
    pub(crate) fn new() -> Self {
        Self {
            caps: capabilities(),
        }
    }

    fn check_usable(path: &std::path::Path) -> Result<()> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if metadata.is_symlink() {
            let target = std::fs::read_link(path)
                .map(|t| t.to_string_lossy().to_string())
                .unwrap_or_default();
            if target.contains("systemd/resolve") {
                return Err(Error::unsupported(
                    BackendKind::ResolvConfFile,
                    "/etc/resolv.conf is managed by systemd-resolved",
                ));
            }
            if target.contains("NetworkManager") {
                return Err(Error::unsupported(
                    BackendKind::ResolvConfFile,
                    "/etc/resolv.conf is managed by NetworkManager",
                ));
            }
            if target.contains("resolvconf") {
                return Err(Error::unsupported(
                    BackendKind::ResolvConfFile,
                    "/etc/resolv.conf is managed by resolvconf",
                ));
            }
            return Err(Error::unsupported(
                BackendKind::ResolvConfFile,
                format_args!("refusing to replace the symlink /etc/resolv.conf -> {target}"),
            ));
        }
        Ok(())
    }

    fn write_content(path: &std::path::Path, content: &[u8], mode: Option<u32>) -> Result<()> {
        let mut file = atomic_write_file::AtomicWriteFile::open(path)?;
        std::io::Write::write_all(&mut file, content)?;
        file.sync_all()?;
        file.commit()?;
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        }
        Ok(())
    }

    fn current_mode(path: &std::path::Path) -> Option<u32> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path).ok().map(|m| m.permissions().mode())
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            None
        }
    }

    fn read_current(path: &std::path::Path) -> DirectSnapshot {
        let content = std::fs::read(path).ok();
        let mode = Self::current_mode(path);
        DirectSnapshot { content, mode }
    }

    fn to_platform(resource: &ResourceId, snapshot: &DirectSnapshot) -> Result<PlatformSnapshot> {
        let data = serde_json::to_value(snapshot)
            .map_err(|e| Error::platform(BackendKind::ResolvConfFile, format_args!("{e}")))?;
        Ok(PlatformSnapshot::new(
            BackendKind::ResolvConfFile,
            resource.clone(),
            data,
        ))
    }

    fn from_platform(snapshot: &PlatformSnapshot) -> Result<DirectSnapshot> {
        serde_json::from_value(snapshot.data.clone()).map_err(|e| {
            Error::platform(
                BackendKind::ResolvConfFile,
                format_args!("snapshot data cannot be interpreted: {e}"),
            )
        })
    }
}

impl Default for DirectResolvConf {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for DirectResolvConf {
    fn kind(&self) -> BackendKind {
        BackendKind::ResolvConfFile
    }

    fn capabilities(&self) -> Capabilities {
        self.caps.clone()
    }

    fn resolve_resources(
        &self,
        scope: &DnsScope,
        _plan: &NormalizedConfig,
    ) -> Result<Vec<ResourceId>> {
        match scope {
            DnsScope::Global => ResourceId::new("linux:resolv-conf").map(|id| vec![id]),
            DnsScope::Interface(_) => Err(Error::unsupported(
                BackendKind::ResolvConfFile,
                "per-interface DNS is not representable in /etc/resolv.conf",
            )),
        }
    }

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        linux::list_interfaces()
    }

    fn capture(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let path = std::path::Path::new(RESOLV_CONF);
        Self::check_usable(path)?;
        let snapshot = Self::read_current(path);
        Self::to_platform(resource, &snapshot)
    }

    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt> {
        let path = std::path::Path::new(RESOLV_CONF);
        Self::check_usable(path)?;
        let existing_mode = Self::current_mode(path);
        Self::write_content(path, &build_resolv_conf_content(plan), existing_mode)?;
        Ok(ApplyReceipt {
            resource: resource.clone(),
        })
    }

    fn readback(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let snapshot = Self::read_current(std::path::Path::new(RESOLV_CONF));
        Self::to_platform(resource, &snapshot)
    }

    fn restore(&self, _resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()> {
        let before = Self::from_platform(snapshot)?;
        let path = std::path::Path::new(RESOLV_CONF);
        match before.content {
            Some(content) => Self::write_content(path, &content, before.mode),
            None => match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            },
        }
    }

    fn equivalent(&self, a: &PlatformSnapshot, b: &PlatformSnapshot) -> bool {
        match (Self::from_platform(a), Self::from_platform(b)) {
            (Ok(x), Ok(y)) => x.content == y.content,
            _ => false,
        }
    }

    fn matches_desired(&self, snapshot: &PlatformSnapshot, plan: &NormalizedConfig) -> bool {
        let Ok(current) = Self::from_platform(snapshot) else {
            return false;
        };
        current.content.as_deref() == Some(build_resolv_conf_content(plan).as_slice())
    }

    fn public_state(&self, snapshot: &PlatformSnapshot, scope: &DnsScope) -> Result<DnsConfig> {
        let snapshot = Self::from_platform(snapshot)?;
        let Some(bytes) = snapshot.content else {
            return Ok(DnsConfig::from_parts(
                scope.clone(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
            ));
        };
        let (nameservers, search) = parse_resolv_conf_content(&bytes)?;
        Ok(DnsConfig::from_parts(
            scope.clone(),
            nameservers,
            search,
            Vec::new(),
            None,
        ))
    }

    fn start_watch(&self, callback: WatchCallback) -> Result<WatchHandle> {
        let parent = std::path::Path::new(RESOLV_CONF)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("/etc"));
        crate::platform::linux::watch::watch_directory(
            BackendKind::ResolvConfFile,
            &parent,
            |name| {
                if name == "resolv.conf" {
                    ResourceId::new("linux:resolv-conf").ok()
                } else {
                    None
                }
            },
            callback,
        )
    }
}
