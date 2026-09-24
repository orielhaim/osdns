use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::capability::{BackendKind, Capabilities, ResourceBinding};
use crate::config::{DnsConfig, DnsScope};
use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::NormalizedConfig;
use crate::ownership::ResourceId;
use crate::platform::text_config::{build_resolv_conf_content, parse_resolv_conf_content};
use crate::platform::unix::{ResourceMapper, WatchDirectory};
use crate::platform::{ApplyReceipt, Backend, PlatformSnapshot, SnapshotData};
use crate::watch::{WatchCallback, WatchHandle};

pub(crate) trait DirectPolicy: Send + Sync {
    fn check_usable(&self, path: &Path) -> Result<()>;
    fn metadata(&self, path: &Path) -> Result<Option<DirectFileMetadata>>;
    fn write(
        &self,
        path: &Path,
        content: &[u8],
        mode: Option<u32>,
        metadata: Option<&DirectFileMetadata>,
        restore_modified_time: bool,
    ) -> Result<()>;
    fn metadata_equivalent(
        &self,
        left: Option<&DirectFileMetadata>,
        right: Option<&DirectFileMetadata>,
    ) -> bool;
    fn mutation_metadata_preserved(
        &self,
        before: Option<&DirectFileMetadata>,
        after: Option<&DirectFileMetadata>,
    ) -> bool;
    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>>;
    fn watch_directory(&self) -> WatchDirectory;
    fn validate_plan(&self, plan: &NormalizedConfig) -> Result<()>;
    fn resource(&self) -> &ResourceId;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DirectFileMetadata {
    pub(crate) mode: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) owner: Option<FileOwner>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) flags: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) links: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) modified: Option<FileTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FileOwner {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FileTime {
    pub(crate) seconds: i64,
    pub(crate) nanoseconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DirectSnapshot {
    pub(crate) content: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metadata: Option<DirectFileMetadata>,
}

pub(crate) struct DirectResolvConf {
    path: PathBuf,
    resource: ResourceId,
    caps: Capabilities,
    policy: Arc<dyn DirectPolicy>,
}

impl DirectResolvConf {
    pub(crate) fn new(path: PathBuf, policy: Arc<dyn DirectPolicy>) -> Self {
        Self {
            path,
            resource: policy.resource().clone(),
            caps: capabilities(),
            policy,
        }
    }

    fn read_current(&self) -> Result<DirectSnapshot> {
        self.policy.check_usable(&self.path)?;
        let content = match std::fs::read(&self.path) {
            Ok(content) => Some(content),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let metadata = self.policy.metadata(&self.path)?;
        let mode = metadata.as_ref().map(|metadata| metadata.mode);
        Ok(DirectSnapshot {
            content,
            mode,
            metadata,
        })
    }

    fn write_content(
        &self,
        content: &[u8],
        snapshot: &DirectSnapshot,
        restore_modified_time: bool,
    ) -> Result<()> {
        self.policy.check_usable(&self.path)?;
        self.policy.write(
            &self.path,
            content,
            snapshot.mode,
            snapshot.metadata.as_ref(),
            restore_modified_time,
        )
    }

    fn to_platform(&self, snapshot: &DirectSnapshot) -> PlatformSnapshot {
        PlatformSnapshot::new(
            BackendKind::ResolvConfFile,
            self.resource.clone(),
            SnapshotData::ResolvConfFile(snapshot.clone()),
        )
    }

    fn from_platform(snapshot: &PlatformSnapshot) -> Result<DirectSnapshot> {
        match &snapshot.data {
            SnapshotData::ResolvConfFile(data) => Ok(data.clone()),
            _ => Err(Error::JournalCorrupt(
                "resolv.conf snapshot has the wrong backend data".to_string(),
            )),
        }
    }

    fn remove_current(&self) -> Result<()> {
        self.policy.check_usable(&self.path)?;
        match std::fs::remove_file(&self.path) {
            Ok(()) => {
                if let Some(parent) = self.path.parent() {
                    crate::fsutil::fsync_dir(parent)?;
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn capabilities() -> Capabilities {
    Capabilities::new(BackendKind::ResolvConfFile)
        .with_read(true)
        .with_global_dns(true)
        .with_per_interface_dns(false)
        .with_search_domains(true)
        .with_split_dns(false)
        .with_watch(true)
        .with_cache_flush(false)
        .with_resource_binding(ResourceBinding::PreflightOnly)
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
            DnsScope::Global => Ok(vec![self.resource.clone()]),
            DnsScope::Interface(_) => Err(Error::unsupported(
                BackendKind::ResolvConfFile,
                "per-interface DNS is not representable in /etc/resolv.conf",
            )),
        }
    }

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        self.policy.list_interfaces()
    }

    fn capture(&self, _resource: &ResourceId) -> Result<PlatformSnapshot> {
        Ok(self.to_platform(&self.read_current()?))
    }

    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt> {
        let current = self.read_current()?;
        let desired = build_resolv_conf_content(plan);
        self.write_content(&desired, &current, false)?;
        let observed = self.read_current()?;
        let preserved = observed.content.as_deref() == Some(desired.as_slice())
            && self
                .policy
                .mutation_metadata_preserved(current.metadata.as_ref(), observed.metadata.as_ref());
        if !preserved {
            if observed.content.as_deref() != Some(desired.as_slice()) {
                return Err(Error::ExternalModification {
                    resource: resource.clone(),
                    detail: "resolv.conf changed before write verification completed".to_string(),
                });
            }
            let unchanged = self.read_current()?;
            if unchanged != observed {
                return Err(Error::ExternalModification {
                    resource: resource.clone(),
                    detail: "resolv.conf changed before verification rollback".to_string(),
                });
            }
            let rollback = match current.content.as_deref() {
                Some(content) => self.write_content(content, &current, true),
                None => self.remove_current(),
            };
            return match rollback {
                Ok(()) => Err(Error::platform(
                    BackendKind::ResolvConfFile,
                    "resolv.conf write verification failed; the captured state was restored",
                )),
                Err(rollback_error) => Err(Error::platform(
                    BackendKind::ResolvConfFile,
                    format_args!(
                        "resolv.conf write verification failed and rollback also failed: {rollback_error}"
                    ),
                )),
            };
        }
        Ok(ApplyReceipt {
            resource: self.resource.clone(),
        })
    }

    fn readback(&self, _resource: &ResourceId) -> Result<PlatformSnapshot> {
        Ok(self.to_platform(&self.read_current()?))
    }

    fn restore(&self, _resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()> {
        let before = Self::from_platform(snapshot)?;
        match before.content.as_deref() {
            Some(content) => self.write_content(content, &before, true),
            None => self.remove_current(),
        }
    }

    fn equivalent(&self, a: &PlatformSnapshot, b: &PlatformSnapshot) -> bool {
        match (Self::from_platform(a), Self::from_platform(b)) {
            (Ok(a), Ok(b)) => {
                a.content == b.content
                    && self
                        .policy
                        .metadata_equivalent(a.metadata.as_ref(), b.metadata.as_ref())
            }
            _ => false,
        }
    }

    fn matches_desired(&self, snapshot: &PlatformSnapshot, plan: &NormalizedConfig) -> bool {
        let Ok(current) = Self::from_platform(snapshot) else {
            return false;
        };
        current.content.as_deref() == Some(build_resolv_conf_content(plan).as_slice())
    }

    fn validate_plan(&self, _scope: &DnsScope, plan: &NormalizedConfig) -> Result<()> {
        self.policy.validate_plan(plan)
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
        let resource = self.resource.clone();
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("resolv.conf")
            .to_string();
        let mapper: ResourceMapper = Arc::new(move |path| {
            if path.file_name().and_then(|name| name.to_str()) == Some(file_name.as_str()) {
                Some(resource.clone())
            } else {
                None
            }
        });
        let parent = self
            .path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/etc"));
        #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
        let watch_paths = vec![parent, self.path.clone()];
        #[cfg(not(any(target_os = "freebsd", target_os = "netbsd")))]
        let watch_paths = vec![parent];
        (self.policy.watch_directory())(
            BackendKind::ResolvConfFile,
            &watch_paths,
            vec![self.resource.clone()],
            mapper,
            callback,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_direct_snapshots_decode_without_metadata() {
        let snapshot: DirectSnapshot = serde_json::from_str(r#"{"content":null}"#).unwrap();
        assert_eq!(snapshot.content, None);
        assert_eq!(snapshot.mode, None);
        assert_eq!(snapshot.metadata, None);
    }
}
