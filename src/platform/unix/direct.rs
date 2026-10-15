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
    fn metadata(&self, file: &std::fs::File) -> Result<DirectFileMetadata>;
    fn write(
        &self,
        path: &Path,
        content: &[u8],
        metadata: Option<&DirectFileMetadata>,
        restore_modified_time: bool,
        verify_expected: &dyn Fn() -> Result<()>,
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
#[serde(deny_unknown_fields)]
pub(crate) struct DirectSnapshot {
    pub(crate) content: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metadata: Option<DirectFileMetadata>,
}

impl DirectSnapshot {
    pub(crate) fn validate(&self) -> Result<()> {
        let valid = match (&self.content, &self.metadata) {
            (None, None) => true,
            (Some(_), Some(metadata)) => metadata
                .modified
                .as_ref()
                .is_none_or(|time| time.nanoseconds < 1_000_000_000),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(Error::JournalCorrupt(
                "resolver file snapshot has inconsistent content or metadata".to_string(),
            ))
        }
    }
}

pub(crate) struct DirectResolvConf {
    path: PathBuf,
    resource: ResourceId,
    caps: Capabilities,
    policy: Box<dyn DirectPolicy>,
}

impl DirectResolvConf {
    pub(crate) fn new(path: PathBuf, policy: Box<dyn DirectPolicy>) -> Self {
        Self {
            path,
            resource: policy.resource().clone(),
            caps: capabilities(),
            policy,
        }
    }

    fn read_current(&self) -> Result<DirectSnapshot> {
        use std::io::Read;
        self.policy.check_usable(&self.path)?;
        let mut file: std::fs::File = match rustix::fs::open(
            &self.path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(file) => file.into(),
            Err(rustix::io::Errno::NOENT) => {
                return Ok(DirectSnapshot {
                    content: None,
                    metadata: None,
                });
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        let before = file.metadata()?;
        if !before.is_file() {
            return Err(Error::UnsafeFilesystem(
                "resolver configuration is not a regular file".to_string(),
            ));
        }
        let metadata = self.policy.metadata(&file)?;
        let mut content = Vec::new();
        Read::by_ref(&mut file)
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut content)?;
        if content.len() > 16 * 1024 * 1024 {
            return Err(Error::unsupported(
                self.kind(),
                "resolver configuration exceeds the storage budget",
            ));
        }
        let after = file.metadata()?;
        use std::os::unix::fs::MetadataExt;
        if before.len() != after.len()
            || before.modified()? != after.modified()?
            || (before.ctime(), before.ctime_nsec()) != (after.ctime(), after.ctime_nsec())
            || metadata != self.policy.metadata(&file)?
        {
            return Err(Error::ResourcePlatform {
                backend: self.kind(),
                resource: self.resource.clone(),
                message: "resolver configuration changed during capture".to_string(),
            });
        }
        Ok(DirectSnapshot {
            content: Some(content),
            metadata: Some(metadata),
        })
    }

    fn apply_snapshot(
        &self,
        current: &DirectSnapshot,
        plan: &NormalizedConfig,
    ) -> Result<ApplyReceipt> {
        let desired = build_resolv_conf_content(plan);
        self.write_content(&desired, current, false, current)?;
        let observed = self.read_current()?;
        let preserved = observed.content.as_deref() == Some(desired.as_slice())
            && self
                .policy
                .mutation_metadata_preserved(current.metadata.as_ref(), observed.metadata.as_ref());
        if !preserved {
            let detail = if observed.content.as_deref() == Some(desired.as_slice()) {
                "resolv.conf metadata changed before write verification completed"
            } else {
                "resolv.conf changed before write verification completed"
            };
            return Err(Error::ResourcePlatform {
                backend: BackendKind::ResolvConfFile,
                resource: self.resource.clone(),
                message: detail.to_string(),
            });
        }
        Ok(ApplyReceipt {
            resource: self.resource.clone(),
        })
    }

    fn verify_expected(&self, expected: &DirectSnapshot) -> Result<()> {
        if self.read_current()? != *expected {
            return Err(Error::ExternalModification {
                resource: self.resource.clone(),
                detail: "resolv.conf changed before publication".to_string(),
            });
        }
        Ok(())
    }

    fn write_content(
        &self,
        content: &[u8],
        snapshot: &DirectSnapshot,
        restore_modified_time: bool,
        expected: &DirectSnapshot,
    ) -> Result<()> {
        self.policy.check_usable(&self.path)?;
        self.policy.write(
            &self.path,
            content,
            snapshot.metadata.as_ref(),
            restore_modified_time,
            &|| self.verify_expected(expected),
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
            SnapshotData::ResolvConfFile(data) => {
                data.validate()?;
                Ok(data.clone())
            }
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

    fn resource_status(
        &self,
        identity: &crate::platform::ResourceIdentity,
    ) -> Result<crate::platform::ResourceStatus> {
        if identity.backend != self.kind()
            || identity.resource != self.resource
            || !matches!(identity.data, crate::platform::IdentityData::Untracked)
        {
            return Err(Error::JournalCorrupt(
                "resolver identity does not name this backend's file resource".to_string(),
            ));
        }
        Ok(crate::platform::ResourceStatus::Same)
    }

    fn capture(&self, _resource: &ResourceId) -> Result<PlatformSnapshot> {
        Ok(self.to_platform(&self.read_current()?))
    }

    fn readback(&self, _resource: &ResourceId) -> Result<PlatformSnapshot> {
        Ok(self.to_platform(&self.read_current()?))
    }

    fn apply_bound(
        &self,
        identity: &crate::platform::ResourceIdentity,
        expected: &PlatformSnapshot,
        plan: &NormalizedConfig,
    ) -> crate::platform::MutationAttempt {
        let preparation = (|| {
            self.resource_status(identity)?;
            if expected.resource != self.resource || expected.backend != self.kind() {
                return Err(Error::JournalCorrupt(
                    "resolver snapshot targets a different resource".to_string(),
                ));
            }
            let expected = Self::from_platform(expected)?;
            self.verify_expected(&expected)?;
            Ok(expected)
        })();
        match preparation {
            Ok(expected) => crate::platform::MutationAttempt::from_apply_result(
                self.apply_snapshot(&expected, plan),
            ),
            Err(error) => crate::platform::MutationAttempt::Rejected { error },
        }
    }

    fn restore_bound(
        &self,
        identity: &crate::platform::ResourceIdentity,
        expected: &PlatformSnapshot,
        target: &PlatformSnapshot,
    ) -> crate::platform::MutationAttempt {
        let preparation = (|| {
            self.resource_status(identity)?;
            if [expected, target]
                .iter()
                .any(|s| s.resource != self.resource || s.backend != self.kind())
            {
                return Err(Error::JournalCorrupt(
                    "resolver snapshot targets a different resource".to_string(),
                ));
            }
            let expected = Self::from_platform(expected)?;
            let target = Self::from_platform(target)?;
            self.verify_expected(&expected)?;
            Ok((expected, target))
        })();
        match preparation {
            Ok((expected, target)) => {
                let result = match target.content.as_deref() {
                    Some(content) => self.write_content(content, &target, true, &expected),
                    None => self
                        .verify_expected(&expected)
                        .and_then(|()| self.remove_current()),
                };
                match result {
                    Ok(()) => crate::platform::MutationAttempt::Performed { produced: None },
                    Err(error) => crate::platform::MutationAttempt::Indeterminate {
                        error,
                        produced: None,
                    },
                }
            }
            Err(error) => crate::platform::MutationAttempt::Rejected { error },
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
    use crate::platform::MutationAttempt;
    use crate::platform::unix::ResourceMapper;
    use crate::watch::{WatchCallback, WatchHandle};
    use std::sync::Mutex;

    struct MetadataChangingPolicy {
        resource: ResourceId,
        mode: Mutex<u32>,
    }

    impl DirectPolicy for MetadataChangingPolicy {
        fn check_usable(&self, _path: &Path) -> Result<()> {
            Ok(())
        }

        fn metadata(&self, _file: &std::fs::File) -> Result<DirectFileMetadata> {
            Ok(DirectFileMetadata {
                mode: *self.mode.lock().unwrap(),
                owner: None,
                flags: None,
                links: None,
                modified: None,
            })
        }

        fn write(
            &self,
            path: &Path,
            content: &[u8],
            _metadata: Option<&DirectFileMetadata>,
            _restore_modified_time: bool,
            verify_expected: &dyn Fn() -> Result<()>,
        ) -> Result<()> {
            verify_expected()?;
            std::fs::write(path, content)?;
            *self.mode.lock().unwrap() = 0o600;
            Ok(())
        }

        fn metadata_equivalent(
            &self,
            _left: Option<&DirectFileMetadata>,
            _right: Option<&DirectFileMetadata>,
        ) -> bool {
            true
        }

        fn mutation_metadata_preserved(
            &self,
            _before: Option<&DirectFileMetadata>,
            _after: Option<&DirectFileMetadata>,
        ) -> bool {
            false
        }

        fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
            Ok(Vec::new())
        }

        fn watch_directory(&self) -> WatchDirectory {
            unsupported_watch
        }

        fn validate_plan(&self, _plan: &NormalizedConfig) -> Result<()> {
            Ok(())
        }

        fn resource(&self) -> &ResourceId {
            &self.resource
        }
    }

    fn unsupported_watch(
        _backend: BackendKind,
        _paths: &[PathBuf],
        _resources: Vec<ResourceId>,
        _mapper: ResourceMapper,
        _callback: WatchCallback,
    ) -> Result<WatchHandle> {
        Err(Error::unsupported(
            BackendKind::ResolvConfFile,
            "test direct policy does not support watching",
        ))
    }

    #[test]
    fn metadata_mismatch_after_commit_is_indeterminate() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resolv.conf");
        std::fs::write(&path, b"nameserver 192.0.2.10\n").unwrap();
        let resource = ResourceId::new("unix:resolv-conf").unwrap();
        let backend = DirectResolvConf::new(
            path.clone(),
            Box::new(MetadataChangingPolicy {
                resource: resource.clone(),
                mode: Mutex::new(0o100644),
            }),
        );
        let plan = NormalizedConfig {
            nameservers: vec!["192.0.2.20".parse().unwrap()],
            ..NormalizedConfig::default()
        };

        let current = backend.read_current().unwrap();
        let error = backend.apply_snapshot(&current, &plan).unwrap_err();
        assert!(matches!(&error, Error::ResourcePlatform { .. }));
        assert!(matches!(
            MutationAttempt::from_apply_result(Err(error)),
            MutationAttempt::Indeterminate { .. }
        ));
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "nameserver 192.0.2.20\n"
        );
    }
}
