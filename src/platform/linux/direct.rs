use atomic_write_file::unix::OpenOptionsExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::NormalizedConfig;
use crate::ownership::ResourceId;
use crate::platform::linux;
use crate::platform::unix::WatchDirectory;
use crate::platform::unix::detect::{self, ResolvConfState};
use crate::platform::unix::direct::{
    DirectFileMetadata, DirectPolicy, DirectResolvConf, FileOwner,
};

struct LinuxDirectPolicy {
    resource: ResourceId,
}

impl LinuxDirectPolicy {
    fn new() -> Self {
        Self {
            resource: ResourceId::new("linux:resolv-conf").expect("valid resource"),
        }
    }
}

impl DirectPolicy for LinuxDirectPolicy {
    fn check_usable(&self, path: &Path) -> Result<()> {
        match detect::classify(path) {
            ResolvConfState::Missing | ResolvConfState::Unmanaged => Ok(()),
            ResolvConfState::OpenResolv => Err(Error::unsupported(
                crate::capability::BackendKind::ResolvConfFile,
                "/etc/resolv.conf is managed by resolvconf",
            )),
            ResolvConfState::Foreign => Err(Error::unsupported(
                crate::capability::BackendKind::ResolvConfFile,
                "/etc/resolv.conf is managed by another DNS configuration system",
            )),
        }
    }

    fn metadata(&self, file: &std::fs::File) -> Result<DirectFileMetadata> {
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(Error::UnsafeFilesystem(
                "resolver configuration must be a single-link regular file".to_string(),
            ));
        }
        Ok(DirectFileMetadata {
            mode: metadata.permissions().mode(),
            owner: Some(FileOwner {
                uid: metadata.uid(),
                gid: metadata.gid(),
            }),
            flags: None,
            links: Some(metadata.nlink()),
            modified: None,
        })
    }

    fn write(
        &self,
        path: &Path,
        content: &[u8],
        metadata: Option<&DirectFileMetadata>,
        _restore_modified_time: bool,
        verify_expected: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        match rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        ) {
            Ok(file) => reject_extended_attributes(&file)?,
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
        let mut options = atomic_write_file::OpenOptions::new();
        options.preserve_owner(true);
        let mut file = options.open(path)?;
        reject_extended_attributes(file.as_file())?;
        std::io::Write::write_all(&mut file, content)?;
        if let Some(metadata) = metadata {
            file.as_file()
                .set_permissions(std::fs::Permissions::from_mode(metadata.mode))?;
        }
        file.sync_all()?;
        verify_expected()?;
        file.commit()?;
        Ok(())
    }

    fn metadata_equivalent(
        &self,
        left: Option<&DirectFileMetadata>,
        right: Option<&DirectFileMetadata>,
    ) -> bool {
        left == right
    }

    fn mutation_metadata_preserved(
        &self,
        before: Option<&DirectFileMetadata>,
        after: Option<&DirectFileMetadata>,
    ) -> bool {
        before.is_none_or(|before| after.is_some_and(|after| before == after))
    }

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        linux::list_interfaces()
    }

    fn watch_directory(&self) -> WatchDirectory {
        linux::watch::watch_directories
    }

    fn validate_plan(&self, _plan: &NormalizedConfig) -> Result<()> {
        Ok(())
    }

    fn resource(&self) -> &ResourceId {
        &self.resource
    }
}

pub(crate) fn new() -> DirectResolvConf {
    DirectResolvConf::new(
        PathBuf::from(linux::RESOLV_CONF_PATH),
        Box::new(LinuxDirectPolicy::new()),
    )
}

fn reject_extended_attributes(file: impl std::os::fd::AsFd) -> Result<()> {
    match rustix::fs::flistxattr(file, &mut [0u8; 0]) {
        Ok(0) | Err(rustix::io::Errno::NOTSUP) => Ok(()),
        Ok(_) => Err(Error::unsupported(
            crate::BackendKind::ResolvConfFile,
            "the atomic writer cannot preserve resolver extended attributes or ACLs",
        )),
        Err(error) => Err(std::io::Error::from(error).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(mode: u32) -> DirectFileMetadata {
        DirectFileMetadata {
            mode,
            owner: None,
            flags: None,
            links: None,
            modified: None,
        }
    }

    #[rstest::rstest]
    #[case(false)]
    #[case(true)]
    fn changed_state_is_preserved_when_final_publication_check_rejects(#[case] restore: bool) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("resolv.conf");
        std::fs::write(&path, b"nameserver 192.0.2.1\n").unwrap();
        let policy = LinuxDirectPolicy::new();
        let captured = policy
            .metadata(&std::fs::File::open(&path).unwrap())
            .unwrap();
        let error = policy
            .write(
                &path,
                b"nameserver 192.0.2.2\n",
                Some(&captured),
                restore,
                &|| {
                    std::fs::write(&path, b"nameserver 192.0.2.3\n")?;
                    Err(Error::ExternalModification {
                        resource: policy.resource().clone(),
                        detail: "changed before publication".to_string(),
                    })
                },
            )
            .unwrap_err();
        assert!(matches!(error, Error::ExternalModification { .. }));
        assert_eq!(std::fs::read(&path).unwrap(), b"nameserver 192.0.2.3\n");
    }

    #[test]
    fn direct_policy_rejects_foreign_generated_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resolv.conf");
        std::fs::write(&path, b"# Generated by NetworkManager\n").unwrap();
        assert!(LinuxDirectPolicy::new().check_usable(&path).is_err());
    }

    #[test]
    fn direct_policy_applies_captured_mode_to_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resolv.conf");
        let policy = LinuxDirectPolicy::new();
        std::fs::write(&path, b"nameserver 192.0.2.1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o100640)).unwrap();
        let captured = policy
            .metadata(&std::fs::File::open(&path).unwrap())
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o100600)).unwrap();

        policy
            .write(
                &path,
                b"nameserver 192.0.2.2\n",
                Some(&captured),
                false,
                &|| Ok(()),
            )
            .unwrap();

        let observed_mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(observed_mode & 0o7777, 0o640);
    }

    #[test]
    fn direct_policy_metadata_equivalent_compares_captured_modes() {
        let policy = LinuxDirectPolicy::new();
        let left = metadata(0o100644);
        let same = metadata(0o100644);
        let different = metadata(0o100600);

        assert!(policy.metadata_equivalent(Some(&left), Some(&same)));
        assert!(!policy.metadata_equivalent(Some(&left), Some(&different)));
        assert!(policy.metadata_equivalent(None, None));
        assert!(!policy.metadata_equivalent(None, Some(&different)));
        assert!(!policy.metadata_equivalent(Some(&different), None));
    }

    #[test]
    fn direct_policy_mutation_metadata_preserved_compares_captured_modes() {
        let policy = LinuxDirectPolicy::new();
        let before = metadata(0o100644);
        let same = metadata(0o100644);
        let different = metadata(0o100600);

        assert!(policy.mutation_metadata_preserved(Some(&before), Some(&same)));
        assert!(!policy.mutation_metadata_preserved(Some(&before), Some(&different)));
        assert!(policy.mutation_metadata_preserved(None, None));
        assert!(policy.mutation_metadata_preserved(None, Some(&different)));
        assert!(!policy.mutation_metadata_preserved(Some(&different), None));
    }
    #[rstest::rstest]
    #[case(false)]
    #[case(true)]
    fn direct_file_metadata_guards_links_and_preserves_extended_state(#[case] hard_link: bool) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resolv.conf");
        std::fs::write(&path, b"nameserver 192.0.2.1\n").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let policy = LinuxDirectPolicy::new();
        if hard_link {
            std::fs::hard_link(&path, directory.path().join("alias")).unwrap();
            assert!(policy.metadata(&file).is_err());
        } else {
            rustix::fs::fsetxattr(
                &file,
                "user.osdns-test",
                b"foreign metadata",
                rustix::fs::XattrFlags::empty(),
            )
            .unwrap();
            let captured = policy.metadata(&file).unwrap();
            assert!(
                policy
                    .write(
                        &path,
                        b"nameserver 192.0.2.2\n",
                        Some(&captured),
                        false,
                        &|| Ok(())
                    )
                    .is_err()
            );
            assert_eq!(std::fs::read(&path).unwrap(), b"nameserver 192.0.2.1\n");
        }
    }
}
