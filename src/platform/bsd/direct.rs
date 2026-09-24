use std::fs::{File, FileTimes, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt as _, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use atomic_write_file::unix::OpenOptionsExt;
use nix::sys::stat::fstat;

use crate::capability::BackendKind;
use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::NormalizedConfig;
use crate::ownership::ResourceId;
use crate::platform::bsd;
use crate::platform::unix::WatchDirectory;
use crate::platform::unix::detect::{self, ResolvConfState};
use crate::platform::unix::direct::{
    DirectFileMetadata, DirectPolicy, DirectResolvConf, FileOwner, FileTime,
};

struct BsdDirectPolicy {
    resource: ResourceId,
}

impl BsdDirectPolicy {
    fn new() -> Self {
        Self {
            resource: ResourceId::new(format!("{}:resolv-conf", bsd::resource_prefix()))
                .expect("valid resource"),
        }
    }
}

impl DirectPolicy for BsdDirectPolicy {
    fn check_usable(&self, path: &Path) -> Result<()> {
        match detect::classify(path) {
            ResolvConfState::Missing => Ok(()),
            ResolvConfState::Unmanaged => self.reject_protected_metadata(path),
            ResolvConfState::OpenResolv => Err(Error::unsupported(
                BackendKind::ResolvConfFile,
                "/etc/resolv.conf is managed by openresolv",
            )),
            ResolvConfState::Foreign => Err(Error::unsupported(
                BackendKind::ResolvConfFile,
                "/etc/resolv.conf is managed by another DNS configuration system",
            )),
        }
    }

    fn metadata(&self, path: &Path) -> Result<Option<DirectFileMetadata>> {
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(Error::unsupported(
                BackendKind::ResolvConfFile,
                "/etc/resolv.conf must be a single-link regular file",
            ));
        }
        let file = File::open(path)?;
        let stat = fstat(&file).map_err(io::Error::from)?;
        Ok(Some(DirectFileMetadata {
            mode: metadata.permissions().mode(),
            owner: Some(FileOwner {
                uid: metadata.uid(),
                gid: metadata.gid(),
            }),
            flags: Some(stat.st_flags as u64),
            links: Some(metadata.nlink()),
            modified: Some(system_time(metadata.modified()?)?),
        }))
    }

    fn write(
        &self,
        path: &Path,
        content: &[u8],
        mode: Option<u32>,
        metadata: Option<&DirectFileMetadata>,
        restore_modified_time: bool,
    ) -> Result<()> {
        if restore_modified_time
            && metadata.is_none_or(|metadata| {
                metadata.owner.is_none()
                    || metadata.flags.is_none()
                    || metadata.links.is_none()
                    || metadata.modified.is_none()
            })
        {
            return Err(Error::JournalCorrupt(
                "BSD resolv.conf journal record lacks required file metadata".to_string(),
            ));
        }
        self.reject_protected_metadata(path)?;
        let mut options = atomic_write_file::OpenOptions::new();
        options.preserve_mode(true).preserve_owner(true);
        options.mode(
            metadata
                .map(|metadata| metadata.mode)
                .or(mode)
                .unwrap_or(0o644),
        );
        let mut file = options.open(path)?;
        clear_file_flags(file.as_file())?;
        std::io::Write::write_all(&mut file, content)?;
        if restore_modified_time
            && let Some(time) = metadata.and_then(|metadata| metadata.modified.as_ref())
        {
            file.as_file()
                .set_times(FileTimes::new().set_modified(system_time_value(time)?))?;
        }
        file.sync_all()?;
        let committed_file = file.as_file().try_clone()?;
        file.commit()?;
        clear_file_flags(&committed_file)?;
        self.reject_protected_file(&committed_file)?;
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
        let Some(before) = before else {
            return true;
        };
        let Some(after) = after else {
            return false;
        };
        before.mode == after.mode
            && before.owner == after.owner
            && before.flags == after.flags
            && before.links == after.links
    }

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        bsd::list_interfaces()
    }

    fn watch_directory(&self) -> WatchDirectory {
        bsd::watch::watch_directories
    }

    fn validate_plan(&self, plan: &NormalizedConfig) -> Result<()> {
        bsd::validate_resolver_limits(plan)
    }

    fn resource(&self) -> &ResourceId {
        &self.resource
    }
}

fn clear_file_flags(file: &File) -> Result<()> {
    if unsafe { libc::fchflags(file.as_raw_fd(), 0) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

impl BsdDirectPolicy {
    fn reject_protected_metadata(&self, path: &Path) -> Result<()> {
        let file = match OpenOptions::new().read(true).open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        self.reject_protected_file(&file)
    }

    fn reject_protected_file(&self, file: &File) -> Result<()> {
        let stat = fstat(file).map_err(io::Error::from)?;
        if stat.st_flags != 0 {
            return Err(Error::unsupported(
                BackendKind::ResolvConfFile,
                "refusing to replace /etc/resolv.conf while BSD file flags are set",
            ));
        }
        if has_extended_attributes(file)? {
            return Err(Error::unsupported(
                BackendKind::ResolvConfFile,
                "refusing to replace /etc/resolv.conf with ACLs or extended attributes",
            ));
        }
        let metadata = file.metadata()?;
        if metadata.nlink() != 1 {
            return Err(Error::unsupported(
                BackendKind::ResolvConfFile,
                "refusing to replace a multiply-linked /etc/resolv.conf",
            ));
        }
        Ok(())
    }
}

fn has_extended_attributes(file: &File) -> Result<bool> {
    for namespace in [libc::EXTATTR_NAMESPACE_USER, libc::EXTATTR_NAMESPACE_SYSTEM] {
        let size =
            unsafe { libc::extattr_list_fd(file.as_raw_fd(), namespace, std::ptr::null_mut(), 0) };
        if size > 0 {
            return Ok(true);
        }
        if size < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(code)
                if code == libc::ENOTSUP || code == libc::EOPNOTSUPP || code == libc::ENOATTR)
            {
                continue;
            }
            return Err(error.into());
        }
    }
    Ok(false)
}

fn system_time(time: SystemTime) -> Result<FileTime> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(FileTime {
        seconds: duration.as_secs() as i64,
        nanoseconds: duration.subsec_nanos(),
    })
}

fn system_time_value(time: &FileTime) -> Result<SystemTime> {
    if time.seconds >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::new(time.seconds as u64, time.nanoseconds))
            .ok_or_else(|| {
                Error::JournalCorrupt("resolv.conf timestamp is out of range".to_string())
            })
    } else {
        let seconds = time.seconds.unsigned_abs();
        let duration = Duration::new(seconds, 0)
            .checked_sub(Duration::from_nanos(time.nanoseconds as u64))
            .ok_or_else(|| {
                Error::JournalCorrupt("resolv.conf timestamp is out of range".to_string())
            })?;
        UNIX_EPOCH.checked_sub(duration).ok_or_else(|| {
            Error::JournalCorrupt("resolv.conf timestamp is out of range".to_string())
        })
    }
}

pub(crate) fn new() -> DirectResolvConf {
    DirectResolvConf::new(
        PathBuf::from(detect::RESOLV_CONF_PATH),
        Arc::new(BsdDirectPolicy::new()),
    )
}
