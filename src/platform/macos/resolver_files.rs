//! Descriptor-relative scoped resolver files under the trusted system directory.

use crate::error::{Error, Result};
use rustix::fs::{self, AtFlags, Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;

const MARKER_PREFIX: &str = "# osdns owner=";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ResolverFile {
    pub(crate) content: Vec<u8>,
    device: u64,
    inode: u64,
    modified: (i64, i64),
}

pub(crate) fn marker_for(owner: &str) -> String {
    format!("{MARKER_PREFIX}{owner}\n")
}

struct ResolverDir(File);

impl ResolverDir {
    fn open(create: bool) -> Result<Option<Self>> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let parent: File = fs::open("/private/etc", flags, Mode::empty())
            .map_err(std::io::Error::from)?
            .into();
        trusted(&parent, true)?;
        let dir = match fs::openat(&parent, "resolver", flags, Mode::empty()) {
            Ok(dir) => dir,
            Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
            Err(rustix::io::Errno::NOENT) => {
                match fs::mkdirat(&parent, "resolver", Mode::from_raw_mode(0o755)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(std::io::Error::from(error).into()),
                }
                fs::openat(&parent, "resolver", flags, Mode::empty())
                    .map_err(std::io::Error::from)?
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        let dir: File = dir.into();
        trusted(&dir, true)?;
        Ok(Some(Self(dir)))
    }

    fn read(&self, domain: &str) -> Result<Option<ResolverFile>> {
        validate_domain(domain)?;
        let fd = match fs::openat(
            &self.0,
            domain,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        let mut file: File = fd.into();
        trusted(&file, false)?;
        let before = file.metadata()?;
        let mut content = Vec::new();
        Read::by_ref(&mut file)
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut content)?;
        if content.len() > 16 * 1024 * 1024 {
            return Err(Error::JournalCorrupt(
                "resolver file exceeds the storage budget".to_string(),
            ));
        }
        let after = file.metadata()?;
        if before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
        {
            return Err(Error::platform(
                crate::BackendKind::MacosSystemConfiguration,
                "resolver file changed during capture",
            ));
        }
        Ok(Some(ResolverFile {
            content,
            device: after.dev(),
            inode: after.ino(),
            modified: (after.mtime(), after.mtime_nsec()),
        }))
    }

    fn replace(
        &self,
        domain: &str,
        expected: Option<&ResolverFile>,
        content: Option<&[u8]>,
        owner: &str,
    ) -> Result<Option<ResolverFile>> {
        if let Some(content) = content {
            validate_content(content, owner)?;
        }
        let current = self.read(domain)?;
        if current.as_ref() != expected {
            return Err(conflict(domain, "resolver object changed before mutation"));
        }
        if let Some(current) = &current
            && !current.content.starts_with(marker_for(owner).as_bytes())
        {
            return Err(conflict(domain, "resolver file is foreign"));
        }
        let Some(content) = content else {
            if current.is_some() {
                fs::unlinkat(&self.0, domain, AtFlags::empty()).map_err(std::io::Error::from)?;
                self.0.sync_all()?;
            }
            return Ok(None);
        };
        let name = format!(".osdns-{}", uuid::Uuid::new_v4().simple());
        let mut file: File = fs::openat(
            &self.0,
            &name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(std::io::Error::from)?
        .into();
        let result = (|| {
            file.write_all(content)?;
            fs::fchmod(&file, Mode::from_raw_mode(0o644)).map_err(std::io::Error::from)?;
            file.sync_all()?;
            if self.read(domain)?.as_ref() != expected {
                return Err(conflict(
                    domain,
                    "resolver object changed before publication",
                ));
            }
            fs::renameat(&self.0, &name, &self.0, domain).map_err(std::io::Error::from)?;
            self.0.sync_all()?;
            let meta = file.metadata()?;
            Ok(Some(ResolverFile {
                content: content.to_vec(),
                device: meta.dev(),
                inode: meta.ino(),
                modified: (meta.mtime(), meta.mtime_nsec()),
            }))
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&self.0, &name, AtFlags::empty());
        }
        result
    }
}

fn trusted(file: &File, directory: bool) -> Result<()> {
    let meta = file.metadata()?;
    if meta.uid() != 0
        || meta.mode() & 0o022 != 0
        || meta.is_dir() != directory
        || (!directory && (!meta.is_file() || meta.nlink() != 1))
    {
        return Err(Error::UnsafeFilesystem(
            "resolver entry has an unexpected owner, type, mode or hard-link count".to_string(),
        ));
    }
    use std::ffi::c_void;
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: i32, kind: i32) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry_id: i32, entry: *mut *mut c_void) -> i32;
        fn acl_valid(acl: *mut c_void) -> i32;
        fn acl_free(acl: *mut c_void) -> i32;
    }
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(2) {
            Ok(())
        } else {
            Err(error.into())
        };
    }
    if unsafe { acl_valid(acl) } != 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            acl_free(acl);
        }
        return Err(error.into());
    }
    let mut entry = std::ptr::null_mut();
    let status = unsafe { acl_get_entry(acl, 0, &mut entry) };
    let error = std::io::Error::last_os_error();
    unsafe {
        acl_free(acl);
    }
    if status == 0 {
        Err(Error::UnsafeFilesystem(
            "resolver entry has an extended ACL".to_string(),
        ))
    } else if error.raw_os_error() == Some(22) {
        // Darwin's valid empty ACL has no first entry and reports EINVAL.
        Ok(())
    } else {
        Err(error.into())
    }
}

fn validate_domain(domain: &str) -> Result<()> {
    let suffix = crate::DnsSuffix::parse(domain)?;
    if suffix.is_root() || suffix.as_str() != domain {
        return Err(Error::invalid_config("noncanonical scoped resolver domain"));
    }
    Ok(())
}

fn conflict(domain: &str, detail: &str) -> Error {
    Error::ExternalModification {
        resource: format!("macos:resolver:{domain}")
            .parse()
            .expect("validated resolver domain"),
        detail: detail.to_string(),
    }
}

pub(crate) fn read(domain: &str) -> Result<Option<ResolverFile>> {
    validate_domain(domain)?;
    match ResolverDir::open(false)? {
        Some(dir) => dir.read(domain),
        None => Ok(None),
    }
}

pub(crate) fn replace(
    domain: &str,
    expected: Option<&ResolverFile>,
    content: Option<&[u8]>,
    owner: &str,
) -> Result<Option<ResolverFile>> {
    validate_domain(domain)?;
    match ResolverDir::open(content.is_some())? {
        Some(dir) => dir.replace(domain, expected, content, owner),
        None if expected.is_none() && content.is_none() => Ok(None),
        None => Err(conflict(domain, "resolver directory disappeared")),
    }
}

pub(crate) fn validate_content(content: &[u8], owner: &str) -> Result<()> {
    if content.len() > 16 * 1024 * 1024 || !content.starts_with(marker_for(owner).as_bytes()) {
        return Err(Error::JournalCorrupt(
            "resolver payload has an invalid owner marker or size".to_string(),
        ));
    }
    crate::platform::text_config::parse_resolv_conf_content(content)?;
    Ok(())
}
