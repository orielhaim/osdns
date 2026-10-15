use std::io;
use std::path::Path;

use crate::error::{Error, Result};

pub(crate) fn private_error(error: private_fs::Error) -> Error {
    match error {
        private_fs::Error::Io(error) => error.into(),
        error => Error::UnsafeFilesystem(error.to_string()),
    }
}

pub(crate) fn ensure_private_dir(path: &Path) -> Result<private_fs::PrivateDir> {
    match private_fs::PrivateDir::ensure(path) {
        Ok(dir) => Ok(dir),
        Err(private_fs::Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .ok_or_else(|| Error::invalid_config("state directory has no parent"))?;
            let parent = ensure_private_dir(parent)?;
            let name = path
                .file_name()
                .ok_or_else(|| Error::invalid_config("invalid state directory"))?;
            parent.ensure_dir(name).map_err(private_error)
        }
        Err(error) => Err(private_error(error)),
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
pub(crate) fn fsync_dir(path: &Path) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}
