use std::fs;
use std::io;
use std::path::Path;

use crate::error::{Error, Result};

pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    match fs::create_dir_all(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return Err(Error::RequiresPrivilege(format!(
                "cannot create directory {}: {e}",
                path.display()
            )));
        }
        Err(e) => return Err(e.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path)?;
        if meta.permissions().mode() & 0o077 != 0 {
            match fs::set_permissions(path, fs::Permissions::from_mode(0o700)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    return Err(Error::RequiresPrivilege(format!(
                        "directory {} is accessible to other users and could not be restricted: {e}",
                        path.display()
                    )));
                }
                Err(e) => return Err(e.into()),
            }
            let meta = fs::metadata(path)?;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(Error::RequiresPrivilege(format!(
                    "directory {} is accessible to other users and could not be restricted",
                    path.display()
                )));
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(crate) fn fsync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let file = fs::File::open(path)?;
        file.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}
