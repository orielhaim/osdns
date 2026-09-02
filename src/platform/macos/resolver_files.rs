//! Scoped resolver files under `/etc/resolver/<domain>`.
//!
//! One file per routing domain, named after the domain itself. Ownership is
//! exact: a file carries a first-line `# osdns owner=<owner>` marker, and a
//! file that exists without our marker (written by another osdns owner or by
//! the user) is never overwritten — the apply reports a conflict instead.

use std::path::{Path, PathBuf};

use crate::error::Result;

const RESOLVER_DIR: &str = "/etc/resolver";
const MARKER_PREFIX: &str = "# osdns owner=";

pub(crate) fn marker_for(owner: &str) -> String {
    format!("{MARKER_PREFIX}{owner}\n")
}

fn file_path(domain: &str) -> PathBuf {
    Path::new(RESOLVER_DIR).join(domain)
}

pub(crate) fn read(domain: &str) -> Result<Option<Vec<u8>>> {
    match std::fs::read(file_path(domain)) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Detail about who owns an existing file, for conflict reporting.
pub(crate) fn foreign_claim(domain: &str, owner: &str) -> Result<Option<String>> {
    let Some(bytes) = read(domain)? else {
        return Ok(None);
    };
    let head = String::from_utf8_lossy(&bytes);
    let first = head.lines().next().unwrap_or_default();
    if first == marker_for(owner).trim_end() {
        return Ok(None);
    }
    if let Some(other) = first.strip_prefix(MARKER_PREFIX) {
        Ok(Some(format!(
            "/etc/resolver/{domain} is owned by the other osdns owner {other:?}"
        )))
    } else {
        Ok(Some(format!(
            "/etc/resolver/{domain} already exists and was not written by osdns"
        )))
    }
}

pub(crate) fn write(domain: &str, content: &[u8]) -> Result<()> {
    std::fs::create_dir_all(RESOLVER_DIR)?;
    let mut file = atomic_write_file::AtomicWriteFile::open(file_path(domain))?;
    std::io::Write::write_all(&mut file, content)?;
    file.sync_all()?;
    file.commit()?;
    Ok(())
}

pub(crate) fn delete(domain: &str) -> Result<()> {
    match std::fs::remove_file(file_path(domain)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
