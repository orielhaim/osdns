use std::collections::HashSet;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{ConflictReason, Error, Result};
use crate::fsutil::ensure_private_dir;

/// A stable identifier for one independently mutable OS DNS resource.
///
/// Examples: `linux:resolved:ifindex:7`, `windows:interface:<guid>`,
/// `macos:resolver:<domain>`. Resource ids are the unit of ownership: every
/// mutation holds an exclusive inter-process lock on its resource id, journals
/// are keyed by it, and restore/conflict decisions are made per id. Ids are
/// lowercase `:`-separated segments (max 128 characters) and survive reboots.
/// Obtain them from [`Lease::resources`](crate::Lease::resources) or [`RecoveryOutcome`](crate::RecoveryOutcome);
/// parse with `"<id>".parse::<ResourceId>()`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceId(String);

impl ResourceId {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_resource_id(&value)?;
        Ok(Self(value))
    }

    /// The canonical string form, e.g. `linux:resolved:ifindex:7`.
    ///
    /// Stable across reboots; suitable as a map key or for logging.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn slug(&self) -> String {
        self.0
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.') {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }
}

fn validate_resource_id(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::invalid_config("resource id must not be empty"));
    }
    if value.len() > 128 {
        return Err(Error::invalid_config("resource id exceeds 128 characters"));
    }
    for c in value.chars() {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, ':' | '-' | '_' | '.')) {
            return Err(Error::invalid_config(format_args!(
                "resource id {value:?} contains invalid character {c:?}"
            )));
        }
    }
    if value.split(':').any(str::is_empty) {
        return Err(Error::invalid_config(format_args!(
            "resource id {value:?} contains an empty segment"
        )));
    }
    Ok(())
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ResourceId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        ResourceId::new(s)
    }
}

impl TryFrom<String> for ResourceId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        ResourceId::new(value)
    }
}

impl Serialize for ResourceId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ResourceId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        validate_resource_id(&raw).map_err(serde::de::Error::custom)?;
        Ok(Self(raw))
    }
}

const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RegistryKey {
    lock_dir: PathBuf,
    resource: ResourceId,
}

fn registry() -> MutexGuard<'static, Option<HashSet<RegistryKey>>> {
    static REGISTRY: Mutex<Option<HashSet<RegistryKey>>> = Mutex::new(None);
    REGISTRY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn registry_contains(key: &RegistryKey) -> bool {
    registry().as_ref().is_some_and(|set| set.contains(key))
}

fn registry_insert(key: RegistryKey) {
    registry().get_or_insert_with(HashSet::new).insert(key);
}

fn registry_remove(key: &RegistryKey) {
    if let Some(set) = registry().as_mut() {
        set.remove(key);
    }
}

/// Acquires and holds inter-process exclusive locks over DNS resources.
#[derive(Debug)]
pub(crate) struct ResourceLockManager {
    lock_dir: PathBuf,
    lock_timeout: Duration,
}

impl ResourceLockManager {
    pub(crate) fn new(lock_dir: PathBuf, lock_timeout: Duration) -> Self {
        Self {
            lock_dir,
            lock_timeout,
        }
    }

    pub(crate) fn ensure_dir(&self) -> Result<()> {
        ensure_private_dir(&self.lock_dir)
    }

    pub(crate) fn acquire(&self, resource: &ResourceId) -> Result<ResourceLock> {
        let key = RegistryKey {
            lock_dir: self.lock_dir.clone(),
            resource: resource.clone(),
        };
        let file = self.open_lock_file(resource)?;
        let deadline = Instant::now() + self.lock_timeout;
        loop {
            if registry_contains(&key) {
                return Err(Error::Conflict {
                    resource: resource.clone(),
                    reason: ConflictReason::AlreadyLeasedInProcess,
                });
            }
            match file.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(Error::Timeout {
                            resource: resource.clone(),
                            operation: "acquiring the resource lock".to_string(),
                        });
                    }
                    thread::sleep(LOCK_POLL_INTERVAL);
                }
                Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
            }
        }
        registry_insert(key.clone());
        Ok(ResourceLock { _file: file, key })
    }

    /// Acquires exclusive locks over every resource, in sorted order so that
    /// multi-resource leases can never deadlock with each other. On failure
    /// all already-acquired locks are released.
    pub(crate) fn acquire_all(&self, resources: &[ResourceId]) -> Result<Vec<ResourceLock>> {
        let mut sorted: Vec<&ResourceId> = resources.iter().collect();
        sorted.sort();
        sorted.dedup();
        let mut locks = Vec::with_capacity(sorted.len());
        for resource in sorted {
            match self.acquire(resource) {
                Ok(lock) => locks.push(lock),
                Err(error) => {
                    drop(locks);
                    return Err(error);
                }
            }
        }
        Ok(locks)
    }

    pub(crate) fn try_acquire(&self, resource: &ResourceId) -> Result<Option<ResourceLock>> {
        let key = RegistryKey {
            lock_dir: self.lock_dir.clone(),
            resource: resource.clone(),
        };
        if registry_contains(&key) {
            return Ok(None);
        }
        let file = self.open_lock_file(resource)?;
        match file.try_lock() {
            Ok(()) => {
                registry_insert(key.clone());
                Ok(Some(ResourceLock { _file: file, key }))
            }
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
        }
    }

    fn open_lock_file(&self, resource: &ResourceId) -> Result<File> {
        let path = self.lock_dir.join(format!("{}.lock", resource.slug()));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
        {
            Ok(file) => Ok(file),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Err(Error::RequiresPrivilege(
                format!("cannot open lock file {}: {e}", path.display()),
            )),
            Err(e) => Err(e.into()),
        }
    }
}

/// A held exclusive lock over one resource. Released on drop.
#[derive(Debug)]
pub(crate) struct ResourceLock {
    _file: File,
    key: RegistryKey,
}

impl ResourceLock {
    #[allow(dead_code)]
    pub(crate) fn resource(&self) -> &ResourceId {
        &self.key.resource
    }
}

impl Drop for ResourceLock {
    fn drop(&mut self) {
        registry_remove(&self.key);
        let _ = self._file.unlock();
    }
}
