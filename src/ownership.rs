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

/// The current locking and mutation target for one OS DNS resource.
///
/// Examples: `linux:resolved:ifindex:7`, `windows:interface:<guid>`,
/// `macos:resolver:<domain>`. Resource ids are the unit of ownership: every
/// mutation holds an exclusive inter-process lock on its resource id, journals
/// are keyed by it. It is not necessarily a durable native-incarnation
/// identity: interface indices, names, and similar selectors can be reused.
/// Ids are lowercase `:`-separated segments (max 128 characters).
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
    /// Suitable as a current-process map key or for logging. Backend-specific
    /// lifetime rules determine whether it remains meaningful after restart.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Filesystem escaping: `:` becomes `+`, which cannot appear in a
    /// valid id, so distinct ids never share a slug. Callers append
    /// [`ResourceId::stable_hash`] for uniqueness on case-insensitive
    /// filesystems.
    pub(crate) fn slug(&self) -> String {
        self.0.replace(':', "+")
    }

    /// Stable content hash of this id. It covers the id only, never the
    /// lock namespace, so every manager sharing a lock directory contends
    /// on the same file.
    pub(crate) fn stable_hash(&self) -> String {
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, self.0.as_bytes())
            .simple()
            .to_string()
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

/// One lockable OS resource inside one ownership universe. The namespace
/// identifies the mutated state (the global OS for real backends, one
/// simulated instance per test fake); exclusion applies exactly when both
/// match, independent of journal storage configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RegistryKey {
    namespace: String,
    resource: ResourceId,
}

/// Namespace for real operating-system resources: globally authoritative.
pub(crate) const GLOBAL_LOCK_NAMESPACE: &str = "osdns:global-os";

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

/// Exclusive inter-process locks over DNS resources. The lock directory is
/// independent of journal storage, so managers with different state
/// directories still exclude each other on the same resource.
#[derive(Debug)]
pub(crate) struct ResourceLockManager {
    lock_dir: PathBuf,
    lock_timeout: Duration,
    namespace: String,
}

impl ResourceLockManager {
    pub(crate) fn new(lock_dir: PathBuf, lock_timeout: Duration) -> Self {
        Self::with_namespace(lock_dir, lock_timeout, GLOBAL_LOCK_NAMESPACE)
    }

    pub(crate) fn with_namespace(
        lock_dir: PathBuf,
        lock_timeout: Duration,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            lock_dir,
            lock_timeout,
            namespace: namespace.into(),
        }
    }

    pub(crate) fn ensure_dir(&self) -> Result<()> {
        ensure_private_dir(&self.lock_dir)
    }

    pub(crate) fn acquire(&self, resource: &ResourceId) -> Result<ResourceLock> {
        // Lazy so read-only manager use never requires lock-directory
        // privileges; the first mutation creates it instead.
        self.ensure_dir()?;
        let key = RegistryKey {
            namespace: self.namespace.clone(),
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
        self.ensure_dir()?;
        let key = RegistryKey {
            namespace: self.namespace.clone(),
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
        // The name excludes the ownership namespace so every manager
        // sharing this directory contends on the same file.
        let path = self.lock_dir.join(format!(
            "{}-{}.lock",
            resource.slug(),
            resource.stable_hash()
        ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_and_hashes_are_collision_free() {
        // Ids differing only in separator placement must never share a
        // lock file.
        let a = ResourceId::new("fake:a_b").unwrap();
        let b = ResourceId::new("fake:a:b").unwrap();
        assert_ne!(a.slug(), b.slug());
        assert_ne!(a.stable_hash(), b.stable_hash());
        assert_ne!(
            format!("{}-{}.lock", a.slug(), a.stable_hash()),
            format!("{}-{}.lock", b.slug(), b.stable_hash())
        );
    }

    #[test]
    fn windows_guid_resources_slug_without_collisions() {
        let a = ResourceId::new("windows:interface:11111111-2222-3333-4444-555555555555").unwrap();
        let b = ResourceId::new("windows:interface:11111111-2222-3333-4444-555555555556").unwrap();
        assert_ne!(a.stable_hash(), b.stable_hash());
    }
}
