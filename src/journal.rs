use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::capability::BackendKind;
use crate::error::{Error, Result};
use crate::fsutil::{ensure_private_dir, fsync_dir};
use crate::normalize::NormalizedConfig;
use crate::ownership::ResourceId;
use crate::platform::{PlatformSnapshot, ResourceIdentity};

/// Current journal schema. Records with any other version are rejected
/// (fail-closed) rather than guessed at.
pub(crate) const SCHEMA_VERSION: u32 = 3;

#[derive(Deserialize)]
struct JournalEnvelope {
    schema_version: u32,
}

/// The phase a journal record reached before its writer stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Phase {
    /// The transaction persisted its intent but the mutation has not been
    /// verified (it may or may not have taken effect).
    Prepared,
    /// The mutation was applied and verified by read-back.
    Applied,
}

/// One durable transaction record: what the resource looked like before, what
/// we intended to apply, and (once known) what we actually applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JournalRecord {
    pub(crate) schema_version: u32,
    pub(crate) owner: String,
    pub(crate) lease_id: Uuid,
    pub(crate) resource: ResourceId,
    pub(crate) backend: BackendKind,
    pub(crate) identity: ResourceIdentity,
    pub(crate) phase: Phase,
    pub(crate) before: PlatformSnapshot,
    pub(crate) desired: NormalizedConfig,
    pub(crate) applied: Option<PlatformSnapshot>,
}

fn record_file_name(lease_id: &Uuid, resource: &ResourceId) -> String {
    format!(
        "{}-{}-{}.json",
        lease_id.simple(),
        resource.slug(),
        resource.stable_hash()
    )
}

fn record_path(dir: &Path, lease_id: &Uuid, resource: &ResourceId) -> PathBuf {
    dir.join(record_file_name(lease_id, resource))
}

/// Durable store of journal records, one file per (lease, resource).
///
/// Writes are atomic and fsynced. Readers reject incompatible versions from
/// the minimal envelope, then deserialize and validate the current schema.
#[derive(Debug)]
pub(crate) struct JournalStore {
    dir: PathBuf,
    #[cfg(feature = "test-util")]
    fail_writes: std::sync::atomic::AtomicBool,
    #[cfg(feature = "test-util")]
    fail_writes_skip: std::sync::atomic::AtomicU32,
    #[cfg(feature = "test-util")]
    fail_removes: std::sync::atomic::AtomicBool,
}

impl JournalStore {
    pub(crate) fn open(dir: PathBuf) -> Result<Self> {
        ensure_private_dir(&dir)?;
        Ok(Self {
            dir,
            #[cfg(feature = "test-util")]
            fail_writes: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "test-util")]
            fail_writes_skip: std::sync::atomic::AtomicU32::new(0),
            #[cfg(feature = "test-util")]
            fail_removes: std::sync::atomic::AtomicBool::new(false),
        })
    }

    #[cfg(feature = "test-util")]
    pub(crate) fn set_fail_writes(&self, fail: bool) {
        self.fail_writes
            .store(fail, std::sync::atomic::Ordering::SeqCst);
        if !fail {
            self.fail_writes_skip
                .store(0, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[cfg(feature = "test-util")]
    pub(crate) fn set_fail_writes_after(&self, skip: u32) {
        self.fail_writes_skip
            .store(skip, std::sync::atomic::Ordering::SeqCst);
        self.fail_writes
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(feature = "test-util")]
    pub(crate) fn set_fail_removes(&self, fail: bool) {
        self.fail_removes
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn write(&self, record: &JournalRecord) -> Result<()> {
        #[cfg(feature = "test-util")]
        if self.fail_writes.load(std::sync::atomic::Ordering::SeqCst) {
            let skip = self
                .fail_writes_skip
                .load(std::sync::atomic::Ordering::SeqCst);
            if skip > 0 {
                self.fail_writes_skip
                    .store(skip - 1, std::sync::atomic::Ordering::SeqCst);
            } else {
                return Err(Error::platform(
                    record.backend,
                    format_args!("injected journal write failure"),
                ));
            }
        }
        let path = record_path(&self.dir, &record.lease_id, &record.resource);
        let bytes = serde_json::to_vec_pretty(record).map_err(|e| {
            Error::platform(
                record.backend,
                format_args!("journal record serialization failed: {e}"),
            )
        })?;
        let mut file = atomic_write_file::AtomicWriteFile::open(&path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        file.commit()?;
        fsync_dir(&self.dir)?;
        Ok(())
    }

    pub(crate) fn remove(&self, lease_id: &Uuid, resource: &ResourceId) -> Result<bool> {
        #[cfg(feature = "test-util")]
        if self.fail_removes.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::platform(
                BackendKind::Fake,
                "injected journal removal failure",
            ));
        }
        let path = record_path(&self.dir, lease_id, resource);
        match fs::remove_file(&path) {
            Ok(()) => {
                fsync_dir(&self.dir)?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub(crate) fn records(&self) -> Result<Vec<JournalRecord>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(&path)?;
            let envelope: JournalEnvelope = serde_json::from_slice(&bytes)
                .map_err(|e| Error::JournalCorrupt(format!("{}: {e}", path.display())))?;
            if envelope.schema_version != SCHEMA_VERSION {
                return Err(Error::UnsupportedJournalVersion {
                    path,
                    found: envelope.schema_version,
                    supported: SCHEMA_VERSION,
                });
            }
            let record: JournalRecord = serde_json::from_slice(&bytes)
                .map_err(|e| Error::JournalCorrupt(format!("{}: {e}", path.display())))?;
            if record.backend != record.before.backend
                || record.backend != record.identity.backend
                || record.resource != record.before.resource
                || record.resource != record.identity.resource
                || record.applied.as_ref().is_some_and(|snapshot| {
                    snapshot.backend != record.backend || snapshot.resource != record.resource
                })
            {
                return Err(Error::JournalCorrupt(format!(
                    "{}: record, identity, and snapshots name different resources or backends",
                    path.display()
                )));
            }
            out.push(record);
        }
        Ok(out)
    }

    pub(crate) fn records_for(&self, resource: &ResourceId) -> Result<Vec<JournalRecord>> {
        Ok(self
            .records()?
            .into_iter()
            .filter(|record| &record.resource == resource)
            .collect())
    }
}
