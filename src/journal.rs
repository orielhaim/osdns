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
use crate::platform::PlatformSnapshot;

/// Current journal schema. Records with any other version are rejected
/// (fail-closed) rather than guessed at.
pub(crate) const SCHEMA_VERSION: u32 = 1;

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
    pub(crate) phase: Phase,
    pub(crate) before: PlatformSnapshot,
    pub(crate) desired: NormalizedConfig,
    pub(crate) applied: Option<PlatformSnapshot>,
}

fn record_file_name(lease_id: &Uuid, resource: &ResourceId) -> String {
    format!("{}-{}.json", lease_id.simple(), resource.slug())
}

fn record_path(dir: &Path, lease_id: &Uuid, resource: &ResourceId) -> PathBuf {
    dir.join(record_file_name(lease_id, resource))
}

/// Durable store of journal records, one file per (lease, resource).
///
/// Writes are atomic and fsynced. Any record that fails to parse, or that
/// carries an unknown schema version, makes every reader fail closed.
#[derive(Debug)]
pub(crate) struct JournalStore {
    dir: PathBuf,
}

impl JournalStore {
    pub(crate) fn open(dir: PathBuf) -> Result<Self> {
        ensure_private_dir(&dir)?;
        Ok(Self { dir })
    }

    #[allow(dead_code)]
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn write(&self, record: &JournalRecord) -> Result<()> {
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
            let record: JournalRecord = serde_json::from_slice(&bytes)
                .map_err(|e| Error::JournalCorrupt(format!("{}: {e}", path.display())))?;
            if record.schema_version != SCHEMA_VERSION {
                return Err(Error::JournalCorrupt(format!(
                    "{}: unsupported journal schema version {} (supported: {})",
                    path.display(),
                    record.schema_version,
                    SCHEMA_VERSION
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
