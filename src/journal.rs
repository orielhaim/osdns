use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::capability::BackendKind;
use crate::error::{Error, Result};
use crate::fsutil::{ensure_private_dir, fsync_dir};
use crate::normalize::NormalizedConfig;
use crate::ownership::ResourceId;
use crate::platform::{IdentityData, PlatformSnapshot, ResourceIdentity, SnapshotData};

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
#[derive(Debug, Clone)]
pub(crate) struct JournalRecord {
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

#[derive(Deserialize)]
struct JournalRecordV3 {
    #[serde(rename = "schema_version")]
    _schema_version: u32,
    owner: String,
    lease_id: Uuid,
    resource: ResourceId,
    backend: BackendKind,
    identity: ResourceIdentityV3,
    phase: Phase,
    before: PlatformSnapshotV3,
    desired: NormalizedConfig,
    applied: Option<PlatformSnapshotV3>,
}

#[derive(Deserialize)]
struct PlatformSnapshotV3 {
    backend: BackendKind,
    resource: ResourceId,
    data: serde_json::Value,
}

#[derive(Deserialize)]
struct ResourceIdentityV3 {
    backend: BackendKind,
    resource: ResourceId,
    data: serde_json::Value,
}

#[derive(Serialize)]
struct JournalRecordV3Ref<'a> {
    schema_version: u32,
    owner: &'a str,
    lease_id: Uuid,
    resource: &'a ResourceId,
    backend: BackendKind,
    identity: ResourceIdentityV3Ref<'a>,
    phase: Phase,
    before: PlatformSnapshotV3Ref<'a>,
    desired: &'a NormalizedConfig,
    applied: Option<PlatformSnapshotV3Ref<'a>>,
}

#[derive(Serialize)]
struct PlatformSnapshotV3Ref<'a> {
    backend: BackendKind,
    resource: &'a ResourceId,
    data: serde_json::Value,
}

#[derive(Serialize)]
struct ResourceIdentityV3Ref<'a> {
    backend: BackendKind,
    resource: &'a ResourceId,
    data: serde_json::Value,
}

impl<'a> TryFrom<&'a JournalRecord> for JournalRecordV3Ref<'a> {
    type Error = String;

    fn try_from(record: &'a JournalRecord) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            owner: &record.owner,
            lease_id: record.lease_id,
            resource: &record.resource,
            backend: record.backend,
            identity: ResourceIdentityV3Ref {
                backend: record.identity.backend,
                resource: &record.identity.resource,
                data: encode_identity(&record.identity.data)?,
            },
            phase: record.phase,
            before: PlatformSnapshotV3Ref::try_from(&record.before)?,
            desired: &record.desired,
            applied: record
                .applied
                .as_ref()
                .map(PlatformSnapshotV3Ref::try_from)
                .transpose()?,
        })
    }
}

impl<'a> TryFrom<&'a PlatformSnapshot> for PlatformSnapshotV3Ref<'a> {
    type Error = String;

    fn try_from(snapshot: &'a PlatformSnapshot) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            backend: snapshot.backend,
            resource: &snapshot.resource,
            data: encode_snapshot(&snapshot.data)?,
        })
    }
}

impl TryFrom<JournalRecordV3> for JournalRecord {
    type Error = String;

    fn try_from(record: JournalRecordV3) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            owner: record.owner,
            lease_id: record.lease_id,
            resource: record.resource,
            backend: record.backend,
            identity: ResourceIdentity {
                backend: record.identity.backend,
                resource: record.identity.resource,
                data: decode_identity(record.identity.backend, record.identity.data)?,
            },
            phase: record.phase,
            before: record.before.try_into()?,
            desired: record.desired,
            applied: record.applied.map(TryInto::try_into).transpose()?,
        })
    }
}

impl TryFrom<PlatformSnapshotV3> for PlatformSnapshot {
    type Error = String;

    fn try_from(snapshot: PlatformSnapshotV3) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            backend: snapshot.backend,
            resource: snapshot.resource,
            data: decode_snapshot(snapshot.backend, snapshot.data)?,
        })
    }
}

fn encode_snapshot(data: &SnapshotData) -> std::result::Result<serde_json::Value, String> {
    match data {
        #[cfg(feature = "test-util")]
        SnapshotData::Fake(value) => serde_json::to_value(value),
        #[cfg(target_os = "linux")]
        SnapshotData::SystemdResolved(value) => serde_json::to_value(value),
        #[cfg(target_os = "linux")]
        SnapshotData::NetworkManager(value) => serde_json::to_value(value),
        #[cfg(target_os = "linux")]
        SnapshotData::Resolvconf(value) => serde_json::to_value(value),
        #[cfg(target_os = "linux")]
        SnapshotData::ResolvConfFile(value) => serde_json::to_value(value),
        #[cfg(target_os = "macos")]
        SnapshotData::MacosSystemConfiguration(value) => serde_json::to_value(value),
        #[cfg(target_os = "windows")]
        SnapshotData::WindowsIpHelper(value) => serde_json::to_value(value),
    }
    .map_err(|error| error.to_string())
}

fn decode_snapshot(
    backend: BackendKind,
    data: serde_json::Value,
) -> std::result::Result<SnapshotData, String> {
    match backend {
        #[cfg(feature = "test-util")]
        BackendKind::Fake => serde_json::from_value(data).map(SnapshotData::Fake),
        #[cfg(target_os = "linux")]
        BackendKind::SystemdResolved => {
            serde_json::from_value(data).map(SnapshotData::SystemdResolved)
        }
        #[cfg(target_os = "linux")]
        BackendKind::NetworkManager => {
            serde_json::from_value(data).map(SnapshotData::NetworkManager)
        }
        #[cfg(target_os = "linux")]
        BackendKind::Resolvconf => serde_json::from_value(data).map(SnapshotData::Resolvconf),
        #[cfg(target_os = "linux")]
        BackendKind::ResolvConfFile => {
            serde_json::from_value(data).map(SnapshotData::ResolvConfFile)
        }
        #[cfg(target_os = "macos")]
        BackendKind::MacosSystemConfiguration => {
            serde_json::from_value(data).map(SnapshotData::MacosSystemConfiguration)
        }
        #[cfg(target_os = "windows")]
        BackendKind::WindowsIpHelper => {
            serde_json::from_value(data).map(SnapshotData::WindowsIpHelper)
        }
        _ => return Err(format!("backend {backend} is unavailable on this platform")),
    }
    .map_err(|error| error.to_string())
}

fn encode_identity(data: &IdentityData) -> std::result::Result<serde_json::Value, String> {
    match data {
        IdentityData::Untracked => Ok(serde_json::Value::Null),
        #[cfg(feature = "test-util")]
        IdentityData::Fake(value) => serde_json::to_value(value).map_err(|error| error.to_string()),
        #[cfg(target_os = "linux")]
        IdentityData::SystemdResolved(value) => {
            serde_json::to_value(value).map_err(|error| error.to_string())
        }
        #[cfg(target_os = "linux")]
        IdentityData::NetworkManager(value) => {
            serde_json::to_value(value).map_err(|error| error.to_string())
        }
    }
}

fn decode_identity(
    backend: BackendKind,
    data: serde_json::Value,
) -> std::result::Result<IdentityData, String> {
    match backend {
        #[cfg(feature = "test-util")]
        BackendKind::Fake => serde_json::from_value(data)
            .map(IdentityData::Fake)
            .map_err(|error| error.to_string()),
        #[cfg(target_os = "linux")]
        BackendKind::SystemdResolved => serde_json::from_value(data)
            .map(IdentityData::SystemdResolved)
            .map_err(|error| error.to_string()),
        #[cfg(target_os = "linux")]
        BackendKind::NetworkManager => serde_json::from_value(data)
            .map(IdentityData::NetworkManager)
            .map_err(|error| error.to_string()),
        BackendKind::Resolvconf
        | BackendKind::ResolvConfFile
        | BackendKind::WindowsIpHelper
        | BackendKind::MacosSystemConfiguration
            if data.is_null() =>
        {
            Ok(IdentityData::Untracked)
        }
        _ => Err(format!("invalid identity data for backend {backend}")),
    }
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
        let durable = JournalRecordV3Ref::try_from(record).map_err(|e| {
            Error::platform(
                record.backend,
                format_args!("journal record conversion failed: {e}"),
            )
        })?;
        let mut file = atomic_write_file::AtomicWriteFile::open(&path)?;
        serde_json::to_writer_pretty(&mut file, &durable).map_err(|e| {
            Error::platform(
                record.backend,
                format_args!("journal record serialization failed: {e}"),
            )
        })?;
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
            let record = decode_record(&path, &bytes)?;
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

fn decode_record(path: &Path, bytes: &[u8]) -> Result<JournalRecord> {
    let envelope: JournalEnvelope = serde_json::from_slice(bytes)
        .map_err(|e| Error::JournalCorrupt(format!("{}: {e}", path.display())))?;
    if envelope.schema_version != SCHEMA_VERSION {
        return Err(Error::UnsupportedJournalVersion {
            path: path.to_path_buf(),
            found: envelope.schema_version,
            supported: SCHEMA_VERSION,
        });
    }
    let durable: JournalRecordV3 = serde_json::from_slice(bytes)
        .map_err(|e| Error::JournalCorrupt(format!("{}: {e}", path.display())))?;
    JournalRecord::try_from(durable)
        .map_err(|e| Error::JournalCorrupt(format!("{}: {e}", path.display())))
}

#[cfg(feature = "test-util")]
pub(crate) fn decode_for_fuzzing(bytes: &[u8]) -> Result<()> {
    decode_record(Path::new("fuzz-journal.json"), bytes).map(|_| ())
}
