use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::capability::BackendKind;
use crate::error::{Error, Result};
use crate::fsutil::{ensure_private_dir, private_error};
use crate::normalize::NormalizedConfig;
use crate::ownership::ResourceId;
use crate::platform::{IdentityData, PlatformSnapshot, ResourceIdentity, SnapshotData};

/// Current journal schema. Records with any other version are rejected
/// (fail-closed) rather than guessed at.
pub(crate) const SCHEMA_VERSION: u32 = 4;
// A symmetric storage budget, including preserved native fields.
const MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;

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
#[serde(deny_unknown_fields)]
struct JournalRecordV4 {
    #[serde(rename = "schema_version")]
    _schema_version: u32,
    owner: String,
    lease_id: Uuid,
    resource: ResourceId,
    backend: BackendKind,
    identity: ResourceIdentityV4,
    phase: Phase,
    before: PlatformSnapshotV4,
    desired: NormalizedConfig,
    applied: Option<PlatformSnapshotV4>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformSnapshotV4 {
    backend: BackendKind,
    resource: ResourceId,
    data: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceIdentityV4 {
    backend: BackendKind,
    resource: ResourceId,
    data: serde_json::Value,
}

#[derive(Serialize)]
struct JournalRecordV4Ref<'a> {
    schema_version: u32,
    owner: &'a str,
    lease_id: Uuid,
    resource: &'a ResourceId,
    backend: BackendKind,
    identity: ResourceIdentityV4Ref<'a>,
    phase: Phase,
    before: PlatformSnapshotV4Ref<'a>,
    desired: &'a NormalizedConfig,
    applied: Option<PlatformSnapshotV4Ref<'a>>,
}

#[derive(Serialize)]
struct PlatformSnapshotV4Ref<'a> {
    backend: BackendKind,
    resource: &'a ResourceId,
    data: serde_json::Value,
}

#[derive(Serialize)]
struct ResourceIdentityV4Ref<'a> {
    backend: BackendKind,
    resource: &'a ResourceId,
    data: serde_json::Value,
}

impl<'a> TryFrom<&'a JournalRecord> for JournalRecordV4Ref<'a> {
    type Error = String;

    fn try_from(record: &'a JournalRecord) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            owner: &record.owner,
            lease_id: record.lease_id,
            resource: &record.resource,
            backend: record.backend,
            identity: ResourceIdentityV4Ref {
                backend: record.identity.backend,
                resource: &record.identity.resource,
                data: encode_identity(&record.identity.data)?,
            },
            phase: record.phase,
            before: PlatformSnapshotV4Ref::try_from(&record.before)?,
            desired: &record.desired,
            applied: record
                .applied
                .as_ref()
                .map(PlatformSnapshotV4Ref::try_from)
                .transpose()?,
        })
    }
}

impl<'a> TryFrom<&'a PlatformSnapshot> for PlatformSnapshotV4Ref<'a> {
    type Error = String;

    fn try_from(snapshot: &'a PlatformSnapshot) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            backend: snapshot.backend,
            resource: &snapshot.resource,
            data: encode_snapshot(&snapshot.data)?,
        })
    }
}

impl TryFrom<JournalRecordV4> for JournalRecord {
    type Error = String;

    fn try_from(record: JournalRecordV4) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            owner: record.owner,
            lease_id: record.lease_id,
            resource: record.resource,
            backend: record.backend,
            identity: ResourceIdentity::new(
                record.identity.backend,
                record.identity.resource,
                decode_identity(record.identity.backend, record.identity.data)?,
            ),
            phase: record.phase,
            before: record.before.try_into()?,
            desired: record.desired,
            applied: record.applied.map(TryInto::try_into).transpose()?,
        })
    }
}

impl TryFrom<PlatformSnapshotV4> for PlatformSnapshot {
    type Error = String;

    fn try_from(snapshot: PlatformSnapshotV4) -> std::result::Result<Self, Self::Error> {
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
        SnapshotData::Fake(value) => serde_json::to_value(value).map_err(|error| error.to_string()),
        #[cfg(target_os = "linux")]
        SnapshotData::SystemdResolved(value) => {
            serde_json::to_value(value).map_err(|error| error.to_string())
        }
        #[cfg(target_os = "linux")]
        SnapshotData::NetworkManager(value) => {
            serde_json::to_value(value).map_err(|error| error.to_string())
        }
        #[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
        SnapshotData::Resolvconf(value) => {
            serde_json::to_value(value).map_err(|error| error.to_string())
        }
        #[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
        SnapshotData::ResolvConfFile(value) => {
            serde_json::to_value(value).map_err(|error| error.to_string())
        }
        #[cfg(target_os = "macos")]
        SnapshotData::MacosSystemConfiguration(value) => {
            serde_json::to_value(value).map_err(|error| error.to_string())
        }
        #[cfg(target_os = "windows")]
        SnapshotData::WindowsIpHelper(value) => {
            serde_json::to_value(value).map_err(|error| error.to_string())
        }
        #[cfg(not(any(
            feature = "test-util",
            target_os = "freebsd",
            target_os = "linux",
            target_os = "netbsd",
            target_os = "macos",
            target_os = "windows"
        )))]
        SnapshotData::NoOsBackend => {
            Err("no OS DNS backend is implemented for this target".to_string())
        }
    }
}

fn decode_snapshot(
    backend: BackendKind,
    data: serde_json::Value,
) -> std::result::Result<SnapshotData, String> {
    match backend {
        #[cfg(feature = "test-util")]
        BackendKind::Fake => serde_json::from_value(data)
            .map(SnapshotData::Fake)
            .map_err(|error| error.to_string()),
        #[cfg(target_os = "linux")]
        BackendKind::SystemdResolved => serde_json::from_value(data)
            .map(SnapshotData::SystemdResolved)
            .map_err(|error| error.to_string()),
        #[cfg(target_os = "linux")]
        BackendKind::NetworkManager => serde_json::from_value(data)
            .map(SnapshotData::NetworkManager)
            .map_err(|error| error.to_string()),
        #[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
        BackendKind::Resolvconf => serde_json::from_value(data)
            .map(SnapshotData::Resolvconf)
            .map_err(|error| error.to_string()),
        #[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
        BackendKind::ResolvConfFile => serde_json::from_value(data)
            .map(SnapshotData::ResolvConfFile)
            .map_err(|error| error.to_string()),
        #[cfg(target_os = "macos")]
        BackendKind::MacosSystemConfiguration => serde_json::from_value(data)
            .map(SnapshotData::MacosSystemConfiguration)
            .map_err(|error| error.to_string()),
        #[cfg(target_os = "windows")]
        BackendKind::WindowsIpHelper => serde_json::from_value(data)
            .map(SnapshotData::WindowsIpHelper)
            .map_err(|error| error.to_string()),
        _ => {
            let _ = data;
            Err(format!("backend {backend} is unavailable on this platform"))
        }
    }
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

fn publication_error(error: private_fs::Error) -> Error {
    match error {
        private_fs::Error::AtomicCommit {
            may_have_published,
            source,
        } => Error::JournalPublication {
            may_have_published,
            source: *source,
        },
        error => private_error(error),
    }
}

/// Durable store of journal records, one file per (lease, resource).
///
/// Writes are atomic and fsynced. Readers reject incompatible versions from
/// the minimal envelope, then deserialize and validate the current schema.
#[derive(Debug)]
pub(crate) struct JournalStore {
    dir: PathBuf,
    handle: OnceLock<private_fs::PrivateDir>,
    #[cfg(feature = "test-util")]
    fail_writes: std::sync::atomic::AtomicBool,
    #[cfg(feature = "test-util")]
    fail_writes_skip: std::sync::atomic::AtomicU32,
    #[cfg(feature = "test-util")]
    fail_removes: std::sync::atomic::AtomicBool,
    #[cfg(feature = "test-util")]
    fail_after_io: std::sync::atomic::AtomicBool,
}

impl JournalStore {
    #[cfg(feature = "test-util")]
    pub(crate) fn open(dir: PathBuf) -> Result<Self> {
        let store = Self::new(dir);
        store.directory()?;
        Ok(store)
    }

    pub(crate) fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            handle: OnceLock::new(),
            #[cfg(feature = "test-util")]
            fail_writes: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "test-util")]
            fail_writes_skip: std::sync::atomic::AtomicU32::new(0),
            #[cfg(feature = "test-util")]
            fail_removes: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "test-util")]
            fail_after_io: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn directory(&self) -> Result<&private_fs::PrivateDir> {
        if let Some(handle) = self.handle.get() {
            return Ok(handle);
        }
        let handle = ensure_private_dir(&self.dir)?;
        let _ = self.handle.set(handle);
        Ok(self.handle.get().expect("directory initialized"))
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

    #[cfg(feature = "test-util")]
    pub(crate) fn set_fail_after_io(&self, fail: bool) {
        self.fail_after_io
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
        let durable = JournalRecordV4Ref::try_from(record).map_err(|e| {
            Error::platform(
                record.backend,
                format_args!("journal record conversion failed: {e}"),
            )
        })?;
        let bytes = serde_json::to_vec(&durable).map_err(|e| {
            Error::platform(
                record.backend,
                format_args!("journal record serialization failed: {e}"),
            )
        })?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(Error::JournalCorrupt(
                "journal record exceeds the 16 MiB storage budget".to_string(),
            ));
        }
        self.directory()?
            .write_atomic_with_durability(
                record_file_name(&record.lease_id, &record.resource),
                &bytes,
                private_fs::Durability::Full,
            )
            .map_err(publication_error)?;
        #[cfg(feature = "test-util")]
        if self.fail_after_io.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::JournalPublication {
                may_have_published: true,
                source: private_fs::Error::Io(std::io::Error::other(
                    "injected post-publication failure",
                )),
            });
        }
        Ok(())
    }

    pub(crate) fn remove(&self, lease_id: &Uuid, resource: &ResourceId) -> Result<()> {
        #[cfg(feature = "test-util")]
        if self.fail_removes.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::platform(
                BackendKind::Fake,
                "injected journal removal failure",
            ));
        }
        let directory = self.directory()?;
        match directory.remove_file(
            record_file_name(lease_id, resource),
            private_fs::Durability::Full,
        ) {
            Ok(()) => {}
            Err(private_fs::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                // Absence can follow a removal whose directory flush failed.
                directory
                    .sync_all()
                    .map_err(|source| Error::JournalRemoval {
                        may_have_removed: true,
                        source,
                    })?;
            }
            Err(private_fs::Error::Removal {
                may_have_removed,
                source,
            }) => {
                return Err(Error::JournalRemoval {
                    may_have_removed,
                    source: *source,
                });
            }
            Err(error) => return Err(private_error(error)),
        }
        #[cfg(feature = "test-util")]
        if self.fail_after_io.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::JournalRemoval {
                may_have_removed: true,
                source: private_fs::Error::Io(std::io::Error::other(
                    "injected post-cleanup failure",
                )),
            });
        }
        Ok(())
    }

    pub(crate) fn records(&self) -> Result<Vec<JournalRecord>> {
        let mut out = Vec::new();
        let directory = self.directory()?;
        for name in directory.entries().map_err(private_error)? {
            let path = self.dir.join(&name);
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let file = directory
                .open_file(Path::new(&name))
                .map_err(private_error)?;
            let mut bytes = Vec::new();
            file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_RECORD_BYTES {
                return Err(Error::JournalCorrupt(format!(
                    "{}: journal record exceeds the 16 MiB storage budget",
                    path.display()
                )));
            }
            let record = decode_record(&path, &bytes)?;
            if name != record_file_name(&record.lease_id, &record.resource).as_str() {
                return Err(Error::JournalCorrupt(format!(
                    "{}: filename does not match the lease and resource",
                    path.display()
                )));
            }
            if out
                .iter()
                .any(|other: &JournalRecord| other.resource == record.resource)
            {
                return Err(Error::JournalCorrupt(format!(
                    "{}: multiple records claim one resource",
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

#[cfg(all(test, not(target_os = "windows")))]
mod snapshot_codec {
    use super::*;

    #[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "netbsd"))]
    #[test]
    fn missing_openresolv_content_is_not_a_legacy_empty_snapshot() {
        let error = decode_snapshot(BackendKind::Resolvconf, serde_json::json!({}))
            .expect_err("missing content must remain malformed");
        assert!(error.contains("content"), "{error}");
    }

    #[test]
    fn decode_snapshot_rejects_backends_without_local_payload() {
        let err = decode_snapshot(BackendKind::WindowsIpHelper, serde_json::json!({}))
            .expect_err("foreign backend snapshots must not decode here");
        assert!(err.contains("unavailable on this platform"), "{err}");
    }
}

fn decode_record(path: &Path, bytes: &[u8]) -> Result<JournalRecord> {
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(Error::JournalCorrupt(
            "journal record exceeds the 16 MiB storage budget".to_string(),
        ));
    }
    let envelope: JournalEnvelope = serde_json::from_slice(bytes)
        .map_err(|e| Error::JournalCorrupt(format!("{}: {e}", path.display())))?;
    if envelope.schema_version != SCHEMA_VERSION {
        return Err(Error::UnsupportedJournalVersion {
            path: path.to_path_buf(),
            found: envelope.schema_version,
            supported: SCHEMA_VERSION,
        });
    }
    let durable: JournalRecordV4 = serde_json::from_slice(bytes)
        .map_err(|e| Error::JournalCorrupt(format!("{}: {e}", path.display())))?;
    let record = JournalRecord::try_from(durable)
        .map_err(|e| Error::JournalCorrupt(format!("{}: {e}", path.display())))?;
    validate_record(path, &record)
        .map_err(|error| Error::JournalCorrupt(format!("{}: {error}", path.display())))?;
    Ok(record)
}

fn validate_record(path: &Path, record: &JournalRecord) -> Result<()> {
    if record
        .desired
        .nameservers
        .iter()
        .any(|server| server.is_unspecified())
    {
        return Err(Error::JournalCorrupt(
            "desired configuration contains an unspecified nameserver".to_string(),
        ));
    }
    crate::manager::validate_owner(&record.owner)
        .map_err(|error| Error::JournalCorrupt(error.to_string()))?;
    if record.phase == Phase::Applied && record.applied.is_none() {
        return Err(Error::JournalCorrupt(format!(
            "{}: Applied record has no applied snapshot",
            path.display()
        )));
    }
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
    for snapshot in std::iter::once(&record.before).chain(record.applied.iter()) {
        #[cfg(windows)]
        if snapshot.backend == BackendKind::WindowsIpHelper {
            crate::platform::windows::WindowsBackend::validate_snapshot(snapshot, &record.owner)?;
        }
        #[cfg(target_os = "macos")]
        if snapshot.backend == BackendKind::MacosSystemConfiguration {
            crate::platform::macos::MacosBackend::validate_snapshot(snapshot, &record.owner)?;
        }
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
        if let SnapshotData::ResolvConfFile(data) = &snapshot.data {
            data.validate()?;
            if snapshot.resource.as_str().strip_suffix(":resolv-conf") != Some(std::env::consts::OS)
                || data
                    .metadata
                    .as_ref()
                    .is_some_and(|metadata| metadata.owner.is_none() || metadata.links != Some(1))
            {
                return Err(Error::JournalCorrupt(
                    "resolver file snapshot has an invalid native resource or ownership metadata"
                        .to_string(),
                ));
            }
        }
        #[cfg(target_os = "linux")]
        if let SnapshotData::SystemdResolved(data) = &snapshot.data {
            data.validate()?;
        }
        let _ = snapshot;
    }
    Ok(())
}

#[cfg(feature = "test-util")]
pub(crate) fn decode_for_fuzzing(bytes: &[u8]) -> Result<()> {
    decode_record(Path::new("fuzz-journal.json"), bytes).map(|_| ())
}
