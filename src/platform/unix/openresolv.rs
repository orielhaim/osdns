use std::collections::HashSet;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::capability::{BackendKind, Capabilities, ResourceBinding};
use crate::config::{DnsConfig, DnsScope};
use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::NormalizedConfig;
use crate::ownership::ResourceId;
use crate::platform::text_config::{build_resolv_conf_content, parse_resolv_conf_content};
use crate::platform::unix::detect::{self, RESOLV_CONF_PATH};
use crate::platform::unix::{ResourceMapper, WatchDirectory};
use crate::platform::{ApplyReceipt, Backend, MutationAttempt, PlatformSnapshot, SnapshotData};
use crate::watch::{WatchCallback, WatchHandle};

const STATE_DIR_CANDIDATES: [&str; 8] = [
    "/run/resolvconf/keys",
    "/run/resolvconf/interfaces",
    "/run/resolvconf/interface",
    "/var/run/resolvconf/keys",
    "/var/run/resolvconf/interfaces",
    "/var/run/resolvconf/interface",
    "/var/run/resolvconf",
    "/var/run",
];
const SEARCH_PATH: [&str; 5] = ["/sbin", "/usr/sbin", "/usr/local/sbin", "/bin", "/usr/bin"];
const METRIC_SUBDIRS: [&str; 5] = ["metrics", "private", "nosearch", "exclusive", "deprecated"];

pub(crate) struct Probe {
    pub(crate) binary: PathBuf,
    pub(crate) key_dir: PathBuf,
    pub(crate) resolv_conf: PathBuf,
}

pub(crate) struct ResolvconfPlatform {
    pub(crate) resource_prefix: &'static str,
    pub(crate) list_interfaces: fn() -> Result<Vec<InterfaceInfo>>,
    pub(crate) watch_directory: WatchDirectory,
    pub(crate) validate_plan: fn(&NormalizedConfig) -> Result<()>,
}

pub(crate) fn probe() -> Option<Probe> {
    probe_for_resolv_conf(Path::new(RESOLV_CONF_PATH))
}

#[cfg(all(feature = "test-util", target_os = "linux"))]
pub(crate) fn probe_for_test(resolv_conf: PathBuf) -> Option<Probe> {
    probe_for_resolv_conf(&resolv_conf)
}

fn probe_for_resolv_conf(resolv_conf: &Path) -> Option<Probe> {
    if !configured_resolv_conf_matches(resolv_conf) {
        return None;
    }
    let binary = find_binary("resolvconf")?;
    let key_dir = locate_key_dir(&binary)?;
    Some(Probe {
        binary,
        key_dir,
        resolv_conf: resolv_conf.to_path_buf(),
    })
}

fn configured_resolv_conf_matches(resolv_conf: &Path) -> bool {
    let Ok(config) = std::fs::read_to_string("/etc/resolvconf.conf") else {
        return true;
    };
    let mut configured = None;
    for line in config.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "resolv_conf" {
            continue;
        }
        let value = value.trim().trim_matches('"');
        let candidate = PathBuf::from(value);
        if configured
            .as_ref()
            .is_some_and(|previous| previous != &candidate)
        {
            return false;
        }
        configured = Some(candidate);
    }
    configured.is_none_or(|candidate| candidate == resolv_conf)
}

fn find_binary(name: &str) -> Option<PathBuf> {
    SEARCH_PATH.iter().find_map(|directory| {
        let path = PathBuf::from(directory).join(name);
        let metadata = std::fs::metadata(&path).ok()?;
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            Some(path)
        } else {
            None
        }
    })
}

fn locate_key_dir(binary: &Path) -> Option<PathBuf> {
    let keys = run(binary, &["-i"], None).ok()?;
    let keys = parse_keys(&keys).ok()?;
    if keys.is_empty() {
        return None;
    }
    let mut seen = HashSet::new();
    let mut matches = Vec::new();
    for candidate in STATE_DIR_CANDIDATES {
        let candidate = PathBuf::from(candidate);
        let Ok(canonical) = candidate.canonicalize() else {
            continue;
        };
        if !seen.insert(canonical.clone())
            || !key_dir_contents(&canonical).is_some_and(|files| files == keys)
        {
            continue;
        }
        matches.push(canonical);
    }
    if matches.len() == 1 {
        matches.pop()
    } else {
        None
    }
}

fn parse_keys(bytes: &[u8]) -> Result<HashSet<String>> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        Error::platform(
            BackendKind::Resolvconf,
            format_args!("resolvconf returned a non-UTF-8 key list: {error}"),
        )
    })?;
    Ok(text.split_whitespace().map(str::to_string).collect())
}

fn key_dir_contents(path: &Path) -> Option<HashSet<String>> {
    let entries = std::fs::read_dir(path).ok()?;
    let mut files = HashSet::new();
    for entry in entries.flatten() {
        let metadata = std::fs::symlink_metadata(entry.path()).ok()?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return None;
        }
        files.insert(entry.file_name().into_string().ok()?);
    }
    Some(files)
}

fn run(binary: &Path, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut command = Command::new(binary);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    let output = match stdin {
        Some(bytes) => {
            command.stdin(Stdio::piped());
            let mut child = command.spawn().map_err(|error| {
                Error::platform(
                    BackendKind::Resolvconf,
                    format_args!("cannot spawn resolvconf: {error}"),
                )
            })?;
            if let Some(mut handle) = child.stdin.take() {
                handle.write_all(bytes).map_err(|error| {
                    Error::platform(
                        BackendKind::Resolvconf,
                        format_args!("cannot write to resolvconf stdin: {error}"),
                    )
                })?;
            }
            child.wait_with_output().map_err(|error| {
                Error::platform(
                    BackendKind::Resolvconf,
                    format_args!("resolvconf failed: {error}"),
                )
            })?
        }
        None => command.output().map_err(|error| {
            Error::platform(
                BackendKind::Resolvconf,
                format_args!("cannot spawn resolvconf: {error}"),
            )
        })?,
    };
    finish(output)
}

fn finish(output: std::process::Output) -> Result<Vec<u8>> {
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(Error::platform(
            BackendKind::Resolvconf,
            format_args!(
                "resolvconf exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ))
    }
}

pub(crate) struct Resolvconf {
    binary: PathBuf,
    key_dir: PathBuf,
    resolv_conf: PathBuf,
    caps: Capabilities,
    resource_prefix: String,
    tag_prefix: String,
    list_interfaces: fn() -> Result<Vec<InterfaceInfo>>,
    watch_directory: WatchDirectory,
    validate_plan: fn(&NormalizedConfig) -> Result<()>,
}

impl Resolvconf {
    pub(crate) fn new(probe: Probe, owner: &str, platform: ResolvconfPlatform) -> Self {
        Self {
            binary: probe.binary,
            key_dir: probe.key_dir,
            resolv_conf: probe.resolv_conf,
            caps: capabilities(),
            resource_prefix: platform.resource_prefix.to_string(),
            tag_prefix: owner_tag(owner),
            list_interfaces: platform.list_interfaces,
            watch_directory: platform.watch_directory,
            validate_plan: platform.validate_plan,
        }
    }

    fn tag_of(&self, resource: &ResourceId) -> Result<String> {
        let prefix = format!("{}:resolvconf:tag:", self.resource_prefix);
        resource
            .as_str()
            .strip_prefix(&prefix)
            .map(str::to_string)
            .ok_or_else(|| {
                Error::invalid_config(format_args!(
                    "resource {resource} is not a resolvconf record"
                ))
            })
    }

    fn resource_of_tag(&self, tag: &str) -> Result<ResourceId> {
        ResourceId::new(format!("{}:resolvconf:tag:{tag}", self.resource_prefix))
    }

    fn state_dir(&self) -> &Path {
        self.key_dir.parent().unwrap_or(&self.key_dir)
    }

    fn watch_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = vec![self.state_dir().to_path_buf(), self.key_dir.clone()];
        for name in METRIC_SUBDIRS {
            let path = self.state_dir().join(name);
            if path.is_dir() {
                dirs.push(path);
            }
        }
        if let Some(parent) = self.resolv_conf.parent() {
            dirs.push(parent.to_path_buf());
        }
        dirs.sort();
        dirs.dedup();
        dirs
    }

    fn record_path(&self, tag: &str) -> PathBuf {
        self.key_dir.join(tag)
    }

    fn read_record(&self, tag: &str) -> Result<Option<Vec<u8>>> {
        let path = self.record_path(tag);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::unsupported(
                BackendKind::Resolvconf,
                format_args!("refusing openresolv key symlink {}", path.display()),
            )),
            Ok(metadata) if !metadata.is_file() => Err(Error::platform(
                BackendKind::Resolvconf,
                format_args!("openresolv key {} is not a regular file", path.display()),
            )),
            Ok(_) => Ok(Some(std::fs::read(path)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn marker_exists(&self, directory: &str, tag: &str) -> Result<bool> {
        let path = self.state_dir().join(directory).join(tag);
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::unsupported(
                BackendKind::Resolvconf,
                format_args!("refusing openresolv marker symlink for {tag}"),
            )),
            Ok(metadata) if !metadata.is_file() => Err(Error::platform(
                BackendKind::Resolvconf,
                format_args!("openresolv marker for {tag} is not a regular file"),
            )),
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn metric_of(&self, tag: &str) -> Result<Option<String>> {
        let directory = self.state_dir().join("metrics");
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut found = None;
        for entry in entries {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(Error::unsupported(
                    BackendKind::Resolvconf,
                    "refusing openresolv metric directory symlinks",
                ));
            }
            if !metadata.is_file() {
                continue;
            }
            let name = entry.file_name().into_string().map_err(|_| {
                Error::platform(
                    BackendKind::Resolvconf,
                    "openresolv metric filename is not UTF-8",
                )
            })?;
            if name.rsplit_once(' ').is_some_and(|(_, key)| key == tag) {
                if found.is_some() {
                    return Err(Error::platform(
                        BackendKind::Resolvconf,
                        format_args!("multiple openresolv metrics exist for {tag}"),
                    ));
                }
                let metric = name.rsplit_once(' ').map(|(metric, _)| metric).unwrap();
                let metric = metric.parse::<i64>().map_err(|_| {
                    Error::platform(
                        BackendKind::Resolvconf,
                        format_args!("invalid openresolv metric for {tag}"),
                    )
                })?;
                found = Some(metric.to_string());
            }
        }
        Ok(found)
    }

    fn exclusive_exists(&self, tag: &str) -> Result<bool> {
        let directory = self.state_dir().join("exclusive");
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(Error::unsupported(
                    BackendKind::Resolvconf,
                    "refusing openresolv exclusive marker symlinks",
                ));
            }
            let name = entry.file_name().into_string().map_err(|_| {
                Error::platform(
                    BackendKind::Resolvconf,
                    "openresolv exclusive filename is not UTF-8",
                )
            })?;
            if name.rsplit_once(' ').is_some_and(|(_, key)| key == tag) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn read_attributes(&self, tag: &str) -> Result<ResolvconfAttributes> {
        if self.exclusive_exists(tag)? {
            return Err(Error::unsupported(
                BackendKind::Resolvconf,
                format_args!("cannot safely restore exclusive openresolv key {tag}"),
            ));
        }
        Ok(ResolvconfAttributes {
            metric: self.metric_of(tag)?,
            private: self.marker_exists("private", tag)?,
            nosearch: self.marker_exists("nosearch", tag)?,
            deprecated: self.marker_exists("deprecated", tag)?,
        })
    }

    fn read_record_state(&self, tag: &str) -> Result<ResolvconfRecord> {
        Ok(ResolvconfRecord {
            content: self.read_record(tag)?,
            attributes: self.read_attributes(tag)?,
        })
    }

    fn add(&self, tag: &str, content: &[u8], attributes: &ResolvconfAttributes) -> Result<()> {
        let mut args = vec!["-a", tag];
        if let Some(metric) = attributes.metric.as_deref() {
            args.extend(["-m", metric]);
        }
        if attributes.nosearch {
            args.extend(["-p", "-p"]);
        } else if attributes.private {
            args.push("-p");
        }
        run(&self.binary, &args, Some(content)).map(|_| ())
    }

    fn delete(&self, tag: &str) -> Result<()> {
        run(&self.binary, &["-d", tag, "-f"], None).map(|_| ())
    }

    fn restore_record(&self, tag: &str, record: &ResolvconfRecord) -> Result<()> {
        let Some(content) = record.content.as_deref() else {
            self.delete(tag)?;
            return Ok(());
        };
        self.add(tag, content, &record.attributes)?;
        if record.attributes.deprecated {
            run(&self.binary, &["-C", tag], None).map(|_| ())?;
        }
        Ok(())
    }

    fn read_live(&self, resource: &ResourceId) -> Result<Vec<u8>> {
        let path = &self.resolv_conf;
        if detect::classify(path) != detect::ResolvConfState::OpenResolv {
            return Err(Error::ExternalModification {
                resource: resource.clone(),
                detail: format!(
                    "{} is no longer owned by openresolv",
                    self.resolv_conf.display()
                ),
            });
        }
        Ok(std::fs::read(path)?)
    }

    fn to_platform(
        &self,
        resource: &ResourceId,
        record: ResolvconfRecord,
        live: Option<Vec<u8>>,
    ) -> PlatformSnapshot {
        PlatformSnapshot::new(
            BackendKind::Resolvconf,
            resource.clone(),
            SnapshotData::Resolvconf(ResolvconfSnapshot {
                content: record.content,
                attributes: Some(record.attributes),
                live,
            }),
        )
    }

    fn record_from_snapshot(snapshot: &PlatformSnapshot) -> Result<ResolvconfRecord> {
        match &snapshot.data {
            SnapshotData::Resolvconf(data) => {
                let content = data.content.clone();
                let attributes = match data.attributes.clone() {
                    Some(attributes) => attributes,
                    None if content.is_none() => ResolvconfAttributes::default(),
                    None => {
                        return Err(Error::JournalCorrupt(
                            "openresolv snapshot with content lacks key attributes".to_string(),
                        ));
                    }
                };
                Ok(ResolvconfRecord {
                    content,
                    attributes,
                })
            }
            _ => Err(Error::JournalCorrupt(
                "resolvconf snapshot has the wrong backend data".to_string(),
            )),
        }
    }

    fn live_from_snapshot(snapshot: &PlatformSnapshot) -> Option<&[u8]> {
        match &snapshot.data {
            SnapshotData::Resolvconf(data) => data.live.as_deref(),
            _ => None,
        }
    }

    fn records_equivalent(a: &PlatformSnapshot, b: &PlatformSnapshot) -> bool {
        match (Self::record_from_snapshot(a), Self::record_from_snapshot(b)) {
            (Ok(left), Ok(right)) => {
                left == right
                    && match (Self::live_from_snapshot(a), Self::live_from_snapshot(b)) {
                        (Some(left), Some(right)) => left == right,
                        (None, None) => true,
                        _ => false,
                    }
            }
            _ => false,
        }
    }

    fn live_matches(live: &[u8], plan: &NormalizedConfig) -> bool {
        let Ok((nameservers, search)) = parse_resolv_conf_content(live) else {
            return false;
        };
        ordered_subsequence(&plan.nameservers, &nameservers)
            && ordered_subsequence(
                &plan
                    .search_domains
                    .iter()
                    .filter(|domain| !domain.is_root())
                    .cloned()
                    .collect::<Vec<_>>(),
                &search,
            )
    }

    fn verification_error(resource: &ResourceId) -> Error {
        Error::platform(
            BackendKind::Resolvconf,
            format_args!(
                "resolvconf key for {resource} was stored but its values are not active in /etc/resolv.conf"
            ),
        )
    }
}

impl ResolvconfAttributes {
    fn applied() -> Self {
        Self {
            metric: Some("0".to_string()),
            ..Self::default()
        }
    }
}

fn ordered_subsequence<T: PartialEq>(wanted: &[T], available: &[T]) -> bool {
    let mut available = available.iter();
    wanted
        .iter()
        .all(|value| available.any(|candidate| candidate == value))
}

fn capabilities() -> Capabilities {
    Capabilities::new(BackendKind::Resolvconf)
        .with_read(true)
        .with_global_dns(true)
        .with_per_interface_dns(false)
        .with_search_domains(true)
        .with_split_dns(false)
        .with_watch(true)
        .with_cache_flush(false)
        .with_resource_binding(ResourceBinding::PreflightOnly)
}

fn owner_tag(owner: &str) -> String {
    const OWNER_TAG_NAMESPACE: u128 = 0x6f73_646e_7372_6573_6f6c_7600_0001;
    let mut readable: String = owner
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '.' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(24)
        .collect();
    if readable.is_empty() {
        readable.push_str("owner");
    }
    let namespace = uuid::Uuid::from_u128(OWNER_TAG_NAMESPACE);
    let hash = uuid::Uuid::new_v5(&namespace, owner.as_bytes()).simple();
    format!("{readable}-{}.osdns", hash.to_string().to_ascii_lowercase())
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ResolvconfAttributes {
    #[serde(default)]
    pub(crate) metric: Option<String>,
    #[serde(default)]
    pub(crate) private: bool,
    #[serde(default)]
    pub(crate) nosearch: bool,
    #[serde(default)]
    pub(crate) deprecated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvconfRecord {
    content: Option<Vec<u8>>,
    attributes: ResolvconfAttributes,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct ResolvconfSnapshot {
    pub(crate) content: Option<Vec<u8>>,
    #[serde(default)]
    pub(crate) attributes: Option<ResolvconfAttributes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) live: Option<Vec<u8>>,
}

fn check_live_snapshot(
    resolvconf: &Resolvconf,
    resource: &ResourceId,
    expected: &PlatformSnapshot,
) -> Result<()> {
    let Some(expected_live) = Resolvconf::live_from_snapshot(expected) else {
        return Ok(());
    };
    let live = resolvconf.read_live(resource)?;
    if live != expected_live {
        return Err(Error::ExternalModification {
            resource: resource.clone(),
            detail: "the effective resolver file changed since it was captured".to_string(),
        });
    }
    Ok(())
}

impl Backend for Resolvconf {
    fn kind(&self) -> BackendKind {
        BackendKind::Resolvconf
    }

    fn capabilities(&self) -> Capabilities {
        self.caps.clone()
    }

    fn resolve_resources(
        &self,
        scope: &DnsScope,
        _plan: &NormalizedConfig,
    ) -> Result<Vec<ResourceId>> {
        match scope {
            DnsScope::Global => self
                .resource_of_tag(&format!("{}.global", self.tag_prefix))
                .map(|resource| vec![resource]),
            DnsScope::Interface(_) => Err(Error::unsupported(
                BackendKind::Resolvconf,
                "openresolv input records do not provide per-interface DNS routing",
            )),
        }
    }

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        (self.list_interfaces)()
    }

    fn capture(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let tag = self.tag_of(resource)?;
        let record = self.read_record_state(&tag)?;
        let live = self.read_live(resource)?;
        Ok(self.to_platform(resource, record, Some(live)))
    }

    fn apply_bound(
        &self,
        identity: &crate::platform::ResourceIdentity,
        expected: &PlatformSnapshot,
        plan: &NormalizedConfig,
    ) -> MutationAttempt {
        match self.resource_status(identity) {
            Ok(crate::platform::ResourceStatus::Same) => {}
            Ok(status) => {
                return MutationAttempt::Rejected {
                    error: Error::ResourceIdentity {
                        backend: self.kind(),
                        resource: identity.resource.clone(),
                        message: format!("resource incarnation is {status:?}; refusing mutation"),
                    },
                };
            }
            Err(error) => return MutationAttempt::Rejected { error },
        }
        let tag = match self.tag_of(&identity.resource) {
            Ok(tag) => tag,
            Err(error) => return MutationAttempt::Rejected { error },
        };
        let current = match self.read_record_state(&tag) {
            Ok(current) => current,
            Err(error) => return MutationAttempt::Rejected { error },
        };
        if let Err(error) = check_live_snapshot(self, &identity.resource, expected) {
            return MutationAttempt::Rejected { error };
        }
        let expected = match Self::record_from_snapshot(expected) {
            Ok(expected) => expected,
            Err(error) => return MutationAttempt::Rejected { error },
        };
        if current != expected {
            return MutationAttempt::Rejected {
                error: Error::ExternalModification {
                    resource: identity.resource.clone(),
                    detail: "the openresolv record changed since it was captured".to_string(),
                },
            };
        }
        if self.resource_status(identity).is_err() {
            return MutationAttempt::Rejected {
                error: Error::ResourceIdentity {
                    backend: self.kind(),
                    resource: identity.resource.clone(),
                    message: "resource incarnation changed before mutation".to_string(),
                },
            };
        }
        let content = build_resolv_conf_content(plan);
        let applied_record = ResolvconfRecord {
            content: Some(content),
            attributes: ResolvconfAttributes::applied(),
        };
        let mutation = self
            .add(
                &tag,
                applied_record.content.as_deref().unwrap(),
                &applied_record.attributes,
            )
            .and_then(|()| run(&self.binary, &["-c", &tag], None).map(|_| ()));
        let observed = match self.read_record_state(&tag) {
            Ok(observed) => observed,
            Err(error) => {
                return MutationAttempt::Indeterminate {
                    error,
                    produced: None,
                };
            }
        };
        let live = self.read_live(&identity.resource).ok();
        let snapshot = self.to_platform(&identity.resource, observed.clone(), live.clone());
        let verified = observed == applied_record
            && live
                .as_deref()
                .is_some_and(|live| Self::live_matches(live, plan));
        match mutation {
            Ok(()) if verified => MutationAttempt::Performed {
                produced: Some(snapshot),
            },
            Ok(()) => MutationAttempt::Indeterminate {
                error: Self::verification_error(&identity.resource),
                produced: (observed == applied_record).then_some(snapshot),
            },
            Err(error) => MutationAttempt::Indeterminate {
                error,
                produced: (observed == applied_record).then_some(snapshot),
            },
        }
    }

    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt> {
        let tag = self.tag_of(resource)?;
        self.add(
            &tag,
            &build_resolv_conf_content(plan),
            &ResolvconfAttributes::applied(),
        )?;
        Ok(ApplyReceipt {
            resource: resource.clone(),
        })
    }

    fn readback(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let tag = self.tag_of(resource)?;
        let record = self.read_record_state(&tag)?;
        let live = self.read_live(resource)?;
        Ok(self.to_platform(resource, record, Some(live)))
    }

    fn restore_bound(
        &self,
        identity: &crate::platform::ResourceIdentity,
        expected: &PlatformSnapshot,
        target: &PlatformSnapshot,
    ) -> MutationAttempt {
        match self.resource_status(identity) {
            Ok(crate::platform::ResourceStatus::Same) => {}
            Ok(status) => {
                return MutationAttempt::Rejected {
                    error: Error::ResourceIdentity {
                        backend: self.kind(),
                        resource: identity.resource.clone(),
                        message: format!("resource incarnation is {status:?}; refusing restore"),
                    },
                };
            }
            Err(error) => return MutationAttempt::Rejected { error },
        }
        let tag = match self.tag_of(&identity.resource) {
            Ok(tag) => tag,
            Err(error) => return MutationAttempt::Rejected { error },
        };
        let current = match self.read_record_state(&tag) {
            Ok(current) => current,
            Err(error) => return MutationAttempt::Rejected { error },
        };
        if let Err(error) = check_live_snapshot(self, &identity.resource, expected) {
            return MutationAttempt::Rejected { error };
        }
        let (expected, target) = match (
            Self::record_from_snapshot(expected),
            Self::record_from_snapshot(target),
        ) {
            (Ok(expected), Ok(target)) => (expected, target),
            (Err(error), _) | (_, Err(error)) => return MutationAttempt::Rejected { error },
        };
        if current != expected {
            return MutationAttempt::Rejected {
                error: Error::ExternalModification {
                    resource: identity.resource.clone(),
                    detail: "the openresolv record changed since ownership was verified"
                        .to_string(),
                },
            };
        }
        if self.resource_status(identity).is_err() {
            return MutationAttempt::Rejected {
                error: Error::ResourceIdentity {
                    backend: self.kind(),
                    resource: identity.resource.clone(),
                    message: "resource incarnation changed before restore".to_string(),
                },
            };
        }
        let mutation = self.restore_record(&tag, &target);
        let observed = match self.read_record_state(&tag) {
            Ok(observed) => observed,
            Err(error) => {
                return MutationAttempt::Indeterminate {
                    error,
                    produced: None,
                };
            }
        };
        let live = self.read_live(&identity.resource).ok();
        let snapshot = self.to_platform(&identity.resource, observed.clone(), live);
        if observed == target {
            match mutation {
                Ok(()) => MutationAttempt::Performed {
                    produced: Some(snapshot),
                },
                Err(error) => MutationAttempt::Indeterminate {
                    error,
                    produced: Some(snapshot),
                },
            }
        } else {
            MutationAttempt::Indeterminate {
                error: mutation.err().unwrap_or_else(|| {
                    Error::platform(
                        BackendKind::Resolvconf,
                        "openresolv restore read-back did not match the captured record",
                    )
                }),
                produced: None,
            }
        }
    }

    fn restore(&self, resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()> {
        let tag = self.tag_of(resource)?;
        self.restore_record(&tag, &Self::record_from_snapshot(snapshot)?)
    }

    fn equivalent(&self, a: &PlatformSnapshot, b: &PlatformSnapshot) -> bool {
        Self::records_equivalent(a, b)
    }

    fn matches_desired(&self, snapshot: &PlatformSnapshot, plan: &NormalizedConfig) -> bool {
        let Ok(record) = Self::record_from_snapshot(snapshot) else {
            return false;
        };
        let expected = ResolvconfRecord {
            content: Some(build_resolv_conf_content(plan)),
            attributes: ResolvconfAttributes::applied(),
        };
        record == expected
            && Self::live_from_snapshot(snapshot).is_some_and(|live| Self::live_matches(live, plan))
    }

    fn validate_plan(&self, _scope: &DnsScope, plan: &NormalizedConfig) -> Result<()> {
        (self.validate_plan)(plan)
    }

    fn public_state(&self, snapshot: &PlatformSnapshot, scope: &DnsScope) -> Result<DnsConfig> {
        let record = Self::record_from_snapshot(snapshot)?;
        let Some(bytes) = record.content else {
            return Ok(DnsConfig::from_parts(
                scope.clone(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
            ));
        };
        let (nameservers, search) = parse_resolv_conf_content(&bytes)?;
        Ok(DnsConfig::from_parts(
            scope.clone(),
            nameservers,
            search,
            Vec::new(),
            None,
        ))
    }

    fn start_watch(&self, callback: WatchCallback) -> Result<WatchHandle> {
        let prefix = self.resource_prefix.clone();
        let live_path = self.resolv_conf.clone();
        let owned_resource = ResourceId::new(format!(
            "{prefix}:resolvconf:tag:{}.global",
            self.tag_prefix
        ))?;
        let mapper: ResourceMapper = Arc::new(move |path| {
            if path == live_path {
                return Some(owned_resource.clone());
            }
            let parent = path.parent()?;
            if ![
                "keys",
                "interfaces",
                "interface",
                "metrics",
                "private",
                "nosearch",
                "exclusive",
                "deprecated",
            ]
            .contains(&parent.file_name()?.to_str()?)
            {
                return None;
            }
            let name = path.file_name()?.to_str()?;
            if matches!(
                parent.file_name().and_then(|name| name.to_str()),
                Some("metrics") | Some("exclusive")
            ) {
                name.rsplit_once(' ')?;
            }
            Some(owned_resource.clone())
        });
        (self.watch_directory)(
            BackendKind::Resolvconf,
            &self.watch_dirs(),
            Vec::new(),
            mapper,
            callback,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_tags_are_resource_id_safe_and_distinct() {
        assert_ne!(owner_tag("io.test/a"), owner_tag("io.test-a"));
        assert_ne!(
            owner_tag("io.example.abcdefghijklmnopqrstuvwx-one"),
            owner_tag("io.example.abcdefghijklmnopqrstuvwx-two")
        );
        assert!(
            owner_tag("IO.Example/Owner")
                .chars()
                .all(|character| !character.is_ascii_uppercase())
        );
        ResourceId::new(format!(
            "linux:resolvconf:tag:{}",
            owner_tag("IO.Example/Owner")
        ))
        .unwrap();
    }

    #[test]
    fn schema_v3_resolvconf_payloads_remain_readable() {
        let snapshot: ResolvconfSnapshot = serde_json::from_str(r#"{"content":null}"#).unwrap();
        assert_eq!(snapshot.content, None);
        assert_eq!(snapshot.attributes, None);
        assert_eq!(snapshot.live, None);
    }

    #[test]
    fn ordered_subsequence_requires_configured_order() {
        assert!(ordered_subsequence(&[1, 3], &[0, 1, 2, 3, 4]));
        assert!(!ordered_subsequence(&[3, 1], &[0, 1, 2, 3, 4]));
        assert!(ordered_subsequence::<u8>(&[], &[1, 2]));
    }
}
