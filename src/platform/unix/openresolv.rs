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
use crate::platform::{Backend, MutationAttempt, PlatformSnapshot, SnapshotData};
use crate::watch::{WatchCallback, WatchHandle};

const STANDARD_STATE_DIRS: [&str; 2] = ["/run/resolvconf", "/var/run/resolvconf"];
const STATE_DIR_CANDIDATES: [&str; 4] = [
    "/run/resolvconf/keys",
    "/run/resolvconf/interfaces",
    "/var/run/resolvconf/keys",
    "/var/run/resolvconf/interfaces",
];
const SEARCH_PATH: [&str; 5] = ["/sbin", "/usr/sbin", "/usr/local/sbin", "/bin", "/usr/bin"];
const METRIC_SUBDIRS: [&str; 5] = ["metrics", "private", "nosearch", "exclusive", "deprecated"];
const MIN_OPENRESOLV_VERSION: (u64, u64, u64) = (3, 12, 0);

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
    let binary = find_supported_openresolv_binary()?;
    let key_dir = locate_key_dir(&binary)?;
    Some(Probe {
        binary,
        key_dir,
        resolv_conf: resolv_conf.to_path_buf(),
    })
}

fn is_openresolv(binary: &Path) -> bool {
    run(binary, &["--version"], None)
        .map(|output| openresolv_version_is_supported(&output))
        .unwrap_or(false)
}

fn openresolv_version_is_supported(output: &[u8]) -> bool {
    let Some(first_line) = output.split(|byte| *byte == b'\n').next() else {
        return false;
    };
    let Ok(first_line) = std::str::from_utf8(first_line) else {
        return false;
    };
    let Some(version) = first_line.strip_prefix("openresolv ") else {
        return false;
    };
    parse_openresolv_version(version).is_some_and(|version| version >= MIN_OPENRESOLV_VERSION)
}

fn parse_openresolv_version(version: &str) -> Option<(u64, u64, u64)> {
    let mut components = version.split('.');
    let major = parse_openresolv_version_component(components.next()?)?;
    let minor = parse_openresolv_version_component(components.next()?)?;
    let patch = parse_openresolv_version_component(components.next()?)?;
    components.next().is_none().then_some((major, minor, patch))
}

fn parse_openresolv_version_component(component: &str) -> Option<u64> {
    if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    component.parse().ok()
}

fn read_resolvconf_config() -> std::io::Result<String> {
    let bytes = super::detect::read_config(Path::new("/etc/resolvconf.conf"))?;
    String::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn configured_resolv_conf_matches(resolv_conf: &Path) -> bool {
    match read_resolvconf_config() {
        Ok(config) => parse_resolvconf_config(&config).is_ok_and(|config| config == *resolv_conf),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            resolv_conf == Path::new(RESOLV_CONF_PATH)
        }
        Err(_) => false,
    }
}

fn config_blocks_direct(resolv_conf: &Path, config: &str) -> bool {
    match parse_resolvconf_config(config) {
        Ok(configured) => configured == *resolv_conf,
        Err(()) => true,
    }
}

pub(crate) fn configuration_blocks_direct(resolv_conf: &Path) -> bool {
    match read_resolvconf_config() {
        Ok(config) => config_blocks_direct(resolv_conf, &config),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

fn parse_resolvconf_config(config: &str) -> Result<PathBuf, ()> {
    let mut configured = None;
    let mut configured_state_dir = false;
    for raw_line in config.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = parse_literal_assignment(line) else {
            return Err(());
        };
        if contains_setting_token(line, "resolv_conf") && key != "resolv_conf" {
            return Err(());
        }
        if contains_setting_token(line, "state_dir") && key != "state_dir" {
            return Err(());
        }
        match key {
            "resolv_conf" => {
                if configured.is_some() {
                    return Err(());
                }
                let candidate = absolute_path(value).ok_or(())?;
                configured = Some(candidate);
            }
            "state_dir" => {
                if configured_state_dir {
                    return Err(());
                }
                let state_dir = absolute_path(value).ok_or(())?;
                if !STANDARD_STATE_DIRS
                    .iter()
                    .any(|candidate| Path::new(candidate) == state_dir.as_path())
                {
                    return Err(());
                }
                configured_state_dir = true;
            }
            "resolvconf" | "libc" if value != "YES" => return Err(()),
            "resolv_conf_passthrough" if value != "NO" => return Err(()),
            _ => {}
        }
    }
    Ok(configured.unwrap_or_else(|| PathBuf::from(RESOLV_CONF_PATH)))
}

fn parse_literal_assignment(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    if key.is_empty()
        || key.trim() != key
        || value.trim() != value
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || byte.is_ascii_digit() || byte == b'_')
    {
        return None;
    }
    Some((key, parse_literal_value(value)?))
}

fn parse_literal_value(value: &str) -> Option<&str> {
    if value.trim() != value {
        return None;
    }
    if let Some(inner) = value
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
    {
        return safe_literal_value(inner, true);
    }
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        return safe_literal_value(inner, true);
    }
    safe_literal_value(value, false)
}

fn safe_literal_value(value: &str, quoted: bool) -> Option<&str> {
    if value.chars().any(|character| {
        (character.is_whitespace() && !quoted)
            || matches!(
                character,
                '$' | '`' | '\\' | '\'' | '"' | ';' | '|' | '&' | '(' | ')' | '<' | '>'
            )
            || (!quoted
                && (character == '#'
                    || matches!(character, '*' | '?' | '[' | ']' | '{' | '}' | '!' | '~')))
    }) {
        return None;
    }
    Some(value)
}

fn absolute_path(value: &str) -> Option<PathBuf> {
    let path = PathBuf::from(value);
    path.is_absolute().then_some(path)
}

fn contains_setting_token(line: &str, setting: &str) -> bool {
    line.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .any(|token| token == setting)
}

fn find_supported_openresolv_binary() -> Option<PathBuf> {
    SEARCH_PATH.iter().find_map(|directory| {
        let path = PathBuf::from(directory).join("resolvconf");
        let metadata = std::fs::metadata(&path).ok()?;
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            is_openresolv(&path).then_some(path)
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

use std::io::{Read, Seek, SeekFrom};
use std::os::unix::process::CommandExt;
use std::time::{Duration, Instant};

fn run(binary: &Path, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
    run_bounded(
        binary,
        args,
        stdin,
        Duration::from_secs(30),
        16 * 1024 * 1024,
    )
}

fn run_bounded(
    binary: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
    limit: u64,
) -> Result<Vec<u8>> {
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let mut command = Command::new(binary);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .process_group(0);
    if let Some(bytes) = stdin {
        let mut input = tempfile::tempfile()?;
        input.write_all(bytes)?;
        input.seek(SeekFrom::Start(0))?;
        command.stdin(input);
    }
    let mut child = command.spawn().map_err(|error| {
        Error::platform(
            BackendKind::Resolvconf,
            format_args!("cannot spawn resolvconf: {error}"),
        )
    })?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        let overflow = match (stdout.metadata(), stderr.metadata()) {
            (Ok(out), Ok(err)) => out.len() > limit || err.len() > limit,
            _ => true,
        };
        if overflow || Instant::now() >= deadline {
            terminate_child(&mut child);
            return Err(Error::IndeterminateMutation {
                backend: BackendKind::Resolvconf,
                message: if overflow {
                    "resolvconf exceeded its output budget"
                } else {
                    "resolvconf exceeded its execution deadline"
                }
                .to_string(),
            });
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                terminate_child(&mut child);
                return Err(Error::IndeterminateMutation {
                    backend: BackendKind::Resolvconf,
                    message: format!("cannot reap resolvconf: {error}"),
                });
            }
        }
    };
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    stdout.take(limit + 1).read_to_end(&mut out)?;
    stderr.take(limit + 1).read_to_end(&mut err)?;
    if out.len() as u64 > limit || err.len() as u64 > limit {
        return Err(Error::IndeterminateMutation {
            backend: BackendKind::Resolvconf,
            message: "resolvconf exceeded its output budget".to_string(),
        });
    }
    finish(
        std::process::Output {
            status,
            stdout: out,
            stderr: err,
        },
        args,
    )
}

fn terminate_child(child: &mut std::process::Child) {
    if let Some(group) = rustix::process::Pid::from_raw(child.id() as i32) {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn finish(output: std::process::Output, args: &[&str]) -> Result<Vec<u8>> {
    if output.status.success() {
        Ok(output.stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = if stderr.trim().is_empty() {
            "no stderr".to_string()
        } else {
            stderr.trim().to_string()
        };
        Err(Error::platform(
            BackendKind::Resolvconf,
            format_args!(
                "resolvconf {:?} exited with {}: {}",
                args, output.status, stderr
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
            Ok(_) => Ok(Some(crate::platform::unix::detect::read_config(&path)?)),
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
        Ok(crate::platform::unix::detect::read_config(path)?)
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
                attributes: record.attributes,
                live,
            }),
        )
    }

    fn record_from_snapshot(snapshot: &PlatformSnapshot) -> Result<ResolvconfRecord> {
        match &snapshot.data {
            SnapshotData::Resolvconf(data) => {
                let content = data.content.clone();
                let attributes = data.attributes.clone();
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
    if !readable
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        readable.insert(0, 'x');
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
    #[serde(deserialize_with = "deserialize_required_content")]
    pub(crate) content: Option<Vec<u8>>,
    pub(crate) attributes: ResolvconfAttributes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) live: Option<Vec<u8>>,
}

fn deserialize_required_content<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<Vec<u8>>::deserialize(deserializer)
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

fn public_state_from_snapshot(snapshot: &PlatformSnapshot, scope: &DnsScope) -> Result<DnsConfig> {
    let SnapshotData::Resolvconf(data) = &snapshot.data else {
        return Err(Error::JournalCorrupt(
            "resolvconf snapshot has the wrong backend data".to_string(),
        ));
    };
    let live = data.live.as_deref().ok_or_else(|| {
        Error::JournalCorrupt(
            "openresolv public snapshot lacks effective resolver content".to_string(),
        )
    })?;
    let (nameservers, search) = parse_resolv_conf_content(live)?;
    Ok(DnsConfig::from_parts(
        scope.clone(),
        nameservers,
        search,
        Vec::new(),
        None,
    ))
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

    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<()> {
        let tag = self.tag_of(resource)?;
        self.add(
            &tag,
            &build_resolv_conf_content(plan),
            &ResolvconfAttributes::applied(),
        )?;
        Ok(())
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
        public_state_from_snapshot(snapshot, scope)
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
    fn owner_tags_are_openresolv_safe_and_deterministic() {
        let owners = ["io.example.agent", ".foo", "-foo", "_foo", "___"];
        let mut tags = Vec::new();
        for owner in owners {
            let tag = owner_tag(owner);
            assert_eq!(tag, owner_tag(owner));
            assert!(
                tag.as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
            );
            assert!(tag.chars().all(
                |character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-')
            ));
            assert!(!tags.contains(&tag));
            tags.push(tag);
        }
        assert!(owner_tag("io.example.agent").starts_with("io.example.agent-"));
    }

    #[test]
    fn openresolv_version_is_parsed_and_bounded() {
        for (version, supported) in [
            ("3.8.1", false),
            ("3.9.0", false),
            ("3.10.0", false),
            ("3.11.0", false),
            ("3.12.0", true),
            ("3.17.4", true),
        ] {
            let output = format!("openresolv {version}\n");
            assert_eq!(
                openresolv_version_is_supported(output.as_bytes()),
                supported,
                "{version}"
            );
        }
        assert!(!openresolv_version_is_supported(
            b"Debian resolvconf 1.91\n"
        ));
        assert!(!openresolv_version_is_supported(b"openresolv\n"));
        assert!(!openresolv_version_is_supported(
            b"prefix openresolv 3.17.4\n"
        ));
        assert!(!openresolv_version_is_supported(b"openresolv 3.12\n"));
    }

    #[test]
    fn subprocess_failures_include_stderr_on_stdin_paths() {
        let input = vec![b'x'; 1024 * 1024];
        let error = run(
            Path::new("/bin/sh"),
            &["-c", "printf 'osdns-test-diagnostic\\n' >&2; exit 7"],
            Some(&input),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("osdns-test-diagnostic"),
            "{error}"
        );
    }

    #[test]
    fn resolvconf_config_accepts_only_literal_assignments() {
        let config = "resolvconf=YES\nstate_dir=/run/resolvconf\nresolv_conf=\"/tmp/resolv.conf\"\nresolv_conf_passthrough=NO\nname_servers=\"8.8.8.8 1.1.1.1\"\nprivate_keys=\"vpn*\"\n";
        assert_eq!(
            parse_resolvconf_config(config).unwrap(),
            PathBuf::from("/tmp/resolv.conf")
        );
        assert_eq!(
            parse_resolvconf_config("").unwrap(),
            PathBuf::from(RESOLV_CONF_PATH)
        );
    }

    #[test]
    fn resolvconf_config_rejects_ambiguous_shell_forms() {
        for config in [
            "export resolv_conf=/tmp/resolv.conf\n",
            "resolv_conf = /tmp/resolv.conf\n",
            "resolv_conf=\"$state\"\n",
            ". /etc/resolvconf.conf.d/other\n",
            "if true; then resolv_conf=/tmp/resolv.conf; fi\n",
            "unset resolv_conf\n",
            "resolv_conf=/tmp/resolv.conf; echo done\n",
            "resolv_conf=/tmp/resolv.conf # comment\n",
            "resolvconf=NO\n",
            "libc=NO\n",
            "resolv_conf_passthrough=YES\n",
            "resolv_conf_passthrough=NULL\n",
            "resolv_conf_passthrough=/dev/null\n",
            "state_dir=/tmp/custom-resolvconf\n",
            "replace=\"$replace nameserver/1.1.1.1/8.8.8.8\"\n",
            "foo=bar; touch /tmp/should-not-run\n",
            "foo=bar touch /tmp/should-not-run\n",
            "resolv_conf=relative/path\n",
            "resolv_conf=/etc/resolv.conf\nresolv_conf=/tmp/resolv.conf\n",
            "resolv_conf=/etc/resolv.conf\nresolv_conf=/etc/resolv.conf\n",
            "state_dir=/run/resolvconf\nstate_dir=/run/resolvconf\n",
        ] {
            assert!(parse_resolvconf_config(config).is_err(), "{config}");
        }
    }

    #[test]
    fn resolvconf_config_blocks_direct_fallback_when_unverifiable() {
        assert!(config_blocks_direct(
            Path::new(RESOLV_CONF_PATH),
            "resolv_conf_passthrough=YES\n"
        ));
        assert!(config_blocks_direct(
            Path::new(RESOLV_CONF_PATH),
            "resolv_conf=\"$state\"\n"
        ));
        assert!(config_blocks_direct(
            Path::new(RESOLV_CONF_PATH),
            "resolv_conf=/etc/resolv.conf\n"
        ));
        assert!(!config_blocks_direct(
            Path::new(RESOLV_CONF_PATH),
            "resolv_conf=/tmp/resolv.conf\n"
        ));
    }

    #[test]
    fn public_global_state_uses_live_when_owner_key_is_absent() {
        let snapshot = snapshot_for(ResolvconfSnapshot {
            content: None,
            attributes: ResolvconfAttributes::default(),
            live: Some(b"nameserver 192.0.2.78\n".to_vec()),
        });
        let state = public_state_from_snapshot(&snapshot, &DnsScope::Global).unwrap();
        assert_eq!(
            state.nameservers(),
            &["192.0.2.78".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn public_global_state_requires_live_content() {
        let snapshot = snapshot_for(ResolvconfSnapshot {
            content: Some(b"nameserver 127.0.0.1\n".to_vec()),
            attributes: ResolvconfAttributes::default(),
            live: None,
        });
        assert!(public_state_from_snapshot(&snapshot, &DnsScope::Global).is_err());
    }

    fn snapshot_for(data: ResolvconfSnapshot) -> PlatformSnapshot {
        PlatformSnapshot::new(
            BackendKind::Resolvconf,
            ResourceId::new("linux:resolvconf:tag:test.global").unwrap(),
            SnapshotData::Resolvconf(data),
        )
    }

    #[test]
    fn ordered_subsequence_requires_configured_order() {
        assert!(ordered_subsequence(&[1, 3], &[0, 1, 2, 3, 4]));
        assert!(!ordered_subsequence(&[3, 1], &[0, 1, 2, 3, 4]));
        assert!(ordered_subsequence::<u8>(&[], &[1, 2]));
    }
}

#[cfg(test)]
mod execution_tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("sleep 10", Duration::from_millis(50), 1024)]
    #[case(
        "while :; do printf 12345678901234567890; done",
        Duration::from_secs(2),
        1024
    )]
    fn interrupted_children_are_indeterminate_and_reaped(
        #[case] script: &str,
        #[case] timeout: Duration,
        #[case] limit: u64,
    ) {
        let started = std::time::Instant::now();
        let result = run_bounded(Path::new("/bin/sh"), &["-c", script], None, timeout, limit);
        assert!(
            matches!(result, Err(Error::IndeterminateMutation { .. })),
            "{result:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn output_before_stdin_does_not_deadlock() {
        let output = run_bounded(
            Path::new("/bin/sh"),
            &["-c", "head -c 131072 /dev/zero; cat >/dev/null"],
            Some(&vec![b'x'; 1024 * 1024]),
            Duration::from_secs(2),
            2 * 1024 * 1024,
        )
        .unwrap();
        assert_eq!(output, vec![0; 131072]);
    }
}
