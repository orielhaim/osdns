use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::capability::{BackendKind, Capabilities};
use crate::config::{DnsConfig, DnsScope};
use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::NormalizedConfig;
use crate::ownership::ResourceId;
use crate::platform::linux;
use crate::platform::text_config::{build_resolv_conf_content, parse_resolv_conf_content};
use crate::platform::{ApplyReceipt, Backend, PlatformSnapshot};
use crate::watch::{WatchCallback, WatchHandle};

// openresolv uses interfaces (3.x) or keys (4.x); Debian resolvconf
// uses interface. These are native state directories, not /etc/resolv.conf.
const STATE_DIR_CANDIDATES: [&str; 6] = [
    "/run/resolvconf/keys",
    "/run/resolvconf/interfaces",
    "/run/resolvconf/interface",
    "/var/run/resolvconf/keys",
    "/var/run/resolvconf/interfaces",
    "/var/run/resolvconf/interface",
];
const SEARCH_PATH: [&str; 5] = ["/sbin", "/usr/sbin", "/usr/local/sbin", "/bin", "/usr/bin"];

pub(crate) struct Probe {
    pub(crate) binary: PathBuf,
    pub(crate) state_dir: PathBuf,
}

pub(crate) fn probe() -> Option<Probe> {
    let binary = find_binary("resolvconf")?;
    let state_dir = STATE_DIR_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|dir| dir.is_dir())?;
    Some(Probe { binary, state_dir })
}

fn find_binary(name: &str) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = SEARCH_PATH
        .iter()
        .map(|dir| PathBuf::from(dir).join(name))
        .collect();
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(
            std::env::split_paths(&path)
                .map(|dir| dir.join(name))
                .collect::<Vec<_>>(),
        );
    }
    candidates.into_iter().find(|p| p.is_file())
}

fn capabilities() -> Capabilities {
    Capabilities::new(BackendKind::Resolvconf)
        .with_read(true)
        .with_global_dns(true)
        .with_per_interface_dns(true)
        .with_search_domains(true)
        .with_split_dns(false)
        .with_watch(true)
        .with_cache_flush(false)
}

pub(crate) struct Resolvconf {
    binary: PathBuf,
    state_dir: PathBuf,
    caps: Capabilities,
    tag_prefix: String,
}

impl Resolvconf {
    pub(crate) fn new(probe: Probe, owner: &str) -> Self {
        let mut sanitized: String = owner
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        sanitized.truncate(64);
        Self {
            binary: probe.binary,
            state_dir: probe.state_dir,
            caps: capabilities(),
            tag_prefix: format!("{sanitized}.osdns"),
        }
    }

    fn tag_of(resource: &ResourceId) -> Result<String> {
        resource
            .as_str()
            .strip_prefix("linux:resolvconf:tag:")
            .map(|s| s.to_string())
            .ok_or_else(|| {
                Error::invalid_config(format_args!(
                    "resource {resource} is not a resolvconf record"
                ))
            })
    }

    fn resource_of(tag: &str) -> Result<ResourceId> {
        ResourceId::new(format!("linux:resolvconf:tag:{tag}"))
    }

    fn record_path(&self, tag: &str) -> PathBuf {
        self.state_dir.join(tag)
    }

    fn read_record(&self, tag: &str) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.record_path(tag)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut command = Command::new(&self.binary);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped());
        match stdin {
            Some(bytes) => {
                command.stdin(Stdio::piped());
                let mut child = command.spawn().map_err(|e| {
                    Error::platform(
                        BackendKind::Resolvconf,
                        format_args!("cannot spawn resolvconf: {e}"),
                    )
                })?;
                if let Some(mut handle) = child.stdin.take() {
                    handle.write_all(bytes).map_err(|e| {
                        Error::platform(
                            BackendKind::Resolvconf,
                            format_args!("cannot write to resolvconf stdin: {e}"),
                        )
                    })?;
                }
                let output = child.wait_with_output().map_err(|e| {
                    Error::platform(
                        BackendKind::Resolvconf,
                        format_args!("resolvconf failed: {e}"),
                    )
                })?;
                finish(output)
            }
            None => {
                let output = command.output().map_err(|e| {
                    Error::platform(
                        BackendKind::Resolvconf,
                        format_args!("cannot spawn resolvconf: {e}"),
                    )
                })?;
                finish(output)
            }
        }
    }

    fn add(&self, tag: &str, content: &[u8]) -> Result<()> {
        self.run(&["-a", tag, "-m", "0"], Some(content)).map(|_| ())
    }

    fn delete(&self, tag: &str) -> Result<()> {
        self.run(&["-d", tag, "-f"], None).map(|_| ())
    }
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

fn snapshot_to_platform(
    resource: &ResourceId,
    content: Option<Vec<u8>>,
) -> Result<PlatformSnapshot> {
    let data = serde_json::to_value(ResolvconfSnapshot { content })
        .map_err(|e| Error::platform(BackendKind::Resolvconf, format_args!("{e}")))?;
    Ok(PlatformSnapshot::new(
        BackendKind::Resolvconf,
        resource.clone(),
        data,
    ))
}

fn snapshot_from_platform(snapshot: &PlatformSnapshot) -> Result<Option<Vec<u8>>> {
    let parsed: ResolvconfSnapshot =
        serde_json::from_value(snapshot.data.clone()).map_err(|e| {
            Error::platform(
                BackendKind::Resolvconf,
                format_args!("snapshot data cannot be interpreted: {e}"),
            )
        })?;
    Ok(parsed.content)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ResolvconfSnapshot {
    pub(crate) content: Option<Vec<u8>>,
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
        let tag = match scope {
            DnsScope::Global => format!("{}.global", self.tag_prefix),
            DnsScope::Interface(_) => {
                let (index, _name) = linux::resolve_interface_selector(scope)?;
                format!("{}.if{index}", self.tag_prefix)
            }
        };
        Self::resource_of(&tag).map(|id| vec![id])
    }

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        linux::list_interfaces()
    }

    fn capture(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let tag = Self::tag_of(resource)?;
        let content = self.read_record(&tag)?;
        snapshot_to_platform(resource, content)
    }

    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt> {
        let tag = Self::tag_of(resource)?;
        let content = build_resolv_conf_content(plan);
        self.add(&tag, &content)?;
        Ok(ApplyReceipt {
            resource: resource.clone(),
        })
    }

    fn readback(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let tag = Self::tag_of(resource)?;
        let content = self.read_record(&tag)?;
        snapshot_to_platform(resource, content)
    }

    fn restore(&self, resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()> {
        let tag = Self::tag_of(resource)?;
        match snapshot_from_platform(snapshot)? {
            Some(content) => self.add(&tag, &content),
            None => self.delete(&tag),
        }
    }

    fn equivalent(&self, a: &PlatformSnapshot, b: &PlatformSnapshot) -> bool {
        match (snapshot_from_platform(a), snapshot_from_platform(b)) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    }

    fn matches_desired(&self, snapshot: &PlatformSnapshot, plan: &NormalizedConfig) -> bool {
        let Ok(current) = snapshot_from_platform(snapshot) else {
            return false;
        };
        current.as_deref() == Some(build_resolv_conf_content(plan).as_slice())
    }

    fn public_state(&self, snapshot: &PlatformSnapshot, scope: &DnsScope) -> Result<DnsConfig> {
        let content = snapshot_from_platform(snapshot)?;
        let Some(bytes) = content else {
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
        crate::platform::linux::watch::watch_directory(
            BackendKind::Resolvconf,
            &self.state_dir,
            move |name| Self::resource_of(name).ok(),
            callback,
        )
    }
}
