use std::collections::HashMap;
use std::fs::File;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use serde::{Deserialize, Serialize};
use zbus::MatchRule;
use zbus::blocking::Connection;
use zbus::blocking::MessageIterator;
use zbus::proxy;

use crate::capability::{BackendKind, Capabilities};
use crate::config::{DnsConfig, DnsScope};
use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::NormalizedConfig;
use crate::ownership::ResourceId;
use crate::platform::linux;
use crate::platform::text_config::{
    resolved_dns_from_plan, resolved_dns_to_nameservers, resolved_domains_from_plan,
    resolved_domains_to_public,
};
use crate::platform::{ApplyReceipt, Backend, PlatformSnapshot, ResourceIdentity, ResourceStatus};
use crate::watch::{DnsEvent, WatchCallback, WatchHandle};

const RESOLVED_SERVICE: &str = "org.freedesktop.resolve1";
const RESOLVED_PATH: &str = "/org/freedesktop/resolve1";

#[proxy(
    interface = "org.freedesktop.resolve1.Manager",
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1"
)]
trait Resolve1Manager {
    fn get_link(&self, ifindex: i32) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;

    #[zbus(name = "SetLinkDNS")]
    fn set_link_dns(&self, ifindex: i32, addresses: Vec<(i32, Vec<u8>)>) -> zbus::Result<()>;

    fn set_link_domains(&self, ifindex: i32, domains: Vec<(String, bool)>) -> zbus::Result<()>;

    fn set_link_default_route(&self, ifindex: i32, enabled: bool) -> zbus::Result<()>;

    fn flush_caches(&self) -> zbus::Result<()>;

    #[zbus(property)]
    fn resolv_conf_mode(&self) -> zbus::Result<String>;
}

#[proxy(
    interface = "org.freedesktop.resolve1.Link",
    default_service = "org.freedesktop.resolve1"
)]
trait Resolve1Link {
    #[zbus(property, name = "DNS")]
    fn dns(&self) -> zbus::Result<Vec<(i32, Vec<u8>)>>;

    #[zbus(property)]
    fn domains(&self) -> zbus::Result<Vec<(String, bool)>>;

    #[zbus(property)]
    fn default_route(&self) -> zbus::Result<bool>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct ResolvedSnapshot {
    pub(crate) dns: Vec<(i32, Vec<u8>)>,
    pub(crate) domains: Vec<(String, bool)>,
    pub(crate) default_route: bool,
}

impl ResolvedSnapshot {
    fn from_plan(plan: &NormalizedConfig) -> Self {
        Self {
            dns: resolved_dns_from_plan(plan),
            domains: resolved_domains_from_plan(plan),
            // Used for verification when `default_route` is explicit.
            // The apply path never manufactures `false` from `None`; see
            // `merged_from_plan`.
            default_route: plan.default_route.unwrap_or(false),
        }
    }

    /// Merges a plan onto the currently captured state.
    ///
    /// Invariant: `None` means preserve / leave unspecified, never implicitly
    /// `false`. Only `Some(_)` may change the link default-route flag.
    fn merged_from_plan(current: &Self, plan: &NormalizedConfig) -> Self {
        Self {
            dns: resolved_dns_from_plan(plan),
            domains: resolved_domains_from_plan(plan),
            default_route: plan.default_route.unwrap_or(current.default_route),
        }
    }
}

pub(crate) struct SystemdResolved {
    conn: Connection,
    caps: Capabilities,
    mode: Option<String>,
    live_links: Mutex<HashMap<String, File>>,
}

impl SystemdResolved {
    pub(crate) fn connect() -> Result<Self> {
        let conn = Connection::system().map_err(|e| {
            Error::BackendUnavailable(format!("cannot connect to the system D-Bus: {e}"))
        })?;
        let manager = Resolve1ManagerProxyBlocking::builder(&conn)
            .build()
            .map_err(dbus_error)?;
        let mode = manager.resolv_conf_mode().ok();
        Ok(Self {
            caps: capabilities(),
            conn,
            mode,
            live_links: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn mode_hint(&self) -> Option<String> {
        self.mode.clone()
    }

    fn manager(&self) -> Result<Resolve1ManagerProxyBlocking<'_>> {
        Resolve1ManagerProxyBlocking::builder(&self.conn)
            .build()
            .map_err(dbus_error)
    }

    fn snapshot_of(&self, resource: &ResourceId, ifindex: u32) -> Result<ResolvedSnapshot> {
        let link = self
            .manager()?
            .get_link(ifindex as i32)
            .map_err(|e| dbus_resource_error(resource, e))?;
        let link = Resolve1LinkProxyBlocking::builder(&self.conn)
            .path(link)
            .map_err(dbus_error)?
            .build()
            .map_err(dbus_error)?;
        let dns = link
            .dns()
            .map_err(|error| dbus_resource_error(resource, error))?;
        let domains = link
            .domains()
            .map_err(|error| dbus_resource_error(resource, error))?;
        let default_route = link
            .default_route()
            .map_err(|error| dbus_resource_error(resource, error))?;
        Ok(ResolvedSnapshot {
            dns,
            domains,
            default_route,
        })
    }

    /// Three D-Bus calls; a later failure may leave earlier ones applied.
    /// The error means indeterminate state per the backend apply contract;
    /// the engine reads back and rolls back under guard on every apply error.
    fn apply_snapshot(
        &self,
        resource: &ResourceId,
        ifindex: u32,
        snapshot: &ResolvedSnapshot,
    ) -> Result<()> {
        let manager = self.manager()?;
        manager
            .set_link_dns(ifindex as i32, snapshot.dns.clone())
            .map_err(|e| dbus_resource_error(resource, e))?;
        manager
            .set_link_domains(ifindex as i32, snapshot.domains.clone())
            .map_err(|e| dbus_resource_error(resource, e))?;
        manager
            .set_link_default_route(ifindex as i32, snapshot.default_route)
            .map_err(|e| dbus_resource_error(resource, e))?;
        Ok(())
    }

    fn ifindex_of(resource: &ResourceId) -> Result<u32> {
        let index = resource
            .as_str()
            .strip_prefix("linux:resolved:ifindex:")
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| {
                Error::invalid_config(format_args!("resource {resource} is not a resolved link"))
            })?;
        Ok(index)
    }

    fn identity_data(
        ifindex: u32,
        handle: Option<&str>,
    ) -> Result<(serde_json::Value, Option<File>)> {
        let entry = std::fs::read_dir("/sys/class/net")?
            .filter_map(std::result::Result::ok)
            .find(|entry| {
                std::fs::read_to_string(entry.path().join("ifindex"))
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    == Some(ifindex)
            });
        let Some(entry) = entry else {
            return Ok((serde_json::json!({ "gone": true }), None));
        };
        let path = entry.path();
        let read = |name: &str| {
            std::fs::read_to_string(path.join(name))
                .ok()
                .map(|s| s.trim().to_string())
        };
        let file = File::open(&path)?;
        Ok((
            serde_json::json!({
                "boot_id": std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
                "netns": std::fs::read_link("/proc/self/ns/net")?.to_string_lossy(),
                "ifindex": ifindex,
                "ifname": entry.file_name().to_string_lossy(),
                "iflink": read("iflink"),
                "address": read("address"),
                "uevent": read("uevent"),
                "handle": handle,
            }),
            Some(file),
        ))
    }
}

fn dbus_error(error: zbus::Error) -> Error {
    Error::Platform {
        backend: BackendKind::SystemdResolved,
        message: error.to_string(),
    }
}

fn dbus_resource_error(resource: &ResourceId, error: zbus::Error) -> Error {
    if matches!(&error, zbus::Error::MethodError(name, _, _) if name.as_str() == "org.freedesktop.resolve1.NoSuchLink")
    {
        Error::ResourceGone {
            backend: BackendKind::SystemdResolved,
            resource: resource.clone(),
            message: error.to_string(),
        }
    } else {
        Error::ResourcePlatform {
            backend: BackendKind::SystemdResolved,
            resource: resource.clone(),
            message: error.to_string(),
        }
    }
}

fn capabilities() -> Capabilities {
    Capabilities::new(BackendKind::SystemdResolved)
        .with_read(true)
        .with_global_dns(false)
        .with_per_interface_dns(true)
        .with_search_domains(true)
        .with_split_dns(true)
        .with_default_route(true)
        .with_watch(true)
        .with_cache_flush(true)
}

impl Backend for SystemdResolved {
    fn kind(&self) -> BackendKind {
        BackendKind::SystemdResolved
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
            DnsScope::Global => Err(Error::unsupported(
                BackendKind::SystemdResolved,
                "global DNS configuration lives in systemd/resolved.conf and has no D-Bus API",
            )),
            DnsScope::Interface(_) => {
                let (ifindex, _name) = linux::resolve_interface_selector(scope)?;
                ResourceId::new(format!("linux:resolved:ifindex:{ifindex}")).map(|id| vec![id])
            }
        }
    }

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        linux::list_interfaces()
    }

    fn identify(&self, resource: &ResourceId) -> Result<ResourceIdentity> {
        let ifindex = Self::ifindex_of(resource)?;
        let handle = uuid::Uuid::new_v4().simple().to_string();
        let (data, file) = Self::identity_data(ifindex, Some(&handle))?;
        if data.get("gone").is_some() {
            return Err(Error::ResourceGone {
                backend: BackendKind::SystemdResolved,
                resource: resource.clone(),
                message: "the kernel link is absent".to_string(),
            });
        }
        self.live_links
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(handle, file.expect("present link has a handle"));
        Ok(ResourceIdentity::new(
            BackendKind::SystemdResolved,
            resource.clone(),
            data,
        ))
    }

    fn resource_status(&self, identity: &ResourceIdentity) -> Result<ResourceStatus> {
        if identity.backend != BackendKind::SystemdResolved
            || Self::ifindex_of(&identity.resource).is_err()
        {
            return Ok(ResourceStatus::Replaced);
        }
        let (mut current, current_file) =
            Self::identity_data(Self::ifindex_of(&identity.resource)?, None)?;
        if current.get("gone").is_some() {
            return Ok(ResourceStatus::Gone);
        }
        if current.get("boot_id") != identity.data.get("boot_id") {
            return Ok(ResourceStatus::Gone);
        }
        let old_handle = identity
            .data
            .get("handle")
            .and_then(serde_json::Value::as_str);
        if let Some(object) = current.as_object_mut() {
            object.insert(
                "handle".to_string(),
                identity
                    .data
                    .get("handle")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            );
        }
        if current != identity.data {
            return Ok(ResourceStatus::Replaced);
        }
        // Linux exposes no durable netdev creation cookie. Equal selectors and
        // attributes after a process boundary are evidence, not proof.
        let handles = self.live_links.lock().unwrap_or_else(|p| p.into_inner());
        Ok(match old_handle.and_then(|key| handles.get(key)) {
            Some(original)
                if original.metadata()?.ino()
                    == current_file.expect("present link").metadata()?.ino() =>
            {
                ResourceStatus::Same
            }
            Some(_) => ResourceStatus::Replaced,
            None => ResourceStatus::Ambiguous,
        })
    }

    fn capture(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let ifindex = Self::ifindex_of(resource)?;
        let snapshot = self.snapshot_of(resource, ifindex)?;
        to_platform_snapshot(resource, snapshot)
    }

    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt> {
        let ifindex = Self::ifindex_of(resource)?;
        // Preserve the current default-route flag when the plan leaves it
        // unspecified (`None`); only an explicit `Some(_)` may change it.
        let current = self.snapshot_of(resource, ifindex)?;
        let merged = ResolvedSnapshot::merged_from_plan(&current, plan);
        self.apply_snapshot(resource, ifindex, &merged)?;
        Ok(ApplyReceipt {
            resource: resource.clone(),
        })
    }

    fn readback(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let ifindex = Self::ifindex_of(resource)?;
        let snapshot = self.snapshot_of(resource, ifindex)?;
        to_platform_snapshot(resource, snapshot)
    }

    fn restore(&self, resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()> {
        let ifindex = Self::ifindex_of(resource)?;
        let captured: ResolvedSnapshot = from_platform_snapshot(snapshot)?;
        self.apply_snapshot(resource, ifindex, &captured)?;
        Ok(())
    }

    fn equivalent(&self, a: &PlatformSnapshot, b: &PlatformSnapshot) -> bool {
        match (from_platform_snapshot(a), from_platform_snapshot(b)) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    }

    fn matches_desired(&self, snapshot: &PlatformSnapshot, plan: &NormalizedConfig) -> bool {
        let Ok(state) = from_platform_snapshot(snapshot) else {
            return false;
        };
        let expected = ResolvedSnapshot::from_plan(plan);
        if plan.default_route.is_none() {
            state.dns == expected.dns && state.domains == expected.domains
        } else {
            state == expected
        }
    }

    fn public_state(&self, snapshot: &PlatformSnapshot, scope: &DnsScope) -> Result<DnsConfig> {
        let state: ResolvedSnapshot = from_platform_snapshot(snapshot)?;
        let nameservers: Vec<IpAddr> = resolved_dns_to_nameservers(&state.dns);
        let (search, routing) = resolved_domains_to_public(&state.domains);
        Ok(DnsConfig::from_parts(
            scope.clone(),
            nameservers,
            search,
            routing,
            Some(state.default_route),
        ))
    }

    fn flush_cache(&self) -> Result<()> {
        self.manager()?.flush_caches().map_err(dbus_error)
    }

    fn start_watch(&self, callback: WatchCallback) -> Result<WatchHandle> {
        let conn = Connection::system().map_err(dbus_error)?;
        let rule = MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(RESOLVED_SERVICE)
            .expect("valid service name")
            .interface("org.freedesktop.DBus.Properties")
            .expect("valid interface")
            .path_namespace(RESOLVED_PATH)
            .expect("valid path")
            .build();
        let iterator =
            MessageIterator::for_match_rule(rule, &conn, Some(64)).map_err(dbus_error)?;
        let flag = Arc::new(AtomicBool::new(false));
        let watch_flag = flag.clone();
        let thread_conn = conn.clone();
        thread::Builder::new()
            .name("osdns-resolved-watch".to_string())
            .spawn(move || {
                for message in iterator {
                    if watch_flag.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(message) = message else { break };
                    let path = match message.header().path() {
                        Some(path) => path.as_str().to_string(),
                        None => continue,
                    };
                    let Some(index) = path
                        .strip_prefix("/org/freedesktop/resolve1/link/_")
                        .and_then(|suffix| suffix.parse::<u32>().ok())
                    else {
                        continue;
                    };
                    let Ok(resource) = ResourceId::new(format!("linux:resolved:ifindex:{index}"))
                    else {
                        continue;
                    };
                    callback(&DnsEvent::ResourceChanged { resource });
                }
                let _ = thread_conn.close();
            })
            .map_err(|e| Error::Platform {
                backend: BackendKind::SystemdResolved,
                message: format!("cannot spawn watch thread: {e}"),
            })?;
        let cancel_flag = flag.clone();
        let cancel_conn = conn;
        Ok(WatchHandle::new(flag, move || {
            cancel_flag.store(true, Ordering::Release);
            let _ = cancel_conn.close();
        }))
    }
}

fn to_platform_snapshot(
    resource: &ResourceId,
    snapshot: ResolvedSnapshot,
) -> Result<PlatformSnapshot> {
    let data = serde_json::to_value(&snapshot)
        .map_err(|e| Error::platform(BackendKind::SystemdResolved, format_args!("{e}")))?;
    Ok(PlatformSnapshot::new(
        BackendKind::SystemdResolved,
        resource.clone(),
        data,
    ))
}

fn from_platform_snapshot(snapshot: &PlatformSnapshot) -> Result<ResolvedSnapshot> {
    serde_json::from_value(snapshot.data.clone()).map_err(|e| {
        Error::platform(
            BackendKind::SystemdResolved,
            format_args!("snapshot data cannot be interpreted: {e}"),
        )
    })
}

#[cfg(test)]
mod resource_identity_tests {
    use super::SystemdResolved;
    use crate::error::Error;
    use crate::platform::Backend;

    #[test]
    fn resolved_resource_parser_validates_the_complete_kind() {
        let malformed = "fake:anything:8".parse().unwrap();
        assert!(SystemdResolved::ifindex_of(&malformed).is_err());
        let valid = "linux:resolved:ifindex:8".parse().unwrap();
        assert_eq!(SystemdResolved::ifindex_of(&valid).unwrap(), 8);
    }

    #[test]
    fn native_no_such_link_is_resource_scoped_when_resolved_is_available() {
        let Ok(backend) = SystemdResolved::connect() else {
            return;
        };
        let resource = "linux:resolved:ifindex:2147483647".parse().unwrap();
        let error = backend.capture(&resource).unwrap_err();
        assert!(matches!(error, Error::ResourceGone { resource: found, .. } if found == resource));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::DnsSuffix;

    fn plan_with(default_route: Option<bool>) -> NormalizedConfig {
        NormalizedConfig {
            nameservers: vec!["1.1.1.1".parse().unwrap()],
            search_domains: vec![],
            routing_domains: vec![DnsSuffix::parse("corp.example").unwrap()],
            default_route,
        }
    }

    fn current_with(default_route: bool) -> ResolvedSnapshot {
        ResolvedSnapshot {
            dns: vec![(2, vec![1, 1, 1, 1])],
            domains: vec![("corp.example".to_string(), true)],
            default_route,
        }
    }

    #[test]
    fn unspecified_default_route_preserves_true() {
        let merged = ResolvedSnapshot::merged_from_plan(&current_with(true), &plan_with(None));
        assert!(merged.default_route);
    }

    #[test]
    fn unspecified_default_route_preserves_false() {
        let merged = ResolvedSnapshot::merged_from_plan(&current_with(false), &plan_with(None));
        assert!(!merged.default_route);
    }

    #[test]
    fn explicit_default_route_overrides() {
        assert!(
            ResolvedSnapshot::merged_from_plan(&current_with(false), &plan_with(Some(true)))
                .default_route
        );
        assert!(
            !ResolvedSnapshot::merged_from_plan(&current_with(true), &plan_with(Some(false)))
                .default_route
        );
    }

    #[test]
    fn merged_plan_keeps_dns_and_domains_from_plan() {
        for current in [true, false] {
            let merged =
                ResolvedSnapshot::merged_from_plan(&current_with(current), &plan_with(None));
            let expected = ResolvedSnapshot::from_plan(&plan_with(None));
            assert_eq!(merged.dns, expected.dns);
            assert_eq!(merged.domains, expected.domains);
        }
    }
}
