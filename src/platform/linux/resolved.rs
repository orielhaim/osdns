use std::net::IpAddr;
use std::sync::Arc;
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
use crate::platform::{ApplyReceipt, Backend, PlatformSnapshot};
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
            default_route: plan.default_route.unwrap_or(false),
        }
    }
}

pub(crate) struct SystemdResolved {
    conn: Connection,
    caps: Capabilities,
    mode: Option<String>,
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

    fn link(&self, ifindex: i32) -> Result<Resolve1LinkProxyBlocking<'_>> {
        let path = self.manager()?.get_link(ifindex).map_err(dbus_error)?;
        Resolve1LinkProxyBlocking::builder(&self.conn)
            .path(path)
            .map_err(dbus_error)?
            .build()
            .map_err(dbus_error)
    }

    fn snapshot_of(&self, ifindex: u32) -> Result<ResolvedSnapshot> {
        let link = self.link(ifindex as i32)?;
        let dns = link.dns().map_err(dbus_error)?;
        let domains = link.domains().map_err(dbus_error)?;
        let default_route = link.default_route().map_err(dbus_error)?;
        Ok(ResolvedSnapshot {
            dns,
            domains,
            default_route,
        })
    }

    fn apply_snapshot(&self, ifindex: u32, snapshot: &ResolvedSnapshot) -> Result<()> {
        let manager = self.manager()?;
        manager
            .set_link_dns(ifindex as i32, snapshot.dns.clone())
            .map_err(dbus_error)?;
        manager
            .set_link_domains(ifindex as i32, snapshot.domains.clone())
            .map_err(dbus_error)?;
        manager
            .set_link_default_route(ifindex as i32, snapshot.default_route)
            .map_err(dbus_error)?;
        Ok(())
    }

    fn ifindex_of(resource: &ResourceId) -> Result<u32> {
        let text = resource.as_str();
        let index = text
            .rsplit(':')
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| {
                Error::invalid_config(format_args!("resource {resource} is not a resolved link"))
            })?;
        Ok(index)
    }
}

fn dbus_error(error: zbus::Error) -> Error {
    Error::Platform {
        backend: BackendKind::SystemdResolved,
        message: error.to_string(),
    }
}

fn capabilities() -> Capabilities {
    Capabilities::new(BackendKind::SystemdResolved)
        .with_read(true)
        .with_global_dns(false)
        .with_per_interface_dns(true)
        .with_search_domains(true)
        .with_split_dns(true)
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

    fn capture(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let ifindex = Self::ifindex_of(resource)?;
        let snapshot = self.snapshot_of(ifindex)?;
        to_platform_snapshot(resource, snapshot)
    }

    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt> {
        let ifindex = Self::ifindex_of(resource)?;
        self.apply_snapshot(ifindex, &ResolvedSnapshot::from_plan(plan))?;
        Ok(ApplyReceipt {
            resource: resource.clone(),
        })
    }

    fn readback(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let ifindex = Self::ifindex_of(resource)?;
        let snapshot = self.snapshot_of(ifindex)?;
        to_platform_snapshot(resource, snapshot)
    }

    fn restore(&self, resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()> {
        let ifindex = Self::ifindex_of(resource)?;
        let captured: ResolvedSnapshot = from_platform_snapshot(snapshot)?;
        self.apply_snapshot(ifindex, &captured)?;
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
