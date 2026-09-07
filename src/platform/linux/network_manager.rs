use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use zbus::blocking::Connection;
use zbus::proxy;
use zbus::zvariant::{Array, OwnedObjectPath, OwnedValue, Value};
use zbus::{MatchRule, blocking::MessageIterator};

use crate::capability::{BackendKind, Capabilities};
use crate::config::{DnsConfig, DnsScope};
use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;
use crate::normalize::NormalizedConfig;
use crate::ownership::ResourceId;
use crate::platform::linux;
use crate::platform::text_config::{NmDnsFields, parse_nm_dns_fields};
use crate::platform::{ApplyReceipt, Backend, PlatformSnapshot};
use crate::platform::{ResourceIdentity, ResourceStatus};
use crate::watch::{DnsEvent, WatchCallback, WatchHandle};

const NM_SERVICE: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const REAPPLY_ATTEMPTS: u32 = 3;
const REAPPLY_BACKOFF: Duration = Duration::from_millis(150);

#[proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager"
)]
trait NmManager {
    fn get_device_by_ip_iface(&self, iface: &str) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device",
    default_service = "org.freedesktop.NetworkManager"
)]
trait NmDevice {
    fn get_applied_connection(&self, flags: u32) -> zbus::Result<AppliedConnection>;

    fn reapply(
        &self,
        connection: HashMap<String, HashMap<String, Value<'static>>>,
        version_id: u64,
        flags: u32,
    ) -> zbus::Result<bool>;

    #[zbus(property)]
    fn interface(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn managed(&self) -> zbus::Result<bool>;

    #[zbus(property)]
    fn active_connection(&self) -> zbus::Result<OwnedObjectPath>;
}

#[allow(clippy::type_complexity)]
type AppliedConnection = (HashMap<String, HashMap<String, OwnedValue>>, u64);
type OwnedSettings = HashMap<String, HashMap<String, OwnedValue>>;
type Settings = HashMap<String, HashMap<String, Value<'static>>>;

pub(crate) struct NetworkManager {
    conn: Connection,
    caps: Capabilities,
}

impl NetworkManager {
    pub(crate) fn connect() -> Result<Self> {
        let conn = Connection::system().map_err(|e| {
            Error::BackendUnavailable(format!("cannot connect to the system D-Bus: {e}"))
        })?;
        Ok(Self {
            caps: capabilities(&Self::read_dns_mode()),
            conn,
        })
    }

    pub(crate) fn dns_mode() -> Result<String> {
        let mut dns = None;
        if let Ok(text) = std::fs::read_to_string("/etc/NetworkManager/NetworkManager.conf") {
            dns = crate::platform::text_config::parse_nm_main_conf(&text).dns;
        }
        if dns.is_none()
            && let Ok(entries) = std::fs::read_dir("/etc/NetworkManager/conf.d")
        {
            let mut paths: Vec<_> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().map(|e| e == "conf").unwrap_or(false))
                .collect();
            paths.sort();
            for path in paths {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    dns = crate::platform::text_config::parse_nm_main_conf(&text).dns;
                    if dns.is_some() {
                        break;
                    }
                }
            }
        }
        Ok(dns.unwrap_or_else(|| "default".to_string()))
    }

    fn read_dns_mode() -> String {
        Self::dns_mode().unwrap_or_else(|_| "default".to_string())
    }

    fn manager(&self) -> Result<NmManagerProxyBlocking<'_>> {
        NmManagerProxyBlocking::builder(&self.conn)
            .build()
            .map_err(dbus_error)
    }

    fn service_owner(&self) -> Result<String> {
        let proxy = zbus::blocking::fdo::DBusProxy::new(&self.conn).map_err(dbus_error)?;
        let name = NM_SERVICE.try_into().map_err(|e| {
            Error::platform(
                BackendKind::NetworkManager,
                format_args!("invalid NetworkManager bus name: {e}"),
            )
        })?;
        proxy
            .get_name_owner(name)
            .map(|owner| owner.to_string())
            .map_err(|error| Error::Platform {
                backend: BackendKind::NetworkManager,
                message: error.to_string(),
            })
    }

    fn device(&self, path: OwnedObjectPath) -> Result<NmDeviceProxyBlocking<'_>> {
        NmDeviceProxyBlocking::builder(&self.conn)
            .path(path)
            .map_err(dbus_error)?
            .build()
            .map_err(dbus_error)
    }

    fn device_for(&self, scope: &DnsScope) -> Result<(NmDeviceProxyBlocking<'_>, String)> {
        let (_index, name) = linux::resolve_interface_selector(scope)?;
        let path = self
            .manager()?
            .get_device_by_ip_iface(&name)
            .map_err(dbus_error)?;
        let device = self.device(path)?;
        if !device.managed().map_err(dbus_error)? {
            return Err(Error::BackendUnavailable(format!(
                "interface {name} is not managed by NetworkManager"
            )));
        }
        let iface = device.interface().map_err(dbus_error)?;
        Ok((device, iface))
    }

    fn device_for_resource(
        &self,
        resource: &ResourceId,
    ) -> Result<(NmDeviceProxyBlocking<'_>, String)> {
        let name = Self::ifname_of(resource)?;
        let path = self
            .manager()?
            .get_device_by_ip_iface(&name)
            .map_err(dbus_error)?;
        let device = self.device(path)?;
        Ok((device, name))
    }

    fn applied(&self, device: &NmDeviceProxyBlocking) -> Result<(OwnedSettings, u64)> {
        let (settings, version) = device.get_applied_connection(0).map_err(dbus_error)?;
        Ok((settings, version))
    }

    fn with_dns_fields(settings: &mut Settings, fields: &NmDnsFields, set_priority: bool) {
        let ipv4 = settings.entry("ipv4".to_string()).or_default();
        ipv4.insert("dns".to_string(), Value::Array(u32_array(&fields.ipv4_dns)));
        ipv4.insert(
            "dns-search".to_string(),
            Value::Array(str_array(&fields.ipv4_dns_search)),
        );
        ipv4.insert(
            "ignore-auto-dns".to_string(),
            Value::Bool(fields.ipv4_ignore_auto_dns),
        );
        if set_priority {
            match fields.ipv4_dns_priority {
                Some(priority) => {
                    ipv4.insert("dns-priority".to_string(), Value::I32(priority));
                }
                None => {
                    ipv4.remove("dns-priority");
                }
            }
        }
        let ipv6 = settings.entry("ipv6".to_string()).or_default();
        ipv6.insert(
            "dns".to_string(),
            Value::Array(byte_list_array(&fields.ipv6_dns)),
        );
        ipv6.insert(
            "dns-search".to_string(),
            Value::Array(str_array(&fields.ipv6_dns_search)),
        );
        ipv6.insert(
            "ignore-auto-dns".to_string(),
            Value::Bool(fields.ipv6_ignore_auto_dns),
        );
        if set_priority {
            match fields.ipv6_dns_priority {
                Some(priority) => {
                    ipv6.insert("dns-priority".to_string(), Value::I32(priority));
                }
                None => {
                    ipv6.remove("dns-priority");
                }
            }
        }
    }

    fn reapply(&self, device: &NmDeviceProxyBlocking, settings: Settings) -> Result<()> {
        self.reapply_versioned(device, settings, 0)
    }

    /// Reapplies with an expected `version_id` for compare-and-swap. A
    /// non-zero version asks NetworkManager to reject the call when the
    /// applied connection changed underneath us.
    fn reapply_versioned(
        &self,
        device: &NmDeviceProxyBlocking,
        settings: Settings,
        version: u64,
    ) -> Result<()> {
        let mut attempts = 0;
        loop {
            match device.reapply(settings.clone(), version, 0) {
                Ok(_result) => return Ok(()),
                Err(error) if attempts + 1 < REAPPLY_ATTEMPTS && version == 0 => {
                    attempts += 1;
                    thread::sleep(REAPPLY_BACKOFF);
                    let _ = error;
                }
                Err(error) => return Err(dbus_error(error)),
            }
        }
    }

    fn to_platform_snapshot(
        resource: &ResourceId,
        fields: &NmDnsFields,
        version: u64,
    ) -> Result<PlatformSnapshot> {
        let data = serde_json::to_value(&NmSnapshotData {
            fields: fields.clone(),
            version,
        })
        .map_err(|e| Error::platform(BackendKind::NetworkManager, format_args!("{e}")))?;
        Ok(PlatformSnapshot::new(
            BackendKind::NetworkManager,
            resource.clone(),
            data,
        ))
    }

    fn fields_from_snapshot(snapshot: &PlatformSnapshot) -> Result<NmDnsFields> {
        Ok(Self::snapshot_data(snapshot)?.fields)
    }

    fn snapshot_data(snapshot: &PlatformSnapshot) -> Result<NmSnapshotData> {
        serde_json::from_value(snapshot.data.clone()).map_err(|e| {
            Error::platform(
                BackendKind::NetworkManager,
                format_args!("snapshot data cannot be interpreted: {e}"),
            )
        })
    }

    fn version_from_snapshot(snapshot: &PlatformSnapshot) -> u64 {
        Self::snapshot_data(snapshot)
            .map(|d| d.version)
            .unwrap_or(0)
    }

    /// Reads the live applied connection and refuses when it no longer
    /// matches the verified `expected` snapshot. Returns the live settings
    /// and the expected version for the caller to reapply under.
    fn guarded_baseline(
        &self,
        resource: &ResourceId,
        expected: &PlatformSnapshot,
    ) -> Result<(NmDeviceProxyBlocking<'_>, OwnedSettings, u64)> {
        let (device, _name) = self.device_for_resource(resource)?;
        self.guarded_baseline_device(resource, device, expected)
    }

    fn guarded_baseline_device<'a>(
        &'a self,
        resource: &ResourceId,
        device: NmDeviceProxyBlocking<'a>,
        expected: &PlatformSnapshot,
    ) -> Result<(NmDeviceProxyBlocking<'a>, OwnedSettings, u64)> {
        let expected_fields = Self::fields_from_snapshot(expected)?;
        let expected_version = Self::version_from_snapshot(expected);
        let (live_settings, live_version) = self.applied(&device)?;
        if parse_nm_dns_fields(&convert_settings(&live_settings)) != expected_fields {
            return Err(Error::ExternalModification {
                resource: resource.clone(),
                detail: "the NetworkManager connection changed since ownership was verified"
                    .to_string(),
            });
        }
        if expected_version != 0 && live_version != expected_version {
            return Err(Error::ExternalModification {
                resource: resource.clone(),
                detail: format!(
                    "the NetworkManager applied connection changed (version {expected_version} -> {live_version}); refusing to overwrite it"
                ),
            });
        }
        Ok((device, live_settings, expected_version))
    }

    /// Maps a versioned reapply failure to a conflict when the connection
    /// version moved underneath the call.
    fn map_reapply_error(
        &self,
        resource: &ResourceId,
        device: &NmDeviceProxyBlocking<'_>,
        expected_version: u64,
        operation: &str,
        error: Error,
    ) -> Error {
        if expected_version != 0
            && let Ok((_, now)) = self.applied(device)
            && now != expected_version
        {
            return Error::ExternalModification {
                resource: resource.clone(),
                detail: format!(
                    "the NetworkManager applied connection changed during {operation} (version {expected_version} -> {now}); refusing to overwrite it"
                ),
            };
        }
        error
    }

    fn ifname_of(resource: &ResourceId) -> Result<String> {
        resource
            .as_str()
            .strip_prefix("linux:network-manager:ifname:")
            .map(|s| s.to_string())
            .ok_or_else(|| {
                Error::invalid_config(format_args!(
                    "resource {resource} is not a NetworkManager device"
                ))
            })
    }
}

fn dbus_error(error: zbus::Error) -> Error {
    Error::Platform {
        backend: BackendKind::NetworkManager,
        message: error.to_string(),
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NmSnapshotData {
    fields: crate::platform::text_config::NmDnsFields,
    /// `version_id` from `GetAppliedConnection` at capture time. `0`
    /// carries no compare-and-swap token, so guarded operations using it
    /// fall back to field comparison.
    version: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NmResourceIdentity {
    ifname: String,
    device_path: String,
    active_path: String,
    connection_uuid: uuid::Uuid,
    service_owner: String,
}

impl NmResourceIdentity {
    fn decode(identity: &ResourceIdentity) -> Result<Self> {
        if identity.backend != BackendKind::NetworkManager {
            return Err(Error::JournalCorrupt(
                "NetworkManager identity has the wrong backend".to_string(),
            ));
        }
        let selector_name = NetworkManager::ifname_of(&identity.resource).map_err(|_| {
            Error::JournalCorrupt("invalid NetworkManager resource selector".to_string())
        })?;
        let decoded: Self = serde_json::from_value(identity.data.clone()).map_err(|error| {
            Error::JournalCorrupt(format!("invalid NetworkManager resource identity: {error}"))
        })?;
        if decoded.ifname != selector_name
            || zbus::names::UniqueName::try_from(decoded.service_owner.as_str()).is_err()
            || OwnedObjectPath::try_from(decoded.device_path.as_str()).is_err()
            || OwnedObjectPath::try_from(decoded.active_path.as_str()).is_err()
            || !native_object_path(&decoded.device_path, "Devices")
            || !native_object_path(&decoded.active_path, "ActiveConnection")
        {
            return Err(Error::JournalCorrupt(
                "invalid NetworkManager resource identity fields".to_string(),
            ));
        }
        Ok(decoded)
    }
}

fn native_object_path(path: &str, kind: &str) -> bool {
    path.strip_prefix(&format!("/org/freedesktop/NetworkManager/{kind}/"))
        .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
}

fn classify_nm_activation(
    recorded: &NmResourceIdentity,
    service_owner: &str,
    active_path: &str,
    connection_uuid: uuid::Uuid,
) -> ResourceStatus {
    if recorded.service_owner != service_owner {
        ResourceStatus::Ambiguous
    } else if recorded.active_path != active_path || recorded.connection_uuid != connection_uuid {
        ResourceStatus::Replaced
    } else {
        ResourceStatus::Same
    }
}

fn classify_lifetime_result(
    resource: &ResourceId,
    result: Result<ResourceStatus>,
) -> Result<ResourceStatus> {
    match result {
        Err(Error::ResourceGone {
            backend: BackendKind::NetworkManager,
            resource: gone,
            ..
        }) if gone == *resource => Ok(ResourceStatus::Gone),
        other => other,
    }
}

fn nm_resource_error(resource: &ResourceId, error: zbus::Error) -> Error {
    if matches!(&error, zbus::Error::MethodError(name, _, _) if name.as_str() == "org.freedesktop.DBus.Error.UnknownObject")
    {
        Error::ResourceGone {
            backend: BackendKind::NetworkManager,
            resource: resource.clone(),
            message: error.to_string(),
        }
    } else {
        Error::ResourcePlatform {
            backend: BackendKind::NetworkManager,
            resource: resource.clone(),
            message: error.to_string(),
        }
    }
}

fn capabilities(dns_mode: &str) -> Capabilities {
    Capabilities::new(BackendKind::NetworkManager)
        .with_read(true)
        .with_global_dns(false)
        .with_per_interface_dns(true)
        .with_search_domains(true)
        .with_split_dns(matches!(dns_mode, "dnsmasq" | "systemd-resolved"))
        .with_default_route(false)
        .with_watch(true)
        .with_cache_flush(false)
        .with_mutation_guard(crate::capability::MutationGuard::CompareAndMutate)
        .with_ownership_identity(crate::capability::OwnershipIdentity::BestEffort)
        .with_resource_binding(crate::capability::ResourceBinding::NativeGuarded)
}

fn u32_array(values: &[u32]) -> Array<'static> {
    Array::from(values.iter().map(|v| Value::U32(*v)).collect::<Vec<_>>())
}

fn byte_list_array(values: &[Vec<u8>]) -> Array<'static> {
    Array::from(
        values
            .iter()
            .map(|bytes| {
                Value::Array(Array::from(
                    bytes.iter().map(|b| Value::U8(*b)).collect::<Vec<_>>(),
                ))
            })
            .collect::<Vec<_>>(),
    )
}

fn str_array(values: &[String]) -> Array<'static> {
    Array::from(
        values
            .iter()
            .map(|s| Value::from(s.clone()))
            .collect::<Vec<_>>(),
    )
}

fn setting_string(value: Option<&Value<'static>>) -> Option<String> {
    match value? {
        Value::Str(s) => Some(s.to_string()),
        _ => None,
    }
}

fn extract_uuid(settings: &Settings) -> Option<String> {
    let connection = settings.get("connection")?;
    setting_string(connection.get("uuid"))
}

impl Backend for NetworkManager {
    fn kind(&self) -> BackendKind {
        BackendKind::NetworkManager
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
                BackendKind::NetworkManager,
                "NetworkManager has no global DNS API; DNS is per-device",
            )),
            DnsScope::Interface(_) => {
                let (device, name) = self.device_for(scope)?;
                let (applied, _) = self.applied(&device)?;
                if extract_uuid(&to_owned_static(&applied)).is_none() {
                    return Err(Error::BackendUnavailable(format!(
                        "interface {name} has no active connection"
                    )));
                }
                ResourceId::new(format!("linux:network-manager:ifname:{name}")).map(|id| vec![id])
            }
        }
    }

    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        linux::list_interfaces()
    }

    fn identify(&self, resource: &ResourceId) -> Result<ResourceIdentity> {
        let (device, name) = self.device_for_resource(resource)?;
        let (settings, _version) = self.applied(&device)?;
        let uuid =
            extract_uuid(&to_owned_static(&settings)).ok_or_else(|| Error::ResourcePlatform {
                backend: BackendKind::NetworkManager,
                resource: resource.clone(),
                message: "the device has no active connection UUID".to_string(),
            })?;
        let data = NmResourceIdentity {
            ifname: name,
            device_path: device.inner().path().as_str().to_string(),
            active_path: device
                .active_connection()
                .map_err(|error| nm_resource_error(resource, error))?
                .as_str()
                .to_string(),
            connection_uuid: uuid.parse().map_err(|error| Error::ResourcePlatform {
                backend: BackendKind::NetworkManager,
                resource: resource.clone(),
                message: format!("invalid active connection UUID: {error}"),
            })?,
            service_owner: self.service_owner()?,
        };
        Ok(ResourceIdentity::new(
            BackendKind::NetworkManager,
            resource.clone(),
            serde_json::to_value(data)
                .map_err(|error| Error::platform(BackendKind::NetworkManager, error))?,
        ))
    }

    fn resource_status(&self, identity: &ResourceIdentity) -> Result<ResourceStatus> {
        classify_lifetime_result(
            &identity.resource,
            (|| {
                let recorded = NmResourceIdentity::decode(identity)?;
                let service_owner = self.service_owner()?;
                if recorded.service_owner != service_owner {
                    return Ok(ResourceStatus::Ambiguous);
                }
                let path = OwnedObjectPath::try_from(recorded.device_path.as_str())
                    .expect("validated path");
                let device = self.device(path)?;
                let active = device
                    .active_connection()
                    .map_err(|error| nm_resource_error(&identity.resource, error))?;
                if active.as_str() != recorded.active_path {
                    return Ok(ResourceStatus::Replaced);
                }
                let (settings, _) = device
                    .get_applied_connection(0)
                    .map_err(|error| nm_resource_error(&identity.resource, error))?;
                let current_uuid = extract_uuid(&to_owned_static(&settings))
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| Error::ResourcePlatform {
                        backend: BackendKind::NetworkManager,
                        resource: identity.resource.clone(),
                        message: "the applied connection has no valid UUID".to_string(),
                    })?;
                Ok(classify_nm_activation(
                    &recorded,
                    &service_owner,
                    active.as_str(),
                    current_uuid,
                ))
            })(),
        )
    }

    fn observe(&self, resource: &ResourceId) -> Result<crate::platform::BoundObservation> {
        let (device, name) = self.device_for_resource(resource)?;
        let owner = self.service_owner()?;
        let active = device
            .active_connection()
            .map_err(|error| nm_resource_error(resource, error))?;
        let (settings, version) = self.applied(&device)?;
        let uuid: uuid::Uuid = extract_uuid(&to_owned_static(&settings))
            .ok_or_else(|| Error::ResourcePlatform {
                backend: BackendKind::NetworkManager,
                resource: resource.clone(),
                message: "the device has no active connection UUID".to_string(),
            })?
            .parse()
            .map_err(|error| Error::ResourcePlatform {
                backend: BackendKind::NetworkManager,
                resource: resource.clone(),
                message: format!("invalid active connection UUID: {error}"),
            })?;
        if owner != self.service_owner()?
            || active
                != device
                    .active_connection()
                    .map_err(|error| nm_resource_error(resource, error))?
        {
            return Err(Error::ResourceIdentity {
                backend: BackendKind::NetworkManager,
                resource: resource.clone(),
                message: "NetworkManager activation changed while it was being observed"
                    .to_string(),
            });
        }
        let data = NmResourceIdentity {
            ifname: name,
            device_path: device.inner().path().as_str().to_string(),
            active_path: active.as_str().to_string(),
            connection_uuid: uuid,
            service_owner: owner,
        };
        let identity = ResourceIdentity::new(
            BackendKind::NetworkManager,
            resource.clone(),
            serde_json::to_value(data)
                .map_err(|error| Error::platform(BackendKind::NetworkManager, error))?,
        );
        let fields = parse_nm_dns_fields(&convert_settings(&settings));
        let snapshot = Self::to_platform_snapshot(resource, &fields, version)?;
        Ok(crate::platform::BoundObservation { identity, snapshot })
    }

    fn capture(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let (device, _name) = self.device_for_resource(resource)?;
        let (settings, version) = self.applied(&device)?;
        let fields = parse_nm_dns_fields(&convert_settings(&settings));
        Self::to_platform_snapshot(resource, &fields, version)
    }

    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt> {
        let (device, _name) = self.device_for_resource(resource)?;
        let (applied, _) = self.applied(&device)?;
        let mut settings = to_owned_static(&applied);
        let fields = NmDnsFields::from_plan(plan, self.caps.split_dns);
        Self::with_dns_fields(&mut settings, &fields, false);
        self.reapply(&device, settings)?;
        Ok(ApplyReceipt {
            resource: resource.clone(),
        })
    }

    fn readback(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let (device, _name) = self.device_for_resource(resource)?;
        let (settings, version) = self.applied(&device)?;
        let fields = parse_nm_dns_fields(&convert_settings(&settings));
        Self::to_platform_snapshot(resource, &fields, version)
    }

    fn restore(&self, resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()> {
        let before = Self::fields_from_snapshot(snapshot)?;
        let (device, _name) = self.device_for_resource(resource)?;
        let (applied, _) = self.applied(&device)?;
        let mut settings = to_owned_static(&applied);
        Self::with_dns_fields(&mut settings, &before, true);
        self.reapply(&device, settings)?;
        Ok(())
    }

    fn apply_bound(
        &self,
        identity: &ResourceIdentity,
        expected: &PlatformSnapshot,
        plan: &NormalizedConfig,
    ) -> crate::platform::MutationAttempt {
        if let Err(error) = match self.resource_status(identity) {
            Ok(ResourceStatus::Same) => Ok(()),
            Ok(status) => Err(Error::ResourceIdentity {
                backend: BackendKind::NetworkManager,
                resource: identity.resource.clone(),
                message: format!("activation is {status:?}; refusing reapply"),
            }),
            Err(error) => Err(error),
        } {
            return crate::platform::MutationAttempt::Rejected { error };
        }
        let recorded = match NmResourceIdentity::decode(identity) {
            Ok(recorded) => recorded,
            Err(error) => return crate::platform::MutationAttempt::Rejected { error },
        };
        let path =
            OwnedObjectPath::try_from(recorded.device_path.as_str()).expect("validated path");
        let device = match self.device(path) {
            Ok(device) => device,
            Err(error) => return crate::platform::MutationAttempt::Rejected { error },
        };
        let (device, live_settings, expected_version) =
            match self.guarded_baseline_device(&identity.resource, device, expected) {
                Ok(value) => value,
                Err(error) => return crate::platform::MutationAttempt::Rejected { error },
            };
        match self.resource_status(identity) {
            Ok(ResourceStatus::Same) => {}
            Ok(status) => {
                return crate::platform::MutationAttempt::Rejected {
                    error: Error::ResourceIdentity {
                        backend: BackendKind::NetworkManager,
                        resource: identity.resource.clone(),
                        message: format!("activation became {status:?} before reapply"),
                    },
                };
            }
            Err(error) => return crate::platform::MutationAttempt::Rejected { error },
        }
        let mut settings = to_owned_static(&live_settings);
        Self::with_dns_fields(
            &mut settings,
            &NmDnsFields::from_plan(plan, self.caps.split_dns),
            false,
        );
        match self.reapply_versioned(&device, settings, expected_version) {
            Ok(()) => crate::platform::MutationAttempt::Performed { produced: None },
            Err(error) => crate::platform::MutationAttempt::Indeterminate {
                error: self.map_reapply_error(
                    &identity.resource,
                    &device,
                    expected_version,
                    "apply",
                    error,
                ),
                produced: None,
            },
        }
    }

    fn restore_bound(
        &self,
        identity: &ResourceIdentity,
        expected: &PlatformSnapshot,
        target: &PlatformSnapshot,
    ) -> crate::platform::MutationAttempt {
        let before = match Self::fields_from_snapshot(target) {
            Ok(fields) => fields,
            Err(error) => return crate::platform::MutationAttempt::Rejected { error },
        };
        match self.resource_status(identity) {
            Ok(ResourceStatus::Same) => {}
            Ok(status) => {
                return crate::platform::MutationAttempt::Rejected {
                    error: Error::ResourceIdentity {
                        backend: BackendKind::NetworkManager,
                        resource: identity.resource.clone(),
                        message: format!("activation is {status:?}; refusing restore"),
                    },
                };
            }
            Err(error) => return crate::platform::MutationAttempt::Rejected { error },
        }
        let recorded = match NmResourceIdentity::decode(identity) {
            Ok(recorded) => recorded,
            Err(error) => return crate::platform::MutationAttempt::Rejected { error },
        };
        let path =
            OwnedObjectPath::try_from(recorded.device_path.as_str()).expect("validated path");
        let device = match self.device(path) {
            Ok(device) => device,
            Err(error) => return crate::platform::MutationAttempt::Rejected { error },
        };
        let (device, live_settings, expected_version) =
            match self.guarded_baseline_device(&identity.resource, device, expected) {
                Ok(value) => value,
                Err(error) => return crate::platform::MutationAttempt::Rejected { error },
            };
        match self.resource_status(identity) {
            Ok(ResourceStatus::Same) => {}
            Ok(status) => {
                return crate::platform::MutationAttempt::Rejected {
                    error: Error::ResourceIdentity {
                        backend: BackendKind::NetworkManager,
                        resource: identity.resource.clone(),
                        message: format!("activation became {status:?} before restore"),
                    },
                };
            }
            Err(error) => return crate::platform::MutationAttempt::Rejected { error },
        }
        let mut settings = to_owned_static(&live_settings);
        Self::with_dns_fields(&mut settings, &before, true);
        match self.reapply_versioned(&device, settings, expected_version) {
            Ok(()) => crate::platform::MutationAttempt::Performed { produced: None },
            Err(error) => crate::platform::MutationAttempt::Indeterminate {
                error: self.map_reapply_error(
                    &identity.resource,
                    &device,
                    expected_version,
                    "restore",
                    error,
                ),
                produced: None,
            },
        }
    }

    fn apply_guarded(
        &self,
        resource: &ResourceId,
        expected: &PlatformSnapshot,
        plan: &NormalizedConfig,
    ) -> crate::platform::MutationAttempt {
        let (device, live_settings, expected_version) =
            match self.guarded_baseline(resource, expected) {
                Ok(baseline) => baseline,
                Err(error) if error.is_external_modification() => {
                    return crate::platform::MutationAttempt::Rejected { error };
                }
                Err(error) => {
                    return crate::platform::MutationAttempt::Indeterminate {
                        error,
                        produced: None,
                    };
                }
            };
        let mut settings = to_owned_static(&live_settings);
        let fields = NmDnsFields::from_plan(plan, self.caps.split_dns);
        Self::with_dns_fields(&mut settings, &fields, false);
        match self.reapply_versioned(&device, settings, expected_version) {
            Ok(()) => crate::platform::MutationAttempt::Performed { produced: None },
            Err(error) => {
                let error =
                    self.map_reapply_error(resource, &device, expected_version, "apply", error);
                if error.is_external_modification() {
                    crate::platform::MutationAttempt::Rejected { error }
                } else {
                    crate::platform::MutationAttempt::Indeterminate {
                        error,
                        produced: None,
                    }
                }
            }
        }
    }

    fn restore_guarded(
        &self,
        resource: &ResourceId,
        expected: &PlatformSnapshot,
        target: &PlatformSnapshot,
    ) -> crate::platform::MutationAttempt {
        let before = match Self::fields_from_snapshot(target) {
            Ok(fields) => fields,
            Err(error) => {
                return crate::platform::MutationAttempt::Indeterminate {
                    error,
                    produced: None,
                };
            }
        };
        let (device, live_settings, expected_version) =
            match self.guarded_baseline(resource, expected) {
                Ok(baseline) => baseline,
                Err(error) if error.is_external_modification() => {
                    return crate::platform::MutationAttempt::Rejected { error };
                }
                Err(error) => {
                    return crate::platform::MutationAttempt::Indeterminate {
                        error,
                        produced: None,
                    };
                }
            };
        let mut settings = to_owned_static(&live_settings);
        Self::with_dns_fields(&mut settings, &before, true);
        match self.reapply_versioned(&device, settings, expected_version) {
            Ok(()) => crate::platform::MutationAttempt::Performed { produced: None },
            Err(error) => {
                let error =
                    self.map_reapply_error(resource, &device, expected_version, "restore", error);
                if error.is_external_modification() {
                    crate::platform::MutationAttempt::Rejected { error }
                } else {
                    crate::platform::MutationAttempt::Indeterminate {
                        error,
                        produced: None,
                    }
                }
            }
        }
    }

    fn proves_current(&self, proof: &PlatformSnapshot, current: &PlatformSnapshot) -> bool {
        let Ok(proof_data) = Self::snapshot_data(proof) else {
            return false;
        };
        let Ok(current_data) = Self::snapshot_data(current) else {
            return false;
        };
        proof_data.fields == current_data.fields
            && proof_data.version != 0
            && proof_data.version == current_data.version
    }

    fn validate_plan(&self, _scope: &DnsScope, plan: &NormalizedConfig) -> Result<()> {
        if plan.default_route.is_some() {
            return Err(Error::unsupported(
                BackendKind::NetworkManager,
                "NetworkManager has no explicit default-route flag; use the root routing domain instead",
            ));
        }
        Ok(())
    }

    fn equivalent(&self, a: &PlatformSnapshot, b: &PlatformSnapshot) -> bool {
        match (Self::fields_from_snapshot(a), Self::fields_from_snapshot(b)) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    }

    fn matches_desired(&self, snapshot: &PlatformSnapshot, plan: &NormalizedConfig) -> bool {
        let Ok(current) = Self::fields_from_snapshot(snapshot) else {
            return false;
        };
        current == NmDnsFields::from_plan(plan, self.caps.split_dns)
    }

    fn public_state(&self, snapshot: &PlatformSnapshot, scope: &DnsScope) -> Result<DnsConfig> {
        let fields = Self::fields_from_snapshot(snapshot)?;
        let mut nameservers = Vec::new();
        for raw in &fields.ipv4_dns {
            nameservers.push(IpAddr::V4(Ipv4Addr::from(raw.to_be_bytes())));
        }
        for bytes in &fields.ipv6_dns {
            if let Ok(octets) = <[u8; 16]>::try_from(bytes.as_slice()) {
                nameservers.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
        }
        let entries = &fields.ipv4_dns_search;
        let (search, routing) = crate::platform::text_config::parse_nm_search_entries(entries);
        Ok(DnsConfig::from_parts(
            scope.clone(),
            nameservers,
            search,
            routing,
            None,
        ))
    }

    fn start_watch(&self, callback: WatchCallback) -> Result<WatchHandle> {
        let conn = Connection::system().map_err(dbus_error)?;
        let rule = MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(NM_SERVICE)
            .expect("valid service name")
            .interface("org.freedesktop.DBus.Properties")
            .expect("valid interface")
            .path_namespace(NM_PATH)
            .expect("valid path")
            .build();
        let iterator =
            MessageIterator::for_match_rule(rule, &conn, Some(64)).map_err(dbus_error)?;
        let flag = Arc::new(AtomicBool::new(false));
        let watch_flag = flag.clone();
        let thread_conn = conn.clone();
        let watch_conn = conn.clone();
        thread::Builder::new()
            .name("osdns-nm-watch".to_string())
            .spawn(move || {
                for message in iterator {
                    if watch_flag.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(message) = message else { break };
                    let path = match message.header().path() {
                        Some(path) => path.to_owned(),
                        None => continue,
                    };
                    if !path
                        .as_str()
                        .starts_with("/org/freedesktop/NetworkManager/Devices/")
                    {
                        continue;
                    }
                    let device = NmDeviceProxyBlocking::builder(&watch_conn)
                        .path(path)
                        .and_then(|builder| builder.build());
                    let Ok(device) = device else { continue };
                    let Ok(iface) = device.interface() else {
                        continue;
                    };
                    let Ok(resource) =
                        ResourceId::new(format!("linux:network-manager:ifname:{iface}"))
                    else {
                        continue;
                    };
                    callback(&DnsEvent::ResourceChanged { resource });
                }
                let _ = thread_conn.close();
            })
            .map_err(|e| Error::Platform {
                backend: BackendKind::NetworkManager,
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

fn to_owned_static(settings: &OwnedSettings) -> Settings {
    settings
        .iter()
        .map(|(section, entries)| {
            (
                section.clone(),
                entries
                    .iter()
                    .map(|(key, value)| (key.clone(), Value::from(value.clone())))
                    .collect(),
            )
        })
        .collect()
}

fn convert_settings(
    settings: &OwnedSettings,
) -> HashMap<String, HashMap<String, crate::platform::text_config::SettingValue>> {
    settings
        .iter()
        .map(|(section, entries)| {
            (
                section.clone(),
                entries
                    .iter()
                    .map(|(key, value)| (key.clone(), to_setting_value(value)))
                    .collect(),
            )
        })
        .collect()
}

fn to_setting_value(owned: &OwnedValue) -> crate::platform::text_config::SettingValue {
    use crate::platform::text_config::SettingValue;
    let value = Value::from(owned.clone());
    match &value {
        Value::Bool(b) => SettingValue::Bool(*b),
        Value::I32(i) => SettingValue::Int(*i),
        Value::U32(u) => SettingValue::Uint(*u),
        Value::Str(s) => SettingValue::Str(s.to_string()),
        Value::Array(array) => {
            let mut strings = Vec::new();
            let mut uints = Vec::new();
            let mut byte_lists = Vec::new();
            let mut all_strings = true;
            let mut all_uints = true;
            let mut all_bytes = true;
            for item in array.iter() {
                match item {
                    Value::Str(s) => {
                        all_uints = false;
                        all_bytes = false;
                        strings.push(s.to_string());
                    }
                    Value::U8(b) => {
                        all_strings = false;
                        all_uints = false;
                        byte_lists.push(vec![*b]);
                    }
                    Value::U32(u) => {
                        all_strings = false;
                        all_bytes = false;
                        uints.push(*u);
                    }
                    Value::Array(inner) => {
                        all_strings = false;
                        all_uints = false;
                        let mut bytes = Vec::new();
                        for byte in inner.iter() {
                            if let Value::U8(b) = byte {
                                bytes.push(*b);
                            }
                        }
                        byte_lists.push(bytes);
                    }
                    _ => {
                        all_strings = false;
                        all_uints = false;
                        all_bytes = false;
                    }
                }
            }
            if all_uints {
                SettingValue::UintList(uints)
            } else if all_bytes && !byte_lists.is_empty() {
                SettingValue::ByteArrayList(byte_lists)
            } else if all_strings {
                SettingValue::StrList(strings)
            } else {
                SettingValue::Other
            }
        }
        _ => SettingValue::Other,
    }
}

#[cfg(test)]
mod identity_tests {
    use super::{
        NmResourceIdentity, classify_lifetime_result, classify_nm_activation, nm_resource_error,
    };
    use crate::Error;
    use crate::platform::ResourceIdentity;
    use crate::platform::ResourceStatus;

    #[test]
    fn malformed_network_manager_identity_is_rejected() {
        let resource: crate::ResourceId = "linux:network-manager:ifname:eth0".parse().unwrap();
        let valid_uuid = uuid::Uuid::new_v4();
        for data in [
            serde_json::json!({}),
            serde_json::json!({
                "ifname": "renamed0", "device_path": "/org/freedesktop/NetworkManager/Devices/1",
                "active_path": "/org/freedesktop/NetworkManager/ActiveConnection/1",
                "connection_uuid": valid_uuid, "service_owner": ":1.42"
            }),
            serde_json::json!({
                "ifname": "eth0", "device_path": "not/a/path",
                "active_path": "/org/freedesktop/NetworkManager/ActiveConnection/1",
                "connection_uuid": valid_uuid, "service_owner": ":1.42"
            }),
            serde_json::json!({
                "ifname": "eth0", "device_path": "/org/freedesktop/NetworkManager/Devices/1",
                "active_path": "/", "connection_uuid": "not-a-uuid",
                "service_owner": "org.freedesktop.NetworkManager"
            }),
            serde_json::json!({
                "ifname": "eth0", "device_path": "/unrelated/Devices/1",
                "active_path": "/org/freedesktop/NetworkManager/ActiveConnection/not_numeric",
                "connection_uuid": valid_uuid, "service_owner": ":1.42"
            }),
        ] {
            let identity =
                ResourceIdentity::new(crate::BackendKind::NetworkManager, resource.clone(), data);
            assert!(NmResourceIdentity::decode(&identity).is_err());
        }
    }

    #[test]
    fn device_rename_does_not_change_activation_identity() {
        let connection_uuid = uuid::Uuid::new_v4();
        let recorded = NmResourceIdentity {
            ifname: "old0".to_string(),
            device_path: "/org/freedesktop/NetworkManager/Devices/7".to_string(),
            active_path: "/org/freedesktop/NetworkManager/ActiveConnection/9".to_string(),
            connection_uuid,
            service_owner: ":1.42".to_string(),
        };
        // The current interface name is deliberately not an input: a rename
        // cannot override the Device + ActiveConnection object identity.
        let _current_interface_name = "renamed0";
        assert_eq!(
            classify_nm_activation(
                &recorded,
                ":1.42",
                "/org/freedesktop/NetworkManager/ActiveConnection/9",
                connection_uuid,
            ),
            ResourceStatus::Same
        );
    }

    #[test]
    fn transient_network_manager_error_is_not_resource_gone() {
        let resource = "linux:network-manager:ifname:eth0".parse().unwrap();
        let error = nm_resource_error(&resource, zbus::Error::Failure("timeout".to_string()));
        assert!(
            matches!(error, Error::ResourcePlatform { resource: found, .. } if found == resource)
        );
    }

    #[test]
    fn structural_device_disappearance_is_a_terminal_status() {
        let resource = "linux:network-manager:ifname:eth0".parse().unwrap();
        assert_eq!(
            classify_lifetime_result(
                &resource,
                Err(Error::ResourceGone {
                    backend: crate::BackendKind::NetworkManager,
                    resource: resource.clone(),
                    message: "device object vanished".to_string(),
                }),
            )
            .unwrap(),
            ResourceStatus::Gone
        );
    }
}
