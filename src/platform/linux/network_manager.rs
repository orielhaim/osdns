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

    fn applied(&self, device: &NmDeviceProxyBlocking) -> Result<OwnedSettings> {
        let (settings, _version) = device.get_applied_connection(0).map_err(dbus_error)?;
        Ok(settings)
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
        let mut attempts = 0;
        loop {
            match device.reapply(settings.clone(), 0, 0) {
                Ok(_result) => return Ok(()),
                Err(error) if attempts + 1 < REAPPLY_ATTEMPTS => {
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
    ) -> Result<PlatformSnapshot> {
        let data = serde_json::to_value(fields)
            .map_err(|e| Error::platform(BackendKind::NetworkManager, format_args!("{e}")))?;
        Ok(PlatformSnapshot::new(
            BackendKind::NetworkManager,
            resource.clone(),
            data,
        ))
    }

    fn fields_from_snapshot(snapshot: &PlatformSnapshot) -> Result<NmDnsFields> {
        serde_json::from_value(snapshot.data.clone()).map_err(|e| {
            Error::platform(
                BackendKind::NetworkManager,
                format_args!("snapshot data cannot be interpreted: {e}"),
            )
        })
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
                let applied = self.applied(&device)?;
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

    fn capture(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let (device, _name) = self.device_for_resource(resource)?;
        let fields = parse_nm_dns_fields(&convert_settings(&self.applied(&device)?));
        Self::to_platform_snapshot(resource, &fields)
    }

    fn apply(&self, resource: &ResourceId, plan: &NormalizedConfig) -> Result<ApplyReceipt> {
        let (device, _name) = self.device_for_resource(resource)?;
        let mut settings = to_owned_static(&self.applied(&device)?);
        let fields = NmDnsFields::from_plan(plan, self.caps.split_dns);
        Self::with_dns_fields(&mut settings, &fields, false);
        self.reapply(&device, settings)?;
        Ok(ApplyReceipt {
            resource: resource.clone(),
        })
    }

    fn readback(&self, resource: &ResourceId) -> Result<PlatformSnapshot> {
        let (device, _name) = self.device_for_resource(resource)?;
        let fields = parse_nm_dns_fields(&convert_settings(&self.applied(&device)?));
        Self::to_platform_snapshot(resource, &fields)
    }

    fn restore(&self, resource: &ResourceId, snapshot: &PlatformSnapshot) -> Result<()> {
        let before = Self::fields_from_snapshot(snapshot)?;
        let (device, _name) = self.device_for_resource(resource)?;
        let mut settings = to_owned_static(&self.applied(&device)?);
        Self::with_dns_fields(&mut settings, &before, true);
        self.reapply(&device, settings)?;
        Ok(())
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
