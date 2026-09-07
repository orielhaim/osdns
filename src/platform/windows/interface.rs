//! Per-interface DNS settings via the native IP Helper API
//! (`GetInterfaceDnsSettings`/`SetInterfaceDnsSettings`, Windows 10 19041+),
//! adapter enumeration, and interface selection.

use std::net::IpAddr;

use uuid::Uuid;

use crate::capability::BackendKind;
use crate::config::InterfaceSelector;
use crate::error::{Error, Result};
use crate::platform::windows::error::{check_status, from_status, map_error, registry_not_found};
use crate::platform::windows::ffi::{
    self, ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, DNS_INTERFACE_SETTINGS,
    DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
    DNS_SETTING_SEARCHLIST, ERROR_BUFFER_OVERFLOW, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, GUID, IN_ADDR, IN_ADDR_0, IN_ADDR_0_0,
    IN6_ADDR, IN6_ADDR_0, IP_ADAPTER_ADDRESSES_LH, IfOperStatusUp, PCHAR, PWSTR, SOCKADDR,
    SOCKADDR_IN, SOCKADDR_IN6_LH, SOCKADDR_IN6_LH_0, open_hklm, wide_to_string,
};

pub(crate) struct AdapterInfo {
    #[allow(dead_code)]
    pub(crate) guid: GUID,
    pub(crate) guid_string: String,
    pub(crate) friendly_name: String,
    pub(crate) index: u32,
    pub(crate) is_up: bool,
}

pub(crate) fn guid_to_string(guid: &GUID) -> String {
    Uuid::from_fields(guid.data1, guid.data2, guid.data3, &guid.data4).to_string()
}

pub(crate) fn parse_guid(text: &str) -> Result<GUID> {
    let cleaned: String = text
        .chars()
        .filter(|c| *c != '{' && *c != '}' && *c != '-')
        .collect();
    let value = u128::from_str_radix(&cleaned, 16)
        .map_err(|_| Error::invalid_config(format_args!("invalid interface GUID {text:?}")))?;
    Ok(guid_from_u128(value))
}

pub(crate) fn guid_from_u128(value: u128) -> GUID {
    let uuid = Uuid::from_u128(value);
    let (data1, data2, data3, data4) = uuid.as_fields();
    GUID {
        data1,
        data2,
        data3,
        data4: *data4,
    }
}

pub(crate) fn list_adapters() -> Result<Vec<AdapterInfo>> {
    let mut size: u32 = 16 * 1024;
    loop {
        let mut buffer = vec![0u8; size as usize];
        let result = unsafe {
            ffi::GetAdaptersAddresses(
                AF_UNSPEC as u32,
                (GAA_FLAG_SKIP_UNICAST
                    | GAA_FLAG_SKIP_ANYCAST
                    | GAA_FLAG_SKIP_MULTICAST
                    | GAA_FLAG_SKIP_DNS_SERVER) as u32,
                std::ptr::null(),
                buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut size,
            )
        };
        match result {
            0 => return unsafe { adapters_from_buffer(&buffer) },
            code if code == ERROR_BUFFER_OVERFLOW as u32 => {
                if size > 64 * 1024 * 1024 {
                    return Err(Error::Platform {
                        backend: BackendKind::WindowsIpHelper,
                        message: "adapter enumeration buffer grew unreasonably large".to_string(),
                    });
                }
                continue;
            }
            error => {
                return Err(from_status(error as i32, "GetAdaptersAddresses"));
            }
        }
    }
}

unsafe fn adapters_from_buffer(buffer: &[u8]) -> Result<Vec<AdapterInfo>> {
    let mut adapters = Vec::new();
    let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !current.is_null() {
        // SAFETY: GetAdaptersAddresses filled a valid linked list within `buffer`.
        let adapter = unsafe { &*current };
        // SAFETY: AdapterName is a NUL-terminated ANSI string owned by the buffer.
        let guid_string = unsafe { pcstr_to_string(adapter.AdapterName) };
        // SAFETY: FriendlyName is a NUL-terminated UTF-16 string owned by the buffer.
        let friendly_name = unsafe { wide_to_string(adapter.FriendlyName) };
        // SAFETY: IfIndex is the documented member of the Alignment/Anonymous union.
        let if_index = unsafe { adapter.Anonymous.Anonymous.IfIndex };
        let guid = parse_guid(&guid_string)?;
        adapters.push(AdapterInfo {
            guid_string: guid_to_string(&guid),
            friendly_name,
            index: if_index,
            is_up: adapter.OperStatus == IfOperStatusUp,
            guid,
        });
        current = adapter.Next;
    }
    Ok(adapters)
}

unsafe fn pcstr_to_string(pointer: PCHAR) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees a valid NUL-terminated ANSI string.
    unsafe {
        while *pointer.add(len) != 0 {
            len += 1;
        }
        std::str::from_utf8(std::slice::from_raw_parts(pointer.cast::<u8>(), len))
            .unwrap_or_default()
            .to_string()
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RawDnsSettings {
    pub(crate) nameserver: Option<String>,
    pub(crate) searchlist: Option<String>,
}

pub(crate) fn get_dns_settings(guid: &GUID) -> Result<RawDnsSettings> {
    let mut settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1 as u32,
        Flags: 0,
        Domain: std::ptr::null_mut(),
        NameServer: std::ptr::null_mut(),
        SearchList: std::ptr::null_mut(),
        RegistrationEnabled: 0,
        RegisterAdapterName: 0,
        EnableLLMNR: 0,
        QueryAdapterName: 0,
        ProfileNameServer: std::ptr::null_mut(),
    };
    // SAFETY: settings is a valid VERSION1 structure with Flags == 0 as required.
    let status = unsafe { ffi::GetInterfaceDnsSettings(*guid, &mut settings) };
    check_status(status, "GetInterfaceDnsSettings")?;
    // SAFETY: returned PWSTRs are owned by settings until FreeInterfaceDnsSettings.
    let raw = unsafe { read_returned_settings(&settings) };
    unsafe { ffi::FreeInterfaceDnsSettings(&mut settings) };
    Ok(raw)
}

unsafe fn read_returned_settings(settings: &DNS_INTERFACE_SETTINGS) -> RawDnsSettings {
    RawDnsSettings {
        // SAFETY: API-owned NUL-terminated strings valid until free.
        nameserver: (!settings.NameServer.is_null())
            .then(|| unsafe { wide_to_string(settings.NameServer) }),
        searchlist: (!settings.SearchList.is_null())
            .then(|| unsafe { wide_to_string(settings.SearchList) }),
    }
}

/// `GetInterfaceDnsSettings` requires `Flags = 0` and returns the IPv4 stack.
/// There is no documented Get selector for IPv6, so configured IPv6 overrides
/// are read from the Tcpip6 interface registry key.
pub(crate) fn get_ipv6_dns_settings(guid: &GUID) -> Result<RawDnsSettings> {
    let path = format!(
        r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{{{}}}",
        guid_to_string(guid)
    );
    let key = match open_hklm(&path, false) {
        Ok(key) => key,
        Err(error) if registry_not_found(&error) => return Ok(RawDnsSettings::default()),
        Err(error) => {
            return Err(map_error(error, "cannot read IPv6 DNS configuration"));
        }
    };
    let read = |name: &str| -> Result<Option<String>> {
        match key.get_string(name) {
            Ok(value) => Ok(Some(value)),
            Err(error) if registry_not_found(&error) => Ok(None),
            Err(error) => Err(map_error(error, &format!("cannot read IPv6 {name}"))),
        }
    };
    Ok(RawDnsSettings {
        nameserver: read("NameServer")?,
        searchlist: read("SearchList")?,
    })
}

pub(crate) fn set_dns_settings(
    guid: &GUID,
    ipv6_stack: bool,
    nameserver: Option<&str>,
    searchlist: Option<&str>,
) -> Result<()> {
    let mut flags = 0u64;
    if ipv6_stack {
        flags |= DNS_SETTING_IPV6 as u64;
    }
    let nameserver_wide = nameserver.map(to_wide);
    let searchlist_wide = searchlist.map(to_wide);
    if nameserver_wide.is_some() {
        flags |= DNS_SETTING_NAMESERVER as u64;
    }
    if searchlist_wide.is_some() {
        flags |= DNS_SETTING_SEARCHLIST as u64;
    }
    // SAFETY: wide buffers outlive the call; the API treats them as read-only.
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1 as u32,
        Flags: flags,
        Domain: std::ptr::null_mut(),
        NameServer: nameserver_wide
            .as_ref()
            .map(|v| v.as_ptr() as PWSTR)
            .unwrap_or(std::ptr::null_mut()),
        SearchList: searchlist_wide
            .as_ref()
            .map(|v| v.as_ptr() as PWSTR)
            .unwrap_or(std::ptr::null_mut()),
        RegistrationEnabled: 0,
        RegisterAdapterName: 0,
        EnableLLMNR: 0,
        QueryAdapterName: 0,
        ProfileNameServer: std::ptr::null_mut(),
    };
    let status = unsafe { ffi::SetInterfaceDnsSettings(*guid, &settings) };
    check_status(status, "SetInterfaceDnsSettings")
}

pub(crate) fn parse_address_list(text: &str) -> Vec<IpAddr> {
    text.split([',', ' ', ';'])
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| entry.parse::<IpAddr>().ok())
        .collect()
}

fn v4_sockaddr(bytes: [u8; 4]) -> SOCKADDR_IN {
    SOCKADDR_IN {
        sin_family: AF_INET as ADDRESS_FAMILY,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_un_b: IN_ADDR_0_0 {
                    s_b1: bytes[0],
                    s_b2: bytes[1],
                    s_b3: bytes[2],
                    s_b4: bytes[3],
                },
            },
        },
        sin_zero: [0; 8],
    }
}

fn v6_sockaddr(bytes: [u8; 16]) -> SOCKADDR_IN6_LH {
    SOCKADDR_IN6_LH {
        sin6_family: AF_INET6 as ADDRESS_FAMILY,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 { Byte: bytes },
        },
        Anonymous: SOCKADDR_IN6_LH_0 { sin6_scope_id: 0 },
    }
}

pub(crate) fn default_route_adapter() -> Result<AdapterInfo> {
    const PROBE_V4: [u8; 4] = [8, 8, 8, 8];
    const PROBE_V6: [u8; 16] = [
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
    ];
    let adapters = list_adapters()?;
    let mut best_index: u32 = 0;
    let v4_addr = v4_sockaddr(PROBE_V4);
    // SAFETY: sockaddr is fully initialized; best_index receives the result.
    let v4 = unsafe {
        ffi::GetBestInterfaceEx(
            (&v4_addr as *const SOCKADDR_IN).cast::<SOCKADDR>(),
            &mut best_index,
        )
    };
    let status = if v4 != 0 {
        let v6_addr = v6_sockaddr(PROBE_V6);
        // SAFETY: as above for the IPv6 probe address.
        unsafe {
            ffi::GetBestInterfaceEx(
                (&v6_addr as *const SOCKADDR_IN6_LH).cast::<SOCKADDR>(),
                &mut best_index,
            )
        }
    } else {
        v4
    };
    if status == 0
        && let Some(adapter) = adapters.into_iter().find(|a| a.index == best_index)
    {
        return Ok(adapter);
    }
    Err(Error::invalid_config("no default route is available"))
}

pub(crate) fn adapter_for_selector(selector: &InterfaceSelector) -> Result<AdapterInfo> {
    match selector {
        InterfaceSelector::Default => default_route_adapter(),
        InterfaceSelector::Index(index) => list_adapters()?
            .into_iter()
            .find(|a| a.index == *index)
            .ok_or_else(|| {
                Error::invalid_config(format_args!("interface with index {index} does not exist"))
            }),
        InterfaceSelector::Name(name) => {
            let wanted = name.to_string_lossy().to_string();
            list_adapters()?
                .into_iter()
                .find(|a| {
                    a.friendly_name.eq_ignore_ascii_case(&wanted)
                        || a.guid_string.eq_ignore_ascii_case(&wanted)
                })
                .ok_or_else(|| {
                    Error::invalid_config(format_args!("interface named {wanted:?} does not exist"))
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returned_settings_do_not_use_the_write_mask() {
        let servers = to_wide("192.0.2.53,2001:db8::53");
        let search = to_wide("osdns.test");
        let settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1 as u32,
            Flags: 0,
            NameServer: servers.as_ptr() as PWSTR,
            SearchList: search.as_ptr() as PWSTR,
            Domain: std::ptr::null_mut(),
            RegistrationEnabled: 0,
            RegisterAdapterName: 0,
            EnableLLMNR: 0,
            QueryAdapterName: 0,
            ProfileNameServer: std::ptr::null_mut(),
        };
        // SAFETY: the owned wide buffers outlive the read.
        let raw = unsafe { read_returned_settings(&settings) };
        assert_eq!(raw.nameserver.as_deref(), Some("192.0.2.53,2001:db8::53"));
        assert_eq!(raw.searchlist.as_deref(), Some("osdns.test"));
        assert_eq!(
            unsafe {
                read_returned_settings(&DNS_INTERFACE_SETTINGS {
                    Version: DNS_INTERFACE_SETTINGS_VERSION1 as u32,
                    Flags: 0,
                    Domain: std::ptr::null_mut(),
                    NameServer: std::ptr::null_mut(),
                    SearchList: std::ptr::null_mut(),
                    RegistrationEnabled: 0,
                    RegisterAdapterName: 0,
                    EnableLLMNR: 0,
                    QueryAdapterName: 0,
                    ProfileNameServer: std::ptr::null_mut(),
                })
            },
            RawDnsSettings::default()
        );
    }

    #[test]
    fn guid_string_roundtrip() {
        let guid = guid_from_u128(0x1234_5678_9abc_def0_1122_3344_5566_7788);
        let text = guid_to_string(&guid);
        assert_eq!(text, "12345678-9abc-def0-1122-334455667788");
        let parsed = parse_guid(&text).unwrap();
        assert_eq!(guid.data1, parsed.data1);
        assert_eq!(guid.data2, parsed.data2);
        assert_eq!(guid.data3, parsed.data3);
        assert_eq!(guid.data4, parsed.data4);
        let braced = parse_guid("{12345678-9ABC-DEF0-1122-334455667788}").unwrap();
        assert_eq!(guid.data1, braced.data1);
    }

    #[test]
    fn parse_guid_rejects_garbage() {
        assert!(parse_guid("not-a-guid").is_err());
    }

    #[test]
    fn address_list_parsing() {
        let list = parse_address_list("1.1.1.1, 8.8.8.8 ; 2606:4700:4700::1111 ,");
        assert_eq!(
            list,
            vec![
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "8.8.8.8".parse::<IpAddr>().unwrap(),
                "2606:4700:4700::1111".parse().unwrap(),
            ]
        );
        assert!(parse_address_list("").is_empty());
        assert!(parse_address_list("garbage 1.1.1.1").len() == 1);
    }

    #[test]
    fn adapter_enumeration_read_only() {
        let adapters = list_adapters().unwrap();
        assert!(!adapters.is_empty());
        for adapter in &adapters {
            assert!(!adapter.guid_string.is_empty());
            assert!(adapter.index > 0);
        }
    }

    #[test]
    fn reading_settings_is_read_only() {
        let adapters = list_adapters().unwrap();
        let target = adapters.first().unwrap();
        let _ = get_dns_settings(&target.guid).unwrap();
        let _ = get_ipv6_dns_settings(&target.guid).unwrap();
    }

    #[test]
    fn system_registry_opens_use_wow64_64() {
        // open_hklm always pins wow64_64. A missing path must fail as NotFound.
        let error = open_hklm(
            r"SYSTEM\CurrentControlSet\Services\osdns-missing-key-for-test",
            false,
        )
        .unwrap_err();
        assert!(registry_not_found(&error));
    }
}
