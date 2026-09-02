//! Per-interface DNS settings via the native IP Helper API
//! (`GetInterfaceDnsSettings`/`SetInterfaceDnsSettings`, Windows 10 19041+),
//! adapter enumeration, and interface selection.

use std::net::IpAddr;

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6,
    DNS_SETTING_NAMESERVER, DNS_SETTING_SEARCHLIST, FreeInterfaceDnsSettings,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, GetBestInterfaceEx, GetInterfaceDnsSettings,
    IP_ADAPTER_ADDRESSES_LH, SetInterfaceDnsSettings,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_IN6_0,
};
use windows::core::{GUID, PWSTR};

use crate::capability::BackendKind;
use crate::config::InterfaceSelector;
use crate::error::{Error, Result};
use crate::interface::InterfaceInfo;

pub(crate) struct AdapterInfo {
    #[allow(dead_code)]
    pub(crate) guid: GUID,
    pub(crate) guid_string: String,
    pub(crate) friendly_name: String,
    pub(crate) index: u32,
    pub(crate) is_up: bool,
}

pub(crate) fn guid_to_string(guid: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7]
    )
}

pub(crate) fn parse_guid(text: &str) -> Result<GUID> {
    let cleaned: String = text
        .chars()
        .filter(|c| *c != '{' && *c != '}' && *c != '-')
        .collect();
    let value = u128::from_str_radix(&cleaned, 16)
        .map_err(|_| Error::invalid_config(format_args!("invalid interface GUID {text:?}")))?;
    Ok(GUID::from_u128(value))
}

pub(crate) fn list_adapters() -> Result<Vec<AdapterInfo>> {
    let mut size: u32 = 16 * 1024;
    loop {
        let mut buffer = vec![0u8; size as usize];
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_SKIP_UNICAST
                    | GAA_FLAG_SKIP_ANYCAST
                    | GAA_FLAG_SKIP_MULTICAST
                    | GAA_FLAG_SKIP_DNS_SERVER,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
        match result {
            0 => return unsafe { adapters_from_buffer(&buffer) },
            111 => {
                if size > 64 * 1024 * 1024 {
                    return Err(Error::Platform {
                        backend: BackendKind::WindowsIpHelper,
                        message: "adapter enumeration buffer grew unreasonably large".to_string(),
                    });
                }
                continue;
            }
            error => {
                return Err(win32_error(
                    BackendKind::WindowsIpHelper,
                    WIN32_ERROR(error),
                    "GetAdaptersAddresses",
                ));
            }
        }
    }
}

unsafe fn adapters_from_buffer(buffer: &[u8]) -> Result<Vec<AdapterInfo>> {
    let mut adapters = Vec::new();
    let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !current.is_null() {
        // SAFETY: the buffer was filled by GetAdaptersAddresses, which
        // guarantees a valid, NUL-terminated linked list of
        // IP_ADAPTER_ADDRESSES structures for the reported size.
        let adapter = unsafe { &*current };
        let guid_string = unsafe { pcstr_to_string(adapter.AdapterName.0) };
        let friendly_name = unsafe { pwstr_to_string(adapter.FriendlyName) };
        // SAFETY: reading the IfIndex variant of the Anonymous1 union is the
        // documented way to obtain the interface index from this structure.
        let if_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
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

unsafe fn pcstr_to_string(pointer: *const u8) -> String {
    if pointer.is_null() {
        return String::new();
    }
    // SAFETY: the pointer refers to a NUL-terminated ANSI string owned by the
    // adapter list for the duration of the call.
    let mut len = 0usize;
    unsafe {
        while *pointer.add(len) != 0 {
            len += 1;
        }
        std::str::from_utf8(std::slice::from_raw_parts(pointer, len))
            .unwrap_or_default()
            .to_string()
    }
}

unsafe fn pwstr_to_string(pointer: PWSTR) -> String {
    if pointer.is_null() {
        return String::new();
    }
    // SAFETY: the pointer refers to a NUL-terminated wide string allocated by
    // GetInterfaceDnsSettings; it is freed by FreeInterfaceDnsSettings after
    // this conversion.
    unsafe { pointer.to_string().unwrap_or_default() }
}

pub(crate) fn win32_error(backend: BackendKind, error: WIN32_ERROR, operation: &str) -> Error {
    if error == windows::Win32::Foundation::ERROR_ACCESS_DENIED {
        return Error::RequiresPrivilege(format!("{operation} requires administrator privileges"));
    }
    Error::Platform {
        backend,
        message: format!("{operation} failed with win32 error {}", error.0),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RawDnsSettings {
    pub(crate) nameserver: Option<String>,
    pub(crate) searchlist: Option<String>,
}

pub(crate) fn get_dns_settings(guid: &GUID) -> Result<RawDnsSettings> {
    let mut settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: 0,
        Domain: PWSTR::null(),
        NameServer: PWSTR::null(),
        SearchList: PWSTR::null(),
        RegistrationEnabled: 0,
        RegisterAdapterName: 0,
        EnableLLMNR: 0,
        QueryAdapterName: 0,
        ProfileNameServer: PWSTR::null(),
    };
    let result = unsafe { GetInterfaceDnsSettings(*guid, &mut settings) };
    if result.0 != 0 {
        return Err(win32_error(
            BackendKind::WindowsIpHelper,
            result,
            "GetInterfaceDnsSettings",
        ));
    }
    // Get populates the fields but does not set the Set operation's mask.
    // SAFETY: these strings belong to settings until FreeInterfaceDnsSettings.
    let raw = unsafe { read_returned_settings(&settings) };
    unsafe { FreeInterfaceDnsSettings(&mut settings) };
    Ok(raw)
}

unsafe fn read_returned_settings(settings: &DNS_INTERFACE_SETTINGS) -> RawDnsSettings {
    RawDnsSettings {
        // SAFETY: caller guarantees valid API-owned NUL-terminated strings.
        nameserver: (!settings.NameServer.is_null())
            .then(|| unsafe { pwstr_to_string(settings.NameServer) }),
        searchlist: (!settings.SearchList.is_null())
            .then(|| unsafe { pwstr_to_string(settings.SearchList) }),
    }
}

pub(crate) fn set_dns_settings(
    guid: &GUID,
    ipv6_stack: bool,
    nameserver: Option<&str>,
    searchlist: Option<&str>,
) -> Result<()> {
    let mut flags = 0u64;
    if ipv6_stack {
        flags |= u64::from(DNS_SETTING_IPV6);
    }
    let mut nameserver_hstring = windows::core::HSTRING::new();
    let mut searchlist_hstring = windows::core::HSTRING::new();
    if let Some(value) = nameserver {
        flags |= u64::from(DNS_SETTING_NAMESERVER);
        nameserver_hstring = windows::core::HSTRING::from(value);
    }
    if let Some(value) = searchlist {
        flags |= u64::from(DNS_SETTING_SEARCHLIST);
        searchlist_hstring = windows::core::HSTRING::from(value);
    }
    // SAFETY: the HSTRING pointers remain valid for the duration of the call
    // and the API treats them as read-only NUL-terminated inputs.
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: flags,
        Domain: PWSTR::null(),
        NameServer: PWSTR::from_raw(nameserver_hstring.as_ptr() as *mut u16),
        SearchList: PWSTR::from_raw(searchlist_hstring.as_ptr() as *mut u16),
        RegistrationEnabled: 0,
        RegisterAdapterName: 0,
        EnableLLMNR: 0,
        QueryAdapterName: 0,
        ProfileNameServer: PWSTR::null(),
    };
    let result = unsafe { SetInterfaceDnsSettings(*guid, &settings) };
    if result.0 != 0 {
        return Err(win32_error(
            BackendKind::WindowsIpHelper,
            result,
            "SetInterfaceDnsSettings",
        ));
    }
    Ok(())
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
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_un_b: windows::Win32::Networking::WinSock::IN_ADDR_0_0 {
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

fn v6_sockaddr(bytes: [u8; 16]) -> SOCKADDR_IN6 {
    SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 { Byte: bytes },
        },
        Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
    }
}

pub(crate) fn default_route_adapter() -> Result<AdapterInfo> {
    const PROBE_V4: [u8; 4] = [8, 8, 8, 8];
    const PROBE_V6: [u8; 16] = [
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
    ];
    let adapters = list_adapters()?;
    let mut best_index: u32 = 0;
    // SAFETY: both sockaddr variants are valid, fully initialized inputs;
    // BestIfIndex receives the route lookup result.
    let v4 = unsafe {
        GetBestInterfaceEx(
            &v4_sockaddr(PROBE_V4) as *const _ as *const _,
            &mut best_index,
        )
    };
    let v6 = if v4 != 0 {
        // SAFETY: see above.
        unsafe {
            GetBestInterfaceEx(
                &v6_sockaddr(PROBE_V6) as *const _ as *const _,
                &mut best_index,
            )
        }
    } else {
        v4
    };
    if v6 == 0
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

pub(crate) fn adapter_list() -> Result<Vec<InterfaceInfo>> {
    Ok(list_adapters()?
        .into_iter()
        .map(|a| InterfaceInfo {
            index: a.index,
            name: a.friendly_name.clone().into(),
            friendly_name: Some(a.friendly_name),
            guid: Some(a.guid_string),
            is_up: a.is_up,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returned_settings_do_not_use_the_write_mask() {
        let servers = windows::core::HSTRING::from("192.0.2.53,2001:db8::53");
        let search = windows::core::HSTRING::from("osdns.test");
        let settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: 0,
            NameServer: PWSTR::from_raw(servers.as_ptr().cast_mut()),
            SearchList: PWSTR::from_raw(search.as_ptr().cast_mut()),
            ..Default::default()
        };
        // SAFETY: the HSTRING values outlive the read.
        let raw = unsafe { read_returned_settings(&settings) };
        assert_eq!(raw.nameserver.as_deref(), Some("192.0.2.53,2001:db8::53"));
        assert_eq!(raw.searchlist.as_deref(), Some("osdns.test"));
        // SAFETY: all string pointers are null.
        assert_eq!(
            unsafe { read_returned_settings(&DNS_INTERFACE_SETTINGS::default()) },
            RawDnsSettings::default()
        );
    }

    #[test]
    fn guid_string_roundtrip() {
        let guid = GUID::from_u128(0x1234_5678_9abc_def0_1122_3344_5566_7788);
        let text = guid_to_string(&guid);
        assert_eq!(text, "12345678-9abc-def0-1122-334455667788");
        let parsed = parse_guid(&text).unwrap();
        assert_eq!(guid, parsed);
        let braced = parse_guid("{12345678-9ABC-DEF0-1122-334455667788}").unwrap();
        assert_eq!(guid, braced);
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
        let target = adapters
            .iter()
            .find(|a| a.guid_string.starts_with("loopback"))
            .or_else(|| adapters.first())
            .unwrap();
        let settings = get_dns_settings(&target.guid).unwrap();
        let _ = settings;
    }
}
