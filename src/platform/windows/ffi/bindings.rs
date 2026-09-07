windows_link::link!("iphlpapi.dll" "system" fn CancelMibChangeNotify2(notificationhandle : HANDLE) -> NTSTATUS);
windows_link::link!("kernel32.dll" "system" fn CloseHandle(hobject : HANDLE) -> BOOL);
windows_link::link!("ole32.dll" "system" fn CoTaskMemFree(pv : *mut core::ffi::c_void));
windows_link::link!("iphlpapi.dll" "system" fn ConvertInterfaceLuidToGuid(interfaceluid : *const NET_LUID, interfaceguid : *mut GUID) -> NTSTATUS);
windows_link::link!("kernel32.dll" "system" fn CreateEventW(lpeventattributes : *const SECURITY_ATTRIBUTES, bmanualreset : BOOL, binitialstate : BOOL, lpname : PCWSTR) -> HANDLE);
windows_link::link!("iphlpapi.dll" "system" fn FreeInterfaceDnsSettings(settings : *mut DNS_INTERFACE_SETTINGS));
windows_link::link!("iphlpapi.dll" "system" fn GetAdaptersAddresses(family : u32, flags : u32, reserved : *const core::ffi::c_void, adapteraddresses : *mut IP_ADAPTER_ADDRESSES_LH, sizepointer : *mut u32) -> u32);
windows_link::link!("iphlpapi.dll" "system" fn GetBestInterfaceEx(destinationaddress : *const SOCKADDR, bestifindex : *mut u32) -> NTSTATUS);
windows_link::link!("iphlpapi.dll" "system" fn GetInterfaceDnsSettings(interface : GUID, settings : *mut DNS_INTERFACE_SETTINGS) -> NTSTATUS);
windows_link::link!("iphlpapi.dll" "system" fn NotifyIpInterfaceChange(family : ADDRESS_FAMILY, callback : PIPINTERFACE_CHANGE_CALLBACK, callercontext : *const core::ffi::c_void, initialnotification : bool, notificationhandle : *mut HANDLE) -> NTSTATUS);
windows_link::link!("advapi32.dll" "system" fn RegNotifyChangeKeyValue(hkey : HKEY, bwatchsubtree : BOOL, dwnotifyfilter : u32, hevent : HANDLE, fasynchronous : BOOL) -> LSTATUS);
windows_link::link!("shell32.dll" "system" fn SHGetFolderPathW(hwnd : HWND, csidl : i32, htoken : HANDLE, dwflags : u32, pszpath : PWSTR) -> HRESULT);
windows_link::link!("shell32.dll" "system" fn SHGetKnownFolderPath(rfid : *const KNOWNFOLDERID, dwflags : u32, htoken : HANDLE, ppszpath : *mut PWSTR) -> HRESULT);
windows_link::link!("kernel32.dll" "system" fn SetEvent(hevent : HANDLE) -> BOOL);
windows_link::link!("iphlpapi.dll" "system" fn SetInterfaceDnsSettings(interface : GUID, settings : *const DNS_INTERFACE_SETTINGS) -> NTSTATUS);
windows_link::link!("kernel32.dll" "system" fn WaitForMultipleObjects(ncount : u32, lphandles : *const HANDLE, bwaitall : BOOL, dwmilliseconds : u32) -> u32);
pub type ADDRESS_FAMILY = u16;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 23;
pub const AF_UNSPEC: i32 = 0;
pub type BOOL = i32;
pub const CSIDL_COMMON_APPDATA: i32 = 35;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DNS_INTERFACE_SETTINGS {
    pub Version: u32,
    pub Flags: u64,
    pub Domain: PWSTR,
    pub NameServer: PWSTR,
    pub SearchList: PWSTR,
    pub RegistrationEnabled: u32,
    pub RegisterAdapterName: u32,
    pub EnableLLMNR: u32,
    pub QueryAdapterName: u32,
    pub ProfileNameServer: PWSTR,
}
pub const DNS_INTERFACE_SETTINGS_VERSION1: i32 = 1;
pub const DNS_SETTING_IPV6: i32 = 1;
pub const DNS_SETTING_NAMESERVER: i32 = 2;
pub const DNS_SETTING_SEARCHLIST: i32 = 4;
pub const ERROR_ACCESS_DENIED: i32 = 5;
pub const ERROR_BUFFER_OVERFLOW: i32 = 111;
pub const ERROR_FILE_NOT_FOUND: i32 = 2;
pub const ERROR_SUCCESS: i32 = 0;
pub const GAA_FLAG_SKIP_ANYCAST: i32 = 2;
pub const GAA_FLAG_SKIP_DNS_SERVER: i32 = 8;
pub const GAA_FLAG_SKIP_MULTICAST: i32 = 4;
pub const GAA_FLAG_SKIP_UNICAST: i32 = 1;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}
pub type HANDLE = *mut core::ffi::c_void;
pub type HKEY = *mut core::ffi::c_void;
pub type HRESULT = i32;
pub type HWND = *mut core::ffi::c_void;
pub type IFTYPE = u32;
pub type IF_INDEX = NET_IFINDEX;
pub type IF_LUID = NET_LUID;
pub type IF_OPER_STATUS = i32;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IN6_ADDR {
    pub u: IN6_ADDR_0,
}
impl Default for IN6_ADDR {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IN6_ADDR_0 {
    pub Byte: [u8; 16],
    pub Word: [u16; 8],
}
impl Default for IN6_ADDR_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const INFINITE: u32 = 4294967295;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IN_ADDR {
    pub S_un: IN_ADDR_0,
}
impl Default for IN_ADDR {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IN_ADDR_0 {
    pub S_un_b: IN_ADDR_0_0,
    pub S_un_w: IN_ADDR_0_1,
    pub S_addr: u32,
}
impl Default for IN_ADDR_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IN_ADDR_0_0 {
    pub s_b1: u8,
    pub s_b2: u8,
    pub s_b3: u8,
    pub s_b4: u8,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IN_ADDR_0_1 {
    pub s_w1: u16,
    pub s_w2: u16,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IP_ADAPTER_ADDRESSES_LH {
    pub Anonymous: IP_ADAPTER_ADDRESSES_LH_0,
    pub Next: *mut Self,
    pub AdapterName: PCHAR,
    pub FirstUnicastAddress: PIP_ADAPTER_UNICAST_ADDRESS_LH,
    pub FirstAnycastAddress: PIP_ADAPTER_ANYCAST_ADDRESS_XP,
    pub FirstMulticastAddress: PIP_ADAPTER_MULTICAST_ADDRESS_XP,
    pub FirstDnsServerAddress: PIP_ADAPTER_DNS_SERVER_ADDRESS_XP,
    pub DnsSuffix: PWCHAR,
    pub Description: PWCHAR,
    pub FriendlyName: PWCHAR,
    pub PhysicalAddress: [u8; 8],
    pub PhysicalAddressLength: u32,
    pub Anonymous2: IP_ADAPTER_ADDRESSES_LH_1,
    pub Mtu: u32,
    pub IfType: IFTYPE,
    pub OperStatus: IF_OPER_STATUS,
    pub Ipv6IfIndex: IF_INDEX,
    pub ZoneIndices: [u32; 16],
    pub FirstPrefix: PIP_ADAPTER_PREFIX_XP,
    pub TransmitLinkSpeed: u64,
    pub ReceiveLinkSpeed: u64,
    pub FirstWinsServerAddress: PIP_ADAPTER_WINS_SERVER_ADDRESS_LH,
    pub FirstGatewayAddress: PIP_ADAPTER_GATEWAY_ADDRESS_LH,
    pub Ipv4Metric: u32,
    pub Ipv6Metric: u32,
    pub Luid: IF_LUID,
    pub Dhcpv4Server: SOCKET_ADDRESS,
    pub CompartmentId: NET_IF_COMPARTMENT_ID,
    pub NetworkGuid: NET_IF_NETWORK_GUID,
    pub ConnectionType: NET_IF_CONNECTION_TYPE,
    pub TunnelType: TUNNEL_TYPE,
    pub Dhcpv6Server: SOCKET_ADDRESS,
    pub Dhcpv6ClientDuid: [u8; 130],
    pub Dhcpv6ClientDuidLength: u32,
    pub Dhcpv6Iaid: u32,
    pub FirstDnsSuffix: PIP_ADAPTER_DNS_SUFFIX,
}
impl Default for IP_ADAPTER_ADDRESSES_LH {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IP_ADAPTER_ADDRESSES_LH_0 {
    pub Alignment: u64,
    pub Anonymous: IP_ADAPTER_ADDRESSES_LH_0_0,
}
impl Default for IP_ADAPTER_ADDRESSES_LH_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IP_ADAPTER_ADDRESSES_LH_0_0 {
    pub Length: u32,
    pub IfIndex: IF_INDEX,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IP_ADAPTER_ADDRESSES_LH_1 {
    pub Flags: u32,
    pub Anonymous: IP_ADAPTER_ADDRESSES_LH_1_0,
}
impl Default for IP_ADAPTER_ADDRESSES_LH_1 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IP_ADAPTER_ADDRESSES_LH_1_0 {
    pub _bitfield: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IP_ADAPTER_ANYCAST_ADDRESS_XP {
    pub Anonymous: IP_ADAPTER_ANYCAST_ADDRESS_XP_0,
    pub Next: *mut Self,
    pub Address: SOCKET_ADDRESS,
}
impl Default for IP_ADAPTER_ANYCAST_ADDRESS_XP {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IP_ADAPTER_ANYCAST_ADDRESS_XP_0 {
    pub Alignment: u64,
    pub Anonymous: IP_ADAPTER_ANYCAST_ADDRESS_XP_0_0,
}
impl Default for IP_ADAPTER_ANYCAST_ADDRESS_XP_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IP_ADAPTER_ANYCAST_ADDRESS_XP_0_0 {
    pub Length: u32,
    pub Flags: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IP_ADAPTER_DNS_SERVER_ADDRESS_XP {
    pub Anonymous: IP_ADAPTER_DNS_SERVER_ADDRESS_XP_0,
    pub Next: *mut Self,
    pub Address: SOCKET_ADDRESS,
}
impl Default for IP_ADAPTER_DNS_SERVER_ADDRESS_XP {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IP_ADAPTER_DNS_SERVER_ADDRESS_XP_0 {
    pub Alignment: u64,
    pub Anonymous: IP_ADAPTER_DNS_SERVER_ADDRESS_XP_0_0,
}
impl Default for IP_ADAPTER_DNS_SERVER_ADDRESS_XP_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IP_ADAPTER_DNS_SERVER_ADDRESS_XP_0_0 {
    pub Length: u32,
    pub Reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IP_ADAPTER_DNS_SUFFIX {
    pub Next: *mut Self,
    pub String: [u16; 256],
}
impl Default for IP_ADAPTER_DNS_SUFFIX {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IP_ADAPTER_GATEWAY_ADDRESS_LH {
    pub Anonymous: IP_ADAPTER_GATEWAY_ADDRESS_LH_0,
    pub Next: *mut Self,
    pub Address: SOCKET_ADDRESS,
}
impl Default for IP_ADAPTER_GATEWAY_ADDRESS_LH {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IP_ADAPTER_GATEWAY_ADDRESS_LH_0 {
    pub Alignment: u64,
    pub Anonymous: IP_ADAPTER_GATEWAY_ADDRESS_LH_0_0,
}
impl Default for IP_ADAPTER_GATEWAY_ADDRESS_LH_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IP_ADAPTER_GATEWAY_ADDRESS_LH_0_0 {
    pub Length: u32,
    pub Reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IP_ADAPTER_MULTICAST_ADDRESS_XP {
    pub Anonymous: IP_ADAPTER_MULTICAST_ADDRESS_XP_0,
    pub Next: *mut Self,
    pub Address: SOCKET_ADDRESS,
}
impl Default for IP_ADAPTER_MULTICAST_ADDRESS_XP {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IP_ADAPTER_MULTICAST_ADDRESS_XP_0 {
    pub Alignment: u64,
    pub Anonymous: IP_ADAPTER_MULTICAST_ADDRESS_XP_0_0,
}
impl Default for IP_ADAPTER_MULTICAST_ADDRESS_XP_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IP_ADAPTER_MULTICAST_ADDRESS_XP_0_0 {
    pub Length: u32,
    pub Flags: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IP_ADAPTER_PREFIX_XP {
    pub Anonymous: IP_ADAPTER_PREFIX_XP_0,
    pub Next: *mut Self,
    pub Address: SOCKET_ADDRESS,
    pub PrefixLength: u32,
}
impl Default for IP_ADAPTER_PREFIX_XP {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IP_ADAPTER_PREFIX_XP_0 {
    pub Alignment: u64,
    pub Anonymous: IP_ADAPTER_PREFIX_XP_0_0,
}
impl Default for IP_ADAPTER_PREFIX_XP_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IP_ADAPTER_PREFIX_XP_0_0 {
    pub Length: u32,
    pub Flags: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IP_ADAPTER_UNICAST_ADDRESS_LH {
    pub Anonymous: IP_ADAPTER_UNICAST_ADDRESS_LH_0,
    pub Next: *mut Self,
    pub Address: SOCKET_ADDRESS,
    pub PrefixOrigin: IP_PREFIX_ORIGIN,
    pub SuffixOrigin: IP_SUFFIX_ORIGIN,
    pub DadState: IP_DAD_STATE,
    pub ValidLifetime: u32,
    pub PreferredLifetime: u32,
    pub LeaseLifetime: u32,
    pub OnLinkPrefixLength: u8,
}
impl Default for IP_ADAPTER_UNICAST_ADDRESS_LH {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IP_ADAPTER_UNICAST_ADDRESS_LH_0 {
    pub Alignment: u64,
    pub Anonymous: IP_ADAPTER_UNICAST_ADDRESS_LH_0_0,
}
impl Default for IP_ADAPTER_UNICAST_ADDRESS_LH_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IP_ADAPTER_UNICAST_ADDRESS_LH_0_0 {
    pub Length: u32,
    pub Flags: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IP_ADAPTER_WINS_SERVER_ADDRESS_LH {
    pub Anonymous: IP_ADAPTER_WINS_SERVER_ADDRESS_LH_0,
    pub Next: *mut Self,
    pub Address: SOCKET_ADDRESS,
}
impl Default for IP_ADAPTER_WINS_SERVER_ADDRESS_LH {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IP_ADAPTER_WINS_SERVER_ADDRESS_LH_0 {
    pub Alignment: u64,
    pub Anonymous: IP_ADAPTER_WINS_SERVER_ADDRESS_LH_0_0,
}
impl Default for IP_ADAPTER_WINS_SERVER_ADDRESS_LH_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IP_ADAPTER_WINS_SERVER_ADDRESS_LH_0_0 {
    pub Length: u32,
    pub Reserved: u32,
}
pub type IP_DAD_STATE = NL_DAD_STATE;
pub type IP_PREFIX_ORIGIN = NL_PREFIX_ORIGIN;
pub type IP_SUFFIX_ORIGIN = NL_SUFFIX_ORIGIN;
pub const IfOperStatusUp: IF_OPER_STATUS = 1;
pub const KEY_NOTIFY: i32 = 16;
pub const KF_FLAG_DEFAULT: KNOWN_FOLDER_FLAG = 0;
pub type KNOWNFOLDERID = GUID;
pub type KNOWN_FOLDER_FLAG = u32;
pub type LPSOCKADDR = *mut SOCKADDR;
pub type LSTATUS = i32;
pub const MAX_PATH: i32 = 260;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MIB_IPINTERFACE_ROW {
    pub Family: ADDRESS_FAMILY,
    pub InterfaceLuid: NET_LUID,
    pub InterfaceIndex: NET_IFINDEX,
    pub MaxReassemblySize: u32,
    pub InterfaceIdentifier: u64,
    pub MinRouterAdvertisementInterval: u32,
    pub MaxRouterAdvertisementInterval: u32,
    pub AdvertisingEnabled: bool,
    pub ForwardingEnabled: bool,
    pub WeakHostSend: bool,
    pub WeakHostReceive: bool,
    pub UseAutomaticMetric: bool,
    pub UseNeighborUnreachabilityDetection: bool,
    pub ManagedAddressConfigurationSupported: bool,
    pub OtherStatefulConfigurationSupported: bool,
    pub AdvertiseDefaultRoute: bool,
    pub RouterDiscoveryBehavior: NL_ROUTER_DISCOVERY_BEHAVIOR,
    pub DadTransmits: u32,
    pub BaseReachableTime: u32,
    pub RetransmitTime: u32,
    pub PathMtuDiscoveryTimeout: u32,
    pub LinkLocalAddressBehavior: NL_LINK_LOCAL_ADDRESS_BEHAVIOR,
    pub LinkLocalAddressTimeout: u32,
    pub ZoneIndices: [u32; 16],
    pub SitePrefixLength: u32,
    pub Metric: u32,
    pub NlMtu: u32,
    pub Connected: bool,
    pub SupportsWakeUpPatterns: bool,
    pub SupportsNeighborDiscovery: bool,
    pub SupportsRouterDiscovery: bool,
    pub ReachableTime: u32,
    pub TransmitOffload: NL_INTERFACE_OFFLOAD_ROD,
    pub ReceiveOffload: NL_INTERFACE_OFFLOAD_ROD,
    pub DisableDefaultRoutes: bool,
}
impl Default for MIB_IPINTERFACE_ROW {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub type MIB_NOTIFICATION_TYPE = i32;
pub const MibAddInstance: MIB_NOTIFICATION_TYPE = 1;
pub const MibDeleteInstance: MIB_NOTIFICATION_TYPE = 2;
pub const MibInitialNotification: MIB_NOTIFICATION_TYPE = 3;
pub const MibParameterNotification: MIB_NOTIFICATION_TYPE = 0;
pub type NET_IFINDEX = u32;
pub type NET_IF_COMPARTMENT_ID = u32;
pub type NET_IF_CONNECTION_TYPE = i32;
pub type NET_IF_NETWORK_GUID = GUID;
pub type NET_LUID = NET_LUID_LH;
#[repr(C)]
#[derive(Clone, Copy)]
pub union NET_LUID_LH {
    pub Value: u64,
    pub Info: NET_LUID_LH_0,
}
impl Default for NET_LUID_LH {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NET_LUID_LH_0 {
    pub _bitfield: u64,
}
pub type NL_DAD_STATE = i32;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NL_INTERFACE_OFFLOAD_ROD {
    pub _bitfield: bool,
}
pub type NL_LINK_LOCAL_ADDRESS_BEHAVIOR = i32;
pub type NL_PREFIX_ORIGIN = i32;
pub type NL_ROUTER_DISCOVERY_BEHAVIOR = i32;
pub type NL_SUFFIX_ORIGIN = i32;
pub const NO_ERROR: i32 = 0;
pub type NTSTATUS = i32;
pub type PCHAR = *mut i8;
pub type PCWSTR = *const u16;
pub type PIPINTERFACE_CHANGE_CALLBACK = Option<
    unsafe extern "system" fn(
        callercontext: *const core::ffi::c_void,
        row: *const MIB_IPINTERFACE_ROW,
        notificationtype: MIB_NOTIFICATION_TYPE,
    ),
>;
pub type PIP_ADAPTER_ANYCAST_ADDRESS_XP = *mut IP_ADAPTER_ANYCAST_ADDRESS_XP;
pub type PIP_ADAPTER_DNS_SERVER_ADDRESS_XP = *mut IP_ADAPTER_DNS_SERVER_ADDRESS_XP;
pub type PIP_ADAPTER_DNS_SUFFIX = *mut IP_ADAPTER_DNS_SUFFIX;
pub type PIP_ADAPTER_GATEWAY_ADDRESS_LH = *mut IP_ADAPTER_GATEWAY_ADDRESS_LH;
pub type PIP_ADAPTER_MULTICAST_ADDRESS_XP = *mut IP_ADAPTER_MULTICAST_ADDRESS_XP;
pub type PIP_ADAPTER_PREFIX_XP = *mut IP_ADAPTER_PREFIX_XP;
pub type PIP_ADAPTER_UNICAST_ADDRESS_LH = *mut IP_ADAPTER_UNICAST_ADDRESS_LH;
pub type PIP_ADAPTER_WINS_SERVER_ADDRESS_LH = *mut IP_ADAPTER_WINS_SERVER_ADDRESS_LH;
pub type PWCHAR = *mut u16;
pub type PWSTR = *mut u16;
pub const REG_NOTIFY_CHANGE_LAST_SET: i32 = 4;
pub const REG_NOTIFY_CHANGE_NAME: i32 = 1;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SCOPE_ID {
    pub Anonymous: SCOPE_ID_0,
}
impl Default for SCOPE_ID {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union SCOPE_ID_0 {
    pub Anonymous: SCOPE_ID_0_0,
    pub Value: u32,
}
impl Default for SCOPE_ID_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SCOPE_ID_0_0 {
    pub _bitfield: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: u32,
    pub lpSecurityDescriptor: *mut core::ffi::c_void,
    pub bInheritHandle: BOOL,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SOCKADDR {
    pub sa_family: ADDRESS_FAMILY,
    pub sa_data: [i8; 14],
}
impl Default for SOCKADDR {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SOCKADDR_IN {
    pub sin_family: ADDRESS_FAMILY,
    pub sin_port: u16,
    pub sin_addr: IN_ADDR,
    pub sin_zero: [i8; 8],
}
impl Default for SOCKADDR_IN {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub type SOCKADDR_IN6 = SOCKADDR_IN6_LH;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SOCKADDR_IN6_LH {
    pub sin6_family: ADDRESS_FAMILY,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: IN6_ADDR,
    pub Anonymous: SOCKADDR_IN6_LH_0,
}
impl Default for SOCKADDR_IN6_LH {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union SOCKADDR_IN6_LH_0 {
    pub sin6_scope_id: u32,
    pub sin6_scope_struct: SCOPE_ID,
}
impl Default for SOCKADDR_IN6_LH_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SOCKET_ADDRESS {
    pub lpSockaddr: LPSOCKADDR,
    pub iSockaddrLength: i32,
}
pub type TUNNEL_TYPE = i32;
pub const WAIT_OBJECT_0: i32 = 0;
