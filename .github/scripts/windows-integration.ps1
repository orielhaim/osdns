# Run only on a disposable CI VM, as administrator. Never select its uplink.
$ErrorActionPreference = 'Stop'
$adapterName = 'osdns-ci-loopback'
if (Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue) {
    throw "Refusing to reuse existing adapter $adapterName"
}

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class OsdnsLoopback {
    [StructLayout(LayoutKind.Sequential)]
    struct DeviceInfo { public uint Size; public Guid ClassGuid; public uint DevInst; public UIntPtr Reserved; }
    [DllImport("setupapi.dll", SetLastError=true)]
    static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid cls, IntPtr parent);
    [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool SetupDiCreateDeviceInfo(IntPtr set, string name, ref Guid cls, string description, IntPtr parent, uint flags, ref DeviceInfo info);
    [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool SetupDiSetDeviceRegistryProperty(IntPtr set, ref DeviceInfo info, uint property, byte[] buffer, uint size);
    [DllImport("setupapi.dll", SetLastError=true)]
    static extern bool SetupDiCallClassInstaller(uint function, IntPtr set, ref DeviceInfo info);
    [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool SetupDiGetDeviceInstanceId(IntPtr set, ref DeviceInfo info, StringBuilder id, uint size, out uint required);
    [DllImport("setupapi.dll")]
    static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("newdev.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool UpdateDriverForPlugAndPlayDevices(IntPtr parent, string hardware, string inf, uint flags, out bool reboot);
    static void Check(bool ok) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    public static string Create(string inf) {
        Guid cls = new Guid("4d36e972-e325-11ce-bfc1-08002be10318");
        IntPtr set = SetupDiCreateDeviceInfoList(ref cls, IntPtr.Zero);
        if (set == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        DeviceInfo info = new DeviceInfo { Size = (uint)Marshal.SizeOf(typeof(DeviceInfo)) };
        bool registered = false;
        try {
            Check(SetupDiCreateDeviceInfo(set, "Net", ref cls, "osdns CI loopback", IntPtr.Zero, 1, ref info));
            byte[] hardware = Encoding.Unicode.GetBytes("*MSLOOP\0\0");
            Check(SetupDiSetDeviceRegistryProperty(set, ref info, 1, hardware, (uint)hardware.Length));
            Check(SetupDiCallClassInstaller(0x19, set, ref info)); // DIF_REGISTERDEVICE
            registered = true;
            bool reboot;
            Check(UpdateDriverForPlugAndPlayDevices(IntPtr.Zero, "*MSLOOP", inf, 5, out reboot));
            if (reboot) throw new Exception("Loopback installation requires a reboot");
            var id = new StringBuilder(512);
            uint required;
            Check(SetupDiGetDeviceInstanceId(set, ref info, id, 512, out required));
            return id.ToString();
        } catch {
            if (registered) SetupDiCallClassInstaller(5, set, ref info); // DIF_REMOVE
            throw;
        } finally { SetupDiDestroyDeviceInfoList(set); }
    }
}
'@

$deviceId = [OsdnsLoopback]::Create("$env:windir\INF\netloop.inf")
try {
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $adapter = Get-CimInstance Win32_NetworkAdapter | Where-Object PNPDeviceID -EQ $deviceId
        if ($adapter.NetConnectionID) { break }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    if (!$adapter.NetConnectionID) { throw "Loopback adapter did not appear: $deviceId" }
    Rename-NetAdapter -Name $adapter.NetConnectionID -NewName $adapterName
    Set-NetIPInterface -InterfaceAlias $adapterName -AddressFamily IPv4 -Dhcp Disabled
    New-NetIPAddress -InterfaceAlias $adapterName -IPAddress 192.0.2.1 -PrefixLength 24 | Out-Null
    Set-DnsClientServerAddress -InterfaceAlias $adapterName -ResetServerAddresses
    $env:OSDNS_TEST_INTERFACE = $adapterName
    $env:OSDNS_ALLOW_SYSTEM_MUTATION = '1'
    cargo +1.98.0 test --features test-util --test backend_matrix --test windows -- --nocapture --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw "Windows integration tests failed ($LASTEXITCODE)" }
} finally {
    pnputil /remove-device $deviceId
    if ($LASTEXITCODE -ne 0) { throw "Failed to remove disposable adapter $deviceId" }
    Remove-Item Env:OSDNS_TEST_INTERFACE -ErrorAction SilentlyContinue
    Remove-Item Env:OSDNS_ALLOW_SYSTEM_MUTATION -ErrorAction SilentlyContinue
}
