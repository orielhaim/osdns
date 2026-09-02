//! Native change notifications: `NotifyIpInterfaceChange` for interface
//! events and `RegNotifyChangeKeyValue` for NRPT registry changes.
//!
//! Callbacks only enqueue; heavy logic never runs inside them, and
//! notifications are never cancelled from inside their own callback.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Sender;
use std::thread;

use windows::Win32::Foundation::{HANDLE, NO_ERROR, WAIT_OBJECT_0};
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, ConvertInterfaceLuidToGuid, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
    NotifyIpInterfaceChange,
};
use windows::Win32::Networking::WinSock::AF_UNSPEC;
use windows::Win32::System::Registry::{
    HKEY, KEY_NOTIFY, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME, REG_NOTIFY_FILTER,
    RegNotifyChangeKeyValue, RegOpenKeyExW,
};
use windows::Win32::System::Threading::{CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects};
use windows::core::GUID;

use crate::capability::BackendKind;
use crate::error::{Error, Result};
use crate::ownership::ResourceId;
use crate::watch::DnsEvent;

const NRPT_WATCH_KEY: &str = "SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters";

fn resource_from_row(row: &MIB_IPINTERFACE_ROW) -> Option<ResourceId> {
    let mut guid = GUID::zeroed();
    // SAFETY: both pointers reference valid caller-owned memory for the
    // duration of the call.
    let result = unsafe { ConvertInterfaceLuidToGuid(&row.InterfaceLuid, &mut guid) };
    if result.is_err() {
        return None;
    }
    let text = crate::platform::windows::interface::guid_to_string(&guid);
    ResourceId::new(format!("windows:interface:{text}")).ok()
}

struct IpNotifyContext {
    sender: Sender<ResourceId>,
}

unsafe extern "system" fn ip_interface_callback(
    caller_context: *const core::ffi::c_void,
    row: *const MIB_IPINTERFACE_ROW,
    _notification_type: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: the context pointer was created by Box::into_raw in
    // start_ip_interface_watch and is only freed after the notification is
    // cancelled on a thread other than this callback.
    let context = unsafe { &*(caller_context as *const IpNotifyContext) };
    // SAFETY: the OS passes a valid row pointer for the duration of the
    // callback.
    let row = unsafe { &*row };
    if let Some(resource) = resource_from_row(row) {
        let _ = context.sender.send(resource);
    }
}

pub(crate) fn start_ip_interface_watch(
    flag: Arc<std::sync::atomic::AtomicBool>,
    callback: Arc<dyn Fn(&DnsEvent) + Send + Sync>,
) -> Result<Box<dyn FnOnce() + Send>> {
    let (tx, rx) = std::sync::mpsc::channel::<ResourceId>();
    let context = Box::into_raw(Box::new(IpNotifyContext { sender: tx }));

    let mut notification: HANDLE = HANDLE::default();
    let result = unsafe {
        NotifyIpInterfaceChange(
            AF_UNSPEC,
            Some(ip_interface_callback),
            Some(context as *mut core::ffi::c_void),
            false,
            &mut notification,
        )
    };
    if result != NO_ERROR {
        // SAFETY: the context was not yet handed to the OS, so reclaiming it
        // here cannot race with the callback.
        unsafe { drop(Box::from_raw(context)) };
        return Err(crate::platform::windows::interface::win32_error(
            BackendKind::WindowsIpHelper,
            result,
            "NotifyIpInterfaceChange",
        ));
    }

    let worker_flag = flag.clone();
    thread::Builder::new()
        .name("osdns-ipnotify-worker".to_string())
        .spawn(move || {
            while let Ok(resource) = rx.recv() {
                if worker_flag.load(Ordering::Acquire) {
                    break;
                }
                callback(&DnsEvent::ResourceChanged { resource });
                if worker_flag.load(Ordering::Acquire) {
                    break;
                }
            }
        })
        .map_err(|e| Error::Platform {
            backend: BackendKind::WindowsIpHelper,
            message: format!("cannot spawn notification worker: {e}"),
        })?;

    // SAFETY: the notification handle outlives every use of this wrapper: the
    // OS guarantees the handle is valid until CancelMibChangeNotify2 runs,
    // and cancellation happens exactly once, on the caller's thread, never
    // from inside the callback.
    struct SendHandle(HANDLE);
    unsafe impl Send for SendHandle {}
    impl SendHandle {
        fn cancel(self) {
            // SAFETY: see the SendHandle safety contract above.
            unsafe {
                let _ = CancelMibChangeNotify2(self.0);
            }
        }
    }
    let wrapped = SendHandle(notification);
    Ok(Box::new(move || {
        flag.store(true, Ordering::Release);
        wrapped.cancel();
    }))
}

struct RegistryWatch {
    notify_event: HANDLE,
    cancel_event: HANDLE,
    key: HKEY,
}

// SAFETY: the worker thread takes exclusive ownership of the handle set; the
// cancel path (SendEvent) touches only cancel_event and runs after the worker
// has been woken by it, and the key handle is closed exactly once by the
// worker on exit.
unsafe impl Send for RegistryWatch {}

impl RegistryWatch {
    fn wait(&self) -> bool {
        let handles = [self.notify_event, self.cancel_event];
        // SAFETY: both handles are valid event handles owned by this watcher.
        let waited = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
        waited == WAIT_OBJECT_0
    }

    fn close(self) {
        // SAFETY: the key handle was opened by RegOpenKeyExW and is closed
        // exactly once, after the watch loop exits.
        unsafe {
            let _ = windows::Win32::System::Registry::RegCloseKey(self.key);
        }
    }
}

pub(crate) fn start_nrpt_registry_watch(
    flag: Arc<std::sync::atomic::AtomicBool>,
    callback: Arc<dyn Fn(&DnsEvent) + Send + Sync>,
) -> Result<Box<dyn FnOnce() + Send>> {
    // SAFETY: CreateEventW with a null name creates a new unnamed event; the
    // returned handles are closed on the stop path.
    let notify_event =
        unsafe { CreateEventW(None, false, false, None) }.map_err(|e| Error::Platform {
            backend: BackendKind::WindowsIpHelper,
            message: format!("CreateEventW failed: {e}"),
        })?;
    // SAFETY: as above; unnamed event.
    let cancel_event =
        unsafe { CreateEventW(None, false, false, None) }.map_err(|e| Error::Platform {
            backend: BackendKind::WindowsIpHelper,
            message: format!("CreateEventW failed: {e}"),
        })?;

    let mut key = HKEY::default();
    let wide: Vec<u16> = NRPT_WATCH_KEY
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: wide is a valid NUL-terminated wide string for the duration of
    // the call; key receives a valid HKEY that is closed on the stop path.
    let open = unsafe {
        RegOpenKeyExW(
            windows::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(wide.as_ptr()),
            None,
            KEY_NOTIFY,
            &mut key,
        )
    };
    if open != windows::Win32::Foundation::ERROR_SUCCESS {
        return Err(crate::platform::windows::interface::win32_error(
            BackendKind::WindowsIpHelper,
            open,
            "RegOpenKeyExW",
        ));
    }

    let watch = RegistryWatch {
        notify_event,
        cancel_event,
        key,
    };
    rearm_notify(&watch)?;

    let worker_flag = flag.clone();
    thread::Builder::new()
        .name("osdns-nrpt-watch".to_string())
        .spawn(move || {
            let watch = watch;
            let mut seen = snapshot_nrpt_rule_states();
            loop {
                if !watch.wait() {
                    break;
                }
                if worker_flag.load(Ordering::Acquire) {
                    break;
                }
                // The change notification cannot identify which subkey or
                // value changed, so fingerprint the relevant rule values
                // (namespaces, servers, options) and diff against the
                // previously seen state: new/missing keys and in-place value
                // mutations all emit resource events.
                let current = snapshot_nrpt_rule_states();
                for (key, removed) in diff_rule_states(&seen, &current) {
                    continue_with(&callback, &key, removed);
                }
                seen = current;
                if rearm_notify(&watch).is_err() {
                    break;
                }
            }
            watch.close();
        })
        .map_err(|e| Error::Platform {
            backend: BackendKind::WindowsIpHelper,
            message: format!("cannot spawn registry watch thread: {e}"),
        })?;

    // SAFETY: the event handles outlive every use of this wrapper: the
    // worker waits on them until SetEvent fires and CloseHandle runs after
    // that, both from this caller thread.
    struct SendEvent(HANDLE);
    unsafe impl Send for SendEvent {}
    impl SendEvent {
        fn cancel(self) {
            // SAFETY: see the SendEvent safety contract above.
            unsafe {
                let _ = SetEvent(self.0);
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
    let wrapped = SendEvent(cancel_event);
    Ok(Box::new(move || {
        flag.store(true, Ordering::Release);
        wrapped.cancel();
    }))
}

fn rearm_notify(watch: &RegistryWatch) -> Result<()> {
    // SAFETY: key is a valid open HKEY and notify_event a valid event handle;
    // re-arming after each fired notification is the documented pattern.
    let result = unsafe {
        RegNotifyChangeKeyValue(
            watch.key,
            true,
            REG_NOTIFY_FILTER(REG_NOTIFY_CHANGE_NAME.0 | REG_NOTIFY_CHANGE_LAST_SET.0),
            Some(watch.notify_event),
            true,
        )
    };
    if result.is_err() {
        return Err(crate::platform::windows::interface::win32_error(
            BackendKind::WindowsIpHelper,
            result,
            "RegNotifyChangeKeyValue",
        ));
    }
    Ok(())
}

fn continue_with(callback: &Arc<dyn Fn(&DnsEvent) + Send + Sync>, key: &str, removed: bool) {
    let Ok(resource) = ResourceId::new(format!("windows:nrpt:{key}")) else {
        return;
    };
    let event = if removed {
        DnsEvent::ResourceRemoved { resource }
    } else {
        DnsEvent::ResourceChanged { resource }
    };
    callback(&event);
}

/// Fingerprints the NRPT-relevant values of one rule key. Any change to
/// namespaces, servers, options, or version produces a different string.
fn rule_fingerprint(key: &windows_registry::Key) -> Option<String> {
    let name = key.get_multi_string("Name").ok()?.join("\u{1}");
    let servers = key.get_string("GenericDNSServers").ok()?;
    let config_options = key.get_u32("ConfigOptions").unwrap_or_default();
    let version = key.get_u32("Version").unwrap_or_default();
    Some(format!(
        "{name}\u{1}{servers}\u{1}{config_options}\u{1}{version}"
    ))
}

/// Snapshots every NRPT rule key with its value fingerprint.
fn snapshot_nrpt_rule_states() -> std::collections::BTreeMap<String, String> {
    use super::nrpt::NRPT_BASE;
    use windows_registry::LOCAL_MACHINE;
    let base = match LOCAL_MACHINE.open(NRPT_BASE) {
        Ok(base) => base,
        Err(_) => return Default::default(),
    };
    let mut out = std::collections::BTreeMap::new();
    let key_names = match base.keys() {
        Ok(keys) => keys,
        Err(_) => return out,
    };
    for key_name in key_names {
        let Some(rule_key) = base.open(&key_name).ok() else {
            continue;
        };
        if let Some(fingerprint) = rule_fingerprint(&rule_key) {
            out.insert(key_name, fingerprint);
        }
    }
    out
}

/// Diffs two rule-state snapshots: `(key, removed)` pairs where `removed`
/// marks a disappearing key and `false` marks a new key or an in-place value
/// change.
fn diff_rule_states(
    previous: &std::collections::BTreeMap<String, String>,
    current: &std::collections::BTreeMap<String, String>,
) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for (key, fingerprint) in current {
        if previous.get(key) != Some(fingerprint) {
            out.push((key.clone(), false));
        }
    }
    for key in previous.keys() {
        if !current.contains_key(key) {
            out.push((key.clone(), true));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn states(entries: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn diff_detects_new_and_removed_keys() {
        let previous = states(&[("rule-a", "v1")]);
        let current = states(&[("rule-b", "v1")]);
        let diff = diff_rule_states(&previous, &current);
        assert!(diff.contains(&("rule-b".to_string(), false)));
        assert!(diff.contains(&("rule-a".to_string(), true)));
    }

    #[test]
    fn diff_detects_in_place_value_mutation() {
        let previous = states(&[("rule-a", "servers=1.1.1.1;names=.corp.example")]);
        let current = states(&[("rule-a", "servers=8.8.8.8;names=.corp.example")]);
        let diff = diff_rule_states(&previous, &current);
        assert_eq!(diff, vec![("rule-a".to_string(), false)]);
    }

    #[test]
    fn diff_ignores_identical_state() {
        let previous = states(&[("rule-a", "v1"), ("rule-b", "v2")]);
        let current = states(&[("rule-a", "v1"), ("rule-b", "v2")]);
        assert!(diff_rule_states(&previous, &current).is_empty());
    }

    #[test]
    fn fingerprint_tracks_namespaces_servers_and_options() {
        let base = windows_registry::CURRENT_USER
            .create("SOFTWARE/osdns-fingerprint-test")
            .unwrap();
        let rule = base.create("rule-x").unwrap();
        rule.set_multi_string("Name", &[".corp.example"]).unwrap();
        rule.set_string("GenericDNSServers", "1.1.1.1").unwrap();
        rule.set_u32("ConfigOptions", 8).unwrap();
        rule.set_u32("Version", 1).unwrap();
        let before = rule_fingerprint(&rule).unwrap();

        rule.set_string("GenericDNSServers", "8.8.8.8").unwrap();
        let after_servers = rule_fingerprint(&rule).unwrap();
        assert_ne!(before, after_servers);

        rule.set_multi_string("Name", &[".other.example"]).unwrap();
        let after_names = rule_fingerprint(&rule).unwrap();
        assert_ne!(after_servers, after_names);

        let _ = base.remove_tree("rule-x");
        let _ = windows_registry::CURRENT_USER.remove_tree("SOFTWARE/osdns-fingerprint-test");
    }
}
