//! Native change notifications: `NotifyIpInterfaceChange` for interface
//! events and `RegNotifyChangeKeyValue` for NRPT registry changes.
//!
//! Callbacks only enqueue; heavy logic never runs inside them, and
//! notifications are never cancelled from inside their own callback.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Sender;
use std::thread;

use windows_registry::Key;

use crate::capability::BackendKind;
use crate::error::{Error, Result};
use crate::ownership::ResourceId;
use crate::platform::windows::error::{check_status, map_error};
use crate::platform::windows::ffi::{
    self, ADDRESS_FAMILY, AF_UNSPEC, BOOL, GUID, HANDLE, INFINITE, MIB_IPINTERFACE_ROW,
    MIB_NOTIFICATION_TYPE, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME, WAIT_OBJECT_0,
    open_hklm,
};
use crate::watch::DnsEvent;

const NRPT_WATCH_KEY: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";

fn resource_from_row(row: &MIB_IPINTERFACE_ROW) -> Option<ResourceId> {
    let mut guid = GUID::default();
    // SAFETY: both pointers reference valid caller-owned memory for the call.
    let status = unsafe { ffi::ConvertInterfaceLuidToGuid(&row.InterfaceLuid, &mut guid) };
    if status != 0 {
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
    // SAFETY: context came from Box::into_raw and lives until cancel completes
    // on a different thread.
    let context = unsafe { &*(caller_context as *const IpNotifyContext) };
    // SAFETY: the OS passes a valid row for the duration of the callback.
    let row = unsafe { &*row };
    if let Some(resource) = resource_from_row(row) {
        let _ = context.sender.send(resource);
    }
}

struct OwnedHandle(HANDLE);

// SAFETY: kernel HANDLEs may be moved between threads; exclusive ownership is
// maintained by this wrapper.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn from_create_event() -> Result<Self> {
        // SAFETY: unnamed auto-reset event; NULL attributes / name.
        let handle = unsafe { ffi::CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if handle.is_null() {
            return Err(Error::Platform {
                backend: BackendKind::WindowsIpHelper,
                message: "CreateEventW returned NULL".to_string(),
            });
        }
        Ok(Self(handle))
    }

    fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: we own the handle and close it exactly once.
            unsafe {
                let _ = ffi::CloseHandle(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

pub(crate) fn start_ip_interface_watch(
    flag: Arc<std::sync::atomic::AtomicBool>,
    callback: Arc<dyn Fn(&DnsEvent) + Send + Sync>,
) -> Result<Box<dyn FnOnce() + Send>> {
    let (tx, rx) = std::sync::mpsc::channel::<ResourceId>();
    let context = Box::into_raw(Box::new(IpNotifyContext { sender: tx }));

    let mut notification: HANDLE = std::ptr::null_mut();
    let status = unsafe {
        ffi::NotifyIpInterfaceChange(
            AF_UNSPEC as ADDRESS_FAMILY,
            Some(ip_interface_callback),
            context as *const core::ffi::c_void,
            false,
            &mut notification,
        )
    };
    if let Err(error) = check_status(status, "NotifyIpInterfaceChange") {
        // SAFETY: registration failed, so reclaim the context before the OS owns it.
        unsafe { drop(Box::from_raw(context)) };
        return Err(error);
    }

    let worker_flag = flag.clone();
    let worker = match thread::Builder::new()
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
        }) {
        Ok(worker) => worker,
        Err(error) => {
            unsafe {
                let _ = ffi::CancelMibChangeNotify2(notification);
                drop(Box::from_raw(context));
            }
            return Err(Error::Platform {
                backend: BackendKind::WindowsIpHelper,
                message: format!("cannot spawn notification worker: {error}"),
            });
        }
    };

    // SAFETY: notification handle is valid until CancelMibChangeNotify2; cancel
    // runs once on the caller thread, never inside the callback.
    struct SendHandle(HANDLE);
    unsafe impl Send for SendHandle {}
    impl SendHandle {
        fn cancel(self) {
            unsafe {
                let _ = ffi::CancelMibChangeNotify2(self.0);
            }
        }
    }
    struct SendContext(*mut IpNotifyContext);
    unsafe impl Send for SendContext {}
    impl SendContext {
        fn release(self) {
            unsafe { drop(Box::from_raw(self.0)) };
        }
    }
    let wrapped = SendHandle(notification);
    let context = SendContext(context);
    Ok(Box::new(move || {
        flag.store(true, Ordering::Release);
        wrapped.cancel();
        context.release();
        let _ = worker.join();
    }))
}

struct RegistryWatch {
    notify_event: OwnedHandle,
    cancel_event: HANDLE,
    key: Key,
}

// SAFETY: the worker takes exclusive ownership of the event handles and Key;
// cancel only signals cancel_event after registration, and Key is Send.
unsafe impl Send for RegistryWatch {}

impl RegistryWatch {
    fn wait(&self) -> bool {
        let handles = [self.notify_event.as_raw(), self.cancel_event];
        // SAFETY: both handles are valid event handles owned by this watcher.
        let waited = unsafe { ffi::WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
        waited == WAIT_OBJECT_0 as u32
    }
}

pub(crate) fn start_nrpt_registry_watch(
    flag: Arc<std::sync::atomic::AtomicBool>,
    callback: Arc<dyn Fn(&DnsEvent) + Send + Sync>,
) -> Result<Box<dyn FnOnce() + Send>> {
    let notify_event = OwnedHandle::from_create_event()?;
    let cancel_event = OwnedHandle::from_create_event()?;

    let key = match open_hklm(NRPT_WATCH_KEY, false) {
        Ok(key) => key,
        Err(error) => {
            return Err(map_error(error, "RegOpenKey (NRPT watch)"));
        }
    };

    let cancel_raw = cancel_event.as_raw();
    let watch = RegistryWatch {
        notify_event,
        cancel_event: cancel_raw,
        key,
    };
    // Keep cancel_event alive via OwnedHandle moved into the cancel closure.
    // The worker owns notify_event + Key; cancel_event is shared by raw handle
    // until the worker exits after SetEvent.
    let cancel_owner = cancel_event;

    if let Err(error) = rearm_notify(&watch) {
        drop(watch);
        drop(cancel_owner);
        return Err(error);
    }

    let worker_flag = flag.clone();
    let worker = match thread::Builder::new()
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
                let current = snapshot_nrpt_rule_states();
                for (key, removed) in diff_rule_states(&seen, &current) {
                    continue_with(&callback, &key, removed);
                }
                seen = current;
                if rearm_notify(&watch).is_err() {
                    break;
                }
            }
            // Key + notify_event drop here after the wait loop exits.
        }) {
        Ok(worker) => worker,
        Err(error) => {
            // `watch` was moved into the closure and dropped when spawn failed.
            drop(cancel_owner);
            return Err(Error::Platform {
                backend: BackendKind::WindowsIpHelper,
                message: format!("cannot spawn registry watch thread: {error}"),
            });
        }
    };

    struct SendEvent(HANDLE);
    unsafe impl Send for SendEvent {}
    impl SendEvent {
        fn signal(self) {
            // SAFETY: cancel event remains open until the worker joins.
            unsafe {
                let _ = ffi::SetEvent(self.0);
            }
        }
    }
    let signal = SendEvent(cancel_raw);
    Ok(Box::new(move || {
        flag.store(true, Ordering::Release);
        signal.signal();
        let _ = worker.join();
        drop(cancel_owner);
    }))
}

fn rearm_notify(watch: &RegistryWatch) -> Result<()> {
    // SAFETY: key.as_raw() is valid for the Key's lifetime; event is owned.
    let status = unsafe {
        ffi::RegNotifyChangeKeyValue(
            watch.key.as_raw(),
            1 as BOOL,
            (REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET) as u32,
            watch.notify_event.as_raw(),
            1 as BOOL,
        )
    };
    check_status(status, "RegNotifyChangeKeyValue")
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

fn rule_fingerprint(key: &Key) -> Option<String> {
    let name = key.get_multi_string("Name").ok()?.join("\u{1}");
    let servers = key.get_string("GenericDNSServers").ok()?;
    let config_options = key.get_u32("ConfigOptions").ok()?;
    let version = key.get_u32("Version").ok()?;
    Some(format!(
        "{name}\u{1}{servers}\u{1}{config_options}\u{1}{version}"
    ))
}

fn snapshot_nrpt_rule_states() -> std::collections::BTreeMap<String, String> {
    use super::nrpt::NRPT_BASE;
    let base = match open_hklm(NRPT_BASE, false) {
        Ok(base) => base,
        Err(_) => return Default::default(),
    };
    let mut out = std::collections::BTreeMap::new();
    let key_names = match base.keys() {
        Ok(keys) => keys,
        Err(_) => return out,
    };
    for key_name in key_names {
        let Ok(rule_key) = base.open(&key_name) else {
            continue;
        };
        if let Some(fingerprint) = rule_fingerprint(&rule_key) {
            out.insert(key_name, fingerprint);
        }
    }
    out
}

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

    #[test]
    fn repeated_ip_watch_start_stop() {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback: Arc<dyn Fn(&DnsEvent) + Send + Sync> = Arc::new(|_| {});
        for _ in 0..8 {
            flag.store(false, Ordering::Release);
            let cancel = start_ip_interface_watch(flag.clone(), callback.clone()).unwrap();
            cancel();
        }
    }

    #[test]
    fn no_callback_after_ip_watch_stop() {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits_cb = hits.clone();
        let callback: Arc<dyn Fn(&DnsEvent) + Send + Sync> = Arc::new(move |_| {
            hits_cb.fetch_add(1, Ordering::SeqCst);
        });
        let cancel = start_ip_interface_watch(flag, callback).unwrap();
        cancel();
        let after = hits.load(Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(hits.load(Ordering::SeqCst), after);
    }

    #[test]
    fn repeated_nrpt_watch_start_stop() {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback: Arc<dyn Fn(&DnsEvent) + Send + Sync> = Arc::new(|_| {});
        for _ in 0..8 {
            flag.store(false, Ordering::Release);
            let cancel = start_nrpt_registry_watch(flag.clone(), callback.clone()).unwrap();
            cancel();
        }
    }
}
