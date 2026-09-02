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
            loop {
                if !watch.wait() {
                    break;
                }
                if worker_flag.load(Ordering::Acquire) {
                    break;
                }
                if let Ok(resource) = ResourceId::new("windows:nrpt:rules") {
                    callback(&DnsEvent::ResourceChanged { resource });
                }
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
