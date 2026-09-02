//! macOS change watchers.
//!
//! `SCDynamicStore` notifications observe the runtime network state on a
//! dedicated run-loop thread; FSEvents (via `notify`) observe
//! `/etc/resolver` so that external resolver-file changes participate in
//! reconciliation. Events are mapped to resources and forwarded through the
//! manager's suppression and coalescing filter; run loops and watchers are
//! stopped from the cancel closures on another thread, never from inside a
//! callback.

use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use system_configuration::core_foundation::array::CFArray;
use system_configuration::core_foundation::runloop::{CFRunLoop, kCFRunLoopCommonModes};
use system_configuration::core_foundation::string::CFString;
use system_configuration::dynamic_store::{
    SCDynamicStore, SCDynamicStoreBuilder, SCDynamicStoreCallBackContext,
};

use crate::error::{Error, Result};
use crate::ownership::ResourceId;
use crate::watch::{DnsEvent, WatchCallback};

struct WatchState {
    sender: mpsc::Sender<ResourceId>,
}

fn sc_callout(_store: SCDynamicStore, changed_keys: CFArray<CFString>, info: &mut WatchState) {
    for key in changed_keys.iter() {
        let key = key.to_string();
        let resource = if let Some(rest) = key.strip_prefix("State:/Network/Service/") {
            rest.strip_suffix("/DNS")
                .and_then(|id| ResourceId::new(format!("macos:service:{id}")).ok())
        } else if key == "State:/Network/Global/IPv4" {
            ResourceId::new("macos:global").ok()
        } else {
            None
        };
        if let Some(resource) = resource {
            let _ = info.sender.send(resource);
        }
    }
}

// SAFETY: the run loop handle is only used for CFRunLoopStop, which is
// documented as thread-safe, and is stopped exactly once from the cancel
// closure after the watch thread has published it.
struct RunLoopHandle(CFRunLoop);
unsafe impl Send for RunLoopHandle {}

pub(crate) fn start_store_watch(
    flag: Arc<std::sync::atomic::AtomicBool>,
    callback: WatchCallback,
) -> Result<Box<dyn FnOnce() + Send>> {
    let (tx, rx) = mpsc::channel::<ResourceId>();
    let shared: Arc<Mutex<Option<RunLoopHandle>>> = Arc::new(Mutex::new(None));
    let (notify_ready, ready) = mpsc::channel::<()>();

    let worker_flag = flag.clone();
    thread::Builder::new()
        .name("osdns-sc-worker".to_string())
        .spawn(move || {
            for resource in rx {
                if worker_flag.load(Ordering::Acquire) {
                    break;
                }
                callback(&DnsEvent::ResourceChanged { resource });
            }
        })
        .map_err(|e| Error::Platform {
            backend: crate::capability::BackendKind::MacosSystemConfiguration,
            message: format!("cannot spawn SC worker thread: {e}"),
        })?;

    let thread_flag = flag.clone();
    let shared_for_thread = Arc::clone(&shared);
    thread::Builder::new()
        .name("osdns-sc-watch".to_string())
        .spawn(move || {
            let state = WatchState { sender: tx };
            let context = SCDynamicStoreCallBackContext {
                callout: sc_callout,
                info: state,
            };
            let Some(store) = SCDynamicStoreBuilder::new("osdns-watch")
                .callback_context(context)
                .build()
            else {
                return;
            };
            let patterns = CFArray::from_CFTypes(&[
                CFString::new("State:/Network/Service/.*[/]DNS"),
                CFString::new("State:/Network/Global/IPv4"),
            ]);
            let keys: CFArray<CFString> = CFArray::from_CFTypes(&[]);
            if !store.set_notification_keys(&keys, &patterns) {
                return;
            }
            let Some(source) = store.create_run_loop_source() else {
                return;
            };
            let run_loop = CFRunLoop::get_current();
            // SAFETY: kCFRunLoopCommonModes is a valid mode for the current
            // run loop.
            run_loop.add_source(&source, unsafe { kCFRunLoopCommonModes });
            *shared_for_thread
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(RunLoopHandle(run_loop));
            let _ = notify_ready.send(());
            if thread_flag.load(Ordering::Acquire) {
                return;
            }
            CFRunLoop::run_current();
        })
        .map_err(|e| Error::Platform {
            backend: crate::capability::BackendKind::MacosSystemConfiguration,
            message: format!("cannot spawn SC watch thread: {e}"),
        })?;

    let cancel_shared = Arc::clone(&shared);
    Ok(Box::new(move || {
        flag.store(true, Ordering::Release);
        let _ = ready.recv_timeout(std::time::Duration::from_secs(2));
        let handle = cancel_shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(handle) = handle {
            handle.0.stop();
        }
    }))
}

const RESOLVER_DIR: &str = "/etc/resolver";

/// Maps an FSEvents path to a scoped resolver resource. Only direct children
/// of `/etc/resolver` map; the file name is the routing domain.
fn resolver_resource_from_path(path: &std::path::Path) -> Option<ResourceId> {
    let parent = path.parent()?.to_string_lossy().to_string();
    if parent != RESOLVER_DIR {
        return None;
    }
    let domain = path.file_name()?.to_string_lossy().to_string();
    if domain.is_empty() || domain.starts_with('.') {
        return None;
    }
    ResourceId::new(format!("macos:resolver:{domain}")).ok()
}

pub(crate) fn start_resolver_watch(
    flag: Arc<std::sync::atomic::AtomicBool>,
    callback: WatchCallback,
) -> Result<Box<dyn FnOnce() + Send>> {
    use notify::Watcher;

    let (tx, rx) = mpsc::channel::<DnsEvent>();
    let watcher = notify::recommended_watcher(
        move |event: std::result::Result<notify::Event, notify::Error>| {
            let Ok(event) = event else { return };
            for path in event.paths {
                let Some(resource) = resolver_resource_from_path(&path) else {
                    continue;
                };
                let removed = matches!(event.kind, notify::event::EventKind::Remove(_));
                let event = if removed {
                    DnsEvent::ResourceRemoved { resource }
                } else {
                    DnsEvent::ResourceChanged { resource }
                };
                let _ = tx.send(event);
            }
        },
    )
    .map_err(|e| Error::Platform {
        backend: crate::capability::BackendKind::MacosSystemConfiguration,
        message: format!("cannot create resolver file watcher: {e}"),
    })?;

    let worker_flag = flag.clone();
    thread::Builder::new()
        .name("osdns-resolver-worker".to_string())
        .spawn(move || {
            for event in rx {
                if worker_flag.load(Ordering::Acquire) {
                    break;
                }
                callback(&event);
            }
        })
        .map_err(|e| Error::Platform {
            backend: crate::capability::BackendKind::MacosSystemConfiguration,
            message: format!("cannot spawn resolver worker thread: {e}"),
        })?;

    // Watching /etc/resolver fails when the directory does not exist yet; in
    // that case watch /etc and filter paths to resolver children, so early
    // creation of the directory itself is observed too.
    let watch_path = std::path::Path::new(RESOLVER_DIR);
    let mut watcher = watcher;
    match watcher.watch(watch_path, notify::RecursiveMode::NonRecursive) {
        Ok(()) => {}
        Err(_) => {
            watcher
                .watch(
                    std::path::Path::new("/etc"),
                    notify::RecursiveMode::NonRecursive,
                )
                .map_err(|e| Error::Platform {
                    backend: crate::capability::BackendKind::MacosSystemConfiguration,
                    message: format!("cannot watch /etc for resolver changes: {e}"),
                })?;
        }
    }

    Ok(Box::new(move || {
        flag.store(true, Ordering::Release);
        drop(watcher);
    }))
}
