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
                .and_then(|id| super::MacosBackend::service_resource(id).ok())
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

/// Whether this path is the resolver directory itself being created. When it
/// appears, the watcher must be armed on it so its children are observed.
fn is_resolver_dir_creation(path: &std::path::Path, created: bool) -> bool {
    created && path.to_string_lossy() == RESOLVER_DIR
}

#[cfg(target_os = "macos")]
fn arm_resolver_dir_watcher(
    watcher: &mut notify::RecommendedWatcher,
) -> std::result::Result<(), notify::Error> {
    use notify::Watcher;
    watcher.watch(
        std::path::Path::new(RESOLVER_DIR),
        notify::RecursiveMode::NonRecursive,
    )
}

pub(crate) fn start_resolver_watch(
    flag: Arc<std::sync::atomic::AtomicBool>,
    callback: WatchCallback,
) -> Result<Box<dyn FnOnce() + Send>> {
    use notify::Watcher;

    let (tx, rx) = mpsc::channel::<DnsEvent>();
    // The watcher lives behind a shared slot: the event handler needs it to
    // arm watching of /etc/resolver when that directory is created late, and
    // the cancel closure drops it to stop the watcher.
    let watcher_slot: Arc<Mutex<Option<notify::RecommendedWatcher>>> = Arc::new(Mutex::new(None));
    let handler_slot = Arc::clone(&watcher_slot);
    let handler_flag = flag.clone();
    let mut watcher = notify::recommended_watcher(
        move |event: std::result::Result<notify::Event, notify::Error>| {
            if handler_flag.load(Ordering::Acquire) {
                return;
            }
            let Ok(event) = event else { return };
            let created = matches!(event.kind, notify::event::EventKind::Create(_));
            for path in event.paths {
                // Late creation of /etc/resolver: arm the watcher on it so
                // its children are observed from now on. Disappearance is
                // handled by re-arming here on the next creation event.
                if is_resolver_dir_creation(&path, created) && path.is_dir() {
                    let arm_result = match handler_slot
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .as_mut()
                    {
                        Some(watcher) => arm_resolver_dir_watcher(watcher),
                        None => continue,
                    };
                    if arm_result.is_err() {
                        continue;
                    }
                }
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

    // Always watch /etc: it observes creation of /etc/resolver itself (so the
    // watcher can be armed on it when the directory appears late), and it
    // doubles as the resolver-children watch until /etc/resolver exists.
    // When /etc/resolver exists at startup it is watched directly as well; if
    // it later disappears and is recreated, the /etc create event re-arms it.
    watcher
        .watch(
            std::path::Path::new("/etc"),
            notify::RecursiveMode::NonRecursive,
        )
        .map_err(|e| Error::Platform {
            backend: crate::capability::BackendKind::MacosSystemConfiguration,
            message: format!("cannot watch /etc for resolver changes: {e}"),
        })?;
    if std::path::Path::new(RESOLVER_DIR).is_dir() {
        let _ = watcher.watch(
            std::path::Path::new(RESOLVER_DIR),
            notify::RecursiveMode::NonRecursive,
        );
    }
    *watcher_slot
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(watcher);

    Ok(Box::new(move || {
        flag.store(true, Ordering::Release);
        drop(watcher_slot);
    }))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_paths_map_to_resources() {
        let path = std::path::Path::new("/etc/resolver/corp.example");
        let resource = resolver_resource_from_path(path).unwrap();
        assert_eq!(resource.as_str(), "macos:resolver:corp.example");
    }

    #[test]
    fn non_resolver_paths_do_not_map() {
        assert!(resolver_resource_from_path(std::path::Path::new("/etc/hosts")).is_none());
        assert!(
            resolver_resource_from_path(std::path::Path::new("/etc/resolver/.hidden")).is_none()
        );
    }

    #[test]
    fn resolver_dir_creation_is_detected() {
        let path = std::path::Path::new("/etc/resolver");
        assert!(is_resolver_dir_creation(path, true));
        assert!(!is_resolver_dir_creation(path, false));
        assert!(!is_resolver_dir_creation(
            std::path::Path::new("/etc/hosts"),
            true
        ));
    }
}
