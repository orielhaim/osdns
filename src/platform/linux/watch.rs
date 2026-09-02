use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use uuid::Uuid;

use crate::capability::BackendKind;
use crate::error::{Error, Result};
use crate::ownership::ResourceId;
use crate::watch::{DnsEvent, WatchCallback, WatchHandle};

const EVENT_MASK: WatchMask = WatchMask::CLOSE_WRITE
    .union(WatchMask::CREATE)
    .union(WatchMask::DELETE)
    .union(WatchMask::MOVED_FROM)
    .union(WatchMask::MOVED_TO);

/// Watches `dir` with inotify and maps file-name events to resources.
///
/// The thread blocks on the inotify descriptor (zero polling) and exits when
/// the returned handle is stopped or dropped; stopping works by arming a
/// cancel flag and touching a private wake directory watched by the same
/// inotify instance.
pub(crate) fn watch_directory(
    kind: BackendKind,
    dir: &Path,
    to_resource: impl Fn(&str) -> Option<ResourceId> + Send + 'static,
    callback: WatchCallback,
) -> Result<WatchHandle> {
    let mut inotify = Inotify::init().map_err(|e| inotify_error(kind, e))?;
    let mut dirs: HashMap<WatchDescriptor, PathBuf> = HashMap::new();
    let main_wd = inotify
        .watches()
        .add(dir, EVENT_MASK)
        .map_err(|e| inotify_error(kind, e))?;
    dirs.insert(main_wd, dir.to_path_buf());

    let wake_dir = std::env::temp_dir().join(format!("osdns-watch-wake-{}", Uuid::new_v4()));
    fs::create_dir_all(&wake_dir)?;
    let wake_wd = inotify
        .watches()
        .add(&wake_dir, WatchMask::CREATE)
        .map_err(|e| inotify_error(kind, e))?;
    dirs.insert(wake_wd.clone(), wake_dir.clone());

    let flag = Arc::new(AtomicBool::new(false));
    let watch_flag = flag.clone();
    let thread_wake_dir = wake_dir.clone();
    thread::Builder::new()
        .name("osdns-inotify-watch".to_string())
        .spawn(move || {
            let _ = dirs;
            let mut buffer = [0u8; 4096];
            loop {
                let Ok(events) = inotify.read_events_blocking(&mut buffer) else {
                    break;
                };
                for event in events {
                    if event.wd == wake_wd {
                        if watch_flag.load(Ordering::Acquire) {
                            return;
                        }
                        if let Some(name) = event.name {
                            let _ = fs::remove_file(thread_wake_dir.join(name));
                        }
                        continue;
                    }
                    let Some(name) = event.name else { continue };
                    let name = name.to_string_lossy().to_string();
                    let Some(resource) = to_resource(&name) else {
                        continue;
                    };
                    let removed = event
                        .mask
                        .intersects(EventMask::DELETE | EventMask::MOVED_FROM);
                    let event = if removed {
                        DnsEvent::ResourceRemoved { resource }
                    } else {
                        DnsEvent::ResourceChanged { resource }
                    };
                    callback(&event);
                }
            }
        })
        .map_err(|e| Error::Platform {
            backend: kind,
            message: format!("cannot spawn watch thread: {e}"),
        })?;

    let cancel_flag = flag.clone();
    let cancel_wake = wake_dir.clone();
    let wake_name = format!("wake-{}", Uuid::new_v4());
    Ok(WatchHandle::new(flag, move || {
        cancel_flag.store(true, Ordering::Release);
        let _ = fs::write(cancel_wake.join(wake_name), b"");
        let _ = fs::remove_dir_all(&cancel_wake);
    }))
}

fn inotify_error(kind: BackendKind, error: std::io::Error) -> Error {
    Error::Platform {
        backend: kind,
        message: format!("inotify error: {error}"),
    }
}
