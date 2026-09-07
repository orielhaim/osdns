use std::collections::{HashMap, HashSet};
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
    initial_resources: Vec<ResourceId>,
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
    let watched_dir = dir.to_path_buf();
    let worker = thread::Builder::new()
        .name("osdns-inotify-watch".to_string())
        .spawn(move || {
            let _ = dirs;
            let mut buffer = [0u8; 4096];
            let seeds: HashSet<ResourceId> = initial_resources.into_iter().collect();
            let mut known = seeds.clone();
            if let Ok(entries) = fs::read_dir(&watched_dir) {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str()
                        && let Some(resource) = to_resource(name)
                    {
                        known.insert(resource);
                    }
                }
            }
            loop {
                let Ok(events) = inotify.read_events_blocking(&mut buffer) else {
                    break;
                };
                for event in events {
                    if event.mask.contains(EventMask::Q_OVERFLOW) {
                        let current = fs::read_dir(&watched_dir).and_then(|entries| {
                            let mut current = HashSet::new();
                            for entry in entries {
                                let entry = entry?;
                                if let Some(name) = entry.file_name().to_str()
                                    && let Some(resource) = to_resource(name)
                                {
                                    current.insert(resource);
                                }
                            }
                            Ok(current)
                        });
                        match current {
                            Ok(current) => {
                                for event in resync_events(&known, &current) {
                                    callback(&event);
                                }
                                known = seeds.union(&current).cloned().collect();
                            }
                            Err(_) => {
                                for resource in &known {
                                    callback(&DnsEvent::ResourceChanged {
                                        resource: resource.clone(),
                                    });
                                }
                            }
                        }
                        continue;
                    }
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
                    known.insert(resource.clone());
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
        let _ = worker.join();
        let _ = fs::remove_dir_all(&cancel_wake);
    }))
}

fn resync_events(known: &HashSet<ResourceId>, current: &HashSet<ResourceId>) -> Vec<DnsEvent> {
    known
        .union(current)
        .cloned()
        .map(|resource| {
            if current.contains(&resource) {
                DnsEvent::ResourceChanged { resource }
            } else {
                DnsEvent::ResourceRemoved { resource }
            }
        })
        .collect()
}

fn inotify_error(kind: BackendKind, error: std::io::Error) -> Error {
    Error::Platform {
        backend: kind,
        message: format!("inotify error: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_resync_reports_current_and_disappeared_resources() {
        let present = ResourceId::new("linux:test:present").unwrap();
        let removed = ResourceId::new("linux:test:removed").unwrap();
        let known = HashSet::from([present.clone(), removed.clone()]);
        let current = HashSet::from([present.clone()]);
        let events = resync_events(&known, &current);
        assert!(events.contains(&DnsEvent::ResourceChanged { resource: present }));
        assert!(events.contains(&DnsEvent::ResourceRemoved { resource: removed }));
    }
}
