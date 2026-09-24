use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use uuid::Uuid;

use crate::capability::BackendKind;
use crate::error::{Error, Result};
use crate::ownership::ResourceId;
use crate::platform::unix::ResourceMapper;
use crate::watch::{DnsEvent, WatchCallback, WatchHandle};

const EVENT_MASK: WatchMask = WatchMask::CLOSE_WRITE
    .union(WatchMask::CREATE)
    .union(WatchMask::DELETE)
    .union(WatchMask::MOVED_FROM)
    .union(WatchMask::MOVED_TO);

pub(crate) fn watch_directories(
    kind: BackendKind,
    directories: &[PathBuf],
    initial_resources: Vec<ResourceId>,
    to_resource: ResourceMapper,
    callback: WatchCallback,
) -> Result<WatchHandle> {
    if directories.is_empty() {
        return Err(Error::platform(
            kind,
            "cannot create a watcher without a directory",
        ));
    }
    let mut inotify = Inotify::init().map_err(|error| inotify_error(kind, error))?;
    let mut watched: HashMap<WatchDescriptor, PathBuf> = HashMap::new();
    for directory in directories {
        let descriptor = inotify
            .watches()
            .add(directory, EVENT_MASK)
            .map_err(|error| inotify_error(kind, error))?;
        watched.insert(descriptor, directory.clone());
    }

    let wake_dir = std::env::temp_dir().join(format!("osdns-watch-wake-{}", Uuid::new_v4()));
    fs::create_dir_all(&wake_dir)?;
    let wake_wd = inotify
        .watches()
        .add(&wake_dir, WatchMask::CREATE)
        .map_err(|error| inotify_error(kind, error))?;
    watched.insert(wake_wd.clone(), wake_dir.clone());

    let flag = Arc::new(AtomicBool::new(false));
    let watch_flag = flag.clone();
    let thread_wake_dir = wake_dir.clone();
    let watched_dirs = directories.to_vec();
    let worker = thread::Builder::new()
        .name("osdns-inotify-watch".to_string())
        .spawn(move || {
            let _ = watched;
            let mut buffer = [0u8; 4096];
            let seeds: HashSet<ResourceId> = initial_resources.into_iter().collect();
            let mut known = seeds.clone();
            for resource in scan(&watched_dirs, &to_resource).unwrap_or_default() {
                known.insert(resource);
            }
            loop {
                let Ok(events) = inotify.read_events_blocking(&mut buffer) else {
                    break;
                };
                for event in events {
                    if event.mask.contains(EventMask::Q_OVERFLOW) {
                        match scan(&watched_dirs, &to_resource) {
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
                    let Some(name) = event.name else {
                        continue;
                    };
                    let Some(directory) = watched_dirs_for_event(&watched, event.wd) else {
                        continue;
                    };
                    let Some(resource) = to_resource(&directory.join(name)) else {
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
        .map_err(|error| Error::Platform {
            backend: kind,
            message: format!("cannot spawn watch thread: {error}"),
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

fn watched_dirs_for_event(
    watched: &HashMap<WatchDescriptor, PathBuf>,
    descriptor: WatchDescriptor,
) -> Option<PathBuf> {
    watched.get(&descriptor).cloned()
}

fn scan(directories: &[PathBuf], mapper: &ResourceMapper) -> Result<HashSet<ResourceId>> {
    let mut resources = HashSet::new();
    for directory in directories {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            if let Some(resource) = mapper(&entry.path()) {
                resources.insert(resource);
            }
        }
    }
    Ok(resources)
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
