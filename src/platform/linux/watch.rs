use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use rustix::event::{PollFd, PollFlags, poll};
use rustix::pipe::{PipeFlags, pipe_with};

use crate::capability::BackendKind;
use crate::error::{Error, Result};
use crate::ownership::ResourceId;
use crate::platform::unix::ResourceMapper;
use crate::watch::{DnsEvent, WatchCallback, WatchHandle};

const EVENT_MASK: WatchMask = WatchMask::CLOSE_WRITE
    .union(WatchMask::CREATE)
    .union(WatchMask::DELETE)
    .union(WatchMask::MOVED_FROM)
    .union(WatchMask::MOVED_TO)
    .union(WatchMask::DELETE_SELF)
    .union(WatchMask::MOVE_SELF);

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

    let (cancel_read, cancel_write) =
        pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).map_err(std::io::Error::from)?;

    let flag = Arc::new(AtomicBool::new(false));
    let watch_flag = flag.clone();
    let watched_dirs = directories.to_vec();
    let initial_scan = scan(&watched_dirs, &to_resource)?;
    let worker = thread::Builder::new()
        .name("osdns-inotify-watch".to_string())
        .spawn(move || {
            let _lifetime = crate::watch::WatchWorker(Arc::clone(&watch_flag));
            let _ = watched;
            let mut buffer = [0u8; 4096];
            let seeds: HashSet<ResourceId> = initial_resources.into_iter().collect();
            let mut known = seeds.clone();
            for resource in initial_scan {
                known.insert(resource);
            }
            loop {
                let mut fds = [
                    PollFd::new(&inotify, PollFlags::IN),
                    PollFd::new(&cancel_read, PollFlags::IN),
                ];
                if let Err(error) = poll(&mut fds, None) {
                    if error == rustix::io::Errno::INTR {
                        continue;
                    }
                    break;
                }
                if !fds[1].revents().is_empty() || watch_flag.load(Ordering::Acquire) {
                    return;
                }
                if fds[0]
                    .revents()
                    .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
                {
                    break;
                }
                let Ok(events) = inotify.read_events(&mut buffer) else {
                    break;
                };
                for event in events {
                    if event.mask.intersects(
                        EventMask::IGNORED | EventMask::DELETE_SELF | EventMask::MOVE_SELF,
                    ) {
                        return;
                    }
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
                    if removed {
                        known.remove(&resource);
                    } else {
                        known.insert(resource.clone());
                    }
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

    Ok(WatchHandle::new(flag, move || {
        let _ = rustix::io::write(&cancel_write, b"x");
        let _ = worker.join();
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
