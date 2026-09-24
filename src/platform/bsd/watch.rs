use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use notify::Watcher;
use parking_lot::Mutex;

use crate::capability::BackendKind;
use crate::error::{Error, Result};
use crate::ownership::ResourceId;
use crate::platform::unix::ResourceMapper;
use crate::watch::{DnsEvent, WatchCallback, WatchHandle};

pub(crate) fn watch_directories(
    kind: BackendKind,
    paths: &[PathBuf],
    initial_resources: Vec<ResourceId>,
    mapper: ResourceMapper,
    callback: WatchCallback,
) -> Result<WatchHandle> {
    if paths.is_empty() {
        return Err(Error::platform(
            kind,
            "cannot create a watcher without a path",
        ));
    }
    let mut canonical = Vec::new();
    for path in paths {
        match path.canonicalize() {
            Ok(path) => canonical.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if canonical.is_empty() {
        return Err(Error::platform(
            kind,
            "cannot create a watcher without an existing path",
        ));
    }
    let known = Arc::new(Mutex::new(
        initial_resources.iter().cloned().collect::<HashSet<_>>(),
    ));
    for resource in scan(&canonical, &mapper)? {
        known.lock().insert(resource);
    }
    let flag = Arc::new(AtomicBool::new(false));
    let handler_flag = flag.clone();
    let handler_known = known.clone();
    let handler_mapper = mapper.clone();
    let handler_paths = canonical.clone();
    let handler_callback = callback;
    let mut watcher = notify::recommended_watcher(
        move |event: std::result::Result<notify::Event, notify::Error>| {
            if handler_flag.load(Ordering::Acquire) {
                return;
            }
            match event {
                Ok(event) => {
                    for path in event.paths {
                        if handler_paths.contains(&path) {
                            if path.is_dir() {
                                for resource in scan_directory(&path, &handler_mapper) {
                                    handler_known.lock().insert(resource.clone());
                                    handler_callback(&DnsEvent::ResourceChanged { resource });
                                }
                            } else if let Some(resource) = handler_mapper(&path) {
                                handler_known.lock().insert(resource.clone());
                                let event =
                                    if matches!(event.kind, notify::event::EventKind::Remove(_)) {
                                        DnsEvent::ResourceRemoved { resource }
                                    } else {
                                        DnsEvent::ResourceChanged { resource }
                                    };
                                handler_callback(&event);
                            }
                            continue;
                        }
                        let Some(parent) = path.parent() else {
                            continue;
                        };
                        if !handler_paths
                            .iter()
                            .any(|watched| watched == parent && watched.is_dir())
                        {
                            continue;
                        }
                        let Some(resource) = handler_mapper(&path) else {
                            continue;
                        };
                        handler_known.lock().insert(resource.clone());
                        let event = if matches!(event.kind, notify::event::EventKind::Remove(_)) {
                            DnsEvent::ResourceRemoved { resource }
                        } else {
                            DnsEvent::ResourceChanged { resource }
                        };
                        handler_callback(&event);
                    }
                }
                Err(_) => {
                    for resource in handler_known.lock().iter() {
                        handler_callback(&DnsEvent::ResourceChanged {
                            resource: resource.clone(),
                        });
                    }
                }
            }
        },
    )
    .map_err(|error| {
        Error::platform(kind, format_args!("cannot create notify watcher: {error}"))
    })?;
    for path in &canonical {
        watcher
            .watch(path, notify::RecursiveMode::NonRecursive)
            .map_err(|error| {
                Error::platform(
                    kind,
                    format_args!("cannot watch {}: {error}", path.display()),
                )
            })?;
    }
    Ok(WatchHandle::new(flag, move || {
        drop(watcher);
    }))
}

fn scan(paths: &[PathBuf], mapper: &ResourceMapper) -> Result<HashSet<ResourceId>> {
    let mut resources = HashSet::new();
    for path in paths {
        if path.is_file() {
            if let Some(resource) = mapper(path) {
                resources.insert(resource);
            }
            continue;
        }
        resources.extend(scan_directory(path, mapper));
    }
    Ok(resources)
}

fn scan_directory(path: &PathBuf, mapper: &ResourceMapper) -> HashSet<ResourceId> {
    let mut resources = HashSet::new();
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => return resources,
    };
    for entry in entries.flatten() {
        if let Some(resource) = mapper(&entry.path()) {
            resources.insert(resource);
        }
    }
    resources
}
