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
    let delivery = Arc::new(Mutex::new(()));
    let handler_delivery = Arc::clone(&delivery);
    let handler_lifetime = crate::watch::WatchWorker(Arc::clone(&flag));
    let mut watcher = notify::recommended_watcher(
        move |event: std::result::Result<notify::Event, notify::Error>| {
            let _lifetime = &handler_lifetime;
            let _delivery = handler_delivery.lock();
            if handler_flag.load(Ordering::Acquire) {
                return;
            }
            match event {
                Ok(event) => {
                    if event.need_rescan()
                        || (event.paths.iter().any(|path| handler_paths.contains(path))
                            && matches!(
                                event.kind,
                                notify::EventKind::Remove(_)
                                    | notify::EventKind::Modify(notify::event::ModifyKind::Name(_))
                            ))
                    {
                        handler_flag.store(true, Ordering::Release);
                        return;
                    }
                    for path in event.paths {
                        if handler_paths.contains(&path) {
                            if path.is_dir() {
                                let resources = match scan_directory(&path, &handler_mapper) {
                                    Ok(resources) => resources,
                                    Err(_) => {
                                        handler_flag.store(true, Ordering::Release);
                                        return;
                                    }
                                };
                                for resource in resources {
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
                    handler_flag.store(true, Ordering::Release);
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
        // notify's kqueue worker is detached; drain its in-flight callback.
        let _delivery = delivery.lock();
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
        resources.extend(scan_directory(path, mapper)?);
    }
    Ok(resources)
}

fn scan_directory(path: &PathBuf, mapper: &ResourceMapper) -> Result<HashSet<ResourceId>> {
    let mut resources = HashSet::new();
    for entry in std::fs::read_dir(path)? {
        if let Some(resource) = mapper(&entry?.path()) {
            resources.insert(resource);
        }
    }
    Ok(resources)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn native_stop_waits_for_an_in_flight_callback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("watched");
        let resource = ResourceId::new("freebsd:resolv-conf").unwrap();
        let mapper: ResourceMapper = Arc::new(move |_| Some(resource.clone()));
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let release_rx = Mutex::new(release_rx);
        let callback: WatchCallback = Arc::new(move |_| {
            let _ = entered_tx.try_send(());
            let _ = release_rx.lock().recv();
        });
        let handle = watch_directories(
            BackendKind::ResolvConfFile,
            &[directory.path().to_path_buf()],
            Vec::new(),
            mapper,
            callback,
        )
        .unwrap();
        std::fs::write(path, b"changed").unwrap();
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (stopped_tx, stopped_rx) = mpsc::sync_channel(1);
        let stop = std::thread::spawn(move || {
            handle.stop();
            stopped_tx.send(()).unwrap();
        });
        assert!(stopped_rx.recv_timeout(Duration::from_millis(50)).is_err());
        release_tx.send(()).unwrap();
        stopped_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        stop.join().unwrap();
    }
}
