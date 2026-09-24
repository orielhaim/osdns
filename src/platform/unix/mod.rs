pub(crate) mod detect;
pub(crate) mod direct;
pub(crate) mod openresolv;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::capability::BackendKind;
use crate::error::Result;
use crate::ownership::ResourceId;
use crate::watch::{WatchCallback, WatchHandle};

pub(crate) type ResourceMapper = Arc<dyn Fn(&Path) -> Option<ResourceId> + Send + Sync>;
pub(crate) type WatchDirectory = fn(
    BackendKind,
    &[PathBuf],
    Vec<ResourceId>,
    ResourceMapper,
    WatchCallback,
) -> Result<WatchHandle>;
