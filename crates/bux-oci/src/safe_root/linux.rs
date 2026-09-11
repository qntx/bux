//! Linux: pathrs (`openat2(RESOLVE_IN_ROOT)`), walk when the path does not exist.

use super::path;
use crate::{OciError, Result};
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};

pub(super) struct Backend {
    root: pathrs::Root,
    root_path: PathBuf,
}

impl Backend {
    pub(super) fn open(root: &Path) -> Result<Self> {
        let inner = pathrs::Root::open(root)
            .map_err(|e| OciError::Extract(format!("pathrs open {}: {e}", root.display())))?;
        Ok(Self {
            root: inner,
            root_path: root.to_path_buf(),
        })
    }

    pub(super) fn resolve(&self, rel: &Path) -> Result<PathBuf> {
        match self.root.resolve(rel) {
            Ok(handle) => {
                let fd = handle.as_fd();
                let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
                std::fs::read_link(&proc_path).map_err(|e| {
                    OciError::Extract(format!("readlink /proc/self/fd for {}: {e}", rel.display()))
                })
            }
            Err(e)
                if e.kind() == pathrs::error::ErrorKind::OsError(Some(libc::ENOENT))
                    || e.kind() == pathrs::error::ErrorKind::OsError(Some(libc::ENOTDIR)) =>
            {
                path::resolve_walk(&self.root_path, rel)
            }
            Err(e) if e.kind() == pathrs::error::ErrorKind::OsError(Some(libc::ELOOP)) => {
                Err(path::hop_limit_error(rel))
            }
            Err(e) => Err(OciError::Extract(format!(
                "pathrs resolve {}: {e}",
                rel.display()
            ))),
        }
    }
}
