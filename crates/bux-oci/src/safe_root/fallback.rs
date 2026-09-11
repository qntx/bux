//! Non-Linux: walk only.

use super::path;
use crate::Result;
use std::path::{Path, PathBuf};

pub(super) struct Backend {
    root: PathBuf,
}

impl Backend {
    #[allow(
        clippy::unnecessary_wraps,
        reason = "signature matches the Linux backend"
    )]
    pub(super) fn open(root: &Path) -> Result<Self> {
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub(super) fn resolve(&self, rel: &Path) -> Result<PathBuf> {
        path::resolve_walk(&self.root, rel)
    }
}
