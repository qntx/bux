//! Rooted path resolution for OCI layer extraction.
//!
//! [`SafeRoot`] follows symlinks inside the extract root and re-anchors
//! absolute targets at that root. Callers then use ordinary `std::fs` on the
//! returned path.

mod path;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as imp;

#[cfg(not(target_os = "linux"))]
mod fallback;
#[cfg(not(target_os = "linux"))]
use fallback as imp;

use crate::{OciError, Result};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// Directory tree that tar members are resolved against.
pub struct SafeRoot {
    root: PathBuf,
    backend: imp::Backend,
}

impl fmt::Debug for SafeRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafeRoot")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl SafeRoot {
    /// Open `root`, creating it if needed. The stored path is canonical.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created, canonicalized, or
    /// opened by the platform backend.
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        let root = fs::canonicalize(root)?;
        Ok(Self {
            backend: imp::Backend::open(&root)?,
            root,
        })
    }

    /// Follow every symlink, including the final component. Absolute targets
    /// are re-anchored at the extract root.
    ///
    /// # Errors
    ///
    /// Returns an error if `rel` walks above the root, the hop limit is
    /// exceeded, or a filesystem error occurs while walking.
    pub fn resolve(&self, rel: &Path) -> Result<PathBuf> {
        let rel = path::normalize_relative(rel)
            .ok_or_else(|| OciError::Extract(format!("path escapes rootfs: {}", rel.display())))?;
        if rel.as_os_str().is_empty() {
            return Ok(self.root.clone());
        }
        let resolved = self.backend.resolve(&rel)?;
        if !resolved.starts_with(&self.root) {
            tracing::error!(
                root = %self.root.display(),
                path = %resolved.display(),
                "extract write-escape"
            );
            return Err(OciError::Extract(format!(
                "path escapes rootfs: {}",
                resolved.display()
            )));
        }
        Ok(resolved)
    }

    /// Like [`Self::resolve`], but an empty `rel` is the root itself.
    pub(crate) fn resolve_or_root(&self, rel: &Path) -> Result<PathBuf> {
        if rel.as_os_str().is_empty() {
            Ok(self.root.clone())
        } else {
            self.resolve(rel)
        }
    }

    /// Strip leading `/` and collapse `.` / `..`. `None` if `..` walks above root.
    #[must_use]
    pub fn normalize(path: &Path) -> Option<PathBuf> {
        path::normalize_relative(path)
    }

    pub(crate) fn root_path(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests;
