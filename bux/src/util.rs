//! Shared internal helpers.

use std::path::PathBuf;

/// Appends `path` to `paths` only if it is not already present.
pub(crate) fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|p| p == &path) {
        paths.push(path);
    }
}
