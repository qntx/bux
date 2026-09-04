//! Shared internal helpers.

use std::fs;
use std::path::{Path, PathBuf};

/// Appends `path` to `paths` only if it is not already present.
pub(crate) fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|p| p == &path) {
        paths.push(path);
    }
}

/// Follows symlinks so sidecars are joined next to the real executable, not the invocation path.
///
/// `None` if `exe` is a symlink that cannot be resolved: joining against the link's
/// directory would pick a leftover next to the invocation path.
#[must_use]
pub(crate) fn real_exe(exe: &Path) -> Option<PathBuf> {
    match exe.canonicalize() {
        Ok(path) => Some(path),
        Err(error) => {
            if is_symlink(exe) {
                tracing::warn!(
                    error = %error,
                    path = %exe.display(),
                    "canonicalize failed for symlink current_exe, skipping sibling lookup"
                );
                None
            } else {
                tracing::warn!(
                    error = %error,
                    path = %exe.display(),
                    "canonicalize failed, using uncanonicalized current_exe"
                );
                Some(exe.to_path_buf())
            }
        }
    }
}

/// Sidecar path next to [`real_exe`]. `None` when sibling lookup should be skipped.
#[must_use]
pub(crate) fn sidecar_path(exe: &Path, name: &str) -> Option<PathBuf> {
    real_exe(exe).map(|exe| exe.with_file_name(name))
}

/// True when `path` itself is a symlink.
fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn real_exe_missing_path_stays_uncanonicalized() {
        let missing = PathBuf::from("/definitely-not-a-bux-exe");
        assert_eq!(
            real_exe(&missing).as_deref(),
            Some(missing.as_path()),
            "missing path must stay uncanonicalized"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_path_from_symlink_exe_uses_real_dir() {
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("real");
        let link_dir = dir.path().join("link");
        fs::create_dir(&real_dir).unwrap();
        fs::create_dir(&link_dir).unwrap();
        let real = real_dir.join("bux");
        fs::write(&real, b"exe").unwrap();
        let link = link_dir.join("bux");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let expected = real.canonicalize().unwrap().with_file_name("bux-shim");
        assert_eq!(
            sidecar_path(&link, "bux-shim").as_deref(),
            Some(expected.as_path()),
            "sidecar join must land next to the real executable"
        );
        assert_ne!(
            sidecar_path(&link, "bux-shim").unwrap().parent(),
            Some(link_dir.as_path()),
            "must not join against the invocation path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_path_dangling_symlink_skips_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("bux");
        std::os::unix::fs::symlink(dir.path().join("missing"), &link).unwrap();
        assert_eq!(
            sidecar_path(&link, "bux-shim"),
            None,
            "unresolved symlink exe must skip sibling lookup"
        );
    }
}
