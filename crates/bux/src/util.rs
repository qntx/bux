//! Shared internal helpers.

use std::path::{Path, PathBuf};

/// Appends `path` to `paths` only if it is not already present.
pub(crate) fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|p| p == &path) {
        paths.push(path);
    }
}

/// Follows symlinks so sidecar lookup uses the payload directory, not `~/.local/bin`.
#[must_use]
pub(crate) fn canonicalize_exe(exe: &Path) -> PathBuf {
    match exe.canonicalize() {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(
                error = %error,
                path = %exe.display(),
                "canonicalize failed, using uncanonicalized current_exe"
            );
            exe.to_path_buf()
        }
    }
}

/// Executable path used to join sibling sidecar names.
///
/// # Errors
///
/// Returns the error from [`std::env::current_exe`].
pub(crate) fn current_exe_for_sidecars() -> std::io::Result<PathBuf> {
    std::env::current_exe().map(|exe| canonicalize_exe(&exe))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn canonicalize_exe_missing_path_stays_uncanonicalized() {
        let missing = PathBuf::from("/definitely-not-a-bux-exe");
        assert_eq!(
            canonicalize_exe(&missing),
            missing,
            "missing path must stay uncanonicalized"
        );
    }

    #[cfg(unix)]
    #[test]
    fn canonicalize_exe_sibling_is_in_real_dir() {
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("payload");
        let bin = dir.path().join("bin");
        fs::create_dir(&payload).unwrap();
        fs::create_dir(&bin).unwrap();
        let real = payload.join("bux");
        fs::write(&real, b"exe").unwrap();
        let link = bin.join("bux");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let canon = canonicalize_exe(&link);
        assert_eq!(
            canon,
            real.canonicalize().unwrap(),
            "symlink current_exe must resolve to the payload file"
        );
        assert_eq!(
            canon.with_file_name("bux-shim"),
            real.canonicalize().unwrap().with_file_name("bux-shim"),
            "sidecar join must land in the payload directory"
        );
    }
}
