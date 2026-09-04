//! Runtime discovery of the bundled `bwrap` binary.
//!
//! Search order, in priority:
//!
//! 1. Sibling of the current executable (e.g. `/opt/bux/bwrap`).
//! 2. `$PATH` lookup.
//! 3. Build-time path baked in by `build.rs` — primarily for
//!    `cargo run` during development.

use std::path::Path;
#[cfg(any(test, target_os = "linux"))]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;

/// Build-time path to the bwrap binary (baked in by `build.rs`).
#[cfg(target_os = "linux")]
const BUILD_PATH: &str = env!("BUX_BWRAP_BUILD_PATH");

/// Return the path to the bundled `bwrap` binary, or `None` if
/// unavailable on this system.
///
/// The result is cached after the first call, so repeat invocations
/// are cheap.
#[cfg(target_os = "linux")]
#[must_use]
pub fn path() -> Option<&'static Path> {
    static CACHED: OnceLock<Option<PathBuf>> = OnceLock::new();
    CACHED
        .get_or_init(|| {
            sibling_path("bwrap")
                .or_else(|| search_path("bwrap"))
                .or_else(|| {
                    let build = Path::new(BUILD_PATH);
                    build.is_file().then(|| build.to_path_buf())
                })
        })
        .as_deref()
}

/// On non-Linux platforms, `bwrap` is unavailable.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub const fn path() -> Option<&'static Path> {
    None
}

/// Follows symlinks so `bwrap` is joined next to the real executable, not the invocation path.
///
/// `None` if `exe` is a symlink that cannot be resolved: do not join against the link.
#[cfg(any(test, target_os = "linux"))]
#[must_use]
fn real_exe(exe: PathBuf) -> Option<PathBuf> {
    exe.canonicalize().ok().or_else(|| {
        let symlink = std::fs::symlink_metadata(&exe).is_ok_and(|m| m.file_type().is_symlink());
        (!symlink).then_some(exe)
    })
}

/// Sidecar next to [`real_exe`] when that path is a file.
#[cfg(any(test, target_os = "linux"))]
#[must_use]
fn sibling_of(exe: PathBuf, name: &str) -> Option<PathBuf> {
    let sibling = real_exe(exe)?.with_file_name(name);
    sibling.is_file().then_some(sibling)
}

/// Check for a binary next to the current executable.
#[cfg(target_os = "linux")]
fn sibling_path(name: &str) -> Option<PathBuf> {
    sibling_of(std::env::current_exe().ok()?, name)
}

/// Search `$PATH` for a binary.
#[cfg(target_os = "linux")]
fn search_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    reason = "tests"
)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn real_exe_missing_path_stays_uncanonicalized() {
        let missing = PathBuf::from("/definitely-not-a-bwrap-exe");
        assert_eq!(
            real_exe(missing.clone()).as_deref(),
            Some(missing.as_path()),
            "missing path must stay uncanonicalized"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sibling_of_symlink_exe_uses_real_dir() {
        let dir = std::env::temp_dir().join(format!("bux-bwrap-canon-{}", std::process::id()));
        drop(fs::remove_dir_all(&dir));
        fs::create_dir_all(dir.join("real")).unwrap();
        fs::create_dir_all(dir.join("link")).unwrap();
        let _guard = DirGuard(dir.clone());
        let real = dir.join("real").join("bux");
        fs::write(&real, b"exe").unwrap();
        let link = dir.join("link").join("bux");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let planted = real.canonicalize().unwrap().with_file_name("bwrap");
        fs::write(&planted, b"planted-bwrap").unwrap();
        fs::write(dir.join("link").join("bwrap"), b"leftover-bwrap").unwrap();

        assert_eq!(
            sibling_of(link, "bwrap").as_deref(),
            Some(planted.as_path()),
            "sibling bwrap must sit next to the real executable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sibling_of_dangling_symlink_skips_leftover() {
        let dir = std::env::temp_dir().join(format!("bux-bwrap-dangle-{}", std::process::id()));
        drop(fs::remove_dir_all(&dir));
        fs::create_dir_all(&dir).unwrap();
        let _guard = DirGuard(dir.clone());
        let link = dir.join("bux");
        std::os::unix::fs::symlink(dir.join("missing"), &link).unwrap();
        fs::write(dir.join("bwrap"), b"leftover-bwrap").unwrap();

        assert_eq!(
            sibling_of(link, "bwrap"),
            None,
            "unresolved symlink exe must not pick leftover sibling"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sibling_path_finds_planted_bwrap() {
        let exe = std::env::current_exe().unwrap();
        let path = real_exe(exe.clone()).unwrap_or(exe).with_file_name("bwrap");
        let backup = fs::read(&path).ok();
        fs::write(&path, b"planted-bwrap").unwrap();
        let _restore = RestorePlanted {
            path: path.clone(),
            backup,
        };
        let found = sibling_path("bwrap");
        assert_eq!(
            found.as_deref(),
            Some(path.as_path()),
            "sibling bwrap must sit next to the running executable"
        );
    }

    #[cfg(unix)]
    struct DirGuard(PathBuf);

    #[cfg(unix)]
    impl Drop for DirGuard {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.0));
        }
    }

    #[cfg(target_os = "linux")]
    struct RestorePlanted {
        path: PathBuf,
        backup: Option<Vec<u8>>,
    }

    #[cfg(target_os = "linux")]
    impl Drop for RestorePlanted {
        fn drop(&mut self) {
            match &self.backup {
                Some(bytes) => drop(fs::write(&self.path, bytes)),
                None => drop(fs::remove_file(&self.path)),
            }
        }
    }
}
