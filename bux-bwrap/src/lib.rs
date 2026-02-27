//! Bundles the [bubblewrap] (`bwrap`) sandbox binary for bux.
//!
//! This crate downloads a pre-built `bwrap` binary at build time and exposes
//! a [`path()`] function for runtime discovery. Bubblewrap provides unprivileged
//! Linux namespace isolation for sandboxing the `bux-shim` process.
//!
//! # Platform
//!
//! Linux only. On other platforms, [`path()`] returns `None`.
//!
//! [bubblewrap]: https://github.com/containers/bubblewrap

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Build-time path to the bwrap binary (baked in by build.rs).
#[cfg(target_os = "linux")]
const BUILD_PATH: &str = env!("BUX_BWRAP_BUILD_PATH");

/// Returns the path to the bundled `bwrap` binary, or `None` if unavailable.
///
/// Search order:
/// 1. Sibling of the current executable (e.g. `/usr/bin/bwrap`).
/// 2. `$PATH` lookup.
/// 3. Build-time path (for `cargo run` during development).
#[cfg(target_os = "linux")]
pub fn path() -> Option<&'static Path> {
    static CACHED: OnceLock<Option<PathBuf>> = OnceLock::new();
    CACHED
        .get_or_init(|| {
            // 1. Sibling of the current executable.
            if let Some(p) = sibling_path("bwrap") {
                return Some(p);
            }

            // 2. Search $PATH.
            if let Some(p) = search_path("bwrap") {
                return Some(p);
            }

            // 3. Build-time fallback (works during `cargo run`).
            let build = Path::new(BUILD_PATH);
            if build.is_file() {
                return Some(build.to_path_buf());
            }

            None
        })
        .as_deref()
}

/// On non-Linux platforms, bwrap is unavailable.
#[cfg(not(target_os = "linux"))]
pub fn path() -> Option<&'static Path> {
    None
}

/// Check for a binary next to the current executable.
#[cfg(target_os = "linux")]
fn sibling_path(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let sibling = exe.with_file_name(name);
    sibling.is_file().then_some(sibling)
}

/// Search `$PATH` for a binary.
#[cfg(target_os = "linux")]
fn search_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}
