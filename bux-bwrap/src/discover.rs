//! Runtime discovery of the bundled `bwrap` binary.
//!
//! Search order, in priority:
//!
//! 1. Sibling of the current executable (e.g. `/opt/bux/bwrap`).
//! 2. `$PATH` lookup.
//! 3. Build-time path baked in by `build.rs` — primarily for
//!    `cargo run` during development.

use std::path::Path;
#[cfg(target_os = "linux")]
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
