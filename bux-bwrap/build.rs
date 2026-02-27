//! Build script for bux-bwrap.
//!
//! 1. Locates or downloads the pre-built `bwrap` binary.
//! 2. Exposes the binary path to dependent crates and the runtime.
//!
//! # Environment variables
//!
//! - `BUX_BWRAP_DIR` — Path to a directory containing a pre-built `bwrap`
//!   binary. When set, skips downloading. Primary flow for local development.
//!
//! - `BUX_BWRAP_VERSION` — Override the bubblewrap release version to download.
//!   Defaults to the crate version from `Cargo.toml`.

// Build scripts legitimately use stderr for diagnostics, expect/panic for
// unrecoverable failures, and have internal-only helpers.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unwrap_used,
    missing_docs
)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// GitHub repository for downloading pre-built bwrap releases.
const GITHUB_REPO: &str = "qntx/bux";

fn main() {
    println!("cargo:rerun-if-env-changed=BUX_BWRAP_DIR");
    println!("cargo:rerun-if-env-changed=BUX_BWRAP_VERSION");
    println!("cargo:rerun-if-env-changed=DOCS_RS");

    // docs.rs: no network, no native binaries needed.
    if env::var("DOCS_RS").is_ok() {
        println!("cargo:BWRAP_PATH=/nonexistent");
        return;
    }

    let target = env::var("TARGET").expect("TARGET not set");

    // bubblewrap is Linux-only.
    if !target.contains("linux") {
        println!("cargo:BWRAP_PATH=/nonexistent");
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let bwrap_path = obtain_binary(&target, &out_dir);

    // Expose the bwrap path to dependent crates' build scripts
    // (available as DEP_BUBBLEWRAP_BWRAP_PATH) and to lib.rs at compile time.
    println!("cargo:BWRAP_PATH={}", bwrap_path.display());
    println!(
        "cargo:rustc-env=BUX_BWRAP_BUILD_PATH={}",
        bwrap_path.display()
    );
}

/// Obtain the pre-built bwrap binary — local directory or GitHub Releases.
fn obtain_binary(target: &str, out_dir: &Path) -> PathBuf {
    if let Ok(dir) = env::var("BUX_BWRAP_DIR") {
        let path = PathBuf::from(&dir).join("bwrap");
        if path.is_file() {
            eprintln!("bux-bwrap: using local binary: {}", path.display());
            return path;
        }
        eprintln!("bux-bwrap: BUX_BWRAP_DIR set but bwrap not found, downloading");
    }

    let version = env::var("BUX_BWRAP_VERSION")
        .unwrap_or_else(|_| env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION not set"));
    let bin_dir = out_dir.join("bwrap");
    let bwrap_path = bin_dir.join("bwrap");

    if !bwrap_path.is_file() && !download_binary(&version, target, &bin_dir) {
        // No pre-built release available yet — emit a sentinel path.
        // path() will return None at runtime since this file won't exist.
        return PathBuf::from("/nonexistent");
    }
    bwrap_path
}

/// Downloads the pre-built bwrap binary from GitHub Releases.
///
/// Returns `true` on success, `false` if the release is not available yet.
fn download_binary(version: &str, target: &str, dest: &Path) -> bool {
    let url = format!(
        "https://github.com/{GITHUB_REPO}/releases/download/bwrap-v{version}/bux-bwrap-{target}.tar.gz"
    );
    eprintln!("bux-bwrap: downloading {url}");

    fs::create_dir_all(dest).expect("Failed to create bwrap dir");

    let resp = match ureq::get(&url).call() {
        Ok(r) => r,
        Err(e) => {
            println!("cargo:warning=bux-bwrap: download failed ({e}), bwrap will be unavailable");
            return false;
        }
    };

    tar::Archive::new(flate2::read::GzDecoder::new(resp.into_body().into_reader()))
        .unpack(dest)
        .expect("Failed to extract bwrap archive");

    let bwrap = dest.join("bwrap");
    if !bwrap.is_file() {
        println!("cargo:warning=bux-bwrap: binary not found in archive");
        return false;
    }

    // Ensure executable permission on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bwrap, fs::Permissions::from_mode(0o755))
            .expect("Failed to set bwrap permissions");
    }

    true
}
