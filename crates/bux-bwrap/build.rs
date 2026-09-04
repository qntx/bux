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
//!   Defaults to `BUBBLEWRAP_VERSION`.

// Build scripts legitimately use stderr for diagnostics, expect/panic for
// unrecoverable failures, and have internal-only helpers.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unwrap_used,
    missing_docs,
    reason = "build script uses expect/panic for unrecoverable failures"
)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// GitHub repository for downloading pre-built bwrap releases.
const GITHUB_REPO: &str = "qntx/bux";

/// Pinned bubblewrap version — keep in sync with `.github/workflows/bwrap-build.yml`.
const BUBBLEWRAP_VERSION: &str = "0.12.0";

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
    stage_bwrap_beside_binaries(&bwrap_path, &out_dir);

    // Expose the bwrap path to dependent crates' build scripts
    // (available as DEP_BUBBLEWRAP_BWRAP_PATH) and to lib.rs at compile time.
    println!("cargo:BWRAP_PATH={}", bwrap_path.display());
    println!(
        "cargo:rustc-env=BUX_BWRAP_BUILD_PATH={}",
        bwrap_path.display()
    );
}

/// `OUT_DIR` ancestor named `$PROFILE` is the cargo bin dir (native or `--target`).
fn profile_bin_dir(out_dir: &Path, profile: &str) -> PathBuf {
    out_dir
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == profile))
        .map_or_else(
            || {
                panic!(
                    "bux-bwrap: cannot resolve profile bin dir from OUT_DIR={} PROFILE={profile}",
                    out_dir.display()
                )
            },
            Path::to_path_buf,
        )
}

/// Copy `bwrap` into the cargo profile dir so sibling lookup finds it for `cargo run`.
fn stage_bwrap_beside_binaries(bwrap: &Path, out_dir: &Path) {
    let profile = env::var("PROFILE").expect("PROFILE not set");
    let dest_dir = profile_bin_dir(out_dir, &profile);
    fs::create_dir_all(&dest_dir).unwrap_or_else(|e| {
        panic!(
            "bux-bwrap: failed to create profile dir {}: {e}",
            dest_dir.display()
        )
    });
    let dest = dest_dir.join("bwrap");
    if dest.symlink_metadata().is_ok() {
        fs::remove_file(&dest).unwrap_or_else(|e| {
            panic!("bux-bwrap: failed to replace {}: {e}", dest.display());
        });
    }
    fs::copy(bwrap, &dest).unwrap_or_else(|e| {
        panic!(
            "bux-bwrap: failed to copy {} -> {}: {e}",
            bwrap.display(),
            dest.display()
        );
    });
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o755)).unwrap_or_else(|e| {
            panic!("bux-bwrap: failed to chmod 0755 {}: {e}", dest.display());
        });
    }
    assert!(
        dest.is_file(),
        "bux-bwrap: bwrap missing next to binaries at {}",
        dest.display()
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

    let version = env::var("BUX_BWRAP_VERSION");
    let version = version.as_deref().unwrap_or(BUBBLEWRAP_VERSION);
    let bin_dir = out_dir.join("bwrap");
    let bwrap_path = bin_dir.join("bwrap");

    if !bwrap_path.is_file() {
        download_binary(version, target, &bin_dir);
    }
    bwrap_path
}

/// Downloads the pre-built bwrap binary from GitHub Releases.
fn download_binary(version: &str, target: &str, dest: &Path) {
    let url = format!(
        "https://github.com/{GITHUB_REPO}/releases/download/bwrap-v{version}/bux-bwrap-{target}.tar.gz"
    );
    eprintln!("bux-bwrap: downloading {url}");

    fs::create_dir_all(dest).expect("Failed to create bwrap dir");

    let resp = ureq::get(&url)
        .call()
        .unwrap_or_else(|e| panic!("Failed to download bwrap: {e}"));

    tar::Archive::new(flate2::read::GzDecoder::new(resp.into_body().into_reader()))
        .unpack(dest)
        .expect("Failed to extract bwrap archive");

    let bwrap = dest.join("bwrap");
    assert!(
        bwrap.is_file(),
        "bwrap not found after extraction. Check GitHub Release bwrap-v{version}."
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bwrap, fs::Permissions::from_mode(0o755))
            .expect("Failed to set bwrap permissions");
    }
}
