//! Build script for bux-net.
//!
//! Compiles the `gvproxy-bridge` Go sources into a C static archive
//! (`libgvproxy.a`) and links it into the Rust binary.
//!
//! # Environment variables
//!
//! - `BUX_DEPS_STUB` — When set, skips the Go build entirely.  Used
//!   for CI linting or when Go is not installed.

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Builds libgvproxy from Go sources as a C static archive.
fn build_gvproxy(source_dir: &Path, output_path: &Path) {
    println!("cargo:warning=Building libgvproxy from Go sources...");

    // Download Go dependencies.
    let download = Command::new("go")
        .args(["mod", "download"])
        .current_dir(source_dir)
        .status()
        .expect("Failed to run 'go mod download' — is Go installed?");

    if !download.success() {
        panic!("Failed to download Go module dependencies");
    }

    // Build as C archive (static library).
    let mut cmd = Command::new("go");
    cmd.args(["build", "-buildmode=c-archive"]);

    if source_dir.join("vendor").exists() {
        cmd.arg("-mod=vendor");
    }

    cmd.args([
        "-o",
        output_path.to_str().expect("invalid output path"),
        ".",
    ]);

    let build = cmd
        .current_dir(source_dir)
        .status()
        .expect("Failed to run 'go build' — is Go installed?");

    if !build.success() {
        panic!("Failed to build libgvproxy");
    }

    println!("cargo:warning=Successfully built libgvproxy");
}

fn main() {
    // Rebuild when any Go source file changes.
    let bridge_dir = Path::new("gvproxy-bridge");
    if bridge_dir.is_dir() {
        for entry in fs::read_dir(bridge_dir).expect("failed to read gvproxy-bridge directory") {
            let entry = entry.expect("failed to read directory entry");
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|ext| ext == "go" || ext == "mod" || ext == "sum")
            {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
    println!("cargo:rerun-if-changed=gvproxy-bridge");
    println!("cargo:rerun-if-env-changed=BUX_DEPS_STUB");

    // Auto-detect crates.io download: Go sources are excluded from the
    // published package.
    if env::var("BUX_DEPS_STUB").is_err() {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        if Path::new(&manifest_dir)
            .join(".cargo_vcs_info.json")
            .exists()
        {
            // build.rs is single-threaded — safe to set env.
            unsafe { env::set_var("BUX_DEPS_STUB", "1") };
        }
    }

    // Stub mode: skip Go build (CI lint, no Go toolchain).
    if env::var("BUX_DEPS_STUB").is_ok() {
        println!("cargo:warning=BUX_DEPS_STUB mode: skipping libgvproxy build");
        return;
    }

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    let source_dir = Path::new(&manifest_dir).join("gvproxy-bridge");
    let lib_output = Path::new(&out_dir).join("libgvproxy.a");

    build_gvproxy(&source_dir, &lib_output);

    // Copy header for downstream C/C++ usage (optional).
    let header_src = source_dir.join("libgvproxy.h");
    if header_src.exists() {
        let header_dst = Path::new(&out_dir).join("libgvproxy.h");
        let _ = fs::copy(&header_src, &header_dst);
    }

    // Tell Cargo where to find the library.
    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=static=gvproxy");

    // Transitive dependencies from the Go runtime.
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
    }

    // On Linux, force static linking of libresolv for full-static binaries.
    #[cfg(target_os = "linux")]
    {
        let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        let gnu_triple = match arch.as_str() {
            "x86_64" => "x86_64-linux-gnu",
            "aarch64" => "aarch64-linux-gnu",
            _ => "x86_64-linux-gnu",
        };
        println!("cargo:rustc-link-search=native=/usr/lib/{gnu_triple}");
        println!("cargo:rustc-link-search=native=/usr/lib64");
        println!("cargo:rustc-link-lib=static=resolv");
    }
    #[cfg(not(target_os = "linux"))]
    println!("cargo:rustc-link-lib=resolv");
}
