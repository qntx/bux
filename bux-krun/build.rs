//! Build script for bux-krun.
//!
//! 1. Locates or downloads the pre-built `libkrun` dynamic library.
//! 2. Optionally runs `bindgen` to regenerate Rust bindings (feature `regenerate`).
//! 3. Configures the linker for dynamic linking.
//!
//! # Environment variables
//!
//! - `BUX_DEPS_DIR` — Path to a local directory containing pre-built libraries.
//!   When set, skips downloading. Primary flow for local development.
//!
//! - `BUX_DEPS_VERSION` — Override the deps release version to download.
//!   Defaults to the crate version from `Cargo.toml`.
//!
//! - `BUX_UPDATE_BINDINGS` — When set alongside the `regenerate` feature, the
//!   freshly generated `bindings.rs` is copied back to `src/bindings.rs` so it
//!   can be committed to the repository.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Pinned native library versions — keep in sync with `.github/workflows/deps-build.yml`.
const LIBKRUN_VERSION: &str = "1.17.4";
const LIBKRUNFW_VERSION: &str = "5.2.1";

/// Base URL template for downloading the libkrun header.
#[cfg(feature = "regenerate")]
const HEADER_URL_BASE: &str = "https://raw.githubusercontent.com/containers/libkrun";

/// GitHub repository for downloading pre-built library releases.
const GITHUB_REPO: &str = "qntx/bux";

fn main() {
    println!("cargo:rerun-if-env-changed=BUX_DEPS_DIR");
    println!("cargo:rerun-if-env-changed=BUX_DEPS_VERSION");
    println!("cargo:rerun-if-env-changed=BUX_UPDATE_BINDINGS");
    println!("cargo:rerun-if-env-changed=DOCS_RS");

    // docs.rs: no network, no native libs — pre-generated bindings suffice.
    if env::var("DOCS_RS").is_ok() {
        return;
    }

    let target = env::var("TARGET").expect("TARGET not set");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    // Optionally regenerate bindings from the remote header.
    #[cfg(feature = "regenerate")]
    {
        let header = download_header(&out_dir);
        generate_bindings(&header, &out_dir);
    }

    // Only link on supported platforms.
    if !is_supported_target(&target) {
        return;
    }

    let lib_dir = obtain_libraries(&target, &out_dir);
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=krun");
    println!("cargo:LIB_DIR={}", lib_dir.display());
}

/// Download `libkrun.h` from the pinned fork into `$OUT_DIR`.
#[cfg(feature = "regenerate")]
fn download_header(out_dir: &Path) -> PathBuf {
    let path = out_dir.join("libkrun.h");
    if path.exists() {
        return path;
    }

    let url = format!("{HEADER_URL_BASE}/v{LIBKRUN_VERSION}/include/libkrun.h");
    eprintln!("bux-krun: downloading header from {url}");
    let resp = ureq::get(&url)
        .call()
        .unwrap_or_else(|e| panic!("Failed to download libkrun.h: {e}"));

    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut resp.into_body().into_reader(), &mut buf)
        .expect("Failed to read header");
    fs::write(&path, &buf).expect("Failed to write libkrun.h");
    path
}

/// Run `bindgen` on the header to produce `$OUT_DIR/bindings.rs`.
#[cfg(feature = "regenerate")]
fn generate_bindings(header: &Path, out_dir: &Path) {
    let out_file = out_dir.join("bindings.rs");

    let bindings = bindgen::Builder::default()
        .header(header.to_str().expect("path is not valid UTF-8"))
        .use_core()
        .allowlist_function("krun_.*")
        .allowlist_var("KRUN_.*")
        .allowlist_var("NET_.*")
        .allowlist_var("COMPAT_.*")
        .allowlist_var("VIRGLRENDERER_.*")
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("bindgen failed to generate bindings from libkrun.h");

    bindings
        .write_to_file(&out_file)
        .expect("Failed to write bindings.rs");

    // Copy back to src/ when requested, so it can be committed.
    if env::var("BUX_UPDATE_BINDINGS").is_ok() {
        let manifest =
            PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
        let committed = manifest.join("src").join("bindings.rs");
        fs::copy(&out_file, &committed).expect("Failed to copy bindings.rs to src/");
        println!(
            "cargo:warning=Updated committed bindings: {}",
            committed.display()
        );
    }
}

/// Obtain the pre-built dynamic library — local directory or GitHub Releases.
fn obtain_libraries(target: &str, out_dir: &Path) -> PathBuf {
    if let Ok(dir) = env::var("BUX_DEPS_DIR") {
        eprintln!("bux-krun: using local deps: {dir}");
        return PathBuf::from(dir);
    }

    let version = env::var("BUX_DEPS_VERSION")
        .unwrap_or_else(|_| env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION not set"));
    let lib_dir = out_dir.join("lib");

    if !lib_dir.join(lib_filename(target)).exists() {
        download_libs(&version, target, &lib_dir);
    }
    lib_dir
}

fn is_supported_target(target: &str) -> bool {
    let linux =
        target.contains("linux") && (target.contains("x86_64") || target.contains("aarch64"));
    let macos = target.contains("apple") && target.contains("aarch64");
    linux || macos
}

fn lib_filename(target: &str) -> &'static str {
    if target.contains("apple") {
        "libkrun.dylib"
    } else {
        "libkrun.so"
    }
}

fn download_libs(version: &str, target: &str, dest: &Path) {
    let url = format!(
        "https://github.com/{GITHUB_REPO}/releases/download/krun-v{version}/bux-deps-{target}.tar.gz"
    );
    eprintln!("bux-krun: downloading {url}");

    let resp = ureq::get(&url)
        .call()
        .unwrap_or_else(|e| panic!("Failed to download deps: {e}"));

    fs::create_dir_all(dest).expect("Failed to create lib dir");
    tar::Archive::new(flate2::read::GzDecoder::new(resp.into_body().into_reader()))
        .unpack(dest)
        .expect("Failed to extract archive");

    assert!(
        dest.join(lib_filename(target)).exists(),
        "Library not found after extraction. Check GitHub Release krun-v{version}."
    );

    // libkrun loads libkrunfw via dlopen with a versioned soname.
    // Create versioned symlinks so the runtime linker can find them.
    create_versioned_symlinks(dest, target);
}

/// Extract the major version component from a semver string (e.g. `"5.2.1"` → `"5"`).
fn major_version(version: &str) -> &str {
    version.split('.').next().expect("empty version string")
}

/// Create versioned symlinks (e.g. `libkrunfw.so.5 -> libkrunfw.so`) so that
/// `dlopen("libkrunfw.so.5")` succeeds at runtime.
fn create_versioned_symlinks(dir: &Path, target: &str) {
    if target.contains("apple") {
        // macOS uses unversioned dylib names — no symlinks needed.
        return;
    }

    // Derive major version from pinned version strings for soname symlinks.
    let krun_major = major_version(LIBKRUN_VERSION);
    let krunfw_major = major_version(LIBKRUNFW_VERSION);

    let pairs = [
        ("libkrun.so", format!("libkrun.so.{krun_major}")),
        ("libkrunfw.so", format!("libkrunfw.so.{krunfw_major}")),
    ];

    for (src, link) in &pairs {
        let src_path = dir.join(src);
        let link_path = dir.join(link);
        if src_path.exists() && !link_path.exists() {
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(src, &link_path).unwrap_or_else(|e| {
                    eprintln!("bux-krun: warning: failed to create symlink {link}: {e}");
                });
            }
            #[cfg(not(unix))]
            {
                let _ = fs::copy(&src_path, &link_path);
            }
        }
    }
}
