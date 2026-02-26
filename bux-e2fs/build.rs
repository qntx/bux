//! Build script for bux-e2fs.
//!
//! 1. Locates or downloads pre-built `libext2fs` static libraries.
//! 2. Optionally runs `bindgen` to regenerate Rust bindings (feature `regenerate`).
//! 3. Configures the linker for static linking.
//!
//! # Environment variables
//!
//! - `BUX_E2FS_DIR` — Path to a local directory containing pre-built static
//!   libraries and headers. When set, skips downloading. Primary flow for
//!   local development.
//!
//! - `BUX_E2FS_VERSION` — Override the e2fsprogs release version to download.
//!   Defaults to the crate version from `Cargo.toml`.
//!
//! - `BUX_UPDATE_BINDINGS` — When set alongside the `regenerate` feature, the
//!   freshly generated `bindings.rs` is copied back to `src/bindings.rs` so it
//!   can be committed to the repository.

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

/// GitHub repository for downloading pre-built library releases.
const GITHUB_REPO: &str = "qntx/bux";

fn main() {
    println!("cargo:rerun-if-env-changed=BUX_E2FS_DIR");
    println!("cargo:rerun-if-env-changed=BUX_E2FS_VERSION");
    println!("cargo:rerun-if-env-changed=BUX_UPDATE_BINDINGS");
    println!("cargo:rerun-if-env-changed=DOCS_RS");

    // docs.rs: no network, no native libs — pre-generated bindings suffice.
    if env::var("DOCS_RS").is_ok() {
        return;
    }

    let target = env::var("TARGET").expect("TARGET not set");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    // Optionally regenerate bindings from downloaded headers.
    #[cfg(feature = "regenerate")]
    {
        let headers_dir = obtain_headers(&target, &out_dir);
        generate_bindings(&headers_dir, &out_dir);
    }

    // Only link on supported platforms.
    if !is_supported_target(&target) {
        return;
    }

    let lib_dir = obtain_libraries(&target, &out_dir);

    // Static linking — all e2fsprogs libraries.
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=ext2fs");
    println!("cargo:rustc-link-lib=static=com_err");
    println!("cargo:rustc-link-lib=static=e2p");
    println!("cargo:rustc-link-lib=static=uuid_e2fs");
    println!("cargo:rustc-link-lib=static=create_inode");
    println!("cargo:LIB_DIR={}", lib_dir.display());
}

/// Download e2fsprogs headers and run bindgen.
#[cfg(feature = "regenerate")]
fn obtain_headers(target: &str, out_dir: &Path) -> PathBuf {
    // If BUX_E2FS_DIR is set, headers should be in `<dir>/include/`.
    if let Ok(dir) = env::var("BUX_E2FS_DIR") {
        let inc = PathBuf::from(&dir).join("include");
        if inc.exists() {
            return inc;
        }
        // Fall through to download.
        eprintln!(
            "bux-e2fs: BUX_E2FS_DIR set but {}/include not found, downloading",
            dir
        );
    }

    // Reuse the library download — headers are in the same archive.
    let lib_dir = obtain_libraries(target, out_dir);
    // Headers are sibling to lib/ in the archive.
    let inc = lib_dir.parent().unwrap().join("include");
    if inc.exists() {
        return inc;
    }

    panic!(
        "bux-e2fs: headers not found. Set BUX_E2FS_DIR or ensure the \
         release archive contains an include/ directory."
    );
}

/// Run `bindgen` on the wrapper header to produce `$OUT_DIR/bindings.rs`.
#[cfg(feature = "regenerate")]
fn generate_bindings(headers_dir: &Path, out_dir: &Path) {
    let wrapper = out_dir.join("wrapper.h");
    fs::write(
        &wrapper,
        "#include \"ext2fs/ext2fs.h\"\n#include \"create_inode.h\"\n",
    )
    .expect("Failed to write wrapper.h");

    let out_file = out_dir.join("bindings.rs");

    let bindings = bindgen::Builder::default()
        .header(wrapper.to_str().expect("path is not valid UTF-8"))
        .clang_arg(format!("-I{}", headers_dir.display()))
        .use_core()
        // Filesystem lifecycle
        .allowlist_function("ext2fs_initialize")
        .allowlist_function("ext2fs_open")
        .allowlist_function("ext2fs_close")
        .allowlist_function("ext2fs_flush")
        .allowlist_function("ext2fs_allocate_tables")
        .allowlist_function("ext2fs_add_journal_inode")
        .allowlist_function("ext2fs_mark_super_dirty")
        // Inode operations
        .allowlist_function("ext2fs_mkdir")
        .allowlist_function("ext2fs_link")
        .allowlist_function("ext2fs_new_inode")
        .allowlist_function("ext2fs_write_new_inode")
        .allowlist_function("ext2fs_read_inode")
        .allowlist_function("ext2fs_write_inode")
        .allowlist_function("ext2fs_read_inode_full")
        .allowlist_function("ext2fs_write_inode_full")
        .allowlist_function("ext2fs_inode_alloc_stats2")
        // Block operations
        .allowlist_function("ext2fs_new_block2")
        .allowlist_function("ext2fs_block_alloc_stats2")
        // Directory population (from create_inode.h)
        .allowlist_function("populate_fs")
        .allowlist_function("populate_fs2")
        .allowlist_function("populate_fs3")
        .allowlist_function("do_write_internal")
        .allowlist_function("do_mkdir_internal")
        .allowlist_function("do_symlink_internal")
        .allowlist_function("set_inode_extra")
        .allowlist_function("add_link")
        // IO manager
        .allowlist_var("unix_io_manager")
        // Types
        .allowlist_type("ext2_filsys")
        .allowlist_type("ext2_ino_t")
        .allowlist_type("ext2_super_block")
        .allowlist_type("ext2_inode")
        .allowlist_type("ext2_inode_large")
        .allowlist_type("errcode_t")
        .allowlist_type("io_manager")
        .allowlist_type("hdlinks_s")
        .allowlist_type("hdlink_s")
        .allowlist_type("fs_ops_callbacks")
        // Constants
        .allowlist_var("EXT2_FLAG_.*")
        .allowlist_var("EXT2_ROOT_INO")
        .allowlist_var("EXT2_DYNAMIC_REV")
        .allowlist_var("EXT2_GOOD_OLD_.*")
        .allowlist_var("EXT2_FT_.*")
        .allowlist_var("POPULATE_FS_.*")
        .allowlist_var("LINUX_S_IF.*")
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("bindgen failed to generate bindings from e2fsprogs headers");

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

/// Obtain the pre-built static libraries — local directory or GitHub Releases.
fn obtain_libraries(target: &str, out_dir: &Path) -> PathBuf {
    if let Ok(dir) = env::var("BUX_E2FS_DIR") {
        let lib = PathBuf::from(&dir).join("lib");
        if lib.exists() {
            eprintln!("bux-e2fs: using local libs: {}", lib.display());
            return lib;
        }
        // BUX_E2FS_DIR itself might contain the .a files directly.
        let direct = PathBuf::from(&dir);
        if direct.join("libext2fs.a").exists() {
            eprintln!("bux-e2fs: using local libs: {}", direct.display());
            return direct;
        }
        eprintln!("bux-e2fs: BUX_E2FS_DIR set but libs not found, downloading");
    }

    let version = env::var("BUX_E2FS_VERSION")
        .unwrap_or_else(|_| env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION not set"));
    let lib_dir = out_dir.join("e2fs").join("lib");

    if !lib_dir.join("libext2fs.a").exists() {
        download_libs(&version, target, out_dir);
    }
    lib_dir
}

/// Returns `true` if the target triple is a supported build platform.
fn is_supported_target(target: &str) -> bool {
    let linux =
        target.contains("linux") && (target.contains("x86_64") || target.contains("aarch64"));
    let macos = target.contains("apple") && target.contains("aarch64");
    linux || macos
}

/// Downloads pre-built static libraries from GitHub Releases.
fn download_libs(version: &str, target: &str, out_dir: &Path) {
    let url = format!(
        "https://github.com/{GITHUB_REPO}/releases/download/e2fs-v{version}/bux-e2fs-{target}.tar.gz"
    );
    eprintln!("bux-e2fs: downloading {url}");

    let dest = out_dir.join("e2fs");
    fs::create_dir_all(&dest).expect("Failed to create e2fs dir");

    let resp = ureq::get(&url)
        .call()
        .unwrap_or_else(|e| panic!("Failed to download e2fs deps: {e}"));

    tar::Archive::new(flate2::read::GzDecoder::new(resp.into_body().into_reader()))
        .unpack(&dest)
        .expect("Failed to extract e2fs archive");

    assert!(
        dest.join("lib").join("libext2fs.a").exists(),
        "libext2fs.a not found after extraction. Check GitHub Release e2fs-v{version}."
    );
}
