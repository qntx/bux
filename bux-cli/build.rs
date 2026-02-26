//! Build script for bux-cli.
//!
//! Sets RPATH so the binary can find `libkrun` and `libkrunfw` at runtime
//! without requiring `LD_LIBRARY_PATH`.

fn main() {
    // DEP_KRUN_LIB_DIR is exported by bux-krun (via `links = "krun"` + `cargo:LIB_DIR=...`).
    if let Ok(lib_dir) = std::env::var("DEP_KRUN_LIB_DIR") {
        // Embed the library directory as RPATH in the binary.
        println!("cargo:rustc-link-arg=-Wl,-rpath,{lib_dir}");
    }
}
