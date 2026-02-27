//! bux-shim — child process that boots a micro-VM.
//!
//! The parent (`Runtime::spawn`) writes a JSON-serialized [`VmConfig`] to a
//! temp file and spawns this binary with the file path as the sole argument.
//! The shim reads the config, deletes the temp file, rebuilds the
//! [`VmBuilder`], and calls [`Vm::start()`] which takes over the process
//! via `krun_start_enter()`.
//!
//! This replaces the previous `fork()` approach, which was undefined
//! behavior in a multi-threaded tokio runtime.

// Shim is a standalone binary — stderr is the correct error channel.
#![allow(clippy::print_stderr)]

#[cfg(not(unix))]
fn main() {
    eprintln!("[bux-shim] only supported on Unix");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() {
    let Some(config_path) = std::env::args().nth(1) else {
        eprintln!("[bux-shim] usage: bux-shim <config.json>");
        std::process::exit(1);
    };

    // Read and immediately delete the temp config file.
    let json = match std::fs::read_to_string(&config_path) {
        Ok(j) => {
            let _ = std::fs::remove_file(&config_path);
            j
        }
        Err(e) => {
            eprintln!("[bux-shim] failed to read config {config_path}: {e}");
            std::process::exit(1);
        }
    };

    let config: bux::VmConfig = match serde_json::from_str(&json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[bux-shim] invalid config JSON: {e}");
            std::process::exit(1);
        }
    };

    let builder = bux::VmBuilder::from_config(&config);

    match builder.build().and_then(bux::Vm::start) {
        // start() never returns on success — the process becomes the VM.
        Ok(()) => unreachable!(),
        Err(e) => {
            eprintln!("[bux-shim] VM start failed: {e}");
            std::process::exit(1);
        }
    }
}
