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

    // Start watchdog thread if the parent passed a pipe FD.
    start_watchdog();

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

/// Spawns a background thread that monitors the watchdog pipe.
///
/// When the parent process dies (or drops its `Keepalive`), the write end
/// of the pipe closes. This thread detects `POLLHUP` and exits the process.
#[cfg(unix)]
fn start_watchdog() {
    let fd_str = match std::env::var(bux::watchdog::ENV_WATCHDOG_FD) {
        Ok(s) => s,
        Err(_) => return, // no watchdog configured (e.g. detach mode)
    };
    let fd: i32 = if let Ok(n) = fd_str.parse() { n } else {
        eprintln!("[bux-shim] invalid BUX_WATCHDOG_FD: {fd_str}");
        return;
    };

    std::thread::Builder::new()
        .name("watchdog".into())
        .spawn(move || {
            // SAFETY: fd was validated by the parent and preserved across exec.
            unsafe { bux::watchdog::wait_for_parent_death(fd) };
            eprintln!("[bux-shim] parent process died, shutting down");
            std::process::exit(0);
        })
        .expect("failed to spawn watchdog thread");
}
