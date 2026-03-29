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

    // Derive exit file path from config path: {id}.json → {id}.exit
    let exit_path = std::path::Path::new(&config_path).with_extension("exit");
    install_crash_capture(&exit_path);

    start_watchdog();

    let json = match std::fs::read_to_string(&config_path) {
        Ok(j) => {
            let _ = std::fs::remove_file(&config_path);
            j
        }
        Err(e) => {
            write_exit_error(&exit_path, &format!("failed to read config: {e}"));
            std::process::exit(1);
        }
    };

    let config: bux::VmConfig = match serde_json::from_str(&json) {
        Ok(c) => c,
        Err(e) => {
            write_exit_error(&exit_path, &format!("invalid config JSON: {e}"));
            std::process::exit(1);
        }
    };

    let builder = bux::VmBuilder::from_config(&config);

    match builder.build().and_then(bux::Vm::start) {
        Ok(()) => unreachable!(),
        Err(e) => {
            write_exit_error(&exit_path, &format!("VM start failed: {e}"));
            std::process::exit(1);
        }
    }
}

/// Writes an [`ExitInfo::Error`] JSON to the exit file.
#[cfg(unix)]
fn write_exit_error(path: &std::path::Path, message: &str) {
    eprintln!("[bux-shim] {message}");
    let info = bux::ExitInfo::Error {
        exit_code: 1,
        message: message.to_owned(),
    };
    if let Ok(json) = serde_json::to_string(&info) {
        let _ = std::fs::write(path, json);
    }
}

/// Global exit file path for signal handlers (must be static — signal handlers
/// cannot capture closures).
#[cfg(unix)]
static SIGNAL_EXIT_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Signal handler that writes [`ExitInfo::Signal`] JSON to the exit file.
#[cfg(unix)]
extern "C" fn handle_crash_signal(sig: libc::c_int) {
    let name = match sig {
        libc::SIGABRT => "SIGABRT",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGBUS => "SIGBUS",
        libc::SIGILL => "SIGILL",
        _ => "UNKNOWN",
    };
    if let Some(path) = SIGNAL_EXIT_PATH.get() {
        let info = bux::ExitInfo::Signal {
            exit_code: bux::exit_info::SIGNAL_EXIT_BASE + sig,
            signal: name.to_owned(),
        };
        if let Ok(json) = serde_json::to_string(&info) {
            let _ = std::fs::write(path, json);
        }
    }
    #[allow(unsafe_code)]
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Installs panic hook and signal handlers that write [`ExitInfo`] JSON.
#[cfg(unix)]
fn install_crash_capture(exit_path: &std::path::Path) {
    // Panic hook — writes ExitInfo::Panic.
    let panic_path = exit_path.to_path_buf();
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".into());
        let location = info.location().map_or_else(
            || "unknown".into(),
            |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
        );

        let exit = bux::ExitInfo::Panic {
            exit_code: bux::exit_info::PANIC_EXIT_CODE,
            message,
            location,
        };
        if let Ok(json) = serde_json::to_string(&exit) {
            let _ = std::fs::write(&panic_path, json);
        }
        default_hook(info);
    }));

    // Signal handlers — write ExitInfo::Signal for fatal signals.
    let _ = SIGNAL_EXIT_PATH.set(exit_path.to_path_buf());

    #[allow(unsafe_code, function_casts_as_integer)]
    unsafe {
        let h = handle_crash_signal as libc::sighandler_t;
        libc::signal(libc::SIGABRT, h);
        libc::signal(libc::SIGSEGV, h);
        libc::signal(libc::SIGBUS, h);
        libc::signal(libc::SIGILL, h);
    }
}

/// Spawns a background thread that monitors the watchdog pipe.
///
/// When the parent process dies (or drops its `Keepalive`), the write end
/// of the pipe closes. This thread detects `POLLHUP` and exits the process.
#[cfg(unix)]
fn start_watchdog() {
    use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};

    let Ok(fd_str) = std::env::var(bux::watchdog::ENV_WATCHDOG_FD) else {
        return; // no watchdog configured (e.g. detach mode)
    };
    let Ok(fd_num) = fd_str.parse::<i32>() else {
        eprintln!("[bux-shim] invalid BUX_WATCHDOG_FD: {fd_str}");
        return;
    };

    // SAFETY: fd_num was created by the parent via pipe() and preserved
    // across exec by not setting O_CLOEXEC on the read end.
    #[allow(unsafe_code)]
    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd_num) };

    if let Err(e) = std::thread::Builder::new()
        .name("watchdog".into())
        .spawn(move || {
            // Borrow the owned FD for the blocking poll.
            // SAFETY: owned_fd lives for the duration of this thread.
            #[allow(unsafe_code)]
            let borrowed = unsafe { BorrowedFd::borrow_raw(fd_num) };
            bux::watchdog::wait_for_parent_death(borrowed);
            drop(owned_fd); // ensure lifetime extends through poll
            eprintln!("[bux-shim] parent process died, shutting down");
            std::process::exit(0);
        })
    {
        eprintln!("[bux-shim] failed to spawn watchdog thread: {e}");
    }
}
