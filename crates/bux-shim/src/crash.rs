//! Panic and fatal-signal capture → [`ExitInfo`] JSON on disk.

#![allow(
    clippy::print_stderr,
    clippy::exit,
    clippy::disallowed_methods,
    clippy::multiple_unsafe_ops_per_block,
    clippy::undocumented_unsafe_blocks,
    clippy::missing_docs_in_private_items,
    reason = "shim process diagnostics: stderr + signal handlers are intentional"
)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::exit_info::{ExitInfo, PANIC_EXIT_CODE, SIGNAL_EXIT_BASE};

static SIGNAL_EXIT_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Write an error exit record and print to stderr.
pub fn write_exit_error(path: &Path, message: &str) {
    eprintln!("[bux-shim] {message}");
    let info = ExitInfo::Error {
        exit_code: 1,
        message: message.to_owned(),
    };
    if let Ok(json) = serde_json::to_string(&info) {
        drop(std::fs::write(path, json));
    }
}

/// Install panic hook + fatal signal handlers that write [`ExitInfo`].
#[cfg(unix)]
pub fn install_crash_capture(exit_path: &Path) {
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

        let exit = ExitInfo::Panic {
            exit_code: PANIC_EXIT_CODE,
            message,
            location,
        };
        if let Ok(json) = serde_json::to_string(&exit) {
            drop(std::fs::write(&panic_path, json));
        }
        default_hook(info);
    }));

    drop(SIGNAL_EXIT_PATH.set(exit_path.to_path_buf()));

    #[allow(
        unsafe_code,
        function_casts_as_integer,
        reason = "register C signal handlers via libc"
    )]
    let h = handle_crash_signal as libc::sighandler_t;
    #[allow(unsafe_code, reason = "register signal handlers via libc")]
    {
        // SAFETY: valid extern "C" handler; signal numbers are POSIX.
        unsafe {
            libc::signal(libc::SIGABRT, h);
            libc::signal(libc::SIGSEGV, h);
            libc::signal(libc::SIGBUS, h);
            libc::signal(libc::SIGILL, h);
        }
    }
}

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
        let info = ExitInfo::Signal {
            exit_code: SIGNAL_EXIT_BASE + sig,
            signal: name.to_owned(),
        };
        if let Ok(json) = serde_json::to_string(&info) {
            drop(std::fs::write(path, json));
        }
    }
    #[allow(unsafe_code, reason = "restore default and re-raise")]
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        // The kernel blocks `sig` while its handler runs, so `raise` would only leave it pending.
        let mut unblock = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        libc::sigemptyset(unblock.as_mut_ptr());
        libc::sigaddset(unblock.as_mut_ptr(), sig);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, unblock.as_ptr(), std::ptr::null_mut());
        libc::raise(sig);
        // PID 1 of a jail ignores its own signal.
        libc::_exit(SIGNAL_EXIT_BASE + sig);
    }
}
