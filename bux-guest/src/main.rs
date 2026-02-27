//! bux guest agent — runs inside a micro-VM, typically as PID 1.
//!
//! Listens on a vsock port and handles host requests via [`bux_proto`].
#![allow(unsafe_code, clippy::print_stderr)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("bux-guest only runs inside a Linux micro-VM");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod control;
#[cfg(target_os = "linux")]
mod exec;
#[cfg(target_os = "linux")]
mod files;
#[cfg(target_os = "linux")]
mod mounts;
#[cfg(target_os = "linux")]
mod server;

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("[bux-guest] PANIC: {info}");
        std::process::exit(1);
    }));

    if let Err(e) = server::run().await {
        eprintln!("[bux-guest] fatal: {e}");
        std::process::exit(1);
    }
}
