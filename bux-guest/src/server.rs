//! Vsock listener and per-connection session dispatch.

use std::io;
use std::sync::OnceLock;
use std::time::Instant;

use bux_proto::{AGENT_PORT, Hello, HelloAck, PROTOCOL_VERSION};
use tokio::io::{AsyncWriteExt, BufReader, BufWriter};
use tokio_vsock::VsockListener;

use crate::control;
use crate::exec;
use crate::files;
use crate::mounts;

/// Boot timestamp, set once at agent startup.
pub static BOOT_T0: OnceLock<Instant> = OnceLock::new();

/// Milliseconds elapsed since agent startup.
#[allow(clippy::cast_possible_truncation)]
pub fn uptime_ms() -> u64 {
    BOOT_T0.get().map_or(0, |t| t.elapsed().as_millis() as u64)
}

/// Entry point: mounts tmpfs, binds vsock, accepts connections.
pub async fn run() -> io::Result<()> {
    BOOT_T0.set(Instant::now()).ok();
    eprintln!("[bux-guest] T+0ms: starting");

    // PID 1 duty: auto-reap zombie children.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };

    mounts::mount_essential_tmpfs();
    eprintln!("[bux-guest] T+{}ms: tmpfs mounted", uptime_ms());

    let addr = tokio_vsock::VsockAddr::new(libc::VMADDR_CID_ANY, AGENT_PORT);
    let listener =
        VsockListener::bind(addr).map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, e))?;
    eprintln!(
        "[bux-guest] T+{}ms: listening on vsock port {AGENT_PORT}",
        uptime_ms()
    );

    loop {
        let (stream, _addr) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = session(stream).await {
                eprintln!("[bux-guest] session error: {e}");
            }
        });
    }
}

/// Dispatches a single connection based on its [`Hello`] message.
async fn session(stream: tokio_vsock::VsockStream) -> io::Result<()> {
    let (reader, writer) = tokio::io::split(stream);
    let mut r = BufReader::new(reader);
    let mut w = BufWriter::new(writer);

    let hello: Hello = match bux_proto::recv(&mut r).await {
        Ok(h) => h,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(e) => return Err(e),
    };

    match hello {
        Hello::Control { version } => {
            if version != PROTOCOL_VERSION {
                let err = bux_proto::ErrorInfo::version_mismatch(format!(
                    "host protocol v{version}, guest protocol v{PROTOCOL_VERSION}"
                ));
                bux_proto::send(&mut w, &HelloAck::Error(err)).await?;
                return w.flush().await;
            }
            bux_proto::send(
                &mut w,
                &HelloAck::Control {
                    version: PROTOCOL_VERSION,
                },
            )
            .await?;
            w.flush().await?;
            control::handle(&mut r, &mut w).await
        }
        Hello::Exec(req) => exec::handle(&mut r, &mut w, req).await,
        Hello::FileRead { path } => {
            bux_proto::send(&mut w, &HelloAck::Ready).await?;
            w.flush().await?;
            files::handle_read(&mut w, &path).await
        }
        Hello::FileWrite { path, mode } => {
            bux_proto::send(&mut w, &HelloAck::Ready).await?;
            w.flush().await?;
            files::handle_write(&mut r, &mut w, &path, mode).await
        }
        Hello::CopyIn { dest } => {
            bux_proto::send(&mut w, &HelloAck::Ready).await?;
            w.flush().await?;
            files::handle_copy_in(&mut r, &mut w, &dest).await
        }
        Hello::CopyOut {
            path,
            follow_symlinks,
        } => {
            bux_proto::send(&mut w, &HelloAck::Ready).await?;
            w.flush().await?;
            files::handle_copy_out(&mut w, &path, follow_symlinks).await
        }
    }
}
