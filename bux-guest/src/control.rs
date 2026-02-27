//! Control channel handler: ping, shutdown, quiesce, thaw.

use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

use bux_proto::{ControlReq, ControlResp};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::mounts;
use crate::server;

/// Mount points frozen by the last Quiesce call.
///
/// Stored globally so a subsequent Thaw can precisely undo the freeze
/// rather than blindly scanning `/proc/mounts` again.
static FROZEN_MOUNTS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Handles a control connection: loops reading requests until EOF.
pub async fn handle(
    r: &mut (impl AsyncRead + Unpin),
    w: &mut (impl AsyncWrite + Unpin),
) -> io::Result<()> {
    loop {
        let req: ControlReq = match bux_proto::recv(r).await {
            Ok(req) => req,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };

        match req {
            ControlReq::Ping => {
                let resp = ControlResp::Pong {
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                    uptime_ms: server::uptime_ms(),
                };
                bux_proto::send(w, &resp).await?;
                w.flush().await?;
            }
            ControlReq::Shutdown => {
                bux_proto::send(w, &ControlResp::ShutdownOk).await?;
                w.flush().await?;
                graceful_shutdown();
            }
            ControlReq::Quiesce => {
                let frozen = mounts::freeze_filesystems();
                #[allow(clippy::cast_possible_truncation)]
                let count = frozen.len() as u32;
                // Store for subsequent Thaw.
                if let Ok(mut guard) = FROZEN_MOUNTS.lock() {
                    *guard = frozen;
                }
                bux_proto::send(
                    w,
                    &ControlResp::QuiesceOk {
                        frozen_count: count,
                    },
                )
                .await?;
                w.flush().await?;
            }
            ControlReq::Thaw => {
                let frozen = FROZEN_MOUNTS
                    .lock()
                    .map(|mut g| std::mem::take(&mut *g))
                    .unwrap_or_default();
                let count = mounts::thaw_frozen(&frozen);
                bux_proto::send(
                    w,
                    &ControlResp::ThawOk {
                        thawed_count: count,
                    },
                )
                .await?;
                w.flush().await?;
            }
        }
    }
}

/// Three-step graceful shutdown:
/// 1. SIGTERM all children → wait briefly → SIGKILL survivors.
/// 2. Sync filesystems.
/// 3. Exit.
fn graceful_shutdown() -> ! {
    // Step 1: signal all children (we are PID 1).
    // SIGTERM to process group 0 hits all children but not us (PID 1 is immune).
    unsafe { libc::kill(0, libc::SIGTERM) };

    // Brief wait for children to exit gracefully.
    std::thread::sleep(std::time::Duration::from_millis(500));

    // SIGKILL stragglers.
    unsafe { libc::kill(0, libc::SIGKILL) };

    // Step 2: sync all filesystems to disk.
    unsafe { libc::sync() };

    // Step 3: exit.
    std::process::exit(0);
}
