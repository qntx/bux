//! Vsock listener and per-connection session dispatch.

use std::io;
use std::sync::OnceLock;
use std::time::Instant;

use bux_proto::{AGENT_PORT, GuestBootConfig, GuestNetworkMode, Hello, HelloAck, PROTOCOL_VERSION};
use tokio::io::{AsyncWriteExt, BufReader, BufWriter};
use tokio_vsock::VsockListener;

use crate::ca_trust;
use crate::control;
use crate::exec;
use crate::files;
use crate::mounts;
use crate::network;
use crate::reaper::Reaper;

/// Boot timestamp, set once at agent startup.
pub static BOOT_T0: OnceLock<Instant> = OnceLock::new();

/// Milliseconds elapsed since agent startup.
#[allow(clippy::cast_possible_truncation)]
pub fn uptime_ms() -> u64 {
    BOOT_T0.get().map_or(0, |t| t.elapsed().as_millis() as u64)
}

/// Entry point: tmpfs, boot config, net, MITM CA, virtio-fs, reaper, then vsock listen.
///
/// # Errors
///
/// Returns an error if boot, network, MITM CA install, virtiofs, reaper start, or vsock listen fails.
pub async fn run() -> io::Result<()> {
    BOOT_T0.set(Instant::now()).ok();
    eprintln!("[bux-guest] T+0ms: starting");

    mounts::mount_essential_tmpfs();
    eprintln!("[bux-guest] T+{}ms: tmpfs mounted", uptime_ms());

    let boot = GuestBootConfig::from_env().map_err(io::Error::other)?;
    eprintln!(
        "[bux-guest] T+{}ms: boot config vm_id={} network={:?}",
        uptime_ms(),
        boot.vm_id,
        boot.network
    );

    match boot.network {
        GuestNetworkMode::Enabled => {
            network::configure_static_eth0().await?;
            eprintln!(
                "[bux-guest] T+{}ms: static eth0 192.168.127.2/24 configured",
                uptime_ms()
            );
        }
        GuestNetworkMode::Disabled => {
            network::configure_offline();
            eprintln!(
                "[bux-guest] T+{}ms: network disabled (offline)",
                uptime_ms()
            );
        }
        _ => {
            return Err(io::Error::other(format!(
                "unsupported GuestNetworkMode: {:?}",
                boot.network
            )));
        }
    }

    if let Some(ref pem) = boot.mitm_ca_pem {
        ca_trust::install_mitm_ca(pem)?;
        eprintln!("[bux-guest] T+{}ms: MITM CA installed", uptime_ms());
    }

    mounts::mount_virtiofs_volumes(&boot.volumes)?;
    if !boot.volumes.is_empty() {
        eprintln!(
            "[bux-guest] T+{}ms: virtiofs volumes mounted ({})",
            uptime_ms(),
            boot.volumes.len()
        );
    }

    let reaper = Reaper::start()?;

    let addr = tokio_vsock::VsockAddr::new(libc::VMADDR_CID_ANY, AGENT_PORT);
    let listener =
        VsockListener::bind(addr).map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, e))?;
    eprintln!(
        "[bux-guest] T+{}ms: listening on vsock port {AGENT_PORT}",
        uptime_ms()
    );

    loop {
        let (stream, _addr) = listener.accept().await?;
        let reaper = reaper.clone();
        tokio::spawn(async move {
            if let Err(e) = session(stream, reaper).await {
                eprintln!("[bux-guest] session error: {e}");
            }
        });
    }
}

/// Dispatches a single connection based on its [`Hello`] message.
async fn session(stream: tokio_vsock::VsockStream, reaper: Reaper) -> io::Result<()> {
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
        Hello::Exec(req) => exec::handle(&mut r, &mut w, req, reaper).await,
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
        _ => Err(io::Error::other("unsupported hello variant")),
    }
}
