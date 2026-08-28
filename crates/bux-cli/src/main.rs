//! CLI for the bux micro-VM sandbox.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_docs_in_private_items,
    clippy::exit,
    clippy::disallowed_methods,
    clippy::let_underscore_must_use,
    clippy::indexing_slicing,
    clippy::struct_excessive_bools,
    unreachable_pub,
    reason = "binary crate: CLI conventions differ from library lints"
)]

mod logs;
mod run;
mod vm;
mod volume;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

#[derive(Parser)]
#[command(name = "bux", version, about = "Micro-VM sandbox powered by libkrun")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create and run a command in a new micro-VM.
    Run(Box<run::RunArgs>),

    /// Create and start a managed VM without an initial command (print ID).
    ///
    /// Equivalent to `bux run -d IMAGE` with no command/entrypoint override.
    Create(Box<run::CreateArgs>),

    /// Execute a command in a running VM.
    Exec(vm::ExecArgs),

    /// Show shim stderr logs for a VM.
    Logs(logs::LogsArgs),

    /// List VMs.
    #[command(visible_alias = "ls")]
    Ps(vm::PsArgs),

    /// Stop one or more running VMs.
    Stop(vm::StopArgs),

    /// Force-kill one or more running VMs.
    Kill(vm::KillArgs),

    /// Remove one or more stopped VMs.
    Rm(vm::RmArgs),

    /// Display detailed information on one or more VMs.
    Inspect(vm::InspectArgs),

    /// Copy files between host and a running VM.
    ///
    /// Use `<vm>:<path>` to refer to a guest path.
    Cp(vm::CpArgs),

    /// Block until one or more VMs stop.
    Wait(vm::WaitArgs),

    /// Remove all stopped VMs.
    Prune,

    /// Rename a VM.
    Rename(vm::RenameArgs),

    /// Restart a stopped or running VM.
    Restart(vm::RestartArgs),

    /// Display VM identity, status, and health.
    Stats(vm::StatsArgs),

    /// Manage VM snapshots.
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },

    /// Disk-clone a VM (overlay flatten; copies `vcpus`, ram, network, `auto_remove`).
    ///
    /// The clone always boots detached and survives CLI exit, matching `bux create`.
    Clone(vm::CloneArgs),

    /// Export a VM's disk as a standalone QCOW2 image.
    Export(vm::ExportArgs),

    /// Pull an OCI image from a registry.
    Pull {
        /// Image reference (e.g., ubuntu:latest).
        image: String,
    },

    /// List locally stored images.
    Images {
        /// Output format.
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },

    /// Remove one or more locally stored images.
    Rmi {
        /// Image references to remove.
        #[arg(required = true, num_args = 1..)]
        images: Vec<String>,
    },

    /// Display host isolation capabilities and libkrun feature support.
    ///
    /// Prefer `bux system info` (same output).
    #[command(visible_alias = "system-info")]
    Info {
        /// Output format.
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },

    /// Host / runtime system commands.
    System {
        #[command(subcommand)]
        action: SystemAction,
    },

    /// Manage named volumes (`{data_dir}/volumes/`).
    Volume {
        #[command(subcommand)]
        action: volume::VolumeAction,
    },

    /// Apply idle auto-stop / auto-delete policies (`Runtime::sweep`).
    ///
    /// Policies default off; set `auto_stop_secs` / `auto_delete_secs` on create.
    Sweep,

    /// Manage ext4 disk images.
    Disk {
        #[command(subcommand)]
        action: DiskAction,
    },

    /// Generate shell completion scripts.
    #[command(hide = true)]
    Completion {
        /// Target shell.
        shell: Shell,
    },
}

/// Subcommands for `bux system`.
#[derive(Subcommand)]
enum SystemAction {
    /// Host capabilities, data dir, and documented capture env vars.
    Info {
        /// Output format.
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },
    /// Delete the runtime data directory (requires no other Runtime).
    Reset,
}

/// Subcommands for `bux snapshot`.
#[derive(Subcommand)]
enum SnapshotAction {
    /// Create a snapshot of a VM's disk state.
    Create {
        /// VM ID or name.
        vm: String,
        /// Optional snapshot name.
        #[arg(long)]
        name: Option<String>,
    },
    /// List snapshots for a VM.
    #[command(visible_alias = "ls")]
    List {
        /// VM ID or name.
        vm: String,
    },
    /// Delete a snapshot.
    Rm {
        /// Snapshot ID.
        id: String,
    },
    /// Restore a snapshot as a new VM (flatten overlay; copies `vcpus`, ram, network, `auto_remove`).
    ///
    /// The restored VM always boots detached, matching `bux clone`. Restore
    /// requires the source VM row: `bux snapshot restore` after `bux rm` of the
    /// source is `NotFound` (`ON DELETE CASCADE`).
    Restore {
        /// Snapshot ID.
        id: String,
        /// Optional name for the restored VM.
        #[arg(long)]
        name: Option<String>,
    },
}

/// Subcommands for `bux disk`.
#[derive(Subcommand)]
enum DiskAction {
    /// Create a base ext4 image from a rootfs directory.
    Create {
        /// Path to the rootfs directory.
        rootfs: String,
        /// Digest identifier for the base image.
        digest: String,
    },
    /// List all base disk images.
    #[command(visible_alias = "ls")]
    List,
    /// Remove a base disk image by digest.
    Rm {
        /// Digest identifier to remove.
        digest: String,
    },
}

/// Output format for list/info commands.
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub(crate) enum OutputFormat {
    /// Human-readable table.
    #[default]
    Table,
    /// Machine-readable JSON.
    Json,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = Cli::parse().dispatch().await {
        eprintln!("bux: {e:#}");
        std::process::exit(1);
    }
}

impl Cli {
    async fn dispatch(self) -> Result<()> {
        match self.command {
            Command::Run(args) => args.run().await,
            Command::Create(args) => args.run().await,
            Command::Exec(args) => vm::exec(args).await,
            Command::Logs(ref args) => logs::logs(args),
            Command::Ps(ref args) => vm::ps(args),
            Command::Stop(args) => vm::stop(args).await,
            Command::Kill(ref args) => vm::kill(args),
            Command::Rm(ref args) => vm::rm(args),
            Command::Inspect(ref args) => vm::inspect(args),
            Command::Cp(args) => vm::cp(args).await,
            Command::Wait(args) => vm::wait(args).await,
            Command::Prune => vm::prune(),
            Command::Rename(ref args) => vm::rename(args),
            Command::Restart(args) => vm::restart(args).await,
            Command::Stats(ref args) => vm::stats(args).await,
            Command::Snapshot { action } => snapshot_cmd(action).await,
            Command::Clone(args) => vm::clone_box(args).await,
            Command::Export(ref args) => vm::export(args),
            Command::Pull { image } => pull(&image).await,
            Command::Images { format } => images(format),
            Command::Rmi { images } => rmi(&images),
            Command::Info { format } => system_info(format),
            Command::System { action } => match action {
                SystemAction::Info { format } => system_info(format),
                SystemAction::Reset => system_reset(),
            },
            Command::Volume { action } => volume::dispatch(action),
            Command::Sweep => sweep_cmd(),
            Command::Disk { action } => disk_cmd(action),
            Command::Completion { shell } => {
                clap_complete::generate(shell, &mut Self::command(), "bux", &mut std::io::stdout());
                Ok(())
            }
        }
    }
}

async fn snapshot_cmd(action: SnapshotAction) -> Result<()> {
    let rt = vm::open_runtime()?;
    match action {
        SnapshotAction::Create { vm, name } => {
            let handle = rt.get(&vm)?;
            let info = handle.create_snapshot(name.as_deref()).await?;
            println!("{}", info.id);
        }
        SnapshotAction::List { vm } => {
            let handle = rt.get(&vm)?;
            let snaps = handle.list_snapshots()?;
            if snaps.is_empty() {
                println!("No snapshots.");
            } else {
                println!("{:<14} {:<20} {:>12}", "ID", "NAME", "SIZE");
                for s in &snaps {
                    println!(
                        "{:<14} {:<20} {:>12}",
                        s.id,
                        s.name.as_deref().unwrap_or("-"),
                        human_size(s.disk_bytes),
                    );
                }
            }
        }
        SnapshotAction::Rm { id } => {
            rt.delete_snapshot(&id)?;
            println!("{id}");
        }
        SnapshotAction::Restore { id, name } => {
            let handle = rt.restore(&id, name).await?;
            println!("{}", handle.info().id);
        }
    }
    Ok(())
}

async fn pull(image: &str) -> Result<()> {
    let rt = vm::open_runtime()?;
    let result = rt.pull(image, |msg| eprintln!("{msg}")).await?;
    println!("{}", result.reference);
    Ok(())
}

fn images(format: OutputFormat) -> Result<()> {
    let rt = vm::open_runtime()?;
    let list = rt.images()?;

    if matches!(format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&list)?);
        return Ok(());
    }

    if list.is_empty() {
        println!("No images.");
        return Ok(());
    }
    println!("{:<50} {:<20} {:>10}", "REFERENCE", "DIGEST", "SIZE");
    for img in &list {
        let short = &img.digest[..img.digest.len().min(19)];
        println!(
            "{:<50} {:<20} {:>10}",
            img.reference,
            short,
            human_size(img.size)
        );
    }
    Ok(())
}

fn rmi(refs: &[String]) -> Result<()> {
    let rt = vm::open_runtime()?;
    for r in refs {
        rt.remove_image(r)?;
        println!("{r}");
    }
    Ok(())
}

/// Environment variables that affect host capture / paths (documented for operators).
const CAPTURE_ENV: &[(&str, &str)] = &[
    (
        "BUX_HOME",
        "Runtime data directory (default: platform data dir / bux)",
    ),
    ("BUX_SHIM_PATH", "Override path to the bux-shim binary"),
    (
        "BUX_GUEST_PATH",
        "Absolute path to a static Linux bux-guest ELF (Runtime inject)",
    ),
    (
        "BUX_GUEST_DIR",
        "Directory containing prebuilt bux-guest Linux binaries (CLI build)",
    ),
    (
        "PATH",
        "Used to locate bux-shim, bwrap, sandbox-exec, go (gvproxy build)",
    ),
];

fn system_info(format: OutputFormat) -> Result<()> {
    let host = bux::HostInfo::probe();
    let data_dir = bux::default_data_dir();

    if matches!(format, OutputFormat::Json) {
        let env: serde_json::Map<String, serde_json::Value> = CAPTURE_ENV
            .iter()
            .map(|(k, doc)| {
                (
                    (*k).to_owned(),
                    serde_json::json!({
                        "doc": doc,
                        "set": std::env::var_os(k).is_some(),
                    }),
                )
            })
            .collect();
        let obj = serde_json::json!({
            "data_dir": data_dir,
            "host": host,
            "env": env,
            "protocol_version": bux_proto::PROTOCOL_VERSION,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
        return Ok(());
    }

    println!("data dir:     {}", data_dir.display());
    if let Some(n) = host.max_vcpus {
        println!("max vCPUs:    {n}");
    }
    let label = if host.krun_features.is_empty() {
        "none".to_owned()
    } else {
        host.krun_features.join(", ")
    };
    println!("libkrun:      {label}");
    match host.nested_virt {
        Some(true) => println!("nested virt:  supported"),
        Some(false) => println!("nested virt:  not supported"),
        None => {}
    }
    println!("virtualization: {}", yn(host.virtualization));
    println!("namespaces:     {} (bwrap)", yn(host.namespaces));
    println!("landlock:       {}", yn(host.landlock));
    println!("seccomp:        {}", yn(host.seccomp));
    println!("cgroups v2:     {}", yn(host.cgroups));
    println!("MAC:            {}", yn(host.mandatory_access_control));
    println!("protocol:       v{}", bux_proto::PROTOCOL_VERSION);
    if !host.isolation_warnings.is_empty() {
        println!("warnings:");
        for w in &host.isolation_warnings {
            println!("  - {w}");
        }
    }
    println!("capture env:");
    for (k, doc) in CAPTURE_ENV {
        let mark = if std::env::var_os(k).is_some() {
            "set"
        } else {
            "-"
        };
        println!("  {k:<20} [{mark}]  {doc}");
    }
    Ok(())
}

const fn yn(v: bool) -> &'static str {
    if v { "yes" } else { "no" }
}

fn sweep_cmd() -> Result<()> {
    let rt = vm::open_runtime()?;
    let report = rt.sweep()?;
    println!("stopped={} deleted={}", report.stopped, report.deleted);
    Ok(())
}

#[cfg(unix)]
fn system_reset() -> Result<()> {
    bux::Runtime::reset(bux::default_data_dir())?;
    println!("reset {}", bux::default_data_dir().display());
    Ok(())
}

#[cfg(not(unix))]
fn system_reset() -> Result<()> {
    anyhow::bail!("system reset requires Linux or macOS")
}

#[cfg(unix)]
fn disk_cmd(action: DiskAction) -> Result<()> {
    let rt = vm::open_runtime()?;

    match action {
        DiskAction::Create { rootfs, digest } => {
            let path = rt.create_base(std::path::Path::new(&rootfs), &digest)?;
            println!("{}", path.display());
        }
        DiskAction::List => {
            let bases = rt.list_bases()?;
            if bases.is_empty() {
                println!("No disk images.");
            } else {
                for d in &bases {
                    let path = rt.base_path(d);
                    let size = std::fs::metadata(&path).map_or(0, |m| m.len());
                    println!("{:<40} {:>10}", d, human_size(size));
                }
            }
        }
        DiskAction::Rm { digest } => {
            rt.remove_base(&digest)?;
            println!("{digest}");
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn disk_cmd(_action: DiskAction) -> Result<()> {
    anyhow::bail!("Disk management requires Linux or macOS")
}

/// Formats bytes into a human-readable size string.
#[allow(clippy::cast_precision_loss, reason = "display-only float conversion")]
fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    for unit in UNITS {
        if size < 1024.0 {
            return format!("{size:.1} {unit}");
        }
        size /= 1024.0;
    }
    format!("{size:.1} TB")
}
