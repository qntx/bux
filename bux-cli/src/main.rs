//! CLI for the bux micro-VM sandbox.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_docs_in_private_items
)]

mod run;
mod vm;

use anyhow::Result;
use bux::{Feature, Vm};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use run::RunArgs;

#[derive(Parser)]
#[command(name = "bux", version, about = "Micro-VM sandbox powered by libkrun")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a command in an isolated micro-VM.
    Run(Box<RunArgs>),
    /// Pull an OCI image from a registry.
    Pull {
        /// Image reference (e.g., ubuntu:latest, ghcr.io/org/app:v1).
        image: String,
    },
    /// List locally stored images.
    Images {
        /// Output format.
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },
    /// Remove a locally stored image.
    Rmi {
        /// Image reference to remove.
        image: String,
    },
    /// Display system capabilities and libkrun feature support.
    Info {
        /// Output format.
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },
    /// Generate shell completion scripts.
    Completion {
        /// Target shell.
        shell: Shell,
    },
    /// List managed VMs.
    Ps {
        /// Output format.
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },
    /// Stop a running VM (graceful shutdown).
    Stop {
        /// VM ID or prefix.
        id: String,
    },
    /// Force-kill a running VM.
    Kill {
        /// VM ID or prefix.
        id: String,
    },
    /// Remove a stopped VM.
    Rm {
        /// VM ID or prefix.
        id: String,
    },
    /// Execute a command inside a running VM.
    Exec {
        /// VM ID or prefix.
        id: String,
        /// Command and arguments (after --).
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Show detailed information about a VM.
    Inspect {
        /// VM ID or prefix.
        id: String,
    },
    /// Copy files between host and a running VM.
    ///
    /// Use `<id>:<path>` to refer to a guest path.
    Cp {
        /// Source (host path or `<id>:<guest_path>`).
        src: String,
        /// Destination (host path or `<id>:<guest_path>`).
        dst: String,
    },
    /// Manage ext4 disk images.
    Disk {
        #[command(subcommand)]
        action: DiskAction,
    },
}

/// Subcommands for `bux disk`.
#[derive(Subcommand)]
enum DiskAction {
    /// Create a base ext4 image from an OCI rootfs directory.
    Create {
        /// Path to the rootfs directory.
        rootfs: String,
        /// Digest identifier for the base image.
        digest: String,
    },
    /// List all base disk images.
    List,
    /// Remove a base disk image by digest.
    Rm {
        /// Digest identifier of the base image to remove.
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
            Command::Pull { image } => pull(&image).await,
            Command::Images { format } => images(format),
            Command::Rmi { image } => rmi(&image),
            Command::Info { format } => info(format),
            Command::Completion { shell } => {
                clap_complete::generate(shell, &mut Self::command(), "bux", &mut std::io::stdout());
                Ok(())
            }
            Command::Ps { format } => vm::ps(format),
            Command::Stop { id } => vm::stop(&id).await,
            Command::Kill { id } => vm::kill(&id),
            Command::Rm { id } => vm::rm(&id),
            Command::Exec { id, command } => vm::exec(&id, command).await,
            Command::Inspect { id } => vm::inspect(&id),
            Command::Cp { src, dst } => vm::cp(&src, &dst).await,
            Command::Disk { action } => disk_cmd(action),
        }
    }
}

#[cfg(unix)]
fn disk_cmd(action: DiskAction) -> Result<()> {
    let data_dir = dirs::data_dir()
        .ok_or_else(|| anyhow::anyhow!("no platform data directory"))?
        .join("bux");
    let dm = bux::DiskManager::open(&data_dir)?;

    match action {
        DiskAction::Create { rootfs, digest } => {
            let path = dm.create_base(std::path::Path::new(&rootfs), &digest)?;
            println!("{}", path.display());
        }
        DiskAction::List => {
            let bases = dm.list_bases()?;
            if bases.is_empty() {
                println!("No disk images.");
            } else {
                for d in &bases {
                    let path = dm.base_path(d);
                    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    println!("{:<40} {:>10}", d, human_size(size));
                }
            }
        }
        DiskAction::Rm { digest } => {
            dm.remove_base(&digest)?;
            eprintln!("Removed: {digest}");
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn disk_cmd(_action: DiskAction) -> Result<()> {
    anyhow::bail!("Disk management requires Linux or macOS")
}

async fn pull(image: &str) -> Result<()> {
    let mut oci = bux_oci::Oci::open()?;
    let result = oci.pull(image, |msg| eprintln!("{msg}")).await?;
    println!("{}", result.reference);
    Ok(())
}

fn images(format: OutputFormat) -> Result<()> {
    let oci = bux_oci::Oci::open()?;
    let list = oci.images()?;

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
        let short_digest = &img.digest[..std::cmp::min(19, img.digest.len())];
        println!(
            "{:<50} {:<20} {:>10}",
            img.reference,
            short_digest,
            human_size(img.size)
        );
    }
    Ok(())
}

fn rmi(image: &str) -> Result<()> {
    let oci = bux_oci::Oci::open()?;
    oci.remove(image)?;
    eprintln!("Removed: {image}");
    Ok(())
}

const FEATURES: &[(Feature, &str)] = &[
    (Feature::Net, "net"),
    (Feature::Blk, "blk"),
    (Feature::Gpu, "gpu"),
    (Feature::Snd, "snd"),
    (Feature::Input, "input"),
    (Feature::Efi, "efi"),
    (Feature::Tee, "tee"),
    (Feature::AmdSev, "amd-sev"),
    (Feature::IntelTdx, "intel-tdx"),
    (Feature::AwsNitro, "aws-nitro"),
    (Feature::VirglResourceMap2, "virgl-resource-map2"),
];

fn info(format: OutputFormat) -> Result<()> {
    let max_vcpus = Vm::max_vcpus()?;
    let supported: Vec<&str> = FEATURES
        .iter()
        .filter(|(f, _)| Vm::has_feature(*f).unwrap_or(false))
        .map(|(_, name)| *name)
        .collect();
    let nested = Vm::check_nested_virt().ok();

    if matches!(format, OutputFormat::Json) {
        let obj = serde_json::json!({
            "max_vcpus": max_vcpus,
            "features": supported,
            "nested_virt": nested,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
        return Ok(());
    }

    println!("max vCPUs: {max_vcpus}");
    let label = if supported.is_empty() {
        "none"
    } else {
        &supported.join(", ")
    };
    println!("features:  {label}");
    match nested {
        Some(true) => println!("nested:    supported"),
        Some(false) => println!("nested:    not supported"),
        None => {}
    }

    Ok(())
}

/// Formats bytes into a human-readable size string.
#[allow(clippy::cast_precision_loss)]
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
