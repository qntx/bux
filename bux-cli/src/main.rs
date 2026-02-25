//! CLI for the bux micro-VM sandbox.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_docs_in_private_items
)]

use anyhow::{Context, Result};
use bux::{Feature, LogLevel, Vm};
use clap::{Parser, Subcommand};

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
    Images,
    /// Remove a locally stored image.
    Rmi {
        /// Image reference to remove.
        image: String,
    },
    /// Display system capabilities and libkrun feature support.
    Info,
}

#[derive(clap::Args)]
struct RunArgs {
    /// OCI image reference (e.g., ubuntu:latest). Auto-pulled if not cached.
    #[arg(conflicts_with = "root")]
    image: Option<String>,

    /// Explicit root filesystem path (alternative to image).
    #[arg(long)]
    root: Option<String>,

    /// Number of virtual CPUs.
    #[arg(long, default_value_t = 1)]
    cpus: u8,

    /// RAM size in MiB.
    #[arg(long, default_value_t = 512)]
    ram: u32,

    /// Working directory inside the VM.
    #[arg(long)]
    workdir: Option<String>,

    /// TCP port mapping (host:guest). Repeatable.
    #[arg(long = "port", short = 'p')]
    ports: Vec<String>,

    /// Share a host directory via virtio-fs (tag:host_path). Repeatable.
    #[arg(long = "volume", short = 'v')]
    volumes: Vec<String>,

    /// Environment variable (KEY=VALUE). Repeatable.
    #[arg(long = "env", short = 'e')]
    envs: Vec<String>,

    /// Set UID inside the VM.
    #[arg(long)]
    uid: Option<u32>,

    /// Set GID inside the VM.
    #[arg(long)]
    gid: Option<u32>,

    /// Resource limit (RESOURCE=RLIM_CUR:RLIM_MAX). Repeatable.
    #[arg(long)]
    rlimit: Vec<String>,

    /// Enable nested virtualization (macOS only).
    #[arg(long)]
    nested_virt: bool,

    /// Enable virtio-snd audio device.
    #[arg(long)]
    snd: bool,

    /// Redirect console output to a file.
    #[arg(long)]
    console_output: Option<String>,

    /// libkrun log level.
    #[arg(long, default_value = "info")]
    log_level: LogLevel,

    /// Command and arguments to run inside the VM (after --).
    #[arg(last = true)]
    command: Vec<String>,
}

fn main() {
    if let Err(e) = Cli::parse().dispatch() {
        eprintln!("bux: {e:#}");
        std::process::exit(1);
    }
}

impl Cli {
    fn dispatch(self) -> Result<()> {
        match self.command {
            Command::Run(args) => args.run(),
            Command::Pull { image } => pull(&image),
            Command::Images => images(),
            Command::Rmi { image } => rmi(&image),
            Command::Info => info(),
        }
    }
}

impl RunArgs {
    fn run(self) -> Result<()> {
        // Resolve rootfs: from OCI image or explicit --root path.
        let (rootfs, oci_config) = self.resolve_rootfs()?;

        let mut builder = Vm::builder()
            .vcpus(self.cpus)
            .ram_mib(self.ram)
            .root(&rootfs)
            .log_level(self.log_level);

        // Working directory: CLI flag > OCI config > none.
        if let Some(ref workdir) = self.workdir {
            builder = builder.workdir(workdir);
        } else if let Some(ref cfg) = oci_config
            && let Some(ref wd) = cfg.working_dir
            && !wd.is_empty()
        {
            builder = builder.workdir(wd);
        }

        // Command: CLI args > OCI Entrypoint+Cmd > none.
        if !self.command.is_empty() {
            let args: Vec<&str> = self.command[1..].iter().map(String::as_str).collect();
            builder = builder.exec(&self.command[0], &args);
        } else if let Some(ref cfg) = oci_config {
            let resolved = resolve_oci_command(cfg);
            if !resolved.is_empty() {
                let args: Vec<&str> = resolved[1..].iter().map(String::as_str).collect();
                builder = builder.exec(&resolved[0], &args);
            }
        }

        // Environment: merge OCI defaults + CLI overrides.
        let mut all_env: Vec<String> = Vec::new();
        if let Some(ref cfg) = oci_config
            && let Some(ref env) = cfg.env
        {
            all_env.extend(env.iter().cloned());
        }
        all_env.extend(self.envs.iter().cloned());
        if !all_env.is_empty() {
            let refs: Vec<&str> = all_env.iter().map(String::as_str).collect();
            builder = builder.env(&refs);
        }

        for port in self.ports {
            builder = builder.port(port);
        }
        for vol in &self.volumes {
            let (tag, path) = vol
                .split_once(':')
                .context("volume must be in TAG:HOST_PATH format")?;
            builder = builder.virtiofs(tag, path);
        }
        if let Some(uid) = self.uid {
            builder = builder.uid(uid);
        }
        if let Some(gid) = self.gid {
            builder = builder.gid(gid);
        }
        for rl in self.rlimit {
            builder = builder.rlimit(rl);
        }
        if self.nested_virt {
            builder = builder.nested_virt(true);
        }
        if self.snd {
            builder = builder.snd_device(true);
        }
        if let Some(path) = self.console_output {
            builder = builder.console_output(path);
        }

        builder.build()?.start()?;
        Ok(())
    }

    /// Resolves rootfs path and optional OCI config from image or --root flag.
    fn resolve_rootfs(&self) -> Result<(String, Option<bux_oci::ImageConfig>)> {
        match (&self.image, &self.root) {
            (Some(image), None) => {
                let mut oci = bux_oci::Oci::open()?;
                let result = oci.ensure(image, |msg| eprintln!("{msg}"))?;
                let path = result.rootfs.to_string_lossy().into_owned();
                Ok((path, result.config))
            }
            (None, Some(root)) => Ok((root.clone(), None)),
            (None, None) => anyhow::bail!("specify an image or --root <path>"),
            _ => unreachable!("clap conflicts_with prevents this"),
        }
    }
}

/// Resolves the command from OCI config: ENTRYPOINT + CMD.
fn resolve_oci_command(cfg: &bux_oci::ImageConfig) -> Vec<String> {
    let mut parts = Vec::new();
    if let Some(ref ep) = cfg.entrypoint {
        parts.extend(ep.iter().cloned());
    }
    if let Some(ref cmd) = cfg.cmd {
        parts.extend(cmd.iter().cloned());
    }
    parts
}

fn pull(image: &str) -> Result<()> {
    let mut oci = bux_oci::Oci::open()?;
    let result = oci.pull(image, |msg| eprintln!("{msg}"))?;
    println!("{}", result.reference);
    Ok(())
}

fn images() -> Result<()> {
    let oci = bux_oci::Oci::open()?;
    let list = oci.images()?;
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

fn info() -> Result<()> {
    println!("max vCPUs: {}", Vm::max_vcpus()?);

    let supported: Vec<&str> = FEATURES
        .iter()
        .filter(|(f, _)| Vm::has_feature(*f).unwrap_or(false))
        .map(|(_, name)| *name)
        .collect();
    let label = if supported.is_empty() {
        "none".into()
    } else {
        supported.join(", ")
    };
    println!("features:  {label}");

    match Vm::check_nested_virt() {
        Ok(true) => println!("nested:    supported"),
        Ok(false) => println!("nested:    not supported"),
        Err(_) => {}
    }

    Ok(())
}
