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
    /// Display system capabilities and libkrun feature support.
    Info,
}

#[derive(clap::Args)]
struct RunArgs {
    /// Root filesystem path.
    #[arg(long)]
    root: String,

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
            Command::Info => info(),
        }
    }
}

impl RunArgs {
    fn run(self) -> Result<()> {
        let mut builder = Vm::builder()
            .vcpus(self.cpus)
            .ram_mib(self.ram)
            .root(&self.root)
            .log_level(self.log_level);

        if let Some(workdir) = self.workdir {
            builder = builder.workdir(workdir);
        }

        if !self.command.is_empty() {
            let args: Vec<&str> = self.command[1..].iter().map(String::as_str).collect();
            builder = builder.exec(&self.command[0], &args);
        }

        if !self.envs.is_empty() {
            let refs: Vec<&str> = self.envs.iter().map(String::as_str).collect();
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
