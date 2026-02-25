//! CLI for the bux micro-VM sandbox.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_docs_in_private_items
)]

use anyhow::{Context, Result};
use bux::{LogLevel, Vm};
use clap::{Parser, Subcommand};

/// Embedded micro-VM sandbox for running AI agents.
#[derive(Parser, Debug)]
#[command(name = "bux", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start a micro-VM with the given root filesystem.
    Run(RunArgs),
    /// Query the maximum number of vCPUs supported by the hypervisor.
    MaxVcpus,
}

#[derive(clap::Args, Debug)]
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

    /// libkrun log level.
    #[arg(long, default_value = "info")]
    log_level: LogLevel,

    /// Command and arguments to run inside the VM (after --).
    #[arg(last = true)]
    command: Vec<String>,
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = dispatch(cli) {
        eprintln!("bux: {e:#}");
        std::process::exit(1);
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run(args) => run(args),
        Command::MaxVcpus => {
            println!("{}", Vm::max_vcpus()?);
            Ok(())
        }
    }
}

fn run(args: RunArgs) -> Result<()> {
    let mut builder = Vm::builder()
        .vcpus(args.cpus)
        .ram_mib(args.ram)
        .root(args.root)
        .log_level(args.log_level);

    if !args.command.is_empty() {
        let exec_args: Vec<&str> = args.command[1..].iter().map(String::as_str).collect();
        builder = builder.exec(&args.command[0], &exec_args);
    }

    if !args.envs.is_empty() {
        let env_refs: Vec<&str> = args.envs.iter().map(String::as_str).collect();
        builder = builder.env(&env_refs);
    }

    if let Some(workdir) = args.workdir {
        builder = builder.workdir(workdir);
    }

    for port in args.ports {
        builder = builder.port(port);
    }

    for vol in &args.volumes {
        let (tag, path) = vol
            .split_once(':')
            .context("volume must be in TAG:HOST_PATH format")?;
        builder = builder.virtiofs(tag, path);
    }

    builder.build()?.start()?;
    Ok(())
}
