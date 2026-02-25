//! CLI for the bux micro-VM sandbox.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_docs_in_private_items
)]

use anyhow::{Context, Result};
use bux::{Feature, LogLevel, Vm};
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
}

/// Output format for list/info commands.
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
enum OutputFormat {
    /// Human-readable table.
    #[default]
    Table,
    /// Machine-readable JSON.
    Json,
}

#[derive(clap::Args)]
struct RunArgs {
    /// OCI image reference (e.g., ubuntu:latest). Auto-pulled if not cached.
    #[arg(conflicts_with = "root")]
    image: Option<String>,

    /// Explicit root filesystem path (alternative to image).
    #[arg(long)]
    root: Option<String>,

    /// Assign a name to the VM.
    #[arg(long)]
    name: Option<String>,

    /// Run in background and print VM ID.
    #[arg(long, short = 'd')]
    detach: bool,

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
            Command::Ps { format } => ps(format),
            Command::Stop { id } => vm_stop(&id).await,
            Command::Kill { id } => vm_kill(&id),
            Command::Rm { id } => vm_rm(&id),
            Command::Exec { id, command } => vm_exec(&id, command).await,
            Command::Inspect { id } => vm_inspect(&id),
            Command::Cp { src, dst } => vm_cp(&src, &dst).await,
        }
    }
}

impl RunArgs {
    async fn run(self) -> Result<()> {
        let (rootfs, cfg) = self.resolve_rootfs().await?;

        // Save fields needed after partial moves below.
        let image = self.image.clone();
        let name = self.name;
        let detach = self.detach;

        let mut b = Vm::builder()
            .vcpus(self.cpus)
            .ram_mib(self.ram)
            .root(&rootfs)
            .log_level(self.log_level);

        // Working directory: CLI flag > OCI config > none.
        let workdir = self
            .workdir
            .or_else(|| cfg.as_ref()?.working_dir.clone())
            .filter(|w| !w.is_empty());
        if let Some(ref wd) = workdir {
            b = b.workdir(wd);
        }

        // Command: CLI args > OCI ENTRYPOINT+CMD > none.
        let cmd = if self.command.is_empty() {
            cfg.as_ref().map(oci_command).unwrap_or_default()
        } else {
            self.command
        };
        if !cmd.is_empty() {
            let args: Vec<&str> = cmd[1..].iter().map(String::as_str).collect();
            b = b.exec(&cmd[0], &args);
        }

        // Environment: OCI defaults + CLI overrides.
        let env: Vec<String> = cfg
            .as_ref()
            .and_then(|c| c.env.clone())
            .unwrap_or_default()
            .into_iter()
            .chain(self.envs)
            .collect();
        if !env.is_empty() {
            let refs: Vec<&str> = env.iter().map(String::as_str).collect();
            b = b.env(&refs);
        }

        // Ports, volumes, resource limits.
        for p in self.ports {
            b = b.port(p);
        }
        for vol in &self.volumes {
            let (tag, path) = vol
                .split_once(':')
                .context("volume must be in TAG:HOST_PATH format")?;
            b = b.virtiofs(tag, path);
        }
        for rl in self.rlimit {
            b = b.rlimit(rl);
        }

        // Optional overrides.
        if let Some(uid) = self.uid {
            b = b.uid(uid);
        }
        if let Some(gid) = self.gid {
            b = b.gid(gid);
        }
        if self.nested_virt {
            b = b.nested_virt(true);
        }
        if self.snd {
            b = b.snd_device(true);
        }
        if let Some(path) = self.console_output {
            b = b.console_output(path);
        }

        spawn_vm(b, image, name, detach).await
    }

    /// Resolves rootfs path and optional OCI config from image or --root flag.
    async fn resolve_rootfs(&self) -> Result<(String, Option<bux_oci::ImageConfig>)> {
        match (&self.image, &self.root) {
            (Some(img), None) => {
                let mut oci = bux_oci::Oci::open()?;
                let r = oci.ensure(img, |msg| eprintln!("{msg}")).await?;
                Ok((r.rootfs.to_string_lossy().into_owned(), r.config))
            }
            (None, Some(root)) => Ok((root.clone(), None)),
            (None, None) => anyhow::bail!("specify an image or --root <path>"),
            _ => unreachable!("clap conflicts_with prevents this"),
        }
    }
}

/// Resolves ENTRYPOINT + CMD from an OCI image config.
fn oci_command(cfg: &bux_oci::ImageConfig) -> Vec<String> {
    let mut parts = Vec::new();
    if let Some(ref ep) = cfg.entrypoint {
        parts.extend(ep.iter().cloned());
    }
    if let Some(ref cmd) = cfg.cmd {
        parts.extend(cmd.iter().cloned());
    }
    parts
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

/// Spawns a VM via the runtime for managed lifecycle.
#[cfg(unix)]
async fn spawn_vm(
    builder: bux::VmBuilder,
    image: Option<String>,
    name: Option<String>,
    detach: bool,
) -> Result<()> {
    let rt = open_runtime()?;
    let handle = rt.spawn(builder, image, name).await?;

    let id = &handle.state().id;
    if detach {
        println!(
            "{}",
            handle.state().name.as_deref().unwrap_or(id)
        );
        return Ok(());
    }

    // Foreground: print ID and wait for VM to exit.
    eprintln!("{id}");
    while handle.is_alive() {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    Ok(())
}

/// Spawns a VM (non-unix stub).
#[cfg(not(unix))]
#[allow(clippy::unused_async)]
async fn spawn_vm(
    _builder: bux::VmBuilder,
    _image: Option<String>,
    _name: Option<String>,
    _detach: bool,
) -> Result<()> {
    anyhow::bail!("VM execution requires Linux or macOS")
}

#[cfg(unix)]
fn open_runtime() -> Result<bux::Runtime> {
    let data_dir = dirs::data_dir()
        .context("no platform data directory")?
        .join("bux");
    Ok(bux::Runtime::open(data_dir)?)
}

#[cfg(unix)]
fn ps(format: OutputFormat) -> Result<()> {
    let rt = open_runtime()?;
    let vms = rt.list()?;

    if matches!(format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&vms)?);
        return Ok(());
    }

    if vms.is_empty() {
        println!("No VMs.");
        return Ok(());
    }
    println!(
        "{:<14} {:<16} {:<8} {:<10} {}",
        "ID", "NAME", "PID", "STATUS", "IMAGE"
    );
    for vm in &vms {
        let name = vm.name.as_deref().unwrap_or("-");
        let image = vm.image.as_deref().unwrap_or("-");
        let status = match vm.status {
            bux::Status::Running => "running",
            bux::Status::Stopped => "stopped",
            _ => "unknown",
        };
        println!(
            "{:<14} {:<16} {:<8} {:<10} {}",
            vm.id, name, vm.pid, status, image
        );
    }
    Ok(())
}

#[cfg(unix)]
async fn vm_stop(id: &str) -> Result<()> {
    let rt = open_runtime()?;
    let mut handle = rt.get(id)?;
    handle.stop().await?;
    eprintln!("Stopped: {}", handle.state().id);
    Ok(())
}

#[cfg(unix)]
fn vm_kill(id: &str) -> Result<()> {
    let rt = open_runtime()?;
    let mut handle = rt.get(id)?;
    handle.kill()?;
    eprintln!("Killed: {}", handle.state().id);
    Ok(())
}

#[cfg(unix)]
fn vm_rm(id: &str) -> Result<()> {
    let rt = open_runtime()?;
    rt.remove(id)?;
    eprintln!("Removed: {id}");
    Ok(())
}

#[cfg(unix)]
async fn vm_exec(id: &str, command: Vec<String>) -> Result<()> {
    use std::io::Write;

    let rt = open_runtime()?;
    let handle = rt.get(id)?;

    let (cmd, args) = command.split_first().context("exec requires a command")?;
    let req = bux::ExecReq::new(cmd).args(args.to_vec());

    let code = handle
        .exec_stream(req, |event| match event {
            bux::ExecEvent::Stdout(d) => {
                let _ = std::io::stdout().write_all(&d);
            }
            bux::ExecEvent::Stderr(d) => {
                let _ = std::io::stderr().write_all(&d);
            }
        })
        .await?;

    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

#[cfg(unix)]
fn vm_inspect(id: &str) -> Result<()> {
    let rt = open_runtime()?;
    let handle = rt.get(id)?;
    println!("{}", serde_json::to_string_pretty(handle.state())?);
    Ok(())
}

/// Parses `id:path` guest reference. Returns `(id, guest_path)`.
#[cfg(unix)]
fn parse_guest_ref(s: &str) -> Option<(&str, &str)> {
    let colon = s.find(':')?;
    if colon == 0 { return None; }
    Some((&s[..colon], &s[colon + 1..]))
}

#[cfg(unix)]
async fn vm_cp(src: &str, dst: &str) -> Result<()> {
    let rt = open_runtime()?;

    match (parse_guest_ref(src), parse_guest_ref(dst)) {
        // guest → host
        (Some((id, guest_path)), None) => {
            let handle = rt.get(id)?;
            let data = handle.read_file(guest_path).await?;
            std::fs::write(dst, &data)?;
        }
        // host → guest
        (None, Some((id, guest_path))) => {
            let handle = rt.get(id)?;
            let data = std::fs::read(src)?;
            handle.write_file(guest_path, &data, 0o644).await?;
        }
        _ => anyhow::bail!("exactly one of src/dst must use <id>:<path> format"),
    }
    Ok(())
}

// Non-unix stubs — VM commands require libkrun (Linux/macOS).
#[cfg(not(unix))]
macro_rules! unix_only_stub {
    (sync: $($name:ident($($arg:ident: $ty:ty),*));+ $(;)?) => {
        $(
            fn $name($(_: $ty),*) -> Result<()> {
                anyhow::bail!("VM management requires Linux or macOS")
            }
        )+
    };
    (async: $($name:ident($($arg:ident: $ty:ty),*));+ $(;)?) => {
        $(
            async fn $name($(_: $ty),*) -> Result<()> {
                anyhow::bail!("VM management requires Linux or macOS")
            }
        )+
    };
}

#[cfg(not(unix))]
unix_only_stub! {
    sync:
    ps(format: OutputFormat);
    vm_kill(id: &str);
    vm_rm(id: &str);
    vm_inspect(id: &str);
}

#[cfg(not(unix))]
unix_only_stub! {
    async:
    vm_stop(id: &str);
    vm_exec(id: &str, command: Vec<String>);
    vm_cp(src: &str, dst: &str);
}
