//! `bux run` — spawn a micro-VM from an OCI image or rootfs.

use anyhow::{Context, Result};
use bux::{LogLevel, Vm};

/// Arguments for the `bux run` subcommand.
#[derive(clap::Args)]
pub struct RunArgs {
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

    /// Automatically remove the VM when it stops.
    #[arg(long)]
    rm: bool,

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

impl RunArgs {
    pub async fn run(self) -> Result<()> {
        let (rootfs, cfg) = self.resolve_rootfs().await?;

        // Save fields needed after partial moves below.
        let image = self.image.clone();
        let name = self.name;
        let detach = self.detach;
        let auto_remove = self.rm;

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

        spawn_vm(b, image, name, detach, auto_remove).await
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

/// Spawns a VM via the runtime for managed lifecycle.
#[cfg(unix)]
async fn spawn_vm(
    mut builder: bux::VmBuilder,
    image: Option<String>,
    name: Option<String>,
    detach: bool,
    auto_remove: bool,
) -> Result<()> {
    let rt = crate::vm::open_runtime()?;
    let handle = rt.spawn(builder, image, name, auto_remove).await?;

    let id = &handle.state().id;
    if detach {
        println!("{}", handle.state().name.as_deref().unwrap_or(id));
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
    _auto_remove: bool,
) -> Result<()> {
    anyhow::bail!("VM execution requires Linux or macOS")
}
