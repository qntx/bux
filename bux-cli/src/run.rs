//! `bux run` — create and run a command in a new micro-VM.
//!
//! Follows the Docker CLI convention: `bux run [OPTIONS] IMAGE [COMMAND] [ARG...]`

use anyhow::{Context, Result};
use bux::{LogLevel, Vm};

/// Arguments for `bux run`.
///
/// Usage: `bux run [OPTIONS] IMAGE [COMMAND] [ARG...]`
#[derive(clap::Args)]
#[command(trailing_var_arg = true)]
pub struct RunArgs {
    /// OCI image reference (e.g., ubuntu:latest). Conflicts with --root/--root-disk.
    #[arg(conflicts_with_all = ["root", "root_disk"], required_unless_present_any = ["root", "root_disk"])]
    image: Option<String>,

    /// Explicit root filesystem directory path.
    #[arg(long, conflicts_with = "root_disk")]
    root: Option<String>,

    /// Root filesystem disk image path (ext4 raw).
    #[arg(long, conflicts_with = "root")]
    root_disk: Option<String>,

    /// Auto-create ext4 disk image from OCI rootfs.
    #[arg(long)]
    disk: bool,

    /// Assign a name to the VM.
    #[arg(long)]
    name: Option<String>,

    /// Run in background and print VM ID.
    #[arg(short = 'd', long)]
    detach: bool,

    /// Automatically remove the VM when it stops.
    #[arg(long)]
    rm: bool,

    /// Number of virtual CPUs.
    #[arg(long, default_value_t = 1)]
    cpus: u8,

    /// Memory in MiB.
    #[arg(long, short = 'm', default_value_t = 512)]
    memory: u32,

    /// Working directory inside the VM.
    #[arg(short = 'w', long)]
    workdir: Option<String>,

    /// Publish a port (format: hostPort:guestPort[/tcp|udp]).
    #[arg(short = 'p', long = "publish")]
    publish: Vec<String>,

    /// Bind mount a volume (format: hostPath:guestPath[:ro]).
    #[arg(short = 'v', long = "volume")]
    volume: Vec<String>,

    /// Set environment variables.
    #[arg(short = 'e', long = "env")]
    env: Vec<String>,

    /// Read environment variables from a file.
    #[arg(long)]
    env_file: Vec<String>,

    /// User inside the VM (format: uid[:gid]).
    #[arg(short = 'u', long = "user")]
    user: Option<String>,

    /// Keep STDIN open even if not attached.
    #[arg(short = 'i', long)]
    interactive: bool,

    /// Allocate a pseudo-TTY.
    #[arg(short = 't', long)]
    tty: bool,

    /// Override the default ENTRYPOINT of the image.
    #[arg(long)]
    entrypoint: Option<String>,

    /// Set ulimits (format: type=soft:hard).
    #[arg(long)]
    ulimit: Vec<String>,

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

    /// Command and arguments to run inside the VM.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

impl RunArgs {
    pub async fn run(self) -> Result<()> {
        let (rootfs, oci_cfg) = self.resolve_rootfs().await?;

        let image = self.image.clone();
        let name = self.name;
        let detach = self.detach;
        let auto_remove = self.rm;
        let root_disk = self.root_disk.clone();
        let use_disk = self.disk;

        let mut b = Vm::builder()
            .vcpus(self.cpus)
            .ram_mib(self.memory)
            .log_level(self.log_level);

        // Root filesystem: explicit disk > --disk (auto-create) > directory.
        if let Some(ref disk) = root_disk {
            b = b.root_disk(disk);
        } else if use_disk && !rootfs.is_empty() {
            let disk_path = create_disk_from_rootfs(&rootfs)?;
            b = b.root_disk(disk_path);
        } else {
            b = b.root(&rootfs);
        }

        // Working directory: CLI flag > OCI config > none.
        if let Some(ref wd) = self
            .workdir
            .or_else(|| oci_cfg.as_ref()?.working_dir.clone())
            .filter(|w| !w.is_empty())
        {
            b = b.workdir(wd);
        }

        // Command: --entrypoint override > CLI args > OCI ENTRYPOINT+CMD.
        let cmd = if let Some(ep) = self.entrypoint {
            let mut parts = vec![ep];
            parts.extend(self.command);
            parts
        } else if self.command.is_empty() {
            oci_cfg.as_ref().map(oci_command).unwrap_or_default()
        } else {
            self.command
        };
        if !cmd.is_empty() {
            let args: Vec<&str> = cmd[1..].iter().map(String::as_str).collect();
            b = b.exec(&cmd[0], &args);
        }

        // Environment: OCI defaults + --env-file + CLI -e overrides.
        let mut env_file_vars = Vec::new();
        for path in &self.env_file {
            env_file_vars.extend(crate::vm::read_env_file(path)?);
        }
        let merged_env: Vec<String> = oci_cfg
            .as_ref()
            .and_then(|c| c.env.clone())
            .unwrap_or_default()
            .into_iter()
            .chain(env_file_vars)
            .chain(self.env)
            .collect();
        if !merged_env.is_empty() {
            let refs: Vec<&str> = merged_env.iter().map(String::as_str).collect();
            b = b.env(&refs);
        }

        // Ports: -p hostPort:guestPort[/proto]
        for spec in &self.publish {
            let port_part = spec.split('/').next().unwrap_or(spec);
            b = b.port(port_part);
        }

        // Volumes: -v hostPath:guestPath[:ro]  →  auto-generate virtiofs tag.
        for (idx, spec) in self.volume.iter().enumerate() {
            let (host, _guest, _ro) = parse_volume(spec)?;
            let tag = format!("vol{idx}");
            b = b.virtiofs(&tag, &host);
        }

        // Ulimits.
        for ul in self.ulimit {
            b = b.rlimit(ul);
        }

        // User: --user uid[:gid]
        if let Some(ref user_spec) = self.user {
            let (uid, gid) = parse_user(user_spec)?;
            b = b.uid(uid);
            if let Some(g) = gid {
                b = b.gid(g);
            }
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

    /// Resolves rootfs path and optional OCI config.
    async fn resolve_rootfs(&self) -> Result<(String, Option<bux_oci::ImageConfig>)> {
        match (&self.image, &self.root, &self.root_disk) {
            (Some(img), None, None) => {
                let mut oci = bux_oci::Oci::open()?;
                let r = oci.ensure(img, |msg| eprintln!("{msg}")).await?;
                Ok((r.rootfs.to_string_lossy().into_owned(), r.config))
            }
            (None, Some(root), None) => Ok((root.clone(), None)),
            (None, None, Some(_)) => Ok((String::new(), None)),
            _ => unreachable!("clap validation"),
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

/// Parses Docker-style volume spec: `hostPath:guestPath[:ro]`.
fn parse_volume(spec: &str) -> Result<(String, String, bool)> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    match parts.as_slice() {
        [host, guest] => Ok((host.to_string(), guest.to_string(), false)),
        [host, guest, opts] => {
            let ro = opts.split(',').any(|o| o.eq_ignore_ascii_case("ro"));
            Ok((host.to_string(), guest.to_string(), ro))
        }
        _ => anyhow::bail!("invalid volume spec {spec:?}; use hostPath:guestPath[:ro]"),
    }
}

/// Parses `uid[:gid]` user spec.
pub fn parse_user(spec: &str) -> Result<(u32, Option<u32>)> {
    if let Some((u, g)) = spec.split_once(':') {
        let uid = u.parse().context("invalid UID")?;
        let gid = g.parse().context("invalid GID")?;
        Ok((uid, Some(gid)))
    } else {
        let uid = spec.parse().context("invalid UID")?;
        Ok((uid, None))
    }
}

/// Creates an ext4 disk image from an OCI rootfs directory.
#[cfg(unix)]
fn create_disk_from_rootfs(rootfs: &str) -> Result<String> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let data_dir = dirs::data_dir()
        .ok_or_else(|| anyhow::anyhow!("no platform data directory"))?
        .join("bux");
    let dm = bux::DiskManager::open(&data_dir)?;

    let mut h = DefaultHasher::new();
    rootfs.hash(&mut h);
    let digest = format!("{:016x}", h.finish());

    let base = dm.create_base(std::path::Path::new(rootfs), &digest)?;
    Ok(base.to_string_lossy().into_owned())
}

#[cfg(not(unix))]
fn create_disk_from_rootfs(_rootfs: &str) -> Result<String> {
    anyhow::bail!("Disk image creation requires Linux or macOS")
}

#[cfg(unix)]
async fn spawn_vm(
    builder: bux::VmBuilder,
    image: Option<String>,
    name: Option<String>,
    detach: bool,
    auto_remove: bool,
) -> Result<()> {
    let rt = crate::vm::open_runtime()?;
    let mut handle = rt.spawn(builder, image, name, auto_remove).await?;

    let id = &handle.state().id;
    if detach {
        println!("{}", handle.state().name.as_deref().unwrap_or(id));
        return Ok(());
    }

    eprintln!("{id}");
    handle.wait().await?;
    Ok(())
}

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
