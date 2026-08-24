//! `bux run` — create and run a command in a new micro-VM.

use anyhow::{Context, Result};
use bux::{NetworkSpec, VmOptions};

/// Arguments for `bux run`.
///
/// Usage: `bux run [OPTIONS] IMAGE [COMMAND] [ARG...]`
#[derive(clap::Args)]
#[command(trailing_var_arg = true)]
pub struct RunArgs {
    /// OCI image reference (e.g., ubuntu:latest). Conflicts with `--root`.
    #[arg(conflicts_with = "root", required_unless_present = "root")]
    image: Option<String>,

    /// Explicit root filesystem directory (virtiofs).
    #[arg(long)]
    root: Option<String>,

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

    /// Publish a TCP port (host:guest, guest, 0:guest, :guest; optional /tcp).
    ///
    /// Host bind is always 0.0.0.0. UDP is not supported in v1.
    #[arg(short = 'p', long = "publish")]
    publish: Vec<String>,

    /// Restrict egress to hostnames/CIDRs (repeatable). Empty = unrestricted.
    #[arg(long = "allow-net")]
    allow_net: Vec<String>,

    /// Network mode: `enabled` (gvproxy, default) or `disabled` (offline).
    #[arg(long, default_value = "enabled", value_parser = ["enabled", "disabled"])]
    network: String,

    /// Host MITM secret (`name=value@host1,host2` or `name=value` using --allow-net hosts).
    ///
    /// Visible on `/proc/<pid>/cmdline`. Prefer `--secret-file` on shared hosts.
    #[arg(long = "secret")]
    secrets: Vec<String>,

    /// Host MITM secrets from a file. Mode must be `0600`. One `name=value[@host]` per line.
    #[arg(long = "secret-file", value_name = "PATH")]
    secret_file: Vec<String>,

    /// Bind mount a volume (format: `hostPath:guestPath[:ro]`).
    #[arg(short = 'v', long = "volume")]
    volume: Vec<String>,

    /// Set environment variables.
    #[arg(short = 'e', long = "env")]
    env: Vec<String>,

    /// Read environment variables from a file.
    #[arg(long)]
    env_file: Vec<String>,

    /// User inside the VM (format: `uid[:gid]` or `name[:group]`).
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

    /// Command and arguments to run inside the VM.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

/// Arguments for `bux create` — start a VM without an initial command.
#[derive(clap::Args)]
pub struct CreateArgs {
    /// OCI image reference.
    #[arg(required = true)]
    image: String,

    /// Assign a name to the VM.
    #[arg(long)]
    name: Option<String>,

    /// Automatically remove the VM when it stops.
    #[arg(long)]
    rm: bool,

    /// Number of virtual CPUs.
    #[arg(long, default_value_t = 1)]
    cpus: u8,

    /// Memory in MiB.
    #[arg(long, short = 'm', default_value_t = 512)]
    memory: u32,

    /// Publish a TCP port.
    #[arg(short = 'p', long = "publish")]
    publish: Vec<String>,

    /// Restrict egress (repeatable). Empty = unrestricted.
    #[arg(long = "allow-net")]
    allow_net: Vec<String>,

    /// Network mode: `enabled` or `disabled`.
    #[arg(long, default_value = "enabled", value_parser = ["enabled", "disabled"])]
    network: String,

    /// Host MITM secret (`name=value@host` or `name=value`).
    ///
    /// Visible on `/proc/<pid>/cmdline`. Prefer `--secret-file` on shared hosts.
    #[arg(long = "secret")]
    secrets: Vec<String>,

    /// Host MITM secrets from a file. Mode must be `0600`. One `name=value[@host]` per line.
    #[arg(long = "secret-file", value_name = "PATH")]
    secret_file: Vec<String>,

    /// Bind mount (`hostPath:guestPath[:ro]`).
    #[arg(short = 'v', long = "volume")]
    volume: Vec<String>,
}

impl CreateArgs {
    /// Create + start VM, print ID (no initial command).
    pub async fn run(self) -> Result<()> {
        RunArgs {
            image: Some(self.image),
            root: None,
            name: self.name,
            detach: true,
            rm: self.rm,
            cpus: self.cpus,
            memory: self.memory,
            workdir: None,
            publish: self.publish,
            allow_net: self.allow_net,
            network: self.network,
            secrets: self.secrets,
            secret_file: self.secret_file,
            volume: self.volume,
            env: vec![],
            env_file: vec![],
            user: None,
            interactive: false,
            tty: false,
            entrypoint: None,
            command: vec![],
        }
        .run()
        .await
    }
}

impl RunArgs {
    /// Create/start VM according to CLI flags.
    #[allow(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "CLI orchestration; splitting obscures flag wiring"
    )]
    pub async fn run(self) -> Result<()> {
        let image = match (&self.image, &self.root) {
            (Some(img), None) => bux::ImageRef::Oci(img.clone()),
            (None, Some(root)) => bux::ImageRef::Rootfs(std::path::PathBuf::from(root)),
            _ => unreachable!("clap validation"),
        };

        let mut opts = VmOptions::from_image(image)
            .vcpus(self.cpus)
            .ram_mib(self.memory)
            .auto_remove(self.rm)
            .detach(self.detach);

        if let Some(ref n) = self.name {
            opts = opts.name(n.clone());
        }
        if let Some(ref wd) = self.workdir {
            opts = opts.workdir(wd.clone());
        }
        if let Some(ref u) = self.user {
            opts = opts.user(u.clone());
        }
        for spec in &self.publish {
            bux::parse_publish_spec(spec).with_context(|| format!("invalid -p {spec:?}"))?;
            opts = opts.port(spec.clone());
        }

        if self.network == "disabled" {
            opts = opts.network(NetworkSpec::Disabled);
        } else if !self.allow_net.is_empty() {
            opts = opts.allow_net(self.allow_net.clone());
        }

        let mut secrets = parse_secrets(&self.secrets, &self.allow_net)?;
        for path in &self.secret_file {
            secrets.extend(parse_secret_file(path, &self.allow_net)?);
        }
        if !secrets.is_empty() {
            if !opts.network.is_enabled() {
                anyhow::bail!("--secret/--secret-file requires --network=enabled (gvproxy MITM)");
            }
            opts = opts.secrets(secrets);
        }

        for spec in &self.volume {
            opts = opts.volume(
                bux::parse_bind_spec(spec).with_context(|| format!("invalid -v {spec:?}"))?,
            );
        }

        let mut env = Vec::new();
        for path in &self.env_file {
            env.extend(crate::vm::read_env_file(path)?);
        }
        env.extend(self.env.clone());
        if !env.is_empty() {
            opts = opts.env(env.clone());
        }

        let cmd = if let Some(ep) = self.entrypoint.clone() {
            let mut parts = vec![ep];
            parts.extend(self.command.clone());
            Some(parts)
        } else if self.command.is_empty() {
            None
        } else {
            Some(self.command.clone())
        };
        if let Some(ref c) = cmd {
            opts = opts.command(c.clone());
        }

        if self.detach && (self.interactive || self.tty) {
            anyhow::bail!("detached run does not support -i/-t");
        }
        if self.detach && cmd.is_some() {
            anyhow::bail!(
                "detached run with an initial command is not supported; start the VM, then bux exec"
            );
        }

        let rt = crate::vm::open_runtime()?;
        let mut handle = rt.create(opts).await?;
        let info = handle.info();
        let id = info.id.clone();

        if self.detach {
            println!("{}", info.name.as_deref().unwrap_or(&id));
            return Ok(());
        }

        let exec_cmd = cmd.or_else(|| {
            let w = handle.workload_cmd();
            (!w.is_empty()).then(|| w.to_vec())
        });

        let exec_req = exec_cmd.filter(|c| !c.is_empty()).and_then(|c| {
            let (prog, rest) = c.split_first()?;
            Some(crate::vm::apply_exec_options(
                bux::ExecStart::new(prog).args(rest.to_vec()),
                env,
                self.workdir.as_deref(),
                self.user.as_deref(),
                self.interactive,
                self.tty,
            ))
        });

        let interactive = self.interactive;
        let did_exec = exec_req.is_some();
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

        let outcome = tokio::select! {
            result = async {
                if let Some(req) = exec_req {
                    let exec_handle = handle.exec(req).await?;
                    let output = crate::vm::stream_exec_output(exec_handle, interactive).await?;
                    anyhow::Ok(output.code)
                } else {
                    handle.wait().await?;
                    Ok(0)
                }
            } => Foreground::Done(result),
            _ = sigterm.recv() => Foreground::Signal(libc::SIGTERM),
            _ = sigint.recv() => Foreground::Signal(libc::SIGINT),
        };

        let exit_code = match outcome {
            Foreground::Done(result) => {
                let code = result?;
                if did_exec {
                    handle.stop().await?;
                }
                code
            }
            Foreground::Signal(sig) => {
                stop_handle(&mut handle).await;
                128 + sig
            }
        };

        if exit_code != 0 {
            std::process::exit(exit_code);
        }
        Ok(())
    }
}

enum Foreground {
    Done(Result<i32>),
    Signal(i32),
}

async fn stop_handle(handle: &mut bux::Vm) {
    if handle.stop().await.is_err() && handle.is_alive() {
        drop(handle.kill());
    }
}

/// Parse `--secret` specs into [`bux::Secret`] values.
///
/// Formats:
/// - `name=value@host1,host2`
/// - `name=value` (hosts from `--allow-net`, or `*` if empty)
pub fn parse_secrets(specs: &[String], allow_net: &[String]) -> Result<Vec<bux::Secret>> {
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        out.push(parse_one_secret(spec, allow_net)?);
    }
    Ok(out)
}

/// Load `--secret` specs from a file that must be mode `0600`.
fn parse_secret_file(path: &str, allow_net: &[String]) -> Result<Vec<bux::Secret>> {
    #[cfg(not(unix))]
    {
        let _ = (path, allow_net);
        anyhow::bail!("--secret-file requires Linux or macOS");
    }
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("cannot open --secret-file {path}"))?;
        let meta = file
            .metadata()
            .with_context(|| format!("cannot stat --secret-file {path}"))?;
        if !meta.is_file() {
            anyhow::bail!("--secret-file {path} must be a regular file");
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            anyhow::bail!("--secret-file {path} must have mode 0600 (got {mode:04o})");
        }
        let mut buf = Vec::new();
        #[allow(
            clippy::verbose_file_reads,
            reason = "read the same fd that was fstat'd; fs::read would reopen"
        )]
        file.read_to_end(&mut buf)
            .with_context(|| format!("cannot read --secret-file {path}"))?;
        let content = String::from_utf8(buf)
            .with_context(|| format!("--secret-file {path} is not valid UTF-8"))?;
        let specs: Vec<String> = content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(ToOwned::to_owned)
            .collect();
        parse_secrets(&specs, allow_net)
    }
}

fn parse_one_secret(spec: &str, allow_net: &[String]) -> Result<bux::Secret> {
    let (left, hosts_part) = match spec.rsplit_once('@') {
        Some((l, h)) if l.contains('=') => (l, Some(h)),
        _ => (spec, None),
    };
    let (name, value) = left.split_once('=').with_context(|| {
        format!("invalid --secret {spec:?}; expected name=value or name=value@host1,host2")
    })?;
    if name.is_empty() || value.is_empty() {
        anyhow::bail!("invalid --secret {spec:?}: name and value must be non-empty");
    }
    let hosts: Vec<String> = hosts_part.map_or_else(
        || {
            if allow_net.is_empty() {
                vec!["*".into()]
            } else {
                allow_net.to_vec()
            }
        },
        |h| {
            h.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        },
    );
    if hosts.is_empty() {
        anyhow::bail!("--secret {name}: no hosts (use @host or --allow-net)");
    }
    Ok(bux::Secret::new(name, hosts, value))
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    #[test]
    fn parse_with_hosts() {
        let s = parse_one_secret("openai=sk-x@api.openai.com,api.example.com", &[]).unwrap();
        assert_eq!(s.name, "openai");
        assert_eq!(s.value, "sk-x");
        assert_eq!(s.hosts, vec!["api.openai.com", "api.example.com"]);
    }

    #[test]
    fn parse_uses_allow_net() {
        let s = parse_one_secret("t=val", &["h1".into()]).unwrap();
        assert_eq!(s.hosts, vec!["h1"]);
    }

    #[test]
    fn parse_star_default() {
        let s = parse_one_secret("t=val", &[]).unwrap();
        assert_eq!(s.hosts, vec!["*"]);
    }

    #[cfg(unix)]
    struct TempSecretFile {
        path: std::path::PathBuf,
    }

    #[cfg(unix)]
    impl TempSecretFile {
        fn create(mode: u32, body: &[u8]) -> Self {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            let path = std::env::temp_dir().join(format!(
                "bux-secret-{}-{}-{mode:o}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&path)
                .unwrap();
            f.write_all(body).unwrap();
            drop(f);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            Self { path }
        }

        fn as_str(&self) -> &str {
            self.path.to_str().unwrap()
        }
    }

    #[cfg(unix)]
    impl Drop for TempSecretFile {
        fn drop(&mut self) {
            drop(std::fs::remove_file(&self.path));
        }
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_rejects_non_0600() {
        let file = TempSecretFile::create(0o644, b"t=val@h\n");
        let err = parse_secret_file(file.as_str(), &[]).unwrap_err();
        assert!(err.to_string().contains("0600"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_reads_0600() {
        let file = TempSecretFile::create(0o600, b"k=v@api.example.com\n");
        let secrets = parse_secret_file(file.as_str(), &[]).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "k");
        assert_eq!(secrets[0].value, "v");
        assert_eq!(secrets[0].hosts, vec!["api.example.com"]);
    }
}
