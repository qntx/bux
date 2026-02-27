//! VM lifecycle commands: ps, stop, kill, rm, exec, inspect, cp.

use anyhow::{Context, Result};

use crate::OutputFormat;

/// Arguments for `bux exec`.
///
/// Usage: `bux exec [OPTIONS] CONTAINER COMMAND [ARG...]`
#[derive(clap::Args)]
#[command(trailing_var_arg = true)]
pub struct ExecArgs {
    /// Detached mode: run command in the background.
    #[arg(short = 'd', long)]
    pub detach: bool,

    /// Set environment variables.
    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,

    /// Read environment variables from a file.
    #[arg(long)]
    pub env_file: Vec<String>,

    /// Keep STDIN open even if not attached.
    #[arg(short = 'i', long)]
    pub interactive: bool,

    /// Allocate a pseudo-TTY.
    #[arg(short = 't', long)]
    pub tty: bool,

    /// Working directory inside the VM.
    #[arg(short = 'w', long)]
    pub workdir: Option<String>,

    /// User (format: uid[:gid]).
    #[arg(short = 'u', long = "user")]
    pub user: Option<String>,

    /// VM ID, name, or prefix.
    #[arg(required = true)]
    pub target: String,

    /// Command and arguments.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    pub command: Vec<String>,
}

/// Arguments for `bux ps`.
#[derive(clap::Args)]
pub struct PsArgs {
    /// Show all VMs (default: only running).
    #[arg(short = 'a', long)]
    pub all: bool,

    /// Only display VM IDs.
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Filter output (e.g. status=running, name=myvm).
    #[arg(short = 'f', long = "filter")]
    pub filter: Vec<String>,

    /// Output format.
    #[arg(long, default_value = "table")]
    pub format: OutputFormat,
}

/// Arguments for `bux stop`.
#[derive(clap::Args)]
pub struct StopArgs {
    /// Seconds to wait before killing the VM.
    #[arg(short = 't', long = "time", default_value_t = 10)]
    pub time: u64,

    /// Signal to send to the VM.
    #[arg(short = 's', long)]
    pub signal: Option<String>,

    /// VM IDs, names, or prefixes.
    #[arg(required = true, num_args = 1..)]
    pub targets: Vec<String>,
}

/// Arguments for `bux kill`.
#[derive(clap::Args)]
pub struct KillArgs {
    /// Signal to send (default: KILL).
    #[arg(short = 's', long, default_value = "KILL")]
    pub signal: String,

    /// VM IDs, names, or prefixes.
    #[arg(required = true, num_args = 1..)]
    pub targets: Vec<String>,
}

/// Arguments for `bux rm`.
#[derive(clap::Args)]
pub struct RmArgs {
    /// Force removal of running VMs.
    #[arg(short = 'f', long)]
    pub force: bool,

    /// VM IDs, names, or prefixes.
    #[arg(required = true, num_args = 1..)]
    pub targets: Vec<String>,
}

/// Arguments for `bux wait`.
#[derive(clap::Args)]
pub struct WaitArgs {
    /// VM IDs, names, or prefixes.
    #[arg(required = true, num_args = 1..)]
    pub targets: Vec<String>,
}

/// Arguments for `bux inspect`.
#[derive(clap::Args)]
pub struct InspectArgs {
    /// Format output (json or Go-template-like).
    #[arg(short = 'f', long, default_value = "json")]
    pub format: String,

    /// VM IDs, names, or prefixes.
    #[arg(required = true, num_args = 1..)]
    pub targets: Vec<String>,
}

/// Arguments for `bux cp`.
#[derive(clap::Args)]
pub struct CpArgs {
    /// Suppress progress output.
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Source (host path or `<vm>:<guest_path>`).
    pub src: String,

    /// Destination (host path or `<vm>:<guest_path>`).
    pub dst: String,
}

/// Arguments for `bux rename`.
#[derive(clap::Args)]
pub struct RenameArgs {
    /// VM ID, name, or prefix.
    pub target: String,

    /// New name.
    pub new_name: String,
}

/// Opens the bux runtime from the platform data directory.
#[cfg(unix)]
pub fn open_runtime() -> Result<bux::Runtime> {
    let data_dir = dirs::data_dir()
        .context("no platform data directory")?
        .join("bux");
    Ok(bux::Runtime::open(data_dir)?)
}

#[cfg(unix)]
pub fn ps(args: &PsArgs) -> Result<()> {
    let rt = open_runtime()?;
    let vms = rt.list()?;

    // Filter: default shows only running, -a shows all.
    let mut filtered: Vec<_> = if args.all {
        vms
    } else {
        vms.into_iter()
            .filter(|v| v.status == bux::Status::Running || v.status == bux::Status::Creating)
            .collect()
    };

    // Apply --filter key=value pairs.
    for f in &args.filter {
        let (key, value) = f.split_once('=').unwrap_or((f, ""));
        filtered.retain(|vm| match key {
            "status" => {
                let s = match vm.status {
                    bux::Status::Creating => "creating",
                    bux::Status::Running => "running",
                    bux::Status::Stopped => "stopped",
                    _ => "unknown",
                };
                s == value
            }
            "name" => vm.name.as_deref() == Some(value),
            "id" => vm.id.starts_with(value),
            "image" => vm.image.as_deref() == Some(value),
            _ => true,
        });
    }

    // Quiet mode: IDs only.
    if args.quiet {
        for vm in &filtered {
            println!("{}", vm.id);
        }
        return Ok(());
    }

    if matches!(args.format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&filtered)?);
        return Ok(());
    }

    if filtered.is_empty() {
        return Ok(());
    }
    println!(
        "{:<14} {:<16} {:<8} {:<10} IMAGE",
        "ID", "NAME", "PID", "STATUS"
    );
    for vm in &filtered {
        let name = vm.name.as_deref().unwrap_or("-");
        let image = vm.image.as_deref().unwrap_or("-");
        let status = match vm.status {
            bux::Status::Creating => "creating",
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
pub async fn stop(args: StopArgs) -> Result<()> {
    let rt = open_runtime()?;
    let mut errors = Vec::new();
    let timeout = std::time::Duration::from_secs(args.time);

    for target in &args.targets {
        match rt.get(target) {
            Ok(mut h) => {
                // Send optional signal before graceful shutdown.
                if let Some(ref sig_name) = args.signal {
                    let sig = parse_signal(sig_name)?;
                    let _ = h.signal(sig);
                }
                match h.stop_timeout(timeout).await {
                    Ok(()) => println!("{target}"),
                    Err(e) => errors.push(format!("{target}: {e}")),
                }
            }
            Err(e) => errors.push(format!("{target}: {e}")),
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("{}", errors.join("\n"))
    }
}

#[cfg(unix)]
pub fn kill(args: &KillArgs) -> Result<()> {
    let rt = open_runtime()?;
    let sig = parse_signal(&args.signal)?;
    let mut errors = Vec::new();

    for target in &args.targets {
        match rt.get(target) {
            Ok(h) => match h.signal(sig) {
                Ok(()) => println!("{target}"),
                Err(e) => errors.push(format!("{target}: {e}")),
            },
            Err(e) => errors.push(format!("{target}: {e}")),
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("{}", errors.join("\n"))
    }
}

#[cfg(unix)]
pub fn rm(args: &RmArgs) -> Result<()> {
    let rt = open_runtime()?;
    let mut errors = Vec::new();

    for target in &args.targets {
        // Force mode: kill before removing.
        if args.force
            && let Ok(mut h) = rt.get(target)
        {
            let _ = h.kill();
        }
        match rt.remove(target) {
            Ok(()) => println!("{target}"),
            Err(e) => errors.push(format!("{target}: {e}")),
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("{}", errors.join("\n"))
    }
}

#[cfg(unix)]
pub async fn exec(args: ExecArgs) -> Result<()> {
    use std::io::Write;

    let rt = open_runtime()?;
    let handle = rt.get(&args.target)?;

    let (cmd, cmd_args) = args.command.split_first().context("command required")?;
    let mut req = bux::ExecReq::new(cmd).args(cmd_args.to_vec());

    // Merge env: --env-file first, then -e overrides.
    let mut env_vars = Vec::new();
    for path in &args.env_file {
        env_vars.extend(read_env_file(path)?);
    }
    env_vars.extend(args.env);
    if !env_vars.is_empty() {
        req = req.env(env_vars);
    }
    if let Some(ref wd) = args.workdir {
        req = req.cwd(wd);
    }
    if let Some(ref user_spec) = args.user {
        let (uid, gid) = crate::run::parse_user(user_spec)?;
        req = req.user(uid, gid.unwrap_or(uid));
    }

    let code = handle
        .exec_stream(req, |event| match event {
            bux::ExecEvent::Stdout(d) => {
                let _ = std::io::stdout().write_all(&d);
            }
            bux::ExecEvent::Stderr(d) => {
                let _ = std::io::stderr().write_all(&d);
            }
            _ => {}
        })
        .await?;

    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

#[cfg(unix)]
pub fn inspect(args: &InspectArgs) -> Result<()> {
    let rt = open_runtime()?;
    let states: Vec<_> = args
        .targets
        .iter()
        .map(|t| rt.get(t).map(|h| h.state().clone()))
        .collect::<std::result::Result<_, _>>()?;

    if states.len() == 1 {
        println!("{}", serde_json::to_string_pretty(&states[0])?);
    } else {
        println!("{}", serde_json::to_string_pretty(&states)?);
    }
    Ok(())
}

/// Parses `vm:path` guest reference. Returns `(vm, guest_path)`.
#[cfg(unix)]
fn parse_guest_ref(s: &str) -> Option<(&str, &str)> {
    let colon = s.find(':')?;
    if colon == 0 {
        return None;
    }
    Some((&s[..colon], &s[colon + 1..]))
}

#[cfg(unix)]
pub async fn cp(args: CpArgs) -> Result<()> {
    let rt = open_runtime()?;
    let (src, dst) = (args.src.as_str(), args.dst.as_str());

    match (parse_guest_ref(src), parse_guest_ref(dst)) {
        // guest → host
        (Some((id, guest_path)), None) => {
            let handle = rt.get(id)?;
            let tar_data = handle.copy_out(guest_path).await?;
            std::fs::create_dir_all(dst)?;
            let cursor = std::io::Cursor::new(tar_data);
            let mut archive = tar::Archive::new(cursor);
            archive.unpack(dst)?;
        }
        // host → guest
        (None, Some((id, guest_path))) => {
            let handle = rt.get(id)?;
            let meta = std::fs::metadata(src)?;
            if meta.is_dir() {
                let mut buf = Vec::new();
                {
                    let mut ar = tar::Builder::new(&mut buf);
                    ar.append_dir_all(".", src)?;
                    ar.finish()?;
                }
                handle.copy_in(guest_path, &buf).await?;
            } else {
                let data = std::fs::read(src)?;
                handle.write_file(guest_path, &data, 0o644).await?;
            }
        }
        _ => anyhow::bail!("exactly one of src/dst must use <vm>:<path> format"),
    }
    Ok(())
}

#[cfg(unix)]
pub async fn wait(args: WaitArgs) -> Result<()> {
    let rt = open_runtime()?;
    let mut errors = Vec::new();

    for target in &args.targets {
        match rt.get(target) {
            Ok(mut h) => match h.wait().await {
                Ok(()) => println!("{target}"),
                Err(e) => errors.push(format!("{target}: {e}")),
            },
            Err(e) => errors.push(format!("{target}: {e}")),
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("{}", errors.join("\n"))
    }
}

#[cfg(unix)]
pub fn prune() -> Result<()> {
    let rt = open_runtime()?;
    let vms = rt.list()?;
    let mut count = 0u32;

    for vm in &vms {
        if vm.status == bux::Status::Stopped {
            match rt.remove(&vm.id) {
                Ok(()) => {
                    println!("{}", vm.id);
                    count += 1;
                }
                Err(e) => eprintln!("warning: {}: {e}", vm.id),
            }
        }
    }
    eprintln!("Total reclaimed VMs: {count}");
    Ok(())
}

#[cfg(unix)]
pub fn rename(args: &RenameArgs) -> Result<()> {
    let rt = open_runtime()?;
    rt.rename(&args.target, &args.new_name)?;
    Ok(())
}

/// Parses a signal name (e.g. "KILL", "TERM", "9") into a signal number.
#[cfg(unix)]
fn parse_signal(name: &str) -> Result<i32> {
    // Try numeric first.
    if let Ok(n) = name.parse::<i32>() {
        return Ok(n);
    }
    // Strip optional "SIG" prefix.
    let upper = name.to_ascii_uppercase();
    let key = upper.strip_prefix("SIG").unwrap_or(&upper);
    match key {
        "HUP" => Ok(1),
        "INT" => Ok(2),
        "QUIT" => Ok(3),
        "KILL" => Ok(9),
        "USR1" => Ok(10),
        "USR2" => Ok(12),
        "TERM" => Ok(15),
        "CONT" => Ok(18),
        "STOP" => Ok(19),
        _ => anyhow::bail!("unknown signal: {name}"),
    }
}

/// Reads environment variables from a file (one `KEY=VALUE` per line).
/// Blank lines and lines starting with `#` are skipped.
pub fn read_env_file(path: &str) -> Result<Vec<String>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("cannot read env file: {path}"))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}

#[cfg(not(unix))]
macro_rules! unix_only_stub {
    (sync: $($name:ident($($arg:ident: $ty:ty),*));+ $(;)?) => {
        $(
            pub fn $name($(_: $ty),*) -> Result<()> {
                anyhow::bail!("VM management requires Linux or macOS")
            }
        )+
    };
    (async: $($name:ident($($arg:ident: $ty:ty),*));+ $(;)?) => {
        $(
            pub async fn $name($(_: $ty),*) -> Result<()> {
                anyhow::bail!("VM management requires Linux or macOS")
            }
        )+
    };
}

#[cfg(not(unix))]
unix_only_stub! {
    sync:
    ps(args: PsArgs);
    kill(args: KillArgs);
    rm(args: RmArgs);
    inspect(args: InspectArgs);
    prune();
    rename(args: RenameArgs);
}

#[cfg(not(unix))]
unix_only_stub! {
    async:
    stop(args: StopArgs);
    exec(args: ExecArgs);
    cp(args: CpArgs);
    wait(args: WaitArgs);
}
