//! VM lifecycle commands: ps, stop, kill, rm, exec, inspect, cp.

use anyhow::{Context, Result};

use crate::OutputFormat;

/// Parse purely numeric `uid` or `uid:gid`. `None` for name-based specs.
fn parse_numeric_user(spec: &str) -> Option<(u32, u32)> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    if let Some((u, g)) = spec.split_once(':') {
        let uid = u.trim().parse().ok()?;
        let gid = g.trim().parse().ok()?;
        return Some((uid, gid));
    }
    let uid = spec.parse().ok()?;
    Some((uid, uid))
}

#[must_use]
pub fn apply_exec_options(
    mut req: bux::ExecStart,
    env: Vec<String>,
    workdir: Option<&str>,
    user: Option<&str>,
    interactive: bool,
    tty: bool,
) -> bux::ExecStart {
    if !env.is_empty() {
        req = req.env(env);
    }
    if let Some(wd) = workdir.filter(|wd| !wd.is_empty()) {
        req = req.cwd(wd);
    }
    if let Some(user_spec) = user {
        if let Some((uid, gid)) = parse_numeric_user(user_spec) {
            req = req.user(uid, gid);
        } else {
            // Name-based: guest resolves via /etc/passwd.
            req = req.user_name(user_spec);
        }
    }
    if interactive {
        req = req.with_stdin();
    }
    if tty {
        req = req.tty(24, 80);
    }
    req
}

pub async fn stream_exec_output(
    handle: bux::ExecHandle,
    interactive: bool,
) -> Result<bux::ExecOutput> {
    use std::io::Write;

    let on_output = |msg: &bux_proto::ExecOut| match msg {
        bux_proto::ExecOut::Stdout(d) => {
            let _ = std::io::stdout().write_all(d);
        }
        bux_proto::ExecOut::Stderr(d) => {
            let _ = std::io::stderr().write_all(d);
        }
        _ => {}
    };

    if interactive {
        Ok(handle
            .stream_with_input(tokio::io::stdin(), on_output)
            .await?)
    } else {
        Ok(handle.stream(on_output).await?)
    }
}

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

    /// User (format: `uid[:gid]`).
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
    let data_dir = bux::default_data_dir();
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
            .filter(|v| v.status == bux::Status::Running)
            .collect()
    };

    // Apply --filter key=value pairs.
    for f in &args.filter {
        let (key, value) = f.split_once('=').unwrap_or((f, ""));
        filtered.retain(|vm| match key {
            "status" => {
                let s = match vm.status {
                    bux::Status::Running => "running",
                    bux::Status::Stopping => "stopping",
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
            bux::Status::Running => "running",
            bux::Status::Stopping => "stopping",
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
    if args.detach {
        anyhow::bail!("detached exec is not supported")
    }

    let rt = open_runtime()?;
    let handle = rt.get(&args.target)?;

    let (cmd, cmd_args) = args.command.split_first().context("command required")?;
    let mut req = bux::ExecStart::new(cmd).args(cmd_args.to_vec());

    // Merge env: --env-file first, then -e overrides.
    let mut env_vars = Vec::new();
    for path in &args.env_file {
        env_vars.extend(read_env_file(path)?);
    }
    env_vars.extend(args.env);
    req = apply_exec_options(
        req,
        env_vars,
        args.workdir.as_deref(),
        args.user.as_deref(),
        args.interactive,
        args.tty,
    );

    let output = stream_exec_output(handle.exec(req).await?, args.interactive).await?;

    if output.code != 0 {
        std::process::exit(output.code);
    }
    Ok(())
}

#[cfg(unix)]
pub fn inspect(args: &InspectArgs) -> Result<()> {
    let rt = open_runtime()?;
    let mut out = Vec::new();
    for t in &args.targets {
        let h = rt.get(t)?;
        out.push(serde_json::to_value(h.info())?);
    }

    if out.len() == 1 {
        println!("{}", serde_json::to_string_pretty(&out[0])?);
    } else {
        println!("{}", serde_json::to_string_pretty(&out)?);
    }
    Ok(())
}

#[cfg(unix)]
fn unpack_guest_tar(bytes: &[u8], dest: &std::path::Path) -> std::io::Result<()> {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = tar::Archive::new(cursor);
    archive.unpack(dest)?;
    Ok(())
}

#[cfg(unix)]
fn pack_dir_for_copy_in(src: &std::path::Path) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut ar = tar::Builder::new(&mut buf);
        append_dir_tree(&mut ar, src, std::path::Path::new(""))?;
        ar.finish()?;
    }
    Ok(buf)
}

#[cfg(unix)]
fn append_dir_tree<W: std::io::Write>(
    ar: &mut tar::Builder<W>,
    src: &std::path::Path,
    rel: &std::path::Path,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let child_rel = rel.join(entry.file_name());
        let child_src = entry.path();
        if entry.file_type()?.is_dir() {
            ar.append_dir(&child_rel, &child_src)?;
            append_dir_tree(ar, &child_src, &child_rel)?;
        } else {
            ar.append_path_with_name(&child_src, &child_rel)?;
        }
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
            // unpack → Entry::unpack_in skips ParentDir (workspace tar 0.4.46).
            unpack_guest_tar(&tar_data, std::path::Path::new(dst))?;
        }
        // host → guest
        (None, Some((id, guest_path))) => {
            let handle = rt.get(id)?;
            let meta = std::fs::metadata(src)?;
            if meta.is_dir() {
                // leftover guest ELF denies CurDir-only `./`; do not pack that member.
                let buf = pack_dir_for_copy_in(std::path::Path::new(src))?;
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

/// Arguments for `bux restart`.
#[derive(clap::Args)]
pub struct RestartArgs {
    /// VM ID or name.
    pub vm: String,
    /// Ready timeout in seconds.
    #[arg(long, default_value = "30")]
    pub timeout: u64,
}

/// Arguments for `bux stats`.
#[derive(clap::Args)]
pub struct StatsArgs {
    /// Dump process-local `RuntimeMetrics` as JSON (opens the runtime; Busy if locked).
    #[arg(long, conflicts_with = "vm")]
    pub runtime: bool,

    /// VM ID or name.
    #[arg(required_unless_present = "runtime")]
    pub vm: Option<String>,
}

/// Arguments for `bux clone`.
///
/// Disk-clone: overlay flatten; copies `vcpus`, ram, network, `auto_remove`.
/// The clone always boots detached and survives CLI exit, matching `bux create`.
#[derive(clap::Args)]
pub struct CloneArgs {
    /// Source VM ID or name.
    pub source: String,
    /// Optional name for the clone.
    #[arg(long)]
    pub name: Option<String>,
}

/// Arguments for `bux export`.
#[derive(clap::Args)]
pub struct ExportArgs {
    /// VM ID or name.
    pub vm: String,
    /// Output file path.
    pub output: String,
}

#[cfg(unix)]
pub async fn restart(args: RestartArgs) -> Result<()> {
    let rt = open_runtime()?;
    let mut handle = rt.get(&args.vm)?;
    if handle.info().status == bux::Status::Running {
        handle.stop().await?;
    }
    handle
        .start(std::time::Duration::from_secs(args.timeout))
        .await?;
    println!("{}", handle.info().id);
    Ok(())
}

/// JSON object whose keys are exactly the [`bux::RuntimeMetrics`] getter names.
#[cfg(unix)]
fn runtime_metrics_json(m: &bux::RuntimeMetrics) -> Result<String> {
    let obj = serde_json::json!({
        "vms_created_total": m.vms_created_total(),
        "num_running_vms": m.num_running_vms(),
        "vms_failed_total": m.vms_failed_total(),
        "total_uptime_ms": m.total_uptime_ms(),
        "disk_bytes_used": m.disk_bytes_used(),
    });
    Ok(serde_json::to_string_pretty(&obj)?)
}

#[cfg(unix)]
pub async fn stats(args: &StatsArgs) -> Result<()> {
    if args.runtime {
        let rt = open_runtime()?;
        println!("{}", runtime_metrics_json(rt.metrics())?);
        return Ok(());
    }
    let vm = args.vm.as_deref().context("VM ID or name required")?;
    let rt = open_runtime()?;
    let handle = rt.get(vm)?;
    let info = handle.info();
    let health = handle.health().await;
    let metrics = handle.metrics();
    println!("ID:             {}", info.id);
    println!("Name:           {}", info.name.as_deref().unwrap_or("-"));
    println!("Status:         {:?}", info.status);
    println!("Health:         {health:?}");
    println!("PID:            {}", info.pid);
    println!("boot_duration_ms: {}", metrics.boot_duration_ms());
    println!("exec_count:     {}", metrics.exec_count());
    Ok(())
}

#[cfg(unix)]
pub async fn clone_box(args: CloneArgs) -> Result<()> {
    let rt = open_runtime()?;
    let source = rt.get(&args.source)?;
    let handle = rt.clone(&source.info().id, args.name).await?;
    println!("{}", handle.info().id);
    Ok(())
}

#[cfg(unix)]
pub fn export(args: &ExportArgs) -> Result<()> {
    let rt = open_runtime()?;
    let handle = rt.get(&args.vm)?;
    handle.export(std::path::Path::new(&args.output))?;
    println!("Exported to {}", args.output);
    Ok(())
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
            pub fn $name($(_: &$ty),*) -> Result<()> {
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
    export(args: ExportArgs);
}

#[cfg(not(unix))]
unix_only_stub! {
    async:
    stop(args: StopArgs);
    exec(args: ExecArgs);
    cp(args: CpArgs);
    wait(args: WaitArgs);
    restart(args: RestartArgs);
    stats(args: StatsArgs);
    clone_box(args: CloneArgs);
}

#[cfg(test)]
#[cfg(unix)]
mod unpack_guest_tar_tests {
    use super::{pack_dir_for_copy_in, unpack_guest_tar};

    #[test]
    fn unpack_guest_tar_skips_parent_dir_member() {
        const NAME: &[u8] = b"../outside.txt\0";
        let dest_dir = tempfile::tempdir().expect("tempdir");
        let dest = dest_dir.path();
        let outside = dest.parent().expect("dest parent").join("outside.txt");

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(1);
            header.set_mode(0o644);
            // set_path rejects `..`; write the ustar name field so unpack_in sees ParentDir.
            header
                .as_old_mut()
                .name
                .get_mut(..NAME.len())
                .expect("ustar name field fits ../outside.txt")
                .copy_from_slice(NAME);
            header.set_cksum();
            builder
                .append(&header, b"x".as_slice())
                .expect("append ../outside.txt");
            builder.finish().expect("finish tar");
        }

        unpack_guest_tar(&buf, dest).expect("unpack_guest_tar");
        assert!(
            !outside.exists(),
            "ParentDir member must not land at dest.parent()/outside.txt"
        );
    }

    #[test]
    fn pack_dir_for_copy_in_omits_curdir_member() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("x.txt"), b"ok\n").expect("write x.txt");
        let bytes = pack_dir_for_copy_in(dir.path()).expect("pack");
        let mut archive = tar::Archive::new(bytes.as_slice());
        let mut saw_x = false;
        for entry in archive.entries().expect("entries") {
            let entry = entry.expect("entry");
            let path = entry.path().expect("path").into_owned();
            assert!(
                path.components()
                    .any(|c| matches!(c, std::path::Component::Normal(_))),
                "must not pack CurDir-only member {path:?}"
            );
            if path.as_os_str() == "x.txt" {
                saw_x = true;
            }
        }
        assert!(saw_x, "packed dir must contain x.txt");
    }
}

#[cfg(test)]
#[cfg(unix)]
mod stats_tests {
    use super::runtime_metrics_json;

    const RUNTIME_METRIC_KEYS: [&str; 5] = [
        "vms_created_total",
        "num_running_vms",
        "vms_failed_total",
        "total_uptime_ms",
        "disk_bytes_used",
    ];

    #[test]
    fn runtime_metrics_json_keys_match_getters() {
        let m = bux::RuntimeMetrics::new();
        let v: serde_json::Value =
            serde_json::from_str(&runtime_metrics_json(&m).expect("json")).expect("parse");
        let obj = v.as_object().expect("object");
        assert_eq!(
            obj.len(),
            RUNTIME_METRIC_KEYS.len(),
            "runtime JSON must be getter keys only: {obj:?}"
        );
        for key in RUNTIME_METRIC_KEYS {
            assert_eq!(obj[key].as_i64(), Some(0), "{key}");
        }
    }
}
