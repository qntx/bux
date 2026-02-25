//! VM lifecycle commands: ps, stop, kill, rm, exec, inspect, cp.

use anyhow::Result;

use crate::OutputFormat;

/// Opens the bux runtime from the platform data directory.
#[cfg(unix)]
pub fn open_runtime() -> Result<bux::Runtime> {
    use anyhow::Context;
    let data_dir = dirs::data_dir()
        .context("no platform data directory")?
        .join("bux");
    Ok(bux::Runtime::open(data_dir)?)
}

#[cfg(unix)]
pub fn ps(format: OutputFormat) -> Result<()> {
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
pub async fn stop(id: &str) -> Result<()> {
    let rt = open_runtime()?;
    let mut handle = rt.get(id)?;
    handle.stop().await?;
    eprintln!("Stopped: {}", handle.state().id);
    Ok(())
}

#[cfg(unix)]
pub fn kill(id: &str) -> Result<()> {
    let rt = open_runtime()?;
    let mut handle = rt.get(id)?;
    handle.kill()?;
    eprintln!("Killed: {}", handle.state().id);
    Ok(())
}

#[cfg(unix)]
pub fn rm(id: &str) -> Result<()> {
    let rt = open_runtime()?;
    rt.remove(id)?;
    eprintln!("Removed: {id}");
    Ok(())
}

#[cfg(unix)]
pub async fn exec(id: &str, command: Vec<String>) -> Result<()> {
    use std::io::Write;
    use anyhow::Context;

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
pub fn inspect(id: &str) -> Result<()> {
    let rt = open_runtime()?;
    let handle = rt.get(id)?;
    println!("{}", serde_json::to_string_pretty(handle.state())?);
    Ok(())
}

/// Parses `id:path` guest reference. Returns `(id, guest_path)`.
#[cfg(unix)]
fn parse_guest_ref(s: &str) -> Option<(&str, &str)> {
    let colon = s.find(':')?;
    if colon == 0 {
        return None;
    }
    Some((&s[..colon], &s[colon + 1..]))
}

#[cfg(unix)]
pub async fn cp(src: &str, dst: &str) -> Result<()> {
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
    ps(format: OutputFormat);
    kill(id: &str);
    rm(id: &str);
    inspect(id: &str);
}

#[cfg(not(unix))]
unix_only_stub! {
    async:
    stop(id: &str);
    exec(id: &str, command: Vec<String>);
    cp(src: &str, dst: &str);
}
