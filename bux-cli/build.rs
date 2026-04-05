#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use std::env;
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const GITHUB_REPO: &str = "qntx/bux";

fn main() {
    println!("cargo:rerun-if-env-changed=BUX_GUEST_DIR");
    println!("cargo:rerun-if-env-changed=BUX_GUEST_DOWNLOAD");
    println!("cargo:rerun-if-env-changed=BUX_GUEST_VERSION");
    if let Ok(lib_dir) = env::var("DEP_KRUN_LIB_DIR") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{lib_dir}");
    }
    stage_guest_binary();
}

fn stage_guest_binary() {
    let Ok(target) = env::var("TARGET") else {
        return;
    };
    let Some(guest_target) = linux_guest_target(&target) else {
        return;
    };
    let Ok(profile) = env::var("PROFILE") else {
        return;
    };
    let Ok(out_dir) = env::var("OUT_DIR") else {
        return;
    };
    let Some(bin_dir) = profile_output_dir(Path::new(&out_dir), &profile) else {
        println!(
            "cargo:warning=unable to determine cargo profile output directory for guest staging"
        );
        return;
    };

    let dest = bin_dir.join(format!("bux-guest-{guest_target}"));
    let Some(source) = find_guest_binary(guest_target, &profile) else {
        println!(
            "cargo:warning=no Linux bux-guest binary found for {guest_target}; build one and point BUX_GUEST_DIR at it, run cargo build --target {guest_target} -p bux-guest, or set BUX_GUEST_DOWNLOAD=1 to fetch a release artifact"
        );
        return;
    };

    if let Err(err) = copy_if_needed(&source, &dest) {
        println!(
            "cargo:warning=failed to stage guest binary {} -> {}: {err}",
            source.display(),
            dest.display()
        );
    }
}

fn linux_guest_target(target: &str) -> Option<&'static str> {
    match target.split('-').next()? {
        "x86_64" => Some("x86_64-unknown-linux-musl"),
        "aarch64" => Some("aarch64-unknown-linux-musl"),
        _ => None,
    }
}

fn profile_output_dir(out_dir: &Path, profile: &str) -> Option<PathBuf> {
    out_dir
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == profile))
        .map(Path::to_path_buf)
}

fn find_guest_binary(guest_target: &str, profile: &str) -> Option<PathBuf> {
    if let Ok(dir) = env::var("BUX_GUEST_DIR") {
        for candidate in candidate_paths(Path::new(&dir), guest_target, profile) {
            if candidate.exists() {
                return Some(candidate);
            }
        }
        println!(
            "cargo:warning=BUX_GUEST_DIR is set but no guest binary was found for {guest_target} under {dir}"
        );
        return None;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").ok()?);
    let workspace_target = manifest_dir
        .parent()?
        .join("target")
        .join(guest_target)
        .join(profile)
        .join("bux-guest");
    if workspace_target.exists() {
        return Some(workspace_target);
    }

    if env::var("BUX_GUEST_DOWNLOAD").ok().as_deref() != Some("1") {
        return None;
    }

    match download_guest_binary(guest_target) {
        Ok(path) => Some(path),
        Err(err) => {
            println!("cargo:warning={err}");
            None
        }
    }
}

fn candidate_paths(base: &Path, guest_target: &str, profile: &str) -> [PathBuf; 4] {
    [
        base.join(format!("bux-guest-{guest_target}")),
        base.join("bux-guest-linux"),
        base.join("bux-guest"),
        base.join(guest_target).join(profile).join("bux-guest"),
    ]
}

fn copy_if_needed(source: &Path, dest: &Path) -> std::io::Result<()> {
    let source_meta = fs::metadata(source)?;
    if let Ok(dest_meta) = fs::metadata(dest)
        && dest_meta.len() == source_meta.len()
        && dest_meta.modified()? >= source_meta.modified()?
    {
        return Ok(());
    }

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, dest)?;
    fs::set_permissions(dest, source_meta.permissions())?;
    println!(
        "cargo:warning=staged guest binary {} -> {}",
        source.display(),
        dest.display()
    );
    Ok(())
}

fn download_guest_binary(guest_target: &str) -> Result<PathBuf, String> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").map_err(|err| err.to_string())?);
    let cache_dir = out_dir.join("guest-cache");
    let dest = cache_dir.join(format!("bux-guest-{guest_target}"));
    if dest.exists() {
        return Ok(dest);
    }

    fs::create_dir_all(&cache_dir).map_err(|err| err.to_string())?;
    let version = env::var("BUX_GUEST_VERSION")
        .or_else(|_| env::var("CARGO_PKG_VERSION"))
        .map_err(|err| err.to_string())?;
    let url = format!(
        "https://github.com/{GITHUB_REPO}/releases/download/v{version}/bux-guest-{guest_target}"
    );
    let response = ureq::get(&url)
        .call()
        .map_err(|err| format!("failed to download guest binary from {url}: {err}"))?;

    let mut body = response.into_body().into_reader();
    let mut bytes = Vec::new();
    body.read_to_end(&mut bytes)
        .map_err(|err| format!("failed to read guest binary from {url}: {err}"))?;

    let tmp = dest.with_extension("tmp");
    fs::write(&tmp, &bytes).map_err(|err| err.to_string())?;
    #[cfg(unix)]
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).map_err(|err| err.to_string())?;
    fs::rename(&tmp, &dest).map_err(|err| err.to_string())?;
    println!("cargo:warning=downloaded guest binary from {url}");
    Ok(dest)
}
