#![allow(
    missing_docs,
    clippy::missing_docs_in_private_items,
    reason = "internal module with crate-private API surface"
)]

//! Product tarball / guest-v ELF provision into `bux-pkg`.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use nix::fcntl::{Flock, FlockArg};
use sha2::{Digest, Sha256};
use tracing::{error, info};

use crate::guest::{ManagedGuestBinary, guest_binary_name};
use crate::util::sidecar_path;
use crate::{Error, Result};

/// `crates/bux-guest` Cargo.toml version. Prebuilt tag is `guest-v{GUEST_VERSION}`.
pub const GUEST_VERSION: &str = "0.1.0";

const INSTALL_HINT: &str = "install with: curl -fsSL https://sh.qntx.org/bux | sh";
const PAYLOAD_NOT_FOUND: &str =
    "bux payload not found; install with: curl -fsSL https://sh.qntx.org/bux | sh";
#[cfg(target_os = "linux")]
const BWRAP_REQUIRED: &str =
    "bwrap required (jailer); install with: curl -fsSL https://sh.qntx.org/bux | sh";
const RELEASE_DOWNLOAD: &str = "https://github.com/qntx/bux/releases/download";
const FETCH_TIMEOUT: Duration = Duration::from_mins(5);
const BODY_LIMIT: u64 = 512 * 1024 * 1024;
const REDIRECT_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];
const USER_AGENT: &str = concat!("bux/", env!("CARGO_PKG_VERSION"));

/// Resolved sidecar paths after [`ensure_blocking`].
#[derive(Debug, Clone)]
pub(crate) struct ResolvedPayload {
    pub shim: PathBuf,
    pub guest: PathBuf,
    pub bwrap: Option<PathBuf>,
}

/// Payload root: `dirs::data_dir()/bux-pkg` (sibling of `BUX_HOME`, not inside it).
#[must_use]
pub fn default_payload_dir() -> PathBuf {
    dirs::data_dir().map_or_else(|| PathBuf::from("bux-pkg"), |d| d.join("bux-pkg"))
}

/// Closed CD-matrix host triple. Musl host and Intel Mac are `InvalidConfig`.
///
/// # Errors
///
/// Unsupported OS/arch, musl host, or Intel Mac.
pub(crate) fn host_target() -> Result<&'static str> {
    if cfg!(target_os = "linux") && musl_host() {
        return Err(Error::InvalidConfig(format!(
            "musl host is unsupported; {INSTALL_HINT}"
        )));
    }
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-gnu"),
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("macos", "x86_64") if darwin_arm64_capable() => Ok("aarch64-apple-darwin"),
        (os, arch) => Err(Error::InvalidConfig(format!(
            "unsupported host {os}/{arch}; {INSTALL_HINT}"
        ))),
    }
}

/// Sibling + product dir + `$PATH` `bwrap` (Linux). Does not fetch.
#[must_use]
#[allow(clippy::missing_const_for_fn, reason = "Linux probes the filesystem")]
pub(crate) fn namespaces_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        lookup_bwrap().is_some()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Resolve shim / guest / bwrap. HTTP, extract, and flock run here (blocking).
///
/// # Errors
///
/// Missing payload, checksum/ELF/archive failure, unsupported host, or Linux
/// jailer without `bwrap`.
pub(crate) fn ensure_blocking(
    shim_override: Option<&Path>,
    guest_override: Option<&Path>,
    jailer: bool,
    need_guest: bool,
) -> Result<ResolvedPayload> {
    let target = host_target()?;
    let (shim, guest) = resolve_artifacts(shim_override, guest_override, need_guest, target)?;
    let shim = shim.ok_or_else(|| Error::NotFound(PAYLOAD_NOT_FOUND.into()))?;
    let guest = if need_guest {
        guest.ok_or_else(|| Error::NotFound(PAYLOAD_NOT_FOUND.into()))?
    } else {
        guest.unwrap_or_default()
    };
    Ok(ResolvedPayload {
        shim,
        guest,
        bwrap: require_bwrap(jailer)?,
    })
}

fn resolve_artifacts(
    shim_override: Option<&Path>,
    guest_override: Option<&Path>,
    need_guest: bool,
    target: &str,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    let mut shim = resolve_override(shim_override, "bux-shim", "shim_path")?;
    let mut guest = resolve_override(guest_override, "bux-guest", "guest_path")?;
    if shim.is_none() {
        shim = sibling_file("bux-shim");
        if let Some(path) = &shim {
            info!(path = %path.display(), "payload hit");
        }
    }
    if guest.is_none() && need_guest {
        guest = sibling_guest()?;
    }
    let shim_local = shim.is_some();
    if shim.is_none() || (need_guest && guest.is_none()) {
        fill_from_store(&mut shim, &mut guest, need_guest, shim_local, target)?;
    }
    Ok((shim, guest))
}

fn fill_from_store(
    shim: &mut Option<PathBuf>,
    guest: &mut Option<PathBuf>,
    need_guest: bool,
    shim_local: bool,
    target: &str,
) -> Result<()> {
    let _lock = lock_payload_root()?;
    if let Some(dir) = complete_product_dir(target) {
        take_product_members(shim, guest, need_guest, &dir);
        return Ok(());
    }
    if shim.is_none() {
        let dir = fetch_product(target)?;
        take_product_members(shim, guest, need_guest, &dir);
    }
    if need_guest && guest.is_none() {
        *guest = guest_from_cache_or_fetch(shim_local, target)?;
    }
    Ok(())
}

fn take_product_members(
    shim: &mut Option<PathBuf>,
    guest: &mut Option<PathBuf>,
    need_guest: bool,
    dir: &Path,
) {
    if shim.is_none() {
        let path = dir.join("bux-shim");
        info!(path = %path.display(), "payload hit");
        *shim = Some(path);
    }
    if need_guest && guest.is_none() {
        *guest = Some(dir.join(guest_binary_name()));
    }
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "Linux jailer missing bwrap is Err; other platforms always Ok"
)]
fn require_bwrap(jailer: bool) -> Result<Option<PathBuf>> {
    let bwrap = lookup_bwrap();
    #[cfg(target_os = "linux")]
    if jailer && bwrap.is_none() {
        return Err(Error::SecurityUnavailable(BWRAP_REQUIRED.into()));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = jailer;
    Ok(bwrap)
}

fn resolve_override(explicit: Option<&Path>, label: &str, option: &str) -> Result<Option<PathBuf>> {
    let Some(path) = explicit else {
        return Ok(None);
    };
    if path.is_file() {
        return Ok(Some(path.to_path_buf()));
    }
    Err(Error::NotFound(format!(
        "{label} not found at {} (RuntimeOptions.{option})",
        path.display()
    )))
}

fn sibling_file(name: &str) -> Option<PathBuf> {
    let exe = exe_path()?;
    let sibling = sidecar_path(&exe, name)?;
    sibling.is_file().then_some(sibling)
}

fn sibling_guest() -> Result<Option<PathBuf>> {
    let Some(path) = sibling_file(&guest_binary_name()) else {
        return Ok(None);
    };
    match ManagedGuestBinary::from_path(&path) {
        Ok(_) => Ok(Some(path)),
        Err(err) => Err(err),
    }
}

fn guest_from_cache_or_fetch(shim_local: bool, target: &str) -> Result<Option<PathBuf>> {
    let dest = guest_cache_path();
    if dest.is_file() && ManagedGuestBinary::from_path(&dest).is_ok() {
        return Ok(Some(dest));
    }
    if shim_local {
        return fetch_guest(target).map(Some);
    }
    Ok(None)
}

fn payload_root() -> PathBuf {
    #[cfg(test)]
    if let Some(dir) = test_env::payload_dir() {
        return dir;
    }
    default_payload_dir()
}

fn product_dir(target: &str) -> PathBuf {
    payload_root().join(format!("{}-{target}", env!("CARGO_PKG_VERSION")))
}

fn guest_cache_path() -> PathBuf {
    payload_root()
        .join(format!("guest-v{GUEST_VERSION}"))
        .join(guest_binary_name())
}

fn exe_path() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(exe) = test_env::exe() {
        return Some(exe);
    }
    std::env::current_exe().ok()
}

fn release_base() -> String {
    #[cfg(test)]
    if let Some(base) = test_env::release_base() {
        return base;
    }
    RELEASE_DOWNLOAD.to_owned()
}

fn musl_host() -> bool {
    if cfg!(target_env = "musl") {
        return true;
    }
    Path::new(&format!("/lib/ld-musl-{}.so.1", std::env::consts::ARCH)).exists()
}

fn darwin_arm64_capable() -> bool {
    std::process::Command::new("sysctl")
        .args(["-n", "hw.optional.arm64"])
        .output()
        .is_ok_and(|o| o.stdout.starts_with(b"1"))
}

fn complete_product_dir(target: &str) -> Option<PathBuf> {
    let dir = product_dir(target);
    product_complete(&dir).then_some(dir)
}

fn product_complete(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    for name in required_exec_names() {
        if !is_exec_file(&dir.join(name)) {
            return false;
        }
    }
    for name in lib_names() {
        if !dir.join(name).is_file() {
            return false;
        }
    }
    let guest = dir.join(guest_binary_name());
    ManagedGuestBinary::from_path(&guest).is_ok()
}

fn required_exec_names() -> Vec<&'static str> {
    let mut names = vec!["bux", "bux-shim"];
    if cfg!(target_os = "linux") {
        names.push("bwrap");
    }
    names
}

const fn lib_names() -> &'static [&'static str] {
    if cfg!(target_os = "macos") {
        &[
            "libkrun.dylib",
            "libkrun.1.dylib",
            "libkrunfw.dylib",
            "libkrunfw.5.dylib",
        ]
    } else {
        &[
            "libkrun.so",
            "libkrun.so.1",
            "libkrunfw.so",
            "libkrunfw.so.5",
        ]
    }
}

fn allowlisted_names() -> HashSet<String> {
    let mut names = HashSet::new();
    for name in required_exec_names() {
        names.insert(name.to_owned());
    }
    names.insert(guest_binary_name());
    for name in lib_names() {
        names.insert((*name).to_owned());
    }
    names.insert("LICENSE-MIT".into());
    names.insert("LICENSE-APACHE".into());
    names
}

fn is_exec_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

fn lookup_bwrap() -> Option<PathBuf> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    if let Some(path) = sibling_file("bwrap") {
        return Some(path);
    }
    if let Ok(target) = host_target() {
        let path = product_dir(target).join("bwrap");
        if path.is_file() {
            return Some(path);
        }
    }
    which_on_path("bwrap")
}

fn which_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

fn lock_payload_root() -> Result<Flock<File>> {
    let root = payload_root();
    fs::create_dir_all(&root)?;
    chmod_0700(&root)?;
    let file = File::create(root.join(".lock"))?;
    Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, err)| Error::from(err))
}

fn chmod_0700(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn chmod_0755(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

fn fetch_product(target: &str) -> Result<PathBuf> {
    let ver = env!("CARGO_PKG_VERSION");
    let base = release_base();
    let url = format!("{base}/v{ver}/bux-{ver}-{target}.tar.gz");
    let sha_url = format!("{url}.sha256");
    info!(url = %url, version = ver, target, "fetch start");
    let bytes = download_verified(&url, &sha_url)?;
    let dest = product_dir(target);
    extract_product(&bytes, &dest)?;
    info!(dest = %dest.display(), "fetch ok");
    Ok(dest)
}

fn fetch_guest(_target: &str) -> Result<PathBuf> {
    let name = guest_binary_name();
    let base = release_base();
    let url = format!("{base}/guest-v{GUEST_VERSION}/{name}");
    let sha_url = format!("{url}.sha256");
    info!(url = %url, version = GUEST_VERSION, "fetch start");
    let bytes = download_verified(&url, &sha_url)?;
    let dest = guest_cache_path();
    install_guest_bytes(&bytes, &dest)?;
    info!(dest = %dest.display(), "fetch ok");
    Ok(dest)
}

fn download_verified(url: &str, sha_url: &str) -> Result<Vec<u8>> {
    let sha_text = String::from_utf8(http_get(sha_url)?)
        .map_err(|_| Error::InvalidConfig("sha256 file is not UTF-8".into()))?;
    let expected = parse_sha256(&sha_text)?;
    let bytes = http_get(url)?;
    let actual = Sha256::digest(&bytes);
    if actual.as_slice() != expected.as_slice() {
        error!(url, "checksum mismatch");
        return Err(Error::InvalidConfig(format!("sha256 mismatch for {url}")));
    }
    let mut prefix = String::new();
    for byte in actual.iter().take(4) {
        std::fmt::Write::write_fmt(&mut prefix, format_args!("{byte:02x}")).ok();
    }
    info!(sha256_prefix = %prefix, url, "fetch ok");
    Ok(bytes)
}

fn parse_sha256(text: &str) -> Result<[u8; 32]> {
    let token = text
        .split_whitespace()
        .next()
        .ok_or_else(|| Error::InvalidConfig("empty sha256 file".into()))?;
    if token.len() != 64 {
        return Err(Error::InvalidConfig(format!(
            "sha256 must be 64 hex chars, got {}",
            token.len()
        )));
    }
    let mut out = [0_u8; 32];
    for (dst, chunk) in out.iter_mut().zip(token.as_bytes().chunks_exact(2)) {
        let hex = std::str::from_utf8(chunk)
            .map_err(|_| Error::InvalidConfig("sha256 is not UTF-8".into()))?;
        *dst = u8::from_str_radix(hex, 16)
            .map_err(|_| Error::InvalidConfig("sha256 is not hex".into()))?;
    }
    Ok(out)
}

fn http_get(url: &str) -> Result<Vec<u8>> {
    let deadline = Instant::now() + FETCH_TIMEOUT;
    let mut delay = Duration::from_secs(1);
    let mut last = None;
    for attempt in 0..3 {
        match http_get_follow(url, deadline) {
            Ok(bytes) => return Ok(bytes),
            Err(err) if retryable(&err) && attempt < 2 => {
                last = Some(err);
                sleep_backoff(delay, deadline)?;
                delay *= 2;
            }
            Err(err) => return Err(err),
        }
    }
    Err(last.unwrap_or_else(|| Error::InvalidConfig(format!("fetch failed: {url}"))))
}

const fn retryable(err: &Error) -> bool {
    matches!(err, Error::Busy(_) | Error::Io(_))
}

fn sleep_backoff(delay: Duration, deadline: Instant) -> Result<()> {
    if Instant::now() + delay > deadline {
        return Err(Error::InvalidConfig("payload fetch timed out".into()));
    }
    #[allow(
        clippy::disallowed_methods,
        reason = "blocking HTTP backoff inside spawn_blocking"
    )]
    std::thread::sleep(delay);
    Ok(())
}

fn http_get_follow(url: &str, deadline: Instant) -> Result<Vec<u8>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(remaining(deadline)?))
        .max_redirects(0)
        .user_agent(USER_AGENT)
        .build()
        .into();
    let mut current = url.to_owned();
    for _ in 0..10 {
        if Instant::now() > deadline {
            return Err(Error::InvalidConfig("payload fetch timed out".into()));
        }
        ensure_host_allowed(&current)?;
        match read_response(&agent, &current)? {
            Fetch::Body(bytes) => return Ok(bytes),
            Fetch::Redirect(next) => current = next,
        }
    }
    Err(Error::InvalidConfig(format!(
        "too many redirects fetching {url}"
    )))
}

enum Fetch {
    Body(Vec<u8>),
    Redirect(String),
}

fn read_response(agent: &ureq::Agent, current: &str) -> Result<Fetch> {
    match agent.get(current).call() {
        Ok(mut resp) => {
            let status = resp.status();
            if status.is_redirection() {
                let loc = resp
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        Error::InvalidConfig(format!("redirect without Location: {current}"))
                    })?;
                return Ok(Fetch::Redirect(resolve_location(current, loc)?));
            }
            if !status.is_success() {
                return map_status(status.as_u16(), current).map(Fetch::Body);
            }
            resp.body_mut()
                .with_config()
                .limit(BODY_LIMIT)
                .read_to_vec()
                .map(Fetch::Body)
                .map_err(|e| map_ureq(e, current))
        }
        Err(err) => Err(map_ureq(err, current)),
    }
}

fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| Error::InvalidConfig("payload fetch timed out".into()))
}

fn map_ureq(err: ureq::Error, url: &str) -> Error {
    match err {
        ureq::Error::StatusCode(404) => {
            error!(url, "HTTP 404");
            Error::NotFound(PAYLOAD_NOT_FOUND.into())
        }
        ureq::Error::StatusCode(code) if (500..600).contains(&code) => {
            Error::Busy(format!("HTTP {code} fetching {url}"))
        }
        ureq::Error::StatusCode(code) => {
            Error::InvalidConfig(format!("HTTP {code} fetching {url}"))
        }
        ureq::Error::Io(err) => Error::Io(err),
        other => Error::InvalidConfig(format!("fetch {url}: {other}")),
    }
}

fn map_status(code: u16, url: &str) -> Result<Vec<u8>> {
    Err(map_ureq(ureq::Error::StatusCode(code), url))
}

fn ensure_host_allowed(url: &str) -> Result<()> {
    let host = url_host(url)?;
    if host_allowed(&host) {
        return Ok(());
    }
    Err(Error::InvalidConfig(format!(
        "refusing fetch host {host} (not in GitHub allowlist)"
    )))
}

fn host_allowed(host: &str) -> bool {
    REDIRECT_HOSTS.contains(&host)
        || (cfg!(test) && (host == "127.0.0.1" || host == "localhost" || host == "[::1]"))
}

fn url_host(url: &str) -> Result<String> {
    let uri: ureq::http::Uri = url
        .parse()
        .map_err(|e| Error::InvalidConfig(format!("invalid url {url}: {e}")))?;
    uri.host()
        .map(str::to_owned)
        .ok_or_else(|| Error::InvalidConfig(format!("url has no host: {url}")))
}

fn resolve_location(current: &str, location: &str) -> Result<String> {
    if location.starts_with("https://") || location.starts_with("http://") {
        return Ok(location.to_owned());
    }
    let uri: ureq::http::Uri = current
        .parse()
        .map_err(|e| Error::InvalidConfig(format!("invalid url {current}: {e}")))?;
    let scheme = uri.scheme_str().unwrap_or("https");
    let auth = uri
        .authority()
        .ok_or_else(|| Error::InvalidConfig(format!("url has no host: {current}")))?;
    location.strip_prefix('/').map_or_else(
        || {
            Err(Error::InvalidConfig(format!(
                "relative redirect not allowed: {location}"
            )))
        },
        |path| Ok(format!("{scheme}://{auth}/{path}")),
    )
}

fn extract_product(bytes: &[u8], dest: &Path) -> Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| Error::InvalidConfig("payload dest has no parent".into()))?;
    fs::create_dir_all(parent)?;
    chmod_0700(parent)?;
    let staging_name = format!(
        "{}.new",
        dest.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Error::InvalidConfig("payload dest is not UTF-8".into()))?
    );
    let staging = parent.join(staging_name);
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(&staging)?;
    chmod_0700(&staging)?;
    let mut guard = StagingGuard {
        path: staging.clone(),
        keep: false,
    };
    unpack_allowlisted(bytes, &staging)?;
    if !product_complete(&staging) {
        return Err(Error::InvalidConfig(format!(
            "extracted payload is incomplete at {}",
            staging.display()
        )));
    }
    if dest.exists() {
        fs::remove_dir_all(dest)?;
    }
    fs::rename(&staging, dest)?;
    guard.keep = true;
    Ok(())
}

struct StagingGuard {
    path: PathBuf,
    keep: bool,
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if !self.keep {
            drop(fs::remove_dir_all(&self.path));
        }
    }
}

fn unpack_allowlisted(bytes: &[u8], dest: &Path) -> Result<()> {
    let allow = allowlisted_names();
    let mut archive = tar::Archive::new(GzDecoder::new(bytes));
    for entry in archive.entries().map_err(|e| tar_err(&e))? {
        let mut entry = entry.map_err(|e| tar_err(&e))?;
        let path = entry.path().map_err(|e| tar_err(&e))?.into_owned();
        let name = member_basename(&path)?;
        if name == "." {
            continue;
        }
        if !allow.contains(&name) {
            return Err(Error::InvalidConfig(format!(
                "unexpected tar member {name}"
            )));
        }
        let out = dest.join(&name);
        match entry.header().entry_type() {
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                let mut file = File::create(&out)?;
                io::copy(&mut entry, &mut file)?;
                if let Ok(mode) = entry.header().mode() {
                    fs::set_permissions(&out, fs::Permissions::from_mode(mode))?;
                }
            }
            tar::EntryType::Symlink => {
                let target = entry
                    .link_name()
                    .map_err(|e| tar_err(&e))?
                    .ok_or_else(|| Error::InvalidConfig(format!("symlink {name} has no target")))?;
                validate_link_target(&target, &allow)?;
                std::os::unix::fs::symlink(&target, &out)?;
            }
            tar::EntryType::Link => {
                let target = entry.link_name().map_err(|e| tar_err(&e))?.ok_or_else(|| {
                    Error::InvalidConfig(format!("hard link {name} has no target"))
                })?;
                validate_link_target(&target, &allow)?;
                let src = dest.join(&target);
                if !src.exists() {
                    return Err(Error::InvalidConfig(format!(
                        "hard link {name} target missing"
                    )));
                }
                fs::hard_link(&src, &out)?;
            }
            tar::EntryType::Directory => {
                return Err(Error::InvalidConfig(format!(
                    "unexpected tar directory {name}"
                )));
            }
            other => {
                return Err(Error::InvalidConfig(format!(
                    "unsupported tar entry {other:?} ({name})"
                )));
            }
        }
    }
    Ok(())
}

fn tar_err(err: &io::Error) -> Error {
    Error::InvalidConfig(format!("tar: {err}"))
}

fn member_basename(path: &Path) -> Result<String> {
    if path.is_absolute() {
        return Err(Error::InvalidConfig(format!(
            "absolute tar path {}",
            path.display()
        )));
    }
    let mut comps = path.components().peekable();
    if matches!(comps.peek(), Some(Component::CurDir)) {
        comps.next();
    }
    match (comps.next(), comps.next()) {
        (None, None) => Ok(".".into()),
        (Some(Component::Normal(name)), None) => name
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::InvalidConfig("non-UTF-8 tar member".into())),
        _ => Err(Error::InvalidConfig(format!(
            "tar member must be a basename: {}",
            path.display()
        ))),
    }
}

fn validate_link_target(target: &Path, allow: &HashSet<String>) -> Result<()> {
    if target.is_absolute() {
        return Err(Error::InvalidConfig(format!(
            "absolute symlink target {}",
            target.display()
        )));
    }
    if target
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::RootDir))
    {
        return Err(Error::InvalidConfig(format!(
            "symlink target escapes dest: {}",
            target.display()
        )));
    }
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|_| target.components().count() == 1)
        .ok_or_else(|| {
            Error::InvalidConfig(format!(
                "symlink target must be a same-dir name: {}",
                target.display()
            ))
        })?;
    if !allow.contains(name) {
        return Err(Error::InvalidConfig(format!(
            "symlink target {name} is not allowlisted"
        )));
    }
    Ok(())
}

fn install_guest_bytes(bytes: &[u8], dest: &Path) -> Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| Error::InvalidConfig("guest dest has no parent".into()))?;
    fs::create_dir_all(parent)?;
    chmod_0700(parent)?;
    let tmp = dest.with_extension("new");
    fs::write(&tmp, bytes)?;
    let mut guard = FileGuard {
        path: tmp.clone(),
        keep: false,
    };
    chmod_0755(&tmp)?;
    ManagedGuestBinary::from_path(&tmp)?;
    if dest.exists() {
        fs::remove_file(dest)?;
    }
    fs::rename(&tmp, dest)?;
    guard.keep = true;
    Ok(())
}

struct FileGuard {
    path: PathBuf,
    keep: bool,
}

impl Drop for FileGuard {
    fn drop(&mut self) {
        if !self.keep {
            drop(fs::remove_file(&self.path));
        }
    }
}

#[cfg(test)]
mod test_env {
    use std::cell::RefCell;
    use std::path::PathBuf;

    thread_local! {
        static PAYLOAD_DIR: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
        static EXE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
        static RELEASE_BASE: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    pub(super) fn payload_dir() -> Option<PathBuf> {
        PAYLOAD_DIR.with(|c| c.borrow().clone())
    }

    pub(super) fn exe() -> Option<PathBuf> {
        EXE.with(|c| c.borrow().clone())
    }

    pub(super) fn release_base() -> Option<String> {
        RELEASE_BASE.with(|c| c.borrow().clone())
    }

    pub(super) struct Guard {
        payload: Option<PathBuf>,
        exe: Option<PathBuf>,
        release: Option<String>,
    }

    impl Guard {
        pub(super) fn new() -> Self {
            Self {
                payload: PAYLOAD_DIR.with(|c| c.borrow_mut().take()),
                exe: EXE.with(|c| c.borrow_mut().take()),
                release: RELEASE_BASE.with(|c| c.borrow_mut().take()),
            }
        }
    }

    pub(super) fn set_payload(dir: PathBuf) {
        PAYLOAD_DIR.with(|c| *c.borrow_mut() = Some(dir));
    }

    pub(super) fn set_exe(exe: PathBuf) {
        EXE.with(|c| *c.borrow_mut() = Some(exe));
    }

    pub(super) fn set_release_base(base: String) {
        RELEASE_BASE.with(|c| *c.borrow_mut() = Some(base));
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            PAYLOAD_DIR.with(|c| *c.borrow_mut() = self.payload.take());
            EXE.with(|c| *c.borrow_mut() = self.exe.take());
            RELEASE_BASE.with(|c| *c.borrow_mut() = self.release.take());
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::guest::test_static_guest_elf;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use tar::{Builder, Header};

    const CD_MATRIX: &[&str] = &[
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "aarch64-apple-darwin",
    ];

    struct Fixture {
        _guard: test_env::Guard,
        payload: tempfile::TempDir,
        _exe_dir: tempfile::TempDir,
        exe: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let guard = test_env::Guard::new();
            let payload = tempfile::tempdir().unwrap();
            let exe_dir = tempfile::tempdir().unwrap();
            let exe = exe_dir.path().join("bux");
            fs::write(&exe, b"exe").unwrap();
            chmod_0755(&exe).unwrap();
            test_env::set_payload(payload.path().to_path_buf());
            test_env::set_exe(exe.clone());
            Self {
                _guard: guard,
                payload,
                _exe_dir: exe_dir,
                exe,
            }
        }

        fn with_release(self, base: &str) -> Self {
            test_env::set_release_base(base.to_owned());
            self
        }

        fn plant_shim(&self) {
            let path = self.exe.with_file_name("bux-shim");
            fs::write(&path, b"shim").unwrap();
            chmod_0755(&path).unwrap();
        }

        fn payload_root(&self) -> &Path {
            self.payload.path()
        }
    }

    struct MockResp {
        status: u16,
        location: Option<String>,
        body: Vec<u8>,
    }

    fn serve(routes: HashMap<String, MockResp>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(false).unwrap();
        let addr = listener.local_addr().unwrap();
        let routes = Arc::new(routes);
        let handle = thread::spawn(move || accept_loop(&listener, &routes));
        (format!("http://{addr}"), handle)
    }

    fn accept_loop(listener: &TcpListener, routes: &HashMap<String, MockResp>) {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            handle_conn(stream, routes);
        }
    }

    fn handle_conn(mut stream: std::net::TcpStream, routes: &HashMap<String, MockResp>) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut req = String::new();
        if reader.read_line(&mut req).is_err() {
            return;
        }
        drain_headers(&mut reader);
        let path = req.split_whitespace().nth(1).unwrap_or("/");
        let (status, location, body) = routes.get(path).map_or_else(
            || (404, None, Vec::new()),
            |r| (r.status, r.location.clone(), r.body.clone()),
        );
        let reason = match status {
            200 => "OK",
            302 => "Found",
            404 => "Not Found",
            _ => "Error",
        };
        let mut head = format!(
            "HTTP/1.0 {status} {reason}\r\nContent-Length: {}\r\n",
            body.len()
        );
        if let Some(loc) = location {
            head.push_str("Location: ");
            head.push_str(&loc);
            head.push_str("\r\n");
        }
        head.push_str("Connection: close\r\n\r\n");
        drop(stream.write_all(head.as_bytes()));
        drop(stream.write_all(&body));
    }

    fn drain_headers(reader: &mut BufReader<std::net::TcpStream>) {
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            if line == "\r\n" || line == "\n" || line.is_empty() {
                break;
            }
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(64);
        for b in digest {
            std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}")).ok();
        }
        out
    }

    fn append_bytes(builder: &mut Builder<Vec<u8>>, name: &str, data: &[u8], mode: u32) {
        let mut header = Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(mode);
        header.set_cksum();
        builder.append_data(&mut header, name, data).unwrap();
    }

    fn append_symlink(builder: &mut Builder<Vec<u8>>, name: &str, target: &str) {
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        builder.append_link(&mut header, name, target).unwrap();
    }

    fn complete_tarball() -> Vec<u8> {
        let guest = test_static_guest_elf(b"PAYLOAD-GUEST-OK");
        let mut tar = Builder::new(Vec::new());
        tar.follow_symlinks(false);
        append_bytes(&mut tar, "bux", b"bux-bin", 0o755);
        append_bytes(&mut tar, "bux-shim", b"shim-bin", 0o755);
        append_bytes(&mut tar, &guest_binary_name(), &guest, 0o755);
        if cfg!(target_os = "macos") {
            append_bytes(&mut tar, "libkrun.dylib", b"krun", 0o644);
            append_symlink(&mut tar, "libkrun.1.dylib", "libkrun.dylib");
            append_bytes(&mut tar, "libkrunfw.dylib", b"firmware", 0o644);
            append_symlink(&mut tar, "libkrunfw.5.dylib", "libkrunfw.dylib");
        } else {
            append_bytes(&mut tar, "libkrun.so", b"krun", 0o644);
            append_symlink(&mut tar, "libkrun.so.1", "libkrun.so");
            append_bytes(&mut tar, "libkrunfw.so", b"firmware", 0o644);
            append_symlink(&mut tar, "libkrunfw.so.5", "libkrunfw.so");
            append_bytes(&mut tar, "bwrap", b"bwrap-bin", 0o755);
        }
        append_bytes(&mut tar, "LICENSE-MIT", b"MIT", 0o644);
        append_bytes(&mut tar, "LICENSE-APACHE", b"APACHE", 0o644);
        let tar_bytes = tar.into_inner().unwrap();
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&tar_bytes).unwrap();
        enc.finish().unwrap()
    }

    fn product_urls(target: &str) -> (String, String) {
        let ver = env!("CARGO_PKG_VERSION");
        (
            format!("/v{ver}/bux-{ver}-{target}.tar.gz"),
            format!("/v{ver}/bux-{ver}-{target}.tar.gz.sha256"),
        )
    }

    #[test]
    fn host_target_equals_cd_matrix() {
        let target = host_target().expect("this host must be a CD matrix member");
        assert!(
            CD_MATRIX.contains(&target),
            "host_target {target} is not a cd.yml matrix member {CD_MATRIX:?}"
        );
    }

    #[test]
    fn guest_version_matches_bux_guest_crate() {
        let manifest = include_str!("../../bux-guest/Cargo.toml");
        let parsed = package_version(manifest).expect("bux-guest [package] version");
        assert_eq!(
            GUEST_VERSION, parsed,
            "GUEST_VERSION must equal crates/bux-guest Cargo.toml version"
        );
    }

    fn package_version(toml: &str) -> Option<&str> {
        let mut in_package = false;
        for line in toml.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                in_package = t == "[package]";
                continue;
            }
            if in_package && let Some(rest) = t.strip_prefix("version") {
                let rest = rest.trim().trim_start_matches('=').trim();
                return rest.strip_prefix('"')?.strip_suffix('"');
            }
        }
        None
    }

    #[test]
    fn extract_preserves_firmware_symlink_and_licenses() {
        let fx = Fixture::new();
        let bytes = complete_tarball();
        let dest = fx.payload_root().join(format!(
            "{}-{}",
            env!("CARGO_PKG_VERSION"),
            host_target().unwrap()
        ));
        extract_product(&bytes, &dest).unwrap();
        assert_eq!(
            dest.parent(),
            Some(fx.payload_root()),
            "extract dest must be a child of bux-pkg (same filesystem)"
        );
        assert!(product_complete(&dest), "planted archive must be complete");
        let fw = if cfg!(target_os = "macos") {
            dest.join("libkrunfw.5.dylib")
        } else {
            dest.join("libkrunfw.so.5")
        };
        let meta = fs::symlink_metadata(&fw).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "firmware must stay a symlink"
        );
        assert!(dest.join("LICENSE-MIT").is_file());
        assert!(dest.join("LICENSE-APACHE").is_file());
    }

    #[test]
    fn extract_accepts_license_files() {
        let fx = Fixture::new();
        let bytes = complete_tarball();
        let dest = fx.payload_root().join("lic-dest");
        extract_product(&bytes, &dest).unwrap();
        let mit = fs::read_to_string(dest.join("LICENSE-MIT")).unwrap();
        let apache = fs::read_to_string(dest.join("LICENSE-APACHE")).unwrap();
        assert_eq!(mit, "MIT");
        assert_eq!(apache, "APACHE");
    }

    #[test]
    fn checksum_mismatch_is_invalid_config() {
        let fx = Fixture::new();
        let target = host_target().unwrap();
        let tarball = complete_tarball();
        let (tar_path, sha_path) = product_urls(target);
        let mut routes = HashMap::new();
        routes.insert(
            tar_path,
            MockResp {
                status: 200,
                location: None,
                body: tarball,
            },
        );
        routes.insert(
            sha_path,
            MockResp {
                status: 200,
                location: None,
                body: b"0000000000000000000000000000000000000000000000000000000000000000  x\n"
                    .to_vec(),
            },
        );
        let (base, _h) = serve(routes);
        let fx = fx.with_release(&base);
        let err = ensure_blocking(None, None, false, true).unwrap_err();
        assert!(
            matches!(err, Error::InvalidConfig(_)),
            "checksum mismatch: {err}"
        );
        assert!(err.to_string().contains("sha256"), "{err}");
        drop(fx);
    }

    #[test]
    fn http_404_is_not_found() {
        let fx = Fixture::new();
        let target = host_target().unwrap();
        let (tar_path, sha_path) = product_urls(target);
        let mut routes = HashMap::new();
        routes.insert(
            tar_path,
            MockResp {
                status: 404,
                location: None,
                body: Vec::new(),
            },
        );
        routes.insert(
            sha_path,
            MockResp {
                status: 404,
                location: None,
                body: Vec::new(),
            },
        );
        let (base, _h) = serve(routes);
        let fx = fx.with_release(&base);
        let err = ensure_blocking(None, None, false, true).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "404: {err}");
        assert!(err.to_string().contains("sh.qntx.org/bux"), "{err}");
        drop(fx);
    }

    #[test]
    fn off_allowlist_redirect_is_error() {
        let fx = Fixture::new();
        let target = host_target().unwrap();
        let (tar_path, sha_path) = product_urls(target);
        let dummy = b"deadbeef";
        let mut routes = HashMap::new();
        routes.insert(
            sha_path,
            MockResp {
                status: 200,
                location: None,
                body: format!("{}\n", sha256_hex(dummy)).into_bytes(),
            },
        );
        routes.insert(
            tar_path,
            MockResp {
                status: 302,
                location: Some("http://evil.example/payload".into()),
                body: Vec::new(),
            },
        );
        let (base, _h) = serve(routes);
        let fx = fx.with_release(&base);
        let err = ensure_blocking(None, None, false, true).unwrap_err();
        assert!(
            matches!(err, Error::InvalidConfig(_)),
            "off-allowlist redirect: {err}"
        );
        assert!(
            err.to_string().contains("evil.example") || err.to_string().contains("allowlist"),
            "{err}"
        );
        drop(fx);
    }

    #[test]
    fn sibling_shim_plus_404_product_fetches_guest_only() {
        let fx = Fixture::new();
        fx.plant_shim();
        let target = host_target().unwrap();
        let guest = test_static_guest_elf(b"GUEST-ONLY-FETCH");
        let guest_name = guest_binary_name();
        let (tar_path, sha_path) = product_urls(target);
        let guest_path = format!("/guest-v{GUEST_VERSION}/{guest_name}");
        let guest_sha = format!("{guest_path}.sha256");
        let mut routes = HashMap::new();
        routes.insert(
            tar_path,
            MockResp {
                status: 404,
                location: None,
                body: Vec::new(),
            },
        );
        routes.insert(
            sha_path,
            MockResp {
                status: 404,
                location: None,
                body: Vec::new(),
            },
        );
        routes.insert(
            guest_path,
            MockResp {
                status: 200,
                location: None,
                body: guest.clone(),
            },
        );
        routes.insert(
            guest_sha,
            MockResp {
                status: 200,
                location: None,
                body: format!("{}\n", sha256_hex(&guest)).into_bytes(),
            },
        );
        let (base, _h) = serve(routes);
        let fx = fx.with_release(&base);
        let resolved = ensure_blocking(None, None, false, true).unwrap();
        let expected = fx
            .payload_root()
            .join(format!("guest-v{GUEST_VERSION}"))
            .join(&guest_name);
        assert_eq!(resolved.guest, expected, "guest-only dest");
        assert_eq!(fs::read(&resolved.guest).unwrap(), guest);
        assert!(
            !product_dir(target).exists(),
            "must not create an incomplete product dir"
        );
        drop(fx);
    }
}
