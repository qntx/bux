#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use std::fmt::Write;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::{Error, Result};

const GUEST_EXEC_PATH: &str = "/bux/bin/bux-guest";
const GUEST_RELATIVE_PATH: &str = "bux/bin/bux-guest";
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EM_X86_64: u16 = 0x3E;
const EM_AARCH64: u16 = 0xB7;
const PT_INTERP: u32 = 3;
const IMAGE_INJECTION_MARGIN_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ManagedGuestBinary {
    host_path: PathBuf,
    cache_key: String,
    size_bytes: u64,
}

impl ManagedGuestBinary {
    pub(crate) fn resolve() -> Result<Self> {
        let mut invalid = Vec::new();
        for path in candidate_paths() {
            if !path.exists() {
                continue;
            }
            match Self::from_path(&path) {
                Ok(guest) => return Ok(guest),
                Err(err) => invalid.push(format!("{}: {err}", path.display())),
            }
        }

        let target = linux_guest_target();
        if invalid.is_empty() {
            return Err(Error::NotFound(format!(
                "no valid Linux bux-guest binary found; set BUX_GUEST_PATH to a static {target} build"
            )));
        }

        Err(Error::InvalidConfig(format!(
            "failed to find a usable Linux bux-guest binary; set BUX_GUEST_PATH to a static {target} build. Candidates: {}",
            invalid.join("; ")
        )))
    }

    fn from_path(path: &Path) -> Result<Self> {
        let data = fs::read(path)?;
        validate_guest_binary(path, &data)?;
        #[allow(clippy::cast_possible_truncation)]
        let size_bytes = data.len() as u64;
        Ok(Self {
            host_path: path.to_path_buf(),
            cache_key: short_hash(&data),
            size_bytes,
        })
    }

    pub(crate) fn versioned_cache_key(&self, base: &str) -> String {
        format!("{base}-guest-{}", self.cache_key)
    }

    pub(crate) const fn exec_path() -> &'static str {
        GUEST_EXEC_PATH
    }

    pub(crate) const fn relative_path() -> &'static str {
        GUEST_RELATIVE_PATH
    }

    pub(crate) const fn image_size_overhead_bytes(&self) -> u64 {
        self.size_bytes.saturating_add(IMAGE_INJECTION_MARGIN_BYTES)
    }

    pub(crate) fn inject_into_rootfs(&self, rootfs: &Path) -> Result<()> {
        let dest = rootfs.join(Self::relative_path());
        if is_binary_up_to_date(&self.host_path, &dest)? {
            return Ok(());
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        if dest.exists() {
            fs::remove_file(&dest)?;
        }
        fs::copy(&self.host_path, &dest)?;
        #[cfg(unix)]
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o555))?;
        Ok(())
    }

    pub(crate) fn inject_into_disk(&self, image: &Path) -> Result<()> {
        bux_e2fs::inject_file(image, &self.host_path, Self::relative_path())?;
        Ok(())
    }
}

fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(explicit) = std::env::var_os("BUX_GUEST_PATH") {
        push_unique_path(&mut paths, PathBuf::from(explicit));
    }

    let names = guest_binary_names();

    if let Ok(current_exe) = std::env::current_exe()
        && let Some(dir) = current_exe.parent()
    {
        for name in &names {
            push_unique_path(&mut paths, dir.join(name));
        }
    }

    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for name in &names {
                push_unique_path(&mut paths, dir.join(name));
            }
        }
    }

    paths
}

fn guest_binary_names() -> [String; 3] {
    [
        format!("bux-guest-{}", linux_guest_target()),
        "bux-guest-linux".to_owned(),
        "bux-guest".to_owned(),
    ]
}

fn linux_guest_target() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-musl",
        "aarch64" => "aarch64-unknown-linux-musl",
        _ => "unknown-linux-musl",
    }
}

fn push_unique_path(paths: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !paths.iter().any(|existing| existing == &candidate) {
        paths.push(candidate);
    }
}

fn validate_guest_binary(path: &Path, data: &[u8]) -> Result<()> {
    if data.len() < 64 {
        return Err(Error::InvalidConfig(format!(
            "guest binary {} is too small to be a valid ELF",
            path.display()
        )));
    }

    if data[..4] != ELF_MAGIC {
        return Err(Error::InvalidConfig(format!(
            "guest binary {} is not a Linux ELF binary",
            path.display()
        )));
    }

    if data[4] != 2 {
        return Err(Error::InvalidConfig(format!(
            "guest binary {} is not a 64-bit ELF",
            path.display()
        )));
    }

    if data[5] != 1 {
        return Err(Error::InvalidConfig(format!(
            "guest binary {} is not little-endian ELF",
            path.display()
        )));
    }

    let expected = expected_machine()?;
    let actual = u16::from_le_bytes([data[18], data[19]]);
    if actual != expected {
        return Err(Error::InvalidConfig(format!(
            "guest binary {} targets {} but this host runtime needs {}; rebuild bux-guest for {}",
            path.display(),
            machine_name(actual),
            machine_name(expected),
            linux_guest_target()
        )));
    }

    if has_pt_interp(data) {
        return Err(Error::InvalidConfig(format!(
            "guest binary {} is dynamically linked; rebuild bux-guest as a static {} binary",
            path.display(),
            linux_guest_target()
        )));
    }

    Ok(())
}

fn expected_machine() -> Result<u16> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(EM_X86_64),
        "aarch64" => Ok(EM_AARCH64),
        arch => Err(Error::InvalidConfig(format!(
            "unsupported host architecture for managed guest validation: {arch}"
        ))),
    }
}

const fn machine_name(machine: u16) -> &'static str {
    match machine {
        EM_X86_64 => "x86_64",
        EM_AARCH64 => "aarch64",
        _ => "unknown",
    }
}

fn has_pt_interp(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false;
    }

    let e_phoff = u64::from_le_bytes(data[32..40].try_into().unwrap_or_default()) as usize;
    let e_phentsize = u16::from_le_bytes(data[54..56].try_into().unwrap_or_default()) as usize;
    let e_phnum = u16::from_le_bytes(data[56..58].try_into().unwrap_or_default()) as usize;
    if e_phoff == 0 || e_phentsize == 0 || e_phnum == 0 {
        return false;
    }

    for idx in 0..e_phnum {
        let Some(offset) = e_phoff.checked_add(idx.saturating_mul(e_phentsize)) else {
            break;
        };
        let Some(end) = offset.checked_add(4) else {
            break;
        };
        if end > data.len() {
            break;
        }
        let p_type = u32::from_le_bytes(data[offset..end].try_into().unwrap_or_default());
        if p_type == PT_INTERP {
            return true;
        }
    }

    false
}

fn is_binary_up_to_date(source: &Path, dest: &Path) -> Result<bool> {
    if !dest.exists() {
        return Ok(false);
    }

    let source_meta = fs::metadata(source)?;
    let dest_meta = fs::metadata(dest)?;
    if source_meta.len() != dest_meta.len() {
        return Ok(false);
    }

    let source_mtime = source_meta.modified()?;
    let dest_mtime = dest_meta.modified()?;
    Ok(dest_mtime >= source_mtime)
}

fn short_hash(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
