#![allow(
    missing_docs,
    clippy::missing_docs_in_private_items,
    reason = "internal module with crate-private API surface"
)]

use std::fmt::Write;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::util::{push_unique_path, sidecar_path};
use crate::{Error, Result};

const GUEST_EXEC_PATH: &str = "/bux/bin/bux-guest";
const GUEST_RELATIVE_PATH: &str = "bux/bin/bux-guest";
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EM_X86_64: u16 = 0x3E;
const EM_AARCH64: u16 = 0xB7;
const PT_INTERP: u32 = 3;
const IMAGE_INJECTION_MARGIN_BYTES: u64 = 8 * 1024 * 1024;
const ELF_PROTOCOL_STAMP: &[u8] = b"bux-guest-protocol-v10";

#[derive(Debug, Clone)]
pub(crate) struct ManagedGuestBinary {
    host_path: PathBuf,
    cache_key: String,
    size_bytes: u64,
}

impl ManagedGuestBinary {
    pub(crate) fn resolve(explicit: Option<&Path>) -> Result<Self> {
        if let Some(path) = explicit {
            if !path.is_file() {
                return Err(Error::NotFound(format!(
                    "bux-guest not found at {} (RuntimeOptions.guest_path)",
                    path.display()
                )));
            }
            return Self::from_path(path);
        }

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

        let name = guest_binary_name();
        if invalid.is_empty() {
            return Err(Error::NotFound(
                "bux payload not found; install with: curl -fsSL https://sh.qntx.org/bux | sh"
                    .into(),
            ));
        }

        Err(Error::InvalidConfig(format!(
            "failed to find a usable Linux bux-guest binary ({name}). Candidates: {}",
            invalid.join("; ")
        )))
    }

    pub(crate) fn from_path(path: &Path) -> Result<Self> {
        let data = fs::read(path)?;
        validate_guest_binary(path, &data)?;
        #[allow(clippy::cast_possible_truncation, reason = "file sizes fit in u64")]
        let size_bytes = data.len() as u64;
        Ok(Self {
            host_path: path.to_path_buf(),
            cache_key: short_hash(&data),
            size_bytes,
        })
    }

    pub(crate) fn versioned_cache_key(&self, base: &str) -> String {
        format!("{base}-guest-{}-x", self.cache_key)
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
            #[cfg(unix)]
            fs::set_permissions(&dest, fs::Permissions::from_mode(0o555))?;
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
        let staged = stage_executable_copy(&self.host_path, image)?;
        let _guard = UnlinkOnDrop(staged.clone());
        bux_e2fs::inject_file(image, &staged, Self::relative_path())?;
        Ok(())
    }
}

#[derive(Debug)]
struct UnlinkOnDrop(PathBuf);

impl Drop for UnlinkOnDrop {
    fn drop(&mut self) {
        drop(fs::remove_file(&self.0));
    }
}

fn stage_executable_copy(src: &Path, beside: &Path) -> Result<PathBuf> {
    let dest = beside.with_extension("guest-inject");
    if let Err(err) = fs::copy(src, &dest) {
        drop(fs::remove_file(&dest));
        return Err(err.into());
    }
    if let Err(err) = fs::set_permissions(&dest, fs::Permissions::from_mode(0o555)) {
        drop(fs::remove_file(&dest));
        return Err(err.into());
    }
    match fs::metadata(&dest) {
        Ok(meta) if meta.permissions().mode() & 0o111 != 0 => Ok(dest),
        Ok(_) => {
            drop(fs::remove_file(&dest));
            Err(Error::InvalidConfig(
                "guest binary is not executable after staging".to_owned(),
            ))
        }
        Err(err) => {
            drop(fs::remove_file(&dest));
            Err(err.into())
        }
    }
}

fn candidate_paths() -> Vec<PathBuf> {
    candidate_paths_from(std::env::current_exe().ok().as_deref())
}

fn candidate_paths_from(exe: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let name = guest_binary_name();

    if let Some(exe) = exe
        && let Some(sibling) = sidecar_path(exe, &name)
    {
        push_unique_path(&mut paths, sibling);
    }

    paths
}

pub(crate) fn guest_binary_name() -> String {
    format!("bux-guest-{}", linux_guest_target())
}

pub(crate) fn linux_guest_target() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-musl",
        "aarch64" => "aarch64-unknown-linux-musl",
        _ => "unknown-linux-musl",
    }
}

#[allow(
    clippy::indexing_slicing,
    reason = "all indices are within bounds: data.len() >= 64 is checked upfront"
)]
fn validate_guest_binary(path: &Path, data: &[u8]) -> Result<()> {
    if data.len() < 64 {
        return Err(Error::InvalidConfig(format!(
            "guest binary {} is too small to be a valid ELF",
            path.display()
        )));
    }

    if data.get(..4) != Some(&ELF_MAGIC) {
        return Err(Error::InvalidConfig(format!(
            "guest binary {} is not a Linux ELF binary",
            path.display()
        )));
    }

    if data.get(4) != Some(&2) {
        return Err(Error::InvalidConfig(format!(
            "guest binary {} is not a 64-bit ELF",
            path.display()
        )));
    }

    if data.get(5) != Some(&1) {
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

    if !data
        .windows(ELF_PROTOCOL_STAMP.len())
        .any(|w| w == ELF_PROTOCOL_STAMP)
    {
        return Err(Error::InvalidConfig(format!(
            "guest binary {} is missing bux-guest-protocol-v10",
            path.display()
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

#[allow(
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    reason = "ELF offsets fit in usize on 64-bit; all slicing is bounds-checked"
)]
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
        write!(out, "{byte:02x}").ok();
    }
    out
}

// libext2fs getmntinfo is not thread-safe on macOS; tests that build images
// must run serially.
#[cfg(all(test, unix))]
pub(crate) static EXT4_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Static Linux ELF for this host with a unique 16-byte tag at offset 64.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test helper")]
pub(crate) fn test_static_guest_elf(tag: &[u8; 16]) -> Vec<u8> {
    let machine = expected_machine().unwrap();
    let mut data = vec![0_u8; 128];
    data[..4].copy_from_slice(&ELF_MAGIC);
    data[4] = 2;
    data[5] = 1;
    data[6] = 1;
    data[18..20].copy_from_slice(&machine.to_le_bytes());
    data[64..80].copy_from_slice(tag);
    data.extend_from_slice(ELF_PROTOCOL_STAMP);
    data
}

#[cfg(test)]
#[allow(
    unsafe_code,
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "tests isolate PATH and BUX_*_PATH under a mutex"
)]
pub(crate) mod sidecar_env {
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());

    #[must_use]
    pub(crate) struct Guard {
        _lock: MutexGuard<'static, ()>,
        restores: Vec<(&'static str, Option<OsString>)>,
    }

    pub(crate) fn lock() -> Guard {
        Guard {
            _lock: LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            restores: Vec::new(),
        }
    }

    impl Guard {
        pub(crate) fn set(&mut self, key: &'static str, val: impl AsRef<OsStr>) {
            if !self.restores.iter().any(|(k, _)| *k == key) {
                self.restores.push((key, std::env::var_os(key)));
            }
            // SAFETY: `LOCK` serializes env mutation for sidecar tests.
            unsafe { std::env::set_var(key, val) };
        }

        pub(crate) fn unset(&mut self, key: &'static str) {
            if !self.restores.iter().any(|(k, _)| *k == key) {
                self.restores.push((key, std::env::var_os(key)));
            }
            // SAFETY: `LOCK` serializes env mutation for sidecar tests.
            unsafe { std::env::remove_var(key) };
        }

        pub(crate) fn prepend_path(&mut self, dir: &Path) {
            let mut dirs = vec![dir.to_path_buf()];
            if let Some(p) = std::env::var_os("PATH") {
                dirs.extend(std::env::split_paths(&p));
            }
            self.set("PATH", std::env::join_paths(&dirs).unwrap());
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            for (key, old) in self.restores.drain(..).rev() {
                restore_var(key, old);
            }
        }
    }

    fn restore_var(key: &'static str, old: Option<OsString>) {
        if let Some(v) = old {
            // SAFETY: caller holds `LOCK` for the Guard lifetime.
            unsafe { std::env::set_var(key, v) };
        } else {
            // SAFETY: caller holds `LOCK` for the Guard lifetime.
            unsafe { std::env::remove_var(key) };
        }
    }

    #[must_use]
    pub(crate) struct Planted {
        path: PathBuf,
        backup: Option<Vec<u8>>,
    }

    impl Planted {
        pub(crate) fn sibling(name: &str, data: &[u8]) -> Self {
            let exe = std::env::current_exe().unwrap();
            let path =
                crate::util::sidecar_path(&exe, name).unwrap_or_else(|| exe.with_file_name(name));
            let backup = fs::read(&path).ok();
            fs::write(&path, data).unwrap();
            Self { path, backup }
        }

        pub(crate) fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for Planted {
        fn drop(&mut self) {
            match &self.backup {
                Some(bytes) => drop(fs::write(&self.path, bytes)),
                None => drop(fs::remove_file(&self.path)),
            }
        }
    }

    /// Removes a sibling sidecar for the duration of a test, then restores it.
    #[must_use]
    pub(crate) struct Hidden {
        path: PathBuf,
        backup: Option<Vec<u8>>,
    }

    impl Hidden {
        pub(crate) fn sibling(name: &str) -> Self {
            let exe = std::env::current_exe().unwrap();
            let path =
                crate::util::sidecar_path(&exe, name).unwrap_or_else(|| exe.with_file_name(name));
            let backup = fs::read(&path).ok();
            drop(fs::remove_file(&path));
            Self { path, backup }
        }
    }

    impl Drop for Hidden {
        fn drop(&mut self) {
            match &self.backup {
                Some(bytes) => drop(fs::write(&self.path, bytes)),
                None => drop(fs::remove_file(&self.path)),
            }
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
    use std::os::unix::fs::PermissionsExt;

    fn make_elf(machine: u16, with_interp: bool) -> Vec<u8> {
        let mut data = vec![0_u8; 128];
        data[0..4].copy_from_slice(&ELF_MAGIC);
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;
        data[18..20].copy_from_slice(&machine.to_le_bytes());
        if with_interp {
            data[32..40].copy_from_slice(&64_u64.to_le_bytes());
            data[54..56].copy_from_slice(&56_u16.to_le_bytes());
            data[56..58].copy_from_slice(&1_u16.to_le_bytes());
            data[64..68].copy_from_slice(&PT_INTERP.to_le_bytes());
        }
        data.extend_from_slice(ELF_PROTOCOL_STAMP);
        data
    }

    #[test]
    fn accepts_static_elf_for_host_arch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bux-guest");
        let machine = expected_machine().unwrap();
        fs::write(&path, make_elf(machine, false)).unwrap();
        assert!(ManagedGuestBinary::from_path(&path).is_ok());
    }

    #[test]
    fn rejects_non_elf_binary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bux-guest");
        fs::write(&path, b"not-elf").unwrap();
        let err = ManagedGuestBinary::from_path(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("valid ELF") || err.contains("Linux ELF"));
    }

    #[test]
    fn rejects_wrong_arch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bux-guest");
        let machine = match expected_machine().unwrap() {
            EM_X86_64 => EM_AARCH64,
            EM_AARCH64 => EM_X86_64,
            other => other,
        };
        fs::write(&path, make_elf(machine, false)).unwrap();
        let err = ManagedGuestBinary::from_path(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("targets"));
    }

    #[test]
    fn rejects_dynamic_elf() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bux-guest");
        fs::write(&path, make_elf(expected_machine().unwrap(), true)).unwrap();
        let err = ManagedGuestBinary::from_path(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("dynamically linked"));
    }

    #[test]
    fn rejects_static_elf_missing_protocol_stamp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bux-guest");
        let mut data = make_elf(expected_machine().unwrap(), false);
        data.truncate(data.len() - ELF_PROTOCOL_STAMP.len());
        assert!(
            !data
                .windows(ELF_PROTOCOL_STAMP.len())
                .any(|w| w == ELF_PROTOCOL_STAMP),
            "precondition: fixture has no protocol stamp"
        );
        fs::write(&path, data).unwrap();
        let err = ManagedGuestBinary::from_path(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("bux-guest-protocol-v10"), "{err}");
    }

    #[test]
    fn versioned_cache_key_includes_guest_hash() {
        let guest = ManagedGuestBinary {
            host_path: PathBuf::from("/tmp/bux-guest"),
            cache_key: "deadbeefcafebabe".to_owned(),
            size_bytes: 123,
        };
        assert_eq!(
            guest.versioned_cache_key("rootfs-digest"),
            "rootfs-digest-guest-deadbeefcafebabe-x"
        );
    }

    #[test]
    fn stage_executable_copy_sets_0555_from_0644() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("guest");
        let beside = dir.path().join("image.raw.tmp");
        fs::write(&src, test_static_guest_elf(b"STAGE-COPY-0555!")).unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o644)).unwrap();
        let dest = stage_executable_copy(&src, &beside).unwrap();
        let mode = fs::metadata(&dest).unwrap().permissions().mode();
        assert_ne!(mode & 0o111, 0, "staged copy must be executable");
        assert_eq!(mode & 0o777, 0o555, "staged copy mode must be 0555");
    }

    #[test]
    fn inject_into_rootfs_sets_0555_from_0644_source() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("guest");
        fs::write(&src, test_static_guest_elf(b"ROOTFS-COPY-0555")).unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o644)).unwrap();
        let guest = ManagedGuestBinary::from_path(&src).unwrap();
        guest.inject_into_rootfs(dir.path()).unwrap();
        let dest = dir.path().join(ManagedGuestBinary::relative_path());
        let mode = fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o555, "rootfs dest must be 0555");
    }

    #[test]
    fn inject_into_rootfs_repairs_existing_0644_dest() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("guest");
        let bytes = test_static_guest_elf(b"REPAIR-ROOTFS-OK");
        fs::write(&src, &bytes).unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o644)).unwrap();
        let dest = dir.path().join(ManagedGuestBinary::relative_path());
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::copy(&src, &dest).unwrap();
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            is_binary_up_to_date(&src, &dest).unwrap(),
            "precondition: dest is up to date so inject skips copy"
        );
        let guest = ManagedGuestBinary::from_path(&src).unwrap();
        guest.inject_into_rootfs(dir.path()).unwrap();
        let mode = fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o555,
            "stale 0644 dest must be repaired to 0555"
        );
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "ext4 lock must outlive create_from_dir and namei"
    )]
    fn inject_into_disk_sets_ext4_inode_0555_from_0644_source() {
        let _lock = EXT4_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs");
        fs::create_dir(&rootfs).unwrap();
        let image = dir.path().join("image.raw");
        bux_e2fs::create_from_dir(&rootfs, &image, 64 * 1024 * 1024).unwrap();

        let planted = dir.path().join("planted-guest");
        fs::write(&planted, test_static_guest_elf(b"INODE-GATE-0555!")).unwrap();
        fs::set_permissions(&planted, fs::Permissions::from_mode(0o644)).unwrap();

        let guest = ManagedGuestBinary::from_path(&planted).unwrap();
        guest.inject_into_disk(&image).unwrap();

        let ext4 = bux_e2fs::Filesystem::open(&image).unwrap();
        let ino = ext4.namei(ManagedGuestBinary::relative_path()).unwrap();
        let inode = ext4.read_inode(ino).unwrap();
        assert_eq!(
            u32::from(inode.i_mode) & 0o777,
            0o555,
            "ext4 inode permission bits must be 0555"
        );
        assert_eq!(
            u32::from(inode.i_mode) & 0o170_000,
            0o100_000,
            "ext4 inode must be a regular file"
        );

        let host_mode = fs::metadata(&planted).unwrap().permissions().mode();
        assert_eq!(
            host_mode & 0o777,
            0o644,
            "inject must not chmod the host planted file"
        );
        assert!(
            !image.with_extension("guest-inject").exists(),
            "sidecar *.guest-inject must be gone after inject_into_disk"
        );
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive resolve"
    )]
    fn resolve_none_ignores_env_and_path_decoy() {
        let mut env = sidecar_env::lock();
        let _hidden = sidecar_env::Hidden::sibling(&guest_binary_name());
        let decoy_dir = tempfile::tempdir().unwrap();
        let decoy_bytes = test_static_guest_elf(b"DECOY-GUEST-ELF!");
        let decoy = decoy_dir.path().join(guest_binary_name());
        fs::write(&decoy, &decoy_bytes).unwrap();
        env.prepend_path(decoy_dir.path());
        env.set("BUX_GUEST_PATH", &decoy);

        let err = ManagedGuestBinary::resolve(None).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, Error::NotFound(_)), "{msg}");
        assert!(
            msg.contains("sh.qntx.org/bux"),
            "None search must name the install URL, not env: {msg}"
        );
        assert!(!msg.contains("BUX_GUEST_PATH"), "{msg}");
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive resolve"
    )]
    fn resolve_some_missing_does_not_consult_path() {
        let mut env = sidecar_env::lock();
        let decoy_dir = tempfile::tempdir().unwrap();
        let decoy_bytes = test_static_guest_elf(b"DECOY-GUEST-ELF!");
        fs::write(decoy_dir.path().join("bux-guest"), &decoy_bytes).unwrap();
        env.prepend_path(decoy_dir.path());
        env.set("BUX_GUEST_PATH", decoy_dir.path().join("bux-guest"));

        let missing = decoy_dir.path().join("missing-guest");
        let err = ManagedGuestBinary::resolve(Some(&missing)).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, Error::NotFound(_)), "{msg}");
        assert!(msg.contains("RuntimeOptions.guest_path"), "{msg}");
        assert!(!msg.contains("bux binary"), "{msg}");
        assert!(!missing.exists(), "must not create the missing path");
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive resolve"
    )]
    fn resolve_none_finds_planted_sibling() {
        let mut env = sidecar_env::lock();
        env.unset("BUX_GUEST_PATH");
        let planted_bytes = test_static_guest_elf(b"SIBLING-GUEST-OK");
        let planted = sidecar_env::Planted::sibling(&guest_binary_name(), &planted_bytes);
        let guest = ManagedGuestBinary::resolve(None).unwrap();
        assert_eq!(guest.host_path, planted.path());
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive resolve"
    )]
    fn resolve_none_ignores_bux_guest_and_bux_guest_linux_aliases() {
        let mut env = sidecar_env::lock();
        env.unset("BUX_GUEST_PATH");
        let empty = tempfile::tempdir().unwrap();
        env.set("PATH", empty.path());
        let bytes = test_static_guest_elf(b"ALIAS-GUEST-ELF!");
        let alias = sidecar_env::Planted::sibling("bux-guest", &bytes);
        let alias_linux = sidecar_env::Planted::sibling("bux-guest-linux", &bytes);
        match ManagedGuestBinary::resolve(None) {
            Ok(guest) => {
                assert_ne!(
                    guest.host_path,
                    alias.path(),
                    "must not resolve bux-guest alias"
                );
                assert_ne!(
                    guest.host_path,
                    alias_linux.path(),
                    "must not resolve bux-guest-linux alias"
                );
                assert_eq!(
                    guest.host_path.file_name().map(std::ffi::OsStr::to_owned),
                    Some(std::ffi::OsString::from(guest_binary_name())),
                    "production guest name is bux-guest-<musl-triple>"
                );
            }
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    matches!(err, Error::NotFound(_) | Error::InvalidConfig(_)),
                    "{msg}"
                );
                assert!(
                    msg.contains(&guest_binary_name()) || msg.contains("sh.qntx.org/bux"),
                    "not-found must name {name} or the install URL: {msg}",
                    name = guest_binary_name()
                );
            }
        }
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive candidate_paths"
    )]
    fn candidate_paths_only_musl_triple_name() {
        let mut env = sidecar_env::lock();
        env.unset("BUX_GUEST_PATH");
        let empty = tempfile::tempdir().unwrap();
        env.set("PATH", empty.path());
        let exe = std::env::current_exe().unwrap();
        let expected = sidecar_path(&exe, &guest_binary_name()).unwrap();
        let paths = candidate_paths();
        assert!(
            paths.contains(&expected),
            "expected canonical sibling {expected:?} in {paths:?}"
        );
        for path in &paths {
            let name = path.file_name().unwrap().to_string_lossy();
            assert_ne!(&*name, "bux-guest", "{path:?}");
            assert_ne!(&*name, "bux-guest-linux", "{path:?}");
            assert_eq!(&*name, guest_binary_name(), "{path:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive candidate_paths_from"
    )]
    fn candidate_paths_from_symlink_exe_uses_real_dir() {
        let mut env = sidecar_env::lock();
        env.unset("BUX_GUEST_PATH");
        let empty = tempfile::tempdir().unwrap();
        env.set("PATH", empty.path());

        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("real");
        let link_dir = dir.path().join("link");
        fs::create_dir(&real_dir).unwrap();
        fs::create_dir(&link_dir).unwrap();
        let real = real_dir.join("bux");
        fs::write(&real, b"exe").unwrap();
        let link = link_dir.join("bux");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let name = guest_binary_name();
        let planted = real.canonicalize().unwrap().with_file_name(&name);
        fs::write(&planted, b"guest").unwrap();
        let leftover = link_dir.join(&name);
        fs::write(&leftover, b"leftover").unwrap();

        let paths = candidate_paths_from(Some(&link));
        assert!(
            paths.contains(&planted),
            "expected sibling next to the real executable in {paths:?}"
        );
        assert!(
            !paths.contains(&leftover),
            "must not join against the invocation path: {paths:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive candidate_paths_from"
    )]
    fn candidate_paths_from_dangling_symlink_skips_sibling() {
        let mut env = sidecar_env::lock();
        env.unset("BUX_GUEST_PATH");
        let empty = tempfile::tempdir().unwrap();
        env.set("PATH", empty.path());

        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("bux");
        std::os::unix::fs::symlink(dir.path().join("missing"), &link).unwrap();
        let leftover = dir.path().join(guest_binary_name());
        fs::write(&leftover, b"leftover").unwrap();

        let paths = candidate_paths_from(Some(&link));
        assert!(
            !paths.contains(&leftover),
            "unresolved symlink exe must skip sibling lookup: {paths:?}"
        );
    }
}
