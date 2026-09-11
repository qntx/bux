//! OCI layer extraction with whiteout handling.
//!
//! Paths are resolved with a rooted walker. Device and FIFO members are
//! skipped. Directory modes are applied once after the last layer.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, BufReader, Read};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use tar::{Archive, EntryType};
use tracing::{debug, error};

use crate::safe_root::{SYMLINK_HOP_LIMIT, SafeRoot, hop_limit_error};
use crate::{OciError, Result};

/// Media types recognized as gzip-compressed layers.
const GZIP_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
];

/// Returns `true` if the media type indicates gzip compression.
fn is_gzip(media_type: &str) -> bool {
    GZIP_MEDIA_TYPES.contains(&media_type) || media_type.ends_with("+gzip")
}

/// Extracts layer tarballs from disk into a rootfs directory (streaming, low memory).
///
/// Each `(path, media_type)` pair is a layer tarball on disk. Layers are applied
/// in order with full OCI whiteout semantics. One rooted resolver is used for
/// every layer; directory modes are chmod'd deepest-first after the last layer.
///
/// # Errors
///
/// Returns an error if a tarball cannot be read, a path escapes the rootfs, or
/// a filesystem operation fails.
pub fn extract_layer_files(
    layers: &[(impl AsRef<Path>, impl AsRef<str>)],
    rootfs: &Path,
) -> Result<()> {
    fs::create_dir_all(rootfs)?;
    let mut extractor = LayerExtractor::open(rootfs)?;
    for (path, media_type) in layers {
        extractor.extract_tarball(path.as_ref(), is_gzip(media_type.as_ref()))?;
    }
    extractor.finalize()
}

struct LayerExtractor {
    root: SafeRoot,
    deferred_dirs: BTreeMap<PathBuf, u32>,
}

impl std::fmt::Debug for LayerExtractor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LayerExtractor")
            .field("root", &self.root)
            .field("deferred_dirs", &self.deferred_dirs.len())
            .finish()
    }
}

impl Drop for LayerExtractor {
    fn drop(&mut self) {
        if !self.deferred_dirs.is_empty() {
            error!("LayerExtractor dropped without finalize");
        }
    }
}

struct DeferredHardlink {
    link_rel: PathBuf,
    target_rel: PathBuf,
}

impl LayerExtractor {
    fn open(rootfs: &Path) -> Result<Self> {
        Ok(Self {
            root: SafeRoot::open(rootfs)?,
            deferred_dirs: BTreeMap::new(),
        })
    }

    fn extract_tarball(&mut self, path: &Path, gzip: bool) -> Result<()> {
        let file = BufReader::new(File::open(path)?);
        let result = if gzip {
            self.extract_reader(GzDecoder::new(file))
        } else {
            self.extract_reader(file)
        };
        if result.is_err() {
            self.deferred_dirs.clear();
        }
        result
    }

    fn extract_reader(&mut self, reader: impl Read) -> Result<()> {
        let mut archive = Archive::new(reader);
        let mut unpacked = HashSet::new();
        let mut written_rels = HashSet::new();
        let mut deferred_hardlinks = Vec::new();

        for raw_entry in archive.entries()? {
            let mut entry = raw_entry?;
            let raw_path = entry.path()?.into_owned();
            let Some(normalized) = SafeRoot::normalize(&raw_path) else {
                continue;
            };
            if normalized.as_os_str().is_empty() {
                continue;
            }

            let entry_type = entry.header().entry_type();
            let mode = entry.header().mode().unwrap_or(0o644);
            if apply_whiteout(&self.root, &normalized, &unpacked, entry_type)? {
                continue;
            }
            if skip_member(entry_type, &normalized) {
                continue;
            }

            if entry_type == EntryType::Link {
                self.apply_hardlink(
                    &raw_path,
                    &normalized,
                    &entry,
                    &mut deferred_hardlinks,
                    &mut written_rels,
                    &mut unpacked,
                )?;
                continue;
            }

            let safe_path = self.place_leaf(&normalized, entry_type == EntryType::Directory)?;
            match entry_type {
                EntryType::Directory => self.create_directory(&safe_path, mode)?,
                EntryType::Regular | EntryType::GNUSparse | EntryType::Continuous => {
                    write_regular(&safe_path, mode, &mut entry)?;
                }
                EntryType::Symlink => create_symlink(&raw_path, &safe_path, &entry)?,
                other => {
                    debug!(
                        path = %normalized.display(),
                        ?other,
                        "skipping unhandled tar member"
                    );
                    continue;
                }
            }
            written_rels.insert(normalized.clone());
            remember_unpacked(&mut unpacked, self.root.root_path(), &safe_path);
        }

        self.flush_hardlinks(deferred_hardlinks, &written_rels)
    }

    fn place_leaf(&self, normalized: &Path, keep_dir: bool) -> Result<PathBuf> {
        let (parent_rel, leaf) = split_parent_leaf(normalized);
        let safe_parent = self.root.resolve_or_root(&parent_rel)?;
        ensure_dir(&safe_parent, self.root.root_path())?;
        let safe_path = safe_parent.join(&leaf);
        ensure_inside(self.root.root_path(), &safe_path)?;
        remove_nofollow(&safe_path, keep_dir)?;
        Ok(safe_path)
    }

    fn create_directory(&mut self, safe_path: &Path, mode: u32) -> Result<()> {
        if fs::symlink_metadata(safe_path).is_err() {
            fs::create_dir(safe_path)?;
        }
        self.deferred_dirs
            .insert(safe_path.to_path_buf(), mode & 0o7777);
        Ok(())
    }

    fn apply_hardlink<R: Read>(
        &self,
        raw_path: &Path,
        normalized: &Path,
        entry: &tar::Entry<'_, R>,
        deferred: &mut Vec<DeferredHardlink>,
        written_rels: &mut HashSet<PathBuf>,
        unpacked: &mut HashSet<PathBuf>,
    ) -> Result<()> {
        let target = entry.link_name()?.ok_or_else(|| {
            OciError::Extract(format!("hardlink without target: {}", raw_path.display()))
        })?;
        let target_rel = SafeRoot::normalize(&target).ok_or_else(|| {
            OciError::Extract(format!(
                "hardlink target escapes rootfs: {}",
                target.display()
            ))
        })?;
        let (tp, tl) = split_parent_leaf(&target_rel);
        let target_safe = self.root.resolve_or_root(&tp)?.join(&tl);
        ensure_inside(self.root.root_path(), &target_safe)?;
        if fs::symlink_metadata(&target_safe).is_ok() {
            let safe_path = self.place_leaf(normalized, false)?;
            fs::hard_link(&target_safe, &safe_path)?;
            written_rels.insert(normalized.to_path_buf());
            remember_unpacked(unpacked, self.root.root_path(), &safe_path);
        } else {
            deferred.push(DeferredHardlink {
                link_rel: normalized.to_path_buf(),
                target_rel,
            });
        }
        Ok(())
    }

    fn flush_hardlinks(
        &self,
        deferred: Vec<DeferredHardlink>,
        written_rels: &HashSet<PathBuf>,
    ) -> Result<()> {
        for item in deferred {
            if written_rels.contains(&item.link_rel) {
                continue;
            }
            let (tp, tl) = split_parent_leaf(&item.target_rel);
            let target_safe = self.root.resolve_or_root(&tp)?.join(&tl);
            ensure_inside(self.root.root_path(), &target_safe)?;
            if fs::symlink_metadata(&target_safe).is_err() {
                return Err(OciError::Extract(format!(
                    "hardlink target missing: {}",
                    item.target_rel.display()
                )));
            }
            let safe_path = self.place_leaf(&item.link_rel, false)?;
            fs::hard_link(&target_safe, &safe_path)?;
        }
        Ok(())
    }

    fn finalize(mut self) -> Result<()> {
        let dirs = std::mem::take(&mut self.deferred_dirs);
        let mut sorted: Vec<(PathBuf, u32)> = dirs.into_iter().collect();
        sorted.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        for (path, mode) in sorted {
            match fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => {
                    fs::set_permissions(&path, Permissions::from_mode(mode))?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn write_regular<R: Read>(
    safe_path: &Path,
    mode: u32,
    entry: &mut tar::Entry<'_, R>,
) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode & 0o7777)
        .open(safe_path)?;
    io::copy(entry, &mut file)?;
    fs::set_permissions(safe_path, Permissions::from_mode(mode & 0o7777))?;
    Ok(())
}

fn skip_member(entry_type: EntryType, normalized: &Path) -> bool {
    match entry_type {
        EntryType::Block | EntryType::Char | EntryType::Fifo => {
            debug!(
                path = %normalized.display(),
                ?entry_type,
                "skipping device/fifo tar member"
            );
            true
        }
        EntryType::XGlobalHeader | EntryType::XHeader => true,
        EntryType::Directory
        | EntryType::Regular
        | EntryType::GNUSparse
        | EntryType::Continuous
        | EntryType::Link
        | EntryType::Symlink => false,
        other => {
            debug!(
                path = %normalized.display(),
                ?other,
                "skipping unhandled tar member"
            );
            true
        }
    }
}

fn create_symlink<R: Read>(
    raw_path: &Path,
    safe_path: &Path,
    entry: &tar::Entry<'_, R>,
) -> Result<()> {
    let target = entry.link_name()?.ok_or_else(|| {
        OciError::Extract(format!("symlink without target: {}", raw_path.display()))
    })?;
    std::os::unix::fs::symlink(&target, safe_path)?;
    Ok(())
}

fn split_parent_leaf(rel: &Path) -> (PathBuf, PathBuf) {
    let parent = rel.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
    let leaf = rel.file_name().map_or_else(PathBuf::new, PathBuf::from);
    (parent, leaf)
}

fn ensure_inside(root: &Path, path: &Path) -> Result<()> {
    if path.starts_with(root) {
        return Ok(());
    }
    error!(
        root = %root.display(),
        path = %path.display(),
        "extract write-escape"
    );
    Err(OciError::Extract(format!(
        "path escapes rootfs: {}",
        path.display()
    )))
}

fn ensure_dir(path: &Path, root: &Path) -> Result<()> {
    if fs::create_dir_all(path).is_ok() {
        return Ok(());
    }
    let mut cursor = path;
    while cursor.starts_with(root) && cursor != root {
        if let Ok(m) = fs::symlink_metadata(cursor)
            && !m.is_dir()
        {
            fs::remove_file(cursor)?;
            break;
        }
        match cursor.parent() {
            Some(p) => cursor = p,
            None => break,
        }
    }
    fs::create_dir_all(path)?;
    Ok(())
}

fn remove_nofollow(path: &Path, keep_if_dir: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            let is_real_dir = meta.is_dir() && !meta.file_type().is_symlink();
            if keep_if_dir && is_real_dir {
                return Ok(());
            }
            let first = if is_real_dir {
                fs::remove_dir_all(path)
            } else {
                fs::remove_file(path)
            };
            match first {
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    if let Some(parent) = path.parent() {
                        make_user_writable(parent);
                    }
                    make_user_writable(path);
                    if is_real_dir {
                        fs::remove_dir_all(path)?;
                    } else {
                        fs::remove_file(path)?;
                    }
                }
                Err(e) => return Err(e.into()),
                Ok(()) => {}
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn make_user_writable(path: &Path) {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return;
        }
        let mode = meta.permissions().mode();
        if mode & 0o200 == 0
            && let Err(e) = fs::set_permissions(path, Permissions::from_mode(mode | 0o200))
        {
            debug!(error = %e, path = %path.display(), "chmod u+w for unlink");
        }
    }
}

fn remember_unpacked(unpacked: &mut HashSet<PathBuf>, root: &Path, path: &Path) {
    let mut current = path;
    while current != root {
        unpacked.insert(current.to_path_buf());
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent;
    }
}

fn apply_whiteout(
    root: &SafeRoot,
    rel: &Path,
    unpacked: &HashSet<PathBuf>,
    entry_type: EntryType,
) -> Result<bool> {
    if !matches!(entry_type, EntryType::Regular | EntryType::GNUSparse) {
        return Ok(false);
    }
    let Some(base) = rel.file_name().and_then(|n| n.to_str()) else {
        return Ok(false);
    };

    if base == ".wh..wh..opq" {
        let parent_rel = rel.parent().unwrap_or_else(|| Path::new(""));
        apply_opaque_whiteout(root, parent_rel, unpacked)?;
        return Ok(true);
    }

    if let Some(target_name) = base.strip_prefix(".wh.") {
        if target_name.is_empty() || target_name == "." || target_name == ".." {
            return Err(OciError::Extract(format!("invalid whiteout name: {base}")));
        }
        let parent_rel = rel.parent().unwrap_or_else(|| Path::new(""));
        refuse_whiteout_escape(root, parent_rel)?;
        let target_safe = root.resolve_or_root(parent_rel)?.join(target_name);
        ensure_inside(root.root_path(), &target_safe)?;
        if fs::symlink_metadata(&target_safe).is_ok() {
            remove_nofollow(&target_safe, false)?;
        }
        return Ok(true);
    }

    Ok(false)
}

fn apply_opaque_whiteout(
    root: &SafeRoot,
    dir_rel: &Path,
    unpacked: &HashSet<PathBuf>,
) -> Result<()> {
    refuse_whiteout_escape(root, dir_rel)?;
    let dir_abs = root.resolve_or_root(dir_rel)?;
    ensure_inside(root.root_path(), &dir_abs)?;
    if !dir_abs.exists() {
        return Ok(());
    }
    clear_dir(&dir_abs, unpacked)
}

/// Whiteouts that would follow a host-escaping symlink must fail, not re-anchor.
fn refuse_whiteout_escape(root: &SafeRoot, parent_rel: &Path) -> Result<()> {
    if !whiteout_parent_escapes(root.root_path(), parent_rel)? {
        return Ok(());
    }
    error!(
        path = %parent_rel.display(),
        "extract write-escape"
    );
    Err(OciError::Extract(format!(
        "path escapes rootfs: {}",
        parent_rel.display()
    )))
}

fn push_path_components(out: &mut VecDeque<OsString>, path: &Path) {
    for c in path.components() {
        match c {
            Component::Normal(s) => out.push_back(s.to_os_string()),
            Component::ParentDir => out.push_back(OsString::from("..")),
            _ => {}
        }
    }
}

fn prepend_path_components(remaining: &mut VecDeque<OsString>, path: &Path) {
    let mut parts = VecDeque::new();
    push_path_components(&mut parts, path);
    while let Some(part) = parts.pop_back() {
        remaining.push_front(part);
    }
}

fn whiteout_parent_escapes(root: &Path, parent_rel: &Path) -> Result<bool> {
    let mut resolved = PathBuf::new();
    let mut hops: u32 = 0;
    let mut remaining = VecDeque::new();
    push_path_components(&mut remaining, parent_rel);

    while let Some(comp) = remaining.pop_front() {
        if comp == ".." {
            if resolved.as_os_str().is_empty() {
                return Ok(true);
            }
            resolved.pop();
            continue;
        }
        resolved.push(&comp);
        let full = root.join(&resolved);
        match fs::symlink_metadata(&full) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
            Ok(meta) if meta.file_type().is_symlink() => {
                hops += 1;
                if hops > SYMLINK_HOP_LIMIT {
                    return Err(hop_limit_error(parent_rel));
                }
                let target = fs::read_link(&full)
                    .map_err(|e| OciError::Extract(format!("readlink {}: {e}", full.display())))?;
                resolved.pop();
                match classify_host_target(root, &root.join(&resolved), &target) {
                    HostFollow::Escape => return Ok(true),
                    HostFollow::Rel => prepend_path_components(&mut remaining, &target),
                    HostFollow::Abs(in_root) => resolved = in_root,
                }
            }
            Ok(_) => {}
        }
    }
    Ok(false)
}

enum HostFollow {
    Escape,
    Rel,
    Abs(PathBuf),
}

fn relative_target_escapes(root: &Path, link_parent: &Path, target: &Path) -> bool {
    let mut acc = link_parent.to_path_buf();
    for comp in target.components() {
        match comp {
            Component::ParentDir if acc == root => return true,
            Component::ParentDir => {
                acc.pop();
            }
            Component::Normal(c) => acc.push(c),
            _ => {}
        }
    }
    !acc.starts_with(root)
}

fn classify_host_target(root: &Path, link_parent: &Path, target: &Path) -> HostFollow {
    if !target.is_absolute() {
        if relative_target_escapes(root, link_parent, target) {
            return HostFollow::Escape;
        }
        return HostFollow::Rel;
    }
    let norm = lexical_normalize(target);
    if !norm.starts_with(root) {
        return HostFollow::Escape;
    }
    HostFollow::Abs(
        norm.strip_prefix(root)
            .map(Path::to_path_buf)
            .unwrap_or_default(),
    )
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut acc = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => acc.push(comp),
            Component::CurDir => {}
            Component::ParentDir => {
                acc.pop();
            }
            Component::Normal(c) => acc.push(c),
        }
    }
    acc
}

fn clear_dir(dir: &Path, unpacked: &HashSet<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let is_real_dir = meta.is_dir() && !meta.file_type().is_symlink();
        if unpacked.contains(&path) {
            if is_real_dir {
                clear_dir(&path, unpacked)?;
            }
            continue;
        }
        remove_nofollow(&path, false)?;
    }
    Ok(())
}
