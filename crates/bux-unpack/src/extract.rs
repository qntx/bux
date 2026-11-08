//! OCI layer extraction with whiteout handling.
//!
//! Paths are resolved with a rooted walker. Device and FIFO members are
//! skipped. Directory modes are applied once after the last layer.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, BufReader, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use tar::{Archive, EntryType};
use tracing::{debug, error, warn};

use crate::safe_root::{SYMLINK_HOP_LIMIT, SafeRoot, hop_limit_error};
use crate::{Error, Result};

/// Media types recognized as gzip-compressed layers.
const GZIP_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
];

/// PAX record prefix for extended attributes, as Docker and containerd write it.
const PAX_XATTR_PREFIX: &[u8] = b"SCHILY.xattr.";

/// Returns `true` if the media type indicates gzip compression.
pub(crate) fn is_gzip(media_type: &str) -> bool {
    GZIP_MEDIA_TYPES.contains(&media_type) || media_type.ends_with("+gzip")
}

/// Extracts layer tarballs from disk into a rootfs directory (streaming, low memory).
///
/// Each `(path, media_type)` pair is a layer tarball on disk. The layers are
/// applied in order by one [`Extractor`] with default [`Options`].
///
/// # Errors
///
/// Returns an error if a tarball cannot be read, a path escapes the rootfs, or
/// a filesystem operation fails.
pub fn extract_layer_files(
    layers: &[(impl AsRef<Path>, impl AsRef<str>)],
    rootfs: &Path,
) -> Result<()> {
    let mut extractor = Extractor::open(rootfs, Options::default())?;
    for (path, media_type) in layers {
        extractor.extract(File::open(path)?, media_type.as_ref())?;
    }
    extractor.finish()
}

/// How an [`Extractor`] applies member metadata.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Give each written member the uid and gid from its tar header, and
    /// restore its `SCHILY.xattr.*` extended attributes.
    ///
    /// This needs the privilege to `chown`, so it is meant for root. When unset,
    /// the extracting user owns every file and extended attributes are dropped.
    pub keep_owners: bool,
}

/// Applies layer tarballs to a directory in order, with OCI whiteout
/// semantics.
///
/// Every member path is resolved inside the root. Directory modes are applied
/// by [`finish`](Self::finish), deepest first, after the last layer.
///
/// # Example
///
/// ```no_run
/// use std::fs::File;
/// use std::path::Path;
///
/// use bux_unpack::{Extractor, Options};
///
/// let mut extractor = Extractor::open(Path::new("/mnt/target"), Options { keep_owners: true })?;
/// let layer = File::open("layer.tar.gz")?;
/// extractor.extract(layer, "application/vnd.oci.image.layer.v1.tar+gzip")?;
/// extractor.finish()?;
/// # Ok::<(), bux_unpack::Error>(())
/// ```
pub struct Extractor {
    root: SafeRoot,
    options: Options,
    deferred_dirs: BTreeMap<PathBuf, u32>,
}

impl std::fmt::Debug for Extractor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extractor")
            .field("root", &self.root)
            .field("options", &self.options)
            .field("deferred_dirs", &self.deferred_dirs.len())
            .finish()
    }
}

impl Drop for Extractor {
    fn drop(&mut self) {
        if !self.deferred_dirs.is_empty() {
            error!("Extractor dropped without finish");
        }
    }
}

struct DeferredHardlink {
    link_rel: PathBuf,
    target_rel: PathBuf,
}

impl Extractor {
    /// Opens `root` for extraction, creating it if needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created or opened.
    pub fn open(root: &Path, options: Options) -> Result<Self> {
        Ok(Self {
            root: SafeRoot::open(root)?,
            options,
            deferred_dirs: BTreeMap::new(),
        })
    }

    /// Applies one layer read from `layer`, which is buffered here.
    ///
    /// A gzip `media_type` selects gzip decompression; any other type is read
    /// as a plain tar.
    ///
    /// # Errors
    ///
    /// Returns an error if the layer cannot be read, a path escapes the root,
    /// or a filesystem operation fails. The directory modes collected so far
    /// are then discarded, so drop the extractor after an error.
    pub fn extract(&mut self, layer: impl Read, media_type: &str) -> Result<()> {
        let layer = BufReader::new(layer);
        let result = if is_gzip(media_type) {
            self.extract_tar(GzDecoder::new(layer))
        } else {
            self.extract_tar(layer)
        };
        if result.is_err() {
            self.deferred_dirs.clear();
        }
        result
    }

    fn extract_tar(&mut self, tar: impl Read) -> Result<()> {
        let mut archive = Archive::new(tar);
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

            let owner = if self.options.keep_owners {
                Some(Ownership::read(&mut entry, &normalized)?)
            } else {
                None
            };
            let owner = owner.as_ref();
            let safe_path = self.place_leaf(&normalized, entry_type == EntryType::Directory)?;
            match entry_type {
                EntryType::Directory => self.create_directory(&safe_path, mode, owner)?,
                EntryType::Regular | EntryType::GNUSparse | EntryType::Continuous => {
                    write_regular(&safe_path, mode, &mut entry, owner)?;
                }
                EntryType::Symlink => create_symlink(&raw_path, &safe_path, &entry, owner)?,
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

    fn create_directory(
        &mut self,
        safe_path: &Path,
        mode: u32,
        owner: Option<&Ownership>,
    ) -> Result<()> {
        if fs::symlink_metadata(safe_path).is_err() {
            fs::create_dir(safe_path)?;
        }
        if let Some(owner) = owner {
            owner.apply(safe_path, None)?;
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
            Error::Extract(format!("hardlink without target: {}", raw_path.display()))
        })?;
        let target_rel = SafeRoot::normalize(&target).ok_or_else(|| {
            Error::Extract(format!(
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
                return Err(Error::Extract(format!(
                    "hardlink target missing: {}",
                    item.target_rel.display()
                )));
            }
            let safe_path = self.place_leaf(&item.link_rel, false)?;
            fs::hard_link(&target_safe, &safe_path)?;
        }
        Ok(())
    }

    /// Applies the directory modes collected from every layer, deepest first.
    ///
    /// # Errors
    ///
    /// Returns an error if a mode cannot be set.
    pub fn finish(mut self) -> Result<()> {
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
    owner: Option<&Ownership>,
) -> Result<()> {
    let mode = mode & 0o7777;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(safe_path)?;
    io::copy(entry, &mut file)?;
    match owner {
        Some(owner) => owner.apply(safe_path, Some(mode))?,
        None => fs::set_permissions(safe_path, Permissions::from_mode(mode))?,
    }
    Ok(())
}

/// Owner and extended attributes of a tar member, kept with
/// [`Options::keep_owners`].
struct Ownership {
    uid: u32,
    gid: u32,
    xattrs: Vec<(OsString, Vec<u8>)>,
}

impl Ownership {
    /// Reads the header uid and gid, which the tar crate has already replaced
    /// with any PAX `uid` and `gid` records, and the `SCHILY.xattr.*` records.
    fn read<R: Read>(entry: &mut tar::Entry<'_, R>, rel: &Path) -> Result<Self> {
        let header = entry.header();
        let (uid, gid) = (header.uid()?, header.gid()?);
        let (Ok(uid), Ok(gid)) = (u32::try_from(uid), u32::try_from(gid)) else {
            return Err(Error::Extract(format!(
                "owner {uid}:{gid} out of range: {}",
                rel.display()
            )));
        };
        Ok(Self {
            uid,
            gid,
            xattrs: pax_xattrs(entry)?,
        })
    }

    /// Applies the owner, then `mode` if given, then the extended attributes.
    ///
    /// `chown` clears setuid and setgid on executables and removes
    /// `security.capability`, even for root, so it has to come first.
    fn apply(&self, path: &Path, mode: Option<u32>) -> Result<()> {
        std::os::unix::fs::lchown(path, Some(self.uid), Some(self.gid))?;
        if let Some(mode) = mode {
            fs::set_permissions(path, Permissions::from_mode(mode))?;
        }
        for (name, value) in &self.xattrs {
            set_xattr(path, name, value)?;
        }
        Ok(())
    }
}

/// The `SCHILY.xattr.*` PAX records of a member, as names and values.
fn pax_xattrs<R: Read>(entry: &mut tar::Entry<'_, R>) -> Result<Vec<(OsString, Vec<u8>)>> {
    let mut xattrs = Vec::new();
    let Some(extensions) = entry.pax_extensions()? else {
        return Ok(xattrs);
    };
    for extension in extensions {
        let extension = extension?;
        if let Some(name) = extension.key_bytes().strip_prefix(PAX_XATTR_PREFIX) {
            xattrs.push((
                OsStr::from_bytes(name).to_os_string(),
                extension.value_bytes().to_vec(),
            ));
        }
    }
    Ok(xattrs)
}

/// Sets one extended attribute without following symlinks.
///
/// Like containerd, a filesystem without xattr support, or a `security.*`
/// attribute the kernel refuses, is logged and skipped.
fn set_xattr(path: &Path, name: &OsStr, value: &[u8]) -> Result<()> {
    let Err(e) = xattr::set(path, name, value) else {
        return Ok(());
    };
    let skippable = e.kind() == io::ErrorKind::Unsupported
        || (e.kind() == io::ErrorKind::PermissionDenied
            && name.as_bytes().starts_with(b"security."));
    if !skippable {
        return Err(Error::Extract(format!(
            "set xattr {} on {}: {e}",
            name.to_string_lossy(),
            path.display()
        )));
    }
    warn!(
        path = %path.display(),
        name = %name.to_string_lossy(),
        error = %e,
        "skipping xattr"
    );
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
    owner: Option<&Ownership>,
) -> Result<()> {
    let target = entry
        .link_name()?
        .ok_or_else(|| Error::Extract(format!("symlink without target: {}", raw_path.display())))?;
    std::os::unix::fs::symlink(&target, safe_path)?;
    if let Some(owner) = owner {
        owner.apply(safe_path, None)?;
    }
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
    Err(Error::Extract(format!(
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

/// What an OCI whiteout member removes.
pub(crate) enum Whiteout<'a> {
    /// `.wh..wh..opq`: everything lower layers put in the parent directory.
    Opaque,
    /// `.wh.<name>`: the sibling `<name>`.
    Entry(&'a str),
}

/// Classifies a member as a whiteout. Only regular files are whiteouts.
pub(crate) fn whiteout(entry_type: EntryType, rel: &Path) -> Option<Whiteout<'_>> {
    if !matches!(entry_type, EntryType::Regular | EntryType::GNUSparse) {
        return None;
    }
    let base = rel.file_name()?.to_str()?;
    if base == ".wh..wh..opq" {
        return Some(Whiteout::Opaque);
    }
    base.strip_prefix(".wh.").map(Whiteout::Entry)
}

fn apply_whiteout(
    root: &SafeRoot,
    rel: &Path,
    unpacked: &HashSet<PathBuf>,
    entry_type: EntryType,
) -> Result<bool> {
    let Some(whiteout) = whiteout(entry_type, rel) else {
        return Ok(false);
    };
    let parent_rel = rel.parent().unwrap_or_else(|| Path::new(""));
    match whiteout {
        Whiteout::Opaque => apply_opaque_whiteout(root, parent_rel, unpacked)?,
        Whiteout::Entry(target_name) => {
            if target_name.is_empty() || target_name == "." || target_name == ".." {
                return Err(Error::Extract(format!(
                    "invalid whiteout name: .wh.{target_name}"
                )));
            }
            refuse_whiteout_escape(root, parent_rel)?;
            let target_safe = root.resolve_or_root(parent_rel)?.join(target_name);
            ensure_inside(root.root_path(), &target_safe)?;
            if fs::symlink_metadata(&target_safe).is_ok() {
                remove_nofollow(&target_safe, false)?;
            }
        }
    }
    Ok(true)
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
    Err(Error::Extract(format!(
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
                    .map_err(|e| Error::Extract(format!("readlink {}: {e}", full.display())))?;
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
