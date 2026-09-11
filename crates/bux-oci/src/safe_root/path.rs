//! Rooted path walk: follow in-root symlinks; re-anchor absolute targets.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::{OciError, Result};

/// 256th follow is treated as a cycle or a crafted chain.
pub(crate) const SYMLINK_HOP_LIMIT: u32 = 255;

pub(crate) fn hop_limit_error(rel: &Path) -> OciError {
    OciError::Extract(format!(
        "symlink hop limit exceeded resolving {}",
        rel.display()
    ))
}

/// Strip `/`, collapse `.` / `..`. `None` if `..` walks above the root.
pub(super) fn normalize_relative(path: &Path) -> Option<PathBuf> {
    let mut components = Vec::new();
    for comp in path.components() {
        match comp {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                components.pop()?;
            }
            Component::Normal(c) => components.push(c.to_os_string()),
        }
    }
    Some(components.into_iter().collect())
}

fn push_components(remaining: &mut VecDeque<OsString>, path: &Path) {
    for c in path.components() {
        match c {
            Component::Normal(s) => remaining.push_back(s.to_os_string()),
            Component::ParentDir => remaining.push_back(OsString::from("..")),
            _ => {}
        }
    }
}

/// Follow every component, including the last. Missing components stay as a
/// path under `root` (the parent of a file being created does not exist yet).
pub(super) fn resolve_walk(root: &Path, rel: &Path) -> Result<PathBuf> {
    let mut resolved = PathBuf::new();
    let mut hops: u32 = 0;
    let mut remaining = VecDeque::new();
    push_components(&mut remaining, rel);

    while let Some(comp) = remaining.pop_front() {
        if comp == ".." {
            resolved.pop();
            continue;
        }
        resolved.push(&comp);

        let full = root.join(&resolved);
        match std::fs::symlink_metadata(&full) {
            Ok(meta) if meta.file_type().is_symlink() => {
                hops += 1;
                if hops > SYMLINK_HOP_LIMIT {
                    return Err(hop_limit_error(rel));
                }
                let target = std::fs::read_link(&full)
                    .map_err(|e| OciError::Extract(format!("readlink {}: {e}", full.display())))?;
                resolved.pop();
                if target.is_absolute() {
                    resolved = PathBuf::new();
                }
                let mut parts = VecDeque::new();
                push_components(&mut parts, &target);
                while let Some(part) = parts.pop_back() {
                    remaining.push_front(part);
                }
            }
            Ok(_) => {}
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    || e.kind() == io::ErrorKind::NotADirectory => {}
            Err(e) => {
                return Err(OciError::Extract(format!(
                    "resolve {} under {}: {e}",
                    rel.display(),
                    root.display()
                )));
            }
        }
    }

    Ok(root.join(resolved))
}
