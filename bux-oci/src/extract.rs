//! OCI layer extraction with whiteout handling.
//!
//! Supports both file-based (streaming from disk) and in-memory layer extraction.
//! Handles all standard OCI/Docker layer media types:
//! - `application/vnd.oci.image.layer.v1.tar+gzip`
//! - `application/vnd.docker.image.rootfs.diff.tar.gzip`
//! - Uncompressed tar fallback

use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::Path;

use flate2::read::GzDecoder;

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
/// in order with full OCI whiteout semantics.
pub fn extract_layer_files(
    layers: &[(impl AsRef<Path>, impl AsRef<str>)],
    rootfs: &Path,
) -> crate::Result<()> {
    fs::create_dir_all(rootfs)?;
    for (path, media_type) in layers {
        let file = BufReader::new(File::open(path.as_ref())?);
        if is_gzip(media_type.as_ref()) {
            apply_tar(GzDecoder::new(file), rootfs)?;
        } else {
            apply_tar(file, rootfs)?;
        }
    }
    Ok(())
}

/// Applies a single tar stream to `rootfs` with OCI whiteout processing.
///
/// Whiteout semantics (OCI Image Spec v1.1):
/// - `.wh.<name>` — removes the named sibling entry from a lower layer.
/// - `.wh..wh..opq` — marks the directory as opaque (clears inherited contents).
fn apply_tar(reader: impl Read, rootfs: &Path) -> crate::Result<()> {
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_overwrite(true);

    for raw_entry in archive.entries()? {
        let mut entry = raw_entry?;
        let rel = entry.path()?.into_owned();

        let file_name = match rel.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_owned(),
            None => continue,
        };

        // Opaque whiteout: clear the parent directory contents.
        if file_name == ".wh..wh..opq" {
            if let Some(parent) = rel.parent() {
                let target = rootfs.join(parent);
                if target.exists() {
                    clear_dir(&target)?;
                }
            }
            continue;
        }

        // Regular whiteout: remove the named entry from a lower layer.
        if let Some(target_name) = file_name.strip_prefix(".wh.") {
            if let Some(parent) = rel.parent() {
                let target = rootfs.join(parent).join(target_name);
                if target.is_dir() {
                    fs::remove_dir_all(&target).ok();
                } else {
                    fs::remove_file(&target).ok();
                }
            }
            continue;
        }

        // Normal entry: extract into rootfs.
        entry.unpack_in(rootfs)?;
    }

    Ok(())
}

/// Removes all contents of a directory without removing the directory itself.
fn clear_dir(dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}
