//! OCI layer extraction with whiteout handling.

use std::fs;
use std::io::Read;
use std::path::Path;

use flate2::read::GzDecoder;

use crate::store;

/// Extracts gzip-compressed tar layers in order into a rootfs directory.
///
/// Handles OCI whiteout files:
/// - `.wh.<name>` — deletes the named entry from a lower layer.
/// - `.wh..wh..opq` — marks the directory as opaque (clears inherited contents).
pub fn extract_layers(blob_paths: &[std::path::PathBuf], rootfs: &Path) -> crate::Result<()> {
    fs::create_dir_all(rootfs)?;

    for path in blob_paths {
        let file = fs::File::open(path)?;
        let gz = GzDecoder::new(file);
        extract_layer(gz, rootfs)?;
    }

    Ok(())
}

/// Extracts a single tar stream into `rootfs`, processing whiteout entries.
fn extract_layer(reader: impl Read, rootfs: &Path) -> crate::Result<()> {
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
                    store::clear_directory(&target)?;
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
