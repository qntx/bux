//! File transfer handlers: single-file read/write and tar-based copy.

use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bux_proto::{Download, ErrorCode, ErrorInfo, STREAM_CHUNK_SIZE, UploadResult};
use tokio::io::{AsyncRead, AsyncWrite};

/// Monotonic counter for unique temp file names (avoids PID-only collision).
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Streams a file's contents back as [`Download`] chunks.
pub async fn handle_read(w: &mut (impl AsyncWrite + Unpin + Send), path: &str) -> io::Result<()> {
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) => {
            return bux_proto::send(
                w,
                &Download::Error(ErrorInfo::new(ErrorCode::NotFound, e.to_string())),
            )
            .await;
        }
    };
    bux_proto::send_download_from_reader(w, &mut file, STREAM_CHUNK_SIZE).await?;
    Ok(())
}

/// Receives chunked data from the host and writes it to a file with the given mode.
pub async fn handle_write(
    r: &mut (impl AsyncRead + Unpin + Send),
    w: &mut (impl AsyncWrite + Unpin + Send),
    path: &str,
    mode: u32,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp_path = match recv_upload_to_file(r).await {
        Ok(p) => p,
        Err(e) => {
            return bux_proto::send(
                w,
                &UploadResult::Error(ErrorInfo::new(ErrorCode::Internal, e.to_string())),
            )
            .await;
        }
    };

    let result = async {
        if let Some(parent) = Path::new(path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(&temp_path, path).await?;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
        io::Result::Ok(())
    }
    .await;

    // Always clean up temp file.
    let _ = tokio::fs::remove_file(&temp_path).await;

    match result {
        Ok(()) => bux_proto::send(w, &UploadResult::Ok).await,
        Err(e) => {
            bux_proto::send(
                w,
                &UploadResult::Error(ErrorInfo::new(ErrorCode::Internal, e.to_string())),
            )
            .await
        }
    }
}

/// Receives a tar archive from the host and extracts it into `dest`.
///
/// Validates each entry to reject path-traversal attacks.
pub async fn handle_copy_in(
    r: &mut (impl AsyncRead + Unpin + Send),
    w: &mut (impl AsyncWrite + Unpin + Send),
    dest: &str,
) -> io::Result<()> {
    let temp_path = match recv_upload_to_file(r).await {
        Ok(p) => p,
        Err(e) => {
            return bux_proto::send(
                w,
                &UploadResult::Error(ErrorInfo::new(ErrorCode::Internal, e.to_string())),
            )
            .await;
        }
    };

    let dest_owned = dest.to_owned();
    let tp = temp_path.clone();

    let result = tokio::task::spawn_blocking(move || -> io::Result<()> {
        let dest_path = Path::new(&dest_owned);
        std::fs::create_dir_all(dest_path)?;
        let canonical_dest = dest_path.canonicalize()?;
        let file = std::fs::File::open(&tp)?;
        copy_in_archive(&canonical_dest, file)
    })
    .await
    .map_err(io::Error::other)?;

    let _ = tokio::fs::remove_file(&temp_path).await;

    match result {
        Ok(()) => bux_proto::send(w, &UploadResult::Ok).await,
        Err(e) => {
            bux_proto::send(
                w,
                &UploadResult::Error(ErrorInfo::new(ErrorCode::Internal, e.to_string())),
            )
            .await
        }
    }
}

/// Packs a path into a tar archive and streams it as [`Download`] chunks.
pub async fn handle_copy_out(
    w: &mut (impl AsyncWrite + Unpin + Send),
    path: &str,
    follow_symlinks: bool,
) -> io::Result<()> {
    let owned_path = path.to_owned();
    let temp_path = temp_file_path("download");
    let tp = temp_path.clone();

    let result = tokio::task::spawn_blocking(move || -> io::Result<()> {
        let file = std::fs::File::create(&tp)?;
        let mut ar = tar::Builder::new(file);
        ar.follow_symlinks(follow_symlinks);
        let meta = if follow_symlinks {
            std::fs::metadata(&owned_path)?
        } else {
            std::fs::symlink_metadata(&owned_path)?
        };
        if meta.is_dir() {
            ar.append_dir_all(".", &owned_path)?;
        } else {
            let name = Path::new(&owned_path)
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("file"));
            ar.append_path_with_name(&owned_path, name)?;
        }
        ar.finish()?;
        Ok(())
    })
    .await
    .map_err(io::Error::other)?;

    match result {
        Ok(()) => {
            // Stream from file — O(chunk_size) memory instead of loading entire tar.
            let mut file = tokio::fs::File::open(&temp_path).await?;
            let send_result =
                bux_proto::send_download_from_reader(w, &mut file, STREAM_CHUNK_SIZE).await;
            let _ = tokio::fs::remove_file(&temp_path).await;
            send_result.map(|_| ())
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            bux_proto::send(
                w,
                &Download::Error(ErrorInfo::new(ErrorCode::NotFound, e.to_string())),
            )
            .await
        }
    }
}

/// Receives `Upload` chunks and streams them directly to a temp file.
///
/// Uses `recv_upload_to_writer` so memory usage is O(chunk_size) regardless
/// of total upload size.
async fn recv_upload_to_file(r: &mut (impl AsyncRead + Unpin + Send)) -> io::Result<PathBuf> {
    let temp_path = temp_file_path("upload");
    let mut file = tokio::fs::File::create(&temp_path).await?;
    match bux_proto::recv_upload_to_writer(r, &mut file, bux_proto::MAX_UPLOAD_BYTES).await {
        Ok(_) => Ok(temp_path),
        Err(e) => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            Err(e)
        }
    }
}

/// Returns a unique temp file path under `/tmp`.
fn temp_file_path(tag: &str) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    Path::new("/tmp").join(format!("bux-{tag}-{}-{seq}", std::process::id()))
}

/// `create_dir_all` and `unpack` follow a planted symlink; only write a jailed path.
fn copy_in_archive(dest: &Path, file: std::fs::File) -> io::Result<()> {
    let mut archive = tar::Archive::new(file);
    archive.set_preserve_permissions(true);
    for raw_entry in archive.entries()? {
        let mut entry = raw_entry?;
        let path = entry.path()?.into_owned();
        let Some(target) = jailed_join(dest, &path) else {
            return Err(copy_in_traversal_blocked(&path));
        };
        // create_dir_all follows a planted symlink.
        if let Some(parent_rel) = path.parent() {
            let Some(parent) = jailed_join(dest, parent_rel) else {
                return Err(copy_in_traversal_blocked(&path));
            };
            std::fs::create_dir_all(parent)?;
        }
        entry.unpack(&target)?;
    }
    Ok(())
}

/// A tar member may plant a symlink; following it would write outside `base`.
fn jailed_join(base: &Path, rel: &Path) -> Option<PathBuf> {
    if rel.is_absolute() {
        return None;
    }
    let mut cur = base.to_path_buf();
    for component in rel.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => {
                cur.push(name);
                match std::fs::symlink_metadata(&cur) {
                    Ok(meta) if meta.is_symlink() => return None,
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => return None,
                }
            }
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    Some(cur)
}

/// Fail closed so a blocked member is not skipped.
fn copy_in_traversal_blocked(entry: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("path traversal blocked: {}", entry.display()),
    )
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    reason = "tests"
)]
mod tests {
    use super::*;

    fn with_canonical_dest(f: impl FnOnce(&Path)) {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().canonicalize().unwrap();
        f(&dest);
    }

    #[test]
    fn rejects_parent_dir_component() {
        with_canonical_dest(|dest| {
            assert!(jailed_join(dest, Path::new("../outside.txt")).is_none());
        });
    }

    #[test]
    fn rejects_absolute_member() {
        with_canonical_dest(|dest| {
            assert!(jailed_join(dest, Path::new("/etc/passwd")).is_none());
        });
    }

    #[test]
    fn allows_direct_child() {
        with_canonical_dest(|dest| {
            assert_eq!(
                jailed_join(dest, Path::new("ok.txt")).unwrap(),
                dest.join("ok.txt")
            );
            assert_eq!(jailed_join(dest, Path::new(".")).unwrap(), dest);
            assert_eq!(jailed_join(dest, Path::new("./")).unwrap(), dest);
        });
    }

    #[tokio::test(flavor = "current_thread")]
    async fn copy_in_refuses_symlink_component() {
        // Planted symlink is a legal leaf; writing through it would follow into `ok/`.
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        std::fs::create_dir(dest.join("ok")).unwrap();

        let mut tar_bytes = Vec::new();
        {
            let mut ar = tar::Builder::new(&mut tar_bytes);
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_path("evil").unwrap();
            link.set_link_name("ok").unwrap();
            link.set_size(0);
            link.set_cksum();
            ar.append(&link, &[][..]).unwrap();

            let payload = b"pwned";
            let mut file = tar::Header::new_gnu();
            file.set_entry_type(tar::EntryType::Regular);
            file.set_path("evil/pwned").unwrap();
            file.set_size(u64::try_from(payload.len()).unwrap());
            file.set_cksum();
            ar.append(&file, &payload[..]).unwrap();
            ar.finish().unwrap();
        }

        let dest_str = dest.to_str().unwrap().to_owned();
        let (mut guest_from_host, mut host_to_guest) = tokio::io::duplex(64 * 1024);
        let (mut host_from_guest, mut guest_to_host) = tokio::io::duplex(64 * 1024);
        let guest = tokio::spawn(async move {
            handle_copy_in(&mut guest_from_host, &mut guest_to_host, &dest_str).await
        });

        bux_proto::send_upload(&mut host_to_guest, &tar_bytes, 256)
            .await
            .unwrap();
        let result: UploadResult = bux_proto::recv(&mut host_from_guest).await.unwrap();
        guest.await.unwrap().unwrap();

        let UploadResult::Error(info) = result else {
            panic!("copy_in followed a symlink component: {result:?}");
        };
        assert!(
            info.message.contains("path traversal blocked"),
            "{}",
            info.message
        );
        assert!(dest.join("evil").symlink_metadata().unwrap().is_symlink());
        assert!(!dest.join("ok").join("pwned").exists());
    }
}
