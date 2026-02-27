//! File transfer handlers: single-file read/write and tar-based copy.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use bux_proto::{Download, ErrorCode, ErrorInfo, STREAM_CHUNK_SIZE, UploadResult};
use tokio::io::{AsyncRead, AsyncWrite};

/// Monotonic counter for unique temp file names (avoids PID-only collision).
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Streams a file's contents back as [`Download`] chunks.
pub async fn handle_read(w: &mut (impl AsyncWrite + Unpin), path: &str) -> io::Result<()> {
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
    r: &mut (impl AsyncRead + Unpin),
    w: &mut (impl AsyncWrite + Unpin),
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
    r: &mut (impl AsyncRead + Unpin),
    w: &mut (impl AsyncWrite + Unpin),
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
        let mut archive = tar::Archive::new(file);
        archive.set_preserve_permissions(true);
        for raw_entry in archive.entries()? {
            let mut entry = raw_entry?;
            let path = entry.path()?.into_owned();
            let target = canonical_dest.join(&path);
            // Resolve symlinks in prefix only, not the final component.
            if let Ok(resolved) = target.parent().unwrap_or(&canonical_dest).canonicalize()
                && !resolved.starts_with(&canonical_dest)
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("path traversal blocked: {}", path.display()),
                ));
            }
            entry.unpack_in(&canonical_dest)?;
        }
        Ok(())
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
    w: &mut (impl AsyncWrite + Unpin),
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

/// Receives [`Upload`] chunks and streams them directly to a temp file.
///
/// Uses `recv_upload_to_writer` so memory usage is O(chunk_size) regardless
/// of total upload size.
async fn recv_upload_to_file(r: &mut (impl AsyncRead + Unpin)) -> io::Result<std::path::PathBuf> {
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
fn temp_file_path(tag: &str) -> std::path::PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    Path::new("/tmp").join(format!("bux-{tag}-{}-{seq}", std::process::id()))
}
