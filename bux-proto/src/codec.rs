//! Async length-prefixed frame codec over any [`AsyncRead`]/[`AsyncWrite`] stream.
//!
//! Each frame is: `[u32 big-endian length][postcard payload]`.

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum allowed frame payload (16 MiB).
const MAX_FRAME: u32 = 16 * 1024 * 1024;

/// Sends a postcard-serialized message with a 4-byte BE length prefix.
pub async fn send(w: &mut (impl AsyncWrite + Unpin), msg: &impl Serialize) -> io::Result<()> {
    let payload =
        postcard::to_allocvec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame exceeds u32::MAX"))?;
    // Pre-assemble frame to minimize syscalls.
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    w.write_all(&frame).await?;
    w.flush().await
}

/// Receives and deserializes a length-prefixed postcard message.
pub async fn recv<T: for<'de> Deserialize<'de>>(r: &mut (impl AsyncRead + Unpin)) -> io::Result<T> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let len = u32::from_be_bytes(hdr);
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds 16 MiB limit",
        ));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    postcard::from_bytes(&payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Sends `data` as a series of [`Upload::Chunk`] messages followed by
/// [`Upload::Done`], using the given chunk size.
pub async fn send_upload(
    w: &mut (impl AsyncWrite + Unpin),
    data: &[u8],
    chunk_size: usize,
) -> io::Result<()> {
    use crate::Upload;
    for chunk in data.chunks(chunk_size) {
        send(w, &Upload::Chunk(chunk.to_vec())).await?;
    }
    send(w, &Upload::Done).await
}

/// Receives an upload stream ([`Upload::Chunk`] + [`Upload::Done`]),
/// collecting all chunks into a single buffer with a size limit.
pub async fn recv_upload(r: &mut (impl AsyncRead + Unpin), max_bytes: u64) -> io::Result<Vec<u8>> {
    use crate::Upload;
    let mut buf = Vec::new();
    loop {
        match recv::<Upload>(r).await? {
            Upload::Chunk(data) => {
                buf.extend(&data);
                if buf.len() as u64 > max_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("upload exceeds {max_bytes} byte limit"),
                    ));
                }
            }
            Upload::Done => return Ok(buf),
        }
    }
}

/// Sends `data` as a series of [`Download::Chunk`] messages followed by
/// [`Download::Done`], using the given chunk size.
pub async fn send_download(
    w: &mut (impl AsyncWrite + Unpin),
    data: &[u8],
    chunk_size: usize,
) -> io::Result<()> {
    use crate::Download;
    for chunk in data.chunks(chunk_size) {
        send(w, &Download::Chunk(chunk.to_vec())).await?;
    }
    send(w, &Download::Done).await
}

/// Receives a download stream ([`Download::Chunk`] + [`Download::Done`]),
/// collecting all chunks into a single buffer.
pub async fn recv_download(r: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    use crate::Download;
    let mut buf = Vec::new();
    loop {
        match recv::<Download>(r).await? {
            Download::Chunk(data) => buf.extend(data),
            Download::Done => return Ok(buf),
            Download::Error(e) => return Err(io::Error::other(e.message)),
        }
    }
}

/// Reads from `src` and sends [`Upload`] chunks until EOF.
///
/// Streams data without buffering the entire payload in memory.
/// Returns the total number of bytes sent.
pub async fn send_upload_from_reader(
    w: &mut (impl AsyncWrite + Unpin),
    src: &mut (impl AsyncRead + Unpin),
    chunk_size: usize,
) -> io::Result<u64> {
    use crate::Upload;
    let mut buf = vec![0u8; chunk_size];
    let mut total: u64 = 0;
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total += n as u64;
        send(w, &Upload::Chunk(buf[..n].to_vec())).await?;
    }
    send(w, &Upload::Done).await?;
    Ok(total)
}

/// Reads from `src` and sends [`Download`] chunks until EOF.
///
/// Streams data without buffering the entire payload in memory.
/// Returns the total number of bytes sent.
pub async fn send_download_from_reader(
    w: &mut (impl AsyncWrite + Unpin),
    src: &mut (impl AsyncRead + Unpin),
    chunk_size: usize,
) -> io::Result<u64> {
    use crate::Download;
    let mut buf = vec![0u8; chunk_size];
    let mut total: u64 = 0;
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total += n as u64;
        send(w, &Download::Chunk(buf[..n].to_vec())).await?;
    }
    send(w, &Download::Done).await?;
    Ok(total)
}

/// Receives an upload stream and writes chunks directly to `dst`.
///
/// Streams data without buffering the entire payload in memory.
/// Returns the total number of bytes written.
pub async fn recv_upload_to_writer(
    r: &mut (impl AsyncRead + Unpin),
    dst: &mut (impl AsyncWrite + Unpin),
    max_bytes: u64,
) -> io::Result<u64> {
    use crate::Upload;
    let mut total: u64 = 0;
    loop {
        match recv::<Upload>(r).await? {
            Upload::Chunk(data) => {
                total += data.len() as u64;
                if total > max_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("upload exceeds {max_bytes} byte limit"),
                    ));
                }
                dst.write_all(&data).await?;
            }
            Upload::Done => {
                dst.flush().await?;
                return Ok(total);
            }
        }
    }
}

/// Receives a download stream and writes chunks directly to `dst`.
///
/// Streams data without buffering the entire payload in memory.
/// Returns the total number of bytes written.
pub async fn recv_download_to_writer(
    r: &mut (impl AsyncRead + Unpin),
    dst: &mut (impl AsyncWrite + Unpin),
) -> io::Result<u64> {
    use crate::Download;
    let mut total: u64 = 0;
    loop {
        match recv::<Download>(r).await? {
            Download::Chunk(data) => {
                total += data.len() as u64;
                dst.write_all(&data).await?;
            }
            Download::Done => {
                dst.flush().await?;
                return Ok(total);
            }
            Download::Error(e) => return Err(io::Error::other(e.message)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ControlReq, ControlResp, ErrorCode, ErrorInfo, ExecIn, ExecOut, ExecStart, Hello, HelloAck,
        Upload, UploadResult,
    };

    #[tokio::test]
    async fn roundtrip_hello_control() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        send(&mut c, &Hello::Control { version: 5 }).await.unwrap();
        let msg: Hello = recv(&mut s).await.unwrap();
        assert!(matches!(msg, Hello::Control { version: 5 }));
    }

    #[tokio::test]
    async fn roundtrip_hello_exec() {
        let start = ExecStart::new("/bin/ls")
            .args(vec!["-la".into()])
            .env(vec!["PATH=/usr/bin".into()])
            .cwd("/tmp")
            .user(1000, 1000)
            .with_stdin()
            .tty(24, 80)
            .timeout(5000);

        let (mut c, mut s) = tokio::io::duplex(4096);
        send(&mut c, &Hello::Exec(start)).await.unwrap();
        let msg: Hello = recv(&mut s).await.unwrap();
        match msg {
            Hello::Exec(e) => {
                assert_eq!(e.cmd, "/bin/ls");
                assert_eq!(e.args, vec!["-la"]);
                assert_eq!(e.uid, Some(1000));
                assert!(e.stdin);
                assert_eq!(e.tty.unwrap().rows, 24);
                assert_eq!(e.tty.unwrap().cols, 80);
                assert_eq!(e.timeout_ms, 5000);
            }
            _ => panic!("expected Hello::Exec"),
        }
    }

    #[tokio::test]
    async fn roundtrip_hello_ack_variants() {
        let cases: Vec<HelloAck> = vec![
            HelloAck::Control { version: 5 },
            HelloAck::ExecStarted {
                exec_id: "abc-123".into(),
                pid: 42,
            },
            HelloAck::Ready,
            HelloAck::Error(ErrorInfo::internal("boom")),
        ];
        for ack in cases {
            let (mut c, mut s) = tokio::io::duplex(1024);
            send(&mut c, &ack).await.unwrap();
            let _: HelloAck = recv(&mut s).await.unwrap();
        }
    }

    #[tokio::test]
    async fn roundtrip_control() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        send(&mut c, &ControlReq::Ping).await.unwrap();
        let msg: ControlReq = recv(&mut s).await.unwrap();
        assert!(matches!(msg, ControlReq::Ping));

        send(
            &mut s,
            &ControlResp::Pong {
                version: "0.6.1".into(),
                uptime_ms: 1234,
            },
        )
        .await
        .unwrap();
        let resp: ControlResp = recv(&mut c).await.unwrap();
        assert!(matches!(
            resp,
            ControlResp::Pong {
                uptime_ms: 1234,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn roundtrip_exec_io() {
        let (mut c, mut s) = tokio::io::duplex(4096);

        // Host sends stdin
        send(&mut c, &ExecIn::Stdin(b"hello".to_vec()))
            .await
            .unwrap();
        send(&mut c, &ExecIn::StdinClose).await.unwrap();
        send(&mut c, &ExecIn::Signal(15)).await.unwrap();
        send(
            &mut c,
            &ExecIn::ResizeTty(crate::TtyConfig {
                rows: 50,
                cols: 120,
                x_pixels: 0,
                y_pixels: 0,
            }),
        )
        .await
        .unwrap();

        // Guest receives
        let m: ExecIn = recv(&mut s).await.unwrap();
        assert!(matches!(m, ExecIn::Stdin(d) if d == b"hello"));
        let m: ExecIn = recv(&mut s).await.unwrap();
        assert!(matches!(m, ExecIn::StdinClose));
        let m: ExecIn = recv(&mut s).await.unwrap();
        assert!(matches!(m, ExecIn::Signal(15)));
        let m: ExecIn = recv(&mut s).await.unwrap();
        assert!(matches!(m, ExecIn::ResizeTty(t) if t.rows == 50 && t.cols == 120));

        // Guest sends output
        send(&mut s, &ExecOut::Stdout(b"world".to_vec()))
            .await
            .unwrap();
        send(&mut s, &ExecOut::Stderr(b"err".to_vec()))
            .await
            .unwrap();
        send(
            &mut s,
            &ExecOut::Exit {
                code: 0,
                signal: None,
                timed_out: false,
                duration_ms: 42,
                error_message: String::new(),
            },
        )
        .await
        .unwrap();

        let m: ExecOut = recv(&mut c).await.unwrap();
        assert!(matches!(m, ExecOut::Stdout(d) if d == b"world"));
        let m: ExecOut = recv(&mut c).await.unwrap();
        assert!(matches!(m, ExecOut::Stderr(d) if d == b"err"));
        let m: ExecOut = recv(&mut c).await.unwrap();
        assert!(matches!(
            m,
            ExecOut::Exit {
                code: 0,
                signal: None,
                timed_out: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn roundtrip_upload_stream() {
        let (mut c, mut s) = tokio::io::duplex(4096);
        let data = vec![42u8; 600];

        send_upload(&mut c, &data, 256).await.unwrap();

        let received = recv_upload(&mut s, 1024).await.unwrap();
        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn roundtrip_download_stream() {
        let (mut c, mut s) = tokio::io::duplex(4096);
        let data = vec![7u8; 500];

        send_download(&mut s, &data, 256).await.unwrap();

        let received = recv_download(&mut c).await.unwrap();
        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn upload_result_roundtrip() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        send(&mut c, &UploadResult::Ok).await.unwrap();
        let r: UploadResult = recv(&mut s).await.unwrap();
        assert!(matches!(r, UploadResult::Ok));

        send(
            &mut s,
            &UploadResult::Error(ErrorInfo::new(ErrorCode::NotFound, "no such file")),
        )
        .await
        .unwrap();
        let r: UploadResult = recv(&mut c).await.unwrap();
        assert!(matches!(r, UploadResult::Error(e) if e.code == ErrorCode::NotFound));
    }

    #[tokio::test]
    async fn rejects_oversized_frame() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(32u32 * 1024 * 1024).to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        let mut cursor = io::Cursor::new(buf);
        let result: io::Result<Hello> = recv(&mut cursor).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn upload_exceeds_limit() {
        let (mut c, mut s) = tokio::io::duplex(4096);
        // Send 200 bytes, limit 100
        send(&mut c, &Upload::Chunk(vec![0u8; 200])).await.unwrap();
        send(&mut c, &Upload::Done).await.unwrap();
        let result = recv_upload(&mut s, 100).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn recv_upload_to_writer_streams() {
        let (mut c, mut s) = tokio::io::duplex(4096);
        let data = vec![42u8; 600];

        send_upload(&mut c, &data, 256).await.unwrap();

        let mut dst = Vec::new();
        let total = recv_upload_to_writer(&mut s, &mut dst, 1024).await.unwrap();
        assert_eq!(total, 600);
        assert_eq!(dst, data);
    }

    #[tokio::test]
    async fn recv_upload_to_writer_rejects_oversized() {
        let (mut c, mut s) = tokio::io::duplex(4096);
        send(&mut c, &Upload::Chunk(vec![0u8; 200])).await.unwrap();
        send(&mut c, &Upload::Done).await.unwrap();

        let mut dst = Vec::new();
        let result = recv_upload_to_writer(&mut s, &mut dst, 100).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn send_download_from_reader_streams() {
        let (mut c, mut s) = tokio::io::duplex(8192);
        let data = vec![7u8; 500];

        let mut src = io::Cursor::new(data.clone());
        let total = send_download_from_reader(&mut s, &mut src, 256)
            .await
            .unwrap();
        assert_eq!(total, 500);

        let received = recv_download(&mut c).await.unwrap();
        assert_eq!(received, data);
    }
}
