//! Async length-prefixed frame codec over any [`AsyncRead`]/[`AsyncWrite`] stream.
//!
//! Two layers:
//!
//! - [`send`] / [`recv`] move one message per frame:
//!   `[u32 big-endian length][postcard payload]`.
//! - [`send_upload`] / [`recv_upload`] (host → guest) and [`send_download`] /
//!   [`recv_download`] (guest → host) move bulk bytes as `Chunk` frames of at
//!   most 1 MiB ended by `Done`; a download may end with [`Download::Error`]
//!   instead. Senders read from any reader and receivers write to any writer —
//!   `&[u8]` and `&mut Vec<u8>` cover in-memory data.

use std::io;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Download, ErrorInfo, Upload};

/// Maximum frame payload (16 MiB).
const MAX_FRAME: u32 = 16 * 1024 * 1024;

/// Data bytes per stream chunk (1 MiB), leaving room for framing within [`MAX_FRAME`].
const CHUNK_SIZE: usize = 1 << 20;

/// Sends `msg` as one frame and flushes `w`.
///
/// # Errors
///
/// Returns an error if serialization fails, the payload exceeds 16 MiB, or the
/// write fails.
pub async fn send(
    w: &mut (impl AsyncWrite + Unpin + Send),
    msg: &(impl Serialize + Sync),
) -> io::Result<()> {
    let payload = postcard::to_allocvec(msg).map_err(invalid_data)?;
    // Enforce the receiver's limit here: an oversized frame fails at its source
    // instead of breaking the peer's stream.
    let len = match u32::try_from(payload.len()) {
        Ok(len) if len <= MAX_FRAME => len,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("frame of {} bytes exceeds 16 MiB limit", payload.len()),
            ));
        }
    };
    // One buffer, one write: the length prefix does not cost its own syscall.
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    w.write_all(&frame).await?;
    w.flush().await
}

/// Receives one frame and deserializes it as `T`.
///
/// # Errors
///
/// Returns an error if the read fails, the frame exceeds 16 MiB, or the payload
/// is not exactly one `T`.
///
/// # Cancel safety
///
/// This method is not cancellation safe. If the future is dropped mid-frame,
/// for example by another `tokio::select!` branch completing first, the bytes
/// read so far are lost and the stream is desynchronized.
pub async fn recv<T: DeserializeOwned>(r: &mut (impl AsyncRead + Unpin + Send)) -> io::Result<T> {
    let len = r.read_u32().await?;
    if len > MAX_FRAME {
        return Err(invalid_data(format!(
            "frame of {len} bytes exceeds 16 MiB limit"
        )));
    }
    let mut payload = vec![0; len as usize];
    r.read_exact(&mut payload).await?;
    // Leftover bytes mean the peer encoded a different message layout.
    match postcard::take_from_bytes(&payload).map_err(invalid_data)? {
        (msg, []) => Ok(msg),
        (_, rest) => Err(invalid_data(format!(
            "{} trailing bytes after message",
            rest.len()
        ))),
    }
}

/// Sends `src` to EOF as an [`Upload`] stream (host → guest).
/// Returns the number of bytes sent.
///
/// # Errors
///
/// Returns an error if a read from `src` or a write to `w` fails.
pub async fn send_upload(
    w: &mut (impl AsyncWrite + Unpin + Send),
    src: impl AsyncRead + Unpin + Send,
) -> io::Result<u64> {
    send_stream::<Upload>(w, src).await
}

/// Receives an [`Upload`] stream (host → guest) into `dst`.
/// Returns the number of bytes written.
///
/// # Errors
///
/// Returns an error if a read or write fails, or the upload exceeds `max_bytes`
/// ([`io::ErrorKind::FileTooLarge`]; nothing past the limit reaches `dst`).
pub async fn recv_upload(
    r: &mut (impl AsyncRead + Unpin + Send),
    dst: impl AsyncWrite + Unpin + Send,
    max_bytes: u64,
) -> io::Result<u64> {
    recv_stream::<Upload>(r, dst, max_bytes).await
}

/// Sends `src` to EOF as a [`Download`] stream (guest → host).
/// Returns the number of bytes sent.
///
/// A read error from `src` is also sent as [`Download::Error`], so the peer
/// learns the cause instead of seeing the stream cut off.
///
/// # Errors
///
/// Returns an error if a read from `src` or a write to `w` fails.
pub async fn send_download(
    w: &mut (impl AsyncWrite + Unpin + Send),
    src: impl AsyncRead + Unpin + Send,
) -> io::Result<u64> {
    send_stream::<Download>(w, src).await
}

/// Receives a [`Download`] stream (guest → host) into `dst`.
/// Returns the number of bytes written.
///
/// # Errors
///
/// Returns an error if a read or write fails, the peer sends
/// [`Download::Error`] (its [`ErrorInfo`] becomes the error's inner value), or
/// the download exceeds `max_bytes` ([`io::ErrorKind::FileTooLarge`]; nothing
/// past the limit reaches `dst`).
pub async fn recv_download(
    r: &mut (impl AsyncRead + Unpin + Send),
    dst: impl AsyncWrite + Unpin + Send,
    max_bytes: u64,
) -> io::Result<u64> {
    recv_stream::<Download>(r, dst, max_bytes).await
}

/// Message type of a chunk stream: everything that differs between [`Upload`]
/// and [`Download`].
trait StreamMessage: Serialize + DeserializeOwned + Send + Sync {
    /// Stream name used in limit errors.
    const NAME: &'static str;
    /// End-of-stream message.
    const DONE: Self;
    /// Wraps a chunk of data.
    fn chunk(data: Vec<u8>) -> Self;
    /// Message reporting a failed read of the source, if the stream can carry one.
    fn read_error(err: &io::Error) -> Option<Self>;
    /// Unwraps a received message: its chunk, `None` at end of stream, or the
    /// error the peer sent.
    fn into_chunk(self) -> io::Result<Option<Vec<u8>>>;
}

impl StreamMessage for Upload {
    const NAME: &'static str = "upload";
    const DONE: Self = Self::Done;

    fn chunk(data: Vec<u8>) -> Self {
        Self::Chunk(data)
    }

    fn read_error(_: &io::Error) -> Option<Self> {
        None
    }

    fn into_chunk(self) -> io::Result<Option<Vec<u8>>> {
        match self {
            Self::Chunk(data) => Ok(Some(data)),
            Self::Done => Ok(None),
        }
    }
}

impl StreamMessage for Download {
    const NAME: &'static str = "download";
    const DONE: Self = Self::Done;

    fn chunk(data: Vec<u8>) -> Self {
        Self::Chunk(data)
    }

    fn read_error(err: &io::Error) -> Option<Self> {
        Some(Self::Error(ErrorInfo::internal(err.to_string())))
    }

    fn into_chunk(self) -> io::Result<Option<Vec<u8>>> {
        match self {
            Self::Chunk(data) => Ok(Some(data)),
            Self::Done => Ok(None),
            Self::Error(e) => Err(io::Error::other(e)),
        }
    }
}

/// Sends `src` to EOF as `M` chunks followed by `M::DONE`.
async fn send_stream<M: StreamMessage>(
    w: &mut (impl AsyncWrite + Unpin + Send),
    mut src: impl AsyncRead + Unpin + Send,
) -> io::Result<u64> {
    let mut total = 0;
    loop {
        let chunk = match read_chunk(&mut src).await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(e) => {
                // Best effort: if this send fails too, the read error is still
                // the one worth returning.
                if let Some(report) = M::read_error(&e) {
                    drop(send(w, &report).await);
                }
                return Err(e);
            }
        };
        total += chunk.len() as u64;
        send(w, &M::chunk(chunk)).await?;
    }
    send(w, &M::DONE).await?;
    Ok(total)
}

/// Receives `M` chunks into `dst` until end of stream, refusing more than
/// `max_bytes` in total.
///
/// The limit is checked before a chunk is written, so `dst` never grows past it.
async fn recv_stream<M: StreamMessage>(
    r: &mut (impl AsyncRead + Unpin + Send),
    mut dst: impl AsyncWrite + Unpin + Send,
    max_bytes: u64,
) -> io::Result<u64> {
    let mut total: u64 = 0;
    while let Some(chunk) = recv::<M>(r).await?.into_chunk()? {
        total = total.saturating_add(chunk.len() as u64);
        if total > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                format!("{} exceeds {max_bytes} byte limit", M::NAME),
            ));
        }
        dst.write_all(&chunk).await?;
    }
    dst.flush().await?;
    Ok(total)
}

/// Reads the next chunk of up to [`CHUNK_SIZE`] bytes, or `None` at EOF.
///
/// Keeps reading until the chunk is full or `src` ends, so short reads do not
/// turn into small frames.
async fn read_chunk(src: &mut (impl AsyncRead + Unpin + Send)) -> io::Result<Option<Vec<u8>>> {
    let mut chunk = Vec::with_capacity(CHUNK_SIZE);
    src.take(CHUNK_SIZE as u64).read_to_end(&mut chunk).await?;
    Ok((!chunk.is_empty()).then_some(chunk))
}

/// Wraps `err` as an [`io::ErrorKind::InvalidData`] error.
fn invalid_data(err: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::shadow_unrelated,
    clippy::panic,
    reason = "tests use unwrap/expect/panic for clarity"
)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::ReadBuf;

    use super::*;
    use crate::{
        ControlReq, ControlResp, ErrorCode, ExecIn, ExecOut, ExecStart, Hello, HelloAck,
        MAX_DOWNLOAD_BYTES, MAX_UPLOAD_BYTES, UploadResult,
    };

    /// Reader whose every read fails.
    struct FailingReader;

    impl AsyncRead for FailingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("disk read failed")))
        }
    }

    /// Two full chunks plus a partial one.
    fn multi_chunk_data() -> Vec<u8> {
        (0..=255).cycle().take(2 * CHUNK_SIZE + 7).collect()
    }

    /// Receives the download stream in `wire` into memory.
    async fn download_to_vec(wire: &[u8], max_bytes: u64) -> io::Result<Vec<u8>> {
        let mut rx = wire;
        let mut data = Vec::new();
        recv_download(&mut rx, &mut data, max_bytes).await?;
        Ok(data)
    }

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
        for req in [
            ControlReq::Ping,
            ControlReq::Shutdown,
            ControlReq::Quiesce,
            ControlReq::Thaw,
        ] {
            send(&mut c, &req).await.unwrap();
            let msg: ControlReq = recv(&mut s).await.unwrap();
            assert_eq!(
                postcard::to_allocvec(&msg).unwrap(),
                postcard::to_allocvec(&req).unwrap()
            );
        }

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

        send(&mut s, &ControlResp::ShutdownOk).await.unwrap();
        let resp: ControlResp = recv(&mut c).await.unwrap();
        assert!(matches!(resp, ControlResp::ShutdownOk));

        send(&mut s, &ControlResp::QuiesceOk { frozen_count: 2 })
            .await
            .unwrap();
        let resp: ControlResp = recv(&mut c).await.unwrap();
        assert!(matches!(resp, ControlResp::QuiesceOk { frozen_count: 2 }));

        send(&mut s, &ControlResp::ThawOk { thawed_count: 2 })
            .await
            .unwrap();
        let resp: ControlResp = recv(&mut c).await.unwrap();
        assert!(matches!(resp, ControlResp::ThawOk { thawed_count: 2 }));

        send(&mut s, &ControlResp::Error(ErrorInfo::internal("boom")))
            .await
            .unwrap();
        let resp: ControlResp = recv(&mut c).await.unwrap();
        assert!(matches!(resp, ControlResp::Error(_)));
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
                error_message: None,
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
    async fn send_rejects_oversized_frame() {
        let mut wire = Vec::new();
        let err = send(&mut wire, &Upload::Chunk(vec![0; MAX_FRAME as usize]))
            .await
            .expect_err("oversize");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "kind");
        assert!(wire.is_empty(), "nothing reaches the wire");
    }

    #[tokio::test]
    async fn recv_rejects_oversized_frame() {
        let mut wire = (MAX_FRAME + 1).to_be_bytes().to_vec();
        wire.extend_from_slice(&[0; 16]);
        let err = recv::<Hello>(&mut wire.as_slice())
            .await
            .expect_err("oversize");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "kind");
    }

    #[tokio::test]
    async fn recv_rejects_trailing_bytes() {
        let mut payload = postcard::to_allocvec(&Hello::Control { version: 5 }).unwrap();
        payload.push(0);
        let mut wire = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        wire.extend_from_slice(&payload);
        let err = recv::<Hello>(&mut wire.as_slice())
            .await
            .expect_err("trailing byte");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "kind");
    }

    #[tokio::test]
    async fn upload_roundtrip() {
        let data = multi_chunk_data();
        let mut wire = Vec::new();
        let sent = send_upload(&mut wire, data.as_slice()).await.unwrap();
        assert_eq!(sent, data.len() as u64, "sent");

        let mut dst = Vec::new();
        let written = recv_upload(&mut wire.as_slice(), &mut dst, MAX_UPLOAD_BYTES)
            .await
            .unwrap();
        assert_eq!(written, data.len() as u64, "written");
        assert!(dst == data, "payload");
    }

    #[tokio::test]
    async fn send_upload_splits_into_full_chunks() {
        let mut wire = Vec::new();
        send_upload(&mut wire, multi_chunk_data().as_slice())
            .await
            .unwrap();

        let mut rx = wire.as_slice();
        let mut sizes = Vec::new();
        while let Upload::Chunk(chunk) = recv(&mut rx).await.unwrap() {
            sizes.push(chunk.len());
        }
        assert_eq!(sizes, [CHUNK_SIZE, CHUNK_SIZE, 7], "chunk sizes");
        assert!(rx.is_empty(), "Done is the last frame");
    }

    #[tokio::test]
    async fn send_upload_joins_short_reads() {
        let src = (&b"ab"[..]).chain(&b"cd"[..]);
        let mut wire = Vec::new();
        send_upload(&mut wire, src).await.unwrap();

        let mut rx = wire.as_slice();
        let first: Upload = recv(&mut rx).await.unwrap();
        assert!(
            matches!(first, Upload::Chunk(d) if d == b"abcd"),
            "short reads are joined into one chunk"
        );
        let second: Upload = recv(&mut rx).await.unwrap();
        assert!(matches!(second, Upload::Done), "then Done");
    }

    #[tokio::test]
    async fn recv_upload_rejects_oversized() {
        let mut wire = Vec::new();
        send_upload(&mut wire, &[0; 200][..]).await.unwrap();
        let mut dst = Vec::new();
        let err = recv_upload(&mut wire.as_slice(), &mut dst, 100)
            .await
            .expect_err("oversize");
        assert_eq!(err.kind(), io::ErrorKind::FileTooLarge, "kind");
        assert!(dst.is_empty(), "nothing past the limit is written");
    }

    #[tokio::test]
    async fn download_roundtrip() {
        let data = multi_chunk_data();
        let mut wire = Vec::new();
        let sent = send_download(&mut wire, data.as_slice()).await.unwrap();
        assert_eq!(sent, data.len() as u64, "sent");

        let received = download_to_vec(&wire, MAX_DOWNLOAD_BYTES).await.unwrap();
        assert!(received == data, "payload");
    }

    #[tokio::test]
    async fn send_download_reports_read_error() {
        let mut wire = Vec::new();
        let err = send_download(&mut wire, FailingReader)
            .await
            .expect_err("read error");
        assert_eq!(
            err.to_string(),
            "disk read failed",
            "caller sees the read error"
        );

        let err = download_to_vec(&wire, MAX_DOWNLOAD_BYTES)
            .await
            .expect_err("peer sees the error");
        let info = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<ErrorInfo>())
            .expect("ErrorInfo");
        assert_eq!(info.message, "disk read failed", "peer sees the cause");
    }

    #[tokio::test]
    async fn recv_download_keeps_error_info() {
        let mut wire = Vec::new();
        send(
            &mut wire,
            &Download::Error(ErrorInfo::not_found("no such file")),
        )
        .await
        .unwrap();
        let err = download_to_vec(&wire, MAX_DOWNLOAD_BYTES)
            .await
            .expect_err("remote error");
        let info = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<ErrorInfo>())
            .expect("ErrorInfo");
        assert_eq!(info.code, ErrorCode::NotFound, "code");
    }

    #[tokio::test]
    async fn recv_download_rejects_oversized() {
        let mut wire = Vec::new();
        send(&mut wire, &Download::Chunk(vec![0; 200]))
            .await
            .unwrap();
        send(&mut wire, &Download::Done).await.unwrap();
        let mut dst = Vec::new();
        let err = recv_download(&mut wire.as_slice(), &mut dst, 100)
            .await
            .expect_err("oversize");
        assert_eq!(err.kind(), io::ErrorKind::FileTooLarge, "kind");
        assert!(dst.is_empty(), "nothing past the limit is written");
    }

    #[tokio::test]
    async fn recv_download_accepts_exact_max() {
        let data = vec![7; 100];
        let mut wire = Vec::new();
        send_download(&mut wire, data.as_slice()).await.unwrap();
        let received = download_to_vec(&wire, 100).await.unwrap();
        assert_eq!(received, data, "exactly max_bytes is accepted");
    }

    #[tokio::test]
    async fn recv_download_empty_ok() {
        let mut wire = Vec::new();
        send(&mut wire, &Download::Done).await.unwrap();
        let received = download_to_vec(&wire, 0).await.unwrap();
        assert!(received.is_empty(), "empty Done is ok at max_bytes 0");
    }
}
