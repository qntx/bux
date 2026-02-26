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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecReq, Request, Response};

    #[tokio::test]
    async fn roundtrip_ping_pong() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        send(&mut client, &Request::Ping).await.unwrap();
        let decoded: Request = recv(&mut server).await.unwrap();
        assert!(matches!(decoded, Request::Ping));
    }

    #[tokio::test]
    async fn roundtrip_exec() {
        let req = Request::Exec(
            ExecReq::new("/bin/ls")
                .args(vec!["-la".into()])
                .env(vec!["PATH=/usr/bin".into()])
                .cwd("/tmp")
                .user(1000, 1000)
                .with_stdin(),
        );

        let (mut client, mut server) = tokio::io::duplex(1024);
        send(&mut client, &req).await.unwrap();
        let decoded: Request = recv(&mut server).await.unwrap();
        match decoded {
            Request::Exec(e) => {
                assert_eq!(e.cmd, "/bin/ls");
                assert_eq!(e.args, vec!["-la"]);
                assert_eq!(e.uid, Some(1000));
                assert!(e.stdin);
            }
            _ => panic!("expected Exec"),
        }
    }

    #[tokio::test]
    async fn roundtrip_response_variants() {
        let cases: Vec<Response> = vec![
            Response::Started { pid: 42 },
            Response::Stdout(b"hello".to_vec()),
            Response::Stderr(b"error".to_vec()),
            Response::Exit(0),
            Response::Error("boom".into()),
            Response::Pong,
            Response::FileData(b"content".to_vec()),
            Response::TarData(b"tarball".to_vec()),
            Response::Ok,
        ];

        for resp in cases {
            let (mut client, mut server) = tokio::io::duplex(1024);
            send(&mut client, &resp).await.unwrap();
            let _: Response = recv(&mut server).await.unwrap();
        }
    }

    #[tokio::test]
    async fn roundtrip_copy_in() {
        let req = Request::CopyIn {
            dest: "/tmp/upload".into(),
            tar: vec![1, 2, 3, 4],
        };
        let (mut client, mut server) = tokio::io::duplex(1024);
        send(&mut client, &req).await.unwrap();
        let decoded: Request = recv(&mut server).await.unwrap();
        assert!(matches!(decoded, Request::CopyIn { .. }));
    }

    #[tokio::test]
    async fn rejects_oversized_frame() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(32u32 * 1024 * 1024).to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]); // dummy payload bytes
        let mut cursor = io::Cursor::new(buf);
        let result: io::Result<Request> = recv(&mut cursor).await;
        assert!(result.is_err());
    }
}
