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

/// Sends `data` as a series of [`Request::Chunk`] messages followed by
/// [`Request::EndOfStream`], using the given chunk size.
pub async fn send_request_chunks(
    w: &mut (impl AsyncWrite + Unpin),
    data: &[u8],
    chunk_size: usize,
) -> io::Result<()> {
    use crate::Request;
    for chunk in data.chunks(chunk_size) {
        send(w, &Request::Chunk(chunk.to_vec())).await?;
    }
    send(w, &Request::EndOfStream).await
}

/// Sends `data` as a series of [`Response::Chunk`] messages followed by
/// [`Response::EndOfStream`], using the given chunk size.
pub async fn send_response_chunks(
    w: &mut (impl AsyncWrite + Unpin),
    data: &[u8],
    chunk_size: usize,
) -> io::Result<()> {
    use crate::Response;
    for chunk in data.chunks(chunk_size) {
        send(w, &Response::Chunk(chunk.to_vec())).await?;
    }
    send(w, &Response::EndOfStream).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecReq, Request, Response};

    #[tokio::test]
    async fn roundtrip_handshake() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        send(&mut client, &Request::Handshake { version: 2 })
            .await
            .unwrap();
        let decoded: Request = recv(&mut server).await.unwrap();
        assert!(matches!(decoded, Request::Handshake { version: 2 }));
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
            Response::Handshake { version: 2 },
            Response::Chunk(b"content".to_vec()),
            Response::EndOfStream,
            Response::Ok,
        ];

        for resp in cases {
            let (mut client, mut server) = tokio::io::duplex(1024);
            send(&mut client, &resp).await.unwrap();
            let _: Response = recv(&mut server).await.unwrap();
        }
    }

    #[tokio::test]
    async fn roundtrip_streaming_copy_in() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        // Send header + chunks + end
        send(
            &mut client,
            &Request::CopyIn {
                dest: "/tmp".into(),
            },
        )
        .await
        .unwrap();
        send(&mut client, &Request::Chunk(vec![1, 2, 3]))
            .await
            .unwrap();
        send(&mut client, &Request::Chunk(vec![4, 5, 6]))
            .await
            .unwrap();
        send(&mut client, &Request::EndOfStream).await.unwrap();

        // Receive and verify
        let header: Request = recv(&mut server).await.unwrap();
        assert!(matches!(header, Request::CopyIn { dest } if dest == "/tmp"));

        let mut collected = Vec::new();
        loop {
            let msg: Request = recv(&mut server).await.unwrap();
            match msg {
                Request::Chunk(data) => collected.extend(data),
                Request::EndOfStream => break,
                _ => panic!("unexpected message"),
            }
        }
        assert_eq!(collected, vec![1, 2, 3, 4, 5, 6]);
    }

    #[tokio::test]
    async fn send_response_chunks_helper() {
        let data = vec![10u8; 600];
        let (mut client, mut server) = tokio::io::duplex(4096);

        send_response_chunks(&mut client, &data, 256).await.unwrap();

        let mut collected = Vec::new();
        loop {
            let msg: Response = recv(&mut server).await.unwrap();
            match msg {
                Response::Chunk(chunk) => collected.extend(chunk),
                Response::EndOfStream => break,
                _ => panic!("unexpected message"),
            }
        }
        assert_eq!(collected, data);
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
