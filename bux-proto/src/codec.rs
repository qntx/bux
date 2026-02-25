//! Length-prefixed frame codec over any `Read`/`Write` stream.
//!
//! Each frame is: `[u32 big-endian length][postcard payload]`.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

/// Maximum allowed frame payload (16 MiB).
const MAX_FRAME: u32 = 16 * 1024 * 1024;

/// Encodes `msg` as a length-prefixed postcard frame and writes it to `w`.
pub fn encode<W: Write>(w: &mut W, msg: &impl Serialize) -> io::Result<()> {
    let payload =
        postcard::to_allocvec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame exceeds u32::MAX"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&payload)?;
    w.flush()
}

/// Reads a length-prefixed postcard frame from `r` and decodes it.
pub fn decode<T: for<'de> Deserialize<'de>>(r: &mut impl Read) -> io::Result<T> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    let len = u32::from_be_bytes(buf);
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds 16 MiB limit",
        ));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    postcard::from_bytes(&payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecReq, Request, Response};

    #[test]
    fn roundtrip_ping_pong() {
        let mut buf = Vec::new();
        encode(&mut buf, &Request::Ping).unwrap();

        let mut cursor = io::Cursor::new(&buf);
        let decoded: Request = decode(&mut cursor).unwrap();
        assert!(matches!(decoded, Request::Ping));
    }

    #[test]
    fn roundtrip_exec() {
        let req = Request::Exec(ExecReq {
            cmd: "/bin/ls".into(),
            args: vec!["-la".into()],
            env: vec!["PATH=/usr/bin".into()],
            cwd: Some("/tmp".into()),
        });

        let mut buf = Vec::new();
        encode(&mut buf, &req).unwrap();

        let mut cursor = io::Cursor::new(&buf);
        let decoded: Request = decode(&mut cursor).unwrap();
        match decoded {
            Request::Exec(e) => {
                assert_eq!(e.cmd, "/bin/ls");
                assert_eq!(e.args, vec!["-la"]);
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn roundtrip_response_variants() {
        let cases: Vec<Response> = vec![
            Response::Stdout(b"hello".to_vec()),
            Response::Stderr(b"error".to_vec()),
            Response::Exit(0),
            Response::Error("boom".into()),
            Response::Pong,
            Response::Ok,
        ];

        for resp in cases {
            let mut buf = Vec::new();
            encode(&mut buf, &resp).unwrap();

            let mut cursor = io::Cursor::new(&buf);
            let _decoded: Response = decode(&mut cursor).unwrap();
        }
    }

    #[test]
    fn rejects_oversized_frame() {
        // Craft a frame header claiming 32 MiB
        let header = (32u32 * 1024 * 1024).to_be_bytes();
        let mut cursor = io::Cursor::new(&header[..]);
        let result: io::Result<Request> = decode(&mut cursor);
        assert!(result.is_err());
    }
}
