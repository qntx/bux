//! Wire protocol for bux host↔guest communication.
//!
//! Messages are serialized with [`postcard`] and framed with a 4-byte
//! big-endian length prefix, suitable for any reliable byte stream
//! (vsock, Unix socket, TCP).

mod codec;
mod message;

pub use codec::{recv, send};
pub use message::{AGENT_PORT, ExecReq, Request, Response};
