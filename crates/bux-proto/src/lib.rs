//! Wire protocol for bux host↔guest communication.
//!
//! Messages are serialized with [`postcard`] and framed with a 4-byte
//! big-endian length prefix, suitable for any reliable byte stream
//! (vsock, Unix socket, TCP).
//!
//! # Per-Operation Connection Model
//!
//! Each operation (exec, file read, etc.) uses its own dedicated connection.
//! The first message on every connection is a [`Hello`] that identifies the
//! operation type, followed by a [`HelloAck`] from the guest. Subsequent
//! messages are operation-specific (e.g. [`ExecIn`]/[`ExecOut`] for exec).

mod codec;
mod message;

pub use codec::{
    recv, recv_download, recv_download_to_writer, recv_upload, recv_upload_to_writer, send,
    send_download, send_download_from_reader, send_upload, send_upload_from_reader,
};
pub use message::{
    AGENT_PORT, ControlReq, ControlResp, Download, ErrorCode, ErrorInfo, ExecIn, ExecOut,
    ExecStart, Hello, HelloAck, MAX_UPLOAD_BYTES, PROTOCOL_VERSION, STREAM_CHUNK_SIZE, TtyConfig,
    Upload, UploadResult,
};
