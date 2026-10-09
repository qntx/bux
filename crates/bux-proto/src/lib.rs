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

mod boot;
mod codec;
mod message;
pub mod net;

pub use boot::{
    GUEST_BOOT_CONFIG_ENV, GuestBootConfig, GuestNetworkMode, GuestVolume,
    validate_guest_mount_path,
};
pub use codec::{recv, recv_download, recv_upload, send, send_download, send_upload};
pub use message::{
    AGENT_PORT, ControlReq, ControlResp, Download, ErrorCode, ErrorInfo, ExecIn, ExecOut,
    ExecStart, Hello, HelloAck, MAX_DOWNLOAD_BYTES, MAX_UPLOAD_BYTES, PROTOCOL_VERSION, TtyConfig,
    Upload, UploadResult,
};
