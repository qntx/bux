//! Start-up errors and the HTTP `{ "error": { "code", "message" } }` envelope.

use std::io;
use std::net::SocketAddr;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::ids::IdError;

/// Result alias for serve start and key loading.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors from worker start, listen, and API-key loading.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(
    clippy::error_impl_error,
    reason = "Error is the crate's public error type"
)]
pub enum Error {
    /// No API keys were provided.
    #[error("at least one API key is required")]
    NoApiKeys,

    /// `--api-key` / `BUX_API_KEYS` value was not `id:secret`.
    #[error("API key must be id:secret")]
    ApiKeyMissingSeparator,

    /// Key file line was not `id=secret`.
    #[error("API key file {path}: line {line}: expected id=secret")]
    ApiKeyFileSyntax {
        /// Path of the key file.
        path: String,
        /// 1-based line number.
        line: usize,
    },

    /// Secret was empty.
    #[error("API key {0:?} has an empty secret")]
    EmptyApiKeySecret(String),

    /// Two keys used the same id.
    #[error("duplicate API key id {0:?}")]
    DuplicateApiKeyId(String),

    /// Tenant / agent / key id failed alphabet or length checks.
    #[error(transparent)]
    InvalidId(#[from] IdError),

    /// `--listen` was not `IP:PORT`.
    #[error("invalid listen address {0:?}")]
    InvalidListen(String),

    /// TCP bind was not loopback.
    #[error("refusing non-loopback listen {0}")]
    NonLoopback(SocketAddr),

    /// Bind, file, or runtime I/O.
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl Error {
    /// Process exit status: `2` for usage / config, `1` for I/O.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Io(_) => 1,
            _ => 2,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    pub(crate) const fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "missing or invalid bearer token",
        }
    }

    pub(crate) const fn payload_too_large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "payload_too_large",
            message: "request body too large",
        }
    }
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorEnvelope {
            error: ErrorBody {
                code: self.code,
                message: self.message,
            },
        };
        (self.status, Json(body)).into_response()
    }
}
