//! Start-up errors and the HTTP `{ "error": { "code", "message", ... } }` envelope.

use std::io;
use std::net::SocketAddr;

use axum::Json;
use axum::extract::FromRequest;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::ids::IdError;

/// Result alias for serve start and key loading.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors from worker start, listen, API-key loading, and runtime open.
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

    /// Engine [`bux::Error`] (exclusive flock [`bux::Error::Busy`], and others).
    #[error(transparent)]
    Runtime(#[from] bux::Error),
}

impl Error {
    /// Process exit status: `2` for usage / config, `1` for I/O and engine.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Io(_) | Self::Runtime(_) => 1,
            _ => 2,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    existing_id: Option<String>,
    field: Option<String>,
}

impl ApiError {
    pub(crate) fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "missing or invalid bearer token".into(),
            existing_id: None,
            field: None,
        }
    }

    pub(crate) fn payload_too_large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "payload_too_large",
            message: "request body too large".into(),
            existing_id: None,
            field: None,
        }
    }

    pub(crate) fn invalid_config(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_config",
            message: message.into(),
            existing_id: None,
            field: None,
        }
    }

    pub(crate) fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: "sandbox not found".into(),
            existing_id: None,
            field: None,
        }
    }

    pub(crate) fn name_occupied(existing_id: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "name_occupied",
            message: "sandbox name is occupied".into(),
            existing_id: Some(existing_id.into()),
            field: None,
        }
    }

    pub(crate) fn name_occupied_unknown() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "name_occupied",
            message: "sandbox name is occupied".into(),
            existing_id: None,
            field: None,
        }
    }

    pub(crate) fn resource_exhausted(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "resource_exhausted",
            message: message.into(),
            existing_id: None,
            field: None,
        }
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: message.into(),
            existing_id: None,
            field: None,
        }
    }

    pub(crate) fn with_field(mut self, field: &'static str) -> Self {
        self.field = Some(field.into());
        self
    }

    pub(crate) fn from_engine(err: bux::Error) -> Self {
        match err {
            bux::Error::InvalidConfig(message) => Self::invalid_config(message),
            bux::Error::NotFound(_) => Self::not_found(),
            bux::Error::Ambiguous(_) => Self::name_occupied_unknown(),
            bux::Error::InvalidState(message) => Self::conflict("invalid_state", message),
            bux::Error::Busy(message) => Self::conflict("busy", message),
            bux::Error::GuestUnavailable(message) => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "guest_unavailable",
                message,
                existing_id: None,
                field: None,
            },
            bux::Error::SecretsRequired => {
                Self::conflict("secrets_required", "secrets required for this sandbox")
            }
            bux::Error::SecretsNeedVirtioNet => Self::invalid_config("secrets require virtio-net"),
            bux::Error::SecurityUnavailable(message) => Self {
                status: StatusCode::PRECONDITION_FAILED,
                code: "security_unavailable",
                message,
                existing_id: None,
                field: None,
            },
            bux::Error::Oci(e) => map_oci(e),
            bux::Error::Shutdown => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "shutdown",
                message: "runtime has been shut down".into(),
                existing_id: None,
                field: None,
            },
            other => Self::internal(other.to_string()),
        }
    }

    fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message: message.into(),
            existing_id: None,
            field: None,
        }
    }
}

/// Display-based OCI mapping so serve does not depend on `bux-oci`.
fn map_oci(err: impl std::fmt::Display) -> ApiError {
    let message = err.to_string();
    if message.starts_with("invalid image reference") {
        ApiError::invalid_config(message)
    } else {
        ApiError {
            status: StatusCode::BAD_GATEWAY,
            code: "oci",
            message,
            existing_id: None,
            field: None,
        }
    }
}

impl From<IdError> for ApiError {
    fn from(err: IdError) -> Self {
        Self::invalid_config(err.to_string())
    }
}

/// JSON body that maps extractor failures to the error envelope (400).
pub(crate) struct JsonBody<T>(pub T);

impl<S, T> FromRequest<S> for JsonBody<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(
        req: axum::extract::Request,
        state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(json_rejection(&rejection)),
        }
    }
}

fn json_rejection(rejection: &JsonRejection) -> ApiError {
    ApiError::invalid_config(rejection.body_text())
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    existing_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<&'a str>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorEnvelope {
            error: ErrorBody {
                code: self.code,
                message: &self.message,
                existing_id: self.existing_id.as_deref(),
                field: self.field.as_deref(),
            },
        };
        (self.status, Json(body)).into_response()
    }
}
