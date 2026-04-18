//! Error types for bux-oci operations.

/// Result type for bux-oci operations.
pub type Result<T> = std::result::Result<T, OciError>;

/// Errors from OCI image operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum OciError {
    /// The image reference string could not be parsed.
    #[error("invalid image reference: {0}")]
    InvalidReference(String),

    /// The image was not found locally.
    #[error("image not found: {0}")]
    NotFound(String),

    /// Local store / database error.
    #[error("db: {0}")]
    Db(#[from] rusqlite::Error),

    /// OCI registry protocol error.
    #[error("registry: {0}")]
    Registry(#[from] oci_client::errors::OciDistributionError),

    /// Filesystem I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// JSON parsing error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
