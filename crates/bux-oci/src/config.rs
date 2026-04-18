//! Configuration and result types for OCI image operations.

use std::path::PathBuf;

use oci_client::secrets::RegistryAuth;

/// Configuration for initializing [`crate::Oci`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct OciConfig {
    /// Root directory for the image store. Defaults to `<platform_data_dir>/bux`.
    pub store_dir: PathBuf,
    /// Registry authentication. Defaults to anonymous.
    pub auth: RegistryAuth,
}

impl Default for OciConfig {
    fn default() -> Self {
        let store_dir = crate::dirs_default_store();
        Self {
            store_dir,
            auth: RegistryAuth::Anonymous,
        }
    }
}

/// Subset of the OCI image configuration relevant to VM execution.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageConfig {
    /// Default command (`CMD`).
    #[serde(default, alias = "Cmd")]
    pub cmd: Option<Vec<String>>,
    /// Default entrypoint (`ENTRYPOINT`).
    #[serde(default, alias = "Entrypoint")]
    pub entrypoint: Option<Vec<String>>,
    /// Default environment variables.
    #[serde(default, alias = "Env")]
    pub env: Option<Vec<String>>,
    /// Default working directory.
    #[serde(default, alias = "WorkingDir")]
    pub working_dir: Option<String>,
    /// Default user (from `USER` directive).
    #[serde(default, alias = "User")]
    pub user: Option<String>,
    /// Exposed ports (from `EXPOSE` directive).
    #[serde(default, alias = "ExposedPorts")]
    pub exposed_ports: Option<serde_json::Value>,
    /// Image labels (from `LABEL` directive).
    #[serde(default, alias = "Labels")]
    pub labels: Option<serde_json::Map<String, serde_json::Value>>,
}

impl ImageConfig {
    /// Returns the combined entrypoint + cmd as the final execution command.
    #[must_use]
    pub fn command(&self) -> Vec<String> {
        let mut parts = Vec::new();
        if let Some(ref ep) = self.entrypoint {
            parts.extend(ep.iter().cloned());
        }
        if let Some(ref cmd) = self.cmd {
            parts.extend(cmd.iter().cloned());
        }
        parts
    }
}

/// Result of a successful image pull.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PullResult {
    /// Canonical image reference string.
    pub reference: String,
    /// Manifest content digest.
    pub digest: String,
    /// Path to the extracted rootfs directory.
    pub rootfs: PathBuf,
    /// Image configuration (Cmd, Env, `WorkingDir`, etc.).
    pub config: Option<ImageConfig>,
}
