//! OCI image management for the bux micro-VM sandbox.
//!
//! Pulls, caches, and extracts OCI container images for use as rootfs
//! directories with libkrun micro-VMs. Powered by [`oci_client`].
//!
//! # Architecture
//!
//! ```text
//! Oci (public API)
//!  ├── Store (SQLite index + content-addressed blob storage)
//!  │    ├── layers/   — sha256-addressed layer tarballs
//!  │    ├── configs/  — sha256-addressed config blobs
//!  │    └── rootfs/   — extracted rootfs directories
//!  └── oci_client::Client (registry communication)
//! ```

#![allow(clippy::missing_docs_in_private_items)]

mod extract;
mod store;

use std::path::{Path, PathBuf};

use oci_client::Reference;
use oci_client::client::ClientConfig;
use oci_client::secrets::RegistryAuth;
pub use store::ImageMeta;
use store::Store;

/// Accepted layer media types (OCI + Docker).
const ACCEPTED_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
];

/// Result type for bux-oci operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors from OCI image operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The image reference string could not be parsed.
    #[error("invalid image reference: {0}")]
    InvalidReference(String),

    /// The image was not found locally.
    #[error("image not found: {0}")]
    NotFound(String),

    /// Local store / database error.
    #[error("db: {0}")]
    Db(String),

    /// OCI registry protocol error.
    #[error("registry: {0}")]
    Registry(String),

    /// Filesystem I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// JSON parsing error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Configuration for initializing [`Oci`].
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
        let store_dir = dirs_default_store();
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
}

impl ImageConfig {
    /// Returns the combined entrypoint + cmd as the final execution command.
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
    /// Image configuration (Cmd, Env, WorkingDir, etc.).
    pub config: Option<ImageConfig>,
}

/// OCI image manager backed by a content-addressed store.
///
/// All methods take `&self` — the underlying store uses SQLite (which serializes
/// writes internally) and content-addressed blobs (immutable files).
pub struct Oci {
    /// Content-addressed image store.
    store: Store,
    /// OCI registry HTTP client.
    client: oci_client::Client,
    /// Registry authentication credentials.
    auth: RegistryAuth,
}

impl std::fmt::Debug for Oci {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oci")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl Oci {
    /// Opens the OCI manager with default configuration.
    pub fn open() -> Result<Self> {
        Self::open_with(OciConfig::default())
    }

    /// Opens the OCI manager with explicit configuration.
    pub fn open_with(config: OciConfig) -> Result<Self> {
        let store = Store::open(&config.store_dir)?;
        let client = oci_client::Client::new(ClientConfig::default());
        Ok(Self {
            store,
            client,
            auth: config.auth,
        })
    }

    /// Opens the OCI manager rooted at a specific directory.
    pub fn open_at(store_dir: &Path) -> Result<Self> {
        Self::open_with(OciConfig {
            store_dir: store_dir.to_path_buf(),
            ..Default::default()
        })
    }

    /// Pulls an image from a registry, caches layers, extracts rootfs.
    ///
    /// Layers are stored individually by digest — shared layers between images
    /// are downloaded only once. `on_status` receives human-readable progress.
    pub async fn pull(&self, image: &str, on_status: impl Fn(&str)) -> Result<PullResult> {
        let reference = parse_reference(image)?;
        let ref_str = reference.to_string();

        // 1. Pull manifest + layers from registry.
        on_status(&format!("Pulling {ref_str}..."));
        let image_data = self
            .client
            .pull(&reference, &self.auth, ACCEPTED_MEDIA_TYPES.to_vec())
            .await
            .map_err(|e| Error::Registry(e.to_string()))?;

        let manifest_digest = image_data.digest.clone().unwrap_or_default();

        // 2. Save each layer to content-addressed blob store (dedup).
        //    `save_layer` is idempotent — if the blob already exists on disk it skips the write.
        let mut layer_digests = Vec::with_capacity(image_data.layers.len());
        let mut total_size: u64 = 0;
        for (i, layer) in image_data.layers.iter().enumerate() {
            let media_type = if layer.media_type.is_empty() {
                "application/vnd.oci.image.layer.v1.tar+gzip"
            } else {
                &layer.media_type
            };
            on_status(&format!(
                "Caching layer {}/{} ({} bytes)...",
                i + 1,
                image_data.layers.len(),
                layer.data.len()
            ));
            let digest = self.store.save_layer(&layer.data, media_type)?;
            layer_digests.push(digest);
            total_size += layer.data.len() as u64;
        }

        // 3. Save config blob.
        let config_digest = self.store.save_config(&image_data.config.data)?;
        let config = parse_image_config(&image_data.config.data);

        // 4. Extract rootfs from cached layer files (streaming from disk).
        let rootfs = self.store.rootfs_path(&manifest_digest);
        if !rootfs.is_dir() {
            on_status("Extracting rootfs...");
            let layer_files: Vec<(PathBuf, String)> = layer_digests
                .iter()
                .map(|d| {
                    let media_type = "application/vnd.oci.image.layer.v1.tar+gzip".to_string();
                    (self.store.layer_path(d), media_type)
                })
                .collect();

            // Run extraction in a blocking task (CPU-bound tar I/O).
            let rootfs_clone = rootfs.clone();
            tokio::task::spawn_blocking(move || {
                extract::extract_layer_files(&layer_files, &rootfs_clone)
            })
            .await
            .map_err(|e| Error::Io(std::io::Error::other(e)))??;
        }

        // 5. Update SQLite index.
        self.store.upsert_image(
            &ref_str,
            &manifest_digest,
            total_size,
            &config_digest,
            &layer_digests,
        )?;

        on_status("Done.");
        Ok(PullResult {
            reference: ref_str,
            digest: manifest_digest,
            rootfs,
            config,
        })
    }

    /// Returns a cached [`PullResult`] if already present, otherwise pulls.
    ///
    /// This is the preferred entry point for `bux run <image>` — instant when cached.
    pub async fn ensure(&self, image: &str, on_status: impl Fn(&str)) -> Result<PullResult> {
        let reference = parse_reference(image)?;
        let ref_str = reference.to_string();

        // Check if we have a cached rootfs for this reference.
        if let Some(digest) = self.store.get_digest(&ref_str)? {
            let rootfs = self.store.rootfs_path(&digest);
            if rootfs.is_dir() {
                let config = self
                    .store
                    .load_image_config(&ref_str)?
                    .and_then(|json| serde_json::from_str(&json).ok());
                return Ok(PullResult {
                    reference: ref_str,
                    digest,
                    rootfs,
                    config,
                });
            }
        }

        self.pull(image, on_status).await
    }

    /// Lists all locally stored images.
    pub fn images(&self) -> Result<Vec<ImageMeta>> {
        self.store.list_images()
    }

    /// Removes a locally stored image and its extracted rootfs.
    ///
    /// Layer blobs are ref-counted; only orphaned blobs are deleted.
    pub fn remove(&self, image: &str) -> Result<()> {
        let reference = parse_reference(image)?;
        self.store.remove_image(&reference.to_string())
    }
}

/// Parses an image string into an [`oci_client::Reference`].
fn parse_reference(image: &str) -> Result<Reference> {
    image
        .parse()
        .map_err(|e: oci_client::ParseError| Error::InvalidReference(e.to_string()))
}

/// Deserializes the raw OCI config JSON blob into our minimal [`ImageConfig`].
///
/// The config blob wraps the actual config under a top-level `"config"` key.
fn parse_image_config(data: &[u8]) -> Option<ImageConfig> {
    #[derive(serde::Deserialize)]
    struct TopLevel {
        config: Option<ImageConfig>,
    }
    serde_json::from_slice::<TopLevel>(data).ok()?.config
}

/// Returns the default store directory: `$BUX_HOME` or `<platform_data_dir>/bux`.
fn dirs_default_store() -> PathBuf {
    if let Ok(home) = std::env::var("BUX_HOME") {
        return PathBuf::from(home);
    }
    // Use dirs crate logic inline to avoid adding the dependency.
    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("bux");
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".local/share/bux");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join("Library/Application Support/bux");
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(appdata).join("bux");
        }
    }
    PathBuf::from("bux")
}
