//! OCI image management for the bux micro-VM sandbox.
//!
//! Pulls, stores, and extracts OCI container images for use as
//! rootfs directories with libkrun micro-VMs. Powered by [`oci_client`].

#![allow(clippy::missing_docs_in_private_items)]

mod extract;
mod store;

use std::path::PathBuf;

use oci_client::Reference;
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE;
use oci_client::secrets::RegistryAuth;
pub use store::ImageMeta;
use store::Store;

/// Result type for bux-oci operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors from OCI image operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The image reference string could not be parsed.
    #[error("invalid image reference: {0}")]
    InvalidReference(String),

    /// The image was not found locally.
    #[error("image not found: {0}")]
    NotFound(String),

    /// Local store error.
    #[error("store: {0}")]
    Store(String),

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

/// Subset of the OCI image configuration relevant to VM execution.
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
}

/// Result of a successful image pull.
#[derive(Debug, Clone)]
pub struct PullResult {
    /// Canonical image reference string.
    pub reference: String,
    /// Path to the extracted rootfs directory.
    pub rootfs: PathBuf,
    /// Image configuration (Cmd, Env, WorkingDir, etc.).
    pub config: Option<ImageConfig>,
}

/// OCI image manager backed by a local rootfs store.
#[allow(missing_debug_implementations)]
pub struct Oci {
    store: Store,
    client: oci_client::Client,
}

impl Oci {
    /// Opens the OCI manager with the default storage location.
    pub fn open() -> Result<Self> {
        let config = ClientConfig {
            protocol: ClientProtocol::Https,
            ..Default::default()
        };
        Ok(Self {
            store: Store::open()?,
            client: oci_client::Client::new(config),
        })
    }

    /// Pulls an image from a registry, extracts its rootfs, and returns the result.
    ///
    /// `on_status` is called with human-readable progress messages.
    pub async fn pull(&mut self, image: &str, on_status: impl Fn(&str)) -> Result<PullResult> {
        let reference = parse_reference(image)?;
        let ref_str = reference.to_string();
        let key = storage_key(&reference);

        // 1. Pull all layers via oci-client.
        on_status("Pulling image...");
        let image_data = self
            .client
            .pull(
                &reference,
                &RegistryAuth::Anonymous,
                vec![IMAGE_LAYER_GZIP_MEDIA_TYPE],
            )
            .await
            .map_err(|e| Error::Registry(e.to_string()))?;

        // 2. Extract rootfs from in-memory layers.
        let rootfs = self.store.rootfs_path(&key);
        if rootfs.exists() {
            std::fs::remove_dir_all(&rootfs)?;
        }
        on_status("Extracting rootfs...");
        let layers: Vec<Vec<u8>> = image_data
            .layers
            .into_iter()
            .map(|l| l.data.to_vec())
            .collect();
        extract::extract_layers(&layers, &rootfs)?;

        // 3. Parse and persist image config.
        let config = parse_image_config(&image_data.config.data);
        if let Some(ref cfg) = config {
            self.store.save_image_config(&key, cfg)?;
        }

        // 4. Persist image metadata.
        let digest = image_data.digest.unwrap_or_default();
        let size = layers.iter().map(|l| l.len() as u64).sum();
        self.store.upsert_image(ImageMeta {
            reference: ref_str.clone(),
            digest,
            size,
        })?;

        on_status("Done.");
        Ok(PullResult {
            reference: ref_str,
            rootfs,
            config,
        })
    }

    /// Returns a cached [`PullResult`] if the image is already present, otherwise pulls it.
    ///
    /// This is the preferred entry point for `bux run <image>` — fast when cached.
    pub async fn ensure(&mut self, image: &str, on_status: impl Fn(&str)) -> Result<PullResult> {
        let reference = parse_reference(image)?;
        let key = storage_key(&reference);

        if self.store.has_rootfs(&key) {
            let config = self.store.load_image_config(&key)?;
            return Ok(PullResult {
                reference: reference.to_string(),
                rootfs: self.store.rootfs_path(&key),
                config,
            });
        }

        self.pull(image, on_status).await
    }

    /// Lists all locally stored images.
    pub fn images(&self) -> Result<Vec<ImageMeta>> {
        self.store.load_images()
    }

    /// Removes a locally stored image and its extracted rootfs.
    pub fn remove(&self, image: &str) -> Result<()> {
        let reference = parse_reference(image)?;
        self.store
            .remove_image(&reference.to_string(), &storage_key(&reference))
    }
}

/// Parses an image string into an [`oci_client::Reference`].
fn parse_reference(image: &str) -> Result<Reference> {
    image
        .parse()
        .map_err(|e: oci_client::ParseError| Error::InvalidReference(e.to_string()))
}

/// Converts a reference into a filesystem-safe storage key.
fn storage_key(reference: &Reference) -> String {
    reference.to_string().replace(['/', ':', '@'], "_")
}

/// Deserializes the raw OCI config JSON blob into our minimal [`ImageConfig`].
///
/// The config blob wraps the config under a top-level `"config"` key with PascalCase fields.
/// [`ImageConfig`] uses `serde(alias)` to accept both PascalCase and lowercase keys.
fn parse_image_config(data: &[u8]) -> Option<ImageConfig> {
    #[derive(serde::Deserialize)]
    struct TopLevel {
        config: Option<ImageConfig>,
    }
    serde_json::from_slice::<TopLevel>(data).ok()?.config
}
