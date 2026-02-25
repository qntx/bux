//! OCI image management for the bux micro-VM sandbox.
//!
//! Pulls, stores, and extracts OCI container images for use as
//! rootfs directories with libkrun micro-VMs.

#![allow(clippy::missing_docs_in_private_items)]

mod extract;
pub mod reference;
mod registry;
mod store;

use std::path::PathBuf;

pub use reference::{Identifier, Reference};
use registry::Client;
pub use store::ImageMeta;
use store::Store;

/// Result type for bux-oci operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors from OCI image operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The image reference string could not be parsed.
    #[error("invalid image reference: {0}")]
    InvalidReference(String),

    /// The image was not found in the registry or local store.
    #[error("image not found: {0}")]
    NotFound(String),

    /// No manifest matched the current platform.
    #[error("no matching platform for {arch}/{os}")]
    NoPlatform {
        /// CPU architecture.
        arch: String,
        /// Operating system.
        os: String,
    },

    /// Downloaded content did not match its expected digest.
    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch {
        /// Expected digest.
        expected: String,
        /// Computed digest.
        actual: String,
    },

    /// Local store error.
    #[error("store error: {0}")]
    Store(String),

    /// HTTP / registry protocol error.
    #[error("HTTP error: {0}")]
    Http(String),

    /// Filesystem I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// JSON parsing error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Subset of the OCI image configuration relevant to container execution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct ImageConfig {
    /// Default command (`CMD`).
    #[serde(rename = "Cmd", default)]
    pub cmd: Option<Vec<String>>,
    /// Default entrypoint (`ENTRYPOINT`).
    #[serde(rename = "Entrypoint", default)]
    pub entrypoint: Option<Vec<String>>,
    /// Default environment variables.
    #[serde(rename = "Env", default)]
    pub env: Option<Vec<String>>,
    /// Default working directory.
    #[serde(rename = "WorkingDir", default)]
    pub working_dir: Option<String>,
}

/// Result of a successful image pull.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PullResult {
    /// Canonical image reference.
    pub reference: Reference,
    /// Path to the extracted rootfs directory.
    pub rootfs: PathBuf,
    /// Image configuration (Cmd, Env, WorkingDir, etc.).
    pub config: Option<ImageConfig>,
}

/// OCI image manager backed by a local content-addressable store.
#[derive(Debug)]
pub struct Oci {
    store: Store,
    client: Client,
}

impl Oci {
    /// Opens the OCI manager with the default storage location.
    pub fn open() -> Result<Self> {
        Ok(Self {
            store: Store::open()?,
            client: Client::new(),
        })
    }

    /// Pulls an image from a registry, extracts its rootfs, and returns the result.
    ///
    /// `on_status` is called with human-readable progress messages.
    pub fn pull(&mut self, image: &str, on_status: impl Fn(&str)) -> Result<PullResult> {
        let reference = Reference::parse(image)?;

        // 1. Pull manifest (resolves multi-arch index automatically).
        on_status("Resolving manifest...");
        let (manifest, manifest_digest) = self.client.pull_manifest(&reference)?;

        // 2. Pull and parse image config.
        self.client
            .download_blob(&reference, &self.store, &manifest.config.digest)?;
        let config_data = std::fs::read(self.store.blob_path(&manifest.config.digest))?;
        let full_config: registry::FullImageConfig = serde_json::from_slice(&config_data)?;

        // 3. Pull layer blobs.
        let total = manifest.layers.len();
        let mut blob_paths = Vec::with_capacity(total);
        for (i, layer) in manifest.layers.iter().enumerate() {
            let short = &layer.digest[..std::cmp::min(19, layer.digest.len())];
            on_status(&format!("Pulling layer {}/{total}: {short}…", i + 1));
            self.client
                .download_blob(&reference, &self.store, &layer.digest)?;
            blob_paths.push(self.store.blob_path(&layer.digest));
        }

        // 4. Extract rootfs.
        let storage_key = reference.storage_key();
        let rootfs = self.store.rootfs_path(&storage_key);
        if rootfs.exists() {
            std::fs::remove_dir_all(&rootfs)?;
        }
        on_status("Extracting rootfs...");
        extract::extract_layers(&blob_paths, &rootfs)?;

        // 5. Persist image metadata and config.
        let size: u64 = manifest.layers.iter().map(|l| l.size).sum();
        self.store.upsert_image(ImageMeta {
            reference: reference.to_string(),
            digest: manifest_digest,
            size,
        })?;
        if let Some(ref cfg) = full_config.config {
            self.store.save_image_config(&storage_key, cfg)?;
        }

        on_status("Done.");
        Ok(PullResult {
            reference,
            rootfs,
            config: full_config.config,
        })
    }

    /// Returns a cached [`PullResult`] if the image is already present, otherwise pulls it.
    ///
    /// This is the preferred entry point for `bux run <image>` — fast when cached.
    pub fn ensure(&mut self, image: &str, on_status: impl Fn(&str)) -> Result<PullResult> {
        let reference = Reference::parse(image)?;
        let key = reference.storage_key();

        if self.store.has_rootfs(&key) {
            let config = self.store.load_image_config(&key)?;
            return Ok(PullResult {
                reference,
                rootfs: self.store.rootfs_path(&key),
                config,
            });
        }

        self.pull(image, on_status)
    }

    /// Returns the rootfs path for a previously pulled image.
    pub fn rootfs(&self, image: &str) -> Result<PathBuf> {
        let reference = Reference::parse(image)?;
        let path = self.store.rootfs_path(&reference.storage_key());
        if !path.exists() {
            return Err(Error::NotFound(image.to_owned()));
        }
        Ok(path)
    }

    /// Lists all locally stored images.
    pub fn images(&self) -> Result<Vec<ImageMeta>> {
        self.store.load_images()
    }

    /// Removes a locally stored image and its extracted rootfs.
    pub fn remove(&self, image: &str) -> Result<()> {
        let reference = Reference::parse(image)?;
        self.store
            .remove_image(&reference.to_string(), &reference.storage_key())
    }
}
