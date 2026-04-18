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

#![allow(
    clippy::missing_docs_in_private_items,
    reason = "internal modules have self-explanatory fields"
)]

mod config;
mod error;
mod extract;
mod store;

use std::path::{Path, PathBuf};

use oci_client::Reference;
use oci_client::client::ClientConfig;
use oci_client::secrets::RegistryAuth;

pub use config::{ImageConfig, OciConfig, PullResult};
pub use error::{OciError, Result};
pub use store::ImageMeta;
use store::Store;

/// OCI image manager backed by a content-addressed store.
///
/// All methods take `&self` — the underlying store uses `SQLite` (which serializes
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
    ///
    /// # Errors
    ///
    /// Returns an error if the store directory cannot be created or the database fails to open.
    pub fn open() -> Result<Self> {
        Self::open_with(OciConfig::default())
    }

    /// Opens the OCI manager with explicit configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the store directory cannot be created or the database fails to open.
    pub fn open_with(config: OciConfig) -> Result<Self> {
        let store = Store::open(&config.store_dir)?;
        let client = oci_client::Client::new(ClientConfig {
            platform_resolver: Some(Box::new(linux_platform_resolver)),
            ..Default::default()
        });
        Ok(Self {
            store,
            client,
            auth: config.auth,
        })
    }

    /// Opens the OCI manager rooted at a specific directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the store directory cannot be created or the database fails to open.
    pub fn open_at(store_dir: &Path) -> Result<Self> {
        Self::open_with(OciConfig {
            store_dir: store_dir.to_path_buf(),
            ..Default::default()
        })
    }

    /// Pulls an image from a registry, caches layers, extracts rootfs.
    ///
    /// Uses streaming downloads — each layer is written directly to disk
    /// via `pull_blob`, keeping memory usage at `O(chunk_size)` instead of
    /// `O(total_image_size)`. `on_status` receives human-readable progress.
    pub async fn pull(&self, image: &str, on_status: impl Fn(&str)) -> Result<PullResult> {
        #![allow(clippy::missing_errors_doc, reason = "documented at module level")]
        let reference = parse_reference(image)?;
        let ref_str = reference.to_string();

        // 1. Pull manifest + config (small, OK in memory).
        on_status(&format!("Pulling {ref_str}..."));
        let (manifest, manifest_digest, config_json) = self
            .client
            .pull_manifest_and_config(&reference, &self.auth)
            .await?;

        // 2. Stream each layer to disk — O(chunk) memory per layer.
        let layer_count = manifest.layers.len();
        let mut total_size: u64 = 0;
        for (i, layer) in manifest.layers.iter().enumerate() {
            let digest = &layer.digest;
            let size = u64::try_from(layer.size).unwrap_or(0);

            if self.store.has_layer(digest) {
                on_status(&format!("Layer {}/{} cached", i + 1, layer_count));
            } else {
                on_status(&format!(
                    "Downloading layer {}/{} ({size} bytes)...",
                    i + 1,
                    layer_count
                ));
                let staging = self.store.layer_staging_path(digest);
                let mut file = tokio::fs::File::create(&staging).await?;
                self.client.pull_blob(&reference, layer, &mut file).await?;
                self.store.commit_layer(digest, &layer.media_type, size)?;
            }
            total_size += size;
        }

        // 3. Save config blob.
        let config_digest = &manifest.config.digest;
        self.store.save_config(config_digest, &config_json)?;
        let config = parse_image_config(&config_json);

        // 4. Extract rootfs atomically (staging dir → rename).
        let rootfs = self.store.rootfs_path(&manifest_digest);
        if !self.store.rootfs_complete(&manifest_digest) {
            on_status("Extracting rootfs...");
            let layer_files: Vec<(PathBuf, String)> = manifest
                .layers
                .iter()
                .map(|l| (self.store.layer_path(&l.digest), l.media_type.clone()))
                .collect();

            // Clean up any stale staging dir from a previous interrupted run.
            let staging = self.store.rootfs_staging_path(&manifest_digest);
            if staging.exists() {
                std::fs::remove_dir_all(&staging)?;
            }

            // Run extraction in a blocking task (CPU-bound tar I/O).
            let staging_clone = staging.clone();
            tokio::task::spawn_blocking(move || {
                extract::extract_layer_files(&layer_files, &staging_clone)
            })
            .await
            .map_err(|e| OciError::Io(std::io::Error::other(e)))??;

            self.store.commit_rootfs(&manifest_digest)?;
        }

        // 5. Update SQLite index.
        let layer_digests: Vec<String> = manifest.layers.iter().map(|l| l.digest.clone()).collect();
        self.store.upsert_image(
            &ref_str,
            &manifest_digest,
            total_size,
            config_digest,
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
    /// This is the preferred entry point for `bux run <image>` — instant when
    /// cached. Uses the private `rootfs_complete` check to verify the
    /// extraction finished successfully (crash-safe).
    /// # Errors
    ///
    /// Returns an error if the image reference is invalid, a pull or extraction fails,
    /// or database access encounters an error.
    pub async fn ensure(&self, image: &str, on_status: impl Fn(&str)) -> Result<PullResult> {
        let reference = parse_reference(image)?;
        let ref_str = reference.to_string();

        // Check if we have a complete cached rootfs for this reference.
        if let Some(digest) = self.store.get_digest(&ref_str)?
            && self.store.rootfs_complete(&digest)
        {
            let rootfs = self.store.rootfs_path(&digest);
            let config = self
                .store
                .load_image_config(&ref_str)?
                .and_then(|json| parse_image_config(&json));
            return Ok(PullResult {
                reference: ref_str,
                digest,
                rootfs,
                config,
            });
        }

        self.pull(image, on_status).await
    }

    /// Lists all locally stored images.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn images(&self) -> Result<Vec<ImageMeta>> {
        self.store.list_images()
    }

    /// Removes a locally stored image and its extracted rootfs.
    ///
    /// Layer blobs are ref-counted; only orphaned blobs are deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the image reference is invalid, the image is not found,
    /// or a database/filesystem operation fails.
    pub fn remove(&self, image: &str) -> Result<()> {
        let reference = parse_reference(image)?;
        self.store.remove_image(&reference.to_string())
    }
}

/// Parses an image string into an [`oci_client::Reference`].
fn parse_reference(image: &str) -> Result<Reference> {
    image
        .parse()
        .map_err(|e: oci_client::ParseError| OciError::InvalidReference(e.to_string()))
}

/// Deserializes the raw OCI config JSON blob into our minimal [`ImageConfig`].
///
/// The config blob wraps the actual config under a top-level `"config"` key.
fn parse_image_config(data: &str) -> Option<ImageConfig> {
    #[derive(serde::Deserialize)]
    struct TopLevel {
        config: Option<ImageConfig>,
    }
    serde_json::from_str::<TopLevel>(data).ok()?.config
}

/// Platform resolver that always selects `linux/{arch}`.
///
/// VMs always run Linux regardless of the host OS, so we must pull Linux
/// images even when running on macOS.
fn linux_platform_resolver(platforms: &[oci_client::manifest::ImageIndexEntry]) -> Option<String> {
    let target_arch = target_oci_arch();

    // Prefer exact linux/{arch} match.
    for entry in platforms {
        if let Some(ref p) = entry.platform
            && p.os.to_string() == "linux"
            && p.architecture.to_string() == target_arch
        {
            return Some(entry.digest.clone());
        }
    }
    // Fallback: first linux entry regardless of arch.
    for entry in platforms {
        if let Some(ref p) = entry.platform
            && p.os.to_string() == "linux"
        {
            return Some(entry.digest.clone());
        }
    }
    None
}

fn target_oci_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
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
