//! Local rootfs storage and image metadata management.

use std::fs;
use std::path::PathBuf;

const BUX_DIR: &str = "bux";
const ROOTFS_DIR: &str = "rootfs";
const IMAGES_FILE: &str = "images.json";

/// Metadata for a locally stored image.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageMeta {
    /// Full image reference string.
    pub reference: String,
    /// Manifest content digest.
    pub digest: String,
    /// Total compressed layer size in bytes.
    pub size: u64,
}

/// Manages local rootfs directories and image metadata.
///
/// Default location: `$BUX_HOME` or `<platform_data_dir>/bux`.
#[derive(Debug)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Opens (or creates) the default store directory.
    pub fn open() -> crate::Result<Self> {
        let root = if let Ok(home) = std::env::var("BUX_HOME") {
            PathBuf::from(home)
        } else {
            dirs::data_local_dir()
                .ok_or_else(|| {
                    crate::Error::Store("cannot determine platform data directory".into())
                })?
                .join(BUX_DIR)
        };
        fs::create_dir_all(root.join(ROOTFS_DIR))?;
        Ok(Self { root })
    }

    /// Returns the rootfs directory path for an image storage key.
    pub fn rootfs_path(&self, key: &str) -> PathBuf {
        self.root.join(ROOTFS_DIR).join(key)
    }

    /// Returns `true` if a rootfs for the given storage key exists.
    pub fn has_rootfs(&self, key: &str) -> bool {
        self.rootfs_path(key).exists()
    }

    /// Loads the image index from disk.
    pub fn load_images(&self) -> crate::Result<Vec<ImageMeta>> {
        let path = self.root.join(IMAGES_FILE);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let data = fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&data)?)
    }

    /// Persists the image index to disk.
    fn save_images(&self, images: &[ImageMeta]) -> crate::Result<()> {
        let data = serde_json::to_string_pretty(images)?;
        fs::write(self.root.join(IMAGES_FILE), data)?;
        Ok(())
    }

    /// Adds or replaces an image entry in the index.
    pub fn upsert_image(&self, meta: ImageMeta) -> crate::Result<()> {
        let mut images = self.load_images()?;
        images.retain(|i| i.reference != meta.reference);
        images.push(meta);
        self.save_images(&images)
    }

    /// Returns the path to the stored image config JSON.
    fn config_path(&self, key: &str) -> PathBuf {
        self.root.join(ROOTFS_DIR).join(format!("{key}.json"))
    }

    /// Saves image config alongside the rootfs.
    pub fn save_image_config(&self, key: &str, config: &crate::ImageConfig) -> crate::Result<()> {
        let data = serde_json::to_string_pretty(config)?;
        fs::write(self.config_path(key), data)?;
        Ok(())
    }

    /// Loads a previously saved image config.
    pub fn load_image_config(&self, key: &str) -> crate::Result<Option<crate::ImageConfig>> {
        let path = self.config_path(key);
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(path)?;
        Ok(Some(serde_json::from_str(&data)?))
    }

    /// Removes an image entry, its rootfs, and its config from disk.
    pub fn remove_image(&self, reference: &str, storage_key: &str) -> crate::Result<()> {
        let mut images = self.load_images()?;
        images.retain(|i| i.reference != reference);
        self.save_images(&images)?;

        let rootfs = self.rootfs_path(storage_key);
        if rootfs.exists() {
            fs::remove_dir_all(&rootfs)?;
        }
        let cfg = self.config_path(storage_key);
        if cfg.exists() {
            fs::remove_file(&cfg)?;
        }
        Ok(())
    }
}
