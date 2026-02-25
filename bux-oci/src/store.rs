//! Local OCI blob and rootfs storage.

use std::fs;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use sha2::Digest as _;

const BUX_DIR: &str = "bux";
const BLOBS_DIR: &str = "blobs/sha256";
const ROOTFS_DIR: &str = "rootfs";
const IMAGES_FILE: &str = "images.json";

/// Metadata for a locally stored image.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct ImageMeta {
    /// Full image reference string.
    pub reference: String,
    /// Manifest content digest.
    pub digest: String,
    /// Total compressed layer size in bytes.
    pub size: u64,
}

/// Manages local OCI blob and rootfs storage.
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
        fs::create_dir_all(root.join(BLOBS_DIR))?;
        fs::create_dir_all(root.join(ROOTFS_DIR))?;
        Ok(Self { root })
    }

    /// Returns the filesystem path for a blob by its digest.
    pub fn blob_path(&self, digest: &str) -> PathBuf {
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        self.root.join(BLOBS_DIR).join(hex)
    }

    /// Returns `true` if a blob with the given digest exists locally.
    pub fn has_blob(&self, digest: &str) -> bool {
        self.blob_path(digest).exists()
    }

    /// Streams data from `reader` into the blob store, verifying the digest.
    pub fn save_blob(&self, digest: &str, reader: impl Read) -> crate::Result<()> {
        if self.has_blob(digest) {
            return Ok(());
        }

        let path = self.blob_path(digest);
        let file = fs::File::create(&path)?;
        let mut hw = HashWriter::new(BufWriter::new(file));
        let mut buf_reader = io::BufReader::new(reader);
        io::copy(&mut buf_reader, &mut hw)?;
        hw.flush()?;

        let computed = hw.finish();
        if computed != digest {
            fs::remove_file(&path).ok();
            return Err(crate::Error::DigestMismatch {
                expected: digest.to_owned(),
                actual: computed,
            });
        }
        Ok(())
    }

    /// Returns the rootfs directory path for an image reference.
    pub fn rootfs_path(&self, key: &str) -> PathBuf {
        self.root.join(ROOTFS_DIR).join(key)
    }

    /// Returns `true` if a rootfs for the given storage key exists.
    #[allow(dead_code)]
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

    /// Returns the path to the stored image config JSON for a given storage key.
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

/// Writer that computes SHA-256 while forwarding data to an inner writer.
struct HashWriter<W> {
    writer: W,
    hasher: sha2::Sha256,
}

impl<W> HashWriter<W> {
    fn new(writer: W) -> Self {
        Self {
            writer,
            hasher: sha2::Sha256::new(),
        }
    }

    /// Consumes the writer and returns the `sha256:<hex>` digest string.
    fn finish(self) -> String {
        format!("sha256:{}", hex::encode(self.hasher.finalize()))
    }
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.writer.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// Computes the `sha256:<hex>` digest of a byte slice.
pub fn content_digest(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(data)))
}

/// Removes all contents of a directory without removing the directory itself.
pub fn clear_directory(dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}
