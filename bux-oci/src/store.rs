//! Local OCI image store backed by SQLite + content-addressed blob storage.
//!
//! Layout:
//! ```text
//! {root}/
//!   images.db          — SQLite: image index + layer refs
//!   layers/            — content-addressed layer tarballs (sha256-{hex}.tar.gz)
//!   configs/           — image config blobs (sha256-{hex}.json)
//!   rootfs/{digest}/   — extracted rootfs directories (keyed by manifest digest)
//! ```

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

/// Extension trait to convert `rusqlite::Result` into `crate::Result`.
trait DbResultExt<T> {
    fn db(self) -> crate::Result<T>;
}

impl<T> DbResultExt<T> for rusqlite::Result<T> {
    fn db(self) -> crate::Result<T> {
        self.map_err(|e| crate::Error::Db(e.to_string()))
    }
}

/// Metadata for a locally stored image.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageMeta {
    /// Full image reference string (e.g. `docker.io/library/alpine:latest`).
    pub reference: String,
    /// Manifest content digest (e.g. `sha256:abcdef...`).
    pub digest: String,
    /// Total compressed layer size in bytes.
    pub size: u64,
    /// ISO 8601 timestamp when the image was cached.
    pub created_at: String,
}

/// Content-addressed OCI image store with SQLite indexing.
pub struct Store {
    /// Root directory for the store.
    root: PathBuf,
    /// SQLite database connection.
    db: Connection,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("root", &self.root)
            .field("db", &"<sqlite>")
            .finish()
    }
}

// SQL schema — single migration for now, extensible via version table.
const SCHEMA: &str = "\
    CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
    INSERT OR IGNORE INTO schema_version VALUES (1);
    CREATE TABLE IF NOT EXISTS images (
        reference TEXT PRIMARY KEY,
        digest    TEXT NOT NULL,
        size      INTEGER NOT NULL DEFAULT 0,
        config    TEXT,
        created   TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS layers (
        digest     TEXT PRIMARY KEY,
        media_type TEXT NOT NULL,
        size       INTEGER NOT NULL DEFAULT 0,
        ref_count  INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS image_layers (
        image_ref   TEXT NOT NULL REFERENCES images(reference) ON DELETE CASCADE,
        layer_digest TEXT NOT NULL REFERENCES layers(digest),
        position    INTEGER NOT NULL,
        PRIMARY KEY (image_ref, layer_digest)
    );
";

impl Store {
    /// Opens (or creates) the store at the given root directory.
    pub fn open(root: &Path) -> crate::Result<Self> {
        fs::create_dir_all(root.join("layers"))?;
        fs::create_dir_all(root.join("configs"))?;
        fs::create_dir_all(root.join("rootfs"))?;

        let db_path = root.join("images.db");
        let db = Connection::open(&db_path).db()?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .db()?;
        db.execute_batch(SCHEMA).db()?;

        Ok(Self {
            root: root.to_path_buf(),
            db,
        })
    }

    /// Returns the path to a layer tarball on disk.
    pub fn layer_path(&self, digest: &str) -> PathBuf {
        let filename = digest.replace(':', "-");
        self.root.join("layers").join(format!("{filename}.tar.gz"))
    }

    /// Returns a staging path for streaming a layer download.
    ///
    /// The caller writes to this path, then calls [`commit_layer`] to
    /// atomically move it into place.
    pub fn layer_staging_path(&self, digest: &str) -> PathBuf {
        let filename = digest.replace(':', "-");
        self.root
            .join("layers")
            .join(format!("{filename}.tar.gz.tmp"))
    }

    /// Returns `true` if a layer blob already exists on disk.
    pub fn has_layer(&self, digest: &str) -> bool {
        self.layer_path(digest).exists()
    }

    /// Commits a streamed layer: atomic rename from staging path + DB upsert.
    ///
    /// The caller must have already written the layer data to the path
    /// returned by [`layer_staging_path`].
    pub fn commit_layer(&self, digest: &str, media_type: &str, size: u64) -> crate::Result<()> {
        let staging = self.layer_staging_path(digest);
        let final_path = self.layer_path(digest);
        fs::rename(&staging, &final_path)?;

        self.db
            .execute(
                "INSERT INTO layers (digest, media_type, size)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(digest) DO UPDATE SET ref_count = ref_count + 1",
                params![digest, media_type, i64::try_from(size).unwrap_or(i64::MAX)],
            )
            .db()?;

        Ok(())
    }

    /// Verifies layer integrity by recomputing SHA256.
    ///
    /// Returns `Ok(true)` if the hash matches, `Ok(false)` if it doesn't,
    /// and `Err` on I/O failure. Not used internally — `oci-client` verifies
    /// digests during download. Exposed for external callers.
    #[allow(dead_code)]
    pub fn verify_layer(&self, digest: &str) -> crate::Result<bool> {
        let path = self.layer_path(digest);
        let data = fs::read(&path)?;
        let computed = format!("sha256:{:x}", Sha256::digest(&data));
        Ok(computed == digest)
    }

    /// Path to a config blob on disk.
    fn config_path(&self, digest: &str) -> PathBuf {
        let filename = digest.replace(':', "-");
        self.root.join("configs").join(format!("{filename}.json"))
    }

    /// Saves an image config blob with a pre-computed digest.
    pub fn save_config(&self, digest: &str, data: &str) -> crate::Result<()> {
        let path = self.config_path(digest);
        if !path.exists() {
            atomic_write(&path, data.as_bytes())?;
        }
        Ok(())
    }

    /// Path to an extracted rootfs directory (keyed by manifest digest).
    pub fn rootfs_path(&self, manifest_digest: &str) -> PathBuf {
        let dirname = manifest_digest.replace(':', "-");
        self.root.join("rootfs").join(dirname)
    }

    /// Returns a staging path for rootfs extraction.
    pub fn rootfs_staging_path(&self, manifest_digest: &str) -> PathBuf {
        let dirname = manifest_digest.replace(':', "-");
        self.root.join("rootfs").join(format!("{dirname}.tmp"))
    }

    /// Returns `true` if an extracted rootfs is complete and valid.
    pub fn rootfs_complete(&self, manifest_digest: &str) -> bool {
        self.rootfs_path(manifest_digest).is_dir()
    }

    /// Atomically installs a staged rootfs extraction.
    ///
    /// Removes any stale staging directory first, then renames the staging
    /// path into its final location. If the final path already exists
    /// (e.g. from a concurrent extraction), the staging directory is removed.
    pub fn commit_rootfs(&self, manifest_digest: &str) -> crate::Result<()> {
        let staging = self.rootfs_staging_path(manifest_digest);
        let final_path = self.rootfs_path(manifest_digest);

        if final_path.is_dir() {
            // Another call already completed — discard our staging dir.
            fs::remove_dir_all(&staging).ok();
            return Ok(());
        }

        fs::rename(&staging, &final_path)?;
        Ok(())
    }

    /// Inserts or updates an image record and its layer associations.
    pub fn upsert_image(
        &self,
        reference: &str,
        digest: &str,
        size: u64,
        config_digest: &str,
        layer_digests: &[String],
    ) -> crate::Result<()> {
        let tx = self.db.unchecked_transaction().db()?;

        // Load config JSON from blob store for embedding in the DB.
        let config_json = fs::read_to_string(self.config_path(config_digest)).ok();

        tx.execute(
            "INSERT INTO images (reference, digest, size, config)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(reference) DO UPDATE SET
                digest = excluded.digest,
                size = excluded.size,
                config = excluded.config,
                created = datetime('now')",
            params![
                reference,
                digest,
                i64::try_from(size).unwrap_or(i64::MAX),
                config_json
            ],
        )
        .db()?;

        // Clear old layer associations, then insert new ones.
        tx.execute(
            "DELETE FROM image_layers WHERE image_ref = ?1",
            params![reference],
        )
        .db()?;

        for (pos, layer_digest) in layer_digests.iter().enumerate() {
            tx.execute(
                "INSERT OR IGNORE INTO image_layers (image_ref, layer_digest, position)
                 VALUES (?1, ?2, ?3)",
                params![
                    reference,
                    layer_digest,
                    i64::try_from(pos).unwrap_or(i64::MAX)
                ],
            )
            .db()?;
        }

        tx.commit().db()?;
        Ok(())
    }

    /// Lists all stored images.
    pub fn list_images(&self) -> crate::Result<Vec<ImageMeta>> {
        let mut stmt = self
            .db
            .prepare("SELECT reference, digest, size, created FROM images ORDER BY created DESC")
            .db()?;

        let rows = stmt
            .query_map([], |row| {
                Ok(ImageMeta {
                    reference: row.get(0)?,
                    digest: row.get(1)?,
                    size: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                    created_at: row.get::<_, String>(3).unwrap_or_default(),
                })
            })
            .db()?;

        let mut images = Vec::new();
        for row in rows {
            images.push(row.db()?);
        }
        Ok(images)
    }

    /// Loads the stored image config JSON for a reference.
    pub fn load_image_config(&self, reference: &str) -> crate::Result<Option<String>> {
        match self.db.query_row(
            "SELECT config FROM images WHERE reference = ?1",
            params![reference],
            |row| row.get(0),
        ) {
            Ok(json) => Ok(Some(json)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(crate::Error::Db(e.to_string())),
        }
    }

    /// Looks up the manifest digest for a reference, if cached.
    pub fn get_digest(&self, reference: &str) -> crate::Result<Option<String>> {
        let result: rusqlite::Result<String> = self.db.query_row(
            "SELECT digest FROM images WHERE reference = ?1",
            params![reference],
            |row| row.get(0),
        );
        match result {
            Ok(d) => Ok(Some(d)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(crate::Error::Db(e.to_string())),
        }
    }

    /// Removes an image and its rootfs. Layer blobs are ref-counted and only
    /// deleted when no other image references them.
    pub fn remove_image(&self, reference: &str) -> crate::Result<()> {
        // Look up digest for rootfs cleanup.
        let digest = self.get_digest(reference)?;

        // Decrement layer ref counts and collect orphans.
        let layer_digests: Vec<String> = {
            let mut stmt = self
                .db
                .prepare("SELECT layer_digest FROM image_layers WHERE image_ref = ?1")
                .db()?;
            let rows = stmt.query_map(params![reference], |row| row.get(0)).db()?;
            rows.filter_map(Result::ok).collect()
        };

        let tx = self.db.unchecked_transaction().db()?;

        for ld in &layer_digests {
            tx.execute(
                "UPDATE layers SET ref_count = ref_count - 1 WHERE digest = ?1",
                params![ld],
            )
            .db()?;
        }

        // Delete the image (CASCADE deletes image_layers).
        tx.execute(
            "DELETE FROM images WHERE reference = ?1",
            params![reference],
        )
        .db()?;

        // Remove orphaned layer blobs (ref_count <= 0).
        let orphans: Vec<String> = {
            let mut stmt = tx
                .prepare("SELECT digest FROM layers WHERE ref_count <= 0")
                .db()?;
            let rows = stmt.query_map([], |row| row.get(0)).db()?;
            rows.filter_map(Result::ok).collect()
        };
        for orphan in &orphans {
            tx.execute("DELETE FROM layers WHERE digest = ?1", params![orphan])
                .db()?;
            fs::remove_file(self.layer_path(orphan)).ok();
        }

        tx.commit().db()?;

        // Remove rootfs directory.
        if let Some(ref d) = digest {
            let rootfs = self.rootfs_path(d);
            if rootfs.exists() {
                fs::remove_dir_all(&rootfs)?;
            }
        }

        Ok(())
    }
}

/// Writes data to a file atomically (write to .tmp, then rename).
fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}
