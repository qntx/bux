//! OCI Distribution protocol client.
//!
//! Supports pulling manifests and blobs from OCI-compliant registries
//! including Docker Hub and GHCR.

use std::collections::HashMap;
use std::io::Read;

use serde::Deserialize;

use crate::store::Store;
use crate::{Error, Reference, Result};

/// OCI / Docker manifest media types accepted during pull.
const ACCEPT_MANIFEST: &str = "\
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json, \
    application/vnd.docker.distribution.manifest.list.v2+json";

/// OCI content descriptor.
#[derive(Debug, Clone, Deserialize)]
pub struct Descriptor {
    #[allow(dead_code)]
    #[serde(rename = "mediaType")]
    pub media_type: Option<String>,
    pub digest: String,
    pub size: u64,
}

/// OCI image manifest (single-platform).
#[derive(Debug, Deserialize)]
pub struct ImageManifest {
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

/// Platform selector in an image index entry.
#[derive(Debug, Deserialize)]
struct Platform {
    architecture: String,
    os: String,
}

/// Entry within an image index (fat manifest).
#[derive(Debug, Deserialize)]
struct IndexEntry {
    digest: String,
    platform: Option<Platform>,
}

/// Image index / manifest list (multi-platform).
#[derive(Debug, Deserialize)]
struct ImageIndex {
    manifests: Vec<IndexEntry>,
}

/// Subset of the OCI image configuration blob.
#[derive(Debug, Clone, Deserialize)]
pub struct FullImageConfig {
    pub config: Option<crate::ImageConfig>,
}

/// OCI registry client with per-repository bearer token caching.
#[derive(Debug)]
pub struct Client {
    tokens: HashMap<String, String>,
}

impl Client {
    pub fn new() -> Self {
        Self {
            tokens: HashMap::new(),
        }
    }

    /// Pulls and resolves the image manifest, returning it with its content digest.
    pub fn pull_manifest(&mut self, reference: &Reference) -> Result<(ImageManifest, String)> {
        let url = format!(
            "{}/{}/manifests/{}",
            reference.api_base(),
            reference.repository,
            reference.reference_str()
        );
        let body = self.request(reference, &url, ACCEPT_MANIFEST)?;

        // Determine whether this is an index or a direct manifest.
        let value: serde_json::Value = serde_json::from_slice(&body)?;

        if value.get("manifests").is_some() {
            // Image index → select platform-specific manifest and re-fetch.
            let index: ImageIndex = serde_json::from_value(value)?;
            let entry = select_platform(&index)?;

            let platform_url = format!(
                "{}/{}/manifests/{}",
                reference.api_base(),
                reference.repository,
                entry.digest
            );
            let platform_body = self.request(reference, &platform_url, ACCEPT_MANIFEST)?;
            let digest = crate::store::content_digest(&platform_body);
            let manifest: ImageManifest = serde_json::from_slice(&platform_body)?;
            Ok((manifest, digest))
        } else {
            let digest = crate::store::content_digest(&body);
            let manifest: ImageManifest = serde_json::from_value(value)?;
            Ok((manifest, digest))
        }
    }

    /// Downloads a blob into the local store (skips if already present).
    pub fn download_blob(
        &mut self,
        reference: &Reference,
        store: &Store,
        digest: &str,
    ) -> Result<()> {
        if store.has_blob(digest) {
            return Ok(());
        }

        let url = format!(
            "{}/{}/blobs/{}",
            reference.api_base(),
            reference.repository,
            digest
        );
        let token = self.ensure_token(reference);

        let mut req = ureq::get(&url);
        if let Some(ref t) = token {
            req = req.header("Authorization", &format!("Bearer {t}"));
        }
        let resp = req.call().map_err(|e| Error::Http(e.to_string()))?;
        store.save_blob(digest, resp.into_body().into_reader())
    }

    /// Performs an authenticated GET and returns the response body.
    fn request(&mut self, reference: &Reference, url: &str, accept: &str) -> Result<Vec<u8>> {
        let token = self.ensure_token(reference);

        let mut req = ureq::get(url).header("Accept", accept);
        if let Some(ref t) = token {
            req = req.header("Authorization", &format!("Bearer {t}"));
        }

        let resp = req.call().map_err(|e| Error::Http(e.to_string()))?;
        let mut body = Vec::new();
        resp.into_body()
            .into_reader()
            .read_to_end(&mut body)
            .map_err(|e| Error::Http(e.to_string()))?;
        Ok(body)
    }

    /// Returns a cached bearer token, fetching one if needed for known registries.
    fn ensure_token(&mut self, reference: &Reference) -> Option<String> {
        let key = format!("{}/{}", reference.registry, reference.repository);
        if let Some(token) = self.tokens.get(&key) {
            return Some(token.clone());
        }

        let (realm, service) = match reference.registry.as_str() {
            "docker.io" => ("https://auth.docker.io/token", "registry.docker.io"),
            "ghcr.io" => ("https://ghcr.io/token", "ghcr.io"),
            _ => return None,
        };

        let token = fetch_bearer_token(realm, service, &reference.repository).ok()?;
        self.tokens.insert(key, token.clone());
        Some(token)
    }
}

/// Fetches a bearer token from a token endpoint.
fn fetch_bearer_token(realm: &str, service: &str, repository: &str) -> Result<String> {
    let scope = format!("repository:{repository}:pull");
    let url = format!("{realm}?service={service}&scope={scope}");

    let resp = ureq::get(&url)
        .call()
        .map_err(|e| Error::Http(e.to_string()))?;
    let mut body = Vec::new();
    resp.into_body()
        .into_reader()
        .read_to_end(&mut body)
        .map_err(|e| Error::Http(e.to_string()))?;

    let t: TokenResp = serde_json::from_slice(&body)?;
    Ok(t.token)
}

/// Bearer token response from a registry auth endpoint.
#[derive(Deserialize)]
struct TokenResp {
    token: String,
}

/// Selects the manifest entry matching the current host architecture and `linux` OS.
fn select_platform(index: &ImageIndex) -> Result<&IndexEntry> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };

    index
        .manifests
        .iter()
        .find(|m| {
            m.platform
                .as_ref()
                .is_some_and(|p| p.architecture == arch && p.os == "linux")
        })
        .ok_or_else(|| Error::NoPlatform {
            arch: arch.to_owned(),
            os: "linux".to_owned(),
        })
}
