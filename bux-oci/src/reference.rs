//! OCI image reference parsing.
//!
//! Handles Docker-style image references:
//! - `ubuntu` → `docker.io/library/ubuntu:latest`
//! - `ubuntu:22.04` → `docker.io/library/ubuntu:22.04`
//! - `ghcr.io/org/app:v1` → `ghcr.io/org/app:v1`

use std::fmt;

const DEFAULT_REGISTRY: &str = "docker.io";
const DEFAULT_TAG: &str = "latest";
const OFFICIAL_REPO_PREFIX: &str = "library";

/// A parsed OCI image reference.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Reference {
    /// Registry hostname (e.g., `docker.io`, `ghcr.io`).
    pub registry: String,
    /// Repository path (e.g., `library/ubuntu`, `org/app`).
    pub repository: String,
    /// Image identifier (tag or digest).
    pub identifier: Identifier,
}

/// Tag or digest identifier for an image.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Identifier {
    /// Named tag (e.g., `latest`, `v1.0`).
    Tag(String),
    /// Content-addressable digest (e.g., `sha256:abc123...`).
    Digest(String),
}

impl Reference {
    /// Parses an image reference string.
    pub fn parse(input: &str) -> crate::Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(crate::Error::InvalidReference("empty reference".into()));
        }

        // Split off @digest
        let (name, raw_id) = if let Some((n, digest)) = trimmed.split_once('@') {
            if !digest.contains(':') {
                return Err(crate::Error::InvalidReference(format!(
                    "invalid digest: {digest}"
                )));
            }
            (n, Identifier::Digest(digest.to_owned()))
        } else {
            (trimmed, Identifier::Tag(DEFAULT_TAG.to_owned()))
        };

        // Split registry from repository
        let (registry, repo_with_tag) = match name.split_once('/') {
            Some((first, rest)) if is_registry(first) => (first.to_owned(), rest.to_owned()),
            _ => {
                let repo = if name.contains('/') {
                    name.to_owned()
                } else {
                    format!("{OFFICIAL_REPO_PREFIX}/{name}")
                };
                (DEFAULT_REGISTRY.to_owned(), repo)
            }
        };

        // Extract tag from repository (only if identifier is a placeholder tag)
        let (repository, identifier) = match raw_id {
            Identifier::Digest(_) => (repo_with_tag, raw_id),
            Identifier::Tag(_) => match repo_with_tag.rsplit_once(':') {
                Some((repo, tag)) => (repo.to_owned(), Identifier::Tag(tag.to_owned())),
                None => (repo_with_tag, Identifier::Tag(DEFAULT_TAG.to_owned())),
            },
        };

        Ok(Self {
            registry,
            repository,
            identifier,
        })
    }

    /// Returns the registry API base URL.
    pub fn api_base(&self) -> String {
        let host = match self.registry.as_str() {
            "docker.io" => "registry-1.docker.io",
            other => other,
        };
        format!("https://{host}/v2")
    }

    /// Returns the tag or digest string for API requests.
    pub fn reference_str(&self) -> &str {
        match &self.identifier {
            Identifier::Tag(t) | Identifier::Digest(t) => t,
        }
    }

    /// Returns a filesystem-safe key for local storage.
    pub fn storage_key(&self) -> String {
        format!(
            "{}/{}/{}",
            self.registry,
            self.repository,
            self.reference_str()
        )
        .replace('/', "_")
        .replace(':', "_")
    }
}

/// Returns `true` if the string looks like a registry hostname.
fn is_registry(s: &str) -> bool {
    s.contains('.') || s.contains(':') || s == "localhost"
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.registry, self.repository)?;
        match &self.identifier {
            Identifier::Tag(t) => write!(f, ":{t}"),
            Identifier::Digest(d) => write!(f, "@{d}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple() {
        let r = Reference::parse("ubuntu").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/ubuntu");
        assert_eq!(r.identifier, Identifier::Tag("latest".into()));
    }

    #[test]
    fn parse_with_tag() {
        let r = Reference::parse("ubuntu:22.04").unwrap();
        assert_eq!(r.repository, "library/ubuntu");
        assert_eq!(r.identifier, Identifier::Tag("22.04".into()));
    }

    #[test]
    fn parse_user_repo() {
        let r = Reference::parse("myuser/myapp:v1").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "myuser/myapp");
        assert_eq!(r.identifier, Identifier::Tag("v1".into()));
    }

    #[test]
    fn parse_custom_registry() {
        let r = Reference::parse("ghcr.io/org/app:latest").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "org/app");
    }

    #[test]
    fn parse_localhost_port() {
        let r = Reference::parse("localhost:5000/test:v1").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "test");
        assert_eq!(r.identifier, Identifier::Tag("v1".into()));
    }

    #[test]
    fn parse_digest() {
        let r = Reference::parse("ubuntu@sha256:abc123").unwrap();
        assert_eq!(r.repository, "library/ubuntu");
        assert_eq!(r.identifier, Identifier::Digest("sha256:abc123".into()));
    }

    #[test]
    fn display_roundtrip() {
        let r = Reference::parse("ghcr.io/org/app:v2").unwrap();
        assert_eq!(r.to_string(), "ghcr.io/org/app:v2");
    }
}
