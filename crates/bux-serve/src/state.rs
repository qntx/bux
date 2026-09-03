//! Worker process state: API keys, exclusive [`bux::Runtime`], admission limits.

use std::sync::Arc;

use serde::Serialize;

use crate::ApiKey;

/// Server-enforced create caps and request defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Limits {
    /// Maximum sandboxes for one tenant.
    pub max_sandboxes: u32,
    /// Maximum sandboxes on this worker (all tenants).
    pub max_sandboxes_global: u32,
    /// Maximum RAM per sandbox (MiB). Exceeded → 400.
    pub max_ram_mib: u32,
    /// Maximum vCPUs per sandbox. Exceeded → 400.
    pub max_vcpus: u8,
    /// Maximum sum of Running+Stopping RAM plus the new request (MiB). Exceeded → 429.
    pub max_running_ram_mib: u32,
    /// Maximum recursive data-dir usage (bytes). Exceeded → 429.
    pub max_disk_bytes: u64,
    /// `ram_mib` when the create body omits it.
    pub default_ram_mib: u32,
    /// `vcpus` when the create body omits it.
    pub default_vcpus: u8,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sandboxes: 32,
            max_sandboxes_global: 32,
            max_ram_mib: 2048,
            max_vcpus: 4,
            max_running_ram_mib: 8192,
            max_disk_bytes: 32_u64 * 1024 * 1024 * 1024,
            default_ram_mib: 512,
            default_vcpus: 1,
        }
    }
}

/// Shared axum state. One [`bux::Runtime`] (one exclusive flock) per process.
#[derive(Clone, Debug)]
pub(crate) struct AppState {
    keys: Arc<[ApiKey]>,
    pub(crate) runtime: Arc<bux::Runtime>,
    pub(crate) limits: Limits,
}

impl AppState {
    pub(crate) fn new(keys: Vec<ApiKey>, runtime: bux::Runtime, limits: Limits) -> Self {
        Self {
            keys: keys.into(),
            runtime: Arc::new(runtime),
            limits,
        }
    }

    /// Compare `token` to every key secret (no early return). Last match wins.
    pub(crate) fn tenant_for_bearer(&self, token: &str) -> Option<&str> {
        let token = token.as_bytes();
        let mut found = None;
        for key in self.keys.iter() {
            if constant_time_eq(key.secret_bytes(), token) {
                found = Some(key.id());
            }
        }
        found
    }
}

/// Pad to at least this many bytes so unequal lengths are not a `zip` min-len oracle.
const CT_EQ_MIN_ITERS: usize = 256;

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut acc = u8::from(left.len() != right.len());
    let n = left.len().max(right.len()).max(CT_EQ_MIN_ITERS);
    for i in 0..n {
        acc |= left.get(i).copied().unwrap_or(0) ^ right.get(i).copied().unwrap_or(0);
    }
    acc == 0
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn tenant_for_bearer_last_match_wins() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = bux::Runtime::open(dir.path()).unwrap();
        let state = AppState::new(
            vec![
                ApiKey::new("first", "shared").unwrap(),
                ApiKey::new("second", "shared").unwrap(),
            ],
            runtime,
            Limits::default(),
        );
        assert_eq!(
            state.tenant_for_bearer("shared"),
            Some("second"),
            "must walk every key"
        );
    }

    #[test]
    fn constant_time_eq_cases() {
        assert!(constant_time_eq(b"abc", b"abc"), "eq");
        assert!(!constant_time_eq(b"abc", b"abd"), "neq");
        assert!(!constant_time_eq(b"abc", b"ab"), "len");
        assert!(constant_time_eq(b"", b""), "empty");
    }

    #[test]
    fn default_disk_cap_is_32_gib() {
        assert_eq!(
            Limits::default().max_disk_bytes,
            32_u64 * 1024 * 1024 * 1024
        );
    }
}
