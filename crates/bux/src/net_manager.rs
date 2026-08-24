//! Per-VM gvproxy lifecycle for managed Runtime.
//!
//! Owns [`GvproxyBackend`] instances keyed by VM id. When a VM uses
//! virtio-net (`NetworkSpec::Enabled`), Runtime starts a backend before
//! spawning the shim and drops it when the VM stops.
//!
//! Managed default uses virtio-net: guest configures static eth0 via
//! `BUX_GUEST_CONFIG`. `NetworkSpec::Disabled` is offline.
//!
//! `allow_net` empty means **unrestricted egress** (K20).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use bux_net::{ConnectionType, GvproxyBackend, NetworkConfig};
use bux_shim::{ShimNetConn, ShimNetwork};
use tracing::{debug, info, warn};

use crate::Result;
use crate::secrets::LiveSecrets;

/// Result of starting a per-VM network backend.
#[derive(Debug)]
pub(crate) struct StartNetResult {
    /// Engine virtio-net attachment.
    pub(crate) shim_network: ShimNetwork,
}

/// Owns live gvproxy instances for a Runtime data directory.
#[derive(Debug)]
pub(crate) struct NetworkManager {
    /// Per-VM backends (RAII: drop stops Go side).
    backends: Mutex<HashMap<String, GvproxyBackend>>,
    /// Directory for per-VM net sockets (`{socks_dir}/{id}.net.sock`).
    socks_dir: PathBuf,
}

impl NetworkManager {
    /// Create a manager that places sockets under `socks_dir`.
    #[must_use]
    pub(crate) fn new(socks_dir: PathBuf) -> Self {
        Self {
            backends: Mutex::new(HashMap::new()),
            socks_dir,
        }
    }

    /// Socket path for a VM's gvproxy endpoint.
    #[must_use]
    pub(crate) fn socket_path(&self, vm_id: &str) -> PathBuf {
        self.socks_dir.join(format!("{vm_id}.net.sock"))
    }

    /// Start gvproxy for `vm_id`.
    ///
    /// - `port_mappings`: concrete `(host, guest)` (ephemeral already resolved)
    /// - `allow_net`: empty = full egress; non-empty = DNS/TCP allow-list
    /// - `secrets`: optional MITM material (CA + secret list)
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Net`] if gvproxy fails, or I/O errors cleaning
    /// a stale socket path.
    pub(crate) fn start(
        &self,
        vm_id: &str,
        port_mappings: Vec<(u16, u16)>,
        allow_net: Vec<String>,
        secrets: Option<&LiveSecrets>,
    ) -> Result<StartNetResult> {
        // Replace any previous backend for this id.
        self.stop(vm_id);

        let socket_path = self.socket_path(vm_id);
        if socket_path.exists() {
            std::fs::remove_file(&socket_path)?;
        }
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let port_count = port_mappings.len();
        let mut config =
            NetworkConfig::new(port_mappings, socket_path.clone()).with_allow_net(allow_net);
        if let Some(live) = secrets {
            config = config.with_secrets(
                live.gvproxy_secrets(),
                live.ca_cert_pem.clone(),
                live.ca_key_pem.clone(),
            );
        }
        let backend = GvproxyBackend::new(config)?;
        let endpoint = backend.endpoint();

        let (path, connection, mac) = match endpoint {
            bux_net::NetworkEndpoint::UnixSocket {
                path,
                connection_type,
                mac_address,
            } => {
                let conn = match connection_type {
                    ConnectionType::UnixStream => ShimNetConn::UnixStream,
                    ConnectionType::UnixDgram => ShimNetConn::UnixDgram,
                    _ => {
                        return Err(crate::Error::InvalidConfig(
                            "unsupported network connection type".into(),
                        ));
                    }
                };
                (path, conn, mac_address)
            }
            _ => {
                return Err(crate::Error::InvalidConfig(
                    "unsupported network endpoint kind".into(),
                ));
            }
        };

        let shim_network = ShimNetwork {
            socket_path: path,
            connection,
            mac,
        };

        self.backends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(vm_id.to_owned(), backend);

        info!(
            vm_id,
            ?socket_path,
            published = port_count,
            "gvproxy backend started"
        );
        Ok(StartNetResult { shim_network })
    }

    /// Stop and drop the backend for `vm_id` (no-op if absent).
    pub(crate) fn stop(&self, vm_id: &str) {
        let removed = self
            .backends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(vm_id);
        if removed.is_some() {
            debug!(vm_id, "gvproxy backend stopped");
        }
        let path = self.socket_path(vm_id);
        if path.exists()
            && let Err(e) = std::fs::remove_file(&path)
        {
            warn!(vm_id, error = %e, path = %path.display(), "failed to remove net socket");
        }
    }

    /// Stop every backend (Runtime shutdown).
    pub(crate) fn stop_all(&self) {
        let ids: Vec<String> = self
            .backends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .cloned()
            .collect();
        for id in ids {
            self.stop(&id);
        }
    }
}
