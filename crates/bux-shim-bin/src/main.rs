//! `bux-shim` process: read `ShimConfig` JSON, optionally start gvproxy, enter the VM.
//!
//! Parent writes [`bux_shim::ShimConfig`] JSON and execs:
//! `bux-shim <config.json>`.

#![allow(clippy::print_stderr, reason = "shim reports errors via stderr")]
#![allow(
    clippy::disallowed_methods,
    clippy::exit,
    reason = "shim binary uses process::exit"
)]
#![allow(
    unused_crate_dependencies,
    reason = "unix-only product; stub main on other targets"
)]

#[cfg(not(unix))]
fn main() {
    eprintln!("[bux-shim] only supported on Unix");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() {
    let Some(config_path) = std::env::args().nth(1) else {
        eprintln!("[bux-shim] usage: bux-shim <config.json>");
        std::process::exit(1);
    };

    let exit_path = std::path::Path::new(&config_path).with_extension("exit");
    bux_shim::install_crash_capture(&exit_path);
    bux_shim::start_watchdog_thread();

    let json = match std::fs::read(&config_path) {
        Ok(j) => {
            drop(std::fs::remove_file(&config_path));
            j
        }
        Err(e) => {
            bux_shim::write_exit_error(&exit_path, &format!("failed to read config: {e}"));
            std::process::exit(1);
        }
    };

    let config = match bux_shim::ShimConfig::from_json(&json) {
        Ok(c) => c,
        Err(e) => {
            bux_shim::write_exit_error(&exit_path, &format!("invalid config JSON: {e}"));
            std::process::exit(1);
        }
    };

    match run(&config) {
        Ok(()) => unreachable!("krun_start_enter returned"),
        Err(e) => {
            bux_shim::write_exit_error(&exit_path, &format!("VM start failed: {e}"));
            std::process::exit(1);
        }
    }
}

/// Start optional gvproxy, prepare libkrun, seccomp when offline, then enter.
#[cfg(unix)]
fn run(cfg: &bux_shim::ShimConfig) -> Result<(), String> {
    let gvp = start_gvproxy(cfg)?;
    let prepared = bux_shim::prepare(cfg).map_err(|e| e.to_string())?;
    if gvp.is_none() {
        bux_shim::install_seccomp().map_err(|e| e.to_string())?;
    }
    let start_result = prepared.start();
    drop(gvp);
    start_result.map_err(|e| e.to_string())
}

/// Own gvproxy in this process. Never constructed inside [`bux_shim::prepare`].
#[cfg(unix)]
fn start_gvproxy(
    cfg: &bux_shim::ShimConfig,
) -> Result<Option<bux_gvproxy::GvproxyInstance>, String> {
    match (&cfg.network, &cfg.gvproxy) {
        (Some(net), Some(g)) => {
            let instance = bux_gvproxy::GvproxyInstance::new(&gvproxy_config(net, g))
                .map_err(|e| e.to_string())?;
            Ok(Some(instance))
        }
        (None, None) => Ok(None),
        _ => Err("gvproxy and network must both be set or both absent".into()),
    }
}

/// Map shim JSON types onto the Go-side config (binary crate only).
#[cfg(unix)]
fn gvproxy_config(
    net: &bux_shim::ShimNetwork,
    g: &bux_shim::ShimGvproxy,
) -> bux_gvproxy::GvproxyConfig {
    let mut c = bux_gvproxy::GvproxyConfig::new(net.socket_path.clone(), g.port_mappings.clone())
        .with_allow_net(g.allow_net.clone());
    if !g.secrets.is_empty() {
        c = c.with_secrets(
            g.secrets
                .iter()
                .map(|s| bux_gvproxy::SecretConfig {
                    name: s.name.clone(),
                    hosts: s.hosts.clone(),
                    placeholder: s.placeholder.clone(),
                    value: s.value.clone(),
                })
                .collect(),
            g.ca_cert_pem.clone(),
            g.ca_key_pem.clone(),
        );
    }
    c
}

#[cfg(test)]
#[cfg(unix)]
#[allow(clippy::unwrap_used, reason = "unit tests")]
mod tests {
    use super::start_gvproxy;
    use bux_shim::{ShimConfig, ShimDiskFormat, ShimGvproxy, ShimNetConn, ShimNetwork};
    use std::path::PathBuf;

    fn base_cfg() -> ShimConfig {
        ShimConfig {
            vm_id: String::new(),
            vcpus: 1,
            ram_mib: 256,
            rootfs: Some("/rootfs".into()),
            root_disk: None,
            disk_format: ShimDiskFormat::Raw,
            virtiofs: vec![],
            vsock_ports: vec![],
            network: None,
            gvproxy: None,
            log_level: None,
            exec_path: None,
            exec_args: vec![],
            env: None,
            workdir: None,
            uid: None,
            gid: None,
            rlimits: vec![],
            nested_virt: None,
            snd_device: None,
            console_output: None,
        }
    }

    #[test]
    fn xor_network_without_gvproxy_is_invalid() {
        let mut cfg = base_cfg();
        cfg.network = Some(ShimNetwork {
            socket_path: PathBuf::from("/tmp/net.sock"),
            connection: ShimNetConn::UnixStream,
            mac: [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee],
        });
        let err = start_gvproxy(&cfg).unwrap_err();
        assert!(err.contains("both"), "{err}");
    }

    #[test]
    fn xor_gvproxy_without_network_is_invalid() {
        let mut cfg = base_cfg();
        cfg.gvproxy = Some(ShimGvproxy {
            port_mappings: vec![],
            allow_net: vec![],
            secrets: vec![],
            ca_cert_pem: String::new(),
            ca_key_pem: String::new(),
        });
        let err = start_gvproxy(&cfg).unwrap_err();
        assert!(err.contains("both"), "{err}");
    }

    #[test]
    fn both_none_skips_gvproxy() {
        let cfg = base_cfg();
        assert!(start_gvproxy(&cfg).unwrap().is_none());
    }
}
