//! `bux system info` stays flock-free; `bux stats --runtime` takes `bux.lock`.

#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    missing_docs,
    reason = "binary integration test"
)]
#![cfg(unix)]

use std::process::Command;

const RUNTIME_METRIC_KEYS: [&str; 5] = [
    "vms_created_total",
    "num_running_vms",
    "vms_failed_total",
    "total_uptime_ms",
    "disk_bytes_used",
];

#[test]
fn system_info_is_flock_free_stats_runtime_takes_lock() {
    let home = tempfile::tempdir().expect("tempdir");
    let bin = env!("CARGO_BIN_EXE_bux");

    {
        let _held = bux::Runtime::open(home.path()).expect("hold flock");

        let info = Command::new(bin)
            .args(["system", "info", "--format", "json"])
            .env("BUX_HOME", home.path())
            .output()
            .expect("system info");
        assert!(
            info.status.success(),
            "system info must not call Runtime::open: {}",
            String::from_utf8_lossy(&info.stderr)
        );
        let info_json: serde_json::Value =
            serde_json::from_slice(&info.stdout).expect("system info json");
        let info_obj = info_json.as_object().expect("system info object");
        assert!(
            info_obj.contains_key("host")
                && info_obj.contains_key("data_dir")
                && info_obj.contains_key("payload_dir"),
            "system info shape: {info_obj:?}"
        );
        let env = info_obj
            .get("env")
            .and_then(serde_json::Value::as_object)
            .expect("system info env");
        for banned in ["BUX_SHIM_PATH", "BUX_GUEST_PATH", "BUX_GUEST_DIR"] {
            assert!(
                !env.contains_key(banned),
                "system info must not document {banned}: {env:?}"
            );
        }
        for required in ["BUX_HOME", "BUX_LISTEN", "BUX_API_KEYS"] {
            assert!(env.contains_key(required), "missing {required} in {env:?}");
        }
        for key in RUNTIME_METRIC_KEYS {
            assert!(
                !info_obj.contains_key(key),
                "system info must not dump RuntimeMetrics key {key}"
            );
        }

        let busy = Command::new(bin)
            .args(["stats", "--runtime"])
            .env("BUX_HOME", home.path())
            .output()
            .expect("stats --runtime while locked");
        assert!(
            !busy.status.success(),
            "stats --runtime must take the flock"
        );
        let err = String::from_utf8_lossy(&busy.stderr);
        assert!(
            err.contains("another bux runtime"),
            "expected Busy, got: {err}"
        );
    }

    let ok = Command::new(bin)
        .args(["stats", "--runtime"])
        .env("BUX_HOME", home.path())
        .output()
        .expect("stats --runtime after unlock");
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let stats: serde_json::Value = serde_json::from_slice(&ok.stdout).expect("stats json");
    let obj = stats.as_object().expect("stats object");
    assert_eq!(
        obj.len(),
        RUNTIME_METRIC_KEYS.len(),
        "runtime JSON must be getter keys only: {obj:?}"
    );
    for key in RUNTIME_METRIC_KEYS {
        assert!(obj.contains_key(key), "missing {key} in {obj:?}");
    }
}
