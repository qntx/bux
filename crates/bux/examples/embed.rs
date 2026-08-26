//! Embedder compile gate: `Runtime::open_with` → `create` → `exec_output` → `stop`.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    missing_docs,
    unused_crate_dependencies,
    reason = "example binary inherits package deps"
)]

use bux::{ExecStart, RegistryAuth, Runtime, RuntimeOptions, VmOptions};

#[tokio::main(flavor = "current_thread")]
async fn main() -> bux::Result<()> {
    let rt = Runtime::open_with(RuntimeOptions {
        data_dir: std::env::temp_dir().join("bux-embed-example"),
        shim_path: std::env::var_os("BUX_SHIM_PATH").map(Into::into),
        guest_path: std::env::var_os("BUX_GUEST_PATH").map(Into::into),
        registry_auth: RegistryAuth::Anonymous,
    })?;
    let mut vm = rt
        .create(VmOptions::from_image("python:slim").vcpus(2).ram_mib(1024))
        .await?;
    let out = vm
        .exec_output(ExecStart::new("python").args(vec!["-c".into(), "print(1)".into()]))
        .await?;
    assert_eq!(out.code, 0, "python -c print");
    vm.stop().await?;
    Ok(())
}
