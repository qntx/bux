//! Embed snippet matching `crates/bux/src/lib.rs`
//! (`Runtime::open` → `create` → `exec_output` → `stop`).

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    missing_docs,
    unused_crate_dependencies,
    reason = "example binary inherits package deps"
)]

use bux::{ExecStart, Runtime, VmOptions};

#[tokio::main(flavor = "current_thread")]
async fn main() -> bux::Result<()> {
    let rt = Runtime::open(bux::default_data_dir())?;
    let mut vm = rt
        .create(VmOptions::from_image("python:slim").vcpus(2).ram_mib(1024))
        .await?;

    vm.exec_output(ExecStart::new("python").args(vec!["-c".into(), "print(1)".into()]))
        .await?;
    vm.stop().await?;
    Ok(())
}
