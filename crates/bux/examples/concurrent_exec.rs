//! R8: 16 concurrent `exec_output` on one `Runtime` / one `Vm`.
//!
//! Sixteen `bux exec` CLI processes cannot do this: each `Runtime::open`
//! takes exclusive `bux.lock` (R5).

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::print_stderr,
    unused_crate_dependencies,
    missing_docs,
    reason = "example binary inherits package deps"
)]

use std::sync::Arc;

use bux::{ExecStart, RegistryAuth, Runtime, RuntimeOptions};
use tokio::task::JoinSet;

const TASKS: usize = 16;

#[tokio::main(flavor = "current_thread")]
async fn main() -> bux::Result<()> {
    let Some(target) = std::env::args().nth(1) else {
        return Err(bux::Error::InvalidConfig(
            "usage: concurrent_exec <vm-id-or-name>".into(),
        ));
    };
    let rt = Runtime::open_with(RuntimeOptions {
        data_dir: bux::default_data_dir(),
        shim_path: std::env::var_os("BUX_SHIM_PATH").map(Into::into),
        guest_path: std::env::var_os("BUX_GUEST_PATH").map(Into::into),
        registry_auth: RegistryAuth::Anonymous,
    })?;
    let vm = Arc::new(rt.get(&target)?);
    let mut set = JoinSet::new();
    for _ in 0..TASKS {
        let vm = Arc::clone(&vm);
        set.spawn(async move {
            vm.exec_output(ExecStart::new("echo").args(vec!["ok".into()]))
                .await
        });
    }
    let mut failed = 0usize;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(out)) if out.code == 0 => {}
            Ok(Ok(out)) => {
                eprintln!("concurrent_exec: echo ok exit {}", out.code);
                failed += 1;
            }
            Ok(Err(err)) => {
                eprintln!("concurrent_exec: {err}");
                failed += 1;
            }
            Err(err) => {
                eprintln!("concurrent_exec: join {err}");
                failed += 1;
            }
        }
    }
    if failed != 0 {
        return Err(bux::Error::InvalidState(format!(
            "{failed} of {TASKS} concurrent exec_output failed"
        )));
    }
    Ok(())
}
