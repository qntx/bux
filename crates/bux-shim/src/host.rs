//! Host probes that wrap libkrun. The shim crate is the only product
//! crate that links libkrun; embedders query through this module.

#[cfg(unix)]
pub use bux_krun::{Feature, KernelFormat, LogStyle, SyncMode};

#[cfg(unix)]
use crate::Result;

/// Maximum vCPUs supported by the hypervisor.
///
/// # Errors
///
/// Returns [`crate::Error::Krun`] if libkrun rejects the query.
#[cfg(unix)]
pub fn max_vcpus() -> Result<u32> {
    Ok(bux_krun::ctx::get_max_vcpus()?)
}

/// Whether this libkrun build includes `feature`.
///
/// # Errors
///
/// Returns [`crate::Error::Krun`] if libkrun rejects the query.
#[cfg(unix)]
pub fn has_feature(feature: Feature) -> Result<bool> {
    Ok(bux_krun::ctx::has_feature(feature)?)
}

/// Nested virtualization support (macOS HVF / Linux nested KVM).
///
/// # Errors
///
/// Returns [`crate::Error::Krun`] if the probe fails.
#[cfg(unix)]
pub fn check_nested_virt() -> Result<bool> {
    Ok(bux_krun::ctx::check_nested_virt()?)
}
