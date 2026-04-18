//! Resource limit configuration for a cgroup.

/// Resource limits applied to a cgroup v2 subtree.
///
/// All fields are optional — unset fields inherit from the parent cgroup
/// and therefore apply no additional limit. Use [`ResourceLimits::builder`]
/// for a fluent construction style, or build the struct literally.
///
/// # Example
///
/// ```
/// use bux_cgroup::ResourceLimits;
///
/// let limits = ResourceLimits::builder()
///     .cpu_cores(2.0)
///     .memory_bytes(512 * 1024 * 1024)
///     .build();
///
/// assert_eq!(limits.cpu_cores, Some(2.0));
/// assert_eq!(limits.memory_bytes, Some(512 * 1024 * 1024));
/// assert_eq!(limits.memory_swap_bytes, None);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[non_exhaustive]
pub struct ResourceLimits {
    /// Maximum CPU bandwidth as a fraction of cores (e.g. `2.0` = 2 cores).
    ///
    /// Translated into `cpu.max` as `"{quota} {period}"` with a fixed
    /// 100 ms period (the kernel default).
    pub cpu_cores: Option<f64>,

    /// Memory limit in bytes. Written to `memory.max`.
    pub memory_bytes: Option<u64>,

    /// Memory + swap limit in bytes. Written to `memory.swap.max`.
    ///
    /// Set equal to `memory_bytes` to effectively disable swap for
    /// processes inside the cgroup.
    pub memory_swap_bytes: Option<u64>,
}

impl ResourceLimits {
    /// Returns a new builder for fluent construction.
    pub const fn builder() -> ResourceLimitsBuilder {
        ResourceLimitsBuilder {
            limits: Self {
                cpu_cores: None,
                memory_bytes: None,
                memory_swap_bytes: None,
            },
        }
    }

    /// Returns `true` if no limits are set (cgroup creation is a no-op).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.cpu_cores.is_none()
            && self.memory_bytes.is_none()
            && self.memory_swap_bytes.is_none()
    }
}

/// Fluent builder for [`ResourceLimits`].
#[derive(Debug, Clone, Copy)]
#[must_use = "builders do nothing unless you call `.build()`"]
pub struct ResourceLimitsBuilder {
    /// Accumulated limits being built.
    limits: ResourceLimits,
}

impl ResourceLimitsBuilder {
    /// Sets the maximum CPU bandwidth in fractional cores.
    pub const fn cpu_cores(mut self, cores: f64) -> Self {
        self.limits.cpu_cores = Some(cores);
        self
    }

    /// Sets the memory limit in bytes.
    pub const fn memory_bytes(mut self, bytes: u64) -> Self {
        self.limits.memory_bytes = Some(bytes);
        self
    }

    /// Sets the memory+swap limit in bytes.
    pub const fn memory_swap_bytes(mut self, bytes: u64) -> Self {
        self.limits.memory_swap_bytes = Some(bytes);
        self
    }

    /// Finalises the builder.
    #[must_use]
    pub const fn build(self) -> ResourceLimits {
        self.limits
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    reason = "tests are allowed to use unwrap and omit docs"
)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        let l = ResourceLimits::default();
        assert!(l.is_empty());
    }

    #[test]
    fn builder_sets_fields() {
        let l = ResourceLimits::builder()
            .cpu_cores(1.5)
            .memory_bytes(256 * 1024 * 1024)
            .memory_swap_bytes(256 * 1024 * 1024)
            .build();
        assert_eq!(l.cpu_cores, Some(1.5));
        assert_eq!(l.memory_bytes, Some(256 * 1024 * 1024));
        assert_eq!(l.memory_swap_bytes, Some(256 * 1024 * 1024));
        assert!(!l.is_empty());
    }

    #[test]
    fn is_empty_detects_any_set_field() {
        assert!(!ResourceLimits::builder().cpu_cores(1.0).build().is_empty());
        assert!(
            !ResourceLimits::builder()
                .memory_bytes(1)
                .build()
                .is_empty()
        );
        assert!(
            !ResourceLimits::builder()
                .memory_swap_bytes(1)
                .build()
                .is_empty()
        );
    }
}
