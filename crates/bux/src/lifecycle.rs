//! Idle auto-stop / auto-delete policies and recovery decision helpers.
//!
//! Policies default **off** (`None`). The sweeper is invoked explicitly via
//! [`crate::Runtime::sweep`] — no background task unless the embedder schedules one.
//!
//! Idle clocks use last-activity timestamps (or create-time when unset).

use std::time::{Duration, SystemTime};

/// Result of evaluating recovery for one VM that was left active in `SQLite`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum RecoverAction {
    /// PID is dead — mark stopped (optionally auto-remove).
    MarkDeadStopped,
    /// PID alive — leave the shim (it owns gvproxy and secrets); vsock reattach only.
    ReattachVsockOnly,
}

/// Decide recovery action for an active-status VM row (unit-testable).
///
/// A live shim owns networking and MITM secrets. Do not SIGTERM it.
#[must_use]
pub(crate) const fn recover_action(pid_alive: bool) -> RecoverAction {
    if pid_alive {
        RecoverAction::ReattachVsockOnly
    } else {
        RecoverAction::MarkDeadStopped
    }
}

/// Whether idle duration has exceeded the policy threshold.
#[must_use]
pub(crate) fn idle_expired(
    now: SystemTime,
    last_activity: Option<SystemTime>,
    created_at: SystemTime,
    policy_secs: Option<u64>,
) -> bool {
    let Some(secs) = policy_secs else {
        return false;
    };
    if secs == 0 {
        return false;
    }
    let anchor = last_activity.unwrap_or(created_at);
    now.duration_since(anchor)
        .unwrap_or(Duration::ZERO)
        .as_secs()
        >= secs
}

/// Report from a single [`crate::Runtime::sweep`] pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SweepReport {
    /// VMs stopped due to `auto_stop_secs`.
    pub stopped: u32,
    /// VMs deleted due to `auto_delete_secs` (or `auto_remove` after stop).
    pub deleted: u32,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn recover_dead() {
        assert_eq!(recover_action(false), RecoverAction::MarkDeadStopped);
    }

    #[test]
    fn recover_live_shim_including_secrets_is_vsock_only() {
        assert_eq!(recover_action(true), RecoverAction::ReattachVsockOnly);
    }

    #[test]
    fn idle_policy_default_off() {
        let now = SystemTime::now();
        assert!(!idle_expired(now, None, now, None));
        assert!(!idle_expired(now, None, now, Some(0)));
    }

    #[test]
    fn idle_expired_after_threshold() {
        let created = epoch_plus(0);
        let last = epoch_plus(10);
        let now = epoch_plus(100);
        assert!(idle_expired(now, Some(last), created, Some(50)));
        assert!(!idle_expired(now, Some(last), created, Some(200)));
    }

    fn epoch_plus(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }
}
