//! Phase A workload process defaults (env / workdir / user) for managed exec.
//!
//! Workload identity is stored on [`crate::state::VmConfig`] and applied when
//! the caller omits overrides on [`bux_proto::ExecStart`].

use bux_oci::ImageConfig;
use bux_proto::ExecStart;

/// Human-readable Phase A security limits (surfaced on VM info / inspect).
pub(crate) const PHASE_A_LIMITS: &str = "Phase A: workload processes share the guest rootfs and kernel \
namespaces with the agent; concurrent execs are not mutually isolated; compromise of a workload \
is compromise of the agent filesystem. Hardware boundary vs host still holds.";

/// Merge environment lists as `KEY=VALUE`. Later entries override earlier keys.
#[must_use]
pub(crate) fn merge_env(base: &[String], overrides: &[String]) -> Vec<String> {
    let mut map = std::collections::HashMap::<String, String>::new();
    let mut order = Vec::<String>::new();
    for entry in base.iter().chain(overrides.iter()) {
        let Some((k, v)) = entry.split_once('=') else {
            continue;
        };
        if map.insert(k.to_owned(), v.to_owned()).is_none() {
            order.push(k.to_owned());
        }
    }
    order
        .into_iter()
        .filter_map(|k| map.remove(&k).map(|v| format!("{k}={v}")))
        .collect()
}

/// Parse purely numeric `uid` or `uid:gid`. Returns `None` for name-based specs.
#[must_use]
pub(crate) fn parse_numeric_user(spec: &str) -> Option<(u32, u32)> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    if let Some((u, g)) = spec.split_once(':') {
        let uid = u.trim().parse().ok()?;
        let gid = g.trim().parse().ok()?;
        return Some((uid, gid));
    }
    let uid = spec.parse().ok()?;
    Some((uid, uid))
}

/// Fold OCI image process config into workload fields (product opts win).
pub(crate) fn merge_image_config(
    workload_env: &mut Vec<String>,
    workload_workdir: &mut Option<String>,
    workload_user: &mut Option<String>,
    workload_cmd: &mut Option<Vec<String>>,
    img: &ImageConfig,
) {
    if let Some(ref e) = img.env
        && !e.is_empty()
    {
        *workload_env = if workload_env.is_empty() {
            e.clone()
        } else {
            merge_env(e, workload_env)
        };
    }
    if workload_workdir.is_none() {
        *workload_workdir = img.working_dir.clone().filter(|w| !w.is_empty());
    }
    if workload_user.is_none() {
        *workload_user = img.user.clone().filter(|u| !u.is_empty());
    }
    if workload_cmd.as_ref().is_none_or(Vec::is_empty) {
        let cmd = img.command();
        if !cmd.is_empty() {
            *workload_cmd = Some(cmd);
        }
    }
}

/// Apply stored workload defaults to an exec request when the caller omitted them.
#[must_use]
pub(crate) fn apply_workload_defaults(
    mut req: ExecStart,
    workload_env: &[String],
    workload_workdir: Option<&str>,
    workload_user: Option<&str>,
) -> ExecStart {
    if req.env.is_empty() {
        if !workload_env.is_empty() {
            req.env = workload_env.to_vec();
        }
    } else if !workload_env.is_empty() {
        req.env = merge_env(workload_env, &req.env);
    }

    if req.cwd.is_none()
        && let Some(wd) = workload_workdir.filter(|w| !w.is_empty())
    {
        req.cwd = Some(wd.to_owned());
    }

    let needs_user = req.uid.is_none() && req.gid.is_none() && req.user.is_none();
    if needs_user && let Some(spec) = workload_user.filter(|u| !u.is_empty()) {
        if let Some((uid, gid)) = parse_numeric_user(spec) {
            req = req.user(uid, gid);
        } else {
            req = req.user_name(spec);
        }
    }

    req
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn merge_env_overrides_by_key() {
        let base = vec!["A=1".into(), "B=2".into(), "PATH=/bin".into()];
        let over = vec!["B=9".into(), "C=3".into()];
        let m = merge_env(&base, &over);
        assert!(m.contains(&"A=1".into()));
        assert!(m.contains(&"B=9".into()));
        assert!(m.contains(&"C=3".into()));
        assert!(m.contains(&"PATH=/bin".into()));
        assert!(!m.iter().any(|e| e == "B=2"));
    }

    #[test]
    fn parse_numeric_user_variants() {
        assert_eq!(parse_numeric_user("1000"), Some((1000, 1000)));
        assert_eq!(parse_numeric_user("1000:100"), Some((1000, 100)));
        assert_eq!(parse_numeric_user("nobody"), None);
        assert_eq!(parse_numeric_user("root:wheel"), None);
        assert_eq!(parse_numeric_user(""), None);
    }

    #[test]
    fn apply_defaults_fill_gaps() {
        let req = apply_workload_defaults(
            ExecStart::new("echo"),
            &["A=1".into()],
            Some("/work"),
            Some("1000:1000"),
        );
        assert_eq!(req.env, vec!["A=1"]);
        assert_eq!(req.cwd.as_deref(), Some("/work"));
        assert_eq!(req.uid, Some(1000));
        assert_eq!(req.gid, Some(1000));
    }

    #[test]
    fn apply_defaults_name_user() {
        let req = apply_workload_defaults(ExecStart::new("id"), &[], None, Some("nobody"));
        assert_eq!(req.user.as_deref(), Some("nobody"));
        assert!(req.uid.is_none());
    }

    #[test]
    fn apply_defaults_caller_wins() {
        let req = apply_workload_defaults(
            ExecStart::new("echo")
                .env(vec!["A=override".into()])
                .cwd("/tmp")
                .user(0, 0),
            &["A=1".into(), "B=2".into()],
            Some("/work"),
            Some("1000"),
        );
        assert!(req.env.iter().any(|e| e == "A=override"));
        assert!(req.env.iter().any(|e| e == "B=2"));
        assert_eq!(req.cwd.as_deref(), Some("/tmp"));
        assert_eq!(req.uid, Some(0));
    }

    #[test]
    fn merge_image_fills_empty_workload() {
        let img: ImageConfig =
            serde_json::from_str(r#"{"Env":["PATH=/usr/bin"],"WorkingDir":"/app","User":"1000"}"#)
                .unwrap();
        let mut env = vec!["EXTRA=1".into()];
        let mut wd = None;
        let mut user = None;
        let mut cmd = None;
        merge_image_config(&mut env, &mut wd, &mut user, &mut cmd, &img);
        assert!(env.iter().any(|e| e == "PATH=/usr/bin"));
        assert!(env.iter().any(|e| e == "EXTRA=1"));
        assert_eq!(wd.as_deref(), Some("/app"));
        assert_eq!(user.as_deref(), Some("1000"));
    }
}
