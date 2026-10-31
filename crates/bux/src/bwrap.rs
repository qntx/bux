//! Choosing the `bwrap` the Linux jailer runs.
//!
//! The system's `bwrap` comes first: `AppArmor` profiles attach by path, so a
//! distro's policy can only cover that binary. The bundled one, whose path is
//! user-writable and changes with each version, serves hosts without bubblewrap.
//!
//! Each candidate is run before it is used, because only that shows it works here.

use std::fs;
use std::path::{Path, PathBuf};

/// Where the Ubuntu steps are explained.
const DOCS: &str = "https://github.com/qntx/bux/blob/main/crates/bux/README.md#linux-jailer";

/// Upstream `AppArmor`'s optional profile, the file Ubuntu 25.04 and 25.10 enable.
const PROFILE_URL: &str = "https://gitlab.com/apparmor/apparmor/-/raw/v4.1.0/profiles/apparmor/profiles/extras/bwrap-userns-restrict";
/// SHA-256 of [`PROFILE_URL`].
const PROFILE_SHA256: &str = "634d3d3427c483f123cb5ed53b71ea13040187e07d9f67ca74421d42a6170f0e";
/// Where Ubuntu keeps the profile. Using the same path leaves one profile after
/// an upgrade to a release that ships it.
const PROFILE_PATH: &str = "/etc/apparmor.d/bwrap-userns-restrict";

/// The only path Ubuntu's profile attaches to.
const SYSTEM_BWRAP: &str = "/usr/bin/bwrap";

/// The first `bwrap` that works here: on `$PATH`, then the bundled one.
///
/// # Errors
///
/// Returns what to tell the operator: why none works and what to do.
pub(crate) fn select() -> Result<PathBuf, String> {
    let candidates = candidates();
    if candidates.is_empty() {
        return Err(bux_jail::Error::BwrapUnavailable.to_string());
    }
    let mut lines =
        vec!["jailer unavailable: no bwrap on this host can start a sandbox".to_owned()];
    for bwrap in candidates {
        match bux_jail::probe_bwrap(&bwrap) {
            Ok(()) => return Ok(bwrap),
            Err(e) => lines.push(format!("  {}: {e}", bwrap.display())),
        }
    }
    lines.extend(advice(Host::read()));
    Err(lines.join("\n"))
}

/// Each `bwrap` on `$PATH`, then the bundled ones, without duplicates.
///
/// Relative `$PATH` entries are skipped: the jailer must not depend on the
/// current directory.
fn candidates() -> Vec<PathBuf> {
    let on_path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path)
                .filter(|dir| dir.is_absolute())
                .map(|dir| dir.join("bwrap"))
                .collect()
        })
        .unwrap_or_default();
    let mut candidates = Vec::new();
    for path in on_path.into_iter().chain(crate::payload::bundled_bwrap()) {
        if let Ok(real) = fs::canonicalize(path)
            && real.is_file()
            && !candidates.contains(&real)
        {
            candidates.push(real);
        }
    }
    candidates
}

/// Make a fake `bwrap` at `path` that runs `body`.
///
/// A child creates the file. `exec` fails with `ETXTBSY` while any process holds
/// the file open for writing, and a test forking in parallel inherits this
/// process's descriptors.
#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test helper")]
pub(crate) fn fake_bwrap(path: &Path, body: &str) {
    let status = std::process::Command::new("/bin/sh")
        .args([
            "-c",
            r#"rm -f "$0" && printf %s "$1" > "$0" && chmod 755 "$0""#,
        ])
        .arg(path)
        .arg(format!("#!/bin/sh\n{body}\n"))
        .env("PATH", "/usr/bin:/bin")
        .status()
        .unwrap();
    assert!(status.success());
}

/// What decides the advice for a host where no `bwrap` works.
#[derive(Debug, Clone, Copy)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent facts about the host"
)]
struct Host {
    /// `kernel.apparmor_restrict_unprivileged_userns=1`.
    apparmor_restricts_userns: bool,
    /// [`SYSTEM_BWRAP`] exists.
    system_bwrap: bool,
    /// [`PROFILE_PATH`] exists: Ubuntu 25.04 and later ship it.
    profile_installed: bool,
    /// `kernel.unprivileged_userns_clone=0`.
    userns_clone_off: bool,
    /// `user.max_user_namespaces=0`.
    max_userns_zero: bool,
}

impl Host {
    /// Read the host's sysctls and files.
    fn read() -> Self {
        let sysctl_is = |path: &str, value: &str| {
            fs::read_to_string(path).is_ok_and(|content| content.trim() == value)
        };
        Self {
            apparmor_restricts_userns: sysctl_is(
                "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
                "1",
            ),
            system_bwrap: Path::new(SYSTEM_BWRAP).is_file(),
            profile_installed: Path::new(PROFILE_PATH).is_file(),
            userns_clone_off: sysctl_is("/proc/sys/kernel/unprivileged_userns_clone", "0"),
            max_userns_zero: sysctl_is("/proc/sys/user/max_user_namespaces", "0"),
        }
    }
}

/// Why `bwrap` fails on `host` and what the operator can do, line by line.
///
/// bux never does this itself: system security policy is the administrator's
/// decision, and bux's own binaries live in a user-writable directory.
fn advice(host: Host) -> Vec<String> {
    let mut lines = Vec::new();
    if host.apparmor_restricts_userns {
        lines.push(
            "AppArmor lets a process create a user namespace only under a profile that allows it"
                .to_owned(),
        );
        lines.push("(kernel.apparmor_restrict_unprivileged_userns=1).".to_owned());
        if !host.system_bwrap {
            lines.push("Install the system's bwrap: sudo apt install bubblewrap".to_owned());
        }
        if !host.profile_installed {
            lines.push(format!(
                "Ubuntu 25.04 and later ship a profile for {SYSTEM_BWRAP}. To install it on this release (once, needs sudo):"
            ));
            lines.push(format!("  curl -fsSLO {PROFILE_URL} &&"));
            lines.push(format!(
                "  echo \"{PROFILE_SHA256}  bwrap-userns-restrict\" | sha256sum -c &&"
            ));
            lines.push(
                "  sudo install -m 0644 bwrap-userns-restrict /etc/apparmor.d/ &&".to_owned(),
            );
            lines.push(format!("  sudo apparmor_parser -r {PROFILE_PATH}"));
        } else if host.system_bwrap {
            lines.push(format!(
                "{PROFILE_PATH} is installed but does not apply: it is not loaded, or another"
            ));
            lines.push(format!(
                "profile also attaches to {SYSTEM_BWRAP}, and then neither applies."
            ));
            lines.push("  sudo aa-status | grep bwrap".to_owned());
            lines.push(format!("  sudo apparmor_parser -r {PROFILE_PATH}"));
        }
    } else if host.userns_clone_off {
        lines.push(
            "Unprivileged user namespaces are off (kernel.unprivileged_userns_clone=0).".to_owned(),
        );
    } else if host.max_userns_zero {
        lines.push("User namespaces are off (user.max_user_namespaces=0).".to_owned());
    }
    lines.push(format!("See {DOCS}"));
    lines.push("Or run without the jailer, and without its namespaces: --no-jailer".to_owned());
    lines
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests")]
mod tests {
    use super::*;
    use crate::guest::sidecar_env;

    const HOST: Host = Host {
        apparmor_restricts_userns: true,
        system_bwrap: true,
        profile_installed: false,
        userns_clone_off: false,
        max_userns_zero: false,
    };

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive select"
    )]
    fn prefers_path_over_the_bundled_bwrap() {
        let mut env = sidecar_env::lock();
        let dir = tempfile::tempdir().unwrap();
        let on_path = dir.path().join("bwrap");
        fake_bwrap(&on_path, "exit 0");
        env.set("PATH", dir.path());
        let bundled = sidecar_env::Planted::sibling("bwrap", b"");
        fake_bwrap(bundled.path(), "exit 0");

        assert_eq!(select().unwrap(), fs::canonicalize(&on_path).unwrap());
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive select"
    )]
    fn ignores_relative_path_entries() {
        let mut env = sidecar_env::lock();
        env.set("PATH", "relative-dir::.");
        assert!(
            candidates()
                .iter()
                .all(|path| crate::payload::bundled_bwrap().contains(path)),
            "{:?}",
            candidates()
        );
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive select"
    )]
    fn falls_back_when_the_one_on_path_fails() {
        let mut env = sidecar_env::lock();
        let dir = tempfile::tempdir().unwrap();
        fake_bwrap(&dir.path().join("bwrap"), "echo denied >&2; exit 1");
        env.set("PATH", dir.path());
        let bundled = sidecar_env::Planted::sibling("bwrap", b"");
        fake_bwrap(bundled.path(), "exit 0");

        assert_eq!(select().unwrap(), fs::canonicalize(bundled.path()).unwrap());
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive select"
    )]
    fn reports_each_failure() {
        let mut env = sidecar_env::lock();
        let dir = tempfile::tempdir().unwrap();
        let on_path = dir.path().join("bwrap");
        fake_bwrap(&on_path, "echo denied-on-path >&2; exit 1");
        env.set("PATH", dir.path());
        let bundled = sidecar_env::Planted::sibling("bwrap", b"");
        fake_bwrap(bundled.path(), "echo denied-bundled >&2; exit 1");

        let err = select().unwrap_err();
        assert!(err.starts_with("jailer unavailable"), "{err}");
        assert!(
            err.contains(&format!(
                "{}: denied-on-path",
                fs::canonicalize(&on_path).unwrap().display()
            )),
            "{err}"
        );
        assert!(err.contains("denied-bundled"), "{err}");
        assert!(err.contains("--no-jailer"), "{err}");
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive select"
    )]
    fn no_candidate_says_how_to_install() {
        let mut env = sidecar_env::lock();
        let dir = tempfile::tempdir().unwrap();
        env.set("PATH", dir.path());
        drop(fs::remove_file(
            crate::util::sidecar_path(&std::env::current_exe().unwrap(), "bwrap").unwrap(),
        ));
        if !crate::payload::bundled_bwrap().is_empty() {
            return;
        }
        assert_eq!(
            select().unwrap_err(),
            bux_jail::Error::BwrapUnavailable.to_string()
        );
    }

    #[test]
    fn advice_for_a_host_without_the_profile_installs_it() {
        let advice = advice(HOST).join("\n");
        assert!(advice.contains("apparmor_restrict_unprivileged_userns=1"));
        assert!(advice.contains(PROFILE_URL));
        assert!(advice.contains(PROFILE_SHA256));
        assert!(advice.contains("sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict"));
        assert!(!advice.contains("apt install"), "{advice}");
        assert!(advice.contains("--no-jailer"));
    }

    #[test]
    fn the_profile_install_stops_at_the_first_failing_step() {
        let steps: Vec<_> = advice(HOST)
            .into_iter()
            .skip_while(|line| !line.contains("curl -fsSLO"))
            .take_while(|line| !line.contains("apparmor_parser -r"))
            .collect();
        assert_eq!(steps.len(), 3, "{steps:?}");
        assert!(steps.iter().all(|line| line.ends_with(" &&")), "{steps:?}");
    }

    #[test]
    fn advice_for_a_host_without_bubblewrap_installs_it() {
        let shipped_profile = advice(Host {
            system_bwrap: false,
            profile_installed: true,
            ..HOST
        })
        .join("\n");
        assert!(shipped_profile.contains("sudo apt install bubblewrap"));
        assert!(!shipped_profile.contains(PROFILE_URL), "{shipped_profile}");
        assert!(
            !shipped_profile.contains("does not apply"),
            "{shipped_profile}"
        );

        let no_profile = advice(Host {
            system_bwrap: false,
            ..HOST
        })
        .join("\n");
        assert!(no_profile.contains("sudo apt install bubblewrap"));
        assert!(no_profile.contains(PROFILE_URL));
    }

    #[test]
    fn advice_for_a_profile_that_does_not_apply_names_the_conflict() {
        let advice = advice(Host {
            profile_installed: true,
            ..HOST
        })
        .join("\n");
        assert!(advice.contains("is not loaded, or another"), "{advice}");
        assert!(!advice.contains(PROFILE_URL), "{advice}");
        assert!(!advice.contains("apt install"), "{advice}");
    }

    #[test]
    fn advice_names_the_other_sysctls() {
        let quiet = Host {
            apparmor_restricts_userns: false,
            ..HOST
        };
        assert!(
            advice(Host {
                userns_clone_off: true,
                ..quiet
            })
            .join("\n")
            .contains("kernel.unprivileged_userns_clone=0")
        );
        assert!(
            advice(Host {
                max_userns_zero: true,
                ..quiet
            })
            .join("\n")
            .contains("user.max_user_namespaces=0")
        );
        let plain = advice(quiet).join("\n");
        assert!(!plain.contains("AppArmor"), "{plain}");
        assert!(plain.contains("--no-jailer"), "{plain}");
    }
}
