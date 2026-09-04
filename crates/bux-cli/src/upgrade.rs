//! Self-upgrade via `https://sh.qntx.org/bux` (`bux upgrade` / `bux update`).
//!
//! Latest product tag is the first non-draft, non-prerelease `^v[0-9]` GitHub
//! Release on the paginated list. GitHub's "latest" pointer is a guest-* tag
//! on this repo. Cargo-installed binaries are not overwritten.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use clap::Args;

/// Unix installer served verbatim by the sh.qntx.org Worker.
const INSTALL_SH_URL: &str = "https://sh.qntx.org/bux";
const REPO: &str = "qntx/bux";

/// Arguments for `bux upgrade` / `bux update`.
#[derive(Args, Debug, Clone, Copy)]
pub struct UpgradeArgs {
    /// Only report whether a newer release is available; do not install.
    #[arg(long)]
    pub check: bool,

    /// Re-run the installer even when already on the latest version.
    #[arg(long)]
    pub force: bool,
}

impl UpgradeArgs {
    /// Compare this binary to the latest product tag and maybe reinstall.
    pub fn run(self) -> Result<()> {
        self.run_with(
            http_get,
            || std::env::current_exe().context("failed to resolve current executable"),
            run_official_installer,
        )
    }

    fn run_with(
        self,
        get: impl FnMut(&str) -> Result<String>,
        exe: impl FnOnce() -> Result<PathBuf>,
        install: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let current = env!("CARGO_PKG_VERSION");
        let latest = fetch_latest_version(get)?;
        let update_available = is_newer(&latest, current);

        if self.check {
            if update_available {
                println!("bux {latest} is available (current {current})");
            } else {
                println!("bux {current} is up to date");
            }
            return Ok(());
        }

        if !update_available && !self.force {
            println!("bux {current} is already the latest version");
            return Ok(());
        }

        if is_cargo_install_path(&exe()?) {
            eprintln!("this binary looks cargo-installed; run: cargo install bux-cli --force");
            return Ok(());
        }

        if update_available {
            println!("Updating bux {current} → {latest} via {INSTALL_SH_URL} …");
        } else {
            println!("Reinstalling bux {current} via installer (--force) …");
        }

        install()?;
        println!("installer finished; run `bux --version` to confirm (target {latest})");
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PageHit {
    Version(String),
    Continue,
    Exhausted,
}

fn releases_url(page: u32) -> String {
    format!("https://api.github.com/repos/{REPO}/releases?per_page=100&page={page}")
}

fn installer_shell() -> String {
    format!("curl -fsSL {INSTALL_SH_URL} | sh")
}

fn fetch_latest_version(mut get: impl FnMut(&str) -> Result<String>) -> Result<String> {
    let mut page = 1_u32;
    loop {
        match parse_product_page(&get(&releases_url(page))?)? {
            PageHit::Version(ver) => return Ok(ver),
            PageHit::Continue => {
                page = page
                    .checked_add(1)
                    .context("GitHub releases page overflow")?;
            }
            PageHit::Exhausted => {
                anyhow::bail!("no product release found (tag matching ^v[0-9])");
            }
        }
    }
}

/// Same predicates as `install.sh` `parse_product_tag`.
fn parse_product_page(body: &str) -> Result<PageHit> {
    let value: serde_json::Value =
        serde_json::from_str(body).context("failed to parse GitHub releases JSON")?;
    let Some(page) = value.as_array() else {
        anyhow::bail!("GitHub releases page must be a JSON array");
    };
    if page.is_empty() {
        return Ok(PageHit::Exhausted);
    }
    for release in page {
        if json_bool(release, "draft") || json_bool(release, "prerelease") {
            continue;
        }
        let tag = release
            .get("tag_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if let Some(ver) = product_version(tag) {
            return Ok(PageHit::Version(ver.to_owned()));
        }
    }
    Ok(PageHit::Continue)
}

fn json_bool(value: &serde_json::Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn product_version(tag: &str) -> Option<&str> {
    let rest = tag.strip_prefix('v')?;
    rest.as_bytes()
        .first()
        .is_some_and(u8::is_ascii_digit)
        .then_some(rest)
}

fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_semver(latest), parse_semver(current)) {
        (Some(latest), Some(current)) => latest > current,
        _ => latest != current,
    }
}

fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn http_get(url: &str) -> Result<String> {
    if command_exists("curl") {
        let out = Command::new("curl")
            .args([
                "-fsSL",
                "-A",
                "bux-upgrade",
                "-H",
                "Accept: application/vnd.github+json",
                url,
            ])
            .output()
            .context("failed to run curl")?;
        if out.status.success() {
            return String::from_utf8(out.stdout).context("GitHub releases response is not UTF-8");
        }
        anyhow::bail!(
            "curl failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    if command_exists("wget") {
        let out = Command::new("wget")
            .args(["-q", "--user-agent=bux-upgrade", "-O-", url])
            .output()
            .context("failed to run wget")?;
        if out.status.success() {
            return String::from_utf8(out.stdout).context("GitHub releases response is not UTF-8");
        }
        anyhow::bail!(
            "wget failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    anyhow::bail!("curl or wget is required for `bux upgrade`")
}

fn command_exists(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn is_cargo_install_path(exe: &Path) -> bool {
    exe.to_string_lossy().contains(".cargo/bin")
}

fn run_official_installer() -> Result<()> {
    if !command_exists("curl") {
        anyhow::bail!("curl is required to run the official installer");
    }
    // dash (Debian `/bin/sh`) rejects `--version`.
    let status = Command::new("sh")
        .args(["-c", &installer_shell()])
        .status()
        .context("failed to run official installer")?;
    if !status.success() {
        anyhow::bail!("installer exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "tests")]
mod tests {
    use std::cell::Cell;

    use super::*;

    /// Live 2026-09-04 shape (21 Releases) plus `guest-v0.1.0` so that tag cannot win.
    const FIXTURE: &str = r#"[
  {"tag_name": "guest-fc094be148bcfc7f3ef50d5e4805a8505afc04ba", "draft": false, "prerelease": false},
  {"tag_name": "guest-da2fc6aa4dca3c39d09e56b95c30ad49b419832a", "draft": false, "prerelease": false},
  {"tag_name": "guest-ccea02856a108acf44d0b8882f88168cd9bbbf1d", "draft": false, "prerelease": false},
  {"tag_name": "krun-v1.19.4", "draft": false, "prerelease": false},
  {"tag_name": "e2fs-v1.47.4", "draft": false, "prerelease": false},
  {"tag_name": "bwrap-v0.12.0", "draft": false, "prerelease": false},
  {"tag_name": "krun-v0.1.4", "draft": false, "prerelease": false},
  {"tag_name": "e2fs-v0.1.5", "draft": false, "prerelease": false},
  {"tag_name": "e2fs-v0.1.4", "draft": false, "prerelease": false},
  {"tag_name": "e2fs-v0.1.3", "draft": false, "prerelease": false},
  {"tag_name": "e2fs-v0.1.2", "draft": false, "prerelease": false},
  {"tag_name": "bwrap-v0.1.0", "draft": false, "prerelease": false},
  {"tag_name": "krun-v0.1.3", "draft": false, "prerelease": false},
  {"tag_name": "e2fs-v0.1.1", "draft": false, "prerelease": false},
  {"tag_name": "e2fs-v0.1.0", "draft": false, "prerelease": false},
  {"tag_name": "guest-v0.1.0", "draft": false, "prerelease": false},
  {"tag_name": "v0.4.1", "draft": false, "prerelease": false},
  {"tag_name": "v0.3.0", "draft": false, "prerelease": false},
  {"tag_name": "v0.2.1", "draft": false, "prerelease": false},
  {"tag_name": "deps-v0.1.3", "draft": false, "prerelease": false},
  {"tag_name": "deps-v0.1.2", "draft": false, "prerelease": false},
  {"tag_name": "deps-v0.1.0", "draft": false, "prerelease": false}
]"#;

    const GUEST_ONLY: &str = r#"[
  {"tag_name":"guest-fc094be148bcfc7f3ef50d5e4805a8505afc04ba","draft":false,"prerelease":false},
  {"tag_name":"krun-v1.19.4","draft":false,"prerelease":false}
]"#;

    #[test]
    fn fixture_first_tag_is_guest_sha() {
        let page: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        let tags: Vec<&str> = page
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["tag_name"].as_str().unwrap())
            .collect();
        assert_eq!(
            tags[0], "guest-fc094be148bcfc7f3ef50d5e4805a8505afc04ba",
            "fixture must be newest-first like live GitHub; first tag must not be v*"
        );
        assert!(
            !tags[0].starts_with('v'),
            "a first-tag_name scan / /releases/latest would poison latest-tag selection"
        );
        for required in [
            "guest-fc094be148bcfc7f3ef50d5e4805a8505afc04ba",
            "guest-v0.1.0",
            "krun-v1.19.4",
            "e2fs-v1.47.4",
            "bwrap-v0.12.0",
        ] {
            assert!(tags.contains(&required), "missing {required}");
        }
    }

    #[test]
    fn fixture_first_hit_is_0_4_1() {
        assert_eq!(
            parse_product_page(FIXTURE).unwrap(),
            PageHit::Version("0.4.1".into())
        );
    }

    #[test]
    fn guest_krun_e2fs_bwrap_never_win() {
        let body = r#"[
          {"tag_name":"guest-v0.1.0","draft":false,"prerelease":false},
          {"tag_name":"krun-v1.19.4","draft":false,"prerelease":false},
          {"tag_name":"e2fs-v1.47.4","draft":false,"prerelease":false},
          {"tag_name":"bwrap-v0.12.0","draft":false,"prerelease":false}
        ]"#;
        assert_eq!(parse_product_page(body).unwrap(), PageHit::Continue);
    }

    #[test]
    fn empty_page_stops_pagination() {
        assert_eq!(parse_product_page("[]").unwrap(), PageHit::Exhausted);
    }

    #[test]
    fn draft_and_prerelease_are_skipped() {
        let body = r#"[
          {"tag_name":"v9.9.9","draft":true,"prerelease":false},
          {"tag_name":"v8.8.8","draft":false,"prerelease":true},
          {"tag_name":"v0.4.1","draft":false,"prerelease":false}
        ]"#;
        assert_eq!(
            parse_product_page(body).unwrap(),
            PageHit::Version("0.4.1".into())
        );
    }

    #[test]
    fn latest_endpoint_object_is_rejected() {
        let body = r#"{
          "tag_name": "guest-fc094be148bcfc7f3ef50d5e4805a8505afc04ba",
          "draft": false,
          "prerelease": false
        }"#;
        let err = parse_product_page(body).unwrap_err().to_string();
        assert!(
            err.contains("JSON array"),
            "object body (the /releases/latest shape) must not yield a version: {err}"
        );
    }

    #[test]
    fn releases_url_paginates_and_is_not_latest() {
        let url = releases_url(1);
        assert_eq!(
            url,
            "https://api.github.com/repos/qntx/bux/releases?per_page=100&page=1"
        );
        assert!(
            !url.contains("/releases/latest"),
            "must not call /releases/latest: {url}"
        );
        assert!(
            !releases_url(2).contains("/releases/latest"),
            "page 2 must still be the list endpoint"
        );
    }

    #[test]
    fn fetch_paginates_until_v0_4_1_and_refuses_latest() {
        let mut urls = Vec::new();
        let latest = fetch_latest_version(|url| {
            urls.push(url.to_owned());
            assert!(
                !url.contains("/releases/latest"),
                "must not call /releases/latest: {url}"
            );
            Ok(match url {
                "https://api.github.com/repos/qntx/bux/releases?per_page=100&page=1" => {
                    GUEST_ONLY.to_owned()
                }
                "https://api.github.com/repos/qntx/bux/releases?per_page=100&page=2" => {
                    FIXTURE.to_owned()
                }
                other => panic!("unexpected url {other}"),
            })
        })
        .unwrap();
        assert_eq!(latest, "0.4.1");
        assert_eq!(
            urls,
            [
                "https://api.github.com/repos/qntx/bux/releases?per_page=100&page=1",
                "https://api.github.com/repos/qntx/bux/releases?per_page=100&page=2",
            ]
        );
    }

    #[test]
    fn fetch_errors_when_pages_exhaust_without_product_tag() {
        let err = fetch_latest_version(|url| {
            assert!(
                !url.contains("/releases/latest"),
                "must not call /releases/latest: {url}"
            );
            Ok(if url.ends_with("page=1") {
                GUEST_ONLY.to_owned()
            } else {
                "[]".to_owned()
            })
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("^v[0-9]"),
            "exhausted list must name the product-tag filter: {err}"
        );
    }

    #[test]
    fn installer_url_is_sh_qntx_org_bux() {
        assert_eq!(INSTALL_SH_URL, "https://sh.qntx.org/bux");
        assert_eq!(installer_shell(), "curl -fsSL https://sh.qntx.org/bux | sh");
        assert!(
            !INSTALL_SH_URL.contains(".fun"),
            "installer host is sh.qntx.org"
        );
        assert!(
            !installer_shell().contains("irm"),
            "no Windows irm installer"
        );
    }

    #[test]
    fn source_does_not_call_releases_latest_or_fun() {
        let src = include_str!("upgrade.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("production source before tests");
        assert!(
            !production.contains("releases/latest"),
            "must paginate /releases, not GET the latest pointer"
        );
        assert!(
            production.contains("releases?per_page=100&page="),
            "production fetch must use the paginated list URL"
        );
        assert!(
            !production.contains("sh.qntx.fun"),
            "installer URL is sh.qntx.org, not .fun"
        );
        assert!(
            !production.contains("INSTALL_PS_URL"),
            "no Windows PowerShell installer constant"
        );
        assert!(
            !production.contains("command_exists(\"sh\")"),
            "dash rejects --version; do not probe sh"
        );
    }

    #[test]
    fn semver_newer() {
        assert!(is_newer("0.4.1", "0.4.0"));
        assert!(is_newer("0.5.0", "0.4.9"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("0.4.1", "0.4.1"));
        assert!(!is_newer("0.4.1", "0.8.0"));
        assert!(!is_newer("0.3.0", "0.4.1"));
    }

    #[test]
    fn cargo_install_is_dot_cargo_bin() {
        assert!(is_cargo_install_path(Path::new("/Users/x/.cargo/bin/bux")));
        assert!(is_cargo_install_path(Path::new("/home/x/.cargo/bin/bux")));
        assert!(!is_cargo_install_path(Path::new("/Users/x/.local/bin/bux")));
        assert!(!is_cargo_install_path(Path::new(
            "/Users/x/Library/Application Support/bux-pkg/0.8.0-aarch64-apple-darwin/bux"
        )));
        assert!(!is_cargo_install_path(Path::new("/usr/local/bin/bux")));
    }

    fn newer_product_page() -> String {
        let current = env!("CARGO_PKG_VERSION");
        let (major, ..) = parse_semver(current).expect("crate version is X.Y.Z");
        let tag = format!("v{}.0.0", major + 1);
        format!(r#"[{{"tag_name":"{tag}","draft":false,"prerelease":false}}]"#)
    }

    fn run_injected(args: UpgradeArgs, exe: Option<&str>, page: &str) -> (bool, Result<()>) {
        let installed = Cell::new(false);
        let result = args.run_with(
            |url| {
                assert!(
                    !url.contains("/releases/latest"),
                    "must not call /releases/latest: {url}"
                );
                Ok(page.to_owned())
            },
            || {
                Ok(PathBuf::from(
                    exe.expect("--check / noop must not inspect current_exe"),
                ))
            },
            || {
                installed.set(true);
                Ok(())
            },
        );
        (installed.get(), result)
    }

    #[test]
    fn check_does_not_run_installer() {
        let (installed, result) = run_injected(
            UpgradeArgs {
                check: true,
                force: true,
            },
            None,
            FIXTURE,
        );
        result.unwrap();
        assert!(!installed, "--check must not run the installer");
    }

    #[test]
    fn cargo_bin_does_not_run_installer() {
        let (installed, result) = run_injected(
            UpgradeArgs {
                check: false,
                force: true,
            },
            Some("/home/x/.cargo/bin/bux"),
            FIXTURE,
        );
        result.unwrap();
        assert!(!installed, ".cargo/bin must not run the installer");
    }

    #[test]
    fn script_install_runs_installer() {
        let (installed, result) = run_injected(
            UpgradeArgs {
                check: false,
                force: true,
            },
            Some("/home/x/.local/bin/bux"),
            FIXTURE,
        );
        result.unwrap();
        assert!(installed, "non-cargo path must run the installer");
    }

    #[test]
    fn noop_when_current_is_newest_does_not_run_installer() {
        assert!(
            !is_newer("0.4.1", env!("CARGO_PKG_VERSION")),
            "FIXTURE product tag must stay older than the crate for this noop"
        );
        let (installed, result) = run_injected(
            UpgradeArgs {
                check: false,
                force: false,
            },
            None,
            FIXTURE,
        );
        result.unwrap();
        assert!(
            !installed,
            "already-latest without --force must not run the installer"
        );
    }

    #[test]
    fn newer_release_installs_without_force() {
        let page = newer_product_page();
        let PageHit::Version(latest) = parse_product_page(&page).unwrap() else {
            panic!("newer page must yield a product version");
        };
        assert!(
            is_newer(&latest, env!("CARGO_PKG_VERSION")),
            "injected tag {latest} must be newer than the crate"
        );
        let (installed, result) = run_injected(
            UpgradeArgs {
                check: false,
                force: false,
            },
            Some("/home/x/.local/bin/bux"),
            &page,
        );
        result.unwrap();
        assert!(
            installed,
            "newer product tag without --force must run the installer"
        );
    }

    #[test]
    fn check_does_not_install_when_newer() {
        let page = newer_product_page();
        let (installed, result) = run_injected(
            UpgradeArgs {
                check: true,
                force: false,
            },
            None,
            &page,
        );
        result.unwrap();
        assert!(!installed, "--check must not run the installer when newer");
    }

    #[test]
    fn cargo_bin_does_not_install_when_newer() {
        let page = newer_product_page();
        let (installed, result) = run_injected(
            UpgradeArgs {
                check: false,
                force: false,
            },
            Some("/home/x/.cargo/bin/bux"),
            &page,
        );
        result.unwrap();
        assert!(
            !installed,
            ".cargo/bin must not run the installer when a newer tag exists"
        );
    }
}
