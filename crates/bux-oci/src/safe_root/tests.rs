//! Tests for rooted path resolution.

use super::SafeRoot;
use std::path::Path;

fn create_symlink(root: &Path, link: &str, target: &str) {
    let link_path = root.join(link);
    if let Some(parent) = link_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::os::unix::fs::symlink(target, link_path).unwrap();
}

#[test]
fn resolve_simple_path() {
    let tmp = tempfile::tempdir().unwrap();
    let root = SafeRoot::open(tmp.path()).unwrap();
    let resolved = root.resolve(Path::new("a/b")).unwrap();
    assert_eq!(resolved, root.root_path().join("a/b"));
}

#[test]
fn resolve_absolute_symlink_reanchors() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("extract");
    let root = SafeRoot::open(&dest).unwrap();

    std::fs::create_dir_all(dest.join("real")).unwrap();
    std::os::unix::fs::symlink("/real", dest.join("link")).unwrap();

    let resolved = root.resolve(Path::new("link/file")).unwrap();
    assert_eq!(resolved, root.root_path().join("real/file"));
}

#[test]
fn resolve_chained_absolute_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("extract");
    let host_side = tmp.path().join("host");
    std::fs::create_dir_all(&host_side).unwrap();
    let root = SafeRoot::open(&dest).unwrap();

    std::os::unix::fs::symlink("b", dest.join("a")).unwrap();
    std::os::unix::fs::symlink(host_side.to_str().unwrap(), dest.join("b")).unwrap();

    let resolved = root.resolve(Path::new("a/file")).unwrap();
    let host_side = std::fs::canonicalize(&host_side).unwrap();
    assert!(
        !resolved.starts_with(&host_side),
        "escaped to host: {}",
        resolved.display()
    );
}

#[test]
fn resolve_hop_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("extract");
    let root = SafeRoot::open(&dest).unwrap();

    std::os::unix::fs::symlink("b", dest.join("a")).unwrap();
    std::os::unix::fs::symlink("a", dest.join("b")).unwrap();

    let result = root.resolve(Path::new("a/file"));
    assert!(result.is_err(), "circular symlink must hit hop limit");
}

#[test]
fn resolve_escaping_path_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let root = SafeRoot::open(tmp.path()).unwrap();
    let result = root.resolve(Path::new("../../etc/passwd"));
    assert!(result.is_err());
}

#[test]
fn absolute_symlink_stored_verbatim() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("extract");
    let root = SafeRoot::open(&dest).unwrap();

    std::os::unix::fs::symlink("/bin/busybox", dest.join("sh")).unwrap();

    let target = std::fs::read_link(dest.join("sh")).unwrap();
    assert_eq!(target, std::path::PathBuf::from("/bin/busybox"));

    let resolved = root.resolve(Path::new("sh/sub")).unwrap();
    assert!(resolved.starts_with(root.root_path()));
}

/// A resolve error must not be papered over with `root.join(rel)`.
#[test]
fn hardlink_resolve_fallback_must_not_escape() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("extract");
    let host_dir = tmp.path().join("host");
    std::fs::create_dir_all(&host_dir).unwrap();
    std::fs::write(host_dir.join("secret"), b"host data").unwrap();

    let root = SafeRoot::open(&dest).unwrap();
    std::os::unix::fs::symlink(&host_dir, dest.join("a")).unwrap();

    let resolved = root.resolve(Path::new("a"));
    let host_dir = std::fs::canonicalize(&host_dir).unwrap();
    if let Ok(p) = &resolved {
        assert!(
            !p.starts_with(&host_dir),
            "resolve escaped to host: {}",
            p.display()
        );
    }
}

#[test]
fn resolve_nonexistent_parent_returns_path_not_error() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("extract");
    let root = SafeRoot::open(&dest).unwrap();

    let result = root.resolve(Path::new("usr/bin"));
    assert!(
        result.is_ok(),
        "missing parents must resolve, got: {:?}",
        result.err()
    );
    let resolved = result.unwrap();
    assert!(
        resolved.starts_with(root.root_path()),
        "resolved path should be under root"
    );
}

#[test]
fn resolve_symlink_cases() {
    struct Case<'a> {
        name: &'a str,
        links: &'a [(&'a str, &'a str)],
        rel: &'a str,
        expected: &'a str,
    }

    let cases = [
        Case {
            name: "absolute symlink is re-anchored",
            links: &[("a", "/b")],
            rel: "a/c/data",
            expected: "b/c/data",
        },
        Case {
            name: "relative symlink parent traversal stays in root",
            links: &[("a", "../b")],
            rel: "a/c/data",
            expected: "b/c/data",
        },
        Case {
            name: "deep relative breakout collapses to root",
            links: &[("a", "../../../../test")],
            rel: "a/c/data",
            expected: "test/c/data",
        },
        Case {
            name: "absolute symlink to root",
            links: &[("a", "/")],
            rel: "a/c/data",
            expected: "c/data",
        },
        Case {
            name: "absolute symlink with parent traversal",
            links: &[("a", "/../../")],
            rel: "a/c/data",
            expected: "c/data",
        },
        Case {
            name: "relative symlink with parent traversal",
            links: &[("a", "../../")],
            rel: "a/c/data",
            expected: "c/data",
        },
        Case {
            name: "absolute chain stays rooted",
            links: &[("a", "b"), ("b", "/c"), ("c", "d")],
            rel: "a/e",
            expected: "d/e",
        },
        Case {
            name: "breakout through missing component is re-cleaned",
            links: &[("slash", "/"), ("sym", "/idontexist/../slash")],
            rel: "sym/file",
            expected: "file",
        },
        Case {
            name: "symlink target is resolved component by component",
            links: &[("sym", "/foo/bar"), ("hello", "/sym/../baz")],
            rel: "hello",
            expected: "foo/baz",
        },
    ];

    for case in cases {
        let tmp = tempfile::tempdir().unwrap();
        let root = SafeRoot::open(tmp.path()).unwrap();
        for (link, target) in case.links {
            create_symlink(tmp.path(), link, target);
        }

        let actual = root.resolve(Path::new(case.rel)).unwrap();
        let expected = root.root_path().join(case.expected);
        assert_eq!(actual, expected, "{}", case.name);
    }
}

#[test]
fn resolve_circular_symlink_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let root = SafeRoot::open(tmp.path()).unwrap();
    create_symlink(tmp.path(), "a", "b");
    create_symlink(tmp.path(), "b", "a");

    assert!(root.resolve(Path::new("a/file")).is_err());
}
