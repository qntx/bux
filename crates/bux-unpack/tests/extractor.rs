//! `Extractor` over readers, `Options::keep_owners`, and `scan`.

#![allow(
    unused_crate_dependencies,
    clippy::unwrap_used,
    clippy::tests_outside_test_module,
    reason = "Cargo tests/ binary; lib deps are unused here"
)]

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Cursor, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use bux_unpack::{Error, Extractor, Member, Options, scan};
use flate2::Compression;
use flate2::write::GzEncoder;

const TAR: &str = "application/vnd.oci.image.layer.v1.tar";
const TAR_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// A layer built in memory.
struct Layer {
    builder: tar::Builder<Vec<u8>>,
    owner: (u64, u64),
}

impl Layer {
    fn new() -> Self {
        Self {
            builder: tar::Builder::new(Vec::new()),
            owner: (0, 0),
        }
    }

    /// Owner of the members added after this.
    const fn owner(mut self, uid: u64, gid: u64) -> Self {
        self.owner = (uid, gid);
        self
    }

    /// PAX records for the next member.
    fn pax(mut self, records: &[(&str, &[u8])]) -> Self {
        self.builder
            .append_pax_extensions(records.iter().copied())
            .unwrap();
        self
    }

    fn append(mut self, mut header: tar::Header, data: &[u8]) -> Self {
        header.set_uid(self.owner.0);
        header.set_gid(self.owner.1);
        header.set_size(data.len() as u64);
        header.set_cksum();
        self.builder.append(&header, data).unwrap();
        self
    }

    fn dir(self, path: &str, mode: u32) -> Self {
        self.append(header(path, tar::EntryType::Directory, mode), &[])
    }

    fn file(self, path: &str, mode: u32, data: &[u8]) -> Self {
        self.append(header(path, tar::EntryType::Regular, mode), data)
    }

    fn symlink(self, path: &str, target: &str) -> Self {
        let mut header = header(path, tar::EntryType::Symlink, 0o777);
        header.set_link_name(target).unwrap();
        self.append(header, &[])
    }

    fn hardlink(self, path: &str, target: &str) -> Self {
        let mut header = header(path, tar::EntryType::Link, 0o644);
        header.set_link_name(target).unwrap();
        self.append(header, &[])
    }

    fn special(self, path: &str, entry_type: tar::EntryType) -> Self {
        self.append(header(path, entry_type, 0o644), &[])
    }

    /// A regular file whose name `Header::set_path` refuses, such as `../x`.
    fn raw_file(self, name: &[u8], data: &[u8]) -> Self {
        let mut header = tar::Header::new_gnu();
        for (dst, src) in header.as_old_mut().name.iter_mut().zip(name) {
            *dst = *src;
        }
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        self.append(header, data)
    }

    fn tar(self) -> Vec<u8> {
        self.builder.into_inner().unwrap()
    }

    fn gzip(self) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&self.tar()).unwrap();
        encoder.finish().unwrap()
    }
}

fn header(path: &str, entry_type: tar::EntryType, mode: u32) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_path(path).unwrap();
    header.set_entry_type(entry_type);
    header.set_mode(mode);
    header
}

fn extract(root: &Path, options: Options, layers: &[(Vec<u8>, &str)]) -> Result<(), Error> {
    let mut extractor = Extractor::open(root, options)?;
    for (layer, media_type) in layers {
        extractor.extract(Cursor::new(layer), media_type)?;
    }
    extractor.finish()
}

/// The uid and gid that new files in `dir` get, which the test may `chown` to
/// without privileges.
fn own_ids(dir: &Path) -> (u64, u64) {
    let probe = dir.join("owner-probe");
    fs::write(&probe, b"").unwrap();
    let meta = fs::metadata(&probe).unwrap();
    (u64::from(meta.uid()), u64::from(meta.gid()))
}

fn ids(path: &Path) -> (u64, u64) {
    let meta = fs::symlink_metadata(path).unwrap();
    (u64::from(meta.uid()), u64::from(meta.gid()))
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn extracts_layers_from_readers() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let lower = Layer::new()
        .dir("etc", 0o755)
        .file("etc/hostname", 0o644, b"bux\n")
        .file("etc/old", 0o644, b"old")
        .symlink("etc/localtime", "/usr/share/zoneinfo/UTC")
        .dir("var/cache", 0o700)
        .file("var/cache/stale", 0o644, b"stale")
        .gzip();
    let upper = Layer::new()
        .file("etc/.wh.old", 0o644, b"")
        .file("var/cache/.wh..wh..opq", 0o644, b"")
        .file("var/cache/fresh", 0o600, b"fresh")
        .tar();

    extract(
        &root,
        Options::default(),
        &[(lower, TAR_GZIP), (upper, TAR)],
    )
    .unwrap();

    assert_eq!(fs::read(root.join("etc/hostname")).unwrap(), b"bux\n");
    assert!(!root.join("etc/old").exists());
    assert_eq!(
        fs::read_link(root.join("etc/localtime")).unwrap(),
        Path::new("/usr/share/zoneinfo/UTC")
    );
    assert!(!root.join("var/cache/stale").exists());
    assert_eq!(fs::read(root.join("var/cache/fresh")).unwrap(), b"fresh");
    assert_eq!(mode(&root.join("var/cache/fresh")), 0o600);
    assert_eq!(mode(&root.join("var/cache")), 0o700);
}

#[test]
fn keep_owners_sets_the_mode_again_after_chown() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let (uid, gid) = own_ids(tmp.path());
    let layer = Layer::new()
        .owner(uid, gid)
        .dir("bin", 0o755)
        .file("bin/su", 0o4755, b"#!/bin/true\n")
        .file("bin/wall", 0o2755, b"#!/bin/true\n")
        .symlink("bin/sh", "su")
        .tar();

    extract(&root, Options { keep_owners: true }, &[(layer, TAR)]).unwrap();

    // chown clears setuid and setgid even when the owner does not change.
    assert_eq!(mode(&root.join("bin/su")), 0o4755);
    assert_eq!(mode(&root.join("bin/wall")), 0o2755);
    for path in ["bin", "bin/su", "bin/wall", "bin/sh"] {
        assert_eq!(ids(&root.join(path)), (uid, gid), "{path}");
    }
}

#[test]
fn keep_owners_restores_xattrs() {
    let tmp = tempfile::tempdir().unwrap();
    let probe = tmp.path().join("xattr-probe");
    fs::write(&probe, b"").unwrap();
    if xattr::set(&probe, "user.bux-probe", b"1").is_err() {
        // This filesystem has no user xattrs.
        return;
    }
    let root = tmp.path().join("root");
    let (uid, gid) = own_ids(tmp.path());
    let binary: &[u8] = b"\x00\x01\xfe\xff";
    let layer = Layer::new()
        .owner(uid, gid)
        .pax(&[("SCHILY.xattr.user.dir", b"d")])
        .dir("data", 0o755)
        .pax(&[
            ("SCHILY.xattr.user.binary", binary),
            ("SCHILY.xattr.user.text", b"t"),
            ("comment", b"not an xattr"),
        ])
        .file("data/file", 0o644, b"x")
        .tar();

    extract(&root, Options { keep_owners: true }, &[(layer, TAR)]).unwrap();

    let get = |path: &str, name: &str| xattr::get(root.join(path), name).unwrap();
    assert_eq!(get("data", "user.dir").as_deref(), Some(&b"d"[..]));
    assert_eq!(get("data/file", "user.binary").as_deref(), Some(binary));
    assert_eq!(get("data/file", "user.text").as_deref(), Some(&b"t"[..]));
    // Only `SCHILY.xattr.*` records become xattrs. macOS adds its own
    // `com.apple.*` attributes to some files.
    let names: BTreeSet<String> = xattr::list(root.join("data/file"))
        .unwrap()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.starts_with("com.apple."))
        .collect();
    assert_eq!(
        names,
        BTreeSet::from(["user.binary".into(), "user.text".into()])
    );
}

#[test]
fn owners_and_xattrs_are_ignored_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let own = own_ids(tmp.path());
    let layer = Layer::new()
        .owner(4242, 4242)
        .pax(&[("SCHILY.xattr.user.bux", b"1")])
        .file("file", 0o644, b"x")
        .tar();

    extract(&root, Options::default(), &[(layer, TAR)]).unwrap();

    assert_eq!(ids(&root.join("file")), own);
    assert_eq!(xattr::get(root.join("file"), "user.bux").unwrap(), None);
}

#[test]
fn keep_owners_needs_the_privilege_to_chown() {
    let tmp = tempfile::tempdir().unwrap();
    if own_ids(tmp.path()).0 == 0 {
        // Root may give files to anyone.
        return;
    }
    let root = tmp.path().join("root");
    let layer = Layer::new()
        .owner(4242, 4242)
        .file("file", 0o644, b"x")
        .tar();

    let err = extract(&root, Options { keep_owners: true }, &[(layer, TAR)]).unwrap_err();
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::PermissionDenied),
        "expected EPERM, got {err:?}"
    );
}

/// Root only: `sudo -E cargo test -p bux-unpack --test extractor -- --ignored`.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs root"]
fn keep_owners_as_root_sets_any_owner_and_file_capabilities() {
    // `cap_net_raw+ep`: VFS_CAP_REVISION_2 with the effective flag, then the
    // permitted and inheritable sets.
    let capability: [u8; 20] = [
        0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let layer = Layer::new()
        .owner(1234, 5678)
        .dir("bin", 0o750)
        .pax(&[("SCHILY.xattr.security.capability", &capability[..])])
        .file("bin/ping", 0o4755, b"#!/bin/true\n")
        .owner(42, 43)
        .symlink("bin/sh", "ping")
        .tar();

    extract(&root, Options { keep_owners: true }, &[(layer, TAR)]).unwrap();

    assert_eq!(ids(&root.join("bin")), (1234, 5678));
    assert_eq!(mode(&root.join("bin")), 0o750);
    assert_eq!(ids(&root.join("bin/ping")), (1234, 5678));
    assert_eq!(mode(&root.join("bin/ping")), 0o4755);
    assert_eq!(ids(&root.join("bin/sh")), (42, 43));
    // Set after the chown, which would have removed it.
    assert_eq!(
        xattr::get(root.join("bin/ping"), "security.capability")
            .unwrap()
            .as_deref(),
        Some(&capability[..])
    );
}

fn scan_layer() -> Layer {
    Layer::new()
        .dir("./", 0o755)
        .dir("etc", 0o755)
        .file("etc/passwd", 0o644, b"root:x:0:0\n")
        .symlink("etc/long", &"t".repeat(80))
        .hardlink("etc/passwd-", "etc/passwd")
        .file("etc/.wh.shadow", 0o644, b"")
        .file("etc/.wh..wh..opq", 0o644, b"")
        .special("dev/null", tar::EntryType::Char)
        .special("run/fifo", tar::EntryType::Fifo)
        .raw_file(b"../outside", b"escape")
        .pax(&[("SCHILY.xattr.user.bux", b"1")])
        .file("big", 0o644, &[0; 5000])
}

#[test]
fn scan_reports_what_extraction_would_create() {
    for (layer, media_type) in [(scan_layer().tar(), TAR), (scan_layer().gzip(), TAR_GZIP)] {
        let mut members = Vec::new();
        scan(Cursor::new(layer), media_type, |member| {
            members.push(member);
        })
        .unwrap();
        assert_eq!(
            members,
            [
                Member::Dir,
                Member::File { size: 11 },
                Member::Symlink { target_len: 80 },
                Member::Hardlink,
                Member::File { size: 5000 },
            ],
            "{media_type}"
        );
    }
}

#[test]
fn scan_fails_on_a_truncated_layer() {
    let mut layer = Layer::new().file("big", 0o644, &[0; 5000]).tar();
    layer.truncate(1024);
    let err = scan(Cursor::new(layer), TAR, |_| {}).unwrap_err();
    assert!(
        matches!(err, Error::Io(_)),
        "expected an I/O error, got {err:?}"
    );
}
