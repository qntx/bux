//! GHSA-f396 class: extract must not write or delete the host via symlinks.

#![allow(
    unused_crate_dependencies,
    clippy::unwrap_used,
    clippy::tests_outside_test_module,
    reason = "Cargo tests/ binary; lib deps are unused here"
)]

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use bux_oci::{OciError, extract_layer_files};

const LAYER: &str = "application/vnd.oci.image.layer.v1.tar";

enum Ent {
    Dir {
        name: String,
        mode: u32,
    },
    File {
        name: String,
        data: Vec<u8>,
        mode: u32,
    },
    Symlink {
        name: String,
        target: String,
    },
}

fn write_tar(tar_path: &Path, ents: &[Ent]) {
    let mut builder = tar::Builder::new(Vec::new());
    for ent in ents {
        match ent {
            Ent::Dir { name, mode } => {
                let mut header = tar::Header::new_gnu();
                header.set_path(name).unwrap();
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(*mode);
                header.set_size(0);
                header.set_cksum();
                builder.append(&header, &[][..]).unwrap();
            }
            Ent::File { name, data, mode } => {
                let mut header = tar::Header::new_gnu();
                header.set_path(name).unwrap();
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(*mode);
                header.set_size(data.len() as u64);
                header.set_cksum();
                builder.append(&header, data.as_slice()).unwrap();
            }
            Ent::Symlink { name, target } => {
                let mut header = tar::Header::new_gnu();
                header.set_path(name).unwrap();
                header.set_link_name(target).unwrap();
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                header.set_cksum();
                builder.append(&header, &[][..]).unwrap();
            }
        }
    }
    let data = builder.into_inner().unwrap();
    fs::write(tar_path, data).unwrap();
}

/// `Header::set_path` refuses `..`; a hostile layer can still encode it.
fn write_dotdot_tar(tar_path: &Path, data: &[u8]) {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    {
        let old = header.as_old_mut();
        for (dst, src) in old.name.iter_mut().zip(b"../outside") {
            *dst = *src;
        }
    }
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_size(data.len() as u64);
    header.set_cksum();
    builder.append(&header, data).unwrap();
    fs::write(tar_path, builder.into_inner().unwrap()).unwrap();
}

fn extract(layers: &[PathBuf], rootfs: &Path) {
    let pairs: Vec<(&Path, &str)> = layers.iter().map(|p| (p.as_path(), LAYER)).collect();
    extract_layer_files(&pairs, rootfs).unwrap();
}

fn extract_err(layers: &[PathBuf], rootfs: &Path) -> OciError {
    let pairs: Vec<(&Path, &str)> = layers.iter().map(|p| (p.as_path(), LAYER)).collect();
    extract_layer_files(&pairs, rootfs).unwrap_err()
}

#[test]
fn symlink_escape_does_not_write_host() {
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().join("rootfs");
    let host = tmp.path().join("bux-oci-escape-target");
    fs::create_dir_all(&host).unwrap();
    let pwned = host.join("pwned");
    assert!(!pwned.exists());

    let tar = tmp.path().join("layer.tar");
    write_tar(
        &tar,
        &[
            Ent::Symlink {
                name: "evil".into(),
                target: host.to_string_lossy().into_owned(),
            },
            Ent::File {
                name: "evil/pwned".into(),
                data: b"pwned".to_vec(),
                mode: 0o644,
            },
        ],
    );

    match extract_layer_files(&[(&tar, LAYER)], &rootfs) {
        Ok(()) | Err(_) => {}
    }
    assert!(
        !pwned.exists(),
        "host must not be written through an extract symlink"
    );
}

#[test]
fn symlink_escape_whiteout_does_not_delete_host() {
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().join("rootfs");
    let host = tmp.path().join("host");
    fs::create_dir_all(&host).unwrap();
    let victim = host.join("keep-me");
    fs::write(&victim, b"host").unwrap();

    let tar = tmp.path().join("layer.tar");
    write_tar(
        &tar,
        &[
            Ent::Symlink {
                name: "evil".into(),
                target: host.to_string_lossy().into_owned(),
            },
            Ent::File {
                name: "evil/.wh.keep-me".into(),
                data: vec![],
                mode: 0o644,
            },
        ],
    );

    match extract_layer_files(&[(&tar, LAYER)], &rootfs) {
        Ok(()) | Err(_) => {}
    }
    assert!(
        victim.exists(),
        "whiteout must not delete a host file through a symlink"
    );
}

#[test]
fn absolute_symlink_is_reanchored() {
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().join("rootfs");
    let probe = "bux-oci-reanchor-probe";
    let host_probe = Path::new("/etc").join(probe);

    let tar = tmp.path().join("layer.tar");
    write_tar(
        &tar,
        &[
            Ent::Symlink {
                name: "link".into(),
                target: "/etc".into(),
            },
            Ent::File {
                name: format!("link/{probe}"),
                data: b"inside-rootfs".to_vec(),
                mode: 0o644,
            },
        ],
    );

    extract(&[tar], &rootfs);
    assert_eq!(
        fs::read(rootfs.join("etc").join(probe)).unwrap(),
        b"inside-rootfs"
    );
    assert!(
        !host_probe.exists(),
        "re-anchored write must not land on the host"
    );
}

#[test]
fn dotdot_entry_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().join("rootfs");
    let outside = tmp.path().join("outside");

    let tar = tmp.path().join("layer.tar");
    write_dotdot_tar(&tar, b"nope");

    extract(&[tar], &rootfs);
    assert!(!outside.exists(), "../outside must not be created");
    assert!(
        !rootfs.join("outside").exists(),
        "skipped .. entry must not land inside rootfs either"
    );
}

#[test]
fn opaque_whiteout_clears_only_in_root() {
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().join("rootfs");
    let host = tmp.path().join("host");
    fs::create_dir_all(&host).unwrap();
    let host_file = host.join("secret");
    fs::write(&host_file, b"host").unwrap();

    let tar = tmp.path().join("layer.tar");
    write_tar(
        &tar,
        &[
            Ent::Symlink {
                name: "dir".into(),
                target: host.to_string_lossy().into_owned(),
            },
            Ent::File {
                name: "dir/.wh..wh..opq".into(),
                data: vec![],
                mode: 0o644,
            },
        ],
    );

    let err = extract_err(&[tar], &rootfs);
    assert!(
        matches!(err, OciError::Extract(ref s) if s.contains("escapes")),
        "opaque whiteout through a host symlink must fail closed, got {err}"
    );
    assert!(host_file.exists(), "host directory must not be cleared");
}

#[test]
fn safe_root_hop_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().join("rootfs");
    let tar = tmp.path().join("layer.tar");

    let mut ents = Vec::new();
    for i in 0..256 {
        ents.push(Ent::Symlink {
            name: format!("n{i}"),
            target: format!("n{}", i + 1),
        });
    }
    ents.push(Ent::File {
        name: "n0/leaf".into(),
        data: b"x".to_vec(),
        mode: 0o644,
    });
    write_tar(&tar, &ents);

    let err = extract_err(&[tar], &rootfs);
    assert!(
        matches!(err, OciError::Extract(ref s) if s.contains("hop limit")),
        "256-hop chain must hit hop limit, got {err}"
    );
}

#[test]
fn cross_layer_dir_mode_finalize() {
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().join("rootfs");

    let layer1 = tmp.path().join("l1.tar");
    write_tar(
        &layer1,
        &[
            Ent::Dir {
                name: "usr".into(),
                mode: 0o755,
            },
            Ent::Dir {
                name: "usr/bin".into(),
                mode: 0o555,
            },
        ],
    );
    let layer2 = tmp.path().join("l2.tar");
    write_tar(
        &layer2,
        &[Ent::File {
            name: "usr/bin/tool".into(),
            data: b"ok".to_vec(),
            mode: 0o755,
        }],
    );

    extract(&[layer1, layer2], &rootfs);
    assert_eq!(fs::read(rootfs.join("usr/bin/tool")).unwrap(), b"ok");
    let mode = fs::symlink_metadata(rootfs.join("usr/bin"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o555,
        "last declared dir mode applied after last layer"
    );
    fs::set_permissions(rootfs.join("usr/bin"), Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn extract_uses_safe_root_not_unpack_in() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/extract.rs"));
    assert!(
        !src.contains("unpack_in"),
        "unpack_in is not RESOLVE_IN_ROOT"
    );
    assert!(
        !src.contains("rootfs.join"),
        "host-view rootfs.join must stay deleted"
    );
    assert!(src.contains("SafeRoot"), "extract must go through SafeRoot");
}
