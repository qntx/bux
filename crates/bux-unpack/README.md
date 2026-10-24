# bux-unpack

Safe OCI layer extraction for the [bux](https://github.com/qntx/bux) micro-VM sandbox.

- `Extractor` applies layer tarballs (plain or gzip, from any reader) to a root directory in order, with OCI whiteout semantics. `extract_layer_files(layers, root)` does the same for layer files on disk.
- Every member is resolved inside the root: symlinks are followed there and absolute targets are re-anchored at the root, so a crafted layer cannot write or delete outside it. The Linux resolver uses `pathrs`. Device and FIFO members are skipped, and directory modes are applied after the last layer.
- `Options { keep_owners: true }` keeps the uid, gid and `SCHILY.xattr.*` extended attributes from the tar headers. It needs the privilege to `chown`, i.e. root.
- `scan` reports what a layer would create (directories, files with their sizes, symlinks, hard links) without writing it, so a filesystem can be sized before extraction.

Part of [bux](https://github.com/qntx/bux).
