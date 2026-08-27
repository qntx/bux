# Native libraries

Prebuilt libkrun / libkrunfw, e2fsprogs, and (Linux) bubblewrap are GitHub
Release tarballs. `build.rs` downloads them with ureq. gvproxy is compiled
from in-tree Go (`gvproxy-bridge`), not a Release.

Product README is not this document. Rpath, capture-env, and the FULL
checklist stay in [`CONTRIBUTING.md`](../CONTRIBUTING.md) — do not copy them
here.

## Pins

Keep `build.rs` constants and the matching workflow `env:` in lockstep.

| Component | Pin | Workflow | Tag / URL key |
| --- | --- | --- | --- |
| libkrun | 1.19.4 | `.github/workflows/krun-build.yml` | `krun-v1.19.4` |
| libkrunfw | 5.5.0 | same tarball as libkrun | (not its own tag) |
| e2fsprogs | 1.47.4 | `.github/workflows/e2fs-build.yml` | `e2fs-v1.47.4` |
| bubblewrap | 0.12.0 | `.github/workflows/bwrap-build.yml` | `bwrap-v0.12.0` |
| gvproxy | 0.8.9 | in-tree `gvproxy-bridge/go.mod` | none |

Soname majors stay **1** (libkrun) and **5** (libkrunfw). Crate versions
(`bux-krun` 0.2.0, …) are not the tag.

Clone and headers: [`libkrun/libkrun`](https://github.com/libkrun/libkrun),
not `qntx/libkrun` (404). Firmware assets:
[`libkrun/libkrunfw`](https://github.com/libkrun/libkrunfw). `containers/libkrun`
redirects; pin the live org.

`publish-krun` / `publish-e2fs` / `publish-bwrap` are already deleted. Native
tags attach assets only. Do not re-add `cargo publish` to these workflows.

## Toolchain

- rustc **1.97.1** (`rust-toolchain.toml`, `.github/workflows/ci.yml`)
- Go for `bux-gvproxy` (`build.rs` `go build -buildmode=c-archive`)
- C toolchain for libkrun / e2fs / qcow2 native deps
- Darwin: `codesign` (shim entitlements + ad-hoc libkrun). `Makefile` `sign`
  target. `crates/bux-shim/bux-shim.entitlements` includes
  `disable-library-validation` so the shim can load ad-hoc libkrun.
- Linux `patchelf` only in GHA (`krun-build.yml`), not on the operator laptop.

Linux embedder `$ORIGIN` rustflags: [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## URL scheme

One scheme. No crate-version URL. No dual GET.

```
https://github.com/qntx/bux/releases/download/krun-v{LIBKRUN_VERSION}/bux-deps-{target}.tar.gz
https://github.com/qntx/bux/releases/download/e2fs-v{E2FSPROGS_VERSION}/bux-e2fs-{target}.tar.gz
https://github.com/qntx/bux/releases/download/bwrap-v{BUBBLEWRAP_VERSION}/bux-bwrap-{target}.tar.gz
```

`BUX_DEPS_VERSION` / `BUX_E2FS_VERSION` / `BUX_BWRAP_VERSION` override that
native version string and default to the pin constant, not `CARGO_PKG_VERSION`.

`LIBKRUN_VERSION` must remain a real `libkrun/libkrun` git tag (`v1.19.4`).
`krun-build.yml` clones `--branch v${LIBKRUN_VERSION}`; bindgen fetches
`https://raw.githubusercontent.com/libkrun/libkrun/v{LIBKRUN_VERSION}/include/libkrun.h`.
Do not invent `1.19.4.1` as `LIBKRUN_VERSION`. A later firmware-only bump
needs a **separate** Release identifier used only in the download URL / `git
tag`; do not reuse `krun-v1.19.4`.

## Offline

| Variable | Meaning |
| --- | --- |
| `BUX_DEPS_DIR` | Directory of unrewritten `libkrun` / `libkrunfw` dylibs (or `.so`). Skips krun download. |
| `BUX_E2FS_DIR` | Directory with `lib/` (or the `.a` files) and headers. Skips e2fs download. |
| `BUX_BWRAP_DIR` | Directory containing a `bwrap` binary. Skips bwrap download (Linux). |

These are local paths, not a second URL. Air-gapped / iterating on a local
`make install` uses them. Darwin `bux-bwrap` does not download (Linux-only).

## Compile from cold

Unset `BUX_DEPS_DIR` / `BUX_E2FS_DIR` / `BUX_BWRAP_DIR`. First
`cargo build -p bux-cli -p bux-shim-bin` downloads `krun-v1.19.4` and
`e2fs-v1.47.4` and compiles gvproxy from Go.

Measured on this machine, 2026-08-26, Darwin arm64, after `krun-v1.19.4` /
`e2fs-v1.47.4` assets existed:

```
[bux-krun 0.2.0] bux-krun: downloading https://github.com/qntx/bux/releases/download/krun-v1.19.4/bux-deps-aarch64-apple-darwin.tar.gz
```

```
otool -L target/debug/libkrun.dylib
@loader_path/libkrun.dylib (compatibility version 1.0.0, current version 1.19.0)
```

```
[bux-e2fs 0.2.0] bux-e2fs: downloading https://github.com/qntx/bux/releases/download/e2fs-v1.47.4/bux-e2fs-aarch64-apple-darwin.tar.gz
```

`cargo build -p bux-cli -p bux-shim-bin` Finished after the krun 1.19 fetch.
Cargo warned that no Linux `bux-guest` binary was found
(`aarch64-unknown-linux-musl`). No musl guest ELF on this host. Darwin does
not compile the guest. That is not a `BUX_E2E_FULL` record.

Releases that exist (same date):

- `krun-v1.19.4`: `bux-deps-aarch64-apple-darwin.tar.gz`,
  `bux-deps-x86_64-unknown-linux-gnu.tar.gz`,
  `bux-deps-aarch64-unknown-linux-gnu.tar.gz`
- `e2fs-v1.47.4`: three `bux-e2fs-*.tar.gz` (same triples)
- `bwrap-v0.12.0`: two Linux `bux-bwrap-*.tar.gz` (no Darwin)

Darwin `cargo build -p bux-bwrap` does not fetch.

## Bindgen before assets exist

`cargo check -p bux-krun --features regenerate` is **not** header-only.
`build.rs` still calls `obtain_libraries` on Darwin/Linux, which GETs
`krun-v{LIBKRUN_VERSION}` and **404s until the Release exists**.

Point `BUX_DEPS_DIR` at an **unrewritten** extract (`$OUT_DIR/lib` from a
prior download, or a fresh unpack of `bux-deps-*.tar.gz`). Do **not** point
it at `target/debug` after the Darwin rewrite: those staged copies already
have `LC_RPATH @loader_path`, and `install_name_tool -add_rpath @loader_path`
panics on the duplicate.

```sh
# before krun-v1.19.4 assets exist — unrewritten extract, not target/debug
export BUX_DEPS_DIR=/path/to/unrewritten/lib
BUX_UPDATE_BINDINGS=1 cargo check -p bux-krun --features regenerate
```

Requires libclang. Commit `crates/bux-krun/src/bindings.rs`. After assets
exist: `unset BUX_DEPS_DIR` and clean-fetch (below). Same pattern for e2fs
with `BUX_E2FS_DIR` if headers moved.

## Tag the PR SHA, then merge

**Never merge-then-tag.** Pin + URL switch in one commit 404s
`ci-rust.yml --workspace` and `e2e-host.yml` (`cargo build -p bux-cli`) until
the Release exists. There is no dual-URL bridge. That 404 is a PR-branch
problem until assets land; it must never be a `main` problem.

Order for **each** native PR (krun / e2fs / bwrap):

1. Land files on the PR branch. Local compile and bindgen use existing blobs
   via `BUX_*_DIR` (unrewritten).
2. Push the PR. Do not expect CI green yet.
3. Tag **that PR SHA**. Tag trigger does not require `main`. The tagged
   commit must already contain the new workflow pins and no `publish-*` job.

   ```bash
   SHA=$(git rev-parse HEAD)
   git tag krun-v1.19.4 "$SHA"
   git push origin krun-v1.19.4
   ```

4. Wait until `gh release view` lists **all** matrix assets (krun/e2fs: three
   tarballs; bwrap: two Linux). Select the native-build run with
   `gh run list --workflow … --commit "$SHA"` and `event==push`. Do not use
   `--limit 1`.
5. `gh run rerun --failed` of failed `pull_request`/`push` CI, then
   `gh run watch --exit-status`. Locally: `unset BUX_*_DIR`; `cargo clean -p …`;
   `cargo build -vv` must log the new URL.
6. Merge **only when `ci` and `e2e-host` are green**. Do not squash-retag.
   Do not move the native tag onto an empty-commit retry SHA.

`workflow_dispatch` on a **branch** is an optional compile dry-run (artifacts
only; `release` job is `if: startsWith(github.ref, 'refs/tags/…')`). It does
not unblock CI. Do not watch a branch dispatch and then `cargo build` as if
the Release existed.

### Wait helper

Do not `gh run list --limit 1`. `--commit "$SHA"` scopes the list; 20×5s
covers a slow enqueue after `git push origin <tag>`.

```bash
# SHA=$(git rev-parse HEAD) on the PR commit that was tagged
# after: git tag krun-v1.19.4 "$SHA" && git push origin krun-v1.19.4
for i in $(seq 1 20); do
  RUN_ID=$(gh run list --repo qntx/bux --workflow krun-build.yml --commit "$SHA" \
    --json databaseId,event \
    --jq '.[] | select(.event=="push") | .databaseId' | head -1)
  [ -n "$RUN_ID" ] && break
  sleep 5
done
if [ -z "$RUN_ID" ]; then
  RUN_ID=$(gh run list --repo qntx/bux --workflow krun-build.yml \
    --json databaseId,headBranch,event \
    --jq '.[] | select(.headBranch=="krun-v1.19.4" and .event=="push") | .databaseId' | head -1)
fi
if [ -z "$RUN_ID" ]; then
  gh workflow run krun-build.yml --ref krun-v1.19.4
  for i in $(seq 1 20); do
    RUN_ID=$(gh run list --repo qntx/bux --workflow krun-build.yml \
      --json databaseId,event,headBranch \
      --jq '.[] | select(.headBranch=="krun-v1.19.4" and .event=="workflow_dispatch") | .databaseId' | head -1)
    [ -n "$RUN_ID" ] && break
    sleep 5
  done
fi
[ -n "$RUN_ID" ]
gh run watch --repo qntx/bux --exit-status "$RUN_ID"
ASSETS=$(gh release view krun-v1.19.4 --repo qntx/bux --json assets --jq '.assets[].name')
echo "$ASSETS"
echo "$ASSETS" | grep -qx 'bux-deps-aarch64-apple-darwin.tar.gz'
echo "$ASSETS" | grep -qx 'bux-deps-x86_64-unknown-linux-gnu.tar.gz'
echo "$ASSETS" | grep -qx 'bux-deps-aarch64-unknown-linux-gnu.tar.gz'
```

Same helper for `e2fs-build.yml` / `e2fs-v1.47.4` (assert
`bux-e2fs-{aarch64-apple-darwin,x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu}.tar.gz`)
and `bwrap-build.yml` / `bwrap-v0.12.0` (assert
`bux-bwrap-{x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu}.tar.gz`).
`event==push` excludes an optional branch `workflow_dispatch` dry-run on the
same SHA.

### Re-run failed PR CI

`ci.yml` and `e2e-host.yml` are `on: pull_request` / `push: branches: [main]`
only — not `workflow_dispatch`. Failed 404 runs stay failed until rerun or a
new head SHA.

```bash
FAILED=$(gh run list --repo qntx/bux --commit "$SHA" \
  --json databaseId,conclusion,event \
  --jq '.[] | select(.conclusion=="failure" and (.event=="pull_request" or .event=="push")) | .databaseId')
for id in $FAILED; do
  gh run rerun --repo qntx/bux "$id" --failed
done
for id in $FAILED; do
  gh run watch --repo qntx/bux --exit-status "$id"
done
```

`gh run watch --exit-status` is the merge gate: both `ci` and `e2e-host` must
exit 0.

If `gh run rerun` is unavailable, empty-commit on the PR branch and watch CI
on the **new** HEAD. Do **not** `git tag -f` / move the native tag onto that
empty commit.

### Local verify after assets exist

```bash
unset BUX_DEPS_DIR BUX_DEPS_VERSION
cargo clean -p bux-krun
cargo build -p bux-krun -vv
# must log:
# bux-krun: downloading https://github.com/qntx/bux/releases/download/krun-v1.19.4/bux-deps-{target}.tar.gz
# Darwin: otool -L target/debug/libkrun.dylib  → current version 1.19.x, not 1.17
cargo build -p bux-cli -p bux-shim-bin
```

Same for e2fs (`e2fs-v1.47.4`). bwrap verify is Linux-only.

## Failure modes

| Failure | What to do |
| --- | --- |
| 404 on PR CI until assets exist | Expected. Tag the PR SHA; wait; `gh run rerun`; never merge-then-tag. Do **not** add a second URL. |
| One matrix leg red (`fail-fast: false`) | `release` `needs: build` already blocks a partial Release. Fix the leg. Do not hand-upload two of three tarballs. |
| Tag exists, assets incomplete | Delete the GitHub Release, fix, new commit. Moving tags is last resort. |
| Watching the wrong GHA run (`--limit 1` / branch dispatch) | `--commit "$SHA"` and `event==push`; assert Release asset names. |
| Darwin `BUX_DEPS_DIR=$PWD/target/debug` after rewrite | Duplicate `LC_RPATH` panic. Use the unrewritten extract. |
| `cargo publish` leftover | Jobs already deleted. Do not restore them. |
| Native tag run never appears in `gh run list --commit` | 20×5s; then tag name; then `gh workflow run --ref <tag>`. Abort if still empty. |

## Guest ELF / FULL

Darwin does not compile musl. FULL needs `BUX_GUEST_PATH` from CD
`workflow_dispatch` or a Linux `aarch64-unknown-linux-musl` /
`x86_64-unknown-linux-musl` build.

This Apple Silicon host (2026-08-26): `kern.hv_support=1`, **no** musl
`bux-guest` ELF. Host CI (`.github/workflows/e2e-host.yml`) forces
`BUX_E2E_FULL=0`. Do not invent a green FULL record. D4 in
[`docs/bux-redesign.md`](bux-redesign.md) stays open until CONTRIBUTING
contains an operator record (OS, arch, date, image digest).
