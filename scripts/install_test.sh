#!/bin/sh
# Host-only tests for install.sh / install.ps1. No live GitHub.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_SH="$ROOT/install.sh"
INSTALL_PS1="$ROOT/install.ps1"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

[ -f "$INSTALL_SH" ] || fail "missing $INSTALL_SH"
[ -f "$INSTALL_PS1" ] || fail "missing $INSTALL_PS1"
command -v python3 >/dev/null 2>&1 || fail "python3 required"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

# Source production helpers. Must be top-level: install.sh `return` would
# otherwise return from a wrapping function.
BUX_INSTALL_SOURCED=1
# shellcheck disable=SC1090
. "$INSTALL_SH"
unset BUX_INSTALL_SOURCED

# Shaped like live 2026-09-04 (21 Releases) plus guest-v0.1.0 so that tag
# cannot win even if it is a non-prerelease.
FIXTURE_JSON="$T/releases-page1.json"
cat >"$FIXTURE_JSON" <<'JSON'
[
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
]
JSON

write_uname() {
    _wu_dir=$1
    _wu_os=$2
    _wu_arch=$3
    mkdir -p "$_wu_dir"
    printf '%s\n' "#!/bin/sh" >"$_wu_dir/uname"
    printf '%s\n' "case \"\$1\" in" >>"$_wu_dir/uname"
    printf '%s\n' "  -s) printf '%s\\n' '$_wu_os' ;;" >>"$_wu_dir/uname"
    printf '%s\n' "  -m) printf '%s\\n' '$_wu_arch' ;;" >>"$_wu_dir/uname"
    printf '%s\n' "  *) printf '%s\\n' '$_wu_arch' ;;" >>"$_wu_dir/uname"
    printf '%s\n' "esac" >>"$_wu_dir/uname"
    chmod 0755 "$_wu_dir/uname"
}

write_sysctl() {
    _ws_dir=$1
    _ws_val=$2
    mkdir -p "$_ws_dir"
    printf '%s\n' "#!/bin/sh" >"$_ws_dir/sysctl"
    printf '%s\n' "if [ \"\$1\" = -n ] && [ \"\$2\" = hw.optional.arm64 ]; then" >>"$_ws_dir/sysctl"
    printf '%s\n' "  printf '%s\\n' '$_ws_val'" >>"$_ws_dir/sysctl"
    printf '%s\n' "  exit 0" >>"$_ws_dir/sysctl"
    printf '%s\n' "fi" >>"$_ws_dir/sysctl"
    printf '%s\n' "exit 1" >>"$_ws_dir/sysctl"
    chmod 0755 "$_ws_dir/sysctl"
}

# Staging dir $1, OS Darwin|Linux, guest triple $3, include_bwrap 0|1, extra name $5.
make_staging() {
    _ms_dir=$1
    _ms_os=$2
    _ms_guest=$3
    _ms_bwrap=$4
    _ms_extra=${5:-}
    rm -rf "$_ms_dir"
    mkdir -p "$_ms_dir"
    printf '%s\n' '#!/bin/sh' 'echo fake-bux' >"$_ms_dir/bux"
    printf '%s\n' '#!/bin/sh' 'echo fake-shim' >"$_ms_dir/bux-shim"
    chmod 0755 "$_ms_dir/bux" "$_ms_dir/bux-shim"
    printf '%s\n' 'guest' >"$_ms_dir/$_ms_guest"
    chmod 0755 "$_ms_dir/$_ms_guest"
    printf '%s\n' 'MIT' >"$_ms_dir/LICENSE-MIT"
    printf '%s\n' 'APACHE' >"$_ms_dir/LICENSE-APACHE"
    if [ "$_ms_os" = Darwin ]; then
        printf '%s\n' 'krun' >"$_ms_dir/libkrun.dylib"
        printf '%s\n' 'krunfw' >"$_ms_dir/libkrunfw.dylib"
        ln -s libkrun.dylib "$_ms_dir/libkrun.1.dylib"
        ln -s libkrunfw.dylib "$_ms_dir/libkrunfw.5.dylib"
    else
        printf '%s\n' 'krun' >"$_ms_dir/libkrun.so"
        printf '%s\n' 'krunfw' >"$_ms_dir/libkrunfw.so"
        ln -s libkrun.so "$_ms_dir/libkrun.so.1"
        ln -s libkrunfw.so "$_ms_dir/libkrunfw.so.5"
        if [ "$_ms_bwrap" = 1 ]; then
            printf '%s\n' '#!/bin/sh' 'echo fake-bwrap' >"$_ms_dir/bwrap"
            chmod 0755 "$_ms_dir/bwrap"
        fi
    fi
    if [ -n "$_ms_extra" ]; then
        printf '%s\n' 'extra' >"$_ms_dir/$_ms_extra"
    fi
}

pack_tar() {
    _pt_src=$1
    _pt_dst=$2
    # Darwin tar otherwise injects AppleDouble ._* members.
    COPYFILE_DISABLE=1 tar czf "$_pt_dst" -C "$_pt_src" .
}

write_sha() {
    _wsh_tar=$1
    _wsh_out=$2
    _wsh_hash=$(
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$_wsh_tar" | awk '{print $1}'
        else
            shasum -a 256 "$_wsh_tar" | awk '{print $1}'
        fi
    )
    _wsh_base=$(basename "$_wsh_tar")
    printf '%s  %s\n' "$_wsh_hash" "$_wsh_base" >"$_wsh_out"
}

# Fake curl: map GitHub URLs onto $T/www. Refuse /releases/latest.
write_curl() {
    _wc_dir=$1
    mkdir -p "$_wc_dir" "$T/www"
    printf '%s\n' "#!/bin/sh" >"$_wc_dir/curl"
    cat >>"$_wc_dir/curl" <<CURL
out=""
url=""
while [ \$# -gt 0 ]; do
    case "\$1" in
        -o) out=\$2; shift 2 ;;
        -A) shift 2 ;;
        -fsSL|-f|-s|-S|-L|-q) shift ;;
        --user-agent) shift 2 ;;
        -O-|-O) shift ;;
        -*) shift ;;
        *) url=\$1; shift ;;
    esac
done
printf '%s\n' "\$url" >>"$T/curl-urls"
case "\$url" in
    */releases/latest*)
        printf '%s\n' "refused /releases/latest: \$url" >&2
        exit 1
        ;;
esac
src=""
case "\$url" in
    *"/releases?per_page=100&page="*)
        page=\${url##*page=}
        page=\${page%%&*}
        src="$T/www/releases-page-\${page}.json"
        ;;
    https://github.com/qntx/bux/releases/download/*)
        src="$T/www/\${url##*/}"
        ;;
    *)
        printf '%s\n' "unexpected url: \$url" >&2
        exit 1
        ;;
esac
if [ ! -f "\$src" ]; then
    printf '%s\n' "missing fixture: \$src (url=\$url)" >&2
    exit 1
fi
if [ -n "\$out" ]; then
    cp "\$src" "\$out"
else
    cat "\$src"
fi
CURL
    chmod 0755 "$_wc_dir/curl"
}

run_install() {
    # `|| return` so set -e does not abort the test shell on expected failures.
    _ri_sh=${INSTALL_UNDER_TEST:-$INSTALL_SH}
    env -i \
        HOME="$HOME" \
        PATH="$PATH" \
        BUX_VERSION="${BUX_VERSION:-}" \
        BUX_INSTALL_DIR="${BUX_INSTALL_DIR:-}" \
        XDG_DATA_HOME="${XDG_DATA_HOME:-}" \
        GITHUB_PATH="${GITHUB_PATH:-}" \
        NO_COLOR=1 \
        DRY_RUN="${DRY_RUN:-}" \
        UNINSTALL="${UNINSTALL:-}" \
        /bin/sh "$_ri_sh" "$@" || return $?
}

# True when inspect rejected ../evil before extract (dest unchanged, no sibling evil).
dotdot_rejected() {
    _dd_err=$1
    _dd_pkg=$2
    _dd_dest=$3
    grep -q 'illegal archive path' "$_dd_err" || return 1
    grep -q '\.\./evil' "$_dd_err" || return 1
    [ -e "$_dd_pkg/evil" ] && return 1
    grep -q first "$_dd_dest/bux" || return 1
    return 0
}

# --- parser ---

st=0
got=$(parse_product_tag <"$FIXTURE_JSON") || st=$?
[ "$st" = 0 ] || fail "fixture parser exit $st"
[ "$got" = "0.4.1" ] || fail "fixture first hit want 0.4.1 got $got"

python3 - "$FIXTURE_JSON" <<'PY' || fail "guest/krun tags must be present in fixture"
import json, sys
tags = [r["tag_name"] for r in json.load(open(sys.argv[1]))]
for t in (
    "guest-fc094be148bcfc7f3ef50d5e4805a8505afc04ba",
    "guest-v0.1.0",
    "krun-v1.19.4",
):
    if t not in tags:
        sys.exit(1)
if tags[0].startswith("v"):
    sys.exit(1)
PY

st=0
got=$(printf '%s' '[]' | parse_product_tag) || st=$?
[ "$st" = 3 ] || fail "empty page want exit 3 got $st"

st=0
got=$(printf '%s' '[{"tag_name":"guest-v0.1.0","draft":false,"prerelease":false},{"tag_name":"krun-v1.19.4","draft":false,"prerelease":false}]' | parse_product_tag) || st=$?
[ "$st" = 2 ] || fail "guest/krun-only page want exit 2 got $st"

st=0
got=$(printf '%s' '[{"tag_name":"v9.9.9","draft":true,"prerelease":false},{"tag_name":"v8.8.8","draft":false,"prerelease":true},{"tag_name":"v0.4.1","draft":false,"prerelease":false}]' | parse_product_tag) || st=$?
[ "$st" = 0 ] && [ "$got" = "0.4.1" ] || fail "draft/prerelease skipped, want 0.4.1 got st=$st val=$got"

# Comments may mention /releases/latest as forbidden; the HTTP URL must not.
if grep -E 'https://api.github.com/repos/[^[:space:]]+/releases/latest' "$INSTALL_SH"; then
    fail "install.sh must not call /releases/latest"
fi
if grep -E 'https://api.github.com/repos/[^[:space:]]+/tags' "$INSTALL_SH"; then
    fail "install.sh must not use /tags"
fi

# Pagination: page 1 has no product tag; page 2 has v0.4.1.
mkdir -p "$T/bin-page"
write_curl "$T/bin-page"
printf '%s\n' '[{"tag_name":"guest-fc094be148bcfc7f3ef50d5e4805a8505afc04ba","draft":false,"prerelease":false},{"tag_name":"krun-v1.19.4","draft":false,"prerelease":false}]' >"$T/www/releases-page-1.json"
cp "$FIXTURE_JSON" "$T/www/releases-page-2.json"
printf '%s\n' '[]' >"$T/www/releases-page-3.json"
PATH="$T/bin-page:$PATH"
st=0
got=$(latest) || st=$?
[ "$st" = 0 ] && [ "$got" = "0.4.1" ] || fail "paginated latest want 0.4.1 got st=$st val=$got"
grep -q 'releases/latest' "$T/curl-urls" && fail "latest() fetched /releases/latest"
grep -q 'page=1' "$T/curl-urls" || fail "latest() did not fetch page=1"
grep -q 'page=2' "$T/curl-urls" || fail "latest() did not fetch page=2"
# Restore PATH after pagination (keep later stubs isolated).
PATH=$(printf '%s' "$PATH" | sed "s|^$T/bin-page:||")

# --- host_target ---

native=$(host_target)
case "$native" in
    x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu | aarch64-apple-darwin) ;;
    *-unknown-linux-musl) fail "host_target must never be musl: $native" ;;
    *) fail "host_target not a CD matrix member: $native" ;;
esac

mkdir -p "$T/ht"
write_uname "$T/ht" Linux x86_64
got=$(PATH="$T/ht:$PATH" host_target)
[ "$got" = "x86_64-unknown-linux-gnu" ] || fail "Linux x86_64 want gnu got $got"

write_uname "$T/ht" Linux aarch64
got=$(PATH="$T/ht:$PATH" host_target)
[ "$got" = "aarch64-unknown-linux-gnu" ] || fail "Linux aarch64 want gnu got $got"

write_uname "$T/ht" Darwin arm64
got=$(PATH="$T/ht:$PATH" host_target)
[ "$got" = "aarch64-apple-darwin" ] || fail "Darwin arm64 want apple-darwin got $got"

write_uname "$T/ht" Darwin x86_64
write_sysctl "$T/ht" 1
got=$(PATH="$T/ht:$PATH" host_target)
[ "$got" = "aarch64-apple-darwin" ] || fail "Rosetta want aarch64-apple-darwin got $got"

write_sysctl "$T/ht" 0
st=0
got=$(PATH="$T/ht:$PATH" host_target 2>"$T/ht.err") || st=$?
[ "$st" != 0 ] || fail "Intel Mac must err"
grep -q 'Intel Mac' "$T/ht.err" || fail "Intel Mac error message missing"

# --- Darwin payload path contains a space ---

HOME="$T/darwin-home"
mkdir -p "$HOME"
BINDIR="$T/darwin-bin"
mkdir -p "$BINDIR" "$T/www"
write_uname "$BINDIR" Darwin arm64
write_curl "$BINDIR"
make_staging "$T/stage-darwin" Darwin bux-guest-aarch64-unknown-linux-musl 0
pack_tar "$T/stage-darwin" "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz"
write_sha "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz" "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz.sha256"

export HOME
export BUX_VERSION=9.9.9
export BUX_INSTALL_DIR="$T/darwin-bindir"
mkdir -p "$BUX_INSTALL_DIR"
PATH="$BINDIR:$PATH"
run_install

pkg="$HOME/Library/Application Support/bux-pkg"
case "$pkg" in
    *" "*) ;;
    *) fail "Darwin payload path must contain a space: $pkg" ;;
esac
dest="$pkg/9.9.9-aarch64-apple-darwin"
[ -d "$dest" ] || fail "missing payload dest $dest"
[ -f "$dest/bux" ] || fail "missing payload bux"
[ -L "$BUX_INSTALL_DIR/bux" ] || fail "missing symlink $BUX_INSTALL_DIR/bux"
link=$(readlink "$BUX_INSTALL_DIR/bux")
[ "$link" = "$dest/bux" ] || fail "symlink want $dest/bux got $link"
[ ! -e "$pkg/current" ] && [ ! -L "$pkg/current" ] || fail "must not create bux-pkg/current"
[ -L "$dest/libkrunfw.5.dylib" ] || fail "tar symlink libkrunfw.5.dylib not preserved"
symtgt=$(readlink "$dest/libkrunfw.5.dylib")
[ "$symtgt" = "libkrunfw.dylib" ] || fail "symlink target want libkrunfw.dylib got $symtgt"
mode=$(python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "$pkg")
[ "$mode" = "0o700" ] || fail "bux-pkg mode want 0700 got $mode"
dev_pkg=$(python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_dev)' "$pkg")
dev_dest=$(python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_dev)' "$dest")
[ "$dev_pkg" = "$dev_dest" ] || fail "extract dest must share st_dev with bux-pkg"
case "$dest" in
    "$pkg"/*) ;;
    *) fail "extract dest is not a child of bux-pkg: $dest" ;;
esac

# path_safe applies only to BUX_INSTALL_DIR (space rejected), not payload.
# Prefix assignment on an exported var persists in this shell; restore after.
_saved_bindir=$BUX_INSTALL_DIR
st=0
BUX_INSTALL_DIR="$T/Application Support/bin"
run_install 2>"$T/path_safe.err" || st=$?
BUX_INSTALL_DIR="$_saved_bindir"
export BUX_INSTALL_DIR
[ "$st" != 0 ] || fail "BUX_INSTALL_DIR with a space must be rejected"
grep -q 'unsafe characters' "$T/path_safe.err" || fail "path_safe error missing"

# Uninstall must not wipe BUX_HOME or the sibling runtime data dir.
export BUX_HOME="$HOME/explicit-bux-home"
mkdir -p "$BUX_HOME" "$HOME/Library/Application Support/bux"
printf '%s\n' stay-home >"$BUX_HOME/marker"
printf '%s\n' stay-data >"$HOME/Library/Application Support/bux/db"
run_install --uninstall
[ -L "$BUX_INSTALL_DIR/bux" ] && fail "symlink still present after uninstall"
[ -e "$pkg" ] && fail "bux-pkg still present after uninstall"
[ -f "$BUX_HOME/marker" ] || fail "uninstall wiped BUX_HOME"
[ -f "$HOME/Library/Application Support/bux/db" ] || fail "uninstall wiped runtime data dir"
unset BUX_HOME

# --- checksum mismatch must not replace dest ---

HOME="$T/cksum-home"
mkdir -p "$HOME" "$T/cksum-bindir"
export HOME
export BUX_INSTALL_DIR="$T/cksum-bindir"
make_staging "$T/stage-ck" Darwin bux-guest-aarch64-unknown-linux-musl 0
printf '%s\n' 'first' >"$T/stage-ck/bux"
chmod 0755 "$T/stage-ck/bux"
pack_tar "$T/stage-ck" "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz"
write_sha "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz" "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz.sha256"
run_install
pkg="$HOME/Library/Application Support/bux-pkg"
dest="$pkg/9.9.9-aarch64-apple-darwin"
grep -q first "$dest/bux" || fail "first payload missing"

printf '%s\n' 'second' >"$T/stage-ck/bux"
chmod 0755 "$T/stage-ck/bux"
pack_tar "$T/stage-ck" "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz"
printf '%s  %s\n' "0000000000000000000000000000000000000000000000000000000000000000" "bux-9.9.9-aarch64-apple-darwin.tar.gz" >"$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz.sha256"
st=0
run_install 2>"$T/cksum.err" || st=$?
[ "$st" != 0 ] || fail "checksum mismatch must err"
grep -q 'checksum mismatch' "$T/cksum.err" || fail "checksum mismatch message missing"
grep -q first "$dest/bux" || fail "checksum mismatch replaced dest"
grep -q second "$dest/bux" && fail "checksum mismatch installed the new payload"

# --- extra archive member rejected; dest not replaced ---

write_sha "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz" "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz.sha256"
make_staging "$T/stage-extra" Darwin bux-guest-aarch64-unknown-linux-musl 0 evil
printf '%s\n' 'first' >"$T/stage-ck/bux"
# dest still has 'first'; extra tarball should fail allowlist
pack_tar "$T/stage-extra" "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz"
write_sha "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz" "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz.sha256"
st=0
run_install 2>"$T/extra.err" || st=$?
[ "$st" != 0 ] || fail "extra member must err"
grep -q 'unexpected archive member' "$T/extra.err" || fail "extra member message missing"
grep -q first "$dest/bux" || fail "extra member replaced dest"

# --- path traversal rejected before extract ---

python3 - "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz" <<'PY'
import tarfile, io, sys
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tf:
    info = tarfile.TarInfo("../evil")
    data = b"x"
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))
open(sys.argv[1], "wb").write(buf.getvalue())
PY
write_sha "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz" "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz.sha256"
st=0
run_install 2>"$T/dotdot.err" || st=$?
[ "$st" != 0 ] || fail "dotdot member must err"
dotdot_rejected "$T/dotdot.err" "$pkg" "$dest" || fail "inspect must reject ../evil before extract (no $pkg/evil)"

# Stub inspect_archive: the same assertions must fail (otherwise they are not load-bearing).
awk '
    /^inspect_archive\(\) \{/ {
        print
        print "    return 0"
        skip=1
        next
    }
    skip && /^}/ { print; skip=0; next }
    skip { next }
    { print }
' "$INSTALL_SH" >"$T/install.stub.sh"
grep -q 'illegal archive path' "$INSTALL_SH" || fail "production inspect_archive missing"
if grep -q 'illegal archive path' "$T/install.stub.sh"; then
    fail "awk did not stub inspect_archive"
fi
INSTALL_UNDER_TEST="$T/install.stub.sh"
st=0
run_install 2>"$T/dotdot.stub.err" || st=$?
unset INSTALL_UNDER_TEST
if dotdot_rejected "$T/dotdot.stub.err" "$pkg" "$dest"; then
    fail "inspect_archive stubbed to return 0 must fail traversal assertions"
fi
grep -q 'illegal archive path' "$T/dotdot.stub.err" && fail "stubbed inspect_archive still emitted inspect error"
rm -f "$pkg/evil"
rm -rf "$pkg/9.9.9-aarch64-apple-darwin.new"

# AppleDouble ._* (Darwin CD without COPYFILE_DISABLE) stays rejected.
make_staging "$T/stage-ad" Darwin bux-guest-aarch64-unknown-linux-musl 0
printf '%s\n' 'first' >"$T/stage-ad/bux"
chmod 0755 "$T/stage-ad/bux"
pack_tar "$T/stage-ad" "$T/www/valid-ad.tar.gz"
python3 - "$T/www/valid-ad.tar.gz" "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz" <<'PY'
import io, sys, tarfile
src, dst = sys.argv[1], sys.argv[2]
with tarfile.open(src, "r:gz") as inn, tarfile.open(dst, "w:gz") as out:
    for m in inn.getmembers():
        f = inn.extractfile(m) if m.isfile() else None
        out.addfile(m, f)
    info = tarfile.TarInfo("._bux")
    data = b"appledouble"
    info.size = len(data)
    out.addfile(info, io.BytesIO(data))
PY
write_sha "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz" "$T/www/bux-9.9.9-aarch64-apple-darwin.tar.gz.sha256"
st=0
run_install 2>"$T/appledouble.err" || st=$?
[ "$st" != 0 ] || fail "._bux member must err"
grep -q 'unexpected archive member' "$T/appledouble.err" || fail "._bux message missing"
grep -q '\._bux' "$T/appledouble.err" || fail "._bux not named in error"
grep -q first "$dest/bux" || fail "._bux member replaced dest"

# --- Linux bwrap required ---

HOME="$T/linux-home"
mkdir -p "$HOME" "$T/linux-bindir" "$T/linux-bin"
write_uname "$T/linux-bin" Linux aarch64
write_curl "$T/linux-bin"
export HOME
export BUX_INSTALL_DIR="$T/linux-bindir"
export XDG_DATA_HOME="$HOME/share"
PATH="$T/linux-bin:$PATH"

make_staging "$T/stage-linux-nobwrap" Linux bux-guest-aarch64-unknown-linux-musl 0
pack_tar "$T/stage-linux-nobwrap" "$T/www/bux-9.9.9-aarch64-unknown-linux-gnu.tar.gz"
write_sha "$T/www/bux-9.9.9-aarch64-unknown-linux-gnu.tar.gz" "$T/www/bux-9.9.9-aarch64-unknown-linux-gnu.tar.gz.sha256"
st=0
run_install 2>"$T/nobwrap.err" || st=$?
[ "$st" != 0 ] || fail "Linux tarball without bwrap must err"
grep -q 'no Linux bwrap in v9.9.9' "$T/nobwrap.err" || fail "missing bwrap error text"
[ -L "$BUX_INSTALL_DIR/bux" ] && fail "must not symlink a jailer-broken tree"
[ -d "$XDG_DATA_HOME/bux-pkg/9.9.9-aarch64-unknown-linux-gnu" ] && fail "must not leave Linux dest without bwrap"

make_staging "$T/stage-linux" Linux bux-guest-aarch64-unknown-linux-musl 1
pack_tar "$T/stage-linux" "$T/www/bux-9.9.9-aarch64-unknown-linux-gnu.tar.gz"
write_sha "$T/www/bux-9.9.9-aarch64-unknown-linux-gnu.tar.gz" "$T/www/bux-9.9.9-aarch64-unknown-linux-gnu.tar.gz.sha256"
run_install
ldest="$XDG_DATA_HOME/bux-pkg/9.9.9-aarch64-unknown-linux-gnu"
[ -f "$ldest/bwrap" ] || fail "Linux payload missing bwrap"
[ -L "$ldest/libkrunfw.so.5" ] || fail "Linux tar symlink not preserved"
[ -L "$BUX_INSTALL_DIR/bux" ] || fail "Linux symlink missing"
[ ! -e "$XDG_DATA_HOME/bux-pkg/current" ] || fail "Linux created bux-pkg/current"

# --- install.ps1 refuses Windows ---

grep -q 'does not support Windows' "$INSTALL_PS1" || fail "install.ps1 missing refusal text"
grep -q 'exit 1' "$INSTALL_PS1" || fail "install.ps1 must exit 1"
if grep -qi 'Invoke-WebRequest' "$INSTALL_PS1"; then
    fail "install.ps1 must not download"
fi
if command -v pwsh >/dev/null 2>&1; then
    st=0
    pwsh -File "$INSTALL_PS1" >/dev/null 2>&1 || st=$?
    [ "$st" = 1 ] || fail "pwsh install.ps1 want exit 1 got $st"
fi

# --- help documents python3 ---

help=$(/bin/sh "$INSTALL_SH" --help)
printf '%s\n' "$help" | grep -q 'python3' || fail "--help must document python3"
printf '%s\n' "$help" | grep -q 'releases/latest' || fail "--help must mention that /releases/latest is not used"

printf 'ok\n'
