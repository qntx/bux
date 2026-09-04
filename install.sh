#!/bin/sh
# Installer for bux. Served verbatim at https://sh.qntx.org/bux.
#
# Usage:
#   curl -fsSL https://sh.qntx.org/bux | sh
#   curl -fsSL https://sh.qntx.org/bux | sh -s -- --uninstall
#   curl -fsSL https://sh.qntx.org/bux | sh -s -- --dry-run
#   curl -fsSL https://sh.qntx.org/bux | sh -s -- --help
#
# Environment:
#   BUX_VERSION      Pin a version (default: newest GitHub product tag ^v[0-9])
#   BUX_INSTALL_DIR  Symlink directory (default: $HOME/.local/bin; absolute, path_safe)
#   UNINSTALL=1      Same as --uninstall
#   DRY_RUN=1        Same as --dry-run
#   HELP=1           Same as --help
#   NO_COLOR         Disable color output
#   GITHUB_PATH      If set (GitHub Actions), append install dir and skip shell rc PATH
#
# python3 is required (product-tag parser and archive allowlist).
# Never uses /releases/latest: that tag is a guest-* / native build, not the product.
#
# POSIX sh has no `local`. Every function MUST use unique prefixed names for
# temporaries so helpers never clobber callers.

set -eu

REPO="qntx/bux"
BIN="bux"
UP="BUX"

if [ -z "${HOME:-}" ]; then
    printf '%s\n' "error: HOME is unset" >&2
    exit 1
fi

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    B=$(printf '\033[1m')
    R=$(printf '\033[31m')
    N=$(printf '\033[0m')
else
    B=''
    R=''
    N=''
fi

say()  { printf '%s%s%s\n' "$B" "$*" "$N"; }
err()  { printf '%serror%s: %s\n' "$R" "$N" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# True if $1 looks like a safe release version (no path / shell metacharacters).
# Accepts: 1, 1.2.3, 1.2.3-beta.1 (caller strips leading v).
version_ok() {
    # shellcheck disable=SC2254
    case "$1" in
        '' | *[' /\\'!@#$%^\&*\(\)+=\[\]\{\}\;\:\'\"\\\|\,\?\*]* | *..* ) return 1 ;;
        [0-9] | [0-9][0-9A-Za-z._-]* ) return 0 ;;
        *) return 1 ;;
    esac
}

absolute_path() {
    case "$1" in
        /*) return 0 ;;
        *) return 1 ;;
    esac
}

# True if $1 is safe to embed in shell rc / fish conf (reject injection vectors).
# Absolute, no "..", no "//", only [A-Za-z0-9/._+-].
# Applied only to BUX_INSTALL_DIR — Darwin payload contains a space.
path_safe() {
    case "$1" in
        /*) ;;
        *) return 1 ;;
    esac
    case "$1" in
        *//* | *..* ) return 1 ;;
    esac
    # shellcheck disable=SC2254
    case "$1" in
        *[!A-Za-z0-9/._+-]* ) return 1 ;;
    esac
    return 0
}

# HTTP GET with 3 attempts and exponential backoff.
# $1=url, $2=outfile (empty for stdout).
http() {
    _http_url=$1
    _http_out=${2:-}
    _http_i=1
    _http_delay=1
    while :; do
        if have curl; then
            if [ -n "$_http_out" ]; then
                curl -fsSL -A "$BIN-installer" -o "$_http_out" "$_http_url" && return 0
            else
                curl -fsSL -A "$BIN-installer" "$_http_url" && return 0
            fi
        elif have wget; then
            if [ -n "$_http_out" ]; then
                wget -q --user-agent="$BIN-installer" -O "$_http_out" "$_http_url" && return 0
            else
                wget -q --user-agent="$BIN-installer" -O- "$_http_url" && return 0
            fi
        else
            err "curl or wget is required"
        fi
        [ "$_http_i" -ge 3 ] && return 1
        sleep "$_http_delay"
        _http_i=$((_http_i + 1))
        _http_delay=$((_http_delay * 2))
    done
}

# Closed CD-matrix map. Musl host and Intel Mac are errors, not a 404 tarball.
host_target() {
    _ht_os=$(uname -s)
    _ht_arch=$(uname -m)
    case "$_ht_os" in
        Linux)
            for _ht_p in /lib /lib64 /usr/lib; do
                # shellcheck disable=SC2086
                ls "$_ht_p"/ld-musl-* >/dev/null 2>&1 && {
                    err "unsupported host: musl libc (bux ships *-unknown-linux-gnu only)"
                }
            done
            case "$_ht_arch" in
                x86_64 | amd64) printf '%s\n' "x86_64-unknown-linux-gnu" ;;
                aarch64 | arm64) printf '%s\n' "aarch64-unknown-linux-gnu" ;;
                *) err "unsupported architecture: $_ht_arch" ;;
            esac
            ;;
        Darwin)
            if [ "$_ht_arch" = x86_64 ] \
                && sysctl -n hw.optional.arm64 2>/dev/null | grep -q 1; then
                _ht_arch=aarch64
            fi
            case "$_ht_arch" in
                aarch64 | arm64) printf '%s\n' "aarch64-apple-darwin" ;;
                x86_64 | amd64)
                    err "unsupported host: Intel Mac (x86_64-apple-darwin is not shipped)"
                    ;;
                *) err "unsupported architecture: $_ht_arch" ;;
            esac
            ;;
        *) err "unsupported OS: $_ht_os" ;;
    esac
}

# dirs::data_dir()/bux-pkg. Not path_safe: Darwin "Application Support" has a space.
payload_root() {
    _pr_os=$(uname -s)
    case "$_pr_os" in
        Linux)
            printf '%s\n' "${XDG_DATA_HOME:-$HOME/.local/share}/bux-pkg"
            ;;
        Darwin)
            printf '%s\n' "$HOME/Library/Application Support/bux-pkg"
            ;;
        *) err "unsupported OS: $_pr_os" ;;
    esac
}

guest_triple() {
    _gt_target=$(host_target)
    case "$_gt_target" in
        x86_64-*) printf '%s\n' "x86_64-unknown-linux-musl" ;;
        aarch64-*) printf '%s\n' "aarch64-unknown-linux-musl" ;;
        *) err "unsupported target: $_gt_target" ;;
    esac
}

# Completeness names ∪ LICENSE-*. Space-separated, no spaces in names.
payload_allowlist() {
    _pa_os=$(uname -s)
    _pa_guest=$(guest_triple)
    _pa_names="bux bux-shim bux-guest-$_pa_guest LICENSE-MIT LICENSE-APACHE"
    case "$_pa_os" in
        Linux)
            printf '%s\n' "$_pa_names libkrun.so libkrun.so.1 libkrunfw.so libkrunfw.so.5 bwrap"
            ;;
        Darwin)
            printf '%s\n' "$_pa_names libkrun.dylib libkrun.1.dylib libkrunfw.dylib libkrunfw.5.dylib"
            ;;
        *) err "unsupported OS: $_pa_os" ;;
    esac
}

# stdin: one /releases page (JSON array). stdout: version without v.
# exit 0 = hit, 2 = no hit on this page, 3 = empty page (stop pagination).
parse_product_tag() {
    have python3 || err "python3 is required to select the latest bux release"
    python3 -c '
import json, re, sys
page = json.load(sys.stdin)
if not isinstance(page, list):
    sys.exit(1)
if page == []:
    sys.exit(3)
for r in page:
    if r.get("draft") or r.get("prerelease"):
        continue
    tag = r.get("tag_name") or ""
    if re.match(r"^v[0-9]", tag) and not tag.startswith(
        ("guest-v", "krun-v", "e2fs-v", "bwrap-v")
    ):
        print(tag[1:] if tag.startswith("v") else tag)
        sys.exit(0)
sys.exit(2)
'
}

# Newest non-draft, non-prerelease GitHub Release whose tag matches ^v[0-9].
# Paginates /releases — never /releases/latest (that is a guest-* tag).
latest() {
    have python3 || err "python3 is required to select the latest bux release"
    _lat_page=1
    while :; do
        _lat_json=$(http "https://api.github.com/repos/$REPO/releases?per_page=100&page=$_lat_page") \
            || err "failed to fetch releases (network error or rate limited)"
        _lat_st=0
        _lat_ver=$(printf '%s' "$_lat_json" | parse_product_tag) || _lat_st=$?
        if [ "$_lat_st" -eq 0 ]; then
            version_ok "$_lat_ver" || err "refusing unsafe version from GitHub: $_lat_ver"
            printf '%s\n' "$_lat_ver"
            return 0
        fi
        if [ "$_lat_st" -eq 3 ]; then
            err "no product release found (tag matching ^v[0-9])"
        fi
        if [ "$_lat_st" -eq 2 ]; then
            _lat_page=$((_lat_page + 1))
            continue
        fi
        err "failed to parse GitHub releases page $_lat_page"
    done
}

sha256_file() {
    _s256_path=$1
    if have sha256sum; then
        sha256sum "$_s256_path" | awk '{print $1}'
    elif have shasum; then
        shasum -a 256 "$_s256_path" | awk '{print $1}'
    else
        have python3 || err "python3 is required to hash the archive"
        python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$_s256_path"
    fi
}

# Reject .., absolute paths, extra names, PaxHeader; allow relative same-dir symlinks.
inspect_archive() {
    _ia_tar=$1
    shift
    have python3 || err "python3 is required to select the latest bux release"
    python3 - "$_ia_tar" "$@" <<'PY'
import sys
import tarfile

archive = sys.argv[1]
allow = set(sys.argv[2:])


def norm(name):
    n = name.replace("\\", "/")
    while n.startswith("./"):
        n = n[2:]
    if n.endswith("/"):
        n = n[:-1]
    return n


try:
    tf = tarfile.open(archive, "r:gz")
except (tarfile.TarError, OSError) as e:
    sys.stderr.write("invalid tar.gz: %s\n" % e)
    sys.exit(1)

with tf:
    for m in tf.getmembers():
        n = norm(m.name)
        if n in ("", "."):
            if m.isdir():
                continue
            sys.stderr.write("invalid archive member: %r\n" % (m.name,))
            sys.exit(1)
        parts = n.split("/")
        if (not n) or n.startswith("/") or ".." in parts or len(parts) != 1:
            sys.stderr.write("illegal archive path: %r\n" % (m.name,))
            sys.exit(1)
        if n == "PaxHeader" or n.startswith("PaxHeader."):
            sys.stderr.write("unexpected archive member: %s\n" % n)
            sys.exit(1)
        if n not in allow:
            sys.stderr.write("unexpected archive member: %s\n" % n)
            sys.exit(1)
        if m.isdir():
            sys.stderr.write("unexpected directory in archive: %s\n" % n)
            sys.exit(1)
        if m.issym() or m.islnk():
            t = norm(m.linkname)
            tparts = t.split("/")
            if (not t) or t.startswith("/") or ".." in tparts or len(tparts) != 1:
                sys.stderr.write("illegal link target: %r -> %r\n" % (n, m.linkname))
                sys.exit(1)
            if t not in allow:
                sys.stderr.write("link target not allowlisted: %s -> %s\n" % (n, t))
                sys.exit(1)
        elif not m.isfile():
            sys.stderr.write("unsupported archive member type: %s\n" % n)
            sys.exit(1)
sys.exit(0)
PY
}

_ve_need_reg() {
    _nr_path=$1
    [ -f "$_nr_path" ] && [ ! -L "$_nr_path" ] || err "missing regular file: $_nr_path"
}

_ve_need_any() {
    _na_path=$1
    if [ -L "$_na_path" ]; then
        _na_t=$(readlink "$_na_path")
        case "$_na_t" in
            '' | /* | *'/'* | .. | ../* | */.. | */../* )
                err "illegal symlink target for $_na_path: $_na_t"
                ;;
        esac
        [ -e "$(dirname "$_na_path")/$_na_t" ] || err "broken symlink: $_na_path"
        return 0
    fi
    [ -f "$_na_path" ] || err "missing file: $_na_path"
}

# After extract, before rename over the live dest.
verify_extracted() {
    _ve_dir=$1
    _ve_ver=$2
    _ve_os=$(uname -s)
    _ve_guest=$(guest_triple)
    _ve_allow=$(payload_allowlist)

    if [ "$_ve_os" = Linux ]; then
        if [ ! -f "$_ve_dir/bwrap" ] || [ -L "$_ve_dir/bwrap" ]; then
            err "no Linux bwrap in v$_ve_ver; wait for a product release that includes it, or set BUX_VERSION=…"
        fi
    fi

    _ve_need_reg "$_ve_dir/bux"
    _ve_need_reg "$_ve_dir/bux-shim"
    _ve_need_reg "$_ve_dir/bux-guest-$_ve_guest"
    case "$_ve_os" in
        Linux)
            _ve_need_reg "$_ve_dir/libkrun.so"
            _ve_need_reg "$_ve_dir/libkrunfw.so"
            _ve_need_any "$_ve_dir/libkrun.so.1"
            _ve_need_any "$_ve_dir/libkrunfw.so.5"
            _ve_need_reg "$_ve_dir/bwrap"
            ;;
        Darwin)
            _ve_need_reg "$_ve_dir/libkrun.dylib"
            _ve_need_reg "$_ve_dir/libkrunfw.dylib"
            _ve_need_any "$_ve_dir/libkrun.1.dylib"
            _ve_need_any "$_ve_dir/libkrunfw.5.dylib"
            ;;
        *) err "unsupported OS: $_ve_os" ;;
    esac

    for _ve_p in "$_ve_dir"/*; do
        if [ ! -e "$_ve_p" ] && [ ! -L "$_ve_p" ]; then
            continue
        fi
        _ve_n=$(basename "$_ve_p")
        if [ -d "$_ve_p" ] && [ ! -L "$_ve_p" ]; then
            err "unexpected directory in archive: $_ve_n"
        fi
        _ve_hit=0
        for _ve_a in $_ve_allow; do
            if [ "$_ve_n" = "$_ve_a" ]; then
                _ve_hit=1
                break
            fi
        done
        [ "$_ve_hit" = 1 ] || err "unexpected archive member: $_ve_n"
    done
}

# Append absolute $1 to shell rc PATH entries when missing.
add_path() {
    _ap_dir=$1
    path_safe "$_ap_dir" || err "refusing unsafe PATH entry: $_ap_dir"
    case ":$PATH:" in
        *":$_ap_dir:"*) return 0 ;;
    esac
    _ap_line="export PATH=\"$_ap_dir:\$PATH\""
    _ap_touched=0
    for _ap_rc in .zshrc .bashrc .bash_profile .profile; do
        [ -f "$HOME/$_ap_rc" ] || continue
        _ap_touched=1
        grep -qF -- "$_ap_line" "$HOME/$_ap_rc" 2>/dev/null && continue
        printf '\n%s\n' "$_ap_line" >>"$HOME/$_ap_rc"
        say "  added PATH entry to ~/$_ap_rc"
    done
    if [ -d "$HOME/.config/fish" ]; then
        _ap_touched=1
        _ap_fc="$HOME/.config/fish/conf.d/$BIN-path.fish"
        _ap_fish_line=$(printf "fish_add_path -g '%s'" "$_ap_dir")
        mkdir -p "$(dirname "$_ap_fc")"
        if [ ! -f "$_ap_fc" ] || ! grep -qF -- "$_ap_fish_line" "$_ap_fc" 2>/dev/null; then
            printf '%s\n' "$_ap_fish_line" >"$_ap_fc"
            say "  added PATH entry to ~/.config/fish/conf.d/$BIN-path.fish"
        fi
    fi
    if [ "$_ap_touched" -eq 0 ]; then
        printf '%s\n' "$_ap_line" >>"$HOME/.profile"
        say "  created ~/.profile"
    fi
    say "  restart your shell to apply"
}

# Resolve symlink directory: env override or $HOME/.local/bin. Absolute + path_safe.
install_dir() {
    eval "_id_val=\"\${${UP}_INSTALL_DIR:-}\""
    if [ -z "$_id_val" ]; then
        _id_val="$HOME/.local/bin"
    fi
    absolute_path "$_id_val" || err "${UP}_INSTALL_DIR must be an absolute path, got: $_id_val"
    path_safe "$_id_val" || err "${UP}_INSTALL_DIR has unsafe characters (allowed: A-Za-z0-9/._+-): $_id_val"
    printf '%s\n' "$_id_val"
}

install_cli() {
    have python3 || err "python3 is required to select the latest bux release"

    _ic_root=$(install_dir)
    _ic_target=$(host_target)
    _ic_pkg=$(payload_root)
    _ic_guest=$(guest_triple)
    eval "_ic_ver=\"\${${UP}_VERSION:-}\""
    if [ -z "$_ic_ver" ]; then
        _ic_ver=$(latest)
    else
        _ic_ver=${_ic_ver#v}
        version_ok "$_ic_ver" || err "refusing unsafe ${UP}_VERSION: $_ic_ver"
    fi
    _ic_archive="$BIN-$_ic_ver-$_ic_target.tar.gz"
    _ic_url="https://github.com/$REPO/releases/download/v$_ic_ver/$_ic_archive"
    _ic_sha_url="$_ic_url.sha256"
    _ic_dest="$_ic_pkg/$_ic_ver-$_ic_target"
    _ic_new="$_ic_dest.new"
    _ic_link="$_ic_root/$BIN"

    say "Installing $BIN v$_ic_ver ($_ic_target)"
    if [ "$DRY" = 1 ]; then
        say "[dry-run] download: $_ic_url"
        say "[dry-run] checksum: $_ic_sha_url"
        say "[dry-run] payload:  $_ic_dest"
        say "[dry-run] symlink:  $_ic_link -> $_ic_dest/$BIN"
        return 0
    fi

    _ic_tmp=$(mktemp -d)
    # shellcheck disable=SC2064
    trap 'rm -rf "$_ic_tmp" "$_ic_new"' EXIT

    mkdir -p "$_ic_pkg"
    chmod 0700 "$_ic_pkg"

    say "  downloading $_ic_archive"
    http "$_ic_url" "$_ic_tmp/$_ic_archive" || err "failed to download $_ic_url"
    http "$_ic_sha_url" "$_ic_tmp/$_ic_archive.sha256" || err "failed to download $_ic_sha_url"

    _ic_want=$(awk '{print $1; exit}' "$_ic_tmp/$_ic_archive.sha256")
    case "$_ic_want" in
        *[!0-9a-fA-F]* | '' ) err "invalid sha256 file for $_ic_archive" ;;
    esac
    [ "${#_ic_want}" -eq 64 ] || err "invalid sha256 file for $_ic_archive"
    _ic_got=$(sha256_file "$_ic_tmp/$_ic_archive")
    _ic_want_l=$(printf '%s' "$_ic_want" | tr '[:upper:]' '[:lower:]')
    _ic_got_l=$(printf '%s' "$_ic_got" | tr '[:upper:]' '[:lower:]')
    [ "$_ic_want_l" = "$_ic_got_l" ] || err "checksum mismatch for $_ic_archive"

    # Re-read install dir after network I/O (defense in depth).
    _ic_root=$(install_dir)
    _ic_link="$_ic_root/$BIN"

    _ic_allow=$(payload_allowlist)
    # shellcheck disable=SC2086
    inspect_archive "$_ic_tmp/$_ic_archive" $_ic_allow \
        || err "archive failed allowlist check"

    rm -rf "$_ic_new"
    mkdir "$_ic_new"
    chmod 0700 "$_ic_new"

    say "  extracting"
    tar xzf "$_ic_tmp/$_ic_archive" -C "$_ic_new" || err "failed to extract $_ic_archive"
    verify_extracted "$_ic_new" "$_ic_ver"

    chmod 0755 "$_ic_new/bux" "$_ic_new/bux-shim" "$_ic_new/bux-guest-$_ic_guest"
    if [ -f "$_ic_new/bwrap" ] && [ ! -L "$_ic_new/bwrap" ]; then
        chmod 0755 "$_ic_new/bwrap"
    fi

    rm -rf "$_ic_dest"
    mv "$_ic_new" "$_ic_dest"
    chmod 0700 "$_ic_dest"

    mkdir -p "$_ic_root"
    if [ -d "$_ic_link" ] && [ ! -L "$_ic_link" ]; then
        err "$_ic_link exists and is a directory"
    fi
    rm -f "$_ic_link"
    ln -s "$_ic_dest/bux" "$_ic_link"
    say "  installed $_ic_link -> $_ic_dest/bux"

    if [ -n "${GITHUB_PATH:-}" ]; then
        printf '%s\n' "$_ic_root" >>"$GITHUB_PATH"
        say "  appended $_ic_root to GITHUB_PATH"
    else
        add_path "$_ic_root"
    fi
    say ""
    say "$BIN v$_ic_ver installed."

    trap - EXIT
    rm -rf "$_ic_tmp"
}

uninstall_cli() {
    _uc_root=$(install_dir)
    _uc_path="$_uc_root/$BIN"
    _uc_pkg=$(payload_root)
    _uc_fc="$HOME/.config/fish/conf.d/$BIN-path.fish"
    if [ "$DRY" = 1 ]; then
        say "[dry-run] remove: $_uc_path"
        say "[dry-run] remove: $_uc_pkg"
        [ -f "$_uc_fc" ] && say "[dry-run] remove: $_uc_fc"
        say "[dry-run] note: shell rc PATH entries would be left in place"
        say "[dry-run] note: BUX_HOME / runtime data would not be touched"
        return 0
    fi
    if [ -L "$_uc_path" ]; then
        _uc_link=$(readlink "$_uc_path")
        case "$_uc_link" in
            "$_uc_pkg"/*)
                rm -f "$_uc_path"
                say "removed $_uc_path"
                ;;
            *)
                say "leaving $_uc_path (not a bux-pkg symlink)"
                ;;
        esac
    elif [ -f "$_uc_path" ]; then
        rm -f "$_uc_path"
        say "removed $_uc_path"
    else
        say "$_uc_path not found"
    fi
    if [ -e "$_uc_pkg" ] || [ -L "$_uc_pkg" ]; then
        rm -rf "$_uc_pkg"
        say "removed $_uc_pkg"
    else
        say "$_uc_pkg not found"
    fi
    if [ -f "$_uc_fc" ]; then
        rm -f "$_uc_fc"
        say "removed $_uc_fc"
    fi
    say "note: PATH entries in shell rc files were left in place"
    say "note: BUX_HOME / runtime data were not touched"
}

usage() {
    cat <<EOF
Installer for $BIN.

Usage:
  curl -fsSL https://sh.qntx.org/bux | sh                            # install
  curl -fsSL https://sh.qntx.org/bux | sh -s -- --uninstall          # uninstall
  curl -fsSL https://sh.qntx.org/bux | sh -s -- --dry-run            # preview
  curl -fsSL https://sh.qntx.org/bux | sh -s -- --help               # show this help

python3 is required to select the latest product release (paginates
GitHub /releases; this script never uses /releases/latest).

Environment:
  ${UP}_VERSION       Pin a version (default: newest product tag ^v[0-9])
  ${UP}_INSTALL_DIR   Symlink directory (default: \$HOME/.local/bin; absolute, safe chars)
  UNINSTALL=1         Same as --uninstall
  DRY_RUN=1           Same as --dry-run (install and uninstall)
  HELP=1              Same as --help
  NO_COLOR            Disable color output
  GITHUB_PATH         If set, append install dir (GitHub Actions) instead of shell rc

Payload (not BUX_HOME; uninstall does not wipe runtime data):
  Linux:  \${XDG_DATA_HOME:-\$HOME/.local/share}/bux-pkg/<ver>-<target>/
  macOS:  \$HOME/Library/Application Support/bux-pkg/<ver>-<target>/
EOF
}

ACT=install
DRY=0
[ "${UNINSTALL:-0}" = 1 ] && ACT=uninstall
[ "${DRY_RUN:-0}" = 1 ] && DRY=1
[ "${HELP:-0}" = 1 ] && { usage; exit 0; }

if [ "${BUX_INSTALL_SOURCED:-}" = 1 ]; then
    return 0
fi

for _arg in "$@"; do
    case "$_arg" in
        -h | --help) usage; exit 0 ;;
        --uninstall) ACT=uninstall ;;
        --dry-run) DRY=1 ;;
        *) err "unknown argument: $_arg" ;;
    esac
done

case "$ACT" in
    install) install_cli ;;
    uninstall) uninstall_cli ;;
    *) err "unknown action: $ACT" ;;
esac
