#!/usr/bin/env bash
# Minimal e2e smoke against a local Runtime.
# Requires: bux + bux-shim on PATH (or built). Full VM tests need KVM/HVF + Linux guest.
#
# BUX_E2E_FULL=1 is a manual HVF/KVM gate (CONTRIBUTING.md). GitHub-hosted CI
# must keep BUX_E2E_FULL=0 — this script never enables FULL by itself.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export BUX_HOME="${BUX_HOME:-$(mktemp -d /tmp/bux-e2e.XXXXXX)}"
cleanup() {
  # Only touch the temp data dir this script created (name contains bux-e2e).
  if [[ "${BUX_E2E_FULL:-}" == "1" && "${BUX_HOME:-}" == *bux-e2e* ]] \
    && command -v bux >/dev/null 2>&1; then
    bux ps -aq 2>/dev/null | while read -r id; do
      [[ -n "${id}" ]] || continue
      bux rm -f "${id}" >/dev/null 2>&1 || true
    done || true
  fi
  if [[ -n "${BUX_HOME:-}" && "${BUX_HOME}" == *bux-e2e* ]]; then
    rm -rf "${BUX_HOME}"
  fi
}
trap cleanup EXIT

echo "==> BUX_HOME=${BUX_HOME}"

full_guest_fail() {
  echo "FULL requires a static Linux bux-guest ELF (CONTRIBUTING.md)" >&2
  exit 1
}

# Same offsets as crates/bux/src/guest.rs validate_guest_binary (no readelf).
validate_guest_elf() {
  local path="$1"
  local arch="$2"
  python3 - "${path}" "${arch}" <<'PY' || return 1
import struct, sys
path, arch = sys.argv[1], sys.argv[2]
expected = {"x86_64": 0x3E, "aarch64": 0xB7}.get(arch)
if expected is None:
    sys.exit(1)
try:
    data = open(path, "rb").read()
except OSError:
    sys.exit(1)
if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
    sys.exit(1)
machine = struct.unpack_from("<H", data, 18)[0]
if machine != expected:
    sys.exit(1)
e_phoff = struct.unpack_from("<Q", data, 32)[0]
e_phentsize = struct.unpack_from("<H", data, 54)[0]
e_phnum = struct.unpack_from("<H", data, 56)[0]
if e_phoff == 0 or e_phentsize == 0 or e_phnum == 0:
    sys.exit(0)
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    end = off + 4
    if end > len(data):
        break
    p_type = struct.unpack_from("<I", data, off)[0]
    if p_type == 3:
        sys.exit(1)
sys.exit(0)
PY
}

linux_musl_target_present() {
  local triple="$1"
  local sysroot
  if command -v rustup >/dev/null 2>&1 \
    && rustup target list --installed 2>/dev/null | grep -qx "${triple}"; then
    return 0
  fi
  sysroot="$(rustc --print sysroot 2>/dev/null || true)"
  [[ -n "${sysroot}" && -d "${sysroot}/lib/rustlib/${triple}" ]]
}

pin_full_guest() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "FULL requires python3 to validate the guest ELF (CONTRIBUTING.md)" >&2
    exit 1
  fi
  local arch musl_triple guest="" c env_var
  case "$(uname -m)" in
    x86_64|amd64)
      arch=x86_64
      musl_triple=x86_64-unknown-linux-musl
      ;;
    aarch64|arm64)
      arch=aarch64
      musl_triple=aarch64-unknown-linux-musl
      ;;
    *)
      full_guest_fail
      ;;
  esac
  if [[ -n "${BUX_GUEST_PATH:-}" ]]; then
    if [[ ! -f "${BUX_GUEST_PATH}" ]] || ! validate_guest_elf "${BUX_GUEST_PATH}" "${arch}"; then
      full_guest_fail
    fi
    guest="${BUX_GUEST_PATH}"
  else
    for c in \
      "${ROOT}/target/debug/bux-guest-${musl_triple}" \
      "${ROOT}/target/${musl_triple}/debug/bux-guest"
    do
      if [[ -f "${c}" ]] && validate_guest_elf "${c}" "${arch}"; then
        guest="${c}"
        break
      fi
    done
    if [[ -z "${guest}" && "$(uname -s)" == "Linux" ]] \
      && command -v musl-gcc >/dev/null 2>&1 \
      && linux_musl_target_present "${musl_triple}"; then
      echo "building bux-guest (${musl_triple})..."
      env_var="CARGO_TARGET_$(echo "${musl_triple}" | tr '[:lower:]-' '[:upper:]_')_LINKER"
      env "${env_var}=musl-gcc" cargo build -p bux-guest --target "${musl_triple}" \
        --manifest-path "${ROOT}/Cargo.toml"
      mkdir -p "${ROOT}/target/debug"
      cp "${ROOT}/target/${musl_triple}/debug/bux-guest" \
        "${ROOT}/target/debug/bux-guest-${musl_triple}"
      guest="${ROOT}/target/debug/bux-guest-${musl_triple}"
      validate_guest_elf "${guest}" "${arch}" || full_guest_fail
    fi
  fi
  [[ -n "${guest}" && -f "${guest}" ]] || full_guest_fail
  export BUX_GUEST_PATH="${guest}"
}

create_or_dump() {
  if bux create "$@"; then
    return 0
  fi
  echo "==> bux create failed; shim stderr:" >&2
  cat "${BUX_HOME}/socks/"*.stderr >&2 2>/dev/null || true
  return 1
}

if [[ "${BUX_E2E_FULL:-}" == "1" ]]; then
  echo "building bux-cli and bux-shim-bin (FULL pin)..."
  cargo build -p bux-cli -p bux-shim-bin --manifest-path "${ROOT}/Cargo.toml"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    codesign --entitlements "${ROOT}/crates/bux-shim/bux-shim.entitlements" \
      -s - --force "${ROOT}/target/debug/bux-shim"
  fi
  pin_full_guest
  export PATH="${ROOT}/target/debug:${PATH}"
  export BUX_SHIM_PATH="${ROOT}/target/debug/bux-shim"
  test -x "${BUX_SHIM_PATH}"
elif ! command -v bux >/dev/null 2>&1; then
  echo "building bux-cli..."
  cargo build -q -p bux-cli --manifest-path "${ROOT}/Cargo.toml"
  export PATH="${ROOT}/target/debug:${PATH}"
fi

# libkrun is linked by bux-cli via bux-shim; rpath often points at OUT_DIR.
krun_name="libkrun.so"
krun_copies=(libkrun.so libkrunfw.so libkrun.so.1 libkrunfw.so.5)
if [[ "$(uname -s)" == "Darwin" ]]; then
  krun_name="libkrun.dylib"
  krun_copies=(libkrun.dylib libkrunfw.dylib libkrun.1.dylib libkrunfw.5.dylib)
fi
KRUN_LIB="$(find "${ROOT}/target/debug/build" -path "*/out/lib/${krun_name}" 2>/dev/null | head -1 || true)"
if [[ -n "${KRUN_LIB}" ]]; then
  KRUN_DIR="$(dirname "${KRUN_LIB}")"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    export DYLD_LIBRARY_PATH="${KRUN_DIR}${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
  else
    export LD_LIBRARY_PATH="${KRUN_DIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  fi
  for f in "${krun_copies[@]}"; do
    src="${KRUN_DIR}/${f}"
    dst="${ROOT}/target/debug/${f}"
    if [[ -f "${src}" && ! -e "${dst}" ]]; then
      ln -sf "${src}" "${dst}" 2>/dev/null || cp "${src}" "${dst}" 2>/dev/null || true
    fi
  done
fi

echo "==> system info"
bux system info
info_json="$(bux system info --format json)"
echo "${info_json}" | grep -q '"krun_features"'
echo "${info_json}" | grep -q '"isolation_warnings"'
echo "${info_json}" | grep -q '"virtualization"'

echo "==> volume create/list/rm"
bux volume create e2e-vol
bux volume ls
bux volume rm e2e-vol

echo "==> sweep (no-op if no idle policies)"
bux sweep

echo "==> help for new commands"
bux create --help >/dev/null
bux logs --help >/dev/null
bux run --help | grep -q secret
bux system reset --help >/dev/null

if [[ "${BUX_E2E_FULL:-}" != "1" ]]; then
  echo "==> skip full VM e2e (set BUX_E2E_FULL=1 on a local HVF/KVM machine; see CONTRIBUTING.md)"
  echo "OK (host-only smoke)"
  exit 0
fi

# Guest wget body (busybox or GNU). Caller requires a non-empty file for egress.
guest_wget() {
  local target="$1"
  local timeout="${2:-10}"
  bux exec "${target}" -- wget -qO- -T "${timeout}" http://example.com \
    || bux exec "${target}" -- busybox wget -qO- -T "${timeout}" http://example.com
}

# One of WGET_OK / WGET_FAIL / WGET_MISSING. Exec transport errors abort (set -e).
guest_wget_probe() {
  local target="$1"
  local timeout="${2:-10}"
  bux exec "${target}" -- sh -c "
    if command -v wget >/dev/null 2>&1; then
      w() { wget -qO- -T ${timeout} http://example.com; }
    elif command -v busybox >/dev/null 2>&1; then
      w() { busybox wget -qO- -T ${timeout} http://example.com; }
    else
      echo WGET_MISSING
      exit 0
    fi
    if w >/dev/null 2>&1; then
      echo WGET_OK
    else
      echo WGET_FAIL
    fi
  "
}

require_wget_ok() {
  local status
  status="$(guest_wget_probe "$1" "$2")"
  if [[ "${status}" != *WGET_OK* ]]; then
    echo "$3: expected wget success, got ${status:-empty}"
    return 1
  fi
}

require_wget_fail() {
  local status
  status="$(guest_wget_probe "$1" "$2")"
  case "${status}" in
    *WGET_FAIL*) return 0 ;;
    *WGET_OK*)
      echo "$3: wget succeeded"
      return 1
      ;;
    *)
      echo "$3: exec/wget missing (${status:-empty})"
      return 1
      ;;
  esac
}

# Alpine busybox has no httpd; busybox-extras does. httpd without -f daemonizes
# so this exec returns and releases bux.lock. Never background bux exec.
start_guest_port80() {
  local name="$1"
  bux exec "${name}" -- sh -c '
    mkdir -p /tmp/www
    printf "bux-e2e-pub\n" > /tmp/www/index.html
    if ! command -v httpd >/dev/null 2>&1; then
      if ! command -v apk >/dev/null 2>&1; then
        echo "start_guest_port80: no httpd and no apk" >&2
        exit 1
      fi
      apk add --no-cache busybox-extras
    fi
    if command -v httpd >/dev/null 2>&1; then
      httpd -p 80 -h /tmp/www
      exit 0
    fi
    if command -v busybox >/dev/null 2>&1; then
      busybox httpd -p 80 -h /tmp/www
      exit 0
    fi
    echo "start_guest_port80: no daemonizing httpd after install" >&2
    exit 1
  '
}

# Host TCP must carry the guest payload (gvproxy bind alone is not enough).
# Heredoc body must sit inside $(...) — closing ) belongs after PY.
assert_host_reaches_guest() {
  local port="$1"
  local i out py=0
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import socket' >/dev/null 2>&1; then
    py=1
  fi
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    out=""
    if [[ "${py}" == 1 ]]; then
      out="$(python3 - "${port}" 2>/dev/null <<'PY' || true
import socket, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), 2)
s.settimeout(2)
try:
    s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
    chunks = []
    try:
        while True:
            b = s.recv(4096)
            if not b:
                break
            chunks.append(b)
            if b"bux-e2e-pub" in b"".join(chunks):
                break
    except OSError:
        pass
    sys.stdout.buffer.write(b"".join(chunks))
finally:
    s.close()
PY
)"
    elif command -v curl >/dev/null 2>&1; then
      out="$(curl -fsS --max-time 2 "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    elif command -v wget >/dev/null 2>&1; then
      out="$(wget -qO- -T 2 "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    else
      echo "D1 publish failed: need python3, curl, or wget for the host TCP client"
      return 1
    fi
    if [[ "${out}" == *bux-e2e-pub* ]]; then
      echo "==> host TCP ${port} reached guest"
      return 0
    fi
    sleep 0.5
  done
  echo "D1 publish failed: host TCP ${port} did not reach the guest"
  return 1
}

IMAGE="${BUX_E2E_IMAGE:-alpine:latest}"
echo "==> pull ${IMAGE}"
bux pull "${IMAGE}"

# create already detach=true: this CLI process exits; later commands are new processes.
NAME="e2e-t1-$(date +%s)"
echo "==> create ${NAME} (CLI exits; VM must survive)"
create_or_dump --name "${NAME}" "${IMAGE}"

echo "==> exec echo"
bux exec "${NAME}" -- echo e2e-ok

echo "==> egress (unrestricted)"
require_wget_ok "${NAME}" 10 "egress"
guest_wget "${NAME}" 10 >/tmp/bux-e2e-egress.out
test -s /tmp/bux-e2e-egress.out

echo "==> stop/rm ${NAME}"
bux stop "${NAME}"
bux rm "${NAME}"

DENY="e2e-deny-$(date +%s)"
echo "==> allow_net deny ${DENY}"
create_or_dump --name "${DENY}" --allow-net 127.0.0.1 "${IMAGE}"
if ! require_wget_fail "${DENY}" 3 "allow_net deny"; then
  bux rm -f "${DENY}" || true
  exit 1
fi
bux rm -f "${DENY}"

PUB="e2e-pub-$(date +%s)"
echo "==> D1 publish ${PUB} (-p 0:80; CLI exits; host TCP must reach guest)"
create_or_dump --name "${PUB}" -p 0:80 "${IMAGE}"
insp="$(bux inspect "${PUB}")"
echo "${insp}" | grep -E '"bind_addr":[[:space:]]*"0.0.0.0"' >/dev/null
echo "${insp}" | grep -E '"guest":[[:space:]]*80' >/dev/null
host_port="$(printf '%s\n' "${insp}" | sed -n 's/.*"host":[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1)"
if [[ -z "${host_port}" || "${host_port}" == "0" ]]; then
  echo "D1 publish failed: host port is '${host_port}' (want concrete != 0)"
  echo "${insp}"
  bux rm -f "${PUB}" || true
  exit 1
fi
start_guest_port80 "${PUB}"
if ! assert_host_reaches_guest "${host_port}"; then
  echo "${insp}"
  bux rm -f "${PUB}" || true
  exit 1
fi
bux rm -f "${PUB}"

# Offline gate: no TSI and no eth0. Do not assert a dummy NIC.
OFF="e2e-offline-$(date +%s)"
echo "==> offline-no-eth0 ${OFF}"
create_or_dump --name "${OFF}" --network=disabled "${IMAGE}"
if ! require_wget_fail "${OFF}" 3 "offline-no-eth0"; then
  bux rm -f "${OFF}" || true
  exit 1
fi
# Tokenize so exec-dead / missing sysfs cannot look like "no eth0".
off_net="$(bux exec "${OFF}" -- sh -c 'test -d /sys/class/net && echo SYSFS_OK || echo SYSFS_MISSING; test -e /sys/class/net/eth0 && echo HAS_ETH0 || echo NO_ETH0')"
case "${off_net}" in
  *SYSFS_OK*NO_ETH0*) ;;
  *HAS_ETH0*)
    echo "offline-no-eth0 failed: eth0 present (${off_net})"
    bux rm -f "${OFF}" || true
    exit 1
    ;;
  *)
    echo "offline-no-eth0 failed: /sys/class/net missing or exec dead (${off_net:-empty})"
    bux rm -f "${OFF}" || true
    exit 1
    ;;
esac
bux rm -f "${OFF}"

VOL="e2e-vol-$(date +%s)"
VOL_HOST="${BUX_HOME}/vol-src"
mkdir -p "${VOL_HOST}"
printf 'vol-ok\n' > "${VOL_HOST}/marker"
echo "==> volume ${VOL} (${VOL_HOST}:/data)"
create_or_dump --name "${VOL}" -v "${VOL_HOST}:/data" "${IMAGE}"
vol_ls="$(bux exec "${VOL}" -- ls /data)"
echo "${vol_ls}" | grep -q marker
bux rm -f "${VOL}"

# stop / restart / rm of a detach=true VM: each CLI exit must leave the VM as designed.
LIFE="e2e-life-$(date +%s)"
echo "==> detach lifecycle ${LIFE} (stop/restart/rm)"
create_or_dump --name "${LIFE}" "${IMAGE}"
bux exec "${LIFE}" -- echo life-ok
bux stop "${LIFE}"
bux restart "${LIFE}"
bux exec "${LIFE}" -- echo life-restart-ok
bux stop "${LIFE}"
bux rm "${LIFE}"

SEC="e2e-sec-$(date +%s)"
SECRET_VAL="e2e-s3cr3t-n0t-persisted-$$"
echo "==> secrets not in sqlite or guest environ ${SEC}"
create_or_dump --name "${SEC}" --secret "e2e=${SECRET_VAL}@example.com" "${IMAGE}"
if grep -a -F "${SECRET_VAL}" "${BUX_HOME}/bux.db" >/dev/null 2>&1; then
  echo "secrets: value found in bux.db"
  bux rm -f "${SEC}" || true
  exit 1
fi
bux exec "${SEC}" -- cat /proc/1/environ > "${BUX_HOME}/guest-environ.bin"
if grep -a -F "${SECRET_VAL}" "${BUX_HOME}/guest-environ.bin" >/dev/null; then
  echo "secrets: value found in guest /proc/1/environ"
  bux rm -f "${SEC}" || true
  exit 1
fi
bux rm -f "${SEC}"

echo "OK (full e2e)"
