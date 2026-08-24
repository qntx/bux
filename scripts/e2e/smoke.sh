#!/usr/bin/env bash
# Minimal e2e smoke against a local Runtime.
# Requires: bux + bux-shim on PATH (or built). Full VM tests need KVM/HVF + Linux guest.
#
# BUX_E2E_FULL=1 is a manual HVF/KVM gate (CONTRIBUTING.md). GitHub-hosted CI
# must keep BUX_E2E_FULL=0 — this script never enables FULL by itself.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export BUX_HOME="${BUX_HOME:-$(mktemp -d -t bux-e2e.XXXXXX)}"
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

if ! command -v bux >/dev/null 2>&1; then
  echo "building bux-cli..."
  cargo build -q -p bux-cli -p bux-shim-bin --manifest-path "${ROOT}/Cargo.toml"
  export PATH="${ROOT}/target/debug:${PATH}"
fi

# Resolve libkrun / libkrunfw for the CLI (macOS rpath often points at target/debug).
if [[ "$(uname -s)" == "Darwin" ]]; then
  KRUN_LIB="$(find "${ROOT}/target/debug/build" -path '*/out/lib/libkrun.dylib' 2>/dev/null | head -1 || true)"
  if [[ -n "${KRUN_LIB}" ]]; then
    KRUN_DIR="$(dirname "${KRUN_LIB}")"
    export DYLD_LIBRARY_PATH="${KRUN_DIR}${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
    # Also drop copies next to binary if missing (shim helper does this at runtime).
    for f in libkrun.dylib libkrunfw.dylib libkrun.1.dylib libkrunfw.5.dylib; do
      src="${KRUN_DIR}/${f}"
      dst="${ROOT}/target/debug/${f}"
      if [[ -f "${src}" && ! -e "${dst}" ]]; then
        ln -sf "${src}" "${dst}" 2>/dev/null || cp "${src}" "${dst}" 2>/dev/null || true
      fi
    done
  fi
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
bux create --name "${NAME}" "${IMAGE}"

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
bux create --name "${DENY}" --allow-net 127.0.0.1 "${IMAGE}"
if ! require_wget_fail "${DENY}" 3 "allow_net deny"; then
  bux rm -f "${DENY}" || true
  exit 1
fi
bux rm -f "${DENY}"

PUB="e2e-pub-$(date +%s)"
echo "==> D1 publish ${PUB} (-p 0:80; CLI exits; host TCP must reach guest)"
bux create --name "${PUB}" -p 0:80 "${IMAGE}"
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
bux create --name "${OFF}" --network=disabled "${IMAGE}"
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
bux create --name "${VOL}" -v "${VOL_HOST}:/data" "${IMAGE}"
vol_ls="$(bux exec "${VOL}" -- ls /data)"
echo "${vol_ls}" | grep -q marker
bux rm -f "${VOL}"

# stop / restart / rm of a detach=true VM: each CLI exit must leave the VM as designed.
LIFE="e2e-life-$(date +%s)"
echo "==> detach lifecycle ${LIFE} (stop/restart/rm)"
bux create --name "${LIFE}" "${IMAGE}"
bux exec "${LIFE}" -- echo life-ok
bux stop "${LIFE}"
bux restart "${LIFE}"
bux exec "${LIFE}" -- echo life-restart-ok
bux stop "${LIFE}"
bux rm "${LIFE}"

SEC="e2e-sec-$(date +%s)"
SECRET_VAL="e2e-s3cr3t-n0t-persisted-$$"
echo "==> secrets not in sqlite or guest environ ${SEC}"
bux create --name "${SEC}" --secret "e2e=${SECRET_VAL}@example.com" "${IMAGE}"
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
