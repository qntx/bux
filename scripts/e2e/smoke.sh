#!/usr/bin/env bash
# Minimal e2e smoke against a local Runtime.
# Requires: bux + bux-shim on PATH (or built). Full VM tests need KVM/HVF + Linux guest.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export BUX_HOME="${BUX_HOME:-$(mktemp -d -t bux-e2e.XXXXXX)}"
cleanup() {
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
  echo "==> skip full VM e2e (set BUX_E2E_FULL=1 on a machine with HVF or KVM)"
  echo "OK (host-only smoke)"
  exit 0
fi

IMAGE="${BUX_E2E_IMAGE:-alpine:latest}"
echo "==> pull ${IMAGE}"
bux pull "${IMAGE}"

NAME="e2e-$(date +%s)"
echo "==> create ${NAME}"
bux create --name "${NAME}" "${IMAGE}"

echo "==> exec echo"
bux exec "${NAME}" -- echo e2e-ok

echo "==> egress (unrestricted)"
bux exec "${NAME}" -- wget -qO- -T 10 http://example.com >/tmp/bux-e2e-egress.out || \
  bux exec "${NAME}" -- busybox wget -qO- -T 10 http://example.com >/tmp/bux-e2e-egress.out
test -s /tmp/bux-e2e-egress.out

echo "==> stop/rm ${NAME}"
bux stop "${NAME}"
bux rm "${NAME}"

DENY="e2e-deny-$(date +%s)"
echo "==> allow_net deny ${DENY}"
bux create --name "${DENY}" --allow-net 127.0.0.1 "${IMAGE}"
if bux exec "${DENY}" -- wget -qO- -T 3 http://example.com; then
  echo "allow_net deny failed: wget succeeded"
  bux rm -f "${DENY}" || true
  exit 1
fi
bux rm -f "${DENY}"

PUB="e2e-pub-$(date +%s)"
echo "==> publish port ${PUB}"
bux create --name "${PUB}" --publish 0:80 "${IMAGE}"
insp="$(bux inspect "${PUB}")"
echo "${insp}" | grep -q '"host"'
echo "${insp}" | grep -q '"guest": 80'
bux rm -f "${PUB}"

echo "OK (full e2e)"
