#!/usr/bin/env bash
# Load e2e: 8 detached alpine VMs, 16 concurrent exec on one.
# Requires BUX_E2E_FULL=1 (same pin as smoke.sh). GitHub-hosted CI keeps FULL=0.
#
# Pass: all 8 Running; 16 parallel `bux exec -- echo ok` exit 0; `bux rm -f`
# then `bux ps -q` empty and no leftover $BUX_HOME/disks/vms/*.qcow2.
# RAM: default 512 MiB × 8; fail with a message if the host cannot allocate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=full_common.sh
source "${E2E_DIR}/full_common.sh"

if [[ "${BUX_E2E_FULL:-}" != "1" ]]; then
  echo "==> skip load e2e (set BUX_E2E_FULL=1 on a local HVF/KVM machine; see CONTRIBUTING.md)"
  echo "OK (skipped load)"
  exit 0
fi

export BUX_HOME="${BUX_HOME:-$(mktemp -d /tmp/bux-e2e.XXXXXX)}"
trap e2e_cleanup_bux_home EXIT

echo "==> BUX_HOME=${BUX_HOME}"

# Fail closed if the host cannot back 8 × 512 MiB guests (do not OOM-flake).
require_ram_8x512() {
  local need_mib=$((8 * 512))
  local measured_mib="" kind=""
  case "$(uname -s)" in
    Linux)
      measured_mib="$(awk '/^MemAvailable:/ {print int($2/1024); exit}' /proc/meminfo)"
      kind=MemAvailable
      ;;
    Darwin)
      measured_mib="$(($(sysctl -n hw.memsize) / 1024 / 1024))"
      kind=hw.memsize
      ;;
    *)
      echo "load: unknown OS; cannot check RAM for 8×512 MiB VMs" >&2
      exit 1
      ;;
  esac
  if [[ -z "${measured_mib}" ]] || ! [[ "${measured_mib}" =~ ^[0-9]+$ ]]; then
    echo "load: cannot measure host RAM (${kind:-unknown}); refusing to flake" >&2
    exit 1
  fi
  if [[ "${measured_mib}" -lt "${need_mib}" ]]; then
    echo "load: host cannot allocate 8×512 MiB (${kind} ${measured_mib} MiB < ${need_mib} MiB)" >&2
    exit 1
  fi
  echo "==> RAM ${kind}=${measured_mib} MiB (need ${need_mib} MiB for 8×512)"
}

pin_full_binaries
require_ram_8x512

IMAGE="${BUX_E2E_IMAGE:-alpine:latest}"
echo "==> pull ${IMAGE}"
bux pull "${IMAGE}"

ts="$(date +%s)"
names=()
echo "==> create 8 detached alpine VMs (default 512 MiB)"
for i in 1 2 3 4 5 6 7 8; do
  name="e2e-load-${ts}-${i}"
  create_or_dump --name "${name}" "${IMAGE}"
  names+=("${name}")
done

echo "==> bux ps (all Running)"
bux ps
psq="$(bux ps -q)"
n="$(printf '%s\n' "${psq}" | grep -c '[^[:space:]]' || true)"
if [[ "${n}" -ne 8 ]]; then
  echo "load: expected 8 running VMs from bux ps -q, got ${n}:" >&2
  printf '%s\n' "${psq}" >&2
  exit 1
fi
for name in "${names[@]}"; do
  insp="$(bux inspect "${name}")"
  if ! echo "${insp}" | grep -E '"status":[[:space:]]*"Running"' >/dev/null; then
    echo "load: ${name} not Running:" >&2
    echo "${insp}" >&2
    exit 1
  fi
done

one="${names[0]}"
echo "==> 16 concurrent exec ${one} -- echo ok"
pids=()
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
  bux exec "${one}" -- echo ok >/dev/null &
  pids+=("$!")
done
fail=0
for pid in "${pids[@]}"; do
  if ! wait "${pid}"; then
    echo "load: concurrent exec pid ${pid} failed" >&2
    fail=1
  fi
done
if [[ "${fail}" -ne 0 ]]; then
  echo "load: not all 16 concurrent execs exited 0" >&2
  exit 1
fi

echo "==> rm -f all 8"
bux rm -f "${names[@]}"

left="$(bux ps -q || true)"
if [[ -n "${left}" ]]; then
  echo "load: bux ps -q not empty after rm -f:" >&2
  printf '%s\n' "${left}" >&2
  exit 1
fi

leftover=""
if [[ -d "${BUX_HOME}/disks/vms" ]]; then
  leftover="$(find "${BUX_HOME}/disks/vms" -maxdepth 1 -name '*.qcow2' -print)"
fi
if [[ -n "${leftover}" ]]; then
  echo "load: leftover overlays after rm -f:" >&2
  printf '%s\n' "${leftover}" >&2
  exit 1
fi

echo "OK (load e2e)"
