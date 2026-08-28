#!/usr/bin/env bash
# Chaos e2e: SIGKILL shim → inspect Stopped → rm without -f; no leftover overlay.
# Requires BUX_E2E_FULL=1 (same pin as smoke.sh). GitHub-hosted CI keeps FULL=0.
# No ulimit disk-full test.
#
# Pass: create → kill -9 shim PID → inspect "Stopped" within 5s → bux rm
# without -f succeeds; $BUX_HOME/disks/vms/{id}.qcow2 is gone.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=full_common.sh
source "${E2E_DIR}/full_common.sh"

if [[ "${BUX_E2E_FULL:-}" != "1" ]]; then
  echo "==> skip chaos e2e (set BUX_E2E_FULL=1 on a local HVF/KVM machine; see CONTRIBUTING.md)"
  echo "OK (skipped chaos)"
  exit 0
fi

export BUX_HOME="${BUX_HOME:-$(mktemp -d /tmp/bux-e2e.XXXXXX)}"
trap e2e_cleanup_bux_home EXIT

echo "==> BUX_HOME=${BUX_HOME}"

pin_full_binaries

IMAGE="${BUX_E2E_IMAGE:-alpine:latest}"
echo "==> pull ${IMAGE}"
bux pull "${IMAGE}"

NAME="e2e-chaos-$(date +%s)"
echo "==> create ${NAME}"
create_or_dump --name "${NAME}" "${IMAGE}"

insp="$(bux inspect "${NAME}")"
echo "${insp}" | grep -E '"status":[[:space:]]*"Running"' >/dev/null
vm_id="$(printf '%s\n' "${insp}" | sed -n 's/.*"id":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
shim_pid="$(printf '%s\n' "${insp}" | sed -n 's/.*"pid":[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | head -n 1)"
test -n "${vm_id}"
test -n "${shim_pid}" && test "${shim_pid}" != "0"
overlay="${BUX_HOME}/disks/vms/${vm_id}.qcow2"
test -f "${overlay}"

echo "==> kill -9 shim pid ${shim_pid} (${vm_id})"
kill -9 "${shim_pid}" || true

ok=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  rec_status="$(bux inspect "${NAME}")"
  if echo "${rec_status}" | grep -E '"status":[[:space:]]*"Stopped"' >/dev/null; then
    ok=1
    break
  fi
  sleep 0.25
done
if [[ "${ok}" -ne 1 ]]; then
  echo "chaos: inspect did not report Stopped within 5s" >&2
  bux inspect "${NAME}" >&2 || true
  exit 1
fi

echo "==> rm ${NAME} (no -f)"
bux rm "${NAME}"
if [[ -e "${overlay}" ]]; then
  echo "chaos: leftover overlay ${overlay}" >&2
  exit 1
fi

echo "OK (chaos e2e)"
