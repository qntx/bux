#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=wget_probe.sh
source "${HERE}/wget_probe.sh"
SMOKE="${HERE}/smoke.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT

echo 0 >"${T}/fail_ok"
echo 0 >"${T}/fail"
echo 0 >"${T}/missing"

inc() {
  local f="$1" n
  n="$(cat "${f}")"
  n=$((n + 1))
  echo "${n}" >"${f}"
  echo "${n}"
}

mock_fail_then_ok() {
  local n
  n="$(inc "${T}/fail_ok")"
  if [ "${n}" -lt 3 ]; then
    echo WGET_FAIL
    return 0
  fi
  echo WGET_OK
}

mock_always_fail() {
  inc "${T}/fail" >/dev/null
  echo WGET_FAIL
}

mock_missing_then_ok() {
  local n
  n="$(inc "${T}/missing")"
  if [ "${n}" -eq 1 ]; then
    echo WGET_MISSING
    return 0
  fi
  echo WGET_OK
}

mock_transport() {
  return 1
}

out="$(retry_until_needle WGET_OK 4 0 mock_fail_then_ok)"
[[ "${out}" == *WGET_OK* ]] || fail "fail-then-ok: expected WGET_OK, got ${out:-empty}"

rc=0
out="$(retry_until_needle WGET_OK 2 0 mock_always_fail)" || rc=$?
[[ "${out}" == *WGET_FAIL* ]] || fail "exhausted: expected WGET_FAIL, got ${out:-empty}"
[ "${rc}" -eq 0 ] || fail "exhausted: helper rc=${rc} want 0"

rc=0
out="$(retry_until_needle WGET_OK 4 0 mock_missing_then_ok)" || rc=$?
[[ "${out}" == *WGET_MISSING* ]] || fail "missing: expected WGET_MISSING, got ${out:-empty}"
[ "$(cat "${T}/missing")" -eq 1 ] || fail "missing: retried ($(cat "${T}/missing"))"
[ "${rc}" -eq 0 ] || fail "missing: helper rc=${rc} want 0"

rc=0
out="$(retry_until_needle WGET_OK 4 0 mock_transport)" || rc=$?
[ "${rc}" -eq 1 ] || fail "transport: helper rc=${rc} want 1"
[ -z "${out}" ] || fail "transport: expected empty stdout, got ${out}"

grep -q 'retry_until_needle WGET_OK' "${SMOKE}" \
  || fail "smoke.sh still one-shot require_wget_ok (no retry_until_needle WGET_OK)"

echo OK
