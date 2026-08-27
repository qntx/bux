#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HELPER="${HERE}/wget_probe.sh"
SMOKE="${HERE}/smoke.sh"
# shellcheck source=wget_probe.sh
source "${HELPER}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT

echo 0 >"${T}/fail_ok"
echo 0 >"${T}/five"
echo 0 >"${T}/fail_d0"
echo 0 >"${T}/missing"
echo 0 >"${T}/fail_wall"

inc() {
  local f="$1" n
  n="$(cat "${f}")"
  n=$((n + 1))
  echo "${n}" >"${f}"
  echo "${n}"
}

FAIL_COUNTER=""

mock_fail_then_ok() {
  local n
  n="$(inc "${T}/fail_ok")"
  if [ "${n}" -lt 3 ]; then
    echo WGET_FAIL
    return 0
  fi
  echo WGET_OK
}

mock_five_fail_then_ok() {
  local n
  n="$(inc "${T}/five")"
  if [ "${n}" -le 5 ]; then
    echo WGET_FAIL
    return 0
  fi
  echo WGET_OK
}

mock_always_fail() {
  inc "${FAIL_COUNTER}" >/dev/null
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

rc=0
out="$(retry_until_needle WGET_OK 8 0 mock_fail_then_ok)" || rc=$?
[[ "${out}" == *WGET_OK* ]] || fail "fail-then-ok: expected WGET_OK, got ${out:-empty}"
[ "${rc}" -eq 0 ] || fail "fail-then-ok: helper rc=${rc} want 0"

rc=0
out="$(retry_until_needle WGET_OK 8 0 mock_five_fail_then_ok)" || rc=$?
[[ "${out}" == *WGET_OK* ]] || fail "beyond-four: expected WGET_OK, got ${out:-empty}"
[ "${rc}" -eq 0 ] || fail "beyond-four: helper rc=${rc} want 0"

FAIL_COUNTER="${T}/fail_d0"
rc=0
out="$(retry_until_needle WGET_OK 0 0 mock_always_fail)" || rc=$?
[[ "${out}" == *WGET_FAIL* ]] || fail "deadline=0: expected WGET_FAIL, got ${out:-empty}"
[ "$(cat "${T}/fail_d0")" -eq 1 ] || fail "deadline=0: calls=$(cat "${T}/fail_d0") want 1"
[ "${rc}" -eq 0 ] || fail "deadline=0: helper rc=${rc} want 0"

rc=0
out="$(retry_until_needle WGET_OK 8 0 mock_missing_then_ok)" || rc=$?
[[ "${out}" == *WGET_MISSING* ]] || fail "missing: expected WGET_MISSING, got ${out:-empty}"
[ "$(cat "${T}/missing")" -eq 1 ] || fail "missing: retried ($(cat "${T}/missing"))"
[ "${rc}" -eq 0 ] || fail "missing: helper rc=${rc} want 0"

rc=0
out="$(retry_until_needle WGET_OK 8 0 mock_transport)" || rc=$?
[ "${rc}" -eq 1 ] || fail "transport: helper rc=${rc} want 1"
[ -z "${out}" ] || fail "transport: expected empty stdout, got ${out}"

[ "${WGET_OK_DEADLINE_SECS}" -eq 8 ] || fail "constants: WGET_OK_DEADLINE_SECS=${WGET_OK_DEADLINE_SECS} want 8"
[ "${WGET_OK_DEADLINE_SECS}" -lt 10 ] || fail "constants: WGET_OK_DEADLINE_SECS=${WGET_OK_DEADLINE_SECS} want < 10"
[ "${WGET_OK_DEADLINE_SECS}" -lt 30 ] || fail "constants: WGET_OK_DEADLINE_SECS=${WGET_OK_DEADLINE_SECS} want < 30"
[ "${WGET_OK_SLEEP_SECS}" = "0.5" ] || fail "constants: WGET_OK_SLEEP_SECS=${WGET_OK_SLEEP_SECS} want 0.5"
grep -q 'require_wget_ok "${NAME}" 10 "egress"' "${SMOKE}" \
  || fail "constants: smoke.sh item 4 landmark missing"

grep -q 'retry_until_needle WGET_OK "${WGET_OK_DEADLINE_SECS}"' "${SMOKE}" \
  || fail "wiring: smoke.sh missing retry_until_needle WGET_OK with WGET_OK_DEADLINE_SECS"
c="$(grep -c 'retry_until_needle WGET_OK' "${SMOKE}" || true)"
[ "${c}" -eq 1 ] || fail "wiring: retry_until_needle WGET_OK count=${c} want 1"
if grep -Eq 'retry_until_needle WGET_OK[[:space:]]+4[[:space:]]+0\.5' "${SMOKE}"; then
  fail "wiring: smoke.sh still uses 4-attempt 0.5s retry"
fi

FAIL_COUNTER="${T}/fail_wall"
t0="$(date +%s)"
while [ "$(date +%s)" -eq "${t0}" ]; do
  :
done
rc=0
out="$(retry_until_needle WGET_OK 1 0 mock_always_fail)" || rc=$?
[ "${rc}" -eq 0 ] || fail "wall-clock: helper rc=${rc} want 0"
[ "$(cat "${T}/fail_wall")" -ge 3 ] || fail "wall-clock: calls=$(cat "${T}/fail_wall") want >= 3"

grep -q 'date +%s' "${HELPER}" || fail "source: helper missing date +%s"
if grep -Eq 'max_attempts|i -lt' "${HELPER}"; then
  fail "source: helper still uses attempt-count loop"
fi

echo OK
