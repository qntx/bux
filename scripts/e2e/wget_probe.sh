#!/usr/bin/env bash
# WHY: wait_ready is vsock Hello/Ack. TAP DNS/TCP can still be cold.
# Fast wget fail does not burn -T 10, so attempt count × 0.5s collapses.
# Deadline is TAP wait even when each probe returns immediately.

WGET_OK_DEADLINE_SECS=8
WGET_OK_SLEEP_SECS=0.5

retry_until_needle() {
  local needle="$1"
  local deadline_secs="$2"
  local sleep_secs="$3"
  shift 3
  local status="" start now
  start="$(date +%s)"
  while :; do
    status="$("$@")" || return 1
    if [[ "${status}" == *WGET_MISSING* ]]; then
      echo "${status}"
      return 0
    fi
    if [[ "${status}" == *"${needle}"* ]]; then
      echo "${status}"
      return 0
    fi
    now="$(date +%s)"
    if [ $((now - start)) -ge "${deadline_secs}" ]; then
      echo "${status}"
      return 0
    fi
    sleep "${sleep_secs}"
  done
}
