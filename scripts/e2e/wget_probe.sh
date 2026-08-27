#!/usr/bin/env bash
# WHY: vsock ready is not TAP DNS/TCP ready; one-shot wget races warmup.

retry_until_needle() {
  local needle="$1"
  local max_attempts="$2"
  local sleep_secs="$3"
  shift 3
  local i=0 status=""
  while [ "${i}" -lt "${max_attempts}" ]; do
    i=$((i + 1))
    status="$("$@")" || return 1
    if [[ "${status}" == *WGET_MISSING* ]]; then
      echo "${status}"
      return 0
    fi
    if [[ "${status}" == *"${needle}"* ]]; then
      echo "${status}"
      return 0
    fi
    if [ "${i}" -lt "${max_attempts}" ]; then
      sleep "${sleep_secs}"
    fi
  done
  echo "${status}"
  return 0
}
