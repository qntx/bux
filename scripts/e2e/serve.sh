#!/usr/bin/env bash
# Hosted `bux serve` e2e. GitHub-hosted CI keeps BUX_E2E_FULL=0 (help/openapi).
# FULL=1 is a manual HVF/KVM gate (CONTRIBUTING.md). This script never enables FULL.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=full_common.sh
source "${E2E_DIR}/full_common.sh"

export BUX_HOME="${BUX_HOME:-$(mktemp -d /tmp/bux-e2e.XXXXXX)}"
SERVE_PID=""
RESP="${BUX_HOME}/http-body"
SOCK=""
PORT=""
HTTP_CODE=""

stop_serve() {
  local pid="${SERVE_PID:-}"
  SERVE_PID=""
  if [[ -z "${pid}" ]]; then
    return 0
  fi
  if kill -0 "${pid}" 2>/dev/null; then
    # SIGTERM the worker only (not the process group). Detached shims must live (R3).
    kill -TERM "${pid}" 2>/dev/null || true
    local i
    for i in $(seq 1 40); do
      kill -0 "${pid}" 2>/dev/null || break
      sleep 0.25
    done
    if kill -0 "${pid}" 2>/dev/null; then
      kill -KILL "${pid}" 2>/dev/null || true
    fi
  fi
  wait "${pid}" 2>/dev/null || true
}

cleanup() {
  stop_serve
  e2e_cleanup_bux_home
}
trap cleanup EXIT

echo "==> BUX_HOME=${BUX_HOME}"

if [[ "${BUX_E2E_FULL:-}" == "1" ]]; then
  pin_full_binaries
elif ! command -v bux >/dev/null 2>&1; then
  echo "building bux-cli..."
  cargo build -q -p bux-cli --manifest-path "${ROOT}/Cargo.toml"
  export PATH="${ROOT}/target/debug:${PATH}"
fi

echo "==> bux serve start --help"
bux serve start --help | grep -q -- '--api-key'
bux serve start --help | grep -q -- '--listen'

echo "==> bux serve openapi"
openapi="$(bux serve openapi)"
grep -q -- '"openapi"' <<<"${openapi}"
grep -q -- '/v1/health' <<<"${openapi}"
grep -q -- '/v1/sandboxes' <<<"${openapi}"
grep -q -- '/v1/sandboxes/{id}/exec' <<<"${openapi}"
grep -q -- '/v1/sandboxes/{id}/snapshots' <<<"${openapi}"

if [[ "${BUX_E2E_FULL:-}" != "1" ]]; then
  echo "==> skip full serve e2e (set BUX_E2E_FULL=1 on a local HVF/KVM machine; see CONTRIBUTING.md)"
  echo "OK (host-only serve smoke)"
  exit 0
fi

info_json="$(bux system info --format json)"
if ! grep -Eq -- '"virtualization":[[:space:]]*true' <<<"${info_json}"; then
  echo "==> skip full serve e2e (host.virtualization is not true)"
  echo "OK (skipped serve full)"
  exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "FULL serve e2e requires curl" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "FULL serve e2e requires python3" >&2
  exit 1
fi

KEY1_ID="t1"
KEY1_SEC="s1e2e"
KEY2_ID="t2"
KEY2_SEC="s2e2e"
KEY1="${KEY1_ID}:${KEY1_SEC}"
KEY2="${KEY2_ID}:${KEY2_SEC}"
IMAGE="${BUX_E2E_IMAGE:-alpine:latest}"
AGENT_LOOP="loop"
AGENT_DENY="deny"
AGENT_IDLE="idle"
AGENT_REST="rest"
AGENT_CLON="clon"
VOL_LOOP="${BUX_HOME}/volumes/ws-${KEY1_ID}-${AGENT_LOOP}"

json_get() {
  python3 - "$1" "$2" <<'PY'
import json, sys
path = sys.argv[2].split(".")
with open(sys.argv[1], encoding="utf-8") as f:
    v = json.load(f)
for key in path:
    if isinstance(v, list):
        v = v[int(key)]
    else:
        v = v[key]
if isinstance(v, (dict, list)):
    json.dump(v, sys.stdout)
    sys.stdout.write("\n")
elif v is None:
    pass
else:
    sys.stdout.write(str(v))
PY
}

dump_fail() {
  echo "body:" >&2
  cat "${RESP}" >&2 2>/dev/null || true
  echo "serve.log:" >&2
  cat "${BUX_HOME}/serve.log" >&2 2>/dev/null || true
  echo "shim stderr:" >&2
  cat "${BUX_HOME}/socks/"*.stderr >&2 2>/dev/null || true
}

require_http() {
  local want="$1"
  local msg="$2"
  if [[ "${HTTP_CODE}" != "${want}" ]]; then
    echo "${msg}: HTTP ${HTTP_CODE} (want ${want})" >&2
    dump_fail
    return 1
  fi
}

# Unix socket is the API transport (also proves --listen unix://). TCP is health + wait.
# Bash 3.2 + set -u: do not expand an empty array.
http() {
  local method="$1" path="$2" token="$3"
  local max="${HTTP_TIMEOUT:-120}"
  shift 3
  if [[ "${method}" == POST ]]; then
    HTTP_CODE="$(
      curl -sS -o "${RESP}" -w '%{http_code}' \
        --unix-socket "${SOCK}" \
        --max-time "${max}" \
        -X POST \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        "$@" \
        "http://localhost${path}"
    )"
  else
    HTTP_CODE="$(
      curl -sS -o "${RESP}" -w '%{http_code}' \
        --unix-socket "${SOCK}" \
        --max-time "${max}" \
        -X "${method}" \
        -H "Authorization: Bearer ${token}" \
        "$@" \
        "http://localhost${path}"
    )"
  fi
}

post_json() {
  local path="$1" token="$2" body="$3"
  http POST "${path}" "${token}" --data-binary "${body}"
}

sandbox_body() {
  python3 - "$1" "$2" "$3" <<'PY'
import json, sys
image, agent, extra = sys.argv[1], sys.argv[2], sys.argv[3]
body = {"agent_id": agent, "image": image}
if extra == "deny":
    body["allow_net"] = ["127.0.0.1"]
elif extra == "idle":
    body["auto_stop_secs"] = 1
print(json.dumps(body))
PY
}

exec_sh() {
  local id="$1" token="$2" script="$3"
  local payload
  payload="$(python3 -c 'import json,sys; print(json.dumps({"cmd":"sh","args":["-c", sys.argv[1]]}))' "${script}")"
  post_json "/v1/sandboxes/${id}/exec" "${token}" "${payload}"
}

wait_serve() {
  local i
  for i in $(seq 1 80); do
    if curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/v1/health" >/dev/null 2>&1 \
      && curl -fsS --max-time 1 --unix-socket "${SOCK}" "http://localhost/v1/health" >/dev/null 2>&1; then
      return 0
    fi
    if [[ -n "${SERVE_PID}" ]] && ! kill -0 "${SERVE_PID}" 2>/dev/null; then
      echo "serve exited before health" >&2
      cat "${BUX_HOME}/serve.log" >&2 || true
      return 1
    fi
    sleep 0.1
  done
  echo "serve health timeout" >&2
  cat "${BUX_HOME}/serve.log" >&2 || true
  return 1
}

start_serve() {
  : >"${BUX_HOME}/serve.log"
  bux serve start \
    --listen "127.0.0.1:${PORT}" \
    --listen "unix://${SOCK}" \
    --api-key "${KEY1}" \
    --api-key "${KEY2}" \
    >>"${BUX_HOME}/serve.log" 2>&1 &
  SERVE_PID=$!
  wait_serve
}

wait_status() {
  local id="$1" token="$2" want="$3" tries="${4:-60}"
  local i got
  for i in $(seq 1 "${tries}"); do
    http GET "/v1/sandboxes/${id}" "${token}"
    require_http 200 "GET ${id} while waiting for ${want}"
    got="$(json_get "${RESP}" status)"
    if [[ "${got}" == "${want}" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "sandbox ${id} status ${got:-empty} (want ${want})" >&2
  dump_fail
  return 1
}

guest_wget_probe() {
  local id="$1" token="$2" timeout="${3:-10}"
  exec_sh "${id}" "${token}" "
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
  require_http 200 "deny-net exec"
  json_get "${RESP}" stdout
}

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
SOCK="${BUX_HOME}/bux.sock"

echo "==> serve start 127.0.0.1:${PORT} unix://${SOCK}"
start_serve

echo "==> curl --unix-socket /v1/health"
curl -fsS --unix-socket "${SOCK}" "http://localhost/v1/health" >/dev/null
http GET "/v1/me" "${KEY1_SEC}"
require_http 200 "GET /v1/me"
test "$(json_get "${RESP}" tenant_id)" = "${KEY1_ID}"

echo "==> pull ${IMAGE}"
HTTP_TIMEOUT=300 post_json "/v1/images/pull" "${KEY1_SEC}" "$(python3 -c 'import json,sys; print(json.dumps({"reference": sys.argv[1]}))' "${IMAGE}")"
require_http 200 "POST /v1/images/pull"

echo "==> POST sandboxes twice (same agent)"
post_json "/v1/sandboxes" "${KEY1_SEC}" "$(sandbox_body "${IMAGE}" "${AGENT_LOOP}" "")"
require_http 201 "POST create"
LOOP_ID="$(json_get "${RESP}" id)"
test "${#LOOP_ID}" -eq 12
test -d "${VOL_LOOP}"
post_json "/v1/sandboxes" "${KEY1_SEC}" "$(sandbox_body "${IMAGE}" "${AGENT_LOOP}" "")"
require_http 200 "POST get-or-create"
test "$(json_get "${RESP}" id)" = "${LOOP_ID}"

echo "==> exec echo"
exec_sh "${LOOP_ID}" "${KEY1_SEC}" "echo e2e-ok"
require_http 200 "exec echo"
test "$(json_get "${RESP}" code)" = "0"
grep -qx -- e2e-ok <<<"$(json_get "${RESP}" stdout)"

echo "==> PUT/GET /workspace/x"
printf 'persist-ok\n' >"${BUX_HOME}/workspace-x"
http PUT "/v1/sandboxes/${LOOP_ID}/files?path=/workspace/x" "${KEY1_SEC}" \
  --data-binary "@${BUX_HOME}/workspace-x"
require_http 204 "PUT /workspace/x"
http GET "/v1/sandboxes/${LOOP_ID}/files?path=/workspace/x" "${KEY1_SEC}"
require_http 200 "GET /workspace/x"
grep -qx persist-ok "${RESP}"

echo "==> second tenant 404"
http GET "/v1/sandboxes/${LOOP_ID}" "${KEY2_SEC}"
require_http 404 "other tenant GET sandbox"
test "$(json_get "${RESP}" error.code)" = "not_found"
http GET "/v1/sandboxes/${LOOP_ID}/snapshots" "${KEY2_SEC}"
require_http 404 "other tenant GET snapshots"
test "$(json_get "${RESP}" error.code)" = "not_found"
post_json "/v1/sandboxes/${LOOP_ID}/snapshots" "${KEY2_SEC}" "{}"
require_http 404 "other tenant POST snapshot"

echo "==> overlay marker + snapshot create"
exec_sh "${LOOP_ID}" "${KEY1_SEC}" "printf '%s\n' serve-ok > /serve-marker && sync"
require_http 200 "write /serve-marker"
post_json "/v1/sandboxes/${LOOP_ID}/snapshots" "${KEY1_SEC}" '{"name":"e2e"}'
require_http 201 "POST snapshot"
SID="$(json_get "${RESP}" id)"
test -n "${SID}"

echo "==> restore {agent_id} + exec marker"
post_json "/v1/sandboxes/${LOOP_ID}/snapshots/${SID}/restore" "${KEY1_SEC}" \
  "$(python3 -c 'import json,sys; print(json.dumps({"agent_id": sys.argv[1]}))' "${AGENT_REST}")"
require_http 201 "POST restore"
REST_ID="$(json_get "${RESP}" id)"
test "${REST_ID}" != "${LOOP_ID}"
exec_sh "${REST_ID}" "${KEY1_SEC}" "cat /serve-marker"
require_http 200 "restore exec marker"
grep -qx -- serve-ok <<<"$(json_get "${RESP}" stdout)"

echo "==> clone {agent_id} + exec marker"
post_json "/v1/sandboxes/${LOOP_ID}/clone" "${KEY1_SEC}" \
  "$(python3 -c 'import json,sys; print(json.dumps({"agent_id": sys.argv[1]}))' "${AGENT_CLON}")"
require_http 201 "POST clone"
CLON_ID="$(json_get "${RESP}" id)"
test "${CLON_ID}" != "${LOOP_ID}"
exec_sh "${CLON_ID}" "${KEY1_SEC}" "cat /serve-marker"
require_http 200 "clone exec marker"
grep -qx -- serve-ok <<<"$(json_get "${RESP}" stdout)"

http DELETE "/v1/sandboxes/${REST_ID}" "${KEY1_SEC}"
require_http 204 "DELETE restore"
http DELETE "/v1/sandboxes/${CLON_ID}" "${KEY1_SEC}"
require_http 204 "DELETE clone"

echo "==> allow_net deny wget"
post_json "/v1/sandboxes" "${KEY1_SEC}" "$(sandbox_body "${IMAGE}" "${AGENT_DENY}" deny)"
require_http 201 "POST deny sandbox"
DENY_ID="$(json_get "${RESP}" id)"
deny_status="$(guest_wget_probe "${DENY_ID}" "${KEY1_SEC}" 3)"
case "${deny_status}" in
  *WGET_FAIL*) ;;
  *WGET_OK*)
    echo "allow_net deny: wget succeeded" >&2
    exit 1
    ;;
  *)
    echo "allow_net deny: exec/wget missing (${deny_status:-empty})" >&2
    dump_fail
    exit 1
    ;;
esac
http DELETE "/v1/sandboxes/${DENY_ID}" "${KEY1_SEC}"
require_http 204 "DELETE deny"

echo "==> idle sandbox (auto_stop_secs=1) + workspace file"
post_json "/v1/sandboxes" "${KEY1_SEC}" "$(sandbox_body "${IMAGE}" "${AGENT_IDLE}" idle)"
require_http 201 "POST idle"
IDLE_ID="$(json_get "${RESP}" id)"
printf 'idle-ok\n' >"${BUX_HOME}/idle-x"
http PUT "/v1/sandboxes/${IDLE_ID}/files?path=/workspace/x" "${KEY1_SEC}" \
  --data-binary "@${BUX_HOME}/idle-x"
require_http 204 "PUT idle /workspace/x"
# Sweep interval is 30s but the first tick is immediate on worker start.
# Sleep past auto_stop_secs so SIGTERM+restart sweep stops this VM.
sleep 2

echo "==> SIGTERM serve, start again, exec still works (R3)"
stop_serve
start_serve
exec_sh "${LOOP_ID}" "${KEY1_SEC}" "echo r3-ok"
require_http 200 "R3 exec"
test "$(json_get "${RESP}" code)" = "0"
grep -qx -- r3-ok <<<"$(json_get "${RESP}" stdout)"

echo "==> stop/start file persists (auto-stop then POST /start)"
wait_status "${IDLE_ID}" "${KEY1_SEC}" stopped 60
http POST "/v1/sandboxes/${IDLE_ID}/start" "${KEY1_SEC}"
require_http 200 "POST /start after auto-stop"
test "$(json_get "${RESP}" status)" = "running"
http GET "/v1/sandboxes/${IDLE_ID}/files?path=/workspace/x" "${KEY1_SEC}"
require_http 200 "GET idle file after start"
grep -qx idle-ok "${RESP}"

echo "==> after auto-stop, POST resume must not immediately stop"
wait_status "${IDLE_ID}" "${KEY1_SEC}" stopped 60
post_json "/v1/sandboxes" "${KEY1_SEC}" "$(sandbox_body "${IMAGE}" "${AGENT_IDLE}" idle)"
require_http 200 "POST resume after auto-stop"
test "$(json_get "${RESP}" id)" = "${IDLE_ID}"
test "$(json_get "${RESP}" status)" = "running"
# start_with resets last_activity_at. Do not wait across a sweep tick:
# auto_stop_secs=1 would then expire. Immediate GET is the "not immediately stop" check.
http GET "/v1/sandboxes/${IDLE_ID}" "${KEY1_SEC}"
require_http 200 "GET after resume"
test "$(json_get "${RESP}" status)" = "running"

echo "==> DELETE removes workspace volume"
http DELETE "/v1/sandboxes/${IDLE_ID}" "${KEY1_SEC}"
require_http 204 "DELETE idle"
http DELETE "/v1/sandboxes/${LOOP_ID}" "${KEY1_SEC}"
require_http 204 "DELETE loop"
if [[ -e "${VOL_LOOP}" ]]; then
  echo "DELETE left ${VOL_LOOP}" >&2
  exit 1
fi
http GET "/v1/sandboxes/${LOOP_ID}" "${KEY1_SEC}"
require_http 404 "GET after DELETE"

echo "OK (full serve e2e)"
