#!/usr/bin/env bash
# Poll cd.yml for this HEAD's guest-<triple> artifact. Does not dispatch.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if ! command -v gh >/dev/null 2>&1; then
  echo "fetch-guest.sh requires gh (GitHub CLI) authenticated to qntx/bux" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "fetch-guest.sh requires python3 to validate the guest ELF" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64)
    ARCH=x86_64
    TRIPLE=x86_64-unknown-linux-musl
    ;;
  aarch64|arm64)
    ARCH=aarch64
    TRIPLE=aarch64-unknown-linux-musl
    ;;
  *)
    echo "unsupported machine: $(uname -m)" >&2
    exit 1
    ;;
esac

SHA="$(git -C "${ROOT}" rev-parse HEAD)"

print_dispatch() {
  local branch
  branch="$(git -C "${ROOT}" rev-parse --abbrev-ref HEAD)"
  if [[ "${branch}" == "HEAD" ]]; then
    branch=main
  fi
  echo "gh workflow run cd.yml --repo qntx/bux --ref ${branch}" >&2
}

RUN="$(gh run list --repo qntx/bux --workflow cd.yml --commit "${SHA}" \
  --json databaseId,headSha,event,status,conclusion \
  --jq 'if length == 0 then empty else (max_by(.databaseId).databaseId | tostring) end')"
if [[ -z "${RUN}" ]]; then
  print_dispatch
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

dest="${ROOT}/target/debug/bux-guest-${TRIPLE}"
artifact="guest-${TRIPLE}"

while true; do
  rm -rf "${tmp:?}/"*
  if gh run download "${RUN}" --repo qntx/bux -n "${artifact}" -D "${tmp}"; then
    nested="${tmp}/${artifact}/bux-guest-${TRIPLE}"
    flat="${tmp}/bux-guest-${TRIPLE}"
    if [[ -f "${nested}" ]]; then
      src="${nested}"
    elif [[ -f "${flat}" ]]; then
      src="${flat}"
    else
      echo "downloaded ${artifact} but missing bux-guest-${TRIPLE}" >&2
      exit 1
    fi
    if ! python3 - "${src}" "${ARCH}" <<'PY'
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
    then
      echo "downloaded bux-guest-${TRIPLE} failed ELF checks (64-bit LE, host arch, no PT_INTERP)" >&2
      exit 1
    fi
    mkdir -p "${ROOT}/target/debug"
    cp "${src}" "${dest}"
    echo "export BUX_GUEST_PATH=${dest}"
    exit 0
  fi

  meta="$(gh run view "${RUN}" --repo qntx/bux --json status,conclusion \
    --jq '[.status // "", .conclusion // ""] | @tsv')"
  status="${meta%%$'\t'*}"
  conclusion="${meta#*$'\t'}"

  terminal=0
  if [[ "${status}" == "completed" ]]; then
    terminal=1
  fi
  case "${conclusion}" in
    success|failure|cancelled|skipped)
      terminal=1
      ;;
  esac
  if [[ "${terminal}" -eq 1 ]]; then
    print_dispatch
    if [[ "${conclusion}" == "failure" ]]; then
      echo "gh run rerun --repo qntx/bux ${RUN}" >&2
    fi
    exit 1
  fi
  sleep 15
done
