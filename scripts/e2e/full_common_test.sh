#!/usr/bin/env bash
# Host-only tests for full_common.sh guest ELF stamp and fake-ip helper.
# No hypervisor. Fake-ip cases use injected addresses (no live DNS).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=full_common.sh
source "${E2E_DIR}/full_common.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

if ! command -v python3 >/dev/null 2>&1; then
  fail "python3 required to build fixture ELFs"
fi

case "$(uname -m)" in
  x86_64|amd64)
    arch=x86_64
    musl_triple=x86_64-unknown-linux-musl
    ;;
  aarch64|arm64)
    arch=aarch64
    musl_triple=aarch64-unknown-linux-musl
    ;;
  *)
    fail "unsupported machine: $(uname -m)"
    ;;
esac

T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT

write_fixture() {
  local dest="$1" stamped="$2"
  python3 - "${dest}" "${arch}" "${stamped}" <<'PY'
import struct, sys

path, arch, stamped = sys.argv[1], sys.argv[2], sys.argv[3]
machine = {"x86_64": 0x3E, "aarch64": 0xB7}[arch]
ident = bytes([0x7F, 0x45, 0x4C, 0x46, 2, 1, 1] + [0] * 9)
rest = struct.pack(
    "<HHIQQQIHHHHHH",
    2,  # e_type ET_EXEC
    machine,
    1,  # e_version
    0,  # e_entry
    0,  # e_phoff
    0,  # e_shoff
    0,  # e_flags
    64,  # e_ehsize
    0,  # e_phentsize
    0,  # e_phnum
    0,  # e_shentsize
    0,  # e_shnum
    0,  # e_shstrndx
)
data = ident + rest
if stamped == "1":
    data += b"bux-guest-protocol-v10"
open(path, "wb").write(data)
PY
}

write_fixture "${T}/unstamped" 0
if validate_guest_elf "${T}/unstamped" "${arch}"; then
  fail "unstamped structurally-valid ELF must fail validate_guest_elf"
fi

write_fixture "${T}/stamped" 1
if ! validate_guest_elf "${T}/stamped" "${arch}"; then
  fail "stamped structurally-valid ELF must pass validate_guest_elf"
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
  leftover_root="${T}/leftover"
  leftover="${leftover_root}/target/debug/bux-guest-${musl_triple}"
  mkdir -p "$(dirname "${leftover}")"
  write_fixture "${leftover}" 1
  rc=0
  (
    ROOT="${leftover_root}"
    unset BUX_GUEST_PATH
    pin_full_guest
  ) && rc=0 || rc=$?
  [[ "${rc}" -ne 0 ]] || fail "Darwin leftover ELF must not pin without BUX_GUEST_PATH"
fi

if refuse_fake_ip_example_com "198.18.0.160"; then
  fail "198.18.0.160 must fail refuse_fake_ip_example_com"
fi
if refuse_fake_ip_example_com "::ffff:198.18.0.160"; then
  fail "::ffff:198.18.0.160 must fail refuse_fake_ip_example_com"
fi
if refuse_fake_ip_example_com "::ffff:0:c612:a0"; then
  fail "::ffff:0:c612:a0 must fail refuse_fake_ip_example_com"
fi
if ! refuse_fake_ip_example_com "93.184.216.34"; then
  fail "93.184.216.34 must pass refuse_fake_ip_example_com"
fi
if ! refuse_fake_ip_example_com "::ffff:93.184.216.34"; then
  fail "::ffff:93.184.216.34 must pass refuse_fake_ip_example_com"
fi

echo OK
