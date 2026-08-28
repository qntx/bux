# Shared FULL pin for load.sh / chaos.sh. Source after ROOT is set.
# shellcheck shell=bash

full_guest_fail() {
  echo "FULL requires a static Linux bux-guest ELF (CONTRIBUTING.md)" >&2
  exit 1
}

# Same offsets as crates/bux/src/guest.rs validate_guest_binary (no readelf).
validate_guest_elf() {
  local path="$1"
  local arch="$2"
  python3 - "${path}" "${arch}" <<'PY' || return 1
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
}

linux_musl_target_present() {
  local triple="$1"
  local sysroot
  if command -v rustup >/dev/null 2>&1 \
    && rustup target list --installed 2>/dev/null | grep -qx "${triple}"; then
    return 0
  fi
  sysroot="$(rustc --print sysroot 2>/dev/null || true)"
  [[ -n "${sysroot}" && -d "${sysroot}/lib/rustlib/${triple}" ]]
}

pin_full_guest() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "FULL requires python3 to validate the guest ELF (CONTRIBUTING.md)" >&2
    exit 1
  fi
  local arch musl_triple guest="" c env_var
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
      full_guest_fail
      ;;
  esac
  if [[ -n "${BUX_GUEST_PATH:-}" ]]; then
    if [[ ! -f "${BUX_GUEST_PATH}" ]] || ! validate_guest_elf "${BUX_GUEST_PATH}" "${arch}"; then
      full_guest_fail
    fi
    guest="${BUX_GUEST_PATH}"
  else
    for c in \
      "${ROOT}/target/debug/bux-guest-${musl_triple}" \
      "${ROOT}/target/${musl_triple}/debug/bux-guest"
    do
      if [[ -f "${c}" ]] && validate_guest_elf "${c}" "${arch}"; then
        guest="${c}"
        break
      fi
    done
    if [[ -z "${guest}" && "$(uname -s)" == "Linux" ]] \
      && command -v musl-gcc >/dev/null 2>&1 \
      && linux_musl_target_present "${musl_triple}"; then
      echo "building bux-guest (${musl_triple})..."
      env_var="CARGO_TARGET_$(echo "${musl_triple}" | tr '[:lower:]-' '[:upper:]_')_LINKER"
      env "${env_var}=musl-gcc" cargo build -p bux-guest --target "${musl_triple}" \
        --manifest-path "${ROOT}/Cargo.toml"
      mkdir -p "${ROOT}/target/debug"
      cp "${ROOT}/target/${musl_triple}/debug/bux-guest" \
        "${ROOT}/target/debug/bux-guest-${musl_triple}"
      guest="${ROOT}/target/debug/bux-guest-${musl_triple}"
      chmod 0755 "${guest}"
      [[ -x "${guest}" ]] || full_guest_fail
      validate_guest_elf "${guest}" "${arch}" || full_guest_fail
    fi
  fi
  [[ -n "${guest}" && -f "${guest}" ]] || full_guest_fail
  export BUX_GUEST_PATH="${guest}"
}

create_or_dump() {
  if bux create "$@"; then
    return 0
  fi
  echo "==> bux create failed; shim stderr:" >&2
  cat "${BUX_HOME}/socks/"*.stderr >&2 2>/dev/null || true
  return 1
}

e2e_cleanup_bux_home() {
  if [[ "${BUX_E2E_FULL:-}" == "1" && "${BUX_HOME:-}" == *bux-e2e* ]] \
    && command -v bux >/dev/null 2>&1; then
    bux ps -aq 2>/dev/null | while read -r id; do
      [[ -n "${id}" ]] || continue
      bux rm -f "${id}" >/dev/null 2>&1 || true
    done || true
  fi
  if [[ -n "${BUX_HOME:-}" && "${BUX_HOME}" == *bux-e2e* ]]; then
    rm -rf "${BUX_HOME}"
  fi
}

# Build cli+shim, Darwin codesign, pin guest, put target/debug on PATH.
pin_full_binaries() {
  echo "building bux-cli and bux-shim-bin (FULL pin)..."
  cargo build -p bux-cli -p bux-shim-bin --manifest-path "${ROOT}/Cargo.toml"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    codesign --entitlements "${ROOT}/crates/bux-shim/bux-shim.entitlements" \
      -s - --force "${ROOT}/target/debug/bux-shim"
  fi
  pin_full_guest
  export PATH="${ROOT}/target/debug:${PATH}"
  export BUX_SHIM_PATH="${ROOT}/target/debug/bux-shim"
  test -x "${BUX_SHIM_PATH}"
}
