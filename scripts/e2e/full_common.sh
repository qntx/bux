# Shared FULL pin for smoke.sh / load.sh / chaos.sh. Source after ROOT is set.
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
if e_phoff != 0 and e_phentsize != 0 and e_phnum != 0:
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        end = off + 4
        if end > len(data):
            break
        p_type = struct.unpack_from("<I", data, off)[0]
        if p_type == 3:
            sys.exit(1)
if b"bux-guest-protocol-v10" not in data:
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
  local arch musl_triple guest="" env_var
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
  elif [[ "$(uname -s)" == "Darwin" ]]; then
    echo "Darwin FULL requires BUX_GUEST_PATH from fetch-guest.sh of this HEAD (CONTRIBUTING.md)" >&2
    echo "unset BUX_GUEST_PATH and delete leftover target/debug/bux-guest-* before fetch" >&2
    exit 1
  elif command -v musl-gcc >/dev/null 2>&1 \
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
  else
    echo "fetching bux-guest via fetch-guest.sh..."
    bash "${ROOT}/scripts/e2e/fetch-guest.sh"
    guest="${ROOT}/target/debug/bux-guest-${musl_triple}"
    if [[ ! -f "${guest}" ]] || ! validate_guest_elf "${guest}" "${arch}"; then
      full_guest_fail
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

# Fail if any address's IPv4 form is in 198.18.0.0/15 (Clash/Surge fake-ip).
# Live: getaddrinfo("example.com", 443, SOCK_STREAM). Args: injected hosts (tests).
# IPv4 form: IPv4; else ipv4_mapped; else last 4 bytes of the 16-byte AAAA packed form.
refuse_fake_ip_example_com() {
  python3 - "$@" <<'PY'
import ipaddress, socket, sys

FAKE = ipaddress.ip_network("198.18.0.0/15")


def ipv4_form(s):
    ip = ipaddress.ip_address(s.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv4Address):
        return ip
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ipaddress.IPv4Address(ip.packed[-4:])


if len(sys.argv) > 1:
    hosts = sys.argv[1:]
    for h in hosts:
        print(f"example.com injected: {h}", file=sys.stderr)
else:
    try:
        infos = socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)
    except OSError as e:
        print(f"FULL refuse: getaddrinfo(example.com, 443) failed: {e}", file=sys.stderr)
        sys.exit(1)
    hosts = []
    for rec in infos:
        print(f"example.com getaddrinfo: {rec}", file=sys.stderr)
        hosts.append(rec[4][0])

hit = False
for h in hosts:
    v4 = ipv4_form(h)
    print(f"example.com ipv4_form: {h} -> {v4}", file=sys.stderr)
    if v4 in FAKE:
        hit = True
if hit:
    print(
        "FULL refuse: example.com IPv4 form in 198.18.0.0/15. "
        "Disable fake-ip/MacPacket (hygiene, not a recorded 502). CONTRIBUTING.md",
        file=sys.stderr,
    )
    sys.exit(1)
sys.exit(0)
PY
}

# Build cli+shim, Darwin codesign, pin guest, fake-ip preflight, PATH.
pin_full_binaries() {
  echo "building bux-cli and bux-shim-bin (FULL pin)..."
  cargo build -p bux-cli --manifest-path "${ROOT}/Cargo.toml"
  cargo build -p bux-shim-bin --manifest-path "${ROOT}/Cargo.toml"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    codesign --entitlements "${ROOT}/crates/bux-shim/bux-shim.entitlements" \
      -s - --force "${ROOT}/target/debug/bux-shim"
  fi
  pin_full_guest
  export PATH="${ROOT}/target/debug:${PATH}"
  export BUX_SHIM_PATH="${ROOT}/target/debug/bux-shim"
  test -x "${BUX_SHIM_PATH}"
  refuse_fake_ip_example_com
}
