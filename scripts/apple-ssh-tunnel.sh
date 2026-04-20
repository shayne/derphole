#!/usr/bin/env bash
set -euo pipefail

tmp="${APPLE_SSH_TUNNEL_TMPDIR:-$(mktemp -d)}"
keep_tmp="${APPLE_SSH_TUNNEL_KEEP_TMP:-0}"
ssh_fixture_pid=""
serve_pid=""

cleanup() {
  local status=$?
  if [[ -n "${serve_pid}" ]]; then
    kill "${serve_pid}" 2>/dev/null || true
    wait "${serve_pid}" 2>/dev/null || true
  fi
  if [[ -n "${ssh_fixture_pid}" ]]; then
    kill "${ssh_fixture_pid}" 2>/dev/null || true
    wait "${ssh_fixture_pid}" 2>/dev/null || true
  fi
  if [[ "${status}" -ne 0 || "${keep_tmp}" == "1" ]]; then
    echo "apple ssh tunnel logs: ${tmp}" >&2
  else
    rm -rf "${tmp}"
  fi
}
trap cleanup EXIT

wait_for_file_value() {
  local path="$1"
  local value=""
  for _ in $(seq 1 100); do
    if [[ -s "${path}" ]]; then
      value="$(tr -d '[:space:]' <"${path}")"
      if [[ -n "${value}" ]]; then
        printf '%s\n' "${value}"
        return 0
      fi
    fi
    sleep 0.1
  done
  return 1
}

wait_for_tcp_payload() {
  local log_path="$1"
  local payload=""
  for _ in $(seq 1 300); do
    payload="$(sed -nE 's/^Payload: (derphole:\/\/tcp[^[:space:]]+).*/\1/p' "${log_path}" | tail -n 1 || true)"
    if [[ -n "${payload}" ]]; then
      printf '%s\n' "${payload}"
      return 0
    fi
    if [[ -n "${serve_pid}" ]] && ! kill -0 "${serve_pid}" 2>/dev/null; then
      return 1
    fi
    sleep 0.1
  done
  return 1
}

resolve_test_destination() {
  local test_destination="${APPLE_TEST_DESTINATION:-}"
  if [[ -n "${test_destination}" ]]; then
    printf '%s\n' "${test_destination}"
    return 0
  fi

  local test_device_name="${APPLE_TEST_DEVICE:-iPhone 17}"
  local test_device=""
  test_device="$(xcrun simctl list devices available | awk -v wanted="$test_device_name" '/^[[:space:]]+iPhone/ || /^[[:space:]]+iPad/ { line=$0; sub(/^[[:space:]]+/, "", line); sub(/[[:space:]]+[(].*/, "", line); if (line == wanted) { print line; exit } }')"
  if [[ -z "${test_device}" ]]; then
    test_device="$(xcrun simctl list devices available | awk '(/^[[:space:]]+iPhone/ || /^[[:space:]]+iPad/) && /[(]Booted[)]/ { sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+[(].*/, ""); print; exit }')"
  fi
  if [[ -z "${test_device}" ]]; then
    test_device="$(xcrun simctl list devices available | awk '/^[[:space:]]+iPhone/ || /^[[:space:]]+iPad/ { sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+[(].*/, ""); print; exit }')"
  fi
  if [[ -z "${test_device}" ]]; then
    echo "No available iOS Simulator devices found; install an iOS simulator or set APPLE_TEST_DESTINATION." >&2
    return 1
  fi

  printf 'platform=iOS Simulator,name=%s\n' "${test_device}"
}

inject_xctestrun_payload() {
  local xctestrun_path="$1"
  local payload="$2"
  local username="$3"
  local password="$4"
  local input_probe="$5"

  python3 - "${xctestrun_path}" "${payload}" "${username}" "${password}" "${input_probe}" <<'PY'
import plistlib
import sys

path, payload, username, password, input_probe = sys.argv[1:]
with open(path, "rb") as f:
    data = plistlib.load(f)

updated = False
for configuration in data.get("TestConfigurations", []):
    for target in configuration.get("TestTargets", []):
        if target.get("BlueprintName") != "DerpholeUITests":
            continue
        for key in ("EnvironmentVariables", "TestingEnvironmentVariables"):
            env = target.setdefault(key, {})
            env["DERPHOLE_LIVE_SSH_PAYLOAD"] = payload
            env["DERPHOLE_LIVE_SSH_USERNAME"] = username
            env["DERPHOLE_LIVE_SSH_PASSWORD"] = password
            env["DERPHOLE_LIVE_SSH_INPUT_PROBE"] = input_probe
        args = list(target.get("CommandLineArguments", []))
        args.extend([
            "--derphole-live-ssh-payload",
            payload,
            "--derphole-live-ssh-username",
            username,
            "--derphole-live-ssh-password",
            password,
            "--derphole-live-ssh-input-probe",
            input_probe,
        ])
        target["CommandLineArguments"] = args
        updated = True

if not updated:
    raise SystemExit("DerpholeUITests target not found in xctestrun")

with open(path, "wb") as f:
    plistlib.dump(data, f)
PY
}

mkdir -p "${tmp}"

username="${APPLE_SSH_TUNNEL_USERNAME:-derphole}"
password="${APPLE_SSH_TUNNEL_PASSWORD:-derphole-$(date +%s)-${RANDOM}}"
marker="${APPLE_SSH_TUNNEL_MARKER:-DerpholeSSHTunnel-$(date +%Y%m%d%H%M%S)-${RANDOM}}"
input_probe="${APPLE_SSH_TUNNEL_INPUT_PROBE:-derphole-input-probe-$(date +%s)-${RANDOM}}"
ssh_addr_file="${tmp}/ssh.addr"
shell_opened_file="${tmp}/ssh-shell-opened"
input_log_file="${tmp}/ssh-input.bin"

go run ./tools/ssh-fixture \
  --addr "127.0.0.1:0" \
  --addr-file "${ssh_addr_file}" \
  --shell-opened-file "${shell_opened_file}" \
  --input-log-file "${input_log_file}" \
  --username "${username}" \
  --password "${password}" \
  --marker "${marker}" >"${tmp}/ssh-fixture.out" 2>"${tmp}/ssh-fixture.err" &
ssh_fixture_pid=$!

if ! ssh_addr="$(wait_for_file_value "${ssh_addr_file}")"; then
  echo "failed to start SSH fixture" >&2
  cat "${tmp}/ssh-fixture.out" >&2 || true
  cat "${tmp}/ssh-fixture.err" >&2 || true
  exit 1
fi
echo "ssh fixture: ${ssh_addr}"

mise run build
mise run apple:mobile-framework

server_token="$(dist/derptun token server)"
serve_log="${tmp}/derptun-serve.log"
dist/derptun serve --token "${server_token}" --tcp "${ssh_addr}" --qr >"${tmp}/derptun-serve.out" 2>"${serve_log}" &
serve_pid=$!

if ! payload="$(wait_for_tcp_payload "${serve_log}")"; then
  echo "failed to capture derphole://tcp payload from derptun serve" >&2
  cat "${serve_log}" >&2 || true
  exit 1
fi
echo "payload: ${payload}"

test_destination="$(resolve_test_destination)"
derived_data="${APPLE_DERIVED_DATA:-dist/apple-ssh-derived-data}"
vvterm_vendor_root="${VVTERM_VENDOR_ROOT:-/Users/shayne/code/vvterm/Vendor}"
if [[ ! -d "${vvterm_vendor_root}/libghostty" || ! -d "${vvterm_vendor_root}/libssh2" ]]; then
  echo "VVTerm vendor libraries not found; set VVTERM_VENDOR_ROOT to a directory containing libghostty and libssh2." >&2
  exit 1
fi

if ! xcodebuild -quiet build-for-testing \
    -project apple/Derphole/Derphole.xcodeproj \
    -scheme Derphole \
    -configuration "${APPLE_CONFIGURATION:-Debug}" \
    -destination "${test_destination}" \
    -derivedDataPath "${derived_data}" \
    VVTERM_VENDOR_ROOT="${vvterm_vendor_root}" \
    CODE_SIGNING_ALLOWED="${CODE_SIGNING_ALLOWED:-NO}" \
    -only-testing:DerpholeUITests/DerpholeUITests/testLiveSSHTunnelPayloadOpensTerminal \
    >"${tmp}/xcodebuild-build-for-testing.out" 2>"${tmp}/xcodebuild-build-for-testing.err"; then
  cat "${tmp}/xcodebuild-build-for-testing.out" >&2 || true
  cat "${tmp}/xcodebuild-build-for-testing.err" >&2 || true
  exit 1
fi

xctestrun_path="$(find "${derived_data}/Build/Products" -name '*.xctestrun' -print -quit)"
if [[ -z "${xctestrun_path}" ]]; then
  echo "failed to locate generated xctestrun under ${derived_data}/Build/Products" >&2
  exit 1
fi
inject_xctestrun_payload "${xctestrun_path}" "${payload}" "${username}" "${password}" "${input_probe}"

if ! xcodebuild -quiet test-without-building \
    -xctestrun "${xctestrun_path}" \
    -destination "${test_destination}" \
    -resultBundlePath "${tmp}/ssh-tunnel.xcresult" \
    -only-testing:DerpholeUITests/DerpholeUITests/testLiveSSHTunnelPayloadOpensTerminal \
    >"${tmp}/xcodebuild.out" 2>"${tmp}/xcodebuild.err"; then
  cat "${tmp}/xcodebuild.out" >&2 || true
  cat "${tmp}/xcodebuild.err" >&2 || true
  xcrun xcresulttool get test-results tests --path "${tmp}/ssh-tunnel.xcresult" --compact >&2 || true
  exit 1
fi

cat "${tmp}/xcodebuild.out"
cat "${tmp}/xcodebuild.err" >&2
if grep -F "testLiveSSHTunnelPayloadOpensTerminal()' skipped" "${tmp}/xcodebuild.out" >/dev/null; then
  echo "live SSH tunnel UI test skipped; runtime payload was not delivered to the UI test runner" >&2
  exit 1
fi
if ! grep -F "testLiveSSHTunnelPayloadOpensTerminal()' passed" "${tmp}/xcodebuild.out" >/dev/null; then
  echo "live SSH tunnel UI test did not report a passing terminal verification" >&2
  exit 1
fi
if [[ ! -s "${shell_opened_file}" ]]; then
  echo "SSH fixture did not observe a shell request" >&2
  exit 1
fi
if [[ ! -s "${input_log_file}" ]]; then
  echo "SSH fixture did not observe terminal input" >&2
  exit 1
fi
if ! python3 - "${input_log_file}" "${input_probe}" <<'PY'
import sys

path, probe = sys.argv[1:]
data = open(path, "rb").read()
missing = []
expected = (probe + "-software").encode() + b"\r"
if expected not in data:
    missing.append(expected)
prefix = (probe + "-software-backspaceX").encode()
if not any(prefix + delete_byte + b"d\r" in data for delete_byte in (b"\x7f", b"\x08")):
    missing.append(prefix + b"<backspace>d\\r")
if missing:
    print(f"SSH fixture did not observe expected input bytes {missing!r}; got {data!r}", file=sys.stderr)
    raise SystemExit(1)
PY
then
  exit 1
fi

echo "ssh tunnel terminal opened: ${marker}"
