#!/usr/bin/env bash
set -euo pipefail

bundle_id="${APPLE_BUNDLE_ID:-dev.shayne.Derphole}"
transfer_mib="${APPLE_PHYSICAL_TRANSFER_MIB:-4}"
transfer_timeout="${APPLE_PHYSICAL_TRANSFER_TIMEOUT:-180}"
device_selector="${APPLE_DEVICE:-${APPLE_DEVICE_ID:-${APPLE_DEVICE_NAME:-}}}"
keep_tmp="${APPLE_PHYSICAL_TRANSFER_KEEP_TMP:-0}"
tmp="${APPLE_PHYSICAL_TRANSFER_TMPDIR:-$(mktemp -d)}"
sender_pid=""
development_team="${APPLE_DEVELOPMENT_TEAM:-}"

cleanup() {
  local status=$?
  if [[ -n "${sender_pid}" ]]; then
    kill "${sender_pid}" 2>/dev/null || true
    wait "${sender_pid}" 2>/dev/null || true
  fi
  if [[ "${status}" -ne 0 || "${keep_tmp}" == "1" ]]; then
    echo "apple physical transfer logs: ${tmp}" >&2
  else
    rm -rf "${tmp}"
  fi
}
trap cleanup EXIT

resolve_device() {
  local selector="$1"
  local json_path="$tmp/devices.json"
  if ! xcrun devicectl list devices --json-output "${json_path}" >"$tmp/devicectl-list.out" 2>"$tmp/devicectl-list.err"; then
    cat "$tmp/devicectl-list.out" >&2 || true
    cat "$tmp/devicectl-list.err" >&2 || true
    return 1
  fi

  python3 - "$json_path" "$selector" <<'PY'
import json
import sys

path, selector = sys.argv[1], sys.argv[2].strip()
data = json.load(open(path))
devices = data.get("result", {}).get("devices", [])

def labels(device):
    hardware = device.get("hardwareProperties", {})
    properties = device.get("deviceProperties", {})
    connection = device.get("connectionProperties", {})
    values = [
        device.get("identifier", ""),
        hardware.get("udid", ""),
        hardware.get("serialNumber", ""),
        properties.get("name", ""),
    ]
    values.extend(connection.get("localHostnames", []))
    values.extend(connection.get("potentialHostnames", []))
    return [value for value in values if value]

def eligible(device):
    hardware = device.get("hardwareProperties", {})
    properties = device.get("deviceProperties", {})
    connection = device.get("connectionProperties", {})
    return (
        hardware.get("platform") == "iOS"
        and hardware.get("reality") == "physical"
        and properties.get("bootState") == "booted"
        and connection.get("tunnelState") == "connected"
    )

matches = []
if selector:
    needle = selector.casefold()
    for device in devices:
        if any(label.casefold() == needle for label in labels(device)):
            matches.append(device)
else:
    matches = [device for device in devices if eligible(device)]

if not matches:
    known = ", ".join(labels(device)[-1] if labels(device) else device.get("identifier", "?") for device in devices)
    raise SystemExit(f"no connected physical iOS device matched {selector!r}; known devices: {known}")
if len(matches) > 1:
    names = ", ".join(device.get("deviceProperties", {}).get("name", device.get("identifier", "?")) for device in matches)
    raise SystemExit(f"multiple physical iOS devices matched; set APPLE_DEVICE. matches: {names}")

device = matches[0]
hardware = device.get("hardwareProperties", {})
properties = device.get("deviceProperties", {})
print(device["identifier"])
print(hardware.get("udid", device["identifier"]))
print(properties.get("name", device["identifier"]))
PY
}

wait_for_token() {
  local log_path="$1"
  local token=""
  for _ in $(seq 1 300); do
    token="$(sed -nE 's/.* receive ([A-Za-z0-9_-]{20,}).*/\1/p' "${log_path}" | tail -n 1 || true)"
    if [[ -n "${token}" ]]; then
      printf '%s\n' "${token}"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_sender() {
  local pid="$1"
  local timeout="$2"
  local started="${SECONDS}"

  while kill -0 "${pid}" 2>/dev/null; do
    if (( SECONDS - started >= timeout )); then
      return 124
    fi
    sleep 1
  done

  wait "${pid}"
}

find_received_file() {
  local device_id="$1"
  local filename="$2"
  local json_path="$tmp/app-files.json"
  xcrun devicectl device info files \
    --device "${device_id}" \
    --domain-type appDataContainer \
    --domain-identifier "${bundle_id}" \
    --subdirectory tmp \
    --recurse \
    --json-output "${json_path}" >"$tmp/device-files.out" 2>"$tmp/device-files.err"

  python3 - "$json_path" "$filename" <<'PY'
import json
import sys

path, filename = sys.argv[1], sys.argv[2]
files = json.load(open(path)).get("result", {}).get("files", [])
matches = [
    file
    for file in files
    if file.get("name", "").endswith("/" + filename)
    and not file.get("resources", {}).get("isDirectory", False)
]
if not matches:
    raise SystemExit(f"received file {filename!r} not found in app tmp container")
matches.sort(key=lambda file: file.get("metadata", {}).get("lastModDate", ""))
print(matches[-1]["relativePath"])
PY
}

live_launch_environment() {
  local token="$1"
  local filename="$2"

  python3 - "$token" "$filename" "$transfer_timeout" <<'PY'
import json
import sys

token, filename, timeout = sys.argv[1:]
print(json.dumps({
	"DERPHOLE_LIVE_RECEIVE_AUTOSTART": "1",
	"DERPHOLE_LIVE_RECEIVE_TOKEN": token,
		"DERPHOLE_LIVE_RECEIVE_FILENAME": filename,
		"DERPHOLE_LIVE_RECEIVE_TIMEOUT": timeout,
}))
PY
}

mkdir -p "${tmp}"

if [[ -z "${development_team}" ]]; then
  development_team="$(awk -F' = ' '/DEVELOPMENT_TEAM = / { gsub(/;/, "", $2); print $2; exit }' apple/Derphole/Derphole.xcodeproj/project.pbxproj || true)"
fi
if [[ -z "${development_team}" ]]; then
  echo "could not infer DEVELOPMENT_TEAM; set APPLE_DEVELOPMENT_TEAM" >&2
  exit 1
fi

mapfile -t device_info < <(resolve_device "${device_selector}")
device_id="${device_info[0]}"
device_udid="${device_info[1]}"
device_name="${device_info[2]}"

echo "device: ${device_name} (${device_udid})"

payload_name="derphole-physical-$(date +%Y%m%d%H%M%S)-${RANDOM}.bin"
payload_path="${tmp}/${payload_name}"
dd if=/dev/urandom of="${payload_path}" bs=1048576 count="${transfer_mib}" 2>"$tmp/payload-dd.log"
source_sha="$(shasum -a 256 "${payload_path}" | awk '{print $1}')"
source_bytes="$(wc -c <"${payload_path}" | tr -d ' ')"

mise run build
APPLE_SDK=iphoneos CODE_SIGNING_ALLOWED=YES DEVELOPMENT_TEAM="${development_team}" mise run apple:build

app_bundle="${APPLE_APP_BUNDLE:-dist/apple-build/Products/Debug-iphoneos/Derphole.app}"
if [[ ! -d "${app_bundle}" ]]; then
  echo "app bundle not found: ${app_bundle}" >&2
  exit 1
fi
xcrun devicectl device install app --device "${device_id}" "${app_bundle}" >"$tmp/install.out" 2>"$tmp/install.err"

sender_log="$tmp/sender.log"
sender_out="$tmp/sender.out"
dist/derphole --verbose send --hide-progress "${payload_path}" >"${sender_out}" 2>"${sender_log}" &
sender_pid=$!

if ! token="$(wait_for_token "${sender_log}")"; then
  echo "failed to capture live send token" >&2
  cat "${sender_log}" >&2 || true
  exit 1
fi

token_file="$tmp/DerpholeLiveReceivePayload.txt"
printf '%s\n' "${token}" >"${token_file}"
xcrun devicectl device copy to \
  --device "${device_id}" \
  --domain-type appDataContainer \
  --domain-identifier "${bundle_id}" \
  --source "${token_file}" \
  --destination "tmp/DerpholeLiveReceivePayload.txt" >"$tmp/token-copy.out" 2>"$tmp/token-copy.err"

launch_env="$(live_launch_environment "${token}" "${payload_name}")"
if ! xcrun devicectl device process launch \
  --device "${device_id}" \
  --terminate-existing \
  --environment-variables "${launch_env}" \
  "${bundle_id}" \
  --derphole-live-receive-token "${token}" \
  --derphole-live-receive-filename "${payload_name}" >"$tmp/launch.out" 2>"$tmp/launch.err"; then
  echo "failed to launch ${bundle_id}; unlock the device and retry" >&2
  cat "$tmp/launch.out" >&2 || true
  cat "$tmp/launch.err" >&2 || true
  exit 1
fi

if ! wait_for_sender "${sender_pid}" "${transfer_timeout}"; then
  sender_pid=""
  echo "CLI sender failed" >&2
  cat "$tmp/launch.out" >&2 || true
  cat "$tmp/launch.err" >&2 || true
  cat "${sender_log}" >&2 || true
  exit 1
fi
sender_pid=""

received_relative_path="$(find_received_file "${device_id}" "${payload_name}")"
copy_dir="$tmp/device-copy"
mkdir -p "${copy_dir}"
xcrun devicectl device copy from \
  --device "${device_id}" \
  --domain-type appDataContainer \
  --domain-identifier "${bundle_id}" \
  --source "tmp/${received_relative_path}" \
  --destination "${copy_dir}/${payload_name}" >"$tmp/copy.out" 2>"$tmp/copy.err"

received_path="$(find "${copy_dir}" -type f -name "${payload_name}" -print -quit)"
if [[ -z "${received_path}" ]]; then
  echo "copied received file not found under ${copy_dir}" >&2
  exit 1
fi

received_sha="$(shasum -a 256 "${received_path}" | awk '{print $1}')"
if [[ "${received_sha}" != "${source_sha}" ]]; then
  echo "sha256 mismatch: source=${source_sha} received=${received_sha}" >&2
  exit 1
fi

route="$(grep -E 'connected-(direct|relay)' "${sender_log}" | tail -n 1 || true)"
echo "transfer complete: ${source_bytes} bytes"
echo "sha256: ${source_sha}"
if [[ -n "${route}" ]]; then
  echo "route: ${route}"
fi
