#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

tmp="${APPLE_WEB_TUNNEL_TMPDIR:-$(mktemp -d)}"
keep_tmp="${APPLE_WEB_TUNNEL_KEEP_TMP:-0}"
http_pid=""
serve_pid=""

cleanup() {
  local status=$?
  if [[ -n "${serve_pid}" ]]; then
    kill "${serve_pid}" 2>/dev/null || true
    wait "${serve_pid}" 2>/dev/null || true
  fi
  if [[ -n "${http_pid}" ]]; then
    kill "${http_pid}" 2>/dev/null || true
    wait "${http_pid}" 2>/dev/null || true
  fi
  if [[ "${status}" -ne 0 || "${keep_tmp}" == "1" ]]; then
    echo "apple web tunnel logs: ${tmp}" >&2
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

wait_for_compact_invite() {
  local log_path="$1"
  local invite=""
  for _ in $(seq 1 300); do
    invite="$(sed -nE 's/^Invite: (DT1[^[:space:]]+).*/\1/p' "${log_path}" | tail -n 1 || true)"
    if [[ -n "${invite}" ]]; then
      printf '%s\n' "${invite}"
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
  local marker="$3"

  python3 - "${xctestrun_path}" "${payload}" "${marker}" <<'PY'
import plistlib
import sys

path, payload, marker = sys.argv[1:]
with open(path, "rb") as f:
    data = plistlib.load(f)

updated = False
for configuration in data.get("TestConfigurations", []):
    for target in configuration.get("TestTargets", []):
        if target.get("BlueprintName") != "DerpholeUITests":
            continue
        target.setdefault("EnvironmentVariables", {})["DERPHOLE_LIVE_WEB_PAYLOAD"] = payload
        target.setdefault("EnvironmentVariables", {})["DERPHOLE_LIVE_WEB_MARKER"] = marker
        target.setdefault("TestingEnvironmentVariables", {})["DERPHOLE_LIVE_WEB_PAYLOAD"] = payload
        target.setdefault("TestingEnvironmentVariables", {})["DERPHOLE_LIVE_WEB_MARKER"] = marker
        args = list(target.get("CommandLineArguments", []))
        args.extend([
            "--derphole-live-web-payload",
            payload,
            "--derphole-live-web-marker",
            marker,
        ])
        target["CommandLineArguments"] = args
        updated = True

if not updated:
    raise SystemExit("DerpholeUITests target not found in xctestrun")

with open(path, "wb") as f:
    plistlib.dump(data, f)
PY
}

start_http_fixture() {
  local marker="$1"
  local addr_file="$2"

  python3 -u - "${marker}" "${addr_file}" <<'PY' >"${tmp}/http.out" 2>"${tmp}/http.err" &
import html
import http.server
import sys

marker, addr_file = sys.argv[1], sys.argv[2]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"""<!doctype html>
<html>
  <head><meta name="viewport" content="width=device-width, initial-scale=1"></head>
  <body>
    <main>
      <h1>{html.escape(marker)}</h1>
      <p>WKWebView loaded the Derphole web tunnel fixture.</p>
    </main>
  </body>
</html>
""".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print(format % args, file=sys.stderr)

class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

with Server(("127.0.0.1", 0), Handler) as server:
    host, port = server.server_address
    with open(addr_file, "w", encoding="utf-8") as f:
        f.write(f"{host}:{port}\n")
    server.serve_forever()
PY
  http_pid=$!
}

mkdir -p "${tmp}"

marker="${APPLE_WEB_TUNNEL_MARKER:-DerpholeWebTunnel-$(date +%Y%m%d%H%M%S)-${RANDOM}}"
fixture_addr_file="${tmp}/fixture.addr"
start_http_fixture "${marker}" "${fixture_addr_file}"
if ! fixture_addr="$(wait_for_file_value "${fixture_addr_file}")"; then
  echo "failed to start HTTP fixture" >&2
  cat "${tmp}/http.out" >&2 || true
  cat "${tmp}/http.err" >&2 || true
  exit 1
fi
echo "fixture: http://${fixture_addr}/"

mise run build
mise run apple:mobile-framework

server_token="$(dist/derptun token server)"
serve_log="${tmp}/derptun-serve.log"
dist/derptun serve --token "${server_token}" --tcp "${fixture_addr}" --qr >"${tmp}/derptun-serve.out" 2>"${serve_log}" &
serve_pid=$!

if ! invite="$(wait_for_compact_invite "${serve_log}")"; then
  echo "failed to capture compact invite from derptun serve" >&2
  cat "${serve_log}" >&2 || true
  exit 1
fi
echo "invite: ${invite}"

test_destination="$(resolve_test_destination)"
derived_data="${APPLE_DERIVED_DATA:-dist/apple-web-derived-data}"
apple_vendor_root="$PWD/apple/Derphole/Vendor"
if [[ ! -f "${apple_vendor_root}/libghostty/ios/lib/libghostty.a" ||
      ! -f "${apple_vendor_root}/libghostty/ios-simulator/lib/libghostty.a" ||
      ! -f "${apple_vendor_root}/libssh2/ios/lib/libssh2.a" ||
      ! -f "${apple_vendor_root}/libssh2/ios-simulator/lib/libssh2.a" ]]; then
  echo "Apple vendor libraries not found under apple/Derphole/Vendor." >&2
  exit 1
fi
if ! xcodebuild -quiet build-for-testing \
    -project apple/Derphole/Derphole.xcodeproj \
    -scheme Derphole \
    -configuration "${APPLE_CONFIGURATION:-Debug}" \
    -destination "${test_destination}" \
    -derivedDataPath "${derived_data}" \
    CODE_SIGNING_ALLOWED="${CODE_SIGNING_ALLOWED:-NO}" \
    -only-testing:DerpholeUITests/DerpholeUITests/testLiveWebTunnelPayloadLoadsFixtureMarker \
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
inject_xctestrun_payload "${xctestrun_path}" "${invite}" "${marker}"

if ! xcodebuild -quiet test-without-building \
    -xctestrun "${xctestrun_path}" \
    -destination "${test_destination}" \
    -resultBundlePath "${tmp}/web-tunnel.xcresult" \
    -only-testing:DerpholeUITests/DerpholeUITests/testLiveWebTunnelPayloadLoadsFixtureMarker \
    >"${tmp}/xcodebuild.out" 2>"${tmp}/xcodebuild.err"; then
  cat "${tmp}/xcodebuild.out" >&2 || true
  cat "${tmp}/xcodebuild.err" >&2 || true
  xcrun xcresulttool get test-results tests --path "${tmp}/web-tunnel.xcresult" --compact >&2 || true
  exit 1
fi

cat "${tmp}/xcodebuild.out"
cat "${tmp}/xcodebuild.err" >&2
if grep -F "testLiveWebTunnelPayloadLoadsFixtureMarker()' skipped" "${tmp}/xcodebuild.out" >/dev/null; then
  echo "live web tunnel UI test skipped; runtime payload was not delivered to the UI test runner" >&2
  exit 1
fi
if ! grep -F "testLiveWebTunnelPayloadLoadsFixtureMarker()' passed" "${tmp}/xcodebuild.out" >/dev/null; then
  echo "live web tunnel UI test did not report a passing marker verification" >&2
  exit 1
fi

echo "web tunnel marker loaded: ${marker}"
