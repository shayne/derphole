#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

target="${1:?usage: $0 <target> [size-mib]}"
size_mib="${2:-1024}"
expected_size="$((size_mib * 1048576))"
tmp="$(mktemp -d)"
start_ms=0
duration_ms=0
remote_target="${target}"
if [[ "${target}" != *"@"* ]]; then
  remote_user="${DERPHOLE_REMOTE_USER:-root}"
  remote_target="${remote_user}@${target}"
fi
iperf_port="${DERPHOLE_IPERF_PORT:-8321}"
iperf_parallel="${DERPHOLE_IPERF_PARALLEL:-4}"

remote() {
  ssh "${remote_target}" 'bash -se' <<<"$1"
}

now_ms() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import time; print(int(time.time() * 1000))'
    return 0
  fi
  perl -MTime::HiRes=time -e 'print int(time() * 1000), "\n"'
}

preserve_logs() {
  local log_dir="${DERPHOLE_BENCH_LOG_DIR:-}"
  if [[ -z "${log_dir}" ]]; then
    return 0
  fi
  mkdir -p "${log_dir}"
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local prefix="iperf-reverse-${target//[^A-Za-z0-9_.-]/_}-${size_mib}MiB-${stamp}"
  cp "${tmp}/server.log" "${log_dir}/${prefix}-server.log"
  cp "${tmp}/client.json" "${log_dir}/${prefix}-client.json"
}

discover_public_ip() {
  if [[ -n "${DERPHOLE_IPERF_SERVER_HOST:-}" ]]; then
    printf '%s\n' "${DERPHOLE_IPERF_SERVER_HOST}"
    return 0
  fi
  curl -4fsSL https://api.ipify.org
}

emit_benchmark_footer() {
  local stream="$1"
  local success="$2"
  local error_text="${3:-}"
  local goodput_mbps="${4:-0}"
  local peak_goodput_mbps="${5:-0}"
  local first_byte_ms="${6:-0}"

  {
    echo "benchmark-host=${target}"
    echo "benchmark-tool=iperf"
    echo "benchmark-direction=reverse"
    echo "benchmark-size-bytes=${expected_size}"
    echo "benchmark-total-duration-ms=${duration_ms:-0}"
    echo "benchmark-goodput-mbps=${goodput_mbps}"
    echo "benchmark-peak-goodput-mbps=${peak_goodput_mbps}"
    echo "benchmark-first-byte-ms=${first_byte_ms}"
    echo "benchmark-success=${success}"
    if [[ -n "${error_text}" ]]; then
      echo "benchmark-error=${error_text}"
    fi
  } >&"${stream}"
}

dump_failure() {
  echo "--- local server log" >&2
  sed -n '1,200p' "${tmp}/server.log" >&2 || true
  echo "--- remote client output" >&2
  sed -n '1,200p' "${tmp}/client.json" >&2 || true
}

cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "${server_pid}" 2>/dev/null || true
  fi
  rm -rf "${tmp}"
}

trap 'status=$?; if [[ ${status} -ne 0 ]]; then if [[ ${start_ms} -gt 0 && ${duration_ms} -eq 0 ]]; then end_ms="$(now_ms)"; duration_ms="$((end_ms - start_ms))"; fi; dump_failure; emit_benchmark_footer 2 false "iperf-benchmark-reverse-exit-${status}"; cleanup; fi; exit ${status}' EXIT

server_host="$(discover_public_ip)"
nix run nixpkgs#iperf3 -- -s -4 -p "${iperf_port}" -1 >"${tmp}/server.log" 2>&1 &
server_pid="$!"
sleep 1

start_ms="$(now_ms)"
remote "
set -euo pipefail
iperf_bin=\"\$(command -v /usr/bin/iperf3 >/dev/null 2>&1 && printf /usr/bin/iperf3 || command -v iperf3)\"
\"\${iperf_bin}\" -4 -J -c '${server_host}' -p '${iperf_port}' -n '${expected_size}' -P '${iperf_parallel}'
" >"${tmp}/client.json"
wait "${server_pid}"
server_pid=""
end_ms="$(now_ms)"
duration_ms="$((end_ms - start_ms))"
if [[ "${duration_ms}" -le 0 ]]; then
  duration_ms=1
fi

read -r goodput_mbps peak_goodput_mbps <<EOF
$(python3 - <<'PY' "${tmp}/client.json"
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
end = data.get("end", {})
summary = end.get("sum_received") or end.get("sum_sent") or {}
goodput = float(summary.get("bits_per_second", 0.0)) / 1_000_000.0
peak = 0.0
for interval in data.get("intervals", []):
    bits = float(interval.get("sum", {}).get("bits_per_second", 0.0))
    if bits > peak:
        peak = bits
print(f"{goodput:.2f} {peak / 1_000_000.0:.2f}")
PY
)
EOF

echo "benchmark-wall-goodput-mbps=${goodput_mbps}"
preserve_logs
emit_benchmark_footer 1 true "" "${goodput_mbps}" "${peak_goodput_mbps}" "0"

cleanup
trap - EXIT
