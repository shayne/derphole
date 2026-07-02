#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

target="${1:-derphole-testing}"
remote_user="${DERPHOLE_REMOTE_USER:-ubuntu}"
size_mib="${DERPHOLE_PUBLIC_PATH_SIZE_MIB:-128}"
iperf_port="${DERPHOLE_PUBLIC_IPERF_PORT:-8321}"
log_dir="${DERPHOLE_BENCH_LOG_DIR:-.tmp/public-path-performance}"
remote="${target}"
if [[ "${target}" != *"@"* ]]; then
  remote="${remote_user}@${target}"
fi

mkdir -p "${log_dir}"

public_ip() {
  curl -4fsS --max-time 8 https://ifconfig.me/ip
}

ensure_iperf3() {
  if ! command -v iperf3 >/dev/null 2>&1; then
    echo "iperf3 is required locally" >&2
    exit 1
  fi
  ssh -o BatchMode=yes "${remote}" "command -v iperf3 >/dev/null || (sudo -n true && sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iperf3)"
}

run_iperf_reverse() {
  local ip="$1"
  local out="${log_dir}/iperf3-${target//[^A-Za-z0-9_.-]/_}-to-local.json"

  iperf3 -s -p "${iperf_port}" --one-off --forceflush >"${log_dir}/iperf3-server.log" 2>&1 &
  local server_pid="$!"
  trap 'kill "${server_pid}" 2>/dev/null || true' RETURN
  sleep 1
  ssh -o BatchMode=yes "${remote}" "iperf3 -c '${ip}' -p '${iperf_port}' -t 20 -P 4 --json" >"${out}"
  wait "${server_pid}" || true
  trap - RETURN

  python3 - "${out}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path) as fh:
    payload = json.load(fh)
bits = payload["end"]["sum_received"]["bits_per_second"]
rtts = [
    stream["sender"].get("mean_rtt", 0)
    for stream in payload["end"]["streams"]
    if stream.get("sender")
]
mean_rtt_ms = (sum(rtts) / len(rtts) / 1000) if rtts else 0
print(f"iperf_reverse_received_mbps={bits / 1_000_000:.2f}")
print(f"iperf_reverse_mean_rtt_ms={mean_rtt_ms:.2f}")
PY
}

run_derphole() {
  local case_name="$1"
  local direction="$2"
  local raw_direct="$3"
  local budget_ms="$4"
  local manager_fanout="$5"
  local script="./scripts/promotion-test.sh"
  local case_log_dir="${log_dir}/${case_name}"

  if [[ "${direction}" == "reverse" ]]; then
    script="./scripts/promotion-test-reverse.sh"
  fi
  mkdir -p "${case_log_dir}"

  echo "derphole_case=${case_name} direction=${direction} raw_direct=${raw_direct} budget_ms=${budget_ms} manager_fanout=${manager_fanout}"
  DERPHOLE_REMOTE_USER="${remote_user}" \
  DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
  DERPHOLE_V2_RAW_DIRECT="${raw_direct}" \
  DERPHOLE_V2_RAW_DIRECT_BUDGET_MS="${budget_ms}" \
  DERPHOLE_V2_MANAGER_QUIC_FANOUT="${manager_fanout}" \
  DERPHOLE_BENCH_LOG_DIR="${case_log_dir}" \
    "${script}" "${target}" "${size_mib}"
}

main() {
  local ip
  ensure_iperf3
  ip="$(public_ip)"
  echo "public_ip=${ip}"
  run_iperf_reverse "${ip}"
  run_derphole raw-direct-reverse reverse 1 0 0
  run_derphole raw-direct-forward forward 1 0 0
  run_derphole manager-reverse reverse 0 0 0
  run_derphole manager-fanout-reverse reverse 0 0 1
  run_derphole startup-budget-reverse reverse 1 850 1
}

main "$@"
