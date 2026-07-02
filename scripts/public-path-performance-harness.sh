#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

hosts_raw="${DERPHOLE_PUBLIC_PATH_HOSTS:-ubuntu@derphole-testing ubuntu@eric-nuc root@hetz root@canlxc}"
size_mib="${DERPHOLE_PUBLIC_PATH_SIZE_MIB:-1024}"
runs="${DERPHOLE_PUBLIC_PATH_RUNS:-3}"
iperf_port="${DERPHOLE_PUBLIC_IPERF_PORT:-8123}"
direction="${DERPHOLE_PUBLIC_PATH_DIRECTION:-forward}"
log_dir="${DERPHOLE_BENCH_LOG_DIR:-.tmp/public-path-performance}"
remote_output_root="${DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT:-derphole-bench/public-path}"
summary_csv="${log_dir}/summary.csv"
remote_user="${DERPHOLE_REMOTE_USER:-ubuntu}"

if [[ "${1:-}" != "" ]]; then
  hosts_raw="$1"
fi

if [[ "${direction}" != "forward" ]]; then
  echo "DERPHOLE_PUBLIC_PATH_DIRECTION only supports forward (got: ${direction})" >&2
  exit 2
fi

public_ip() {
  curl -4fsS --max-time 8 https://ifconfig.me/ip
}

ensure_iperf3() {
  local remote="$1"

  if ! command -v iperf3 >/dev/null 2>&1; then
    echo "iperf3 is required locally" >&2
    exit 1
  fi
  ssh -o BatchMode=yes "${remote}" 'bash -se' <<'SH'
if command -v iperf3 >/dev/null 2>&1; then
  exit 0
fi
if [ "$(id -u)" = "0" ]; then
  DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iperf3
elif command -v sudo >/dev/null 2>&1 && sudo -n true; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iperf3
else
  echo "iperf3 is required on the remote host" >&2
  exit 1
fi
SH
}

run_iperf_forward_sample() {
  local remote="$1"
  local host_label="$2"
  local run="$3"
  local ip="$4"
  local out="${log_dir}/${host_label}/iperf3-run-${run}.json"

  mkdir -p "$(dirname "${out}")"
  iperf3 -s -4 -p "${iperf_port}" --one-off --forceflush >"${log_dir}/${host_label}/iperf3-server-${run}.log" 2>&1 &
  local server_pid="$!"
  trap 'kill "${server_pid}" 2>/dev/null || true' RETURN
  sleep 1
  ssh -o BatchMode=yes "${remote}" "iperf3 -4 -J -R -c '${ip}' -p '${iperf_port}' -t 20 -P 4" >"${out}"
  wait "${server_pid}" || true
  trap - RETURN

  python3 - "${out}" <<'PY'
import json
import sys

with open(sys.argv[1]) as fh:
    payload = json.load(fh)
bits = payload["end"]["sum_received"]["bits_per_second"]
print(f"{bits / 1_000_000:.2f}")
PY
}

run_derphole_forward_sample() {
  local remote="$1"
  local host_label="$2"
  local run="$3"
  local case_log_dir="${log_dir}/${host_label}/derphole-run-${run}"
  local target="${remote}"

  mkdir -p "${case_log_dir}"
  env \
  -u DERPHOLE_V2_RAW_DIRECT \
  -u DERPHOLE_V2_RAW_DIRECT_BUDGET_MS \
  -u DERPHOLE_V2_MANAGER_QUIC_FANOUT \
  DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
  DERPHOLE_BENCH_DIRECTION="${direction}" \
  DERPHOLE_BENCH_LOG_DIR="${case_log_dir}" \
  DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT="${remote_output_root}/${host_label}/run-${run}" \
    ./scripts/promotion-test.sh "${target}" "${size_mib}"
}

append_summary_row() {
  local host_label="$1"
  local run="$2"
  local tool="$3"
  local mbps="$4"
  local iperf_mbps="$5"
  local trace_ok="$6"
  local max_queue="$7"
  local max_flatline="$8"
  local sample_log_dir="$9"

  python3 - "${summary_csv}" "${host_label}" "${run}" "${tool}" "${direction}" "${mbps}" "${iperf_mbps}" "${trace_ok}" "${max_queue}" "${max_flatline}" "${sample_log_dir}" <<'PY'
import csv
import sys

path, host, run, tool, direction, mbps, iperf_mbps, trace_ok, max_queue, max_flatline, log_dir = sys.argv[1:]
ratio = ""
if float(iperf_mbps) > 0:
    ratio = f"{float(mbps) / float(iperf_mbps):.3f}"
with open(path, "a", newline="") as fh:
    csv.writer(fh).writerow([host, run, tool, direction, mbps, ratio, trace_ok, max_queue, max_flatline, log_dir])
PY
}

host_label_for() {
  local remote="$1"
  printf '%s' "${remote//[^A-Za-z0-9_.-]/_}"
}

latest_file() {
  local dir="$1"
  local pattern="$2"
  find "${dir}" -type f -name "${pattern}" -print | sort | tail -n 1
}

extract_benchmark_goodput() {
  local output="$1"

  python3 - "${output}" <<'PY'
import sys

value = ""
with open(sys.argv[1], errors="replace") as fh:
    for line in fh:
        line = line.strip()
        for prefix in ("sender_goodput_mbps=", "benchmark-goodput-mbps="):
            if line.startswith(prefix):
                value = line[len(prefix):]
if not value:
    value = "0"
print(value)
PY
}

extract_tracecheck_summary() {
  python3 - "$@" <<'PY'
import re
import sys

unit_seconds = {
    "ns": 0.000000001,
    "us": 0.000001,
    "ms": 0.001,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
}

def duration_seconds(value):
    total = 0.0
    for number, unit in re.findall(r"([0-9]+(?:\.[0-9]+)?)(ns|us|ms|s|m|h)", value):
        total += float(number) * unit_seconds[unit]
    return total

max_queue = 0
max_flatline = "0s"
max_flatline_seconds = -1.0
for path in sys.argv[1:]:
    with open(path, errors="replace") as fh:
        text = fh.read()
    for match in re.findall(r"max_peer_recv_queue_depth=([0-9]+)", text):
        max_queue = max(max_queue, int(match))
    match = re.search(r"max_flatline=([^ \n]+)", text)
    if match:
        value = match.group(1)
        seconds = duration_seconds(value)
        if seconds > max_flatline_seconds:
            max_flatline = value
            max_flatline_seconds = seconds
print(f"{max_queue}\t{max_flatline}")
PY
}

run_trace_checks() {
  local case_log_dir="$1"
  local sender_trace
  local receiver_trace
  local sender_check="${case_log_dir}/sender-transfertracecheck.txt"
  local receiver_check="${case_log_dir}/receiver-transfertracecheck.txt"
  local status=0

  sender_trace="$(latest_file "${case_log_dir}" "*-sender.trace.csv")"
  receiver_trace="$(latest_file "${case_log_dir}" "*-receiver.trace.csv")"
  if [[ -z "${sender_trace}" || -z "${receiver_trace}" ]]; then
    echo "missing preserved transfer traces in ${case_log_dir}" >&2
    printf '0\t0s\n'
    return 1
  fi

  if ! mise exec -- go run ./tools/transfertracecheck -role send -stall-window 1s -peer-trace "${receiver_trace}" "${sender_trace}" >"${sender_check}" 2>&1; then
    status=1
  fi
  if ! mise exec -- go run ./tools/transfertracecheck -role receive -stall-window 1s "${receiver_trace}" >"${receiver_check}" 2>&1; then
    status=1
  fi
  extract_tracecheck_summary "${sender_check}" "${receiver_check}"
  return "${status}"
}

main() {
  local ip
  local hosts=()
  local trace_failures=0

  mkdir -p "${log_dir}"
  printf 'host,run,tool,direction,mbps,ratio_to_iperf,trace_ok,max_peer_recv_queue_depth,max_flatline,log_dir\n' >"${summary_csv}"

  read -r -a hosts <<<"${hosts_raw}"
  if [[ "${#hosts[@]}" -eq 0 ]]; then
    echo "no public-path hosts configured" >&2
    exit 1
  fi

  ip="$(public_ip)"
  echo "public_ip=${ip}"

  for host in "${hosts[@]}"; do
    local remote="${host}"
    local host_label
    if [[ "${remote}" != *"@"* ]]; then
      remote="${remote_user}@${remote}"
    fi
    host_label="$(host_label_for "${remote}")"
    ensure_iperf3 "${remote}"

    for run in $(seq 1 "${runs}"); do
      local iperf_mbps
      local case_log_dir="${log_dir}/${host_label}/derphole-run-${run}"
      local promotion_out="${case_log_dir}/promotion.out"
      local derphole_mbps
      local trace_summary
      local max_queue
      local max_flatline
      local trace_ok
      local trace_status=0
      local promotion_status=0

      echo "public_path_sample host=${remote} run=${run} tool=iperf3"
      iperf_mbps="$(run_iperf_forward_sample "${remote}" "${host_label}" "${run}" "${ip}")"
      append_summary_row "${host_label}" "${run}" "iperf3" "${iperf_mbps}" "${iperf_mbps}" "" "" "" "${log_dir}/${host_label}"

      echo "public_path_sample host=${remote} run=${run} tool=derphole"
      mkdir -p "${case_log_dir}"
      if run_derphole_forward_sample "${remote}" "${host_label}" "${run}" >"${promotion_out}" 2>&1; then
        promotion_status=0
      else
        promotion_status="$?"
        cat "${promotion_out}" >&2
      fi
      cat "${promotion_out}"
      derphole_mbps="$(extract_benchmark_goodput "${promotion_out}")"
      if trace_summary="$(run_trace_checks "${case_log_dir}")"; then
        if [[ "${promotion_status}" -eq 0 ]]; then
          trace_ok="true"
        else
          trace_ok="false"
        fi
      else
        trace_status="$?"
        trace_ok="false"
      fi
      IFS=$'\t' read -r max_queue max_flatline <<<"${trace_summary}"
      append_summary_row "${host_label}" "${run}" "derphole" "${derphole_mbps}" "${iperf_mbps}" "${trace_ok}" "${max_queue}" "${max_flatline}" "${case_log_dir}"
      if [[ "${trace_status}" -ne 0 || "${promotion_status}" -ne 0 ]]; then
        trace_failures=1
      fi
    done
  done

  echo "summary_csv=${summary_csv}"
  if [[ "${trace_failures}" -ne 0 ]]; then
    exit 1
  fi
}

main "$@"
