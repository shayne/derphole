#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

hosts_raw="${DERPHOLE_PUBLIC_PATH_HOSTS:-ubuntu@derphole-testing ubuntu@eric-nuc root@hetz root@canlxc}"
size_mib="${DERPHOLE_PUBLIC_PATH_SIZE_MIB:-1024}"
runs="${DERPHOLE_PUBLIC_PATH_RUNS:-3}"
initial_rates_raw="${DERPHOLE_PUBLIC_PATH_INITIAL_RATES:-}"
initial_rates=()
iperf_port="${DERPHOLE_PUBLIC_IPERF_PORT:-8123}"
direction="${DERPHOLE_PUBLIC_PATH_DIRECTION:-forward}"
iperf_server_host="${DERPHOLE_PUBLIC_IPERF_SERVER_HOST:-}"
log_dir="${DERPHOLE_BENCH_LOG_DIR:-.tmp/public-path-performance}"
remote_output_root="${DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT:-derphole-bench/public-path}"
summary_csv="${log_dir}/summary.csv"
remote_user="${DERPHOLE_REMOTE_USER:-ubuntu}"

if [[ "${1:-}" != "" ]]; then
  hosts_raw="$1"
fi

if [[ -n "${initial_rates_raw}" ]]; then
  read -r -a initial_rates <<<"${initial_rates_raw}"
  for initial_rate in "${initial_rates[@]}"; do
    if [[ ! "${initial_rate}" =~ ^[0-9]+$ ]] ||
       ((initial_rate < 128 || initial_rate > 2400)); then
      echo "DERPHOLE_PUBLIC_PATH_INITIAL_RATES contains invalid rate: ${initial_rate}" >&2
      exit 2
    fi
  done
  runs="${#initial_rates[@]}"
else
  for _ in $(seq 1 "${runs}"); do
    initial_rates+=("")
  done
fi

case "${direction}" in
  forward)
    promotion_script="./scripts/promotion-test.sh"
    iperf_reverse_flag="-R"
    ;;
  reverse)
    promotion_script="./scripts/promotion-test-reverse.sh"
    iperf_reverse_flag=""
    ;;
  *)
    echo "DERPHOLE_PUBLIC_PATH_DIRECTION must be forward or reverse (got: ${direction})" >&2
    exit 2
    ;;
esac

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

run_iperf_sample() {
  local remote="$1"
  local host_label="$2"
  local run="$3"
  local out="${log_dir}/${host_label}/iperf3-run-${run}.json"
  local remote_cmd=(iperf3 -4 -J)
  local remote_cmd_quoted

  mkdir -p "$(dirname "${out}")"
  iperf3 -s -4 -p "${iperf_port}" --one-off --forceflush >"${log_dir}/${host_label}/iperf3-server-${run}.log" 2>&1 &
  local server_pid="$!"
  trap 'kill "${server_pid}" 2>/dev/null || true' RETURN
  sleep 1
  if [[ -n "${iperf_reverse_flag}" ]]; then
    remote_cmd+=("${iperf_reverse_flag}")
  fi
  remote_cmd+=(-c "${iperf_server_host}" -p "${iperf_port}" -t 20 -P 4)
  printf -v remote_cmd_quoted '%q ' "${remote_cmd[@]}"
  ssh -n -o BatchMode=yes "${remote}" "${remote_cmd_quoted}" >"${out}"
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

run_derphole_sample() {
  local remote="$1"
  local host_label="$2"
  local run="$3"
  local initial_rate="$4"
  local case_log_dir="${log_dir}/${host_label}/derphole-run-${run}"
  local target="${remote}"
  local experiment_env=()

  mkdir -p "${case_log_dir}"
  if [[ -n "${initial_rate}" ]]; then
    experiment_env+=(DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS="${initial_rate}")
  fi
  env \
    -u DERPHOLE_V2_RAW_DIRECT \
    -u DERPHOLE_V2_RAW_DIRECT_BUDGET_MS \
    -u DERPHOLE_V2_MANAGER_QUIC_FANOUT \
    -u DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS \
    "${experiment_env[@]}" \
    DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
    DERPHOLE_BENCH_WORKLOAD=file \
    DERPHOLE_BENCH_DIRECTION="${direction}" \
    DERPHOLE_BENCH_LOG_DIR="${case_log_dir}" \
    DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT="${remote_output_root}/${host_label}/run-${run}" \
      "${promotion_script}" "${target}" "${size_mib}"
}

append_summary_row() {
  local host_label="$1"
  local run="$2"
  local tool="$3"
  local workload="$4"
  local transfer_mode="$5"
  local mbps="$6"
  local iperf_mbps="$7"
  local trace_mbps="$8"
  local wall_mbps="$9"
  local transfer_elapsed_ms="${10}"
  local command_duration_ms="${11}"
  local total_duration_ms="${12}"
  local trace_ok="${13}"
  local max_queue="${14}"
  local max_flatline="${15}"
  local sample_log_dir="${16}"
  local initial_rate_mbps="${17}"
  local repair_bytes="${18}"
  local retransmits="${19}"
  local local_enobufs_retries="${20}"
  local local_enobufs_wait_us="${21}"
  local local_enobufs_max_consecutive="${22}"
  local min_rate_target_mbps="${23}"
  local final_rate_target_mbps="${24}"
  local controller_decreases="${25}"
  local receiver_rate_p10_mbps="${26}"
  local receiver_rate_p50_mbps="${27}"
  local receiver_rate_p90_mbps="${28}"
  local receiver_rate_cv="${29}"
  local receiver_windows_below_500_mbps="${30}"
  local benchmark_size_bytes="${31}"
  local revision_label="${32}"
  local sender_user_cpu_seconds="${33}"
  local sender_system_cpu_seconds="${34}"
  local sender_max_rss_bytes="${35}"
  local receiver_user_cpu_seconds="${36}"
  local receiver_system_cpu_seconds="${37}"
  local receiver_max_rss_bytes="${38}"
  local missing_scan_checks="${39}"
  local pending_missing="${40}"
  local pending_missing_peak="${41}"
  local repair_requested_packets="${42}"
  local repair_request_batches="${43}"
  local reorder_trail_packets="${44}"
  local receive_packet_rate_pps="${45}"

  python3 - \
    "${summary_csv}" \
    "${host_label}" \
    "${run}" \
    "${tool}" \
    "${direction}" \
    "${workload}" \
    "${transfer_mode}" \
    "${mbps}" \
    "${iperf_mbps}" \
    "${trace_mbps}" \
    "${wall_mbps}" \
    "${transfer_elapsed_ms}" \
    "${command_duration_ms}" \
    "${total_duration_ms}" \
    "${trace_ok}" \
    "${max_queue}" \
    "${max_flatline}" \
    "${sample_log_dir}" \
    "${initial_rate_mbps}" \
    "${repair_bytes}" \
    "${retransmits}" \
    "${local_enobufs_retries}" \
    "${local_enobufs_wait_us}" \
    "${local_enobufs_max_consecutive}" \
    "${min_rate_target_mbps}" \
    "${final_rate_target_mbps}" \
    "${controller_decreases}" \
    "${receiver_rate_p10_mbps}" \
    "${receiver_rate_p50_mbps}" \
    "${receiver_rate_p90_mbps}" \
    "${receiver_rate_cv}" \
    "${receiver_windows_below_500_mbps}" \
    "${benchmark_size_bytes}" \
    "${revision_label}" \
    "${sender_user_cpu_seconds}" \
    "${sender_system_cpu_seconds}" \
    "${sender_max_rss_bytes}" \
    "${receiver_user_cpu_seconds}" \
    "${receiver_system_cpu_seconds}" \
    "${receiver_max_rss_bytes}" \
    "${missing_scan_checks}" \
    "${pending_missing}" \
    "${pending_missing_peak}" \
    "${repair_requested_packets}" \
    "${repair_request_batches}" \
    "${reorder_trail_packets}" \
    "${receive_packet_rate_pps}" <<'PY'
import csv
import math
import sys

(
    path,
    host,
    run,
    tool,
    direction,
    workload,
    transfer_mode,
    mbps,
    iperf_mbps,
    trace_mbps,
    wall_mbps,
    transfer_elapsed_ms,
    command_duration_ms,
    total_duration_ms,
    trace_ok,
    max_queue,
    max_flatline,
    log_dir,
    initial_rate_mbps,
    repair_bytes,
    retransmits,
    local_enobufs_retries,
    local_enobufs_wait_us,
    local_enobufs_max_consecutive,
    min_rate_target_mbps,
    final_rate_target_mbps,
    controller_decreases,
    receiver_rate_p10_mbps,
    receiver_rate_p50_mbps,
    receiver_rate_p90_mbps,
    receiver_rate_cv,
    receiver_windows_below_500_mbps,
    benchmark_size_bytes,
    revision_label,
    sender_user_cpu_seconds,
    sender_system_cpu_seconds,
    sender_max_rss_bytes,
    receiver_user_cpu_seconds,
    receiver_system_cpu_seconds,
    receiver_max_rss_bytes,
    missing_scan_checks,
    pending_missing,
    pending_missing_peak,
    repair_requested_packets,
    repair_request_batches,
    reorder_trail_packets,
    receive_packet_rate_pps,
) = sys.argv[1:]
ratio = ""
wall_ratio = ""
repair_ratio = ""
sender_cpu_seconds_per_gib = ""
receiver_cpu_seconds_per_gib = ""
scan_checks_per_packet = ""
if mbps and float(iperf_mbps) > 0:
    ratio = f"{float(mbps) / float(iperf_mbps):.3f}"
if wall_mbps and float(iperf_mbps) > 0:
    wall_ratio = f"{float(wall_mbps) / float(iperf_mbps):.3f}"
if repair_bytes and int(benchmark_size_bytes) > 0:
    repair_ratio = f"{int(repair_bytes) / int(benchmark_size_bytes):.4f}"
if benchmark_size_bytes and int(benchmark_size_bytes) > 0:
    gib = int(benchmark_size_bytes) / float(1 << 30)
    if sender_user_cpu_seconds and sender_system_cpu_seconds:
        sender_cpu_seconds_per_gib = f"{(float(sender_user_cpu_seconds) + float(sender_system_cpu_seconds)) / gib:.6f}"
    if receiver_user_cpu_seconds and receiver_system_cpu_seconds:
        receiver_cpu_seconds_per_gib = f"{(float(receiver_user_cpu_seconds) + float(receiver_system_cpu_seconds)) / gib:.6f}"
    if missing_scan_checks:
        packets = math.ceil(int(benchmark_size_bytes) / 1358)
        scan_checks_per_packet = f"{int(missing_scan_checks) / packets:.6f}"
bulk_values = [
    missing_scan_checks,
    pending_missing,
    pending_missing_peak,
    repair_requested_packets,
    repair_request_batches,
    reorder_trail_packets,
    receive_packet_rate_pps,
    scan_checks_per_packet,
]
if transfer_mode == "blocks-v1":
    bulk_values = [""] * len(bulk_values)
with open(path, "a", newline="") as fh:
    csv.writer(fh).writerow([
        host,
        run,
        tool,
        direction,
        workload,
        transfer_mode,
        mbps,
        ratio,
        trace_mbps,
        wall_mbps,
        wall_ratio,
        transfer_elapsed_ms,
        command_duration_ms,
        total_duration_ms,
        trace_ok,
        max_queue,
        max_flatline,
        log_dir,
        initial_rate_mbps,
        repair_bytes,
        repair_ratio,
        retransmits,
        local_enobufs_retries,
        local_enobufs_wait_us,
        local_enobufs_max_consecutive,
        min_rate_target_mbps,
        final_rate_target_mbps,
        controller_decreases,
        receiver_rate_p10_mbps,
        receiver_rate_p50_mbps,
        receiver_rate_p90_mbps,
        receiver_rate_cv,
        receiver_windows_below_500_mbps,
        revision_label,
        sender_user_cpu_seconds,
        sender_system_cpu_seconds,
        sender_cpu_seconds_per_gib,
        sender_max_rss_bytes,
        receiver_user_cpu_seconds,
        receiver_system_cpu_seconds,
        receiver_cpu_seconds_per_gib,
        receiver_max_rss_bytes,
        *bulk_values,
    ])
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

extract_benchmark_value() {
  local output="$1"
  local field="$2"
  local default_value="${3-0}"

  python3 - "${output}" "${field}" "${default_value}" <<'PY'
import sys

path, field, default = sys.argv[1:]
prefix = field + "="
value = ""
with open(path, errors="replace") as fh:
    for line in fh:
        line = line.strip()
        if line.startswith(prefix):
            value = line[len(prefix):]
print(value or default)
PY
}

extract_benchmark_goodput() {
  local output="$1"
  local value

  value="$(extract_benchmark_value "${output}" "benchmark-goodput-mbps" "")"
  if [[ -n "${value}" ]]; then
    printf '%s\n' "${value}"
    return 0
  fi
  extract_benchmark_value "${output}" "sender_goodput_mbps" ""
}

accounting_mbps_match() {
  local footer_mbps="$1"
  local trace_mbps="$2"

  python3 - "${footer_mbps}" "${trace_mbps}" <<'PY'
from decimal import Decimal, InvalidOperation
import sys

try:
    footer, trace = (Decimal(value) for value in sys.argv[1:])
    matches = footer.is_finite() and trace.is_finite() and abs(footer - trace) <= Decimal("0.01")
except (InvalidOperation, ValueError):
    matches = False

raise SystemExit(0 if matches else 1)
PY
}

extract_tracecheck_summary() {
  python3 - "$@" <<'PY'
import re
import sys

def metric(text, key):
    match = re.search(rf"(?:^| ){re.escape(key)}=([^ \n]+)", text)
    return match.group(1) if match else ""

combined_text = ""
for path in sys.argv[1:]:
    with open(path, errors="replace") as fh:
        combined_text += fh.read() + "\n"

keys = [
    "max_peer_recv_queue_depth",
    "max_flatline",
    "sender_mbps",
    "final_repair_bytes",
    "max_retransmits",
    "local_enobufs_retries",
    "local_enobufs_wait_us",
    "local_enobufs_max_consecutive",
    "min_rate_target_mbps",
    "final_rate_target_mbps",
    "controller_decreases",
    "receiver_rate_p10_mbps",
    "receiver_rate_p50_mbps",
    "receiver_rate_p90_mbps",
    "receiver_rate_cv",
    "receiver_windows_below_500_mbps",
    "missing_scan_checks",
    "pending_missing",
    "pending_missing_peak",
    "repair_requested_packets",
    "repair_request_batches",
    "reorder_trail_packets",
    "receive_packet_rate_pps",
]
print("\t".join(metric(combined_text, key) for key in keys))
PY
}

validate_current_sender_health_summary() {
  local sender_trace="$1"
  local sender_check="$2"

  python3 - "${sender_trace}" "${sender_check}" <<'PY'
import csv
import re
import sys

trace_path, summary_path = sys.argv[1:]
with open(trace_path, newline="") as fh:
    header = next(csv.reader(fh), [])
if "local_enobufs_retries" not in header:
    raise SystemExit(0)

with open(summary_path, errors="replace") as fh:
    text = fh.read()
required = [
    "final_repair_bytes",
    "max_retransmits",
    "local_enobufs_retries",
    "local_enobufs_wait_us",
    "local_enobufs_max_consecutive",
    "min_rate_target_mbps",
    "final_rate_target_mbps",
    "controller_decreases",
]
for key in required:
    match = re.search(rf"(?:^| ){re.escape(key)}=([^ \n]+)", text)
    if not match or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", match.group(1)):
        print(f"current sender trace missing numeric {key}", file=sys.stderr)
        raise SystemExit(1)
PY
}

first_sender_rate_selected() {
  local sender_trace="$1"

  python3 - "${sender_trace}" <<'PY'
import csv
import sys

with open(sys.argv[1], newline="") as fh:
    for row in csv.DictReader(fh):
        if (row.get("role") or "").strip() != "send":
            continue
        value = (row.get("rate_selected_mbps") or "").strip()
        if value:
            print(value)
            break
PY
}

run_trace_checks() {
  local case_log_dir="$1"
  local initial_rate="$2"
  local sender_trace
  local receiver_trace
  local sender_check="${case_log_dir}/sender-transfertracecheck.txt"
  local receiver_check="${case_log_dir}/receiver-transfertracecheck.txt"
  local selected_rate
  local summary
  local status=0

  sender_trace="$(latest_file "${case_log_dir}" "*-sender.trace.csv")"
  receiver_trace="$(latest_file "${case_log_dir}" "*-receiver.trace.csv")"
  if [[ -z "${sender_trace}" || -z "${receiver_trace}" ]]; then
    echo "missing preserved transfer traces in ${case_log_dir}" >&2
    printf '0\t0s\t\n'
    return 1
  fi

  if ! mise exec -- go run ./tools/transfertracecheck -role send -stall-window 999ms -peer-trace "${receiver_trace}" "${sender_trace}" >"${sender_check}" 2>&1; then
    status=1
  fi
  if ! mise exec -- go run ./tools/transfertracecheck -role receive -stall-window 999ms "${receiver_trace}" >"${receiver_check}" 2>&1; then
    status=1
  fi
  summary="$(extract_tracecheck_summary "${sender_check}" "${receiver_check}")"
  if ! validate_current_sender_health_summary "${sender_trace}" "${sender_check}"; then
    status=1
  fi
  if [[ -n "${initial_rate}" ]]; then
    selected_rate="$(first_sender_rate_selected "${sender_trace}")"
    if [[ "${selected_rate}" != "${initial_rate}" ]]; then
      echo "initial rate mismatch: requested=${initial_rate} selected=${selected_rate:-missing}" >&2
      status=1
    fi
  fi
  printf '%s\n' "${summary}"
  return "${status}"
}

main() {
  local hosts=()
  local trace_failures=0

  mkdir -p "${log_dir}"
  printf 'host,run,tool,direction,workload,transfer_mode,mbps,ratio_to_iperf,trace_mbps,wall_mbps,wall_ratio_to_iperf,transfer_elapsed_ms,command_duration_ms,total_duration_ms,trace_ok,max_peer_recv_queue_depth,max_flatline,log_dir,initial_rate_mbps,repair_bytes,repair_ratio,retransmits,local_enobufs_retries,local_enobufs_wait_us,local_enobufs_max_consecutive,min_rate_target_mbps,final_rate_target_mbps,controller_decreases,receiver_rate_p10_mbps,receiver_rate_p50_mbps,receiver_rate_p90_mbps,receiver_rate_cv,receiver_windows_below_500_mbps,revision_label,sender_user_cpu_seconds,sender_system_cpu_seconds,sender_cpu_seconds_per_gib,sender_max_rss_bytes,receiver_user_cpu_seconds,receiver_system_cpu_seconds,receiver_cpu_seconds_per_gib,receiver_max_rss_bytes,missing_scan_checks,pending_missing,pending_missing_peak,repair_requested_packets,repair_request_batches,reorder_trail_packets,receive_packet_rate_pps,scan_checks_per_packet\n' >"${summary_csv}"

  read -r -a hosts <<<"${hosts_raw}"
  if [[ "${#hosts[@]}" -eq 0 ]]; then
    echo "no public-path hosts configured" >&2
    exit 1
  fi

  if [[ -z "${iperf_server_host}" ]]; then
    iperf_server_host="$(public_ip)"
  fi
  echo "iperf_server_host=${iperf_server_host}"

  for host in "${hosts[@]}"; do
    local remote="${host}"
    local host_label
    if [[ "${remote}" != *"@"* ]]; then
      remote="${remote_user}@${remote}"
    fi
    host_label="$(host_label_for "${remote}")"
    ensure_iperf3 "${remote}"

    for run in $(seq 1 "${runs}"); do
      local initial_rate="${initial_rates[run-1]}"
      local iperf_mbps
      local case_log_dir="${log_dir}/${host_label}/derphole-run-${run}"
      local promotion_out="${case_log_dir}/promotion.out"
      local derphole_mbps
      local trace_summary
      local max_queue
      local max_flatline
      local trace_sender_mbps
      local wall_mbps
      local transfer_elapsed_ms
      local command_duration_ms
      local total_duration_ms
      local workload
      local transfer_mode
      local trace_ok
      local benchmark_size_bytes
      local repair_bytes
      local retransmits
      local local_enobufs_retries
      local local_enobufs_wait_us
      local local_enobufs_max_consecutive
      local min_rate_target_mbps
      local final_rate_target_mbps
      local controller_decreases
      local receiver_rate_p10_mbps
      local receiver_rate_p50_mbps
      local receiver_rate_p90_mbps
      local receiver_rate_cv
      local receiver_windows_below_500_mbps
      local revision_label
      local sender_user_cpu_seconds
      local sender_system_cpu_seconds
      local sender_max_rss_bytes
      local receiver_user_cpu_seconds
      local receiver_system_cpu_seconds
      local receiver_max_rss_bytes
      local missing_scan_checks
      local pending_missing
      local pending_missing_peak
      local repair_requested_packets
      local repair_request_batches
      local reorder_trail_packets
      local receive_packet_rate_pps
      local trace_status=0
      local promotion_status=0

      echo "public_path_sample host=${remote} run=${run} tool=iperf3"
      iperf_mbps="$(run_iperf_sample "${remote}" "${host_label}" "${run}")"
      append_summary_row \
        "${host_label}" \
        "${run}" \
        "iperf3" \
        "stream" \
        "tcp" \
        "${iperf_mbps}" \
        "${iperf_mbps}" \
        "" "" "" "" "" "" "" "" \
        "${log_dir}/${host_label}" \
        "${initial_rate}" \
        "" "" "" "" "" "" "" "" "" "" "" "" "" "" \
        "" "" "" "" "" "" "" "" "" "" "" "" "" ""

      echo "public_path_sample host=${remote} run=${run} tool=derphole"
      mkdir -p "${case_log_dir}"
      if run_derphole_sample "${remote}" "${host_label}" "${run}" "${initial_rate}" >"${promotion_out}" 2>&1; then
        promotion_status=0
      else
        promotion_status="$?"
        cat "${promotion_out}" >&2
      fi
      cat "${promotion_out}"
      derphole_mbps="$(extract_benchmark_goodput "${promotion_out}")"
      wall_mbps="$(extract_benchmark_value "${promotion_out}" "benchmark-wall-goodput-mbps")"
      transfer_elapsed_ms="$(extract_benchmark_value "${promotion_out}" "benchmark-transfer-elapsed-ms")"
      command_duration_ms="$(extract_benchmark_value "${promotion_out}" "benchmark-command-duration-ms")"
      total_duration_ms="$(extract_benchmark_value "${promotion_out}" "benchmark-total-duration-ms")"
      benchmark_size_bytes="$(extract_benchmark_value "${promotion_out}" "benchmark-size-bytes")"
      workload="$(extract_benchmark_value "${promotion_out}" "benchmark-workload" "unknown")"
      transfer_mode="$(extract_benchmark_value "${promotion_out}" "benchmark-transfer-mode" "unknown")"
      revision_label="$(extract_benchmark_value "${promotion_out}" "benchmark-revision-label" "")"
      sender_user_cpu_seconds="$(extract_benchmark_value "${promotion_out}" "benchmark-sender-user-cpu-seconds" "")"
      sender_system_cpu_seconds="$(extract_benchmark_value "${promotion_out}" "benchmark-sender-system-cpu-seconds" "")"
      sender_max_rss_bytes="$(extract_benchmark_value "${promotion_out}" "benchmark-sender-max-rss-bytes" "")"
      receiver_user_cpu_seconds="$(extract_benchmark_value "${promotion_out}" "benchmark-receiver-user-cpu-seconds" "")"
      receiver_system_cpu_seconds="$(extract_benchmark_value "${promotion_out}" "benchmark-receiver-system-cpu-seconds" "")"
      receiver_max_rss_bytes="$(extract_benchmark_value "${promotion_out}" "benchmark-receiver-max-rss-bytes" "")"
      if trace_summary="$(run_trace_checks "${case_log_dir}" "${initial_rate}")"; then
        if [[ "${promotion_status}" -eq 0 ]]; then
          trace_ok="true"
        else
          trace_ok="false"
        fi
      else
        trace_status="$?"
        trace_ok="false"
      fi
      trace_summary="${trace_summary//$'\t'/$'\x1f'}"
      IFS=$'\x1f' read -r \
        max_queue \
        max_flatline \
        trace_sender_mbps \
        repair_bytes \
        retransmits \
        local_enobufs_retries \
        local_enobufs_wait_us \
        local_enobufs_max_consecutive \
        min_rate_target_mbps \
        final_rate_target_mbps \
        controller_decreases \
        receiver_rate_p10_mbps \
        receiver_rate_p50_mbps \
        receiver_rate_p90_mbps \
        receiver_rate_cv \
        receiver_windows_below_500_mbps \
        missing_scan_checks \
        pending_missing \
        pending_missing_peak \
        repair_requested_packets \
        repair_request_batches \
        reorder_trail_packets \
        receive_packet_rate_pps <<<"${trace_summary}"
      if ! accounting_mbps_match "${derphole_mbps}" "${trace_sender_mbps}"; then
        echo "benchmark accounting mismatch: footer=${derphole_mbps} trace=${trace_sender_mbps:-missing}" >&2
        trace_ok="false"
        trace_status=1
      fi
      append_summary_row \
        "${host_label}" \
        "${run}" \
        "derphole" \
        "${workload}" \
        "${transfer_mode}" \
        "${derphole_mbps}" \
        "${iperf_mbps}" \
        "${trace_sender_mbps}" \
        "${wall_mbps}" \
        "${transfer_elapsed_ms}" \
        "${command_duration_ms}" \
        "${total_duration_ms}" \
        "${trace_ok}" \
        "${max_queue}" \
        "${max_flatline}" \
        "${case_log_dir}" \
        "${initial_rate}" \
        "${repair_bytes}" \
        "${retransmits}" \
        "${local_enobufs_retries}" \
        "${local_enobufs_wait_us}" \
        "${local_enobufs_max_consecutive}" \
        "${min_rate_target_mbps}" \
        "${final_rate_target_mbps}" \
        "${controller_decreases}" \
        "${receiver_rate_p10_mbps}" \
        "${receiver_rate_p50_mbps}" \
        "${receiver_rate_p90_mbps}" \
        "${receiver_rate_cv}" \
        "${receiver_windows_below_500_mbps}" \
        "${benchmark_size_bytes}" \
        "${revision_label}" \
        "${sender_user_cpu_seconds}" \
        "${sender_system_cpu_seconds}" \
        "${sender_max_rss_bytes}" \
        "${receiver_user_cpu_seconds}" \
        "${receiver_system_cpu_seconds}" \
        "${receiver_max_rss_bytes}" \
        "${missing_scan_checks}" \
        "${pending_missing}" \
        "${pending_missing_peak}" \
        "${repair_requested_packets}" \
        "${repair_request_batches}" \
        "${reorder_trail_packets}" \
        "${receive_packet_rate_pps}"
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
