#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

tool="${DERPHOLE_BENCH_TOOL:?DERPHOLE_BENCH_TOOL is required}"
direction="${DERPHOLE_BENCH_DIRECTION:?DERPHOLE_BENCH_DIRECTION is required}"
workload="${DERPHOLE_BENCH_WORKLOAD:-file}"
case "${workload}" in
  file|stream) ;;
  *) echo "DERPHOLE_BENCH_WORKLOAD must be file or stream (got: ${workload})" >&2; exit 2 ;;
esac
if [[ "${workload}" == "file" && -n "${DERPHOLE_BENCH_PARALLEL:-}" ]]; then
  echo "DERPHOLE_BENCH_PARALLEL is only valid for the stream workload" >&2
  exit 2
fi
bulk_initial_rate="${DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS:-}"
if [[ -n "${bulk_initial_rate}" ]]; then
  if [[ ! "${bulk_initial_rate}" =~ ^[0-9]+$ ]] ||
     ((bulk_initial_rate < 128 || bulk_initial_rate > 2400)); then
    echo "DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS must be an integer from 128 through 2400" >&2
    exit 2
  fi
fi
bulk_batched_io="${DERPHOLE_TEST_BULK_BATCHED_IO:-}"
if [[ -n "${bulk_batched_io}" && "${bulk_batched_io}" != "1" ]]; then
  echo "DERPHOLE_TEST_BULK_BATCHED_IO must be empty or 1" >&2
  exit 2
fi
force_bulk_packets="${DERPHOLE_TEST_FORCE_BULK_PACKET_TRANSFER:-}"
if [[ -n "${force_bulk_packets}" && "${force_bulk_packets}" != "1" ]]; then
  echo "DERPHOLE_TEST_FORCE_BULK_PACKET_TRANSFER must be empty or 1" >&2
  exit 2
fi
bulk_probe_outcome="${DERPHOLE_TEST_BULK_PROBE_OUTCOME-}"
bulk_probe_outcome_configured=false
if [[ "${DERPHOLE_TEST_BULK_PROBE_OUTCOME+x}" == x ]]; then
  bulk_probe_outcome_configured=true
  if [[ "${bulk_probe_outcome}" != "sender-reject" ]]; then
    echo "DERPHOLE_TEST_BULK_PROBE_OUTCOME must be unset or sender-reject" >&2
    exit 2
  fi
  if [[ "${tool}" != "derphole" || "${workload}" != "file" ]]; then
    echo "DERPHOLE_TEST_BULK_PROBE_OUTCOME requires the derphole file workload" >&2
    exit 2
  fi
fi
unset DERPHOLE_TEST_BULK_PROBE_OUTCOME
bulk_probe_outcome_label="unset"
sender_test_env=()
sender_test_env_remote=""
if [[ "${bulk_probe_outcome_configured}" == true ]]; then
  bulk_probe_outcome_label="${bulk_probe_outcome}"
  sender_test_env+=(DERPHOLE_TEST_BULK_PROBE_OUTCOME="${bulk_probe_outcome}")
  sender_test_env_remote="DERPHOLE_TEST_BULK_PROBE_OUTCOME=sender-reject "
fi
bulk_probe_dirty_rate="${DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS-}"
bulk_probe_dirty_rate_configured=false
if [[ "${DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS+x}" == x ]]; then
  bulk_probe_dirty_rate_configured=true
  if [[ ! "${bulk_probe_dirty_rate}" =~ ^(128|512|1000|1600|2000|2200|2400)$ ]]; then
    echo "DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS must be one configured probe rate" >&2
    exit 2
  fi
  if [[ "${tool}" != "derphole" || "${workload}" != "file" ]]; then
    echo "DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS requires the derphole file workload" >&2
    exit 2
  fi
fi
unset DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS
bulk_probe_dirty_rate_label="unset"
receiver_test_env=()
receiver_test_env_remote=""
if [[ "${bulk_probe_dirty_rate_configured}" == true ]]; then
  bulk_probe_dirty_rate_label="${bulk_probe_dirty_rate}"
  receiver_test_env+=(DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS="${bulk_probe_dirty_rate}")
  receiver_test_env_remote="DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS=${bulk_probe_dirty_rate} "
fi
direct_tcp_port="${DERPHOLE_BENCH_DIRECT_TCP_PORT:-}"
if [[ -n "${direct_tcp_port}" ]]; then
  if [[ ! "${direct_tcp_port}" =~ ^[0-9]+$ ]] ||
     ((direct_tcp_port < 1 || direct_tcp_port > 65535)); then
    echo "DERPHOLE_BENCH_DIRECT_TCP_PORT must be an integer from 1 through 65535" >&2
    exit 2
  fi
fi
test_cpu_profile="${DERPHOLE_TEST_CPU_PROFILE:-}"
if [[ "${test_cpu_profile}" == *$'\n'* || "${test_cpu_profile}" == *$'\r'* ]]; then
  echo "DERPHOLE_TEST_CPU_PROFILE must be one path" >&2
  exit 2
fi
ready_file="${DERPHOLE_BENCH_READY_FILE:-}"
start_file="${DERPHOLE_BENCH_START_FILE:-}"
if [[ -n "${ready_file}" && -z "${start_file}" ]] || [[ -z "${ready_file}" && -n "${start_file}" ]]; then
  echo "DERPHOLE_BENCH_READY_FILE and DERPHOLE_BENCH_START_FILE must be set together" >&2
  exit 2
fi
for gate_file in "${ready_file}" "${start_file}"; do
  if [[ -n "${gate_file}" && ( "${gate_file}" != /* || "${gate_file}" == *$'\n'* || "${gate_file}" == *$'\r'* ) ]]; then
    echo "benchmark gate paths must be absolute single-line paths" >&2
    exit 2
  fi
done
process_identify_local="${DERPHOLE_BENCH_PROCESS_IDENTIFY_LOCAL:-}"
process_identify_remote="${DERPHOLE_BENCH_PROCESS_IDENTIFY_REMOTE:-}"
process_evidence_dir="${DERPHOLE_BENCH_PROCESS_EVIDENCE_DIR:-}"
child_cleanup_out="${DERPHOLE_BENCH_CHILD_CLEANUP_OUT:-}"
identity_evidence_enabled=false
if [[ -n "${process_identify_local}${process_identify_remote}${process_evidence_dir}${child_cleanup_out}" ]]; then
  if [[ -z "${process_identify_local}" || -z "${process_identify_remote}" || -z "${process_evidence_dir}" || -z "${child_cleanup_out}" ]]; then
    echo "benchmark process identity evidence variables must be set together" >&2
    exit 2
  fi
  for identity_path in "${process_identify_local}" "${process_identify_remote}" "${process_evidence_dir}" "${child_cleanup_out}"; do
    if [[ "${identity_path}" != /* || "${identity_path}" == *$'\n'* || "${identity_path}" == *$'\r'* ]]; then
      echo "benchmark process identity evidence paths must be absolute single-line paths" >&2
      exit 2
    fi
  done
  [[ -x "${process_identify_local}" ]] || { echo "local process identity helper is not executable" >&2; exit 2; }
  [[ -d "$(dirname "${process_evidence_dir}")" && ! -L "$(dirname "${process_evidence_dir}")" ]] || { echo "process evidence parent is invalid" >&2; exit 2; }
  [[ ! -e "${process_evidence_dir}" && ! -L "${process_evidence_dir}" && ! -e "${child_cleanup_out}" && ! -L "${child_cleanup_out}" ]] || { echo "process evidence output already exists" >&2; exit 2; }
  mkdir -m 0700 "${process_evidence_dir}"
  identity_evidence_enabled=true
fi
transfer_mode="unknown"

local_override="${DERPHOLE_BENCH_LOCAL_BIN:-}"
linux_override="${DERPHOLE_BENCH_LINUX_BIN:-}"
local_expected_sha256="${DERPHOLE_BENCH_LOCAL_BIN_SHA256:-}"
linux_expected_sha256="${DERPHOLE_BENCH_LINUX_BIN_SHA256:-}"
if [[ -n "${local_override}" && -z "${linux_override}" ]] ||
   [[ -z "${local_override}" && -n "${linux_override}" ]]; then
  echo "DERPHOLE_BENCH_LOCAL_BIN and DERPHOLE_BENCH_LINUX_BIN must be set together" >&2
  exit 2
fi
if [[ -n "${local_expected_sha256}" && -z "${linux_expected_sha256}" ]] ||
   [[ -z "${local_expected_sha256}" && -n "${linux_expected_sha256}" ]]; then
  echo "DERPHOLE_BENCH_LOCAL_BIN_SHA256 and DERPHOLE_BENCH_LINUX_BIN_SHA256 must be set together" >&2
  exit 2
fi
for expected_sha256 in "${local_expected_sha256}" "${linux_expected_sha256}"; do
  if [[ -n "${expected_sha256}" && ! "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "benchmark binary SHA-256 values must be lowercase hexadecimal" >&2
    exit 2
  fi
done

echo "benchmark-test-bulk-probe-outcome=${bulk_probe_outcome_label}"
echo "benchmark-test-bulk-probe-dirty-rate-mbps=${bulk_probe_dirty_rate_label}"

target="${1:?usage: $0 <target> [size-mib]}"
size_mib="${2:-1024}"
expected_size="$((size_mib * 1048576))"
local_tmp_root="${DERPHOLE_BENCH_LOCAL_TMP_ROOT:-.tmp/promotion-benchmark}"
mkdir -p "${local_tmp_root}"
tmp="$(mktemp -d "${local_tmp_root%/}/${tool}-${direction}.XXXXXX")"
start_ms=0
command_end_ms=0
command_duration_ms=0
duration_ms=0
sender_transfer_elapsed_ms=0
sender_goodput_mbps=0
sender_peak_goodput_mbps=0
sender_first_byte_ms=0
wall_goodput=0
remote_suffix=""
if [[ "${direction}" == "reverse" ]]; then
  remote_suffix="-reverse"
fi
remote_output_root="${DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT:-derphole-bench/promotion}"
remote_run_dir="${remote_output_root%/}/${tool}-promotion${remote_suffix}-$$"
remote_base="${remote_run_dir}/run"
remote_target="${target}"
if [[ "${target}" != *"@"* ]]; then
  remote_user="${DERPHOLE_REMOTE_USER:-root}"
  remote_target="${remote_user}@${target}"
fi
remote_bin_dir="${remote_run_dir}/bin"
if [[ -n "${DERPHOLE_REMOTE_BIN_DIR:-}" ]]; then
  remote_bin_dir="${DERPHOLE_REMOTE_BIN_DIR%/}/${tool}-promotion${remote_suffix}-$$"
fi
remote_bin="${remote_bin_dir}/${tool}"
remote_upload="${remote_bin_dir}/${tool}.upload"
local_bin="${DERPHOLE_BENCH_LOCAL_BIN:-./dist/${tool}}"
linux_bin="${DERPHOLE_BENCH_LINUX_BIN:-dist/${tool}-linux-amd64}"
local_runstats="${tmp}/runstats"
linux_runstats="${tmp}/runstats-linux-amd64"
remote_runstats="${remote_bin_dir}/runstats"
remote_runstats_upload="${remote_runstats}.upload"
sender_log="${tmp}/sender.err"
receiver_log="${tmp}/receiver.err"
sender_trace_csv="${tmp}/sender.trace.csv"
receiver_trace_csv="${tmp}/receiver.trace.csv"
sender_resource_json="${tmp}/sender.resource.json"
receiver_resource_json="${tmp}/receiver.resource.json"
remote_sender_resource_json="${remote_base}.sender.resource.json"
remote_receiver_resource_json="${remote_base}.receiver.resource.json"
receiver_out="${tmp}/receiver.out"
payload="${tmp}/payload.bin"
local_payload_override="${DERPHOLE_BENCH_LOCAL_PAYLOAD:-}"
remote_payload_override="${DERPHOLE_BENCH_REMOTE_PAYLOAD:-}"
remote_payload="${remote_base}.payload"
if [[ -n "${local_payload_override}" ]]; then
  payload="${local_payload_override}"
fi
if [[ -n "${remote_payload_override}" ]]; then
  remote_payload="${remote_payload_override}"
fi
revision_label="${DERPHOLE_BENCH_REVISION_LABEL:-}"
sender_user_cpu_seconds=""
sender_system_cpu_seconds=""
sender_max_rss_bytes=""
sender_resource_stats_available="false"
sender_resource_exit_code=""
receiver_user_cpu_seconds=""
receiver_system_cpu_seconds=""
receiver_max_rss_bytes=""
receiver_resource_stats_available="false"
receiver_resource_exit_code=""
send_pid=""
send_ref=""
send_child_ref=""
listener_pid=""
listener_ref=""
listener_child_ref=""
local_tool_pids_baseline=""
remote_tool_pids_baseline=""
source_sha=""
sink_sha=""
sink_size=""
remote_linux_bin_sha256=""
benchmark_cleanup_success="false"
benchmark_child_cleanup_success="false"
benchmark_child_cleanup_sha256=""
process_recheck_sequence=0
transfer_children_waited=false
remote_env=()
parallel_args=()
parallel_args_remote=""
direct_tcp_args=()

if [[ "${DERPHOLE_BENCH_PARALLEL:-}" != "" ]]; then
  parallel_args=(--parallel "${DERPHOLE_BENCH_PARALLEL}")
  parallel_args_remote="${parallel_args[*]-}"
fi
if [[ -n "${direct_tcp_port}" ]]; then
  direct_tcp_args=(--direct-tcp-port "${direct_tcp_port}")
fi
if [[ "${DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES:-}" == "1" ]]; then
  remote_env+=(DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1)
fi
if [[ -n "${DERPHOLE_V2_RAW_DIRECT:-}" ]]; then
  remote_env+=(DERPHOLE_V2_RAW_DIRECT="${DERPHOLE_V2_RAW_DIRECT}")
fi
if [[ -n "${DERPHOLE_V2_RAW_DIRECT_BUDGET_MS:-}" ]]; then
  remote_env+=(DERPHOLE_V2_RAW_DIRECT_BUDGET_MS="${DERPHOLE_V2_RAW_DIRECT_BUDGET_MS}")
fi
if [[ -n "${DERPHOLE_V2_MANAGER_QUIC_FANOUT:-}" ]]; then
  remote_env+=(DERPHOLE_V2_MANAGER_QUIC_FANOUT="${DERPHOLE_V2_MANAGER_QUIC_FANOUT}")
fi
if [[ -n "${bulk_initial_rate}" ]]; then
  remote_env+=(DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS="${bulk_initial_rate}")
fi
if [[ "${bulk_batched_io}" == "1" ]]; then
  remote_env+=(DERPHOLE_TEST_BULK_BATCHED_IO=1)
fi
if [[ "${force_bulk_packets}" == "1" ]]; then
  remote_env+=(DERPHOLE_TEST_FORCE_BULK_PACKET_TRANSFER=1)
fi
if [[ -n "${test_cpu_profile}" ]]; then
  remote_env+=(DERPHOLE_TEST_CPU_PROFILE="${test_cpu_profile}")
fi
remote() {
  local remote_command='env -i HOME="$HOME" PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}"'
  local assignment quoted
  for assignment in "${remote_env[@]+"${remote_env[@]}"}"; do
    printf -v quoted '%q' "${assignment}"
    remote_command+=" ${quoted}"
  done
  ssh "${remote_target}" "${remote_command} bash -se" <<<"$1"
}

install_remote_bin() {
  local desired_dir="$1"
  local desired_bin="${desired_dir%/}/${tool}"
  local desired_runstats="${desired_dir%/}/runstats"
  remote "install -m 0755 '${remote_upload}' '${desired_bin}' && install -m 0755 '${remote_runstats_upload}' '${desired_runstats}' && rm -f '${remote_upload}' '${remote_runstats_upload}' && '${desired_bin}' --help >/dev/null 2>&1"
}

now_ms() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import time; print(int(time.time() * 1000))'
    return 0
  fi
  perl -MTime::HiRes=time -e 'print int(time() * 1000), "\n"'
}

goodput_mbps() {
  python3 - <<'PY' "$1" "$2"
import sys
size = int(sys.argv[1])
duration_ms = max(int(sys.argv[2]), 1)
print(f"{(size * 8.0) / (duration_ms * 1000.0):.2f}")
PY
}

trace_metric_value() {
  local mode="$1"
  local file="$2"
  local key="$3"

  if [[ ! -s "${file}" ]]; then
    return 0
  fi
  python3 - "${mode}" "${file}" "${key}" <<'PY'
import csv
import sys

mode, path, key = sys.argv[1:4]
result = ""
best = None
with open(path, newline="") as fh:
    for row in csv.DictReader(fh):
        value = (row.get(key) or "").strip()
        if not value:
            continue
        if mode == "last":
            result = value
            continue
        try:
            numeric = float(value)
        except ValueError:
            continue
        if best is None or numeric > best:
            best = numeric
            result = f"{numeric:.2f}"
print(result)
PY
}

last_trace_value() {
  trace_metric_value last "$1" "$2"
}

max_trace_value() {
  trace_metric_value max "$1" "$2"
}

trace_transfer_goodput_mbps() {
  local file="$1"
  local expected_bytes="$2"
  local transfer_elapsed_ms

  transfer_elapsed_ms="$(last_trace_value "${file}" "transfer_elapsed_ms")"
  if [[ ! "${transfer_elapsed_ms}" =~ ^[1-9][0-9]*$ ]]; then
    return 1
  fi
  goodput_mbps "${expected_bytes}" "${transfer_elapsed_ms}"
}

trace_has_direct_bytes() {
  local file="$1"
  if [[ ! -s "${file}" ]]; then
    return 1
  fi
  python3 - "${file}" <<'PY'
import csv
import sys

with open(sys.argv[1], newline="") as fh:
    for row in csv.DictReader(fh):
        try:
            if int(row.get("direct_bytes") or "0") > 0:
                sys.exit(0)
        except ValueError:
            pass
        if (row.get("direct_validated") or "").lower() == "true":
            sys.exit(0)
sys.exit(1)
PY
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
    echo "benchmark-tool=${tool}"
    echo "benchmark-direction=${direction}"
    echo "benchmark-workload=${workload}"
    echo "benchmark-transfer-mode=${transfer_mode}"
    echo "benchmark-test-bulk-probe-outcome=${bulk_probe_outcome_label}"
    echo "benchmark-test-bulk-probe-dirty-rate-mbps=${bulk_probe_dirty_rate_label}"
    echo "benchmark-size-bytes=${expected_size}"
    echo "benchmark-transfer-elapsed-ms=${sender_transfer_elapsed_ms:-0}"
    echo "benchmark-command-duration-ms=${command_duration_ms:-0}"
    echo "benchmark-total-duration-ms=${duration_ms:-0}"
    echo "benchmark-goodput-mbps=${goodput_mbps}"
    echo "benchmark-wall-goodput-mbps=${wall_goodput:-0}"
    echo "benchmark-peak-goodput-mbps=${peak_goodput_mbps}"
    echo "benchmark-first-byte-ms=${first_byte_ms}"
    echo "benchmark-sender-user-cpu-seconds=${sender_user_cpu_seconds}"
    echo "benchmark-sender-system-cpu-seconds=${sender_system_cpu_seconds}"
    echo "benchmark-sender-max-rss-bytes=${sender_max_rss_bytes}"
    echo "benchmark-sender-resource-stats-available=${sender_resource_stats_available}"
    echo "benchmark-receiver-user-cpu-seconds=${receiver_user_cpu_seconds}"
    echo "benchmark-receiver-system-cpu-seconds=${receiver_system_cpu_seconds}"
    echo "benchmark-receiver-max-rss-bytes=${receiver_max_rss_bytes}"
    echo "benchmark-receiver-resource-stats-available=${receiver_resource_stats_available}"
    echo "benchmark-revision-label=${revision_label}"
    echo "benchmark-source-sha256=${source_sha}"
    echo "benchmark-sink-sha256=${sink_sha}"
    echo "benchmark-sink-size-bytes=${sink_size}"
    echo "benchmark-remote-linux-bin-sha256=${remote_linux_bin_sha256}"
    echo "benchmark-cleanup-success=${benchmark_cleanup_success}"
    echo "benchmark-child-cleanup-success=${benchmark_child_cleanup_success}"
    echo "benchmark-child-cleanup-sha256=${benchmark_child_cleanup_sha256}"
    echo "benchmark-success=${success}"
    if [[ -n "${error_text}" ]]; then
      echo "benchmark-error=${error_text}"
    fi
  } >&"${stream}"
}

load_resource_stats_for_role() {
  local role="$1"
  local file="$2"
  local summary
  local user_cpu_seconds
  local system_cpu_seconds
  local max_rss_bytes
  local available
  local exit_code

  if [[ ! -s "${file}" ]]; then
    echo "missing ${role} resource JSON: ${file}" >&2
    return 1
  fi
  if ! summary="$(python3 - "${file}" <<'PY'
import json
import math
import sys

path = sys.argv[1]
try:
    with open(path) as fh:
        value = json.load(fh)
    required = {
        "user_cpu_seconds",
        "system_cpu_seconds",
        "max_rss_bytes",
        "resource_stats_available",
        "exit_code",
    }
    if not isinstance(value, dict) or not required.issubset(value):
        raise ValueError("missing required fields")
    user = value["user_cpu_seconds"]
    system = value["system_cpu_seconds"]
    rss = value["max_rss_bytes"]
    available = value["resource_stats_available"]
    exit_code = value["exit_code"]
    if isinstance(user, bool) or not isinstance(user, (int, float)) or not math.isfinite(user) or user < 0:
        raise ValueError("invalid user_cpu_seconds")
    if isinstance(system, bool) or not isinstance(system, (int, float)) or not math.isfinite(system) or system < 0:
        raise ValueError("invalid system_cpu_seconds")
    if isinstance(rss, bool) or not isinstance(rss, int) or rss < 0:
        raise ValueError("invalid max_rss_bytes")
    if not isinstance(available, bool):
        raise ValueError("invalid resource_stats_available")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or exit_code < 0 or exit_code > 255:
        raise ValueError("invalid exit_code")
except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
    print(f"malformed resource JSON {path}: {exc}", file=sys.stderr)
    raise SystemExit(1)
print("\x1f".join((str(user), str(system), str(rss), str(available).lower(), str(exit_code))))
PY
)"; then
    return 1
  fi
  IFS=$'\x1f' read -r user_cpu_seconds system_cpu_seconds max_rss_bytes available exit_code <<<"${summary}"
  printf -v "${role}_user_cpu_seconds" '%s' "${user_cpu_seconds}"
  printf -v "${role}_system_cpu_seconds" '%s' "${system_cpu_seconds}"
  printf -v "${role}_max_rss_bytes" '%s' "${max_rss_bytes}"
  printf -v "${role}_resource_stats_available" '%s' "${available}"
  printf -v "${role}_resource_exit_code" '%s' "${exit_code}"
}

load_resource_stats() {
  local status=0
  load_resource_stats_for_role sender "${sender_resource_json}" || status=1
  load_resource_stats_for_role receiver "${receiver_resource_json}" || status=1
  return "${status}"
}

require_resource_stats() {
  local local_role="sender"
  local remote_role="receiver"
  local sender_location="local"
  local receiver_location="remote"
  if [[ "${direction}" == "reverse" ]]; then
    local_role="receiver"
    remote_role="sender"
    sender_location="remote"
    receiver_location="local"
  fi
  if [[ "${sender_resource_exit_code}" != "0" ]]; then
    echo "${sender_location} ${tool} process exited with status ${sender_resource_exit_code}" >&2
    return "${sender_resource_exit_code}"
  fi
  if [[ "${receiver_resource_exit_code}" != "0" ]]; then
    echo "${receiver_location} ${tool} process exited with status ${receiver_resource_exit_code}" >&2
    return "${receiver_resource_exit_code}"
  fi
  if [[ "${remote_role}" == "sender" && "${sender_resource_stats_available}" != "true" ]] ||
     [[ "${remote_role}" == "receiver" && "${receiver_resource_stats_available}" != "true" ]]; then
    echo "remote Linux ${remote_role} resource stats are unavailable" >&2
    return 1
  fi
  case "$(uname -s)" in
    Darwin|Linux)
      if [[ "${local_role}" == "sender" && "${sender_resource_stats_available}" != "true" ]] ||
         [[ "${local_role}" == "receiver" && "${receiver_resource_stats_available}" != "true" ]]; then
        echo "local ${local_role} resource stats are unavailable" >&2
        return 1
      fi
      ;;
  esac
}

list_local_tool_pids() {
  pgrep -x "${tool}" | sort -n | paste -sd, - || true
}

list_remote_tool_pids() {
  remote "pgrep -x '${tool}' | sort -n | paste -sd, - || true"
}

exclude_tool_pid_baseline() {
  local current="$1"
  local baseline="$2"
  local pid
  local new_pids=()

  while IFS= read -r pid; do
    [[ -n "${pid}" ]] || continue
    if [[ ",${baseline}," != *",${pid},"* ]]; then
      new_pids+=("${pid}")
    fi
  done < <(tr ',' '\n' <<<"${current}")
  (IFS=,; echo "${new_pids[*]-}")
}

new_local_tool_pids() {
  exclude_tool_pid_baseline "$(list_local_tool_pids)" "${local_tool_pids_baseline}"
}

new_remote_tool_pids() {
  exclude_tool_pid_baseline "$(list_remote_tool_pids)" "${remote_tool_pids_baseline}"
}

snapshot_tool_processes() {
  local_tool_pids_baseline="$(list_local_tool_pids)"
  remote_tool_pids_baseline="$(list_remote_tool_pids)"
}

count_local_udp_sockets() {
  local pids
  pids="$(new_local_tool_pids)"
  if [[ -z "${pids}" ]]; then
    echo 0
    return 0
  fi
  lsof -nP -a -p "${pids}" -iUDP 2>/dev/null | awk 'NR > 1 { count++ } END { print count + 0 }' || true
}

count_pid_list() {
  local pids="$1"
  if [[ -z "${pids}" ]]; then
    echo 0
    return 0
  fi
  awk -F, '{ print NF }' <<<"${pids}"
}

count_local_tool_processes() {
  count_pid_list "$(new_local_tool_pids)"
}

count_remote_udp_sockets() {
  local pids
  pids="$(new_remote_tool_pids)"
  remote "pids='${pids}'; if [[ -z \"\${pids}\" ]]; then echo 0; else lsof -nP -a -p \"\${pids}\" -iUDP 2>/dev/null | awk 'NR > 1 { count++ } END { print count + 0 }' || true; fi"
}

count_remote_tool_processes() {
  count_pid_list "$(new_remote_tool_pids)"
}

path_trace() {
  local file="$1"
  grep -E 'connected-(relay|direct)|v2-data-plane=(raw-direct|direct-tcp-files)|v2-raw-direct-active=[1-9][0-9]*|v2-direct-tcp-selected=true' "${file}" 2>/dev/null || true
}

path_changed_mid_run() {
  local trace="$1"
  grep -q 'connected-relay' <<<"${trace}" && grep -q 'connected-direct' <<<"${trace}"
}

has_direct_path_evidence() {
  grep -Eq 'connected-direct|v2-data-plane=(raw-direct|direct-tcp-files)|v2-raw-direct-active=[1-9][0-9]*|v2-direct-tcp-selected=true'
}

require_direct_evidence() {
  local label="$1"
  local trace="$2"

  if ! has_direct_path_evidence <<<"${trace}"; then
    echo "${label} missing direct promotion evidence" >&2
    exit 1
  fi
}

require_direct_trace() {
  local label="$1"
  local file="$2"

  if [[ ! -s "${file}" ]]; then
    echo "${label} missing transfer trace" >&2
    exit 1
  fi
  if ! trace_has_direct_bytes "${file}"; then
    echo "${label} missing direct transfer trace evidence" >&2
    exit 1
  fi
}

preserve_logs() {
  local log_dir="${DERPHOLE_BENCH_LOG_DIR:-}"
  local preserve_status=0
  if [[ -z "${log_dir}" ]]; then
    return 0
  fi
  if ! mkdir -p "${log_dir}"; then
    preserve_status=1
  fi
  local stamp
  if ! stamp="$(date -u +%Y%m%dT%H%M%SZ)"; then
    stamp="unknown"
    preserve_status=1
  fi
  local prefix="${tool}-${direction}-${target//[^A-Za-z0-9_.-]/_}-${size_mib}MiB-${stamp}"
  if [[ -f "${sender_log}" ]]; then
    if ! cp "${sender_log}" "${log_dir}/${prefix}-sender.log"; then
      preserve_status=1
    fi
  fi
  if [[ -f "${receiver_log}" ]]; then
    if ! cp "${receiver_log}" "${log_dir}/${prefix}-receiver.log"; then
      preserve_status=1
    fi
  fi
  if [[ -f "${sender_trace_csv}" ]]; then
    if ! cp "${sender_trace_csv}" "${log_dir}/${prefix}-sender.trace.csv"; then
      preserve_status=1
    fi
  fi
  if [[ -f "${receiver_trace_csv}" ]]; then
    if ! cp "${receiver_trace_csv}" "${log_dir}/${prefix}-receiver.trace.csv"; then
      preserve_status=1
    fi
  fi
  if [[ -f "${sender_resource_json}" ]]; then
    if ! cp "${sender_resource_json}" "${log_dir}/${prefix}-sender.resource.json"; then
      preserve_status=1
    fi
  fi
  if [[ -f "${receiver_resource_json}" ]]; then
    if ! cp "${receiver_resource_json}" "${log_dir}/${prefix}-receiver.resource.json"; then
      preserve_status=1
    fi
  fi
  return "${preserve_status}"
}

assert_no_tool_leaks() {
  local local_udp_count
  local local_process_count
  local remote_udp_count
  local remote_process_count

  local_udp_count="$(count_local_udp_sockets | tr -d '[:space:]')"
  local_process_count="$(count_local_tool_processes | tr -d '[:space:]')"
  remote_udp_count="$(count_remote_udp_sockets | tr -d '[:space:]')"
  remote_process_count="$(count_remote_tool_processes | tr -d '[:space:]')"

  if [[ "${local_udp_count}" != "0" ]]; then
    echo "local ${tool} UDP sockets leaked: ${local_udp_count}" >&2
    exit 1
  fi
  if [[ "${local_process_count}" != "0" ]]; then
    echo "local ${tool} processes leaked: ${local_process_count}" >&2
    exit 1
  fi
  if [[ "${remote_udp_count}" != "0" ]]; then
    echo "remote ${tool} UDP sockets leaked on ${target}: ${remote_udp_count}" >&2
    exit 1
  fi
  if [[ "${remote_process_count}" != "0" ]]; then
    echo "remote ${tool} processes leaked on ${target}: ${remote_process_count}" >&2
    exit 1
  fi
}

wait_remote_pid_exit() {
  local state

  for _ in $(seq 1 400); do
    if ! state="$(remote "if [[ ! -f '${remote_base}.pid' ]]; then printf 'exited\\n'; else pid=\$(cat '${remote_base}.pid') || exit 1; if [[ ! \"\${pid}\" =~ ^[0-9]+$ ]]; then exit 1; fi; if kill -0 \"\${pid}\" 2>/dev/null; then printf 'running\\n'; else printf 'exited\\n'; fi; fi")"; then
      echo "failed to query remote ${tool} process on ${target}" >&2
      return 1
    fi
    case "${state}" in
      exited)
        return 0
        ;;
      running)
        ;;
      *)
        echo "invalid remote ${tool} process state on ${target}: ${state:-empty}" >&2
        return 1
        ;;
    esac
    sleep 0.25
  done
  echo "timed out waiting for remote ${tool} process on ${target}" >&2
  return 1
}

wait_remote_pid_status() {
  local state
  local remote_status
  local status_missing_polls=0
  # Bound sidecar visibility lag to four normal polling intervals (one second).
  local status_missing_grace_polls=4
  local status_poll_interval_seconds=0.25

  for _ in $(seq 1 400); do
    if ! state="$(remote "if [[ -f '${remote_base}.status' ]]; then status=\$(cat '${remote_base}.status') || exit 1; if [[ ! \"\${status}\" =~ ^[0-9]+$ ]]; then exit 1; fi; pid=''; if [[ -f '${remote_base}.pid' ]]; then pid=\$(cat '${remote_base}.pid') || exit 1; fi; if [[ -n \"\${pid}\" && ! \"\${pid}\" =~ ^[0-9]+$ ]]; then exit 1; fi; if [[ -n \"\${pid}\" ]] && kill -0 \"\${pid}\" 2>/dev/null; then printf 'running\\n'; else printf 'exited:%s\\n' \"\${status}\"; fi; elif [[ ! -f '${remote_base}.pid' ]]; then printf 'status-missing\\n'; else pid=\$(cat '${remote_base}.pid') || exit 1; if [[ ! \"\${pid}\" =~ ^[0-9]+$ ]]; then exit 1; fi; if kill -0 \"\${pid}\" 2>/dev/null; then printf 'running\\n'; else printf 'status-missing\\n'; fi; fi")"; then
      echo "failed to query remote ${tool} process status on ${target}" >&2
      return 1
    fi
    case "${state}" in
      exited:*)
        remote_status="${state#exited:}"
        if [[ "${remote_status}" == "0" ]]; then
          return 0
        fi
        echo "remote ${tool} process exited with status ${remote_status}" >&2
        return "${remote_status}"
        ;;
      running)
        status_missing_polls=0
        ;;
      status-missing)
        status_missing_polls=$((status_missing_polls + 1))
        if ((status_missing_polls > status_missing_grace_polls)); then
          echo "remote ${tool} process exited without a status on ${target}" >&2
          return 1
        fi
        ;;
      *)
        echo "invalid remote ${tool} process status on ${target}: ${state:-empty}" >&2
        return 1
        ;;
    esac
    sleep "${status_poll_interval_seconds}"
  done
  echo "timed out waiting for remote ${tool} process status on ${target}" >&2
  return 1
}

collect_remote_artifacts() {
  local collect_status=0
  local remote_log="${receiver_log}"
  local remote_trace="${receiver_trace_csv}"
  local remote_resource="${remote_receiver_resource_json}"
  local local_resource="${receiver_resource_json}"

  collect_remote_artifact() {
    local remote_path="$1"
    local local_path="$2"
    local temporary_path="${local_path}.collect.$$"

    rm -f "${temporary_path}"
    if ! remote "if [[ -s '${remote_path}' ]]; then cat '${remote_path}'; else exit 1; fi" >"${temporary_path}"; then
      rm -f "${temporary_path}"
      return 1
    fi
    if [[ ! -s "${temporary_path}" ]]; then
      rm -f "${temporary_path}"
      return 1
    fi
    if ! mv "${temporary_path}" "${local_path}"; then
      rm -f "${temporary_path}"
      return 1
    fi
  }

  if [[ "${direction}" == "reverse" ]]; then
    remote_log="${sender_log}"
    remote_trace="${sender_trace_csv}"
    remote_resource="${remote_sender_resource_json}"
    local_resource="${sender_resource_json}"
  fi
  if ! collect_remote_artifact "${remote_base}.err" "${remote_log}"; then
    collect_status=1
  fi
  if ! collect_remote_artifact "${remote_base}.trace.csv" "${remote_trace}"; then
    collect_status=1
  fi
  if ! collect_remote_artifact "${remote_resource}" "${local_resource}"; then
    collect_status=1
  fi
  return "${collect_status}"
}

refresh_benchmark_operands() {
  local value
  local end_ms

  if [[ "${command_end_ms}" -gt "${start_ms}" && "${start_ms}" -gt 0 ]]; then
    command_duration_ms="$((command_end_ms - start_ms))"
    if value="$(goodput_mbps "${expected_size}" "${command_duration_ms}")"; then
      wall_goodput="${value}"
    fi
  fi

  if [[ -s "${sender_trace_csv}" ]]; then
    value="$(last_trace_value "${sender_trace_csv}" "transfer_elapsed_ms" 2>/dev/null || true)"
    if [[ "${value}" =~ ^[1-9][0-9]*$ ]]; then
      sender_transfer_elapsed_ms="${value}"
      if value="$(trace_transfer_goodput_mbps "${sender_trace_csv}" "${expected_size}")"; then
        sender_goodput_mbps="${value}"
      fi
    fi

    value="$(max_trace_value "${sender_trace_csv}" "send_goodput_mbps" 2>/dev/null || true)"
    if [[ -z "${value}" ]]; then
      value="$(max_trace_value "${sender_trace_csv}" "app_mbps" 2>/dev/null || true)"
    fi
    if [[ -n "${value}" ]]; then
      sender_peak_goodput_mbps="${value}"
    fi

    value="$(last_trace_value "${sender_trace_csv}" "quic_first_byte_ms" 2>/dev/null || true)"
    if [[ -n "${value}" ]]; then
      sender_first_byte_ms="${value}"
    fi
  fi

  if [[ "${start_ms}" -gt 0 && "${duration_ms}" -eq 0 ]]; then
    end_ms="$(now_ms 2>/dev/null || true)"
    if [[ "${end_ms}" =~ ^[0-9]+$ && "${end_ms}" -gt "${start_ms}" ]]; then
      duration_ms="$((end_ms - start_ms))"
    else
      duration_ms=1
    fi
  fi

  return 0
}

dump_failure() {
  if [[ "${direction}" == "forward" ]]; then
    if [[ -f "${sender_log}" ]]; then
      echo "--- local sender log" >&2
      sed -n '1,200p' "${sender_log}" >&2 || true
    fi
    echo "--- remote receiver log" >&2
    remote "sed -n '1,200p' '${remote_base}.err'" >&2 || true
    echo "--- remote receiver size" >&2
    remote "wc -c < '${remote_base}.out'" >&2 || true
    return
  fi

  if [[ -f "${receiver_log}" ]]; then
    echo "--- local receiver log" >&2
    sed -n '1,200p' "${receiver_log}" >&2 || true
  fi
  echo "--- remote sender log" >&2
  remote "sed -n '1,200p' '${remote_base}.err'" >&2 || true
  if [[ -f "${receiver_out}" ]]; then
    echo "--- local receiver size" >&2
    wc -c < "${receiver_out}" >&2 || true
  fi
}

process_ref_field() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)[sys.argv[2]])
PY
}

identify_local_owned_process() {
  local role="$1" name="$2" pid="$3" output="${process_evidence_dir}/$1.ref.json"
  [[ "${identity_evidence_enabled}" == true ]] || return 0
  "${process_identify_local}" process-identify -name "${name}" -pid "${pid}" -timeout 5s -out "${output}" >"${output}.sha256"
  printf '%s\n' "${output}"
}

identify_local_owned_child() {
  local role="$1" parent_pid="$2" name="$3" child_pid=""
  [[ "${identity_evidence_enabled}" == true ]] || return 0
  for _ in $(seq 1 100); do
    child_pid="$(pgrep -P "${parent_pid}" -x "${name}" 2>/dev/null | head -n 1 || true)"
    [[ "${child_pid}" =~ ^[1-9][0-9]*$ ]] && break
    sleep 0.02
  done
  [[ "${child_pid}" =~ ^[1-9][0-9]*$ ]] || { echo "failed to identify local ${role} child" >&2; return 1; }
  identify_local_owned_process "${role}" "${name}" "${child_pid}"
}

record_remote_process_identity() {
  local role="$1" name="$2" pid_file="$3" remote_ref="${remote_base}.$1.ref.json"
  [[ "${identity_evidence_enabled}" == true ]] || return 0
  remote "pid=\$(cat '${pid_file}') || exit 1; [[ \"\${pid}\" =~ ^[1-9][0-9]*$ ]] || exit 1; '${process_identify_remote}' process-identify -name '${name}' -pid \"\${pid}\" -timeout 5s -out '${remote_ref}' >'${remote_ref}.sha256'"
  scp "${remote_target}:${remote_ref}" "${process_evidence_dir}/${role}.ref.json" >/dev/null
  scp "${remote_target}:${remote_ref}.sha256" "${process_evidence_dir}/${role}.ref.json.sha256" >/dev/null
}

copy_remote_process_identity() {
  local role="$1" remote_ref="${remote_base}.$1.ref.json"
  [[ "${identity_evidence_enabled}" == true ]] || return 0
  scp "${remote_target}:${remote_ref}" "${process_evidence_dir}/${role}.ref.json" >/dev/null
  scp "${remote_target}:${remote_ref}.sha256" "${process_evidence_dir}/${role}.ref.json.sha256" >/dev/null
}

record_remote_child_identity() {
  local role="$1" parent_pid_file="$2" name="$3" pid_file="${remote_base}.$1.pid"
  [[ "${identity_evidence_enabled}" == true ]] || return 0
  remote "parent=\$(cat '${parent_pid_file}') || exit 1; child=''; for _ in \$(seq 1 100); do child=\$(pgrep -P \"\${parent}\" -x '${name}' | head -n 1 || true); [[ \"\${child}\" =~ ^[1-9][0-9]*$ ]] && break; sleep 0.02; done; [[ \"\${child}\" =~ ^[1-9][0-9]*$ ]] || exit 1; printf '%s\n' \"\${child}\" >'${pid_file}'"
  record_remote_process_identity "${role}" "${name}" "${pid_file}"
}

same_local_process() {
  local reference="$1" name pid fresh
  name="$(process_ref_field "${reference}" name)" || return 2
  pid="$(process_ref_field "${reference}" pid)" || return 2
  process_recheck_sequence=$((process_recheck_sequence + 1))
  fresh="${process_evidence_dir}/recheck-${process_recheck_sequence}.ref.json"
  if "${process_identify_local}" process-identify -name "${name}" -pid "${pid}" -timeout 5s -out "${fresh}" >"${fresh}.sha256" 2>"${fresh}.err"; then
    cmp -s -- "${reference}" "${fresh}" && return 0
    return 1
  fi
  return 2
}

terminate_local_process_ref() {
  local reference="$1" pid state
  [[ -f "${reference}" && ! -L "${reference}" ]] || return 1
  pid="$(process_ref_field "${reference}" pid)" || return 1
  if same_local_process "${reference}"; then
    kill -TERM -- "${pid}" || return 1
  else
    state=$?
    ((state == 1)) && return 0
    return 1
  fi
  for _ in $(seq 1 40); do
    if same_local_process "${reference}"; then :; else state=$?; ((state == 1)) && { wait "${pid}" 2>/dev/null || true; return 0; }; return 1; fi
    sleep 0.05
  done
  if same_local_process "${reference}"; then
    kill -KILL -- "${pid}" || return 1
  else
    state=$?
    ((state == 1)) && return 0
    return 1
  fi
  for _ in $(seq 1 40); do
    if same_local_process "${reference}"; then :; else state=$?; ((state == 1)) && { wait "${pid}" 2>/dev/null || true; return 0; }; return 1; fi
    sleep 0.05
  done
  return 1
}

terminate_remote_processes() {
  if [[ "${identity_evidence_enabled}" == true ]]; then
    remote "set +e
helper='${process_identify_remote}'
status=0
sequence=0
same_process() {
  reference=\$1
  name=\$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[\"name\"])' \"\${reference}\") || return 2
  pid=\$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[\"pid\"])' \"\${reference}\") || return 2
  sequence=\$((sequence + 1))
  fresh=\"\${reference}.cleanup-recheck.\${sequence}\"
  if \"\${helper}\" process-identify -name \"\${name}\" -pid \"\${pid}\" -timeout 5s -out \"\${fresh}\" >\"\${fresh}.sha256\" 2>\"\${fresh}.err\"; then cmp -s -- \"\${reference}\" \"\${fresh}\" && return 0; return 1; fi
  return 2
}
terminate_exact() {
  reference=\$1
  [[ -f \"\${reference}\" && ! -L \"\${reference}\" ]] || return 0
  pid=\$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[\"pid\"])' \"\${reference}\") || return 1
  if same_process \"\${reference}\"; then kill -TERM -- \"\${pid}\" || return 1; else state=\$?; [[ \"\${state}\" == 1 ]] && return 0; return 1; fi
  for _ in \$(seq 1 40); do if same_process \"\${reference}\"; then :; else state=\$?; [[ \"\${state}\" == 1 ]] && return 0; return 1; fi; sleep 0.05; done
  if same_process \"\${reference}\"; then kill -KILL -- \"\${pid}\" || return 1; else state=\$?; [[ \"\${state}\" == 1 ]] && return 0; return 1; fi
  for _ in \$(seq 1 40); do if same_process \"\${reference}\"; then :; else state=\$?; [[ \"\${state}\" == 1 ]] && return 0; return 1; fi; sleep 0.05; done
  return 1
}
for role in derphole runstats wrapper; do terminate_exact '${remote_base}'.\${role}.ref.json || status=1; done
exit \"\${status}\""
    return
  fi
  remote "set +e
cleanup_status=0
wrapper_pid=''
child_pid=''
if [[ -f '${remote_base}.pid' ]]; then
  wrapper_pid=\$(cat '${remote_base}.pid') || cleanup_status=1
  if [[ ! \"\${wrapper_pid}\" =~ ^[0-9]+$ ]]; then
    wrapper_pid=''
    cleanup_status=1
  fi
fi
if [[ -f '${remote_base}.child.pid' ]]; then
  child_pid=\$(cat '${remote_base}.child.pid') || cleanup_status=1
  if [[ ! \"\${child_pid}\" =~ ^[0-9]+$ ]]; then
    child_pid=''
    cleanup_status=1
  fi
fi
for process_pid in \"\${wrapper_pid}\" \"\${child_pid}\"; do
  if [[ -n \"\${process_pid}\" ]] && kill -0 \"\${process_pid}\" 2>/dev/null; then
    kill -TERM \"\${process_pid}\" 2>/dev/null || cleanup_status=1
  fi
done
for _ in \$(seq 1 40); do
  running=0
  for process_pid in \"\${wrapper_pid}\" \"\${child_pid}\"; do
    if [[ -n \"\${process_pid}\" ]] && kill -0 \"\${process_pid}\" 2>/dev/null; then
      running=1
    fi
  done
  [[ \"\${running}\" == '0' ]] && break
  sleep 0.05
done
for process_pid in \"\${wrapper_pid}\" \"\${child_pid}\"; do
  if [[ -n \"\${process_pid}\" ]] && kill -0 \"\${process_pid}\" 2>/dev/null; then
    kill -KILL \"\${process_pid}\" 2>/dev/null || cleanup_status=1
  fi
done
for _ in \$(seq 1 40); do
  running=0
  for process_pid in \"\${wrapper_pid}\" \"\${child_pid}\"; do
    if [[ -n \"\${process_pid}\" ]] && kill -0 \"\${process_pid}\" 2>/dev/null; then
      running=1
    fi
  done
  [[ \"\${running}\" == '0' ]] && break
  sleep 0.05
done
for process_pid in \"\${wrapper_pid}\" \"\${child_pid}\"; do
  if [[ -n \"\${process_pid}\" ]] && kill -0 \"\${process_pid}\" 2>/dev/null; then
    cleanup_status=1
  fi
done
exit \"\${cleanup_status}\""
}

local_process_running() {
  local pid="$1"
  local state
  if ! kill -0 "${pid}" 2>/dev/null; then
    return 1
  fi
  state="$(ps -o stat= -p "${pid}" 2>/dev/null | tr -d '[:space:]')"
  [[ -n "${state}" && "${state}" != Z* ]]
}

terminate_local_process() {
  local pid="$1" reference="${2:-}"
  if [[ "${identity_evidence_enabled}" == true ]]; then
    [[ -n "${reference}" ]] || return 1
    terminate_local_process_ref "${reference}"
    return
  fi
  if [[ ! "${pid}" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  if local_process_running "${pid}"; then
    kill -TERM "${pid}" 2>/dev/null || true
  fi
  for _ in $(seq 1 40); do
    local_process_running "${pid}" || break
    sleep 0.05
  done
  if local_process_running "${pid}"; then
    kill -KILL "${pid}" 2>/dev/null || true
  fi
  for _ in $(seq 1 40); do
    local_process_running "${pid}" || break
    sleep 0.05
  done
  if local_process_running "${pid}"; then
    return 1
  fi
  wait "${pid}" 2>/dev/null || true
}

write_child_cleanup_evidence() {
  local cleanup_status="$1" count=0
  [[ "${identity_evidence_enabled}" == true ]] || return 0
  count="$(find "${process_evidence_dir}" -maxdepth 1 -type f -name '*.ref.json' ! -name 'recheck-*' | wc -l | tr -d '[:space:]')"
  python3 - "${child_cleanup_out}" "${cleanup_status}" "${count}" "${process_evidence_dir}" <<'PY'
import glob
import hashlib
import json
import os
import sys

path, cleanup_status, count, evidence_dir = sys.argv[1:]
references = []
for reference_path in sorted(glob.glob(os.path.join(evidence_dir, "*.ref.json"))):
    if os.path.basename(reference_path).startswith("recheck-"):
        continue
    with open(reference_path, "rb") as source:
        digest = hashlib.sha256(source.read()).hexdigest()
    references.append({"role": os.path.basename(reference_path)[:-9], "sha256": digest})
expected_roles = {"local-runstats", "local-derphole", "wrapper", "runstats", "derphole"}
success = cleanup_status == "0" and int(count) == 5 and {item["role"] for item in references} == expected_roles
with open(path, "x", encoding="utf-8") as output:
    json.dump({
        "identity_cleanup_complete": cleanup_status == "0",
        "references": references,
        "schema_version": 1,
        "success": success,
    }, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
raise SystemExit(0 if success else 1)
PY
  local evidence_status=$?
  benchmark_child_cleanup_sha256="$(shasum -a 256 "${child_cleanup_out}" | awk '{print $1}')"
  chmod a-w "${child_cleanup_out}"
  if ((evidence_status == 0)); then
    benchmark_child_cleanup_success=true
  fi
  return "${evidence_status}"
}

cleanup() {
  local cleanup_status=0
  local remote_cleanup_status=0

  if [[ "${transfer_children_waited}" != true && -n "${send_pid}" ]]; then
    if [[ -n "${send_child_ref}" ]] && ! terminate_local_process_ref "${send_child_ref}"; then
      echo "local sender child cleanup incomplete" >&2
      cleanup_status=1
    fi
    if ! terminate_local_process "${send_pid}" "${send_ref}"; then
      echo "local sender cleanup incomplete: ${send_pid}" >&2
      cleanup_status=1
    fi
    send_pid=""
  fi
  if [[ "${transfer_children_waited}" != true && -n "${listener_pid}" ]]; then
    if [[ -n "${listener_child_ref}" ]] && ! terminate_local_process_ref "${listener_child_ref}"; then
      echo "local receiver child cleanup incomplete" >&2
      cleanup_status=1
    fi
    if ! terminate_local_process "${listener_pid}" "${listener_ref}"; then
      echo "local receiver cleanup incomplete: ${listener_pid}" >&2
      cleanup_status=1
    fi
    listener_pid=""
  fi
  if [[ "${transfer_children_waited}" != true ]]; then
    if ! terminate_remote_processes >/dev/null 2>&1; then
      remote_cleanup_status=1
    fi
  fi
  if [[ "${identity_evidence_enabled}" == true ]] && ! write_child_cleanup_evidence "$((cleanup_status == 0 && remote_cleanup_status == 0 ? 0 : 1))"; then
    cleanup_status=1
  fi
  if ! remote "rm -f '${remote_base}.pid' '${remote_base}.child.pid' '${remote_base}.child.pid.tmp' '${remote_base}.wrapper.pid' '${remote_base}.runstats.pid' '${remote_base}.derphole.pid' '${remote_base}.wrapper.ref.json' '${remote_base}.wrapper.ref.json.sha256' '${remote_base}.runstats.ref.json' '${remote_base}.runstats.ref.json.sha256' '${remote_base}.derphole.ref.json' '${remote_base}.derphole.ref.json.sha256' '${remote_base}.wrapper.ref.json.cleanup-recheck.'* '${remote_base}.runstats.ref.json.cleanup-recheck.'* '${remote_base}.derphole.ref.json.cleanup-recheck.'* '${remote_base}.status' '${remote_base}.status.tmp' '${remote_base}.payload' '${remote_base}.out' '${remote_base}.err' '${remote_base}.trace.csv' '${remote_sender_resource_json}' '${remote_receiver_resource_json}' '${remote_upload}' '${remote_runstats_upload}'; rm -f '${remote_bin}' '${remote_runstats}'; rmdir '${remote_bin_dir}' '${remote_run_dir}' 2>/dev/null || true; if [[ -e '${remote_base}.pid' || -e '${remote_base}.child.pid' || -e '${remote_base}.status' || -e '${remote_sender_resource_json}' || -e '${remote_receiver_resource_json}' || -e '${remote_upload}' || -e '${remote_runstats_upload}' || -e '${remote_bin}' || -e '${remote_runstats}' || -e '${remote_bin_dir}' || -e '${remote_run_dir}' ]]; then exit 1; fi" >/dev/null 2>&1; then
    remote_cleanup_status=1
  fi
  if [[ "${remote_cleanup_status}" -ne 0 ]]; then
    echo "remote benchmark cleanup incomplete on ${target}" >&2
    cleanup_status=1
  fi
  if ! rm -rf "${tmp}" || [[ -e "${tmp}" ]]; then
    echo "local benchmark cleanup incomplete: ${tmp}" >&2
    cleanup_status=1
  fi
  return "${cleanup_status}"
}

handle_exit() {
  local status="$1"
  local preserve_status=0
  local cleanup_status=0
  local error_text

  trap - EXIT
  if [[ "${status}" -eq 0 ]]; then
    return 0
  fi

  set +e
  refresh_benchmark_operands
  if ! collect_remote_artifacts; then
    echo "failed to collect remote benchmark artifacts" >&2
  fi
  load_resource_stats || true
  dump_failure
  preserve_logs
  preserve_status="$?"
  if [[ "${preserve_status}" -ne 0 ]]; then
    echo "failed to preserve benchmark logs" >&2
  fi
  cleanup
  cleanup_status="$?"
  if [[ "${cleanup_status}" -eq 0 ]]; then
    benchmark_cleanup_success="true"
  fi
  if [[ "${cleanup_status}" -ne 0 ]]; then
    echo "benchmark cleanup failed" >&2
  fi

  error_text="promotion-benchmark-driver-exit-${status}"
  if [[ "${preserve_status}" -ne 0 ]]; then
    error_text+="-log-preservation-failed"
  fi
  if [[ "${cleanup_status}" -ne 0 ]]; then
    error_text+="-cleanup-failed"
  fi
  emit_benchmark_footer 2 false "${error_text}" "${sender_goodput_mbps:-0}" "${sender_peak_goodput_mbps:-0}" "${sender_first_byte_ms:-0}"
  exit "${status}"
}

trap 'handle_exit "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_caller_start_gate() {
  [[ -n "${ready_file}" ]] || return 0
  [[ -d "$(dirname "${ready_file}")" && ! -L "$(dirname "${ready_file}")" ]] || { echo "benchmark ready-file parent is invalid" >&2; return 1; }
  [[ -d "$(dirname "${start_file}")" && ! -L "$(dirname "${start_file}")" ]] || { echo "benchmark start-file parent is invalid" >&2; return 1; }
  [[ ! -e "${ready_file}" && ! -L "${ready_file}" && ! -e "${start_file}" && ! -L "${start_file}" ]] || { echo "benchmark gate path already exists" >&2; return 1; }
  (set -o noclobber; printf 'ready\n' >"${ready_file}") || return 1
  for _ in $(seq 1 600); do
    if [[ -f "${start_file}" && ! -L "${start_file}" ]]; then
      return 0
    fi
    sleep 0.05
  done
  echo "timed out waiting for benchmark start gate" >&2
  return 1
}

build_and_install_remote_binary() {
  local actual_sha256 remote_upload_sha256
  if [[ -z "${local_override}" ]]; then
    mise run build
    mise run build-linux-amd64
  fi
  if [[ -n "${local_expected_sha256}" ]]; then
    actual_sha256="$(shasum -a 256 "${local_bin}" | awk '{print $1}')"
    if [[ "${actual_sha256}" != "${local_expected_sha256}" ]]; then
      echo "local benchmark binary SHA-256 mismatch" >&2
      exit 1
    fi
    actual_sha256="$(shasum -a 256 "${linux_bin}" | awk '{print $1}')"
    if [[ "${actual_sha256}" != "${linux_expected_sha256}" ]]; then
      echo "Linux benchmark binary SHA-256 mismatch" >&2
      exit 1
    fi
  fi
  mise exec -- go build -o "${local_runstats}" ./tools/runstats
  GOOS=linux GOARCH=amd64 mise exec -- go build -o "${linux_runstats}" ./tools/runstats
  remote "mkdir -p '${remote_run_dir}' '${remote_bin_dir}'"
  scp "${linux_bin}" "${remote_target}:${remote_upload}" >/dev/null
  scp "${linux_runstats}" "${remote_target}:${remote_runstats_upload}" >/dev/null
  remote_upload_sha256="$(remote "sha256sum '${remote_upload}' | awk '{print \$1}'")"
  if [[ -n "${linux_expected_sha256}" && "${remote_upload_sha256}" != "${linux_expected_sha256}" ]]; then
    echo "remote Linux benchmark binary SHA-256 mismatch" >&2
    exit 1
  fi
  if ! install_remote_bin "${remote_bin_dir}"; then
    echo "remote benchmark directory is not writable and executable; set DERPHOLE_REMOTE_BIN_DIR to a writable executable root" >&2
    exit 1
  fi
  remote_linux_bin_sha256="$(remote "sha256sum '${remote_bin}' | awk '{print \$1}'")"
  if [[ -n "${linux_expected_sha256}" && "${remote_linux_bin_sha256}" != "${linux_expected_sha256}" ]]; then
    echo "installed remote Linux benchmark binary SHA-256 mismatch" >&2
    exit 1
  fi
}

validate_caller_owned_payloads() {
  local actual_size
  if [[ -n "${local_payload_override}" ]]; then
    if [[ ! -f "${local_payload_override}" ]]; then
      echo "local benchmark payload must be a regular file: ${local_payload_override}" >&2
      exit 2
    fi
    actual_size="$(wc -c <"${local_payload_override}" | tr -d '[:space:]')"
    if [[ "${actual_size}" != "${expected_size}" ]]; then
      echo "local benchmark payload size ${actual_size}, want ${expected_size}" >&2
      exit 2
    fi
  fi
  if [[ -n "${remote_payload_override}" ]]; then
    if ! remote "test -f '${remote_payload_override}'"; then
      echo "remote benchmark payload must be a regular file: ${remote_payload_override}" >&2
      exit 2
    fi
    actual_size="$(remote "wc -c < '${remote_payload_override}'" | tr -d '[:space:]')"
    if [[ "${actual_size}" != "${expected_size}" ]]; then
      echo "remote benchmark payload size ${actual_size}, want ${expected_size}" >&2
      exit 2
    fi
  fi
}

prepare_local_payload() {
  if [[ -z "${local_payload_override}" ]]; then
    echo "generating ${size_mib} MiB random payload"
    dd if=/dev/urandom of="${payload}" bs=1048576 count="${size_mib}" 2>/dev/null
  else
    echo "using caller-owned local payload ${payload}"
  fi
}

prepare_remote_payload() {
  if [[ -z "${remote_payload_override}" ]]; then
    echo "generating ${size_mib} MiB random payload on ${target}"
    remote "dd if=/dev/urandom of='${remote_payload}' bs=1048576 count='${size_mib}' 2>/dev/null"
  else
    echo "using caller-owned remote payload ${remote_payload}"
  fi
}

run_forward_derphole_stream() {
  prepare_local_payload
  source_sha="$(shasum -a 256 "${payload}" | awk '{print $1}')"

  remote "rm -f '${remote_base}.pid' '${remote_base}.out' '${remote_base}.err' '${remote_base}.trace.csv' '${remote_receiver_resource_json}'; nohup env DERPHOLE_TRANSFER_TRACE_CSV='${remote_base}.trace.csv' '${remote_runstats}' -out '${remote_receiver_resource_json}' -- '${remote_bin}' --verbose listen >'${remote_base}.out' 2>'${remote_base}.err' </dev/null & echo \$! > '${remote_base}.pid'"

  token=""
  for _ in $(seq 1 200); do
    token="$(remote "grep -E '^[A-Za-z0-9_-]{20,}$' '${remote_base}.err' | head -n 1 || true")"
    if [[ -n "${token}" ]]; then
      break
    fi
    sleep 0.1
  done
  if [[ -z "${token}" ]]; then
    echo "failed to capture listener token" >&2
    exit 1
  fi

  start_ms="$(now_ms)"
  if ((${#parallel_args[@]})); then
    DERPHOLE_TRANSFER_TRACE_CSV="${sender_trace_csv}" "${local_runstats}" -out "${sender_resource_json}" -- "${local_bin}" --verbose pipe "${parallel_args[@]}" "${token}" < "${payload}" >/dev/null 2>"${sender_log}"
  else
    DERPHOLE_TRANSFER_TRACE_CSV="${sender_trace_csv}" "${local_runstats}" -out "${sender_resource_json}" -- "${local_bin}" --verbose pipe "${token}" < "${payload}" >/dev/null 2>"${sender_log}"
  fi

  wait_remote_pid_exit
  command_end_ms="$(now_ms)"
  remote "cat '${remote_base}.err'" >"${receiver_log}"
  remote "cat '${remote_base}.trace.csv'" >"${receiver_trace_csv}"
  remote "cat '${remote_receiver_resource_json}'" >"${receiver_resource_json}"
  sink_sha="$(remote "sha256sum '${remote_base}.out' | awk '{print \$1}'")"
  sink_size="$(remote "wc -c < '${remote_base}.out'")"
}

run_forward_derphole_file() {
  prepare_local_payload
  source_sha="$(shasum -a 256 "${payload}" | awk '{print $1}')"
  rm -f "${sender_log}" "${sender_trace_csv}" "${sender_resource_json}"
  remote "rm -f '${remote_base}.pid' '${remote_base}.out' '${remote_base}.err' '${remote_base}.trace.csv' '${remote_receiver_resource_json}'"

  start_ms="$(now_ms)"
  env "${sender_test_env[@]+"${sender_test_env[@]}"}" DERPHOLE_TRANSFER_TRACE_CSV="${sender_trace_csv}" "${local_runstats}" -out "${sender_resource_json}" -- "${local_bin}" --verbose send "${direct_tcp_args[@]+"${direct_tcp_args[@]}"}" "${payload}" >/dev/null 2>"${sender_log}" &
  send_pid="$!"
  if [[ "${identity_evidence_enabled}" == true ]]; then
    send_ref="$(identify_local_owned_process local-runstats runstats "${send_pid}")"
    send_child_ref="$(identify_local_owned_child local-derphole "${send_pid}" "${tool}")"
  fi

  token=""
  for _ in $(seq 1 200); do
    token="$(sed -nE 's/.* receive ([A-Za-z0-9_-]{20,})$/\1/p' "${sender_log}" | head -n 1)"
    [[ -n "${token}" ]] && break
    kill -0 "${send_pid}" 2>/dev/null || break
    sleep 0.1
  done
  [[ -n "${token}" ]] || { echo "failed to capture send token" >&2; exit 1; }

  if [[ "${identity_evidence_enabled}" == true ]]; then
    remote "set +e
printf '%s\n' \"\$\$\" >'${remote_base}.wrapper.pid'
'${process_identify_remote}' process-identify -name bash -pid \"\$\$\" -timeout 5s -out '${remote_base}.wrapper.ref.json' >'${remote_base}.wrapper.ref.json.sha256' || exit 1
${receiver_test_env_remote}DERPHOLE_TRANSFER_TRACE_CSV='${remote_base}.trace.csv' '${remote_runstats}' -out '${remote_receiver_resource_json}' -- '${remote_bin}' --verbose receive -o '${remote_base}.out' '${token}' >/dev/null 2>'${remote_base}.err' &
child=\$!
printf '%s\n' \"\${child}\" >'${remote_base}.runstats.pid'
'${process_identify_remote}' process-identify -name runstats -pid \"\${child}\" -timeout 5s -out '${remote_base}.runstats.ref.json' >'${remote_base}.runstats.ref.json.sha256' || exit 1
derphole_pid=''
for _ in \$(seq 1 100); do derphole_pid=\$(pgrep -P \"\${child}\" -x '${tool}' | head -n 1 || true); [[ \"\${derphole_pid}\" =~ ^[1-9][0-9]*$ ]] && break; sleep 0.02; done
[[ \"\${derphole_pid}\" =~ ^[1-9][0-9]*$ ]] || exit 1
printf '%s\n' \"\${derphole_pid}\" >'${remote_base}.derphole.pid'
'${process_identify_remote}' process-identify -name '${tool}' -pid \"\${derphole_pid}\" -timeout 5s -out '${remote_base}.derphole.ref.json' >'${remote_base}.derphole.ref.json.sha256' || exit 1
wait \"\${child}\""
    copy_remote_process_identity wrapper
    copy_remote_process_identity runstats
    copy_remote_process_identity derphole
  else
    remote "${receiver_test_env_remote}DERPHOLE_TRANSFER_TRACE_CSV='${remote_base}.trace.csv' '${remote_runstats}' -out '${remote_receiver_resource_json}' -- '${remote_bin}' --verbose receive -o '${remote_base}.out' '${token}' >/dev/null 2>'${remote_base}.err'"
  fi
  wait "${send_pid}"
  send_pid=""
  command_end_ms="$(now_ms)"

  remote "cat '${remote_base}.err'" >"${receiver_log}"
  remote "cat '${remote_base}.trace.csv'" >"${receiver_trace_csv}"
  remote "cat '${remote_receiver_resource_json}'" >"${receiver_resource_json}"
  sink_sha="$(remote "sha256sum '${remote_base}.out' | awk '{print \$1}'")"
  sink_size="$(remote "wc -c < '${remote_base}.out'")"
}

run_reverse_derphole_stream() {
  prepare_remote_payload
  source_sha="$(remote "sha256sum '${remote_payload}' | awk '{print \$1}'")"

  DERPHOLE_TRANSFER_TRACE_CSV="${receiver_trace_csv}" "${local_runstats}" -out "${receiver_resource_json}" -- "${local_bin}" --verbose listen >"${receiver_out}" 2>"${receiver_log}" &
  listener_pid="$!"

  token=""
  for _ in $(seq 1 200); do
    token="$(grep -E '^[A-Za-z0-9_-]{20,}$' "${receiver_log}" | head -n 1 || true)"
    if [[ -n "${token}" ]]; then
      break
    fi
    sleep 0.1
  done
  if [[ -z "${token}" ]]; then
    echo "failed to capture listener token" >&2
    exit 1
  fi

  local remote_send_cmd
  remote_send_cmd="DERPHOLE_TRANSFER_TRACE_CSV='${remote_base}.trace.csv' '${remote_runstats}' -out '${remote_sender_resource_json}' -- '${remote_bin}' --verbose pipe"
  if [[ -n "${parallel_args_remote}" ]]; then
    remote_send_cmd+=" ${parallel_args_remote}"
  fi
  remote_send_cmd+=" '${token}' <'${remote_payload}' >/dev/null 2>'${remote_base}.err'"

  start_ms="$(now_ms)"
  remote "${remote_send_cmd}"

  wait "${listener_pid}"
  listener_pid=""
  command_end_ms="$(now_ms)"
  remote "cat '${remote_base}.err'" >"${sender_log}"
  remote "cat '${remote_base}.trace.csv'" >"${sender_trace_csv}"
  remote "cat '${remote_sender_resource_json}'" >"${sender_resource_json}"
  sink_sha="$(shasum -a 256 "${receiver_out}" | awk '{print $1}')"
  sink_size="$(wc -c < "${receiver_out}" | tr -d '[:space:]')"
}

run_reverse_derphole_file() {
  prepare_remote_payload
  source_sha="$(remote "sha256sum '${remote_payload}' | awk '{print \$1}'")"
  if [[ "${identity_evidence_enabled}" == true ]]; then
    remote "rm -f '${remote_base}.pid' '${remote_base}.child.pid' '${remote_base}.child.pid.tmp' '${remote_base}.status' '${remote_base}.status.tmp' '${remote_base}.out' '${remote_base}.err' '${remote_base}.trace.csv' '${remote_sender_resource_json}'; nohup sh -c 'set +e; ${sender_test_env_remote}DERPHOLE_TRANSFER_TRACE_CSV=\"${remote_base}.trace.csv\" \"${remote_runstats}\" -out \"${remote_sender_resource_json}\" -- \"${remote_bin}\" --verbose send \"${remote_payload}\" >\"${remote_base}.out\" 2>\"${remote_base}.err\" & child_pid=\$!; printf \"%s\\n\" \"\${child_pid}\" >\"${remote_base}.child.pid.tmp\"; mv \"${remote_base}.child.pid.tmp\" \"${remote_base}.child.pid\"; wait \"\${child_pid}\"; status=\$?; printf \"%s\\n\" \"\${status}\" >\"${remote_base}.status.tmp\"; mv \"${remote_base}.status.tmp\" \"${remote_base}.status\"; exit \"\${status}\"' >/dev/null 2>&1 </dev/null & echo \$! >'${remote_base}.pid'"
  else
    remote "rm -f '${remote_base}.pid' '${remote_base}.child.pid' '${remote_base}.child.pid.tmp' '${remote_base}.status' '${remote_base}.status.tmp' '${remote_base}.out' '${remote_base}.err' '${remote_base}.trace.csv' '${remote_sender_resource_json}'; nohup sh -c 'set +e; child_pid=; forward_signal() { signal=\$1; if [ -n \"\${child_pid}\" ]; then kill -\"\${signal}\" \"\${child_pid}\" 2>/dev/null || true; fi; }; trap \"forward_signal TERM\" TERM; trap \"forward_signal INT\" INT; ${sender_test_env_remote}DERPHOLE_TRANSFER_TRACE_CSV=\"${remote_base}.trace.csv\" \"${remote_runstats}\" -out \"${remote_sender_resource_json}\" -- \"${remote_bin}\" --verbose send \"${remote_payload}\" >\"${remote_base}.out\" 2>\"${remote_base}.err\" & child_pid=\$!; printf \"%s\\n\" \"\${child_pid}\" >\"${remote_base}.child.pid.tmp\"; mv \"${remote_base}.child.pid.tmp\" \"${remote_base}.child.pid\"; wait \"\${child_pid}\"; status=\$?; printf \"%s\\n\" \"\${status}\" >\"${remote_base}.status.tmp\"; mv \"${remote_base}.status.tmp\" \"${remote_base}.status\"; exit \"\${status}\"' >/dev/null 2>&1 </dev/null & echo \$! >'${remote_base}.pid'"
  fi
  if [[ "${identity_evidence_enabled}" == true ]]; then
    record_remote_process_identity wrapper sh "${remote_base}.pid"
    for _ in $(seq 1 100); do remote "test -s '${remote_base}.child.pid'" 2>/dev/null && break; sleep 0.02; done
    record_remote_process_identity runstats runstats "${remote_base}.child.pid"
    record_remote_child_identity derphole "${remote_base}.child.pid" "${tool}"
  fi

  token=""
  for _ in $(seq 1 200); do
    token="$(remote "sed -nE 's/.* receive ([A-Za-z0-9_-]{20,})$/\\1/p' '${remote_base}.err' | head -n 1")"
    [[ -n "${token}" ]] && break
    sleep 0.1
  done
  [[ -n "${token}" ]] || { echo "failed to capture remote send token" >&2; exit 1; }

  start_ms="$(now_ms)"
  env "${receiver_test_env[@]+"${receiver_test_env[@]}"}" DERPHOLE_TRANSFER_TRACE_CSV="${receiver_trace_csv}" "${local_runstats}" -out "${receiver_resource_json}" -- "${local_bin}" --verbose receive "${direct_tcp_args[@]+"${direct_tcp_args[@]}"}" -o "${receiver_out}" "${token}" >/dev/null 2>"${receiver_log}" &
  listener_pid="$!"
  if [[ "${identity_evidence_enabled}" == true ]]; then
    listener_ref="$(identify_local_owned_process local-runstats runstats "${listener_pid}")"
    listener_child_ref="$(identify_local_owned_child local-derphole "${listener_pid}" "${tool}")"
  fi
  wait "${listener_pid}"
  listener_pid=""
  wait_remote_pid_status
  command_end_ms="$(now_ms)"

  remote "cat '${remote_base}.err'" >"${sender_log}"
  remote "cat '${remote_base}.trace.csv'" >"${sender_trace_csv}"
  remote "cat '${remote_sender_resource_json}'" >"${sender_resource_json}"
  sink_sha="$(shasum -a 256 "${receiver_out}" | awk '{print $1}')"
  sink_size="$(wc -c < "${receiver_out}" | tr -d '[:space:]')"
}

require_bulk_probe_outcome_marker() {
  [[ "${bulk_probe_outcome_configured}" == true ]] || return 0
  local marker="v2-bulk-probe-test-outcome=${bulk_probe_outcome}"
  local sender_count
  sender_count="$(grep -Fxc "${marker}" "${sender_log}" || true)"
  if [[ "${sender_count}" != "1" ]]; then
    echo "sender bulk probe outcome marker count = ${sender_count}, want 1" >&2
    return 1
  fi
  if grep -Fq 'v2-bulk-probe-test-outcome=' "${receiver_log}"; then
    echo "receiver unexpectedly emitted a bulk probe outcome marker" >&2
    return 1
  fi
}

require_bulk_probe_dirty_rate_marker() {
  [[ "${bulk_probe_dirty_rate_configured}" == true ]] || return 0
  local marker="v2-bulk-probe-test-dirty-rate-mbps=${bulk_probe_dirty_rate}"
  local receiver_count
  receiver_count="$(grep -Fxc "${marker}" "${receiver_log}" || true)"
  if [[ "${receiver_count}" != "1" ]]; then
    echo "receiver bulk probe dirty-rate marker count = ${receiver_count}, want 1" >&2
    return 1
  fi
  if grep -Fq 'v2-bulk-probe-test-dirty-rate-mbps=' "${sender_log}"; then
    echo "sender unexpectedly emitted a bulk probe dirty-rate marker" >&2
    return 1
  fi
}

finalize_run() {
  local sender_trace
  local receiver_trace
  local sender_path_changed="false"
  local receiver_path_changed="false"

  require_bulk_probe_outcome_marker
  require_bulk_probe_dirty_rate_marker
  sender_trace="$(path_trace "${sender_log}")"
  receiver_trace="$(path_trace "${receiver_log}")"

  if grep -Fq 'v2-block-transfer=direct-tcp-files' "${sender_log}" && grep -Fq 'v2-block-transfer=direct-tcp-files' "${receiver_log}"; then
    transfer_mode="direct-tcp-files-v1"
  elif grep -Fq 'v2-bulk-decision=mode:quic' "${sender_log}" && grep -Fq 'v2-bulk-decision=mode:quic' "${receiver_log}"; then
    transfer_mode="blocks-v1"
  elif grep -Fq 'v2-block-transfer=bulk-packets' "${sender_log}" && grep -Fq 'v2-block-transfer=bulk-packets' "${receiver_log}"; then
    transfer_mode="bulk-packets-v1"
  elif grep -Fq 'v2-block-policy=mode:blocks-v1' "${sender_log}" || grep -Fq 'v2-block-policy=mode:blocks-v1' "${receiver_log}"; then
    transfer_mode="blocks-v1"
  fi
  if [[ -n "${DERPHOLE_BENCH_EXPECT_TRANSFER_MODE:-}" && "${DERPHOLE_BENCH_EXPECT_TRANSFER_MODE}" != "${transfer_mode}" ]]; then
    echo "unexpected benchmark transfer mode: got ${transfer_mode}, want ${DERPHOLE_BENCH_EXPECT_TRANSFER_MODE}" >&2
    exit 1
  fi
  if ! load_resource_stats; then
    echo "benchmark resource JSON validation failed" >&2
    exit 1
  fi
  require_resource_stats

  if path_changed_mid_run "${sender_trace}"; then
    sender_path_changed="true"
  fi
  if path_changed_mid_run "${receiver_trace}"; then
    receiver_path_changed="true"
  fi

  [[ "${source_sha}" == "${sink_sha}" ]]
  [[ "${sink_size}" == "${expected_size}" ]]
  [[ -n "${sender_trace}" ]]
  [[ -n "${receiver_trace}" ]]
  require_direct_evidence "sender" "${sender_trace}"
  require_direct_evidence "receiver" "${receiver_trace}"
  require_direct_trace "sender" "${sender_trace_csv}"
  require_direct_trace "receiver" "${receiver_trace_csv}"

  sender_transfer_elapsed_ms="$(last_trace_value "${sender_trace_csv}" "transfer_elapsed_ms")"
  if ! sender_goodput_mbps="$(trace_transfer_goodput_mbps "${sender_trace_csv}" "${expected_size}")"; then
    echo "sender trace missing positive transfer_elapsed_ms" >&2
    exit 1
  fi

  if [[ "${command_end_ms}" -le "${start_ms}" ]]; then
    echo "invalid benchmark command timing" >&2
    exit 1
  fi
  command_duration_ms="$((command_end_ms - start_ms))"
  wall_goodput="$(goodput_mbps "${expected_size}" "${command_duration_ms}")"

  sender_peak_goodput_mbps="$(max_trace_value "${sender_trace_csv}" "send_goodput_mbps")"
  if [[ -z "${sender_peak_goodput_mbps}" ]]; then
    sender_peak_goodput_mbps="$(max_trace_value "${sender_trace_csv}" "app_mbps")"
  fi
  sender_first_byte_ms="$(last_trace_value "${sender_trace_csv}" "quic_first_byte_ms")"
  assert_no_tool_leaks

  end_ms="$(now_ms)"
  duration_ms="$((end_ms - start_ms))"
  if [[ "${duration_ms}" -le 0 ]]; then
    duration_ms=1
  fi
  if [[ -z "${sender_peak_goodput_mbps}" ]]; then
    sender_peak_goodput_mbps="${sender_goodput_mbps}"
  fi
  if [[ -z "${sender_first_byte_ms}" ]]; then
    sender_first_byte_ms=0
  fi

  preserve_logs

  echo "target=${target}"
  echo "size_mib=${size_mib}"
  echo "duration_seconds=$((duration_ms / 1000))"
  echo "sha256=${source_sha}"
  echo "sender_path_changed=${sender_path_changed}"
  echo "receiver_path_changed=${receiver_path_changed}"
  echo "sender_path_trace=$(printf '%s' "${sender_trace}" | tr '\n' ';')"
  echo "receiver_path_trace=$(printf '%s' "${receiver_trace}" | tr '\n' ';')"
  echo "--- sender log"
  cat "${sender_log}"
  echo "--- receiver log"
  cat "${receiver_log}"
  echo "--- sender trace"
  cat "${sender_trace_csv}"
  echo "--- receiver trace"
  cat "${receiver_trace_csv}"
}

wait_for_caller_start_gate
snapshot_tool_processes
build_and_install_remote_binary
validate_caller_owned_payloads

case "${tool}:${direction}:${workload}" in
  derphole:forward:file) run_forward_derphole_file ;;
  derphole:reverse:file) run_reverse_derphole_file ;;
  derphole:forward:stream) run_forward_derphole_stream ;;
  derphole:reverse:stream) run_reverse_derphole_stream ;;
  *) echo "unsupported benchmark mode: ${tool}:${direction}:${workload}" >&2; exit 1 ;;
esac

transfer_children_waited=true
finalize_run
if ! cleanup; then
  echo "benchmark cleanup failed" >&2
  exit 1
fi
benchmark_cleanup_success="true"
emit_benchmark_footer 1 true "" "${sender_goodput_mbps}" "${sender_peak_goodput_mbps}" "${sender_first_byte_ms}"
trap - EXIT
