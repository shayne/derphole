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
transfer_mode="unknown"

local_override="${DERPHOLE_BENCH_LOCAL_BIN:-}"
linux_override="${DERPHOLE_BENCH_LINUX_BIN:-}"
if [[ -n "${local_override}" && -z "${linux_override}" ]] ||
   [[ -z "${local_override}" && -n "${linux_override}" ]]; then
  echo "DERPHOLE_BENCH_LOCAL_BIN and DERPHOLE_BENCH_LINUX_BIN must be set together" >&2
  exit 2
fi

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
listener_pid=""
remote_env=()
parallel_args=()
parallel_args_remote=""

if [[ "${DERPHOLE_BENCH_PARALLEL:-}" != "" ]]; then
  parallel_args=(--parallel "${DERPHOLE_BENCH_PARALLEL}")
  parallel_args_remote="${parallel_args[*]-}"
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
remote() {
  ssh "${remote_target}" "${remote_env[@]}" 'bash -se' <<<"$1"
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

count_local_udp_sockets() {
  local pids
  pids="$(pgrep -x "${tool}" | paste -sd, - || true)"
  if [[ -z "${pids}" ]]; then
    echo 0
    return 0
  fi
  lsof -nP -a -p "${pids}" -iUDP 2>/dev/null | awk 'NR > 1 { count++ } END { print count + 0 }' || true
}

count_local_tool_processes() {
  pgrep -x "${tool}" | awk '{ count++ } END { print count + 0 }' || true
}

count_remote_udp_sockets() {
  remote "pids=\$(pgrep -x '${tool}' | paste -sd, - || true); if [[ -z \"\${pids}\" ]]; then echo 0; else lsof -nP -a -p \"\${pids}\" -iUDP 2>/dev/null | awk 'NR > 1 { count++ } END { print count + 0 }' || true; fi"
}

count_remote_tool_processes() {
  remote "pgrep -x '${tool}' | awk '{ count++ } END { print count + 0 }' || true"
}

path_trace() {
  local file="$1"
  grep -E 'connected-(relay|direct)|v2-data-plane=raw-direct|v2-raw-direct-active=[1-9][0-9]*' "${file}" 2>/dev/null || true
}

path_changed_mid_run() {
  local trace="$1"
  grep -q 'connected-relay' <<<"${trace}" && grep -q 'connected-direct' <<<"${trace}"
}

has_direct_path_evidence() {
  grep -Eq 'connected-direct|v2-data-plane=raw-direct|v2-raw-direct-active=[1-9][0-9]*'
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

terminate_remote_processes() {
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
  local pid="$1"
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

cleanup() {
  local cleanup_status=0
  local remote_cleanup_status=0

  if [[ -n "${send_pid}" ]]; then
    if ! terminate_local_process "${send_pid}"; then
      echo "local sender cleanup incomplete: ${send_pid}" >&2
      cleanup_status=1
    fi
    send_pid=""
  fi
  if [[ -n "${listener_pid}" ]]; then
    if ! terminate_local_process "${listener_pid}"; then
      echo "local receiver cleanup incomplete: ${listener_pid}" >&2
      cleanup_status=1
    fi
    listener_pid=""
  fi
  if ! terminate_remote_processes >/dev/null 2>&1; then
    remote_cleanup_status=1
  fi
  if ! remote "rm -f '${remote_base}.pid' '${remote_base}.child.pid' '${remote_base}.child.pid.tmp' '${remote_base}.status' '${remote_base}.status.tmp' '${remote_base}.payload' '${remote_base}.out' '${remote_base}.err' '${remote_base}.trace.csv' '${remote_sender_resource_json}' '${remote_receiver_resource_json}' '${remote_upload}' '${remote_runstats_upload}'; rm -f '${remote_bin}' '${remote_runstats}'; rmdir '${remote_bin_dir}' '${remote_run_dir}' 2>/dev/null || true; if [[ -e '${remote_base}.pid' || -e '${remote_base}.child.pid' || -e '${remote_base}.child.pid.tmp' || -e '${remote_base}.status' || -e '${remote_base}.status.tmp' || -e '${remote_sender_resource_json}' || -e '${remote_receiver_resource_json}' || -e '${remote_upload}' || -e '${remote_runstats_upload}' || -e '${remote_bin}' || -e '${remote_runstats}' || -e '${remote_bin_dir}' || -e '${remote_run_dir}' ]]; then exit 1; fi" >/dev/null 2>&1; then
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

build_and_install_remote_binary() {
  if [[ -z "${local_override}" ]]; then
    mise run build
    mise run build-linux-amd64
  fi
  mise exec -- go build -o "${local_runstats}" ./tools/runstats
  GOOS=linux GOARCH=amd64 mise exec -- go build -o "${linux_runstats}" ./tools/runstats
  remote "mkdir -p '${remote_run_dir}' '${remote_bin_dir}'"
  scp "${linux_bin}" "${remote_target}:${remote_upload}" >/dev/null
  scp "${linux_runstats}" "${remote_target}:${remote_runstats_upload}" >/dev/null
  if ! install_remote_bin "${remote_bin_dir}"; then
    echo "remote benchmark directory is not writable and executable; set DERPHOLE_REMOTE_BIN_DIR to a writable executable root" >&2
    exit 1
  fi
}

run_forward_derphole_stream() {
  echo "generating ${size_mib} MiB random payload"
  dd if=/dev/urandom of="${payload}" bs=1048576 count="${size_mib}" 2>/dev/null
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
  echo "generating ${size_mib} MiB random payload"
  dd if=/dev/urandom of="${payload}" bs=1048576 count="${size_mib}" 2>/dev/null
  source_sha="$(shasum -a 256 "${payload}" | awk '{print $1}')"
  rm -f "${sender_log}" "${sender_trace_csv}" "${sender_resource_json}"
  remote "rm -f '${remote_base}.pid' '${remote_base}.out' '${remote_base}.err' '${remote_base}.trace.csv' '${remote_receiver_resource_json}'"

  start_ms="$(now_ms)"
  DERPHOLE_TRANSFER_TRACE_CSV="${sender_trace_csv}" "${local_runstats}" -out "${sender_resource_json}" -- "${local_bin}" --verbose send "${payload}" >/dev/null 2>"${sender_log}" &
  send_pid="$!"

  token=""
  for _ in $(seq 1 200); do
    token="$(sed -nE 's/.* receive ([A-Za-z0-9_-]{20,})$/\1/p' "${sender_log}" | head -n 1)"
    [[ -n "${token}" ]] && break
    kill -0 "${send_pid}" 2>/dev/null || break
    sleep 0.1
  done
  [[ -n "${token}" ]] || { echo "failed to capture send token" >&2; exit 1; }

  remote "DERPHOLE_TRANSFER_TRACE_CSV='${remote_base}.trace.csv' '${remote_runstats}' -out '${remote_receiver_resource_json}' -- '${remote_bin}' --verbose receive -o '${remote_base}.out' '${token}' >/dev/null 2>'${remote_base}.err'"
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
  echo "generating ${size_mib} MiB random payload on ${target}"
  remote "dd if=/dev/urandom of='${remote_base}.payload' bs=1048576 count='${size_mib}' 2>/dev/null"
  source_sha="$(remote "sha256sum '${remote_base}.payload' | awk '{print \$1}'")"

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
  remote_send_cmd+=" '${token}' <'${remote_base}.payload' >/dev/null 2>'${remote_base}.err'"

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
  echo "generating ${size_mib} MiB random payload on ${target}"
  remote "dd if=/dev/urandom of='${remote_base}.payload' bs=1048576 count='${size_mib}' 2>/dev/null"
  source_sha="$(remote "sha256sum '${remote_base}.payload' | awk '{print \$1}'")"
  remote "rm -f '${remote_base}.pid' '${remote_base}.child.pid' '${remote_base}.child.pid.tmp' '${remote_base}.status' '${remote_base}.status.tmp' '${remote_base}.out' '${remote_base}.err' '${remote_base}.trace.csv' '${remote_sender_resource_json}'; nohup sh -c 'set +e; child_pid=; forward_signal() { signal=\$1; if [ -n \"\${child_pid}\" ]; then kill -\"\${signal}\" \"\${child_pid}\" 2>/dev/null || true; fi; }; trap \"forward_signal TERM\" TERM; trap \"forward_signal INT\" INT; DERPHOLE_TRANSFER_TRACE_CSV=\"${remote_base}.trace.csv\" \"${remote_runstats}\" -out \"${remote_sender_resource_json}\" -- \"${remote_bin}\" --verbose send \"${remote_base}.payload\" >\"${remote_base}.out\" 2>\"${remote_base}.err\" & child_pid=\$!; printf \"%s\\n\" \"\${child_pid}\" >\"${remote_base}.child.pid.tmp\"; mv \"${remote_base}.child.pid.tmp\" \"${remote_base}.child.pid\"; wait \"\${child_pid}\"; status=\$?; printf \"%s\\n\" \"\${status}\" >\"${remote_base}.status.tmp\"; mv \"${remote_base}.status.tmp\" \"${remote_base}.status\"; exit \"\${status}\"' >/dev/null 2>&1 </dev/null & echo \$! >'${remote_base}.pid'"

  token=""
  for _ in $(seq 1 200); do
    token="$(remote "sed -nE 's/.* receive ([A-Za-z0-9_-]{20,})$/\\1/p' '${remote_base}.err' | head -n 1")"
    [[ -n "${token}" ]] && break
    sleep 0.1
  done
  [[ -n "${token}" ]] || { echo "failed to capture remote send token" >&2; exit 1; }

  start_ms="$(now_ms)"
  DERPHOLE_TRANSFER_TRACE_CSV="${receiver_trace_csv}" "${local_runstats}" -out "${receiver_resource_json}" -- "${local_bin}" --verbose receive -o "${receiver_out}" "${token}" >/dev/null 2>"${receiver_log}"
  wait_remote_pid_status
  command_end_ms="$(now_ms)"

  remote "cat '${remote_base}.err'" >"${sender_log}"
  remote "cat '${remote_base}.trace.csv'" >"${sender_trace_csv}"
  remote "cat '${remote_sender_resource_json}'" >"${sender_resource_json}"
  sink_sha="$(shasum -a 256 "${receiver_out}" | awk '{print $1}')"
  sink_size="$(wc -c < "${receiver_out}" | tr -d '[:space:]')"
}

finalize_run() {
  local sender_trace
  local receiver_trace
  local sender_path_changed="false"
  local receiver_path_changed="false"

  sender_trace="$(path_trace "${sender_log}")"
  receiver_trace="$(path_trace "${receiver_log}")"

  if grep -Fq 'v2-block-transfer=bulk-packets' "${sender_log}" && grep -Fq 'v2-block-transfer=bulk-packets' "${receiver_log}"; then
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

build_and_install_remote_binary

case "${tool}:${direction}:${workload}" in
  derphole:forward:file) run_forward_derphole_file ;;
  derphole:reverse:file) run_reverse_derphole_file ;;
  derphole:forward:stream) run_forward_derphole_stream ;;
  derphole:reverse:stream) run_reverse_derphole_stream ;;
  *) echo "unsupported benchmark mode: ${tool}:${direction}:${workload}" >&2; exit 1 ;;
esac

finalize_run
if ! cleanup; then
  echo "benchmark cleanup failed" >&2
  exit 1
fi
emit_benchmark_footer 1 true "" "${sender_goodput_mbps}" "${sender_peak_goodput_mbps}" "${sender_first_byte_ms}"
trap - EXIT
