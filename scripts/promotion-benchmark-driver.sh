#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

tool="${DERPHOLE_BENCH_TOOL:?DERPHOLE_BENCH_TOOL is required}"
direction="${DERPHOLE_BENCH_DIRECTION:?DERPHOLE_BENCH_DIRECTION is required}"

target="${1:?usage: $0 <target> [size-mib]}"
size_mib="${2:-1024}"
expected_size="$((size_mib * 1048576))"
tmp="$(mktemp -d)"
start_ms=0
duration_ms=0
remote_suffix=""
if [[ "${direction}" == "reverse" ]]; then
  remote_suffix="-reverse"
fi
remote_base="/tmp/${tool}-promotion${remote_suffix}-$$"
remote_upload="/tmp/${tool}-promotion${remote_suffix}-bin-$$"
remote_target="${target}"
if [[ "${target}" != *"@"* ]]; then
  remote_user="${DERPHOLE_REMOTE_USER:-root}"
  remote_target="${remote_user}@${target}"
fi
requested_remote_bin_dir="${DERPHOLE_REMOTE_BIN_DIR:-/usr/local/bin}"
remote_bin_dir="${requested_remote_bin_dir}"
remote_bin="${remote_bin_dir%/}/${tool}"
local_bin="./dist/${tool}"
linux_bin="dist/${tool}-linux-amd64"
sender_log="${tmp}/sender.err"
receiver_log="${tmp}/receiver.err"
sender_trace_csv="${tmp}/sender.trace.csv"
receiver_trace_csv="${tmp}/receiver.trace.csv"
receiver_out="${tmp}/receiver.out"
payload="${tmp}/payload.bin"
send_pid=""
listener_pid=""
remote_env=()
parallel_args=()
parallel_args_remote=""

if [[ "${DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES:-}" == "1" ]]; then
  remote_env+=(DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1)
fi
if [[ "${tool}" == "derphole" && -n "${DERPHOLE_PARALLEL_ARGS:-}" ]]; then
  read -r -a parallel_args <<<"${DERPHOLE_PARALLEL_ARGS}"
  parallel_args_remote="${parallel_args[*]-}"
fi

remote() {
  ssh "${remote_target}" "${remote_env[@]}" 'bash -se' <<<"$1"
}

remote_home="$(remote 'printf %s "$HOME"')"
fallback_remote_bin_dirs=(
  "${remote_home}/.local/share/${tool}-bench/bin"
  "${remote_home}/.cache/${tool}-bench/bin"
  "/var/tmp/${tool}-bench-bin"
  "/tmp/${tool}-bench-bin"
)

install_remote_bin() {
  local desired_dir="$1"
  local desired_bin="${desired_dir%/}/${tool}"
  remote "mkdir -p '${desired_dir}' && install -m 0755 '${remote_upload}' '${desired_bin}' && rm -f '${remote_upload}' && '${desired_bin}' --help >/dev/null 2>&1"
}

now_ms() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import time; print(int(time.time() * 1000))'
    return 0
  fi
  perl -MTime::HiRes=time -e 'print int(time() * 1000), "\n"'
}

wall_goodput_mbps() {
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

trace_average_mbps() {
  local file="$1"
  local bytes_key="$2"
  local elapsed_key="$3"

  if [[ ! -s "${file}" ]]; then
    return 0
  fi
  python3 - "${file}" "${bytes_key}" "${elapsed_key}" <<'PY'
import csv
import sys

path, bytes_key, elapsed_key = sys.argv[1:4]
last = None
with open(path, newline="") as fh:
    for row in csv.DictReader(fh):
        last = row
if not last:
    sys.exit(0)
try:
    byte_count = int((last.get(bytes_key) or "0").strip())
    elapsed_ms = int((last.get(elapsed_key) or "0").strip())
except ValueError:
    sys.exit(0)
if byte_count <= 0 or elapsed_ms <= 0:
    sys.exit(0)
print(f"{(byte_count * 8.0) / (elapsed_ms * 1000.0):.2f}")
PY
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
  if [[ -z "${log_dir}" ]]; then
    return 0
  fi
  mkdir -p "${log_dir}"
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local prefix="${tool}-${direction}-${target//[^A-Za-z0-9_.-]/_}-${size_mib}MiB-${stamp}"
  if [[ -f "${sender_log}" ]]; then
    cp "${sender_log}" "${log_dir}/${prefix}-sender.log"
  fi
  if [[ -f "${receiver_log}" ]]; then
    cp "${receiver_log}" "${log_dir}/${prefix}-receiver.log"
  fi
  if [[ -f "${sender_trace_csv}" ]]; then
    cp "${sender_trace_csv}" "${log_dir}/${prefix}-sender.trace.csv"
  fi
  if [[ -f "${receiver_trace_csv}" ]]; then
    cp "${receiver_trace_csv}" "${log_dir}/${prefix}-receiver.trace.csv"
  fi
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
  for _ in $(seq 1 400); do
    if ! remote "if [[ -f '${remote_base}.pid' ]]; then kill -0 \$(cat '${remote_base}.pid') 2>/dev/null; else false; fi" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
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

cleanup() {
  if [[ -n "${send_pid}" ]]; then
    kill "${send_pid}" 2>/dev/null || true
  fi
  if [[ -n "${listener_pid}" ]]; then
    kill "${listener_pid}" 2>/dev/null || true
  fi
  remote "if [[ -f '${remote_base}.pid' ]]; then kill \$(cat '${remote_base}.pid') 2>/dev/null || true; fi; rm -f '${remote_base}.pid' '${remote_base}.payload' '${remote_base}.out' '${remote_base}.err' '${remote_base}.trace.csv' '${remote_upload}'; if [[ '${remote_bin_dir}' != '${requested_remote_bin_dir}' ]]; then rm -f '${remote_bin}'; fi" >/dev/null 2>&1 || true
  rm -rf "${tmp}"
}

trap 'status=$?; if [[ ${status} -ne 0 ]]; then if [[ ${start_ms} -gt 0 && ${duration_ms} -eq 0 ]]; then end_ms="$(now_ms)"; duration_ms="$((end_ms - start_ms))"; fi; dump_failure; preserve_logs; emit_benchmark_footer 2 false "promotion-benchmark-driver-exit-${status}"; cleanup; fi; exit ${status}' EXIT

build_and_install_remote_binary() {
  mise run build
  mise run build-linux-amd64
  scp "${linux_bin}" "${remote_target}:${remote_upload}" >/dev/null
  if install_remote_bin "${remote_bin_dir}"; then
    return 0
  fi
  if [[ -n "${DERPHOLE_REMOTE_BIN_DIR:-}" ]]; then
    exit 1
  fi
  local installed_fallback=0
  for fallback_dir in "${fallback_remote_bin_dirs[@]}"; do
    remote_bin_dir="${fallback_dir}"
    remote_bin="${remote_bin_dir}/${tool}"
    scp "${linux_bin}" "${remote_target}:${remote_upload}" >/dev/null
    if install_remote_bin "${remote_bin_dir}"; then
      installed_fallback=1
      break
    fi
  done
  if [[ "${installed_fallback}" != "1" ]]; then
    echo "failed to install remote benchmark binary in any writable exec-capable directory" >&2
    exit 1
  fi
}

run_forward_derphole() {
  echo "generating ${size_mib} MiB random payload"
  dd if=/dev/urandom of="${payload}" bs=1048576 count="${size_mib}" 2>/dev/null
  source_sha="$(shasum -a 256 "${payload}" | awk '{print $1}')"

  remote "rm -f '${remote_base}.pid' '${remote_base}.out' '${remote_base}.err' '${remote_base}.trace.csv'; nohup env DERPHOLE_TRANSFER_TRACE_CSV='${remote_base}.trace.csv' '${remote_bin}' --verbose listen >'${remote_base}.out' 2>'${remote_base}.err' </dev/null & echo \$! > '${remote_base}.pid'"

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
    DERPHOLE_TRANSFER_TRACE_CSV="${sender_trace_csv}" "${local_bin}" --verbose pipe "${parallel_args[@]}" "${token}" < "${payload}" >/dev/null 2>"${sender_log}"
  else
    DERPHOLE_TRANSFER_TRACE_CSV="${sender_trace_csv}" "${local_bin}" --verbose pipe "${token}" < "${payload}" >/dev/null 2>"${sender_log}"
  fi

  wait_remote_pid_exit
  remote "cat '${remote_base}.err'" >"${receiver_log}"
  remote "cat '${remote_base}.trace.csv'" >"${receiver_trace_csv}"
  sink_sha="$(remote "sha256sum '${remote_base}.out' | awk '{print \$1}'")"
  sink_size="$(remote "wc -c < '${remote_base}.out'")"
}

run_reverse_derphole() {
  echo "generating ${size_mib} MiB random payload on ${target}"
  remote "dd if=/dev/urandom of='${remote_base}.payload' bs=1048576 count='${size_mib}' 2>/dev/null"
  source_sha="$(remote "sha256sum '${remote_base}.payload' | awk '{print \$1}'")"

  DERPHOLE_TRANSFER_TRACE_CSV="${receiver_trace_csv}" "${local_bin}" --verbose listen >"${receiver_out}" 2>"${receiver_log}" &
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
  remote_send_cmd="DERPHOLE_TRANSFER_TRACE_CSV='${remote_base}.trace.csv' '${remote_bin}' --verbose pipe"
  if [[ -n "${parallel_args_remote}" ]]; then
    remote_send_cmd+=" ${parallel_args_remote}"
  fi
  remote_send_cmd+=" '${token}' <'${remote_base}.payload' >/dev/null 2>'${remote_base}.err'"

  start_ms="$(now_ms)"
  remote "${remote_send_cmd}"

  wait "${listener_pid}"
  listener_pid=""
  remote "cat '${remote_base}.err'" >"${sender_log}"
  remote "cat '${remote_base}.trace.csv'" >"${sender_trace_csv}"
  sink_sha="$(shasum -a 256 "${receiver_out}" | awk '{print $1}')"
  sink_size="$(wc -c < "${receiver_out}" | tr -d '[:space:]')"
}

finalize_run() {
  local sender_trace
  local receiver_trace
  local sender_path_changed="false"
  local receiver_path_changed="false"
  local sender_goodput_mbps
  local sender_peak_goodput_mbps
  local sender_first_byte_ms
  local wall_goodput

  sender_trace="$(path_trace "${sender_log}")"
  receiver_trace="$(path_trace "${receiver_log}")"

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

  sender_goodput_mbps="$(trace_average_mbps "${sender_trace_csv}" "app_bytes" "elapsed_ms")"
  if [[ -z "${sender_goodput_mbps}" ]]; then
    sender_goodput_mbps="$(last_trace_value "${sender_trace_csv}" "send_goodput_mbps")"
  fi
  if [[ -z "${sender_goodput_mbps}" ]]; then
    sender_goodput_mbps="$(last_trace_value "${sender_trace_csv}" "app_mbps")"
  fi
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
  wall_goodput="$(wall_goodput_mbps "${expected_size}" "${duration_ms}")"
  if [[ -z "${sender_goodput_mbps}" ]]; then
    sender_goodput_mbps="${wall_goodput}"
  fi
  if [[ -z "${sender_peak_goodput_mbps}" ]]; then
    sender_peak_goodput_mbps="${sender_goodput_mbps}"
  fi
  if [[ -z "${sender_first_byte_ms}" ]]; then
    sender_first_byte_ms=0
  fi

  echo "benchmark-wall-goodput-mbps=${wall_goodput}"
  preserve_logs
  emit_benchmark_footer 1 true "" "${sender_goodput_mbps}" "${sender_peak_goodput_mbps}" "${sender_first_byte_ms}"

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

case "${tool}:${direction}" in
  derphole:forward)
    run_forward_derphole
    ;;
  derphole:reverse)
    run_reverse_derphole
    ;;
  *)
    echo "unsupported benchmark mode: ${tool}:${direction}" >&2
    exit 1
    ;;
esac

finalize_run
cleanup
trap - EXIT
