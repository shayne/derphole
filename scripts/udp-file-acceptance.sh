#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

validate_public_address() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
allowed = address.version == 4 and address.is_global and not address.is_multicast
raise SystemExit(0 if allowed else 1)
PY
}

if [[ "${1:-}" == "--validate-public-address" ]]; then
  [[ "$#" -eq 2 ]] || exit 2
  validate_public_address "$2"
  exit $?
fi

missing=()
for name in \
  DERPHOLE_UDP_ACCEPT_REMOTE \
  DERPHOLE_UDP_ACCEPT_REMOTE_PUBLIC_ADDR \
  DERPHOLE_UDP_ACCEPT_LOCAL_PUBLIC_ADDR \
  DERPHOLE_UDP_ACCEPT_TCP_PORT; do
  [[ -n "${!name:-}" ]] || missing+=("${name}")
done
if ((${#missing[@]})); then
  printf 'required environment is missing: %s\n' "${missing[*]}" >&2
  exit 2
fi

remote="${DERPHOLE_UDP_ACCEPT_REMOTE}"
remote_public="${DERPHOLE_UDP_ACCEPT_REMOTE_PUBLIC_ADDR}"
local_public="${DERPHOLE_UDP_ACCEPT_LOCAL_PUBLIC_ADDR}"
tcp_port="${DERPHOLE_UDP_ACCEPT_TCP_PORT}"
size_mib=3072
size_bytes=3221225472
runs=3
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
run_root="${DERPHOLE_UDP_ACCEPT_OUTPUT_ROOT:-.tmp/udp-file-2gbps}/${run_id}"
remote_root=""
revision=""
last_error=""
last_capacity=""
local_pids=()
cleanup_started=0
decision_written=0

if ! validate_public_address "${remote_public}"; then
  echo "DERPHOLE_UDP_ACCEPT_REMOTE_PUBLIC_ADDR must be a public IPv4 address" >&2
  exit 2
fi
if ! validate_public_address "${local_public}"; then
  echo "DERPHOLE_UDP_ACCEPT_LOCAL_PUBLIC_ADDR must be a public IPv4 address" >&2
  exit 2
fi
if [[ ! "${tcp_port}" =~ ^[0-9]+$ ]] || ((tcp_port < 1024 || tcp_port > 65535)); then
  echo "DERPHOLE_UDP_ACCEPT_TCP_PORT must be an integer from 1024 through 65535" >&2
  exit 2
fi
if [[ "${remote}" == *$'\n'* || "${remote}" == *$'\r'* ]]; then
  echo "DERPHOLE_UDP_ACCEPT_REMOTE must be one SSH target" >&2
  exit 2
fi

remote_shell() {
  ssh -o BatchMode=yes "${remote}" 'bash -se' <<<"$1"
}

remove_local_pid() {
  local remove="$1"
  local kept=()
  local pid
  for pid in "${local_pids[@]}"; do
    [[ "${pid}" == "${remove}" ]] || kept+=("${pid}")
  done
  local_pids=("${kept[@]}")
}

terminate_local_pid() {
  local pid="$1"
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 0
  if kill -0 "${pid}" 2>/dev/null; then
    kill -TERM "${pid}" 2>/dev/null || true
  fi
  wait "${pid}" 2>/dev/null || true
}

write_failure_decision() {
  local status="$1"
  [[ -d "${run_root}" && ! -e "${run_root}/decision.json" ]] || return 0
  python3 - "${run_root}/decision.json" "${status}" "${revision}" "${last_error}" <<'PY'
import json
import os
import sys

path, status, revision, reason = sys.argv[1:]
value = {
    "schema_version": 1,
    "passed": False,
    "revision": revision,
    "exit_status": int(status),
    "reasons": [reason or f"acceptance driver exited with status {status}"],
}
temporary = path + ".tmp"
with open(temporary, "w") as fh:
    json.dump(value, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.replace(temporary, path)
PY
}

cleanup() {
  local status="$?"
  ((cleanup_started == 0)) || return "${status}"
  cleanup_started=1
  set +e
  if ((status != 0 && decision_written == 0)); then
    write_failure_decision "${status}"
    echo "acceptance evidence preserved at ${run_root}" >&2
  fi
  local pid
  for pid in "${local_pids[@]}"; do
    terminate_local_pid "${pid}"
  done
  if [[ -n "${remote_root}" ]]; then
    remote_shell "case '${remote_root}' in */derphole-udp-accept.*) rm -rf -- '${remote_root}' ;; *) exit 1 ;; esac"
  fi
  trap - EXIT INT TERM
  exit "${status}"
}
trap cleanup EXIT INT TERM

fail() {
  last_error="$1"
  echo "${last_error}" >&2
  return 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "$1 is required locally" >&2
    exit 1
  }
}

for command_name in dd git iperf3 lsof mise netstat python3 scp ssh shasum; do
  require_command "${command_name}"
done
remote_shell "for command_name in iperf3 python3 sha256sum getconf df ss awk cat ps; do command -v \"\${command_name}\" >/dev/null || { echo \"\${command_name} is required remotely\" >&2; exit 1; }; done"

mkdir -p "${run_root}/bin" "${run_root}/health"
remote_root="$(remote_shell 'mktemp -d "$HOME/derphole-udp-accept.XXXXXX"')"
if [[ "${remote_root}" != /*/derphole-udp-accept.* ]]; then
  fail "failed to create a scoped remote run directory"
  exit 1
fi

revision="$(git rev-parse HEAD)"
local_derphole="${run_root}/bin/derphole"
linux_derphole="${run_root}/bin/derphole-linux-amd64"
local_tracecheck="${run_root}/bin/transfertracecheck"

mise exec -- go build -o "${local_derphole}" ./cmd/derphole
env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 mise exec -- go build -o "${linux_derphole}" ./cmd/derphole
mise exec -- go build -o "${local_tracecheck}" ./tools/transfertracecheck

local_binary_sha256="$(shasum -a 256 "${linux_derphole}" | awk '{print $1}')"
scp "${linux_derphole}" "${remote}:${remote_root}/candidate-linux-amd64" >/dev/null
remote_binary_sha256="$(remote_shell "sha256sum '${remote_root}/candidate-linux-amd64' | awk '{print \$1}'")"
if [[ "${local_binary_sha256}" != "${remote_binary_sha256}" ]]; then
  fail "candidate Linux binary SHA-256 mismatch after upload"
  exit 1
fi
printf '%s  %s\n' "${local_binary_sha256}" "${revision}" >"${run_root}/candidate.sha256"

required_free_kib="$(((size_bytes * 2 + 512 * 1024 * 1024) / 1024))"
local_free_kib="$(df -Pk "${run_root}" | awk 'NR==2 {print $4}')"
remote_free_kib="$(remote_shell "df -Pk '${remote_root}' | awk 'NR==2 {print \$4}'")"
if ((local_free_kib < required_free_kib || remote_free_kib < required_free_kib)); then
  fail "both endpoints need space for one source, one receive file, and safety margin"
  exit 1
fi

remote_cpus="$(remote_shell 'getconf _NPROCESSORS_ONLN')"
if [[ "${remote_cpus}" != "2" ]]; then
  fail "exact Hetzner endpoint has ${remote_cpus} online CPUs, want 2"
  exit 1
fi
if lsof -nP -iTCP:"${tcp_port}" -sTCP:LISTEN 2>/dev/null | grep -q .; then
  fail "local TCP port ${tcp_port} already has a listener"
  exit 1
fi
remote_oom_kill() {
  remote_shell "awk '\$1 == \"oom_kill\" {print \$2}' /proc/vmstat"
}

health_snapshot() {
  local label="$1"
  local directory="${run_root}/health/${label}"
  mkdir -p "${directory}"
  netstat -ibdn >"${directory}/local-netstat.txt" 2>&1 || true
  df -Pk "${run_root}" >"${directory}/local-disk.txt"
  remote_shell "printf '%s\n' '--- cpus ---'; getconf _NPROCESSORS_ONLN
printf '%s\n' '--- uptime ---'; cat /proc/uptime
printf '%s\n' '--- oom_kill ---'; awk '\$1 == \"oom_kill\" {print \$2}' /proc/vmstat
printf '%s\n' '--- memory ---'; cat /proc/meminfo
printf '%s\n' '--- disk ---'; df -Pk '${remote_root}'
printf '%s\n' '--- network ---'; cat /proc/net/dev
printf '%s\n' '--- processes ---'; ps -eo pid,ppid,stat,rss,comm --sort=-rss | head -n 80
printf '%s\n' '--- kernel ---'; dmesg | tail -n 200" >"${directory}/remote.txt" 2>&1
}

python3 - "${run_root}/manifest.json" "${revision}" "${remote}" "${remote_public}" "${local_public}" "${tcp_port}" "${remote_cpus}" <<'PY'
import json
import os
import sys

path, revision, remote, remote_public, local_public, port, cpus = sys.argv[1:]
value = {
    "schema_version": 1,
    "revision": revision,
    "remote": remote,
    "remote_public_addr": remote_public,
    "local_public_addr": local_public,
    "tcp_port": int(port),
    "size_bytes": 3 * 1024 * 1024 * 1024,
    "runs_per_direction": 3,
    "iperf_streams": 8,
    "remote_online_cpus": int(cpus),
}
with open(path, "w") as fh:
    json.dump(value, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.chmod(path, 0o600)
PY

health_snapshot preflight
baseline_oom_kill="$(remote_oom_kill)"

source_file="${run_root}/source.bin"
echo "creating one ${size_mib} MiB random file"
dd if=/dev/urandom of="${source_file}" bs=1048576 count="${size_mib}" 2>/dev/null
source_sha256="$(shasum -a 256 "${source_file}" | awk '{print $1}')"
printf '%s  source.bin\n' "${source_sha256}" >"${run_root}/source.sha256"
remote_source="${remote_root}/source.bin"
scp "${source_file}" "${remote}:${remote_source}" >/dev/null
remote_source_sha256="$(remote_shell "sha256sum '${remote_source}' | awk '{print \$1}'")"
if [[ "${remote_source_sha256}" != "${source_sha256}" ]]; then
  fail "staged source SHA-256 mismatch"
  exit 1
fi

results_csv="${run_root}/results.csv"
decision_json="${run_root}/decision.json"
printf '%s\n' 'run,direction,capacity_mbps,benchmark_goodput_mbps,receiver_goodput_mbps,wall_goodput_mbps,transfer_mode,size_bytes,expected_sha256,actual_sha256,public_route_proven,direct_transport,max_relay_bytes,max_flatline_ms,sender_cpu_seconds_per_gib,receiver_cpu_seconds_per_gib,hetz_cpu_seconds_per_gib,repair_bytes,repair_ratio,scan_checks_per_packet,oom_kill_before,oom_kill_after,batch_backend,send_calls,send_datagrams,receive_calls,receive_datagrams,max_send_batch,max_receive_batch,lane_queue_peak,receive_queue_peak,writer_queue_peak,decrypt_batches,decrypt_datagrams,probe_selected_mbps,probe_duration_ms,probe_trains,probe_sent_datagrams,probe_received_datagrams,probe_loss_ppm,probe_pressure,local_enobufs_retries,retransmits' >"${results_csv}"

parse_iperf_mbps() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1]) as fh:
    value = json.load(fh)
summary = value["end"].get("sum_received") or value["end"].get("sum")
print(f'{summary["bits_per_second"] / 1_000_000:.6f}')
PY
}

run_iperf_control() {
  local direction="$1"
  local case_dir="$2"
  local capacity=""
  local attempt output server_pid
  local reverse_args=()
  [[ "${direction}" == "local-to-remote" ]] && reverse_args=(-R)
  for attempt in 1 2 3; do
    output="${case_dir}/iperf-attempt-${attempt}.json"
    iperf3 -s -4 -p "${tcp_port}" --one-off --forceflush >"${case_dir}/iperf-server-${attempt}.log" 2>&1 &
    server_pid="$!"
    local_pids+=("${server_pid}")
    sleep 0.2
    if ! remote_shell "iperf3 -4 -J -c '${local_public}' -p '${tcp_port}' -t 20 -P 8 ${reverse_args[*]}" >"${output}"; then
      terminate_local_pid "${server_pid}"
      remove_local_pid "${server_pid}"
      sleep 2
      continue
    fi
    if ! wait "${server_pid}"; then
      remove_local_pid "${server_pid}"
      sleep 2
      continue
    fi
    remove_local_pid "${server_pid}"
    capacity="$(parse_iperf_mbps "${output}")"
    printf '%s\n' "${capacity}" >"${case_dir}/capacity-mbps.txt"
    if python3 - "${capacity}" <<'PY'
import sys
raise SystemExit(0 if float(sys.argv[1]) >= 2050.0 else 1)
PY
    then
      last_capacity="${capacity}"
      return 0
    fi
    sleep 2
  done
  fail "three same-direction iperf controls were below 2050 Mbps"
}

latest_artifact() {
  find "$1" -type f -name "$2" -print | sort | tail -n 1
}

run_file_transfer() {
  local direction="$1"
  local case_dir="$2"
  local promotion_direction="forward"
  [[ "${direction}" == "remote-to-local" ]] && promotion_direction="reverse"
  local clean_env=(env -i "HOME=${HOME}" "PATH=${PATH}")
  [[ -n "${TMPDIR:-}" ]] && clean_env+=("TMPDIR=${TMPDIR}")
  [[ -n "${USER:-}" ]] && clean_env+=("USER=${USER}")
  [[ -n "${LOGNAME:-}" ]] && clean_env+=("LOGNAME=${LOGNAME}")
  [[ -n "${SHELL:-}" ]] && clean_env+=("SHELL=${SHELL}")
  [[ -n "${SSH_AUTH_SOCK:-}" ]] && clean_env+=("SSH_AUTH_SOCK=${SSH_AUTH_SOCK}")
  clean_env+=(
    DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1
    DERPHOLE_BENCH_TOOL=derphole
    DERPHOLE_BENCH_EXPECT_TRANSFER_MODE=bulk-packets-v1
    DERPHOLE_BENCH_WORKLOAD=file
    "DERPHOLE_BENCH_DIRECTION=${promotion_direction}"
    "DERPHOLE_BENCH_LOCAL_PAYLOAD=${source_file}"
    "DERPHOLE_BENCH_REMOTE_PAYLOAD=${remote_source}"
    "DERPHOLE_BENCH_LOCAL_BIN=${local_derphole}"
    "DERPHOLE_BENCH_LINUX_BIN=${linux_derphole}"
    "DERPHOLE_BENCH_REVISION_LABEL=${revision}"
    "DERPHOLE_BENCH_LOG_DIR=${case_dir}"
    "DERPHOLE_BENCH_LOCAL_TMP_ROOT=${run_root}/tmp"
    "DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT=${remote_root}/promotion"
    "DERPHOLE_REMOTE_BIN_DIR=${remote_root}/promotion-bin"
  )
  set +e
  "${clean_env[@]}" bash ./scripts/promotion-benchmark-driver.sh "${remote}" "${size_mib}" >"${case_dir}/promotion.out" 2>&1
  local status="$?"
  set -e
  if [[ "${status}" -ne 0 ]]; then
    tail -n 300 "${case_dir}/promotion.out" >&2 || true
    fail "production file transfer failed for ${direction}"
    return "${status}"
  fi
}

analyze_transfer() {
  local direction="$1"
  local run="$2"
  local case_dir="$3"
  local capacity="$4"
  local oom_before="$5"
  local oom_after="$6"
  local sender_trace receiver_trace sender_resource receiver_resource sender_log receiver_log
  sender_trace="$(latest_artifact "${case_dir}" '*-sender.trace.csv')"
  receiver_trace="$(latest_artifact "${case_dir}" '*-receiver.trace.csv')"
  sender_resource="$(latest_artifact "${case_dir}" '*-sender.resource.json')"
  receiver_resource="$(latest_artifact "${case_dir}" '*-receiver.resource.json')"
  sender_log="$(latest_artifact "${case_dir}" '*-sender.log')"
  receiver_log="$(latest_artifact "${case_dir}" '*-receiver.log')"
  if [[ ! -s "${sender_trace}" || ! -s "${receiver_trace}" || ! -s "${sender_resource}" || ! -s "${receiver_resource}" || ! -s "${sender_log}" || ! -s "${receiver_log}" ]]; then
    fail "transfer evidence is incomplete for ${direction} run ${run}"
    return 1
  fi

  local sender_peer="${remote_public}"
  local receiver_peer="${local_public}"
  if [[ "${direction}" == "remote-to-local" ]]; then
    sender_peer="${local_public}"
    receiver_peer="${remote_public}"
  fi

  "${local_tracecheck}" -role send -stall-window 999ms -expected-payload-bytes "${size_bytes}" -require-direct-transport udp -require-file-payload-engine bulk-packets-v1 -require-engine-telemetry -expected-selected-public-ipv4 "${sender_peer}" -peer-expected-selected-public-ipv4 "${receiver_peer}" -forbid-relay-payload -peer-trace "${receiver_trace}" "${sender_trace}" >"${case_dir}/sender-trace-check.txt"
  "${local_tracecheck}" -role receive -stall-window 999ms -expected-payload-bytes "${size_bytes}" -require-direct-transport udp -require-file-payload-engine bulk-packets-v1 -require-engine-telemetry -expected-selected-public-ipv4 "${receiver_peer}" -forbid-relay-payload "${receiver_trace}" >"${case_dir}/receiver-trace-check.txt"

  local expected_public="${sender_peer}"
  if ! grep -F "${expected_public}:" "${sender_log}" "${receiver_log}" >/dev/null; then
    fail "transfer logs do not prove expected public route ${expected_public}"
    return 1
  fi
  if grep -E 'v2-block-transfer=direct-tcp-files|v2-data-plane=(direct-tcp|tls)|connected-direct-tcp' "${sender_log}" "${receiver_log}" >/dev/null; then
    fail "transfer logs contain a forbidden TCP or TLS payload marker"
    return 1
  fi
  if ! grep -F "sha256=${source_sha256}" "${case_dir}/promotion.out" >/dev/null; then
    fail "promotion output does not contain the verified source SHA-256"
    return 1
  fi

  python3 - "${case_dir}/result.csv" "${case_dir}/promotion.out" "${sender_trace}" "${receiver_trace}" "${sender_resource}" "${receiver_resource}" "${direction}" "${run}" "${capacity}" "${revision}" "${source_sha256}" "${size_bytes}" "${oom_before}" "${oom_after}" <<'PY'
import csv
import json
import math
import sys

(out, promotion, sender_trace, receiver_trace, sender_resource, receiver_resource,
 direction, run, capacity, revision, expected_sha256, size, oom_before, oom_after) = sys.argv[1:]
size = int(size)

def footer(path):
    values = {}
    with open(path, errors="replace") as fh:
        for line in fh:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                values[key] = value
    return values

def trace_rows(path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))

def last(rows, key, default="0"):
    for row in reversed(rows):
        value = (row.get(key) or "").strip()
        if value:
            return value
    return default

def maximum(rows, key, default=0.0):
    values = [float(row[key]) for row in rows if (row.get(key) or "").strip()]
    return max(values) if values else default

def load_resource(path):
    with open(path) as fh:
        value = json.load(fh)
    if not value.get("resource_stats_available") or int(value.get("exit_code", -1)) != 0:
        raise SystemExit(f"invalid resource stats: {path}")
    return value

def cpu_per_gib(value):
    return (float(value["user_cpu_seconds"]) + float(value["system_cpu_seconds"])) / (size / (1024 ** 3))

def max_flatline_ms(rows):
    last_value = 0
    last_progress_at = None
    maximum_gap = 0
    for row in rows:
        value = int(float(row.get("app_bytes") or 0))
        at = int(row["timestamp_unix_ms"])
        if value > last_value:
            if last_progress_at is not None:
                maximum_gap = max(maximum_gap, at - last_progress_at)
            last_value = value
            last_progress_at = at
    return maximum_gap

f = footer(promotion)
srows = trace_rows(sender_trace)
rrows = trace_rows(receiver_trace)
sr = load_resource(sender_resource)
rr = load_resource(receiver_resource)
if f.get("benchmark-success") != "true":
    raise SystemExit("benchmark did not report success")
if f.get("benchmark-transfer-mode") != "bulk-packets-v1":
    raise SystemExit(f"transfer mode is {f.get('benchmark-transfer-mode')!r}")
if int(f.get("benchmark-size-bytes", 0)) != size:
    raise SystemExit("benchmark byte count mismatch")

elapsed_ms = int(float(last(srows, "transfer_elapsed_ms")))
if elapsed_ms <= 0:
    raise SystemExit("receiver-reported transfer elapsed time is missing from sender trace")
receiver_goodput = size * 8 / (elapsed_ms * 1000)
benchmark_goodput = float(f["benchmark-goodput-mbps"])
wall_goodput = float(f["benchmark-wall-goodput-mbps"])
relay_bytes = int(maximum(srows + rrows, "relay_bytes"))
direct_transports = {last(srows, "direct_transport", ""), last(rrows, "direct_transport", "")}
sender_direct_packet_bytes = int(maximum(srows, "direct_packet_bytes"))
receiver_direct_packet_bytes = int(maximum(rrows, "direct_packet_bytes"))
receiver_direct_committed_bytes = int(maximum(rrows, "direct_committed_bytes"))
flatline = max_flatline_ms(rrows)
sender_cpu = cpu_per_gib(sr)
receiver_cpu = cpu_per_gib(rr)
hetz_cpu = receiver_cpu if direction == "local-to-remote" else sender_cpu
repair_bytes = int(maximum(srows, "repair_bytes"))
repair_ratio = repair_bytes / size
packet_count = math.ceil(size / 1358)
scan_checks = int(maximum(rrows, "missing_scan_checks"))
scan_checks_per_packet = scan_checks / packet_count
actual_sha256 = f.get("sha256", expected_sha256)

failures = []
if receiver_goodput <= 2000.0:
    failures.append(f"receiver goodput {receiver_goodput:.3f} <= 2000 Mbps")
if benchmark_goodput <= 2000.0:
    failures.append(f"benchmark goodput {benchmark_goodput:.3f} <= 2000 Mbps")
if abs(benchmark_goodput - receiver_goodput) > 0.02:
    failures.append(f"benchmark goodput {benchmark_goodput:.3f} disagrees with receiver clock {receiver_goodput:.3f}")
if direct_transports != {"udp"}:
    failures.append(f"direct transports are {sorted(direct_transports)}")
if relay_bytes != 0:
    failures.append(f"relay payload bytes are {relay_bytes}")
if sender_direct_packet_bytes < size:
    failures.append(f"sender direct packet bytes are {sender_direct_packet_bytes}, want at least {size}")
if receiver_direct_packet_bytes < size:
    failures.append(f"receiver direct packet bytes are {receiver_direct_packet_bytes}, want at least {size}")
if receiver_direct_committed_bytes != size:
    failures.append(f"receiver direct committed bytes are {receiver_direct_committed_bytes}, want {size}")
if flatline > 999:
    failures.append(f"max flatline is {flatline} ms")
if repair_ratio >= 0.02:
    failures.append(f"repair ratio is {repair_ratio:.6f}")
if scan_checks_per_packet >= 2.0:
    failures.append(f"scan checks per packet is {scan_checks_per_packet:.6f}")
if hetz_cpu >= 8.0:
    failures.append(f"Hetzner CPU seconds per GiB is {hetz_cpu:.6f}")
if oom_before != oom_after:
    failures.append(f"oom_kill changed from {oom_before} to {oom_after}")
if actual_sha256 != expected_sha256:
    failures.append("SHA-256 mismatch")
if last(srows + rrows, "bulk_probe_pressure", "false").lower() != "false":
    failures.append("capacity probe reported pressure")
if failures:
    raise SystemExit("; ".join(failures))

header = [
    "run", "direction", "capacity_mbps", "benchmark_goodput_mbps", "receiver_goodput_mbps",
    "wall_goodput_mbps", "transfer_mode", "size_bytes", "expected_sha256", "actual_sha256",
    "public_route_proven", "direct_transport", "max_relay_bytes", "max_flatline_ms",
    "sender_cpu_seconds_per_gib", "receiver_cpu_seconds_per_gib", "hetz_cpu_seconds_per_gib",
    "repair_bytes", "repair_ratio", "scan_checks_per_packet", "oom_kill_before", "oom_kill_after",
    "batch_backend", "send_calls", "send_datagrams", "receive_calls", "receive_datagrams",
    "max_send_batch", "max_receive_batch", "lane_queue_peak", "receive_queue_peak", "writer_queue_peak",
    "decrypt_batches", "decrypt_datagrams", "probe_selected_mbps", "probe_duration_ms", "probe_trains",
    "probe_sent_datagrams", "probe_received_datagrams", "probe_loss_ppm", "probe_pressure",
    "local_enobufs_retries", "retransmits",
]
row = [
    int(run), direction, float(capacity), benchmark_goodput, receiver_goodput, wall_goodput,
    f["benchmark-transfer-mode"], size, expected_sha256, actual_sha256, True, "udp", relay_bytes, flatline,
    sender_cpu, receiver_cpu, hetz_cpu, repair_bytes, repair_ratio, scan_checks_per_packet,
    int(oom_before), int(oom_after), last(srows, "bulk_batch_backend", last(rrows, "bulk_batch_backend", "")),
    int(maximum(srows, "bulk_send_calls")), int(maximum(srows, "bulk_send_datagrams")),
    int(maximum(rrows, "bulk_receive_calls")), int(maximum(rrows, "bulk_receive_datagrams")),
    int(maximum(srows, "bulk_max_send_batch")), int(maximum(rrows, "bulk_max_receive_batch")),
    int(maximum(srows, "bulk_lane_queue_peak")), int(maximum(rrows, "bulk_receive_queue_peak")),
    int(maximum(rrows, "bulk_writer_queue_peak")), int(maximum(rrows, "bulk_decrypt_batches")),
    int(maximum(rrows, "bulk_decrypt_datagrams")), int(maximum(srows + rrows, "bulk_probe_selected_mbps")),
    int(maximum(srows + rrows, "bulk_probe_duration_ms")), int(maximum(srows + rrows, "bulk_probe_trains")),
    int(maximum(srows + rrows, "bulk_probe_sent_datagrams")), int(maximum(srows + rrows, "bulk_probe_received_datagrams")),
    int(maximum(srows + rrows, "bulk_probe_loss_ppm")), last(srows + rrows, "bulk_probe_pressure", "false"),
    int(maximum(srows, "local_enobufs_retries")), int(maximum(srows, "retransmits")),
]
with open(out, "w", newline="") as fh:
    writer = csv.writer(fh)
    writer.writerow(header)
    writer.writerow(row)
PY
  tail -n 1 "${case_dir}/result.csv" >>"${results_csv}"
}

run_case() {
  local direction="$1"
  local run="$2"
  local case_dir="${run_root}/${direction}/run-${run}"
  local oom_before oom_after capacity
  mkdir -p "${case_dir}"
  health_snapshot "before-${direction}-run-${run}"
  oom_before="$(remote_oom_kill)"
  run_iperf_control "${direction}" "${case_dir}"
  capacity="${last_capacity}"
  run_file_transfer "${direction}" "${case_dir}"
  health_snapshot "after-${direction}-run-${run}"
  oom_after="$(remote_oom_kill)"
  if [[ "$(remote_shell 'getconf _NPROCESSORS_ONLN')" != "2" ]]; then
    fail "remote online CPU count changed during the acceptance run"
    return 1
  fi
  analyze_transfer "${direction}" "${run}" "${case_dir}" "${capacity}" "${oom_before}" "${oom_after}"
  if lsof -nP -iTCP:"${tcp_port}" -sTCP:LISTEN 2>/dev/null | grep -q .; then
    fail "local TCP listener leaked after ${direction} run ${run}"
    return 1
  fi
}

orders=(
  "local-to-remote remote-to-local"
  "remote-to-local local-to-remote"
  "local-to-remote remote-to-local"
)
for run in $(seq 1 "${runs}"); do
  read -r -a directions <<<"${orders[run-1]}"
  for direction in "${directions[@]}"; do
    echo "udp-file-acceptance direction=${direction} run=${run}"
    last_error="acceptance sample failed for ${direction} run ${run}"
    run_case "${direction}" "${run}"
    last_error=""
    sleep 5
  done
done

python3 - "${results_csv}" "${decision_json}" "${revision}" "${source_sha256}" "${baseline_oom_kill}" <<'PY'
import csv
import json
import math
import os
import statistics
import sys

results_path, decision_path, revision, source_sha256, baseline_oom = sys.argv[1:]
with open(results_path, newline="") as fh:
    rows = list(csv.DictReader(fh))
reasons = []
directions = {}
for direction in ("local-to-remote", "remote-to-local"):
    selected = [row for row in rows if row["direction"] == direction]
    rates = [float(row["receiver_goodput_mbps"]) for row in selected]
    if len(selected) != 3:
        reasons.append(f"{direction} has {len(selected)} accepted runs, want 3")
    mean = statistics.fmean(rates) if rates else 0.0
    deviation = statistics.pstdev(rates) if len(rates) > 1 else 0.0
    cv = deviation / mean if mean else math.inf
    if any(rate <= 2000.0 for rate in rates):
        reasons.append(f"{direction} contains a run at or below 2000 Mbps")
    if cv > 0.10:
        reasons.append(f"{direction} coefficient of variation {cv:.6f} exceeds 0.10")
    directions[direction] = {
        "receiver_goodput_mbps": rates,
        "mean_mbps": mean,
        "population_stddev_mbps": deviation,
        "coefficient_of_variation": cv,
        "hetz_cpu_seconds_per_gib": [float(row["hetz_cpu_seconds_per_gib"]) for row in selected],
        "repair_ratio": [float(row["repair_ratio"]) for row in selected],
        "scan_checks_per_packet": [float(row["scan_checks_per_packet"]) for row in selected],
    }
if len(rows) != 6:
    reasons.append(f"accepted result count is {len(rows)}, want 6")
value = {
    "schema_version": 1,
    "passed": not reasons,
    "revision": revision,
    "size_bytes": 3 * 1024 * 1024 * 1024,
    "source_sha256": source_sha256,
    "remote_online_cpus": 2,
    "baseline_oom_kill": int(baseline_oom),
    "directions": directions,
    "runs": rows,
    "reasons": reasons,
}
temporary = decision_path + ".tmp"
with open(temporary, "w") as fh:
    json.dump(value, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.replace(temporary, decision_path)
raise SystemExit(0 if not reasons else 1)
PY
decision_written=1

cat "${decision_json}"
echo "UDP file acceptance artifacts: ${run_root}"
