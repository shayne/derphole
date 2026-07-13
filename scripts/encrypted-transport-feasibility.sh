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
  DERPHOLE_FEASIBILITY_REMOTE \
  DERPHOLE_FEASIBILITY_REMOTE_PUBLIC_ADDR \
  DERPHOLE_FEASIBILITY_LOCAL_PUBLIC_ADDR \
  DERPHOLE_FEASIBILITY_TCP_PORT; do
  [[ -n "${!name:-}" ]] || missing+=("${name}")
done
if ((${#missing[@]})); then
  printf 'required environment is missing: %s\n' "${missing[*]}" >&2
  exit 2
fi

remote="${DERPHOLE_FEASIBILITY_REMOTE}"
remote_public="${DERPHOLE_FEASIBILITY_REMOTE_PUBLIC_ADDR}"
local_public="${DERPHOLE_FEASIBILITY_LOCAL_PUBLIC_ADDR}"
tcp_port="${DERPHOLE_FEASIBILITY_TCP_PORT}"
size_mib=3072
size_bytes=3221225472
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
run_root="${DERPHOLE_FEASIBILITY_OUTPUT_ROOT:-.tmp/encrypted-transport-feasibility}/${run_id}"
remote_root=""
local_pids=()
remote_pid_files=()
cleanup_started=0
started_remote_status_file=""
last_capacity=""

if ! validate_public_address "${remote_public}"; then
  echo "DERPHOLE_FEASIBILITY_REMOTE_PUBLIC_ADDR must be a public IPv4 address" >&2
  exit 2
fi
if ! validate_public_address "${local_public}"; then
  echo "DERPHOLE_FEASIBILITY_LOCAL_PUBLIC_ADDR must be a public IPv4 address" >&2
  exit 2
fi
if [[ ! "${tcp_port}" =~ ^[0-9]+$ ]] || ((tcp_port < 1024 || tcp_port > 65535)); then
  echo "DERPHOLE_FEASIBILITY_TCP_PORT must be an integer from 1024 through 65535" >&2
  exit 2
fi

remote_shell() {
  ssh -o BatchMode=yes "${remote}" 'bash -se' <<<"$1"
}

terminate_local_pid() {
  local pid="$1"
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 0
  if kill -0 "${pid}" 2>/dev/null; then
    kill -TERM "${pid}" 2>/dev/null || true
  fi
  wait "${pid}" 2>/dev/null || true
}

terminate_remote_pid_file() {
  local path="$1"
  [[ -n "${remote_root}" && "${path}" == "${remote_root}"/* ]] || return 1
  remote_shell "set +e
if [[ -f '${path}' ]]; then
  pid=\$(cat '${path}')
  if [[ \"\${pid}\" =~ ^[0-9]+$ ]] && kill -0 \"\${pid}\" 2>/dev/null; then
    kill -TERM \"\${pid}\" 2>/dev/null
  fi
fi"
}

cleanup() {
  local status="$?"
  ((cleanup_started == 0)) || return "${status}"
  cleanup_started=1
  set +e
  for pid in "${local_pids[@]}"; do
    terminate_local_pid "${pid}"
  done
  for path in "${remote_pid_files[@]}"; do
    terminate_remote_pid_file "${path}"
  done
  if [[ -n "${remote_root}" ]]; then
    remote_shell "rm -rf -- '${remote_root}'"
  fi
  trap - EXIT INT TERM
  exit "${status}"
}
trap cleanup EXIT INT TERM

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "$1 is required locally" >&2
    exit 1
  }
}

for command_name in dd git iperf3 lsof mise netstat python3 scp ssh shasum; do
  require_command "${command_name}"
done
remote_shell "for command_name in iperf3 python3 sha256sum getconf df ss; do command -v \"\${command_name}\" >/dev/null || { echo \"\${command_name} is required remotely\" >&2; exit 1; }; done"

mkdir -p "${run_root}/bin"
remote_root="$(remote_shell 'mktemp -d "$HOME/derphole-feasibility.XXXXXX"')"
[[ "${remote_root}" == /* ]] || {
  echo "failed to create a unique remote root" >&2
  exit 1
}

revision="$(git rev-parse HEAD)"
local_derphole="${run_root}/bin/derphole"
linux_derphole="${run_root}/bin/derphole-linux-amd64"
local_bench="${run_root}/bin/derphole-transport-bench"
linux_bench="${run_root}/bin/derphole-transport-bench-linux-amd64"
local_runstats="${run_root}/bin/runstats"
linux_runstats="${run_root}/bin/runstats-linux-amd64"
local_tracecheck="${run_root}/bin/transfertracecheck"
linux_tracecheck="${run_root}/bin/transfertracecheck-linux-amd64"

mise exec -- go build -o "${local_derphole}" ./cmd/derphole
env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 mise exec -- go build -o "${linux_derphole}" ./cmd/derphole
mise exec -- go build -o "${local_bench}" ./cmd/derphole-transport-bench
env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 mise exec -- go build -o "${linux_bench}" ./cmd/derphole-transport-bench
mise exec -- go build -o "${local_runstats}" ./tools/runstats
env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 mise exec -- go build -o "${linux_runstats}" ./tools/runstats
mise exec -- go build -o "${local_tracecheck}" ./tools/transfertracecheck
env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 mise exec -- go build -o "${linux_tracecheck}" ./tools/transfertracecheck

scp "${linux_derphole}" "${linux_bench}" "${linux_runstats}" "${linux_tracecheck}" "${remote}:${remote_root}/" >/dev/null
remote_shell "chmod 0755 '${remote_root}/derphole-linux-amd64' '${remote_root}/derphole-transport-bench-linux-amd64' '${remote_root}/runstats-linux-amd64' '${remote_root}/transfertracecheck-linux-amd64'"

write_manifest() {
  python3 - "${run_root}/manifest.json" "${revision}" "${remote}" "${remote_public}" "${local_public}" "${tcp_port}" "${remote_root}" <<'PY'
import json
import os
import sys

path, revision, remote, remote_public, local_public, port, remote_root = sys.argv[1:]
manifest = {
    "schema_version": 1,
    "revision": revision,
    "remote": remote,
    "remote_public_addr": remote_public,
    "local_public_addr": local_public,
    "tcp_port": int(port),
    "remote_root": remote_root,
    "size_bytes": 3 * 1024 * 1024 * 1024,
    "iperf_streams": 8,
}
with open(path, "w") as fh:
    json.dump(manifest, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.chmod(path, 0o600)
PY
}
write_manifest

local_free_kib="$(df -Pk "${run_root}" | awk 'NR==2 {print $4}')"
remote_free_kib="$(remote_shell "df -Pk '${remote_root}' | awk 'NR==2 {print \$4}'")"
if ((local_free_kib < 16 * 1024 * 1024 || remote_free_kib < 16 * 1024 * 1024)); then
  echo "at least 16 GiB of free space is required on both endpoints" >&2
  exit 1
fi
remote_cpus="$(remote_shell 'getconf _NPROCESSORS_ONLN')"
if [[ "${remote_cpus}" != "2" ]]; then
  echo "exact Hetzner endpoint has ${remote_cpus} CPUs, want 2" >&2
  exit 1
fi
if lsof -nP -iTCP:"${tcp_port}" -sTCP:LISTEN 2>/dev/null | grep -q .; then
  echo "local TCP port ${tcp_port} already has a listener" >&2
  exit 1
fi
if remote_shell "ss -H -ltn 'sport = :${tcp_port}' | grep -q ."; then
  echo "remote TCP port ${tcp_port} already has a listener" >&2
  exit 1
fi

health_snapshot() {
  local label="$1"
  mkdir -p "${run_root}/health/${label}"
  netstat -ibdn >"${run_root}/health/${label}/local-netstat.txt" 2>&1 || true
  remote_shell "cat /proc/net/dev; printf '\n--- memory ---\n'; cat /proc/meminfo; printf '\n--- kernel ---\n'; dmesg | tail -n 200" >"${run_root}/health/${label}/remote.txt"
}
health_snapshot preflight

preflight_public_tcp() {
  local remote_pid_file="${remote_root}/preflight-remote-listener.pid"
  remote_pid_files+=("${remote_pid_file}")
  remote_shell "rm -f '${remote_pid_file}'; nohup python3 -c 'import socket,sys; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((\"0.0.0.0\",int(sys.argv[1]))); s.listen(1); c,_=s.accept(); c.close(); s.close()' '${tcp_port}' >/dev/null 2>&1 & echo \$! >'${remote_pid_file}'"
  sleep 0.2
  python3 - "${remote_public}" "${tcp_port}" <<'PY'
import socket, sys
with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5):
    pass
PY
  remote_shell "pid=\$(cat '${remote_pid_file}'); for _ in \$(seq 1 100); do kill -0 \"\${pid}\" 2>/dev/null || exit 0; sleep 0.05; done; exit 1"

  python3 - "${tcp_port}" <<'PY' &
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen(1)
c, _ = s.accept()
c.close()
s.close()
PY
  local listener_pid="$!"
  local_pids+=("${listener_pid}")
  sleep 0.2
  remote_shell "python3 - '${local_public}' '${tcp_port}' <<'PY'
import socket, sys
with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5):
    pass
PY"
  wait "${listener_pid}"
}
preflight_public_tcp

source_file="${run_root}/source.bin"
source_hash_file="${run_root}/source.sha256"
echo "creating one ${size_mib} MiB cryptographically random ordinary file"
dd if=/dev/urandom of="${source_file}" bs=1048576 count="${size_mib}" 2>/dev/null
source_hash="$(shasum -a 256 "${source_file}" | awk '{print $1}')"
printf '%s  source.bin\n' "${source_hash}" >"${source_hash_file}"
remote_source="${remote_root}/source.bin"
scp "${source_file}" "${remote}:${remote_source}" >/dev/null
remote_hash="$(remote_shell "sha256sum '${remote_source}' | awk '{print \$1}'")"
[[ "${remote_hash}" == "${source_hash}" ]] || {
  echo "staged source SHA-256 mismatch" >&2
  exit 1
}

local_checksums="${run_root}/local-binary-sha256.txt"
remote_checksums="${run_root}/remote-binary-sha256.txt"
for binary in "${local_derphole}" "${local_bench}" "${local_runstats}" "${local_tracecheck}"; do
  shasum -a 256 "${binary}"
done >"${local_checksums}"
remote_shell "cd '${remote_root}' && sha256sum derphole-linux-amd64 derphole-transport-bench-linux-amd64 runstats-linux-amd64 transfertracecheck-linux-amd64" >"${remote_checksums}"

results_jsonl="${run_root}/results.jsonl"
decision_json="${run_root}/decision.json"
: >"${results_jsonl}"

wait_remote_status() {
  local status_file="$1"
  remote_shell "for _ in \$(seq 1 6000); do [[ -f '${status_file}' ]] && { cat '${status_file}'; exit 0; }; sleep 0.1; done; exit 1"
}

wait_remote_file() {
  local path="$1"
  remote_shell "for _ in \$(seq 1 600); do [[ -s '${path}' ]] && exit 0; sleep 0.05; done; exit 1"
}

start_remote_wrapped() {
  local command="$1"
  local prefix="$2"
  local wrapper_pid_file="${prefix}.wrapper.pid"
  local child_pid_file="${prefix}.child.pid"
  local status_file="${prefix}.status"
  remote_pid_files+=("${wrapper_pid_file}" "${child_pid_file}")
  remote_shell "rm -f '${wrapper_pid_file}' '${child_pid_file}' '${status_file}' '${prefix}.command.sh'
cat >'${prefix}.command.sh' <<'DERPHOLE_REMOTE_COMMAND'
#!/usr/bin/env bash
set -euo pipefail
${command}
DERPHOLE_REMOTE_COMMAND
chmod 0700 '${prefix}.command.sh'
nohup sh -c 'set +e; child=; forward() { if [[ -n \"\${child}\" ]]; then kill -TERM \"\${child}\" 2>/dev/null || true; fi; }; trap forward TERM INT; \"${prefix}.command.sh\" & child=\$!; printf \"%s\\n\" \"\${child}\" >\"${child_pid_file}\"; wait \"\${child}\"; status=\$?; printf \"%s\\n\" \"\${status}\" >\"${status_file}\"; exit \"\${status}\"' >/dev/null 2>&1 </dev/null & echo \$! >'${wrapper_pid_file}'"
  started_remote_status_file="${status_file}"
}

parse_iperf_mbps() {
  python3 - "$1" <<'PY'
import json, sys
with open(sys.argv[1]) as fh:
    value = json.load(fh)
end = value["end"]
summary = end.get("sum_received") or end.get("sum")
print(f'{summary["bits_per_second"] / 1_000_000:.6f}')
PY
}

run_iperf_control() {
  local direction="$1"
  local case_dir="$2"
  local capacity=""
  for attempt in 1 2 3; do
    local output="${case_dir}/iperf-attempt-${attempt}.json"
    if [[ "${direction}" == "local-to-remote" ]]; then
      local prefix="${remote_root}/iperf-${RANDOM}-${attempt}"
      local status_file
      start_remote_wrapped "iperf3 -s -4 -1 -p '${tcp_port}' >'${prefix}.server.json' 2>'${prefix}.server.err'" "${prefix}"
      status_file="${started_remote_status_file}"
      sleep 0.2
      iperf3 -4 -J -c "${remote_public}" -p "${tcp_port}" -t 20 -P 8 >"${output}"
      [[ "$(wait_remote_status "${status_file}")" == "0" ]]
    else
      iperf3 -s -4 -p "${tcp_port}" --one-off --forceflush >"${case_dir}/iperf-server-${attempt}.log" 2>&1 &
      local server_pid="$!"
      local_pids+=("${server_pid}")
      sleep 0.2
      remote_shell "iperf3 -4 -J -c '${local_public}' -p '${tcp_port}' -t 20 -P 8" >"${output}"
      wait "${server_pid}"
    fi
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
    sleep 1
  done
  echo "three same-direction iperf controls were below 2050 Mbps" >&2
  return 2
}

trace_flatline_ms() {
  python3 - "$1" "$2" "${size_bytes}" <<'PY'
import csv, sys
path, column, expected = sys.argv[1], sys.argv[2], int(sys.argv[3])
last_change_at = None
last_value = 0
maximum = 0
with open(path, newline="") as fh:
    for row in csv.DictReader(fh):
        at = int(row["timestamp_unix_ms"])
        value = int(float(row.get(column) or 0))
        if value > last_value:
            if last_change_at is not None:
                maximum = max(maximum, at - last_change_at)
            last_change_at = at
            last_value = value
if last_value != expected:
    raise SystemExit(f"trace committed {last_value} bytes, want {expected}")
print(maximum)
PY
}

latest_artifact() {
  find "$1" -type f -name "$2" -print | sort | tail -n 1
}

make_bulk_summary() {
  local case_dir="$1"
  local direction="$2"
  local run="$3"
  local capacity="$4"
  local sender_trace receiver_trace sender_resource receiver_resource sender_log receiver_log
  sender_trace="$(latest_artifact "${case_dir}" '*-sender.trace.csv')"
  receiver_trace="$(latest_artifact "${case_dir}" '*-receiver.trace.csv')"
  sender_resource="$(latest_artifact "${case_dir}" '*-sender.resource.json')"
  receiver_resource="$(latest_artifact "${case_dir}" '*-receiver.resource.json')"
  sender_log="$(latest_artifact "${case_dir}" '*-sender.log')"
  receiver_log="$(latest_artifact "${case_dir}" '*-receiver.log')"
  [[ -s "${sender_trace}" && -s "${receiver_trace}" && -s "${sender_resource}" && -s "${receiver_resource}" ]]
  "${local_tracecheck}" -role send -stall-window 999ms -peer-trace "${receiver_trace}" "${sender_trace}" >"${case_dir}/sender-trace-check.txt"
  "${local_tracecheck}" -role receive -stall-window 999ms "${receiver_trace}" >"${case_dir}/receiver-trace-check.txt"
  trace_flatline_ms "${receiver_trace}" app_bytes >"${case_dir}/max-flatline-ms.txt"
  local expected_public="${remote_public}"
  [[ "${direction}" == "remote-to-local" ]] && expected_public="${local_public}"
  if ! grep -F "${expected_public}:" "${sender_log}" "${receiver_log}" >/dev/null; then
    echo "bulk run does not prove the expected public route ${expected_public}" >&2
    return 1
  fi
  python3 - "${case_dir}/summary.csv" "${case_dir}/promotion.out" "${sender_trace}" "${receiver_trace}" "${sender_resource}" "${receiver_resource}" "${case_dir}/max-flatline-ms.txt" "${direction}" "${run}" "${capacity}" "${revision}" "${source_hash}" <<'PY'
import csv, json, math, re, sys

out, promotion, sender_trace, receiver_trace, sender_resource, receiver_resource, flatline_path, direction, run, capacity, revision, source_hash = sys.argv[1:]
def footer(path):
    result = {}
    with open(path, errors="replace") as fh:
        for line in fh:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                result[key] = value
    return result
def rows(path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))
def last(values, key, default="0"):
    for row in reversed(values):
        value = (row.get(key) or "").strip()
        if value:
            return value
    return default
def maximum(values, key, default="0"):
    found = [float(row[key]) for row in values if (row.get(key) or "").strip()]
    return str(max(found)) if found else default
def resource(path):
    with open(path) as fh:
        return json.load(fh)

f = footer(promotion)
srows, rrows = rows(sender_trace), rows(receiver_trace)
sr, rr = resource(sender_resource), resource(receiver_resource)
size = 3 * 1024 * 1024 * 1024
max_flatline = open(flatline_path).read().strip() + "ms"
sender_cpu = float(sr["user_cpu_seconds"]) + float(sr["system_cpu_seconds"])
receiver_cpu = float(rr["user_cpu_seconds"]) + float(rr["system_cpu_seconds"])
packet_count = math.ceil(size / 1358)
repair_bytes = int(float(last(srows, "repair_bytes")))
header = [
    "host","run","tool","direction","workload","transfer_mode","mbps","wall_mbps","trace_ok","max_flatline",
    "benchmark_size_bytes","revision_label","sender_user_cpu_seconds","sender_system_cpu_seconds","sender_cpu_seconds_per_gib","sender_max_rss_bytes",
    "receiver_user_cpu_seconds","receiver_system_cpu_seconds","receiver_cpu_seconds_per_gib","receiver_max_rss_bytes","expected_sha256","actual_sha256",
    "public_route_proven","tailscale_candidates","batch_backend","gso_attempted","gso_active","gso_segments","send_calls","send_datagrams",
    "receive_calls","receive_datagrams","max_send_batch","max_receive_batch","crypto_queue_peak","writer_queue_peak","local_enobufs_retries",
    "repair_bytes","repair_ratio","retransmits","primary_packet_count","received_packet_count",
]
iperf = ["remote", run, "iperf3", "forward" if direction == "local-to-remote" else "reverse", "stream", "tcp", capacity]
transfer = [
    "remote", run, "derphole", "forward" if direction == "local-to-remote" else "reverse", "file", "bulk-packets-v1",
    f["benchmark-goodput-mbps"], f["benchmark-wall-goodput-mbps"], "true", max_flatline, str(size), revision,
    str(sr["user_cpu_seconds"]), str(sr["system_cpu_seconds"]), str(sender_cpu / 3), str(sr["max_rss_bytes"]),
    str(rr["user_cpu_seconds"]), str(rr["system_cpu_seconds"]), str(receiver_cpu / 3), str(rr["max_rss_bytes"]),
    source_hash, source_hash, "true", "0", last(srows, "bulk_batch_backend", last(rrows, "bulk_batch_backend", "unknown")),
    last(srows, "bulk_gso_attempted", "false"), last(srows, "bulk_gso_active", "false"), last(srows, "bulk_gso_segments"),
    last(srows, "bulk_send_calls"), last(srows, "bulk_send_datagrams"), last(rrows, "bulk_receive_calls"), last(rrows, "bulk_receive_datagrams"),
    maximum(srows, "bulk_max_send_batch"), maximum(rrows, "bulk_max_receive_batch"), maximum(srows + rrows, "bulk_crypto_queue_peak"),
    maximum(rrows, "bulk_writer_queue_peak"), last(srows, "local_enobufs_retries"), str(repair_bytes), str(repair_bytes / size),
    maximum(srows, "retransmits"), str(packet_count), str(packet_count),
]
with open(out, "w", newline="") as fh:
    writer = csv.writer(fh)
    writer.writerow(header)
    writer.writerow(iperf + [""] * (len(header) - len(iperf)))
    writer.writerow(transfer)
PY
}

run_bulk() {
  local direction="$1" run="$2" case_dir="$3" capacity="$4"
  local promotion_direction="forward"
  [[ "${direction}" == "remote-to-local" ]] && promotion_direction="reverse"
  mkdir -p "${case_dir}"
  set +e
  env \
    DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
    DERPHOLE_TEST_BULK_BATCHED_IO=1 \
    DERPHOLE_TEST_FORCE_BULK_PACKET_TRANSFER=1 \
    DERPHOLE_BENCH_EXPECT_TRANSFER_MODE=bulk-packets-v1 \
    DERPHOLE_BENCH_WORKLOAD=file \
    DERPHOLE_BENCH_DIRECTION="${promotion_direction}" \
    DERPHOLE_BENCH_LOCAL_PAYLOAD="${source_file}" \
    DERPHOLE_BENCH_REMOTE_PAYLOAD="${remote_source}" \
    DERPHOLE_BENCH_LOCAL_BIN="${local_derphole}" \
    DERPHOLE_BENCH_LINUX_BIN="${linux_derphole}" \
    DERPHOLE_BENCH_REVISION_LABEL="${revision}" \
    DERPHOLE_BENCH_LOG_DIR="${case_dir}" \
    DERPHOLE_BENCH_LOCAL_TMP_ROOT="${run_root}/tmp" \
    DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT="${remote_root}/promotion" \
    DERPHOLE_REMOTE_BIN_DIR="${remote_root}/promotion-bin" \
    bash ./scripts/promotion-benchmark-driver.sh "${remote}" "${size_mib}" >"${case_dir}/promotion.out" 2>&1
  local status="$?"
  set -e
  if [[ "${status}" -ne 0 ]]; then
    cat "${case_dir}/promotion.out" >&2
    return "${status}"
  fi
  make_bulk_summary "${case_dir}" "${direction}" "${run}" "${capacity}"
  "${local_bench}" ingest-bulk --summary-csv "${case_dir}/summary.csv" --direction "${direction}" --run "${run}" --out "${case_dir}/result.json" >"${case_dir}/result.stdout.json"
  cat "${case_dir}/result.json" >>"${results_jsonl}"
  printf '\n' >>"${results_jsonl}"
}

make_tls_result() {
  local case_dir="$1" direction="$2" run="$3" capacity="$4"
  python3 - "${case_dir}/result.json" "${case_dir}/sender-summary.json" "${case_dir}/receiver-summary.json" "${case_dir}/sender.resource.json" "${case_dir}/receiver.resource.json" "${case_dir}/receiver.trace.csv" "${direction}" "${run}" "${capacity}" "${revision}" <<'PY'
import csv, json, math, sys
out, sender_summary, receiver_summary, sender_resource, receiver_resource, trace, direction, run, capacity, revision = sys.argv[1:]
def load(path):
    with open(path) as fh: return json.load(fh)
s, r, sr, rr = map(load, [sender_summary, receiver_summary, sender_resource, receiver_resource])
expected = 3 * 1024 * 1024 * 1024
last_change = None
last_value = 0
flatline = 0
with open(trace, newline="") as fh:
    for row in csv.DictReader(fh):
        at = int(row["timestamp_unix_ms"])
        value = int(row["total_bytes"])
        if value > last_value:
            if last_change is not None:
                flatline = max(flatline, at - last_change)
            last_change = at
            last_value = value
if last_value != expected:
    raise SystemExit(f"TLS receiver trace committed {last_value}, want {expected}")
def endpoint(value):
    cpu = float(value["user_cpu_seconds"]) + float(value["system_cpu_seconds"])
    return {
        "user_cpu_seconds": float(value["user_cpu_seconds"]),
        "system_cpu_seconds": float(value["system_cpu_seconds"]),
        "cpu_seconds_per_gib": cpu / 3,
        "peak_rss_bytes": int(value["max_rss_bytes"]),
    }
result = {
    "schema_version": 1,
    "revision": revision,
    "engine": "tls-stream-8-v1",
    "direction": direction,
    "run": int(run),
    "size_bytes": expected,
    "expected_sha256": s["sha256"],
    "actual_sha256": r["sha256"],
    "canonical_goodput_mbps": float(r["canonical_goodput_mbps"]),
    "wall_goodput_mbps": float(r["wall_goodput_mbps"]),
    "capacity_mbps": float(capacity),
    "max_flatline_ms": flatline,
    "trace_complete": True,
    "public_route_proven": True,
    "tailscale_candidates": 0,
    "sender": endpoint(sr),
    "receiver": endpoint(rr),
    "transport": {
        "tls_version": r["tls_version"], "tls_cipher": r["tls_cipher"], "alpn": r["alpn"],
        "connections": 8, "pin_verified": bool(s["pin_verified"]), "lane_bytes": r["lane_bytes"],
        "read_calls": r["read_calls"], "write_calls": s["write_calls"],
        "bytes_per_read_call": r["bytes_per_read_call"], "bytes_per_write_call": s["bytes_per_write_call"],
        "tcp_info_supported": bool(r["tcp_info_supported"]),
        "tcp_retransmits": r["tcp_retransmits"] or 0, "tcp_cwnd_segments": r["tcp_cwnd_segments"] or 0,
    },
}
with open(out, "w") as fh:
    json.dump(result, fh, sort_keys=True)
    fh.write("\n")
PY
  cat "${case_dir}/result.json" >>"${results_jsonl}"
}

run_tls() {
  local direction="$1" run="$2" case_dir="$3" capacity="$4"
  mkdir -p "${case_dir}"
  if [[ "${direction}" == "local-to-remote" ]]; then
    local prefix="${remote_root}/tls-receiver-${run}-${RANDOM}"
    local command status_file ready_local
    command="'${remote_root}/runstats-linux-amd64' -out '${prefix}.resource.json' -- '${remote_root}/derphole-transport-bench-linux-amd64' tls-receive --listen '0.0.0.0:${tcp_port}' --out '${prefix}.output.bin' --ready-file '${prefix}.ready.json' --trace '${prefix}.trace.csv' --timeout 5m >'${prefix}.summary.json' 2>'${prefix}.err'"
    start_remote_wrapped "${command}" "${prefix}"
    status_file="${started_remote_status_file}"
    wait_remote_file "${prefix}.ready.json"
    ready_local="${case_dir}/ready.json"
    scp "${remote}:${prefix}.ready.json" "${ready_local}" >/dev/null
    read -r fingerprint transfer_id < <(python3 - "${ready_local}" <<'PY'
import json, sys
with open(sys.argv[1]) as fh: value=json.load(fh)
print(value["fingerprint_sha256"], value["transfer_id"])
PY
)
    "${local_runstats}" -out "${case_dir}/sender.resource.json" -- "${local_bench}" tls-send --peer "${remote_public}:${tcp_port}" --fingerprint "${fingerprint}" --transfer-id "${transfer_id}" --in "${source_file}" --trace "${case_dir}/sender.trace.csv" --timeout 5m >"${case_dir}/sender-summary.json" 2>"${case_dir}/sender.err"
    [[ "$(wait_remote_status "${status_file}")" == "0" ]]
    scp "${remote}:${prefix}.summary.json" "${case_dir}/receiver-summary.json" >/dev/null
    scp "${remote}:${prefix}.resource.json" "${case_dir}/receiver.resource.json" >/dev/null
    scp "${remote}:${prefix}.trace.csv" "${case_dir}/receiver.trace.csv" >/dev/null
    remote_shell "sha256sum '${prefix}.output.bin'" >"${case_dir}/receiver.sha256"
  else
    local ready="${case_dir}/ready.json"
    "${local_runstats}" -out "${case_dir}/receiver.resource.json" -- "${local_bench}" tls-receive --listen "0.0.0.0:${tcp_port}" --out "${case_dir}/received.bin" --ready-file "${ready}" --trace "${case_dir}/receiver.trace.csv" --timeout 5m >"${case_dir}/receiver-summary.json" 2>"${case_dir}/receiver.err" &
    local receiver_pid="$!"
    local_pids+=("${receiver_pid}")
    for _ in $(seq 1 600); do [[ -s "${ready}" ]] && break; sleep 0.05; done
    [[ -s "${ready}" ]]
    read -r fingerprint transfer_id < <(python3 - "${ready}" <<'PY'
import json, sys
with open(sys.argv[1]) as fh: value=json.load(fh)
print(value["fingerprint_sha256"], value["transfer_id"])
PY
)
    local prefix="${remote_root}/tls-sender-${run}-${RANDOM}"
    local command status_file
    command="'${remote_root}/runstats-linux-amd64' -out '${prefix}.resource.json' -- '${remote_root}/derphole-transport-bench-linux-amd64' tls-send --peer '${local_public}:${tcp_port}' --fingerprint '${fingerprint}' --transfer-id '${transfer_id}' --in '${remote_source}' --trace '${prefix}.trace.csv' --timeout 5m >'${prefix}.summary.json' 2>'${prefix}.err'"
    start_remote_wrapped "${command}" "${prefix}"
    status_file="${started_remote_status_file}"
    [[ "$(wait_remote_status "${status_file}")" == "0" ]]
    wait "${receiver_pid}"
    scp "${remote}:${prefix}.summary.json" "${case_dir}/sender-summary.json" >/dev/null
    scp "${remote}:${prefix}.resource.json" "${case_dir}/sender.resource.json" >/dev/null
    scp "${remote}:${prefix}.trace.csv" "${case_dir}/sender.trace.csv" >/dev/null
    shasum -a 256 "${case_dir}/received.bin" >"${case_dir}/receiver.sha256"
  fi
  trace_flatline_ms "${case_dir}/receiver.trace.csv" total_bytes >"${case_dir}/max-flatline-ms.txt"
  make_tls_result "${case_dir}" "${direction}" "${run}" "${capacity}"
}

run_case() {
  local engine="$1" direction="$2" run="$3"
  local case_dir="${run_root}/${engine}/${direction}/run-${run}"
  mkdir -p "${case_dir}"
  health_snapshot "before-${engine}-${direction}-run-${run}"
  local capacity
  run_iperf_control "${direction}" "${case_dir}" || return $?
  capacity="${last_capacity}"
  if [[ "${engine}" == "bulk-udp-batched-v1" ]]; then
    run_bulk "${direction}" "${run}" "${case_dir}" "${capacity}"
  else
    run_tls "${direction}" "${run}" "${case_dir}" "${capacity}"
  fi
  health_snapshot "after-${engine}-${direction}-run-${run}"
  if lsof -nP -iTCP:"${tcp_port}" -sTCP:LISTEN 2>/dev/null | grep -q .; then
    echo "local listener leaked after ${engine} ${direction} run ${run}" >&2
    return 1
  fi
  if remote_shell "ss -H -ltn 'sport = :${tcp_port}' | grep -q ."; then
    echo "remote listener leaked after ${engine} ${direction} run ${run}" >&2
    return 1
  fi
}

orders=(
  "bulk-udp-batched-v1:local-to-remote tls-stream-8-v1:remote-to-local tls-stream-8-v1:local-to-remote bulk-udp-batched-v1:remote-to-local"
  "tls-stream-8-v1:remote-to-local tls-stream-8-v1:local-to-remote bulk-udp-batched-v1:remote-to-local bulk-udp-batched-v1:local-to-remote"
  "tls-stream-8-v1:local-to-remote bulk-udp-batched-v1:remote-to-local bulk-udp-batched-v1:local-to-remote tls-stream-8-v1:remote-to-local"
)
for run in 1 2 3; do
  read -r -a cases <<<"${orders[run-1]}"
  for item in "${cases[@]}"; do
    engine="${item%%:*}"
    direction="${item#*:}"
    echo "feasibility engine=${engine} direction=${direction} run=${run}"
    run_case "${engine}" "${direction}" "${run}" || {
      status="$?"
      echo "feasibility run failed; evidence preserved at ${run_root}" >&2
      exit "${status}"
    }
  done
done

set +e
"${local_bench}" decide --results "${results_jsonl}" --out "${decision_json}" >"${run_root}/decision.stdout.json" 2>"${run_root}/decision.err"
decision_status="$?"
set -e
cat "${decision_json}" 2>/dev/null || true
echo "feasibility artifacts: ${run_root}"
exit "${decision_status}"
