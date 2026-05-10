#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <sender-host> <receiver-host> [size-mib]" >&2
  echo "set DERPHOLE_STALL_REMOTE_CMD='npx -y derphole@dev' to test the npm package instead of the local Linux binary" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

sender_target="${1:?missing sender host}"
receiver_target="${2:?missing receiver host}"
size_mib="${3:-1024}"
sample_interval_sec="${DERPHOLE_STALL_SAMPLE_INTERVAL_SEC:-1}"
stall_timeout_sec="${DERPHOLE_STALL_TIMEOUT_SEC:-20}"
start_timeout_sec="${DERPHOLE_STALL_START_TIMEOUT_SEC:-60}"
total_timeout_sec="${DERPHOLE_STALL_TOTAL_TIMEOUT_SEC:-900}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
log_dir="${DERPHOLE_STALL_LOG_DIR:-/tmp/derphole-stall-${stamp}}"
samples_file="${log_dir}/samples.tsv"
sender_dir=""
receiver_dir=""
sender_payload=""
receiver_out=""
sender_cmd=""
receiver_cmd=""
expected_size=0
source_sha=""
sink_sha=""
failed=0

mkdir -p "${log_dir}/sender" "${log_dir}/receiver"

quote() {
  printf "%q" "$1"
}

now_ms() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import time; print(int(time.time() * 1000))'
    return 0
  fi
  perl -MTime::HiRes=time -e 'print int(time() * 1000), "\n"'
}

normalize_target() {
  local target="$1"
  if [[ "${target}" == *"@"* ]]; then
    printf '%s\n' "${target}"
    return 0
  fi
  printf '%s@%s\n' "${DERPHOLE_REMOTE_USER:-root}" "${target}"
}

sender_target="$(normalize_target "${sender_target}")"
receiver_target="$(normalize_target "${receiver_target}")"

remote_sh() {
  local target="$1"
  local script="$2"
  ssh "${target}" 'bash -se' <<<"${script}"
}

remote_mktemp() {
  remote_sh "$1" 'mktemp -d "${TMPDIR:-/tmp}/derphole-stall.XXXXXX"'
}

remote_env_prefix() {
  local prefix=()
  local disable_tailscale="${DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES:-${DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES:-1}}"
  if [[ "${disable_tailscale}" == "1" ]]; then
    prefix+=(DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1)
    prefix+=(DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1)
  fi
  if [[ "${DERPHOLE_STALL_TRACE:-1}" == "1" ]]; then
    prefix+=(DERPHOLE_TRACE_HANDOFF=1)
    prefix+=(DERPHOLE_PROBE_TRACE=1)
  fi
  if [[ -n "${DERPHOLE_NATIVE_QUIC_CONNS:-}" ]]; then
    prefix+=(DERPHOLE_NATIVE_QUIC_CONNS="$(quote "${DERPHOLE_NATIVE_QUIC_CONNS}")")
  fi
  if [[ -n "${DERPHOLE_NATIVE_TCP_CONNS:-}" ]]; then
    prefix+=(DERPHOLE_NATIVE_TCP_CONNS="$(quote "${DERPHOLE_NATIVE_TCP_CONNS}")")
  fi
  printf '%s ' "${prefix[@]}"
}

collect_counters() {
  local target="$1"
  local dir="$2"
  local label="$3"
  if [[ -z "${dir}" ]]; then
    return 0
  fi
  remote_sh "${target}" "
out=$(quote "${dir}/${label}.counters")
{
  echo 'label=${label}'
  date -Ins 2>/dev/null || date
  uname -a || true
  echo '--- ss -s'
  ss -s || true
  echo '--- ss -u -a -i -n'
  ss -u -a -i -n || true
  echo '--- ip -s -s link'
  ip -s -s link || true
  echo '--- nstat -az'
  nstat -az || true
  echo '--- /proc/net/snmp'
  cat /proc/net/snmp || true
  echo '--- /proc/net/netstat'
  cat /proc/net/netstat || true
  echo '--- /proc/net/udp'
  cat /proc/net/udp || true
  echo '--- /proc/net/udp6'
  cat /proc/net/udp6 || true
  iface=\$(ip route show default 2>/dev/null | awk '{print \$5; exit}')
  if [[ -n \"\${iface}\" ]] && command -v ethtool >/dev/null 2>&1; then
    echo \"--- ethtool -S \${iface}\"
    ethtool -S \"\${iface}\" || true
  fi
} >\"\${out}\" 2>&1
"
}

fetch_remote_dir() {
  local target="$1"
  local remote_dir="$2"
  local local_dir="$3"
  if [[ -z "${remote_dir}" ]]; then
    return 0
  fi
  mkdir -p "${local_dir}"
  ssh "${target}" "tar -C $(quote "${remote_dir}") --exclude=payload.bin --exclude=received.bin -cf - ." | tar -C "${local_dir}" -xf -
}

cleanup_remote() {
  if [[ "${DERPHOLE_STALL_KEEP_REMOTE:-0}" == "1" ]]; then
    return 0
  fi
  if [[ -n "${sender_dir}" ]]; then
    remote_sh "${sender_target}" "rm -rf $(quote "${sender_dir}")" >/dev/null 2>&1 || true
  fi
  if [[ -n "${receiver_dir}" ]]; then
    remote_sh "${receiver_target}" "rm -rf $(quote "${receiver_dir}")" >/dev/null 2>&1 || true
  fi
}

finish() {
  local status=$?
  set +e
  collect_counters "${sender_target}" "${sender_dir}" "after"
  collect_counters "${receiver_target}" "${receiver_dir}" "after"
  fetch_remote_dir "${sender_target}" "${sender_dir}" "${log_dir}/sender"
  fetch_remote_dir "${receiver_target}" "${receiver_dir}" "${log_dir}/receiver"
  cleanup_remote
  echo "stall-harness-log-dir=${log_dir}"
  exit "${status}"
}
trap finish EXIT

signal_quit() {
  local target="$1"
  local dir="$2"
  local pid_file="$3"
  remote_sh "${target}" "if [[ -f $(quote "${dir}/${pid_file}") ]]; then kill -QUIT \$(cat $(quote "${dir}/${pid_file}")) 2>/dev/null || true; fi" || true
}

abort_with_dumps() {
  local reason="$1"
  failed=1
  echo "stall-harness-error=${reason}" >&2
  signal_quit "${sender_target}" "${sender_dir}" "send.pid"
  signal_quit "${receiver_target}" "${receiver_dir}" "receive.pid"
  sleep 2
  exit 124
}

remote_state() {
  local target="$1"
  local out_file="$2"
  local pid_file="$3"
  remote_sh "${target}" "
size=0
if [[ -f $(quote "${out_file}") ]]; then
  size=\$(stat -c %s $(quote "${out_file}") 2>/dev/null || echo 0)
fi
alive=0
if [[ -f $(quote "${pid_file}") ]] && kill -0 \$(cat $(quote "${pid_file}")) 2>/dev/null; then
  alive=1
fi
printf '%s %s\n' \"\${size}\" \"\${alive}\"
"
}

sender_dir="$(remote_mktemp "${sender_target}")"
receiver_dir="$(remote_mktemp "${receiver_target}")"
receiver_out="${receiver_dir}/received.bin"

if [[ -z "${DERPHOLE_STALL_REMOTE_CMD:-}" ]]; then
  mise run build-linux-amd64
  scp "dist/derphole-linux-amd64" "${sender_target}:${sender_dir}/derphole" >/dev/null
  scp "dist/derphole-linux-amd64" "${receiver_target}:${receiver_dir}/derphole" >/dev/null
  remote_sh "${sender_target}" "chmod +x $(quote "${sender_dir}/derphole")"
  remote_sh "${receiver_target}" "chmod +x $(quote "${receiver_dir}/derphole")"
  sender_cmd="$(quote "${sender_dir}/derphole")"
  receiver_cmd="$(quote "${receiver_dir}/derphole")"
else
  sender_cmd="${DERPHOLE_STALL_SENDER_CMD:-${DERPHOLE_STALL_REMOTE_CMD}}"
  receiver_cmd="${DERPHOLE_STALL_RECEIVER_CMD:-${DERPHOLE_STALL_REMOTE_CMD}}"
fi

if [[ -n "${DERPHOLE_STALL_SOURCE_PATH:-}" ]]; then
  sender_payload="${DERPHOLE_STALL_SOURCE_PATH}"
else
  sender_payload="${sender_dir}/payload.bin"
  echo "generating ${size_mib} MiB payload on ${sender_target}" >&2
  remote_sh "${sender_target}" "dd if=/dev/urandom of=$(quote "${sender_payload}") bs=1048576 count=$(quote "${size_mib}") status=none"
fi

expected_size="$(remote_sh "${sender_target}" "stat -c %s $(quote "${sender_payload}")")"
source_sha="$(remote_sh "${sender_target}" "sha256sum $(quote "${sender_payload}") | awk '{print \$1}'")"

collect_counters "${sender_target}" "${sender_dir}" "before"
collect_counters "${receiver_target}" "${receiver_dir}" "before"

env_prefix="$(remote_env_prefix)"
remote_sh "${sender_target}" "
	rm -f $(quote "${sender_dir}/send.out") $(quote "${sender_dir}/send.err") $(quote "${sender_dir}/send.pid") $(quote "${sender_dir}/send.status")
(
  set +e
  ${env_prefix}${sender_cmd} --verbose send --hide-progress $(quote "${sender_payload}") >$(quote "${sender_dir}/send.out") 2>$(quote "${sender_dir}/send.err") </dev/null &
  child=\$!
  echo \"\${child}\" >$(quote "${sender_dir}/send.pid")
  wait \"\${child}\"
  echo \$? >$(quote "${sender_dir}/send.status")
) </dev/null >/dev/null 2>/dev/null &
"

token=""
for _ in $(seq 1 300); do
  token="$(remote_sh "${sender_target}" "cat $(quote "${sender_dir}/send.out") $(quote "${sender_dir}/send.err") 2>/dev/null | grep -Eo '[A-Za-z0-9_-]{40,}' | tail -n 1 || true")"
  if [[ -n "${token}" ]]; then
    break
  fi
  sleep 0.1
done
if [[ -z "${token}" ]]; then
  abort_with_dumps "missing-token"
fi

remote_sh "${receiver_target}" "
	rm -f $(quote "${receiver_out}") $(quote "${receiver_dir}/receive.out") $(quote "${receiver_dir}/receive.err") $(quote "${receiver_dir}/receive.pid") $(quote "${receiver_dir}/receive.status")
(
  set +e
  ${env_prefix}${receiver_cmd} --verbose receive --hide-progress -o $(quote "${receiver_out}") $(quote "${token}") >$(quote "${receiver_dir}/receive.out") 2>$(quote "${receiver_dir}/receive.err") </dev/null &
  child=\$!
  echo \"\${child}\" >$(quote "${receiver_dir}/receive.pid")
  wait \"\${child}\"
  echo \$? >$(quote "${receiver_dir}/receive.status")
) </dev/null >/dev/null 2>/dev/null &
"

{
  echo -e "timestamp_ms\telapsed_ms\treceived_bytes\tdelta_bytes\tmbps\tsender_alive\treceiver_alive"
} >"${samples_file}"

start_ms="$(now_ms)"
last_ms="${start_ms}"
last_progress_ms="${start_ms}"
last_bytes=0

while true; do
  now="$(now_ms)"
  elapsed_ms="$((now - start_ms))"
  if (( elapsed_ms > total_timeout_sec * 1000 )); then
    abort_with_dumps "total-timeout-sec=${total_timeout_sec}"
  fi

  read -r received_bytes receiver_alive < <(remote_state "${receiver_target}" "${receiver_out}" "${receiver_dir}/receive.pid")
  read -r _ sender_alive < <(remote_state "${sender_target}" "/dev/null" "${sender_dir}/send.pid")

  delta_bytes=$((received_bytes - last_bytes))
  delta_ms=$((now - last_ms))
  if (( delta_ms <= 0 )); then
    delta_ms=1
  fi
  mbps="$(awk -v bytes="${delta_bytes}" -v ms="${delta_ms}" 'BEGIN { printf "%.2f", (bytes * 8) / (ms * 1000) }')"
  echo -e "${now}\t${elapsed_ms}\t${received_bytes}\t${delta_bytes}\t${mbps}\t${sender_alive}\t${receiver_alive}" >>"${samples_file}"

  if (( received_bytes > last_bytes )); then
    last_progress_ms="${now}"
  fi

  if (( sender_alive == 0 && receiver_alive == 0 )); then
    break
  fi

  idle_ms="$((now - last_progress_ms))"
  if (( received_bytes == 0 && elapsed_ms > start_timeout_sec * 1000 )); then
    abort_with_dumps "start-timeout-sec=${start_timeout_sec}"
  fi
  if (( received_bytes > 0 && idle_ms > stall_timeout_sec * 1000 )); then
    abort_with_dumps "stall-timeout-sec=${stall_timeout_sec}"
  fi

  last_bytes="${received_bytes}"
  last_ms="${now}"
  sleep "${sample_interval_sec}"
done

sender_status="$(remote_sh "${sender_target}" "cat $(quote "${sender_dir}/send.status") 2>/dev/null || echo 127" || true)"
receiver_status="$(remote_sh "${receiver_target}" "cat $(quote "${receiver_dir}/receive.status") 2>/dev/null || echo 127" || true)"
sink_sha="$(remote_sh "${receiver_target}" "sha256sum $(quote "${receiver_out}") 2>/dev/null | awk '{print \$1}' || true")"
sink_size="$(remote_sh "${receiver_target}" "stat -c %s $(quote "${receiver_out}") 2>/dev/null || echo 0")"

echo "source-size-bytes=${expected_size}"
echo "sink-size-bytes=${sink_size}"
echo "source-sha256=${source_sha}"
echo "sink-sha256=${sink_sha}"
echo "sender-status=${sender_status}"
echo "receiver-status=${receiver_status}"

if [[ "${sender_status}" != "0" || "${receiver_status}" != "0" ]]; then
  abort_with_dumps "process-exit sender=${sender_status} receiver=${receiver_status}"
fi
if [[ "${sink_size}" != "${expected_size}" || "${sink_sha}" != "${source_sha}" ]]; then
  abort_with_dumps "verification-failed"
fi

echo "stall-harness-success=true"
