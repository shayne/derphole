#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: $0 <target> [size-mib]}"
size_mib="${2:-1024}"
expected_size="$((size_mib * 1048576))"
tmp="$(mktemp -d)"
remote_base="/tmp/derpcat-promotion-$$"
remote_upload="/tmp/derpcat-promotion-bin-$$"
remote_user="${DERPCAT_REMOTE_USER:-root}"
remote_bin_dir="${DERPCAT_REMOTE_BIN_DIR:-/usr/local/bin}"
remote_bin="${remote_bin_dir%/}/derpcat"
remote_env=()

if [[ "${DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES:-}" == "1" ]]; then
  remote_env+=(DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1)
fi
if [[ "${DERPCAT_ENABLE_TAILSCALE_CANDIDATES:-}" == "1" ]]; then
  remote_env+=(DERPCAT_ENABLE_TAILSCALE_CANDIDATES=1)
fi
if [[ -n "${DERPCAT_NATIVE_QUIC_CONNS:-}" ]]; then
  remote_env+=(DERPCAT_NATIVE_QUIC_CONNS="${DERPCAT_NATIVE_QUIC_CONNS}")
fi
if [[ -n "${DERPCAT_NATIVE_TCP_CONNS:-}" ]]; then
  remote_env+=(DERPCAT_NATIVE_TCP_CONNS="${DERPCAT_NATIVE_TCP_CONNS}")
fi
if [[ "${DERPCAT_TRACE_HANDOFF:-}" == "1" ]]; then
  remote_env+=(DERPCAT_TRACE_HANDOFF=1)
fi
if [[ "${DERPCAT_PROBE_TRACE:-}" == "1" ]]; then
  remote_env+=(DERPCAT_PROBE_TRACE=1)
fi

parallel_args=()
if [[ -n "${DERPCAT_PARALLEL_ARGS:-}" ]]; then
  read -r -a parallel_args <<<"${DERPCAT_PARALLEL_ARGS}"
fi
remote() {
  ssh "${remote_user}@${target}" "${remote_env[@]}" 'bash -se' <<<"$1"
}

now_ms() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import time; print(int(time.time() * 1000))'
    return 0
  fi
  perl -MTime::HiRes=time -e 'print int(time() * 1000), "\n"'
}

last_metric_value() {
  local file="$1"
  local key="$2"
  sed -n "s/^${key}=//p" "${file}" | tail -n 1
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
    echo "benchmark-direction=forward"
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
  pids="$(pgrep -x derpcat | paste -sd, - || true)"
  if [[ -z "${pids}" ]]; then
    echo 0
    return 0
  fi
  lsof -nP -a -p "${pids}" -iUDP 2>/dev/null | awk 'NR > 1 { count++ } END { print count + 0 }' || true
}

count_local_derpcat_processes() {
  pgrep -x derpcat | awk '{ count++ } END { print count + 0 }' || true
}

count_remote_udp_sockets() {
  remote "pids=\$(pgrep -x derpcat | paste -sd, - || true); if [[ -z \"\${pids}\" ]]; then echo 0; else lsof -nP -a -p \"\${pids}\" -iUDP 2>/dev/null | awk 'NR > 1 { count++ } END { print count + 0 }' || true; fi"
}

count_remote_derpcat_processes() {
  remote "pgrep -x derpcat | awk '{ count++ } END { print count + 0 }' || true"
}

dump_failure() {
  echo "--- local sender log" >&2
  sed -n '1,200p' "${tmp}/send.err" >&2 || true
  echo "--- remote listener log" >&2
  remote "sed -n '1,200p' '${remote_base}.err'" >&2 || true
  echo "--- remote listener size" >&2
  remote "wc -c < '${remote_base}.out'" >&2 || true
}

path_trace() {
  local file="$1"
  grep -Eo 'connected-(relay|direct)' "${file}" 2>/dev/null || true
}

remote_path_trace() {
  local file="$1"
  remote "grep -Eo 'connected-(relay|direct)' '${file}' 2>/dev/null || true"
}

path_changed_mid_run() {
  local trace="$1"
  grep -q 'connected-relay' <<<"${trace}" && grep -q 'connected-direct' <<<"${trace}"
}

require_direct_evidence() {
  local label="$1"
  local trace="$2"

  if ! grep -q 'connected-direct' <<<"${trace}"; then
    echo "${label} missing direct promotion evidence" >&2
    exit 1
  fi
}

require_direct_blast_log() {
  local label="$1"
  local file="$2"
  local metric_prefix="$3"

  if grep -q '^udp-relay=true$' "${file}"; then
    echo "${label} fell back to relay instead of direct UDP blast" >&2
    exit 1
  fi
  if ! grep -q "^${metric_prefix}-data-goodput-mbps=" "${file}"; then
    echo "${label} missing direct UDP blast goodput evidence" >&2
    exit 1
  fi
}

cleanup() {
  remote "if [[ -f '${remote_base}.pid' ]]; then kill \$(cat '${remote_base}.pid') 2>/dev/null || true; fi; rm -f '${remote_base}.pid' '${remote_base}.out' '${remote_base}.err' '${remote_upload}'; if [[ '${remote_bin_dir}' == /tmp* ]]; then rm -f '${remote_bin}'; fi" >/dev/null 2>&1 || true
  rm -rf "${tmp}"
}

assert_no_derpcat_leaks() {
  local local_udp_count
  local local_process_count
  local remote_udp_count
  local remote_process_count

  local_udp_count="$(count_local_udp_sockets | tr -d '[:space:]')"
  local_process_count="$(count_local_derpcat_processes | tr -d '[:space:]')"
  remote_udp_count="$(count_remote_udp_sockets | tr -d '[:space:]')"
  remote_process_count="$(count_remote_derpcat_processes | tr -d '[:space:]')"

  if [[ "${local_udp_count}" != "0" ]]; then
    echo "local derpcat UDP sockets leaked: ${local_udp_count}" >&2
    exit 1
  fi
  if [[ "${local_process_count}" != "0" ]]; then
    echo "local derpcat processes leaked: ${local_process_count}" >&2
    exit 1
  fi
  if [[ "${remote_udp_count}" != "0" ]]; then
    echo "remote derpcat UDP sockets leaked on ${target}: ${remote_udp_count}" >&2
    exit 1
  fi
  if [[ "${remote_process_count}" != "0" ]]; then
    echo "remote derpcat processes leaked on ${target}: ${remote_process_count}" >&2
    exit 1
  fi
}

trap 'status=$?; if [[ ${status} -ne 0 ]]; then dump_failure; emit_benchmark_footer 2 false "promotion-test-exit-${status}"; cleanup; fi; exit ${status}' EXIT

mise run build
mise run build-linux-amd64
scp dist/derpcat-linux-amd64 "${remote_user}@${target}:${remote_upload}" >/dev/null
remote "mkdir -p '${remote_bin_dir}' && install -m 0755 '${remote_upload}' '${remote_bin}' && rm -f '${remote_upload}' && '${remote_bin}' --help >/dev/null 2>&1"

payload="${tmp}/payload.bin"
send_log="${tmp}/send.err"
listener_log="${tmp}/listener.err"

echo "generating ${size_mib} MiB random payload"
dd if=/dev/urandom of="${payload}" bs=1048576 count="${size_mib}" 2>/dev/null
local_sha="$(shasum -a 256 "${payload}" | awk '{print $1}')"

remote "rm -f '${remote_base}.pid' '${remote_base}.out' '${remote_base}.err'; nohup '${remote_bin}' --verbose listen >'${remote_base}.out' 2>'${remote_base}.err' </dev/null & echo \$! > '${remote_base}.pid'"

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

duration_ms=0
start_ms="$(now_ms)"
./dist/derpcat --verbose send "${parallel_args[@]+"${parallel_args[@]}"}" "${token}" <"${payload}" >/dev/null 2>"${send_log}"

for _ in $(seq 1 400); do
  if ! remote "if [[ -f '${remote_base}.pid' ]]; then kill -0 \$(cat '${remote_base}.pid') 2>/dev/null; else false; fi" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

remote "cat '${remote_base}.err'" >"${listener_log}"
remote_sha="$(remote "sha256sum '${remote_base}.out' | awk '{print \$1}'")"
remote_size="$(remote "wc -c < '${remote_base}.out'")"
sender_trace="$(path_trace "${send_log}")"
listener_trace="$(remote_path_trace "${remote_base}.err")"
sender_path_changed="false"
listener_path_changed="false"

if path_changed_mid_run "${sender_trace}"; then
  sender_path_changed="true"
fi
if path_changed_mid_run "${listener_trace}"; then
  listener_path_changed="true"
fi

[[ "${local_sha}" == "${remote_sha}" ]]
[[ "${remote_size}" == "${expected_size}" ]]
[[ -n "${sender_trace}" ]]
[[ -n "${listener_trace}" ]]
require_direct_evidence "sender" "${sender_trace}"
require_direct_evidence "listener" "${listener_trace}"
require_direct_blast_log "sender" "${send_log}" "udp-send"
require_direct_blast_log "listener" "${listener_log}" "udp-receive"

sender_goodput_mbps="$(last_metric_value "${send_log}" "udp-send-goodput-mbps")"
sender_peak_goodput_mbps="$(last_metric_value "${send_log}" "udp-send-peak-goodput-mbps")"
sender_first_byte_ms="$(last_metric_value "${send_log}" "udp-send-session-first-byte-ms")"
end_ms="$(now_ms)"
duration_ms="$((end_ms - start_ms))"
duration="$((duration_ms / 1000))"
assert_no_derpcat_leaks
emit_benchmark_footer 1 true "" "${sender_goodput_mbps:-0}" "${sender_peak_goodput_mbps:-0}" "${sender_first_byte_ms:-0}"

echo "target=${target}"
echo "size_mib=${size_mib}"
echo "duration_seconds=${duration}"
echo "sha256=${local_sha}"
echo "sender_path_changed=${sender_path_changed}"
echo "listener_path_changed=${listener_path_changed}"
echo "sender_path_trace=$(printf '%s' "${sender_trace}" | tr '\n' ';')"
echo "listener_path_trace=$(printf '%s' "${listener_trace}" | tr '\n' ';')"
echo "--- sender log"
cat "${send_log}"
echo "--- listener log"
cat "${listener_log}"
cleanup
trap - EXIT
