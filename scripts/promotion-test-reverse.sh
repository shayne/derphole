#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: $0 <target> [size-mib]}"
size_mib="${2:-1024}"
expected_size="$((size_mib * 1048576))"
tmp="$(mktemp -d)"
start_ms=0
duration_ms=0
remote_base="/tmp/derpcat-promotion-reverse-$$"
remote_upload="/tmp/derpcat-promotion-reverse-bin-$$"
remote_target="${target}"
if [[ "${target}" != *"@"* ]]; then
  remote_user="${DERPCAT_REMOTE_USER:-root}"
  remote_target="${remote_user}@${target}"
fi
requested_remote_bin_dir="${DERPCAT_REMOTE_BIN_DIR:-/usr/local/bin}"
remote_bin_dir="${requested_remote_bin_dir}"
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
parallel_args_remote="${parallel_args[*]-}"
remote() {
  ssh "${remote_target}" "${remote_env[@]}" 'bash -se' <<<"$1"
}

remote_home="$(remote 'printf %s "$HOME"')"
fallback_remote_bin_dirs=(
  "${remote_home}/.local/share/derpcat-bench/bin"
  "${remote_home}/.cache/derpcat-bench/bin"
  "/var/tmp/derpcat-bench-bin"
  "/tmp/derpcat-bench-bin"
)

install_remote_bin() {
  local desired_dir="$1"
  local desired_bin="${desired_dir%/}/derpcat"
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
    echo "benchmark-tool=derpcat"
    echo "benchmark-direction=reverse"
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
  echo "--- local listener log" >&2
  sed -n '1,200p' "${tmp}/listen.err" >&2 || true
  echo "--- remote sender log" >&2
  remote "sed -n '1,200p' '${remote_base}.err'" >&2 || true
  echo "--- local listener size" >&2
  wc -c <"${tmp}/listen.out" >&2 || true
}

preserve_logs() {
  local log_dir="${DERPCAT_BENCH_LOG_DIR:-}"
  if [[ -z "${log_dir}" ]]; then
    return 0
  fi
  mkdir -p "${log_dir}"
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local prefix="derpcat-reverse-${target//[^A-Za-z0-9_.-]/_}-${size_mib}MiB-${stamp}"
  cp "${sender_log}" "${log_dir}/${prefix}-sender.log"
  cp "${listener_log}" "${log_dir}/${prefix}-receiver.log"
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
  remote "rm -f '${remote_base}.payload' '${remote_base}.err' '${remote_upload}'; if [[ '${remote_bin_dir}' != '${requested_remote_bin_dir}' ]]; then rm -f '${remote_bin}'; fi" >/dev/null 2>&1 || true
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

trap 'rc=$?; if [[ ${rc} -ne 0 ]]; then if [[ ${start_ms} -gt 0 && ${duration_ms} -eq 0 ]]; then end_ms="$(now_ms)"; duration_ms="$((end_ms - start_ms))"; fi; dump_failure; emit_benchmark_footer 2 false "promotion-test-reverse-exit-${rc}"; cleanup; fi; exit ${rc}' EXIT

mise run build
mise run build-linux-amd64
scp dist/derpcat-linux-amd64 "${remote_target}:${remote_upload}" >/dev/null
if ! install_remote_bin "${remote_bin_dir}"; then
  if [[ -n "${DERPCAT_REMOTE_BIN_DIR:-}" ]]; then
    exit 1
  fi
  installed_fallback=0
  for fallback_dir in "${fallback_remote_bin_dirs[@]}"; do
    remote_bin_dir="${fallback_dir}"
    remote_bin="${remote_bin_dir}/derpcat"
    scp dist/derpcat-linux-amd64 "${remote_target}:${remote_upload}" >/dev/null
    if install_remote_bin "${remote_bin_dir}"; then
      installed_fallback=1
      break
    fi
  done
  if [[ "${installed_fallback}" != "1" ]]; then
    echo "failed to install remote benchmark binary in any writable exec-capable directory" >&2
    exit 1
  fi
fi

payload="${remote_base}.payload"
sender_log="${tmp}/send.err"
listener_log="${tmp}/listen.err"
listener_out="${tmp}/listen.out"
listener_pid=""

echo "generating ${size_mib} MiB random payload on ${target}"
remote "dd if=/dev/urandom of='${payload}' bs=1048576 count='${size_mib}' 2>/dev/null"
remote_sha="$(remote "sha256sum '${payload}' | awk '{print \$1}'")"

./dist/derpcat --verbose listen >"${listener_out}" 2>"${listener_log}" &
listener_pid="$!"

token=""
for _ in $(seq 1 200); do
  token="$(grep -E '^[A-Za-z0-9_-]{20,}$' "${listener_log}" | head -n 1 || true)"
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
remote "'${remote_bin}' --verbose send ${parallel_args_remote} '${token}' <'${payload}' >/dev/null 2>'${remote_base}.err'"

wait "${listener_pid}"
listener_pid=""
remote "cat '${remote_base}.err'" >"${sender_log}"

local_sha="$(shasum -a 256 "${listener_out}" | awk '{print $1}')"
local_size="$(wc -c <"${listener_out}" | tr -d '[:space:]')"
sender_trace="$(path_trace "${sender_log}")"
listener_trace="$(path_trace "${listener_log}")"
sender_path_changed="false"
listener_path_changed="false"

if path_changed_mid_run "${sender_trace}"; then
  sender_path_changed="true"
fi
if path_changed_mid_run "${listener_trace}"; then
  listener_path_changed="true"
fi

[[ "${local_sha}" == "${remote_sha}" ]]
[[ "${local_size}" == "${expected_size}" ]]
[[ -n "${sender_trace}" ]]
[[ -n "${listener_trace}" ]]
require_direct_evidence "sender" "${sender_trace}"
require_direct_evidence "listener" "${listener_trace}"
require_direct_blast_log "sender" "${sender_log}" "udp-send"
require_direct_blast_log "listener" "${listener_log}" "udp-receive"

sender_goodput_mbps="$(last_metric_value "${sender_log}" "udp-send-goodput-mbps")"
sender_peak_goodput_mbps="$(last_metric_value "${sender_log}" "udp-send-peak-goodput-mbps")"
sender_first_byte_ms="$(last_metric_value "${sender_log}" "udp-send-session-first-byte-ms")"
assert_no_derpcat_leaks
end_ms="$(now_ms)"
duration_ms="$((end_ms - start_ms))"
duration="$((duration_ms / 1000))"
wall_goodput="$(wall_goodput_mbps "${expected_size}" "${duration_ms}")"
echo "benchmark-wall-goodput-mbps=${wall_goodput}"
preserve_logs
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
cat "${sender_log}"
echo "--- listener log"
cat "${listener_log}"
cleanup
trap - EXIT
