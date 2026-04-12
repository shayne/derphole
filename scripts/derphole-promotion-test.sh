#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: $0 <target> [size-mib]}"
size_mib="${2:-1024}"
expected_size="$((size_mib * 1048576))"
tmp="$(mktemp -d)"
start_ms=0
duration_ms=0
remote_base="/tmp/derphole-promotion-$$"
remote_upload="/tmp/derphole-promotion-bin-$$"
remote_target="${target}"
if [[ "${target}" != *"@"* ]]; then
  remote_user="${DERPCAT_REMOTE_USER:-root}"
  remote_target="${remote_user}@${target}"
fi
requested_remote_bin_dir="${DERPCAT_REMOTE_BIN_DIR:-/usr/local/bin}"
remote_bin_dir="${requested_remote_bin_dir}"
remote_bin="${remote_bin_dir%/}/derphole"
remote_env=()

if [[ "${DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES:-}" == "1" ]]; then
  remote_env+=(DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1)
fi
if [[ "${DERPCAT_ENABLE_TAILSCALE_CANDIDATES:-}" == "1" ]]; then
  remote_env+=(DERPCAT_ENABLE_TAILSCALE_CANDIDATES=1)
fi
if [[ "${DERPCAT_TRACE_HANDOFF:-}" == "1" ]]; then
  remote_env+=(DERPCAT_TRACE_HANDOFF=1)
fi
if [[ "${DERPCAT_PROBE_TRACE:-}" == "1" ]]; then
  remote_env+=(DERPCAT_PROBE_TRACE=1)
fi

remote() {
  ssh "${remote_target}" "${remote_env[@]}" 'bash -se' <<<"$1"
}

remote_home="$(remote 'printf %s "$HOME"')"
fallback_remote_bin_dirs=(
  "${remote_home}/.local/share/derphole-bench/bin"
  "${remote_home}/.cache/derphole-bench/bin"
  "/var/tmp/derphole-bench-bin"
  "/tmp/derphole-bench-bin"
)

install_remote_bin() {
  local desired_dir="$1"
  local desired_bin="${desired_dir%/}/derphole"
  remote "mkdir -p '${desired_dir}' && install -m 0755 '${remote_upload}' '${desired_bin}' && rm -f '${remote_upload}' && '${desired_bin}' --help >/dev/null 2>&1"
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

wall_goodput_mbps() {
  python3 - <<'PY' "$1" "$2"
import sys
size = int(sys.argv[1])
duration_ms = max(int(sys.argv[2]), 1)
print(f"{(size * 8.0) / (duration_ms * 1000.0):.2f}")
PY
}

preserve_logs() {
  local log_dir="${DERPCAT_BENCH_LOG_DIR:-}"
  if [[ -z "${log_dir}" ]]; then
    return 0
  fi
  mkdir -p "${log_dir}"
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local prefix="derphole-forward-${target//[^A-Za-z0-9_.-]/_}-${size_mib}MiB-${stamp}"
  cp "${send_log}" "${log_dir}/${prefix}-sender.log"
  cp "${listener_log}" "${log_dir}/${prefix}-receiver.log"
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
    echo "benchmark-tool=derphole"
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

dump_failure() {
  echo "--- local sender log" >&2
  sed -n '1,200p' "${tmp}/send.err" >&2 || true
  echo "--- remote receiver log" >&2
  remote "sed -n '1,200p' '${remote_base}.err'" >&2 || true
  echo "--- remote receiver size" >&2
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

cleanup() {
  if [[ -n "${send_pid:-}" ]]; then
    kill "${send_pid}" 2>/dev/null || true
  fi
  remote "if [[ -f '${remote_base}.pid' ]]; then kill \$(cat '${remote_base}.pid') 2>/dev/null || true; fi; rm -f '${remote_base}.pid' '${remote_base}.out' '${remote_base}.err' '${remote_upload}'; if [[ '${remote_bin_dir}' != '${requested_remote_bin_dir}' ]]; then rm -f '${remote_bin}'; fi" >/dev/null 2>&1 || true
  rm -rf "${tmp}"
}

trap 'status=$?; if [[ ${status} -ne 0 ]]; then if [[ ${start_ms} -gt 0 && ${duration_ms} -eq 0 ]]; then end_ms="$(now_ms)"; duration_ms="$((end_ms - start_ms))"; fi; dump_failure; emit_benchmark_footer 2 false "derphole-promotion-test-exit-${status}"; cleanup; fi; exit ${status}' EXIT

mise run build
mise run build-linux-amd64
scp dist/derphole-linux-amd64 "${remote_target}:${remote_upload}" >/dev/null
if ! install_remote_bin "${remote_bin_dir}"; then
  if [[ -n "${DERPCAT_REMOTE_BIN_DIR:-}" ]]; then
    exit 1
  fi
  installed_fallback=0
  for fallback_dir in "${fallback_remote_bin_dirs[@]}"; do
    remote_bin_dir="${fallback_dir}"
    remote_bin="${remote_bin_dir}/derphole"
    scp dist/derphole-linux-amd64 "${remote_target}:${remote_upload}" >/dev/null
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

payload="${tmp}/payload.bin"
send_log="${tmp}/send.err"
listener_log="${tmp}/listener.err"

echo "generating ${size_mib} MiB random payload"
dd if=/dev/urandom of="${payload}" bs=1048576 count="${size_mib}" 2>/dev/null
local_sha="$(shasum -a 256 "${payload}" | awk '{print $1}')"

./dist/derphole --verbose send --hide-progress "${payload}" >/dev/null 2>"${send_log}" &
send_pid="$!"

token=""
for _ in $(seq 1 200); do
  token="$(sed -n 's#^npx -y derphole@latest receive ##p' "${send_log}" | head -n 1 || true)"
  if [[ -n "${token}" ]]; then
    break
  fi
  if ! kill -0 "${send_pid}" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if [[ -z "${token}" ]]; then
  echo "failed to capture sender token" >&2
  exit 1
fi

start_ms="$(now_ms)"
remote "rm -f '${remote_base}.pid' '${remote_base}.err'; nohup '${remote_bin}' --verbose receive --hide-progress --output '${remote_base}.out' '${token}' >/dev/null 2>'${remote_base}.err' </dev/null & echo \$! > '${remote_base}.pid'"
wait "${send_pid}"
send_pid=""
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
require_direct_evidence "receiver" "${listener_trace}"

end_ms="$(now_ms)"
duration_ms="$((end_ms - start_ms))"
if [[ "${duration_ms}" -le 0 ]]; then
  duration_ms=1
fi
sender_goodput_mbps="$(last_metric_value "${send_log}" "udp-send-goodput-mbps")"
sender_peak_goodput_mbps="$(last_metric_value "${send_log}" "udp-send-peak-goodput-mbps")"
sender_first_byte_ms="$(last_metric_value "${send_log}" "udp-send-session-first-byte-ms")"
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

echo "sender_path_changed=${sender_path_changed}"
echo "listener_path_changed=${listener_path_changed}"
echo "sender_path_trace=$(tr '\n' ';' <"${send_log}" | grep -Eo 'connected-(relay|direct)' | paste -sd';' - || true)"
echo "listener_path_trace=$(echo "${listener_trace}" | paste -sd';' - || true)"
echo "benchmark-wall-goodput-mbps=${wall_goodput}"
preserve_logs
emit_benchmark_footer 1 true "" "${sender_goodput_mbps}" "${sender_peak_goodput_mbps}" "${sender_first_byte_ms}"

cleanup
trap - EXIT
