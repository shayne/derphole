#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: $0 <target> [size-mib]}"
size_mib="${2:-1024}"
expected_size="$((size_mib * 1048576))"
tmp="$(mktemp -d)"
remote_base="/tmp/derpcat-promotion-reverse-$$"
remote_upload="/tmp/derpcat-promotion-reverse-bin-$$"
remote_user="${DERPCAT_REMOTE_USER:-root}"
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

remote() {
  ssh "${remote_user}@${target}" "${remote_env[@]}" 'bash -se' <<<"$1"
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
  remote "rm -f '${remote_base}.payload' '${remote_base}.err' '${remote_upload}'" >/dev/null 2>&1 || true
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

trap 'rc=$?; if [[ ${rc} -ne 0 ]]; then dump_failure; fi; cleanup; if [[ ${rc} -eq 0 ]]; then assert_no_derpcat_leaks; fi; exit ${rc}' EXIT

mise run build
mise run build-linux-amd64
scp dist/derpcat-linux-amd64 "${remote_user}@${target}:${remote_upload}" >/dev/null
remote "install -m 0755 '${remote_upload}' /usr/local/bin/derpcat && rm -f '${remote_upload}' && /usr/local/bin/derpcat --help >/dev/null 2>&1"

payload="${remote_base}.payload"
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

SECONDS=0
remote "/usr/local/bin/derpcat --verbose send '${token}' <'${payload}' >/dev/null 2>'${remote_base}.err'"
duration="${SECONDS}"

wait "${listener_pid}"
listener_pid=""

local_sha="$(shasum -a 256 "${listener_out}" | awk '{print $1}')"
local_size="$(wc -c <"${listener_out}" | tr -d '[:space:]')"
sender_trace="$(remote_path_trace "${remote_base}.err")"
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

echo "target=${target}"
echo "size_mib=${size_mib}"
echo "duration_seconds=${duration}"
echo "sha256=${local_sha}"
echo "sender_path_changed=${sender_path_changed}"
echo "listener_path_changed=${listener_path_changed}"
echo "sender_path_trace=$(printf '%s' "${sender_trace}" | tr '\n' ';')"
echo "listener_path_trace=$(printf '%s' "${listener_trace}" | tr '\n' ';')"
echo "--- sender log"
remote "sed -n '1,200p' '${remote_base}.err'"
echo "--- listener log"
cat "${listener_log}"
