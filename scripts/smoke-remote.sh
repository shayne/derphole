#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: $0 <host>}"
tmp="$(mktemp -d)"
remote_base="/tmp/derphole-smoke-$$"
remote_upload="/tmp/derphole-smoke-bin-$$"
local_listener_pid=""
transfer_pause=5
remote_user="${DERPHOLE_REMOTE_USER:-root}"
remote_env=()

if [[ "${DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES:-}" == "1" ]]; then
  remote_env+=(DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1)
fi

remote() {
  ssh "${remote_user}@${target}" "${remote_env[@]}" 'bash -se' <<<"$1"
}

cleanup() {
  if [[ -n "${local_listener_pid}" ]]; then
    kill "${local_listener_pid}" 2>/dev/null || true
    wait "${local_listener_pid}" 2>/dev/null || true
  fi
  remote "if [[ -f '${remote_base}.pid' ]]; then kill \$(cat '${remote_base}.pid') 2>/dev/null || true; fi; rm -f '${remote_base}.pid' '${remote_base}.out' '${remote_base}.err' '${remote_base}.sender.out' '${remote_base}.sender.err'" >/dev/null 2>&1 || true
  rm -rf "${tmp}"
}
trap cleanup EXIT

wait_for_remote_token() {
  local token=""
  for _ in $(seq 1 100); do
    token="$(remote "grep -E '^[A-Za-z0-9_-]{20,}\$' '${remote_base}.err' | head -n 1 || true")"
    if [[ -n "${token}" ]]; then
      printf '%s\n' "${token}"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_local_token() {
  local log_file="$1"
  local token=""
  for _ in $(seq 1 100); do
    token="$(grep -E '^[A-Za-z0-9_-]{20,}$' "${log_file}" | head -n 1 || true)"
    if [[ -n "${token}" ]]; then
      printf '%s\n' "${token}"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_remote_exit() {
  for _ in $(seq 1 120); do
    if ! remote "if [[ -f '${remote_base}.pid' ]]; then kill -0 \$(cat '${remote_base}.pid') 2>/dev/null; else false; fi" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_for_local_exit() {
  local pid="$1"
  for _ in $(seq 1 120); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

path_trace() {
  local file="$1"
  grep -Eo 'connected-(relay|direct)' "${file}" 2>/dev/null || true
}

remote_path_trace() {
  local file="$1"
  remote "grep -Eo 'connected-(relay|direct)' '${file}' 2>/dev/null || true"
}

send_staged_payload() {
  local payload="$1"
  local split_at=$(( ${#payload} / 2 ))

  # Keep the stdio session open long enough to observe late direct promotion.
  printf '%s' "${payload:0:split_at}"
  sleep "${transfer_pause}"
  printf '%s' "${payload:split_at}"
}

assert_path_evidence() {
  local label="$1"
  local trace="$2"

  if [[ -z "${trace}" ]]; then
    echo "${label} missing path evidence" >&2
    exit 1
  fi

  printf '%s path trace:\n%s\n' "${label}" "${trace}" >&2
  if grep -q 'connected-relay' <<<"${trace}" && grep -q 'connected-direct' <<<"${trace}"; then
    echo "${label} path transition observed" >&2
  fi
}

require_direct_evidence_on_either_side() {
  local label="$1"
  local left_trace="$2"
  local right_trace="$3"

  if grep -q 'connected-direct' <<<"${left_trace}" || grep -q 'connected-direct' <<<"${right_trace}"; then
    return 0
  fi

  echo "${label} missing direct promotion evidence on both sides" >&2
  exit 1
}

dump_remote_logs() {
  remote "echo '--- remote err'; sed -n '1,160p' '${remote_base}.err' 2>/dev/null || true; echo '--- remote out'; sed -n '1,160p' '${remote_base}.out' 2>/dev/null || true; echo '--- remote sender err'; sed -n '1,160p' '${remote_base}.sender.err' 2>/dev/null || true; echo '--- remote sender out'; sed -n '1,160p' '${remote_base}.sender.out' 2>/dev/null || true"
}

dump_local_sender_logs() {
  echo '--- local sender err'
  sed -n '1,160p' "${tmp}/local-sender.err" 2>/dev/null || true
  echo '--- local sender out'
  sed -n '1,160p' "${tmp}/local-sender.out" 2>/dev/null || true
}

mise run build
mise run build-linux-amd64
scp dist/derphole-linux-amd64 "${remote_user}@${target}:${remote_upload}"
remote "install -m 0755 '${remote_upload}' /usr/local/bin/derphole && rm -f '${remote_upload}' && /usr/local/bin/derphole --help >/dev/null 2>&1"

payload_local_to_remote="hello local-to-${target}-$(date +%s)"
remote "rm -f '${remote_base}.pid' '${remote_base}.out' '${remote_base}.err'; nohup /usr/local/bin/derphole --verbose listen >'${remote_base}.out' 2>'${remote_base}.err' </dev/null & echo \$! > '${remote_base}.pid'"
remote_token="$(wait_for_remote_token)" || {
  echo "failed to capture remote listener token" >&2
  dump_remote_logs >&2
  exit 1
}
send_staged_payload "${payload_local_to_remote}" | dist/derphole --verbose send "${remote_token}" >"${tmp}/local-sender.out" 2>"${tmp}/local-sender.err"
wait_for_remote_exit || {
  echo "remote listener did not exit" >&2
  dump_remote_logs >&2
  exit 1
}
remote_output="$(remote "cat '${remote_base}.out'")"
if [[ "${remote_output}" != "${payload_local_to_remote}" ]]; then
  echo "remote output mismatch" >&2
  printf 'want=%q\n' "${payload_local_to_remote}" >&2
  printf ' got=%q\n' "${remote_output}" >&2
  dump_local_sender_logs >&2
  dump_remote_logs >&2
  exit 1
fi
remote_listener_trace="$(remote_path_trace "${remote_base}.err")"
local_sender_trace="$(path_trace "${tmp}/local-sender.err")"
assert_path_evidence "local sender" "${local_sender_trace}"
assert_path_evidence "remote listener" "${remote_listener_trace}"
require_direct_evidence_on_either_side "local-to-${target}" "${local_sender_trace}" "${remote_listener_trace}"

payload_remote_to_local="hello ${target}-to-local-$(date +%s)"
local_listener_log="${tmp}/local-listener.err"
local_listener_out="${tmp}/local-listener.out"
dist/derphole --verbose listen >"${local_listener_out}" 2>"${local_listener_log}" &
local_listener_pid=$!
local_token="$(wait_for_local_token "${local_listener_log}")" || {
  echo "failed to capture local listener token" >&2
  sed -n '1,160p' "${local_listener_log}" >&2 || true
  exit 1
}
remote "payload='${payload_remote_to_local}'; split_at=\$(( \${#payload} / 2 )); { printf '%s' \"\${payload:0:split_at}\"; sleep '${transfer_pause}'; printf '%s' \"\${payload:split_at}\"; } | /usr/local/bin/derphole --verbose send '${local_token}' >'${remote_base}.sender.out' 2>'${remote_base}.sender.err'"
wait_for_local_exit "${local_listener_pid}" || {
  echo "local listener did not exit" >&2
  sed -n '1,160p' "${local_listener_log}" >&2 || true
  dump_remote_logs >&2
  exit 1
}
local_listener_pid=""
local_output="$(cat "${local_listener_out}")"
if [[ "${local_output}" != "${payload_remote_to_local}" ]]; then
  echo "local output mismatch" >&2
  printf 'want=%q\n' "${payload_remote_to_local}" >&2
  printf ' got=%q\n' "${local_output}" >&2
  sed -n '1,160p' "${local_listener_log}" >&2 || true
  dump_remote_logs >&2
  exit 1
fi
remote_sender_trace="$(remote_path_trace "${remote_base}.sender.err")"
local_listener_trace="$(path_trace "${local_listener_log}")"
assert_path_evidence "local listener" "${local_listener_trace}"
assert_path_evidence "remote sender" "${remote_sender_trace}"
require_direct_evidence_on_either_side "${target}-to-local" "${local_listener_trace}" "${remote_sender_trace}"
