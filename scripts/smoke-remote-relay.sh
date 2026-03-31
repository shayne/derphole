#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: $0 <host>}"
tmp="$(mktemp -d)"
remote_base="/tmp/derpcat-relay-smoke-$$"
remote_upload="/tmp/derpcat-relay-bin-$$"
local_listener_pid=""
remote_user="${DERPCAT_REMOTE_USER:-root}"

remote() {
  ssh "${remote_user}@${target}" 'bash -se' <<<"$1"
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

dump_remote_logs() {
  remote "echo '--- remote err'; sed -n '1,160p' '${remote_base}.err' 2>/dev/null || true; echo '--- remote out'; sed -n '1,160p' '${remote_base}.out' 2>/dev/null || true; echo '--- remote sender err'; sed -n '1,160p' '${remote_base}.sender.err' 2>/dev/null || true; echo '--- remote sender out'; sed -n '1,160p' '${remote_base}.sender.out' 2>/dev/null || true"
}

mise run build
mise run build-linux-amd64
scp dist/derpcat-linux-amd64 "${remote_user}@${target}:${remote_upload}" >/dev/null
remote "install -m 0755 '${remote_upload}' /usr/local/bin/derpcat && rm -f '${remote_upload}' && /usr/local/bin/derpcat --help >/dev/null 2>&1"

payload_local_to_remote="hello relay local-to-${target}-$(date +%s)"
remote "rm -f '${remote_base}.pid' '${remote_base}.out' '${remote_base}.err'; nohup /usr/local/bin/derpcat listen --force-relay >'${remote_base}.out' 2>'${remote_base}.err' </dev/null & echo \$! > '${remote_base}.pid'"
remote_token="$(wait_for_remote_token)" || {
  echo "failed to capture remote listener token" >&2
  dump_remote_logs >&2
  exit 1
}
printf '%s' "${payload_local_to_remote}" | dist/derpcat send "${remote_token}" --force-relay >"${tmp}/local-sender.out" 2>"${tmp}/local-sender.err"
wait_for_remote_exit || {
  echo "remote relay listener did not exit" >&2
  dump_remote_logs >&2
  exit 1
}
remote_output="$(remote "cat '${remote_base}.out'")"
if [[ "${remote_output}" != "${payload_local_to_remote}" ]]; then
  echo "remote relay output mismatch" >&2
  printf 'want=%q\n' "${payload_local_to_remote}" >&2
  printf ' got=%q\n' "${remote_output}" >&2
  dump_remote_logs >&2
  exit 1
fi
grep -q 'connected-relay' "${tmp}/local-sender.err"
remote "grep -q 'connected-relay' '${remote_base}.err'"

payload_remote_to_local="hello relay ${target}-to-local-$(date +%s)"
local_listener_log="${tmp}/local-listener.err"
local_listener_out="${tmp}/local-listener.out"
dist/derpcat listen --force-relay >"${local_listener_out}" 2>"${local_listener_log}" &
local_listener_pid=$!
local_token="$(wait_for_local_token "${local_listener_log}")" || {
  echo "failed to capture local relay listener token" >&2
  sed -n '1,160p' "${local_listener_log}" >&2 || true
  exit 1
}
remote "printf '%s' '${payload_remote_to_local}' | /usr/local/bin/derpcat send '${local_token}' --force-relay >'${remote_base}.sender.out' 2>'${remote_base}.sender.err'"
wait_for_local_exit "${local_listener_pid}" || {
  echo "local relay listener did not exit" >&2
  sed -n '1,160p' "${local_listener_log}" >&2 || true
  dump_remote_logs >&2
  exit 1
}
local_listener_pid=""
local_output="$(cat "${local_listener_out}")"
if [[ "${local_output}" != "${payload_remote_to_local}" ]]; then
  echo "local relay output mismatch" >&2
  printf 'want=%q\n' "${payload_remote_to_local}" >&2
  printf ' got=%q\n' "${local_output}" >&2
  sed -n '1,160p' "${local_listener_log}" >&2 || true
  dump_remote_logs >&2
  exit 1
fi
grep -q 'connected-relay' "${local_listener_log}"
remote "grep -q 'connected-relay' '${remote_base}.sender.err'"

echo "target=${target}"
echo "relay smoke passed"
