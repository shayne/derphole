#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: $0 <hetz|pve1>}"
tmp="$(mktemp -d)"
remote_base="/tmp/derpcat-share-smoke-$$"
remote_upload="/tmp/derpcat-share-bin-$$"
local_share_pid=""
local_http_pid=""

remote() {
  ssh "root@${target}" 'bash -se' <<<"$1"
}

cleanup() {
  if [[ -n "${local_share_pid}" ]]; then
    kill "${local_share_pid}" 2>/dev/null || true
    wait "${local_share_pid}" 2>/dev/null || true
  fi
  if [[ -n "${local_http_pid}" ]]; then
    kill "${local_http_pid}" 2>/dev/null || true
    wait "${local_http_pid}" 2>/dev/null || true
  fi
  remote "if [[ -f '${remote_base}.pid' ]]; then kill \$(cat '${remote_base}.pid') 2>/dev/null || true; fi; rm -f '${remote_base}'.* '/tmp/derpcat-share-'* >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
  rm -rf "${tmp}"
}
trap cleanup EXIT

free_local_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

wait_for_local_token() {
  local log_file="$1"
  local token=""
  for _ in $(seq 1 150); do
    token="$(grep -E '^[A-Za-z0-9_-]{20,}$' "${log_file}" | head -n 1 || true)"
    if [[ -n "${token}" ]]; then
      printf '%s\n' "${token}"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_remote_bind() {
  local err_file="$1"
  local bind_addr=""
  for _ in $(seq 1 150); do
    bind_addr="$(remote "grep -Eo 'listening on 127\\.0\\.0\\.1:[0-9]+' '${err_file}' | awk '{print \$3}' | tail -n 1 || true")"
    if [[ -n "${bind_addr}" ]]; then
      printf '%s\n' "${bind_addr}"
      return 0
    fi
    sleep 0.1
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

mise run build
mise run build-linux-amd64
scp dist/derpcat-linux-amd64 "root@${target}:${remote_upload}" >/dev/null
remote "install -m 0755 '${remote_upload}' /usr/local/bin/derpcat && rm -f '${remote_upload}' && /usr/local/bin/derpcat help open >/dev/null 2>&1"

shared_content="hello shared service ${target} $(date +%s)"
printf '%s\n' "${shared_content}" >"${tmp}/index.html"
local_http_port="$(free_local_port | tr -d '\n')"
python3 -m http.server "${local_http_port}" --bind 127.0.0.1 --directory "${tmp}" >"${tmp}/http.log" 2>&1 &
local_http_pid=$!

local_share_log="${tmp}/share.err"
dist/derpcat --verbose share "127.0.0.1:${local_http_port}" >"${tmp}/share.out" 2>"${local_share_log}" &
local_share_pid=$!

token="$(wait_for_local_token "${local_share_log}")" || {
  echo "failed to capture share token" >&2
  sed -n '1,200p' "${local_share_log}" >&2 || true
  exit 1
}

remote_open_err="${remote_base}.open.err"
remote "rm -f '${remote_base}.pid' '${remote_open_err}'; nohup /usr/local/bin/derpcat --verbose open '${token}' >/dev/null 2>'${remote_open_err}' </dev/null & echo \$! > '${remote_base}.pid'"
bind_addr="$(wait_for_remote_bind "${remote_open_err}")" || {
  echo "failed to capture remote bind address" >&2
  remote "sed -n '1,200p' '${remote_open_err}'" >&2 || true
  exit 1
}

response_one="$(remote "curl --fail --silent 'http://${bind_addr}/'")"
response_two="$(remote "curl --fail --silent 'http://${bind_addr}/'")"

if [[ "${response_one}" != "${shared_content}" ]]; then
  echo "share response mismatch on first request" >&2
  printf 'want=%q\n' "${shared_content}" >&2
  printf ' got=%q\n' "${response_one}" >&2
  exit 1
fi
if [[ "${response_two}" != "${shared_content}" ]]; then
  echo "share response mismatch on second request" >&2
  printf 'want=%q\n' "${shared_content}" >&2
  printf ' got=%q\n' "${response_two}" >&2
  exit 1
fi

grep -q '^claimed$' "${local_share_log}"
assert_path_evidence "share" "$(path_trace "${local_share_log}")"
assert_path_evidence "open" "$(remote_path_trace "${remote_open_err}")"
