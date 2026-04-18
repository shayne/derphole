#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: smoke-remote-derptun.sh HOST}"
root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
remote_user="${DERPHOLE_REMOTE_USER:-root}"
remote_base="/tmp/derptun-smoke-$$"
remote_upload="/tmp/derptun-bin-$$"
tmp="$(mktemp -d)"
token_file="${tmp}/token"
open_log="${tmp}/open.log"
serve_log="${tmp}/serve.log"
local_open_pid=""

remote() {
  ssh "${remote_user}@${target}" 'bash -se' <<<"$1"
}

cleanup() {
  if [[ -n "${local_open_pid}" ]]; then
    kill "${local_open_pid}" 2>/dev/null || true
    wait "${local_open_pid}" 2>/dev/null || true
  fi
  remote "if [[ -f '${remote_base}/serve.pid' ]]; then kill \$(cat '${remote_base}/serve.pid') 2>/dev/null || true; fi; if [[ -f '${remote_base}/echo.pid' ]]; then kill \$(cat '${remote_base}/echo.pid') 2>/dev/null || true; fi; rm -rf '${remote_base}' '${remote_upload}'" >/dev/null 2>&1 || true
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

wait_for_file_pattern() {
  local file="$1"
  local pattern="$2"
  for _ in $(seq 1 120); do
    if grep -qE "${pattern}" "${file}" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

fetch_remote_serve_log() {
  ssh "${remote_user}@${target}" "cat '${remote_base}/serve.err' 2>/dev/null || true" >"${serve_log}" || true
}

request_pong() {
  local port="$1"
  python3 - "${port}" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
    sock.sendall(b"ping\n")
    data = sock.recv(1024)
print(data.decode("utf-8", "replace").strip())
PY
}

require_direct_evidence() {
  local label="$1"
  local file="$2"
  if ! grep -q 'connected-direct' "${file}"; then
    echo "${label} did not report connected-direct with Tailscale candidates disabled" >&2
    sed -n '1,200p' "${file}" >&2 || true
    exit 1
  fi
}

mkdir -p "${root_dir}/dist"
go build -o "${root_dir}/dist/derptun" "${root_dir}/cmd/derptun"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "${root_dir}/dist/derptun-linux-amd64" "${root_dir}/cmd/derptun"
"${root_dir}/dist/derptun" token --days 1 >"${token_file}"

remote "mkdir -p '${remote_base}'"
scp "${root_dir}/dist/derptun-linux-amd64" "${remote_user}@${target}:${remote_upload}" >/dev/null
remote "install -m 0755 '${remote_upload}' '${remote_base}/derptun'; rm -f '${remote_upload}'"
scp "${token_file}" "${remote_user}@${target}:${remote_base}/token" >/dev/null

remote "nohup python3 -u - <<'PY' >'${remote_base}/echo.log' 2>&1 & echo \$! >'${remote_base}/echo.pid'
import socket

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('127.0.0.1', 22345))
server.listen()
while True:
    conn, _ = server.accept()
    with conn:
        conn.recv(1024)
        conn.sendall(b'pong\n')
PY"

remote "DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 nohup '${remote_base}/derptun' --verbose serve --token \"\$(cat '${remote_base}/token')\" --tcp 127.0.0.1:22345 >'${remote_base}/serve.out' 2>'${remote_base}/serve.err' </dev/null & echo \$! >'${remote_base}/serve.pid'"

local_port="$(free_local_port | tr -d '\n')"
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 "${root_dir}/dist/derptun" --verbose open --token "$(cat "${token_file}")" --listen "127.0.0.1:${local_port}" >"${open_log}" 2>&1 &
local_open_pid=$!

wait_for_file_pattern "${open_log}" "listening on 127\\.0\\.0\\.1:${local_port}" || {
  echo "derptun open did not bind local listener" >&2
  sed -n '1,200p' "${open_log}" >&2 || true
  exit 1
}

for _ in $(seq 1 80); do
  got="$(request_pong "${local_port}")"
  if [[ "${got}" != "pong" ]]; then
    echo "derptun payload mismatch" >&2
    printf 'want=%q\n' "pong" >&2
    printf ' got=%q\n' "${got}" >&2
    exit 1
  fi
  fetch_remote_serve_log
  if grep -q 'connected-direct' "${open_log}" && grep -q 'connected-direct' "${serve_log}"; then
    break
  fi
  sleep 0.25
done

fetch_remote_serve_log
require_direct_evidence "local derptun open" "${open_log}"
require_direct_evidence "remote derptun serve" "${serve_log}"
