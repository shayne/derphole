#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: smoke-remote-derptun.sh HOST}"
root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
remote_user="${DERPHOLE_REMOTE_USER:-root}"
remote_base="/tmp/derptun-smoke-$$"
remote_upload="/tmp/derptun-bin-$$"
tmp="$(mktemp -d)"
server_token_file="${tmp}/server.dts"
client_token_file="${tmp}/client.dtc"
open_log="${tmp}/open.log"
serve_log="${tmp}/serve.log"
connect_first_log="${tmp}/connect-first.log"
connect_first_out="${tmp}/connect-first.out"
connect_second_log="${tmp}/connect-second.log"
connect_second_out="${tmp}/connect-second.out"
connect_after_dead_log="${tmp}/connect-after-dead.log"
connect_after_dead_out="${tmp}/connect-after-dead.out"
active_in="${tmp}/connect-active.in"
active_log="${tmp}/connect-active.log"
active_out="${tmp}/connect-active.out"
contender_log="${tmp}/connect-contender.log"
contender_out="${tmp}/connect-contender.out"
local_open_pid=""
active_connect_pid=""

remote() {
  ssh "${remote_user}@${target}" 'bash -se' <<<"$1"
}

cleanup() {
  set +e
  { exec 9>&-; } 2>/dev/null || true
  set -e
  if [[ -n "${active_connect_pid}" ]]; then
    kill "${active_connect_pid}" 2>/dev/null || true
    wait "${active_connect_pid}" 2>/dev/null || true
  fi
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

connect_request_pongs() {
  local label="$1"
  local out_file="$2"
  local log_file="$3"
  local connect_pid=""

  python3 - <<'PY' | DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 "${root_dir}/dist/derptun" --verbose connect --token "$(cat "${client_token_file}")" --stdio >"${out_file}" 2>"${log_file}" &
import sys
import time

for _ in range(80):
    sys.stdout.write("ping\n")
    sys.stdout.flush()
    time.sleep(0.05)
PY
  connect_pid=$!

  for _ in $(seq 1 120); do
    got_count="$(grep -c '^pong$' "${out_file}" 2>/dev/null || true)"
    if [[ "${got_count}" == "80" ]] && grep -q 'connected-direct' "${log_file}" 2>/dev/null; then
      break
    fi
    if ! kill -0 "${connect_pid}" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done

  got_count="$(grep -c '^pong$' "${out_file}" || true)"
  if [[ "${got_count}" != "80" ]]; then
    echo "derptun connect ${label} payload mismatch" >&2
    printf 'want pong lines=%q\n' "80" >&2
    printf ' got pong lines=%q\n' "${got_count}" >&2
    fetch_remote_serve_log
    sed -n '1,120p' "${out_file}" >&2 || true
    sed -n '1,200p' "${log_file}" >&2 || true
    echo "serve log:" >&2
    sed -n '1,260p' "${serve_log}" >&2 || true
    exit 1
  fi
  require_direct_evidence "local derptun connect ${label}" "${log_file}"
  for _ in $(seq 1 40); do
    if ! kill -0 "${connect_pid}" 2>/dev/null; then
      wait "${connect_pid}" 2>/dev/null || true
      return 0
    fi
    sleep 0.25
  done
  kill "${connect_pid}" 2>/dev/null || true
  wait "${connect_pid}" 2>/dev/null || true
}

start_holding_connect() {
  mkfifo "${active_in}"
  DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 "${root_dir}/dist/derptun" --verbose connect --token "$(cat "${client_token_file}")" --stdio <"${active_in}" >"${active_out}" 2>"${active_log}" &
  active_connect_pid=$!
  exec 9>"${active_in}"
  printf 'ping\n' >&9

  for _ in $(seq 1 120); do
    if grep -q '^pong$' "${active_out}" 2>/dev/null && grep -q 'connected-direct' "${active_log}" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "${active_connect_pid}" 2>/dev/null; then
      echo "active derptun connect exited before becoming direct" >&2
      fetch_remote_serve_log
      sed -n '1,120p' "${active_out}" >&2 || true
      sed -n '1,200p' "${active_log}" >&2 || true
      echo "serve log:" >&2
      sed -n '1,240p' "${serve_log}" >&2 || true
      exit 1
    fi
    sleep 0.25
  done

  echo "active derptun connect did not become direct" >&2
  fetch_remote_serve_log
  sed -n '1,120p' "${active_out}" >&2 || true
  sed -n '1,200p' "${active_log}" >&2 || true
  echo "serve log:" >&2
  sed -n '1,240p' "${serve_log}" >&2 || true
  exit 1
}

require_active_pong_count() {
  local want_count="$1"
  for _ in $(seq 1 40); do
    got_count="$(grep -c '^pong$' "${active_out}" 2>/dev/null || true)"
    if [[ "${got_count}" == "${want_count}" ]]; then
      return 0
    fi
    if ! kill -0 "${active_connect_pid}" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  echo "active derptun connect did not return ${want_count} pong lines" >&2
  sed -n '1,120p' "${active_out}" >&2 || true
  sed -n '1,200p' "${active_log}" >&2 || true
  exit 1
}

refresh_active_connect() {
  printf 'ping\n' >&9
  require_active_pong_count 2
}

expect_claimed_contender() {
  if ! kill -0 "${active_connect_pid}" 2>/dev/null; then
    echo "active derptun connect exited before contender started" >&2
    sed -n '1,120p' "${active_out}" >&2 || true
    sed -n '1,200p' "${active_log}" >&2 || true
    exit 1
  fi
  (printf 'ping\n' | DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 "${root_dir}/dist/derptun" --verbose connect --token "$(cat "${client_token_file}")" --stdio >"${contender_out}" 2>"${contender_log}") &
  contender_pid=$!

  for _ in $(seq 1 40); do
    if grep -q 'session already claimed' "${contender_log}" "${contender_out}" 2>/dev/null; then
      set +e
      wait "${contender_pid}"
      contender_status=$?
      set -e
      if [[ "${contender_status}" == "0" ]]; then
        echo "contending derptun connect reported claimed rejection but exited successfully" >&2
        sed -n '1,120p' "${contender_out}" >&2 || true
        sed -n '1,200p' "${contender_log}" >&2 || true
        exit 1
      fi
      return 0
    fi
    if ! kill -0 "${contender_pid}" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  if kill -0 "${contender_pid}" 2>/dev/null; then
    kill "${contender_pid}" 2>/dev/null || true
    wait "${contender_pid}" 2>/dev/null || true
    echo "contending derptun connect timed out instead of receiving claimed rejection" >&2
    fetch_remote_serve_log
    sed -n '1,120p' "${contender_out}" >&2 || true
    sed -n '1,200p' "${contender_log}" >&2 || true
    echo "active connect output:" >&2
    sed -n '1,120p' "${active_out}" >&2 || true
    echo "active connect log:" >&2
    sed -n '1,200p' "${active_log}" >&2 || true
    echo "serve log:" >&2
    sed -n '1,240p' "${serve_log}" >&2 || true
    exit 1
  fi

  set +e
  wait "${contender_pid}"
  contender_status=$?
  set -e
  if [[ "${contender_status}" == "0" ]]; then
    echo "contending derptun connect succeeded while active client was connected" >&2
    fetch_remote_serve_log
    sed -n '1,120p' "${contender_out}" >&2 || true
    sed -n '1,200p' "${contender_log}" >&2 || true
    echo "active connect output:" >&2
    sed -n '1,120p' "${active_out}" >&2 || true
    echo "active connect log:" >&2
    sed -n '1,200p' "${active_log}" >&2 || true
    echo "serve log:" >&2
    sed -n '1,240p' "${serve_log}" >&2 || true
    exit 1
  fi
  if ! grep -q 'session already claimed' "${contender_log}" "${contender_out}" 2>/dev/null; then
    echo "contending derptun connect did not report claimed rejection" >&2
    fetch_remote_serve_log
    sed -n '1,120p' "${contender_out}" >&2 || true
    sed -n '1,200p' "${contender_log}" >&2 || true
    echo "active connect output:" >&2
    sed -n '1,120p' "${active_out}" >&2 || true
    echo "active connect log:" >&2
    sed -n '1,200p' "${active_log}" >&2 || true
    echo "serve log:" >&2
    sed -n '1,240p' "${serve_log}" >&2 || true
    exit 1
  fi
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
"${root_dir}/dist/derptun" token server --days 1 >"${server_token_file}"
"${root_dir}/dist/derptun" token client --token "$(cat "${server_token_file}")" --days 1 >"${client_token_file}"

remote "mkdir -p '${remote_base}'"
scp "${root_dir}/dist/derptun-linux-amd64" "${remote_user}@${target}:${remote_upload}" >/dev/null
remote "install -m 0755 '${remote_upload}' '${remote_base}/derptun'; rm -f '${remote_upload}'"
scp "${server_token_file}" "${remote_user}@${target}:${remote_base}/server.dts" >/dev/null

remote "nohup python3 -u - <<'PY' >'${remote_base}/echo.log' 2>&1 & echo \$! >'${remote_base}/echo.pid'
import socket

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('127.0.0.1', 22345))
server.listen()
while True:
    conn, _ = server.accept()
    with conn:
        stream = conn.makefile('rwb', buffering=0)
        for index, line in enumerate(stream, start=1):
            if not line:
                break
            conn.sendall(b'pong\n')
            if index >= 80:
                break
PY"

remote "DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 nohup '${remote_base}/derptun' --verbose serve --token \"\$(cat '${remote_base}/server.dts')\" --tcp 127.0.0.1:22345 >'${remote_base}/serve.out' 2>'${remote_base}/serve.err' </dev/null & echo \$! >'${remote_base}/serve.pid'"

connect_request_pongs "first" "${connect_first_out}" "${connect_first_log}"
fetch_remote_serve_log
require_direct_evidence "remote derptun serve after first connect" "${serve_log}"
remote "kill \$(cat '${remote_base}/serve.pid') 2>/dev/null || true; DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 nohup '${remote_base}/derptun' --verbose serve --token \"\$(cat '${remote_base}/server.dts')\" --tcp 127.0.0.1:22345 >'${remote_base}/serve.out' 2>'${remote_base}/serve.err' </dev/null & echo \$! >'${remote_base}/serve.pid'"

start_holding_connect
refresh_active_connect
expect_claimed_contender
require_direct_evidence "active derptun connect" "${active_log}"
kill "${active_connect_pid}" 2>/dev/null || true
wait "${active_connect_pid}" 2>/dev/null || true
active_connect_pid=""
set +e
{ exec 9>&-; } 2>/dev/null || true
set -e

connect_request_pongs "after dead client" "${connect_after_dead_out}" "${connect_after_dead_log}"
fetch_remote_serve_log
require_direct_evidence "remote derptun serve after dead client reconnect" "${serve_log}"

connect_request_pongs "second" "${connect_second_out}" "${connect_second_log}"
fetch_remote_serve_log
require_direct_evidence "remote derptun serve after second connect" "${serve_log}"

local_port="$(free_local_port | tr -d '\n')"
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 "${root_dir}/dist/derptun" --verbose open --token "$(cat "${client_token_file}")" --listen "127.0.0.1:${local_port}" >"${open_log}" 2>&1 &
local_open_pid=$!

wait_for_file_pattern "${open_log}" "listening on 127\\.0\\.0\\.1:${local_port}" || {
  echo "derptun open did not bind local listener" >&2
  fetch_remote_serve_log
  echo "first connect log:" >&2
  sed -n '1,200p' "${connect_first_log}" >&2 || true
  echo "second connect log:" >&2
  sed -n '1,200p' "${connect_second_log}" >&2 || true
  echo "serve log:" >&2
  sed -n '1,240p' "${serve_log}" >&2 || true
  echo "open log:" >&2
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
