#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: $0 <hetz|pve1>}"
tmp="$(mktemp -d)"
remote_base="/tmp/derpcat-tcp-smoke-$$"
remote_upload="/tmp/derpcat-tcp-bin-$$"
local_listener_pid=""
remote_sender_ssh_pid=""

remote() {
  ssh "root@${target}" 'bash -se' <<<"$1"
}

cleanup() {
  if [[ -n "${local_listener_pid}" ]]; then
    kill "${local_listener_pid}" 2>/dev/null || true
    wait "${local_listener_pid}" 2>/dev/null || true
  fi
  if [[ -n "${remote_sender_ssh_pid}" ]]; then
    kill "${remote_sender_ssh_pid}" 2>/dev/null || true
    wait "${remote_sender_ssh_pid}" 2>/dev/null || true
  fi
  remote "rm -f '${remote_base}'.* '/tmp/derpcat-tcp-remote-'* '/tmp/derpcat-tcp-local-'* >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
  rm -rf "${tmp}"
}
trap cleanup EXIT

wait_for_remote_token() {
  local token=""
  local err_file="$1"
  for _ in $(seq 1 100); do
    token="$(remote "grep -E '^[A-Za-z0-9_-]{20,}\$' '${err_file}' | head -n 1 || true")"
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

wait_for_local_pid_exit() {
  local pid="$1"
  for _ in $(seq 1 120); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

free_local_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

free_remote_port() {
  remote "python3 -c \"import socket; s=socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1]); s.close()\""
}

retry_local_nc() {
  local host="$1"
  local port="$2"
  local file="$3"
  (
    while true; do
      if nc "${host}" "${port}" >"${file}"; then
        exit 0
      fi
      sleep 0.1
    done
  ) >/dev/null 2>&1 &
  echo $!
}

retry_remote_send_nc() {
  local port="$1"
  local file="$2"
  remote "python3 - ${port} '${file}' <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
path = sys.argv[2]
payload = open(path, 'rb').read()
deadline = time.time() + 30

while True:
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=1) as conn:
            conn.sendall(payload)
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            break
    except OSError:
        if time.time() >= deadline:
            raise
        time.sleep(0.1)
PY"
}

start_local_source_server() {
  local port="$1"
  local file="$2"
  python3 - "${port}" "${file}" <<'PY' >/dev/null 2>&1 &
import socket
import sys

port = int(sys.argv[1])
path = sys.argv[2]

with socket.socket() as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(1)
    conn, _ = sock.accept()
    with conn, open(path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            conn.sendall(chunk)
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
PY
  echo $!
}

start_remote_sink_server() {
  local port="$1"
  local file="$2"
  remote "rm -f '${file}' '/tmp/derpcat-tcp-remote-connect.py.err' '/tmp/derpcat-tcp-remote-connect.py.pid'; nohup python3 -c \"import socket; sock=socket.socket(); sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); sock.bind(('127.0.0.1', ${port})); sock.listen(1); conn, _ = sock.accept(); out=open('${file}', 'wb'); data=conn.recv(1048576); out.write(data); out.close(); conn.close(); sock.close()\" >'/tmp/derpcat-tcp-remote-connect.py.err' 2>&1 </dev/null & echo \$! > '/tmp/derpcat-tcp-remote-connect.py.pid'"
}

mise run build
mise run build-linux-amd64
scp dist/derpcat-linux-amd64 "root@${target}:${remote_upload}" >/dev/null
remote "install -m 0755 '${remote_upload}' /usr/local/bin/derpcat && rm -f '${remote_upload}' && /usr/local/bin/derpcat --help >/dev/null 2>&1"

# Part A: tcp-connect on both ends
echo "phase=tcp-connect:start"
connect_payload="hello tcp-connect ${target} $(date +%s)"
printf '%s' "${connect_payload}" >"${tmp}/connect-payload.txt"
local_source_port="$(free_local_port | tr -d '\n')"
remote_sink_port="$(free_remote_port | tr -d '\n')"
echo "phase=tcp-connect:ports local_source=${local_source_port} remote_sink=${remote_sink_port}"

start_remote_sink_server "${remote_sink_port}" "/tmp/derpcat-tcp-remote-connect.out"
local_source_pid="$(start_local_source_server "${local_source_port}" "${tmp}/connect-payload.txt")"
echo "phase=tcp-connect:sidecars-started"

remote_connect_err="/tmp/derpcat-tcp-remote-connect.err"
remote "rm -f '${remote_base}.pid' '${remote_connect_err}'; nohup /usr/local/bin/derpcat listen --tcp-connect 127.0.0.1:${remote_sink_port} >/dev/null 2>'${remote_connect_err}' </dev/null & echo \$! > '${remote_base}.pid'"
echo "phase=tcp-connect:listener-started"
remote_token="$(wait_for_remote_token "${remote_connect_err}")" || {
  echo "failed to capture tcp-connect remote token" >&2
  remote "sed -n '1,200p' '${remote_connect_err}'" >&2 || true
  exit 1
}
echo "phase=tcp-connect:token"
dist/derpcat send "${remote_token}" --tcp-connect 127.0.0.1:${local_source_port} >"${tmp}/tcp-connect.out" 2>"${tmp}/tcp-connect.err"
echo "phase=tcp-connect:send-complete"
wait_for_local_pid_exit "${local_source_pid}" || {
  echo "local tcp-connect source did not exit" >&2
  exit 1
}
for _ in $(seq 1 120); do
  if ! remote "if [[ -f '${remote_base}.pid' ]]; then kill -0 \$(cat '${remote_base}.pid') 2>/dev/null; else false; fi" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
remote_connect_output="$(remote "cat '/tmp/derpcat-tcp-remote-connect.out'")"
if [[ "${remote_connect_output}" != "${connect_payload}" ]]; then
  echo "tcp-connect output mismatch" >&2
  printf 'want=%q\n' "${connect_payload}" >&2
  printf ' got=%q\n' "${remote_connect_output}" >&2
  remote "sed -n '1,200p' '${remote_connect_err}'" >&2 || true
  exit 1
fi
remote "grep -q 'stream-complete' '${remote_connect_err}'"
echo "phase=tcp-connect:done"

# Part B: tcp-listen on both ends
echo "phase=tcp-listen:start"
listen_payload="hello tcp-listen ${target} $(date +%s)"
printf '%s' "${listen_payload}" >"${tmp}/listen-payload.txt"
local_sink_port="$(free_local_port | tr -d '\n')"
remote_source_port="$(free_remote_port | tr -d '\n')"
remote_listen_payload="/tmp/derpcat-tcp-remote-listen.payload"
local_listener_log="${tmp}/local-tcp-listen.err"
local_listener_out="${tmp}/local-tcp-listener.out"

dist/derpcat listen --tcp-listen 127.0.0.1:${local_sink_port} >"${local_listener_out}" 2>"${local_listener_log}" &
local_listener_pid=$!
local_token="$(wait_for_local_token "${local_listener_log}")" || {
  echo "failed to capture local tcp-listen token" >&2
  sed -n '1,200p' "${local_listener_log}" >&2 || true
  exit 1
}
echo "phase=tcp-listen:token"
local_sink_file="${tmp}/tcp-listen-sink.out"
local_sink_pid="$(retry_local_nc 127.0.0.1 "${local_sink_port}" "${local_sink_file}")"

remote "printf '%s' '${listen_payload}' >'${remote_listen_payload}'; rm -f '/tmp/derpcat-tcp-remote-listen.err' '/tmp/derpcat-tcp-remote-listen.out'"
( remote "/usr/local/bin/derpcat send '${local_token}' --tcp-listen 127.0.0.1:${remote_source_port} >'/tmp/derpcat-tcp-remote-listen.out' 2>'/tmp/derpcat-tcp-remote-listen.err'" ) &
remote_sender_ssh_pid=$!
echo "phase=tcp-listen:remote-sender-started pid=${remote_sender_ssh_pid}"
retry_remote_send_nc "${remote_source_port}" "${remote_listen_payload}"
echo "phase=tcp-listen:remote-source-sent"

wait_for_local_exit "${local_listener_pid}" || {
  echo "local tcp-listen listener did not exit" >&2
  sed -n '1,200p' "${local_listener_log}" >&2 || true
  remote "sed -n '1,200p' '/tmp/derpcat-tcp-remote-listen.err'" >&2 || true
  exit 1
}
local_listener_pid=""
echo "phase=tcp-listen:listener-complete"
wait_for_local_pid_exit "${local_sink_pid}" || {
  echo "local tcp-listen sink did not exit" >&2
  exit 1
}
echo "phase=tcp-listen:sink-complete"
wait "${remote_sender_ssh_pid}"
remote_sender_ssh_pid=""
local_sink_output="$(cat "${local_sink_file}")"
if [[ "${local_sink_output}" != "${listen_payload}" ]]; then
  echo "tcp-listen output mismatch" >&2
  printf 'want=%q\n' "${listen_payload}" >&2
  printf ' got=%q\n' "${local_sink_output}" >&2
  sed -n '1,200p' "${local_listener_log}" >&2 || true
  remote "sed -n '1,200p' '/tmp/derpcat-tcp-remote-listen.err'" >&2 || true
  exit 1
fi
remote "grep -q 'stream-complete' '/tmp/derpcat-tcp-remote-listen.err'"
echo "phase=tcp-listen:done"

echo "target=${target}"
echo "tcp smoke passed"
