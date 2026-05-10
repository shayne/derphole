#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

tmp="$(mktemp -d)"
cleanup() {
  if [[ -n "${listener_pid:-}" ]]; then
    kill "${listener_pid}" 2>/dev/null || true
    wait "${listener_pid}" 2>/dev/null || true
  fi
  if [[ -n "${open_pid:-}" ]]; then
    kill "${open_pid}" 2>/dev/null || true
    wait "${open_pid}" 2>/dev/null || true
  fi
  if [[ -n "${share_pid:-}" ]]; then
    kill "${share_pid}" 2>/dev/null || true
    wait "${share_pid}" 2>/dev/null || true
  fi
  if [[ -n "${http_pid:-}" ]]; then
    kill "${http_pid}" 2>/dev/null || true
    wait "${http_pid}" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

mise run build

listener_log="$tmp/listener.log"
sender_log="$tmp/sender.log"
output_file="$tmp/output.txt"
share_log="$tmp/share.log"
open_log="$tmp/open.log"
http_dir="$tmp/http"
mkdir -p "$http_dir"

dist/derphole listen >"$output_file" 2>"$listener_log" &
listener_pid=$!

token=""
for _ in $(seq 1 100); do
  token="$(grep -E '^[A-Za-z0-9_-]{20,}$' "$listener_log" | head -n 1 || true)"
  if [[ -n "$token" ]]; then
    break
  fi
  sleep 0.1
done

if [[ -z "$token" ]]; then
  echo "failed to capture listener token" >&2
  exit 1
fi

printf 'hello smoke' | dist/derphole pipe "$token" >"$tmp/sender.out" 2>"$sender_log"
wait "$listener_pid"

test "$(cat "$output_file")" = "hello smoke"

http_port="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
printf 'hello shared smoke\n' >"$http_dir/index.html"
python3 -m http.server "$http_port" --bind 127.0.0.1 --directory "$http_dir" >"$tmp/http.log" 2>&1 &
http_pid=$!

dist/derphole share "127.0.0.1:${http_port}" >"$tmp/share.out" 2>"$share_log" &
share_pid=$!

share_token=""
for _ in $(seq 1 100); do
  share_token="$(grep -E '^[A-Za-z0-9_-]{20,}$' "$share_log" | head -n 1 || true)"
  if [[ -n "$share_token" ]]; then
    break
  fi
  sleep 0.1
done

if [[ -z "$share_token" ]]; then
  echo "failed to capture share token" >&2
  exit 1
fi

dist/derphole open "$share_token" >"$tmp/open.out" 2>"$open_log" &
open_pid=$!

bind_addr=""
for _ in $(seq 1 100); do
  bind_addr="$(grep -Eo 'listening on 127\.0\.0\.1:[0-9]+' "$open_log" | awk '{print $3}' | tail -n 1 || true)"
  if [[ -n "$bind_addr" ]]; then
    break
  fi
  sleep 0.1
done

if [[ -z "$bind_addr" ]]; then
  echo "failed to capture open bind address" >&2
  exit 1
fi

test "$(curl --fail --silent "http://${bind_addr}/")" = "hello shared smoke"
test "$(curl --fail --silent "http://${bind_addr}/")" = "hello shared smoke"

kill "$open_pid" 2>/dev/null || true
wait "$open_pid" 2>/dev/null || true
kill "$share_pid" 2>/dev/null || true
wait "$share_pid" 2>/dev/null || true
