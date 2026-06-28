#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

mise run build
test -x dist/derpssh

tmp=$(mktemp -d "${TMPDIR:-/tmp}/derpssh-local.XXXXXXXXXX")
cleanup() {
  if [[ -n "${connect_fd:-}" ]]; then
    exec {connect_fd}>&- || true
  fi
  if [[ -n "${share_fd:-}" ]]; then
    exec {share_fd}>&- || true
  fi
  if [[ -n "${connect_pid:-}" ]]; then
    kill "$connect_pid" 2>/dev/null || true
    wait "$connect_pid" 2>/dev/null || true
  fi
  if [[ -n "${share_pid:-}" ]]; then
    kill "$share_pid" 2>/dev/null || true
    wait "$share_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

share_out="$tmp/share.out"
share_err="$tmp/share.err"
connect_out="$tmp/connect.out"
connect_err="$tmp/connect.err"
share_in="$tmp/share.in"
connect_in="$tmp/connect.in"

wait_for_contains() {
  local file="$1"
  local want="$2"
  for _ in $(seq 1 100); do
    if grep -F "$want" "$file" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_local_exit() {
  local pid="$1"
  local name="$2"
  for _ in $(seq 1 150); do
    if ! jobs -pr | grep -qx "$pid"; then
      wait "$pid" 2>/dev/null || true
      return 0
    fi
    sleep 0.1
  done
  echo "${name} did not exit after host quit" >&2
  return 1
}

mkfifo "$share_in" "$connect_in"
exec {share_fd}<>"$share_in"
exec {connect_fd}<>"$connect_in"

DERPSSH_TEST_HARNESS=1 \
DERPSSH_TEST_AUTO_APPROVE=write \
DERPSSH_TEST_COMMAND="printf ready; read line; printf input:%s \"\$line\"" \
DERPSSH_TEST_HOST_ACTIONS=$'chat host-side\nsleep 5s\nquit' \
  dist/derpssh share <&$share_fd >"$share_out" 2>"$share_err" &
share_pid=$!

for _ in $(seq 1 100); do
  if grep -E 'derpssh(@latest)? connect ' "$share_err" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

connect_line=$(grep -Eo '(npx -y derpssh@latest connect|dist/derpssh connect) [^[:space:]]+' "$share_err" | head -n1 || true)
invite="${connect_line##* }"
if [[ -z "$connect_line" || -z "$invite" ]]; then
  echo "failed to capture derpssh connect command" >&2
  cat "$share_err" >&2
  exit 1
fi

DERPSSH_TEST_HARNESS=1 \
DERPSSH_TEST_GUEST_ACTIONS=$'chat guest-side\ninput hello\\n\n' \
  dist/derpssh connect --name smoke "$invite" <&$connect_fd >"$connect_out" 2>"$connect_err" &
connect_pid=$!

for _ in $(seq 1 100); do
  if grep -F 'role: write' "$connect_out" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$connect_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if ! grep -F 'role: write' "$connect_out" >/dev/null 2>&1; then
  echo "failed to observe derpssh write promotion" >&2
  cat "$connect_out" >&2
  cat "$connect_err" >&2
  cat "$share_out" >&2
  cat "$share_err" >&2
  exit 1
fi

for _ in $(seq 1 100); do
  if grep -F 'input:hello' "$connect_out" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$connect_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if grep -F 'input:hello' "$connect_out" >/dev/null 2>&1; then
  for want in 'terminal:' 'chat:' 'guest-side' 'host-side'; do
    if ! wait_for_contains "$connect_out" "$want"; then
      echo "connect TUI missing $want" >&2
      cat "$connect_out" >&2
      exit 1
    fi
    if ! wait_for_contains "$share_out" "$want"; then
      echo "share TUI missing $want" >&2
      cat "$share_out" >&2
      exit 1
    fi
  done
  if ! wait_for_contains "$connect_out" 'role: write'; then
    echo "connect TUI missing role: write" >&2
    cat "$connect_out" >&2
    exit 1
  fi
  if ! wait_for_contains "$share_out" 'peer: smoke/write'; then
    echo "share TUI missing peer: smoke/write" >&2
    cat "$share_out" >&2
    exit 1
  fi
  for _ in $(seq 1 100); do
    if grep -F 'input:hello' "$share_out" >/dev/null 2>&1; then
      if ! wait_for_local_exit "$connect_pid" "connect"; then
        cat "$connect_out" >&2
        cat "$connect_err" >&2
        exit 1
      fi
      connect_pid=""
      if ! wait_for_local_exit "$share_pid" "share"; then
        cat "$share_out" >&2
        cat "$share_err" >&2
        exit 1
      fi
      share_pid=""
      exit 0
    fi
    sleep 0.1
  done
  echo "failed to observe derpssh host terminal echo" >&2
  cat "$share_out" >&2
  cat "$share_err" >&2
  exit 1
fi

echo "failed to observe derpssh terminal echo" >&2
cat "$connect_out" >&2
cat "$connect_err" >&2
exit 1
