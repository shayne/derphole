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

DERPSSH_TEST_AUTO_APPROVE=write DERPSSH_TEST_COMMAND="printf ready; read line; printf input:%s \"\$line\"" \
  dist/derpssh share >"$share_out" 2>"$share_err" &
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

printf 'hello\n' | dist/derpssh connect --name smoke "$invite" >"$connect_out" 2>"$connect_err" &
connect_pid=$!

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
  for _ in $(seq 1 100); do
    if grep -F 'input:hello' "$share_out" >/dev/null 2>&1; then
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
