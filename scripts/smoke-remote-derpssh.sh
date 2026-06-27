#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

target="${1:?usage: smoke-remote-derpssh.sh HOST}"
root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp="$(mktemp -d)"
remote_user="${DERPHOLE_REMOTE_USER:-root}"
remote_target="${remote_user}@${target}"
remote_tmp=""
remote_base=""
remote_upload=""
remote_bin=""
connect_pid=""
connect_in="${tmp}/connect.in"
connect_out="${tmp}/connect.out"
connect_err="${tmp}/connect.err"
connect_fd=""
remote_env=()

if [[ "${target}" == *@* ]]; then
  remote_target="${target}"
fi
if [[ "${DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES:-}" == "1" ]]; then
  remote_env+=(DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1)
fi

remote() {
  ssh "${remote_target}" "${remote_env[@]}" 'bash -se' <<<"$1"
}

remote_tmp="$(remote 'mktemp -d "${TMPDIR:-/tmp}/derpssh-smoke.XXXXXXXXXX"')"
remote_base="${remote_tmp}/derpssh-smoke"
remote_upload="${remote_tmp}/derpssh-bin"
remote_bin="${remote_tmp}/derpssh"

cleanup() {
  if [[ -n "${connect_fd}" ]]; then
    exec {connect_fd}>&- || true
  fi
  if [[ -n "${connect_pid}" ]]; then
    kill "${connect_pid}" 2>/dev/null || true
    wait "${connect_pid}" 2>/dev/null || true
  fi
  if [[ -n "${remote_tmp}" ]]; then
    remote "if [[ -f '${remote_base}.share.pid' ]]; then kill \$(cat '${remote_base}.share.pid') 2>/dev/null || true; fi; rm -rf -- '${remote_tmp}'" >/dev/null 2>&1 || true
  fi
  rm -rf "${tmp}"
}
trap cleanup EXIT

wait_for_remote_invite() {
  local connect_line=""
  for _ in $(seq 1 180); do
    connect_line="$(remote "grep -Eo '(npx -y derpssh@latest connect|dist/derpssh connect) [^[:space:]]+' '${remote_base}.share.err' | head -n 1 || true")"
    if [[ -n "${connect_line}" ]]; then
      printf '%s\n' "${connect_line}"
      return 0
    fi
    sleep 0.25
  done
  return 1
}

path_trace() {
  local file="$1"
  grep -E 'connected-(relay|direct)|v2-data-plane=raw-direct|v2-raw-direct-active=[1-9][0-9]*' "${file}" 2>/dev/null || true
}

remote_path_trace() {
  local file="$1"
  remote "grep -E 'connected-(relay|direct)|v2-data-plane=raw-direct|v2-raw-direct-active=[1-9][0-9]*' '${file}' 2>/dev/null || true"
}

dump_logs() {
  echo '--- local connect err' >&2
  sed -n '1,220p' "${connect_err}" >&2 || true
  echo '--- local connect out' >&2
  sed -n '1,220p' "${connect_out}" >&2 || true
  echo '--- remote share err' >&2
  remote "sed -n '1,220p' '${remote_base}.share.err' 2>/dev/null || true" >&2 || true
  echo '--- remote share out' >&2
  remote "sed -n '1,220p' '${remote_base}.share.out' 2>/dev/null || true" >&2 || true
}

mise run build
mise run build-linux-amd64
scp "${root_dir}/dist/derpssh-linux-amd64" "${remote_target}:${remote_upload}" >/dev/null
remote "install -m 0755 '${remote_upload}' '${remote_bin}' && rm -f '${remote_upload}' && '${remote_bin}' version >/dev/null"

echo "starting remote derpssh share on ${remote_target}" >&2
remote "rm -f '${remote_base}.share.pid' '${remote_base}.share.out' '${remote_base}.share.err' '${remote_base}.share.in'; mkfifo '${remote_base}.share.in'; exec 9<>'${remote_base}.share.in'; env DERPSSH_TEST_AUTO_APPROVE=read DERPSSH_TEST_COMMAND='printf ready; read line; printf input:%s \"\$line\"' nohup '${remote_bin}' --verbose share <&9 >'${remote_base}.share.out' 2>'${remote_base}.share.err' & echo \$! >'${remote_base}.share.pid'"

connect_line="$(wait_for_remote_invite)" || {
  echo "failed to capture remote derpssh connect command" >&2
  dump_logs
  exit 1
}
invite="${connect_line##* }"
if [[ -z "${invite}" ]]; then
  echo "remote derpssh connect command did not include an invite" >&2
  dump_logs
  exit 1
fi

mkfifo "${connect_in}"
exec {connect_fd}<>"${connect_in}"
"${root_dir}/dist/derpssh" --verbose connect --name smoke "${invite}" <&$connect_fd >"${connect_out}" 2>"${connect_err}" &
connect_pid=$!

printf ':chat guest-side\n' >&$connect_fd
remote "printf '%s\n' ':chat host-side' ':write' > '${remote_base}.share.in'"

for _ in $(seq 1 180); do
  if grep -F 'role write' "${connect_out}" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${connect_pid}" 2>/dev/null; then
    break
  fi
  sleep 0.25
done
if ! grep -F 'role write' "${connect_out}" >/dev/null 2>&1; then
  echo "failed to observe remote derpssh write promotion" >&2
  dump_logs
  exit 1
fi

printf 'hello\n' >&$connect_fd

for _ in $(seq 1 180); do
  if grep -F 'input:hello' "${connect_out}" >/dev/null 2>&1; then
    for _ in $(seq 1 180); do
      if remote "grep -F 'input:hello' '${remote_base}.share.out' >/dev/null 2>&1"; then
        break
      fi
      sleep 0.25
    done
    if ! remote "grep -F 'input:hello' '${remote_base}.share.out' >/dev/null 2>&1"; then
      echo "failed to observe remote derpssh host terminal echo" >&2
      dump_logs
      exit 1
    fi
    for want in 'terminal' 'sidechat' 'status' 'guest-side' 'host-side'; do
      if ! grep -F "${want}" "${connect_out}" >/dev/null 2>&1; then
        echo "local connect TUI missing ${want}" >&2
        dump_logs
        exit 1
      fi
      if ! remote "grep -F '${want}' '${remote_base}.share.out' >/dev/null 2>&1"; then
        echo "remote share TUI missing ${want}" >&2
        dump_logs
        exit 1
      fi
    done
    connect_trace="$(path_trace "${connect_err}")"
    share_trace="$(remote_path_trace "${remote_base}.share.err")"
    if [[ -n "${connect_trace}" ]]; then
      printf 'connect path trace:\n%s\n' "${connect_trace}" >&2
    fi
    if [[ -n "${share_trace}" ]]; then
      printf 'share path trace:\n%s\n' "${share_trace}" >&2
    fi
    exit 0
  fi
  if ! kill -0 "${connect_pid}" 2>/dev/null; then
    break
  fi
  sleep 0.25
done

echo "failed to observe remote derpssh terminal echo" >&2
dump_logs
exit 1
