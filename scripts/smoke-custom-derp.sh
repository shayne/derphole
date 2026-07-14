#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

derphole_bin="${DERPHOLE_BIN:-dist/derphole}"
legacy_bin="${DERPHOLE_LEGACY_BIN:-}"
inspect="${DERPHOLE_SMOKE_INSPECT:-0}"
tmp="$(mktemp -d)"
listener_log="${tmp}/listener.err"
listener_out="${tmp}/listener.out"
consumer_log="${tmp}/consumer.err"
consumer_out="${tmp}/consumer.out"
legacy_log="${tmp}/legacy.err"
legacy_out="${tmp}/legacy.out"
listener_pid=""
consumer_pid=""
legacy_pid=""
consumer_input_open=0
socket_summary=""

touch "${listener_log}" "${listener_out}" "${consumer_log}" "${consumer_out}" "${legacy_log}" "${legacy_out}"

dump_logs() {
  echo "--- custom DERP listener log" >&2
  cat "${listener_log}" >&2 || true
  echo "--- custom DERP consumer log" >&2
  cat "${consumer_log}" >&2 || true
  if [[ -n "${legacy_bin}" ]]; then
    echo "--- legacy consumer log" >&2
    cat "${legacy_log}" >&2 || true
  fi
}

stop_process() {
  local pid="$1"
  if [[ -n "${pid}" ]]; then
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  fi
}

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if (( consumer_input_open )); then
    exec 3>&- || true
  fi
  stop_process "${legacy_pid}"
  stop_process "${consumer_pid}"
  stop_process "${listener_pid}"
  if (( status != 0 )); then
    dump_logs
  fi
  rm -rf "${tmp}"
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  echo "custom DERP smoke failed: $*" >&2
  exit 1
}

wait_for_exit() {
  local pid="$1"
  for _ in $(seq 1 300); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

token_from_log() {
  tr -d '\r' <"$1" | awk 'length($0) >= 20 && $0 ~ /^[A-Za-z0-9_-]+$/ { print; exit }'
}

wait_for_token() {
  local token=""
  for _ in $(seq 1 100); do
    token="$(token_from_log "${listener_log}")"
    if [[ -n "${token}" ]]; then
      printf '%s\n' "${token}"
      return 0
    fi
    if ! kill -0 "${listener_pid}" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  return 1
}

wait_for_log_marker() {
  local log_file="$1"
  local marker="$2"
  for _ in $(seq 1 100); do
    if grep -Fq "${marker}" "${log_file}"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

parse_custom_endpoint() {
  local server="${DERPHOLE_DERP_SERVER#https://}"
  local authority="${server%%/*}"
  custom_host=""
  custom_port="443"

  if [[ "${authority}" =~ ^\[([^]]+)\](:([0-9]+))?$ ]]; then
    custom_host="${BASH_REMATCH[1]}"
    custom_port="${BASH_REMATCH[3]:-443}"
  elif [[ "${authority}" =~ ^([^:]+)(:([0-9]+))?$ ]]; then
    custom_host="${BASH_REMATCH[1]}"
    custom_port="${BASH_REMATCH[3]:-443}"
  fi
  [[ -n "${custom_host}" ]] || fail "cannot inspect malformed DERPHOLE_DERP_SERVER authority"
}

capture_socket_evidence() {
  local pid="$1"
  local name="$2"
  local all_file="${tmp}/${name}.lsof"
  local custom_file="${tmp}/${name}.custom.lsof"
  local named_file="${tmp}/${name}.named.lsof"
  local lsof_host="${custom_host}"
  local all_count=0
  local custom_count=0

  if [[ "${lsof_host}" == *:* ]]; then
    lsof_host="[${lsof_host}]"
  fi
  lsof -nP -a -p "${pid}" -iTCP -sTCP:ESTABLISHED >"${all_file}" 2>/dev/null || true
  lsof -nP -a -p "${pid}" -iTCP@"${lsof_host}:${custom_port}" -sTCP:ESTABLISHED >"${custom_file}" 2>/dev/null || true
  lsof -P -a -p "${pid}" -iTCP -sTCP:ESTABLISHED >"${named_file}" 2>/dev/null || true

  all_count="$(awk 'NR > 1 { count++ } END { print count + 0 }' "${all_file}")"
  custom_count="$(awk 'NR > 1 { count++ } END { print count + 0 }' "${custom_file}")"
  (( custom_count > 0 )) || fail "${name} has no established TCP socket to ${custom_host}:${custom_port}"
  (( all_count == custom_count )) || fail "${name} has an established TCP socket outside the custom DERP destination"
  if grep -Eiq 'derp1|derp2|tailscale\.com|controlplane\.tailscale\.com' "${named_file}"; then
    fail "${name} connected to a public Tailscale DERP destination"
  fi

  awk 'NR > 1 { print $9 }' "${all_file}" | paste -sd, -
}

run_legacy_check() {
  local token="$1"
  local legacy_status=0
  local exited=0

  [[ -x "${legacy_bin}" ]] || fail "DERPHOLE_LEGACY_BIN is not executable: ${legacy_bin}"
  env -u DERPHOLE_DERP_SERVER "${legacy_bin}" --verbose pipe "${token}" </dev/null >"${legacy_out}" 2>"${legacy_log}" &
  legacy_pid=$!
  for _ in $(seq 1 30); do
    if ! kill -0 "${legacy_pid}" 2>/dev/null; then
      exited=1
      break
    fi
    sleep 0.1
  done
  (( exited )) || fail "legacy consumer did not reject the custom token immediately"
  if wait "${legacy_pid}"; then
    legacy_status=0
  else
    legacy_status=$?
  fi
  legacy_pid=""
  (( legacy_status != 0 )) || fail "legacy consumer accepted the custom token"
  grep -Fq 'token unsupported version' "${legacy_log}" || fail "legacy consumer did not report the unsupported token version"
  if grep -Fq 'connected-relay' "${legacy_log}"; then
    fail "legacy consumer connected to a relay before rejecting the custom token"
  fi
}

assert_session_log() {
  local log_file="$1"
  local name="$2"
  grep -Fq 'derp-route=custom' "${log_file}" || fail "${name} did not report derp-route=custom"
  grep -Fq 'connected-relay' "${log_file}" || fail "${name} did not report connected-relay"
  if grep -Eiq 'connected-direct|derp1|derp2|tailscale\.com|controlplane\.tailscale\.com' "${log_file}"; then
    fail "${name} reported a direct or public Tailscale DERP path"
  fi
}

[[ -n "${DERPHOLE_DERP_SERVER:-}" ]] || fail "DERPHOLE_DERP_SERVER is required"
[[ -x "${derphole_bin}" ]] || fail "DERPHOLE_BIN is not executable: ${derphole_bin}"
if [[ "${inspect}" == "1" ]] && command -v lsof >/dev/null 2>&1; then
  parse_custom_endpoint
fi

DERPHOLE_DERP_SERVER="${DERPHOLE_DERP_SERVER}" \
  "${derphole_bin}" --verbose listen --force-relay >"${listener_out}" 2>"${listener_log}" &
listener_pid=$!

token="$(wait_for_token)" || fail "could not capture a token-shaped listener line"
if [[ -n "${legacy_bin}" ]]; then
  run_legacy_check "${token}"
fi

payload_file="${tmp}/payload"
consumer_input="${tmp}/consumer.input"
printf '%s' 'derphole custom DERP smoke payload' >"${payload_file}"
mkfifo "${consumer_input}"
exec 3<>"${consumer_input}"
consumer_input_open=1
env -u DERPHOLE_DERP_SERVER \
  "${derphole_bin}" --verbose pipe "${token}" --force-relay \
  3>&- <"${consumer_input}" >"${consumer_out}" 2>"${consumer_log}" &
consumer_pid=$!
cat "${payload_file}" >&3

if [[ "${inspect}" == "1" ]] && command -v lsof >/dev/null 2>&1; then
  wait_for_log_marker "${listener_log}" 'connected-relay' || fail "listener did not connect before socket inspection"
  wait_for_log_marker "${consumer_log}" 'connected-relay' || fail "consumer did not connect before socket inspection"
  listener_sockets="$(capture_socket_evidence "${listener_pid}" listener)"
  consumer_sockets="$(capture_socket_evidence "${consumer_pid}" consumer)"
  socket_summary="; sockets=${listener_sockets},${consumer_sockets}"
  sleep 5
fi

exec 3>&-
consumer_input_open=0
wait_for_exit "${consumer_pid}" || fail "consumer did not exit"
if ! wait "${consumer_pid}"; then
  consumer_pid=""
  fail "consumer exited unsuccessfully"
fi
consumer_pid=""
wait_for_exit "${listener_pid}" || fail "listener did not exit"
if ! wait "${listener_pid}"; then
  listener_pid=""
  fail "listener exited unsuccessfully"
fi
listener_pid=""

cmp -s "${payload_file}" "${listener_out}" || fail "payload bytes differ"
assert_session_log "${listener_log}" listener
assert_session_log "${consumer_log}" consumer

legacy_summary=""
if [[ -n "${legacy_bin}" ]]; then
  legacy_summary="; legacy-v6=rejected"
fi
printf 'custom DERP smoke passed: payload=exact; route=custom; transport=relay%s%s\n' "${legacy_summary}" "${socket_summary}"
