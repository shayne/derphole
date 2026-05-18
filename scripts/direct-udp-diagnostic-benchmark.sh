#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

usage() {
  echo "usage: $0 <sender-host> <receiver-host> [size-mib]" >&2
  echo "set DERPHOLE_DIAG_IPERF_EXTERNAL_HOST to compare against an already-running forwarded iperf3 server" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

sender_host="${1:?missing sender host}"
receiver_host="${2:?missing receiver host}"
size_mib="${3:-1024}"
size_bytes="$((size_mib * 1048576))"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
log_dir="${DERPHOLE_DIAG_LOG_DIR:-/tmp/derphole-direct-udp-diagnostic-${stamp}}"
iperf_port="${DERPHOLE_IPERF_PORT:-8321}"
iperf_parallel="${DERPHOLE_IPERF_PARALLEL:-4}"
iperf_udp_bitrate="${DERPHOLE_IPERF_UDP_BITRATE:-0}"
receiver_iperf_host="${DERPHOLE_DIAG_IPERF_HOST:-${receiver_host#*@}}"
external_iperf_host="${DERPHOLE_DIAG_IPERF_EXTERNAL_HOST:-}"
start_local_iperf="${DERPHOLE_DIAG_IPERF_START_LOCAL_SERVER:-0}"
tcp_error=""
udp_error=""
tcp_goodput="0.00"
udp_goodput="0.00"
udp_loss="0.00"
local_iperf_pid=""

mkdir -p "${log_dir}/iperf" "${log_dir}/transfer"

normalize_target() {
  local target="$1"
  if [[ "${target}" == *"@"* ]]; then
    printf '%s\n' "${target}"
    return 0
  fi
  printf '%s@%s\n' "${DERPHOLE_REMOTE_USER:-root}" "${target}"
}

remote_sh() {
  local target="$1"
  shift
  LC_ALL=C LANG=C ssh "${target}" 'bash -se' -- "$@"
}

local_iperf_bin() {
  if command -v iperf3 >/dev/null 2>&1; then
    printf '%s\n' "iperf3"
    return 0
  fi
  if command -v nix >/dev/null 2>&1; then
    printf '%s\n' "nix run nixpkgs#iperf3 --"
    return 0
  fi
  echo "iperf3 not found locally" >&2
  return 1
}

cleanup() {
  if [[ -n "${remote_iperf_pid:-}" && -n "${remote_iperf_target:-}" ]]; then
    remote_sh "${remote_iperf_target}" "${remote_iperf_pid}" <<'REMOTE' >/dev/null 2>&1 || true
pid="$1"
kill "${pid}" 2>/dev/null || true
REMOTE
  fi
  if [[ -n "${local_iperf_pid}" ]]; then
    kill "${local_iperf_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

sender_target="$(normalize_target "${sender_host}")"
receiver_target="$(normalize_target "${receiver_host}")"

start_remote_iperf_server() {
  local mode="$1"
  remote_sh "${receiver_target}" "${iperf_port}" "${mode}" <<'REMOTE'
set -euo pipefail
port="$1"
mode="$2"
iperf_bin="$(command -v /usr/bin/iperf3 2>/dev/null || command -v iperf3)"
"${iperf_bin}" -s -4 -p "${port}" -1 >"/tmp/derphole-diag-iperf-${mode}-server.log" 2>&1 &
echo "$!"
REMOTE
}

fetch_remote_iperf_server_log() {
  local mode="$1"
  remote_sh "${receiver_target}" "${mode}" <<'REMOTE' >"${log_dir}/iperf/${mode}-server.log" || true
mode="$1"
cat "/tmp/derphole-diag-iperf-${mode}-server.log" 2>/dev/null || true
REMOTE
}

stop_remote_iperf_server() {
  if [[ -z "${remote_iperf_pid:-}" || -z "${remote_iperf_target:-}" ]]; then
    return 0
  fi
  remote_sh "${remote_iperf_target}" "${remote_iperf_pid}" <<'REMOTE' >/dev/null 2>&1 || true
pid="$1"
kill "${pid}" 2>/dev/null || true
REMOTE
  remote_iperf_pid=""
  remote_iperf_target=""
}

start_local_iperf_server() {
  local mode="$1"
  local bin
  bin="$(local_iperf_bin)"
  # shellcheck disable=SC2086
  ${bin} -s -4 -p "${iperf_port}" -1 >"${log_dir}/iperf/${mode}-local-server.log" 2>&1 &
  local_iperf_pid="$!"
}

run_remote_iperf_client() {
  local mode="$1"
  local host="$2"
  local out_file="$3"
  local err_file="$4"
  remote_sh "${sender_target}" "${host}" "${iperf_port}" "${size_bytes}" "${iperf_parallel}" "${mode}" "${iperf_udp_bitrate}" <<'REMOTE' >"${out_file}" 2>"${err_file}"
set -euo pipefail
host="$1"
port="$2"
size_bytes="$3"
parallel="$4"
mode="$5"
udp_bitrate="$6"
iperf_bin="$(command -v /usr/bin/iperf3 2>/dev/null || command -v iperf3)"
if [[ "${mode}" == "udp" ]]; then
  exec "${iperf_bin}" -4 -u -J --connect-timeout 5000 -c "${host}" -p "${port}" -b "${udp_bitrate}" -n "${size_bytes}" -P "${parallel}"
fi
exec "${iperf_bin}" -4 -J --connect-timeout 5000 -c "${host}" -p "${port}" -n "${size_bytes}" -P "${parallel}"
REMOTE
}

parse_iperf_summary() {
  local file="$1"
  python3 - <<'PY' "${file}"
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception:
    print("0.00 0.00")
    raise SystemExit(0)

end = data.get("end", {})
summary = (
    end.get("sum_received")
    or end.get("sum")
    or end.get("sum_sent")
    or {}
)
goodput = float(summary.get("bits_per_second", 0.0)) / 1_000_000.0
loss = float(summary.get("lost_percent", 0.0) or 0.0)
print(f"{goodput:.2f} {loss:.2f}")
PY
}

run_iperf_mode() {
  local mode="$1"
  local out_file="${log_dir}/iperf/${mode}-client.json"
  local err_file="${log_dir}/iperf/${mode}-client.err"
  local host="${external_iperf_host:-${receiver_iperf_host}}"
  remote_iperf_pid=""
  remote_iperf_target=""
  local_iperf_pid=""

  set +e
  if [[ -z "${external_iperf_host}" ]]; then
    remote_iperf_target="${receiver_target}"
    remote_iperf_pid="$(start_remote_iperf_server "${mode}")"
    sleep 1
  elif [[ "${start_local_iperf}" == "1" ]]; then
    start_local_iperf_server "${mode}"
    sleep 1
  fi

  run_remote_iperf_client "${mode}" "${host}" "${out_file}" "${err_file}"
  local status=$?
  if [[ -n "${remote_iperf_pid}" ]]; then
    fetch_remote_iperf_server_log "${mode}"
    stop_remote_iperf_server
  fi
  if [[ -n "${local_iperf_pid}" ]]; then
    wait "${local_iperf_pid}" >/dev/null 2>&1 || true
    local_iperf_pid=""
  fi
  set -e

  if (( status != 0 )); then
    printf 'iperf-%s-exit-%s\n' "${mode}" "${status}"
    return 0
  fi
  parse_iperf_summary "${out_file}"
}

read -r tcp_goodput tcp_loss_or_error < <(run_iperf_mode tcp)
if [[ "${tcp_goodput}" == iperf-tcp-exit-* ]]; then
  tcp_error="${tcp_goodput}"
  tcp_goodput="0.00"
fi
read -r udp_goodput udp_loss_or_error < <(run_iperf_mode udp)
if [[ "${udp_goodput}" == iperf-udp-exit-* ]]; then
  udp_error="${udp_goodput}"
  udp_goodput="0.00"
else
  udp_loss="${udp_loss_or_error:-0.00}"
fi

transfer_status=0
set +e
DERPHOLE_STALL_LOG_DIR="${log_dir}/transfer" \
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES="${DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES:-1}" \
DERPHOLE_DIRECT_TRANSPORT="${DERPHOLE_DIRECT_TRANSPORT:-}" \
./scripts/transfer-stall-harness.sh "${sender_host}" "${receiver_host}" "${size_mib}" | tee "${log_dir}/transfer/harness.out"
transfer_status=${PIPESTATUS[0]}
set -e

find_metric() {
  local key="$1"
  local matches
  matches="$(find "${log_dir}/transfer" -maxdepth 3 -type f -exec grep -Ih "${key}=" {} + 2>/dev/null || true)"
  printf '%s\n' "${matches}" \
    | sed "s/^.*${key}=//" \
    | tail -n 1
}

find_trace_metric() {
  local key="$1"
  awk -v key="${key}" '
    /trace-ok/ {
      for (i = 1; i <= NF; i++) {
        split($i, parts, "=")
        if (parts[1] == key) {
          value = parts[2]
        }
      }
    }
    END {
      if (value != "") {
        print value
      }
    }
  ' "${log_dir}/transfer/harness.out" 2>/dev/null || true
}

fill_zero_metric() {
  local current="$1"
  local fallback="$2"
  if [[ -z "${current}" || "${current}" == "0" || "${current}" == "0.00" ]]; then
    printf '%s\n' "${fallback}"
    return 0
  fi
  printf '%s\n' "${current}"
}

probe_samples="$(find_metric "udp-rate-probe-samples")"
sender_goodput="$(find_metric "udp-send-goodput-mbps")"
receiver_goodput="$(find_metric "udp-receive-goodput-mbps")"
sender_peak="$(find_metric "udp-send-peak-goodput-mbps")"
receiver_peak="$(find_metric "udp-receive-peak-goodput-mbps")"
queue_depth="$(find_metric "transport-max-peer-recv-queue-depth")"
sender_goodput="$(fill_zero_metric "${sender_goodput}" "$(find_trace_metric "sender_mbps")")"
receiver_goodput="$(fill_zero_metric "${receiver_goodput}" "$(find_trace_metric "receiver_mbps")")"

{
  echo "diagnostic-log-dir=${log_dir}"
  echo "diagnostic-size-bytes=${size_bytes}"
  echo "diagnostic-iperf-host=${external_iperf_host:-${receiver_iperf_host}}"
  echo "diagnostic-iperf-port=${iperf_port}"
  echo "diagnostic-iperf-parallel=${iperf_parallel}"
  echo "diagnostic-iperf-udp-bitrate=${iperf_udp_bitrate}"
  echo "diagnostic-iperf-goodput-mbps=${tcp_goodput:-0.00}"
  echo "diagnostic-iperf-tcp-goodput-mbps=${tcp_goodput:-0.00}"
  echo "diagnostic-iperf-udp-goodput-mbps=${udp_goodput:-0.00}"
  echo "diagnostic-iperf-udp-loss-percent=${udp_loss:-0.00}"
  echo "diagnostic-transfer-sender-goodput-mbps=${sender_goodput:-0}"
  echo "diagnostic-transfer-receiver-goodput-mbps=${receiver_goodput:-0}"
  echo "diagnostic-transfer-sender-peak-goodput-mbps=${sender_peak:-0}"
  echo "diagnostic-transfer-receiver-peak-goodput-mbps=${receiver_peak:-0}"
  echo "diagnostic-transport-max-peer-recv-queue-depth=${queue_depth:-0}"
  echo "diagnostic-probe-samples=${probe_samples:-}"
  echo "diagnostic-transfer-status=${transfer_status}"
  if [[ -n "${tcp_error}" ]]; then
    echo "diagnostic-iperf-tcp-error=${tcp_error}"
  fi
  if [[ -n "${udp_error}" ]]; then
    echo "diagnostic-iperf-udp-error=${udp_error}"
  fi
} | tee "${log_dir}/diagnostic-summary.env"

exit "${transfer_status}"
