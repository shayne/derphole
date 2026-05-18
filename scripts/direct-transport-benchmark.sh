#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

usage() {
  echo "usage: $0 <sender-host> <receiver-host> [size-mib]" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

sender_host="${1:?missing sender host}"
receiver_host="${2:?missing receiver host}"
size_mib="${3:-1024}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
log_dir="${DERPHOLE_DIRECT_TRANSPORT_LOG_DIR:-/tmp/derphole-direct-transport-${stamp}}"
diag_dir="${log_dir}/diag"
summary="${diag_dir}/diagnostic-summary.env"

# The wrapped diagnostic summary provides diagnostic-iperf-tcp-goodput-mbps,
# diagnostic-transfer-sender-goodput-mbps, and
# diagnostic-transfer-receiver-goodput-mbps for direct transport comparisons.
mkdir -p "${diag_dir}"

status=0
set +e
DERPHOLE_DIAG_LOG_DIR="${diag_dir}" \
DERPHOLE_DIRECT_TRANSPORT=quic \
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES="${DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES:-1}" \
./scripts/direct-udp-diagnostic-benchmark.sh "${sender_host}" "${receiver_host}" "${size_mib}"
status=$?
set -e

{
  echo "diagnostic-direct-transport=quic"
  if [[ -f "${summary}" ]]; then
    cat "${summary}"
  else
    echo "diagnostic-log-dir=${diag_dir}"
    echo "diagnostic-transfer-status=${status}"
  fi
} | tee "${log_dir}/diagnostic-summary.env"

exit "${status}"
