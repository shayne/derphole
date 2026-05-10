#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

size_bytes_values=(10240 1048576 10485760 52428800 134217728 1073741824)
probe_mode="${DERPHOLE_PROBE_MODE:-raw}"
probe_transport="${DERPHOLE_PROBE_TRANSPORT:-}"
if [[ -z "${probe_transport}" ]]; then
  if [[ "${probe_mode}" == "wg" ]]; then
    probe_transport="batched"
  else
    probe_transport="legacy"
  fi
fi

for host in ktzlxc canlxc uklxc november-oscar.exe.xyz eric@eric-nuc; do
  for size_bytes in "${size_bytes_values[@]}"; do
    DERPHOLE_PROBE_MODE="${probe_mode}" DERPHOLE_PROBE_TRANSPORT="${probe_transport}" ./scripts/probe-benchmark.sh "${host}" "${size_bytes}"
  done
done
