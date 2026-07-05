#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

usage() {
  echo "usage: scripts/toposim-linux.sh [--quick] [--run PATTERN]" >&2
}

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "toposim-linux requires ${tool}" >&2
    exit 1
  fi
}

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "toposim-linux requires Linux network namespace support" >&2
  exit 77
fi

require_tool ip
require_tool iptables
require_tool tc
require_tool sudo

pattern='TestTopology|TestLinuxLab'
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)
      pattern='TestTopology|TestLinuxLab'
      shift
      ;;
    --run)
      if [[ $# -lt 2 ]]; then
        usage
        exit 2
      fi
      pattern="$2"
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

mkdir -p .tmp/toposim
go build -o .tmp/toposim/toposimnode ./tools/toposimnode

if [[ "${EUID}" -eq 0 ]]; then
  go test -tags=toposim ./pkg/toposim --run "$pattern" -count=1 -timeout=180s
else
  sudo env "PATH=${PATH}" "HOME=${HOME}" "GOCACHE=${GOCACHE:-}" \
    go test -tags=toposim ./pkg/toposim --run "$pattern" -count=1 -timeout=180s
fi
