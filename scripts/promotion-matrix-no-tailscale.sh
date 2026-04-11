#!/usr/bin/env bash
set -euo pipefail

size_mib="${1:-1024}"
iterations="${2:-10}"

go build -o dist/derpcat-probe ./cmd/derpcat-probe
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./dist/derpcat-probe matrix --hosts "ktzlxc,canlxc,uklxc,orange-india.exe.xyz" --iterations "${iterations}" --size-mib "${size_mib}"
