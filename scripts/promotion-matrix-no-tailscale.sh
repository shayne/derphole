#!/usr/bin/env bash
set -euo pipefail

size_mib="${1:-1024}"
iterations="${2:-10}"

go build -o dist/derphole-probe ./cmd/derphole-probe
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./dist/derphole-probe matrix --hosts "ktzlxc,canlxc,uklxc,november-oscar.exe.xyz,eric@eric-nuc" --iterations "${iterations}" --size-mib "${size_mib}"
