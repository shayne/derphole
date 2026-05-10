#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

size_mib="${1:-1024}"
iterations="${2:-10}"

go build -o dist/derphole-probe ./cmd/derphole-probe
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./dist/derphole-probe matrix --hosts "ktzlxc,canlxc,uklxc,november-oscar.exe.xyz,eric@eric-nuc" --iterations "${iterations}" --size-mib "${size_mib}"
