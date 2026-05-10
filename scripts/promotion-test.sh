#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DERPHOLE_BENCH_TOOL=derphole DERPHOLE_BENCH_DIRECTION=forward exec "${script_dir}/promotion-benchmark-driver.sh" "$@"
