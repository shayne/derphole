#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DERPHOLE_BENCH_TOOL=derphole DERPHOLE_BENCH_DIRECTION=reverse exec "${script_dir}/promotion-benchmark-driver.sh" "$@"
