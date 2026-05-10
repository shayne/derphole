#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

check_mode=""
auto_fix=false
if [[ "${1:-}" == "--check" ]]; then
  check_mode="-check"
  auto_fix=true
  shift
fi

# Apply/check BSD headers across tracked source files.
set +e
go run github.com/google/addlicense $check_mode \
  -l bsd \
  -c "Shayne" \
  -y 2026 \
  cmd pkg tools scripts packaging
status=$?
set -e

if [[ $status -ne 0 && "$auto_fix" == "true" ]]; then
  echo "License headers missing; running addlicense to fix."
  go run github.com/google/addlicense \
    -l bsd \
    -c "Shayne" \
    -y 2026 \
    cmd pkg tools scripts packaging
  echo "License headers added. Please stage the changes and retry the commit."
  exit 1
fi

exit $status
