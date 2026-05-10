#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

version="${1:?usage: update-swiftpm-binary-target.sh vX.Y.Z}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root}"

zip_path="dist/swiftpm/DerpholeMobile.xcframework.zip"
if [[ ! -f "${zip_path}" ]]; then
  echo "missing ${zip_path}; run tools/packaging/build-swiftpm-framework.sh first" >&2
  exit 1
fi
checksum="$(swift package compute-checksum "${zip_path}")"
url="https://github.com/shayne/derphole/releases/download/${version}/DerpholeMobile.xcframework.zip"

python3 - "${url}" "${checksum}" <<'PY'
from pathlib import Path
import sys

url, checksum = sys.argv[1:]
path = Path("Package.swift")
text = path.read_text()
start = text.index('        .binaryTarget(\n            name: "DerpholeMobile",')
end = text.index("\n        ),", start) + len("\n        ),")
replacement = f'''        .binaryTarget(
            name: "DerpholeMobile",
            url: "{url}",
            checksum: "{checksum}"
        ),'''
path.write_text(text[:start] + replacement + text[end:])
PY
