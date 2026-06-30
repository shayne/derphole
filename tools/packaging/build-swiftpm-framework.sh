#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root}"

mise run apple:mobile-framework
rm -rf dist/swiftpm
mkdir -p dist/swiftpm
cp -R dist/apple/DerpholeMobile.xcframework dist/swiftpm/DerpholeMobile.xcframework

python3 - "${DERPHOLE_MOBILE_FRAMEWORK_VERSION:-0.0.0}" <<'PY'
from pathlib import Path
import plistlib
import sys

framework_version = sys.argv[1].removeprefix("v")
root = Path("dist/swiftpm/DerpholeMobile.xcframework")

info_path = root / "Info.plist"
with info_path.open("rb") as handle:
    info = plistlib.load(handle)
info["AvailableLibraries"] = sorted(
    info.get("AvailableLibraries", []),
    key=lambda library: library.get("LibraryIdentifier", ""),
)
with info_path.open("wb") as handle:
    plistlib.dump(info, handle, sort_keys=True)

for framework_info_path in sorted(root.glob("*/DerpholeMobile.framework/Info.plist")):
    with framework_info_path.open("rb") as handle:
        framework_info = plistlib.load(handle)
    framework_info["CFBundleShortVersionString"] = framework_version
    framework_info["CFBundleVersion"] = framework_version
    with framework_info_path.open("wb") as handle:
        plistlib.dump(framework_info, handle, sort_keys=True)
PY

(
  cd dist/swiftpm
  rm -f DerpholeMobile.xcframework.zip
  find DerpholeMobile.xcframework -exec touch -h -t 202001010000 {} +
  find DerpholeMobile.xcframework -print | LC_ALL=C sort | zip -q -X -@ DerpholeMobile.xcframework.zip
)
swift package compute-checksum dist/swiftpm/DerpholeMobile.xcframework.zip
