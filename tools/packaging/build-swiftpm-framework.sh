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
(
  cd dist/swiftpm
  rm -f DerpholeMobile.xcframework.zip
  ditto -c -k --sequesterRsrc --keepParent DerpholeMobile.xcframework DerpholeMobile.xcframework.zip
)
swift package compute-checksum dist/swiftpm/DerpholeMobile.xcframework.zip
