#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist/web/derphole-web"
RELEASE_DIR="${ROOT_DIR}/dist/release"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}" "${RELEASE_DIR}"

GOOS=js GOARCH=wasm go build -trimpath -o "${OUT_DIR}/derphole-web.wasm" "${ROOT_DIR}/cmd/derphole-web"
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "${OUT_DIR}/wasm_exec.js"
cp "${ROOT_DIR}/web/derphole/index.html" "${OUT_DIR}/index.html"
cp "${ROOT_DIR}/web/derphole/styles.css" "${OUT_DIR}/styles.css"
cp "${ROOT_DIR}/web/derphole/webrtc.js" "${OUT_DIR}/webrtc.js"
cp "${ROOT_DIR}/web/derphole/app.js" "${OUT_DIR}/app.js"
touch "${OUT_DIR}/.nojekyll"

asset_version="${DERPHOLE_WEB_ASSET_VERSION:-}"
if [[ -z "${asset_version}" ]]; then
  asset_version="$(git -C "${ROOT_DIR}" rev-parse --short=12 HEAD 2>/dev/null || true)"
fi
if [[ -z "${asset_version}" ]]; then
  asset_version="$(date -u +%Y%m%d%H%M%S)"
fi
asset_version="${asset_version//[^A-Za-z0-9._-]/-}"
DERPHOLE_WEB_ASSET_VERSION="${asset_version}" perl -0pi -e 's/\?v=dev/\?v=$ENV{DERPHOLE_WEB_ASSET_VERSION}/g' "${OUT_DIR}/index.html"

{
  printf 'window.derpholeWasmBase64 = "'
  base64 < "${OUT_DIR}/derphole-web.wasm" | tr -d '\n'
  printf '";\n'
} > "${OUT_DIR}/wasm_payload.js"

rm -f "${RELEASE_DIR}/derphole-web.zip" "${RELEASE_DIR}/derphole-web.zip.sha256"
(
  cd "${ROOT_DIR}/dist/web"
  zip -qr "${RELEASE_DIR}/derphole-web.zip" derphole-web
)
(
  cd "${RELEASE_DIR}"
  shasum -a 256 derphole-web.zip > derphole-web.zip.sha256
)
