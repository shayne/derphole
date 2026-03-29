#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${VERSION:?VERSION is required}"

COMMIT="${COMMIT:-$(git -C "${ROOT_DIR}" rev-parse HEAD)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
export VERSION COMMIT BUILD_DATE

bash "${ROOT_DIR}/tools/packaging/build-vendor.sh"
bash "${ROOT_DIR}/tools/packaging/build-npm.sh"

test -x "${ROOT_DIR}/dist/vendor/x86_64-unknown-linux-musl/derpcat/derpcat"
test -x "${ROOT_DIR}/dist/vendor/aarch64-unknown-linux-musl/derpcat/derpcat"
test -x "${ROOT_DIR}/dist/vendor/x86_64-apple-darwin/derpcat/derpcat"
test -x "${ROOT_DIR}/dist/vendor/aarch64-apple-darwin/derpcat/derpcat"

node -e "const fs=require('fs'); const pkg=JSON.parse(fs.readFileSync('${ROOT_DIR}/dist/npm/package.json','utf8')); if (pkg.version !== process.env.VERSION.replace(/^v/,'')) { process.exit(1); }"
npm publish "${ROOT_DIR}/dist/npm" --access public --dry-run
