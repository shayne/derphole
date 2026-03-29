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

mkdir -p "${ROOT_DIR}/dist/raw"
cp "${ROOT_DIR}/dist/vendor/x86_64-unknown-linux-musl/derpcat/derpcat" "${ROOT_DIR}/dist/raw/derpcat-linux-amd64"
cp "${ROOT_DIR}/dist/vendor/aarch64-unknown-linux-musl/derpcat/derpcat" "${ROOT_DIR}/dist/raw/derpcat-linux-arm64"
cp "${ROOT_DIR}/dist/vendor/x86_64-apple-darwin/derpcat/derpcat" "${ROOT_DIR}/dist/raw/derpcat-darwin-amd64"
cp "${ROOT_DIR}/dist/vendor/aarch64-apple-darwin/derpcat/derpcat" "${ROOT_DIR}/dist/raw/derpcat-darwin-arm64"

bash "${ROOT_DIR}/tools/packaging/build-release-assets.sh"

test -f "${ROOT_DIR}/dist/release/derpcat-linux-amd64.tar.gz"
test -f "${ROOT_DIR}/dist/release/derpcat-linux-amd64.tar.gz.sha256"
test -f "${ROOT_DIR}/dist/release/derpcat-linux-arm64.tar.gz"
test -f "${ROOT_DIR}/dist/release/derpcat-linux-arm64.tar.gz.sha256"
test -f "${ROOT_DIR}/dist/release/derpcat-darwin-amd64.tar.gz"
test -f "${ROOT_DIR}/dist/release/derpcat-darwin-amd64.tar.gz.sha256"
test -f "${ROOT_DIR}/dist/release/derpcat-darwin-arm64.tar.gz"
test -f "${ROOT_DIR}/dist/release/derpcat-darwin-arm64.tar.gz.sha256"

node -e "const fs=require('fs'); const pkg=JSON.parse(fs.readFileSync('${ROOT_DIR}/dist/npm/package.json','utf8')); if (pkg.version !== process.env.VERSION.replace(/^v/,'')) { process.exit(1); }"
npm_launcher_version="$(node "${ROOT_DIR}/dist/npm/bin/derpcat.js" --version)"
if [ "${npm_launcher_version}" != "${VERSION}" ]; then
  echo "packaged launcher version mismatch: ${npm_launcher_version} != ${VERSION}" >&2
  exit 1
fi

package_name="$(node -e "const fs=require('fs'); const pkg=JSON.parse(fs.readFileSync('${ROOT_DIR}/dist/npm/package.json','utf8')); process.stdout.write(pkg.name)")"
if [ "${package_name}" != "derpcat" ]; then
  echo "packaged npm metadata mismatch: ${package_name}" >&2
  exit 1
fi

npm publish "${ROOT_DIR}/dist/npm" --access public --dry-run
