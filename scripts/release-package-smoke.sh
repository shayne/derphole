#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${VERSION:?VERSION is required}"

COMMIT="${COMMIT:-$(git -C "${ROOT_DIR}" rev-parse HEAD)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
export VERSION COMMIT BUILD_DATE

bash "${ROOT_DIR}/tools/packaging/build-vendor.sh"
bash "${ROOT_DIR}/tools/packaging/build-npm.sh"

for product in derphole derptun; do
  test -x "${ROOT_DIR}/dist/vendor/x86_64-unknown-linux-musl/${product}/${product}"
  test -x "${ROOT_DIR}/dist/vendor/aarch64-unknown-linux-musl/${product}/${product}"
  test -x "${ROOT_DIR}/dist/vendor/x86_64-apple-darwin/${product}/${product}"
  test -x "${ROOT_DIR}/dist/vendor/aarch64-apple-darwin/${product}/${product}"
done

rm -rf "${ROOT_DIR}/dist/raw"
mkdir -p "${ROOT_DIR}/dist/raw"
for product in derphole derptun; do
  cp "${ROOT_DIR}/dist/vendor/x86_64-unknown-linux-musl/${product}/${product}" "${ROOT_DIR}/dist/raw/${product}-linux-amd64"
  cp "${ROOT_DIR}/dist/vendor/aarch64-unknown-linux-musl/${product}/${product}" "${ROOT_DIR}/dist/raw/${product}-linux-arm64"
  cp "${ROOT_DIR}/dist/vendor/x86_64-apple-darwin/${product}/${product}" "${ROOT_DIR}/dist/raw/${product}-darwin-amd64"
  cp "${ROOT_DIR}/dist/vendor/aarch64-apple-darwin/${product}/${product}" "${ROOT_DIR}/dist/raw/${product}-darwin-arm64"
done

bash "${ROOT_DIR}/tools/packaging/build-release-assets.sh"

for product in derphole derptun; do
  test -f "${ROOT_DIR}/dist/release/${product}-linux-amd64.tar.gz"
  test -f "${ROOT_DIR}/dist/release/${product}-linux-amd64.tar.gz.sha256"
  test -f "${ROOT_DIR}/dist/release/${product}-linux-arm64.tar.gz"
  test -f "${ROOT_DIR}/dist/release/${product}-linux-arm64.tar.gz.sha256"
  test -f "${ROOT_DIR}/dist/release/${product}-darwin-amd64.tar.gz"
  test -f "${ROOT_DIR}/dist/release/${product}-darwin-amd64.tar.gz.sha256"
  test -f "${ROOT_DIR}/dist/release/${product}-darwin-arm64.tar.gz"
  test -f "${ROOT_DIR}/dist/release/${product}-darwin-arm64.tar.gz.sha256"
done

for product in derphole derptun; do
  node -e "const fs=require('fs'); const pkg=JSON.parse(fs.readFileSync('${ROOT_DIR}/dist/npm-${product}/package.json','utf8')); if (pkg.version !== process.env.VERSION.replace(/^v/,'')) { process.exit(1); }"
  npm_launcher_version="$(node "${ROOT_DIR}/dist/npm-${product}/bin/${product}.js" version)"
  if [ "${npm_launcher_version}" != "${VERSION}" ]; then
    echo "packaged launcher version mismatch for ${product}: ${npm_launcher_version} != ${VERSION}" >&2
    exit 1
  fi

  package_name="$(node -e "const fs=require('fs'); const pkg=JSON.parse(fs.readFileSync('${ROOT_DIR}/dist/npm-${product}/package.json','utf8')); process.stdout.write(pkg.name)")"
  if [ "${package_name}" != "${product}" ]; then
    echo "packaged npm metadata mismatch: ${package_name}" >&2
    exit 1
  fi

  pkg_version="$(node -e "const fs=require('fs'); const pkg=JSON.parse(fs.readFileSync('${ROOT_DIR}/dist/npm-${product}/package.json','utf8')); process.stdout.write(pkg.version)")"
  publish_args=("${ROOT_DIR}/dist/npm-${product}" --access public --dry-run)
  if [[ "${pkg_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+-.+ ]]; then
    publish_args+=(--tag dev)
  fi

  npm publish "${publish_args[@]}"
done
