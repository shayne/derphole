#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SRC_DIR="${ROOT_DIR}/packaging/npm"
VENDOR_DIR="${ROOT_DIR}/dist/vendor"
OUT_DIR="${ROOT_DIR}/dist/npm"

: "${VERSION:?VERSION is required}"
PACKAGE_VERSION="${VERSION#v}"
export PACKAGE_VERSION

if [ ! -d "${VENDOR_DIR}" ]; then
  echo "missing vendor dir: ${VENDOR_DIR}" >&2
  exit 1
fi

expected_vendor_paths=(
  "${VENDOR_DIR}/x86_64-unknown-linux-musl/derpcat/derpcat"
  "${VENDOR_DIR}/aarch64-unknown-linux-musl/derpcat/derpcat"
  "${VENDOR_DIR}/x86_64-apple-darwin/derpcat/derpcat"
  "${VENDOR_DIR}/aarch64-apple-darwin/derpcat/derpcat"
)

for vendor_path in "${expected_vendor_paths[@]}"; do
  if [ ! -x "${vendor_path}" ]; then
    echo "missing expected vendored binary: ${vendor_path}" >&2
    exit 1
  fi
done

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

cp -R "${SRC_DIR}/bin" "${OUT_DIR}/"
cp "${SRC_DIR}/package.json" "${OUT_DIR}/"
cp "${ROOT_DIR}/README.md" "${OUT_DIR}/"
cp "${ROOT_DIR}/LICENSE" "${OUT_DIR}/"
cp -R "${VENDOR_DIR}" "${OUT_DIR}/vendor"
chmod +x "${OUT_DIR}/bin/derpcat.js"

node -e "const fs=require('fs'); const path=require('path'); const pkgPath=path.join('${OUT_DIR}','package.json'); const pkg=JSON.parse(fs.readFileSync(pkgPath,'utf8')); pkg.version=process.env.PACKAGE_VERSION; fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');"
