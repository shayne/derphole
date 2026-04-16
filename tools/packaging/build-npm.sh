#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SRC_DIR="${ROOT_DIR}/packaging/npm"
VENDOR_DIR="${ROOT_DIR}/dist/vendor"

: "${VERSION:?VERSION is required}"
PACKAGE_VERSION="${VERSION#v}"
export PACKAGE_VERSION

if [ ! -d "${VENDOR_DIR}" ]; then
  echo "missing vendor dir: ${VENDOR_DIR}" >&2
  exit 1
fi

rm -rf "${ROOT_DIR}"/dist/npm-*

products=(derphole)
triples=(
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
  x86_64-apple-darwin
  aarch64-apple-darwin
)

for product in "${products[@]}"; do
  for triple in "${triples[@]}"; do
    vendor_path="${VENDOR_DIR}/${triple}/${product}/${product}"
    if [ ! -x "${vendor_path}" ]; then
      echo "missing expected vendored binary: ${vendor_path}" >&2
      exit 1
    fi
  done

  out_dir="${ROOT_DIR}/dist/npm-${product}"
  rm -rf "${out_dir}"
  mkdir -p "${out_dir}"

  cp -R "${SRC_DIR}/${product}/bin" "${out_dir}/"
  cp "${SRC_DIR}/${product}/package.json" "${out_dir}/"
  cp "${ROOT_DIR}/README.md" "${out_dir}/"
  cp "${ROOT_DIR}/LICENSE" "${out_dir}/"
  mkdir -p "${out_dir}/vendor"
  for triple in "${triples[@]}"; do
    mkdir -p "${out_dir}/vendor/${triple}/${product}"
    cp "${VENDOR_DIR}/${triple}/${product}/${product}" "${out_dir}/vendor/${triple}/${product}/${product}"
  done
  chmod +x "${out_dir}/bin/${product}.js"

  node -e "const fs=require('fs'); const path=require('path'); const pkgPath=path.join('${out_dir}','package.json'); const pkg=JSON.parse(fs.readFileSync(pkgPath,'utf8')); pkg.version=process.env.PACKAGE_VERSION; fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');"
done
