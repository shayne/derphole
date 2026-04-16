#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RAW_DIR="${ROOT_DIR}/dist/raw"
OUT_DIR="${ROOT_DIR}/dist/release"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

if command -v sha256sum >/dev/null 2>&1; then
  checksum_cmd=(sha256sum)
else
  checksum_cmd=(shasum -a 256)
fi

for product in derphole derphole; do
  for asset in \
    "${product}-linux-amd64" \
    "${product}-linux-arm64" \
    "${product}-darwin-amd64" \
    "${product}-darwin-arm64"
  do
    if [ ! -f "${RAW_DIR}/${asset}" ]; then
      echo "missing raw asset: ${RAW_DIR}/${asset}" >&2
      exit 1
    fi
    chmod +x "${RAW_DIR}/${asset}"
    tar -czf "${OUT_DIR}/${asset}.tar.gz" -C "${RAW_DIR}" "${asset}"
    (cd "${OUT_DIR}" && "${checksum_cmd[@]}" "${asset}.tar.gz" > "${asset}.tar.gz.sha256")
  done
done
