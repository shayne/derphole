#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RAW_DIR="${ROOT_DIR}/dist/raw"
OUT_DIR="${ROOT_DIR}/dist/release"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

for asset in \
  derpcat-linux-amd64 \
  derpcat-linux-arm64 \
  derpcat-darwin-amd64 \
  derpcat-darwin-arm64

do
  if [ ! -f "${RAW_DIR}/${asset}" ]; then
    echo "missing raw asset: ${RAW_DIR}/${asset}" >&2
    exit 1
  fi
  chmod +x "${RAW_DIR}/${asset}"
  tar -czf "${OUT_DIR}/${asset}.tar.gz" -C "${RAW_DIR}" "${asset}"
  (cd "${OUT_DIR}" && shasum -a 256 "${asset}.tar.gz" > "${asset}.tar.gz.sha256")
done
