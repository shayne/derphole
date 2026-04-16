#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT_DIR="${ROOT_DIR}/dist/vendor"

: "${VERSION:?VERSION is required}"
COMMIT="${COMMIT:-$(git -C "${ROOT_DIR}" rev-parse HEAD)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

targets=(
  "linux amd64 x86_64-unknown-linux-musl"
  "linux arm64 aarch64-unknown-linux-musl"
  "darwin amd64 x86_64-apple-darwin"
  "darwin arm64 aarch64-apple-darwin"
)

for target in "${targets[@]}"; do
  read -r goos goarch triple <<<"${target}"
  for product in derphole derphole; do
    dest_dir="${OUT_DIR}/${triple}/${product}"
    mkdir -p "${dest_dir}"
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
      go build \
        -trimpath \
        -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
        -o "${dest_dir}/${product}" \
        ./cmd/${product}
    chmod +x "${dest_dir}/${product}"
  done
done
