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
  "linux amd64 x86_64-unknown-linux-musl derpcat"
  "linux arm64 aarch64-unknown-linux-musl derpcat"
  "darwin amd64 x86_64-apple-darwin derpcat"
  "darwin arm64 aarch64-apple-darwin derpcat"
)

for target in "${targets[@]}"; do
  read -r goos goarch triple binary <<<"${target}"
  dest_dir="${OUT_DIR}/${triple}/derpcat"
  mkdir -p "${dest_dir}"
  CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
    go build \
      -trimpath \
      -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
      -o "${dest_dir}/${binary}" \
      ./cmd/derpcat
  chmod +x "${dest_dir}/${binary}"
done
