#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/derphole-web-cli-smoke"
SIZE="${SIZE:-1048576}"
rm -rf "$TMP"
mkdir -p "$TMP"

dd if=/dev/urandom of="$TMP/input.bin" bs="$SIZE" count=1 status=none

GOOS=js GOARCH=wasm go build -o "$TMP/derphole-web.wasm" "$ROOT/cmd/derphole-web"
cp "$ROOT/web/derphole/"*.js "$TMP/"
cp "$ROOT/web/derphole/"*.html "$TMP/" 2>/dev/null || true

echo "Built browser assets in $TMP"
echo "Manual smoke:"
echo "1. Serve $TMP with: python3 -m http.server --directory \"$TMP\" 8765"
echo "2. Open http://127.0.0.1:8765/"
echo "3. Send from browser, receive with: go run ./cmd/derpcat derphole receive <token>"
