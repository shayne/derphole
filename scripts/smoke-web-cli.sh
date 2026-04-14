#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/derphole-web-cli-smoke"
SIZE="${SIZE:-1048576}"
rm -rf "$TMP"
mkdir -p "$TMP"

dd if=/dev/urandom of="$TMP/input.bin" bs="$SIZE" count=1 status=none

GOOS=js GOARCH=wasm go build -o "$TMP/derphole-web.wasm" "$ROOT/cmd/derphole-web"
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$TMP/wasm_exec.js"
cp "$ROOT/web/derphole/index.html" "$TMP/index.html"
cp "$ROOT/web/derphole/styles.css" "$TMP/styles.css"
cp "$ROOT/web/derphole/webrtc.js" "$TMP/webrtc.js"
cp "$ROOT/web/derphole/app.js" "$TMP/app.js"
{
  printf 'window.derpholeWasmBase64 = "'
  base64 < "$TMP/derphole-web.wasm" | tr -d '\n'
  printf '";\n'
} > "$TMP/wasm_payload.js"

echo "Built browser assets in $TMP"
echo "Manual smoke:"
echo "1. Serve $TMP with: python3 -m http.server --directory \"$TMP\" 8765"
echo "2. Open http://127.0.0.1:8765/"
echo "3. Send from browser, receive with: go run ./cmd/derpcat derphole receive <token>"
