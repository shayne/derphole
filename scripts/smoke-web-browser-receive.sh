#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/derphole-web-browser-receive-smoke"
SIZE="${SIZE:-65536}"
PORT="${PORT:-0}"
TIMEOUT_MS="${TIMEOUT_MS:-60000}"
INPUT_FILE="$TMP/browser-input.bin"

rm -rf "$TMP"
mkdir -p "$TMP"

cd "$ROOT"
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
dd if=/dev/urandom of="$INPUT_FILE" bs="$SIZE" count=1 status=none

if [[ "$PORT" = "0" ]]; then
  PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
fi

server_log="$TMP/http.log"
python3 -m http.server --directory "$TMP" "$PORT" >"$server_log" 2>&1 &
server_pid=$!
cleanup() {
  kill "$server_pid" >/dev/null 2>&1 || true
  wait "$server_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

node_script="$TMP/browser-receive-harness.cjs"
cat >"$node_script" <<'NODE'
const { readFileSync, existsSync } = require("node:fs");
const { chromium } = require("playwright");

const inputFile = process.env.INPUT_FILE;
const port = process.env.PORT;
const timeoutMs = Number(process.env.TIMEOUT_MS || "60000");
const expected = readFileSync(inputFile);

function withTimeout(promise, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(label + " timed out after " + timeoutMs + "ms")), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function buffersEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

async function installSavePickerHarness(page) {
  await page.addInitScript(() => {
    window.__derpholeReceiveMode = "save-picker";
    window.__derpholeSavedOptions = null;
    window.__derpholeReceivedChunks = [];
    window.__derpholeClosed = false;
    window.showDirectoryPicker = async () => {
      throw new Error("browser receive must not request directory access");
    };
    window.showSaveFilePicker = async (options) => {
      window.__derpholeSavedOptions = options;
      const stream = {
        async write(chunk) {
          if (this !== stream) {
            throw new Error("FileSystemWritableFileStream.write lost receiver");
          }
          const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
          const copy = new Uint8Array(bytes.byteLength);
          copy.set(bytes);
          window.__derpholeReceivedChunks.push(Array.from(copy));
        },
        async close() {
          if (this !== stream) {
            throw new Error("FileSystemWritableFileStream.close lost receiver");
          }
          window.__derpholeClosed = true;
        },
      };
      return {
        async createWritable() {
          return stream;
        },
      };
    };
  });
}

async function installMemoryFallbackHarness(page) {
  await page.addInitScript(() => {
    window.__derpholeReceiveMode = "memory-fallback";
    window.__derpholeFallbackBlob = null;
    window.__derpholeFallbackDownload = "";
    window.__derpholeClosed = false;
    window.showSaveFilePicker = undefined;
    window.showDirectoryPicker = async () => {
      throw new Error("browser receive must not request directory access");
    };

    URL.createObjectURL = (blob) => {
      window.__derpholeFallbackBlob = blob;
      return "blob:derphole-fallback";
    };
    URL.revokeObjectURL = () => {};

    const createElement = Document.prototype.createElement;
    Document.prototype.createElement = function(tagName, ...args) {
      const element = createElement.call(this, tagName, ...args);
      if (String(tagName).toLowerCase() === "a") {
        element.click = function() {
          window.__derpholeFallbackDownload = this.download;
          window.__derpholeClosed = true;
        };
      }
      return element;
    };
  });
}

async function collectReceiveResult(receiver) {
  return await receiver.evaluate(async () => {
    let bytes = [];
    if (window.__derpholeReceivedChunks) {
      bytes = window.__derpholeReceivedChunks.flat();
    } else if (window.__derpholeFallbackBlob) {
      bytes = Array.from(new Uint8Array(await window.__derpholeFallbackBlob.arrayBuffer()));
    }
    return {
      mode: window.__derpholeReceiveMode,
      savedOptions: window.__derpholeSavedOptions || null,
      fallbackDownload: window.__derpholeFallbackDownload || "",
      closed: Boolean(window.__derpholeClosed),
      bytes,
      status: document.querySelector("#receive-status")?.textContent || "",
      progress: document.querySelector("#receive-progress")?.textContent || "",
    };
  });
}

async function runReceiveScenario(browser, name, installReceiverHarness) {
  const sender = await browser.newPage();
  const receiver = await browser.newPage();
  try {
    await installReceiverHarness(receiver);

    await Promise.all([
      sender.goto(`http://127.0.0.1:${port}/`, { waitUntil: "networkidle" }),
      receiver.goto(`http://127.0.0.1:${port}/`, { waitUntil: "networkidle" }),
    ]);
    await Promise.all([
      sender.waitForFunction(() => Boolean(window.derpholeWASM?.sendFile)),
      receiver.waitForFunction(() => Boolean(window.derpholeWASM?.receiveFile)),
    ]);
    await receiver.evaluate(() => {
      window.createDerpholeWebRTCTransport = undefined;
    });

    console.error(`browser receive smoke (${name}): creating web offer`);
    const token = await sender.evaluate(async (bytes) => {
      const raw = Uint8Array.from(bytes);
      const file = new File([raw], "browser-input.bin", { type: "application/octet-stream" });
      const logs = [];
      window.__derpholeSendState = { done: false, error: null, logs };
      const callbacks = {
        status(value) { logs.push({ kind: "status", value }); },
        progress(bytes, total) { logs.push({ kind: "progress", bytes, total }); },
        trace(value) { logs.push({ kind: "trace", value }); },
      };
      const token = await window.derpholeWASM.createOffer();
      window.__derpholeSendPromise = window.derpholeWASM.sendFile(file, callbacks, null)
        .then(() => { window.__derpholeSendState.done = true; })
        .catch((err) => { window.__derpholeSendState.error = String(err?.message || err); });
      return token;
    }, Array.from(expected));

    console.error(`browser receive smoke (${name}): claiming web offer`);
    await receiver.fill("#receive-token", token);
    await receiver.click("#start-receive");
    await withTimeout(receiver.waitForFunction(() => {
      const status = document.querySelector("#receive-status")?.textContent || "";
      return window.__derpholeClosed || status.startsWith("error:");
    }, { timeout: timeoutMs }), `browser receive (${name})`);

    const result = await collectReceiveResult(receiver);
    if (result.status.startsWith("error:")) {
      throw new Error(`browser receive (${name}) failed: ${result.status}`);
    }
    if (!result.closed) {
      throw new Error(`browser receive (${name}) did not close output`);
    }
    if (name === "save-picker") {
      if (!result.savedOptions || result.savedOptions.startIn !== "downloads") {
        throw new Error("browser receive did not use save picker with downloads start directory");
      }
      if (result.savedOptions.suggestedName !== "browser-input.bin") {
        throw new Error("browser receive save picker did not preserve filename");
      }
    } else {
      if (result.savedOptions) {
        throw new Error("browser receive fallback unexpectedly used save picker");
      }
      if (result.fallbackDownload !== "browser-input.bin") {
        throw new Error("browser receive fallback did not preserve filename");
      }
    }
    const actual = Buffer.from(result.bytes);
    if (!buffersEqual(actual, expected)) {
      throw new Error(`received bytes mismatch (${name}): got ${actual.length}, want ${expected.length}`);
    }

    await withTimeout(sender.evaluate(() => window.__derpholeSendPromise), `browser send (${name})`);
    const sendState = await sender.evaluate(() => window.__derpholeSendState);
    if (sendState.error || !sendState.done) {
      throw new Error(`browser send (${name}) failed: ${sendState.error || "not done"}`);
    }
    return {
      name,
      receivedBytes: actual.length,
      savedOptions: result.savedOptions,
      fallbackDownload: result.fallbackDownload,
      receiveStatus: result.status,
      receiveProgress: result.progress,
      sendEvents: sendState.logs.filter((entry) => entry.kind !== "progress").slice(-20),
    };
  } finally {
    await sender.close().catch(() => {});
    await receiver.close().catch(() => {});
  }
}

(async () => {
  const launchOptions = { headless: true };
  const chromePath = process.env.PLAYWRIGHT_CHROME_EXECUTABLE || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  if (existsSync(chromePath)) {
    launchOptions.executablePath = chromePath;
  } else if (process.env.PLAYWRIGHT_CHROME_CHANNEL) {
    launchOptions.channel = process.env.PLAYWRIGHT_CHROME_CHANNEL;
  }
  const browser = await chromium.launch(launchOptions);
  try {
    const scenarios = [];
    scenarios.push(await runReceiveScenario(browser, "save-picker", installSavePickerHarness));
    scenarios.push(await runReceiveScenario(browser, "memory-fallback", installMemoryFallbackHarness));
    console.error(JSON.stringify({ scenarios }, null, 2));
  } finally {
    await browser.close();
  }
})().catch((err) => {
  console.error(err.stack || err.message);
  process.exit(1);
});
NODE

export INPUT_FILE PORT TIMEOUT_MS
export DERPHOLE_WEB_BROWSER_RECEIVE_NODE_SCRIPT="$node_script"
npx -y -p playwright -c 'NODE_PATH="$(dirname "$(dirname "$(command -v playwright)")")" node "$DERPHOLE_WEB_BROWSER_RECEIVE_NODE_SCRIPT"'
