#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/derphole-web-cli-smoke"
REMOTE_HOST="${REMOTE_HOST:-root@ktzlxc}"
REMOTE_BIN="${REMOTE_BIN:-/tmp/derphole-web-harness}"
REMOTE_OUT="${REMOTE_OUT:-/tmp/derphole-web-harness.bin}"
REMOTE_LOG="${REMOTE_LOG:-/tmp/derphole-web-harness.err}"
SIZE_MB="${SIZE_MB:-64}"
PORT="${PORT:-8765}"
TIMEOUT="${TIMEOUT:-180s}"
DIRECT="${DIRECT:-1}"
HIDE_PROGRESS="${HIDE_PROGRESS:-1}"
VERBOSE="${VERBOSE:-0}"
INPUT_FILE="$TMP/browser-input.bin"

cd "$ROOT"
./scripts/smoke-web-cli.sh >/dev/null
dd if=/dev/zero of="$INPUT_FILE" bs=1048576 count="$SIZE_MB" status=none
GOOS=linux GOARCH=amd64 go build -o "$TMP/derphole-linux-amd64" ./cmd/derphole
scp -q "$TMP/derphole-linux-amd64" "$REMOTE_HOST:$REMOTE_BIN"
ssh "$REMOTE_HOST" "chmod +x '$REMOTE_BIN'"

server_log="$TMP/http.log"
python3 -m http.server --directory "$TMP" "$PORT" >"$server_log" 2>&1 &
server_pid=$!
cleanup() {
  kill "$server_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

node_script="$TMP/browser-harness.cjs"
cat >"$node_script" <<'NODE'
const { spawn } = require("node:child_process");
const { existsSync } = require("node:fs");
const { chromium } = require("playwright");

const remoteHost = process.env.REMOTE_HOST;
const remoteBin = process.env.REMOTE_BIN;
const remoteOut = process.env.REMOTE_OUT;
const remoteLog = process.env.REMOTE_LOG;
const sizeBytes = Number(process.env.SIZE_MB || "64") * 1024 * 1024;
const inputFile = process.env.INPUT_FILE;
const port = process.env.PORT || "8765";
const timeout = process.env.TIMEOUT || "180s";
const directEnabled = process.env.DIRECT !== "0";
const hideProgress = process.env.HIDE_PROGRESS !== "0";
const verbose = process.env.VERBOSE === "1";

function shellQuote(value) {
  return `'${String(value).replaceAll("'", `'\\''`)}'`;
}

function runSSH(token) {
  const forceRelay = directEnabled ? "" : " --force-relay";
  const progress = hideProgress ? " --hide-progress" : "";
  const verboseFlag = verbose ? " --verbose" : "";
  const command = [
    `rm -f ${shellQuote(remoteOut)} ${shellQuote(remoteLog)}`,
    `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 timeout ${shellQuote(timeout)} ${shellQuote(remoteBin)}${verboseFlag} receive${forceRelay}${progress} -o ${shellQuote(remoteOut)} ${shellQuote(token)} >/tmp/derphole-web-harness.out 2>${shellQuote(remoteLog)}`,
    "rc=$?",
    `bytes=0; [ -f ${shellQuote(remoteOut)} ] && bytes=$(wc -c < ${shellQuote(remoteOut)})`,
    `echo rc=$rc bytes=$bytes`,
    `tail -80 ${shellQuote(remoteLog)} 2>/dev/null || true`,
    "exit $rc",
  ].join("; ");
  return new Promise((resolve) => {
    const child = spawn("ssh", [remoteHost, command], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      process.stdout.write(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      process.stderr.write(chunk);
    });
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
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
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "networkidle" });
    await page.evaluate(() => {
      const input = document.createElement("input");
      input.type = "file";
      input.id = "derphole-web-harness-input";
      input.style.display = "none";
      document.body.append(input);
    });
    await page.setInputFiles("#derphole-web-harness-input", inputFile);
    const { token } = await page.evaluate(async ({ directEnabled }) => {
      const file = document.querySelector("#derphole-web-harness-input").files[0];
      if (!file) {
        throw new Error("missing harness input file");
      }
      const logs = [];
      const state = { bytes: 0, total: 0, done: false, error: null, logs };
      window.__derpholeHarness = state;
      const token = await window.derpholeWASM.createOffer();
      const callbacks = {
        status(value) { logs.push({ t: performance.now(), kind: "status", value }); },
        progress(bytes, total) {
          state.bytes = bytes;
          state.total = total;
          logs.push({ t: performance.now(), kind: "progress", bytes, total });
        },
        trace(value) { logs.push({ t: performance.now(), kind: "trace", value }); },
      };
      const direct = directEnabled && window.createDerpholeWebRTCTransport
        ? window.createDerpholeWebRTCTransport({ status(value) { logs.push({ t: performance.now(), kind: "direct-status", value }); } })
        : null;
      window.__derpholeHarnessDirect = direct;
      window.__derpholeHarnessPromise = window.derpholeWASM.sendFile(file, callbacks, direct)
        .then(() => { state.done = true; logs.push({ t: performance.now(), kind: "done" }); })
        .catch((err) => { state.error = String(err && (err.message || err)); logs.push({ t: performance.now(), kind: "error", value: state.error }); });
      return { token };
    }, { directEnabled });

    const remote = runSSH(token);
    const progress = setInterval(async () => {
      const state = await page.evaluate(() => ({
        bytes: window.__derpholeHarness?.bytes || 0,
        total: window.__derpholeHarness?.total || 0,
        done: Boolean(window.__derpholeHarness?.done),
        error: window.__derpholeHarness?.error || null,
      }));
      console.error(`browser bytes=${state.bytes}/${state.total} done=${state.done} error=${state.error || ""}`);
    }, 2000);
    const remoteResult = await remote;
    clearInterval(progress);
    await page.evaluate(() => window.__derpholeHarnessPromise);
    const finalState = await page.evaluate(() => window.__derpholeHarness);
    const directStats = await page.evaluate(() => {
      const direct = window.__derpholeHarnessDirect;
      return direct && typeof direct.stats === "function" ? direct.stats() : null;
    });
    const progressEvents = finalState.logs.filter((entry) => entry.kind === "progress");
    const firstProgress = progressEvents[0];
    const lastProgress = progressEvents[progressEvents.length - 1];
    let peakMiBps = 0;
    for (let i = 0; i < progressEvents.length; i++) {
      for (let j = i + 1; j < progressEvents.length; j++) {
        const seconds = (progressEvents[j].t - progressEvents[i].t) / 1000;
        if (seconds < 4.5) {
          continue;
        }
        if (seconds > 5.5) {
          break;
        }
        const mibps = ((progressEvents[j].bytes - progressEvents[i].bytes) / seconds) / 1048576;
        if (mibps > peakMiBps) {
          peakMiBps = mibps;
        }
      }
    }
    const elapsedSeconds = firstProgress && lastProgress ? (lastProgress.t - firstProgress.t) / 1000 : 0;
    const averageMiBps = elapsedSeconds > 0 && lastProgress ? (lastProgress.bytes / elapsedSeconds) / 1048576 : 0;
    console.error(JSON.stringify({
      browser: {
        bytes: finalState.bytes,
        total: finalState.total,
        done: finalState.done,
        error: finalState.error,
        elapsedSeconds,
        averageMiBps,
        peak5sMiBps: peakMiBps,
        directStats,
        events: finalState.logs.filter((entry) => entry.kind !== "progress").slice(-40),
      },
    }, null, 2));
    if (remoteResult.code !== 0 || !finalState.done || finalState.error) {
      process.exit(1);
    }
  } finally {
    await browser.close();
  }
})().catch((err) => {
  console.error(err.stack || err.message);
  process.exit(1);
});
NODE

export REMOTE_HOST REMOTE_BIN REMOTE_OUT REMOTE_LOG SIZE_MB INPUT_FILE PORT TIMEOUT DIRECT HIDE_PROGRESS VERBOSE
export DERPHOLE_WEB_CLI_NODE_SCRIPT="$node_script"
npx -y -p playwright -c 'NODE_PATH="$(dirname "$(dirname "$(command -v playwright)")")" node "$DERPHOLE_WEB_CLI_NODE_SCRIPT"'
