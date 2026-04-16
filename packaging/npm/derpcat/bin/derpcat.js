#!/usr/bin/env node

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const triples = new Map([
  ["linux:x64", "x86_64-unknown-linux-musl"],
  ["linux:arm64", "aarch64-unknown-linux-musl"],
  ["darwin:x64", "x86_64-apple-darwin"],
  ["darwin:arm64", "aarch64-apple-darwin"]
]);

const triple = triples.get(`${process.platform}:${process.arch}`);
if (!triple) {
  console.error(`Unsupported platform: ${process.platform} (${process.arch})`);
  process.exit(1);
}

const binaryName = process.platform === "win32" ? "derphole.exe" : "derphole";
const binaryPath = path.join(__dirname, "..", "vendor", triple, "derphole", binaryName);
if (!existsSync(binaryPath)) {
  console.error(`Missing vendored binary: ${binaryPath}`);
  process.exit(1);
}

const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  env: { ...process.env, DERPHOLE_MANAGED_BY_NPM: "1" }
});

child.on("error", (err) => {
  const reason = err instanceof Error ? err.message : String(err);
  console.error(`Failed to launch vendored binary: ${reason}`);
  process.exit(1);
});

["SIGINT", "SIGTERM", "SIGHUP"].forEach((sig) => {
  process.on(sig, () => {
    if (!child.killed) {
      child.kill(sig);
    }
  });
});

const result = await new Promise((resolve) => {
  child.on("exit", (code, signal) => {
    if (signal) {
      resolve({ signal });
      return;
    }
    resolve({ code: code ?? 1 });
  });
});

if (result.signal) {
  const signalNumber = os.constants.signals[result.signal];
  process.exit(typeof signalNumber === "number" ? 128 + signalNumber : 1);
} else {
  process.exit(result.code);
}
