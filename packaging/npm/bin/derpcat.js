#!/usr/bin/env node

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const triples = new Map([
  ["linux:x64", "x86_64-unknown-linux-musl"],
  ["linux:arm64", "aarch64-unknown-linux-musl"],
  ["android:x64", "x86_64-unknown-linux-musl"],
  ["android:arm64", "aarch64-unknown-linux-musl"],
  ["darwin:x64", "x86_64-apple-darwin"],
  ["darwin:arm64", "aarch64-apple-darwin"],
]);

const triple = triples.get(`${process.platform}:${process.arch}`);
if (!triple) {
  throw new Error(`Unsupported platform: ${process.platform} (${process.arch})`);
}

const binaryName = process.platform === "win32" ? "derpcat.exe" : "derpcat";
const binaryPath = path.join(__dirname, "..", "vendor", triple, "derpcat", binaryName);
if (!existsSync(binaryPath)) {
  throw new Error(`Missing vendored binary: ${binaryPath}`);
}

const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  env: { ...process.env, DERPCAT_MANAGED_BY_NPM: "1" },
});

child.on("error", (err) => {
  console.error(err);
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
  process.kill(process.pid, result.signal);
} else {
  process.exit(result.code);
}
