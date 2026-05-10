// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebProgressUsesOverallAverageForDisplayedRate(t *testing.T) {
	t.Parallel()

	script := `
const fs = require("fs");
const vm = require("vm");

const source = fs.readFileSync(process.argv[1], "utf8");
const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, {
      id,
      disabled: false,
      textContent: "",
      value: "",
      addEventListener() {},
    });
  }
  return elements.get(id);
}

let now = 0;
class Go {
  constructor() {
    this.importObject = {};
  }
  run() {
    context.window.derpholeWASM = {};
  }
}

const context = {
  window: {
    Go,
    derpholeWasmBase64: "AA==",
  },
  document: {
    querySelector(selector) { return element(selector); },
    createElement() { return { addEventListener() {}, click() {}, style: {} }; },
    body: { append() {} },
  },
  WebAssembly: { instantiate: async () => ({ instance: {} }) },
  Blob,
  Error,
  Promise,
  Uint8Array,
  URL: { createObjectURL: () => "blob:test", revokeObjectURL() {} },
  atob: () => "\0",
  clearTimeout,
  console,
  performance: { now: () => now },
  setTimeout,
};
context.globalThis = context;
context.self = context.window;
context.navigator = { clipboard: { writeText: async () => {} } };

vm.createContext(context);
vm.runInContext(source, context);

const mib = 1024 * 1024;
const state = {
  started: 0,
  bytes: 129.8 * mib,
  total: 1000 * mib,
};
now = 134000;
const rendered = context.formatProgress(state);
if (rendered.includes("228.6MiB/s") || rendered.includes("198.0MiB/s")) {
  throw new Error("progress rendered burst rate instead of overall average: " + rendered);
}
if (!rendered.includes("991.9KiB/s") && !rendered.includes("1.0MiB/s")) {
  throw new Error("progress did not render the overall average rate: " + rendered);
}
if (rendered.includes("<00:03")) {
  throw new Error("progress rendered burst-rate ETA: " + rendered);
}
`

	cmd := exec.Command("node", "-e", script, filepath.Join("..", "web", "derphole", "app.js"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node web progress regression failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "Error") {
		t.Fatalf("unexpected node output: %s", out)
	}
}
