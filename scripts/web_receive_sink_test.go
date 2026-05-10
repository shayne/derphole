// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebReceiveSinkUsesFileSavePickerAndBoundWriter(t *testing.T) {
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

let savedOptions;
let wrote = false;
let closed = false;
const stream = {
  async write(chunk) {
    if (this !== stream) {
      throw new Error("writer.write lost receiver");
    }
    if (!(chunk instanceof Uint8Array) || chunk.length !== 3) {
      throw new Error("writer.write got unexpected chunk");
    }
    wrote = true;
  },
  async close() {
    if (this !== stream) {
      throw new Error("writer.close lost receiver");
    }
    closed = true;
  },
};

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
    showSaveFilePicker: async (options) => {
      savedOptions = options;
      return {
        async createWritable() {
          return stream;
        },
      };
    },
    showDirectoryPicker: async () => {
      throw new Error("receive sink should not request directory access");
    },
  },
  document: {
    querySelector(selector) {
      return element(selector);
    },
    createElement() {
      return {
        addEventListener() {},
        click() {},
        style: {},
      };
    },
    body: { append() {} },
  },
  WebAssembly: {
    instantiate: async () => ({ instance: {} }),
  },
  Blob,
  Error,
  Promise,
  Uint8Array,
  URL: {
    createObjectURL: () => "blob:test",
    revokeObjectURL() {},
  },
  atob: () => "\0",
  clearTimeout,
  console,
  performance: { now: () => 0 },
  setTimeout,
};
context.globalThis = context;
context.self = context.window;
context.navigator = { clipboard: { writeText: async () => {} } };

vm.createContext(context);
vm.runInContext(source, context);

(async () => {
  const statuses = [];
  const sink = await context.makeSink({ status(value) { statuses.push(value); } });
  const writer = await sink.open("report.bin", 3);
  await writer.write(new Uint8Array([1, 2, 3]));
  await writer.close();

  if (!savedOptions) {
    throw new Error("showSaveFilePicker was not called");
  }
  if (savedOptions.suggestedName !== "report.bin") {
    throw new Error("save picker did not receive the transfer filename");
  }
  if (savedOptions.startIn !== "downloads") {
    throw new Error("save picker should start in downloads");
  }
  if (!wrote || !closed) {
    throw new Error("writer did not write and close");
  }
})().catch((err) => {
  console.error(err.stack || err.message);
  process.exit(1);
});
`

	cmd := exec.Command("node", "-e", script, filepath.Join("..", "web", "derphole", "app.js"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node receive sink regression failed: %v\n%s", err, out)
	}
}

func TestWebReceiveSinkMemoryFallbackOpenDoesNotDependOnThis(t *testing.T) {
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

let clickedDownload = "";
let objectURLBlob;

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
    querySelector(selector) {
      return element(selector);
    },
    createElement(tag) {
      if (tag !== "a") {
        return {
          addEventListener() {},
          click() {},
          style: {},
        };
      }
      return {
        href: "",
        download: "",
        click() {
          clickedDownload = this.download;
        },
        style: {},
      };
    },
    body: { append() {} },
  },
  WebAssembly: {
    instantiate: async () => ({ instance: {} }),
  },
  Blob,
  Error,
  Promise,
  Uint8Array,
  URL: {
    createObjectURL: (blob) => {
      objectURLBlob = blob;
      return "blob:test";
    },
    revokeObjectURL() {},
  },
  atob: () => "\0",
  clearTimeout,
  console,
  performance: { now: () => 0 },
  setTimeout,
};
context.globalThis = context;
context.self = context.window;
context.navigator = { clipboard: { writeText: async () => {} } };

vm.createContext(context);
vm.runInContext(source, context);

(async () => {
  const statuses = [];
  const sink = await context.makeSink({ status(value) { statuses.push(value); } });
  const open = sink.open;
  const writer = await open("fallback.bin", 3);
  await writer.write(new Uint8Array([4, 5, 6]));
  await writer.close();

  if (clickedDownload !== "fallback.bin") {
    throw new Error("fallback download name was not preserved");
  }
  if (!objectURLBlob || objectURLBlob.size !== 3) {
    throw new Error("fallback did not buffer received bytes");
  }
  if (!statuses.some((value) => value.includes("buffering receive"))) {
    throw new Error("fallback warning was not emitted");
  }
})().catch((err) => {
  console.error(err.stack || err.message);
  process.exit(1);
});
`

	cmd := exec.Command("node", "-e", script, filepath.Join("..", "web", "derphole", "app.js"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node receive sink fallback regression failed: %v\n%s", err, out)
	}
}

func TestWebReceiveSinkBridgeCallsWriterMethodsWithReceiver(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "cmd", "derphole-web", "main.go"))
	if err != nil {
		t.Fatalf("read derphole web bridge: %v", err)
	}
	body := string(data)
	if strings.Contains(body, "write.Invoke(u8)") {
		t.Fatal("jsFileSink.WriteChunk extracts writer.write and invokes it without the writer receiver")
	}
	if strings.Contains(body, "closeFn.Invoke()") {
		t.Fatal("jsFileSink.Close extracts writer.close and invokes it without the writer receiver")
	}
	for _, want := range []string{
		`s.writer.Call("write", u8)`,
		`s.writer.Call("close")`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("derphole web bridge missing receiver-preserving call %q", want)
		}
	}
}
