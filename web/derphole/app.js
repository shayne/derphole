const els = {
  selectSendFile: document.querySelector("#select-send-file"),
  startSend: document.querySelector("#start-send"),
  sendFile: document.querySelector("#send-file"),
  sendToken: document.querySelector("#send-token"),
  copyToken: document.querySelector("#copy-token"),
  sendProgress: document.querySelector("#send-progress"),
  sendStatus: document.querySelector("#send-status"),
  receiveToken: document.querySelector("#receive-token"),
  startReceive: document.querySelector("#start-receive"),
  receiveProgress: document.querySelector("#receive-progress"),
  receiveStatus: document.querySelector("#receive-status"),
};

let selectedFile = null;

const wasmReady = startWASM();

els.selectSendFile.addEventListener("click", async () => {
  selectedFile = await pickFile();
  if (!selectedFile) {
    return;
  }
  els.sendFile.textContent = `${selectedFile.name} (${formatBytes(selectedFile.size)})`;
  els.startSend.disabled = false;
});

els.startSend.addEventListener("click", async () => {
  if (!selectedFile) {
    return;
  }
  await wasmReady;
  const progress = makeProgress(els.sendProgress, els.sendStatus);
  setBusy(els.startSend, true);
  try {
    progress.status("creating-offer");
    const token = await window.derpholeWASM.createOffer();
    els.sendToken.value = token;
    els.copyToken.disabled = false;
    progress.status("waiting-for-claim");
    const direct = makeDirectTransport(progress);
    await window.derpholeWASM.sendFile(selectedFile, progress.callbacks, direct);
  } catch (err) {
    progress.status(`error: ${err.message || err}`);
  } finally {
    setBusy(els.startSend, false);
  }
});

els.copyToken.addEventListener("click", async () => {
  await navigator.clipboard.writeText(els.sendToken.value);
});

els.startReceive.addEventListener("click", async () => {
  const token = els.receiveToken.value.trim();
  if (!token) {
    els.receiveStatus.textContent = "error: paste a token first";
    return;
  }
  await wasmReady;
  const progress = makeProgress(els.receiveProgress, els.receiveStatus);
  setBusy(els.startReceive, true);
  try {
    const sink = await makeSink(progress);
    progress.status("claiming");
    const direct = makeDirectTransport(progress);
    await window.derpholeWASM.receiveFile(token, sink, progress.callbacks, direct);
  } catch (err) {
    progress.status(`error: ${err.message || err}`);
  } finally {
    setBusy(els.startReceive, false);
  }
});

async function startWASM() {
  if (!window.Go) {
    throw new Error("wasm_exec.js did not load");
  }
  const go = new window.Go();
  const bytes = await loadWASMBytes();
  const result = await WebAssembly.instantiate(bytes, go.importObject);
  go.run(result.instance);
  await waitForAPI();
}

async function loadWASMBytes() {
  if (window.derpholeWasmBase64) {
    const binary = atob(window.derpholeWasmBase64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  const response = await fetch("derphole-web.wasm");
  if (!response.ok) {
    throw new Error(`failed to fetch wasm: ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

async function waitForAPI() {
  for (let i = 0; i < 100; i++) {
    if (window.derpholeWASM) {
      return;
    }
    await delay(20);
  }
  throw new Error("derphole wasm API did not initialize");
}

async function pickFile() {
  if (window.showOpenFilePicker) {
    const [handle] = await window.showOpenFilePicker({ multiple: false });
    return handle.getFile();
  }
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.addEventListener("change", () => resolve(input.files?.[0] || null), { once: true });
    input.click();
  });
}

async function makeSink(progress) {
  if (window.showSaveFilePicker) {
    return {
      async open(name) {
        const handle = await window.showSaveFilePicker({
          suggestedName: name || "derphole-download",
          startIn: "downloads",
          id: "derphole-receive",
        });
        const stream = await handle.createWritable();
        return bindWritableStream(stream);
      },
    };
  }
  progress.status("warning: save picker unavailable; buffering receive in browser memory");
  return {
    async open(name) {
      const chunks = [];
      const filename = name || "derphole-download";
      return {
        write: async (chunk) => {
          chunks.push(chunk.slice());
        },
        close: async () => {
          const blob = new Blob(chunks);
          const url = URL.createObjectURL(blob);
          const link = document.createElement("a");
          link.href = url;
          link.download = filename;
          link.click();
          URL.revokeObjectURL(url);
        },
      };
    },
  };
}

function bindWritableStream(stream) {
  return {
    write: async (chunk) => stream.write(chunk),
    close: async () => stream.close(),
  };
}

function makeProgress(output, statusEl) {
  const state = {
    started: performance.now(),
    samples: [],
    bytes: 0,
    total: -1,
  };
  const render = () => {
    output.textContent = formatProgress(state);
  };
  render();
  return {
    callbacks: {
      status(value) {
        statusEl.textContent = value;
      },
      progress(bytes, total) {
        state.bytes = bytes;
        state.total = total;
        recordSample(state, bytes);
        render();
      },
      trace(value) {
        console.debug(`[derphole] ${value}`);
      },
    },
    status(value) {
      statusEl.textContent = value;
    },
  };
}

function makeDirectTransport(progress) {
  if (typeof window.createDerpholeWebRTCTransport !== "function") {
    progress.status("relay-only: WebRTC unavailable");
    return null;
  }
  const direct = window.createDerpholeWebRTCTransport({
    status(value) {
      progress.status(value);
    },
  });
  if (!direct) {
    progress.status("relay-only: WebRTC unavailable");
  }
  return direct;
}

function recordSample(state, bytes) {
  const now = performance.now();
  state.samples.push({ time: now, bytes });
  const cutoff = now - 5000;
  while (state.samples.length > 2 && state.samples[0].time < cutoff) {
    state.samples.shift();
  }
}

function formatProgress(state) {
  const total = state.total > 0 ? state.total : state.bytes;
  const ratio = total > 0 ? Math.min(1, state.bytes / total) : 0;
  const percent = String(Math.floor(ratio * 100)).padStart(3, " ");
  const width = 20;
  const fill = Math.round(ratio * width);
  const bar = `${"#".repeat(fill)}${".".repeat(width - fill)}`;
  const elapsed = (performance.now() - state.started) / 1000;
  const rate = currentRate(state);
  const remaining = rate > 0 && total > state.bytes ? (total - state.bytes) / rate : 0;
  return `${percent}%|${bar}| ${formatBytes(state.bytes)}/${formatBytes(total)} [${formatDuration(elapsed)}<${formatDuration(remaining)}, ${formatBytes(rate)}/s]`;
}

function currentRate(state) {
  if (state.samples.length < 2) {
    return 0;
  }
  const first = state.samples[0];
  const last = state.samples[state.samples.length - 1];
  const seconds = (last.time - first.time) / 1000;
  if (seconds <= 0) {
    return 0;
  }
  return Math.max(0, (last.bytes - first.bytes) / seconds);
}

function formatBytes(value) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let n = Number.isFinite(value) && value >= 0 ? value : 0;
  let unit = 0;
  while (n >= 1024 && unit < units.length - 1) {
    n /= 1024;
    unit++;
  }
  if (unit === 0) {
    return `${Math.round(n)}B`;
  }
  return `${n.toFixed(1)}${units[unit]}`;
}

function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) {
    seconds = 0;
  }
  const total = Math.floor(seconds);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) {
    return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function setBusy(button, busy) {
  button.disabled = busy;
}
