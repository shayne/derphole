package scripts

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWebRTCTransportWaitsForSendQueueCapacity(t *testing.T) {
	t.Parallel()

	script := `
const fs = require("fs");
const vm = require("vm");

const source = fs.readFileSync(process.argv[1], "utf8");
let dataChannel;

class FakeDataChannel {
  constructor() {
    this.binaryType = "";
    this.bufferedAmount = 0;
    this.bufferedAmountLowThreshold = 0;
    this.failNextSend = false;
    this.readyState = "open";
    this.sent = 0;
  }
  send(bytes) {
    const length = bytes.byteLength ?? bytes.length ?? 0;
    if (this.failNextSend) {
      this.failNextSend = false;
      throw new Error("Failed to execute 'send' on 'RTCDataChannel': RTCDataChannel send queue is full");
    }
    if (this.bufferedAmount + length > 16 * 1024 * 1024) {
      throw new Error("Failed to execute 'send' on 'RTCDataChannel': RTCDataChannel send queue is full");
    }
    this.bufferedAmount += length;
    this.sent++;
  }
  close() {
    this.readyState = "closed";
  }
}

class FakeRTCPeerConnection {
  constructor() {
    this.connectionState = "new";
    this.iceConnectionState = "new";
  }
  createDataChannel() {
    dataChannel = new FakeDataChannel();
    queueMicrotask(() => dataChannel.onopen?.({}));
    return dataChannel;
  }
  async createOffer() {
    return { type: "offer", sdp: "fake-offer" };
  }
  async setLocalDescription() {}
  close() {}
}

const context = {
  window: { RTCPeerConnection: FakeRTCPeerConnection },
  ArrayBuffer,
  Error,
  Promise,
  Uint8Array,
  clearTimeout,
  queueMicrotask,
  setTimeout,
};
vm.createContext(context);
vm.runInContext(source, context);

(async () => {
  const transport = context.window.createDerpholeWebRTCTransport();
  await transport.start("sender", () => {});
  await transport.ready();

  dataChannel.bufferedAmount = 16 * 1024 * 1024 - 1;
  let rejected;
  let resolved = false;
  const sendPromise = transport.send(new Uint8Array(16 * 1024)).then(
    () => { resolved = true; },
    (err) => { rejected = err; },
  );

  await new Promise((resolve) => setTimeout(resolve, 0));
  if (rejected) {
    throw new Error("send rejected instead of waiting for capacity: " + rejected.message);
  }
  if (resolved || dataChannel.sent !== 0) {
    throw new Error("send should wait while the next frame would exceed queue capacity");
  }

  dataChannel.bufferedAmount = 0;
  dataChannel.onbufferedamountlow?.({});
  await sendPromise;

  if (rejected) {
    throw rejected;
  }
  if (!resolved || dataChannel.sent !== 1) {
    throw new Error("send did not resume after bufferedamountlow");
  }

  dataChannel.bufferedAmount = 0;
  dataChannel.failNextSend = true;
  await transport.send(new Uint8Array(16 * 1024));
  if (dataChannel.sent !== 2) {
    throw new Error("send did not retry a transient queue-full exception");
  }
})().catch((err) => {
  console.error(err.stack || err.message);
  process.exit(1);
});
`

	cmd := exec.Command("node", "-e", script, filepath.Join("..", "web", "derphole", "webrtc.js"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node regression failed: %v\n%s", err, out)
	}
}
