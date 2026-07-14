// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
const createdPeerConnections = [];
const createdChannels = [];
const emittedSignals = [];

class FakeDataChannel {
  constructor(label, options) {
    this.label = label;
    this.options = options || {};
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
  constructor(config) {
	this.config = config;
    this.connectionState = "new";
    this.iceConnectionState = "new";
    createdPeerConnections.push(this);
  }
  createDataChannel(label, options) {
    const channel = new FakeDataChannel(label, options);
    dataChannel = channel;
    createdChannels.push(channel);
    queueMicrotask(() => channel.onopen?.({}));
    return channel;
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
	performance: { now: () => Date.now() },
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
  const publicSTUNURLs = [
	"stun:stun.l.google.com:19302",
	"stun:stun.cloudflare.com:3478",
  ];
  await transport.start("sender", (signal) => emittedSignals.push(signal), publicSTUNURLs);
  await Promise.race([
    transport.ready(),
    new Promise((_, reject) => setTimeout(() => reject(new Error("timed out waiting for WebRTC ready")), 100)),
  ]);

  if (createdPeerConnections.length !== 2) {
    throw new Error("expected 2 independent PeerConnections, got " + createdPeerConnections.length);
  }
  for (const pc of createdPeerConnections) {
	const got = pc.config.iceServers.map((server) => server.urls);
	if (got.join(",") !== publicSTUNURLs.join(",")) {
	  throw new Error("public ICE servers changed: " + got.join(","));
	}
  }
  const offerLanes = emittedSignals.filter((signal) => signal.kind === "offer").map((signal) => signal.lane).sort();
  if (offerLanes.join(",") !== "0,1") {
    throw new Error("expected lane-tagged offers for lanes 0..1, got " + offerLanes.join(","));
  }
  if (createdChannels.length !== 2) {
    throw new Error("expected 2 striped DataChannels, got " + createdChannels.length);
  }
  for (const channel of createdChannels) {
    if (channel.options.ordered !== false) {
      throw new Error("striped DataChannel should be unordered");
    }
  }

  for (let i = 0; i < 4; i++) {
    await transport.send(new Uint8Array(1024));
  }
  for (const channel of createdChannels) {
    if (channel.sent !== 2) {
      throw new Error("expected round-robin striping across channels, got sent=" + createdChannels.map((ch) => ch.sent).join(","));
    }
    channel.sent = 0;
  }

  for (const channel of createdChannels) {
    channel.bufferedAmount = 8 * 1024 * 1024 - 1;
  }
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

  createdChannels[1].bufferedAmount = 0;
  createdChannels[1].onbufferedamountlow?.({});
  await sendPromise;

  if (rejected) {
    throw rejected;
  }
  if (!resolved || createdChannels[1].sent !== 1) {
    throw new Error("send did not resume after bufferedamountlow");
  }

  for (const channel of createdChannels) {
    channel.bufferedAmount = 0;
    channel.failNextSend = true;
  }
  await transport.send(new Uint8Array(16 * 1024));
  const sentAfterRetry = createdChannels.reduce((sum, channel) => sum + channel.sent, 0);
  if (sentAfterRetry !== 2) {
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

func TestWebRTCTransportUsesOnlyConfiguredCustomSTUNServer(t *testing.T) {
	t.Parallel()

	script := `
const fs = require("fs");
const vm = require("vm");

const source = fs.readFileSync(process.argv[1], "utf8");
const configs = [];
class FakeRTCPeerConnection {
  constructor(config) {
	configs.push(config);
	this.connectionState = "new";
	this.iceConnectionState = "new";
  }
  close() {}
}
const context = {
  window: { RTCPeerConnection: FakeRTCPeerConnection },
  ArrayBuffer,
  Error,
  performance: { now: () => Date.now() },
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
  const custom = "stun:[2001:db8::7]:5349";
  await transport.start("receiver", () => {}, [custom]);
  if (configs.length !== 2) {
	throw new Error("expected 2 PeerConnections, got " + configs.length);
  }
  for (const config of configs) {
	const got = config.iceServers.map((server) => server.urls);
	if (got.length !== 1 || got[0] !== custom) {
	  throw new Error("custom ICE servers leaked public fallback: " + got.join(","));
	}
  }
})().catch((err) => {
  console.error(err.stack || err.message);
  process.exit(1);
});
`

	cmd := exec.Command("node", "-e", script, filepath.Join("..", "web", "derphole", "webrtc.js"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node custom STUN regression failed: %v\n%s", err, out)
	}
}
