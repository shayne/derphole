(function () {
  const dataChannelCount = 2;
  const bufferHighWater = 8 * 1024 * 1024;
  const bufferLowWater = 2 * 1024 * 1024;

  window.createDerpholeWebRTCTransport = function createDerpholeWebRTCTransport(callbacks = {}) {
    const PeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    if (!PeerConnection) {
      return null;
    }

    let nextSendLane = 0;
    let frameHandler = null;
    let signalSink = null;
    let readySettled = false;
    let failedSettled = false;
    const stats = {
      sendFrames: 0,
      sendBytes: 0,
      sendCallMs: 0,
      waitCount: 0,
      waitMs: 0,
      queueFullErrors: 0,
      maxBufferedAmount: 0,
      lanes: [],
    };

    let readyResolve;
    let readyReject;
    const readyPromise = new Promise((resolve, reject) => {
      readyResolve = resolve;
      readyReject = reject;
    });

    let failedReject;
    const failedPromise = new Promise((resolve, reject) => {
      failedReject = reject;
    });

    let lanes = [];

    function createLane(index, iceServers) {
      const pc = new PeerConnection({
        iceServers,
      });
      const lane = {
        index,
        pc,
        channel: null,
        open: false,
        lowWaiters: [],
        pendingCandidates: [],
        sendFrames: 0,
        sendBytes: 0,
        maxBufferedAmount: 0,
      };

      pc.onicecandidate = (event) => {
        if (event.candidate) {
          status(`webrtc-ice-candidate-${index}`);
          emitSignal(lane, {
            kind: "candidate",
            candidate: event.candidate.candidate,
            sdpMid: event.candidate.sdpMid || "",
            sdpMLineIndex: event.candidate.sdpMLineIndex || 0,
            usernameFragment: event.candidate.usernameFragment || "",
          });
          return;
        }
        status(`webrtc-ice-complete-${index}`);
        emitSignal(lane, { kind: "ice-complete" });
      };

      pc.onconnectionstatechange = () => {
        const state = pc.connectionState;
        status(`webrtc-${index}-${state}`);
        if (state === "failed") {
          fail(`webrtc lane ${index} ${state}`);
        }
      };

      pc.oniceconnectionstatechange = () => {
        const state = pc.iceConnectionState;
        if (state === "failed") {
          fail(`webrtc lane ${index} ice ${state}`);
        }
      };

      pc.ondatachannel = (event) => {
        attachChannel(lane, event.channel);
      };

      return lane;
    }

    function status(value) {
      callbacks.status?.(value);
    }

    function resolveReadyIfEnoughOpenChannels() {
      if (readySettled) {
        return;
      }
      if (openLanes().length < dataChannelCount) {
        return;
      }
      readySettled = true;
      status("connected-direct");
      readyResolve();
    }

    function fail(reason) {
      const error = reason instanceof Error ? reason : new Error(String(reason || "direct path failed"));
      if (!readySettled) {
        readySettled = true;
        readyReject(error);
      }
      if (!failedSettled) {
        failedSettled = true;
        failedReject(error);
      }
    }

    function emitSignal(lane, signal) {
      if (signalSink) {
        signalSink({ lane: lane.index, ...signal });
      }
    }

    function attachChannel(lane, dc) {
      lane.channel = dc;
      lane.open = false;
      dc.binaryType = "arraybuffer";
      dc.bufferedAmountLowThreshold = bufferLowWater;
      dc.onopen = () => {
        lane.open = true;
        status(`webrtc-datachannel-open-${openLanes().length}/${dataChannelCount}`);
        resolveReadyIfEnoughOpenChannels();
      };
      dc.onerror = () => fail("webrtc datachannel error");
      dc.onclose = () => {
        lane.open = false;
        resolveLaneWaiters(lane);
        if (!readySettled) {
          fail("webrtc datachannel closed before open");
          return;
        }
        if (openLanes().length === 0) {
          fail("webrtc datachannels closed");
        }
      };
      dc.onbufferedamountlow = () => resolveLaneWaiters(lane);
      dc.onmessage = (event) => {
        if (!frameHandler) {
          return;
        }
        if (event.data instanceof ArrayBuffer) {
          frameHandler(new Uint8Array(event.data));
          return;
        }
        if (ArrayBuffer.isView(event.data)) {
          frameHandler(new Uint8Array(event.data.buffer, event.data.byteOffset, event.data.byteLength));
        }
      };
    }

    async function start(role, nextSignalSink, stunURLs) {
      if (!Array.isArray(stunURLs)) {
        throw new Error("webrtc STUN URLs are required");
      }
      if (lanes.length !== 0) {
        throw new Error("webrtc transport already started");
      }
      const iceServers = stunURLs.map((url) => ({ urls: url }));
      lanes = Array.from({ length: dataChannelCount }, (_, index) => createLane(index, iceServers));
      signalSink = nextSignalSink;
      status("probing-direct");
      status(`webrtc-role-${role}`);
      if (role !== "sender") {
        return;
      }
      for (const lane of lanes) {
        attachChannel(lane, lane.pc.createDataChannel(`derphole-${lane.index}`, { ordered: false }));
        const offer = await lane.pc.createOffer();
        await lane.pc.setLocalDescription(offer);
        status(`webrtc-offer-${lane.index}`);
        emitSignal(lane, { kind: "offer", type: offer.type, sdp: offer.sdp || "" });
      }
    }

    async function applySignal(signal) {
      if (typeof signal === "string") {
        signal = JSON.parse(signal);
      }
      const lane = laneForSignal(signal);
      const pc = lane.pc;
      if (signal.kind === "offer") {
        status(`webrtc-offer-received-${lane.index}`);
        await pc.setRemoteDescription({ type: signal.type, sdp: signal.sdp });
        await flushPendingCandidates(lane);
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        status(`webrtc-answer-${lane.index}`);
        emitSignal(lane, { kind: "answer", type: answer.type, sdp: answer.sdp || "" });
        return;
      }
      if (signal.kind === "answer") {
        status(`webrtc-answer-received-${lane.index}`);
        await pc.setRemoteDescription({ type: signal.type, sdp: signal.sdp });
        await flushPendingCandidates(lane);
        return;
      }
      if (signal.kind === "candidate") {
        const candidate = {
          candidate: signal.candidate,
          sdpMid: signal.sdpMid || null,
          sdpMLineIndex: signal.sdpMLineIndex || 0,
          usernameFragment: signal.usernameFragment || undefined,
        };
        if (!pc.remoteDescription) {
          lane.pendingCandidates.push(candidate);
          return;
        }
        await pc.addIceCandidate(candidate);
        return;
      }
      if (signal.kind === "ice-complete" && pc.remoteDescription) {
        await pc.addIceCandidate(null).catch(() => {});
      }
    }

    function laneForSignal(signal) {
      const index = Number.isInteger(signal.lane) ? signal.lane : 0;
      if (index < 0 || index >= lanes.length) {
        throw new Error("invalid webrtc signal lane");
      }
      return lanes[index];
    }

    async function flushPendingCandidates(lane) {
      const candidates = lane.pendingCandidates;
      lane.pendingCandidates = [];
      for (const candidate of candidates) {
        await lane.pc.addIceCandidate(candidate);
      }
    }

    async function send(bytes) {
      await readyPromise;
      for (;;) {
        const lane = pickSendLane(byteLength(bytes));
        if (!lane) {
          const started = performance.now();
          stats.waitCount++;
          await Promise.race([waitForAnyLaneCapacity(byteLength(bytes)), failedPromise]);
          stats.waitMs += performance.now() - started;
          continue;
        }
        try {
          const started = performance.now();
          lane.channel.send(bytes);
          stats.sendCallMs += performance.now() - started;
          stats.sendFrames++;
          stats.sendBytes += byteLength(bytes);
          lane.sendFrames++;
          lane.sendBytes += byteLength(bytes);
          if (lane.channel.bufferedAmount > lane.maxBufferedAmount) {
            lane.maxBufferedAmount = lane.channel.bufferedAmount;
          }
          if (lane.channel.bufferedAmount > stats.maxBufferedAmount) {
            stats.maxBufferedAmount = lane.channel.bufferedAmount;
          }
          return;
        } catch (err) {
          if (!isSendQueueFullError(err)) {
            throw err;
          }
          stats.queueFullErrors++;
          await Promise.race([waitForLaneLow(lane), failedPromise]);
        }
      }
    }

    function pickSendLane(size) {
      for (let i = 0; i < lanes.length; i++) {
        const idx = (nextSendLane + i) % lanes.length;
        const lane = lanes[idx];
        if (laneHasCapacity(lane, size)) {
          nextSendLane = (idx + 1) % lanes.length;
          return lane;
        }
      }
      return null;
    }

    function laneHasCapacity(lane, size) {
      return lane && lane.open && lane.channel && lane.channel.readyState === "open" && lane.channel.bufferedAmount + size <= bufferHighWater;
    }

    function openLanes() {
      return lanes.filter((lane) => lane.open && lane.channel && lane.channel.readyState === "open");
    }

    function waitForAnyLaneCapacity(size) {
      if (lanes.some((lane) => laneHasCapacity(lane, size))) {
        return Promise.resolve();
      }
      return new Promise((resolve) => {
        let done = false;
        const waiter = () => {
          if (done || !lanes.some((lane) => laneHasCapacity(lane, size))) {
            return;
          }
          done = true;
          resolve();
        };
        for (const lane of lanes) {
          lane.lowWaiters.push(waiter);
        }
      });
    }

    function waitForLaneLow(lane) {
      if (!lane || !lane.channel || lane.channel.bufferedAmount <= bufferLowWater) {
        return Promise.resolve();
      }
      return new Promise((resolve) => {
        lane.lowWaiters.push(resolve);
      });
    }

    function resolveLaneWaiters(lane) {
      const waiters = lane.lowWaiters.splice(0);
      for (const resolve of waiters) {
        resolve();
      }
    }

    function byteLength(bytes) {
      if (!bytes) {
        return 0;
      }
      if (typeof bytes === "string") {
        return new TextEncoder().encode(bytes).byteLength;
      }
      if (typeof bytes.byteLength === "number") {
        return bytes.byteLength;
      }
      if (typeof bytes.length === "number") {
        return bytes.length;
      }
      return 0;
    }

    function isSendQueueFullError(err) {
      return String(err?.message || err).includes("send queue is full");
    }

    function close() {
      fail("webrtc closed");
      for (const lane of lanes) {
        if (lane.channel && lane.channel.readyState !== "closed") {
          lane.channel.close();
        }
        lane.pc.close();
      }
    }

    return {
      start,
      applySignal,
      ready: () => readyPromise,
      failed: () => failedPromise,
      send,
      stats() {
        return {
          ...stats,
          bufferedAmount: lanes.reduce((sum, lane) => sum + (lane.channel ? lane.channel.bufferedAmount : 0), 0),
          lanes: lanes.map((lane) => ({
            index: lane.index,
            label: lane.channel?.label || "",
            open: lane.open,
            bufferedAmount: lane.channel ? lane.channel.bufferedAmount : 0,
            maxBufferedAmount: lane.maxBufferedAmount,
            sendFrames: lane.sendFrames,
            sendBytes: lane.sendBytes,
          })),
        };
      },
      onFrame(callback) {
        frameHandler = callback;
      },
      close,
    };
  };
})();
