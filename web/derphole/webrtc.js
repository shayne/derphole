(function () {
  const bufferHighWater = 16 * 1024 * 1024;
  const bufferLowWater = 4 * 1024 * 1024;

  window.createDerpholeWebRTCTransport = function createDerpholeWebRTCTransport(callbacks = {}) {
    const PeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    if (!PeerConnection) {
      return null;
    }

    const pc = new PeerConnection({
      iceServers: [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun.cloudflare.com:3478" },
      ],
    });

    let channel = null;
    let frameHandler = null;
    let signalSink = null;
    let pendingCandidates = [];
    let readySettled = false;
    let failedSettled = false;

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

    function status(value) {
      callbacks.status?.(value);
    }

    function resolveReady() {
      if (readySettled) {
        return;
      }
      readySettled = true;
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

    function emitSignal(signal) {
      if (signalSink) {
        signalSink(signal);
      }
    }

    pc.onicecandidate = (event) => {
      if (event.candidate) {
        emitSignal({
          kind: "candidate",
          candidate: event.candidate.candidate,
          sdpMid: event.candidate.sdpMid || "",
          sdpMLineIndex: event.candidate.sdpMLineIndex || 0,
          usernameFragment: event.candidate.usernameFragment || "",
        });
        return;
      }
      emitSignal({ kind: "ice-complete" });
    };

    pc.onconnectionstatechange = () => {
      const state = pc.connectionState;
      status(`webrtc-${state}`);
      if (state === "failed") {
        fail(`webrtc ${state}`);
      }
    };

    pc.oniceconnectionstatechange = () => {
      const state = pc.iceConnectionState;
      if (state === "failed") {
        fail(`webrtc ice ${state}`);
      }
    };

    pc.ondatachannel = (event) => {
      attachChannel(event.channel);
    };

    function attachChannel(dc) {
      channel = dc;
      channel.binaryType = "arraybuffer";
      channel.bufferedAmountLowThreshold = bufferLowWater;
      channel.onopen = () => {
        status("connected-direct");
        resolveReady();
      };
      channel.onerror = () => fail("webrtc datachannel error");
      channel.onclose = () => {
        if (!readySettled) {
          fail("webrtc datachannel closed before open");
        }
      };
      channel.onmessage = (event) => {
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

    async function start(role, nextSignalSink) {
      signalSink = nextSignalSink;
      status("probing-direct");
      if (role === "sender") {
        attachChannel(pc.createDataChannel("derphole", { ordered: true }));
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        emitSignal({ kind: "offer", type: offer.type, sdp: offer.sdp || "" });
      }
    }

    async function applySignal(signal) {
      if (typeof signal === "string") {
        signal = JSON.parse(signal);
      }
      if (signal.kind === "offer") {
        await pc.setRemoteDescription({ type: signal.type, sdp: signal.sdp });
        await flushPendingCandidates();
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        emitSignal({ kind: "answer", type: answer.type, sdp: answer.sdp || "" });
        return;
      }
      if (signal.kind === "answer") {
        await pc.setRemoteDescription({ type: signal.type, sdp: signal.sdp });
        await flushPendingCandidates();
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
          pendingCandidates.push(candidate);
          return;
        }
        await pc.addIceCandidate(candidate);
        return;
      }
      if (signal.kind === "ice-complete" && pc.remoteDescription) {
        await pc.addIceCandidate(null).catch(() => {});
      }
    }

    async function flushPendingCandidates() {
      const candidates = pendingCandidates;
      pendingCandidates = [];
      for (const candidate of candidates) {
        await pc.addIceCandidate(candidate);
      }
    }

    async function send(bytes) {
      await readyPromise;
      if (!channel || channel.readyState !== "open") {
        throw new Error("webrtc datachannel is not open");
      }
      while (channel.bufferedAmount > bufferHighWater) {
        await Promise.race([waitForBufferedAmountLow(), failedPromise]);
        if (!channel || channel.readyState !== "open") {
          throw new Error("webrtc datachannel closed");
        }
      }
      channel.send(bytes);
    }

    function waitForBufferedAmountLow() {
      if (!channel || channel.bufferedAmount <= bufferLowWater) {
        return Promise.resolve();
      }
      return new Promise((resolve) => {
        const previous = channel.onbufferedamountlow;
        channel.onbufferedamountlow = (event) => {
          channel.onbufferedamountlow = previous || null;
          previous?.(event);
          resolve();
        };
      });
    }

    function close() {
      fail("webrtc closed");
      if (channel && channel.readyState !== "closed") {
        channel.close();
      }
      pc.close();
    }

    return {
      start,
      applySignal,
      ready: () => readyPromise,
      failed: () => failedPromise,
      send,
      onFrame(callback) {
        frameHandler = callback;
      },
      close,
    };
  };
})();
