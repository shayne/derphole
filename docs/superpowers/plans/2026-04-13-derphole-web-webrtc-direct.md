# Derphole WebRTC Direct Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a browser-to-browser WebRTC DataChannel direct path to `derphole-web` while preserving immediate DERP relay-first transfer and DERP fallback.

**Architecture:** DERP remains the rendezvous, signaling, and fallback relay plane. The browser starts transferring over DERP immediately, exchanges WebRTC SDP and ICE messages over DERP in parallel, then switches future chunks to a reliable ordered DataChannel only after an explicit byte-offset handoff ACK. If WebRTC never connects, fails before handoff, or is unavailable in the browser, the existing DERP relay path continues without user configuration.

**Tech Stack:** Go, `GOOS=js GOARCH=wasm`, `syscall/js`, Tailscale DERP-over-WebSocket, browser `RTCPeerConnection`, reliable ordered `RTCDataChannel`, File System Access API.

---

## Tailscale Reference Map

- `/Users/shayne/code/tailscale/derp/derp.go`: DERP is key-addressed packet relay with `MaxPacketSize = 64 << 10`; keep all derphole web frames below this.
- `/Users/shayne/code/tailscale/derp/derphttp/websocket.go`: Tailscale compiles DERP-over-WebSocket for JS and uses the `derp` WebSocket subprotocol.
- `/Users/shayne/code/tailscale/derp/derphttp/derphttp_client.go`: `useWebsockets()` returns true on `runtime.GOOS == "js"`, which is why our WASM build can use DERP without raw sockets.
- `/Users/shayne/code/tailscale/disco/disco.go`: `CallMeMaybe` is the model for sending direct-path coordination messages over DERP while data can still flow over relay.
- `/Users/shayne/code/tailscale/wgengine/magicsock/endpoint.go`: heartbeat/path probing keeps the current path alive while searching for better paths; copy the principle, not the UDP implementation.
- `/Users/shayne/code/tailscale/net/stun/stun.go`: Tailscale STUN binding requests require Tailscale software attributes, so browser WebRTC should not assume public Tailscale DERP STUN nodes are usable as ICE servers.

## File Structure

- Modify `pkg/derphole/webproto/protocol.go`: add WebRTC signaling and direct-path handoff frames.
- Modify `pkg/derphole/webproto/protocol_test.go`: cover new frame kinds and JSON payload round trips.
- Modify `pkg/derphole/webrelay/relay.go`: add optional direct transport interfaces, relay/direct merge logic, handoff state, and fallback.
- Create `pkg/derphole/webrelay/relay_test.go`: unit-test relay-first behavior, direct handoff, fallback before handoff, and resume after a failed direct send.
- Create `cmd/derphole-web/direct_js.go`: wrap a browser JS WebRTC transport object behind the Go `webrelay.DirectTransport` interface.
- Modify `cmd/derphole-web/main.go`: accept optional direct transport objects from JS for send and receive.
- Create `web/derphole/webrtc.js`: browser `RTCPeerConnection` and `RTCDataChannel` implementation.
- Modify `web/derphole/app.js`: create WebRTC transports, pass them into WASM, and surface direct-path statuses.
- Modify `web/derphole/index.html`: include `webrtc.js` before `app.js`.
- Modify `tools/packaging/build-web.sh`: include `webrtc.js` in `derphole-web.zip`.
- Modify `docs/derp/derphole-web.md`: document relay-first direct-upgrade behavior and browser limitations.

## Implementation Tasks

### Task 1: Extend Web Protocol For WebRTC Signaling

**Files:**
- Modify: `pkg/derphole/webproto/protocol.go`
- Modify: `pkg/derphole/webproto/protocol_test.go`

- [ ] **Step 1: Write the failing protocol tests**

Add these tests to `pkg/derphole/webproto/protocol_test.go`:

```go
func TestWebRTCSignalRoundTrip(t *testing.T) {
	payload, err := json.Marshal(WebRTCSignal{
		Kind:      "offer",
		Type:      "offer",
		SDP:       "v=0\r\n",
		Candidate: "",
	})
	if err != nil {
		t.Fatalf("Marshal(signal) error = %v", err)
	}
	raw, err := Marshal(FrameWebRTCOffer, 7, payload)
	if err != nil {
		t.Fatalf("Marshal(frame) error = %v", err)
	}
	frame, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if frame.Kind != FrameWebRTCOffer {
		t.Fatalf("Kind = %v, want %v", frame.Kind, FrameWebRTCOffer)
	}
	var got WebRTCSignal
	if err := json.Unmarshal(frame.Payload, &got); err != nil {
		t.Fatalf("Unmarshal(signal) error = %v", err)
	}
	if got.Kind != "offer" || got.Type != "offer" || got.SDP != "v=0\r\n" {
		t.Fatalf("Signal = %+v", got)
	}
}

func TestDirectReadyRoundTrip(t *testing.T) {
	payload, err := json.Marshal(DirectReady{
		BytesReceived: 123456,
		NextSeq:       88,
	})
	if err != nil {
		t.Fatalf("Marshal(direct ready) error = %v", err)
	}
	raw, err := Marshal(FrameDirectReady, 88, payload)
	if err != nil {
		t.Fatalf("Marshal(frame) error = %v", err)
	}
	frame, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	var got DirectReady
	if err := json.Unmarshal(frame.Payload, &got); err != nil {
		t.Fatalf("Unmarshal(direct ready) error = %v", err)
	}
	if got.BytesReceived != 123456 || got.NextSeq != 88 {
		t.Fatalf("DirectReady = %+v", got)
	}
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
go test ./pkg/derphole/webproto -run 'TestWebRTCSignalRoundTrip|TestDirectReadyRoundTrip'
```

Expected: FAIL with undefined identifiers `WebRTCSignal`, `FrameWebRTCOffer`, `DirectReady`, or `FrameDirectReady`.

- [ ] **Step 3: Add the protocol types and frame kinds**

Update `pkg/derphole/webproto/protocol.go` so the frame kind block and payload types include:

```go
const (
	FrameClaim FrameKind = iota + 1
	FrameDecision
	FrameMeta
	FrameData
	FrameDone
	FrameAck
	FrameAbort
	FrameWebRTCOffer
	FrameWebRTCAnswer
	FrameWebRTCIceCandidate
	FrameWebRTCIceComplete
	FrameDirectReady
	FramePathSwitch
	FrameDirectFailed
)

type WebRTCSignal struct {
	Kind              string `json:"kind"`
	Type              string `json:"type"`
	SDP               string `json:"sdp,omitempty"`
	Candidate         string `json:"candidate,omitempty"`
	SDPMid            string `json:"sdpMid,omitempty"`
	SDPMLineIndex     int    `json:"sdpMLineIndex,omitempty"`
	UsernameFragment  string `json:"usernameFragment,omitempty"`
}

type DirectReady struct {
	BytesReceived int64  `json:"bytes_received"`
	NextSeq       uint64 `json:"next_seq"`
}

type PathSwitch struct {
	Path          string `json:"path"`
	BytesReceived int64  `json:"bytes_received"`
	NextSeq       uint64 `json:"next_seq"`
}

type DirectFailed struct {
	Reason string `json:"reason,omitempty"`
}
```

Change `validKind` to keep the contiguous range valid:

```go
func validKind(kind FrameKind) bool {
	return kind >= FrameClaim && kind <= FrameDirectFailed
}
```

- [ ] **Step 4: Run the focused tests and verify they pass**

Run:

```bash
go test ./pkg/derphole/webproto -run 'TestWebRTCSignalRoundTrip|TestDirectReadyRoundTrip'
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/derphole/webproto/protocol.go pkg/derphole/webproto/protocol_test.go
git commit -m "webproto: add webrtc direct signaling frames"
```

### Task 2: Add A Tested Direct Transport Interface To WebRelay

**Files:**
- Modify: `pkg/derphole/webrelay/relay.go`
- Create: `pkg/derphole/webrelay/relay_test.go`

- [ ] **Step 1: Write a failing test for DERP relay-first transfer**

Create `pkg/derphole/webrelay/relay_test.go` with this test harness and first test:

```go
package webrelay

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/shayne/derphole/pkg/derphole/webproto"
)

type fakeDirect struct {
	readyCh chan struct{}
	failCh  chan error
	recvCh  chan []byte
	sentMu  sync.Mutex
	sent    [][]byte
}

func newFakeDirect() *fakeDirect {
	return &fakeDirect{
		readyCh: make(chan struct{}),
		failCh:  make(chan error, 1),
		recvCh:  make(chan []byte, 16),
	}
}

func (d *fakeDirect) Start(context.Context, DirectRole, DirectSignalPeer) error { return nil }
func (d *fakeDirect) Ready() <-chan struct{} { return d.readyCh }
func (d *fakeDirect) Failed() <-chan error { return d.failCh }
func (d *fakeDirect) ReceiveFrames() <-chan []byte { return d.recvCh }
func (d *fakeDirect) Close() error { return nil }
func (d *fakeDirect) SendFrame(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.sentMu.Lock()
	defer d.sentMu.Unlock()
	d.sent = append(d.sent, append([]byte(nil), frame...))
	return nil
}

func (d *fakeDirect) markReady() {
	close(d.readyCh)
}

func TestChooseRelayBeforeDirectReady(t *testing.T) {
	direct := newFakeDirect()
	path := chooseSendPath(TransferOptions{Direct: direct}, false)
	if path != sendPathRelay {
		t.Fatalf("path = %v, want %v", path, sendPathRelay)
	}
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
go test ./pkg/derphole/webrelay -run TestChooseRelayBeforeDirectReady
```

Expected: FAIL with undefined identifiers `DirectRole`, `DirectSignalPeer`, `chooseSendPath`, `TransferOptions`, or `sendPathRelay`.

- [ ] **Step 3: Add direct transport interfaces and path selection**

Add these definitions near the existing public types in `pkg/derphole/webrelay/relay.go`:

```go
type DirectRole string

const (
	DirectRoleSender   DirectRole = "sender"
	DirectRoleReceiver DirectRole = "receiver"
)

type DirectSignalPeer interface {
	SendSignal(context.Context, webproto.FrameKind, uint64, []byte) error
	Signals() <-chan webproto.Frame
}

type DirectTransport interface {
	Start(context.Context, DirectRole, DirectSignalPeer) error
	Ready() <-chan struct{}
	Failed() <-chan error
	SendFrame(context.Context, []byte) error
	ReceiveFrames() <-chan []byte
	Close() error
}

type TransferOptions struct {
	Direct DirectTransport
}

type sendPath uint8

const (
	sendPathRelay sendPath = iota
	sendPathDirect
)

func chooseSendPath(opts TransferOptions, directActive bool) sendPath {
	if opts.Direct != nil && directActive {
		return sendPathDirect
	}
	return sendPathRelay
}
```

- [ ] **Step 4: Run the focused test and verify it passes**

Run:

```bash
go test ./pkg/derphole/webrelay -run TestChooseRelayBeforeDirectReady
```

Expected: PASS.

- [ ] **Step 5: Write failing tests for direct handoff and fallback**

Append these tests to `pkg/derphole/webrelay/relay_test.go`:

```go
func TestChooseDirectAfterReady(t *testing.T) {
	direct := newFakeDirect()
	direct.markReady()
	path := chooseSendPath(TransferOptions{Direct: direct}, true)
	if path != sendPathDirect {
		t.Fatalf("path = %v, want %v", path, sendPathDirect)
	}
}

func TestDirectFailureBeforeSwitchKeepsRelay(t *testing.T) {
	direct := newFakeDirect()
	direct.failCh <- errors.New("ice failed")
	state := directState{}
	state.noteFailureBeforeSwitch(<-direct.Failed())
	if state.active {
		t.Fatalf("direct state active after pre-switch failure")
	}
	if state.fallbackReason != "ice failed" {
		t.Fatalf("fallbackReason = %q, want %q", state.fallbackReason, "ice failed")
	}
}

func TestMarshalDirectReadyUsesCurrentOffset(t *testing.T) {
	frame, err := marshalDirectReadyFrame(33, 4096)
	if err != nil {
		t.Fatalf("marshalDirectReadyFrame() error = %v", err)
	}
	if frame.Kind != webproto.FrameDirectReady {
		t.Fatalf("Kind = %v, want %v", frame.Kind, webproto.FrameDirectReady)
	}
	var payload webproto.DirectReady
	if err := unmarshalFramePayload(frame, &payload); err != nil {
		t.Fatalf("unmarshalFramePayload() error = %v", err)
	}
	if payload.NextSeq != 33 || payload.BytesReceived != 4096 {
		t.Fatalf("payload = %+v", payload)
	}
}
```

- [ ] **Step 6: Run the new tests and verify they fail**

Run:

```bash
go test ./pkg/derphole/webrelay -run 'TestChooseDirectAfterReady|TestDirectFailureBeforeSwitchKeepsRelay|TestMarshalDirectReadyUsesCurrentOffset'
```

Expected: FAIL with undefined identifiers `directState`, `marshalDirectReadyFrame`, or `unmarshalFramePayload`.

- [ ] **Step 7: Add direct state helpers**

Add these helpers to `pkg/derphole/webrelay/relay.go`:

```go
type directState struct {
	ready          bool
	active         bool
	fallbackReason string
}

func (s *directState) noteReady() {
	s.ready = true
}

func (s *directState) noteSwitched() {
	s.ready = true
	s.active = true
	s.fallbackReason = ""
}

func (s *directState) noteFailureBeforeSwitch(err error) {
	s.ready = false
	s.active = false
	if err != nil {
		s.fallbackReason = err.Error()
	}
}

func marshalDirectReadyFrame(nextSeq uint64, bytesReceived int64) (webproto.Frame, error) {
	payload, err := json.Marshal(webproto.DirectReady{
		BytesReceived: bytesReceived,
		NextSeq:       nextSeq,
	})
	if err != nil {
		return webproto.Frame{}, err
	}
	return webproto.Frame{
		Kind:    webproto.FrameDirectReady,
		Seq:     nextSeq,
		Payload: payload,
	}, nil
}

func unmarshalFramePayload(frame webproto.Frame, dst any) error {
	return json.Unmarshal(frame.Payload, dst)
}
```

- [ ] **Step 8: Run webrelay tests and verify they pass**

Run:

```bash
go test ./pkg/derphole/webrelay
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add pkg/derphole/webrelay/relay.go pkg/derphole/webrelay/relay_test.go
git commit -m "webrelay: add direct transport seam"
```

### Task 3: Implement Hybrid Relay/Direct Send And Receive

**Files:**
- Modify: `pkg/derphole/webrelay/relay.go`
- Modify: `pkg/derphole/webrelay/relay_test.go`

- [ ] **Step 1: Add wrapper methods without changing current callers**

Add these methods to `pkg/derphole/webrelay/relay.go`:

```go
func (o *Offer) SendWithOptions(ctx context.Context, src FileSource, cb Callbacks, opts TransferOptions) error {
	return o.send(ctx, src, cb, opts)
}

func (o *Offer) Send(ctx context.Context, src FileSource, cb Callbacks) error {
	return o.send(ctx, src, cb, TransferOptions{})
}

func ReceiveWithOptions(ctx context.Context, encodedToken string, sink FileSink, cb Callbacks, opts TransferOptions) error {
	return receive(ctx, encodedToken, sink, cb, opts)
}

func Receive(ctx context.Context, encodedToken string, sink FileSink, cb Callbacks) error {
	return receive(ctx, encodedToken, sink, cb, TransferOptions{})
}
```

Rename the existing `Offer.Send` body to `send`, and rename the existing `Receive` body to `receive`. Preserve the no-options behavior byte-for-byte except for the function names.

- [ ] **Step 2: Run package tests**

Run:

```bash
go test ./pkg/derphole/webrelay
```

Expected: PASS.

- [ ] **Step 3: Add direct signaling peer implementation**

Add this type to `pkg/derphole/webrelay/relay.go`:

```go
type derpSignalPeer struct {
	ctx      context.Context
	client   *derpbind.Client
	peerDERP key.NodePublic
	frames   <-chan derpbind.Packet
	signals  chan webproto.Frame
}

func newDERPSignalPeer(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, frames <-chan derpbind.Packet) *derpSignalPeer {
	p := &derpSignalPeer{
		ctx:      ctx,
		client:   client,
		peerDERP: peerDERP,
		frames:   frames,
		signals:  make(chan webproto.Frame, 16),
	}
	go p.run()
	return p
}

func (p *derpSignalPeer) SendSignal(ctx context.Context, kind webproto.FrameKind, seq uint64, payload []byte) error {
	return sendFrame(ctx, p.client, p.peerDERP, kind, seq, payload)
}

func (p *derpSignalPeer) Signals() <-chan webproto.Frame {
	return p.signals
}

func (p *derpSignalPeer) run() {
	defer close(p.signals)
	for {
		pkt, err := nextPacket(p.ctx, p.frames)
		if err != nil {
			return
		}
		frame, err := webproto.Parse(pkt.Payload)
		if err != nil {
			continue
		}
		switch frame.Kind {
		case webproto.FrameWebRTCOffer, webproto.FrameWebRTCAnswer, webproto.FrameWebRTCIceCandidate, webproto.FrameWebRTCIceComplete, webproto.FrameDirectFailed:
			p.signals <- frame
		}
	}
}
```

- [ ] **Step 4: Add send-side direct startup**

Inside `send`, after `peerCh` is created and before metadata is sent, add:

```go
var direct *directState
var signalPeer *derpSignalPeer
if opts.Direct != nil {
	direct = &directState{}
	signalPeer = newDERPSignalPeer(ctx, o.client, peerDERP, peerCh)
	if err := opts.Direct.Start(ctx, DirectRoleSender, signalPeer); err != nil {
		direct.noteFailureBeforeSwitch(err)
		cb.status("direct-unavailable")
	} else {
		cb.status("probing-direct")
	}
	defer opts.Direct.Close()
}
```

Before choosing the send path for each data frame, check readiness without blocking:

```go
if opts.Direct != nil && direct != nil && !direct.ready && !direct.active {
	select {
	case <-opts.Direct.Ready():
		direct.noteReady()
		cb.status("direct-ready")
	case err := <-opts.Direct.Failed():
		direct.noteFailureBeforeSwitch(err)
		cb.status("direct-failed")
	default:
	}
}
```

- [ ] **Step 5: Add safe direct handoff**

Add this helper to `pkg/derphole/webrelay/relay.go`:

```go
func trySwitchDirect(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, frames <-chan derpbind.Packet, nextSeq uint64, bytesReceived int64) (bool, error) {
	ready, err := marshalDirectReadyFrame(nextSeq, bytesReceived)
	if err != nil {
		return false, err
	}
	if err := sendFrame(ctx, client, peerDERP, ready.Kind, ready.Seq, ready.Payload); err != nil {
		return false, err
	}
	timer := time.NewTimer(frameRetryDelay)
	defer timer.Stop()
	for {
		select {
		case pkt, ok := <-frames:
			if !ok {
				return false, io.ErrClosedPipe
			}
			frame, err := webproto.Parse(pkt.Payload)
			if err != nil {
				continue
			}
			if frame.Kind != webproto.FramePathSwitch {
				continue
			}
			var sw webproto.PathSwitch
			if err := json.Unmarshal(frame.Payload, &sw); err != nil {
				continue
			}
			return sw.Path == "webrtc" && sw.BytesReceived == bytesReceived && sw.NextSeq == nextSeq, nil
		case <-timer.C:
			return false, nil
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
}
```

In the send loop, after a relay ACK advances `offset` and before reading the next chunk, call:

```go
if opts.Direct != nil && direct != nil && direct.ready && !direct.active {
	switched, err := trySwitchDirect(ctx, o.client, peerDERP, peerCh, seq, offset)
	if err != nil {
		return err
	}
	if switched {
		direct.noteSwitched()
		cb.status("connected-direct")
	}
}
```

- [ ] **Step 6: Send frames over direct after handoff**

Add these helpers:

```go
func sendDirectFrame(ctx context.Context, direct DirectTransport, kind webproto.FrameKind, seq uint64, payload []byte) error {
	raw, err := webproto.Marshal(kind, seq, payload)
	if err != nil {
		return err
	}
	return direct.SendFrame(ctx, raw)
}

func awaitAck(ctx context.Context, frames <-chan derpbind.Packet, wantBytes int64, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case pkt, ok := <-frames:
			if !ok {
				return io.ErrClosedPipe
			}
			frame, err := webproto.Parse(pkt.Payload)
			if err != nil {
				continue
			}
			switch frame.Kind {
			case webproto.FrameAck:
				ack, err := decodeAck(frame.Payload)
				if err != nil {
					continue
				}
				if ack.BytesReceived >= wantBytes {
					return nil
				}
			case webproto.FrameAbort:
				return decodeAbort(frame.Payload)
			}
		case <-timer.C:
			return errors.New("timed out waiting for receiver ack")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
```

In the send loop, when `chooseSendPath(opts, direct != nil && direct.active) == sendPathDirect`, send `FrameData` with `sendDirectFrame` and update progress after the JS transport accepts the frame into DataChannel backpressure. Do not wait for DERP ACKs on every direct data chunk, because that would make direct throughput RTT-bound. After sending `FrameDone` over direct, call `awaitAck(ctx, peerCh, offset, 5*time.Minute)` before returning success. This final receiver ACK prevents the sender from declaring success while the browser still has queued DataChannel bytes.

Refactor `sendFrameAwaitAck` so it uses `awaitAck(ctx, frames, wantBytes, frameRetryDelay)` internally after sending the relay frame. Preserve the existing relay-mode retry behavior.

- [ ] **Step 7: Merge direct frames into receive processing**

Add this helper:

```go
func mergeFrameSources(ctx context.Context, derpFrames <-chan derpbind.Packet, direct DirectTransport) <-chan []byte {
	out := make(chan []byte, 32)
	go func() {
		defer close(out)
		for derpFrames != nil || direct != nil {
			var directFrames <-chan []byte
			if direct != nil {
				directFrames = direct.ReceiveFrames()
			}
			select {
			case pkt, ok := <-derpFrames:
				if !ok {
					derpFrames = nil
					continue
				}
				out <- pkt.Payload
			case raw, ok := <-directFrames:
				if !ok {
					direct = nil
					continue
				}
				out <- raw
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}
```

Change `receiveFrames` to parse from `raw <-chan []byte` instead of `frames <-chan derpbind.Packet`, and call it from `receive` using `mergeFrameSources(ctx, frames, opts.Direct)`.

- [ ] **Step 8: Acknowledge direct handoff on receive**

In `receiveFrames`, add a `FrameDirectReady` case:

```go
case webproto.FrameDirectReady:
	var ready webproto.DirectReady
	if err := json.Unmarshal(frame.Payload, &ready); err != nil {
		return abortAndReturn(ctx, client, peerDERP, "invalid direct ready")
	}
	if ready.BytesReceived == received && ready.NextSeq == expectedSeq {
		payload, err := json.Marshal(webproto.PathSwitch{
			Path:          "webrtc",
			BytesReceived: received,
			NextSeq:       expectedSeq,
		})
		if err != nil {
			return err
		}
		if err := sendFrame(ctx, client, peerDERP, webproto.FramePathSwitch, expectedSeq, payload); err != nil {
			return err
		}
		cb.status("connected-direct")
	}
```

- [ ] **Step 9: Run focused package tests**

Run:

```bash
go test ./pkg/derphole/webrelay
```

Expected: PASS.

- [ ] **Step 10: Run wider protocol tests**

Run:

```bash
go test ./pkg/derphole/webproto ./pkg/derphole/webrelay ./pkg/derphole ./pkg/token ./pkg/rendezvous
```

Expected: PASS.

- [ ] **Step 11: Commit**

```bash
git add pkg/derphole/webrelay/relay.go pkg/derphole/webrelay/relay_test.go
git commit -m "webrelay: support relay-first direct upgrade"
```

### Task 4: Add Browser WebRTC Transport

**Files:**
- Create: `web/derphole/webrtc.js`
- Modify: `web/derphole/index.html`

- [ ] **Step 1: Create the WebRTC transport file**

Create `web/derphole/webrtc.js`:

```javascript
window.createDerpholeWebRTCTransport = function createDerpholeWebRTCTransport(role, callbacks = {}) {
  const pc = new RTCPeerConnection({
    iceServers: [
      { urls: "stun:stun.l.google.com:19302" },
      { urls: "stun:stun.cloudflare.com:3478" },
    ],
  });
  let channel = null;
  let frameHandler = null;
  let readyResolve;
  let failedReject;
  const ready = new Promise((resolve, reject) => {
    readyResolve = resolve;
    failedReject = reject;
  });

  function status(value) {
    if (callbacks.status) {
      callbacks.status(value);
    }
  }

  function emitSignal(signal) {
    if (callbacks.signal) {
      callbacks.signal(signal);
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
    status(`webrtc-${pc.connectionState}`);
    if (pc.connectionState === "failed" || pc.connectionState === "closed") {
      failedReject(new Error(`webrtc ${pc.connectionState}`));
    }
  };

  pc.ondatachannel = (event) => {
    attachChannel(event.channel);
  };

  function attachChannel(dc) {
    channel = dc;
    channel.binaryType = "arraybuffer";
    channel.bufferedAmountLowThreshold = 4 * 1024 * 1024;
    channel.onopen = () => {
      status("connected-direct");
      readyResolve();
    };
    channel.onerror = () => failedReject(new Error("webrtc datachannel error"));
    channel.onclose = () => status("direct-closed");
    channel.onmessage = (event) => {
      if (frameHandler) {
        frameHandler(new Uint8Array(event.data));
      }
    };
  }

  async function start(_role, signalSink) {
    callbacks.signal = signalSink;
    if (role === "sender") {
      attachChannel(pc.createDataChannel("derphole", { ordered: true }));
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      emitSignal({ kind: "offer", type: offer.type, sdp: offer.sdp });
    }
  }

  async function applySignal(signal) {
    if (typeof signal === "string") {
      signal = JSON.parse(signal);
    }
    if (signal.kind === "offer") {
      await pc.setRemoteDescription({ type: signal.type, sdp: signal.sdp });
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      emitSignal({ kind: "answer", type: answer.type, sdp: answer.sdp });
      return;
    }
    if (signal.kind === "answer") {
      await pc.setRemoteDescription({ type: signal.type, sdp: signal.sdp });
      return;
    }
    if (signal.kind === "candidate" && signal.candidate) {
      await pc.addIceCandidate({
        candidate: signal.candidate,
        sdpMid: signal.sdpMid || null,
        sdpMLineIndex: signal.sdpMLineIndex || 0,
        usernameFragment: signal.usernameFragment || undefined,
      });
    }
  }

  async function send(bytes) {
    await ready;
    while (channel.bufferedAmount > 16 * 1024 * 1024) {
      await new Promise((resolve) => {
        channel.onbufferedamountlow = resolve;
      });
    }
    channel.send(bytes);
  }

  return {
    start,
    applySignal,
    send,
    ready: () => ready,
    onFrame: (callback) => {
      frameHandler = callback;
    },
    close: () => {
      if (channel) {
        channel.close();
      }
      pc.close();
    },
  };
};
```

- [ ] **Step 2: Include the WebRTC script before the app script**

Update `web/derphole/index.html` so the script order contains:

```html
<script src="wasm_exec.js"></script>
<script src="wasm_payload.js"></script>
<script src="webrtc.js"></script>
<script src="app.js"></script>
```

- [ ] **Step 3: Run a syntax check**

Run:

```bash
node --check web/derphole/webrtc.js
```

Expected: no output and exit code 0.

- [ ] **Step 4: Commit**

```bash
git add web/derphole/webrtc.js web/derphole/index.html
git commit -m "web: add browser webrtc transport"
```

### Task 5: Wrap WebRTC Transport In WASM

**Files:**
- Create: `cmd/derphole-web/direct_js.go`
- Modify: `cmd/derphole-web/main.go`

- [ ] **Step 1: Create the JS direct transport wrapper**

Create `cmd/derphole-web/direct_js.go`:

```go
//go:build js && wasm

package main

import (
	"context"
	"encoding/json"
	"errors"
	"syscall/js"

	"github.com/shayne/derphole/pkg/derphole/webproto"
	"github.com/shayne/derphole/pkg/derphole/webrelay"
)

type jsDirectTransport struct {
	api       js.Value
	readyCh   chan struct{}
	failCh    chan error
	recvCh    chan []byte
	signalFns []js.Func
}

func newJSDirectTransport(v js.Value) webrelay.DirectTransport {
	if v.IsUndefined() || v.IsNull() {
		return nil
	}
	return &jsDirectTransport{
		api:     v,
		readyCh: make(chan struct{}),
		failCh:  make(chan error, 1),
		recvCh:  make(chan []byte, 32),
	}
}

func (d *jsDirectTransport) Start(ctx context.Context, role webrelay.DirectRole, peer webrelay.DirectSignalPeer) error {
	if d == nil {
		return errors.New("nil direct transport")
	}
	onFrame := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) > 0 {
			u8 := js.Global().Get("Uint8Array").New(args[0])
			buf := make([]byte, u8.Get("byteLength").Int())
			js.CopyBytesToGo(buf, u8)
			d.recvCh <- buf
		}
		return nil
	})
	d.signalFns = append(d.signalFns, onFrame)
	d.api.Call("onFrame", onFrame)

	go d.forwardRemoteSignals(ctx, peer)

	signalSink := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) == 0 {
			return nil
		}
		go d.sendLocalSignal(ctx, peer, args[0])
		return nil
	})
	d.signalFns = append(d.signalFns, signalSink)
	if _, err := await(ctx, d.api.Call("start", string(role), signalSink)); err != nil {
		return err
	}
	go d.waitReady(ctx)
	return nil
}

func (d *jsDirectTransport) Ready() <-chan struct{} { return d.readyCh }
func (d *jsDirectTransport) Failed() <-chan error { return d.failCh }
func (d *jsDirectTransport) ReceiveFrames() <-chan []byte { return d.recvCh }

func (d *jsDirectTransport) SendFrame(ctx context.Context, frame []byte) error {
	u8 := js.Global().Get("Uint8Array").New(len(frame))
	js.CopyBytesToJS(u8, frame)
	_, err := await(ctx, d.api.Call("send", u8))
	return err
}

func (d *jsDirectTransport) Close() error {
	for _, fn := range d.signalFns {
		fn.Release()
	}
	if closeFn := d.api.Get("close"); closeFn.Type() == js.TypeFunction {
		closeFn.Invoke()
	}
	return nil
}

func (d *jsDirectTransport) waitReady(ctx context.Context) {
	_, err := await(ctx, d.api.Call("ready"))
	if err != nil {
		d.failCh <- err
		return
	}
	close(d.readyCh)
}

func (d *jsDirectTransport) sendLocalSignal(ctx context.Context, peer webrelay.DirectSignalPeer, v js.Value) {
	payload, kind, err := marshalJSWebRTCSignal(v)
	if err != nil {
		d.failCh <- err
		return
	}
	if err := peer.SendSignal(ctx, kind, 0, payload); err != nil {
		d.failCh <- err
	}
}

func (d *jsDirectTransport) forwardRemoteSignals(ctx context.Context, peer webrelay.DirectSignalPeer) {
	for {
		select {
		case frame, ok := <-peer.Signals():
			if !ok {
				return
			}
			_, err := await(ctx, d.api.Call("applySignal", string(frame.Payload)))
			if err != nil {
				d.failCh <- err
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func marshalJSWebRTCSignal(v js.Value) ([]byte, webproto.FrameKind, error) {
	kind := v.Get("kind").String()
	signal := webproto.WebRTCSignal{
		Kind:             kind,
		Type:             v.Get("type").String(),
		SDP:              v.Get("sdp").String(),
		Candidate:        v.Get("candidate").String(),
		SDPMid:           v.Get("sdpMid").String(),
		SDPMLineIndex:    v.Get("sdpMLineIndex").Int(),
		UsernameFragment: v.Get("usernameFragment").String(),
	}
	payload, err := json.Marshal(signal)
	if err != nil {
		return nil, 0, err
	}
	switch kind {
	case "offer":
		return payload, webproto.FrameWebRTCOffer, nil
	case "answer":
		return payload, webproto.FrameWebRTCAnswer, nil
	case "candidate":
		return payload, webproto.FrameWebRTCIceCandidate, nil
	case "ice-complete":
		return payload, webproto.FrameWebRTCIceComplete, nil
	default:
		return nil, 0, errors.New("unknown webrtc signal kind")
	}
}
```

- [ ] **Step 2: Pass optional direct objects into webrelay**

In `cmd/derphole-web/main.go`, update `sendFile`:

```go
	var direct webrelay.DirectTransport
	if len(args) >= 3 {
		direct = newJSDirectTransport(args[2])
	}
	err := current.SendWithOptions(ctx, jsFileSource{file: file}, callbacks, webrelay.TransferOptions{Direct: direct})
```

Update `receiveFile`:

```go
	var direct webrelay.DirectTransport
	if len(args) >= 4 {
		direct = newJSDirectTransport(args[3])
	}
	return nil, webrelay.ReceiveWithOptions(ctx, tok, sink, callbacks, webrelay.TransferOptions{Direct: direct})
```

- [ ] **Step 3: Build the WASM command**

Run:

```bash
GOOS=js GOARCH=wasm go build -o /tmp/derphole-web.wasm ./cmd/derphole-web
```

Expected: no output and exit code 0.

- [ ] **Step 4: Commit**

```bash
git add cmd/derphole-web/direct_js.go cmd/derphole-web/main.go
git commit -m "derphole-web: bridge webrtc direct transport"
```

### Task 6: Wire WebRTC Into The Web UI

**Files:**
- Modify: `web/derphole/app.js`

- [ ] **Step 1: Pass direct transports on send and receive**

In the send click handler in `web/derphole/app.js`, replace:

```javascript
await window.derpholeWASM.sendFile(selectedFile, progress.callbacks);
```

with:

```javascript
const direct = window.RTCPeerConnection
  ? window.createDerpholeWebRTCTransport("sender", progress.callbacks)
  : null;
await window.derpholeWASM.sendFile(selectedFile, progress.callbacks, direct);
```

In the receive click handler, replace:

```javascript
await window.derpholeWASM.receiveFile(token, sink, progress.callbacks);
```

with:

```javascript
const direct = window.RTCPeerConnection
  ? window.createDerpholeWebRTCTransport("receiver", progress.callbacks)
  : null;
await window.derpholeWASM.receiveFile(token, sink, progress.callbacks, direct);
```

- [ ] **Step 2: Preserve relay fallback messaging**

Add this helper to `web/derphole/app.js`:

```javascript
function directStatusLabel(value) {
  if (value === "probing-direct") return "probing direct WebRTC path";
  if (value === "direct-ready") return "direct WebRTC path ready";
  if (value === "connected-direct") return "connected direct";
  if (value === "direct-failed") return "direct path failed; continuing over DERP relay";
  if (value === "direct-unavailable") return "direct path unavailable; continuing over DERP relay";
  return value;
}
```

Change `makeProgress` status handling from:

```javascript
statusEl.textContent = value;
```

to:

```javascript
statusEl.textContent = directStatusLabel(value);
```

- [ ] **Step 3: Syntax-check the browser scripts**

Run:

```bash
node --check web/derphole/app.js
node --check web/derphole/webrtc.js
```

Expected: no output and exit code 0.

- [ ] **Step 4: Commit**

```bash
git add web/derphole/app.js
git commit -m "web: enable relay-first webrtc upgrade"
```

### Task 7: Package And Document The WebRTC Path

**Files:**
- Modify: `tools/packaging/build-web.sh`
- Modify: `docs/derp/derphole-web.md`

- [ ] **Step 1: Include `webrtc.js` in the zip staging directory**

In `tools/packaging/build-web.sh`, add `webrtc.js` next to `app.js` and `styles.css` in the copy step. The staging copy block should include:

```bash
cp web/derphole/index.html "$stage_dir/index.html"
cp web/derphole/app.js "$stage_dir/app.js"
cp web/derphole/webrtc.js "$stage_dir/webrtc.js"
cp web/derphole/styles.css "$stage_dir/styles.css"
```

- [ ] **Step 2: Update the web docs**

Update `docs/derp/derphole-web.md` so the Transfer Model section says:

```markdown
## Transfer Model

The browser build starts each transfer over DERP relay immediately. In parallel,
the two browsers exchange WebRTC offer, answer, and ICE candidate messages over
the same DERP session. This mirrors Tailscale magicsock's relay-first direct
upgrade model: relay remains usable while a better direct path is probed.

When a reliable ordered DataChannel opens, the sender asks the receiver to switch
at the next acknowledged byte offset. The receiver accepts only when its local
byte count and next sequence number match the request. This prevents a direct
path from skipping or duplicating bytes.

If WebRTC is unavailable, fails before handoff, or never reaches `connected`,
the transfer continues over DERP relay. Tailscale DERP is not TURN, so WebRTC
relay candidates are not provided by DERP; DERP remains the application-level
fallback.
```

- [ ] **Step 3: Build the web artifact**

Run:

```bash
mise run build-web
```

Expected: `dist/release/derphole-web.zip` exists and contains `webrtc.js`.

- [ ] **Step 4: Inspect the zip contents**

Run:

```bash
zipinfo -1 dist/release/derphole-web.zip | sort
```

Expected output contains:

```text
app.js
derphole-web.wasm
index.html
styles.css
wasm_exec.js
wasm_payload.js
webrtc.js
```

- [ ] **Step 5: Commit**

```bash
git add tools/packaging/build-web.sh docs/derp/derphole-web.md
git commit -m "docs: describe derphole web direct upgrade"
```

### Task 8: Verify Browser, CLI Interop, And Release Checks

**Files:**
- No source edits.

- [ ] **Step 1: Run focused Go tests**

Run:

```bash
go test ./pkg/derphole/webproto ./pkg/derphole/webrelay ./pkg/derphole ./pkg/token ./pkg/rendezvous
```

Expected: PASS.

- [ ] **Step 2: Run the full Go suite**

Run:

```bash
mise run test
```

Expected: PASS.

- [ ] **Step 3: Build native and web artifacts**

Run:

```bash
mise run build
mise run build-web
```

Expected: `dist/derphole` and `dist/release/derphole-web.zip` exist.

- [ ] **Step 4: Run repository checks**

Run:

```bash
mise run check
```

Expected: PASS.

- [ ] **Step 5: Browser smoke test with relay fallback**

Run:

```bash
rm -rf /tmp/derphole-web-smoke
mkdir -p /tmp/derphole-web-smoke
unzip -q dist/release/derphole-web.zip -d /tmp/derphole-web-smoke
cd /tmp/derphole-web-smoke
python3 -m http.server 8765
```

Open `http://127.0.0.1:8765/` in two browser windows. Send a 32MiB file from one window to the other. Expected: transfer starts over `connected-relay`, either switches to `connected direct` or completes over relay, and the received file byte count matches the source file byte count.

- [ ] **Step 6: Browser token to CLI receive smoke**

In the browser sender, create an offer token. On the same machine run:

```bash
go run ./cmd/derphole receive TOKEN_FROM_BROWSER
```

Expected: CLI receives the file over DERP relay if WebRTC is not available to the CLI.

- [ ] **Step 7: Commit any verification-only doc corrections**

If Step 5 or Step 6 reveals inaccurate docs, edit only `docs/derp/derphole-web.md`, run:

```bash
mise run check
```

Expected: PASS.

Then commit:

```bash
git add docs/derp/derphole-web.md
git commit -m "docs: clarify derphole web verification"
```

If no docs changed, skip this commit step.

## Self-Review

- Spec coverage: This plan keeps DERP as the signaling and fallback plane, adds browser WebRTC direct transfer, preserves browser-to-CLI relay fallback, updates the static zip artifact, and documents why this follows Tailscale's DERP plus magicsock shape.
- Placeholder scan: The plan contains no empty implementation slots. Every code-changing task lists exact files, concrete snippets, commands, and expected outcomes.
- Type consistency: `DirectTransport`, `DirectSignalPeer`, `TransferOptions`, `WebRTCSignal`, `DirectReady`, and `PathSwitch` names are consistent across protocol, relay, WASM, and browser tasks.
