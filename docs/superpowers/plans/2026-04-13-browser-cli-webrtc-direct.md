# Browser CLI WebRTC Direct Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make browser-to-CLI and CLI-to-browser derphole web-token transfers stream immediately over DERP relay, upgrade to WebRTC direct when possible, and retain relay as a bounded safety net.

**Architecture:** Keep `pkg/derphole/webrelay` as the single transfer engine. Add a bounded relay send window, offset-safe path switching, and a native Pion-backed implementation of the existing `webrelay.DirectTransport` interface. Wire native CLI web-token paths to the new direct transport while preserving browser WASM direct support.

**Tech Stack:** Go 1.26, existing DERP/webrelay protocol, browser `RTCPeerConnection`, Pion WebRTC for native CLI, existing `mise` tasks, local fake DERP tests, headless browser smoke tests.

---

## File Structure

- Create `pkg/derphole/webrelay/window.go`: bounded in-flight relay frame window, cumulative ACK retirement, retransmission selection, direct replay extraction.
- Create `pkg/derphole/webrelay/window_test.go`: fast unit tests for window accounting and memory bounds.
- Modify `pkg/derphole/webrelay/relay.go`: replace stop-and-wait data sending with windowed relay sending; keep metadata and done ACKs strict; make direct switch offset-safe.
- Modify `pkg/derphole/webrelay/relay_test.go`: add transfer-level tests for pipelining, direct handoff replay, relay fallback, cancel, and EOF.
- Create `pkg/derphole/webrtcdirect/transport.go`: Pion-backed native `webrelay.DirectTransport`.
- Create `pkg/derphole/webrtcdirect/transport_test.go`: loopback and signal-exchange tests for native transport.
- Modify `pkg/derphole/transfer.go`: instantiate native WebRTC direct transport for browser web-file tokens unless relay is forced.
- Modify `pkg/derphole/transfer_test.go`: assert browser web-file receive gets direct transport by default and skips it when forced relay is set.
- Modify `web/derphole/webrtc.js`: keep browser behavior compatible with the native Pion signal format and expose direct timing statuses.
- Modify `docs/derp/derphole-web.md`: document relay-first, WebRTC-target behavior and relay-only fallback.
- Modify `docs/benchmarks.md`: add browser↔CLI benchmark commands and expected metrics.

## Task 1: Relay Window Primitive

**Files:**
- Create: `pkg/derphole/webrelay/window.go`
- Create: `pkg/derphole/webrelay/window_test.go`

- [ ] **Step 1: Write failing relay window tests**

Create `pkg/derphole/webrelay/window_test.go`:

```go
package webrelay

import (
	"bytes"
	"testing"
)

func TestRelayWindowEnforcesFrameAndByteLimits(t *testing.T) {
	w := newRelayWindow(relayWindowConfig{MaxBytes: 6, MaxFrames: 2})
	if !w.canSend(3) {
		t.Fatal("window should accept first 3 byte frame")
	}
	w.push(relayFrame{Seq: 1, Offset: 0, NextOffset: 3, Payload: []byte("abc")})
	w.push(relayFrame{Seq: 2, Offset: 3, NextOffset: 6, Payload: []byte("def")})
	if w.canSend(1) {
		t.Fatal("window accepted frame past frame limit")
	}
	w.ack(3)
	if !w.canSend(1) {
		t.Fatal("window did not free capacity after cumulative ACK")
	}
}

func TestRelayWindowAckRetiresOnlyCommittedFrames(t *testing.T) {
	w := newRelayWindow(relayWindowConfig{MaxBytes: 64, MaxFrames: 8})
	w.push(relayFrame{Seq: 1, Offset: 0, NextOffset: 3, Payload: []byte("abc")})
	w.push(relayFrame{Seq: 2, Offset: 3, NextOffset: 6, Payload: []byte("def")})
	w.push(relayFrame{Seq: 3, Offset: 6, NextOffset: 9, Payload: []byte("ghi")})
	w.ack(5)
	if got := w.ackedOffset(); got != 5 {
		t.Fatalf("ackedOffset = %d, want 5", got)
	}
	if got := w.inFlightBytes(); got != 6 {
		t.Fatalf("inFlightBytes = %d, want 6", got)
	}
	w.ack(6)
	if got := w.inFlightBytes(); got != 3 {
		t.Fatalf("inFlightBytes = %d, want 3", got)
	}
}

func TestRelayWindowReplayFromOffset(t *testing.T) {
	w := newRelayWindow(relayWindowConfig{MaxBytes: 64, MaxFrames: 8})
	w.push(relayFrame{Seq: 1, Offset: 0, NextOffset: 3, Payload: []byte("abc")})
	w.push(relayFrame{Seq: 2, Offset: 3, NextOffset: 6, Payload: []byte("def")})
	w.push(relayFrame{Seq: 3, Offset: 6, NextOffset: 9, Payload: []byte("ghi")})
	w.ack(3)

	replay := w.replayFrom(3)
	if len(replay) != 2 {
		t.Fatalf("replay frame count = %d, want 2", len(replay))
	}
	if replay[0].Seq != 2 || !bytes.Equal(replay[0].Payload, []byte("def")) {
		t.Fatalf("first replay frame = %+v", replay[0])
	}
	if replay[1].Seq != 3 || !bytes.Equal(replay[1].Payload, []byte("ghi")) {
		t.Fatalf("second replay frame = %+v", replay[1])
	}
}

func TestRelayWindowBoundsUnknownLengthBufferedBytes(t *testing.T) {
	w := newRelayWindow(relayWindowConfig{MaxBytes: 10, MaxFrames: 10})
	w.push(relayFrame{Seq: 1, Offset: 0, NextOffset: 4, Payload: []byte("aaaa")})
	w.push(relayFrame{Seq: 2, Offset: 4, NextOffset: 8, Payload: []byte("bbbb")})
	if w.canSend(4) {
		t.Fatal("window accepted payload that would exceed MaxBytes")
	}
	if got := w.bufferedPayloadBytes(); got != 8 {
		t.Fatalf("bufferedPayloadBytes = %d, want 8", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./pkg/derphole/webrelay -run 'TestRelayWindow' -count=1
```

Expected: FAIL with undefined identifiers `newRelayWindow`, `relayWindowConfig`, and `relayFrame`.

- [ ] **Step 3: Implement relay window primitive**

Create `pkg/derphole/webrelay/window.go`:

```go
package webrelay

type relayWindowConfig struct {
	MaxBytes  int64
	MaxFrames int
}

type relayFrame struct {
	Seq        uint64
	Offset     int64
	NextOffset int64
	Payload    []byte
	Sent       bool
}

type relayWindow struct {
	cfg          relayWindowConfig
	frames       []relayFrame
	acked        int64
	inFlight     int64
	bufferedBytes int64
}

func newRelayWindow(cfg relayWindowConfig) *relayWindow {
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = int64(chunkBytes)
	}
	if cfg.MaxFrames <= 0 {
		cfg.MaxFrames = 1
	}
	return &relayWindow{cfg: cfg}
}

func (w *relayWindow) canSend(payloadBytes int) bool {
	if payloadBytes < 0 {
		return false
	}
	if len(w.frames) >= w.cfg.MaxFrames {
		return false
	}
	return w.inFlight+int64(payloadBytes) <= w.cfg.MaxBytes
}

func (w *relayWindow) push(frame relayFrame) {
	frame.Payload = append([]byte(nil), frame.Payload...)
	w.frames = append(w.frames, frame)
	w.inFlight += int64(len(frame.Payload))
	w.bufferedBytes += int64(len(frame.Payload))
}

func (w *relayWindow) markSent(seq uint64) {
	for i := range w.frames {
		if w.frames[i].Seq == seq {
			w.frames[i].Sent = true
			return
		}
	}
}

func (w *relayWindow) unsent() []relayFrame {
	out := make([]relayFrame, 0, len(w.frames))
	for _, frame := range w.frames {
		if !frame.Sent {
			out = append(out, cloneRelayFrame(frame))
		}
	}
	return out
}

func (w *relayWindow) ack(bytesReceived int64) {
	if bytesReceived <= w.acked {
		return
	}
	w.acked = bytesReceived
	kept := w.frames[:0]
	var inFlight int64
	var buffered int64
	for _, frame := range w.frames {
		if frame.NextOffset <= bytesReceived {
			continue
		}
		kept = append(kept, frame)
		inFlight += int64(len(frame.Payload))
		buffered += int64(len(frame.Payload))
	}
	w.frames = kept
	w.inFlight = inFlight
	w.bufferedBytes = buffered
}

func (w *relayWindow) ackedOffset() int64 {
	return w.acked
}

func (w *relayWindow) inFlightBytes() int64 {
	return w.inFlight
}

func (w *relayWindow) bufferedPayloadBytes() int64 {
	return w.bufferedBytes
}

func (w *relayWindow) empty() bool {
	return len(w.frames) == 0
}

func (w *relayWindow) replayFrom(offset int64) []relayFrame {
	out := make([]relayFrame, 0, len(w.frames))
	for _, frame := range w.frames {
		if frame.NextOffset <= offset {
			continue
		}
		out = append(out, cloneRelayFrame(frame))
	}
	return out
}

func cloneRelayFrame(frame relayFrame) relayFrame {
	frame.Payload = append([]byte(nil), frame.Payload...)
	return frame
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
go test ./pkg/derphole/webrelay -run 'TestRelayWindow' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/derphole/webrelay/window.go pkg/derphole/webrelay/window_test.go
git commit -m "webrelay: add bounded relay send window"
```

## Task 2: Windowed Relay Sending

**Files:**
- Modify: `pkg/derphole/webrelay/relay.go`
- Modify: `pkg/derphole/webrelay/relay_test.go`

- [ ] **Step 1: Write failing pipelining test**

Append to `pkg/derphole/webrelay/relay_test.go`:

```go
func TestSendWithOptionsPipelinesRelayDataBeforeAck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newFakeDERPClient()
	peerDERP := key.NewNode().Public()
	tok, err := newToken(client.PublicKey(), 1)
	if err != nil {
		t.Fatalf("newToken() error = %v", err)
	}

	source := newFakeSource("file.txt", []byte("abc"), []byte("def"), []byte("ghi"))
	metaAcked := make(chan struct{})
	releaseDataAcks := make(chan struct{})
	var dataSent int

	client.sendHook = func(_ key.NodePublic, payload []byte) {
		frame, err := webproto.Parse(payload)
		if err != nil {
			t.Fatalf("Parse(sent frame) error = %v", err)
		}
		switch frame.Kind {
		case webproto.FrameMeta:
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: 0}))
			close(metaAcked)
		case webproto.FrameData:
			dataSent++
			if dataSent == 3 {
				go func() {
					<-releaseDataAcks
					client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: 3}))
					client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: 6}))
					client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: 9}))
				}()
			}
		case webproto.FrameDone:
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: 9}))
		}
	}

	offer := &Offer{client: client, token: tok, gate: rendezvous.NewGate(tok)}
	errCh := make(chan error, 1)
	go func() {
		errCh <- offer.Send(ctx, source, Callbacks{})
	}()

	client.waitForSubscribers(t, 1)
	claim, err := newClaim(tok, peerDERP)
	if err != nil {
		t.Fatalf("newClaim() error = %v", err)
	}
	client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameClaim, 0, claim))

	select {
	case <-metaAcked:
	case <-ctx.Done():
		t.Fatal("timed out waiting for metadata ack")
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && dataSent < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	if dataSent < 3 {
		t.Fatalf("data frames sent before ack = %d, want 3", dataSent)
	}
	close(releaseDataAcks)

	if err := <-errCh; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./pkg/derphole/webrelay -run TestSendWithOptionsPipelinesRelayDataBeforeAck -count=1
```

Expected: FAIL because current `sendFrameAwaitAck` waits for each data ACK before sending the next data frame.

- [ ] **Step 3: Add relay window constants and helper**

Modify the const block near the top of `pkg/derphole/webrelay/relay.go`:

```go
const (
	chunkBytes               = webproto.MaxPayloadBytes
	relayWindowBytes        = 8 << 20
	relayWindowFrames       = relayWindowBytes / chunkBytes
	claimRetryDelay         = 250 * time.Millisecond
	frameRetryDelay         = 2 * time.Second
	offerTokenTTL           = time.Hour
	defaultClaimPar         = 1
	maxFilenameBytes        = 255
	statusWaitingClaim      = "waiting-for-claim"
	statusClaimed           = "claimed"
	statusProbing           = "probing-direct"
	statusRelay             = "connected-relay"
	statusDirect            = "connected-direct"
	statusComplete          = "complete"
)
```

Add this helper below `sendDirectFrame`:

```go
func sendRelayDataFrame(ctx context.Context, client derpClient, peerDERP key.NodePublic, frame relayFrame) error {
	return sendFrame(ctx, client, peerDERP, webproto.FrameData, frame.Seq, frame.Payload)
}
```

- [ ] **Step 4: Replace data loop with windowed sender**

Inside `func (o *Offer) send(...)`, keep metadata as strict `sendFrameAwaitAck`, then replace the existing data `for` loop with a call to a new helper:

```go
	offset, seq, directTransport, direct, err := o.sendDataWindowed(ctx, src, cb, peerDERP, peerCh, meta.Size, opts.Direct, direct)
	if err != nil {
		return err
	}
```

Add the helper below `func (o *Offer) send(...)`:

```go
func (o *Offer) sendDataWindowed(ctx context.Context, src FileSource, cb Callbacks, peerDERP key.NodePublic, peerCh <-chan derpbind.Packet, total int64, directTransport DirectTransport, direct *directState) (int64, uint64, DirectTransport, *directState, error) {
	window := newRelayWindow(relayWindowConfig{MaxBytes: relayWindowBytes, MaxFrames: relayWindowFrames})
	var offset int64
	var seq uint64 = 1
	var eof bool

	for {
		directTransport, directErr := pollSendDirectState(cb, direct, directTransport)
		if directErr != nil {
			return offset, seq, directTransport, direct, notifyAbort(ctx, o.client, peerDERP, directErr)
		}

		for !eof && window.canSend(chunkBytes) {
			chunk, err := src.ReadChunk(ctx, offset, chunkBytes)
			if err != nil {
				return offset, seq, directTransport, direct, notifyAbort(ctx, o.client, peerDERP, err)
			}
			if len(chunk) == 0 {
				eof = true
				break
			}
			nextOffset := offset + int64(len(chunk))
			frame := relayFrame{Seq: seq, Offset: offset, NextOffset: nextOffset, Payload: chunk}
			window.push(frame)
			if direct != nil && direct.active && directTransport != nil {
				if err := sendDirectFrame(ctx, directTransport, webproto.FrameData, seq, chunk); err != nil {
					return offset, seq, directTransport, direct, notifyAbort(ctx, o.client, peerDERP, err)
				}
				window.ack(nextOffset)
			} else if err := sendRelayDataFrame(ctx, o.client, peerDERP, frame); err != nil {
				return offset, seq, directTransport, direct, err
			} else {
				window.markSent(seq)
			}
			offset = nextOffset
			cb.progress(Progress{Bytes: offset, Total: total})
			seq++
		}

		directTransport, directErr = pollSendDirectState(cb, direct, directTransport)
		if directErr != nil {
			return offset, seq, directTransport, direct, notifyAbort(ctx, o.client, peerDERP, directErr)
		}
		if direct != nil && directTransport != nil && direct.ready && !direct.active {
			switched, err := trySwitchDirect(ctx, o.client, peerDERP, peerCh, seq, window.ackedOffset())
			if err != nil {
				return offset, seq, directTransport, direct, err
			}
			if switched {
				direct.noteSwitched()
				cb.status(statusDirect)
			}
		}

		if eof && window.empty() {
			return offset, seq, directTransport, direct, nil
		}

		if err := awaitRelayWindowAck(ctx, peerCh, window); err != nil {
			return offset, seq, directTransport, direct, err
		}
	}
}
```

Add `awaitRelayWindowAck` below `awaitAck`:

```go
func awaitRelayWindowAck(ctx context.Context, frames <-chan derpbind.Packet, window *relayWindow) error {
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
				window.ack(ack.BytesReceived)
				return nil
			case webproto.FrameAbort:
				return decodeAbort(frame.Payload)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
```

- [ ] **Step 5: Keep done ACK strict**

After the new helper returns in `func (o *Offer) send(...)`, keep the existing `FrameDone` logic but use the returned `offset`, `seq`, `directTransport`, and `direct`. The final `FrameDone` still waits for final receiver ACK because completion must be confirmed.

- [ ] **Step 6: Run focused tests**

Run:

```bash
go test ./pkg/derphole/webrelay -run 'TestSendWithOptionsPipelinesRelayDataBeforeAck|TestSendWithOptionsDirectFailureBeforeHandoffKeepsRelay|TestSendWithOptionsSwitchesToDirectAfterHandoff' -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/derphole/webrelay/relay.go pkg/derphole/webrelay/relay_test.go
git commit -m "webrelay: pipeline relay data frames"
```

## Task 3: Offset-Safe Direct Switch With Relay Replay

**Files:**
- Modify: `pkg/derphole/webrelay/relay.go`
- Modify: `pkg/derphole/webrelay/relay_test.go`

- [ ] **Step 1: Write failing direct replay test**

Append to `pkg/derphole/webrelay/relay_test.go`:

```go
func TestDirectSwitchReplaysUnackedRelayFrames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newFakeDERPClient()
	peerDERP := key.NewNode().Public()
	direct := newFakeDirect()
	window := newRelayWindow(relayWindowConfig{MaxBytes: 64, MaxFrames: 8})
	window.push(relayFrame{Seq: 2, Offset: 3, NextOffset: 6, Payload: []byte("def"), Sent: true})
	window.push(relayFrame{Seq: 3, Offset: 6, NextOffset: 9, Payload: []byte("ghi"), Sent: true})
	window.ack(3)

	client.sendHook = func(_ key.NodePublic, payload []byte) {
		frame, err := webproto.Parse(payload)
		if err != nil {
			t.Fatalf("Parse(sent frame) error = %v", err)
		}
		if frame.Kind == webproto.FrameDirectReady {
			var ready webproto.DirectReady
			if err := json.Unmarshal(frame.Payload, &ready); err != nil {
				t.Fatalf("Unmarshal(DirectReady) error = %v", err)
			}
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FramePathSwitch, ready.NextSeq, webproto.PathSwitch{
				Path:          "webrtc",
				BytesReceived: ready.BytesReceived,
				NextSeq:       ready.NextSeq,
			}))
		}
	}
	frames, unsubscribe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && webproto.IsWebFrame(pkt.Payload)
	})
	defer unsubscribe()

	switched, err := trySwitchDirectWithReplay(ctx, client, peerDERP, frames, direct, window)
	if err != nil {
		t.Fatalf("trySwitchDirectWithReplay() error = %v", err)
	}
	if !switched {
		t.Fatal("trySwitchDirectWithReplay() switched = false, want true")
	}

	got := direct.sentFrames(t)
	if len(got) != 2 {
		t.Fatalf("direct frame count = %d, want 2", len(got))
	}
	if got[0].Kind != webproto.FrameData || got[0].Seq != 2 || string(got[0].Payload) != "def" {
		t.Fatalf("first replay frame = %+v", got[0])
	}
	if got[1].Kind != webproto.FrameData || got[1].Seq != 3 || string(got[1].Payload) != "ghi" {
		t.Fatalf("second replay frame = %+v", got[1])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./pkg/derphole/webrelay -run TestDirectSwitchReplaysUnackedRelayFrames -count=1
```

Expected: FAIL with undefined `trySwitchDirectWithReplay`.

- [ ] **Step 3: Implement switch with replay**

Replace `trySwitchDirect` usage in `sendDataWindowed` with `trySwitchDirectWithReplay`.

Add this function below `trySwitchDirect`:

```go
func trySwitchDirectWithReplay(ctx context.Context, client derpClient, peerDERP key.NodePublic, frames <-chan derpbind.Packet, direct DirectTransport, window *relayWindow) (bool, error) {
	if direct == nil || window == nil {
		return false, nil
	}
	nextSeq := uint64(1)
	replay := window.replayFrom(window.ackedOffset())
	if len(replay) > 0 {
		nextSeq = replay[0].Seq
	}
	ready, err := marshalDirectReadyFrame(nextSeq, window.ackedOffset())
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
			switch frame.Kind {
			case webproto.FramePathSwitch:
				var sw webproto.PathSwitch
				if err := json.Unmarshal(frame.Payload, &sw); err != nil {
					continue
				}
				if sw.Path != "webrtc" || sw.BytesReceived != window.ackedOffset() || sw.NextSeq != nextSeq {
					return false, nil
				}
				for _, replayFrame := range replay {
					if err := sendDirectFrame(ctx, direct, webproto.FrameData, replayFrame.Seq, replayFrame.Payload); err != nil {
						return false, err
					}
					window.ack(replayFrame.NextOffset)
				}
				return true, nil
			case webproto.FrameAbort:
				return false, decodeAbort(frame.Payload)
			case webproto.FrameAck:
				ack, err := decodeAck(frame.Payload)
				if err == nil {
					window.ack(ack.BytesReceived)
				}
			}
		case <-timer.C:
			return false, nil
		case err := <-direct.Failed():
			if err == nil {
				err = errors.New("direct path failed")
			}
			return false, err
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
}
```

- [ ] **Step 4: Ensure receiver discards relay duplicates after direct switch**

In `receiveFrames`, the existing `FrameData` handling already discards `frame.Seq < expectedSeq` and ACKs the current byte count. Keep that behavior. Add a test proving duplicate relay data after direct replay is harmless:

```go
func TestReceiveFramesDiscardsRelayDuplicateAfterDirectSwitch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newFakeDERPClient()
	peerDERP := key.NewNode().Public()
	sink := &fakeSink{}
	direct := newFakeDirect()
	derpFrames := make(chan derpbind.Packet, 16)
	merged, stopMerge := mergeFrameSources(ctx, derpFrames, direct)
	defer stopMerge()

	errCh := make(chan error, 1)
	go func() {
		errCh <- receiveFrames(ctx, client, peerDERP, merged, direct, sink, Callbacks{})
	}()

	derpFrames <- derpbind.Packet{From: peerDERP, Payload: mustMarshalFrame(t, webproto.FrameMeta, 0, webproto.Meta{Name: "file.txt", Size: 6})}
	derpFrames <- derpbind.Packet{From: peerDERP, Payload: mustMarshalFrame(t, webproto.FrameData, 1, []byte("abc"))}
	derpFrames <- derpbind.Packet{From: peerDERP, Payload: mustMarshalFrame(t, webproto.FrameDirectReady, 2, webproto.DirectReady{BytesReceived: 3, NextSeq: 2})}
	client.waitForSentKind(t, webproto.FramePathSwitch)

	direct.recvCh <- mustMarshalFrame(t, webproto.FrameData, 2, []byte("def"))
	derpFrames <- derpbind.Packet{From: peerDERP, Payload: mustMarshalFrame(t, webproto.FrameData, 2, []byte("def"))}
	direct.recvCh <- mustMarshalFrame(t, webproto.FrameDone, 3, nil)
	close(direct.recvCh)
	close(derpFrames)

	if err := <-errCh; err != nil {
		t.Fatalf("receiveFrames() error = %v", err)
	}
	if got := sink.buf.String(); got != "abcdef" {
		t.Fatalf("sink data = %q, want abcdef", got)
	}
}
```

- [ ] **Step 5: Run focused tests**

Run:

```bash
go test ./pkg/derphole/webrelay -run 'TestDirectSwitchReplaysUnackedRelayFrames|TestReceiveFramesDiscardsRelayDuplicateAfterDirectSwitch|TestReceiveFramesDirectReadySwitchesAndMergesDirectData' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/derphole/webrelay/relay.go pkg/derphole/webrelay/relay_test.go
git commit -m "webrelay: replay relay window on direct switch"
```

## Task 4: Transfer Cancellation And Completion Semantics

**Files:**
- Modify: `pkg/derphole/webrelay/relay.go`
- Modify: `pkg/derphole/webrelay/relay_test.go`

- [ ] **Step 1: Write failing sender cancellation test**

Append to `pkg/derphole/webrelay/relay_test.go`:

```go
func TestSendContextCancelNotifiesReceiverAbort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := newFakeDERPClient()
	peerDERP := key.NewNode().Public()
	tok, err := newToken(client.PublicKey(), 1)
	if err != nil {
		t.Fatalf("newToken() error = %v", err)
	}
	source := newFakeSource("file.txt", []byte("abc"), []byte("def"))

	client.sendHook = func(_ key.NodePublic, payload []byte) {
		frame, err := webproto.Parse(payload)
		if err != nil {
			t.Fatalf("Parse(sent frame) error = %v", err)
		}
		switch frame.Kind {
		case webproto.FrameMeta:
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: 0}))
		case webproto.FrameData:
			cancel()
		}
	}

	offer := &Offer{client: client, token: tok, gate: rendezvous.NewGate(tok)}
	errCh := make(chan error, 1)
	go func() {
		errCh <- offer.Send(ctx, source, Callbacks{})
	}()

	client.waitForSubscribers(t, 1)
	claim, err := newClaim(tok, peerDERP)
	if err != nil {
		t.Fatalf("newClaim() error = %v", err)
	}
	client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameClaim, 0, claim))

	err = <-errCh
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Send() error = %v, want context.Canceled", err)
	}
	if indexOfFrameKind(client.sentFrames(t), webproto.FrameAbort) == -1 {
		t.Fatal("sender did not notify receiver with FrameAbort")
	}
}
```

- [ ] **Step 2: Write failing done confirmation test**

Append to `pkg/derphole/webrelay/relay_test.go`:

```go
func TestReceiveFramesRejectsShortKnownSizeOnDone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client := newFakeDERPClient()
	peerDERP := key.NewNode().Public()
	sink := &fakeSink{}
	frames := make(chan []byte, 4)
	frames <- mustMarshalFrame(t, webproto.FrameMeta, 0, webproto.Meta{Name: "file.txt", Size: 6})
	frames <- mustMarshalFrame(t, webproto.FrameData, 1, []byte("abc"))
	frames <- mustMarshalFrame(t, webproto.FrameDone, 2, nil)
	close(frames)

	err := receiveFrames(ctx, client, peerDERP, frames, nil, sink, Callbacks{})
	if err == nil || err.Error() != "received byte count does not match metadata" {
		t.Fatalf("receiveFrames() error = %v, want byte count mismatch", err)
	}
}
```

- [ ] **Step 3: Run tests to verify cancellation fails and known-size check passes**

Run:

```bash
go test ./pkg/derphole/webrelay -run 'TestSendContextCancelNotifiesReceiverAbort|TestReceiveFramesRejectsShortKnownSizeOnDone' -count=1
```

Expected: `TestSendContextCancelNotifiesReceiverAbort` FAILS before the implementation. `TestReceiveFramesRejectsShortKnownSizeOnDone` may already PASS; keep it as regression coverage.

- [ ] **Step 4: Add context-cancel abort helper**

In `pkg/derphole/webrelay/relay.go`, add:

```go
func abortIfContextDone(ctx context.Context, client derpClient, peerDERP key.NodePublic) error {
	if err := ctx.Err(); err != nil {
		_ = sendAbort(context.Background(), client, peerDERP, err.Error())
		return err
	}
	return nil
}
```

Call it in `sendDataWindowed` before returning `ctx.Err()` from the data path:

```go
if err := abortIfContextDone(ctx, o.client, peerDERP); err != nil {
	return offset, seq, directTransport, direct, err
}
```

Also call it before returning from `sendFrameAwaitAck` when `awaitAck` returns `ctx.Err()`.

- [ ] **Step 5: Run focused tests**

Run:

```bash
go test ./pkg/derphole/webrelay -run 'TestSendContextCancelNotifiesReceiverAbort|TestReceiveFramesRejectsShortKnownSizeOnDone' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/derphole/webrelay/relay.go pkg/derphole/webrelay/relay_test.go
git commit -m "webrelay: propagate transfer cancellation"
```

## Task 5: Native Pion Direct Transport

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `pkg/derphole/webrtcdirect/transport.go`
- Create: `pkg/derphole/webrtcdirect/transport_test.go`

- [ ] **Step 1: Add Pion dependency**

Run:

```bash
go get github.com/pion/webrtc/v4
go mod tidy
```

Expected: `go.mod` includes `github.com/pion/webrtc/v4`, and `go.sum` includes Pion transitive modules.

- [ ] **Step 2: Write failing loopback transport test**

Create `pkg/derphole/webrtcdirect/transport_test.go`:

```go
package webrtcdirect

import (
	"context"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derphole/webproto"
	"github.com/shayne/derphole/pkg/derphole/webrelay"
)

type memoryPeer struct {
	in  chan webproto.Frame
	out chan webproto.Frame
}

func newMemoryPeerPair() (*memoryPeer, *memoryPeer) {
	a := &memoryPeer{in: make(chan webproto.Frame, 64), out: make(chan webproto.Frame, 64)}
	b := &memoryPeer{in: a.out, out: a.in}
	return a, b
}

func (p *memoryPeer) SendSignal(_ context.Context, kind webproto.FrameKind, seq uint64, payload []byte) error {
	p.out <- webproto.Frame{Kind: kind, Seq: seq, Payload: append([]byte(nil), payload...)}
	return nil
}

func (p *memoryPeer) Signals() <-chan webproto.Frame {
	return p.in
}

func TestTransportLoopbackSendsFrame(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	senderPeer, receiverPeer := newMemoryPeerPair()
	sender := New()
	receiver := New()
	defer sender.Close()
	defer receiver.Close()

	if err := receiver.Start(ctx, webrelay.DirectRoleReceiver, receiverPeer); err != nil {
		t.Fatalf("receiver Start() error = %v", err)
	}
	if err := sender.Start(ctx, webrelay.DirectRoleSender, senderPeer); err != nil {
		t.Fatalf("sender Start() error = %v", err)
	}

	select {
	case <-sender.Ready():
	case err := <-sender.Failed():
		t.Fatalf("sender failed before ready: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for sender ready")
	}
	select {
	case <-receiver.Ready():
	case err := <-receiver.Failed():
		t.Fatalf("receiver failed before ready: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for receiver ready")
	}

	raw, err := webproto.Marshal(webproto.FrameData, 1, []byte("abc"))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := sender.SendFrame(ctx, raw); err != nil {
		t.Fatalf("SendFrame() error = %v", err)
	}

	select {
	case got := <-receiver.ReceiveFrames():
		frame, err := webproto.Parse(got)
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if frame.Kind != webproto.FrameData || frame.Seq != 1 || string(frame.Payload) != "abc" {
			t.Fatalf("received frame = %+v", frame)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for received frame")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run:

```bash
go test ./pkg/derphole/webrtcdirect -run TestTransportLoopbackSendsFrame -count=1
```

Expected: FAIL with undefined `New`.

- [ ] **Step 4: Implement Pion transport**

Create `pkg/derphole/webrtcdirect/transport.go`:

```go
package webrtcdirect

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/pion/webrtc/v4"
	"github.com/shayne/derphole/pkg/derphole/webproto"
	"github.com/shayne/derphole/pkg/derphole/webrelay"
)

const receiveQueueFrames = 512

type Transport struct {
	mu       sync.Mutex
	pc       *webrtc.PeerConnection
	dc       *webrtc.DataChannel
	readyCh  chan struct{}
	failCh   chan error
	recvCh   chan []byte
	ready    bool
	closed   bool
	failOnce sync.Once
}

func New() *Transport {
	return &Transport{
		readyCh: make(chan struct{}),
		failCh:  make(chan error, 1),
		recvCh:  make(chan []byte, receiveQueueFrames),
	}
}

func (t *Transport) Start(ctx context.Context, role webrelay.DirectRole, peer webrelay.DirectSignalPeer) error {
	config := webrtc.Configuration{ICEServers: []webrtc.ICEServer{
		{URLs: []string{"stun:stun.l.google.com:19302"}},
		{URLs: []string{"stun:stun.cloudflare.com:3478"}},
	}}
	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.pc = pc
	t.mu.Unlock()

	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			_ = sendSignal(ctx, peer, webproto.FrameWebRTCIceComplete, webproto.WebRTCSignal{Kind: "ice-complete"})
			return
		}
		init := candidate.ToJSON()
		_ = sendSignal(ctx, peer, webproto.FrameWebRTCIceCandidate, webproto.WebRTCSignal{
			Kind:             "candidate",
			Candidate:        init.Candidate,
			SDPMid:           stringValue(init.SDPMid),
			SDPMLineIndex:    uint16Value(init.SDPMLineIndex),
			UsernameFragment: stringValue(init.UsernameFragment),
		})
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		switch state {
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed, webrtc.PeerConnectionStateDisconnected:
			t.fail(errors.New("webrtc " + state.String()))
		}
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		t.attachDataChannel(dc)
	})

	go t.forwardSignals(ctx, peer)

	if role == webrelay.DirectRoleSender {
		dc, err := pc.CreateDataChannel("derphole", &webrtc.DataChannelInit{Ordered: boolPtr(true)})
		if err != nil {
			t.fail(err)
			return err
		}
		t.attachDataChannel(dc)
		offer, err := pc.CreateOffer(nil)
		if err != nil {
			t.fail(err)
			return err
		}
		if err := pc.SetLocalDescription(offer); err != nil {
			t.fail(err)
			return err
		}
		if err := sendSignal(ctx, peer, webproto.FrameWebRTCOffer, webproto.WebRTCSignal{Kind: "offer", Type: offer.Type.String(), SDP: offer.SDP}); err != nil {
			t.fail(err)
			return err
		}
	}
	return nil
}

func (t *Transport) Ready() <-chan struct{} { return t.readyCh }

func (t *Transport) Failed() <-chan error { return t.failCh }

func (t *Transport) ReceiveFrames() <-chan []byte { return t.recvCh }

func (t *Transport) SendFrame(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-t.readyCh:
	case err := <-t.failCh:
		if err == nil {
			err = errors.New("direct path failed")
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
	t.mu.Lock()
	dc := t.dc
	t.mu.Unlock()
	if dc == nil {
		return errors.New("webrtc datachannel is not open")
	}
	return dc.Send(frame)
}

func (t *Transport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	dc := t.dc
	pc := t.pc
	t.mu.Unlock()
	if dc != nil {
		_ = dc.Close()
	}
	if pc != nil {
		return pc.Close()
	}
	return nil
}

func (t *Transport) attachDataChannel(dc *webrtc.DataChannel) {
	t.mu.Lock()
	t.dc = dc
	t.mu.Unlock()
	dc.OnOpen(func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.ready || t.closed {
			return
		}
		t.ready = true
		close(t.readyCh)
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		raw := append([]byte(nil), msg.Data...)
		select {
		case t.recvCh <- raw:
		default:
			t.fail(errors.New("direct receive queue full"))
		}
	})
	dc.OnError(func(err error) {
		t.fail(err)
	})
	dc.OnClose(func() {
		t.mu.Lock()
		ready := t.ready
		t.mu.Unlock()
		if !ready {
			t.fail(errors.New("webrtc datachannel closed before open"))
		}
	})
}

func (t *Transport) forwardSignals(ctx context.Context, peer webrelay.DirectSignalPeer) {
	for {
		select {
		case frame, ok := <-peer.Signals():
			if !ok {
				return
			}
			if err := t.applySignal(ctx, peer, frame); err != nil {
				t.fail(err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (t *Transport) applySignal(ctx context.Context, peer webrelay.DirectSignalPeer, frame webproto.Frame) error {
	t.mu.Lock()
	pc := t.pc
	t.mu.Unlock()
	if pc == nil {
		return errors.New("webrtc peer connection is not started")
	}
	var signal webproto.WebRTCSignal
	if err := json.Unmarshal(frame.Payload, &signal); err != nil {
		return err
	}
	switch frame.Kind {
	case webproto.FrameWebRTCOffer:
		if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: signal.SDP}); err != nil {
			return err
		}
		answer, err := pc.CreateAnswer(nil)
		if err != nil {
			return err
		}
		if err := pc.SetLocalDescription(answer); err != nil {
			return err
		}
		return sendSignal(ctx, peer, webproto.FrameWebRTCAnswer, webproto.WebRTCSignal{Kind: "answer", Type: answer.Type.String(), SDP: answer.SDP})
	case webproto.FrameWebRTCAnswer:
		return pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: signal.SDP})
	case webproto.FrameWebRTCIceCandidate:
		return pc.AddICECandidate(webrtc.ICECandidateInit{
			Candidate:        signal.Candidate,
			SDPMid:           &signal.SDPMid,
			SDPMLineIndex:    uint16Ptr(uint16(signal.SDPMLineIndex)),
			UsernameFragment: &signal.UsernameFragment,
		})
	case webproto.FrameWebRTCIceComplete:
		return nil
	default:
		return nil
	}
}

func sendSignal(ctx context.Context, peer webrelay.DirectSignalPeer, kind webproto.FrameKind, signal webproto.WebRTCSignal) error {
	payload, err := json.Marshal(signal)
	if err != nil {
		return err
	}
	return peer.SendSignal(ctx, kind, 0, payload)
}

func (t *Transport) fail(err error) {
	if err == nil {
		err = errors.New("direct path failed")
	}
	t.failOnce.Do(func() {
		select {
		case t.failCh <- err:
		default:
		}
	})
}

func boolPtr(v bool) *bool { return &v }

func uint16Ptr(v uint16) *uint16 { return &v }

func stringValue(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func uint16Value(v *uint16) int {
	if v == nil {
		return 0
	}
	return int(*v)
}
```

- [ ] **Step 5: Run tests and verify the Pion implementation**

Run:

```bash
go test ./pkg/derphole/webrtcdirect -run TestTransportLoopbackSendsFrame -count=1
```

Expected: PASS. If the local Pion version has a signature mismatch, adjust only the Pion call site while preserving the public `webrelay.DirectTransport` interface and the test behavior.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum pkg/derphole/webrtcdirect/transport.go pkg/derphole/webrtcdirect/transport_test.go
git commit -m "derphole: add native webrtc direct transport"
```

## Task 6: CLI Web-Token Wiring

**Files:**
- Modify: `pkg/derphole/transfer.go`
- Modify: `pkg/derphole/transfer_test.go`

- [ ] **Step 1: Write failing direct factory test**

Append to `pkg/derphole/transfer_test.go`:

```go
func TestReceiveViaWebRelayUsesNativeDirectByDefault(t *testing.T) {
	oldReceive := derpholeWebRelayReceiveWithOptions
	oldDirect := derpholeNewWebDirect
	defer func() {
		derpholeWebRelayReceiveWithOptions = oldReceive
		derpholeNewWebDirect = oldDirect
	}()

	var gotDirect bool
	derpholeNewWebDirect = func() webrelay.DirectTransport {
		return newFakeDirect()
	}
	derpholeWebRelayReceiveWithOptions = func(_ context.Context, _ string, _ webrelay.FileSink, _ webrelay.Callbacks, opts webrelay.TransferOptions) error {
		gotDirect = opts.Direct != nil
		return nil
	}

	err := receiveViaWebRelay(context.Background(), ReceiveConfig{}, "token")
	if err != nil {
		t.Fatalf("receiveViaWebRelay() error = %v", err)
	}
	if !gotDirect {
		t.Fatal("receiveViaWebRelay did not pass native direct transport")
	}
}

func TestReceiveViaWebRelaySkipsNativeDirectWhenForcedRelay(t *testing.T) {
	oldReceive := derpholeWebRelayReceiveWithOptions
	oldDirect := derpholeNewWebDirect
	defer func() {
		derpholeWebRelayReceiveWithOptions = oldReceive
		derpholeNewWebDirect = oldDirect
	}()

	var gotDirect bool
	derpholeNewWebDirect = func() webrelay.DirectTransport {
		return newFakeDirect()
	}
	derpholeWebRelayReceiveWithOptions = func(_ context.Context, _ string, _ webrelay.FileSink, _ webrelay.Callbacks, opts webrelay.TransferOptions) error {
		gotDirect = opts.Direct != nil
		return nil
	}

	err := receiveViaWebRelay(context.Background(), ReceiveConfig{ForceRelay: true}, "token")
	if err != nil {
		t.Fatalf("receiveViaWebRelay() error = %v", err)
	}
	if gotDirect {
		t.Fatal("receiveViaWebRelay passed direct transport despite ForceRelay")
	}
}
```

If `transfer_test.go` does not already have `newFakeDirect`, add this local fake:

```go
type fakeWebDirect struct{}

func newFakeDirect() webrelay.DirectTransport { return fakeWebDirect{} }

func (fakeWebDirect) Start(context.Context, webrelay.DirectRole, webrelay.DirectSignalPeer) error { return nil }
func (fakeWebDirect) Ready() <-chan struct{} { return make(chan struct{}) }
func (fakeWebDirect) Failed() <-chan error { return make(chan error) }
func (fakeWebDirect) SendFrame(context.Context, []byte) error { return nil }
func (fakeWebDirect) ReceiveFrames() <-chan []byte { return make(chan []byte) }
func (fakeWebDirect) Close() error { return nil }
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./pkg/derphole -run 'TestReceiveViaWebRelayUsesNativeDirectByDefault|TestReceiveViaWebRelaySkipsNativeDirectWhenForcedRelay' -count=1
```

Expected: FAIL with undefined `derpholeWebRelayReceiveWithOptions` and `derpholeNewWebDirect`.

- [ ] **Step 3: Wire native direct factory**

Modify imports in `pkg/derphole/transfer.go`:

```go
	"github.com/shayne/derphole/pkg/derphole/webrtcdirect"
```

Modify package variables:

```go
	derpholeWebRelayReceiveWithOptions = webrelay.ReceiveWithOptions
	derpholeNewWebDirect               = func() webrelay.DirectTransport { return webrtcdirect.New() }
```

Keep `derpholeWebRelayReceive = webrelay.Receive` only if other tests still use it. Otherwise remove it.

Modify `receiveViaWebRelay`:

```go
func receiveViaWebRelay(ctx context.Context, cfg ReceiveConfig, receiveToken string) error {
	sink := newNativeWebFileSink(cfg.OutputPath, cfg.Stderr, cfg.ProgressOutput)
	cb := webrelay.Callbacks{
		Status: func(status string) {
			if cfg.Emitter != nil {
				cfg.Emitter.Debug(status)
			}
		},
		Progress: func(webrelay.Progress) {},
	}
	opts := webrelay.TransferOptions{}
	if !cfg.ForceRelay && derpholeNewWebDirect != nil {
		opts.Direct = derpholeNewWebDirect()
	}
	return derpholeWebRelayReceiveWithOptions(ctx, receiveToken, sink, cb, opts)
}
```

- [ ] **Step 4: Run focused tests**

Run:

```bash
go test ./pkg/derphole -run 'TestReceiveViaWebRelayUsesNativeDirectByDefault|TestReceiveViaWebRelaySkipsNativeDirectWhenForcedRelay' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/derphole/transfer.go pkg/derphole/transfer_test.go
git commit -m "derphole: enable native webrtc for web tokens"
```

## Task 7: Browser Signal Compatibility And Status Trace

**Files:**
- Modify: `web/derphole/webrtc.js`
- Modify: `cmd/derphole-web/direct_js.go`
- Modify: `docs/derp/derphole-web.md`

- [ ] **Step 1: Verify browser signal shape**

Run:

```bash
go test ./pkg/derphole/webproto -run TestWebRTCSignalRoundTrip -count=1
```

Expected: PASS. This confirms existing `webproto.WebRTCSignal` fields are still compatible.

- [ ] **Step 2: Add browser status events**

In `web/derphole/webrtc.js`, update handlers to emit more explicit statuses:

```js
pc.onicecandidate = (event) => {
  if (event.candidate) {
    status("webrtc-ice-candidate");
    emitSignal({
      kind: "candidate",
      candidate: event.candidate.candidate,
      sdpMid: event.candidate.sdpMid || "",
      sdpMLineIndex: event.candidate.sdpMLineIndex || 0,
      usernameFragment: event.candidate.usernameFragment || "",
    });
    return;
  }
  status("webrtc-ice-complete");
  emitSignal({ kind: "ice-complete" });
};
```

In `start`, emit role-aware statuses:

```js
async function start(role, nextSignalSink) {
  signalSink = nextSignalSink;
  status("probing-direct");
  status(`webrtc-role-${role}`);
  if (role === "sender") {
    attachChannel(pc.createDataChannel("derphole", { ordered: true }));
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    status("webrtc-offer");
    emitSignal({ kind: "offer", type: offer.type, sdp: offer.sdp || "" });
  }
}
```

In `applySignal`, emit status for offer and answer:

```js
if (signal.kind === "offer") {
  status("webrtc-offer-received");
  await pc.setRemoteDescription({ type: signal.type, sdp: signal.sdp });
  await flushPendingCandidates();
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  status("webrtc-answer");
  emitSignal({ kind: "answer", type: answer.type, sdp: answer.sdp || "" });
  return;
}
if (signal.kind === "answer") {
  status("webrtc-answer-received");
  await pc.setRemoteDescription({ type: signal.type, sdp: signal.sdp });
  await flushPendingCandidates();
  return;
}
```

- [ ] **Step 3: Build WASM to catch syntax or bridge breakage**

Run:

```bash
GOOS=js GOARCH=wasm go build -o /tmp/derphole-web.wasm ./cmd/derphole-web
```

Expected: PASS and `/tmp/derphole-web.wasm` exists.

- [ ] **Step 4: Update docs**

In `docs/derp/derphole-web.md`, ensure the transfer model section contains:

```markdown
The browser demo starts each transfer over DERP relay, then automatically attempts WebRTC direct transport. DERP remains the safety net for blocked WebRTC, failed ICE, or browser policy restrictions. Browser-to-CLI and CLI-to-browser use the same WebRTC signaling frames as browser-to-browser; native CLI uses a Pion-backed WebRTC transport.
```

- [ ] **Step 5: Commit**

```bash
git add web/derphole/webrtc.js cmd/derphole-web/direct_js.go docs/derp/derphole-web.md
git commit -m "web: trace webrtc direct negotiation"
```

## Task 8: Local Browser CLI Smoke Harness

**Files:**
- Create: `scripts/smoke-web-cli.sh`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Add smoke script**

Create `scripts/smoke-web-cli.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/derphole-web-cli-smoke"
SIZE="${SIZE:-1048576}"
rm -rf "$TMP"
mkdir -p "$TMP"

dd if=/dev/urandom of="$TMP/input.bin" bs="$SIZE" count=1 status=none

GOOS=js GOARCH=wasm go build -o "$TMP/derphole-web.wasm" "$ROOT/cmd/derphole-web"
cp "$ROOT/web/derphole/"*.js "$TMP/"
cp "$ROOT/web/derphole/"*.html "$TMP/" 2>/dev/null || true

echo "Built browser assets in $TMP"
echo "Manual smoke:"
echo "1. Serve $TMP with: python3 -m http.server --directory \"$TMP\" 8765"
echo "2. Open http://127.0.0.1:8765/"
echo "3. Send from browser, receive with: go run ./cmd/derphole receive <token>"
```

Make it executable:

```bash
chmod +x scripts/smoke-web-cli.sh
```

- [ ] **Step 2: Run script**

Run:

```bash
./scripts/smoke-web-cli.sh
```

Expected: PASS and output includes `Built browser assets`.

- [ ] **Step 3: Add benchmark docs**

Append to `docs/benchmarks.md`:

````markdown
### Browser to CLI WebRTC

Use this after changing `pkg/derphole/webrelay`, `pkg/derphole/webrtcdirect`, `cmd/derphole-web`, or `web/derphole`.

1. Build and serve the browser demo locally:

```bash
./scripts/smoke-web-cli.sh
python3 -m http.server --directory "${TMPDIR:-/tmp}/derphole-web-cli-smoke" 8765
```

2. Open `http://127.0.0.1:8765/`, select a file, and copy the receive command.

3. Receive with native CLI:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 go run ./cmd/derphole receive '<token>'
```

Record time to first byte, path-switch time, average throughput, final path, and whether relay fallback was used.
````

- [ ] **Step 4: Commit**

```bash
git add scripts/smoke-web-cli.sh docs/benchmarks.md
git commit -m "benchmarks: add browser cli smoke harness"
```

## Task 9: Verification And Remote Benchmark Pass

**Files:**
- Modify only if verification reveals a bug in files touched by prior tasks.

- [ ] **Step 1: Run package tests**

Run:

```bash
go test ./pkg/derphole/webrelay ./pkg/derphole/webrtcdirect ./pkg/derphole ./pkg/derphole/webproto -count=1
```

Expected: PASS.

- [ ] **Step 2: Run full repository tests**

Run:

```bash
mise run test
```

Expected: PASS.

- [ ] **Step 3: Run vet and hooks**

Run:

```bash
mise run vet
mise run check:hooks
```

Expected: PASS.

- [ ] **Step 4: Run release package dry run**

Run:

```bash
mise run release:npm-dry-run
```

Expected: PASS.

- [ ] **Step 5: Run local smoke**

Run:

```bash
mise run smoke-local
```

Expected: PASS.

- [ ] **Step 6: Run high-throughput remote browser CLI check against ktzlxc**

Build local binaries first:

```bash
mise run build
```

Then run the browser demo locally, use a 1 GiB file from this Mac, receive on `ktzlxc`, and capture verbose logs:

```bash
ssh root@ktzlxc 'rm -f ~/derphole-web-cli-recv.log ~/1GBFile.browser'
```

Use the browser page to generate a token, then on `ktzlxc` run:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 npx -y derphole@dev --verbose receive '<token>' > ~/1GBFile.browser 2> ~/derphole-web-cli-recv.log
```

Expected: payload starts immediately over relay, WebRTC direct is attempted, final logs show `connected-direct` when direct succeeds, and no early freeze around the first five seconds.

- [ ] **Step 7: Run asymmetric remote browser CLI check against eric-nuc**

Use a 128 MiB file for uploads toward the residential host:

```bash
ssh eric@eric-nuc 'rm -f ~/derphole-web-cli-recv.log ~/128MBFile.browser'
```

Use the browser page to generate a token, then on `eric-nuc` run:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 npx -y derphole@dev --verbose receive '<token>' > ~/128MBFile.browser 2> ~/derphole-web-cli-recv.log
```

Expected: transfer does not hang; throughput is judged against current residential upload ceiling rather than ktzlxc expectations.

- [ ] **Step 8: Commit verification-driven fixes**

If a verification step exposes a bug, make the smallest source change, add or update the focused test that reproduces it, run the focused test and `mise run test`, then commit:

```bash
git add -A
git commit -m "webrelay: fix browser cli direct regression"
```

Expected: no uncommitted source changes remain after the fix commit.

- [ ] **Step 9: Final status**

Run:

```bash
git status --short
git log --oneline -8
```

Expected: clean worktree and recent commits show this plan's implementation commits.

## Self-Review

- Spec coverage: relay-first behavior is covered by Tasks 1, 2, and 3; native CLI WebRTC is covered by Tasks 5 and 6; browser compatibility is covered by Task 7; benchmarks and smoke coverage are covered by Tasks 8 and 9; cancellation and EOF are covered by Task 4.
- Placeholder scan: no `TBD`, incomplete task, or deferred implementation language remains.
- Type consistency: `webrelay.DirectTransport`, `DirectSignalPeer`, `TransferOptions`, `webproto.WebRTCSignal`, `webproto.DirectReady`, and `webproto.PathSwitch` are used consistently across tasks.
- Scope check: this is one implementation track because relay fallback and WebRTC direct handoff share the same webrelay state machine.
