package webrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/derphole/webproto"
	"github.com/shayne/derpcat/pkg/rendezvous"
	"tailscale.com/types/key"
)

type fakeDirect struct {
	readyCh   chan struct{}
	readyOnce sync.Once
	failCh    chan error
	recvCh    chan []byte
	sendHook  func([]byte) error

	sentMu sync.Mutex
	sent   [][]byte
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

func (d *fakeDirect) SendFrame(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	frame = append([]byte(nil), frame...)
	if d.sendHook != nil {
		if err := d.sendHook(frame); err != nil {
			return err
		}
	}
	d.sentMu.Lock()
	defer d.sentMu.Unlock()
	d.sent = append(d.sent, frame)
	return nil
}

func (d *fakeDirect) ReceiveFrames() <-chan []byte { return d.recvCh }

func (d *fakeDirect) Close() error { return nil }

func (d *fakeDirect) markReady() {
	d.readyOnce.Do(func() {
		close(d.readyCh)
	})
}

func (d *fakeDirect) fail(err error) {
	d.failCh <- err
}

func (d *fakeDirect) sentFrames(t *testing.T) []webproto.Frame {
	t.Helper()
	d.sentMu.Lock()
	defer d.sentMu.Unlock()
	frames := make([]webproto.Frame, 0, len(d.sent))
	for _, raw := range d.sent {
		frame, err := webproto.Parse(raw)
		if err != nil {
			t.Fatalf("Parse(direct frame) error = %v", err)
		}
		frames = append(frames, frame)
	}
	return frames
}

type fakeDERPClient struct {
	pub key.NodePublic

	sendHook func(key.NodePublic, []byte)

	mu          sync.Mutex
	sent        []sentDERPPacket
	subscribers map[int]*fakeSubscriber
	nextSubID   int
}

type sentDERPPacket struct {
	dst     key.NodePublic
	payload []byte
}

type fakeSubscriber struct {
	filter func(derpbind.Packet) bool
	ch     chan derpbind.Packet
	mu     sync.Mutex
	closed bool
}

func newFakeDERPClient() *fakeDERPClient {
	return &fakeDERPClient{
		pub:         key.NewNode().Public(),
		subscribers: make(map[int]*fakeSubscriber),
	}
}

func (c *fakeDERPClient) PublicKey() key.NodePublic { return c.pub }

func (c *fakeDERPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, sub := range c.subscribers {
		close(sub.ch)
		delete(c.subscribers, id)
	}
	return nil
}

func (c *fakeDERPClient) Send(ctx context.Context, dst key.NodePublic, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	payload = append([]byte(nil), payload...)
	c.mu.Lock()
	c.sent = append(c.sent, sentDERPPacket{dst: dst, payload: payload})
	hook := c.sendHook
	c.mu.Unlock()
	if hook != nil {
		hook(dst, payload)
	}
	return nil
}

func (c *fakeDERPClient) SubscribeLossless(filter func(derpbind.Packet) bool) (<-chan derpbind.Packet, func()) {
	ch := make(chan derpbind.Packet, 128)
	c.mu.Lock()
	id := c.nextSubID
	c.nextSubID++
	c.subscribers[id] = &fakeSubscriber{filter: filter, ch: ch}
	c.mu.Unlock()
	return ch, func() {
		c.mu.Lock()
		sub, ok := c.subscribers[id]
		if ok {
			delete(c.subscribers, id)
		}
		c.mu.Unlock()
		if ok {
			sub.close()
		}
	}
}

func (c *fakeDERPClient) emit(from key.NodePublic, payload []byte) {
	pkt := derpbind.Packet{
		From:    from,
		Payload: append([]byte(nil), payload...),
	}
	c.mu.Lock()
	subs := make([]*fakeSubscriber, 0, len(c.subscribers))
	for _, sub := range c.subscribers {
		subs = append(subs, sub)
	}
	c.mu.Unlock()
	for _, sub := range subs {
		sub.emit(pkt)
	}
}

func (s *fakeSubscriber) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.ch)
}

func (s *fakeSubscriber) emit(pkt derpbind.Packet) {
	if s.filter != nil && !s.filter(pkt) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- pkt:
	default:
		panic("fake DERP subscriber channel full")
	}
}

func (c *fakeDERPClient) sentFrames(t *testing.T) []webproto.Frame {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	frames := make([]webproto.Frame, 0, len(c.sent))
	for _, pkt := range c.sent {
		frame, err := webproto.Parse(pkt.payload)
		if err != nil {
			t.Fatalf("Parse(sent frame) error = %v", err)
		}
		frames = append(frames, frame)
	}
	return frames
}

func (c *fakeDERPClient) waitForSubscribers(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		count := len(c.subscribers)
		c.mu.Unlock()
		if count >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("subscriber count did not reach %d", want)
}

func (c *fakeDERPClient) waitForSentKind(t *testing.T, want webproto.FrameKind) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		frames := c.sentFrames(t)
		for _, frame := range frames {
			if frame.Kind == want {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("did not send frame kind %v", want)
}

type fakeSource struct {
	name   string
	chunks [][]byte
	size   int64
}

func newFakeSource(name string, chunks ...[]byte) *fakeSource {
	src := &fakeSource{name: name}
	for _, chunk := range chunks {
		chunk = append([]byte(nil), chunk...)
		src.chunks = append(src.chunks, chunk)
		src.size += int64(len(chunk))
	}
	return src
}

func (s *fakeSource) Name() string { return s.name }

func (s *fakeSource) Size() int64 { return s.size }

func (s *fakeSource) ReadChunk(ctx context.Context, offset int64, _ int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var at int64
	for _, chunk := range s.chunks {
		if at == offset {
			return append([]byte(nil), chunk...), nil
		}
		at += int64(len(chunk))
	}
	if at == offset {
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected offset %d", offset)
}

type fakeSink struct {
	meta   webproto.Meta
	opened bool
	closed bool
	buf    bytes.Buffer
}

func (s *fakeSink) Open(_ context.Context, meta webproto.Meta) error {
	s.meta = meta
	s.opened = true
	return nil
}

func (s *fakeSink) WriteChunk(_ context.Context, chunk []byte) error {
	_, err := s.buf.Write(chunk)
	return err
}

func (s *fakeSink) Close(context.Context) error {
	s.closed = true
	return nil
}

func mustMarshalFrame(t *testing.T, kind webproto.FrameKind, seq uint64, payload any) []byte {
	t.Helper()
	var rawPayload []byte
	switch v := payload.(type) {
	case nil:
	case []byte:
		rawPayload = append([]byte(nil), v...)
	default:
		var err error
		rawPayload, err = json.Marshal(v)
		if err != nil {
			t.Fatalf("Marshal(payload) error = %v", err)
		}
	}
	raw, err := webproto.Marshal(kind, seq, rawPayload)
	if err != nil {
		t.Fatalf("Marshal(frame) error = %v", err)
	}
	return raw
}

func indexOfFrameKind(frames []webproto.Frame, want webproto.FrameKind) int {
	for i, frame := range frames {
		if frame.Kind == want {
			return i
		}
	}
	return -1
}

func ackBytes(t *testing.T, frame webproto.Frame) int64 {
	t.Helper()
	var ack webproto.Ack
	if err := json.Unmarshal(frame.Payload, &ack); err != nil {
		t.Fatalf("Unmarshal(ack) error = %v", err)
	}
	return ack.BytesReceived
}

func collectStatuses() (Callbacks, func() []string) {
	var mu sync.Mutex
	var statuses []string
	cb := Callbacks{
		Status: func(status string) {
			mu.Lock()
			defer mu.Unlock()
			statuses = append(statuses, status)
		},
	}
	return cb, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(statuses))
		copy(out, statuses)
		return out
	}
}

func collectTraces() (Callbacks, func() []string) {
	var mu sync.Mutex
	var traces []string
	cb := Callbacks{
		Trace: func(trace string) {
			mu.Lock()
			defer mu.Unlock()
			traces = append(traces, trace)
		},
	}
	return cb, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(traces))
		copy(out, traces)
		return out
	}
}

func requireTraceContains(t *testing.T, traces []string, want string) {
	t.Helper()
	for _, trace := range traces {
		if trace == want {
			return
		}
	}
	t.Fatalf("traces = %#v, missing %q", traces, want)
}

func TestSendClaimUntilDecisionTracesClaimAttemptsAndDecision(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newFakeDERPClient()
	peerDERP := key.NewNode().Public()
	frames, unsubscribe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && webproto.IsWebFrame(pkt.Payload)
	})
	defer unsubscribe()

	claim := rendezvous.Claim{
		Version:      4,
		SessionID:    [16]byte{1, 2, 3},
		DERPPublic:   derpPublicKeyRaw32(client.PublicKey()),
		QUICPublic:   [32]byte{4, 5, 6},
		Parallel:     1,
		Candidates:   []string{"websocket-derp"},
		Capabilities: 1 << 4,
	}
	cb, traces := collectTraces()
	client.sendHook = func(dst key.NodePublic, payload []byte) {
		if dst != peerDERP {
			t.Fatalf("dst = %v, want peerDERP", dst)
		}
		frame, err := webproto.Parse(payload)
		if err != nil {
			t.Fatalf("Parse(sent frame) error = %v", err)
		}
		if frame.Kind != webproto.FrameClaim {
			return
		}
		client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameDecision, 0, rendezvous.Decision{Accepted: true}))
	}

	if err := sendClaimUntilDecision(ctx, client, peerDERP, frames, claim, cb); err != nil {
		t.Fatalf("sendClaimUntilDecision() error = %v", err)
	}

	got := traces()
	requireTraceContains(t, got, "claim-send-attempt=1")
	requireTraceContains(t, got, "claim-frame-received=decision")
	requireTraceContains(t, got, "claim-decision=accepted")
}

func TestChooseRelayBeforeDirectReady(t *testing.T) {
	direct := newFakeDirect()
	path := chooseSendPath(TransferOptions{Direct: direct}, false)
	if path != sendPathRelay {
		t.Fatalf("path = %v, want %v", path, sendPathRelay)
	}
}

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
	direct.fail(errors.New("ice failed"))
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

func TestSendWrappersPreserveNilOfferError(t *testing.T) {
	ctx := context.Background()
	var offer *Offer
	src := newFakeSource("file.txt")

	err := offer.Send(ctx, src, Callbacks{})
	if err == nil || err.Error() != "nil offer" {
		t.Fatalf("Send() error = %v, want nil offer", err)
	}

	err = offer.SendWithOptions(ctx, src, Callbacks{}, TransferOptions{Direct: newFakeDirect()})
	if err == nil || err.Error() != "nil offer" {
		t.Fatalf("SendWithOptions() error = %v, want nil offer", err)
	}
}

func TestReceiveWrappersPreserveNilSinkError(t *testing.T) {
	ctx := context.Background()

	err := Receive(ctx, "ignored", nil, Callbacks{})
	if err == nil || err.Error() != "nil sink" {
		t.Fatalf("Receive() error = %v, want nil sink", err)
	}

	err = ReceiveWithOptions(ctx, "ignored", nil, Callbacks{}, TransferOptions{Direct: newFakeDirect()})
	if err == nil || err.Error() != "nil sink" {
		t.Fatalf("ReceiveWithOptions() error = %v, want nil sink", err)
	}
}

func TestSendWithOptionsDirectFailureBeforeHandoffKeepsRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newFakeDERPClient()
	peerDERP := key.NewNode().Public()
	tok, err := newToken(client.PublicKey(), 1)
	if err != nil {
		t.Fatalf("newToken() error = %v", err)
	}

	source := newFakeSource("file.txt", []byte("abc"), []byte("def"))
	direct := newFakeDirect()
	direct.fail(errors.New("ice failed"))

	client.sendHook = func(_ key.NodePublic, payload []byte) {
		frame, err := webproto.Parse(payload)
		if err != nil {
			t.Fatalf("Parse(sent frame) error = %v", err)
		}
		switch frame.Kind {
		case webproto.FrameMeta:
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: 0}))
		case webproto.FrameData:
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: int64(frame.Seq * 3)}))
		case webproto.FrameDone:
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: source.Size()}))
		}
	}

	cb, _ := collectStatuses()
	offer := &Offer{
		client: client,
		token:  tok,
		gate:   rendezvous.NewGate(tok),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- offer.SendWithOptions(ctx, source, cb, TransferOptions{Direct: direct})
	}()

	client.waitForSubscribers(t, 1)
	claim, err := newClaim(tok, peerDERP)
	if err != nil {
		t.Fatalf("newClaim() error = %v", err)
	}
	client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameClaim, 0, claim))

	if err := <-errCh; err != nil {
		t.Fatalf("SendWithOptions() error = %v", err)
	}

	derpFrames := client.sentFrames(t)
	if indexOfFrameKind(derpFrames, webproto.FrameDirectReady) != -1 {
		t.Fatalf("sent unexpected direct ready over DERP: %+v", derpFrames)
	}
	if len(direct.sentFrames(t)) != 0 {
		t.Fatalf("direct transport sent frames before handoff failure")
	}
	if indexOfFrameKind(derpFrames, webproto.FrameMeta) == -1 || indexOfFrameKind(derpFrames, webproto.FrameDone) == -1 {
		t.Fatalf("relay frames missing from transfer: %+v", derpFrames)
	}
}

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
	var dataSent atomic.Int32

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
			if dataSent.Add(1) == 3 {
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
	for time.Now().Before(deadline) && dataSent.Load() < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := dataSent.Load(); got < 3 {
		t.Fatalf("data frames sent before ack = %d, want 3", got)
	}
	close(releaseDataAcks)

	if err := <-errCh; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestReceiveFramesDirectReadySwitchesAndMergesDirectData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newFakeDERPClient()
	peerDERP := key.NewNode().Public()
	sink := &fakeSink{}
	direct := newFakeDirect()
	derpFrames := make(chan derpbind.Packet, 16)
	cb, statuses := collectStatuses()
	merged, stopMerge := mergeFrameSources(ctx, derpFrames, direct)
	defer stopMerge()

	errCh := make(chan error, 1)
	go func() {
		errCh <- receiveFrames(ctx, client, peerDERP, merged, direct, sink, cb)
	}()

	derpFrames <- derpbind.Packet{
		From:    peerDERP,
		Payload: mustMarshalFrame(t, webproto.FrameMeta, 0, webproto.Meta{Name: "file.txt", Size: 6}),
	}
	derpFrames <- derpbind.Packet{
		From:    peerDERP,
		Payload: mustMarshalFrame(t, webproto.FrameData, 1, []byte("abc")),
	}
	derpFrames <- derpbind.Packet{
		From:    peerDERP,
		Payload: mustMarshalFrame(t, webproto.FrameDirectReady, 2, webproto.DirectReady{BytesReceived: 3, NextSeq: 2}),
	}

	client.waitForSentKind(t, webproto.FramePathSwitch)

	direct.recvCh <- mustMarshalFrame(t, webproto.FrameData, 2, []byte("def"))
	direct.recvCh <- mustMarshalFrame(t, webproto.FrameDone, 3, nil)
	close(direct.recvCh)
	close(derpFrames)

	if err := <-errCh; err != nil {
		t.Fatalf("receiveFrames() error = %v", err)
	}

	if !sink.opened || !sink.closed {
		t.Fatalf("sink state opened=%v closed=%v", sink.opened, sink.closed)
	}
	if got := sink.buf.String(); got != "abcdef" {
		t.Fatalf("sink data = %q, want %q", got, "abcdef")
	}

	frames := client.sentFrames(t)
	pathSwitchIdx := indexOfFrameKind(frames, webproto.FramePathSwitch)
	if pathSwitchIdx == -1 {
		t.Fatalf("receiver did not send path switch: %+v", frames)
	}
	lastAckIdx := -1
	for i, frame := range frames {
		if frame.Kind == webproto.FrameAck {
			lastAckIdx = i
		}
	}
	if lastAckIdx == -1 {
		t.Fatalf("receiver did not send final ack: %+v", frames)
	}
	if got := ackBytes(t, frames[lastAckIdx]); got != 6 {
		t.Fatalf("final ack bytes = %d, want 6", got)
	}

	gotStatuses := statuses()
	if len(gotStatuses) == 0 || gotStatuses[len(gotStatuses)-1] != statusComplete {
		t.Fatalf("statuses = %v, want trailing %q", gotStatuses, statusComplete)
	}
	if index := func() int {
		for i, status := range gotStatuses {
			if status == statusDirect {
				return i
			}
		}
		return -1
	}(); index == -1 {
		t.Fatalf("statuses = %v, want connected-direct", gotStatuses)
	}
}

func TestReceiveFramesAcceptsStaleDirectReadyAndDropsReplayDuplicates(t *testing.T) {
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

	derpFrames <- derpbind.Packet{From: peerDERP, Payload: mustMarshalFrame(t, webproto.FrameMeta, 0, webproto.Meta{Name: "file.txt", Size: 9})}
	derpFrames <- derpbind.Packet{From: peerDERP, Payload: mustMarshalFrame(t, webproto.FrameData, 1, []byte("abc"))}
	derpFrames <- derpbind.Packet{From: peerDERP, Payload: mustMarshalFrame(t, webproto.FrameData, 2, []byte("def"))}
	derpFrames <- derpbind.Packet{
		From:    peerDERP,
		Payload: mustMarshalFrame(t, webproto.FrameDirectReady, 2, webproto.DirectReady{BytesReceived: 3, NextSeq: 2}),
	}

	client.waitForSentKind(t, webproto.FramePathSwitch)

	direct.recvCh <- mustMarshalFrame(t, webproto.FrameData, 2, []byte("def"))
	direct.recvCh <- mustMarshalFrame(t, webproto.FrameData, 3, []byte("ghi"))
	direct.recvCh <- mustMarshalFrame(t, webproto.FrameDone, 4, nil)
	close(direct.recvCh)
	close(derpFrames)

	if err := <-errCh; err != nil {
		t.Fatalf("receiveFrames() error = %v", err)
	}
	if got := sink.buf.String(); got != "abcdefghi" {
		t.Fatalf("sink data = %q, want abcdefghi", got)
	}

	frames := client.sentFrames(t)
	pathSwitchIdx := indexOfFrameKind(frames, webproto.FramePathSwitch)
	if pathSwitchIdx == -1 {
		t.Fatalf("receiver did not send path switch: %+v", frames)
	}
	var sw webproto.PathSwitch
	if err := json.Unmarshal(frames[pathSwitchIdx].Payload, &sw); err != nil {
		t.Fatalf("Unmarshal(PathSwitch) error = %v", err)
	}
	if sw.BytesReceived != 3 || sw.NextSeq != 2 {
		t.Fatalf("path switch = %+v, want stale sender switch point bytes=3 seq=2", sw)
	}
}

func TestSendWithOptionsSwitchesToDirectAfterHandoff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newFakeDERPClient()
	peerDERP := key.NewNode().Public()
	tok, err := newToken(client.PublicKey(), 1)
	if err != nil {
		t.Fatalf("newToken() error = %v", err)
	}

	source := newFakeSource("file.txt", []byte("abc"), []byte("def"))
	direct := newFakeDirect()
	direct.markReady()

	doneSent := make(chan struct{})
	releaseFinalAck := make(chan struct{})
	direct.sendHook = func(raw []byte) error {
		frame, err := webproto.Parse(raw)
		if err != nil {
			t.Fatalf("Parse(direct sent frame) error = %v", err)
		}
		if frame.Kind == webproto.FrameDone {
			close(doneSent)
			go func() {
				<-releaseFinalAck
				client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: source.Size()}))
			}()
		}
		return nil
	}

	client.sendHook = func(_ key.NodePublic, payload []byte) {
		frame, err := webproto.Parse(payload)
		if err != nil {
			t.Fatalf("Parse(sent frame) error = %v", err)
		}
		switch frame.Kind {
		case webproto.FrameMeta:
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: 0}))
		case webproto.FrameData:
			if frame.Seq != 1 {
				t.Fatalf("relay data seq = %d, want first chunk over relay", frame.Seq)
			}
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: 3}))
		case webproto.FrameDirectReady:
			var ready webproto.DirectReady
			if err := json.Unmarshal(frame.Payload, &ready); err != nil {
				t.Fatalf("Unmarshal(DirectReady) error = %v", err)
			}
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FramePathSwitch, ready.NextSeq, webproto.PathSwitch{
				Path:          "webrtc",
				BytesReceived: ready.BytesReceived,
				NextSeq:       ready.NextSeq,
			}))
		case webproto.FrameDone:
			t.Fatalf("done frame should not be sent over DERP after handoff")
		}
	}

	cb, statuses := collectStatuses()
	offer := &Offer{
		client: client,
		token:  tok,
		gate:   rendezvous.NewGate(tok),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- offer.SendWithOptions(ctx, source, cb, TransferOptions{Direct: direct})
	}()

	client.waitForSubscribers(t, 1)
	claim, err := newClaim(tok, peerDERP)
	if err != nil {
		t.Fatalf("newClaim() error = %v", err)
	}
	client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameClaim, 0, claim))

	select {
	case <-doneSent:
	case <-ctx.Done():
		t.Fatal("timed out waiting for direct done frame")
	}

	select {
	case err := <-errCh:
		t.Fatalf("SendWithOptions() returned before final ack: %v", err)
	default:
	}

	close(releaseFinalAck)
	if err := <-errCh; err != nil {
		t.Fatalf("SendWithOptions() error = %v", err)
	}

	derpFrames := client.sentFrames(t)
	if indexOfFrameKind(derpFrames, webproto.FrameDirectReady) == -1 {
		t.Fatalf("missing direct ready handoff frame: %+v", derpFrames)
	}
	if idx := indexOfFrameKind(derpFrames, webproto.FrameDone); idx != -1 {
		t.Fatalf("sent done over DERP after direct handoff at index %d", idx)
	}

	directFrames := direct.sentFrames(t)
	if len(directFrames) != 2 {
		t.Fatalf("direct frame count = %d, want 2", len(directFrames))
	}
	if directFrames[0].Kind != webproto.FrameData || directFrames[0].Seq != 2 {
		t.Fatalf("first direct frame = %+v, want data seq 2", directFrames[0])
	}
	if directFrames[1].Kind != webproto.FrameDone || directFrames[1].Seq != 3 {
		t.Fatalf("second direct frame = %+v, want done seq 3", directFrames[1])
	}

	gotStatuses := statuses()
	if index := func() int {
		for i, status := range gotStatuses {
			if status == statusDirect {
				return i
			}
		}
		return -1
	}(); index == -1 {
		t.Fatalf("statuses = %v, want connected-direct", gotStatuses)
	}
}

func TestSendWithOptionsActiveDirectFailureDoesNotResumeRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newFakeDERPClient()
	peerDERP := key.NewNode().Public()
	tok, err := newToken(client.PublicKey(), 1)
	if err != nil {
		t.Fatalf("newToken() error = %v", err)
	}

	source := newFakeSource("file.txt", []byte("abc"), []byte("def"))
	direct := newFakeDirect()
	direct.markReady()
	direct.sendHook = func(raw []byte) error {
		frame, err := webproto.Parse(raw)
		if err != nil {
			t.Fatalf("Parse(direct sent frame) error = %v", err)
		}
		if frame.Kind == webproto.FrameData && frame.Seq == 2 {
			return errors.New("datachannel closed")
		}
		return nil
	}

	client.sendHook = func(_ key.NodePublic, payload []byte) {
		frame, err := webproto.Parse(payload)
		if err != nil {
			t.Fatalf("Parse(sent frame) error = %v", err)
		}
		switch frame.Kind {
		case webproto.FrameMeta:
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: 0}))
		case webproto.FrameData:
			if frame.Seq != 1 {
				t.Fatalf("relay data seq = %d after active direct failure; relay resume is unsafe", frame.Seq)
			}
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: 3}))
		case webproto.FrameDirectReady:
			var ready webproto.DirectReady
			if err := json.Unmarshal(frame.Payload, &ready); err != nil {
				t.Fatalf("Unmarshal(DirectReady) error = %v", err)
			}
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FramePathSwitch, ready.NextSeq, webproto.PathSwitch{
				Path:          "webrtc",
				BytesReceived: ready.BytesReceived,
				NextSeq:       ready.NextSeq,
			}))
		case webproto.FrameDone:
			t.Fatalf("done frame should not be sent over DERP after active direct failure")
		}
	}

	offer := &Offer{
		client: client,
		token:  tok,
		gate:   rendezvous.NewGate(tok),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- offer.SendWithOptions(ctx, source, Callbacks{}, TransferOptions{Direct: direct})
	}()

	client.waitForSubscribers(t, 1)
	claim, err := newClaim(tok, peerDERP)
	if err != nil {
		t.Fatalf("newClaim() error = %v", err)
	}
	client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameClaim, 0, claim))

	err = <-errCh
	if err == nil || err.Error() != "datachannel closed" {
		t.Fatalf("SendWithOptions() error = %v, want datachannel closed", err)
	}
}

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

	switched, err := trySwitchDirectWithReplay(ctx, client, peerDERP, frames, direct, 4, window, Callbacks{})
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

func TestReceiveFramesBuffersOutOfOrderDataFrames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newFakeDERPClient()
	peerDERP := key.NewNode().Public()
	frames := make(chan []byte, 5)
	sink := &fakeSink{}

	errCh := make(chan error, 1)
	go func() {
		errCh <- receiveFrames(ctx, client, peerDERP, frames, nil, sink, Callbacks{})
	}()

	frames <- mustMarshalFrame(t, webproto.FrameMeta, 0, webproto.Meta{Name: "file.txt", Size: 9})
	frames <- mustMarshalFrame(t, webproto.FrameData, 1, []byte("abc"))
	frames <- mustMarshalFrame(t, webproto.FrameData, 3, []byte("ghi"))
	frames <- mustMarshalFrame(t, webproto.FrameData, 2, []byte("def"))
	frames <- mustMarshalFrame(t, webproto.FrameDone, 4, nil)

	if err := <-errCh; err != nil {
		t.Fatalf("receiveFrames() error = %v", err)
	}
	if got := sink.buf.String(); got != "abcdefghi" {
		t.Fatalf("received = %q, want abcdefghi", got)
	}
}

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

func TestReceiveContextCancelNotifiesSenderAbort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := newFakeDERPClient()
	peerDERP := key.NewNode().Public()
	sink := &fakeSink{}
	frames := make(chan []byte)

	errCh := make(chan error, 1)
	go func() {
		errCh <- receiveFrames(ctx, client, peerDERP, frames, nil, sink, Callbacks{})
	}()

	cancel()
	err := <-errCh
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("receiveFrames() error = %v, want context.Canceled", err)
	}
	if indexOfFrameKind(client.sentFrames(t), webproto.FrameAbort) == -1 {
		t.Fatal("receiver did not notify sender with FrameAbort")
	}
}

func TestReceiveFramesActiveDirectFailureReturnsImmediately(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
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

	derpFrames <- derpbind.Packet{
		From:    peerDERP,
		Payload: mustMarshalFrame(t, webproto.FrameMeta, 0, webproto.Meta{Name: "file.txt", Size: 6}),
	}
	derpFrames <- derpbind.Packet{
		From:    peerDERP,
		Payload: mustMarshalFrame(t, webproto.FrameData, 1, []byte("abc")),
	}
	derpFrames <- derpbind.Packet{
		From:    peerDERP,
		Payload: mustMarshalFrame(t, webproto.FrameDirectReady, 2, webproto.DirectReady{BytesReceived: 3, NextSeq: 2}),
	}
	client.waitForSentKind(t, webproto.FramePathSwitch)

	direct.fail(errors.New("datachannel closed"))

	err := <-errCh
	if err == nil || err.Error() != "datachannel closed" {
		t.Fatalf("receiveFrames() error = %v, want datachannel closed", err)
	}
}

func TestMergeFrameSourcesStopsOnPrivateCancel(t *testing.T) {
	ctx := context.Background()
	derpFrames := make(chan derpbind.Packet)
	direct := newFakeDirect()
	merged, stop := mergeFrameSources(ctx, derpFrames, direct)

	stop()

	select {
	case _, ok := <-merged:
		if ok {
			t.Fatal("merged source produced a frame after stop")
		}
	case <-time.After(time.Second):
		t.Fatal("merged source did not close after stop")
	}
}

func TestSendWithOptionsDirectDoneWaitIgnoresDirectCloseAfterFinalAck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client := newFakeDERPClient()
	peerDERP := key.NewNode().Public()
	tok, err := newToken(client.PublicKey(), 1)
	if err != nil {
		t.Fatalf("newToken() error = %v", err)
	}

	source := newFakeSource("file.txt", []byte("abc"), []byte("def"))
	direct := newFakeDirect()
	direct.markReady()
	direct.sendHook = func(raw []byte) error {
		frame, err := webproto.Parse(raw)
		if err != nil {
			t.Fatalf("Parse(direct sent frame) error = %v", err)
		}
		if frame.Kind == webproto.FrameDone {
			direct.fail(errors.New("datachannel closed"))
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: 6}))
		}
		return nil
	}

	client.sendHook = func(_ key.NodePublic, payload []byte) {
		frame, err := webproto.Parse(payload)
		if err != nil {
			t.Fatalf("Parse(sent frame) error = %v", err)
		}
		switch frame.Kind {
		case webproto.FrameMeta:
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: 0}))
		case webproto.FrameData:
			client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameAck, 0, webproto.Ack{BytesReceived: 3}))
		case webproto.FrameDirectReady:
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

	offer := &Offer{
		client: client,
		token:  tok,
		gate:   rendezvous.NewGate(tok),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- offer.SendWithOptions(ctx, source, Callbacks{}, TransferOptions{Direct: direct})
	}()

	client.waitForSubscribers(t, 1)
	claim, err := newClaim(tok, peerDERP)
	if err != nil {
		t.Fatalf("newClaim() error = %v", err)
	}
	client.emit(peerDERP, mustMarshalFrame(t, webproto.FrameClaim, 0, claim))

	if err := <-errCh; err != nil {
		t.Fatalf("SendWithOptions() error = %v", err)
	}
}
