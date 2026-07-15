// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"tailscale.com/types/key"
)

func TestExternalV2BulkPacketBatchedSenderMatchesLegacyPackets(t *testing.T) {
	const laneCount = 2
	payload := make([]byte, externalV2BulkPacketPayloadSize*900+17)
	for index := range payload {
		payload[index] = byte((index*29 + 7) % 251)
	}
	senders, receivers := listenExternalV2BulkPacketTestConns(t, laneCount)
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	sender := newExternalV2BulkPacketSender(context.Background(), &BlockSource{
		Payload:     bytes.NewReader(payload),
		PayloadSize: int64(len(payload)),
	}, externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receivers)}, auth, nil)
	sender.pacer = rate.NewLimiter(rate.Inf, externalV2BulkPacketPaceBurstBytes)
	captures := make([]*captureExternalV2BulkPacketBatchConn, laneCount)
	sender.batchConns = make([]externalV2BulkPacketBatchConn, laneCount)
	for lane := range laneCount {
		captures[lane] = &captureExternalV2BulkPacketBatchConn{}
		sender.batchConns[lane] = captures[lane]
	}

	if err := sender.sendInitialPacketsBatched(); err != nil {
		t.Fatal(err)
	}

	totalPackets := externalV2BulkPacketCount(int64(len(payload)))
	seen := make([]bool, totalPackets)
	for lane, capture := range captures {
		var previous uint32
		for capturedIndex, packet := range capture.packets {
			header, data, ok := openExternalV2BulkPacket(auth.data, packet)
			if !ok {
				t.Fatalf("lane %d packet %d did not authenticate", lane, capturedIndex)
			}
			if got := externalV2BulkPacketPrimaryLane(header.index, laneCount); got != lane {
				t.Fatalf("packet %d lane = %d, want %d", header.index, lane, got)
			}
			if capturedIndex > 0 && header.index <= previous {
				t.Fatalf("lane %d packet order regressed from %d to %d", lane, previous, header.index)
			}
			previous = header.index
			if seen[header.index] {
				t.Fatalf("packet %d duplicated", header.index)
			}
			seen[header.index] = true
			offset := int(header.index) * externalV2BulkPacketPayloadSize
			end := min(len(payload), offset+externalV2BulkPacketPayloadSize)
			if !bytes.Equal(data, payload[offset:end]) {
				t.Fatalf("packet %d payload mismatch", header.index)
			}
			legacy, err := sealExternalV2BulkPacket(auth.data, externalV2BulkPacketHeader{
				kind: externalV2BulkPacketData, runID: sender.runID, index: header.index, total: totalPackets,
			}, payload[offset:end])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(packet, legacy) {
				t.Fatalf("packet %d differs from legacy wire encoding", header.index)
			}
		}
	}
	for index, received := range seen {
		if !received {
			t.Fatalf("packet %d was not sent", index)
		}
	}
	for lane, capture := range captures {
		if capture.maxBatch > externalV2BulkPacketDataBatchSize {
			t.Fatalf("lane %d maximum batch = %d, want <= %d", lane, capture.maxBatch, externalV2BulkPacketDataBatchSize)
		}
	}
	if got := sender.sentPackets.Load(); got != uint64(totalPackets) {
		t.Fatalf("sent packets = %d, want %d", got, totalPackets)
	}
	if got := sender.primaryPayloadBytes.Load(); got != int64(len(payload)) {
		t.Fatalf("primary payload = %d, want %d", got, len(payload))
	}
	var acceptedPayloadBytes int
	for _, capture := range captures {
		for _, n := range capture.payloadBytes {
			acceptedPayloadBytes += n
		}
	}
	if acceptedPayloadBytes != len(payload) {
		t.Fatalf("batch message payload bytes = %d, want %d", acceptedPayloadBytes, len(payload))
	}
}

func TestExternalV2BulkPacketRepairUsesBatchesAndPreservesLaneRotation(t *testing.T) {
	const laneCount = 4
	payload := make([]byte, externalV2BulkPacketPayloadSize*9+17)
	for index := range payload {
		payload[index] = byte((index*31 + 11) % 251)
	}
	senders, receivers := listenExternalV2BulkPacketTestConns(t, laneCount)
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	sender := newExternalV2BulkPacketSender(context.Background(), &BlockSource{
		Payload: bytes.NewReader(payload), PayloadSize: int64(len(payload)),
	}, externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receivers)}, auth, nil)
	sender.pacer = rate.NewLimiter(rate.Inf, externalV2BulkPacketPaceBurstBytes)
	captures := make([]*captureExternalV2BulkPacketBatchConn, laneCount)
	sender.batchConns = make([]externalV2BulkPacketBatchConn, laneCount)
	for lane := range laneCount {
		captures[lane] = &captureExternalV2BulkPacketBatchConn{}
		sender.batchConns[lane] = captures[lane]
	}

	missing := []uint32{0, 1, 2, 3, 4, 9, sender.totalPackets}
	lastRepair := make(map[uint32]time.Time)
	repairAttempt := map[uint32]uint64{4: 1}
	sent, err := sender.repairMissing(missing, lastRepair, repairAttempt)
	if err != nil {
		t.Fatal(err)
	}
	if !sent {
		t.Fatal("repairMissing() sent = false, want true")
	}

	wantLane := map[uint32]int{
		0: 1,
		1: 2,
		2: 3,
		3: 0,
		4: 2,
		9: 2,
	}
	seen := make(map[uint32]bool, len(wantLane))
	var wantPayload int64
	var wantWire int64
	for lane, capture := range captures {
		if capture.maxBatch > externalV2BulkPacketDataBatchSize {
			t.Fatalf("lane %d maximum repair batch = %d, want <= %d", lane, capture.maxBatch, externalV2BulkPacketDataBatchSize)
		}
		for _, packet := range capture.packets {
			header, data, ok := openExternalV2BulkPacket(auth.data, packet)
			if !ok {
				t.Fatalf("lane %d repair packet did not authenticate", lane)
			}
			if got, ok := wantLane[header.index]; !ok || got != lane {
				t.Fatalf("packet %d lane = %d, want %d", header.index, lane, got)
			}
			if seen[header.index] {
				t.Fatalf("packet %d sent more than once", header.index)
			}
			seen[header.index] = true
			offset := int(header.index) * externalV2BulkPacketPayloadSize
			end := min(len(payload), offset+externalV2BulkPacketPayloadSize)
			if !bytes.Equal(data, payload[offset:end]) {
				t.Fatalf("packet %d payload mismatch", header.index)
			}
			wantPayload += int64(len(data))
			wantWire += int64(externalV2BulkPacketIPv4WireBytes(len(packet)))
		}
	}
	if len(seen) != len(wantLane) {
		t.Fatalf("sent %d repair packets, want %d", len(seen), len(wantLane))
	}
	if got := sender.repairPackets.Load(); got != int64(len(wantLane)) {
		t.Fatalf("repair packets = %d, want %d", got, len(wantLane))
	}
	if got := sender.repairPayloadBytes.Load(); got != wantPayload {
		t.Fatalf("repair payload bytes = %d, want %d", got, wantPayload)
	}
	if got := sender.repairWireBytes.Load(); got != wantWire {
		t.Fatalf("repair wire bytes = %d, want %d", got, wantWire)
	}
	if got := sender.sentPackets.Load(); got != uint64(len(wantLane)) {
		t.Fatalf("sent packets = %d, want %d", got, len(wantLane))
	}
	if got := sender.sentPayload.Load(); got != wantPayload {
		t.Fatalf("sent payload = %d, want %d", got, wantPayload)
	}
	var acceptedRepairPayload int64
	for _, capture := range captures {
		for _, n := range capture.payloadBytes {
			acceptedRepairPayload += int64(n)
		}
	}
	if acceptedRepairPayload != wantPayload {
		t.Fatalf("repair batch message payload bytes = %d, want %d", acceptedRepairPayload, wantPayload)
	}
	if got := repairAttempt[4]; got != 2 {
		t.Fatalf("packet 4 repair attempt = %d, want 2", got)
	}
	if _, ok := lastRepair[sender.totalPackets]; ok {
		t.Fatal("out-of-range repair was recorded")
	}
}

func TestExternalV2BulkPacketWorkerCountCapsAtTwo(t *testing.T) {
	tests := []struct{ cpus, want int }{{0, 1}, {1, 1}, {2, 2}, {8, 2}}
	for _, tt := range tests {
		if got := externalV2BulkPacketWorkerCount(tt.cpus); got != tt.want {
			t.Errorf("worker count for %d CPUs = %d, want %d", tt.cpus, got, tt.want)
		}
	}
}

func TestExternalV2BulkPacketDataLaneCountIsBounded(t *testing.T) {
	for _, tt := range []struct {
		conns int
		addrs int
		want  int
	}{
		{conns: 1, addrs: 1, want: 1},
		{conns: 8, addrs: 3, want: 3},
		{conns: 8, addrs: 8, want: 4},
	} {
		if got := externalV2BulkPacketDataLaneCount(tt.conns, tt.addrs); got != tt.want {
			t.Errorf("data lanes for %d/%d = %d, want %d", tt.conns, tt.addrs, got, tt.want)
		}
	}
}

func TestExternalV2BulkPacketSenderWaitsForPeerReceiveWindow(t *testing.T) {
	metrics := newExternalTransferMetrics(time.Now())
	sender := &externalV2BulkPacketSender{
		metrics:             metrics,
		ackNegotiationUntil: time.Now().Add(time.Second),
	}
	sender.primaryPayloadBytes.Store(externalV2BulkPacketDirectReceiveWindow)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- sender.waitForPeerReceiveWindow(ctx, 1)
	}()
	select {
	case err := <-done:
		t.Fatalf("receive window did not block: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if !sender.receiveWindowBlocked.Load() {
		t.Fatal("receive-window blocking was not exposed to the rate controller")
	}

	sender.receiveAck.record(1, externalV2BulkPacketDirectReceiveWindow)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("receive window did not reopen after peer progress")
	}
}

func TestExternalV2BulkPacketSenderFallsBackWhenPeerDoesNotAck(t *testing.T) {
	now := time.Now()
	metrics := newExternalTransferMetrics(now)
	metrics.RecordPeerProgress(4<<20, 25, now)
	sender := &externalV2BulkPacketSender{
		metrics:             metrics,
		ackNegotiationUntil: now.Add(externalV2BulkPacketAckNegotiationWait),
	}

	peerBytes, window := sender.peerReceiveWindow(now)
	if peerBytes != 4<<20 || window != externalV2BulkPacketBufferedReceiveWindow {
		t.Fatalf("negotiating window = %d + %d, want 4 MiB + %d", peerBytes, window, externalV2BulkPacketBufferedReceiveWindow)
	}
	peerBytes, window = sender.peerReceiveWindow(now.Add(externalV2BulkPacketAckNegotiationWait))
	if peerBytes != 4<<20 || window != externalV2BulkPacketFallbackReceiveWindow {
		t.Fatalf("fallback window = %d + %d, want 4 MiB + %d", peerBytes, window, externalV2BulkPacketFallbackReceiveWindow)
	}

	sender.receiveAck.record(7<<20, externalV2BulkPacketDirectReceiveWindow)
	peerBytes, window = sender.peerReceiveWindow(now.Add(time.Second))
	if peerBytes != 7<<20 || window != externalV2BulkPacketDirectReceiveWindow {
		t.Fatalf("direct ACK window = %d + %d, want 7 MiB + %d", peerBytes, window, externalV2BulkPacketDirectReceiveWindow)
	}
}

func TestExternalV2BulkPacketBatchedSenderRetriesENOBUFSFromFirstUnsent(t *testing.T) {
	sender := &externalV2BulkPacketSender{ctx: context.Background()}
	batch := &enobufsExternalV2BulkPacketBatchConn{remaining: 3, partialFirst: true}
	sender.batchConns = []externalV2BulkPacketBatchConn{batch}
	messages := make([]externalV2BulkPacketBatchMessage, 4)
	for index := range messages {
		messages[index].Buffers = [][]byte{{byte(index)}}
	}

	if err := sender.writeDataBatch(0, messages); err != nil {
		t.Fatal(err)
	}
	if batch.attempts != 4 {
		t.Fatalf("attempts = %d, want 4", batch.attempts)
	}
	if !bytes.Equal(batch.starts, []byte{0, 1, 1, 1}) {
		t.Fatalf("retry starts = %v, want [0 1 1 1]", batch.starts)
	}
	if sender.localENOBUFSRetries.Load() != 3 || sender.localENOBUFSMaxConsecutive.Load() != 3 {
		t.Fatalf("ENOBUFS counters = retries %d max %d", sender.localENOBUFSRetries.Load(), sender.localENOBUFSMaxConsecutive.Load())
	}
}

func TestExternalV2BulkPacketBatchedSenderStopsBlockedBatchOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	batch := &blockingExternalV2BulkPacketBatchConn{started: make(chan struct{})}
	sender := &externalV2BulkPacketSender{ctx: ctx, batchConns: []externalV2BulkPacketBatchConn{batch}}
	result := make(chan error, 1)
	go func() {
		result <- sender.writeDataBatch(0, []externalV2BulkPacketBatchMessage{{Buffers: [][]byte{{1}}}})
	}()
	<-batch.started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestExternalV2BulkPacketSenderWritesLanesConcurrently(t *testing.T) {
	const laneCount = 4
	payload := bytes.Repeat([]byte{0x51}, externalV2BulkPacketPayloadSize*externalV2BulkPacketSlabPackets*3)
	senders, receivers := listenExternalV2BulkPacketTestConns(t, laneCount)
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	sender := newExternalV2BulkPacketSender(context.Background(), &BlockSource{
		Payload: bytes.NewReader(payload), PayloadSize: int64(len(payload)),
	}, externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receivers)}, auth, nil)
	sender.pacer = rate.NewLimiter(rate.Inf, externalV2BulkPacketPaceBurstBytes)

	lanes := make([]*signalingExternalV2BulkPacketBatchConn, laneCount)
	sender.batchConns = make([]externalV2BulkPacketBatchConn, laneCount)
	for lane := range laneCount {
		lanes[lane] = &signalingExternalV2BulkPacketBatchConn{started: make(chan struct{})}
		sender.batchConns[lane] = lanes[lane]
	}
	lanes[0].block = make(chan struct{})

	done := make(chan error, 1)
	go func() { done <- sender.sendInitialPacketsBatched() }()
	select {
	case <-lanes[0].started:
	case <-time.After(time.Second):
		t.Fatal("lane 0 did not start")
	}
	select {
	case <-lanes[1].started:
	case <-time.After(time.Second):
		close(lanes[0].block)
		t.Fatal("lane 1 did not progress while lane 0 was blocked")
	}
	close(lanes[0].block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if peak := sender.batchLaneQueuePeak.Load(); peak == 0 || peak > externalV2BulkPacketLaneQueueDepth {
		t.Fatalf("lane queue peak = %d, want 1..%d", peak, externalV2BulkPacketLaneQueueDepth)
	}
}

func TestExternalV2BulkPacketLaneQueuePeakRecordsImmediateHandoff(t *testing.T) {
	pool := newCountingExternalV2BulkPacketSlabPool()
	queue := make(chan externalV2BulkPacketLaneJob, externalV2BulkPacketLaneQueueDepth)
	received := make(chan struct{})
	go func() {
		job := <-queue
		job.lease.release()
		close(received)
	}()
	sender := &externalV2BulkPacketSender{}
	prepared := externalV2BulkPacketPreparedSlab{
		byLane: [][]externalV2BulkPacketBatchMessage{{{Buffers: [][]byte{{1}}}}},
		slab:   pool.Get().(*externalV2BulkPacketSlab),
	}
	if err := sender.dispatchPreparedPacketSlab(context.Background(), prepared, []chan externalV2BulkPacketLaneJob{queue}, pool); err != nil {
		t.Fatal(err)
	}
	<-received
	if peak := sender.batchLaneQueuePeak.Load(); peak != 1 {
		t.Fatalf("lane queue peak = %d, want 1 for immediate handoff", peak)
	}
}

var errInjectedLaneWrite = errors.New("injected lane write failure")

func TestExternalV2BulkPacketLaneWritersCancelAndReleaseEverySlab(t *testing.T) {
	const laneCount = 3
	payload := bytes.Repeat([]byte{0x73}, externalV2BulkPacketPayloadSize*(externalV2BulkPacketSlabPackets*3+1))
	senders, receivers := listenExternalV2BulkPacketTestConns(t, laneCount)
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	pool := newCountingExternalV2BulkPacketSlabPool()
	sender := newExternalV2BulkPacketSender(context.Background(), &BlockSource{
		Payload: bytes.NewReader(payload), PayloadSize: int64(len(payload)),
	}, externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receivers)}, auth, nil)
	sender.pacer = rate.NewLimiter(rate.Inf, externalV2BulkPacketPaceBurstBytes)
	sender.slabPool = pool
	sender.batchConns = []externalV2BulkPacketBatchConn{
		&signalingExternalV2BulkPacketBatchConn{started: make(chan struct{}), err: errInjectedLaneWrite},
		&signalingExternalV2BulkPacketBatchConn{started: make(chan struct{})},
		&signalingExternalV2BulkPacketBatchConn{started: make(chan struct{})},
	}

	err = sender.sendInitialPacketsBatched()
	if !errors.Is(err, errInjectedLaneWrite) {
		t.Fatalf("error = %v, want injected lane failure", err)
	}
	if got, want := pool.gets.Load(), pool.puts.Load(); got != want {
		t.Fatalf("slab pool gets=%d puts=%d", got, want)
	}
}

type captureExternalV2BulkPacketBatchConn struct {
	mu           sync.Mutex
	packets      [][]byte
	payloadBytes []int
	maxBatch     int
}

func (c *captureExternalV2BulkPacketBatchConn) WriteBatch(_ context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxBatch = max(c.maxBatch, len(messages))
	for _, message := range messages {
		packet := append([]byte(nil), message.Buffers[0]...)
		c.packets = append(c.packets, packet)
		c.payloadBytes = append(c.payloadBytes, message.PayloadBytes)
	}
	return len(messages), nil
}

func (*captureExternalV2BulkPacketBatchConn) ReadBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, errors.New("unexpected read")
}

func (c *captureExternalV2BulkPacketBatchConn) Stats() externalV2BulkPacketBatchStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return externalV2BulkPacketBatchStats{Backend: "capture", SendDatagrams: uint64(len(c.packets))}
}

type enobufsExternalV2BulkPacketBatchConn struct {
	remaining    int
	attempts     int
	partialFirst bool
	starts       []byte
}

func (c *enobufsExternalV2BulkPacketBatchConn) WriteBatch(_ context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	c.attempts++
	c.starts = append(c.starts, messages[0].Buffers[0][0])
	if c.remaining > 0 {
		c.remaining--
		if c.partialFirst && c.attempts == 1 {
			return 1, syscall.ENOBUFS
		}
		return 0, syscall.ENOBUFS
	}
	return len(messages), nil
}

func (*enobufsExternalV2BulkPacketBatchConn) ReadBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, errors.New("unexpected read")
}

func (*enobufsExternalV2BulkPacketBatchConn) Stats() externalV2BulkPacketBatchStats {
	return externalV2BulkPacketBatchStats{Backend: "enobufs"}
}

type blockingExternalV2BulkPacketBatchConn struct {
	started chan struct{}
	once    sync.Once
}

func (c *blockingExternalV2BulkPacketBatchConn) WriteBatch(ctx context.Context, _ []externalV2BulkPacketBatchMessage) (int, error) {
	c.once.Do(func() { close(c.started) })
	<-ctx.Done()
	return 0, ctx.Err()
}

func (*blockingExternalV2BulkPacketBatchConn) ReadBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, errors.New("unexpected read")
}

func (*blockingExternalV2BulkPacketBatchConn) Stats() externalV2BulkPacketBatchStats {
	return externalV2BulkPacketBatchStats{Backend: "blocking"}
}

type signalingExternalV2BulkPacketBatchConn struct {
	once    sync.Once
	started chan struct{}
	block   chan struct{}
	err     error
}

func (c *signalingExternalV2BulkPacketBatchConn) WriteBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	c.once.Do(func() { close(c.started) })
	if c.block != nil {
		select {
		case <-c.block:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	if c.err != nil {
		return 0, c.err
	}
	return len(messages), nil
}

func (*signalingExternalV2BulkPacketBatchConn) ReadBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, errors.New("unexpected read")
}

func (*signalingExternalV2BulkPacketBatchConn) Stats() externalV2BulkPacketBatchStats {
	return externalV2BulkPacketBatchStats{Backend: "signaling"}
}

type countingExternalV2BulkPacketSlabPool struct {
	pool sync.Pool
	gets atomic.Int64
	puts atomic.Int64
}

func newCountingExternalV2BulkPacketSlabPool() *countingExternalV2BulkPacketSlabPool {
	p := &countingExternalV2BulkPacketSlabPool{}
	p.pool.New = func() any { return newExternalV2BulkPacketSlab() }
	return p
}

func (p *countingExternalV2BulkPacketSlabPool) Get() any {
	p.gets.Add(1)
	return p.pool.Get()
}

func (p *countingExternalV2BulkPacketSlabPool) Put(value any) {
	p.puts.Add(1)
	p.pool.Put(value)
}
