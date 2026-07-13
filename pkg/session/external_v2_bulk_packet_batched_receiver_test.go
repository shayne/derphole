// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/types/key"
)

func TestExternalV2BulkPacketReceivePipelineBuffersOneDirectWindow(t *testing.T) {
	if externalV2BulkPacketMaxBatch < 192 {
		t.Fatalf("maximum receive batch = %d, want at least 192 to drain receive bursts", externalV2BulkPacketMaxBatch)
	}
	if externalV2BulkPacketDirectDecryptQueue < 128 {
		t.Fatalf("direct decrypt queue = %d batches, want at least 128", externalV2BulkPacketDirectDecryptQueue)
	}
	queueBytes := externalV2BulkPacketDataQueue * externalV2BulkPacketMaxSize
	if queueBytes < externalV2BulkPacketBufferedReceiveWindow {
		t.Fatalf("receive queue = %d bytes, want one buffered window", queueBytes)
	}
	if queueBytes > 40<<20 {
		t.Fatalf("receive queue = %d bytes, want at most 40 MiB", queueBytes)
	}
	directDecryptBytes := externalV2BulkPacketDirectDecryptQueue * externalV2BulkPacketMaxBatch * externalV2BulkPacketMaxSize
	if externalV2BulkPacketDirectReceiveWindow != 32<<20 {
		t.Fatalf("direct receive window = %d, want 32 MiB", externalV2BulkPacketDirectReceiveWindow)
	}
	if directDecryptBytes < externalV2BulkPacketBufferedReceiveWindow {
		t.Fatalf("direct decrypt queue = %d bytes, want at least one buffered-sink window %d", directDecryptBytes, externalV2BulkPacketBufferedReceiveWindow)
	}
	if directDecryptBytes > 40<<20 {
		t.Fatalf("direct decrypt queue = %d bytes, want at most 40 MiB", directDecryptBytes)
	}
}

func TestExternalV2BulkPacketDecryptEmitsOneReceiveBatch(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	const packetCount = 64
	packets := make([][]byte, packetCount)
	for index := range packetCount {
		payload := bytes.Repeat([]byte{byte(index)}, 32+index)
		packets[index], err = sealExternalV2BulkPacket(auth.data, externalV2BulkPacketHeader{
			kind: externalV2BulkPacketData, runID: 7, index: uint32(index), total: packetCount,
		}, payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	batch := &scriptedReceiveExternalV2BulkPacketBatchConn{packets: packets, delivered: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	dataCh := make(chan externalV2BulkPacketReceiveBatch, 1)
	errCh := make(chan error, 1)
	arrivals := newExternalV2BulkPacketArrivalTracker(packetCount)
	done := startExternalV2BulkPacketBatchedDataReaders(ctx, []externalV2BulkPacketBatchConn{batch}, auth, dataCh, errCh, arrivals, nil, nil)

	seen := make([]bool, packetCount)
	select {
	case receiveBatch := <-dataCh:
		defer receiveBatch.release()
		if len(receiveBatch.results) != packetCount {
			t.Fatalf("receive batch size = %d, want %d", len(receiveBatch.results), packetCount)
		}
		for _, result := range receiveBatch.results {
			if result.header.index >= packetCount {
				t.Fatalf("index = %d", result.header.index)
			}
			if result.sealedBuffer == nil || len(result.data) == 0 ||
				&result.data[0] != &result.sealedBuffer.data[externalV2BulkPacketHeaderSize] {
				t.Fatalf("packet %d was not decrypted in its receive buffer", result.header.index)
			}
			if result.header.index == 0 && &result.sealedBuffer.data[0] != batch.firstBuffer {
				t.Fatal("receive buffer was copied before decryption")
			}
			want := bytes.Repeat([]byte{byte(result.header.index)}, 32+int(result.header.index))
			if !bytes.Equal(result.data, want) {
				t.Fatalf("packet %d payload mismatch", result.header.index)
			}
			seen[result.header.index] = true
			if !arrivals.contains(result.header.index) {
				t.Fatalf("authenticated packet %d was not marked arrived before assembly", result.header.index)
			}
		}
	case err := <-errCh:
		t.Fatalf("reader error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for decrypted batch")
	}
	for index, ok := range seen {
		if !ok {
			t.Fatalf("packet %d missing", index)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("batched readers did not stop after cancellation")
	}
}

func TestExternalV2BulkPacketDecryptCopiesAuthenticatedPayloadIntoDirectBuffer(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	const packetCount = 3
	payloadSize := int64(packetCount * externalV2BulkPacketPayloadSize)
	directBuffer := make([]byte, payloadSize)
	packets := make([][]byte, packetCount)
	for index := range packetCount {
		payload := bytes.Repeat([]byte{byte(index + 1)}, externalV2BulkPacketPayloadSize)
		packets[index], err = sealExternalV2BulkPacket(auth.data, externalV2BulkPacketHeader{
			kind: externalV2BulkPacketData, runID: 11, index: uint32(index), total: packetCount,
		}, payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	batch := &scriptedReceiveExternalV2BulkPacketBatchConn{packets: packets, delivered: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dataCh := make(chan externalV2BulkPacketReceiveBatch, 1)
	errCh := make(chan error, 1)
	arrivals := newExternalV2BulkPacketArrivalTracker(packetCount)
	done := startExternalV2BulkPacketBatchedDataReaders(ctx, []externalV2BulkPacketBatchConn{batch}, auth, dataCh, errCh, arrivals, directBuffer, nil, nil, nil)

	select {
	case receiveBatch := <-dataCh:
		defer receiveBatch.release()
		if len(receiveBatch.results) != packetCount {
			t.Fatalf("receive batch size = %d, want %d", len(receiveBatch.results), packetCount)
		}
		for _, result := range receiveBatch.results {
			if len(result.data) != 0 || result.sealedBuffer != nil || !result.direct {
				t.Fatalf("packet %d retained payload after direct copy: %+v", result.header.index, result)
			}
			start := int(result.header.index) * externalV2BulkPacketPayloadSize
			want := bytes.Repeat([]byte{byte(result.header.index + 1)}, externalV2BulkPacketPayloadSize)
			if !bytes.Equal(directBuffer[start:start+externalV2BulkPacketPayloadSize], want) {
				t.Fatalf("packet %d was not copied into the direct buffer", result.header.index)
			}
		}
	case err := <-errCh:
		t.Fatalf("reader error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for direct receive batch")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("batched readers did not stop after cancellation")
	}
}

func TestExternalV2BulkPacketDirectDecryptRejectsForgedDuplicatesWithoutCorruption(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x73}, externalV2BulkPacketPayloadSize)
	valid, err := sealExternalV2BulkPacket(auth.data, externalV2BulkPacketHeader{
		kind: externalV2BulkPacketData, runID: 19, index: 0, total: 1,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	forged := append([]byte(nil), valid...)
	forged[len(forged)-1] ^= 0xff
	batch := &scriptedReceiveExternalV2BulkPacketBatchConn{
		packets:   [][]byte{forged, valid, forged},
		delivered: make(chan struct{}),
	}
	directBuffer := make([]byte, len(payload))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dataCh := make(chan externalV2BulkPacketReceiveBatch, 1)
	errCh := make(chan error, 1)
	arrivals := newExternalV2BulkPacketArrivalTracker(1)
	done := startExternalV2BulkPacketBatchedDataReaders(ctx, []externalV2BulkPacketBatchConn{batch}, auth, dataCh, errCh, arrivals, directBuffer, nil, nil, nil)
	select {
	case receiveBatch := <-dataCh:
		defer receiveBatch.release()
		if len(receiveBatch.results) != 1 {
			t.Fatalf("authenticated results = %d, want 1", len(receiveBatch.results))
		}
		if !bytes.Equal(directBuffer, payload) {
			t.Fatal("forged duplicate corrupted authenticated direct payload")
		}
	case err := <-errCh:
		t.Fatalf("reader error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for authenticated direct payload")
	}
	cancel()
	<-done
}

func TestCopyExternalV2BulkPacketDirectPayloadValidatesLayout(t *testing.T) {
	direct := make([]byte, externalV2BulkPacketPayloadSize+17)
	payload := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize)
	header := externalV2BulkPacketHeader{index: 0, total: externalV2BulkPacketCount(int64(len(direct)))}
	if !copyExternalV2BulkPacketDirectPayload(direct, header, payload) {
		t.Fatal("valid direct payload was rejected")
	}
	if !bytes.Equal(direct[:len(payload)], payload) {
		t.Fatal("valid direct payload was not copied")
	}

	invalid := []struct {
		name    string
		header  externalV2BulkPacketHeader
		payload []byte
	}{
		{name: "wrong total", header: externalV2BulkPacketHeader{index: 0, total: header.total + 1}, payload: payload},
		{name: "index outside total", header: externalV2BulkPacketHeader{index: header.total, total: header.total}, payload: payload},
		{name: "wrong payload length", header: header, payload: payload[:len(payload)-1]},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			if copyExternalV2BulkPacketDirectPayload(direct, tt.header, tt.payload) {
				t.Fatal("invalid direct payload was accepted")
			}
		})
	}
}

func TestExternalV2BulkPacketBatchedReceiverIgnoresInvalidPackets(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	batch := &scriptedReceiveExternalV2BulkPacketBatchConn{packets: [][]byte{{1, 2, 3}}, delivered: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	dataCh := make(chan externalV2BulkPacketReceiveBatch, 1)
	errCh := make(chan error, 1)
	done := startExternalV2BulkPacketBatchedDataReaders(ctx, []externalV2BulkPacketBatchConn{batch}, auth, dataCh, errCh, nil, nil, nil)
	<-batch.delivered
	select {
	case receiveBatch := <-dataCh:
		receiveBatch.release()
		t.Fatal("invalid packet produced a receive result")
	case err := <-errCh:
		t.Fatalf("invalid packet produced a fatal error: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	<-done
}

func TestExternalV2BulkPacketBatchAccountingMatchesSinglePacketAccounting(t *testing.T) {
	const packetCount = 5
	sequence := []uint32{0, 2, 1, 4, 3, 4}
	newReceiver := func() (*externalV2BulkPacketReceiver, *memoryBlockSink) {
		sink := newMemoryBlockSink(packetCount * externalV2BulkPacketPayloadSize)
		receiver := newExternalV2BulkPacketReceiver(sink, externalV2BlockReceiveConfig{
			PayloadSize: packetCount * externalV2BulkPacketPayloadSize,
		}, externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, nil)
		receiver.stopHello = func() {}
		return receiver, sink
	}
	resultFor := func(index uint32) externalV2BulkPacketReceiveResult {
		return externalV2BulkPacketReceiveResult{
			header: externalV2BulkPacketHeader{runID: 9, index: index, total: packetCount},
			data:   bytes.Repeat([]byte{byte(index + 1)}, externalV2BulkPacketPayloadSize),
		}
	}

	single, singleSink := newReceiver()
	for _, index := range sequence {
		if err := single.handleDataResult(resultFor(index)); err != nil {
			t.Fatal(err)
		}
	}
	batched, batchedSink := newReceiver()
	receiveBatch := externalV2BulkPacketReceiveBatch{}
	for _, index := range sequence {
		receiveBatch.results = append(receiveBatch.results, resultFor(index))
	}
	if err := batched.handleDataBatch(receiveBatch, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}

	if single.receivedPackets != batched.receivedPackets || single.committedPayload != batched.committedPayload {
		t.Fatalf("accounting differs: single packets=%d bytes=%d batch packets=%d bytes=%d", single.receivedPackets, single.committedPayload, batched.receivedPackets, batched.committedPayload)
	}
	if single.missing.stats() != batched.missing.stats() {
		t.Fatalf("missing stats differ: single=%+v batch=%+v", single.missing.stats(), batched.missing.stats())
	}
	if !bytes.Equal(singleSink.bytes(), batchedSink.bytes()) {
		t.Fatal("batched coordinator output differs from single-result coordinator")
	}
}

func TestExternalV2BulkPacketReceiverCommitsDirectBatchesWithoutAssembler(t *testing.T) {
	const packetCount = 4
	payloadSize := int64(packetCount * externalV2BulkPacketPayloadSize)
	sink := &directMemoryBulkPacketSink{buffer: make([]byte, payloadSize)}
	receiver := newExternalV2BulkPacketReceiver(sink, externalV2BlockReceiveConfig{
		PayloadSize: payloadSize,
	}, externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, nil)
	receiver.stopHello = func() {}
	if receiver.directSink == nil || receiver.assembler != nil {
		t.Fatalf("direct receiver sink=%T assembler=%p", receiver.directSink, receiver.assembler)
	}
	batch := externalV2BulkPacketReceiveBatch{}
	for index := range packetCount {
		batch.results = append(batch.results, externalV2BulkPacketReceiveResult{
			header: externalV2BulkPacketHeader{
				runID: 23, index: uint32(index), total: packetCount, length: externalV2BulkPacketPayloadSize,
			},
			direct: true,
		})
	}
	if err := receiver.handleDataBatch(batch, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	if got := sink.committed.Load(); got != payloadSize {
		t.Fatalf("direct committed bytes = %d, want %d", got, payloadSize)
	}
	if receiver.committedPayload != payloadSize || receiver.receivedPackets != packetCount {
		t.Fatalf("receiver committed=%d packets=%d", receiver.committedPayload, receiver.receivedPackets)
	}
}

func TestExternalV2BulkPacketBatchedTransferEndToEnd(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_BULK_BATCHED_IO", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 4)
	// Keep the lossless transfer active across multiple repair ticks. A repair
	// tick must not request packets beyond the sender's current high-water mark.
	payload := make([]byte, 32<<20+37)
	for index := range payload {
		payload[index] = byte((index*23 + 11) % 251)
	}
	sink := newMemoryBlockSink(int64(len(payload)))
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	receiveResult := make(chan error, 1)
	var receiveStats externalDirectTransferStats
	go func() {
		received, stats, err := receiveExternalV2BulkBlockPackets(ctx, sink, externalV2BlockReceiveConfig{
			PayloadSize: int64(len(payload)), ChunkSize: 1 << 20, HeaderBytes: 7,
		}, externalV2BulkPacketPath{Conns: receivers, Addrs: externalV2BulkPacketTestAddrs(senders)}, auth, nil)
		receiveStats = stats
		if err == nil && received != int64(len(payload))+7 {
			err = errors.New("received byte count does not include exact payload and header")
		}
		receiveResult <- err
	}()
	sendStats, err := sendExternalV2BulkBlockPackets(ctx, &BlockSource{
		Payload: bytes.NewReader(payload), PayloadSize: int64(len(payload)), ChunkSize: 1 << 20,
	}, externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receivers)}, auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-receiveResult; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sink.bytes(), payload) {
		t.Fatal("batched transfer output does not match")
	}
	if sendStats.BytesSent != int64(len(payload)) || sendStats.Retransmits != 0 {
		t.Fatalf("send stats = %+v", sendStats)
	}
	if receiveStats.Diagnostics.RepairRequests != 0 {
		t.Fatalf("lossless receive repair requests = %d, want 0", receiveStats.Diagnostics.RepairRequests)
	}
	if sendStats.Diagnostics.BulkProbeSelectedMbps < 1000 || sendStats.Diagnostics.BulkProbeSentDatagrams == 0 || sendStats.Diagnostics.BulkProbeReceivedDatagrams == 0 {
		t.Fatalf("send probe diagnostics = %+v", sendStats.Diagnostics)
	}
	if receiveStats.Diagnostics.BulkProbeSelectedMbps != sendStats.Diagnostics.BulkProbeSelectedMbps {
		t.Fatalf("probe selection differs: send=%d receive=%d", sendStats.Diagnostics.BulkProbeSelectedMbps, receiveStats.Diagnostics.BulkProbeSelectedMbps)
	}
}

func TestExternalV2BulkPacketBatchedDirectTransferEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 4)
	payload := make([]byte, 8<<20+37)
	for index := range payload {
		payload[index] = byte((index*31 + 7) % 251)
	}
	sink := &directMemoryBulkPacketSink{buffer: make([]byte, len(payload))}
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	receiveResult := make(chan struct {
		stats externalDirectTransferStats
		err   error
	}, 1)
	go func() {
		_, stats, receiveErr := receiveExternalV2BulkBlockPacketsWithProbe(ctx, sink, externalV2BlockReceiveConfig{
			PayloadSize: int64(len(payload)), ChunkSize: 1 << 20,
		}, externalV2BulkPacketPath{Conns: receivers, Addrs: externalV2BulkPacketTestAddrs(senders)}, auth, nil, false)
		receiveResult <- struct {
			stats externalDirectTransferStats
			err   error
		}{stats: stats, err: receiveErr}
	}()
	_, err = sendExternalV2BulkBlockPacketsWithProbe(ctx, &BlockSource{
		Payload: bytes.NewReader(payload), PayloadSize: int64(len(payload)), ChunkSize: 1 << 20,
	}, externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receivers)}, auth, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	received := <-receiveResult
	if received.err != nil {
		t.Fatal(received.err)
	}
	if !bytes.Equal(sink.buffer, payload) {
		t.Fatal("direct transfer output does not match")
	}
	if got := sink.committed.Load(); got != int64(len(payload)) {
		t.Fatalf("direct committed bytes = %d, want %d", got, len(payload))
	}
	if received.stats.Diagnostics.BulkWriterQueuePeak != 0 {
		t.Fatalf("direct transfer used async writer queue: %+v", received.stats.Diagnostics)
	}
}

type directMemoryBulkPacketSink struct {
	buffer    []byte
	committed atomic.Int64
}

func (s *directMemoryBulkPacketSink) DirectWriteBuffer() []byte { return s.buffer }

func (s *directMemoryBulkPacketSink) CommitDirectWrite(n int, _ int64) error {
	s.committed.Add(int64(n))
	return nil
}

func (s *directMemoryBulkPacketSink) WriteAt(payload []byte, offset int64) (int, error) {
	return copy(s.buffer[offset:], payload), nil
}

func (*directMemoryBulkPacketSink) Close() error { return nil }

func TestExternalV2BulkPacketProbeRejectsBeforePayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	senders, receiverConns := listenExternalV2BulkPacketTestConns(t, 4)
	receivers := make([]net.PacketConn, len(receiverConns))
	for index, conn := range receiverConns {
		receivers[index] = &dropProbeDataPacketConn{PacketConn: conn}
	}
	payload := bytes.Repeat([]byte{0x4c}, 4<<20)
	sink := newMemoryBlockSink(int64(len(payload)))
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	receiveResult := make(chan struct {
		stats externalDirectTransferStats
		err   error
	}, 1)
	go func() {
		_, stats, err := receiveExternalV2BulkBlockPackets(ctx, sink, externalV2BlockReceiveConfig{
			PayloadSize: int64(len(payload)), ChunkSize: 1 << 20,
		}, externalV2BulkPacketPath{Conns: receivers, Addrs: externalV2BulkPacketTestAddrs(senders)}, auth, nil)
		receiveResult <- struct {
			stats externalDirectTransferStats
			err   error
		}{stats: stats, err: err}
	}()
	sendStats, sendErr := sendExternalV2BulkBlockPackets(ctx, &BlockSource{
		Payload: bytes.NewReader(payload), PayloadSize: int64(len(payload)), ChunkSize: 1 << 20,
	}, externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receiverConns)}, auth, nil)
	received := <-receiveResult
	if !errors.Is(sendErr, errExternalV2BulkPacketProbeRejected) || !errors.Is(received.err, errExternalV2BulkPacketProbeRejected) {
		t.Fatalf("probe errors: send=%v receive=%v", sendErr, received.err)
	}
	if sendStats.BytesSent != 0 || received.stats.BytesReceived != 0 {
		t.Fatalf("payload counters changed before fallback: send=%d receive=%d", sendStats.BytesSent, received.stats.BytesReceived)
	}
	if got := sink.bytes(); !bytes.Equal(got, make([]byte, len(got))) {
		t.Fatal("destination changed before rejected probe fallback")
	}
}

type scriptedReceiveExternalV2BulkPacketBatchConn struct {
	mu          sync.Mutex
	packets     [][]byte
	delivered   chan struct{}
	once        sync.Once
	capture     sync.Once
	firstBuffer *byte
}

func (*scriptedReceiveExternalV2BulkPacketBatchConn) WriteBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, errors.New("unexpected write")
}

func (c *scriptedReceiveExternalV2BulkPacketBatchConn) ReadBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	c.mu.Lock()
	if len(c.packets) > 0 {
		count := min(len(messages), len(c.packets))
		c.capture.Do(func() { c.firstBuffer = &messages[0].Buffers[0][0] })
		for index := range count {
			copy(messages[index].Buffers[0], c.packets[index])
			messages[index].N = len(c.packets[index])
		}
		c.packets = c.packets[count:]
		c.mu.Unlock()
		c.once.Do(func() { close(c.delivered) })
		return count, nil
	}
	c.mu.Unlock()
	<-ctx.Done()
	return 0, ctx.Err()
}

func (*scriptedReceiveExternalV2BulkPacketBatchConn) Stats() externalV2BulkPacketBatchStats {
	return externalV2BulkPacketBatchStats{Backend: "scripted-receive"}
}

type dropProbeDataPacketConn struct {
	net.PacketConn
}

func (c *dropProbeDataPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(buffer)
		if err != nil {
			return n, addr, err
		}
		header, ok := parseExternalV2BulkPacketHeader(buffer[:n])
		if ok && (header.kind == externalV2BulkPacketProbeData || header.kind == externalV2BulkPacketProbeTaggedData) && header.index%5 == 0 {
			continue
		}
		return n, addr, nil
	}
}
