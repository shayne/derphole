// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"tailscale.com/types/key"
)

func TestExternalV2BulkPacketBatchedReceiverDecryptsBatch(t *testing.T) {
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
	dataCh := make(chan externalV2BulkPacketReceiveResult, packetCount)
	errCh := make(chan error, 1)
	done := startExternalV2BulkPacketBatchedDataReaders(ctx, []externalV2BulkPacketBatchConn{batch}, auth, dataCh, errCh)

	seen := make([]bool, packetCount)
	for range packetCount {
		select {
		case result := <-dataCh:
			if result.header.index >= packetCount {
				t.Fatalf("index = %d", result.header.index)
			}
			want := bytes.Repeat([]byte{byte(result.header.index)}, 32+int(result.header.index))
			if !bytes.Equal(result.data, want) {
				t.Fatalf("packet %d payload mismatch", result.header.index)
			}
			seen[result.header.index] = true
			result.release()
		case err := <-errCh:
			t.Fatalf("reader error: %v", err)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for decrypted batch")
		}
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

func TestExternalV2BulkPacketBatchedReceiverIgnoresInvalidPackets(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	batch := &scriptedReceiveExternalV2BulkPacketBatchConn{packets: [][]byte{{1, 2, 3}}, delivered: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	dataCh := make(chan externalV2BulkPacketReceiveResult, 1)
	errCh := make(chan error, 1)
	done := startExternalV2BulkPacketBatchedDataReaders(ctx, []externalV2BulkPacketBatchConn{batch}, auth, dataCh, errCh)
	<-batch.delivered
	select {
	case result := <-dataCh:
		result.release()
		t.Fatal("invalid packet produced a receive result")
	case err := <-errCh:
		t.Fatalf("invalid packet produced a fatal error: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	<-done
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
}

type scriptedReceiveExternalV2BulkPacketBatchConn struct {
	mu        sync.Mutex
	packets   [][]byte
	delivered chan struct{}
	once      sync.Once
}

func (*scriptedReceiveExternalV2BulkPacketBatchConn) WriteBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, errors.New("unexpected write")
}

func (c *scriptedReceiveExternalV2BulkPacketBatchConn) ReadBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	c.mu.Lock()
	if len(c.packets) > 0 {
		count := min(len(messages), len(c.packets))
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
