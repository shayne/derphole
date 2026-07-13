// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"syscall"
	"testing"

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
		if capture.maxBatch > 45 {
			t.Fatalf("lane %d maximum batch = %d, want <= 45 for IPv4 GSO and pacer eligibility", lane, capture.maxBatch)
		}
	}
	if got := sender.sentPackets.Load(); got != uint64(totalPackets) {
		t.Fatalf("sent packets = %d, want %d", got, totalPackets)
	}
	if got := sender.primaryPayloadBytes.Load(); got != int64(len(payload)) {
		t.Fatalf("primary payload = %d, want %d", got, len(payload))
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

func TestExternalV2BulkPacketBatchedSenderRetriesENOBUFSFromFirstUnsent(t *testing.T) {
	sender := &externalV2BulkPacketSender{ctx: context.Background()}
	batch := &enobufsExternalV2BulkPacketBatchConn{remaining: 3}
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

type captureExternalV2BulkPacketBatchConn struct {
	mu       sync.Mutex
	packets  [][]byte
	maxBatch int
}

func (c *captureExternalV2BulkPacketBatchConn) WriteBatch(_ context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxBatch = max(c.maxBatch, len(messages))
	for _, message := range messages {
		packet := append([]byte(nil), message.Buffers[0]...)
		c.packets = append(c.packets, packet)
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
	remaining int
	attempts  int
}

func (c *enobufsExternalV2BulkPacketBatchConn) WriteBatch(_ context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	c.attempts++
	if c.remaining > 0 {
		c.remaining--
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
