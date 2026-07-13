// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/types/key"
)

func TestExternalV2BulkPacketBatchBackendConfiguredByDefault(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_BULK_BATCHED_IO", "")
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 2)
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	sender := newExternalV2BulkPacketSender(context.Background(), &BlockSource{
		Payload: bytes.NewReader([]byte("batch by default")), PayloadSize: int64(len("batch by default")),
	}, externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receivers)}, auth, nil)
	if len(sender.batchConns) != 2 {
		t.Fatalf("batch backends = %d, want 2 without an environment gate", len(sender.batchConns))
	}
}

func TestExternalV2BulkPacketBatchWriteAllResumesAtFirstUnsentMessage(t *testing.T) {
	batch := &scriptedExternalV2BulkPacketBatchConn{writeResults: []int{2, 1, 2}}
	messages := make([]externalV2BulkPacketBatchMessage, 5)
	for index := range messages {
		messages[index].Buffers = [][]byte{{byte(index)}}
	}

	if err := writeExternalV2BulkPacketBatchAll(context.Background(), batch, messages); err != nil {
		t.Fatal(err)
	}
	wantStarts := []byte{0, 2, 3}
	if len(batch.writeStarts) != len(wantStarts) {
		t.Fatalf("write starts = %v, want %v", batch.writeStarts, wantStarts)
	}
	for index := range wantStarts {
		if batch.writeStarts[index] != wantStarts[index] {
			t.Fatalf("write starts = %v, want %v", batch.writeStarts, wantStarts)
		}
	}
}

func TestExternalV2BulkPacketBatchWriteAllRejectsNoProgress(t *testing.T) {
	batch := &scriptedExternalV2BulkPacketBatchConn{writeResults: []int{0}}
	err := writeExternalV2BulkPacketBatchAll(context.Background(), batch, []externalV2BulkPacketBatchMessage{{Buffers: [][]byte{{1}}}})
	if !errors.Is(err, errExternalV2BulkPacketBatchNoProgress) {
		t.Fatalf("error = %v, want no progress", err)
	}
}

func TestExternalV2BulkPacketBatchWriteDoesNotLeaveArtificialDeadline(t *testing.T) {
	receiverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiverConn.Close()
	senderConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderConn.Close()
	recording := &writeDeadlineRecordingPacketConn{UDPConn: senderConn.(*net.UDPConn)}
	batch := newExternalV2BulkPacketBatchConn(recording)

	written, err := batch.WriteBatch(context.Background(), []externalV2BulkPacketBatchMessage{{
		Buffers: [][]byte{[]byte("payload")}, Addr: receiverConn.LocalAddr(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if written != 1 {
		t.Fatalf("written = %d, want 1", written)
	}
	if got := recording.nonzero.Load(); got != 0 {
		t.Fatalf("non-zero write deadlines = %d, want none without a context deadline", got)
	}
}

func TestExternalV2BulkPacketPortableBatchRoundTrip(t *testing.T) {
	receiverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiverConn.Close()
	senderConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderConn.Close()

	sender := newExternalV2BulkPacketBatchConn(senderConn)
	receiver := newExternalV2BulkPacketBatchConn(receiverConn)
	payloads := [][]byte{[]byte("first"), []byte("second")}
	messages := make([]externalV2BulkPacketBatchMessage, len(payloads))
	for index, payload := range payloads {
		messages[index] = externalV2BulkPacketBatchMessage{Buffers: [][]byte{payload}, Addr: receiverConn.LocalAddr()}
	}
	if err := writeExternalV2BulkPacketBatchAll(context.Background(), sender, messages); err != nil {
		t.Fatal(err)
	}

	readMessages := []externalV2BulkPacketBatchMessage{{Buffers: [][]byte{make([]byte, externalV2BulkPacketMaxSize)}}}
	for _, want := range payloads {
		count, err := receiver.ReadBatch(context.Background(), readMessages)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 || readMessages[0].N != len(want) || string(readMessages[0].Buffers[0][:readMessages[0].N]) != string(want) {
			t.Fatalf("read = count %d n %d payload %q, want %q", count, readMessages[0].N, readMessages[0].Buffers[0][:readMessages[0].N], want)
		}
	}

	sendStats := sender.Stats()
	receiveStats := receiver.Stats()
	wantSendBackend := "portable-single"
	wantReceiveBackend := "portable-single"
	if runtime.GOOS == "linux" {
		wantSendBackend = "linux-sendmmsg"
		wantReceiveBackend = "linux-recvmmsg"
	} else if runtime.GOOS == "darwin" {
		wantSendBackend = "darwin-sendmsg-x"
		wantReceiveBackend = "darwin-recvmsg-x"
	}
	if sendStats.Backend != wantSendBackend || sendStats.SendCalls < 1 || sendStats.SendDatagrams != 2 || sendStats.MaxSendBatch < 1 {
		t.Fatalf("send stats = %+v", sendStats)
	}
	if receiveStats.Backend != wantReceiveBackend || receiveStats.ReceiveCalls != 2 || receiveStats.ReceiveDatagrams != 2 || receiveStats.MaxReceiveBatch != 1 {
		t.Fatalf("receive stats = %+v", receiveStats)
	}
}

func TestExternalV2BulkPacketPortableBatchReadHonorsCancellation(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	batch := newExternalV2BulkPacketBatchConn(conn)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	_, err = batch.ReadBatch(ctx, []externalV2BulkPacketBatchMessage{{Buffers: [][]byte{make([]byte, externalV2BulkPacketMaxSize)}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("canceled read took %s", elapsed)
	}
}

func TestExternalV2BulkPacketPortableBatchReadRetriesIdleTimeouts(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	wrapped := &writeDeadlineRecordingPacketConn{UDPConn: conn.(*net.UDPConn)}
	batch := newExternalV2BulkPacketBatchConn(wrapped)
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = batch.ReadBatch(ctx, []externalV2BulkPacketBatchMessage{{Buffers: [][]byte{make([]byte, externalV2BulkPacketMaxSize)}}})
	if !errors.Is(err, context.DeadlineExceeded) {
		networkError, ok := err.(net.Error)
		t.Fatalf("error = %T %v net_error=%t timeout=%t, want context deadline after retrying idle socket timeouts", err, err, ok, ok && networkError.Timeout())
	}
	if elapsed := time.Since(started); elapsed < 300*time.Millisecond {
		t.Fatalf("read returned after %s, want retries until context deadline", elapsed)
	}
}

func TestExternalV2BulkPacketBatchDiagnosticsAggregateLanes(t *testing.T) {
	conns := []externalV2BulkPacketBatchConn{
		staticExternalV2BulkPacketBatchConn{stats: externalV2BulkPacketBatchStats{
			Backend: "linux-sendmmsg", GSOAttempted: true, SendCalls: 3, SendDatagrams: 100, MaxSendBatch: 40,
		}},
		staticExternalV2BulkPacketBatchConn{stats: externalV2BulkPacketBatchStats{
			Backend: "linux-gso", GSOAttempted: true, GSOActive: true, GSOSegments: 64, SendCalls: 2, SendDatagrams: 64,
			ReceiveCalls: 4, ReceiveDatagrams: 128, MaxSendBatch: 64, MaxReceiveBatch: 32,
		}},
	}
	diagnostics := externalV2BulkPacketBatchDiagnostics(conns, 4, 3, 2)
	if !diagnostics.BulkBatchPresent || diagnostics.BulkBatchBackend != "linux-gso" || !diagnostics.BulkGSOAttempted || !diagnostics.BulkGSOActive {
		t.Fatalf("identity = %+v", diagnostics)
	}
	if diagnostics.BulkGSOSegments != 64 || diagnostics.BulkSendCalls != 5 || diagnostics.BulkSendDatagrams != 164 || diagnostics.BulkReceiveCalls != 4 || diagnostics.BulkReceiveDatagrams != 128 {
		t.Fatalf("counters = %+v", diagnostics)
	}
	if diagnostics.BulkMaxSendBatch != 64 || diagnostics.BulkMaxReceiveBatch != 32 || diagnostics.BulkCryptoQueuePeak != 4 || diagnostics.BulkWriterQueuePeak != 3 || diagnostics.BulkLaneQueuePeak != 2 {
		t.Fatalf("peaks = %+v", diagnostics)
	}
}

type scriptedExternalV2BulkPacketBatchConn struct {
	writeResults []int
	writeStarts  []byte
}

type staticExternalV2BulkPacketBatchConn struct {
	stats externalV2BulkPacketBatchStats
}

type writeDeadlineRecordingPacketConn struct {
	*net.UDPConn
	nonzero atomic.Int64
}

func (c *writeDeadlineRecordingPacketConn) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		c.nonzero.Add(1)
	}
	return c.UDPConn.SetWriteDeadline(deadline)
}

func (staticExternalV2BulkPacketBatchConn) WriteBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, errors.New("unexpected write")
}
func (staticExternalV2BulkPacketBatchConn) ReadBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, errors.New("unexpected read")
}
func (c staticExternalV2BulkPacketBatchConn) Stats() externalV2BulkPacketBatchStats { return c.stats }

func (c *scriptedExternalV2BulkPacketBatchConn) WriteBatch(_ context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	if len(messages) == 0 {
		return 0, nil
	}
	c.writeStarts = append(c.writeStarts, messages[0].Buffers[0][0])
	result := c.writeResults[0]
	c.writeResults = c.writeResults[1:]
	return result, nil
}

func (*scriptedExternalV2BulkPacketBatchConn) ReadBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, errors.New("unexpected ReadBatch")
}

func (*scriptedExternalV2BulkPacketBatchConn) Stats() externalV2BulkPacketBatchStats {
	return externalV2BulkPacketBatchStats{Backend: "scripted"}
}
