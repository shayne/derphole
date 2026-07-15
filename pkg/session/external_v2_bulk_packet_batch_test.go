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
			Backend: "linux-sendmmsg", CandidateID: "combined-gso3", GSOAttempted: true,
			NativeSendAttempts: 4, NativeSendSyscalls: 3, LogicalDatagrams: 100, NativeAcceptedPayloadBytes: 140_000,
			SendCalls: 3, SendDatagrams: 100, MaxSendBatch: 40,
		}},
		staticExternalV2BulkPacketBatchConn{stats: externalV2BulkPacketBatchStats{
			Backend: "linux-gso", CandidateID: "combined-gso3", GSOAttempted: true, GSOActive: true, GSOSegments: 64,
			NativeSendAttempts: 2, NativeSendSyscalls: 2, NativeGSOMessages: 22, LogicalDatagrams: 64,
			NativeAcceptedPayloadBytes: 89_600, GSOSegmentsPerMessage: 3, SendCalls: 2, SendDatagrams: 64,
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
	if diagnostics.BulkCandidateID != "combined-gso3" || diagnostics.BulkNativeSendAttempts != 6 || diagnostics.BulkNativeSendSyscalls != 5 || diagnostics.BulkNativeGSOMessages != 22 || diagnostics.BulkLogicalDatagrams != 164 || diagnostics.BulkNativeAcceptedPayloadBytes != 229_600 || diagnostics.BulkGSOSegmentsPerMessage != 3 {
		t.Fatalf("native counters = %+v", diagnostics)
	}
	if diagnostics.BulkMaxSendBatch != 64 || diagnostics.BulkMaxReceiveBatch != 32 || diagnostics.BulkCryptoQueuePeak != 4 || diagnostics.BulkWriterQueuePeak != 3 || diagnostics.BulkLaneQueuePeak != 2 {
		t.Fatalf("peaks = %+v", diagnostics)
	}
}

func TestExternalV2BulkPacketFixedPeersRequireSpareControlSocket(t *testing.T) {
	path, batches := fixedPeerFixture(4)
	if err := enableExternalV2BulkPacketFixedPeers(path, batches, 4); err != nil {
		t.Fatal(err)
	}
	for lane, batch := range batches {
		if batch.(*recordingFixedPeerBatch).peer != nil {
			t.Fatalf("lane %d enabled a fixed peer without a spare control socket", lane)
		}
	}
}

func TestExternalV2BulkPacketFixedPeersUseFourDataSocketsAndPreserveFifthControlSocket(t *testing.T) {
	path, batches := fixedPeerFixture(5)
	if err := enableExternalV2BulkPacketFixedPeers(path, batches, 4); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 4 {
		t.Fatalf("batch sockets = %d, want 4 data sockets", len(batches))
	}
	for lane, batch := range batches {
		if got := batch.(*recordingFixedPeerBatch).peer; got != path.Addrs[lane] {
			t.Fatalf("lane %d peer = %v, want %v", lane, got, path.Addrs[lane])
		}
	}
}

func TestExternalV2BulkPacketFixedPeersValidateBoundsBeforeActivation(t *testing.T) {
	for _, test := range []struct {
		name       string
		laneCount  int
		connCount  int
		addrCount  int
		batchCount int
		wantErr    bool
		wantPeers  bool
	}{
		{name: "negative lane count", laneCount: -1, connCount: 5, addrCount: 5, batchCount: 4, wantErr: true},
		{name: "lane count exceeds maximum", laneCount: 5, connCount: 6, addrCount: 6, batchCount: 6, wantErr: true},
		{name: "short batch conns", laneCount: 4, connCount: 5, addrCount: 5, batchCount: 3, wantErr: true},
		{name: "short path conns", laneCount: 4, connCount: 3, addrCount: 5, batchCount: 4, wantErr: true},
		{name: "short path addrs", laneCount: 4, connCount: 5, addrCount: 3, batchCount: 4, wantErr: true},
		{name: "five conns four addrs has no paired spare", laneCount: 4, connCount: 5, addrCount: 4, batchCount: 4},
		{name: "four conns five addrs has no paired spare", laneCount: 4, connCount: 4, addrCount: 5, batchCount: 4},
		{name: "zero lanes", laneCount: 0},
		{name: "paired fifth socket activates", laneCount: 4, connCount: 5, addrCount: 5, batchCount: 4, wantPeers: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path, batches := fixedPeerFixtureSizes(test.connCount, test.addrCount, test.batchCount)
			var err error
			var panicValue any
			func() {
				defer func() { panicValue = recover() }()
				err = enableExternalV2BulkPacketFixedPeers(path, batches, test.laneCount)
			}()
			if panicValue != nil {
				t.Fatalf("enable fixed peers panicked: %v", panicValue)
			}
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, want error %t", err, test.wantErr)
			}
			for lane, batch := range batches {
				peerSet := batch.(*recordingFixedPeerBatch).peer != nil
				if peerSet != test.wantPeers {
					t.Fatalf("lane %d peer set = %t, want %t", lane, peerSet, test.wantPeers)
				}
			}
		})
	}
}

func fixedPeerFixture(socketCount int) (externalV2BulkPacketPath, []externalV2BulkPacketBatchConn) {
	return fixedPeerFixtureSizes(socketCount, socketCount, min(socketCount, externalV2BulkPacketMaximumDataLanes))
}

func fixedPeerFixtureSizes(connCount, addrCount, batchCount int) (externalV2BulkPacketPath, []externalV2BulkPacketBatchConn) {
	path := externalV2BulkPacketPath{
		Conns: make([]net.PacketConn, connCount),
		Addrs: make([]net.Addr, addrCount),
	}
	for lane := range addrCount {
		path.Addrs[lane] = &net.UDPAddr{IP: net.IPv4(192, 0, 2, byte(lane+1)), Port: 8000 + lane}
	}
	batches := make([]externalV2BulkPacketBatchConn, batchCount)
	for lane := range batches {
		batches[lane] = &recordingFixedPeerBatch{}
	}
	return path, batches
}

type scriptedExternalV2BulkPacketBatchConn struct {
	writeResults []int
	writeStarts  []byte
}

type staticExternalV2BulkPacketBatchConn struct {
	stats externalV2BulkPacketBatchStats
}

type recordingFixedPeerBatch struct {
	peer net.Addr
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

func (*recordingFixedPeerBatch) WriteBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, errors.New("unexpected write")
}

func (*recordingFixedPeerBatch) ReadBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, errors.New("unexpected read")
}

func (*recordingFixedPeerBatch) Stats() externalV2BulkPacketBatchStats {
	return externalV2BulkPacketBatchStats{Backend: "recording-fixed-peer"}
}

func (b *recordingFixedPeerBatch) enableFixedPeerConnect(peer net.Addr) error {
	b.peer = peer
	return nil
}

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
