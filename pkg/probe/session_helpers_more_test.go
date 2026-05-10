// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestBlastReplayWindowAndLaneLimitHelpers(t *testing.T) {
	if got := laneReplayWindowBytes(100, 4); got != 25 {
		t.Fatalf("laneReplayWindowBytes(100, 4) = %d, want 25", got)
	}
	if got := laneReplayWindowBytes(3, 4); got != 3 {
		t.Fatalf("laneReplayWindowBytes(3, 4) = %d, want original budget", got)
	}

	lane := &blastParallelSendLane{
		batcher:    &capsBatcher{caps: TransportCaps{BatchSize: 7}},
		batchLimit: 3,
	}
	if got := normalizedBlastParallelLaneBatchLimit(lane); got != 3 {
		t.Fatalf("normalizedBlastParallelLaneBatchLimit(explicit) = %d, want 3", got)
	}
	lane.batchLimit = 0
	if got := normalizedBlastParallelLaneBatchLimit(lane); got != 7 {
		t.Fatalf("normalizedBlastParallelLaneBatchLimit(batcher) = %d, want 7", got)
	}
	lane.batcher = &capsBatcher{}
	if got := normalizedBlastParallelLaneBatchLimit(lane); got != 1 {
		t.Fatalf("normalizedBlastParallelLaneBatchLimit(default) = %d, want 1", got)
	}

	history := &blastRepairHistory{
		streamReplay: newStreamReplayWindow(testRunID(0x91), 4, uint64(headerLen+4), nil),
	}
	if blastParallelSendItemReplayFull(nil) {
		t.Fatal("blastParallelSendItemReplayFull(nil) = true, want false")
	}
	if blastReplayWindowFull(history) {
		t.Fatal("blastReplayWindowFull(empty) = true, want false")
	}
	if _, err := history.streamReplay.AddDataPacket(0, 0, 0, []byte("data")); err != nil {
		t.Fatalf("AddDataPacket() error = %v", err)
	}
	if !blastReplayWindowFull(history) {
		t.Fatal("blastReplayWindowFull(full) = false, want true")
	}
	if !blastParallelSendItemReplayFull(history) {
		t.Fatal("blastParallelSendItemReplayFull(full) = false, want true")
	}
}

func TestFlushAndDrainBlastReplayWindow(t *testing.T) {
	var flushed int
	nonAdaptive := newBlastSendControl(0, 0, time.Now())
	if err := flushAndDrainBlastReplayWindow(func() error {
		flushed++
		return nil
	}, nonAdaptive, func() (bool, error) {
		t.Fatal("non-adaptive control should not drain")
		return false, nil
	}, testRunID(0x92)); err != nil {
		t.Fatalf("flushAndDrainBlastReplayWindow(non-adaptive) error = %v", err)
	}
	if flushed != 1 {
		t.Fatalf("flush count = %d, want 1", flushed)
	}

	flushErr := errors.New("flush failed")
	if err := flushAndDrainBlastReplayWindow(func() error {
		return flushErr
	}, nonAdaptive, nil, testRunID(0x93)); !errors.Is(err, flushErr) {
		t.Fatalf("flushAndDrainBlastReplayWindow(flush error) = %v, want %v", err, flushErr)
	}

	var drained int
	adaptive := newBlastSendControl(100, 200, time.Now())
	if err := flushAndDrainBlastReplayWindow(func() error {
		return nil
	}, adaptive, func() (bool, error) {
		drained++
		return true, nil
	}, testRunID(0x94)); err != nil {
		t.Fatalf("flushAndDrainBlastReplayWindow(adaptive) error = %v", err)
	}
	if drained != 1 {
		t.Fatalf("drain count = %d, want 1", drained)
	}

	drainErr := errors.New("drain failed")
	if err := drainBlastReplayControl(adaptive, func() (bool, error) {
		return false, drainErr
	}, testRunID(0x95)); !errors.Is(err, drainErr) {
		t.Fatalf("drainBlastReplayControl(error) = %v, want %v", err, drainErr)
	}
}

func TestBlastReceiveReadErrorClassification(t *testing.T) {
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if handled, err := handleBlastReceiveReadError(canceledCtx, io.ErrUnexpectedEOF); !handled || !errors.Is(err, context.Canceled) {
		t.Fatalf("handleBlastReceiveReadError(canceled) = (%t, %v), want handled context.Canceled", handled, err)
	}
	if handled, err := handleBlastReceiveReadError(context.Background(), testTimeoutError{}); handled || err != nil {
		t.Fatalf("handleBlastReceiveReadError(timeout) = (%t, %v), want ignored", handled, err)
	}
	if handled, err := handleBlastReceiveReadError(context.Background(), net.ErrClosed); !handled || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("handleBlastReceiveReadError(net closed) = (%t, %v), want handled net.ErrClosed", handled, err)
	}
	if handled, err := handleBlastReceiveReadError(context.Background(), io.ErrUnexpectedEOF); handled || err != nil {
		t.Fatalf("handleBlastReceiveReadError(other) = (%t, %v), want ignored", handled, err)
	}
}

func TestResultErrorPreference(t *testing.T) {
	specific := errors.New("disk failed")
	if got := preferInformativeResultError(nil, specific); !errors.Is(got, specific) {
		t.Fatalf("preferInformativeResultError(nil, specific) = %v", got)
	}
	if got := preferInformativeResultError(specific, nil); !errors.Is(got, specific) {
		t.Fatalf("preferInformativeResultError(specific, nil) = %v", got)
	}
	if got := preferInformativeResultError(context.Canceled, specific); !errors.Is(got, specific) {
		t.Fatalf("preferInformativeResultError(context.Canceled, specific) = %v, want specific", got)
	}
	if got := preferInformativeResultError(specific, net.ErrClosed); !errors.Is(got, specific) {
		t.Fatalf("preferInformativeResultError(specific, net.ErrClosed) = %v, want specific", got)
	}
	for _, err := range []error{context.Canceled, io.ErrClosedPipe, net.ErrClosed} {
		if !fallbackResultError(err) {
			t.Fatalf("fallbackResultError(%v) = false, want true", err)
		}
	}
	if fallbackResultError(specific) {
		t.Fatal("fallbackResultError(specific) = true, want false")
	}
}

func TestBlastRepairHistoryPacketBufferValidation(t *testing.T) {
	var nilHistory *blastRepairHistory
	if err := nilHistory.validatePacketBufferRequest(1); err == nil {
		t.Fatal("nil validatePacketBufferRequest() error = nil, want error")
	}
	history := &blastRepairHistory{chunkSize: 8}
	if err := history.validatePacketBufferRequest(1); err == nil {
		t.Fatal("non-retaining validatePacketBufferRequest() error = nil, want error")
	}
	history.retainPayloads = true
	if err := history.validatePacketBufferRequest(0); err == nil {
		t.Fatal("zero-length validatePacketBufferRequest() error = nil, want error")
	}
	if err := history.validatePacketBufferRequest(9); err == nil {
		t.Fatal("oversized validatePacketBufferRequest() error = nil, want error")
	}
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error = %v", err)
	}
	history.packetAEAD = aead
	if err := history.validatePacketBufferRequest(8); err == nil {
		t.Fatal("AEAD validatePacketBufferRequest() error = nil, want error")
	}
	history.packetAEAD = nil
	if err := history.validatePacketBufferRequest(8); err != nil {
		t.Fatalf("valid validatePacketBufferRequest() error = %v", err)
	}
}

func TestBlastStreamReceiveStatsAndMissingSeqHelpers(t *testing.T) {
	coordinator := &blastStreamReceiveCoordinator{bytesReceived: 123}
	if got := coordinator.rateFeedbackPayloadBytesLocked(nil); got != 0 {
		t.Fatalf("rateFeedbackPayloadBytesLocked(nil) = %d, want 0", got)
	}
	state := &blastReceiveRunState{}
	if got := coordinator.rateFeedbackPayloadBytesLocked(state); got != 123 {
		t.Fatalf("rateFeedbackPayloadBytesLocked(fallback) = %d, want 123", got)
	}
	state.feedbackBytes = 77
	if got := coordinator.rateFeedbackPayloadBytesLocked(state); got != 77 {
		t.Fatalf("rateFeedbackPayloadBytesLocked(feedback) = %d, want 77", got)
	}
	if got := coordinator.committedPayloadBytesLocked(state); got != 123 {
		t.Fatalf("committedPayloadBytesLocked() = %d, want 123", got)
	}
	if got := (*blastStreamReceiveCoordinator)(nil).committedPayloadBytesLocked(state); got != 0 {
		t.Fatalf("nil committedPayloadBytesLocked() = %d, want 0", got)
	}

	stripe := &blastStreamReceiveStripeState{expectedSeq: 5, nextRepairSeq: 7}
	if got := stripe.missingSeqStartInRange(10); got != 5 {
		t.Fatalf("missingSeqStartInRange(unseen expected) = %d, want 5", got)
	}
	stripe.seen.Add(5)
	if got := stripe.missingSeqStartInRange(10); got != 7 {
		t.Fatalf("missingSeqStartInRange(next repair) = %d, want 7", got)
	}
	stripe.nextRepairSeq = 4
	if got := stripe.missingSeqStartInRange(10); got != 5 {
		t.Fatalf("missingSeqStartInRange(before expected) = %d, want 5", got)
	}
	stripe.nextRepairSeq = 10
	if got := stripe.missingSeqStartInRange(10); got != 5 {
		t.Fatalf("missingSeqStartInRange(at end) = %d, want 5", got)
	}
	if !stripe.seen.Has(5) || stripe.seen.Has(6) || stripe.seen.Len() != 1 {
		t.Fatalf("blastSeqSet state Has(5)=%t Has(6)=%t Len=%d", stripe.seen.Has(5), stripe.seen.Has(6), stripe.seen.Len())
	}
}

func TestBlastStreamReceiveDoneResult(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	cancelParent()
	connected := &atomic.Bool{}
	receiveComplete := &atomic.Bool{}
	if _, err := blastStreamReceiveDoneResult(parent, context.Background(), nil, &blastStreamReceiveCoordinator{}, connected, receiveComplete, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("blastStreamReceiveDoneResult(parent canceled) = %v, want context.Canceled", err)
	}

	receiveComplete.Store(true)
	connected.Store(true)
	coordinator := &blastStreamReceiveCoordinator{
		bytesReceived: 42,
		startedAt:     time.Now().Add(-time.Second),
	}
	stats, err := blastStreamReceiveDoneResult(context.Background(), context.Background(), nil, coordinator, connected, receiveComplete, nil)
	if err != nil {
		t.Fatalf("blastStreamReceiveDoneResult(complete) error = %v", err)
	}
	if stats.BytesReceived != 42 || !stats.Transport.Connected {
		t.Fatalf("stats = %+v, want received bytes and connected transport", stats)
	}

	errCh := make(chan error, 1)
	wantErr := errors.New("receive loop failed")
	errCh <- wantErr
	receiveComplete.Store(false)
	if _, err := blastStreamReceiveDoneResult(context.Background(), context.Background(), nil, coordinator, connected, receiveComplete, errCh); !errors.Is(err, wantErr) {
		t.Fatalf("blastStreamReceiveDoneResult(errCh) = %v, want %v", err, wantErr)
	}

	receiveCtx, cancelReceive := context.WithCancel(context.Background())
	cancelReceive()
	if _, err := blastStreamReceiveDoneResult(context.Background(), receiveCtx, nil, coordinator, connected, receiveComplete, make(chan error)); !errors.Is(err, context.Canceled) {
		t.Fatalf("blastStreamReceiveDoneResult(receive canceled) = %v, want context.Canceled", err)
	}
}

func TestWaitForBlastReplayWindowFlushesDrainsAndCancelsWhenStillFull(t *testing.T) {
	runID := testRunID(0x96)
	history := &blastRepairHistory{
		streamReplay: newStreamReplayWindow(runID, 4, uint64(headerLen+4), nil),
	}
	if _, err := history.streamReplay.AddDataPacket(0, 0, 0, []byte("data")); err != nil {
		t.Fatalf("AddDataPacket() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var flushed, drained int
	err := waitForBlastReplayWindow(ctx, history, func() error {
		flushed++
		return nil
	}, newBlastSendControl(100, 200, time.Now()), func() (bool, error) {
		drained++
		return false, nil
	}, runID, &TransferStats{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForBlastReplayWindow() error = %v, want context.Canceled", err)
	}
	if flushed != 1 || drained != 1 {
		t.Fatalf("flush/drain counts = %d/%d, want 1/1", flushed, drained)
	}

	history.streamReplay.AckFloor(1)
	if err := waitForBlastReplayWindow(context.Background(), history, func() error {
		flushed++
		return nil
	}, newBlastSendControl(0, 0, time.Now()), nil, runID, &TransferStats{}); err != nil {
		t.Fatalf("waitForBlastReplayWindow(non-full) error = %v", err)
	}
}

func TestNoBlastParallelSendLanesErrorPrefersHandshakeError(t *testing.T) {
	wantErr := errors.New("handshake failed")
	if err := noBlastParallelSendLanesError(wantErr); !errors.Is(err, wantErr) {
		t.Fatalf("noBlastParallelSendLanesError(specific) = %v, want %v", err, wantErr)
	}
	if err := noBlastParallelSendLanesError(nil); err == nil || err.Error() != "no parallel blast lanes completed handshake" {
		t.Fatalf("noBlastParallelSendLanesError(nil) = %v", err)
	}
}

type scriptedBlastBatcher struct {
	packets [][]byte
	addrs   []net.Addr
	writes  [][]byte
	index   int
}

func (b *scriptedBlastBatcher) Capabilities() TransportCaps {
	return TransportCaps{Kind: "test", BatchSize: 2}
}
func (b *scriptedBlastBatcher) MaxBatch() int { return 2 }

func (b *scriptedBlastBatcher) WriteBatch(_ context.Context, _ net.Addr, packets [][]byte) (int, error) {
	for _, packet := range packets {
		b.writes = append(b.writes, append([]byte(nil), packet...))
	}
	return len(packets), nil
}

func (b *scriptedBlastBatcher) ReadBatch(ctx context.Context, _ time.Duration, bufs []batchReadBuffer) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if b.index >= len(b.packets) {
		return 0, testTimeoutError{}
	}
	bufs[0].N = copy(bufs[0].Bytes, b.packets[b.index])
	if len(b.addrs) > b.index {
		bufs[0].Addr = b.addrs[b.index]
	}
	b.index++
	return 1, nil
}

func TestReceiveBlastDataBatchedProcessesDataAndDone(t *testing.T) {
	runID := testRunID(0x97)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
	data, err := marshalBlastPayloadPacket(PacketTypeData, runID, 0, 0, 0, 0, 0, []byte("batched-payload"), nil)
	if err != nil {
		t.Fatalf("marshal data packet error = %v", err)
	}
	done, err := marshalBlastPayloadPacket(PacketTypeDone, runID, 0, 1, uint64(len("batched-payload")), 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("marshal done packet error = %v", err)
	}
	batcher := &scriptedBlastBatcher{
		packets: [][]byte{data, done},
		addrs:   []net.Addr{peer, peer},
	}
	var dst bytes.Buffer
	stats, err := receiveBlastDataBatched(context.Background(), nil, batcher, peer, runID, &dst, &TransferStats{}, make([]byte, 1500), nil)
	if err != nil {
		t.Fatalf("receiveBlastDataBatched() error = %v", err)
	}
	if dst.String() != "batched-payload" {
		t.Fatalf("received payload = %q, want batched-payload", dst.String())
	}
	if stats.BytesReceived != int64(len("batched-payload")) || stats.CompletedAt.IsZero() {
		t.Fatalf("stats = %+v, want received bytes and completion time", stats)
	}
	if len(batcher.writes) != 1 {
		t.Fatalf("repair-complete writes = %d, want 1", len(batcher.writes))
	}
}

func TestReceiveBlastDataBatchIgnoresMismatchedPacketsAndSurfacesClosed(t *testing.T) {
	runID := testRunID(0x98)
	otherRun := testRunID(0x99)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9998}
	otherPeer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 9998}
	mismatched, err := marshalBlastPayloadPacket(PacketTypeData, otherRun, 0, 0, 0, 0, 0, []byte("ignored"), nil)
	if err != nil {
		t.Fatalf("marshal mismatched packet error = %v", err)
	}
	readBufs := []batchReadBuffer{{Bytes: append([]byte(nil), mismatched...), N: len(mismatched), Addr: otherPeer}}
	complete, err := processBlastReceiveBatch(context.Background(), nil, &scriptedBlastBatcher{}, peer, runID, io.Discard, &TransferStats{}, readBufs, nil)
	if err != nil || complete {
		t.Fatalf("processBlastReceiveBatch(mismatch) = (%t, %v), want ignored", complete, err)
	}

	closedBatcher := &scriptedBlastBatcher{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = receiveBlastDataBatch(ctx, nil, closedBatcher, peer, runID, io.Discard, &TransferStats{}, []batchReadBuffer{{Bytes: make([]byte, 1500)}}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("receiveBlastDataBatch(canceled) error = %v, want context.Canceled", err)
	}
}
