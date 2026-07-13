// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"
)

const externalV2BulkPacketMaxBatch = 192

var errExternalV2BulkPacketBatchNoProgress = errors.New("bulk packet batch write made no progress")

func externalV2BulkPacketFlattenMessage(buffers [][]byte) ([]byte, error) {
	if len(buffers) == 0 {
		return nil, errors.New("bulk packet batch message has no buffers")
	}
	if len(buffers) == 1 {
		return buffers[0], nil
	}
	total := 0
	for _, buffer := range buffers {
		total += len(buffer)
	}
	payload := make([]byte, 0, total)
	for _, buffer := range buffers {
		payload = append(payload, buffer...)
	}
	return payload, nil
}

type externalV2BulkPacketBatchMessage struct {
	Buffers      [][]byte
	Addr         net.Addr
	OOB          []byte
	PayloadBytes int
	N            int
	NN           int
	Flags        int
}

type externalV2BulkPacketBatchStats struct {
	Backend          string
	GSOAttempted     bool
	GSOActive        bool
	GSOSegments      uint64
	SendCalls        uint64
	SendDatagrams    uint64
	ReceiveCalls     uint64
	ReceiveDatagrams uint64
	MaxSendBatch     uint32
	MaxReceiveBatch  uint32
	CryptoQueuePeak  uint32
	WriterQueuePeak  uint32
}

type externalV2BulkPacketBatchConn interface {
	WriteBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error)
	ReadBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error)
	Stats() externalV2BulkPacketBatchStats
}

func enableExternalV2BulkPacketFixedPeerConnect(conn externalV2BulkPacketBatchConn) {
	if connector, ok := conn.(interface{ enableFixedPeerConnect() }); ok {
		connector.enableFixedPeerConnect()
	}
}

func enableExternalV2BulkPacketReceiveCoalescing(conn externalV2BulkPacketBatchConn) {
	if coalescer, ok := conn.(interface{ enableReceiveCoalescing() }); ok {
		coalescer.enableReceiveCoalescing()
	}
}

type externalV2BulkPacketAtomicBatchStats struct {
	backend          atomic.Pointer[string]
	gsoAttempted     atomic.Bool
	gsoActive        atomic.Bool
	gsoSegments      atomic.Uint64
	sendCalls        atomic.Uint64
	sendDatagrams    atomic.Uint64
	receiveCalls     atomic.Uint64
	receiveDatagrams atomic.Uint64
	maxSendBatch     atomic.Uint32
	maxReceiveBatch  atomic.Uint32
	cryptoQueuePeak  atomic.Uint32
	writerQueuePeak  atomic.Uint32
}

func newExternalV2BulkPacketAtomicBatchStats(backend string) *externalV2BulkPacketAtomicBatchStats {
	stats := &externalV2BulkPacketAtomicBatchStats{}
	stats.setBackend(backend)
	return stats
}

func (s *externalV2BulkPacketAtomicBatchStats) setBackend(backend string) {
	value := backend
	s.backend.Store(&value)
}

func (s *externalV2BulkPacketAtomicBatchStats) snapshot() externalV2BulkPacketBatchStats {
	backend := ""
	if value := s.backend.Load(); value != nil {
		backend = *value
	}
	return externalV2BulkPacketBatchStats{
		Backend:          backend,
		GSOAttempted:     s.gsoAttempted.Load(),
		GSOActive:        s.gsoActive.Load(),
		GSOSegments:      s.gsoSegments.Load(),
		SendCalls:        s.sendCalls.Load(),
		SendDatagrams:    s.sendDatagrams.Load(),
		ReceiveCalls:     s.receiveCalls.Load(),
		ReceiveDatagrams: s.receiveDatagrams.Load(),
		MaxSendBatch:     s.maxSendBatch.Load(),
		MaxReceiveBatch:  s.maxReceiveBatch.Load(),
		CryptoQueuePeak:  s.cryptoQueuePeak.Load(),
		WriterQueuePeak:  s.writerQueuePeak.Load(),
	}
}

func (s *externalV2BulkPacketAtomicBatchStats) observeSend(batch int) {
	if batch <= 0 {
		return
	}
	s.sendCalls.Add(1)
	s.sendDatagrams.Add(uint64(batch))
	externalV2BulkPacketAtomicMaxUint32(&s.maxSendBatch, uint32(batch))
}

func (s *externalV2BulkPacketAtomicBatchStats) observeReceive(batch int) {
	if batch <= 0 {
		return
	}
	s.receiveCalls.Add(1)
	s.receiveDatagrams.Add(uint64(batch))
	externalV2BulkPacketAtomicMaxUint32(&s.maxReceiveBatch, uint32(batch))
}

func externalV2BulkPacketAtomicMaxUint32(counter *atomic.Uint32, candidate uint32) {
	for {
		current := counter.Load()
		if candidate <= current || counter.CompareAndSwap(current, candidate) {
			return
		}
	}
}

func externalV2BulkPacketMessageLength(buffers [][]byte) int {
	total := 0
	for _, buffer := range buffers {
		total += len(buffer)
	}
	return total
}

func externalV2BulkPacketBatchDeadline(ctx context.Context, now time.Time) time.Time {
	deadline := now.Add(externalV2BulkPacketReadIdle)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func externalV2BulkPacketArmWriteDeadline(ctx context.Context, conn net.PacketConn) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	return conn.SetWriteDeadline(deadline)
}

func externalV2BulkPacketRetryReadError(ctx context.Context, err error) (bool, error) {
	networkError, ok := err.(net.Error)
	if !ok || !networkError.Timeout() {
		return false, err
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	return true, nil
}

func writeExternalV2BulkPacketBatchAll(ctx context.Context, conn externalV2BulkPacketBatchConn, messages []externalV2BulkPacketBatchMessage) error {
	for len(messages) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		written, err := conn.WriteBatch(ctx, messages)
		if written < 0 || written > len(messages) {
			return errors.New("bulk packet batch returned invalid write count")
		}
		messages = messages[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return errExternalV2BulkPacketBatchNoProgress
		}
	}
	return nil
}

func externalV2BulkPacketBatchDiagnostics(conns []externalV2BulkPacketBatchConn, cryptoQueuePeak, writerQueuePeak, laneQueuePeak uint32) externalDirectTransferDiagnostics {
	diagnostics := externalDirectTransferDiagnostics{
		BulkBatchPresent:    len(conns) > 0,
		BulkCryptoQueuePeak: cryptoQueuePeak,
		BulkWriterQueuePeak: writerQueuePeak,
		BulkLaneQueuePeak:   laneQueuePeak,
	}
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		stats := conn.Stats()
		if diagnostics.BulkBatchBackend == "" || stats.GSOActive {
			diagnostics.BulkBatchBackend = stats.Backend
		}
		diagnostics.BulkGSOAttempted = diagnostics.BulkGSOAttempted || stats.GSOAttempted
		diagnostics.BulkGSOActive = diagnostics.BulkGSOActive || stats.GSOActive
		diagnostics.BulkGSOSegments += stats.GSOSegments
		diagnostics.BulkSendCalls += stats.SendCalls
		diagnostics.BulkSendDatagrams += stats.SendDatagrams
		diagnostics.BulkReceiveCalls += stats.ReceiveCalls
		diagnostics.BulkReceiveDatagrams += stats.ReceiveDatagrams
		diagnostics.BulkMaxSendBatch = max(diagnostics.BulkMaxSendBatch, stats.MaxSendBatch)
		diagnostics.BulkMaxReceiveBatch = max(diagnostics.BulkMaxReceiveBatch, stats.MaxReceiveBatch)
		diagnostics.BulkCryptoQueuePeak = max(diagnostics.BulkCryptoQueuePeak, stats.CryptoQueuePeak)
		diagnostics.BulkWriterQueuePeak = max(diagnostics.BulkWriterQueuePeak, stats.WriterQueuePeak)
	}
	return diagnostics
}

func mergeExternalV2BulkPacketBatchDiagnostics(target *externalDirectTransferDiagnostics, batch externalDirectTransferDiagnostics) {
	if target == nil || !batch.BulkBatchPresent {
		return
	}
	target.BulkBatchPresent = true
	target.BulkBatchBackend = batch.BulkBatchBackend
	target.BulkGSOAttempted = batch.BulkGSOAttempted
	target.BulkGSOActive = batch.BulkGSOActive
	target.BulkGSOSegments = batch.BulkGSOSegments
	target.BulkSendCalls = batch.BulkSendCalls
	target.BulkSendDatagrams = batch.BulkSendDatagrams
	target.BulkReceiveCalls = batch.BulkReceiveCalls
	target.BulkReceiveDatagrams = batch.BulkReceiveDatagrams
	target.BulkMaxSendBatch = batch.BulkMaxSendBatch
	target.BulkMaxReceiveBatch = batch.BulkMaxReceiveBatch
	target.BulkCryptoQueuePeak = batch.BulkCryptoQueuePeak
	target.BulkLaneQueuePeak = batch.BulkLaneQueuePeak
	target.BulkWriterQueuePeak = batch.BulkWriterQueuePeak
}
