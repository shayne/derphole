// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"fmt"
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
	Backend                    string
	CandidateID                string
	NativeSendAttempts         uint64
	NativeSendSyscalls         uint64
	NativeGSOMessages          uint64
	LogicalDatagrams           uint64
	NativeAcceptedPayloadBytes uint64
	GSOSegmentsPerMessage      uint32
	GSOAttempted               bool
	GSOActive                  bool
	GSOSegments                uint64
	SendCalls                  uint64
	SendDatagrams              uint64
	ReceiveCalls               uint64
	ReceiveDatagrams           uint64
	MaxSendBatch               uint32
	MaxReceiveBatch            uint32
	CryptoQueuePeak            uint32
	WriterQueuePeak            uint32
}

type externalV2BulkPacketBatchConn interface {
	WriteBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error)
	ReadBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error)
	Stats() externalV2BulkPacketBatchStats
}

type externalV2BulkPacketFixedPeerConnector interface {
	enableFixedPeerConnect(net.Addr) error
}

type externalV2BulkPacketWriteCancellationDisarmer interface {
	disarmWriteCancellation()
}

func disarmExternalV2BulkPacketWriteCancellations(conns []externalV2BulkPacketBatchConn) {
	for _, conn := range conns {
		disarmer, ok := conn.(externalV2BulkPacketWriteCancellationDisarmer)
		if ok {
			disarmer.disarmWriteCancellation()
		}
	}
}

func enableExternalV2BulkPacketFixedPeerConnect(conn externalV2BulkPacketBatchConn, peer net.Addr) error {
	connector, ok := conn.(externalV2BulkPacketFixedPeerConnector)
	if !ok {
		return nil
	}
	return connector.enableFixedPeerConnect(peer)
}

func enableExternalV2BulkPacketFixedPeers(path externalV2BulkPacketPath, conns []externalV2BulkPacketBatchConn, laneCount int) error {
	if laneCount < 0 || laneCount > externalV2BulkPacketMaximumDataLanes {
		return fmt.Errorf("invalid bulk packet fixed peer lane count %d", laneCount)
	}
	if laneCount > len(conns) {
		return fmt.Errorf("bulk packet fixed peer lane count %d exceeds %d batch conns", laneCount, len(conns))
	}
	if laneCount > len(path.Conns) {
		return fmt.Errorf("bulk packet fixed peer lane count %d exceeds %d path conns", laneCount, len(path.Conns))
	}
	if laneCount > len(path.Addrs) {
		return fmt.Errorf("bulk packet fixed peer lane count %d exceeds %d path addrs", laneCount, len(path.Addrs))
	}
	if len(path.Conns) <= laneCount || len(path.Addrs) <= laneCount {
		return nil
	}
	for lane := 0; lane < laneCount; lane++ {
		if err := enableExternalV2BulkPacketFixedPeerConnect(conns[lane], path.Addrs[lane]); err != nil {
			return err
		}
	}
	return nil
}

func enableExternalV2BulkPacketReceiveCoalescing(conn externalV2BulkPacketBatchConn) {
	if coalescer, ok := conn.(interface{ enableReceiveCoalescing() }); ok {
		coalescer.enableReceiveCoalescing()
	}
}

type externalV2BulkPacketAtomicBatchStats struct {
	backend                    atomic.Pointer[string]
	candidateID                atomic.Pointer[string]
	nativeSendAttempts         atomic.Uint64
	nativeSendSyscalls         atomic.Uint64
	nativeGSOMessages          atomic.Uint64
	logicalDatagrams           atomic.Uint64
	nativeAcceptedPayloadBytes atomic.Uint64
	gsoSegmentsPerMessage      atomic.Uint32
	gsoAttempted               atomic.Bool
	gsoActive                  atomic.Bool
	gsoSegments                atomic.Uint64
	sendCalls                  atomic.Uint64
	sendDatagrams              atomic.Uint64
	receiveCalls               atomic.Uint64
	receiveDatagrams           atomic.Uint64
	maxSendBatch               atomic.Uint32
	maxReceiveBatch            atomic.Uint32
	cryptoQueuePeak            atomic.Uint32
	writerQueuePeak            atomic.Uint32
}

var externalV2BulkPacketBackendNames = struct {
	linuxSendMMsg  string
	linuxGSO       string
	linuxRecvMMsg  string
	darwinSendMsgX string
	darwinRecvMsgX string
	portableSingle string
}{
	linuxSendMMsg:  "linux-sendmmsg",
	linuxGSO:       "linux-gso",
	linuxRecvMMsg:  "linux-recvmmsg",
	darwinSendMsgX: "darwin-sendmsg-x",
	darwinRecvMsgX: "darwin-recvmsg-x",
	portableSingle: "portable-single",
}

func newExternalV2BulkPacketAtomicBatchStats(backend string) *externalV2BulkPacketAtomicBatchStats {
	stats := &externalV2BulkPacketAtomicBatchStats{}
	stats.setBackend(backend)
	return stats
}

func (s *externalV2BulkPacketAtomicBatchStats) setBackend(backend string) {
	if current := s.backend.Load(); current != nil && *current == backend {
		return
	}
	value := externalV2BulkPacketStableBackend(backend)
	s.backend.Store(value)
}

func externalV2BulkPacketStableBackend(backend string) *string {
	switch backend {
	case "linux-sendmmsg":
		return &externalV2BulkPacketBackendNames.linuxSendMMsg
	case "linux-gso":
		return &externalV2BulkPacketBackendNames.linuxGSO
	case "linux-recvmmsg":
		return &externalV2BulkPacketBackendNames.linuxRecvMMsg
	case "darwin-sendmsg-x":
		return &externalV2BulkPacketBackendNames.darwinSendMsgX
	case "darwin-recvmsg-x":
		return &externalV2BulkPacketBackendNames.darwinRecvMsgX
	case "portable-single":
		return &externalV2BulkPacketBackendNames.portableSingle
	default:
		value := backend
		return &value
	}
}

func (s *externalV2BulkPacketAtomicBatchStats) setCandidateID(candidateID string) {
	value := candidateID
	s.candidateID.Store(&value)
}

func (s *externalV2BulkPacketAtomicBatchStats) snapshot() externalV2BulkPacketBatchStats {
	backend := ""
	if value := s.backend.Load(); value != nil {
		backend = *value
	}
	candidateID := ""
	if value := s.candidateID.Load(); value != nil {
		candidateID = *value
	}
	return externalV2BulkPacketBatchStats{
		Backend:                    backend,
		CandidateID:                candidateID,
		NativeSendAttempts:         s.nativeSendAttempts.Load(),
		NativeSendSyscalls:         s.nativeSendSyscalls.Load(),
		NativeGSOMessages:          s.nativeGSOMessages.Load(),
		LogicalDatagrams:           s.logicalDatagrams.Load(),
		NativeAcceptedPayloadBytes: s.nativeAcceptedPayloadBytes.Load(),
		GSOSegmentsPerMessage:      s.gsoSegmentsPerMessage.Load(),
		GSOAttempted:               s.gsoAttempted.Load(),
		GSOActive:                  s.gsoActive.Load(),
		GSOSegments:                s.gsoSegments.Load(),
		SendCalls:                  s.sendCalls.Load(),
		SendDatagrams:              s.sendDatagrams.Load(),
		ReceiveCalls:               s.receiveCalls.Load(),
		ReceiveDatagrams:           s.receiveDatagrams.Load(),
		MaxSendBatch:               s.maxSendBatch.Load(),
		MaxReceiveBatch:            s.maxReceiveBatch.Load(),
		CryptoQueuePeak:            s.cryptoQueuePeak.Load(),
		WriterQueuePeak:            s.writerQueuePeak.Load(),
	}
}

func (s *externalV2BulkPacketAtomicBatchStats) observeNativeAttempt() {
	s.nativeSendAttempts.Add(1)
}

func (s *externalV2BulkPacketAtomicBatchStats) observeNativeSyscall() {
	s.nativeSendSyscalls.Add(1)
}

func (s *externalV2BulkPacketAtomicBatchStats) observeNativeAccepted(
	messages []externalV2BulkPacketBatchMessage,
	logicalDatagrams int,
	gsoMessages int,
	gsoSegmentsPerMessage int,
) {
	logicalDatagrams = min(max(logicalDatagrams, 0), len(messages))
	if logicalDatagrams == 0 {
		return
	}
	payloadBytes := uint64(0)
	for index := range logicalDatagrams {
		if messages[index].PayloadBytes > 0 {
			payloadBytes += uint64(messages[index].PayloadBytes)
		}
	}
	s.logicalDatagrams.Add(uint64(logicalDatagrams))
	s.nativeAcceptedPayloadBytes.Add(payloadBytes)
	if gsoMessages > 0 {
		s.nativeGSOMessages.Add(uint64(gsoMessages))
		externalV2BulkPacketAtomicMaxUint32(&s.gsoSegmentsPerMessage, uint32(gsoSegmentsPerMessage))
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
	candidateSeen := false
	candidateMismatch := false
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		stats := conn.Stats()
		if !candidateSeen {
			diagnostics.BulkCandidateID = stats.CandidateID
			candidateSeen = true
		} else if diagnostics.BulkCandidateID != stats.CandidateID {
			candidateMismatch = true
		}
		if diagnostics.BulkBatchBackend == "" || stats.GSOActive {
			diagnostics.BulkBatchBackend = stats.Backend
		}
		diagnostics.BulkGSOAttempted = diagnostics.BulkGSOAttempted || stats.GSOAttempted
		diagnostics.BulkGSOActive = diagnostics.BulkGSOActive || stats.GSOActive
		diagnostics.BulkGSOSegments += stats.GSOSegments
		diagnostics.BulkNativeSendAttempts += stats.NativeSendAttempts
		diagnostics.BulkNativeSendSyscalls += stats.NativeSendSyscalls
		diagnostics.BulkNativeGSOMessages += stats.NativeGSOMessages
		diagnostics.BulkLogicalDatagrams += stats.LogicalDatagrams
		diagnostics.BulkNativeAcceptedPayloadBytes += stats.NativeAcceptedPayloadBytes
		diagnostics.BulkGSOSegmentsPerMessage = max(diagnostics.BulkGSOSegmentsPerMessage, stats.GSOSegmentsPerMessage)
		diagnostics.BulkSendCalls += stats.SendCalls
		diagnostics.BulkSendDatagrams += stats.SendDatagrams
		diagnostics.BulkReceiveCalls += stats.ReceiveCalls
		diagnostics.BulkReceiveDatagrams += stats.ReceiveDatagrams
		diagnostics.BulkMaxSendBatch = max(diagnostics.BulkMaxSendBatch, stats.MaxSendBatch)
		diagnostics.BulkMaxReceiveBatch = max(diagnostics.BulkMaxReceiveBatch, stats.MaxReceiveBatch)
		diagnostics.BulkCryptoQueuePeak = max(diagnostics.BulkCryptoQueuePeak, stats.CryptoQueuePeak)
		diagnostics.BulkWriterQueuePeak = max(diagnostics.BulkWriterQueuePeak, stats.WriterQueuePeak)
	}
	if candidateMismatch {
		diagnostics.BulkCandidateID = ""
	}
	return diagnostics
}

func mergeExternalV2BulkPacketBatchDiagnostics(target *externalDirectTransferDiagnostics, batch externalDirectTransferDiagnostics) {
	if target == nil || !batch.BulkBatchPresent {
		return
	}
	target.BulkBatchPresent = true
	target.BulkBatchBackend = batch.BulkBatchBackend
	target.BulkCandidateID = batch.BulkCandidateID
	target.BulkNativeSendAttempts = batch.BulkNativeSendAttempts
	target.BulkNativeSendSyscalls = batch.BulkNativeSendSyscalls
	target.BulkNativeGSOMessages = batch.BulkNativeGSOMessages
	target.BulkLogicalDatagrams = batch.BulkLogicalDatagrams
	target.BulkNativeAcceptedPayloadBytes = batch.BulkNativeAcceptedPayloadBytes
	target.BulkGSOSegmentsPerMessage = batch.BulkGSOSegmentsPerMessage
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
