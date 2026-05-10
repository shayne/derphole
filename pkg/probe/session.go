// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultChunkSize                    = 1400
	defaultWindowSize                   = 4096
	defaultRetryInterval                = 20 * time.Millisecond
	minRetryInterval                    = 50 * time.Millisecond
	maxRetryInterval                    = 250 * time.Millisecond
	terminalAckLinger                   = 3 * defaultRetryInterval
	terminalDoneGrace                   = 500 * time.Millisecond
	terminalDoneAttempts                = 4
	delayedAckInterval                  = 1 * time.Millisecond
	delayedAckPackets                   = 16
	blastReceiveWriteBuffer             = 4 << 20
	zeroReadRetryDelay                  = 1 * time.Millisecond
	blastDoneLinger                     = 5 * defaultRetryInterval
	blastDoneInterval                   = defaultRetryInterval
	parallelBlastDoneGrace              = 10 * blastDoneLinger
	parallelBlastRepairGrace            = 4 * time.Second
	parallelBlastRepairGraceMax         = 60 * time.Second
	parallelBlastRepairGraceBytes       = 4 << 20
	blastRepairQuietGrace               = 500 * time.Millisecond
	blastRepairQuietGraceMax            = 8 * time.Second
	blastRepairQuietGraceMinMbps        = 1
	blastRepairResendInterval           = 2 * blastRepairInterval
	blastKnownGapRepairDelay            = 50 * time.Millisecond
	stripedBlastKnownGapRepairDelay     = 50 * time.Millisecond
	parallelActiveLaneOneMaxMbps        = 350
	parallelActiveLaneTwoMaxMbps        = 700
	parallelActiveLaneFourMaxMbps       = 1200
	parallelBlastDataIdle               = 500 * time.Millisecond
	blastReadPoll                       = 250 * time.Millisecond
	blastRepairInterval                 = defaultRetryInterval
	blastRepairMemorySlab               = 4 << 20
	parallelBlastStripeBlockPackets     = 128
	stripedBlastPendingOutputLimitBytes = 256 << 20
	stripedBlastFutureBufferLimitBytes  = 256 << 20
	maxRepairRequestSeqs                = 128
	maxRepairRequestBatches             = 4
	maxAckMaskBits                      = 64
	extendedAckBits                     = 4096
	extendedAckBytes                    = extendedAckBits / 8
	maxBufferedPackets                  = 4096
	defaultSocketBuffer                 = 8 << 20
)

func parallelBlastRepairGraceForExpectedBytes(expectedBytes int64) time.Duration {
	if expectedBytes <= 0 {
		return parallelBlastRepairGrace
	}
	grace := parallelBlastRepairGrace + time.Duration(expectedBytes/parallelBlastRepairGraceBytes)*time.Second
	if grace > parallelBlastRepairGraceMax {
		return parallelBlastRepairGraceMax
	}
	return grace
}

func blastRepairSafeExpectedBytes(totalBytes uint64) int64 {
	if totalBytes > uint64(maxInt()) {
		return int64(maxInt())
	}
	return int64(totalBytes)
}

func blastRepairQuietGraceForExpectedBytes(expectedBytes int64, hadRepair bool) time.Duration {
	if !hadRepair || expectedBytes <= 0 {
		return blastRepairQuietGrace
	}
	grace := parallelBlastRepairGraceForExpectedBytes(expectedBytes)
	if grace < blastRepairQuietGrace {
		return blastRepairQuietGrace
	}
	return grace
}

func blastRepairQuietGraceForRepairBytes(repairBytes int64) time.Duration {
	if repairBytes <= 0 {
		return blastRepairQuietGrace
	}
	grace := blastRepairQuietGrace + time.Duration((float64(repairBytes*8)/float64(blastRepairQuietGraceMinMbps*1000*1000))*float64(time.Second))
	if grace > blastRepairQuietGraceMax {
		return blastRepairQuietGraceMax
	}
	return grace
}

type SendConfig struct {
	Raw                        bool
	Blast                      bool
	Transport                  string
	ChunkSize                  int
	WindowSize                 int
	Parallel                   int
	RateMbps                   int
	RunID                      [16]byte
	RepairPayloads             bool
	TailReplayBytes            int
	FECGroupSize               int
	StripedBlast               bool
	PacketAEAD                 cipher.AEAD
	AllowPartialParallel       bool
	ParallelHandshakeTimeout   time.Duration
	RateCeilingMbps            int
	RateExplorationCeilingMbps int
	StreamReplayWindowBytes    uint64
	MaxActiveLanes             int
	MinActiveLanes             int
}

type ReceiveConfig struct {
	Raw                  bool
	Blast                bool
	Transport            string
	ExpectedRunID        [16]byte
	ExpectedRunIDs       [][16]byte
	RequireComplete      bool
	DeferKnownGapRepairs bool
	FECGroupSize         int
	SpoolOutput          bool
	PacketAEAD           cipher.AEAD
}

type TransferStats struct {
	BytesSent                    int64
	BytesReceived                int64
	PacketsSent                  int64
	PacketsAcked                 int64
	Retransmits                  int64
	Lanes                        int
	StartedAt                    time.Time
	CompletedAt                  time.Time
	FirstByteAt                  time.Time
	PeakGoodputMbps              float64
	Transport                    TransportCaps
	MaxReplayBytes               uint64
	ReplayWindowFullWaits        int64
	ReplayWindowFullWaitDuration time.Duration
	peakGoodput                  intervalStats
}

func (s *TransferStats) observePeakGoodput(now time.Time, totalBytes int64) {
	if s == nil {
		return
	}
	s.peakGoodput.Observe(now, totalBytes)
	s.PeakGoodputMbps = s.peakGoodput.PeakMbps()
}

func (s *TransferStats) markComplete(now time.Time) {
	if s == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	if s.PeakGoodputMbps <= 0 {
		if !s.peakGoodput.seen && !s.StartedAt.IsZero() {
			s.peakGoodput.seen = true
			s.peakGoodput.lastAt = s.StartedAt
			s.peakGoodput.lastBytes = 0
		}
		s.peakGoodput.ObserveCompletion(now, max(s.BytesSent, s.BytesReceived))
		s.PeakGoodputMbps = s.peakGoodput.PeakMbps()
	}
	s.CompletedAt = now
}

func recordReplayWindowFullWait(stats *TransferStats, retainedBytes uint64, waited time.Duration) {
	if stats == nil {
		return
	}
	stats.ReplayWindowFullWaits++
	stats.ReplayWindowFullWaitDuration += waited
	stats.MaxReplayBytes = max(stats.MaxReplayBytes, retainedBytes)
}

func Send(ctx context.Context, conn net.PacketConn, remoteAddr string, src io.Reader, cfg SendConfig) (TransferStats, error) {
	if conn == nil {
		return TransferStats{}, errors.New("nil packet conn")
	}
	if src == nil {
		return TransferStats{}, errors.New("nil source reader")
	}
	cfg = normalizeSendConfig(cfg)
	peer, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return TransferStats{}, err
	}
	stats := newSendTransferStats()
	batcher := newPacketBatcher(conn, cfg.Transport)
	stats.Transport = batcher.Capabilities()
	runID, err := sendRunID(cfg)
	if err != nil {
		return TransferStats{}, err
	}
	if cfg.Raw && cfg.Parallel > 1 {
		return sendStriped(ctx, conn, peer, src, runID, cfg)
	}
	state := newSenderState(src, cfg, runID)
	retryInterval, err := performHelloHandshake(ctx, conn, peer, runID, 0, 1, &stats)
	if err != nil {
		return TransferStats{}, err
	}
	if cfg.Blast {
		batcher = maybeConnectedBlastSendBatcher(conn, peer, batcher, cfg)
		return sendBlast(ctx, batcher, conn, peer, runID, src, cfg.ChunkSize, cfg.RateMbps, cfg.RateCeilingMbps, cfg.RepairPayloads, cfg.TailReplayBytes, cfg.FECGroupSize, cfg.PacketAEAD, cfg.StreamReplayWindowBytes, stats)
	}
	readBufs := newSizedBlastBatchReadBuffers(batcher.MaxBatch(), 64<<10)
	return runReliableSendLoop(ctx, batcher, peer, &state, &stats, readBufs, retryInterval)
}

func normalizeSendConfig(cfg SendConfig) SendConfig {
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = defaultChunkSize
	}
	cfg.WindowSize = effectiveWindowSize(cfg.WindowSize)
	if cfg.Parallel <= 0 {
		cfg.Parallel = 1
	}
	return cfg
}

func newSendTransferStats() TransferStats {
	stats := TransferStats{StartedAt: time.Now()}
	stats.observePeakGoodput(stats.StartedAt, 0)
	return stats
}

func sendRunID(cfg SendConfig) ([16]byte, error) {
	if !isZeroRunID(cfg.RunID) {
		return cfg.RunID, nil
	}
	return newRunID()
}

func newSenderState(src io.Reader, cfg SendConfig, runID [16]byte) senderState {
	return senderState{
		src:       src,
		chunkSize: cfg.ChunkSize,
		window:    cfg.WindowSize,
		stripeID:  0,
		nextSeq:   0,
		offset:    0,
		runID:     runID,
		rateMbps:  cfg.RateMbps,
		inFlight:  make(map[uint64]*outboundPacket, cfg.WindowSize),
	}
}

func maybeConnectedBlastSendBatcher(conn net.PacketConn, peer net.Addr, batcher packetBatcher, cfg SendConfig) packetBatcher {
	if !shouldUseConnectedBatcherForParallelSend(batcher, 1, cfg) {
		return batcher
	}
	if connectedBatcher, ok := newConnectedUDPBatcher(conn, peer, cfg.Transport); ok {
		return connectedBatcher
	}
	return batcher
}

func runReliableSendLoop(ctx context.Context, batcher packetBatcher, peer net.Addr, state *senderState, stats *TransferStats, readBufs []batchReadBuffer, retryInterval time.Duration) (TransferStats, error) {
	for {
		if err := fillSendWindow(ctx, batcher, peer, state, stats); err != nil {
			return TransferStats{}, err
		}
		done, skipRead, err := handleReliableSendState(ctx, batcher, peer, state, stats, readBufs, retryInterval)
		if err != nil || done {
			if err != nil {
				return TransferStats{}, err
			}
			return *stats, nil
		}
		if skipRead {
			continue
		}
		if err := readReliableSendAcks(ctx, batcher, peer, state, stats, readBufs, retryInterval); err != nil {
			return TransferStats{}, err
		}
	}
}

func handleReliableSendState(ctx context.Context, batcher packetBatcher, peer net.Addr, state *senderState, stats *TransferStats, readBufs []batchReadBuffer, retryInterval time.Duration) (bool, bool, error) {
	if len(state.inFlight) == 0 && !state.doneQueued {
		return false, true, waitReliableSendIdle(ctx, batcher, peer, state, stats, readBufs, retryInterval)
	}
	if state.doneQueued && (len(state.inFlight) == 0 || donePacketSettled(state.inFlight)) {
		stats.markComplete(time.Now())
		return true, false, nil
	}
	return false, false, nil
}

func waitReliableSendIdle(ctx context.Context, batcher packetBatcher, peer net.Addr, state *senderState, stats *TransferStats, readBufs []batchReadBuffer, retryInterval time.Duration) error {
	if !sendWindowHasCapacity(state) {
		return waitForAckProgress(ctx, batcher, state, stats, readBufs, retryInterval, peer)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return waitZeroReadRetry(ctx, state.zeroReads)
}

func readReliableSendAcks(ctx context.Context, batcher packetBatcher, peer net.Addr, state *senderState, stats *TransferStats, readBufs []batchReadBuffer, retryInterval time.Duration) error {
	n, err := batcher.ReadBatch(ctx, nextRetransmitDeadline(ctx, state.inFlight, retryInterval), readBufs)
	if err != nil {
		return handleReliableSendAckReadError(ctx, batcher, peer, state, stats, retryInterval, err)
	}
	applyAckBatch(readBufs[:n], peer, state, stats)
	return nil
}

func handleReliableSendAckReadError(ctx context.Context, batcher packetBatcher, peer net.Addr, state *senderState, stats *TransferStats, retryInterval time.Duration, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if isNetTimeout(err) {
		return retransmitExpired(ctx, batcher, peer, state.inFlight, retryInterval, stats)
	}
	return err
}

func waitForAckProgress(ctx context.Context, batcher packetBatcher, state *senderState, stats *TransferStats, readBufs []batchReadBuffer, retryInterval time.Duration, peer net.Addr) error {
	n, err := batcher.ReadBatch(ctx, retryInterval, readBufs)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if isNetTimeout(err) {
			return nil
		}
		return err
	}
	applyAckBatch(readBufs[:n], peer, state, stats)
	return nil
}

func applyAckBatch(readBufs []batchReadBuffer, peer net.Addr, state *senderState, stats *TransferStats) {
	for i := range readBufs {
		addr := readBufs[i].Addr
		if !sameAddr(addr, peer) {
			continue
		}

		packet, err := UnmarshalPacket(readBufs[i].Bytes[:readBufs[i].N], nil)
		if err != nil {
			continue
		}
		if packet.Type != PacketTypeAck {
			continue
		}
		if packet.RunID != state.runID {
			continue
		}
		if !ackIsPlausible(state.nextSeq, packet.AckFloor, packet.AckMask, packet.Payload) {
			continue
		}

		if packet.AckFloor > state.ackFloor {
			state.ackFloor = packet.AckFloor
		}
		stats.PacketsAcked += int64(applyAck(state.inFlight, packet.AckFloor, packet.AckMask, packet.Payload))
	}
}

func Receive(ctx context.Context, conn net.PacketConn, remoteAddr string, cfg ReceiveConfig) ([]byte, error) {
	var out bytes.Buffer
	_, err := ReceiveToWriter(ctx, conn, remoteAddr, &out, cfg)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func ReceiveToWriter(ctx context.Context, conn net.PacketConn, remoteAddr string, dst io.Writer, cfg ReceiveConfig) (TransferStats, error) {
	if conn == nil {
		return TransferStats{}, errors.New("nil packet conn")
	}
	if dst == nil {
		return TransferStats{}, errors.New("nil destination writer")
	}

	peer, err := resolveRemoteAddr(remoteAddr)
	if err != nil {
		return TransferStats{}, err
	}
	batcher := newPacketBatcher(conn, cfg.Transport)
	loop := newReceiveLoop(conn, batcher, peer, dst, cfg)
	return loop.run(ctx)
}

type receiveLoop struct {
	conn            net.PacketConn
	batcher         packetBatcher
	peer            net.Addr
	dst             io.Writer
	cfg             ReceiveConfig
	stats           TransferStats
	buf             []byte
	readBufs        []batchReadBuffer
	expectedSeq     uint64
	buffered        map[uint64]Packet
	runID           [16]byte
	runIDSet        bool
	lastAckAt       time.Time
	packetsSinceAck int
	ackDirty        bool
}

func newReceiveLoop(conn net.PacketConn, batcher packetBatcher, peer net.Addr, dst io.Writer, cfg ReceiveConfig) *receiveLoop {
	stats := TransferStats{StartedAt: time.Now()}
	stats.peakGoodput.minWindow = blastRateFeedbackInterval
	stats.observePeakGoodput(stats.StartedAt, 0)
	buf := make([]byte, 64<<10)
	stats.Transport = batcher.Capabilities()
	return &receiveLoop{
		conn:     conn,
		batcher:  batcher,
		peer:     peer,
		dst:      dst,
		cfg:      cfg,
		stats:    stats,
		buf:      buf,
		readBufs: newSizedBlastBatchReadBuffers(batcher.MaxBatch(), len(buf)),
		buffered: make(map[uint64]Packet),
	}
}

func (r *receiveLoop) run(ctx context.Context) (TransferStats, error) {
	for {
		n, err := r.batcher.ReadBatch(ctx, defaultRetryInterval, r.readBufs)
		if err != nil {
			if err := r.handleReadError(ctx, err); err != nil {
				return TransferStats{}, err
			}
			continue
		}
		stats, done, err := r.processBatch(ctx, r.readBufs[:n])
		if err != nil || done {
			return stats, err
		}
	}
}

func (r *receiveLoop) handleReadError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if isNetTimeout(err) {
		if r.runIDSet {
			return r.sendPendingAck(ctx, r.peer)
		}
		return nil
	}
	if errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (r *receiveLoop) processBatch(ctx context.Context, readBufs []batchReadBuffer) (TransferStats, bool, error) {
	for i := range readBufs {
		stats, done, err := r.processBuffer(ctx, readBufs[i])
		if err != nil || done {
			return stats, done, err
		}
	}
	return TransferStats{}, false, nil
}

func (r *receiveLoop) processBuffer(ctx context.Context, readBuf batchReadBuffer) (TransferStats, bool, error) {
	if r.peer != nil && !sameAddr(readBuf.Addr, r.peer) {
		return TransferStats{}, false, nil
	}
	packet, err := UnmarshalPacket(readBuf.Bytes[:readBuf.N], nil)
	if err != nil || isZeroRunID(packet.RunID) {
		return TransferStats{}, false, nil
	}
	if !r.runIDSet {
		return r.handleFirstPacket(ctx, readBuf.Addr, packet)
	}
	if packet.RunID != r.runID {
		return TransferStats{}, false, nil
	}
	return r.handleEstablishedPacket(ctx, readBuf.Addr, packet)
}

func (r *receiveLoop) handleFirstPacket(ctx context.Context, addr net.Addr, packet Packet) (TransferStats, bool, error) {
	if !r.acceptFirstHello(packet) {
		return TransferStats{}, false, nil
	}
	r.runID = packet.RunID
	r.runIDSet = true
	if r.peer == nil {
		r.peer = cloneAddr(addr)
	}
	if r.shouldReceiveStripedFromFirstHello(packet) {
		stats, err := receiveStripedFromFirstHello(ctx, r.conn, r.batcher, addr, r.runID, packet, r.dst, &r.stats, r.buf)
		return stats, true, err
	}
	if err := sendHelloAck(ctx, r.conn, addr, r.runID, 0, 1); err != nil {
		return TransferStats{}, true, err
	}
	if r.cfg.Blast {
		stats, err := receiveBlastData(ctx, r.conn, cloneAddr(addr), r.runID, r.dst, &r.stats, r.buf, r.cfg.PacketAEAD)
		return stats, true, err
	}
	return TransferStats{}, false, nil
}

func (r *receiveLoop) acceptFirstHello(packet Packet) bool {
	if packet.Type != PacketTypeHello {
		return false
	}
	return isZeroRunID(r.cfg.ExpectedRunID) || packet.RunID == r.cfg.ExpectedRunID
}

func (r *receiveLoop) shouldReceiveStripedFromFirstHello(packet Packet) bool {
	return r.cfg.Raw && !r.cfg.Blast && (packet.StripeID != 0 || packet.Seq > 1)
}

func (r *receiveLoop) handleEstablishedPacket(ctx context.Context, addr net.Addr, packet Packet) (TransferStats, bool, error) {
	if packet.Type == PacketTypeHello {
		return TransferStats{}, false, sendHelloAck(ctx, r.conn, addr, r.runID, 0, 1)
	}
	switch packet.Type {
	case PacketTypeData:
		return r.handleDataPacket(ctx, addr, packet)
	case PacketTypeDone:
		return r.handleDonePacket(ctx, addr, packet)
	default:
		return TransferStats{}, false, nil
	}
}

func (r *receiveLoop) handleDataPacket(ctx context.Context, addr net.Addr, packet Packet) (TransferStats, bool, error) {
	if r.cfg.Blast {
		if err := writeBlastReceivePayload(r.dst, &r.stats, packet.Payload); err != nil {
			return TransferStats{}, true, err
		}
		return TransferStats{}, false, nil
	}
	if err := r.acceptOrderedDataPacket(packet); err != nil {
		return TransferStats{}, true, err
	}
	complete, err := r.advanceAndMaybeAck(ctx, addr)
	if err != nil || !complete {
		return TransferStats{}, false, err
	}
	return r.completeOrderedReceive(ctx, addr)
}

func (r *receiveLoop) acceptOrderedDataPacket(packet Packet) error {
	if packet.Seq == r.expectedSeq {
		if err := writeBlastReceivePayload(r.dst, &r.stats, packet.Payload); err != nil {
			return err
		}
		r.expectedSeq++
		return nil
	}
	if packet.Seq > r.expectedSeq && packet.Seq <= r.expectedSeq+maxBufferedPackets {
		r.buffered[packet.Seq] = clonePacket(packet)
	}
	return nil
}

func (r *receiveLoop) advanceAndMaybeAck(ctx context.Context, addr net.Addr) (bool, error) {
	var complete bool
	var err error
	r.expectedSeq, complete, err = advanceReceiveWindow(r.dst, r.buffered, r.expectedSeq, &r.stats)
	if err != nil {
		return false, err
	}
	r.ackDirty = true
	r.packetsSinceAck++
	if r.packetsSinceAck >= delayedAckPackets || time.Since(r.lastAckAt) >= delayedAckInterval {
		return complete, r.sendPendingAck(ctx, addr)
	}
	return complete, nil
}

func (r *receiveLoop) handleDonePacket(ctx context.Context, addr net.Addr, packet Packet) (TransferStats, bool, error) {
	if r.cfg.Blast {
		r.stats.markComplete(time.Now())
		return r.stats, true, nil
	}
	complete, err := r.acceptDonePacket(packet)
	if err != nil {
		return TransferStats{}, true, err
	}
	r.ackDirty = true
	if err := r.sendPendingAck(ctx, addr); err != nil {
		return TransferStats{}, true, err
	}
	if !complete {
		return TransferStats{}, false, nil
	}
	return r.completeTerminalReceive(ctx, addr)
}

func (r *receiveLoop) acceptDonePacket(packet Packet) (bool, error) {
	complete := false
	if packet.Seq == r.expectedSeq {
		r.expectedSeq++
		complete = true
	} else if packet.Seq > r.expectedSeq && packet.Seq <= r.expectedSeq+maxBufferedPackets {
		r.buffered[packet.Seq] = packet
	}
	if complete {
		return true, nil
	}
	var err error
	r.expectedSeq, complete, err = advanceReceiveWindow(r.dst, r.buffered, r.expectedSeq, &r.stats)
	return complete, err
}

func (r *receiveLoop) completeOrderedReceive(ctx context.Context, addr net.Addr) (TransferStats, bool, error) {
	r.stats.markComplete(time.Now())
	if err := r.sendPendingAck(ctx, addr); err != nil {
		return TransferStats{}, true, err
	}
	return r.completeTerminalReceive(ctx, addr)
}

func (r *receiveLoop) completeTerminalReceive(ctx context.Context, addr net.Addr) (TransferStats, bool, error) {
	r.stats.markComplete(time.Now())
	if err := lingerTerminalAcks(ctx, r.conn, addr, r.runID, r.expectedSeq); err != nil {
		return TransferStats{}, true, err
	}
	return r.stats, true, nil
}

func (r *receiveLoop) sendPendingAck(ctx context.Context, addr net.Addr) error {
	if !r.ackDirty || addr == nil {
		return nil
	}
	if err := sendAck(ctx, r.conn, addr, r.runID, 0, r.expectedSeq, ackMaskFor(r.buffered, r.expectedSeq), extendedAckPayloadFor(r.buffered, r.expectedSeq)); err != nil {
		return err
	}
	r.ackDirty = false
	r.packetsSinceAck = 0
	r.lastAckAt = time.Now()
	return nil
}

func sendBlast(ctx context.Context, batcher packetBatcher, conn net.PacketConn, peer net.Addr, runID [16]byte, src io.Reader, chunkSize int, rateMbps int, rateCeilingMbps int, repairPayloads bool, tailReplayBytes int, fecGroupSize int, packetAEAD cipher.AEAD, streamReplayWindowBytes uint64, stats TransferStats) (TransferStats, error) {
	state, err := newBlastSendState(ctx, batcher, conn, peer, runID, chunkSize, rateMbps, rateCeilingMbps, repairPayloads, tailReplayBytes, fecGroupSize, packetAEAD, streamReplayWindowBytes, stats)
	if err != nil {
		return TransferStats{}, err
	}
	defer state.close()
	if err := state.run(ctx, src); err != nil {
		return TransferStats{}, err
	}
	return state.finish(ctx)
}

type blastSendState struct {
	batcher           packetBatcher
	peer              net.Addr
	runID             [16]byte
	chunkSize         int
	rateMbps          int
	repairPayloads    bool
	tailReplayBytes   int
	packetAEAD        cipher.AEAD
	packetOverhead    int
	control           *blastSendControl
	pacer             *blastPacer
	wireBatch         [][]byte
	packetBatch       [][]byte
	readBatch         []byte
	history           *blastRepairHistory
	fec               *blastFECGroup
	repairDeduper     *blastRepairDeduper
	repairReadBufs    []batchReadBuffer
	controlEvents     <-chan blastSendControlEvent
	stopControlReader func()
	seq               uint64
	offset            uint64
	startedAt         time.Time
	wireIndex         int
	batchPayloadBytes uint64
	backlogBudget     uint64
	stats             TransferStats
}

func newBlastSendState(ctx context.Context, batcher packetBatcher, conn net.PacketConn, peer net.Addr, runID [16]byte, chunkSize int, rateMbps int, rateCeilingMbps int, repairPayloads bool, tailReplayBytes int, fecGroupSize int, packetAEAD cipher.AEAD, streamReplayWindowBytes uint64, stats TransferStats) (*blastSendState, error) {
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}
	if batcher == nil {
		batcher = newPacketBatcher(conn, stats.Transport.RequestedKind)
	}
	stats.Transport = batcher.Capabilities()
	_ = setSocketPacing(conn, blastSocketPacingRateMbps(rateMbps, rateCeilingMbps))
	control := newBlastSendControl(rateMbps, rateCeilingMbps, time.Now())
	history, err := newBlastSendHistory(runID, chunkSize, rateCeilingMbps, repairPayloads, tailReplayBytes, packetAEAD, streamReplayWindowBytes)
	if err != nil {
		return nil, err
	}
	state := &blastSendState{
		batcher:           batcher,
		peer:              peer,
		runID:             runID,
		chunkSize:         chunkSize,
		rateMbps:          rateMbps,
		repairPayloads:    repairPayloads,
		tailReplayBytes:   tailReplayBytes,
		packetAEAD:        packetAEAD,
		packetOverhead:    blastPacketOverhead(packetAEAD),
		control:           control,
		pacer:             newBlastPacer(time.Now()),
		history:           history,
		fec:               newBlastFECGroup(runID, chunkSize, fecGroupSize, packetAEAD),
		repairDeduper:     newBlastRepairDeduper(),
		stopControlReader: func() {},
		startedAt:         time.Now(),
		backlogBudget: blastReceiverBacklogBudgetBytes(SendConfig{
			RateCeilingMbps:         rateCeilingMbps,
			StreamReplayWindowBytes: streamReplayWindowBytes,
		}),
		stats: stats,
	}
	state.initBuffers(pacedBatchLimit(normalizedBlastSendBatchLimit(batcher), chunkSize, control.RateMbps()))
	state.startControlReader(ctx)
	return state, nil
}

func newBlastSendHistory(runID [16]byte, chunkSize int, rateCeilingMbps int, repairPayloads bool, tailReplayBytes int, packetAEAD cipher.AEAD, streamReplayWindowBytes uint64) (*blastRepairHistory, error) {
	streamReplayEnabled := repairPayloads && (rateCeilingMbps > 0 || streamReplayWindowBytes > 0)
	retainHistoryPayloads := (repairPayloads || tailReplayBytes > 0) && !streamReplayEnabled
	history, err := newBlastRepairHistory(runID, chunkSize, retainHistoryPayloads, packetAEAD)
	if err != nil {
		return nil, err
	}
	if streamReplayEnabled {
		history.streamReplay = newStreamReplayWindow(runID, chunkSize, blastStreamReplayWindowBytes(streamReplayWindowBytes), packetAEAD)
	}
	return history, nil
}

func blastStreamReplayWindowBytes(configured uint64) uint64 {
	if configured > 0 {
		return configured
	}
	return defaultStreamReplayWindowBytes
}

func blastPacketOverhead(packetAEAD cipher.AEAD) int {
	if packetAEAD == nil {
		return 0
	}
	return packetAEAD.Overhead()
}

func normalizedBlastSendBatchLimit(batcher packetBatcher) int {
	limit := batcher.MaxBatch()
	if limit < 128 {
		return 128
	}
	if limit > 512 {
		return 512
	}
	return limit
}

func (s *blastSendState) initBuffers(batchLimit int) {
	s.wireBatch = make([][]byte, batchLimit)
	s.packetBatch = make([][]byte, 0, batchLimit)
	s.readBatch = make([]byte, batchLimit*s.chunkSize)
	for i := range s.wireBatch {
		s.wireBatch[i] = make([]byte, headerLen+s.chunkSize+s.packetOverhead)
	}
}

func (s *blastSendState) startControlReader(ctx context.Context) {
	if s.control.Adaptive() {
		var stop func()
		s.controlEvents, stop = startBlastSendControlReader(ctx, s.batcher, s.runID)
		s.stopControlReader = sync.OnceFunc(stop)
		return
	}
	s.repairReadBufs = make([]batchReadBuffer, s.batcher.MaxBatch())
	for i := range s.repairReadBufs {
		s.repairReadBufs[i].Bytes = make([]byte, 64<<10)
	}
}

func (s *blastSendState) close() {
	s.stopControlReader()
	if s.history != nil {
		_ = s.history.Close()
	}
}

func (s *blastSendState) run(ctx context.Context, src io.Reader) error {
	for {
		eof, err := s.runBatch(ctx, src)
		if err != nil {
			return err
		}
		if eof {
			break
		}
	}
	return nil
}

func (s *blastSendState) runBatch(ctx context.Context, src io.Reader) (bool, error) {
	s.packetBatch = s.packetBatch[:0]
	s.wireIndex = 0
	s.batchPayloadBytes = 0
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.control.Adaptive() {
		s.observeReceiverBacklog()
	}
	n, readErr := src.Read(s.readBatch)
	if n > 0 {
		if err := s.appendReadBatch(ctx, s.readBatch[:n]); err != nil {
			return false, err
		}
	}
	eof, err := s.handleReadResult(ctx, n, readErr)
	if err != nil {
		return false, err
	}
	if err := s.flushPacketBatch(ctx); err != nil {
		return false, err
	}
	return eof, nil
}

func (s *blastSendState) appendReadBatch(ctx context.Context, readBatch []byte) error {
	for len(readBatch) > 0 {
		payloadLen := min(s.chunkSize, len(readBatch))
		if err := s.appendPayload(ctx, readBatch[:payloadLen]); err != nil {
			return err
		}
		readBatch = readBatch[payloadLen:]
	}
	return nil
}

func (s *blastSendState) appendPayload(ctx context.Context, payload []byte) error {
	wire, payloadBuf, err := s.packetForPayload(ctx, payload)
	if err != nil {
		return err
	}
	if s.packetAEAD == nil {
		copy(payloadBuf, payload)
	}
	if !s.repairPayloads && s.packetAEAD == nil {
		if err := s.history.Record(s.seq, payloadBuf); err != nil {
			return err
		}
	}
	packet := wire[:headerLen+len(payload)+s.packetOverhead]
	s.packetBatch = append(s.packetBatch, packet)
	s.batchPayloadBytes += uint64(len(payload))
	s.stats.PacketsSent++
	s.stats.BytesSent += int64(len(payload))
	if parity := s.fec.Record(s.seq, s.offset, payloadBuf); parity != nil {
		s.packetBatch = append(s.packetBatch, parity)
		s.stats.PacketsSent++
	}
	s.seq++
	s.offset += uint64(len(payload))
	return nil
}

func (s *blastSendState) packetForPayload(ctx context.Context, payload []byte) ([]byte, []byte, error) {
	if s.packetAEAD != nil {
		return s.authenticatedPacketForPayload(ctx, payload)
	}
	if s.repairPayloads {
		return s.repairablePacketForPayload(ctx, payload)
	}
	wire := s.wireBatch[s.wireIndex]
	s.wireIndex++
	payloadBuf := wire[headerLen : headerLen+len(payload)]
	encodePacketHeader(wire[:headerLen], PacketTypeData, s.runID, 0, s.seq, s.offset, 0, 0)
	return wire, payloadBuf, nil
}

func (s *blastSendState) authenticatedPacketForPayload(ctx context.Context, payload []byte) ([]byte, []byte, error) {
	if s.history.streamReplay != nil {
		wire, err := s.addReplayPacket(ctx, payload)
		return wire, payload, err
	}
	if err := s.history.Record(s.seq, payload); err != nil {
		return nil, nil, err
	}
	wire, err := marshalBlastPayloadPacket(PacketTypeData, s.runID, 0, s.seq, s.offset, 0, 0, payload, s.packetAEAD)
	return wire, payload, err
}

func (s *blastSendState) repairablePacketForPayload(ctx context.Context, payload []byte) ([]byte, []byte, error) {
	if s.history.streamReplay != nil {
		wire, err := s.addReplayPacket(ctx, payload)
		return wire, payload, err
	}
	wire, err := s.history.packetBuffer(s.seq, s.offset, len(payload))
	if err != nil {
		return nil, nil, err
	}
	return wire, wire[headerLen:], nil
}

func (s *blastSendState) handleReadResult(ctx context.Context, n int, readErr error) (bool, error) {
	if errors.Is(readErr, io.EOF) {
		return true, nil
	}
	if readErr != nil {
		return false, readErr
	}
	if n > 0 {
		return false, nil
	}
	return false, sleepWithContext(ctx, zeroReadRetryDelay)
}

func (s *blastSendState) flushPacketBatch(ctx context.Context) error {
	drainControl := func() (bool, error) {
		return s.drainControlWithContext(ctx)
	}
	return flushBlastPacketBatch(ctx, s.batcher, s.peer, &s.packetBatch, s.control, s.pacer, s.batchPayloadBytes, s.offset, s.rateMbps, s.startedAt, &s.stats, drainControl, s.runID, s.history, s.repairDeduper, s.repairReadBufs, &s.wireIndex, &s.batchPayloadBytes)
}

func (s *blastSendState) addReplayPacket(ctx context.Context, payload []byte) ([]byte, error) {
	drainControl := func() (bool, error) {
		return s.drainControlWithContext(ctx)
	}
	flushPacketBatch := func() error {
		return s.flushPacketBatch(ctx)
	}
	return addBlastReplayPacket(ctx, s.history, s.seq, s.offset, payload, flushPacketBatch, s.control, drainControl, s.runID, &s.stats)
}

func (s *blastSendState) observeReceiverBacklog() {
	if !s.control.Adaptive() || s.backlogBudget == 0 {
		return
	}
	s.control.SetSentPayloadBytes(s.offset)
	if s.control.ReceiverBacklogBytes() <= s.backlogBudget {
		return
	}
	s.control.ObserveReceiverBacklogPressure(time.Now(), s.control.ReceiverBacklogBytes(), s.backlogBudget)
}

func (s *blastSendState) finish(ctx context.Context) (TransferStats, error) {
	if err := s.flushFEC(ctx); err != nil {
		return TransferStats{}, err
	}
	s.history.MarkComplete(s.offset, s.seq)
	if err := s.sendTailReplay(ctx); err != nil {
		return TransferStats{}, err
	}
	donePacket := make([]byte, headerLen)
	encodePacketHeader(donePacket, PacketTypeDone, s.runID, 0, s.seq, s.offset, 0, 0)
	writeBlastDoneBestEffort(ctx, s.batcher, s.peer, donePacket)
	s.stats.PacketsSent++
	complete, err := s.lingerDone(ctx, donePacket)
	if err != nil {
		return TransferStats{}, err
	}
	if complete {
		s.stats.markComplete(time.Now())
		return s.stats, nil
	}
	complete, err = s.drainDoneControl(ctx)
	if err != nil {
		return TransferStats{}, err
	}
	if complete {
		s.stats.markComplete(time.Now())
		return s.stats, nil
	}
	s.stopControlReader()
	return serveBlastRepairs(ctx, s.batcher, s.peer, s.runID, s.history, s.stats)
}

func (s *blastSendState) flushFEC(ctx context.Context) error {
	parity := s.fec.Flush()
	if parity == nil {
		return nil
	}
	if err := writeBlastBatch(ctx, s.batcher, s.peer, [][]byte{parity}); err != nil {
		return err
	}
	s.stats.PacketsSent++
	return nil
}

func (s *blastSendState) sendTailReplay(ctx context.Context) error {
	packets := s.history.tailPackets(s.tailReplayBytes)
	if len(packets) == 0 {
		return nil
	}
	if err := writeBlastBatch(ctx, s.batcher, s.peer, packets); err != nil {
		return err
	}
	s.stats.PacketsSent += int64(len(packets))
	s.stats.Retransmits += int64(len(packets))
	return nil
}

func (s *blastSendState) lingerDone(ctx context.Context, donePacket []byte) (bool, error) {
	lingerUntil := time.Now().Add(blastDoneLinger)
	for time.Now().Before(lingerUntil) {
		if err := sleepWithContext(ctx, blastDoneInterval); err != nil {
			return false, err
		}
		writeBlastDoneBestEffort(ctx, s.batcher, s.peer, donePacket)
		s.stats.PacketsSent++
		if complete, err := s.drainDoneControl(ctx); err != nil || complete {
			return complete, err
		}
	}
	return false, nil
}

func (s *blastSendState) drainDoneControl(ctx context.Context) (bool, error) {
	if !s.control.Adaptive() {
		return false, nil
	}
	return s.drainControlWithContext(ctx)
}

func (s *blastSendState) drainControlWithContext(ctx context.Context) (bool, error) {
	complete, err := drainBlastSendControlEvents(ctx, s.batcher, s.peer, s.history, &s.stats, s.repairDeduper, s.control, s.controlEvents)
	if err != nil {
		return complete, err
	}
	s.history.AckFloor(s.control.AckFloor())
	s.stats.MaxReplayBytes = max(s.stats.MaxReplayBytes, s.history.MaxReplayBytes())
	s.observeReceiverBacklog()
	return complete, nil
}

func flushBlastPacketBatch(ctx context.Context, batcher packetBatcher, peer net.Addr, packetBatch *[][]byte, control *blastSendControl, pacer *blastPacer, batchPayloadBytes uint64, offset uint64, rateMbps int, startedAt time.Time, stats *TransferStats, drainControl func() (bool, error), runID [16]byte, history *blastRepairHistory, repairDeduper *blastRepairDeduper, repairReadBufs []batchReadBuffer, wireIndex *int, batchPayloadBytesOut *uint64) error {
	if len(*packetBatch) == 0 {
		return nil
	}
	if err := writeBlastBatch(ctx, batcher, peer, *packetBatch); err != nil {
		return err
	}
	control.SetSentPayloadBytes(offset)
	if control.Adaptive() {
		if err := pacer.Pace(ctx, batchPayloadBytes, control.RateMbps()); err != nil {
			return err
		}
	} else {
		if err := paceBlastSend(ctx, startedAt, offset, rateMbps); err != nil {
			return err
		}
		stats.observePeakGoodput(time.Now(), stats.BytesSent)
	}
	if control.Adaptive() {
		complete, err := drainControl()
		if err != nil {
			return err
		}
		if complete {
			sessionTracef("blast repair complete received before sender EOF run=%x", runID[:4])
		}
	} else if _, err := serviceBlastRepairRequests(ctx, batcher, peer, runID, history, stats, repairDeduper, repairReadBufs, 0, nil); err != nil {
		return err
	}
	*packetBatch = (*packetBatch)[:0]
	*batchPayloadBytesOut = 0
	*wireIndex = 0
	return nil
}

func addBlastReplayPacket(ctx context.Context, history *blastRepairHistory, seq uint64, offset uint64, payload []byte, flushPacketBatch func() error, control *blastSendControl, drainControl func() (bool, error), runID [16]byte, stats *TransferStats) ([]byte, error) {
	for {
		wire, err := history.streamReplay.AddDataPacket(0, seq, offset, payload)
		if !errors.Is(err, errStreamReplayWindowFull) {
			return wire, err
		}
		if err := waitForBlastReplayWindow(ctx, history, flushPacketBatch, control, drainControl, runID, stats); err != nil {
			return nil, err
		}
	}
}

func waitForBlastReplayWindow(ctx context.Context, history *blastRepairHistory, flushPacketBatch func() error, control *blastSendControl, drainControl func() (bool, error), runID [16]byte, stats *TransferStats) error {
	if err := flushAndDrainBlastReplayWindow(flushPacketBatch, control, drainControl, runID); err != nil {
		return err
	}
	if !blastReplayWindowFull(history) {
		return nil
	}
	return pauseForBlastReplayWindow(ctx, history, control, stats)
}

func flushAndDrainBlastReplayWindow(flushPacketBatch func() error, control *blastSendControl, drainControl func() (bool, error), runID [16]byte) error {
	if err := flushPacketBatch(); err != nil {
		return err
	}
	return drainBlastReplayControl(control, drainControl, runID)
}

func blastReplayWindowFull(history *blastRepairHistory) bool {
	return history.streamReplay != nil && history.streamReplay.RetainedBytes() >= history.streamReplay.MaxBytes()
}

func pauseForBlastReplayWindow(ctx context.Context, history *blastRepairHistory, control *blastSendControl, stats *TransferStats) error {
	waitStart := time.Now()
	observeBlastReplayWindowPressure(control, history, waitStart)
	if err := sleepWithContext(ctx, blastRepairInterval); err != nil {
		return err
	}
	recordReplayWindowFullWait(stats, history.streamReplay.RetainedBytes(), time.Since(waitStart))
	return nil
}

func observeBlastReplayWindowPressure(control *blastSendControl, history *blastRepairHistory, observedAt time.Time) {
	if control.Adaptive() {
		control.ObserveReplayPressure(observedAt, history.streamReplay.RetainedBytes(), history.streamReplay.MaxBytes())
	}
}

func drainBlastReplayControl(control *blastSendControl, drainControl func() (bool, error), runID [16]byte) error {
	if !control.Adaptive() {
		return nil
	}
	complete, err := drainControl()
	if err != nil {
		return err
	}
	if complete {
		sessionTracef("blast repair complete received while replay window was full run=%x", runID[:4])
	}
	return nil
}

func serviceBlastRepairRequests(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, history *blastRepairHistory, stats *TransferStats, deduper *blastRepairDeduper, readBufs []batchReadBuffer, timeout time.Duration, control *blastSendControl) (bool, error) {
	if batcher == nil || history == nil || len(readBufs) == 0 {
		return false, nil
	}
	n, err := batcher.ReadBatch(ctx, timeout, readBufs)
	if err != nil {
		return false, serviceBlastRepairReadError(ctx, err)
	}
	repaired := false
	now := time.Now()
	for i := 0; i < n; i++ {
		repairHandled, err := serviceBlastRepairPacket(ctx, batcher, peer, runID, history, stats, deduper, control, now, readBufs[i].Bytes[:readBufs[i].N])
		if err != nil {
			return repaired, err
		}
		repaired = repaired || repairHandled
	}
	return repaired, nil
}

func serviceBlastRepairReadError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if isNetTimeout(err) {
		return nil
	}
	if errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func serviceBlastRepairPacket(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, history *blastRepairHistory, stats *TransferStats, deduper *blastRepairDeduper, control *blastSendControl, now time.Time, packet []byte) (bool, error) {
	packetType, payload, packetRunID, _, _, ok := decodeBlastPacketFull(packet)
	if !ok || packetRunID != runID {
		return false, nil
	}
	switch packetType {
	case PacketTypeRepairRequest:
		retransmits, err := sendBlastRepairs(ctx, batcher, peer, history, payload, stats, deduper, now)
		if err != nil {
			return true, err
		}
		if control != nil && retransmits > 0 {
			control.ObserveRepairPressure(now, retransmits)
		}
		return true, nil
	case PacketTypeStats:
		if control == nil {
			return false, nil
		}
		sessionTracef("blast stats receive rx_payload_len=%d", len(payload))
		control.ObserveReceiverStats(payload, now)
	}
	return false, nil
}

type blastParallelSendItem struct {
	wire     []byte
	payload  []byte
	history  *blastRepairHistory
	stripeID uint16
	seq      uint64
	offset   uint64
}

type blastParallelSendLane struct {
	conn        net.PacketConn
	peer        net.Addr
	batcher     packetBatcher
	batchLimit  int
	ch          chan blastParallelSendItem
	stripeID    uint16
	nextSeq     uint64
	history     *blastRepairHistory
	deduper     *blastRepairDeduper
	fec         *blastFECGroup
	rateMbps    atomic.Int64
	pacer       *blastPacer
	runID       [16]byte
	sendConfig  SendConfig
	payloadPool sync.Pool
}

func (l *blastParallelSendLane) setRateMbps(rateMbps int) {
	if l == nil {
		return
	}
	l.rateMbps.Store(int64(rateMbps))
}

func (l *blastParallelSendLane) currentRateMbps() int {
	if l == nil {
		return 0
	}
	return int(l.rateMbps.Load())
}

func (l *blastParallelSendLane) copyPayload(payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	var buf []byte
	if l != nil {
		if pooled := l.payloadPool.Get(); pooled != nil {
			if pooledBuf, ok := pooled.(*[]byte); ok && cap(*pooledBuf) >= len(payload) {
				buf = (*pooledBuf)[:len(payload)]
			}
		}
	}
	if buf == nil {
		buf = make([]byte, len(payload))
	}
	copy(buf, payload)
	return buf
}

func (l *blastParallelSendLane) releasePayload(payload []byte) {
	if l == nil || payload == nil {
		return
	}
	buf := payload[:0]
	l.payloadPool.Put(&buf)
}

type blastParallelSendControlEvent struct {
	lane  *blastParallelSendLane
	event blastSendControlEvent
}

func startBlastParallelSendControlReaders(ctx context.Context, lanes []*blastParallelSendLane, runID [16]byte) (<-chan blastParallelSendControlEvent, func()) {
	buffer := 0
	for _, lane := range lanes {
		if lane != nil {
			buffer += blastSendControlEventBuffer(lane.batcher)
		}
	}
	if buffer < 1024 {
		buffer = 1024
	}
	events := make(chan blastParallelSendControlEvent, buffer)
	controlCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	for _, lane := range lanes {
		if lane == nil || lane.batcher == nil {
			continue
		}
		wg.Add(1)
		go func(lane *blastParallelSendLane) {
			defer wg.Done()
			readBlastParallelSendControlEvents(controlCtx, lane, runID, events)
		}(lane)
	}
	stop := func() {
		cancel()
		wg.Wait()
	}
	return events, stop
}

func readBlastParallelSendControlEvents(ctx context.Context, lane *blastParallelSendLane, runID [16]byte, events chan<- blastParallelSendControlEvent) {
	if lane == nil || lane.batcher == nil {
		return
	}
	readBufs := newBlastBatchReadBuffers(lane.batcher.MaxBatch())
	for {
		n, err := lane.batcher.ReadBatch(ctx, blastRepairInterval, readBufs)
		now := time.Now()
		if err != nil {
			if stop := handleBlastParallelSendControlReadError(ctx, lane, events, err, now); stop {
				return
			}
			continue
		}
		if !emitBlastParallelSendControlEvents(ctx, lane, runID, readBufs[:n], events, now) {
			return
		}
	}
}

func newBlastBatchReadBuffers(maxBatch int) []batchReadBuffer {
	readBufs := make([]batchReadBuffer, maxBatch)
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, 64<<10)
	}
	return readBufs
}

func handleBlastParallelSendControlReadError(ctx context.Context, lane *blastParallelSendLane, events chan<- blastParallelSendControlEvent, err error, now time.Time) bool {
	if ctx.Err() != nil {
		return true
	}
	if isNetTimeout(err) {
		return false
	}
	if !errors.Is(err, net.ErrClosed) {
		return false
	}
	select {
	case events <- blastParallelSendControlEvent{lane: lane, event: blastSendControlEvent{err: err, receivedAt: now}}:
	case <-ctx.Done():
	}
	return true
}

func emitBlastParallelSendControlEvents(ctx context.Context, lane *blastParallelSendLane, runID [16]byte, readBufs []batchReadBuffer, events chan<- blastParallelSendControlEvent, now time.Time) bool {
	for i := range readBufs {
		event, ok := decodeBlastSendControlEvent(readBufs[i], runID, now)
		if !ok {
			continue
		}
		select {
		case events <- blastParallelSendControlEvent{lane: lane, event: event}:
		case <-ctx.Done():
			return false
		}
	}
	return true
}

func blastParallelRepairHistoryForLane(global *blastRepairHistory, lane *blastParallelSendLane) *blastRepairHistory {
	if lane != nil && lane.history != nil {
		return lane.history
	}
	return global
}

func SendBlastParallel(ctx context.Context, conns []net.PacketConn, remoteAddrs []string, src io.Reader, cfg SendConfig) (TransferStats, error) {
	if singleStats, handled, err := sendBlastParallelEarlyResult(ctx, conns, remoteAddrs, src, cfg); handled {
		return singleStats, err
	}
	cfg = defaultedSendConfig(cfg)
	runID, err := sendBlastParallelRunID(cfg)
	if err != nil {
		return TransferStats{}, err
	}

	stats := TransferStats{StartedAt: time.Now()}
	stats.observePeakGoodput(stats.StartedAt, 0)
	stripedBlast := cfg.StripedBlast
	lanes, err := buildBlastParallelSendLanes(ctx, conns, remoteAddrs, runID, stripedBlast, cfg, &stats)
	if err != nil {
		return TransferStats{}, err
	}
	stats.Lanes = len(lanes)
	control, activeLanes, err := configureBlastParallelSendLanes(lanes, stripedBlast, cfg)
	if err != nil {
		return TransferStats{}, err
	}
	history, fec, cleanupHistories, err := newBlastParallelSendHistories(runID, lanes, stripedBlast, cfg)
	if err != nil {
		return TransferStats{}, err
	}
	defer cleanupHistories()

	sendCtx, sendCancel := context.WithCancel(ctx)
	defer sendCancel()
	repairDeduper := newBlastRepairDeduper()
	var controlEvents <-chan blastParallelSendControlEvent
	stopControlReader := func() {}
	if control.Adaptive() {
		controlEvents, stopControlReader = startBlastParallelSendControlReaders(sendCtx, lanes, runID)
		stopControlReader = sync.OnceFunc(stopControlReader)
		defer stopControlReader()
	}
	errCh, wg := startBlastParallelSendLaneWorkers(sendCtx, sendCancel, lanes)

	var seq uint64
	var offset uint64
	readBatch := make([]byte, parallelBlastReadBatchSize(len(lanes), cfg.ChunkSize))
	readErr := error(nil)
	receiverBacklogBudget := blastReceiverBacklogBudgetBytes(cfg)
	controlRuntime := &blastParallelSendControlRuntime{
		ctx:                   ctx,
		sendCtx:               sendCtx,
		cfg:                   cfg,
		runID:                 runID,
		stripedBlast:          stripedBlast,
		lanes:                 lanes,
		history:               history,
		control:               control,
		stats:                 &stats,
		repairDeduper:         repairDeduper,
		controlEvents:         controlEvents,
		activeLanes:           &activeLanes,
		offset:                &offset,
		receiverBacklogBudget: receiverBacklogBudget,
	}
	readErr = (&blastParallelSendReadLoop{
		ctx:                    ctx,
		sendCtx:                sendCtx,
		src:                    src,
		cfg:                    cfg,
		runID:                  runID,
		stripedBlast:           stripedBlast,
		lanes:                  lanes,
		history:                history,
		fec:                    fec,
		control:                control,
		stats:                  &stats,
		seq:                    &seq,
		offset:                 &offset,
		activeLanes:            &activeLanes,
		readBatch:              readBatch,
		drainControlEvents:     controlRuntime.drainControlEvents,
		observeReceiverBacklog: controlRuntime.observeReceiverBacklog,
		waitForReceiverBacklog: controlRuntime.waitForReceiverBacklog,
		updateLaneRates:        controlRuntime.updateLaneRates,
		addParallelPacket:      controlRuntime.addParallelPacket,
	}).run()
	return (&blastParallelSendCompletion{
		ctx:               ctx,
		sendCtx:           sendCtx,
		sendCancel:        sendCancel,
		cfg:               cfg,
		runID:             runID,
		stripedBlast:      stripedBlast,
		lanes:             lanes,
		history:           history,
		fec:               fec,
		control:           control,
		controlRuntime:    controlRuntime,
		stats:             &stats,
		wg:                wg,
		errCh:             errCh,
		activeLanes:       activeLanes,
		seq:               seq,
		offset:            offset,
		stopControlReader: stopControlReader,
	}).finish(readErr)
}

type blastParallelSendCompletion struct {
	ctx               context.Context
	sendCtx           context.Context
	sendCancel        context.CancelFunc
	cfg               SendConfig
	runID             [16]byte
	stripedBlast      bool
	lanes             []*blastParallelSendLane
	history           *blastRepairHistory
	fec               *blastFECGroup
	control           *blastSendControl
	controlRuntime    *blastParallelSendControlRuntime
	stats             *TransferStats
	wg                *sync.WaitGroup
	errCh             <-chan error
	activeLanes       int
	seq               uint64
	offset            uint64
	stopControlReader func()
}

func (c *blastParallelSendCompletion) finish(readErr error) (TransferStats, error) {
	readErr = c.normalizeReadError(readErr)
	if readErr != nil {
		c.sendCancel()
	}
	if err := c.flushStripedFEC(&readErr); err != nil {
		return TransferStats{}, err
	}
	c.closeLaneQueues()
	controlComplete, err := c.waitForLaneWorkers()
	if err != nil {
		return TransferStats{}, err
	}
	if err := c.laneWorkerError(); err != nil {
		return TransferStats{}, err
	}
	if readErr != nil {
		return TransferStats{}, readErr
	}
	complete, err := c.drainFinalControl(controlComplete)
	if err != nil {
		return TransferStats{}, err
	}
	if complete {
		return c.completedStats(true), nil
	}
	if err := c.markPayloadComplete(); err != nil {
		return TransferStats{}, err
	}
	return c.lingerDoneAndServeRepairs()
}

func (c *blastParallelSendCompletion) normalizeReadError(readErr error) error {
	if errors.Is(readErr, io.EOF) {
		return nil
	}
	return readErr
}

func (c *blastParallelSendCompletion) flushStripedFEC(readErr *error) error {
	if *readErr != nil || !c.stripedBlast {
		return nil
	}
	for _, lane := range c.lanes {
		if parity := lane.fec.Flush(); parity != nil {
			if err := enqueueBlastParallelPacket(c.sendCtx, lane, parity); err != nil {
				*readErr = err
				c.sendCancel()
				return nil
			}
			c.stats.PacketsSent++
		}
	}
	return nil
}

func (c *blastParallelSendCompletion) closeLaneQueues() {
	for _, lane := range c.lanes {
		close(lane.ch)
	}
}

func (c *blastParallelSendCompletion) waitForLaneWorkers() (bool, error) {
	if !c.control.Adaptive() {
		c.wg.Wait()
		return false, nil
	}
	controlComplete, waitErr := waitBlastParallelSendLanes(c.sendCtx, c.wg, c.control, c.controlRuntime.setSentPayloadBytes, c.controlRuntime.drainControlEvents)
	if waitErr != nil {
		c.sendCancel()
		c.wg.Wait()
		return false, waitErr
	}
	return controlComplete, nil
}

func (c *blastParallelSendCompletion) laneWorkerError() error {
	select {
	case err := <-c.errCh:
		return err
	default:
		return nil
	}
}

func (c *blastParallelSendCompletion) drainFinalControl(controlComplete bool) (bool, error) {
	if !c.control.Adaptive() {
		return false, nil
	}
	c.controlRuntime.setSentPayloadBytes()
	complete, err := c.controlRuntime.drainControlEvents()
	return complete || controlComplete, err
}

func (c *blastParallelSendCompletion) completedStats(complete bool) TransferStats {
	if complete {
		c.stats.markComplete(time.Now())
	}
	return *c.stats
}

func (c *blastParallelSendCompletion) markPayloadComplete() error {
	if c.stripedBlast {
		for _, lane := range c.lanes {
			lane.history.MarkComplete(0, lane.nextSeq)
		}
		return nil
	}
	c.history.MarkComplete(c.offset, c.seq)
	if err := c.flushSharedFEC(); err != nil {
		return err
	}
	return c.replayTailPackets()
}

func (c *blastParallelSendCompletion) flushSharedFEC() error {
	parity := c.fec.Flush()
	if parity == nil {
		return nil
	}
	lane := c.lanes[int(c.seq%uint64(c.activeLanes))]
	if err := writeBlastBatch(c.ctx, lane.batcher, lane.peer, [][]byte{parity}); err != nil {
		return err
	}
	c.stats.PacketsSent++
	return nil
}

func (c *blastParallelSendCompletion) replayTailPackets() error {
	packets := c.history.tailPackets(c.cfg.TailReplayBytes)
	if len(packets) == 0 {
		return nil
	}
	if err := writeBlastParallelPackets(c.ctx, c.lanes, packets); err != nil {
		return err
	}
	c.stats.PacketsSent += int64(len(packets))
	c.stats.Retransmits += int64(len(packets))
	return nil
}

func (c *blastParallelSendCompletion) lingerDoneAndServeRepairs() (TransferStats, error) {
	complete, err := c.lingerDonePackets()
	if err != nil {
		return TransferStats{}, err
	}
	if complete {
		return c.completedStats(true), nil
	}
	complete, err = c.drainFinalControl(false)
	if err != nil {
		return TransferStats{}, err
	}
	if complete {
		return c.completedStats(true), nil
	}
	c.stopControlReader()
	return serveBlastRepairsParallel(c.ctx, c.lanes, c.runID, c.history, *c.stats, c.resendTerminal)
}

func (c *blastParallelSendCompletion) lingerDonePackets() (bool, error) {
	c.writeDoneAllBestEffort()
	lingerUntil := time.Now().Add(blastDoneLinger)
	for time.Now().Before(lingerUntil) {
		if err := sleepWithContext(c.ctx, blastDoneInterval); err != nil {
			return false, err
		}
		c.writeDoneAllBestEffort()
		if complete, err := c.drainDoneLingerControl(); err != nil || complete {
			return complete, err
		}
	}
	return false, nil
}

func (c *blastParallelSendCompletion) drainDoneLingerControl() (bool, error) {
	if !c.control.Adaptive() {
		return false, nil
	}
	return c.controlRuntime.drainControlEvents()
}

func (c *blastParallelSendCompletion) writeDoneAllBestEffort() {
	writeBlastDoneAllBestEffort(c.ctx, c.lanes, c.runID, c.seq, c.offset, c.stripedBlast, c.stats)
}

func (c *blastParallelSendCompletion) resendTerminal() {
	c.writeDoneAllBestEffort()
}

func sendBlastParallelEarlyResult(ctx context.Context, conns []net.PacketConn, remoteAddrs []string, src io.Reader, cfg SendConfig) (TransferStats, bool, error) {
	if len(conns) == 0 {
		return TransferStats{}, true, errors.New("no packet conns")
	}
	if len(conns) != len(remoteAddrs) {
		return TransferStats{}, true, fmt.Errorf("packet conn count %d does not match remote addr count %d", len(conns), len(remoteAddrs))
	}
	if len(conns) == 1 {
		stats, err := Send(ctx, conns[0], remoteAddrs[0], src, cfg)
		if stats.Lanes == 0 {
			stats.Lanes = 1
		}
		return stats, true, err
	}
	if src == nil {
		return TransferStats{}, true, errors.New("nil source reader")
	}
	return TransferStats{}, false, nil
}

func defaultedSendConfig(cfg SendConfig) SendConfig {
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = defaultChunkSize
	}
	return cfg
}

func sendBlastParallelRunID(cfg SendConfig) ([16]byte, error) {
	if !isZeroRunID(cfg.RunID) {
		return cfg.RunID, nil
	}
	return newRunID()
}

func buildBlastParallelSendLanes(ctx context.Context, conns []net.PacketConn, remoteAddrs []string, runID [16]byte, stripedBlast bool, cfg SendConfig, stats *TransferStats) ([]*blastParallelSendLane, error) {
	lanes := make([]*blastParallelSendLane, 0, len(conns))
	var skippedHandshakeErr error
	for i, conn := range conns {
		lane, skipped, err := buildBlastParallelSendLane(ctx, conn, remoteAddrs[i], i, len(conns), runID, stripedBlast, cfg, stats)
		if err != nil && !skipped {
			return nil, err
		}
		if skipped {
			skippedHandshakeErr = err
			continue
		}
		lanes = append(lanes, lane)
	}
	return finalizeBlastParallelSendLanes(ctx, lanes, len(conns), runID, stripedBlast, cfg, stats, skippedHandshakeErr)
}

func buildBlastParallelSendLane(ctx context.Context, conn net.PacketConn, remoteAddr string, index int, laneCount int, runID [16]byte, stripedBlast bool, cfg SendConfig, stats *TransferStats) (*blastParallelSendLane, bool, error) {
	if conn == nil {
		return nil, false, fmt.Errorf("nil packet conn at lane %d", index)
	}
	peer, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, false, err
	}
	batcher := newPacketBatcher(conn, cfg.Transport)
	rememberFirstLaneTransport(stats, batcher)
	if err := performParallelLaneHandshake(ctx, conn, peer, runID, index, laneCount, stripedBlast, cfg, stats); err != nil {
		if cfg.AllowPartialParallel {
			return nil, true, err
		}
		return nil, false, err
	}
	batcher = maybeConnectedParallelSendBatcher(conn, peer, batcher, laneCount, cfg, stats)
	return newBlastParallelSendLane(conn, peer, batcher, uint16(index), runID, cfg), false, nil
}

func rememberFirstLaneTransport(stats *TransferStats, batcher packetBatcher) {
	if stats != nil && stats.Transport.Kind == "" {
		stats.Transport = batcher.Capabilities()
	}
}

func performParallelLaneHandshake(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, index int, laneCount int, stripedBlast bool, cfg SendConfig, stats *TransferStats) error {
	handshakeCtx, cancel := parallelHandshakeContext(ctx, cfg)
	defer cancel()
	stripeID, totalStripes := parallelHandshakeStripe(index, laneCount, stripedBlast)
	sessionTracef("parallel hello start lane=%d local=%s peer=%s run=%x stripe=%d total=%d", index, conn.LocalAddr(), peer, runID[:4], stripeID, totalStripes)
	_, err := performHelloHandshake(handshakeCtx, conn, peer, runID, stripeID, totalStripes, stats)
	if err != nil {
		sessionTracef("parallel hello fail lane=%d local=%s peer=%s run=%x stripe=%d err=%v", index, conn.LocalAddr(), peer, runID[:4], stripeID, err)
		return err
	}
	sessionTracef("parallel hello ok lane=%d local=%s peer=%s run=%x stripe=%d", index, conn.LocalAddr(), peer, runID[:4], stripeID)
	return nil
}

func parallelHandshakeContext(ctx context.Context, cfg SendConfig) (context.Context, context.CancelFunc) {
	if !cfg.AllowPartialParallel {
		return ctx, func() {}
	}
	timeout := cfg.ParallelHandshakeTimeout
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	return context.WithTimeout(ctx, timeout)
}

func parallelHandshakeStripe(index int, laneCount int, stripedBlast bool) (uint16, uint16) {
	if !stripedBlast {
		return 0, 1
	}
	return uint16(index), uint16(laneCount)
}

func maybeConnectedParallelSendBatcher(conn net.PacketConn, peer net.Addr, batcher packetBatcher, laneCount int, cfg SendConfig, stats *TransferStats) packetBatcher {
	if !shouldUseConnectedBatcherForParallelSend(batcher, laneCount, cfg) {
		return batcher
	}
	connectedBatcher, ok := newConnectedUDPBatcher(conn, peer, cfg.Transport)
	if !ok {
		return batcher
	}
	rememberFirstLaneTransport(stats, connectedBatcher)
	return connectedBatcher
}

func newBlastParallelSendLane(conn net.PacketConn, peer net.Addr, batcher packetBatcher, stripeID uint16, runID [16]byte, cfg SendConfig) *blastParallelSendLane {
	lane := &blastParallelSendLane{
		conn:       conn,
		peer:       peer,
		batcher:    batcher,
		stripeID:   stripeID,
		runID:      runID,
		sendConfig: cfg,
	}
	chunkSize := cfg.ChunkSize
	lane.payloadPool.New = func() any {
		buf := make([]byte, chunkSize)
		return &buf
	}
	return lane
}

func finalizeBlastParallelSendLanes(ctx context.Context, lanes []*blastParallelSendLane, requestedLanes int, runID [16]byte, stripedBlast bool, cfg SendConfig, stats *TransferStats, skippedHandshakeErr error) ([]*blastParallelSendLane, error) {
	if len(lanes) == 0 {
		return nil, noBlastParallelSendLanesError(skippedHandshakeErr)
	}
	if !stripedBlast {
		return lanes, nil
	}
	if err := renumberBlastParallelSendStripes(ctx, lanes, requestedLanes, runID, cfg, stats); err != nil {
		return nil, err
	}
	return lanes, nil
}

func noBlastParallelSendLanesError(skippedHandshakeErr error) error {
	if skippedHandshakeErr != nil {
		return skippedHandshakeErr
	}
	return errors.New("no parallel blast lanes completed handshake")
}

func renumberBlastParallelSendStripes(ctx context.Context, lanes []*blastParallelSendLane, requestedLanes int, runID [16]byte, cfg SendConfig, stats *TransferStats) error {
	finalStripes := uint16(len(lanes))
	for i, lane := range lanes {
		lane.stripeID = uint16(i)
	}
	if !cfg.AllowPartialParallel || len(lanes) == requestedLanes {
		return nil
	}
	for _, lane := range lanes {
		if _, err := performHelloHandshakeBatch(ctx, lane.batcher, lane.peer, runID, lane.stripeID, finalStripes, stats); err != nil {
			return err
		}
	}
	return nil
}

func configureBlastParallelSendLanes(lanes []*blastParallelSendLane, stripedBlast bool, cfg SendConfig) (*blastSendControl, int, error) {
	controlCeilingMbps := max(cfg.RateCeilingMbps, cfg.RateExplorationCeilingMbps)
	control := newBlastSendControlWithInitialLossCeiling(cfg.RateMbps, controlCeilingMbps, cfg.RateCeilingMbps, time.Now())
	activeLanes := parallelActiveLanesForConfig(control.RateMbps(), len(lanes), stripedBlast, cfg.MinActiveLanes, cfg.MaxActiveLanes)
	if activeLanes == 0 {
		return nil, 0, errors.New("no active parallel blast lanes")
	}
	configureBlastParallelLaneQueues(lanes, activeLanes, control.RateMbps(), controlCeilingMbps, stripedBlast, cfg)
	return control, activeLanes, nil
}

func configureBlastParallelLaneQueues(lanes []*blastParallelSendLane, activeLanes int, totalRateMbps int, controlCeilingMbps int, stripedBlast bool, cfg SendConfig) {
	laneRate := parallelLaneRateMbps(totalRateMbps, activeLanes)
	sendStartedAt := time.Now()
	for i, lane := range lanes {
		rate := 0
		if i < activeLanes {
			rate = laneRate
		}
		_ = setSocketPacing(lane.conn, laneRate)
		lane.batchLimit = sendLaneBatchLimit(lane, laneRate, controlCeilingMbps, activeLanes, cfg.ChunkSize)
		lane.ch = make(chan blastParallelSendItem, blastParallelLaneQueueCapacity(lane.batchLimit, stripedBlast))
		lane.setRateMbps(rate)
		lane.pacer = newBlastPacer(sendStartedAt)
	}
}

func sendLaneBatchLimit(lane *blastParallelSendLane, laneRate int, controlCeilingMbps int, activeLanes int, chunkSize int) int {
	buildBatchLimit := lane.batcher.MaxBatch()
	if buildBatchLimit < 128 {
		buildBatchLimit = 128
	}
	return pacedBatchLimit(buildBatchLimit, chunkSize, blastParallelLaneBatchRateMbps(laneRate, controlCeilingMbps, activeLanes))
}

func newBlastParallelSendHistories(runID [16]byte, lanes []*blastParallelSendLane, stripedBlast bool, cfg SendConfig) (*blastRepairHistory, *blastFECGroup, func(), error) {
	replay := newBlastParallelReplayConfig(cfg)
	history, err := newBlastRepairHistory(runID, cfg.ChunkSize, replay.retainGlobalPayloads, cfg.PacketAEAD)
	if err != nil {
		return nil, nil, func() {}, err
	}
	if replay.enabled {
		history.streamReplay = newStreamReplayWindow(runID, cfg.ChunkSize, replay.bytes, cfg.PacketAEAD)
	}
	if err := configureBlastParallelLaneHistories(runID, lanes, stripedBlast, replay, cfg); err != nil {
		_ = history.Close()
		return nil, nil, func() {}, err
	}
	cleanup := func() {
		_ = history.Close()
		for _, lane := range lanes {
			if lane.history != nil {
				_ = lane.history.Close()
			}
		}
	}
	return history, newBlastParallelFEC(runID, stripedBlast, cfg), cleanup, nil
}

type blastParallelReplaySettings struct {
	enabled              bool
	bytes                uint64
	retainGlobalPayloads bool
}

func newBlastParallelReplayConfig(cfg SendConfig) blastParallelReplaySettings {
	enabled := cfg.RepairPayloads && (cfg.RateCeilingMbps > 0 || cfg.StreamReplayWindowBytes > 0)
	replayBytes := cfg.StreamReplayWindowBytes
	if enabled && replayBytes == 0 {
		replayBytes = defaultStreamReplayWindowBytes
	}
	return blastParallelReplaySettings{
		enabled:              enabled,
		bytes:                replayBytes,
		retainGlobalPayloads: (cfg.RepairPayloads || cfg.TailReplayBytes > 0) && !enabled,
	}
}

func configureBlastParallelLaneHistories(runID [16]byte, lanes []*blastParallelSendLane, stripedBlast bool, replay blastParallelReplaySettings, cfg SendConfig) error {
	if !stripedBlast {
		return nil
	}
	for _, lane := range lanes {
		if err := configureBlastParallelLaneHistory(runID, lane, len(lanes), replay, cfg); err != nil {
			return err
		}
	}
	return nil
}

func configureBlastParallelLaneHistory(runID [16]byte, lane *blastParallelSendLane, laneCount int, replay blastParallelReplaySettings, cfg SendConfig) error {
	var err error
	lane.history, err = newBlastRepairHistory(runID, cfg.ChunkSize, !replay.enabled, cfg.PacketAEAD)
	if err != nil {
		return err
	}
	if replay.enabled {
		lane.history.streamReplay = newStreamReplayWindow(runID, cfg.ChunkSize, laneReplayWindowBytes(replay.bytes, laneCount), cfg.PacketAEAD)
	}
	lane.fec = newBlastFECGroupForStripe(runID, lane.stripeID, cfg.ChunkSize, cfg.FECGroupSize, cfg.PacketAEAD)
	return nil
}

func laneReplayWindowBytes(replayBytes uint64, laneCount int) uint64 {
	laneReplayBytes := replayBytes / uint64(laneCount)
	if laneReplayBytes == 0 {
		return replayBytes
	}
	return laneReplayBytes
}

func newBlastParallelFEC(runID [16]byte, stripedBlast bool, cfg SendConfig) *blastFECGroup {
	if stripedBlast {
		return nil
	}
	return newBlastFECGroup(runID, cfg.ChunkSize, cfg.FECGroupSize, cfg.PacketAEAD)
}

func startBlastParallelSendLaneWorkers(ctx context.Context, cancel context.CancelFunc, lanes []*blastParallelSendLane) (<-chan error, *sync.WaitGroup) {
	errCh := make(chan error, len(lanes))
	wg := &sync.WaitGroup{}
	for _, lane := range lanes {
		wg.Add(1)
		go runBlastParallelSendLaneWorker(ctx, cancel, lane, errCh, wg)
	}
	return errCh, wg
}

func runBlastParallelSendLaneWorker(ctx context.Context, cancel context.CancelFunc, lane *blastParallelSendLane, errCh chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	if err := runBlastParallelSendLane(ctx, lane); err != nil {
		select {
		case errCh <- err:
		default:
		}
		cancel()
	}
}

type blastParallelSendControlRuntime struct {
	ctx                   context.Context
	sendCtx               context.Context
	cfg                   SendConfig
	runID                 [16]byte
	stripedBlast          bool
	lanes                 []*blastParallelSendLane
	history               *blastRepairHistory
	control               *blastSendControl
	stats                 *TransferStats
	repairDeduper         *blastRepairDeduper
	controlEvents         <-chan blastParallelSendControlEvent
	activeLanes           *int
	offset                *uint64
	receiverBacklogBudget uint64
}

func (r *blastParallelSendControlRuntime) setSentPayloadBytes() {
	r.control.SetSentPayloadBytes(*r.offset)
}

func (r *blastParallelSendControlRuntime) updateLaneRates() {
	*r.activeLanes = parallelActiveLanesForConfig(r.control.RateMbps(), len(r.lanes), r.stripedBlast, r.cfg.MinActiveLanes, r.cfg.MaxActiveLanes)
	rate := parallelLaneRateMbps(r.control.RateMbps(), *r.activeLanes)
	for i, lane := range r.lanes {
		if i >= *r.activeLanes {
			lane.setRateMbps(0)
			continue
		}
		lane.setRateMbps(rate)
	}
}

func (r *blastParallelSendControlRuntime) applyControlAck() {
	r.history.AckFloor(r.control.AckFloor())
	r.stats.MaxReplayBytes = max(r.stats.MaxReplayBytes, r.history.MaxReplayBytes())
	if r.stripedBlast {
		r.applyStripedControlAck()
	}
}

func (r *blastParallelSendControlRuntime) applyStripedControlAck() {
	for _, lane := range r.lanes {
		if lane.history == nil {
			continue
		}
		lane.history.AckFloor(r.control.AckFloor())
		r.stats.MaxReplayBytes = max(r.stats.MaxReplayBytes, lane.history.MaxReplayBytes())
	}
}

func (r *blastParallelSendControlRuntime) drainControlEvents() (bool, error) {
	if !r.control.Adaptive() {
		return false, nil
	}
	complete := false
	beforeRate := r.control.RateMbps()
	for {
		select {
		case event := <-r.controlEvents:
			eventComplete, err := r.handleControlEvent(event)
			if err != nil {
				return complete, err
			}
			complete = complete || eventComplete
		default:
			r.applyControlAck()
			if r.control.RateMbps() != beforeRate {
				r.updateLaneRates()
			}
			return complete, nil
		}
	}
}

func (r *blastParallelSendControlRuntime) handleControlEvent(event blastParallelSendControlEvent) (bool, error) {
	if event.lane == nil || event.lane.batcher == nil {
		return false, nil
	}
	eventHistory, repairLane := r.controlEventHistory(event)
	if r.handleStripedStatsEvent(event, eventHistory) {
		return false, nil
	}
	eventComplete, _, err := handleBlastSendControlEvent(r.ctx, event.lane.batcher, event.lane.peer, eventHistory, r.stats, blastParallelRepairDeduperForEvent(r.repairDeduper, event.lane, repairLane), r.control, event.event)
	return eventComplete, err
}

func (r *blastParallelSendControlRuntime) controlEventHistory(event blastParallelSendControlEvent) (*blastRepairHistory, *blastParallelSendLane) {
	eventHistory := blastParallelRepairHistoryForLane(r.history, event.lane)
	repairLane := event.lane
	if !r.stripedBlast || (event.event.typ != PacketTypeRepairRequest && event.event.typ != PacketTypeStats) {
		return eventHistory, repairLane
	}
	stripeLane := blastParallelStripeLane(r.lanes, event.event.stripe)
	if stripeLane == nil || stripeLane.history == nil {
		return eventHistory, repairLane
	}
	return stripeLane.history, stripeLane
}

func (r *blastParallelSendControlRuntime) handleStripedStatsEvent(event blastParallelSendControlEvent, eventHistory *blastRepairHistory) bool {
	if !r.stripedBlast || event.event.typ != PacketTypeStats || eventHistory == nil || eventHistory == r.history {
		return false
	}
	sessionTracef("blast stats receive stripe=%d rx_payload_len=%d", event.event.stripe, len(event.event.payload))
	observeStripedBlastStatsEvent(r.stats, eventHistory, r.control, event.event)
	return true
}

func (r *blastParallelSendControlRuntime) observeReceiverBacklog() {
	if !r.control.Adaptive() || r.receiverBacklogBudget == 0 {
		return
	}
	r.setSentPayloadBytes()
	backlog := r.control.ReceiverBacklogBytes()
	if backlog <= r.receiverBacklogBudget {
		return
	}
	r.control.ObserveReceiverBacklogPressure(time.Now(), backlog, r.receiverBacklogBudget)
	r.updateLaneRates()
}

func (r *blastParallelSendControlRuntime) waitForReceiverBacklog() (bool, error) {
	return waitBlastReceiverBacklog(r.sendCtx, r.control, r.receiverBacklogBudget, r.setSentPayloadBytes, r.drainControlEvents, r.updateLaneRates, time.Now, nil)
}

func (r *blastParallelSendControlRuntime) addParallelPacket(packetHistory *blastRepairHistory, stripeID uint16, packetSeq uint64, packetOffset uint64, payload []byte) ([]byte, error) {
	for {
		wire, err := blastParallelDataPacket(packetHistory, r.runID, stripeID, packetSeq, packetOffset, payload, r.cfg)
		if !errors.Is(err, errStreamReplayWindowFull) {
			return wire, err
		}
		if err := r.waitForReplayWindow(packetHistory); err != nil {
			return nil, err
		}
	}
}

func (r *blastParallelSendControlRuntime) waitForReplayWindow(packetHistory *blastRepairHistory) error {
	r.setSentPayloadBytes()
	if complete, err := r.drainControlEvents(); err != nil {
		return err
	} else if complete {
		sessionTracef("blast repair complete received while parallel replay window was full run=%x", r.runID[:4])
	}
	r.observeReceiverBacklog()
	if complete, err := r.waitForReceiverBacklog(); err != nil {
		return err
	} else if complete {
		sessionTracef("blast repair complete received while parallel sender waited for receiver backlog run=%x", r.runID[:4])
	}
	if !replayWindowStillFull(packetHistory) {
		return nil
	}
	return r.sleepForReplayWindow(packetHistory)
}

func replayWindowStillFull(packetHistory *blastRepairHistory) bool {
	return packetHistory != nil &&
		packetHistory.streamReplay != nil &&
		packetHistory.streamReplay.RetainedBytes() >= packetHistory.streamReplay.MaxBytes()
}

func (r *blastParallelSendControlRuntime) sleepForReplayWindow(packetHistory *blastRepairHistory) error {
	waitStart := time.Now()
	if r.control.Adaptive() {
		r.control.ObserveReplayPressure(waitStart, packetHistory.streamReplay.RetainedBytes(), packetHistory.streamReplay.MaxBytes())
		r.updateLaneRates()
	}
	if err := sleepWithContext(r.ctx, blastRepairInterval); err != nil {
		return err
	}
	recordReplayWindowFullWait(r.stats, packetHistory.streamReplay.RetainedBytes(), time.Since(waitStart))
	return nil
}

type blastParallelSendReadLoop struct {
	ctx                    context.Context
	sendCtx                context.Context
	src                    io.Reader
	cfg                    SendConfig
	runID                  [16]byte
	stripedBlast           bool
	lanes                  []*blastParallelSendLane
	history                *blastRepairHistory
	fec                    *blastFECGroup
	control                *blastSendControl
	stats                  *TransferStats
	seq                    *uint64
	offset                 *uint64
	activeLanes            *int
	readBatch              []byte
	drainControlEvents     func() (bool, error)
	observeReceiverBacklog func()
	waitForReceiverBacklog func() (bool, error)
	updateLaneRates        func()
	addParallelPacket      func(*blastRepairHistory, uint16, uint64, uint64, []byte) ([]byte, error)
}

type blastParallelSendChunkTarget struct {
	lane          *blastParallelSendLane
	packetSeq     uint64
	packetHistory *blastRepairHistory
	stripeID      uint16
}

func (r *blastParallelSendReadLoop) run() error {
	for {
		if err := r.beforeRead(); err != nil {
			return err
		}
		n, readErr := r.src.Read(r.readBatch)
		if n > 0 {
			if err := r.queueReadPayloads(r.readBatch[:n]); err != nil {
				return err
			}
			if err := r.afterReadPayloads(); err != nil {
				return err
			}
		}
		if readErr != nil {
			return readErr
		}
	}
}

func (r *blastParallelSendReadLoop) beforeRead() error {
	if r.control == nil || !r.control.Adaptive() {
		return nil
	}
	r.observeReceiverBacklog()
	complete, err := r.waitForReceiverBacklog()
	if err != nil {
		return err
	}
	if complete {
		sessionTracef("blast repair complete received while parallel sender waited for receiver backlog before read run=%x", r.runID[:4])
	}
	return nil
}

func (r *blastParallelSendReadLoop) queueReadPayloads(data []byte) error {
	remaining := data
	for len(remaining) > 0 {
		payloadLen := min(r.cfg.ChunkSize, len(remaining))
		payload := remaining[:payloadLen]
		if err := r.queuePayload(payload); err != nil {
			return err
		}
		remaining = remaining[payloadLen:]
	}
	return nil
}

func (r *blastParallelSendReadLoop) queuePayload(payload []byte) error {
	target := r.nextChunkTarget()
	if err := r.enqueuePayload(target, payload); err != nil {
		return err
	}
	r.recordPayloadStats(len(payload))
	if err := r.recordPayloadFEC(target, payload); err != nil {
		return err
	}
	*r.seq++
	*r.offset += uint64(len(payload))
	return nil
}

func (r *blastParallelSendReadLoop) nextChunkTarget() blastParallelSendChunkTarget {
	laneIndex := int(*r.seq % uint64(*r.activeLanes))
	if r.stripedBlast {
		laneIndex = blastParallelLaneIndexForOffset(*r.offset, *r.activeLanes, r.cfg.ChunkSize)
	}
	lane := r.lanes[laneIndex]
	target := blastParallelSendChunkTarget{lane: lane, packetSeq: *r.seq, packetHistory: r.history}
	if r.stripedBlast {
		target.packetSeq = lane.nextSeq
		lane.nextSeq++
		target.packetHistory = lane.history
		target.stripeID = lane.stripeID
	}
	return target
}

func (r *blastParallelSendReadLoop) enqueuePayload(target blastParallelSendChunkTarget, payload []byte) error {
	if r.stripedBlast {
		return enqueueBlastParallelPayloadWithProgress(r.sendCtx, target.lane, target.packetHistory, target.stripeID, target.packetSeq, *r.offset, payload, func() error {
			return r.progressWhileQueued(target.packetHistory)
		})
	}
	wire, err := r.addParallelPacket(target.packetHistory, target.stripeID, target.packetSeq, *r.offset, payload)
	if err != nil {
		return err
	}
	return enqueueBlastParallelPacket(r.sendCtx, target.lane, wire)
}

func (r *blastParallelSendReadLoop) progressWhileQueued(packetHistory *blastRepairHistory) error {
	r.setQueuedProgressSentBytes()
	if err := r.drainQueuedProgressControl(); err != nil {
		return err
	}
	r.observeReceiverBacklog()
	if err := r.waitQueuedProgressReceiverBacklog(); err != nil {
		return err
	}
	return r.observeQueueReplayPressure(packetHistory)
}

func (r *blastParallelSendReadLoop) setQueuedProgressSentBytes() {
	if r.control != nil && r.control.Adaptive() {
		r.control.SetSentPayloadBytes(*r.offset)
	}
}

func (r *blastParallelSendReadLoop) drainQueuedProgressControl() error {
	complete, err := r.drainControlEvents()
	if err != nil {
		return err
	}
	if complete {
		sessionTracef("blast repair complete received while parallel lane queue was full run=%x", r.runID[:4])
	}
	return nil
}

func (r *blastParallelSendReadLoop) waitQueuedProgressReceiverBacklog() error {
	complete, err := r.waitForReceiverBacklog()
	if err != nil {
		return err
	}
	if complete {
		sessionTracef("blast repair complete received while parallel sender waited for receiver backlog during queue pressure run=%x", r.runID[:4])
	}
	return nil
}

func (r *blastParallelSendReadLoop) observeQueueReplayPressure(packetHistory *blastRepairHistory) error {
	if r.control == nil || !r.control.Adaptive() {
		return nil
	}
	observeBlastParallelQueueReplayPressure(r.control, packetHistory, time.Now())
	r.updateLaneRates()
	return nil
}

func (r *blastParallelSendReadLoop) recordPayloadStats(payloadLen int) {
	r.stats.PacketsSent++
	r.stats.BytesSent += int64(payloadLen)
}

func (r *blastParallelSendReadLoop) recordPayloadFEC(target blastParallelSendChunkTarget, payload []byte) error {
	if r.stripedBlast {
		return r.recordStripedPayloadFEC(target, payload)
	}
	return r.recordSharedPayloadFEC(payload)
}

func (r *blastParallelSendReadLoop) recordStripedPayloadFEC(target blastParallelSendChunkTarget, payload []byte) error {
	parity := target.lane.fec.Record(target.packetSeq, *r.offset, payload)
	if parity == nil {
		return nil
	}
	if err := enqueueBlastParallelPacket(r.sendCtx, target.lane, parity); err != nil {
		return err
	}
	r.stats.PacketsSent++
	return nil
}

func (r *blastParallelSendReadLoop) recordSharedPayloadFEC(payload []byte) error {
	parity := r.fec.Record(*r.seq, *r.offset, payload)
	if parity == nil {
		return nil
	}
	parityLane := r.lanes[int(*r.seq%uint64(*r.activeLanes))]
	if err := enqueueBlastParallelPacket(r.sendCtx, parityLane, parity); err != nil {
		return err
	}
	r.stats.PacketsSent++
	return nil
}

func (r *blastParallelSendReadLoop) afterReadPayloads() error {
	if r.control == nil || !r.control.Adaptive() {
		return nil
	}
	r.control.SetSentPayloadBytes(*r.offset)
	if complete, err := r.drainControlEvents(); err != nil {
		return err
	} else if complete {
		sessionTracef("blast repair complete received before parallel sender EOF run=%x", r.runID[:4])
	}
	r.observeReceiverBacklog()
	if complete, err := r.waitForReceiverBacklog(); err != nil {
		return err
	} else if complete {
		sessionTracef("blast repair complete received while parallel sender waited for receiver backlog after read run=%x", r.runID[:4])
	}
	return nil
}

func parallelLaneRateMbps(totalRateMbps int, lanes int) int {
	if totalRateMbps <= 0 || lanes <= 1 {
		return totalRateMbps
	}
	rate := totalRateMbps / lanes
	if rate < 1 {
		return 1
	}
	return rate
}

func blastParallelLaneBatchRateMbps(laneRateMbps int, ceilingMbps int, lanes int) int {
	if laneRateMbps < probeLargeChunkPacedBatchMinMbps {
		return laneRateMbps
	}
	if ceilingMbps <= 1500 || lanes <= 0 {
		return laneRateMbps
	}
	ceilingLaneRate := parallelLaneRateMbps(ceilingMbps, lanes)
	if ceilingLaneRate > laneRateMbps {
		return ceilingLaneRate
	}
	return laneRateMbps
}

func parallelActiveLanesForRate(rateMbps int, available int, striped bool) int {
	if available <= 0 {
		return 0
	}
	if striped {
		return available
	}
	target := available
	switch {
	case rateMbps <= parallelActiveLaneOneMaxMbps:
		target = 1
	case rateMbps <= parallelActiveLaneTwoMaxMbps:
		target = 2
	case rateMbps <= parallelActiveLaneFourMaxMbps:
		target = 4
	}
	if target > available {
		return available
	}
	return target
}

func parallelActiveLanesForConfig(rateMbps int, available int, striped bool, minActiveLanes int, maxActiveLanes int) int {
	active := parallelActiveLanesForRate(rateMbps, available, striped)
	if minActiveLanes > 0 && active < minActiveLanes {
		active = minActiveLanes
		if active > available {
			active = available
		}
	}
	if maxActiveLanes <= 0 || active <= maxActiveLanes {
		return active
	}
	if maxActiveLanes > available {
		return available
	}
	return maxActiveLanes
}

func shouldUseConnectedBatcherForParallelSend(batcher packetBatcher, laneCount int, cfg SendConfig) bool {
	if batcher == nil {
		return false
	}
	if batcher.MaxBatch() == 1 {
		return true
	}
	rateBasisMbps := parallelSendRateBasisMbps(cfg)
	if laneCount > 1 {
		return shouldUseConnectedBatcherForMultiLaneSend(batcher, laneCount, cfg, rateBasisMbps)
	}
	return rateBasisMbps > 0 && rateBasisMbps <= parallelActiveLaneOneMaxMbps
}

func parallelSendRateBasisMbps(cfg SendConfig) int {
	rateBasisMbps := cfg.RateCeilingMbps
	if cfg.RateMbps > 0 && (rateBasisMbps <= 0 || cfg.RateMbps < rateBasisMbps) {
		return cfg.RateMbps
	}
	return rateBasisMbps
}

func shouldUseConnectedBatcherForMultiLaneSend(batcher packetBatcher, laneCount int, cfg SendConfig, rateBasisMbps int) bool {
	activeLanes := laneCount
	if cfg.MaxActiveLanes > 0 && cfg.MaxActiveLanes < activeLanes {
		activeLanes = cfg.MaxActiveLanes
	}
	laneCeilingMbps := parallelLaneRateMbps(rateBasisMbps, activeLanes)
	caps := batcher.Capabilities()
	return caps.Kind == probeTransportBatched &&
		!caps.TXOffload &&
		!caps.RXQOverflow &&
		laneCeilingMbps > 0 &&
		laneCeilingMbps <= parallelActiveLaneOneMaxMbps
}

func blastParallelLaneIndexForOffset(offset uint64, lanes int, chunkSize int) int {
	if lanes <= 1 {
		return 0
	}
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}
	blockBytes := uint64(parallelBlastStripeBlockPackets * chunkSize)
	if blockBytes == 0 {
		return 0
	}
	return int((offset / blockBytes) % uint64(lanes))
}

func parallelBlastReadBatchSize(lanes int, chunkSize int) int {
	if lanes < 1 {
		lanes = 1
	}
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}
	return lanes * 128 * chunkSize
}

func blastParallelLaneQueueCapacity(batchLimit int, striped bool) int {
	if batchLimit <= 0 {
		batchLimit = 1
	}
	capacity := batchLimit * 2
	if striped {
		stripeCapacity := parallelBlastStripeBlockPackets * 2
		if capacity < stripeCapacity {
			capacity = stripeCapacity
		}
	}
	return capacity
}

func blastParallelDataPacket(history *blastRepairHistory, runID [16]byte, stripeID uint16, seq uint64, offset uint64, payload []byte, cfg SendConfig) ([]byte, error) {
	payloadLen := len(payload)
	if payloadLen == 0 {
		return nil, errors.New("empty blast payload")
	}
	if history != nil && history.streamReplay != nil {
		return history.streamReplay.AddDataPacket(stripeID, seq, offset, payload)
	}
	if cfg.PacketAEAD != nil {
		if err := history.Record(seq, payload); err != nil {
			return nil, err
		}
		return marshalBlastPayloadPacket(PacketTypeData, runID, stripeID, seq, offset, 0, 0, payload, cfg.PacketAEAD)
	}
	if cfg.RepairPayloads {
		wire, err := history.packetBufferForStripe(stripeID, seq, offset, payloadLen)
		if err != nil {
			return nil, err
		}
		copy(wire[headerLen:], payload)
		return wire[:headerLen+payloadLen], nil
	}
	wire := make([]byte, headerLen+payloadLen)
	encodePacketHeader(wire[:headerLen], PacketTypeData, runID, stripeID, seq, offset, 0, 0)
	copy(wire[headerLen:], payload)
	if err := history.Record(seq, payload); err != nil {
		return nil, err
	}
	return wire, nil
}

func enqueueBlastParallelPacket(ctx context.Context, lane *blastParallelSendLane, packet []byte) error {
	if lane == nil {
		return errors.New("nil blast parallel lane")
	}
	select {
	case lane.ch <- blastParallelSendItem{wire: packet}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func observeBlastParallelQueueReplayPressure(control *blastSendControl, history *blastRepairHistory, now time.Time) bool {
	if control == nil || !control.Adaptive() || history == nil || history.streamReplay == nil {
		return false
	}
	maxBytes := history.streamReplay.MaxBytes()
	if maxBytes == 0 {
		return false
	}
	retainedBytes := history.streamReplay.RetainedBytes()
	if retainedBytes < maxBytes {
		return false
	}
	before := control.RateMbps()
	control.ObserveReplayPressure(now, retainedBytes, maxBytes)
	return control.RateMbps() != before
}

func blastReceiverBacklogBudgetBytes(cfg SendConfig) uint64 {
	if cfg.RateCeilingMbps <= 0 && cfg.StreamReplayWindowBytes == 0 {
		return 0
	}
	budget := cfg.StreamReplayWindowBytes
	if budget == 0 {
		budget = defaultStreamReplayWindowBytes
	}
	const minBudget = 16 << 20
	if budget < minBudget {
		return minBudget
	}
	return budget
}

func waitBlastReceiverBacklog(ctx context.Context, control *blastSendControl, budgetBytes uint64, beforeDrain func(), drainControlEvents func() (bool, error), updateRates func(), now func() time.Time, wait func(context.Context) error) (bool, error) {
	if control == nil || !control.Adaptive() || budgetBytes == 0 {
		return false, nil
	}
	now = blastBacklogNowFunc(now)
	wait = blastBacklogWaitFunc(wait)
	return waitBlastReceiverBacklogLoop(ctx, control, budgetBytes, beforeDrain, drainControlEvents, updateRates, now, wait)
}

func blastBacklogNowFunc(now func() time.Time) func() time.Time {
	if now != nil {
		return now
	}
	return time.Now
}

func blastBacklogWaitFunc(wait func(context.Context) error) func(context.Context) error {
	if wait != nil {
		return wait
	}
	return func(ctx context.Context) error {
		return sleepWithContext(ctx, blastRepairInterval)
	}
}

func waitBlastReceiverBacklogLoop(ctx context.Context, control *blastSendControl, budgetBytes uint64, beforeDrain func(), drainControlEvents func() (bool, error), updateRates func(), now func() time.Time, wait func(context.Context) error) (bool, error) {
	complete := false
	for {
		eventComplete, err := drainBlastReceiverBacklogControl(beforeDrain, drainControlEvents)
		if err != nil {
			return complete, err
		}
		complete = complete || eventComplete
		if !blastReceiverBacklogExceeded(control, budgetBytes) {
			return complete, nil
		}
		backlog := control.ReceiverBacklogBytes()
		control.ObserveReceiverBacklogPressure(now(), backlog, budgetBytes)
		if updateRates != nil {
			updateRates()
		}
		if err := wait(ctx); err != nil {
			return complete, err
		}
	}
}

func drainBlastReceiverBacklogControl(beforeDrain func(), drainControlEvents func() (bool, error)) (bool, error) {
	if beforeDrain != nil {
		beforeDrain()
	}
	if drainControlEvents == nil {
		return false, nil
	}
	return drainControlEvents()
}

func blastReceiverBacklogExceeded(control *blastSendControl, budgetBytes uint64) bool {
	return control.ReceiverStatsSeen() && control.ReceiverBacklogBytes() > budgetBytes
}

func waitBlastParallelSendLanes(ctx context.Context, wg *sync.WaitGroup, control *blastSendControl, beforeDrain func(), drainControlEvents func() (bool, error)) (bool, error) {
	if wg == nil {
		return false, nil
	}
	if control == nil || !control.Adaptive() || drainControlEvents == nil {
		wg.Wait()
		return false, nil
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	complete := false
	for {
		if blastParallelSendLanesDone(done) {
			return complete, nil
		}

		eventComplete, err := drainBlastReceiverBacklogControl(beforeDrain, drainControlEvents)
		if err != nil {
			return complete, err
		}
		complete = complete || eventComplete

		if err := waitBlastParallelSendLanePoll(ctx, done); err != nil {
			return complete, err
		}
	}
}

func blastParallelSendLanesDone(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func waitBlastParallelSendLanePoll(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(blastRepairInterval):
		return nil
	}
}

func enqueueBlastParallelPayloadWithProgress(ctx context.Context, lane *blastParallelSendLane, history *blastRepairHistory, stripeID uint16, seq uint64, offset uint64, payload []byte, onWait func() error) error {
	if lane == nil {
		return errors.New("nil blast parallel lane")
	}
	if len(payload) == 0 {
		return errors.New("empty blast payload")
	}
	item := newBlastParallelSendItem(lane, history, stripeID, seq, offset, payload)
	for {
		if tryEnqueueBlastParallelSendItem(lane, item) {
			return nil
		}
		if err := runBlastParallelEnqueueWait(onWait); err != nil {
			lane.releasePayload(item.payload)
			return err
		}
		queued, err := waitBlastParallelEnqueueRetry(ctx, lane, item)
		if err != nil {
			lane.releasePayload(item.payload)
			return err
		}
		if queued {
			return nil
		}
	}
}

func newBlastParallelSendItem(lane *blastParallelSendLane, history *blastRepairHistory, stripeID uint16, seq uint64, offset uint64, payload []byte) blastParallelSendItem {
	return blastParallelSendItem{
		payload:  lane.copyPayload(payload),
		history:  history,
		stripeID: stripeID,
		seq:      seq,
		offset:   offset,
	}
}

func tryEnqueueBlastParallelSendItem(lane *blastParallelSendLane, item blastParallelSendItem) bool {
	select {
	case lane.ch <- item:
		return true
	default:
		return false
	}
}

func runBlastParallelEnqueueWait(onWait func() error) error {
	if onWait == nil {
		return nil
	}
	return onWait()
}

func waitBlastParallelEnqueueRetry(ctx context.Context, lane *blastParallelSendLane, item blastParallelSendItem) (bool, error) {
	timer := time.NewTimer(blastRepairInterval)
	defer stopTimer(timer)
	select {
	case lane.ch <- item:
		return true, nil
	case <-ctx.Done():
		return false, ctx.Err()
	case <-timer.C:
		return false, nil
	}
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func encodeBlastParallelSendItem(ctx context.Context, lane *blastParallelSendLane, item blastParallelSendItem) ([]byte, error) {
	if len(item.wire) > 0 {
		return item.wire, nil
	}
	if len(item.payload) == 0 {
		return nil, errors.New("empty blast payload")
	}
	if lane == nil {
		return nil, errors.New("nil blast parallel lane")
	}
	history := blastParallelSendItemHistory(lane, item)
	cfg := blastParallelSendItemConfig(lane)
	for {
		wire, err := blastParallelDataPacket(history, lane.runID, item.stripeID, item.seq, item.offset, item.payload, cfg)
		if !errors.Is(err, errStreamReplayWindowFull) {
			return wire, err
		}
		if !blastParallelSendItemReplayFull(history) {
			continue
		}
		if err := sleepWithContext(ctx, blastRepairInterval); err != nil {
			return nil, err
		}
	}
}

func blastParallelSendItemHistory(lane *blastParallelSendLane, item blastParallelSendItem) *blastRepairHistory {
	if item.history != nil {
		return item.history
	}
	return lane.history
}

func blastParallelSendItemConfig(lane *blastParallelSendLane) SendConfig {
	cfg := lane.sendConfig
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = defaultChunkSize
	}
	return cfg
}

func blastParallelSendItemReplayFull(history *blastRepairHistory) bool {
	return history != nil &&
		history.streamReplay != nil &&
		history.streamReplay.RetainedBytes() >= history.streamReplay.MaxBytes()
}

func runBlastParallelSendLane(ctx context.Context, lane *blastParallelSendLane) error {
	if lane == nil || lane.batcher == nil {
		return errors.New("nil blast parallel lane")
	}
	lane.batchLimit = normalizedBlastParallelLaneBatchLimit(lane)
	flusher := newBlastParallelLaneFlusher(ctx, lane)
	for {
		select {
		case item, ok := <-lane.ch:
			if !ok {
				return flusher.flush()
			}
			if err := flusher.add(item); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func normalizedBlastParallelLaneBatchLimit(lane *blastParallelSendLane) int {
	if lane.batchLimit > 0 {
		return lane.batchLimit
	}
	if limit := lane.batcher.MaxBatch(); limit > 0 {
		return limit
	}
	return 1
}

type blastParallelLaneFlusher struct {
	ctx     context.Context
	lane    *blastParallelSendLane
	pending [][]byte
}

func newBlastParallelLaneFlusher(ctx context.Context, lane *blastParallelSendLane) *blastParallelLaneFlusher {
	return &blastParallelLaneFlusher{
		ctx:     ctx,
		lane:    lane,
		pending: make([][]byte, 0, lane.batchLimit),
	}
}

func (f *blastParallelLaneFlusher) add(item blastParallelSendItem) error {
	packet, err := encodeBlastParallelSendItem(f.ctx, f.lane, item)
	f.lane.releasePayload(item.payload)
	if err != nil {
		return err
	}
	f.pending = append(f.pending, packet)
	if len(f.pending) >= f.lane.batchLimit {
		return f.flush()
	}
	return nil
}

func (f *blastParallelLaneFlusher) flush() error {
	if len(f.pending) == 0 {
		return nil
	}
	defer f.reset()
	if err := writeBlastBatch(f.ctx, f.lane.batcher, f.lane.peer, f.pending); err != nil {
		return err
	}
	return f.pace()
}

func (f *blastParallelLaneFlusher) reset() {
	f.pending = f.pending[:0]
}

func (f *blastParallelLaneFlusher) pace() error {
	rateMbps := f.lane.currentRateMbps()
	if rateMbps <= 0 {
		return nil
	}
	if f.lane.pacer == nil {
		f.lane.pacer = newBlastPacer(time.Now())
	}
	return f.lane.pacer.Pace(f.ctx, f.payloadBytes(), rateMbps)
}

func (f *blastParallelLaneFlusher) payloadBytes() uint64 {
	var batchPayloadBytes uint64
	for _, packet := range f.pending {
		batchPayloadBytes += blastParallelPaceBytes(packet)
	}
	return batchPayloadBytes
}

func blastParallelPaceBytes(packet []byte) uint64 {
	if len(packet) <= headerLen {
		return 0
	}
	return uint64(len(packet) - headerLen)
}

func writeBlastParallelPackets(ctx context.Context, lanes []*blastParallelSendLane, packets [][]byte) error {
	for _, packet := range packets {
		if len(packet) < headerLen {
			continue
		}
		_, _, _, seq, _, ok := decodeBlastPacketFull(packet)
		if !ok {
			continue
		}
		lane := lanes[int(seq%uint64(len(lanes)))]
		if err := writeBlastBatch(ctx, lane.batcher, lane.peer, [][]byte{packet}); err != nil {
			return err
		}
	}
	return nil
}

func writeBlastDoneAllBestEffort(ctx context.Context, lanes []*blastParallelSendLane, runID [16]byte, seq uint64, offset uint64, striped bool, stats *TransferStats) {
	for _, lane := range lanes {
		doneSeq := seq
		stripeID := uint16(0)
		if striped {
			doneSeq = lane.nextSeq
			stripeID = lane.stripeID
		}
		donePacket := make([]byte, headerLen)
		if striped && lane != nil && lane.history != nil && lane.history.streamReplay != nil {
			if replayPacket, err := lane.history.streamReplay.AddPacket(PacketTypeDone, stripeID, doneSeq, offset, nil); err == nil {
				donePacket = replayPacket
			} else {
				sessionTracef("blast done replay store ignored stripe=%d seq=%d err=%v", stripeID, doneSeq, err)
				encodePacketHeader(donePacket, PacketTypeDone, runID, stripeID, doneSeq, offset, 0, 0)
			}
		} else {
			encodePacketHeader(donePacket, PacketTypeDone, runID, stripeID, doneSeq, offset, 0, 0)
		}
		writeBlastDoneBestEffort(ctx, lane.batcher, lane.peer, donePacket)
		if stats != nil {
			stats.PacketsSent++
		}
	}
}

type blastParallelRepairEvent struct {
	lane    *blastParallelSendLane
	typ     PacketType
	stripe  uint16
	payload []byte
	err     error
}

func serveBlastRepairsParallel(ctx context.Context, lanes []*blastParallelSendLane, runID [16]byte, history *blastRepairHistory, stats TransferStats, resendTerminal func()) (TransferStats, error) {
	if len(lanes) == 0 {
		stats.markComplete(time.Now())
		return stats, nil
	}
	repairCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	events := make(chan blastParallelRepairEvent, len(lanes)*2)
	waitReaders := startBlastParallelRepairReaders(repairCtx, lanes, runID, events)
	defer waitReaders()
	state := newBlastParallelRepairServeState()
	defer state.Close()
	return state.run(ctx, cancel, lanes, history, stats, resendTerminal, events)
}

func startBlastParallelRepairReaders(ctx context.Context, lanes []*blastParallelSendLane, runID [16]byte, events chan<- blastParallelRepairEvent) func() {
	var wg sync.WaitGroup
	for _, lane := range lanes {
		wg.Add(1)
		go func(lane *blastParallelSendLane) {
			defer wg.Done()
			readBlastParallelRepairEvents(ctx, lane, runID, events)
		}(lane)
	}
	return wg.Wait
}

type blastParallelRepairRequestKey struct {
	stripe  uint16
	payload string
}

type blastParallelRepairServeState struct {
	quietTimer           *time.Timer
	doneTicker           *time.Ticker
	recentRepairRequests map[blastParallelRepairRequestKey]time.Time
	deduper              *blastRepairDeduper
	quietDeadline        time.Time
	hadRepair            bool
}

func newBlastParallelRepairServeState() *blastParallelRepairServeState {
	return &blastParallelRepairServeState{
		quietTimer:           time.NewTimer(blastRepairQuietGrace),
		doneTicker:           time.NewTicker(blastDoneInterval),
		recentRepairRequests: make(map[blastParallelRepairRequestKey]time.Time),
		deduper:              newBlastRepairDeduper(),
		quietDeadline:        time.Now().Add(blastRepairQuietGrace),
	}
}

func (s *blastParallelRepairServeState) Close() {
	s.quietTimer.Stop()
	s.doneTicker.Stop()
}

func (s *blastParallelRepairServeState) run(ctx context.Context, cancel context.CancelFunc, lanes []*blastParallelSendLane, history *blastRepairHistory, stats TransferStats, resendTerminal func(), events <-chan blastParallelRepairEvent) (TransferStats, error) {
	for {
		select {
		case <-ctx.Done():
			return TransferStats{}, ctx.Err()
		case <-s.quietTimer.C:
			return s.complete(stats, cancel), nil
		case <-s.doneTicker.C:
			resendBlastTerminal(resendTerminal)
		case event := <-events:
			nextStats, done, err := s.handleEvent(ctx, cancel, lanes, history, stats, event)
			if err != nil || done {
				return nextStats, err
			}
			stats = nextStats
		}
	}
}

func resendBlastTerminal(resendTerminal func()) {
	if resendTerminal != nil {
		resendTerminal()
	}
}

func (s *blastParallelRepairServeState) complete(stats TransferStats, cancel context.CancelFunc) TransferStats {
	stats.markComplete(time.Now())
	cancel()
	return stats
}

func (s *blastParallelRepairServeState) handleEvent(ctx context.Context, cancel context.CancelFunc, lanes []*blastParallelSendLane, history *blastRepairHistory, stats TransferStats, event blastParallelRepairEvent) (TransferStats, bool, error) {
	if event.err != nil {
		return TransferStats{}, true, event.err
	}
	switch event.typ {
	case PacketTypeRepairComplete:
		return s.complete(stats, cancel), true, nil
	case PacketTypeRepairRequest:
		return s.handleRepairRequest(ctx, cancel, lanes, history, stats, event)
	default:
		return stats, false, nil
	}
}

func (s *blastParallelRepairServeState) handleRepairRequest(ctx context.Context, cancel context.CancelFunc, lanes []*blastParallelSendLane, history *blastRepairHistory, stats TransferStats, event blastParallelRepairEvent) (TransferStats, bool, error) {
	now := time.Now()
	if now.After(s.quietDeadline) {
		return s.completeAt(stats, cancel, now), true, nil
	}
	key := blastParallelRepairRequestKey{stripe: event.stripe, payload: string(event.payload)}
	if s.ignoreRecentRepairRequest(key, now) {
		return stats, false, nil
	}
	repairHistory, repairLane := blastParallelRepairEventHistory(lanes, history, event)
	s.hadRepair = s.hadRepair || repairHistory.CanRepair()
	retransmits, err := sendBlastRepairs(ctx, event.lane.batcher, event.lane.peer, repairHistory, event.payload, &stats, blastParallelRepairDeduperForEvent(s.deduper, event.lane, repairLane), now)
	if err != nil {
		return TransferStats{}, true, err
	}
	s.afterRepairRequest(key, retransmits, blastRepairHistoryChunkSize(repairHistory))
	if retransmits <= 0 && time.Now().After(s.quietDeadline) {
		return s.complete(stats, cancel), true, nil
	}
	return stats, false, nil
}

func (s *blastParallelRepairServeState) completeAt(stats TransferStats, cancel context.CancelFunc, now time.Time) TransferStats {
	stats.markComplete(now)
	cancel()
	return stats
}

func (s *blastParallelRepairServeState) ignoreRecentRepairRequest(key blastParallelRepairRequestKey, now time.Time) bool {
	if ignoreUntil, ok := s.recentRepairRequests[key]; ok && now.Before(ignoreUntil) {
		return true
	}
	s.recentRepairRequests[key] = now
	return false
}

func (s *blastParallelRepairServeState) afterRepairRequest(key blastParallelRepairRequestKey, retransmits int, chunkSize int) {
	s.resetQuiet(retransmits, chunkSize)
	if retransmits > 0 {
		s.recentRepairRequests[key] = s.quietDeadline
	}
}

func (s *blastParallelRepairServeState) resetQuiet(retransmits int, chunkSize int) {
	if retransmits <= 0 {
		return
	}
	if !s.quietTimer.Stop() {
		select {
		case <-s.quietTimer.C:
		default:
		}
	}
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}
	quietFor := blastRepairQuietGraceForRepairBytes(int64(retransmits * chunkSize))
	s.quietDeadline = time.Now().Add(quietFor)
	s.quietTimer.Reset(quietFor)
}

func blastParallelRepairEventHistory(lanes []*blastParallelSendLane, history *blastRepairHistory, event blastParallelRepairEvent) (*blastRepairHistory, *blastParallelSendLane) {
	repairHistory := history
	repairLane := event.lane
	if stripeLane := blastParallelStripeLane(lanes, event.stripe); stripeLane != nil && stripeLane.history != nil {
		return stripeLane.history, stripeLane
	}
	if event.lane != nil && event.lane.history != nil && event.stripe == event.lane.stripeID {
		repairHistory = event.lane.history
	}
	return repairHistory, repairLane
}

func blastRepairHistoryChunkSize(history *blastRepairHistory) int {
	if history == nil {
		return defaultChunkSize
	}
	return history.chunkSize
}

func blastRepairDeduperForLane(global *blastRepairDeduper, lane *blastParallelSendLane) *blastRepairDeduper {
	if lane == nil || lane.history == nil {
		return global
	}
	if lane.deduper == nil {
		lane.deduper = newBlastRepairDeduper()
	}
	return lane.deduper
}

func blastParallelRepairDeduperForEvent(global *blastRepairDeduper, eventLane *blastParallelSendLane, repairLane *blastParallelSendLane) *blastRepairDeduper {
	if repairLane != nil && repairLane.history != nil {
		return blastRepairDeduperForLane(global, repairLane)
	}
	return blastRepairDeduperForLane(global, eventLane)
}

func blastParallelStripeLane(lanes []*blastParallelSendLane, stripeID uint16) *blastParallelSendLane {
	for _, lane := range lanes {
		if lane != nil && lane.stripeID == stripeID {
			return lane
		}
	}
	if int(stripeID) < len(lanes) {
		return lanes[stripeID]
	}
	return nil
}

func readBlastParallelRepairEvents(ctx context.Context, lane *blastParallelSendLane, runID [16]byte, events chan<- blastParallelRepairEvent) {
	if lane == nil || lane.batcher == nil {
		return
	}
	readBufs := newBlastBatchReadBuffers(lane.batcher.MaxBatch())
	for {
		n, err := lane.batcher.ReadBatch(ctx, blastRepairInterval, readBufs)
		now := time.Now()
		if err != nil {
			if stop := handleBlastParallelRepairReadError(ctx, events, err, now); stop {
				return
			}
			continue
		}
		if !emitBlastParallelRepairEvents(ctx, lane, runID, readBufs[:n], events) {
			return
		}
	}
}

func handleBlastParallelRepairReadError(ctx context.Context, events chan<- blastParallelRepairEvent, err error, _ time.Time) bool {
	if ctx.Err() != nil {
		return true
	}
	if isNetTimeout(err) {
		return false
	}
	if !errors.Is(err, net.ErrClosed) {
		return false
	}
	select {
	case events <- blastParallelRepairEvent{err: err}:
	case <-ctx.Done():
	}
	return true
}

func emitBlastParallelRepairEvents(ctx context.Context, lane *blastParallelSendLane, runID [16]byte, readBufs []batchReadBuffer, events chan<- blastParallelRepairEvent) bool {
	for i := range readBufs {
		event, ok := decodeBlastParallelRepairEvent(lane, readBufs[i], runID)
		if !ok {
			continue
		}
		select {
		case events <- event:
		case <-ctx.Done():
			return false
		}
	}
	return true
}

func decodeBlastParallelRepairEvent(lane *blastParallelSendLane, buf batchReadBuffer, runID [16]byte) (blastParallelRepairEvent, bool) {
	packetType, payload, packetRunID, _, _, ok := decodeBlastPacketFull(buf.Bytes[:buf.N])
	if !ok || packetRunID != runID {
		return blastParallelRepairEvent{}, false
	}
	if !isBlastParallelRepairEventPacket(packetType) {
		return blastParallelRepairEvent{}, false
	}
	return blastParallelRepairEvent{
		lane:    lane,
		typ:     packetType,
		stripe:  binary.BigEndian.Uint16(buf.Bytes[2:4]),
		payload: append([]byte(nil), payload...),
	}, true
}

func isBlastParallelRepairEventPacket(packetType PacketType) bool {
	return packetType == PacketTypeRepairComplete || packetType == PacketTypeRepairRequest
}

type blastFECGroup struct {
	runID      [16]byte
	stripeID   uint16
	chunkSize  int
	groupSize  int
	packetAEAD cipher.AEAD
	startSeq   uint64
	startOff   uint64
	count      int
	parity     []byte
	seenPacket bool
}

func newBlastFECGroup(runID [16]byte, chunkSize int, groupSize int, packetAEAD cipher.AEAD) *blastFECGroup {
	return newBlastFECGroupForStripe(runID, 0, chunkSize, groupSize, packetAEAD)
}

func newBlastFECGroupForStripe(runID [16]byte, stripeID uint16, chunkSize int, groupSize int, packetAEAD cipher.AEAD) *blastFECGroup {
	if chunkSize <= 0 || groupSize <= 1 {
		return nil
	}
	return &blastFECGroup{
		runID:      runID,
		stripeID:   stripeID,
		chunkSize:  chunkSize,
		groupSize:  groupSize,
		packetAEAD: packetAEAD,
		parity:     make([]byte, chunkSize),
	}
}

func (g *blastFECGroup) Record(seq uint64, offset uint64, payload []byte) []byte {
	if g == nil || len(payload) == 0 {
		return nil
	}
	if !g.seenPacket {
		g.startSeq = seq
		g.startOff = offset
		g.seenPacket = true
	}
	for i := range payload {
		g.parity[i] ^= payload[i]
	}
	g.count++
	if g.count < g.groupSize {
		return nil
	}
	return g.flush()
}

func (g *blastFECGroup) Flush() []byte {
	if g == nil || !g.seenPacket || g.count == 0 {
		return nil
	}
	return g.flush()
}

func (g *blastFECGroup) flush() []byte {
	wire, _ := marshalBlastPayloadPacket(PacketTypeParity, g.runID, g.stripeID, g.startSeq, g.startOff, uint64(g.count), 0, g.parity, g.packetAEAD)
	for i := range g.parity {
		g.parity[i] = 0
	}
	g.count = 0
	g.seenPacket = false
	return wire
}

func writeBlastDoneBestEffort(ctx context.Context, batcher packetBatcher, peer net.Addr, donePacket []byte) {
	if _, err := batcher.WriteBatch(ctx, peer, [][]byte{donePacket}); err != nil {
		sessionTracef("blast done write ignored peer=%s err=%v", peer, err)
	}
}

func writeBlastBatch(ctx context.Context, batcher packetBatcher, peer net.Addr, packets [][]byte) error {
	pending := packets
	for len(pending) > 0 {
		n, err := batcher.WriteBatch(ctx, peer, pending)
		if n > 0 {
			pending = pending[n:]
		}
		if err == nil {
			continue
		}
		if !isNoBufferSpace(err) {
			return err
		}
		if err := sleepWithContext(ctx, 250*time.Microsecond); err != nil {
			return err
		}
	}
	return nil
}

func isNoBufferSpace(err error) bool {
	return errors.Is(err, syscall.ENOBUFS)
}

func preferInformativeResultError(current, candidate error) error {
	if current == nil {
		return candidate
	}
	if candidate == nil {
		return current
	}
	if fallbackResultError(current) && !fallbackResultError(candidate) {
		return candidate
	}
	return current
}

func fallbackResultError(err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed)
}

type blastRepairHistory struct {
	runID           [16]byte
	chunkSize       int
	mu              sync.RWMutex
	totalBytes      uint64
	packets         uint64
	complete        bool
	retainPayloads  bool
	payloadCapacity uint64
	payloadSlabs    [][]byte
	packetCapacity  uint64
	packetLens      []int
	packetSlabs     [][]byte
	packetAEAD      cipher.AEAD
	streamReplay    *streamReplayWindow
}

func newBlastRepairHistory(runID [16]byte, chunkSize int, retainPayloads bool, packetAEAD cipher.AEAD) (*blastRepairHistory, error) {
	return &blastRepairHistory{runID: runID, chunkSize: chunkSize, retainPayloads: retainPayloads, packetAEAD: packetAEAD}, nil
}

func maxInt() int {
	return int(^uint(0) >> 1)
}

func (h *blastRepairHistory) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.payloadSlabs = nil
	h.packetLens = nil
	h.packetSlabs = nil
	return nil
}

func (h *blastRepairHistory) Record(seq uint64, payload []byte) error {
	if h == nil || !h.retainPayloads || len(payload) == 0 {
		return nil
	}
	offset := seq * uint64(h.chunkSize)
	end := offset + uint64(len(payload))
	if end < offset || end > uint64(maxInt()) {
		return errors.New("blast repair payload too large")
	}
	if err := h.ensurePayloadCapacity(end); err != nil {
		return err
	}
	h.copyPayloadAt(offset, payload)
	return nil
}

func (h *blastRepairHistory) MarkComplete(totalBytes uint64, packets uint64) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.totalBytes = totalBytes
	h.packets = packets
	h.complete = true
}

func (h *blastRepairHistory) Complete() bool {
	if h == nil {
		return true
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.complete
}

func (h *blastRepairHistory) TotalBytes() int64 {
	if h == nil {
		return 0
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.totalBytes > uint64(maxInt()) {
		return int64(maxInt())
	}
	return int64(h.totalBytes)
}

func (h *blastRepairHistory) CanRepair() bool {
	if h == nil {
		return false
	}
	if h.streamReplay != nil {
		return true
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.retainPayloads
}

func (h *blastRepairHistory) AckFloor(seq uint64) {
	if h == nil || h.streamReplay == nil {
		return
	}
	h.streamReplay.AckFloor(seq)
}

func (h *blastRepairHistory) MaxReplayBytes() uint64 {
	if h == nil || h.streamReplay == nil {
		return 0
	}
	return h.streamReplay.MaxRetainedBytes()
}

func (h *blastRepairHistory) ensurePayloadCapacity(end uint64) error {
	if h == nil || end == 0 {
		return nil
	}
	if end <= h.payloadCapacity {
		return nil
	}
	if end > uint64(maxInt()) {
		return errors.New("blast repair payload too large")
	}
	needSlabs := int((end + uint64(blastRepairMemorySlab) - 1) / uint64(blastRepairMemorySlab))
	for len(h.payloadSlabs) < needSlabs {
		h.payloadSlabs = append(h.payloadSlabs, make([]byte, blastRepairMemorySlab))
	}
	h.payloadCapacity = uint64(len(h.payloadSlabs)) * uint64(blastRepairMemorySlab)
	return nil
}

func (h *blastRepairHistory) copyPayloadAt(offset uint64, payload []byte) {
	for len(payload) > 0 {
		slabIndex := int(offset / uint64(blastRepairMemorySlab))
		slabOffset := int(offset % uint64(blastRepairMemorySlab))
		n := copy(h.payloadSlabs[slabIndex][slabOffset:], payload)
		payload = payload[n:]
		offset += uint64(n)
	}
}

func (h *blastRepairHistory) Flush() error {
	return nil
}

func (h *blastRepairHistory) packet(seq uint64) []byte {
	if h == nil {
		return nil
	}
	if h.streamReplay != nil {
		return h.streamReplay.Packet(seq)
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.packetLocked(seq)
}

func (h *blastRepairHistory) packetLocked(seq uint64) []byte {
	if packet := h.bufferedPacketLocked(seq); packet != nil {
		return packet
	}
	offset, payloadLen, ok := h.packetPayloadRangeLocked(seq)
	if !ok {
		return nil
	}
	payload, ok := h.packetPayloadLocked(offset, payloadLen)
	if !ok {
		return nil
	}
	wire, err := marshalBlastPayloadPacket(PacketTypeData, h.runID, 0, seq, offset, 0, 0, payload, h.packetAEAD)
	if err != nil {
		return nil
	}
	return wire
}

func (h *blastRepairHistory) bufferedPacketLocked(seq uint64) []byte {
	if h.chunkSize <= 0 || len(h.packetSlabs) == 0 {
		return nil
	}
	return h.packetFromBufferLocked(seq)
}

func (h *blastRepairHistory) packetPayloadRangeLocked(seq uint64) (uint64, int, bool) {
	if h.chunkSize <= 0 || h.packets == 0 || seq >= h.packets {
		return 0, 0, false
	}
	offset := seq * uint64(h.chunkSize)
	if offset >= h.totalBytes {
		return 0, 0, false
	}
	payloadLen := h.chunkSize
	if remaining := h.totalBytes - offset; remaining < uint64(payloadLen) {
		payloadLen = int(remaining)
	}
	return offset, payloadLen, true
}

func (h *blastRepairHistory) packetPayloadLocked(offset uint64, payloadLen int) ([]byte, bool) {
	if !h.retainPayloads && payloadLen > 0 {
		return nil, false
	}
	if !h.hasPayloadRange(offset, payloadLen) {
		return nil, false
	}
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		h.readPayloadAt(payload, offset)
	}
	return payload, true
}

func (h *blastRepairHistory) packetBuffer(seq uint64, offset uint64, payloadLen int) ([]byte, error) {
	return h.packetBufferForStripe(0, seq, offset, payloadLen)
}

func (h *blastRepairHistory) packetBufferForStripe(stripeID uint16, seq uint64, offset uint64, payloadLen int) ([]byte, error) {
	if err := h.validatePacketBufferRequest(payloadLen); err != nil {
		return nil, err
	}
	if err := h.ensurePacketBufferForSeq(seq); err != nil {
		return nil, err
	}
	slabIndex, slabOffset := h.packetLocation(seq)
	packet := h.packetSlabs[slabIndex][slabOffset : slabOffset+headerLen+payloadLen]
	encodePacketHeader(packet[:headerLen], PacketTypeData, h.runID, stripeID, seq, offset, 0, 0)
	h.packetLens[seq] = headerLen + payloadLen
	return packet, nil
}

func (h *blastRepairHistory) validatePacketBufferRequest(payloadLen int) error {
	switch {
	case h == nil || !h.retainPayloads || h.chunkSize <= 0 || payloadLen <= 0:
		return errors.New("invalid blast repair packet buffer")
	case h.packetAEAD != nil:
		return errors.New("encrypted blast repair packets require retained payload assembly")
	case payloadLen > h.chunkSize:
		return errors.New("blast repair packet payload too large")
	default:
		return nil
	}
}

func (h *blastRepairHistory) ensurePacketBufferForSeq(seq uint64) error {
	if err := h.ensurePacketCapacityForSeq(seq); err != nil {
		return err
	}
	h.ensurePacketLensForSeq(seq)
	return nil
}

func (h *blastRepairHistory) ensurePacketLensForSeq(seq uint64) {
	if seq < uint64(len(h.packetLens)) {
		return
	}
	nextLen := len(h.packetLens)
	if nextLen == 0 {
		nextLen = 1
	}
	for seq >= uint64(nextLen) {
		nextLen *= 2
	}
	grown := make([]int, nextLen)
	copy(grown, h.packetLens)
	h.packetLens = grown
}

func (h *blastRepairHistory) packetFromBufferLocked(seq uint64) []byte {
	if seq >= uint64(len(h.packetLens)) {
		return nil
	}
	packetLen := h.packetLens[seq]
	if packetLen <= headerLen {
		return nil
	}
	slabIndex, slabOffset := h.packetLocation(seq)
	if slabIndex >= len(h.packetSlabs) || slabOffset+packetLen > len(h.packetSlabs[slabIndex]) {
		return nil
	}
	return h.packetSlabs[slabIndex][slabOffset : slabOffset+packetLen]
}

func (h *blastRepairHistory) packetStride() int {
	overhead := 0
	if h.packetAEAD != nil {
		overhead = h.packetAEAD.Overhead()
	}
	return headerLen + h.chunkSize + overhead
}

func (h *blastRepairHistory) ensurePacketCapacityForSeq(seq uint64) error {
	slabIndex, _ := h.packetLocation(seq)
	for len(h.packetSlabs) <= slabIndex {
		h.packetSlabs = append(h.packetSlabs, make([]byte, blastRepairMemorySlab))
	}
	h.packetCapacity = uint64(len(h.packetSlabs)) * uint64(blastRepairMemorySlab)
	return nil
}

func (h *blastRepairHistory) packetLocation(seq uint64) (int, int) {
	stride := h.packetStride()
	packetsPerSlab := blastRepairMemorySlab / stride
	if packetsPerSlab < 1 {
		packetsPerSlab = 1
	}
	return int(seq / uint64(packetsPerSlab)), int(seq%uint64(packetsPerSlab)) * stride
}

func (h *blastRepairHistory) tailPackets(bytesBudget int) [][]byte {
	if h == nil || bytesBudget <= 0 || h.chunkSize <= 0 {
		return nil
	}
	packets, retainPayloads, streamReplay := h.tailPacketSnapshot()
	if !retainPayloads && streamReplay == nil || packets == 0 {
		return nil
	}
	count := h.tailPacketCount(bytesBudget, packets)
	if count <= 0 {
		return nil
	}
	start := packets - uint64(count)
	out := make([][]byte, 0, count)
	for seq := start; seq < packets; seq++ {
		if packet := h.tailPacket(seq, streamReplay); len(packet) > 0 {
			out = append(out, packet)
		}
	}
	return out
}

func (h *blastRepairHistory) tailPacketSnapshot() (uint64, bool, *streamReplayWindow) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.packets, h.retainPayloads, h.streamReplay
}

func (h *blastRepairHistory) tailPacketCount(bytesBudget int, packets uint64) int {
	count := (bytesBudget + h.chunkSize - 1) / h.chunkSize
	if uint64(count) > packets {
		return int(packets)
	}
	return count
}

func (h *blastRepairHistory) tailPacket(seq uint64, streamReplay *streamReplayWindow) []byte {
	packet := h.packet(seq)
	if len(packet) == 0 && streamReplay != nil {
		return streamReplay.Packet(seq)
	}
	return packet
}

func (h *blastRepairHistory) hasPayloadRange(offset uint64, payloadLen int) bool {
	if payloadLen <= 0 {
		return true
	}
	end := offset + uint64(payloadLen)
	if end < offset {
		return false
	}
	needSlabs := int((end + uint64(blastRepairMemorySlab) - 1) / uint64(blastRepairMemorySlab))
	return needSlabs <= len(h.payloadSlabs)
}

func (h *blastRepairHistory) readPayloadAt(dst []byte, offset uint64) {
	for len(dst) > 0 {
		slabIndex := int(offset / uint64(blastRepairMemorySlab))
		slabOffset := int(offset % uint64(blastRepairMemorySlab))
		n := copy(dst, h.payloadSlabs[slabIndex][slabOffset:])
		dst = dst[n:]
		offset += uint64(n)
	}
}

func serveBlastRepairs(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, history *blastRepairHistory, stats TransferStats) (TransferStats, error) {
	if batcher == nil {
		stats.markComplete(time.Now())
		return stats, nil
	}
	readBufs := newBlastBatchReadBuffers(batcher.MaxBatch())
	state := newBlastRepairServeState()
	for {
		wait, complete := state.nextReadWait(history)
		if complete {
			stats.markComplete(time.Now())
			return stats, nil
		}
		n, err := batcher.ReadBatch(ctx, wait, readBufs)
		if err != nil {
			if handled, readErr := handleBlastReceiveReadError(ctx, err); handled {
				return TransferStats{}, readErr
			}
			continue
		}
		done, err := state.processBatch(ctx, batcher, peer, runID, history, &stats, readBufs[:n])
		if err != nil {
			return TransferStats{}, err
		}
		if done {
			return stats, nil
		}
	}
}

type blastRepairServeState struct {
	quietDeadline time.Time
	deduper       *blastRepairDeduper
	hadRepair     bool
}

func newBlastRepairServeState() *blastRepairServeState {
	return &blastRepairServeState{deduper: newBlastRepairDeduper()}
}

func (s *blastRepairServeState) nextReadWait(history *blastRepairHistory) (time.Duration, bool) {
	complete := history.Complete()
	if complete && s.quietDeadline.IsZero() {
		s.quietDeadline = time.Now().Add(blastRepairQuietGraceForExpectedBytes(history.TotalBytes(), s.hadRepair))
	}
	wait := parallelBlastDataIdle
	if complete {
		wait = time.Until(s.quietDeadline)
	}
	if wait > blastRepairInterval {
		wait = blastRepairInterval
	}
	return wait, complete && wait <= 0
}

func (s *blastRepairServeState) processBatch(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, history *blastRepairHistory, stats *TransferStats, readBufs []batchReadBuffer) (bool, error) {
	for i := range readBufs {
		done, err := s.processBuffer(ctx, batcher, peer, runID, history, stats, readBufs[i])
		if err != nil || done {
			return done, err
		}
	}
	return false, nil
}

func (s *blastRepairServeState) processBuffer(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, history *blastRepairHistory, stats *TransferStats, readBuf batchReadBuffer) (bool, error) {
	packetType, payload, packetRunID, _, _, ok := decodeBlastPacketFull(readBuf.Bytes[:readBuf.N])
	if !ok || packetRunID != runID {
		return false, nil
	}
	switch packetType {
	case PacketTypeRepairComplete:
		stats.markComplete(time.Now())
		return true, nil
	case PacketTypeRepairRequest:
		return false, s.handleRepairRequest(ctx, batcher, peer, history, stats, payload)
	default:
		return false, nil
	}
}

func (s *blastRepairServeState) handleRepairRequest(ctx context.Context, batcher packetBatcher, peer net.Addr, history *blastRepairHistory, stats *TransferStats, payload []byte) error {
	s.hadRepair = s.hadRepair || history.CanRepair()
	if history.Complete() {
		s.quietDeadline = time.Now().Add(blastRepairQuietGraceForExpectedBytes(history.TotalBytes(), s.hadRepair))
	}
	_, err := sendBlastRepairs(ctx, batcher, peer, history, payload, stats, s.deduper, time.Now())
	return err
}

type blastRepairDeduper struct {
	sentAt map[uint64]time.Time
}

func newBlastRepairDeduper() *blastRepairDeduper {
	return &blastRepairDeduper{sentAt: make(map[uint64]time.Time)}
}

func (d *blastRepairDeduper) ShouldSend(seq uint64, now time.Time) bool {
	if d == nil {
		return true
	}
	if now.IsZero() {
		now = time.Now()
	}
	if last, ok := d.sentAt[seq]; ok && now.Sub(last) < blastRepairResendInterval {
		return false
	}
	d.sentAt[seq] = now
	return true
}

func sendBlastRepairs(ctx context.Context, batcher packetBatcher, peer net.Addr, history *blastRepairHistory, payload []byte, stats *TransferStats, deduper *blastRepairDeduper, now time.Time) (int, error) {
	if len(payload) < 8 {
		return 0, nil
	}
	requested := len(payload) / 8
	repairStats := blastRepairRequestStats{requested: requested}
	pending := make([][]byte, 0, batcher.MaxBatch())
	retransmits := 0
	for len(payload) >= 8 {
		seq := binary.BigEndian.Uint64(payload[:8])
		payload = payload[8:]
		packet, queued := blastRepairPacketForRequest(seq, history, deduper, now, &repairStats)
		if !queued {
			continue
		}
		pending = append(pending, packet)
		if len(pending) == batcher.MaxBatch() {
			written, err := flushBlastRepairPackets(ctx, batcher, peer, pending, stats)
			if err != nil {
				return retransmits, err
			}
			retransmits += written
			pending = pending[:0]
		}
	}
	if len(pending) == 0 {
		traceBlastRepairRequest(repairStats, retransmits)
		return retransmits, nil
	}
	written, err := flushBlastRepairPackets(ctx, batcher, peer, pending, stats)
	if err != nil {
		return retransmits, err
	}
	retransmits += written
	traceBlastRepairRequest(repairStats, retransmits)
	return retransmits, nil
}

type blastRepairRequestStats struct {
	requested   int
	unavailable int
	duplicate   int
}

func blastRepairPacketForRequest(seq uint64, history *blastRepairHistory, deduper *blastRepairDeduper, now time.Time, stats *blastRepairRequestStats) ([]byte, bool) {
	packet := history.packet(seq)
	if packet == nil {
		stats.unavailable++
		return nil, false
	}
	if !deduper.ShouldSend(seq, now) {
		stats.duplicate++
		return nil, false
	}
	return packet, true
}

func flushBlastRepairPackets(ctx context.Context, batcher packetBatcher, peer net.Addr, pending [][]byte, stats *TransferStats) (int, error) {
	if err := writeBlastBatch(ctx, batcher, peer, pending); err != nil {
		return 0, err
	}
	if stats != nil {
		stats.Retransmits += int64(len(pending))
		stats.PacketsSent += int64(len(pending))
	}
	return len(pending), nil
}

func traceBlastRepairRequest(stats blastRepairRequestStats, retransmits int) {
	if stats.unavailable == 0 && stats.duplicate == 0 {
		return
	}
	sessionTracef("blast repair request handled requested=%d retransmits=%d unavailable=%d duplicate=%d", stats.requested, retransmits, stats.unavailable, stats.duplicate)
}

func paceBlastSend(ctx context.Context, startedAt time.Time, bytesSent uint64, rateMbps int) error {
	if rateMbps <= 0 || bytesSent == 0 {
		return nil
	}
	target := time.Duration((float64(bytesSent*8) / float64(rateMbps*1000*1000)) * float64(time.Second))
	sleepFor := time.Until(startedAt.Add(target))
	if sleepFor <= 0 {
		return nil
	}
	return sleepWithContext(ctx, sleepFor)
}

func receiveBlastData(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, dst io.Writer, stats *TransferStats, buf []byte, packetAEAD cipher.AEAD) (TransferStats, error) {
	batcher := newPacketBatcher(conn, stats.Transport.RequestedKind)
	stats.Transport = batcher.Capabilities()
	if udpConn, ok := blastUDPReceiveFastPath(conn, batcher); ok {
		return receiveBlastDataUDP(ctx, udpConn, peer, runID, dst, stats, buf, packetAEAD)
	}
	return receiveBlastDataBatched(ctx, conn, batcher, peer, runID, dst, stats, buf, packetAEAD)
}

func blastUDPReceiveFastPath(conn net.PacketConn, batcher packetBatcher) (*net.UDPConn, bool) {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil, false
	}
	if batcher.MaxBatch() != 1 {
		return nil, false
	}
	return udpConn, true
}

func receiveBlastDataBatched(ctx context.Context, conn net.PacketConn, batcher packetBatcher, peer net.Addr, runID [16]byte, dst io.Writer, stats *TransferStats, buf []byte, packetAEAD cipher.AEAD) (TransferStats, error) {
	readBufs := newSizedBlastBatchReadBuffers(batcher.MaxBatch(), len(buf))
	for {
		complete, err := receiveBlastDataBatch(ctx, conn, batcher, peer, runID, dst, stats, readBufs, packetAEAD)
		if err != nil {
			return TransferStats{}, err
		}
		if complete {
			return *stats, nil
		}
	}
}

func receiveBlastDataBatch(ctx context.Context, conn net.PacketConn, batcher packetBatcher, peer net.Addr, runID [16]byte, dst io.Writer, stats *TransferStats, readBufs []batchReadBuffer, packetAEAD cipher.AEAD) (bool, error) {
	n, err := batcher.ReadBatch(ctx, blastReadPoll, readBufs)
	if err != nil {
		return false, ignoredBlastReceiveReadError(ctx, err)
	}
	return processBlastReceiveBatch(ctx, conn, batcher, peer, runID, dst, stats, readBufs[:n], packetAEAD)
}

func ignoredBlastReceiveReadError(ctx context.Context, err error) error {
	if handled, readErr := handleBlastReceiveReadError(ctx, err); handled {
		return readErr
	}
	return nil
}

func newSizedBlastBatchReadBuffers(maxBatch int, size int) []batchReadBuffer {
	readBufs := make([]batchReadBuffer, maxBatch)
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, size)
	}
	return readBufs
}

func handleBlastReceiveReadError(ctx context.Context, err error) (bool, error) {
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	if isNetTimeout(err) {
		return false, nil
	}
	if errors.Is(err, net.ErrClosed) {
		return true, err
	}
	return false, nil
}

func processBlastReceiveBatch(ctx context.Context, helloConn net.PacketConn, batcher packetBatcher, peer net.Addr, runID [16]byte, dst io.Writer, stats *TransferStats, readBufs []batchReadBuffer, packetAEAD cipher.AEAD) (bool, error) {
	for i := range readBufs {
		complete, err := processBlastReceiveBuffer(ctx, helloConn, batcher, peer, runID, dst, stats, readBufs[i], packetAEAD)
		if err != nil || complete {
			return complete, err
		}
	}
	return false, nil
}

func processBlastReceiveBuffer(ctx context.Context, helloConn net.PacketConn, batcher packetBatcher, peer net.Addr, runID [16]byte, dst io.Writer, stats *TransferStats, readBuf batchReadBuffer, packetAEAD cipher.AEAD) (bool, error) {
	if peer != nil && !sameAddr(readBuf.Addr, peer) {
		return false, nil
	}
	packetType, payload, packetRunID, ok := decodeBlastPacketWithAEAD(readBuf.Bytes[:readBuf.N], packetAEAD)
	if !ok || packetRunID != runID {
		return false, nil
	}
	return processBlastReceivePacket(ctx, helloConn, batcher, readBuf.Addr, runID, dst, stats, packetType, payload)
}

func processBlastReceivePacket(ctx context.Context, helloConn net.PacketConn, batcher packetBatcher, addr net.Addr, runID [16]byte, dst io.Writer, stats *TransferStats, packetType PacketType, payload []byte) (bool, error) {
	switch packetType {
	case PacketTypeHello:
		return false, sendHelloAck(ctx, helloConn, addr, runID, 0, 1)
	case PacketTypeData:
		return false, writeBlastReceivePayload(dst, stats, payload)
	case PacketTypeDone:
		if err := sendRepairComplete(ctx, batcher, addr, runID); err != nil {
			return false, err
		}
		stats.markComplete(time.Now())
		return true, nil
	default:
		return false, nil
	}
}

func writeBlastReceivePayload(dst io.Writer, stats *TransferStats, payload []byte) error {
	if stats.FirstByteAt.IsZero() && len(payload) > 0 {
		stats.FirstByteAt = time.Now()
	}
	written, err := writeBlastPayload(dst, payload)
	if err != nil {
		return err
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}
	stats.BytesReceived += int64(written)
	stats.observePeakGoodput(time.Now(), stats.BytesReceived)
	return nil
}

func receiveBlastDataUDP(ctx context.Context, conn *net.UDPConn, peer net.Addr, runID [16]byte, dst io.Writer, stats *TransferStats, buf []byte, packetAEAD cipher.AEAD) (TransferStats, error) {
	if cleanup, err := configureBlastUDPReadDeadline(ctx, conn); err != nil {
		return TransferStats{}, err
	} else {
		defer cleanup()
	}
	batcher := newLegacyBatcher(conn)
	for {
		n, addrPort, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if handled, readErr := handleBlastReceiveReadError(ctx, err); handled {
				return TransferStats{}, readErr
			}
			continue
		}
		if !udpAddrPortMatchesPeer(addrPort, peer) {
			continue
		}
		addr := net.UDPAddrFromAddrPort(addrPort)
		packetType, payload, packetRunID, ok := decodeBlastPacketWithAEAD(buf[:n], packetAEAD)
		if !ok || packetRunID != runID {
			continue
		}
		complete, err := processBlastReceivePacket(ctx, conn, batcher, addr, runID, dst, stats, packetType, payload)
		if err != nil {
			return TransferStats{}, err
		}
		if complete {
			return *stats, nil
		}
	}
}

func configureBlastUDPReadDeadline(ctx context.Context, conn *net.UDPConn) (func(), error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
		return func() { _ = conn.SetReadDeadline(time.Time{}) }, nil
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-done:
		}
	}()
	return func() { close(done) }, nil
}

func ReceiveBlastParallelToWriter(ctx context.Context, conns []net.PacketConn, dst io.Writer, cfg ReceiveConfig, expectedBytes int64) (TransferStats, error) {
	state, err := newBlastParallelReceiveState(conns, dst, cfg, expectedBytes)
	if err != nil {
		return TransferStats{}, err
	}
	state.start(ctx)
	state.wait()
	return state.result(ctx)
}

type blastParallelReceiveState struct {
	conns                    []net.PacketConn
	dst                      io.Writer
	cfg                      ReceiveConfig
	expectedBytes            int64
	startedAt                time.Time
	done                     chan struct{}
	errCh                    chan error
	doneOnce                 sync.Once
	wg                       sync.WaitGroup
	bytesReceived            atomic.Int64
	donePackets              atomic.Int32
	lastPacketAt             atomic.Int64
	writeMu                  sync.Mutex
	firstByteAt              time.Time
	firstByteOnce            sync.Once
	connected                atomic.Bool
	repairActive             atomic.Bool
	incompleteDoneRuns       atomic.Int32
	doneTarget               int32
	terminalGraceOnce        sync.Once
	terminalGraceActive      atomic.Bool
	repairGraceOnce          sync.Once
	repairGraceExpired       atomic.Bool
	repairGraceDeadline      atomic.Int64
	repairGraceExpectedBytes atomic.Int64
	peakMu                   sync.Mutex
	peak                     intervalStats
}

func newBlastParallelReceiveState(conns []net.PacketConn, dst io.Writer, cfg ReceiveConfig, expectedBytes int64) (*blastParallelReceiveState, error) {
	if len(conns) == 0 {
		return nil, errors.New("no packet conns")
	}
	if dst == nil {
		dst = io.Discard
	}
	startedAt := time.Now()
	state := &blastParallelReceiveState{
		conns:         conns,
		dst:           dst,
		cfg:           cfg,
		expectedBytes: expectedBytes,
		startedAt:     startedAt,
		done:          make(chan struct{}),
		errCh:         make(chan error, len(conns)),
		doneTarget:    int32(len(conns)),
	}
	state.peak.minWindow = blastRateFeedbackInterval
	state.peak.Observe(startedAt, 0)
	if expectedBytes > 0 {
		state.repairGraceExpectedBytes.Store(expectedBytes)
	}
	return state, nil
}

func (s *blastParallelReceiveState) start(ctx context.Context) {
	s.startContextWatcher(ctx)
	s.startIdleWatcher()
	for _, conn := range s.conns {
		s.startConn(ctx, conn)
	}
}

func (s *blastParallelReceiveState) startContextWatcher(ctx context.Context) {
	go func() {
		select {
		case <-ctx.Done():
			s.closeDone()
		case <-s.done:
		}
	}()
}

func (s *blastParallelReceiveState) startIdleWatcher() {
	go func() {
		ticker := time.NewTicker(parallelBlastDataIdle / 4)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if s.idleExpired() {
					s.closeDone()
					return
				}
			case <-s.done:
				return
			}
		}
	}()
}

func (s *blastParallelReceiveState) idleExpired() bool {
	if s.cfg.RequireComplete || s.bytesReceived.Load() <= 0 || s.terminalGraceActive.Load() || s.repairActive.Load() {
		return false
	}
	last := s.lastPacketAt.Load()
	return last > 0 && time.Since(time.Unix(0, last)) >= parallelBlastDataIdle
}

func (s *blastParallelReceiveState) startConn(ctx context.Context, conn net.PacketConn) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		err := receiveBlastParallelConn(ctx, conn, s.dst, s.cfg, s.expectedBytes, s.doneTarget, &s.bytesReceived, &s.donePackets, &s.incompleteDoneRuns, &s.lastPacketAt, &s.writeMu, &s.firstByteOnce, &s.firstByteAt, &s.connected, &s.repairActive, s.done, s.closeDone, s.startTerminalGrace, s.startRepairGrace, s.observeRepairGraceExpectedBytes, s.observePeak)
		if err != nil {
			s.reportError(err)
		}
	}()
}

func (s *blastParallelReceiveState) reportError(err error) {
	select {
	case s.errCh <- err:
	default:
	}
	s.closeDone()
}

func (s *blastParallelReceiveState) wait() {
	s.wg.Wait()
}

func (s *blastParallelReceiveState) result(ctx context.Context) (TransferStats, error) {
	select {
	case err := <-s.errCh:
		if incomplete := s.contextIncompleteError(ctx, err); incomplete != nil {
			return s.currentStats(time.Now()), incomplete
		}
		return s.currentStats(time.Now()), err
	default:
	}
	if err := s.completionError(ctx); err != nil {
		return s.currentStats(time.Now()), err
	}
	return s.currentStats(time.Now()), nil
}

func (s *blastParallelReceiveState) completionError(ctx context.Context) error {
	if s.repairGraceExpired.Load() && s.incompleteDoneRuns.Load() > 0 {
		return fmt.Errorf("blast incomplete: received %d bytes before repair grace expired", s.bytesReceived.Load())
	}
	received := s.bytesReceived.Load()
	sessionTracef("parallel recv return expected=%d received=%d ctx_err=%v repair_expired=%t incomplete_done_runs=%d", s.expectedBytes, received, ctx.Err(), s.repairGraceExpired.Load(), s.incompleteDoneRuns.Load())
	if s.requireCompleteMissingBytes(ctx, received) {
		return fmt.Errorf("blast incomplete: received %d bytes, want %d", received, s.expectedBytes)
	}
	return nil
}

func (s *blastParallelReceiveState) requireCompleteMissingBytes(ctx context.Context, received int64) bool {
	if s.expectedBytes <= 0 || received >= s.expectedBytes {
		return false
	}
	return s.cfg.RequireComplete || received == 0 || ctx.Err() != nil
}

func (s *blastParallelReceiveState) contextIncompleteError(ctx context.Context, err error) error {
	received := s.bytesReceived.Load()
	if s.expectedBytes <= 0 || received >= s.expectedBytes {
		return nil
	}
	if ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return fmt.Errorf("blast incomplete: received %d bytes, want %d", received, s.expectedBytes)
}

func (s *blastParallelReceiveState) observeRepairGraceExpectedBytes(totalBytes uint64) {
	if totalBytes == 0 {
		return
	}
	next := blastRepairSafeExpectedBytes(totalBytes)
	for {
		current := s.repairGraceExpectedBytes.Load()
		if next <= current {
			return
		}
		if s.repairGraceExpectedBytes.CompareAndSwap(current, next) {
			return
		}
	}
}

func (s *blastParallelReceiveState) repairGrace() time.Duration {
	return parallelBlastRepairGraceForExpectedBytes(s.repairGraceExpectedBytes.Load())
}

func (s *blastParallelReceiveState) observePeak(now time.Time, totalBytes int64) {
	s.peakMu.Lock()
	s.peak.Observe(now, totalBytes)
	s.peakMu.Unlock()
}

func (s *blastParallelReceiveState) peakMbps() float64 {
	s.peakMu.Lock()
	defer s.peakMu.Unlock()
	return s.peak.PeakMbps()
}

func (s *blastParallelReceiveState) closeDone() {
	s.doneOnce.Do(func() {
		close(s.done)
		for _, conn := range s.conns {
			_ = conn.SetReadDeadline(time.Now())
		}
	})
}

func (s *blastParallelReceiveState) startTerminalGrace() {
	s.terminalGraceOnce.Do(func() {
		s.terminalGraceActive.Store(true)
		go s.terminalGraceLoop()
	})
}

func (s *blastParallelReceiveState) terminalGraceLoop() {
	timer := time.NewTimer(parallelBlastDoneGrace)
	defer timer.Stop()
	select {
	case <-timer.C:
		s.closeDone()
	case <-s.done:
	}
}

func (s *blastParallelReceiveState) startRepairGrace() {
	s.repairActive.Store(true)
	s.repairGraceDeadline.Store(time.Now().Add(s.repairGrace()).UnixNano())
	s.repairGraceOnce.Do(func() {
		go s.repairGraceLoop()
	})
}

func (s *blastParallelReceiveState) repairGraceLoop() {
	ticker := time.NewTicker(blastRepairInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if s.repairGraceTimedOut() {
				s.repairGraceExpired.Store(true)
				s.closeDone()
				return
			}
		case <-s.done:
			return
		}
	}
}

func (s *blastParallelReceiveState) repairGraceTimedOut() bool {
	deadline := s.repairGraceDeadline.Load()
	return s.repairActive.Load() && deadline > 0 && time.Now().UnixNano() >= deadline
}

func (s *blastParallelReceiveState) currentStats(completedAt time.Time) TransferStats {
	received := s.bytesReceived.Load()
	firstByte := s.firstByteAt
	if firstByte.IsZero() && received > 0 {
		firstByte = completedAt
	}
	transport := PreviewTransportCaps(s.conns[0], s.cfg.Transport)
	if s.connected.Load() {
		transport.Connected = true
	}
	out := TransferStats{
		BytesReceived:   received,
		StartedAt:       s.startedAt,
		FirstByteAt:     firstByte,
		CompletedAt:     completedAt,
		PeakGoodputMbps: s.peakMbps(),
		Transport:       transport,
	}
	out.markComplete(completedAt)
	return out
}

type blastStreamReceiveLane struct {
	conn    net.PacketConn
	batcher packetBatcher
	peer    net.Addr
}

type blastStreamReceiveCoordinator struct {
	mu             sync.Mutex
	lanes          []*blastStreamReceiveLane
	dst            io.Writer
	cfg            ReceiveConfig
	expectedBytes  int64
	startedAt      time.Time
	runs           map[[16]byte]*blastReceiveRunState
	bytesReceived  int64
	feedbackBytes  int64
	firstByteAt    time.Time
	repairDeadline time.Time
	writeMu        sync.Mutex
	lastStatsAt    map[[16]byte]time.Time
	recoveringFEC  bool
	peakMu         sync.Mutex
	peak           intervalStats
}

func (c *blastStreamReceiveCoordinator) observePeak(now time.Time, totalBytes int64) {
	if c == nil {
		return
	}
	c.peakMu.Lock()
	c.peak.Observe(now, totalBytes)
	c.peakMu.Unlock()
}

func (c *blastStreamReceiveCoordinator) peakMbps() float64 {
	if c == nil {
		return 0
	}
	c.peakMu.Lock()
	defer c.peakMu.Unlock()
	return c.peak.PeakMbps()
}

func (c *blastStreamReceiveCoordinator) repairGraceForState(state *blastReceiveRunState) time.Duration {
	expectedBytes := c.expectedBytes
	if expectedBytes <= 0 && state != nil {
		if state.totalBytes > 0 {
			expectedBytes = blastRepairSafeExpectedBytes(state.totalBytes)
		} else if state.finalTotalSet {
			expectedBytes = blastRepairSafeExpectedBytes(state.finalTotal)
		}
	}
	return parallelBlastRepairGraceForExpectedBytes(expectedBytes)
}

func newBlastStreamReceiveCoordinator(ctx context.Context, lanes []*blastStreamReceiveLane, dst io.Writer, cfg ReceiveConfig, expectedBytes int64, startedAt time.Time) *blastStreamReceiveCoordinator {
	if dst == nil {
		dst = io.Discard
	}
	cfg.RequireComplete = true
	coordinator := &blastStreamReceiveCoordinator{
		lanes:         lanes,
		dst:           dst,
		cfg:           cfg,
		expectedBytes: expectedBytes,
		startedAt:     startedAt,
		runs:          make(map[[16]byte]*blastReceiveRunState),
		lastStatsAt:   make(map[[16]byte]time.Time),
	}
	coordinator.peak.minWindow = blastRateFeedbackInterval
	coordinator.peak.Observe(startedAt, 0)
	return coordinator
}

func (c *blastStreamReceiveCoordinator) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, state := range c.runs {
		if state != nil {
			state.closeStripedPayloadSpool()
		}
	}
}

func (c *blastStreamReceiveCoordinator) runState(runID [16]byte, addr net.Addr) *blastReceiveRunState {
	state := c.runs[runID]
	if state == nil {
		state = newBlastReceiveRunState(addr)
		c.runs[runID] = state
	}
	if state.addr == nil && addr != nil {
		state.addr = cloneAddr(addr)
	}
	return state
}

func (c *blastStreamReceiveCoordinator) sendStatsFeedbackLocked(ctx context.Context, runID [16]byte, state *blastReceiveRunState, now time.Time, force bool) {
	if c == nil || state == nil {
		return
	}
	if state.striped {
		c.sendStripedStatsFeedbackLocked(ctx, runID, state, now, force)
		return
	}
	now = statsFeedbackNow(now)
	if !c.statsFeedbackDueLocked(runID, now, force) {
		return
	}
	c.lastStatsAt[runID] = now
	c.sendStatsToLanes(ctx, runID, c.globalReceiverStatsLocked(state))
}

func (c *blastStreamReceiveCoordinator) sendStripedStatsFeedbackLocked(ctx context.Context, runID [16]byte, state *blastReceiveRunState, now time.Time, force bool) {
	if c == nil || state == nil {
		return
	}
	now = statsFeedbackNow(now)
	if !c.statsFeedbackDueLocked(runID, now, force) {
		return
	}
	c.lastStatsAt[runID] = now
	aggregateStats := c.stripedAggregateStatsLocked(state)
	c.sendStripedStatsToLanes(ctx, runID, state, aggregateStats)
}

func statsFeedbackNow(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now()
	}
	return now
}

func (c *blastStreamReceiveCoordinator) statsFeedbackDueLocked(runID [16]byte, now time.Time, force bool) bool {
	if force {
		return true
	}
	last := c.lastStatsAt[runID]
	return last.IsZero() || now.Sub(last) >= blastRateFeedbackInterval
}

func (c *blastStreamReceiveCoordinator) globalReceiverStatsLocked(state *blastReceiveRunState) blastReceiverStats {
	return blastReceiverStats{
		ReceivedPayloadBytes:  c.rateFeedbackPayloadBytesLocked(state),
		ReceivedPackets:       state.seen.Len(),
		MaxSeqPlusOne:         state.maxSeqPlusOne,
		AckFloor:              state.nextWriteSeq,
		CommittedPayloadBytes: c.committedPayloadBytesLocked(state),
	}
}

func (c *blastStreamReceiveCoordinator) stripedAggregateStatsLocked(state *blastReceiveRunState) blastReceiverStats {
	stats := blastReceiverStats{
		ReceivedPayloadBytes:  c.rateFeedbackPayloadBytesLocked(state),
		CommittedPayloadBytes: c.committedPayloadBytesLocked(state),
	}
	for _, stripe := range state.stripes {
		if stripe == nil {
			continue
		}
		stats.ReceivedPackets += stripe.seen.Len()
		stats.MaxSeqPlusOne += stripe.maxSeqPlusOne
	}
	return stats
}

func (c *blastStreamReceiveCoordinator) sendStatsToLanes(ctx context.Context, runID [16]byte, stats blastReceiverStats) {
	for _, lane := range c.lanes {
		if !blastStreamReceiveLaneReady(lane) {
			continue
		}
		sendBlastStatsBestEffort(ctx, lane.batcher, lane.peer, runID, stats)
	}
}

func (c *blastStreamReceiveCoordinator) sendStripedStatsToLanes(ctx context.Context, runID [16]byte, state *blastReceiveRunState, aggregateStats blastReceiverStats) {
	for stripeID, stripe := range state.stripes {
		if stripe == nil || !blastStreamReceiveLaneReady(stripe.lane) {
			continue
		}
		stripeStats := aggregateStats
		stripeStats.AckFloor = stripe.expectedSeq
		sendBlastStatsBestEffortStripe(ctx, stripe.lane.batcher, stripe.lane.peer, runID, stripeID, stripeStats)
	}
}

func blastStreamReceiveLaneReady(lane *blastStreamReceiveLane) bool {
	return lane != nil && lane.batcher != nil && lane.peer != nil
}

func (c *blastStreamReceiveCoordinator) rateFeedbackPayloadBytesLocked(state *blastReceiveRunState) uint64 {
	if state == nil {
		return 0
	}
	if state.feedbackBytes > 0 {
		return state.feedbackBytes
	}
	if c == nil || c.bytesReceived <= 0 {
		return 0
	}
	return uint64(c.bytesReceived)
}

func (c *blastStreamReceiveCoordinator) committedPayloadBytesLocked(state *blastReceiveRunState) uint64 {
	if state == nil || c == nil || c.bytesReceived <= 0 {
		return 0
	}
	return uint64(c.bytesReceived)
}

func (c *blastStreamReceiveCoordinator) sendStatsFeedbackForAllLocked(ctx context.Context, now time.Time, force bool) {
	if c == nil {
		return
	}
	for runID, state := range c.runs {
		c.sendStatsFeedbackLocked(ctx, runID, state, now, force)
	}
}

func (c *blastStreamReceiveCoordinator) handlePacket(ctx context.Context, lane *blastStreamReceiveLane, packetType PacketType, runID [16]byte, seq uint64, offset uint64, count uint64, payload []byte, addr net.Addr) (bool, error) {
	return c.handlePacketStripe(ctx, lane, 0, 1, packetType, runID, seq, offset, count, payload, addr)
}

func (c *blastStreamReceiveCoordinator) handlePacketStripe(ctx context.Context, lane *blastStreamReceiveLane, stripeID uint16, totalStripes int, packetType PacketType, runID [16]byte, seq uint64, offset uint64, count uint64, payload []byte, addr net.Addr) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if lane != nil && lane.peer == nil && addr != nil {
		lane.peer = cloneAddr(addr)
	}
	state := c.runs[runID]
	if stripeID != 0 || totalStripes > 1 || (state != nil && state.striped) {
		return c.handleStripedPacketLocked(ctx, lane, stripeID, totalStripes, packetType, runID, seq, offset, count, payload, addr)
	}
	return c.handleGlobalPacketLocked(ctx, lane, packetType, runID, seq, offset, count, payload, addr)
}

func (c *blastStreamReceiveCoordinator) handleGlobalPacketLocked(ctx context.Context, lane *blastStreamReceiveLane, packetType PacketType, runID [16]byte, seq uint64, offset uint64, count uint64, payload []byte, addr net.Addr) (bool, error) {
	switch packetType {
	case PacketTypeHello:
		c.runState(runID, addr)
		return false, nil
	case PacketTypeData:
		return c.handleGlobalDataLocked(ctx, runID, seq, offset, payload, addr)
	case PacketTypeParity:
		return c.handleGlobalParityLocked(ctx, runID, seq, offset, count, payload, addr)
	case PacketTypeDone:
		return c.handleGlobalDoneLocked(ctx, runID, seq, offset, addr)
	}
	return false, nil
}

func (c *blastStreamReceiveCoordinator) handleGlobalDataLocked(ctx context.Context, runID [16]byte, seq uint64, offset uint64, payload []byte, addr net.Addr) (bool, error) {
	if len(payload) == 0 {
		return false, nil
	}
	state := c.runState(runID, addr)
	if !state.acceptData(seq) {
		return false, nil
	}
	if err := c.observeGlobalPayloadLocked(state, seq, offset, payload); err != nil {
		return false, err
	}
	if err := c.recoverFEC(ctx, runID, state); err != nil {
		return false, err
	}
	complete, err := c.completeRun(ctx, runID, state)
	if err != nil || complete {
		return complete, err
	}
	return c.expectedBytes > 0 && c.bytesReceived >= c.expectedBytes && state.done, nil
}

func (c *blastStreamReceiveCoordinator) observeGlobalPayloadLocked(state *blastReceiveRunState, seq uint64, offset uint64, payload []byte) error {
	if c.firstByteAt.IsZero() {
		c.firstByteAt = time.Now()
	}
	state.feedbackBytes += uint64(len(payload))
	c.feedbackBytes += int64(len(payload))
	state.storeFECPayload(c.cfg.FECGroupSize, seq, payload)
	written, err := c.writeGlobalPayloadLocked(state, seq, offset, payload)
	if err != nil {
		return err
	}
	c.bytesReceived += int64(written)
	c.observePeak(time.Now(), c.feedbackBytes)
	return nil
}

func (c *blastStreamReceiveCoordinator) handleGlobalParityLocked(ctx context.Context, runID [16]byte, seq uint64, offset uint64, count uint64, payload []byte, addr net.Addr) (bool, error) {
	if c.cfg.FECGroupSize <= 1 {
		return false, nil
	}
	state := c.runState(runID, addr)
	state.storeFECParity(seq, offset, count, payload)
	return false, c.recoverFEC(ctx, runID, state)
}

func (c *blastStreamReceiveCoordinator) handleGlobalDoneLocked(ctx context.Context, runID [16]byte, seq uint64, offset uint64, addr net.Addr) (bool, error) {
	state := c.runState(runID, addr)
	state.markDoneWithTotalBytes(seq, offset, addr)
	if err := c.recoverFEC(ctx, runID, state); err != nil {
		return false, err
	}
	complete, err := c.completeRun(ctx, runID, state)
	if err != nil || complete {
		return complete, err
	}
	c.sendStatsFeedbackLocked(ctx, runID, state, time.Now(), true)
	c.repairDeadline = time.Now().Add(c.repairGraceForState(state))
	return false, c.requestMissingRepairs(ctx, runID, state)
}

func (c *blastStreamReceiveCoordinator) handleStripedPacketLocked(ctx context.Context, lane *blastStreamReceiveLane, stripeID uint16, totalStripes int, packetType PacketType, runID [16]byte, seq uint64, offset uint64, count uint64, payload []byte, addr net.Addr) (bool, error) {
	state := c.runState(runID, addr)
	state.enableStriped(totalStripes)
	stripe := state.stripeState(stripeID, lane, addr)
	switch packetType {
	case PacketTypeHello:
		return false, nil
	case PacketTypeData:
		return c.handleStripedDataLocked(ctx, runID, state, stripe, stripeID, seq, offset, payload)
	case PacketTypeDone:
		return c.handleStripedDoneLocked(ctx, runID, state, stripe, stripeID, seq, offset)
	case PacketTypeParity:
		return c.handleStripedParityLocked(ctx, runID, state, stripe, seq, offset, count, payload)
	default:
		return false, nil
	}
}

func (c *blastStreamReceiveCoordinator) handleStripedDataLocked(ctx context.Context, runID [16]byte, state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, stripeID uint16, seq uint64, offset uint64, payload []byte) (bool, error) {
	if len(payload) == 0 {
		return false, nil
	}
	if c.firstByteAt.IsZero() {
		c.firstByteAt = time.Now()
	}
	packet := newStripedPacket(PacketTypeData, runID, stripeID, seq, offset, payload)
	return c.handleStripedDataOrDoneLocked(ctx, runID, state, stripe, packet)
}

func (c *blastStreamReceiveCoordinator) handleStripedDoneLocked(ctx context.Context, runID [16]byte, state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, stripeID uint16, seq uint64, offset uint64) (bool, error) {
	complete, err := c.handleStripedDataOrDoneLocked(ctx, runID, state, stripe, newStripedPacket(PacketTypeDone, runID, stripeID, seq, offset, nil))
	if err != nil || complete {
		return complete, err
	}
	c.repairDeadline = time.Now().Add(c.repairGraceForState(state))
	return false, c.requestMissingStripedRepairs(ctx, runID, state)
}

func (c *blastStreamReceiveCoordinator) handleStripedParityLocked(ctx context.Context, runID [16]byte, state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, seq uint64, offset uint64, count uint64, payload []byte) (bool, error) {
	if c.cfg.FECGroupSize <= 1 || count == 0 || len(payload) == 0 {
		return false, nil
	}
	stripe.storeFECParity(seq, offset, count, payload)
	if err := c.recoverStripedFEC(ctx, runID, state); err != nil {
		return false, err
	}
	return c.stripedCompleteLocked(state), nil
}

func newStripedPacket(packetType PacketType, runID [16]byte, stripeID uint16, seq uint64, offset uint64, payload []byte) Packet {
	return Packet{Version: ProtocolVersion, Type: packetType, StripeID: stripeID, RunID: runID, Seq: seq, Offset: offset, Payload: payload}
}

func (c *blastStreamReceiveCoordinator) handleStripedDataOrDoneLocked(ctx context.Context, runID [16]byte, state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, packet Packet) (bool, error) {
	if state == nil || stripe == nil {
		return false, nil
	}
	stripe.observeTerminalPacket(packet)
	if packet.Seq < stripe.expectedSeq || stripe.seen.Has(packet.Seq) {
		return c.stripedCompleteLocked(state), nil
	}
	if packet.Seq > stripe.expectedSeq {
		return c.handleStripedFuturePacketLocked(ctx, runID, state, stripe, packet)
	}
	if !stripe.seen.Add(packet.Seq) {
		return c.stripedCompleteLocked(state), nil
	}
	if err := c.acceptStripedCurrentPacketLocked(state, stripe, packet); err != nil {
		return false, err
	}
	if err := c.recoverStripedFEC(ctx, runID, state); err != nil {
		return false, err
	}
	return c.finishStripedIfCompleteLocked(ctx, runID, state)
}

func (s *blastStreamReceiveStripeState) observeTerminalPacket(packet Packet) {
	if s == nil || packet.Type != PacketTypeDone {
		return
	}
	s.terminalSeen = true
	if packet.Seq > s.totalPackets {
		s.totalPackets = packet.Seq
	}
}

func (c *blastStreamReceiveCoordinator) handleStripedFuturePacketLocked(ctx context.Context, runID [16]byte, state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, packet Packet) (bool, error) {
	if err := c.storeStripedFuturePacketLocked(state, stripe, packet); err != nil {
		return false, err
	}
	if packet.Type == PacketTypeData {
		stripe.storeFECPayload(c.cfg.FECGroupSize, packet.Seq, packet.Payload)
		if err := c.recoverStripedFEC(ctx, runID, state); err != nil {
			return false, err
		}
	}
	return c.stripedCompleteLocked(state), nil
}

func (c *blastStreamReceiveCoordinator) acceptStripedCurrentPacketLocked(state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, packet Packet) error {
	if packet.Seq+1 > stripe.maxSeqPlusOne {
		stripe.maxSeqPlusOne = packet.Seq + 1
	}
	if packet.Type == PacketTypeData {
		stripe.storeFECPayload(c.cfg.FECGroupSize, packet.Seq, packet.Payload)
	}
	if err := c.acceptStripedSequentialPacketLocked(state, stripe, packet); err != nil {
		return err
	}
	return c.acceptBufferedStripedPacketsLocked(state, stripe)
}

func (c *blastStreamReceiveCoordinator) acceptBufferedStripedPacketsLocked(state *blastReceiveRunState, stripe *blastStreamReceiveStripeState) error {
	for {
		buffered, ok, err := c.popStripedBufferedPacketLocked(state, stripe)
		if err != nil || !ok {
			return err
		}
		if err := c.acceptStripedSequentialPacketLocked(state, stripe, buffered); err != nil {
			return err
		}
	}
}

func (c *blastStreamReceiveCoordinator) finishStripedIfCompleteLocked(ctx context.Context, runID [16]byte, state *blastReceiveRunState) (bool, error) {
	if state.completedStripes == state.totalStripes {
		state.done = true
	}
	if !c.stripedCompleteLocked(state) {
		return false, nil
	}
	if err := c.flushStripedPayloadLocked(state); err != nil {
		return false, err
	}
	if err := sendBlastStreamRepairCompleteAll(ctx, c.lanes, runID); err != nil {
		return false, err
	}
	return true, nil
}

func (c *blastStreamReceiveCoordinator) acceptStripedSequentialPacketLocked(state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, packet Packet) error {
	switch packet.Type {
	case PacketTypeData:
		if err := c.acceptStripedDataPayloadLocked(state, stripe, packet); err != nil {
			return err
		}
		stripe.expectedSeq++
	case PacketTypeDone:
		if err := c.acceptStripedDonePacketLocked(state, stripe, packet); err != nil {
			return err
		}
		stripe.expectedSeq++
	}
	return nil
}

func (c *blastStreamReceiveCoordinator) acceptStripedDataPayloadLocked(state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, packet Packet) error {
	if len(packet.Payload) == 0 {
		return nil
	}
	if stripe == nil || !stripe.feedbackCounted.Has(packet.Seq) {
		c.countStripedPayloadFeedbackLocked(state, packet.Payload)
	}
	if c.dst == io.Discard {
		c.bytesReceived += int64(len(packet.Payload))
		return nil
	}
	if packet.Offset == state.nextOffset {
		if err := c.writeStripedPayloadLocked(state, packet.Payload); err != nil {
			return err
		}
		return c.flushStripedPendingPayloadsLocked(state)
	}
	if packet.Offset > state.nextOffset {
		return c.storeStripedPendingOutputLocked(state, packet.Offset, packet.Payload)
	}
	return nil
}

func (c *blastStreamReceiveCoordinator) acceptStripedDonePacketLocked(state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, packet Packet) error {
	if !stripe.done {
		stripe.done = true
		stripe.totalPackets = packet.Seq
		state.completedStripes++
	}
	if !state.finalTotalSet {
		state.finalTotal = packet.Offset
		state.finalTotalSet = true
	} else if state.finalTotal != packet.Offset {
		return errors.New("striped blast done packets disagree on final size")
	}
	return c.validateFinalTotalLocked("striped blast", state.finalTotal)
}

func (c *blastStreamReceiveCoordinator) countStripedPayloadFeedbackLocked(state *blastReceiveRunState, payload []byte) {
	if c == nil || state == nil || len(payload) == 0 {
		return
	}
	state.observeStripedPayload(payload)
	state.feedbackBytes += uint64(len(payload))
	c.feedbackBytes += int64(len(payload))
	c.observePeak(time.Now(), c.feedbackBytes)
}

func (c *blastStreamReceiveCoordinator) storeStripedFuturePacketLocked(state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, packet Packet) error {
	if state == nil || stripe == nil {
		return nil
	}
	if packet.Type != PacketTypeData || len(packet.Payload) == 0 {
		stripe.acceptFutureSeq(packet.Seq)
		stripe.storeBufferedPacket(packet)
		return nil
	}
	if state.canBufferStripedFuturePayload(len(packet.Payload)) {
		return c.storeStripedFuturePacketInMemoryLocked(state, stripe, packet)
	}
	return c.storeStripedFuturePacketSpooledLocked(state, stripe, packet)
}

func (c *blastStreamReceiveCoordinator) storeStripedFuturePacketInMemoryLocked(state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, packet Packet) error {
	if !stripe.acceptFutureSeq(packet.Seq) {
		return nil
	}
	stripe.feedbackCounted.Add(packet.Seq)
	c.countStripedPayloadFeedbackLocked(state, packet.Payload)
	stripe.storeBufferedPacket(packet)
	state.stripedFutureBufferedBytes += uint64(len(packet.Payload))
	return nil
}

func (c *blastStreamReceiveCoordinator) storeStripedFuturePacketSpooledLocked(state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, packet Packet) error {
	if packet.Offset > uint64(maxInt()) {
		return errors.New("striped future packet offset exceeds spool range")
	}
	spool, err := state.ensureStripedPayloadSpool()
	if err != nil {
		return err
	}
	written, err := spool.WriteAt(packet.Payload, int64(packet.Offset))
	if err != nil {
		return err
	}
	if written != len(packet.Payload) {
		return io.ErrShortWrite
	}
	if !stripe.acceptFutureSeq(packet.Seq) {
		return nil
	}
	stripe.feedbackCounted.Add(packet.Seq)
	c.countStripedPayloadFeedbackLocked(state, packet.Payload)
	if stripe.bufferedSpool == nil {
		stripe.bufferedSpool = make(map[uint64]stripedSpooledPacket)
	}
	spooled := packet
	spooled.Payload = nil
	stripe.bufferedSpool[packet.Seq] = stripedSpooledPacket{
		packet:     spooled,
		payloadLen: len(packet.Payload),
	}
	return nil
}

func (s *blastStreamReceiveStripeState) acceptFutureSeq(seq uint64) bool {
	if s == nil || !s.seen.Add(seq) {
		return false
	}
	if seq+1 > s.maxSeqPlusOne {
		s.maxSeqPlusOne = seq + 1
	}
	return true
}

func (c *blastStreamReceiveCoordinator) popStripedBufferedPacketLocked(state *blastReceiveRunState, stripe *blastStreamReceiveStripeState) (Packet, bool, error) {
	if state == nil || stripe == nil {
		return Packet{}, false, nil
	}
	if packet, ok := stripe.buffered[stripe.expectedSeq]; ok {
		delete(stripe.buffered, stripe.expectedSeq)
		state.releaseStripedFutureBuffer(len(packet.Payload))
		return packet, true, nil
	}
	spooled, ok := stripe.bufferedSpool[stripe.expectedSeq]
	if !ok {
		return Packet{}, false, nil
	}
	if state.pendingOutputSpool == nil {
		return Packet{}, false, errors.New("striped future packet spool missing")
	}
	payload := make([]byte, spooled.payloadLen)
	n, err := state.pendingOutputSpool.ReadAt(payload, int64(spooled.packet.Offset))
	if err != nil && !errors.Is(err, io.EOF) {
		return Packet{}, false, err
	}
	if n != len(payload) {
		return Packet{}, false, io.ErrUnexpectedEOF
	}
	delete(stripe.bufferedSpool, stripe.expectedSeq)
	state.maybeCloseStripedPayloadSpool()
	packet := spooled.packet
	packet.Payload = payload
	return packet, true, nil
}

func (c *blastStreamReceiveCoordinator) storeStripedPendingOutputLocked(state *blastReceiveRunState, offset uint64, payload []byte) error {
	if state == nil || len(payload) == 0 {
		return nil
	}
	state.ensurePendingOutputMap()
	if state.hasPendingOutput(offset) {
		return nil
	}
	if state.pendingOutputBytes+uint64(len(payload)) <= stripedBlastPendingOutputLimitBytes {
		state.storePendingOutputMemory(offset, payload)
		return nil
	}
	return state.storePendingOutputSpool(offset, payload)
}

func (s *blastReceiveRunState) ensurePendingOutputMap() {
	if s.pendingOutput == nil {
		s.pendingOutput = make(map[uint64][]byte)
	}
}

func (s *blastReceiveRunState) hasPendingOutput(offset uint64) bool {
	if _, exists := s.pendingOutput[offset]; exists {
		return true
	}
	if s.pendingOutputSpoolLens == nil {
		return false
	}
	_, exists := s.pendingOutputSpoolLens[offset]
	return exists
}

func (s *blastReceiveRunState) storePendingOutputMemory(offset uint64, payload []byte) {
	s.pendingOutput[offset] = append([]byte(nil), payload...)
	s.pendingOutputBytes += uint64(len(payload))
}

func (s *blastReceiveRunState) storePendingOutputSpool(offset uint64, payload []byte) error {
	if offset > uint64(maxInt()) {
		return errors.New("striped pending output offset exceeds spool range")
	}
	spool, err := s.ensureStripedPayloadSpool()
	if err != nil {
		return err
	}
	written, err := spool.WriteAt(payload, int64(offset))
	if err != nil {
		return err
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}
	if s.pendingOutputSpoolLens == nil {
		s.pendingOutputSpoolLens = make(map[uint64]int)
	}
	s.pendingOutputSpoolLens[offset] = len(payload)
	return nil
}

func (c *blastStreamReceiveCoordinator) stripedCompleteLocked(state *blastReceiveRunState) bool {
	if state == nil {
		return false
	}
	if c != nil && c.expectedBytes > 0 && state.nextOffset == uint64(c.expectedBytes) {
		return true
	}
	if !state.finalTotalSet {
		return false
	}
	return c.stripedPayloadCompleteLocked(state)
}

func (c *blastStreamReceiveCoordinator) writeStripedPayloadLocked(state *blastReceiveRunState, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	if c.dst != io.Discard {
		if err := bufferOrderedParallelBlastPayload(c.dst, state, payload); err != nil {
			return err
		}
	}
	state.nextOffset += uint64(len(payload))
	c.bytesReceived += int64(len(payload))
	return nil
}

func (c *blastStreamReceiveCoordinator) flushStripedPayloadLocked(state *blastReceiveRunState) error {
	if c.dst == io.Discard || state == nil {
		return nil
	}
	return flushOrderedParallelBlastPayloadLocked(c.dst, state)
}

func (c *blastStreamReceiveCoordinator) flushStripedPendingPayloadsLocked(state *blastReceiveRunState) error {
	for {
		payload, ok := state.pendingOutput[state.nextOffset]
		if !ok {
			spooledLen, ok := state.pendingOutputSpoolLens[state.nextOffset]
			if !ok {
				return nil
			}
			if state.pendingOutputSpool == nil {
				return errors.New("striped pending output spool missing")
			}
			payload = make([]byte, spooledLen)
			n, err := state.pendingOutputSpool.ReadAt(payload, int64(state.nextOffset))
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if n != len(payload) {
				return io.ErrUnexpectedEOF
			}
			delete(state.pendingOutputSpoolLens, state.nextOffset)
			state.maybeCloseStripedPayloadSpool()
		} else {
			delete(state.pendingOutput, state.nextOffset)
			if uint64(len(payload)) >= state.pendingOutputBytes {
				state.pendingOutputBytes = 0
			} else {
				state.pendingOutputBytes -= uint64(len(payload))
			}
		}
		if err := c.writeStripedPayloadLocked(state, payload); err != nil {
			return err
		}
	}
}

func (c *blastStreamReceiveCoordinator) handleRepairTick(ctx context.Context, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.requestKnownRepairs(ctx, now); err != nil {
		return err
	}
	c.sendStatsFeedbackForAllLocked(ctx, now, false)
	for runID, state := range c.runs {
		if err := c.handleRepairTickRunLocked(ctx, runID, state, now); err != nil {
			return err
		}
	}
	return nil
}

func (c *blastStreamReceiveCoordinator) handleRepairTickRunLocked(ctx context.Context, runID [16]byte, state *blastReceiveRunState, now time.Time) error {
	if state == nil {
		return nil
	}
	if state.striped {
		return c.handleStripedRepairTickRunLocked(ctx, runID, state, now)
	}
	return c.handleLinearRepairTickRunLocked(ctx, runID, state, now)
}

func (c *blastStreamReceiveCoordinator) handleStripedRepairTickRunLocked(ctx context.Context, runID [16]byte, state *blastReceiveRunState, now time.Time) error {
	if c.stripedCompleteLocked(state) || !state.done && !state.finalTotalSet {
		return nil
	}
	if err := c.ensureRepairDeadlineOpenLocked("striped blast", state, now); err != nil {
		return err
	}
	if state.finalTotalSet {
		return c.requestFinalTotalStripedRepairs(ctx, runID, state, now)
	}
	return c.requestMissingStripedRepairs(ctx, runID, state)
}

func (c *blastStreamReceiveCoordinator) handleLinearRepairTickRunLocked(ctx context.Context, runID [16]byte, state *blastReceiveRunState, now time.Time) error {
	if !state.done || state.complete() {
		return nil
	}
	if err := c.ensureRepairDeadlineOpenLocked("blast", state, now); err != nil {
		return err
	}
	return c.requestMissingRepairs(ctx, runID, state)
}

func (c *blastStreamReceiveCoordinator) ensureRepairDeadlineOpenLocked(label string, state *blastReceiveRunState, now time.Time) error {
	if c.repairDeadline.IsZero() {
		c.repairDeadline = now.Add(c.repairGraceForState(state))
	}
	if now.After(c.repairDeadline) {
		return fmt.Errorf("%s incomplete: received %d bytes before repair grace expired", label, c.bytesReceived)
	}
	return nil
}

func (c *blastStreamReceiveCoordinator) stripedPayloadCompleteLocked(state *blastReceiveRunState) bool {
	if c == nil || state == nil || !state.finalTotalSet {
		return false
	}
	if c.dst == io.Discard {
		return c.bytesReceived >= int64(state.finalTotal)
	}
	return state.nextOffset == state.finalTotal
}

func (c *blastStreamReceiveCoordinator) requestMissingRepairs(ctx context.Context, runID [16]byte, state *blastReceiveRunState) error {
	for _, missing := range state.missingSeqBatches(maxRepairRequestSeqs, maxRepairRequestBatches) {
		if err := sendBlastStreamRepairRequestAll(ctx, c.lanes, runID, missing); err != nil {
			return err
		}
	}
	return nil
}

func (c *blastStreamReceiveCoordinator) requestFinalTotalStripedRepairs(ctx context.Context, runID [16]byte, state *blastReceiveRunState, now time.Time) error {
	if state == nil || !state.finalTotalSet || state.totalStripes <= 0 {
		return nil
	}
	chunkSize := stripedChunkSize(state)
	for stripeID, stripe := range state.stripes {
		missing := c.finalTotalMissingForStripe(state, stripe, stripeID, chunkSize, now)
		if len(missing) == 0 {
			continue
		}
		stripe.lastRepairRequestAt = now
		if err := sendBlastStreamRepairRequestStripeAll(ctx, c.lanes, stripe, runID, stripeID, missing); err != nil {
			return err
		}
	}
	return nil
}

func stripedChunkSize(state *blastReceiveRunState) int {
	if state == nil || state.stripedChunk <= 0 {
		return defaultChunkSize
	}
	return state.stripedChunk
}

func (c *blastStreamReceiveCoordinator) finalTotalMissingForStripe(state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, stripeID uint16, chunkSize int, now time.Time) []uint64 {
	if stripe == nil || stripe.done || repairRequestThrottled(stripe.lastRepairRequestAt, now) {
		return nil
	}
	expectedDataPackets := stripedDataPacketsForStripe(state.finalTotal, chunkSize, state.totalStripes, stripeID)
	if stripe.expectedSeq < expectedDataPackets {
		return stripe.missingSeqsBefore(expectedDataPackets, maxRepairRequestSeqs)
	}
	if c.stripedPayloadCompleteLocked(state) {
		return []uint64{stripe.expectedSeq}
	}
	return nil
}

func (c *blastStreamReceiveCoordinator) requestKnownRepairs(ctx context.Context, now time.Time) error {
	if c.cfg.DeferKnownGapRepairs {
		return nil
	}
	for runID, state := range c.runs {
		if err := c.requestKnownRepairRun(ctx, runID, state, now); err != nil {
			return err
		}
	}
	return nil
}

func (c *blastStreamReceiveCoordinator) requestKnownRepairRun(ctx context.Context, runID [16]byte, state *blastReceiveRunState, now time.Time) error {
	if state != nil && state.striped {
		return c.requestKnownStripedRepairs(ctx, runID, state, now)
	}
	batches := knownRepairBatches(state, now, blastKnownGapRepairDelay)
	if len(batches) == 0 {
		return nil
	}
	state.lastRepairRequestAt = now
	for _, missing := range batches {
		if err := sendBlastStreamRepairRequestAll(ctx, c.lanes, runID, missing); err != nil {
			return err
		}
	}
	return nil
}

func knownRepairBatches(state *blastReceiveRunState, now time.Time, delay time.Duration) [][]uint64 {
	if state == nil || state.done || repairRequestThrottled(state.lastRepairRequestAt, now) {
		return nil
	}
	if !knownGapReady(&state.gapFirstObservedAt, now, delay, state.hasKnownMissingSeqs()) {
		return nil
	}
	batches := state.knownMissingSeqBatches(maxRepairRequestSeqs, maxRepairRequestBatches)
	if len(batches) == 0 {
		state.gapFirstObservedAt = time.Time{}
	}
	return batches
}

func (c *blastStreamReceiveCoordinator) requestKnownStripedRepairs(ctx context.Context, runID [16]byte, state *blastReceiveRunState, now time.Time) error {
	if state == nil || c.stripedCompleteLocked(state) {
		return nil
	}
	for stripeID, stripe := range state.stripes {
		missing := knownStripedRepairSeqs(stripe, now)
		if len(missing) == 0 {
			continue
		}
		stripe.lastRepairRequestAt = now
		if err := sendBlastStreamRepairRequestStripeAll(ctx, c.lanes, stripe, runID, stripeID, missing); err != nil {
			return err
		}
	}
	return nil
}

func knownStripedRepairSeqs(stripe *blastStreamReceiveStripeState, now time.Time) []uint64 {
	if stripe == nil || stripe.done || repairRequestThrottled(stripe.lastRepairRequestAt, now) {
		return nil
	}
	if !knownGapReady(&stripe.gapFirstObservedAt, now, stripedBlastKnownGapRepairDelay, stripe.hasKnownMissingSeqs()) {
		return nil
	}
	missing := stripe.knownMissingSeqs(maxRepairRequestSeqs)
	if len(missing) == 0 {
		stripe.gapFirstObservedAt = time.Time{}
	}
	return missing
}

func repairRequestThrottled(last time.Time, now time.Time) bool {
	return !last.IsZero() && now.Sub(last) < blastRepairInterval
}

func knownGapReady(firstObserved *time.Time, now time.Time, delay time.Duration, hasGap bool) bool {
	if !hasGap {
		*firstObserved = time.Time{}
		return false
	}
	if firstObserved.IsZero() {
		*firstObserved = now
		return false
	}
	return now.Sub(*firstObserved) >= delay
}

func (c *blastStreamReceiveCoordinator) requestMissingStripedRepairs(ctx context.Context, runID [16]byte, state *blastReceiveRunState) error {
	if state == nil {
		return nil
	}
	for stripeID, stripe := range state.stripes {
		if stripe == nil || (!stripe.done && !stripe.terminalSeen) {
			continue
		}
		missing := stripe.missingSeqs(maxRepairRequestSeqs)
		if len(missing) == 0 {
			continue
		}
		if err := sendBlastStreamRepairRequestStripeAll(ctx, c.lanes, stripe, runID, stripeID, missing); err != nil {
			return err
		}
	}
	return nil
}

func (c *blastStreamReceiveCoordinator) completeRun(ctx context.Context, runID [16]byte, state *blastReceiveRunState) (bool, error) {
	if state == nil || !state.complete() {
		return false, nil
	}
	if err := c.validateFinalTotalLocked("blast", state.totalBytes); err != nil {
		return false, err
	}
	if err := c.flushGlobalPayload(state); err != nil {
		return false, err
	}
	c.sendStatsFeedbackLocked(ctx, runID, state, time.Now(), true)
	if err := sendBlastStreamRepairCompleteAll(ctx, c.lanes, runID); err != nil {
		return false, err
	}
	return true, nil
}

func (c *blastStreamReceiveCoordinator) validateFinalTotalLocked(label string, finalTotal uint64) error {
	if c == nil || c.expectedBytes <= 0 {
		return nil
	}
	expected := uint64(c.expectedBytes)
	if finalTotal < expected {
		return fmt.Errorf("%s incomplete: received %d bytes, want %d", label, finalTotal, expected)
	}
	if finalTotal > expected {
		return fmt.Errorf("%s final size %d exceeds expected %d", label, finalTotal, expected)
	}
	return nil
}

func (c *blastStreamReceiveCoordinator) recoverFEC(ctx context.Context, runID [16]byte, state *blastReceiveRunState) error {
	if !c.canRecoverFEC(state) {
		return nil
	}
	return c.recoverFECLoop(ctx, runID, state)
}

func (c *blastStreamReceiveCoordinator) canRecoverFEC(state *blastReceiveRunState) bool {
	if state == nil {
		return false
	}
	return c.cfg.FECGroupSize > 1
}

func (c *blastStreamReceiveCoordinator) recoverFECLoop(ctx context.Context, runID [16]byte, state *blastReceiveRunState) error {
	for {
		recovered := state.recoverFEC(c.expectedBytes)
		if len(recovered) == 0 {
			return nil
		}
		if err := c.applyRecoveredFEC(ctx, runID, state, recovered); err != nil {
			return err
		}
	}
}

func (c *blastStreamReceiveCoordinator) applyRecoveredFEC(ctx context.Context, runID [16]byte, state *blastReceiveRunState, recovered []blastRecoveredPacket) error {
	for _, packet := range recovered {
		if err := c.applyRecoveredFECPacket(state, packet); err != nil {
			return err
		}
	}
	_, err := c.completeRun(ctx, runID, state)
	return err
}

func (c *blastStreamReceiveCoordinator) applyRecoveredFECPacket(state *blastReceiveRunState, packet blastRecoveredPacket) error {
	if !state.acceptData(packet.seq) {
		return nil
	}
	state.feedbackBytes += uint64(len(packet.payload))
	c.feedbackBytes += int64(len(packet.payload))
	state.storeFECPayload(c.cfg.FECGroupSize, packet.seq, packet.payload)
	written, err := c.writeGlobalPayloadLocked(state, packet.seq, packet.offset, packet.payload)
	if err != nil {
		return err
	}
	c.bytesReceived += int64(written)
	c.observePeak(time.Now(), c.feedbackBytes)
	return nil
}

type recoveredStripedPacket struct {
	stripe *blastStreamReceiveStripeState
	packet Packet
}

func (c *blastStreamReceiveCoordinator) recoverStripedFEC(ctx context.Context, runID [16]byte, state *blastReceiveRunState) error {
	if state == nil || c.cfg.FECGroupSize <= 1 || c.recoveringFEC {
		return nil
	}
	c.recoveringFEC = true
	defer func() {
		c.recoveringFEC = false
	}()
	for {
		recovered := c.collectRecoveredStripedPackets(runID, state)
		if len(recovered) == 0 {
			return nil
		}
		if err := c.applyRecoveredStripedPackets(ctx, runID, state, recovered); err != nil {
			return err
		}
	}
}

func (c *blastStreamReceiveCoordinator) collectRecoveredStripedPackets(runID [16]byte, state *blastReceiveRunState) []recoveredStripedPacket {
	recovered := make([]recoveredStripedPacket, 0, 1)
	knownTotalBytes := c.stripedKnownTotalBytes(state)
	chunkSize := stripedChunkSize(state)
	for stripeID, stripe := range state.stripes {
		recovered = append(recovered, c.recoveredPacketsForStripe(runID, state, stripeID, stripe, chunkSize, knownTotalBytes)...)
	}
	return recovered
}

func (c *blastStreamReceiveCoordinator) stripedKnownTotalBytes(state *blastReceiveRunState) uint64 {
	if state.finalTotalSet {
		return state.finalTotal
	}
	if c.expectedBytes > 0 {
		return uint64(c.expectedBytes)
	}
	return 0
}

func (c *blastStreamReceiveCoordinator) recoveredPacketsForStripe(runID [16]byte, state *blastReceiveRunState, stripeID uint16, stripe *blastStreamReceiveStripeState, chunkSize int, knownTotalBytes uint64) []recoveredStripedPacket {
	if stripe == nil {
		return nil
	}
	recovered := make([]recoveredStripedPacket, 0, 1)
	for _, packet := range stripe.recoverFEC(c.cfg.FECGroupSize, chunkSize, state.totalStripes, knownTotalBytes) {
		recovered = append(recovered, recoveredStripedPacket{stripe: stripe, packet: newStripedPacket(PacketTypeData, runID, stripeID, packet.seq, packet.offset, packet.payload)})
	}
	return recovered
}

func (c *blastStreamReceiveCoordinator) applyRecoveredStripedPackets(ctx context.Context, runID [16]byte, state *blastReceiveRunState, recovered []recoveredStripedPacket) error {
	for _, item := range recovered {
		if _, err := c.handleStripedDataOrDoneLocked(ctx, runID, state, item.stripe, item.packet); err != nil {
			return err
		}
	}
	return nil
}

func (c *blastStreamReceiveCoordinator) stats(conns []net.PacketConn, connected bool) TransferStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	completedAt := time.Now()
	firstByteAt := c.firstByteAt
	if firstByteAt.IsZero() && c.bytesReceived > 0 {
		firstByteAt = completedAt
	}
	transport := TransportCaps{}
	if len(conns) > 0 {
		transport = PreviewTransportCaps(conns[0], c.cfg.Transport)
	}
	if connected {
		transport.Connected = true
	}
	out := TransferStats{
		BytesReceived:   c.bytesReceived,
		Lanes:           len(conns),
		StartedAt:       c.startedAt,
		FirstByteAt:     firstByteAt,
		CompletedAt:     completedAt,
		PeakGoodputMbps: c.peakMbps(),
		Transport:       transport,
	}
	out.markComplete(completedAt)
	return out
}

func ReceiveBlastStreamParallelToWriter(ctx context.Context, conns []net.PacketConn, dst io.Writer, cfg ReceiveConfig, expectedBytes int64) (TransferStats, error) {
	if len(conns) == 0 {
		return TransferStats{}, errors.New("no packet conns")
	}
	if len(conns) == 1 {
		return ReceiveBlastParallelToWriter(ctx, conns, dst, cfg, expectedBytes)
	}
	if dst == nil {
		dst = io.Discard
	}
	cfg.RequireComplete = true
	startedAt := time.Now()
	receiveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	lanes, err := newBlastStreamReceiveLanes(conns, cfg)
	if err != nil {
		return TransferStats{}, err
	}
	var connected atomic.Bool
	var receiveComplete atomic.Bool
	var wg sync.WaitGroup
	errCh := make(chan error, len(conns)+1)
	coordinator := newBlastStreamReceiveCoordinator(receiveCtx, lanes, dst, cfg, expectedBytes, startedAt)
	startBlastStreamReceiveLaneReaders(ctx, receiveCtx, lanes, cfg, coordinator, &connected, &receiveComplete, cancel, errCh, &wg)
	defer coordinator.Close()
	defer wg.Wait()
	return runBlastStreamReceiveLoop(ctx, receiveCtx, conns, coordinator, &connected, &receiveComplete, errCh)
}

func newBlastStreamReceiveLanes(conns []net.PacketConn, cfg ReceiveConfig) ([]*blastStreamReceiveLane, error) {
	lanes := make([]*blastStreamReceiveLane, len(conns))
	for i, conn := range conns {
		if conn == nil {
			return nil, fmt.Errorf("nil packet conn at lane %d", i)
		}
		sessionTracef("stream receive lane start lane=%d local=%s run=%x", i, conn.LocalAddr(), cfg.ExpectedRunID[:4])
		lanes[i] = &blastStreamReceiveLane{conn: conn, batcher: newPacketBatcher(conn, cfg.Transport)}
	}
	return lanes, nil
}

func startBlastStreamReceiveLaneReaders(parent context.Context, receiveCtx context.Context, lanes []*blastStreamReceiveLane, cfg ReceiveConfig, coordinator *blastStreamReceiveCoordinator, connected *atomic.Bool, receiveComplete *atomic.Bool, cancel context.CancelFunc, errCh chan<- error, wg *sync.WaitGroup) {
	for i, lane := range lanes {
		wg.Add(1)
		go func(i int, lane *blastStreamReceiveLane) {
			defer wg.Done()
			if err := readBlastStreamReceiveLaneDirect(receiveCtx, i, lane, cfg, coordinator, connected, receiveComplete, cancel); err != nil {
				reportBlastStreamReceiveLaneError(parent, receiveComplete, cancel, errCh, err)
			}
		}(i, lane)
	}
}

func reportBlastStreamReceiveLaneError(parent context.Context, receiveComplete *atomic.Bool, cancel context.CancelFunc, errCh chan<- error, err error) {
	if blastStreamReceiveCompletionCanceled(err, parent, receiveComplete) {
		return
	}
	select {
	case errCh <- err:
	default:
	}
	cancel()
}

func runBlastStreamReceiveLoop(ctx context.Context, receiveCtx context.Context, conns []net.PacketConn, coordinator *blastStreamReceiveCoordinator, connected *atomic.Bool, receiveComplete *atomic.Bool, errCh <-chan error) (TransferStats, error) {
	repairTicker := time.NewTicker(blastRepairInterval)
	defer repairTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return TransferStats{}, ctx.Err()
		case now := <-repairTicker.C:
			if stats, done, err := handleBlastStreamReceiveLoopError(ctx, conns, coordinator, connected, receiveComplete, coordinator.handleRepairTick(receiveCtx, now)); done || err != nil {
				return stats, err
			}
		case err := <-errCh:
			if stats, done, err := handleBlastStreamReceiveLoopError(ctx, conns, coordinator, connected, receiveComplete, err); done || err != nil {
				return stats, err
			}
		case <-receiveCtx.Done():
			return blastStreamReceiveDoneResult(ctx, receiveCtx, conns, coordinator, connected, receiveComplete, errCh)
		}
	}
}

func handleBlastStreamReceiveLoopError(ctx context.Context, conns []net.PacketConn, coordinator *blastStreamReceiveCoordinator, connected *atomic.Bool, receiveComplete *atomic.Bool, err error) (TransferStats, bool, error) {
	if err == nil {
		return TransferStats{}, false, nil
	}
	if blastStreamReceiveCompletionCanceled(err, ctx, receiveComplete) {
		return coordinator.stats(conns, connected.Load()), true, nil
	}
	return TransferStats{}, true, err
}

func blastStreamReceiveDoneResult(ctx context.Context, receiveCtx context.Context, conns []net.PacketConn, coordinator *blastStreamReceiveCoordinator, connected *atomic.Bool, receiveComplete *atomic.Bool, errCh <-chan error) (TransferStats, error) {
	if ctx.Err() != nil {
		return TransferStats{}, ctx.Err()
	}
	if receiveComplete.Load() {
		return coordinator.stats(conns, connected.Load()), nil
	}
	select {
	case err := <-errCh:
		if err != nil {
			return TransferStats{}, err
		}
	default:
	}
	return TransferStats{}, receiveCtx.Err()
}

func blastStreamReceiveCompletionCanceled(err error, parent context.Context, receiveComplete *atomic.Bool) bool {
	if err == nil || parent == nil || receiveComplete == nil {
		return false
	}
	return errors.Is(err, context.Canceled) && parent.Err() == nil && receiveComplete.Load()
}

func readBlastStreamReceiveLaneDirect(ctx context.Context, _ int, lane *blastStreamReceiveLane, cfg ReceiveConfig, coordinator *blastStreamReceiveCoordinator, connected *atomic.Bool, receiveComplete *atomic.Bool, cancel context.CancelFunc) error {
	if lane == nil || lane.batcher == nil {
		return nil
	}
	readBufs := newBlastBatchReadBuffers(lane.batcher.MaxBatch())
	for {
		n, err := lane.batcher.ReadBatch(ctx, blastReadPoll, readBufs)
		if err != nil {
			if handled, readErr := handleBlastStreamLaneReadError(ctx, err); handled {
				return readErr
			}
			continue
		}
		if err := processBlastStreamLaneBatch(ctx, lane, cfg, coordinator, connected, receiveComplete, cancel, readBufs[:n]); err != nil {
			return err
		}
	}
}

func handleBlastStreamLaneReadError(ctx context.Context, err error) (bool, error) {
	if ctx.Err() != nil {
		return true, nil
	}
	if isNetTimeout(err) {
		return false, nil
	}
	if errors.Is(err, net.ErrClosed) {
		return true, err
	}
	return false, nil
}

type blastStreamLanePacket struct {
	packetType   PacketType
	runID        [16]byte
	stripeID     uint16
	totalStripes int
	seq          uint64
	offset       uint64
	groupCount   uint64
	payload      []byte
	addr         net.Addr
}

func processBlastStreamLaneBatch(ctx context.Context, lane *blastStreamReceiveLane, cfg ReceiveConfig, coordinator *blastStreamReceiveCoordinator, connected *atomic.Bool, receiveComplete *atomic.Bool, cancel context.CancelFunc, readBufs []batchReadBuffer) error {
	for i := range readBufs {
		packet, ok := decodeBlastStreamLanePacket(readBufs[i], cfg)
		if !ok {
			continue
		}
		complete, err := handleBlastStreamLanePacket(ctx, lane, cfg, coordinator, connected, packet)
		if err != nil {
			return err
		}
		if complete {
			if receiveComplete != nil {
				receiveComplete.Store(true)
			}
			cancel()
			return nil
		}
	}
	return nil
}

func decodeBlastStreamLanePacket(buf batchReadBuffer, cfg ReceiveConfig) (blastStreamLanePacket, bool) {
	packetType, payload, runID, seq, offset, ok := decodeBlastPacketFullWithAEAD(buf.Bytes[:buf.N], cfg.PacketAEAD)
	if !ok || !receiveConfigAllowsRunID(cfg, runID) {
		return blastStreamLanePacket{}, false
	}
	packet := blastStreamLanePacket{
		packetType:   packetType,
		payload:      payload,
		runID:        runID,
		seq:          seq,
		offset:       offset,
		stripeID:     binary.BigEndian.Uint16(buf.Bytes[2:4]),
		totalStripes: blastStreamLaneTotalStripes(packetType, seq),
		addr:         buf.Addr,
	}
	if packetType == PacketTypeParity && buf.N >= headerLen {
		packet.groupCount = binary.BigEndian.Uint64(buf.Bytes[36:44])
	}
	return packet, true
}

func blastStreamLaneTotalStripes(packetType PacketType, seq uint64) int {
	if packetType == PacketTypeHello && seq > 0 && seq <= uint64(maxParallelStripes) {
		return int(seq)
	}
	return 1
}

func handleBlastStreamLanePacket(ctx context.Context, lane *blastStreamReceiveLane, cfg ReceiveConfig, coordinator *blastStreamReceiveCoordinator, connected *atomic.Bool, packet blastStreamLanePacket) (bool, error) {
	if packet.packetType == PacketTypeHello {
		if err := handleBlastStreamLaneHello(ctx, lane, cfg, connected, packet); err != nil {
			return false, err
		}
	}
	return coordinator.handlePacketStripe(
		ctx,
		lane,
		packet.stripeID,
		packet.totalStripes,
		packet.packetType,
		packet.runID,
		packet.seq,
		packet.offset,
		packet.groupCount,
		packet.payload,
		packet.addr,
	)
}

func handleBlastStreamLaneHello(ctx context.Context, lane *blastStreamReceiveLane, cfg ReceiveConfig, connected *atomic.Bool, packet blastStreamLanePacket) error {
	maybeConnectBlastStreamReceiveLane(lane, cfg, connected, packet.addr)
	lane.peer = cloneAddr(packet.addr)
	return sendHelloAckBatch(ctx, lane.batcher, packet.addr, packet.runID, packet.stripeID, uint16(packet.totalStripes))
}

func maybeConnectBlastStreamReceiveLane(lane *blastStreamReceiveLane, cfg ReceiveConfig, connected *atomic.Bool, addr net.Addr) {
	if lane.batcher.MaxBatch() != 1 || lane.batcher.Capabilities().Connected {
		return
	}
	connectedBatcher, ok := newConnectedUDPBatcher(lane.conn, addr, cfg.Transport)
	if !ok {
		return
	}
	lane.batcher = connectedBatcher
	if connected != nil {
		connected.Store(true)
	}
}

func sendBlastStreamRepairRequestAll(ctx context.Context, lanes []*blastStreamReceiveLane, runID [16]byte, missing []uint64) error {
	if len(missing) == 0 {
		return nil
	}
	for _, lane := range lanes {
		if lane == nil || lane.batcher == nil || lane.peer == nil {
			continue
		}
		if err := sendRepairRequest(ctx, lane.batcher, lane.peer, runID, missing); err != nil {
			return err
		}
	}
	return nil
}

func sendBlastStreamRepairRequestStripeAll(ctx context.Context, lanes []*blastStreamReceiveLane, stripe *blastStreamReceiveStripeState, runID [16]byte, stripeID uint16, missing []uint64) error {
	if len(missing) == 0 {
		return nil
	}
	sent := 0
	primary := stripePrimaryLane(stripe)
	if blastStreamReceiveLaneReady(primary) {
		if err := sendRepairRequestToLane(ctx, primary, runID, stripeID, missing); err != nil {
			return err
		}
		sent++
	}
	for _, lane := range lanes {
		if lane == primary || !blastStreamReceiveLaneReady(lane) {
			continue
		}
		if err := sendRepairRequestToLane(ctx, lane, runID, stripeID, missing); err != nil {
			return err
		}
		sent++
	}
	if sent > 0 {
		sessionTracef("blast striped repair request stripe=%d missing=%d first=%d lanes=%d", stripeID, len(missing), missing[0], sent)
	}
	return nil
}

func stripePrimaryLane(stripe *blastStreamReceiveStripeState) *blastStreamReceiveLane {
	if stripe == nil {
		return nil
	}
	return stripe.lane
}

func sendRepairRequestToLane(ctx context.Context, lane *blastStreamReceiveLane, runID [16]byte, stripeID uint16, missing []uint64) error {
	return sendRepairRequestStripe(ctx, lane.batcher, lane.peer, runID, stripeID, missing)
}

func sendBlastStreamRepairCompleteAll(ctx context.Context, lanes []*blastStreamReceiveLane, runID [16]byte) error {
	for _, lane := range lanes {
		if lane == nil || lane.batcher == nil || lane.peer == nil {
			continue
		}
		if err := sendRepairComplete(ctx, lane.batcher, lane.peer, runID); err != nil {
			return err
		}
	}
	return nil
}

type reliableParallelResult struct {
	stats TransferStats
	err   error
}

func ReceiveReliableParallelToWriter(ctx context.Context, conns []net.PacketConn, dst io.Writer, cfg ReceiveConfig, expectedBytes int64) (TransferStats, error) {
	if len(conns) == 0 {
		return TransferStats{}, errors.New("no packet conns")
	}
	if dst == nil {
		dst = io.Discard
	}
	recvCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	startedAt := time.Now()
	receiverDst := newPeakTrackingWriter(dst, startedAt)

	results := make(chan reliableParallelResult, len(conns))
	var wg sync.WaitGroup
	for _, conn := range conns {
		startReliableParallelReceiver(recvCtx, conn, receiverDst, cfg, results, &wg, cancel)
	}
	wg.Wait()
	close(results)

	out, receiveErr := collectReliableParallelResults(results, startedAt, receiverDst.PeakMbps())
	if receiveErr != nil {
		return TransferStats{}, receiveErr
	}
	if expectedBytes > 0 && out.BytesReceived != expectedBytes {
		return TransferStats{}, fmt.Errorf("parallel reliable received %d bytes, want %d", out.BytesReceived, expectedBytes)
	}
	out.markComplete(time.Now())
	return out, nil
}

func startReliableParallelReceiver(ctx context.Context, conn net.PacketConn, dst io.Writer, cfg ReceiveConfig, results chan<- reliableParallelResult, wg *sync.WaitGroup, cancel context.CancelFunc) {
	if conn == nil {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		stats, err := ReceiveToWriter(ctx, conn, "", dst, cfg)
		if err != nil {
			cancel()
		}
		results <- reliableParallelResult{stats: stats, err: err}
	}()
}

func collectReliableParallelResults(results <-chan reliableParallelResult, startedAt time.Time, peakGoodputMbps float64) (TransferStats, error) {
	out := TransferStats{
		StartedAt:       startedAt,
		PeakGoodputMbps: peakGoodputMbps,
	}
	var receiveErr error
	for result := range results {
		mergeReliableParallelResult(&out, result.stats)
		receiveErr = preferInformativeResultError(receiveErr, result.err)
	}
	return out, receiveErr
}

func mergeReliableParallelResult(out *TransferStats, stats TransferStats) {
	out.BytesReceived += stats.BytesReceived
	out.PacketsSent += stats.PacketsSent
	out.PacketsAcked += stats.PacketsAcked
	out.Retransmits += stats.Retransmits
	if !stats.FirstByteAt.IsZero() && (out.FirstByteAt.IsZero() || stats.FirstByteAt.Before(out.FirstByteAt)) {
		out.FirstByteAt = stats.FirstByteAt
	}
	if out.Transport.Kind == "" {
		out.Transport = stats.Transport
	}
}

type peakTrackingWriter struct {
	w     io.Writer
	mu    sync.Mutex
	total int64
	peak  intervalStats
	now   func() time.Time
}

func newPeakTrackingWriter(w io.Writer, startedAt time.Time) *peakTrackingWriter {
	if w == nil {
		w = io.Discard
	}
	writer := &peakTrackingWriter{w: w}
	writer.peak.minWindow = blastRateFeedbackInterval
	writer.peak.Observe(startedAt, 0)
	writer.now = time.Now
	return writer
}

func (w *peakTrackingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.w.Write(p)
	if n > 0 {
		w.total += int64(n)
		w.peak.Observe(w.now(), w.total)
	}
	return n, err
}

func (w *peakTrackingWriter) PeakMbps() float64 {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.peak.PeakMbps()
}

type blastReceiveRunState struct {
	addr                       net.Addr
	seen                       blastSeqSet
	pending                    map[uint64][]byte
	fecGroups                  map[uint64]*blastFECReceiveGroup
	fecParity                  map[uint64]blastFECParity
	writeBuf                   []byte
	nextWriteSeq               uint64
	maxSeqPlusOne              uint64
	done                       bool
	doneAt                     time.Time
	totalPackets               uint64
	totalBytes                 uint64
	repairPending              bool
	nextRepairSeq              uint64
	gapFirstObservedAt         time.Time
	lastRepairRequestAt        time.Time
	receivedBytes              uint64
	feedbackBytes              uint64
	striped                    bool
	totalStripes               int
	stripes                    map[uint16]*blastStreamReceiveStripeState
	pendingOutput              map[uint64][]byte
	pendingOutputBytes         uint64
	stripedFutureBufferedBytes uint64
	pendingOutputSpool         *os.File
	pendingOutputSpoolLens     map[uint64]int
	pendingOutputSpoolPath     string
	nextOffset                 uint64
	finalTotal                 uint64
	finalTotalSet              bool
	completedStripes           int
	stripedChunk               int
	spool                      *os.File
	spoolPath                  string
}

type blastSeqSet struct {
	dense  []uint64
	sparse map[uint64]uint64
	count  uint64
}

type blastStreamReceiveStripeState struct {
	lane                *blastStreamReceiveLane
	addr                net.Addr
	seen                blastSeqSet
	buffered            map[uint64]Packet
	bufferedSpool       map[uint64]stripedSpooledPacket
	fecGroups           map[uint64]*blastFECReceiveGroup
	fecParity           map[uint64]blastFECParity
	feedbackCounted     blastSeqSet
	expectedSeq         uint64
	maxSeqPlusOne       uint64
	done                bool
	terminalSeen        bool
	totalPackets        uint64
	nextRepairSeq       uint64
	gapFirstObservedAt  time.Time
	lastRepairRequestAt time.Time
}

type stripedSpooledPacket struct {
	packet     Packet
	payloadLen int
}

const blastSeqSetMaxDenseWords = 1 << 20

func (s *blastSeqSet) Add(seq uint64) bool {
	word := seq / 64
	bit := uint64(1) << (seq % 64)
	if word < blastSeqSetMaxDenseWords {
		if word >= uint64(len(s.dense)) {
			s.dense = append(s.dense, make([]uint64, int(word)+1-len(s.dense))...)
		}
		if s.dense[word]&bit != 0 {
			return false
		}
		s.dense[word] |= bit
		s.count++
		return true
	}
	if s.sparse == nil {
		s.sparse = make(map[uint64]uint64)
	}
	if s.sparse[word]&bit != 0 {
		return false
	}
	s.sparse[word] |= bit
	s.count++
	return true
}

func (s *blastSeqSet) Has(seq uint64) bool {
	if s == nil {
		return false
	}
	word := seq / 64
	bit := uint64(1) << (seq % 64)
	if word < uint64(len(s.dense)) {
		return s.dense[word]&bit != 0
	}
	if s.sparse == nil {
		return false
	}
	return s.sparse[word]&bit != 0
}

func (s *blastSeqSet) Len() uint64 {
	if s == nil {
		return 0
	}
	return s.count
}

type blastFECParity struct {
	startSeq uint64
	offset   uint64
	count    uint64
	payload  []byte
}

type blastFECReceiveGroup struct {
	xor []byte
}

type blastRecoveredPacket struct {
	seq     uint64
	offset  uint64
	payload []byte
}

func newBlastReceiveRunState(addr net.Addr) *blastReceiveRunState {
	return &blastReceiveRunState{
		addr: cloneAddr(addr),
	}
}

func (s *blastReceiveRunState) enableStriped(totalStripes int) {
	if s == nil {
		return
	}
	if totalStripes < 1 {
		totalStripes = 1
	}
	s.striped = true
	if totalStripes > s.totalStripes || (s.totalStripes > 0 && totalStripes != s.totalStripes && !s.stripedDataStarted()) {
		s.totalStripes = totalStripes
	}
	if s.stripes == nil {
		s.stripes = make(map[uint16]*blastStreamReceiveStripeState, totalStripes)
	}
	if s.pendingOutput == nil {
		s.pendingOutput = make(map[uint64][]byte)
	}
}

func (s *blastReceiveRunState) stripedDataStarted() bool {
	if s == nil {
		return false
	}
	if s.hasStripedRunProgress() || s.hasStripedPendingOutput() {
		return true
	}
	for _, stripe := range s.stripes {
		if stripe.stripedDataStarted() {
			return true
		}
	}
	return false
}

func (s *blastReceiveRunState) hasStripedRunProgress() bool {
	return s.nextOffset != 0 ||
		s.finalTotalSet ||
		s.completedStripes != 0 ||
		s.pendingOutputBytes != 0 ||
		s.stripedFutureBufferedBytes != 0
}

func (s *blastReceiveRunState) hasStripedPendingOutput() bool {
	return len(s.pendingOutput) > 0 || len(s.pendingOutputSpoolLens) > 0
}

func (s *blastStreamReceiveStripeState) stripedDataStarted() bool {
	if s == nil {
		return false
	}
	return s.seen.Len() > 0 ||
		s.expectedSeq != 0 ||
		s.maxSeqPlusOne != 0 ||
		s.done ||
		s.terminalSeen ||
		s.totalPackets != 0 ||
		len(s.buffered) > 0 ||
		len(s.bufferedSpool) > 0
}

func (s *blastReceiveRunState) stripeState(stripeID uint16, lane *blastStreamReceiveLane, addr net.Addr) *blastStreamReceiveStripeState {
	if s == nil {
		return nil
	}
	if s.stripes == nil {
		s.stripes = make(map[uint16]*blastStreamReceiveStripeState)
	}
	stripe := s.stripes[stripeID]
	if stripe == nil {
		stripe = &blastStreamReceiveStripeState{buffered: make(map[uint64]Packet)}
		s.stripes[stripeID] = stripe
	}
	if lane != nil {
		stripe.lane = lane
	}
	if stripe.addr == nil && addr != nil {
		stripe.addr = cloneAddr(addr)
	}
	return stripe
}

func (s *blastStreamReceiveStripeState) storeBufferedPacket(packet Packet) {
	if s == nil {
		return
	}
	if s.buffered == nil {
		s.buffered = make(map[uint64]Packet)
	}
	s.buffered[packet.Seq] = clonePacket(packet)
}

func (s *blastReceiveRunState) observeStripedPayload(payload []byte) {
	if s == nil || len(payload) == 0 {
		return
	}
	if len(payload) > s.stripedChunk {
		s.stripedChunk = len(payload)
	}
}

func (s *blastReceiveRunState) canBufferStripedFuturePayload(payloadLen int) bool {
	if s == nil || payloadLen <= 0 {
		return true
	}
	return s.stripedFutureBufferedBytes+uint64(payloadLen) <= stripedBlastFutureBufferLimitBytes
}

func (s *blastReceiveRunState) releaseStripedFutureBuffer(payloadLen int) {
	if s == nil || payloadLen <= 0 {
		return
	}
	payloadBytes := uint64(payloadLen)
	if payloadBytes >= s.stripedFutureBufferedBytes {
		s.stripedFutureBufferedBytes = 0
		return
	}
	s.stripedFutureBufferedBytes -= payloadBytes
}

func (s *blastReceiveRunState) ensureStripedPayloadSpool() (*os.File, error) {
	if s == nil {
		return nil, errors.New("striped payload spool state missing")
	}
	if s.pendingOutputSpool != nil {
		return s.pendingOutputSpool, nil
	}
	spool, err := os.CreateTemp("", "derphole-striped-pending-*")
	if err != nil {
		return nil, err
	}
	s.pendingOutputSpool = spool
	s.pendingOutputSpoolPath = spool.Name()
	return spool, nil
}

func (s *blastReceiveRunState) maybeCloseStripedPayloadSpool() {
	if s == nil || s.pendingOutputSpool == nil {
		return
	}
	if len(s.pendingOutputSpoolLens) > 0 || s.hasStripedFutureSpooledPackets() {
		return
	}
	s.closeStripedPayloadSpool()
}

func (s *blastReceiveRunState) hasStripedFutureSpooledPackets() bool {
	if s == nil {
		return false
	}
	for _, stripe := range s.stripes {
		if stripe != nil && len(stripe.bufferedSpool) > 0 {
			return true
		}
	}
	return false
}

func (s *blastReceiveRunState) closeStripedPayloadSpool() {
	if s == nil || s.pendingOutputSpool == nil {
		return
	}
	_ = s.pendingOutputSpool.Close()
	_ = os.Remove(s.pendingOutputSpoolPath)
	s.pendingOutputSpool = nil
	s.pendingOutputSpoolLens = nil
	s.pendingOutputSpoolPath = ""
}

func (s *blastReceiveRunState) acceptData(seq uint64) bool {
	if s == nil {
		return false
	}
	if !s.seen.Add(seq) {
		return false
	}
	if seq+1 > s.maxSeqPlusOne {
		s.maxSeqPlusOne = seq + 1
	}
	return true
}

func (s *blastReceiveRunState) markDoneWithTotalBytes(totalPackets uint64, totalBytes uint64, addr net.Addr) {
	if s == nil {
		return
	}
	if s.addr == nil && addr != nil {
		s.addr = cloneAddr(addr)
	}
	if totalPackets < s.maxSeqPlusOne {
		totalPackets = s.maxSeqPlusOne
	}
	s.totalPackets = totalPackets
	s.totalBytes = totalBytes
	s.done = true
}

func (s *blastReceiveRunState) complete() bool {
	return s != nil && s.done && s.seen.Len() >= s.totalPackets
}

func (s *blastReceiveRunState) missingSeqBatches(batchSize int, maxBatches int) [][]uint64 {
	if s == nil || !s.done || s.totalPackets == 0 || !validRepairBatchLimits(batchSize, maxBatches) {
		return nil
	}
	start := s.nextRepairSeq
	if start >= s.totalPackets {
		start = 0
	}
	batches, last, found := collectMissingSeqBatches(s.totalPackets, batchSize, maxBatches, func(checked uint64) uint64 {
		return (start + checked) % s.totalPackets
	}, s.seen.Has)
	if found {
		s.nextRepairSeq = (last + 1) % s.totalPackets
	}
	return batches
}

func (s *blastReceiveRunState) knownMissingSeqBatches(batchSize int, maxBatches int) [][]uint64 {
	if s == nil || s.maxSeqPlusOne <= s.nextWriteSeq || !validRepairBatchLimits(batchSize, maxBatches) {
		return nil
	}
	span := s.maxSeqPlusOne - s.nextWriteSeq
	start := s.nextRepairSeq
	if start < s.nextWriteSeq || start >= s.maxSeqPlusOne {
		start = s.nextWriteSeq
	}
	batches, last, found := collectMissingSeqBatches(span, batchSize, maxBatches, func(checked uint64) uint64 {
		return s.nextWriteSeq + ((start - s.nextWriteSeq + checked) % span)
	}, s.seen.Has)
	if found {
		s.nextRepairSeq = last + 1
	}
	return batches
}

func validRepairBatchLimits(batchSize int, maxBatches int) bool {
	return batchSize > 0 && maxBatches > 0
}

func collectMissingSeqBatches(span uint64, batchSize int, maxBatches int, seqAt func(uint64) uint64, seen func(uint64) bool) ([][]uint64, uint64, bool) {
	batches := make([][]uint64, 0, maxBatches)
	current := make([]uint64, 0, batchSize)
	maxSeqs := batchSize * maxBatches
	var last uint64
	found := false
	for checked := uint64(0); checked < span && len(batches) < maxBatches; checked++ {
		seq := seqAt(checked)
		if seen(seq) {
			continue
		}
		current = append(current, seq)
		last = seq
		found = true
		if len(current) == batchSize {
			batches = append(batches, current)
			current = make([]uint64, 0, batchSize)
		}
		if len(batches)*batchSize+len(current) >= maxSeqs {
			break
		}
	}
	if len(current) > 0 && len(batches) < maxBatches {
		batches = append(batches, current)
	}
	return batches, last, found
}

func (s *blastReceiveRunState) hasKnownMissingSeqs() bool {
	if s == nil || s.maxSeqPlusOne <= s.nextWriteSeq {
		return false
	}
	for seq := s.nextWriteSeq; seq < s.maxSeqPlusOne; seq++ {
		if !s.seen.Has(seq) {
			return true
		}
	}
	return false
}

func (s *blastStreamReceiveStripeState) missingSeqs(limit int) []uint64 {
	if s == nil || (!s.done && !s.terminalSeen) || limit <= 0 || s.totalPackets == 0 {
		return nil
	}
	start := s.missingSeqStart()
	out, last := collectMissingSeqs(s.totalPackets, limit, func(checked uint64) uint64 {
		return (start + checked) % s.totalPackets
	}, s.seen.Has)
	if len(out) != 0 {
		s.nextRepairSeq = (last + 1) % s.totalPackets
	}
	return out
}

func (s *blastStreamReceiveStripeState) missingSeqStart() uint64 {
	if s.expectedSeq < s.totalPackets && !s.seen.Has(s.expectedSeq) {
		return s.expectedSeq
	}
	if s.nextRepairSeq >= s.totalPackets {
		return 0
	}
	return s.nextRepairSeq
}

func (s *blastStreamReceiveStripeState) missingSeqsBefore(endSeq uint64, limit int) []uint64 {
	if s == nil || limit <= 0 || endSeq <= s.expectedSeq {
		return nil
	}
	span := endSeq - s.expectedSeq
	start := s.missingSeqStartInRange(endSeq)
	out, last := collectMissingSeqs(span, limit, func(checked uint64) uint64 {
		return s.expectedSeq + ((start - s.expectedSeq + checked) % span)
	}, s.seen.Has)
	if len(out) != 0 {
		s.nextRepairSeq = last + 1
	}
	return out
}

func (s *blastStreamReceiveStripeState) knownMissingSeqs(limit int) []uint64 {
	if s == nil || limit <= 0 || s.maxSeqPlusOne <= s.expectedSeq {
		return nil
	}
	span := s.maxSeqPlusOne - s.expectedSeq
	start := s.missingSeqStartInRange(s.maxSeqPlusOne)
	out, last := collectMissingSeqs(span, limit, func(checked uint64) uint64 {
		return s.expectedSeq + ((start - s.expectedSeq + checked) % span)
	}, s.seen.Has)
	if len(out) != 0 {
		s.nextRepairSeq = last + 1
	}
	return out
}

func (s *blastStreamReceiveStripeState) missingSeqStartInRange(endSeq uint64) uint64 {
	if !s.seen.Has(s.expectedSeq) {
		return s.expectedSeq
	}
	if s.nextRepairSeq < s.expectedSeq || s.nextRepairSeq >= endSeq {
		return s.expectedSeq
	}
	return s.nextRepairSeq
}

func collectMissingSeqs(span uint64, limit int, seqAt func(uint64) uint64, seen func(uint64) bool) ([]uint64, uint64) {
	out := make([]uint64, 0, limit)
	var last uint64
	for checked := uint64(0); checked < span && len(out) < limit; checked++ {
		seq := seqAt(checked)
		if seen(seq) {
			continue
		}
		out = append(out, seq)
		last = seq
	}
	return out, last
}

func (s *blastStreamReceiveStripeState) hasKnownMissingSeqs() bool {
	if s == nil || s.maxSeqPlusOne <= s.expectedSeq {
		return false
	}
	for seq := s.expectedSeq; seq < s.maxSeqPlusOne; seq++ {
		if !s.seen.Has(seq) {
			return true
		}
	}
	return false
}

func (s *blastStreamReceiveStripeState) storeFECPayload(groupSize int, seq uint64, payload []byte) {
	if s == nil || groupSize <= 1 || len(payload) == 0 {
		return
	}
	groupStart := (seq / uint64(groupSize)) * uint64(groupSize)
	if s.fecGroups == nil {
		s.fecGroups = make(map[uint64]*blastFECReceiveGroup)
	}
	group := s.fecGroups[groupStart]
	if group == nil {
		group = &blastFECReceiveGroup{}
		s.fecGroups[groupStart] = group
	}
	if len(group.xor) < len(payload) {
		grown := make([]byte, len(payload))
		copy(grown, group.xor)
		group.xor = grown
	}
	for i := range payload {
		group.xor[i] ^= payload[i]
	}
	s.cleanupFECGroupIfComplete(groupStart, uint64(groupSize))
}

func (s *blastStreamReceiveStripeState) storeFECParity(startSeq uint64, offset uint64, count uint64, payload []byte) {
	if s == nil || count == 0 || len(payload) == 0 {
		return
	}
	if s.fecParity == nil {
		s.fecParity = make(map[uint64]blastFECParity)
	}
	s.fecParity[startSeq] = blastFECParity{
		startSeq: startSeq,
		offset:   offset,
		count:    count,
		payload:  append([]byte(nil), payload...),
	}
	s.cleanupFECGroupIfComplete(startSeq, count)
}

func (s *blastStreamReceiveStripeState) cleanupFECGroupIfComplete(startSeq uint64, count uint64) {
	if s == nil || count == 0 {
		return
	}
	for seq := startSeq; seq < startSeq+count; seq++ {
		if !s.seen.Has(seq) {
			return
		}
	}
	if s.fecGroups != nil {
		delete(s.fecGroups, startSeq)
	}
	if s.fecParity != nil {
		delete(s.fecParity, startSeq)
	}
}

func (s *blastStreamReceiveStripeState) recoverFEC(groupSize int, chunkSize int, totalStripes int, knownTotalBytes uint64) []blastRecoveredPacket {
	if s == nil || groupSize <= 1 || len(s.fecParity) == 0 {
		return nil
	}
	chunkSize = normalizedBlastChunkSize(chunkSize)
	totalStripes = normalizedBlastStripeCount(totalStripes)
	recovered := make([]blastRecoveredPacket, 0, 1)
	for startSeq, parity := range s.fecParity {
		packet, ok, deleteParity := s.recoverStripedFECPacket(startSeq, parity, chunkSize, totalStripes, knownTotalBytes)
		if deleteParity {
			delete(s.fecParity, startSeq)
		}
		if ok {
			recovered = append(recovered, packet)
		}
	}
	return recovered
}

func (s *blastStreamReceiveStripeState) recoverStripedFECPacket(startSeq uint64, parity blastFECParity, chunkSize int, totalStripes int, knownTotalBytes uint64) (blastRecoveredPacket, bool, bool) {
	if skipLeadingFECRecovery(knownTotalBytes, parity, s.maxSeqPlusOne) {
		return blastRecoveredPacket{}, false, false
	}
	missingSeq, missing, ok := singleFECMissingSeq(&s.seen, parity)
	if !ok {
		if missing == 0 {
			s.cleanupFECGroupIfComplete(parity.startSeq, parity.count)
		}
		return blastRecoveredPacket{}, false, false
	}
	group := s.fecGroups[startSeq]
	if group == nil || len(group.xor) == 0 {
		return blastRecoveredPacket{}, false, false
	}
	payload := recoverFECPayload(parity, group)
	offset := stripedFECOffsetForSeq(parity.offset, parity.startSeq, missingSeq, chunkSize, totalStripes)
	payload, ok = trimRecoveredFECPayload(payload, offset, knownTotalBytes)
	if !ok {
		return blastRecoveredPacket{}, false, true
	}
	return blastRecoveredPacket{seq: missingSeq, offset: offset, payload: payload}, true, true
}

func (s *blastReceiveRunState) recoverLinearFECPacket(startSeq uint64, parity blastFECParity, knownTotalBytes uint64) (blastRecoveredPacket, bool, bool) {
	missingSeq, group, ok, deleteParity := s.linearFECRecoveryInputs(startSeq, parity, knownTotalBytes)
	if !ok {
		return blastRecoveredPacket{}, false, deleteParity
	}
	payload := recoverFECPayload(parity, group)
	offset := linearFECOffsetForSeq(parity, missingSeq)
	payload, ok = trimRecoveredFECPayload(payload, offset, knownTotalBytes)
	if !ok {
		return blastRecoveredPacket{}, false, true
	}
	return blastRecoveredPacket{seq: missingSeq, offset: offset, payload: payload}, true, true
}

func (s *blastReceiveRunState) linearFECRecoveryInputs(startSeq uint64, parity blastFECParity, knownTotalBytes uint64) (uint64, *blastFECReceiveGroup, bool, bool) {
	if skipLeadingFECRecovery(knownTotalBytes, parity, s.maxSeqPlusOne) {
		return 0, nil, false, false
	}
	missingSeq, ok := s.linearFECMissingSeq(parity)
	if !ok {
		return 0, nil, false, false
	}
	group := s.linearFECReceiveGroup(startSeq)
	if group == nil {
		return 0, nil, false, false
	}
	return missingSeq, group, true, false
}

func (s *blastReceiveRunState) linearFECMissingSeq(parity blastFECParity) (uint64, bool) {
	missingSeq, missing, ok := singleFECMissingSeq(&s.seen, parity)
	if ok {
		return missingSeq, true
	}
	if missing == 0 {
		s.cleanupFECGroupIfComplete(parity.startSeq, parity.count)
	}
	return 0, false
}

func (s *blastReceiveRunState) linearFECReceiveGroup(startSeq uint64) *blastFECReceiveGroup {
	group := s.fecGroups[startSeq]
	if group == nil {
		return nil
	}
	if len(group.xor) == 0 {
		return nil
	}
	return group
}

func linearFECOffsetForSeq(parity blastFECParity, seq uint64) uint64 {
	return parity.offset + (seq-parity.startSeq)*uint64(len(parity.payload))
}

func normalizedBlastChunkSize(chunkSize int) int {
	if chunkSize > 0 {
		return chunkSize
	}
	return defaultChunkSize
}

func normalizedBlastStripeCount(totalStripes int) int {
	if totalStripes > 0 {
		return totalStripes
	}
	return 1
}

func skipLeadingFECRecovery(knownTotalBytes uint64, parity blastFECParity, maxSeqPlusOne uint64) bool {
	// Sender-side parity is padded to the chunk size, so avoid guessing the
	// current leading edge length until later data or DONE prove it.
	return knownTotalBytes == 0 && parity.startSeq+parity.count >= maxSeqPlusOne
}

func singleFECMissingSeq(seen *blastSeqSet, parity blastFECParity) (uint64, int, bool) {
	var missingSeq uint64
	missing := 0
	for seq := parity.startSeq; seq < parity.startSeq+parity.count; seq++ {
		if seen.Has(seq) {
			continue
		}
		missing++
		missingSeq = seq
		if missing > 1 {
			return missingSeq, missing, false
		}
	}
	return missingSeq, missing, missing == 1
}

func recoverFECPayload(parity blastFECParity, group *blastFECReceiveGroup) []byte {
	payload := append([]byte(nil), parity.payload...)
	for i := range group.xor {
		payload[i] ^= group.xor[i]
	}
	return payload
}

func trimRecoveredFECPayload(payload []byte, offset uint64, knownTotalBytes uint64) ([]byte, bool) {
	if knownTotalBytes == 0 {
		return payload, true
	}
	if offset >= knownTotalBytes {
		return nil, false
	}
	if remaining := knownTotalBytes - offset; remaining < uint64(len(payload)) {
		return payload[:int(remaining)], true
	}
	return payload, true
}

func stripedDataPacketsForStripe(totalBytes uint64, chunkSize int, totalStripes int, stripeID uint16) uint64 {
	if totalBytes == 0 || totalStripes <= 0 || int(stripeID) >= totalStripes {
		return 0
	}
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}
	globalPackets := (totalBytes + uint64(chunkSize) - 1) / uint64(chunkSize)
	blockPackets := uint64(parallelBlastStripeBlockPackets)
	if blockPackets == 0 {
		return 0
	}
	cyclePackets := blockPackets * uint64(totalStripes)
	if cyclePackets == 0 {
		return 0
	}
	fullCycles := globalPackets / cyclePackets
	remainder := globalPackets % cyclePackets
	packets := fullCycles * blockPackets
	stripeStart := uint64(stripeID) * blockPackets
	if remainder > stripeStart {
		extra := remainder - stripeStart
		if extra > blockPackets {
			extra = blockPackets
		}
		packets += extra
	}
	return packets
}

func stripedFECOffsetForSeq(startOffset uint64, startSeq uint64, seq uint64, chunkSize int, totalStripes int) uint64 {
	if seq <= startSeq {
		return startOffset
	}
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}
	if totalStripes <= 1 {
		return startOffset + (seq-startSeq)*uint64(chunkSize)
	}
	blockPackets := uint64(parallelBlastStripeBlockPackets)
	if blockPackets == 0 {
		return startOffset + (seq-startSeq)*uint64(chunkSize)
	}
	startBlock := startSeq / blockPackets
	startWithin := startSeq % blockPackets
	seqBlock := seq / blockPackets
	seqWithin := seq % blockPackets
	deltaPackets := (seqBlock-startBlock)*blockPackets*uint64(totalStripes) + seqWithin - startWithin
	return startOffset + deltaPackets*uint64(chunkSize)
}

func (s *blastReceiveRunState) storeFECPayload(groupSize int, seq uint64, payload []byte) {
	if s == nil || groupSize <= 1 || len(payload) == 0 {
		return
	}
	groupStart := (seq / uint64(groupSize)) * uint64(groupSize)
	if s.fecGroups == nil {
		s.fecGroups = make(map[uint64]*blastFECReceiveGroup)
	}
	group := s.fecGroups[groupStart]
	if group == nil {
		group = &blastFECReceiveGroup{}
		s.fecGroups[groupStart] = group
	}
	if len(group.xor) < len(payload) {
		grown := make([]byte, len(payload))
		copy(grown, group.xor)
		group.xor = grown
	}
	for i := range payload {
		group.xor[i] ^= payload[i]
	}
	s.cleanupFECGroupIfComplete(groupStart, uint64(groupSize))
}

func (s *blastReceiveRunState) storeFECParity(startSeq uint64, offset uint64, count uint64, payload []byte) {
	if s == nil || count == 0 || len(payload) == 0 {
		return
	}
	if s.fecParity == nil {
		s.fecParity = make(map[uint64]blastFECParity)
	}
	s.fecParity[startSeq] = blastFECParity{
		startSeq: startSeq,
		offset:   offset,
		count:    count,
		payload:  append([]byte(nil), payload...),
	}
	s.cleanupFECGroupIfComplete(startSeq, count)
}

func (s *blastReceiveRunState) cleanupFECGroupIfComplete(startSeq uint64, count uint64) {
	if !s.hasCompleteFECGroup(startSeq, count) {
		return
	}
	s.deleteFECGroup(startSeq)
}

func (s *blastReceiveRunState) hasCompleteFECGroup(startSeq uint64, count uint64) bool {
	if s == nil {
		return false
	}
	if count == 0 {
		return false
	}
	for seq := startSeq; seq < startSeq+count; seq++ {
		if !s.seen.Has(seq) {
			return false
		}
	}
	return true
}

func (s *blastReceiveRunState) deleteFECGroup(startSeq uint64) {
	if s.fecGroups != nil {
		delete(s.fecGroups, startSeq)
	}
	if s.fecParity != nil {
		delete(s.fecParity, startSeq)
	}
}

func (s *blastReceiveRunState) recoverFEC(expectedBytes int64) []blastRecoveredPacket {
	if !s.hasFECParity() {
		return nil
	}
	knownTotalBytes := knownBlastTotalBytes(s.done, s.totalBytes, expectedBytes)
	return s.recoverFECWithTotal(knownTotalBytes)
}

func (s *blastReceiveRunState) hasFECParity() bool {
	if s == nil {
		return false
	}
	return len(s.fecParity) > 0
}

func (s *blastReceiveRunState) recoverFECWithTotal(knownTotalBytes uint64) []blastRecoveredPacket {
	recovered := make([]blastRecoveredPacket, 0, 1)
	for startSeq, parity := range s.fecParity {
		packet, ok := s.recoverFECParity(startSeq, parity, knownTotalBytes)
		if ok {
			recovered = append(recovered, packet)
		}
	}
	return recovered
}

func (s *blastReceiveRunState) recoverFECParity(startSeq uint64, parity blastFECParity, knownTotalBytes uint64) (blastRecoveredPacket, bool) {
	packet, ok, deleteParity := s.recoverLinearFECPacket(startSeq, parity, knownTotalBytes)
	if deleteParity {
		delete(s.fecParity, startSeq)
	}
	return packet, ok
}

func knownBlastTotalBytes(done bool, totalBytes uint64, expectedBytes int64) uint64 {
	if done {
		return totalBytes
	}
	if expectedBytes > 0 {
		return uint64(expectedBytes)
	}
	return 0
}

func receiveBlastParallelConn(ctx context.Context, conn net.PacketConn, dst io.Writer, cfg ReceiveConfig, expectedBytes int64, doneTarget int32, bytesReceived *atomic.Int64, donePackets *atomic.Int32, incompleteDoneRuns *atomic.Int32, lastPacketAt *atomic.Int64, writeMu *sync.Mutex, firstByteOnce *sync.Once, firstByteAt *time.Time, connected *atomic.Bool, repairActive *atomic.Bool, done <-chan struct{}, closeDone func(), startTerminalGrace func(), startRepairGrace func(), observeRepairGraceExpectedBytes func(uint64), observePeak func(time.Time, int64)) error {
	state := newBlastParallelConnReceiveState(ctx, conn, dst, cfg, expectedBytes, doneTarget, bytesReceived, donePackets, incompleteDoneRuns, lastPacketAt, writeMu, firstByteOnce, firstByteAt, connected, repairActive, done, closeDone, startTerminalGrace, startRepairGrace, observeRepairGraceExpectedBytes, observePeak)
	return state.run()
}

var errBlastParallelConnDone = errors.New("blast parallel receive complete")

type blastParallelConnPacket struct {
	packetType   PacketType
	payload      []byte
	runID        [16]byte
	seq          uint64
	offset       uint64
	stripeID     uint16
	totalStripes uint16
	now          time.Time
	addr         net.Addr
	raw          []byte
}

type blastParallelConnReceiveState struct {
	ctx                             context.Context
	conn                            net.PacketConn
	dst                             io.Writer
	cfg                             ReceiveConfig
	expectedBytes                   int64
	doneTarget                      int32
	bytesReceived                   *atomic.Int64
	donePackets                     *atomic.Int32
	incompleteDoneRuns              *atomic.Int32
	lastPacketAt                    *atomic.Int64
	writeMu                         *sync.Mutex
	firstByteOnce                   *sync.Once
	firstByteAt                     *time.Time
	connected                       *atomic.Bool
	repairActive                    *atomic.Bool
	done                            <-chan struct{}
	closeDone                       func()
	startTerminalGrace              func()
	startRepairGrace                func()
	observeRepairGraceExpectedBytes func(uint64)
	observePeak                     func(time.Time, int64)
	traceEnabled                    bool
	tracePacketsEnabled             bool
	batcher                         packetBatcher
	readBufs                        []batchReadBuffer
	seenDoneRuns                    map[[16]byte]bool
	runs                            map[[16]byte]*blastReceiveRunState
	lastStatsAt                     map[[16]byte]time.Time
	feedbackBytes                   atomic.Int64
}

func newBlastParallelConnReceiveState(ctx context.Context, conn net.PacketConn, dst io.Writer, cfg ReceiveConfig, expectedBytes int64, doneTarget int32, bytesReceived *atomic.Int64, donePackets *atomic.Int32, incompleteDoneRuns *atomic.Int32, lastPacketAt *atomic.Int64, writeMu *sync.Mutex, firstByteOnce *sync.Once, firstByteAt *time.Time, connected *atomic.Bool, repairActive *atomic.Bool, done <-chan struct{}, closeDone func(), startTerminalGrace func(), startRepairGrace func(), observeRepairGraceExpectedBytes func(uint64), observePeak func(time.Time, int64)) *blastParallelConnReceiveState {
	batcher := newPacketBatcher(conn, cfg.Transport)
	return &blastParallelConnReceiveState{
		ctx:                             ctx,
		conn:                            conn,
		dst:                             dst,
		cfg:                             cfg,
		expectedBytes:                   expectedBytes,
		doneTarget:                      doneTarget,
		bytesReceived:                   bytesReceived,
		donePackets:                     donePackets,
		incompleteDoneRuns:              incompleteDoneRuns,
		lastPacketAt:                    lastPacketAt,
		writeMu:                         writeMu,
		firstByteOnce:                   firstByteOnce,
		firstByteAt:                     firstByteAt,
		connected:                       connected,
		repairActive:                    repairActive,
		done:                            done,
		closeDone:                       closeDone,
		startTerminalGrace:              startTerminalGrace,
		startRepairGrace:                startRepairGrace,
		observeRepairGraceExpectedBytes: observeRepairGraceExpectedBytes,
		observePeak:                     observePeak,
		traceEnabled:                    sessionTraceEnabled(),
		tracePacketsEnabled:             sessionPacketTraceEnabled(),
		batcher:                         batcher,
		readBufs:                        newBlastParallelReadBuffers(batcher.MaxBatch()),
		seenDoneRuns:                    make(map[[16]byte]bool),
		runs:                            make(map[[16]byte]*blastReceiveRunState),
		lastStatsAt:                     make(map[[16]byte]time.Time),
	}
}

func newBlastParallelReadBuffers(n int) []batchReadBuffer {
	readBufs := make([]batchReadBuffer, n)
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, 64<<10)
	}
	return readBufs
}

func (s *blastParallelConnReceiveState) run() error {
	for {
		if s.isDone() {
			return nil
		}
		n, err := s.batcher.ReadBatch(s.ctx, blastReadPoll, s.readBufs)
		if err != nil {
			stop, readErr := s.handleReadError(err)
			if stop || readErr != nil {
				return readErr
			}
			continue
		}
		if err := s.processBatch(n); errors.Is(err, errBlastParallelConnDone) {
			return nil
		} else if err != nil {
			return err
		}
	}
}

func (s *blastParallelConnReceiveState) isDone() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *blastParallelConnReceiveState) handleReadError(err error) (bool, error) {
	if s.isDone() {
		return true, nil
	}
	if s.ctx.Err() != nil {
		return true, s.ctx.Err()
	}
	if isNetTimeout(err) {
		return false, s.onReadTimeout()
	}
	if errors.Is(err, net.ErrClosed) {
		return true, err
	}
	return false, nil
}

func (s *blastParallelConnReceiveState) onReadTimeout() error {
	now := time.Now()
	s.sendStatsFeedbackForAll(now)
	if err := s.fastIncompleteDoneError(); err != nil {
		return err
	}
	if err := s.requestRepairs(); err != nil {
		return err
	}
	return s.requestKnownRepairsForAll(now)
}

func (s *blastParallelConnReceiveState) processBatch(n int) error {
	for i := 0; i < n; i++ {
		packet, ok := s.decodePacket(i)
		if !ok {
			continue
		}
		if err := s.handlePacket(packet); err != nil {
			return err
		}
	}
	return nil
}

func (s *blastParallelConnReceiveState) decodePacket(i int) (blastParallelConnPacket, bool) {
	buf := s.readBufs[i].Bytes[:s.readBufs[i].N]
	packetType, payload, runID, seq, offset, ok := decodeBlastPacketFullWithAEAD(buf, s.cfg.PacketAEAD)
	if !ok || !receiveConfigAllowsRunID(s.cfg, runID) {
		return blastParallelConnPacket{}, false
	}
	return blastParallelConnPacket{
		packetType:   packetType,
		payload:      payload,
		runID:        runID,
		seq:          seq,
		offset:       offset,
		stripeID:     binary.BigEndian.Uint16(buf[2:4]),
		totalStripes: blastParallelTotalStripes(packetType, seq),
		now:          time.Now(),
		addr:         s.readBufs[i].Addr,
		raw:          buf,
	}, true
}

func blastParallelTotalStripes(packetType PacketType, seq uint64) uint16 {
	if packetType == PacketTypeHello && seq > 0 && seq <= uint64(maxParallelStripes) {
		return uint16(seq)
	}
	return 1
}

func (s *blastParallelConnReceiveState) handlePacket(packet blastParallelConnPacket) error {
	if s.lastPacketAt != nil {
		s.lastPacketAt.Store(packet.now.UnixNano())
	}
	switch packet.packetType {
	case PacketTypeHello:
		return s.handleHello(packet)
	case PacketTypeData:
		return s.handleData(packet)
	case PacketTypeParity:
		return s.handleParity(packet)
	case PacketTypeDone:
		return s.handleDone(packet)
	default:
		return nil
	}
}

func (s *blastParallelConnReceiveState) handleHello(packet blastParallelConnPacket) error {
	if s.traceEnabled {
		sessionTracef("parallel recv hello local=%s from=%s run=%x", s.conn.LocalAddr(), packet.addr, packet.runID[:4])
	}
	s.maybeConnectBatcher(packet.addr)
	if err := sendHelloAckBatch(s.ctx, s.batcher, packet.addr, packet.runID, packet.stripeID, packet.totalStripes); err != nil {
		return err
	}
	s.runState(packet.runID, packet.addr)
	return nil
}

func (s *blastParallelConnReceiveState) maybeConnectBatcher(addr net.Addr) {
	if s.batcher.MaxBatch() != 1 || s.batcher.Capabilities().Connected {
		return
	}
	connectedBatcher, ok := newConnectedUDPBatcher(s.conn, addr, s.cfg.Transport)
	if !ok {
		return
	}
	s.batcher = connectedBatcher
	if s.connected != nil {
		s.connected.Store(true)
	}
}

func (s *blastParallelConnReceiveState) handleData(packet blastParallelConnPacket) error {
	if len(packet.payload) == 0 {
		return nil
	}
	state := s.runState(packet.runID, packet.addr)
	if !state.acceptData(packet.seq) {
		return nil
	}
	totalFeedback := s.observeDataPacket(packet, state)
	written, err := s.writeDataPayload(packet, state)
	if err != nil {
		return err
	}
	if err := s.afterDataWrite(packet, state, written, totalFeedback); err != nil {
		return err
	}
	s.sendStatsFeedback(packet.runID, state, packet.now, false)
	return s.requestKnownRepairs(packet.runID, state, packet.now)
}

func (s *blastParallelConnReceiveState) observeDataPacket(packet blastParallelConnPacket, state *blastReceiveRunState) int64 {
	state.feedbackBytes += uint64(len(packet.payload))
	totalFeedback := s.feedbackBytes.Add(int64(len(packet.payload)))
	if s.tracePacketsEnabled {
		sessionTracef("parallel recv data local=%s from=%s bytes=%d run=%x", s.conn.LocalAddr(), packet.addr, len(packet.payload), packet.runID[:4])
	}
	s.firstByteOnce.Do(func() {
		*s.firstByteAt = packet.now
	})
	return totalFeedback
}

func (s *blastParallelConnReceiveState) writeDataPayload(packet blastParallelConnPacket, state *blastReceiveRunState) (int, error) {
	if s.cfg.RequireComplete {
		state.storeFECPayload(s.cfg.FECGroupSize, packet.seq, packet.payload)
		return writeOrderedParallelBlastPayload(s.dst, state, packet.seq, packet.payload, s.writeMu)
	}
	written, err := writeParallelBlastPayload(s.dst, packet.payload, s.writeMu)
	if err == nil && written != len(packet.payload) {
		return written, io.ErrShortWrite
	}
	return written, err
}

func (s *blastParallelConnReceiveState) afterDataWrite(packet blastParallelConnPacket, state *blastReceiveRunState, written int, totalFeedback int64) error {
	if written > 0 {
		state.receivedBytes += uint64(written)
	}
	totalReceived := s.bytesReceived.Add(int64(written))
	if err := s.recoverFECIfNeeded(packet.runID, state); err != nil {
		return err
	}
	s.startRepairGraceIfNeeded(state)
	if s.observePeak != nil {
		s.observePeak(packet.now, totalFeedback)
	}
	if done, err := s.finishFastDataRun(packet.runID, state); err != nil || done {
		return blastParallelDoneOrError(done, err)
	}
	if done, err := s.finishExpectedDataRun(packet.runID, state, totalReceived); err != nil || done {
		return blastParallelDoneOrError(done, err)
	}
	return s.maybeFinishRun(packet.runID, state)
}

func blastParallelDoneOrError(done bool, err error) error {
	if err != nil {
		return err
	}
	if done {
		return errBlastParallelConnDone
	}
	return nil
}

func (s *blastParallelConnReceiveState) finishFastDataRun(runID [16]byte, state *blastReceiveRunState) (bool, error) {
	if !s.fastMode() || !state.done || state.totalBytes == 0 || state.receivedBytes < state.totalBytes {
		return false, nil
	}
	return s.maybeFinishFastRun(runID, state)
}

func (s *blastParallelConnReceiveState) finishExpectedDataRun(runID [16]byte, state *blastReceiveRunState, totalReceived int64) (bool, error) {
	if s.expectedBytes <= 0 || totalReceived < s.expectedBytes {
		return false, nil
	}
	if s.cfg.RequireComplete {
		if err := s.recoverFEC(runID, state); err != nil {
			return false, err
		}
		if err := flushOrderedParallelBlastPayload(s.dst, state, s.writeMu); err != nil {
			return false, err
		}
	}
	if err := sendRepairComplete(s.ctx, s.batcher, state.addr, runID); err != nil {
		return false, err
	}
	if err := s.maybeFinishRun(runID, state); err != nil {
		return false, err
	}
	s.closeDone()
	return true, nil
}

func (s *blastParallelConnReceiveState) handleParity(packet blastParallelConnPacket) error {
	if s.cfg.FECGroupSize <= 1 {
		return nil
	}
	state := s.runState(packet.runID, packet.addr)
	groupCount := binary.BigEndian.Uint64(packet.raw[36:44])
	state.storeFECParity(packet.seq, packet.offset, groupCount, packet.payload)
	if err := s.recoverFEC(packet.runID, state); err != nil {
		return err
	}
	s.startRepairGraceIfNeeded(state)
	return nil
}

func (s *blastParallelConnReceiveState) handleDone(packet blastParallelConnPacket) error {
	state := s.runState(packet.runID, packet.addr)
	state.markDoneWithTotalBytes(packet.seq, packet.offset, packet.addr)
	if s.observeRepairGraceExpectedBytes != nil {
		s.observeRepairGraceExpectedBytes(state.totalBytes)
	}
	s.sendStatsFeedback(packet.runID, state, packet.now, true)
	if err := s.recoverFEC(packet.runID, state); err != nil {
		return err
	}
	if s.fastMode() || s.donePackets == nil {
		return s.handleFastDone(packet, state)
	}
	return s.handleCompleteDone(packet, state)
}

func (s *blastParallelConnReceiveState) handleFastDone(packet blastParallelConnPacket, state *blastReceiveRunState) error {
	if !s.cfg.RequireComplete && packet.offset > 0 && state.receivedBytes < packet.offset {
		state.doneAt = packet.now
		s.markRepairPending(state)
		return s.requestRepairs()
	}
	done, err := s.maybeFinishFastRun(packet.runID, state)
	return blastParallelDoneOrError(done, err)
}

func (s *blastParallelConnReceiveState) handleCompleteDone(packet blastParallelConnPacket, state *blastReceiveRunState) error {
	s.markDoneRun(packet.runID)
	if state.complete() {
		return s.maybeFinishRun(packet.runID, state)
	}
	s.markRepairPending(state)
	if err := s.requestRepairs(); err != nil {
		return err
	}
	s.startTerminalGraceIfReady()
	return nil
}

func (s *blastParallelConnReceiveState) runState(runID [16]byte, addr net.Addr) *blastReceiveRunState {
	state := s.runs[runID]
	if state == nil {
		state = newBlastReceiveRunState(addr)
		s.runs[runID] = state
	}
	if state.addr == nil && addr != nil {
		state.addr = cloneAddr(addr)
	}
	return state
}

func (s *blastParallelConnReceiveState) sendStatsFeedback(runID [16]byte, state *blastReceiveRunState, now time.Time, force bool) {
	if state == nil || state.addr == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	if !force {
		if last := s.lastStatsAt[runID]; !last.IsZero() && now.Sub(last) < blastRateFeedbackInterval {
			return
		}
	}
	s.lastStatsAt[runID] = now
	sendBlastStatsBestEffort(s.ctx, s.batcher, state.addr, runID, blastReceiverStats{
		ReceivedPayloadBytes:  state.feedbackBytes,
		ReceivedPackets:       state.seen.Len(),
		MaxSeqPlusOne:         state.maxSeqPlusOne,
		AckFloor:              state.nextWriteSeq,
		CommittedPayloadBytes: state.receivedBytes,
	})
}

func (s *blastParallelConnReceiveState) sendStatsFeedbackForAll(now time.Time) {
	for runID, state := range s.runs {
		s.sendStatsFeedback(runID, state, now, true)
	}
}

func (s *blastParallelConnReceiveState) requestRepairs() error {
	for runID, state := range s.runs {
		if state == nil || !state.repairPending {
			continue
		}
		if err := sendRepairRequestBatches(s.ctx, s.batcher, state.addr, runID, 0, state.missingSeqBatches(maxRepairRequestSeqs, maxRepairRequestBatches)); err != nil {
			return err
		}
	}
	return nil
}

func (s *blastParallelConnReceiveState) requestKnownRepairsForAll(now time.Time) error {
	for runID, state := range s.runs {
		if err := s.requestKnownRepairs(runID, state, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *blastParallelConnReceiveState) requestKnownRepairs(runID [16]byte, state *blastReceiveRunState, now time.Time) error {
	if state == nil || !s.cfg.RequireComplete {
		return nil
	}
	if !state.lastRepairRequestAt.IsZero() && now.Sub(state.lastRepairRequestAt) < blastRepairInterval {
		return nil
	}
	if !state.hasKnownMissingSeqs() {
		state.gapFirstObservedAt = time.Time{}
		return nil
	}
	if state.gapFirstObservedAt.IsZero() {
		state.gapFirstObservedAt = now
		return nil
	}
	if now.Sub(state.gapFirstObservedAt) < blastKnownGapRepairDelay {
		return nil
	}
	return s.requestKnownRepairBatches(runID, state, now)
}

func (s *blastParallelConnReceiveState) requestKnownRepairBatches(runID [16]byte, state *blastReceiveRunState, now time.Time) error {
	batches := state.knownMissingSeqBatches(maxRepairRequestSeqs, maxRepairRequestBatches)
	if len(batches) == 0 {
		state.gapFirstObservedAt = time.Time{}
		return nil
	}
	state.lastRepairRequestAt = now
	if s.repairActive != nil {
		s.repairActive.Store(true)
	}
	return sendRepairRequestBatches(s.ctx, s.batcher, state.addr, runID, 0, batches)
}

func (s *blastParallelConnReceiveState) fastIncompleteDoneError() error {
	if s.cfg.RequireComplete || s.expectedBytes > 0 {
		return nil
	}
	for _, state := range s.runs {
		if err := fastIncompleteDoneStateError(state); err != nil {
			return err
		}
	}
	return nil
}

func fastIncompleteDoneStateError(state *blastReceiveRunState) error {
	if state == nil || !state.done || state.totalBytes == 0 || state.doneAt.IsZero() {
		return nil
	}
	received := state.receivedBytes
	if received >= state.totalBytes || time.Since(state.doneAt) < parallelBlastDataIdle {
		return nil
	}
	return fmt.Errorf("blast incomplete: received %d bytes, want %d", received, state.totalBytes)
}

func (s *blastParallelConnReceiveState) fastMode() bool {
	return s.expectedBytes <= 0 && !s.cfg.RequireComplete
}

func (s *blastParallelConnReceiveState) markDoneRun(runID [16]byte) {
	if s.donePackets == nil || s.seenDoneRuns[runID] {
		return
	}
	s.seenDoneRuns[runID] = true
	s.donePackets.Add(1)
}

func (s *blastParallelConnReceiveState) fastAllDone() bool {
	return s.donePackets == nil || s.doneTarget <= 1 || s.donePackets.Load() >= s.doneTarget
}

func (s *blastParallelConnReceiveState) maybeFinishFastRun(runID [16]byte, state *blastReceiveRunState) (bool, error) {
	if state == nil || !state.done {
		return false, nil
	}
	if state.totalBytes > 0 && state.receivedBytes < state.totalBytes {
		return false, nil
	}
	s.clearRepairPending(state)
	if err := sendRepairComplete(s.ctx, s.batcher, state.addr, runID); err != nil {
		return false, err
	}
	s.markDoneRun(runID)
	s.clearRepairActiveIfComplete()
	if !s.fastAllDone() {
		return false, nil
	}
	s.closeDone()
	return true, nil
}

func (s *blastParallelConnReceiveState) maybeFinishRun(runID [16]byte, state *blastReceiveRunState) error {
	if state == nil || !state.complete() {
		return nil
	}
	if s.cfg.RequireComplete {
		if err := flushOrderedParallelBlastPayload(s.dst, state, s.writeMu); err != nil {
			return err
		}
	}
	s.clearRepairPending(state)
	if err := sendRepairComplete(s.ctx, s.batcher, state.addr, runID); err != nil {
		return err
	}
	s.clearRepairActiveIfComplete()
	s.closeIfReceiveComplete(state)
	s.startTerminalGraceIfReady()
	return nil
}

func (s *blastParallelConnReceiveState) closeIfReceiveComplete(state *blastReceiveRunState) {
	if s.expectedBytes > 0 && s.bytesReceived.Load() >= s.expectedBytes {
		s.closeDone()
		return
	}
	if s.expectedBytes <= 0 && s.cfg.RequireComplete && state.done && s.bytesReceived.Load() >= int64(state.totalBytes) {
		s.closeDone()
	}
}

func (s *blastParallelConnReceiveState) recoverFECIfNeeded(runID [16]byte, state *blastReceiveRunState) error {
	if !s.cfg.RequireComplete {
		return nil
	}
	return s.recoverFEC(runID, state)
}

func (s *blastParallelConnReceiveState) recoverFEC(runID [16]byte, state *blastReceiveRunState) error {
	if state == nil || !s.cfg.RequireComplete || s.cfg.FECGroupSize <= 1 {
		return nil
	}
	for {
		recovered := state.recoverFEC(s.expectedBytes)
		if len(recovered) == 0 {
			return nil
		}
		if err := s.writeRecoveredFEC(runID, state, recovered); err != nil {
			return err
		}
		if err := s.maybeFinishRun(runID, state); err != nil {
			return err
		}
	}
}

func (s *blastParallelConnReceiveState) writeRecoveredFEC(runID [16]byte, state *blastReceiveRunState, recovered []blastRecoveredPacket) error {
	for _, packet := range recovered {
		if !state.acceptData(packet.seq) {
			continue
		}
		state.storeFECPayload(s.cfg.FECGroupSize, packet.seq, packet.payload)
		written, err := writeOrderedParallelBlastPayload(s.dst, state, packet.seq, packet.payload, s.writeMu)
		if err != nil {
			return err
		}
		if s.bytesReceived.Add(int64(written)) >= s.expectedBytes && s.expectedBytes > 0 {
			return s.finishRecoveredFEC(runID, state)
		}
	}
	return nil
}

func (s *blastParallelConnReceiveState) finishRecoveredFEC(runID [16]byte, state *blastReceiveRunState) error {
	if err := flushOrderedParallelBlastPayload(s.dst, state, s.writeMu); err != nil {
		return err
	}
	if err := sendRepairComplete(s.ctx, s.batcher, state.addr, runID); err != nil {
		return err
	}
	s.closeDone()
	return nil
}

func (s *blastParallelConnReceiveState) startRepairGraceIfNeeded(state *blastReceiveRunState) {
	if s.cfg.RequireComplete && state.done && state.repairPending && !state.complete() && s.startRepairGrace != nil {
		s.startRepairGrace()
	}
}

func (s *blastParallelConnReceiveState) markRepairPending(state *blastReceiveRunState) {
	if state.repairPending {
		return
	}
	state.repairPending = true
	if s.incompleteDoneRuns != nil {
		s.incompleteDoneRuns.Add(1)
	}
	if s.startRepairGrace != nil {
		s.startRepairGrace()
	} else if s.repairActive != nil {
		s.repairActive.Store(true)
	}
}

func (s *blastParallelConnReceiveState) clearRepairPending(state *blastReceiveRunState) {
	if !state.repairPending {
		return
	}
	state.repairPending = false
	if s.incompleteDoneRuns != nil {
		s.incompleteDoneRuns.Add(-1)
	}
}

func (s *blastParallelConnReceiveState) clearRepairActiveIfComplete() {
	if s.repairActive != nil && s.incompleteDoneRuns != nil && s.incompleteDoneRuns.Load() == 0 {
		s.repairActive.Store(false)
	}
}

func (s *blastParallelConnReceiveState) startTerminalGraceIfReady() {
	if s.donePackets == nil || s.incompleteDoneRuns == nil || s.startTerminalGrace == nil {
		return
	}
	if s.donePackets.Load() >= s.doneTarget && s.incompleteDoneRuns.Load() == 0 {
		s.startTerminalGrace()
	}
}

func receiveConfigAllowsRunID(cfg ReceiveConfig, runID [16]byte) bool {
	if cfg.ExpectedRunID != ([16]byte{}) && runID != cfg.ExpectedRunID {
		return false
	}
	if len(cfg.ExpectedRunIDs) == 0 {
		return true
	}
	for _, expected := range cfg.ExpectedRunIDs {
		if runID == expected {
			return true
		}
	}
	return false
}

func writeParallelBlastPayload(dst io.Writer, payload []byte, writeMu *sync.Mutex) (int, error) {
	if dst == io.Discard {
		return len(payload), nil
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	return dst.Write(payload)
}

func (c *blastStreamReceiveCoordinator) writeGlobalPayloadLocked(state *blastReceiveRunState, seq uint64, offset uint64, payload []byte) (int, error) {
	if c.cfg.SpoolOutput {
		return writeSpoolParallelBlastPayload(c.dst, state, seq, offset, payload)
	}
	return writeOrderedParallelBlastPayload(c.dst, state, seq, payload, &c.writeMu)
}

func writeOrderedParallelBlastPayload(dst io.Writer, state *blastReceiveRunState, seq uint64, payload []byte, writeMu *sync.Mutex) (int, error) {
	if state == nil {
		return writeParallelBlastPayload(dst, payload, writeMu)
	}
	if seq > state.nextWriteSeq {
		state.storePendingParallelPayload(seq, payload)
		return 0, nil
	}
	if seq < state.nextWriteSeq {
		return 0, nil
	}
	if dst == io.Discard {
		return advanceDiscardedParallelPayloads(state, len(payload)), nil
	}

	writeMu.Lock()
	defer writeMu.Unlock()
	if err := bufferOrderedParallelBlastPayload(dst, state, payload); err != nil {
		return 0, err
	}
	return flushBufferedParallelPayloads(dst, state, len(payload))
}

func (s *blastReceiveRunState) storePendingParallelPayload(seq uint64, payload []byte) {
	if s.pending == nil {
		s.pending = make(map[uint64][]byte)
	}
	s.pending[seq] = append([]byte(nil), payload...)
}

func advanceDiscardedParallelPayloads(state *blastReceiveRunState, initial int) int {
	total := initial
	state.nextWriteSeq++
	for {
		next, ok := state.pending[state.nextWriteSeq]
		if !ok {
			return total
		}
		total += len(next)
		delete(state.pending, state.nextWriteSeq)
		state.nextWriteSeq++
	}
}

func flushBufferedParallelPayloads(dst io.Writer, state *blastReceiveRunState, initial int) (int, error) {
	total := initial
	state.nextWriteSeq++
	for {
		next, ok := state.pending[state.nextWriteSeq]
		if !ok {
			return total, nil
		}
		if err := bufferOrderedParallelBlastPayload(dst, state, next); err != nil {
			return total, err
		}
		total += len(next)
		delete(state.pending, state.nextWriteSeq)
		state.nextWriteSeq++
	}
}

func bufferOrderedParallelBlastPayload(dst io.Writer, state *blastReceiveRunState, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	state.writeBuf = append(state.writeBuf, payload...)
	if len(state.writeBuf) < blastReceiveWriteBuffer {
		return nil
	}
	return flushOrderedParallelBlastPayloadLocked(dst, state)
}

func flushOrderedParallelBlastPayload(dst io.Writer, state *blastReceiveRunState, writeMu *sync.Mutex) error {
	if dst == io.Discard || state == nil || len(state.writeBuf) == 0 {
		return nil
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	return flushOrderedParallelBlastPayloadLocked(dst, state)
}

func flushOrderedParallelBlastPayloadLocked(dst io.Writer, state *blastReceiveRunState) error {
	if len(state.writeBuf) == 0 {
		return nil
	}
	written, err := dst.Write(state.writeBuf)
	if err != nil {
		return err
	}
	if written != len(state.writeBuf) {
		return io.ErrShortWrite
	}
	state.writeBuf = state.writeBuf[:0]
	return nil
}

func writeSpoolParallelBlastPayload(dst io.Writer, state *blastReceiveRunState, seq uint64, offset uint64, payload []byte) (int, error) {
	if state == nil {
		return len(payload), nil
	}
	if dst != io.Discard && state.spool == nil {
		spool, err := os.CreateTemp("", "derphole-blast-spool-*")
		if err != nil {
			return 0, err
		}
		state.spool = spool
		state.spoolPath = spool.Name()
	}
	if dst != io.Discard {
		written, err := state.spool.WriteAt(payload, int64(offset))
		if err != nil {
			return written, err
		}
		if written != len(payload) {
			return written, io.ErrShortWrite
		}
	}
	state.advanceWriteSeq(seq)
	return len(payload), nil
}

func (s *blastReceiveRunState) advanceWriteSeq(seq uint64) {
	if s == nil || seq != s.nextWriteSeq {
		return
	}
	for s.seen.Has(s.nextWriteSeq) {
		s.nextWriteSeq++
	}
}

func (c *blastStreamReceiveCoordinator) flushGlobalPayload(state *blastReceiveRunState) error {
	if c.cfg.SpoolOutput {
		return flushSpoolParallelBlastPayload(c.dst, state, &c.writeMu)
	}
	return flushOrderedParallelBlastPayload(c.dst, state, &c.writeMu)
}

func flushSpoolParallelBlastPayload(dst io.Writer, state *blastReceiveRunState, writeMu *sync.Mutex) error {
	if state == nil || state.spool == nil {
		return nil
	}
	defer func() {
		_ = state.spool.Close()
		_ = os.Remove(state.spoolPath)
		state.spool = nil
		state.spoolPath = ""
	}()
	if dst == io.Discard || state.totalBytes == 0 {
		return nil
	}
	if _, err := state.spool.Seek(0, io.SeekStart); err != nil {
		return err
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	written, err := io.CopyN(dst, state.spool, int64(state.totalBytes))
	if err != nil {
		return err
	}
	if written != int64(state.totalBytes) {
		return io.ErrShortWrite
	}
	return nil
}

func writeBlastPayload(dst io.Writer, payload []byte) (int, error) {
	if dst == io.Discard {
		return len(payload), nil
	}
	return dst.Write(payload)
}

func udpAddrPortMatchesPeer(addr netip.AddrPort, peer net.Addr) bool {
	if peer == nil {
		return true
	}
	udpPeer, ok := peer.(*net.UDPAddr)
	if !ok {
		return net.UDPAddrFromAddrPort(addr).String() == peer.String()
	}
	if udpPeer.Port != int(addr.Port()) {
		return false
	}
	if udpPeer.Zone != "" && udpPeer.Zone != addr.Addr().Zone() {
		return false
	}
	return udpPeer.IP.Equal(net.IP(addr.Addr().AsSlice()))
}

func encodePacketHeader(dst []byte, packetType PacketType, runID [16]byte, stripeID uint16, seq, offset, ackFloor, ackMask uint64) {
	if len(dst) < headerLen {
		return
	}
	clear(dst[:headerLen])
	dst[0] = ProtocolVersion
	dst[1] = byte(packetType)
	binary.BigEndian.PutUint16(dst[2:4], stripeID)
	copy(dst[4:20], runID[:])
	binary.BigEndian.PutUint64(dst[20:28], seq)
	binary.BigEndian.PutUint64(dst[28:36], offset)
	binary.BigEndian.PutUint64(dst[36:44], ackFloor)
	binary.BigEndian.PutUint64(dst[44:52], ackMask)
}

func marshalBlastPayloadPacket(packetType PacketType, runID [16]byte, stripeID uint16, seq uint64, offset uint64, ackFloor uint64, ackMask uint64, payload []byte, packetAEAD cipher.AEAD) ([]byte, error) {
	return marshalBlastPayloadPacketWithNonce(packetType, runID, stripeID, seq, offset, ackFloor, ackMask, payload, packetAEAD, nil)
}

func marshalBlastPayloadPacketWithNonce(packetType PacketType, runID [16]byte, stripeID uint16, seq uint64, offset uint64, ackFloor uint64, ackMask uint64, payload []byte, packetAEAD cipher.AEAD, nonce *[12]byte) ([]byte, error) {
	capacity := headerLen + len(payload)
	if packetAEAD != nil {
		capacity += packetAEAD.Overhead()
	}
	wire := make([]byte, capacity)
	return marshalBlastPayloadPacketInto(wire, packetType, runID, stripeID, seq, offset, ackFloor, ackMask, payload, packetAEAD, nonce)
}

func marshalBlastPayloadPacketInto(dst []byte, packetType PacketType, runID [16]byte, stripeID uint16, seq uint64, offset uint64, ackFloor uint64, ackMask uint64, payload []byte, packetAEAD cipher.AEAD, nonce *[12]byte) ([]byte, error) {
	capacity := headerLen + len(payload)
	if packetAEAD != nil {
		capacity += packetAEAD.Overhead()
	}
	if len(dst) < capacity {
		return nil, errors.New("short blast payload packet buffer")
	}
	wire := dst[:headerLen]
	encodePacketHeader(wire[:headerLen], packetType, runID, stripeID, seq, offset, ackFloor, ackMask)
	if packetAEAD != nil {
		if nonce == nil {
			var localNonce [12]byte
			nonce = &localNonce
		}
		if packetAEAD.NonceSize() != len(*nonce) {
			return nil, errors.New("unsupported packet AEAD nonce size")
		}
		nonceBuf := nonce[:]
		if err := packetAEADNonceTo(nonceBuf, wire[:headerLen]); err != nil {
			return nil, err
		}
		return packetAEAD.Seal(wire, nonceBuf, payload, wire[:headerLen]), nil
	}
	wire = dst[:headerLen+len(payload)]
	copy(wire[headerLen:], payload)
	return wire, nil
}

func sessionTracef(format string, args ...any) {
	if !sessionTraceEnabled() {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "probe-session-trace: "+format+"\n", args...)
}

func sessionTraceEnabled() bool {
	return strings.TrimSpace(os.Getenv("DERPHOLE_PROBE_TRACE")) != ""
}

func sessionPacketTraceEnabled() bool {
	return strings.TrimSpace(os.Getenv("DERPHOLE_PROBE_TRACE_PACKETS")) != ""
}

func decodeBlastPacketFull(buf []byte) (PacketType, []byte, [16]byte, uint64, uint64, bool) {
	return decodeBlastPacketFullWithAEAD(buf, nil)
}

func decodeBlastPacketWithAEAD(buf []byte, packetAEAD cipher.AEAD) (PacketType, []byte, [16]byte, bool) {
	packetType, payload, runID, _, _, ok := decodeBlastPacketFullWithAEAD(buf, packetAEAD)
	return packetType, payload, runID, ok
}

func decodeBlastPacketFullWithAEAD(buf []byte, packetAEAD cipher.AEAD) (PacketType, []byte, [16]byte, uint64, uint64, bool) {
	if len(buf) < headerLen || buf[0] != ProtocolVersion {
		return 0, nil, [16]byte{}, 0, 0, false
	}
	packetType := PacketType(buf[1])
	if packetAEAD != nil && (packetType == PacketTypeData || packetType == PacketTypeParity) {
		packet, err := UnmarshalPacket(buf, packetAEAD)
		if err != nil {
			return 0, nil, [16]byte{}, 0, 0, false
		}
		return packet.Type, packet.Payload, packet.RunID, packet.Seq, packet.Offset, true
	}
	var runID [16]byte
	copy(runID[:], buf[4:20])
	seq := binary.BigEndian.Uint64(buf[20:28])
	offset := binary.BigEndian.Uint64(buf[28:36])
	return packetType, buf[headerLen:], runID, seq, offset, true
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func sendAck(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, stripeID uint16, ackFloor, ackMask uint64, ackPayload []byte) error {
	packet, err := MarshalPacket(Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeAck,
		StripeID: stripeID,
		RunID:    runID,
		AckFloor: ackFloor,
		AckMask:  ackMask,
		Payload:  ackPayload,
	}, nil)
	if err != nil {
		return err
	}
	_, err = writeWithContext(ctx, conn, peer, packet)
	return err
}

func performHelloHandshake(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, stripeID uint16, totalStripes uint16, stats *TransferStats) (time.Duration, error) {
	hello, err := marshalHelloPacket(runID, stripeID, totalStripes)
	if err != nil {
		return 0, err
	}

	buf := make([]byte, 64<<10)
	for {
		sentAt, err := sendHelloAttempt(ctx, conn, peer, hello, stats)
		if err != nil {
			return 0, err
		}

		if err := setReadDeadline(ctx, conn, defaultRetryInterval); err != nil {
			return 0, err
		}
		addr, matched, err := readHelloAck(ctx, conn, peer, runID, stripeID, buf)
		if err != nil {
			return 0, err
		}
		if !matched {
			continue
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return 0, err
		}
		sessionTracef("hello ack local=%s peer=%s from=%s run=%x", conn.LocalAddr(), peer, addr, runID[:4])
		return sessionRetryInterval(time.Since(sentAt)), nil
	}
}

func readHelloAck(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, stripeID uint16, buf []byte) (net.Addr, bool, error) {
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		retry, readErr := helloReadOutcome(ctx, err)
		return nil, !retry, readErr
	}
	if !sameAddr(addr, peer) {
		return addr, false, nil
	}
	return addr, helloAckMatches(buf[:n], runID, stripeID), nil
}

func sendHelloAttempt(ctx context.Context, conn net.PacketConn, peer net.Addr, hello []byte, stats *TransferStats) (time.Time, error) {
	sentAt := time.Now()
	if _, err := writeWithContext(ctx, conn, peer, hello); err != nil {
		return time.Time{}, err
	}
	if stats != nil {
		stats.PacketsSent++
	}
	return sentAt, nil
}

func performHelloHandshakeBatch(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, stripeID uint16, totalStripes uint16, stats *TransferStats) (time.Duration, error) {
	if batcher == nil {
		return 0, errors.New("nil hello batcher")
	}
	hello, err := marshalHelloPacket(runID, stripeID, totalStripes)
	if err != nil {
		return 0, err
	}

	readBufs := newHelloReadBuffers(batcher.MaxBatch())
	for {
		sentAt := time.Now()
		if err := writeBlastBatch(ctx, batcher, peer, [][]byte{hello}); err != nil {
			return 0, err
		}
		if stats != nil {
			stats.PacketsSent++
		}
		n, err := batcher.ReadBatch(ctx, defaultRetryInterval, readBufs)
		if err != nil {
			retry, readErr := helloReadOutcome(ctx, err)
			if readErr != nil {
				return 0, readErr
			}
			if retry {
				continue
			}
		}
		if helloBatchHasAck(readBufs[:n], peer, runID, stripeID) {
			sessionTracef("hello ack peer=%s run=%x stripe=%d total=%d", peer, runID[:4], stripeID, totalStripes)
			return sessionRetryInterval(time.Since(sentAt)), nil
		}
	}
}

func marshalHelloPacket(runID [16]byte, stripeID uint16, totalStripes uint16) ([]byte, error) {
	return MarshalPacket(Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeHello,
		StripeID: stripeID,
		RunID:    runID,
		Seq:      uint64(totalStripes),
	}, nil)
}

func helloReadOutcome(ctx context.Context, err error) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if isNetTimeout(err) {
		return true, nil
	}
	return false, err
}

func helloAckMatches(data []byte, runID [16]byte, stripeID uint16) bool {
	packet, err := UnmarshalPacket(data, nil)
	if err != nil {
		return false
	}
	return packet.Type == PacketTypeHelloAck && packet.RunID == runID && packet.StripeID == stripeID
}

func newHelloReadBuffers(n int) []batchReadBuffer {
	readBufs := make([]batchReadBuffer, n)
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, 64<<10)
	}
	return readBufs
}

func helloBatchHasAck(readBufs []batchReadBuffer, peer net.Addr, runID [16]byte, stripeID uint16) bool {
	for i := range readBufs {
		if !helloBatchAddrMatches(readBufs[i].Addr, peer) {
			continue
		}
		if helloAckMatches(readBufs[i].Bytes[:readBufs[i].N], runID, stripeID) {
			return true
		}
	}
	return false
}

func helloBatchAddrMatches(addr, peer net.Addr) bool {
	return addr == nil || peer == nil || sameAddr(addr, peer)
}

func sendHelloAck(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, stripeID uint16, totalStripes uint16) error {
	packet, err := helloAckPacket(runID, stripeID, totalStripes)
	if err != nil {
		return err
	}
	_, err = writeWithContext(ctx, conn, peer, packet)
	return err
}

func sendHelloAckBatch(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, stripeID uint16, totalStripes uint16) error {
	packet, err := helloAckPacket(runID, stripeID, totalStripes)
	if err != nil {
		return err
	}
	return writeBlastBatch(ctx, batcher, peer, [][]byte{packet})
}

func sendRepairRequest(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, seqs []uint64) error {
	return sendRepairRequestStripe(ctx, batcher, peer, runID, 0, seqs)
}

func sendRepairRequestBatches(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, stripeID uint16, batches [][]uint64) error {
	for _, seqs := range batches {
		if len(seqs) == 0 {
			continue
		}
		if err := sendRepairRequestStripe(ctx, batcher, peer, runID, stripeID, seqs); err != nil {
			return err
		}
	}
	return nil
}

func sendRepairRequestStripe(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, stripeID uint16, seqs []uint64) error {
	if len(seqs) == 0 {
		return nil
	}
	payload := make([]byte, len(seqs)*8)
	for i, seq := range seqs {
		binary.BigEndian.PutUint64(payload[i*8:(i+1)*8], seq)
	}
	packet, err := MarshalPacket(Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeRepairRequest,
		StripeID: stripeID,
		RunID:    runID,
		Payload:  payload,
	}, nil)
	if err != nil {
		return err
	}
	return writeBlastBatch(ctx, batcher, peer, [][]byte{packet})
}

func sendRepairComplete(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte) error {
	packet, err := MarshalPacket(Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeRepairComplete,
		RunID:   runID,
	}, nil)
	if err != nil {
		return err
	}
	return writeBlastBatch(ctx, batcher, peer, [][]byte{packet})
}

func sendBlastStatsBestEffort(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, stats blastReceiverStats) {
	sendBlastStatsBestEffortStripe(ctx, batcher, peer, runID, 0, stats)
}

func sendBlastStatsBestEffortStripe(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, stripeID uint16, stats blastReceiverStats) {
	if batcher == nil || peer == nil {
		return
	}
	packet, err := MarshalPacket(Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeStats,
		StripeID: stripeID,
		RunID:    runID,
		Payload:  marshalBlastStatsPayload(stats),
	}, nil)
	if err != nil {
		return
	}
	if err := writeBlastBatch(ctx, batcher, peer, [][]byte{packet}); err != nil {
		sessionTracef("blast stats write ignored peer=%s err=%v", peer, err)
		return
	}
	sessionTracef("blast stats write peer=%s rx_bytes=%d rx_packets=%d rx_max_seq=%d", peer, stats.ReceivedPayloadBytes, stats.ReceivedPackets, stats.MaxSeqPlusOne)
}

func helloAckPacket(runID [16]byte, stripeID uint16, totalStripes uint16) ([]byte, error) {
	packet, err := MarshalPacket(Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeHelloAck,
		StripeID: stripeID,
		RunID:    runID,
		Seq:      uint64(totalStripes),
	}, nil)
	if err != nil {
		return nil, err
	}
	return packet, nil
}

type outboundPacket struct {
	seq         uint64
	packetType  PacketType
	wire        []byte
	sentAt      time.Time
	firstSentAt time.Time
	attempts    int
	payload     int
}

type senderState struct {
	src        io.Reader
	chunkSize  int
	window     int
	stripeID   uint16
	nextSeq    uint64
	ackFloor   uint64
	offset     uint64
	runID      [16]byte
	rateMbps   int
	eof        bool
	doneQueued bool
	pendingErr error
	inFlight   map[uint64]*outboundPacket
	zeroReads  int
}

func fillSendWindow(ctx context.Context, batcher packetBatcher, peer net.Addr, state *senderState, stats *TransferStats) error {
	if len(state.inFlight) == 0 && state.pendingErr != nil {
		return state.pendingErr
	}
	pending, err := collectSendWindowPackets(state)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}
	if err := writeOutboundPackets(ctx, batcher, peer, pending); err != nil {
		return err
	}
	recordOutboundPackets(pending, stats)
	return paceSendWindow(ctx, state, stats)
}

func collectSendWindowPackets(state *senderState) ([]*outboundPacket, error) {
	var pending []*outboundPacket
	for sendWindowHasCapacity(state) && !state.doneQueued {
		packet, err := nextOutboundPacket(state)
		if err != nil {
			return nil, err
		}
		if packet == nil {
			break
		}
		state.inFlight[packet.seq] = packet
		pending = append(pending, packet)
	}
	return pending, nil
}

func writeOutboundPackets(ctx context.Context, batcher packetBatcher, peer net.Addr, pending []*outboundPacket) error {
	wires := make([][]byte, len(pending))
	for i, packet := range pending {
		wires[i] = packet.wire
	}
	_, err := batcher.WriteBatch(ctx, peer, wires)
	return err
}

func recordOutboundPackets(pending []*outboundPacket, stats *TransferStats) {
	now := time.Now()
	for _, packet := range pending {
		packet.attempts++
		if packet.firstSentAt.IsZero() {
			packet.firstSentAt = now
		}
		packet.sentAt = now
		stats.PacketsSent++
		stats.BytesSent += int64(packet.payload)
		stats.observePeakGoodput(now, stats.BytesSent)
	}
}

func paceSendWindow(ctx context.Context, state *senderState, stats *TransferStats) error {
	if state.rateMbps > 0 && stats != nil && !stats.StartedAt.IsZero() {
		return paceBlastSend(ctx, stats.StartedAt, uint64(stats.BytesSent), state.rateMbps)
	}
	return nil
}

func sendWindowHasCapacity(state *senderState) bool {
	if state == nil || state.window <= 0 {
		return false
	}
	if state.nextSeq < state.ackFloor {
		return len(state.inFlight) < state.window
	}
	return state.nextSeq-state.ackFloor < uint64(state.window)
}

func nextOutboundPacket(state *senderState) (*outboundPacket, error) {
	if state.doneQueued || state.pendingErr != nil {
		return nil, nil
	}
	if state.eof {
		return nextDonePacket(state)
	}

	buf := make([]byte, state.chunkSize)
	n, readErr := state.src.Read(buf)
	if n > 0 {
		return nextDataPacket(state, buf[:n], readErr)
	}
	return handleEmptyOutboundRead(state, readErr)
}

func nextDonePacket(state *senderState) (*outboundPacket, error) {
	wire, err := MarshalPacket(Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeDone,
		StripeID: state.stripeID,
		RunID:    state.runID,
		Seq:      state.nextSeq,
		Offset:   state.offset,
	}, nil)
	if err != nil {
		return nil, err
	}
	packet := &outboundPacket{seq: state.nextSeq, packetType: PacketTypeDone, wire: wire}
	state.nextSeq++
	state.doneQueued = true
	state.zeroReads = 0
	return packet, nil
}

func nextDataPacket(state *senderState, payload []byte, readErr error) (*outboundPacket, error) {
	payload = append([]byte(nil), payload...)
	wire, err := MarshalPacket(Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeData,
		StripeID: state.stripeID,
		RunID:    state.runID,
		Seq:      state.nextSeq,
		Offset:   state.offset,
		Payload:  payload,
	}, nil)
	if err != nil {
		return nil, err
	}
	packet := &outboundPacket{
		seq:        state.nextSeq,
		packetType: PacketTypeData,
		wire:       wire,
		payload:    len(payload),
	}
	state.nextSeq++
	state.offset += uint64(len(payload))
	state.zeroReads = 0
	rememberOutboundReadError(state, readErr)
	return packet, nil
}

func rememberOutboundReadError(state *senderState, readErr error) {
	if errors.Is(readErr, io.EOF) {
		state.eof = true
		return
	}
	if readErr != nil {
		state.pendingErr = readErr
	}
}

func handleEmptyOutboundRead(state *senderState, readErr error) (*outboundPacket, error) {
	if errors.Is(readErr, io.EOF) {
		state.eof = true
		return nextDonePacket(state)
	}
	if readErr != nil {
		return nil, readErr
	}
	state.zeroReads++
	return nil, nil
}

func retransmitExpired(ctx context.Context, batcher packetBatcher, peer net.Addr, packets map[uint64]*outboundPacket, retryInterval time.Duration, stats *TransferStats) error {
	now := time.Now()
	var expired []*outboundPacket
	for _, packet := range packets {
		if packet.sentAt.IsZero() {
			continue
		}
		if now.Sub(packet.sentAt) < retryInterval {
			continue
		}
		expired = append(expired, packet)
	}
	if len(expired) == 0 {
		return nil
	}
	wires := make([][]byte, len(expired))
	for i, packet := range expired {
		wires[i] = packet.wire
	}
	if _, err := batcher.WriteBatch(ctx, peer, wires); err != nil {
		return err
	}
	now = time.Now()
	for _, packet := range expired {
		packet.attempts++
		packet.sentAt = now
		stats.PacketsSent++
		stats.Retransmits++
	}
	return nil
}

func donePacketSettled(packets map[uint64]*outboundPacket) bool {
	if len(packets) != 1 {
		return false
	}
	for _, packet := range packets {
		if packet == nil || packet.packetType != PacketTypeDone {
			return false
		}
		if packet.firstSentAt.IsZero() || packet.attempts < terminalDoneAttempts {
			return false
		}
		return time.Since(packet.firstSentAt) >= terminalDoneGrace
	}
	return false
}

func nextRetransmitDeadline(ctx context.Context, packets map[uint64]*outboundPacket, retryInterval time.Duration) time.Duration {
	wait := retryInterval
	now := time.Now()
	for _, packet := range packets {
		if packet.sentAt.IsZero() {
			continue
		}
		deadline := packet.sentAt.Add(retryInterval)
		if deadline.Before(now) {
			return 0
		}
		packetWait := deadline.Sub(now)
		if packetWait < wait {
			wait = packetWait
		}
	}
	if ctxDeadline, ok := ctx.Deadline(); ok {
		ctxWait := time.Until(ctxDeadline)
		if ctxWait < wait {
			return ctxWait
		}
	}
	return wait
}

func sessionRetryInterval(rtt time.Duration) time.Duration {
	if rtt <= 0 {
		return minRetryInterval
	}
	retry := 4 * rtt
	if retry < minRetryInterval {
		return minRetryInterval
	}
	if retry > maxRetryInterval {
		return maxRetryInterval
	}
	return retry
}

func effectiveWindowSize(requested int) int {
	if requested <= 0 {
		return defaultWindowSize
	}
	return requested
}

func applyAck(packets map[uint64]*outboundPacket, ackFloor, ackMask uint64, ackPayload []byte) int {
	acked := applyAckFloorAndMask(packets, ackFloor, ackMask)
	return acked + applyAckPayload(packets, ackFloor, ackPayload)
}

func applyAckFloorAndMask(packets map[uint64]*outboundPacket, ackFloor, ackMask uint64) int {
	acked := 0
	for seq := range packets {
		if seq < ackFloor {
			delete(packets, seq)
			acked++
			continue
		}
		if seq <= ackFloor {
			continue
		}
		delta := seq - ackFloor - 1
		if delta >= maxAckMaskBits {
			continue
		}
		if ackMask&(uint64(1)<<delta) == 0 {
			continue
		}
		delete(packets, seq)
		acked++
	}
	return acked
}

func applyAckPayload(packets map[uint64]*outboundPacket, ackFloor uint64, ackPayload []byte) int {
	acked := 0
	for byteIndex, b := range ackPayload {
		if b == 0 {
			continue
		}
		for bit := 0; bit < 8; bit++ {
			if b&(1<<bit) == 0 {
				continue
			}
			seq := ackFloor + uint64(byteIndex*8+bit) + 1
			if _, ok := packets[seq]; !ok {
				continue
			}
			delete(packets, seq)
			acked++
		}
	}
	return acked
}

func advanceReceiveWindow(dst io.Writer, buffered map[uint64]Packet, expectedSeq uint64, stats *TransferStats) (uint64, bool, error) {
	for {
		packet, ok := buffered[expectedSeq]
		if !ok {
			return expectedSeq, false, nil
		}
		delete(buffered, expectedSeq)
		if packet.Type == PacketTypeDone {
			return expectedSeq + 1, true, nil
		}
		if packet.Type != PacketTypeData {
			return expectedSeq, false, nil
		}
		if err := writeReceiveWindowPacket(dst, packet, stats); err != nil {
			return expectedSeq, false, err
		}
		expectedSeq++
	}
}

func writeReceiveWindowPacket(dst io.Writer, packet Packet, stats *TransferStats) error {
	if stats != nil && stats.FirstByteAt.IsZero() && len(packet.Payload) > 0 {
		stats.FirstByteAt = time.Now()
	}
	n, err := dst.Write(packet.Payload)
	if err != nil {
		return err
	}
	if n != len(packet.Payload) {
		return io.ErrShortWrite
	}
	if stats != nil {
		stats.BytesReceived += int64(n)
		stats.observePeakGoodput(time.Now(), stats.BytesReceived)
	}
	return nil
}

func ackMaskFor(buffered map[uint64]Packet, ackFloor uint64) uint64 {
	var mask uint64
	for seq := range buffered {
		if seq <= ackFloor || seq > ackFloor+maxAckMaskBits {
			continue
		}
		mask |= uint64(1) << (seq - ackFloor - 1)
	}
	return mask
}

func extendedAckPayloadFor(buffered map[uint64]Packet, ackFloor uint64) []byte {
	var payload []byte
	for seq := range buffered {
		if seq <= ackFloor {
			continue
		}
		delta := seq - ackFloor - 1
		if delta >= extendedAckBits {
			continue
		}
		if payload == nil {
			payload = make([]byte, extendedAckBytes)
		}
		payload[delta/8] |= 1 << (delta % 8)
	}
	return payload
}

func clonePacket(packet Packet) Packet {
	packet.Payload = append([]byte(nil), packet.Payload...)
	return packet
}

func newRunID() ([16]byte, error) {
	var runID [16]byte
	for {
		if _, err := rand.Read(runID[:]); err != nil {
			return [16]byte{}, err
		}
		if !isZeroRunID(runID) {
			return runID, nil
		}
	}
}

func isZeroRunID(runID [16]byte) bool {
	return runID == [16]byte{}
}

func waitZeroReadRetry(ctx context.Context, zeroReads int) error {
	delay := zeroReadRetryDelay
	if zeroReads > 4 {
		delay = defaultRetryInterval
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func ackIsPlausible(nextSeq, ackFloor, ackMask uint64, ackPayload []byte) bool {
	if ackFloor > nextSeq {
		return false
	}
	if !ackMaskIsPlausible(nextSeq, ackFloor, ackMask) {
		return false
	}
	return ackPayloadIsPlausible(nextSeq, ackFloor, ackPayload)
}

func ackMaskIsPlausible(nextSeq, ackFloor, ackMask uint64) bool {
	for bit := 0; bit < maxAckMaskBits; bit++ {
		if ackMask&(uint64(1)<<bit) == 0 {
			continue
		}
		seq := ackFloor + uint64(bit) + 1
		if seq >= nextSeq {
			return false
		}
	}
	return true
}

func ackPayloadIsPlausible(nextSeq, ackFloor uint64, ackPayload []byte) bool {
	for byteIndex, b := range ackPayload {
		if !ackPayloadByteIsPlausible(nextSeq, ackFloor, byteIndex, b) {
			return false
		}
	}
	return true
}

func ackPayloadByteIsPlausible(nextSeq, ackFloor uint64, byteIndex int, b byte) bool {
	if b == 0 {
		return true
	}
	for bit := 0; bit < 8; bit++ {
		if b&(1<<bit) == 0 {
			continue
		}
		seq := ackFloor + uint64(byteIndex*8+bit) + 1
		if seq >= nextSeq {
			return false
		}
	}
	return true
}

func cloneAddr(addr net.Addr) net.Addr {
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.UDPAddr:
		cp := *a
		if a.IP != nil {
			cp.IP = append([]byte(nil), a.IP...)
		}
		return &cp
	default:
		return addr
	}
}

func sameAddr(a, b net.Addr) bool {
	if a == nil {
		return b == nil
	}
	if b == nil {
		return false
	}
	ua, ub, ok := udpAddrPair(a, b)
	if ok {
		return sameUDPAddr(ua, ub)
	}
	return a.String() == b.String()
}

func udpAddrPair(a, b net.Addr) (*net.UDPAddr, *net.UDPAddr, bool) {
	ua, aok := a.(*net.UDPAddr)
	if !aok {
		return nil, nil, false
	}
	ub, bok := b.(*net.UDPAddr)
	if !bok {
		return nil, nil, false
	}
	return ua, ub, true
}

func sameUDPAddr(a, b *net.UDPAddr) bool {
	if a.Port != b.Port {
		return false
	}
	if a.Zone != b.Zone {
		return false
	}
	return a.IP.Equal(b.IP)
}

func lingerTerminalAcks(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, expectedSeq uint64) error {
	lingerDeadline := time.Now().Add(terminalAckLinger)
	buf := make([]byte, 64<<10)
	for !terminalAckDeadlinePassed(lingerDeadline) {
		n, addr, done, err := readTerminalAckPacket(ctx, conn, lingerDeadline, buf)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if err := handleTerminalAckPacket(ctx, conn, peer, addr, runID, expectedSeq, buf[:n]); err != nil {
			return err
		}
	}
	return nil
}

func terminalAckDeadlinePassed(deadline time.Time) bool {
	return time.Now().After(deadline)
}

func readTerminalAckPacket(ctx context.Context, conn net.PacketConn, deadline time.Time, buf []byte) (int, net.Addr, bool, error) {
	if err := setReadDeadlineAbsolute(ctx, conn, deadline); err != nil {
		return 0, nil, false, err
	}
	n, addr, err := conn.ReadFrom(buf)
	if err == nil {
		return n, addr, false, nil
	}
	done, readErr := terminalAckReadOutcome(ctx, err)
	return 0, nil, done, readErr
}

func terminalAckReadOutcome(ctx context.Context, err error) (bool, error) {
	if ctx.Err() != nil || isNetTimeout(err) || errors.Is(err, net.ErrClosed) {
		return true, nil
	}
	return false, err
}

func handleTerminalAckPacket(ctx context.Context, conn net.PacketConn, peer, addr net.Addr, runID [16]byte, expectedSeq uint64, data []byte) error {
	if !sameAddr(addr, peer) {
		return nil
	}
	packet, err := UnmarshalPacket(data, nil)
	if err != nil || packet.RunID != runID {
		return nil
	}
	return sendTerminalAckResponse(ctx, conn, addr, runID, expectedSeq, packet)
}

func sendTerminalAckResponse(ctx context.Context, conn net.PacketConn, addr net.Addr, runID [16]byte, expectedSeq uint64, packet Packet) error {
	switch packet.Type {
	case PacketTypeHello:
		return sendHelloAck(ctx, conn, addr, runID, packet.StripeID, 1)
	case PacketTypeData, PacketTypeDone:
		return sendAck(ctx, conn, addr, runID, packet.StripeID, expectedSeq, 0, nil)
	default:
		return nil
	}
}

func setReadDeadlineAbsolute(ctx context.Context, conn net.PacketConn, deadline time.Time) error {
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return conn.SetReadDeadline(deadline)
}

func writeWithContext(ctx context.Context, conn net.PacketConn, peer net.Addr, packet []byte) (int, error) {
	for {
		n, retry, err := writePacketWithDeadline(ctx, conn, peer, packet)
		if err != nil {
			return n, err
		}
		if !retry {
			return n, nil
		}
		if err := sleepWithContext(ctx, 250*time.Microsecond); err != nil {
			return n, err
		}
	}
}

func writePacketWithDeadline(ctx context.Context, conn net.PacketConn, peer net.Addr, packet []byte) (int, bool, error) {
	deadline, err := writeDeadline(ctx)
	if err != nil {
		return 0, false, err
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return 0, false, err
	}
	n, writeErr := conn.WriteTo(packet, peer)
	clearErr := conn.SetWriteDeadline(time.Time{})
	return writePacketOutcome(n, writeErr, clearErr)
}

func writePacketOutcome(n int, writeErr, clearErr error) (int, bool, error) {
	if writeErr == nil {
		return n, false, clearErr
	}
	if !isNoBufferSpace(writeErr) {
		return n, false, writeErr
	}
	if clearErr != nil {
		return n, false, clearErr
	}
	return n, true, nil
}

func resolveRemoteAddr(remoteAddr string) (net.Addr, error) {
	if remoteAddr == "" {
		return nil, nil
	}
	return net.ResolveUDPAddr("udp", remoteAddr)
}

func setReadDeadline(ctx context.Context, conn net.PacketConn, fallback time.Duration) error {
	deadline := time.Now().Add(fallback)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return conn.SetReadDeadline(deadline)
}

func writeDeadline(ctx context.Context) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		return deadline, nil
	}
	return time.Now().Add(defaultRetryInterval), nil
}

func isNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
