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
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = defaultChunkSize
	}
	cfg.WindowSize = effectiveWindowSize(cfg.WindowSize)
	if cfg.Parallel <= 0 {
		cfg.Parallel = 1
	}

	peer, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return TransferStats{}, err
	}

	stats := TransferStats{StartedAt: time.Now()}
	stats.observePeakGoodput(stats.StartedAt, 0)
	batcher := newPacketBatcher(conn, cfg.Transport)
	stats.Transport = batcher.Capabilities()
	runID := cfg.RunID
	if isZeroRunID(runID) {
		runID, err = newRunID()
		if err != nil {
			return TransferStats{}, err
		}
	}
	if cfg.Raw && cfg.Parallel > 1 {
		return sendStriped(ctx, conn, peer, src, runID, cfg)
	}

	buf := make([]byte, 64<<10)
	readBufs := make([]batchReadBuffer, batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, len(buf))
	}
	state := senderState{
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
	retryInterval, err := performHelloHandshake(ctx, conn, peer, state.runID, 0, 1, &stats)
	if err != nil {
		return TransferStats{}, err
	}
	if cfg.Blast {
		if shouldUseConnectedBatcherForParallelSend(batcher, 1, cfg) {
			if connectedBatcher, ok := newConnectedUDPBatcher(conn, peer, cfg.Transport); ok {
				batcher = connectedBatcher
			}
		}
		return sendBlast(ctx, batcher, conn, peer, state.runID, src, cfg.ChunkSize, cfg.RateMbps, cfg.RateCeilingMbps, cfg.RepairPayloads, cfg.TailReplayBytes, cfg.FECGroupSize, cfg.PacketAEAD, cfg.StreamReplayWindowBytes, stats)
	}

	for {
		if err := fillSendWindow(ctx, batcher, peer, &state, &stats); err != nil {
			return TransferStats{}, err
		}
		if len(state.inFlight) == 0 && !state.doneQueued {
			if !sendWindowHasCapacity(&state) {
				if err := waitForAckProgress(ctx, batcher, &state, &stats, readBufs, retryInterval, peer); err != nil {
					return TransferStats{}, err
				}
				continue
			}
			if err := ctx.Err(); err != nil {
				return TransferStats{}, err
			}
			if err := waitZeroReadRetry(ctx, state.zeroReads); err != nil {
				return TransferStats{}, err
			}
			continue
		}
		if state.doneQueued && len(state.inFlight) == 0 {
			stats.markComplete(time.Now())
			return stats, nil
		}
		if state.doneQueued && donePacketSettled(state.inFlight) {
			stats.markComplete(time.Now())
			return stats, nil
		}

		n, err := batcher.ReadBatch(ctx, nextRetransmitDeadline(ctx, state.inFlight, retryInterval), readBufs)
		if err != nil {
			if ctx.Err() != nil {
				return TransferStats{}, ctx.Err()
			}
			if isNetTimeout(err) {
				if err := retransmitExpired(ctx, batcher, peer, state.inFlight, retryInterval, &stats); err != nil {
					return TransferStats{}, err
				}
				continue
			}
			return TransferStats{}, err
		}
		applyAckBatch(readBufs[:n], peer, &state, &stats)
	}
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

	stats := TransferStats{StartedAt: time.Now()}
	stats.peakGoodput.minWindow = blastRateFeedbackInterval
	stats.observePeakGoodput(stats.StartedAt, 0)
	buf := make([]byte, 64<<10)
	batcher := newPacketBatcher(conn, cfg.Transport)
	stats.Transport = batcher.Capabilities()
	readBufs := make([]batchReadBuffer, batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, len(buf))
	}
	var expectedSeq uint64
	buffered := make(map[uint64]Packet)
	var runID [16]byte
	var runIDSet bool
	var lastAckAt time.Time
	packetsSinceAck := 0
	ackDirty := false

	sendPendingAck := func(addr net.Addr) error {
		if !ackDirty || addr == nil {
			return nil
		}
		if err := sendAck(ctx, conn, addr, runID, 0, expectedSeq, ackMaskFor(buffered, expectedSeq), extendedAckPayloadFor(buffered, expectedSeq)); err != nil {
			return err
		}
		ackDirty = false
		packetsSinceAck = 0
		lastAckAt = time.Now()
		return nil
	}

	for {
		n, err := batcher.ReadBatch(ctx, defaultRetryInterval, readBufs)
		if err != nil {
			if ctx.Err() != nil {
				return TransferStats{}, ctx.Err()
			}
			if isNetTimeout(err) {
				if runIDSet {
					if err := sendPendingAck(peer); err != nil {
						return TransferStats{}, err
					}
				}
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return TransferStats{}, err
			}
			continue
		}
		for i := 0; i < n; i++ {
			addr := readBufs[i].Addr
			if peer != nil && !sameAddr(addr, peer) {
				continue
			}
			packet, err := UnmarshalPacket(readBufs[i].Bytes[:readBufs[i].N], nil)
			if err != nil {
				continue
			}
			if isZeroRunID(packet.RunID) {
				continue
			}
			if !runIDSet {
				if packet.Type != PacketTypeHello {
					continue
				}
				if !isZeroRunID(cfg.ExpectedRunID) && packet.RunID != cfg.ExpectedRunID {
					continue
				}
				runID = packet.RunID
				runIDSet = true
				if peer == nil {
					peer = cloneAddr(addr)
				}
				if cfg.Raw && !cfg.Blast && (packet.StripeID != 0 || packet.Seq > 1) {
					return receiveStripedFromFirstHello(ctx, conn, batcher, addr, runID, packet, dst, &stats, buf)
				}
				if err := sendHelloAck(ctx, conn, addr, runID, 0, 1); err != nil {
					return TransferStats{}, err
				}
				if cfg.Blast {
					return receiveBlastData(ctx, conn, cloneAddr(addr), runID, dst, &stats, buf, cfg.PacketAEAD)
				}
				continue
			}
			if packet.RunID != runID {
				continue
			}
			if packet.Type == PacketTypeHello {
				if err := sendHelloAck(ctx, conn, addr, runID, 0, 1); err != nil {
					return TransferStats{}, err
				}
				continue
			}

			switch packet.Type {
			case PacketTypeData:
				if cfg.Blast {
					if stats.FirstByteAt.IsZero() && len(packet.Payload) > 0 {
						stats.FirstByteAt = time.Now()
					}
					n, err := dst.Write(packet.Payload)
					if err != nil {
						return TransferStats{}, err
					}
					if n != len(packet.Payload) {
						return TransferStats{}, io.ErrShortWrite
					}
					stats.BytesReceived += int64(n)
					stats.observePeakGoodput(time.Now(), stats.BytesReceived)
					continue
				}
				if packet.Seq == expectedSeq {
					if stats.FirstByteAt.IsZero() && len(packet.Payload) > 0 {
						stats.FirstByteAt = time.Now()
					}
					n, err := dst.Write(packet.Payload)
					if err != nil {
						return TransferStats{}, err
					}
					if n != len(packet.Payload) {
						return TransferStats{}, io.ErrShortWrite
					}
					stats.BytesReceived += int64(n)
					stats.observePeakGoodput(time.Now(), stats.BytesReceived)
					expectedSeq++
				} else if packet.Seq > expectedSeq && packet.Seq <= expectedSeq+maxBufferedPackets {
					buffered[packet.Seq] = clonePacket(packet)
				}
				var complete bool
				expectedSeq, complete, err = advanceReceiveWindow(dst, buffered, expectedSeq, &stats)
				if err != nil {
					return TransferStats{}, err
				}
				ackDirty = true
				packetsSinceAck++
				if packetsSinceAck >= delayedAckPackets || time.Since(lastAckAt) >= delayedAckInterval {
					if err := sendPendingAck(addr); err != nil {
						return TransferStats{}, err
					}
				}
				if complete {
					stats.markComplete(time.Now())
					if err := sendPendingAck(addr); err != nil {
						return TransferStats{}, err
					}
					if err := lingerTerminalAcks(ctx, conn, addr, runID, expectedSeq); err != nil {
						return TransferStats{}, err
					}
					return stats, nil
				}
			case PacketTypeDone:
				if cfg.Blast {
					stats.markComplete(time.Now())
					return stats, nil
				}
				complete := false
				if packet.Seq == expectedSeq {
					expectedSeq++
					complete = true
				} else if packet.Seq > expectedSeq && packet.Seq <= expectedSeq+maxBufferedPackets {
					buffered[packet.Seq] = packet
				}
				if !complete {
					expectedSeq, complete, err = advanceReceiveWindow(dst, buffered, expectedSeq, &stats)
					if err != nil {
						return TransferStats{}, err
					}
				}
				ackDirty = true
				if err := sendPendingAck(addr); err != nil {
					return TransferStats{}, err
				}
				if complete {
					stats.markComplete(time.Now())
					if err := lingerTerminalAcks(ctx, conn, addr, runID, expectedSeq); err != nil {
						return TransferStats{}, err
					}
					return stats, nil
				}
			}
		}
	}
}

func sendBlast(ctx context.Context, batcher packetBatcher, conn net.PacketConn, peer net.Addr, runID [16]byte, src io.Reader, chunkSize int, rateMbps int, rateCeilingMbps int, repairPayloads bool, tailReplayBytes int, fecGroupSize int, packetAEAD cipher.AEAD, streamReplayWindowBytes uint64, stats TransferStats) (TransferStats, error) {
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}
	if batcher == nil {
		batcher = newPacketBatcher(conn, stats.Transport.RequestedKind)
	}
	stats.Transport = batcher.Capabilities()
	_ = setSocketPacing(conn, blastSocketPacingRateMbps(rateMbps, rateCeilingMbps))
	buildBatchLimit := batcher.MaxBatch()
	if buildBatchLimit < 128 {
		buildBatchLimit = 128
	}
	if buildBatchLimit > 512 {
		buildBatchLimit = 512
	}
	control := newBlastSendControl(rateMbps, rateCeilingMbps, time.Now())
	pacer := newBlastPacer(time.Now())
	batchLimit := pacedBatchLimit(buildBatchLimit, chunkSize, control.RateMbps())
	wireBatch := make([][]byte, batchLimit)
	packetBatch := make([][]byte, 0, batchLimit)
	readBatch := make([]byte, batchLimit*chunkSize)
	packetOverhead := 0
	if packetAEAD != nil {
		packetOverhead = packetAEAD.Overhead()
	}
	for i := range wireBatch {
		wireBatch[i] = make([]byte, headerLen+chunkSize+packetOverhead)
	}
	streamReplayEnabled := repairPayloads && (rateCeilingMbps > 0 || streamReplayWindowBytes > 0)
	retainHistoryPayloads := (repairPayloads || tailReplayBytes > 0) && !streamReplayEnabled
	history, err := newBlastRepairHistory(runID, chunkSize, retainHistoryPayloads, packetAEAD)
	if err != nil {
		return TransferStats{}, err
	}
	if streamReplayEnabled {
		replayBytes := streamReplayWindowBytes
		if replayBytes == 0 {
			replayBytes = defaultStreamReplayWindowBytes
		}
		history.streamReplay = newStreamReplayWindow(runID, chunkSize, replayBytes, packetAEAD)
	}
	defer history.Close()
	fec := newBlastFECGroup(runID, chunkSize, fecGroupSize, packetAEAD)
	repairDeduper := newBlastRepairDeduper()
	var repairReadBufs []batchReadBuffer
	var controlEvents <-chan blastSendControlEvent
	stopControlReader := func() {}
	if control.Adaptive() {
		controlEvents, stopControlReader = startBlastSendControlReader(ctx, batcher, runID)
		stopControlReader = sync.OnceFunc(stopControlReader)
		defer stopControlReader()
	} else {
		repairReadBufs = make([]batchReadBuffer, batcher.MaxBatch())
		for i := range repairReadBufs {
			repairReadBufs[i].Bytes = make([]byte, 64<<10)
		}
	}
	var seq uint64
	var offset uint64
	startedAt := time.Now()
	for {
		packetBatch = packetBatch[:0]
		wireIndex := 0
		batchPayloadBytes := uint64(0)
		flushPacketBatch := func() error {
			if len(packetBatch) == 0 {
				return nil
			}
			if err := writeBlastBatch(ctx, batcher, peer, packetBatch); err != nil {
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
			}
			if !control.Adaptive() {
				stats.observePeakGoodput(time.Now(), stats.BytesSent)
			}
			if control.Adaptive() {
				if complete, err := drainBlastSendControlEvents(ctx, batcher, peer, history, &stats, repairDeduper, control, controlEvents); err != nil {
					return err
				} else if complete {
					sessionTracef("blast repair complete received before sender EOF run=%x", runID[:4])
				}
				history.AckFloor(control.AckFloor())
				stats.MaxReplayBytes = max(stats.MaxReplayBytes, history.MaxReplayBytes())
			} else {
				if _, err := serviceBlastRepairRequests(ctx, batcher, peer, runID, history, &stats, repairDeduper, repairReadBufs, 0, nil); err != nil {
					return err
				}
			}
			packetBatch = packetBatch[:0]
			batchPayloadBytes = 0
			wireIndex = 0
			return nil
		}
		addReplayPacket := func(seq uint64, offset uint64, payload []byte) ([]byte, error) {
			for {
				wire, err := history.streamReplay.AddDataPacket(0, seq, offset, payload)
				if !errors.Is(err, errStreamReplayWindowFull) {
					return wire, err
				}
				if err := flushPacketBatch(); err != nil {
					return nil, err
				}
				if control.Adaptive() {
					if complete, err := drainBlastSendControlEvents(ctx, batcher, peer, history, &stats, repairDeduper, control, controlEvents); err != nil {
						return nil, err
					} else if complete {
						sessionTracef("blast repair complete received while replay window was full run=%x", runID[:4])
					}
					history.AckFloor(control.AckFloor())
					stats.MaxReplayBytes = max(stats.MaxReplayBytes, history.MaxReplayBytes())
				}
				if history.streamReplay == nil || history.streamReplay.RetainedBytes() < history.streamReplay.MaxBytes() {
					continue
				}
				waitStart := time.Now()
				if control.Adaptive() {
					control.ObserveReplayPressure(waitStart, history.streamReplay.RetainedBytes(), history.streamReplay.MaxBytes())
				}
				if err := sleepWithContext(ctx, blastRepairInterval); err != nil {
					return nil, err
				}
				recordReplayWindowFullWait(&stats, history.streamReplay.RetainedBytes(), time.Since(waitStart))
			}
		}
		if err := ctx.Err(); err != nil {
			return TransferStats{}, err
		}
		n, readErr := src.Read(readBatch)
		if n > 0 {
			remaining := readBatch[:n]
			for len(remaining) > 0 {
				payloadLen := chunkSize
				if payloadLen > len(remaining) {
					payloadLen = len(remaining)
				}
				var wire []byte
				var payloadBuf []byte
				if packetAEAD != nil {
					payloadBuf = remaining[:payloadLen]
					var err error
					if history.streamReplay != nil {
						wire, err = addReplayPacket(seq, offset, payloadBuf)
					} else {
						if err := history.Record(seq, payloadBuf); err != nil {
							return TransferStats{}, err
						}
						wire, err = marshalBlastPayloadPacket(PacketTypeData, runID, 0, seq, offset, 0, 0, payloadBuf, packetAEAD)
					}
					if err != nil {
						return TransferStats{}, err
					}
				} else if repairPayloads {
					if history.streamReplay != nil {
						payloadBuf = remaining[:payloadLen]
						var err error
						wire, err = addReplayPacket(seq, offset, payloadBuf)
						if err != nil {
							return TransferStats{}, err
						}
					} else {
						var err error
						wire, err = history.packetBuffer(seq, offset, payloadLen)
						if err != nil {
							return TransferStats{}, err
						}
						payloadBuf = wire[headerLen:]
					}
				} else {
					wire = wireBatch[wireIndex]
					wireIndex++
					payloadBuf = wire[headerLen : headerLen+payloadLen]
					encodePacketHeader(wire[:headerLen], PacketTypeData, runID, 0, seq, offset, 0, 0)
				}
				if packetAEAD == nil {
					copy(payloadBuf, remaining[:payloadLen])
				}
				if !repairPayloads && packetAEAD == nil {
					if err := history.Record(seq, payloadBuf); err != nil {
						return TransferStats{}, err
					}
				}
				packet := wire[:headerLen+payloadLen+packetOverhead]
				packetBatch = append(packetBatch, packet)
				batchPayloadBytes += uint64(payloadLen)
				stats.PacketsSent++
				stats.BytesSent += int64(payloadLen)
				if parity := fec.Record(seq, offset, payloadBuf); parity != nil {
					packetBatch = append(packetBatch, parity)
					stats.PacketsSent++
				}
				seq++
				offset += uint64(payloadLen)
				remaining = remaining[payloadLen:]
			}
		}
		eof := false
		if errors.Is(readErr, io.EOF) {
			eof = true
		} else if readErr != nil {
			return TransferStats{}, readErr
		}
		if n == 0 && !eof {
			if err := sleepWithContext(ctx, zeroReadRetryDelay); err != nil {
				return TransferStats{}, err
			}
		}
		if len(packetBatch) > 0 {
			if err := flushPacketBatch(); err != nil {
				return TransferStats{}, err
			}
		}
		if eof {
			break
		}
	}
	if parity := fec.Flush(); parity != nil {
		if err := writeBlastBatch(ctx, batcher, peer, [][]byte{parity}); err != nil {
			return TransferStats{}, err
		}
		stats.PacketsSent++
	}
	history.MarkComplete(offset, seq)
	if packets := history.tailPackets(tailReplayBytes); len(packets) > 0 {
		if err := writeBlastBatch(ctx, batcher, peer, packets); err != nil {
			return TransferStats{}, err
		}
		stats.PacketsSent += int64(len(packets))
		stats.Retransmits += int64(len(packets))
	}
	donePacket := make([]byte, headerLen)
	encodePacketHeader(donePacket, PacketTypeDone, runID, 0, seq, offset, 0, 0)
	writeBlastDoneBestEffort(ctx, batcher, peer, donePacket)
	stats.PacketsSent++
	lingerUntil := time.Now().Add(blastDoneLinger)
	for time.Now().Before(lingerUntil) {
		if err := sleepWithContext(ctx, blastDoneInterval); err != nil {
			return TransferStats{}, err
		}
		writeBlastDoneBestEffort(ctx, batcher, peer, donePacket)
		stats.PacketsSent++
		if control.Adaptive() {
			if complete, err := drainBlastSendControlEvents(ctx, batcher, peer, history, &stats, repairDeduper, control, controlEvents); err != nil {
				return TransferStats{}, err
			} else if complete {
				stats.markComplete(time.Now())
				return stats, nil
			}
			history.AckFloor(control.AckFloor())
			stats.MaxReplayBytes = max(stats.MaxReplayBytes, history.MaxReplayBytes())
		}
	}
	if control.Adaptive() {
		if complete, err := drainBlastSendControlEvents(ctx, batcher, peer, history, &stats, repairDeduper, control, controlEvents); err != nil {
			return TransferStats{}, err
		} else if complete {
			stats.markComplete(time.Now())
			return stats, nil
		}
		history.AckFloor(control.AckFloor())
		stats.MaxReplayBytes = max(stats.MaxReplayBytes, history.MaxReplayBytes())
	}
	stopControlReader()
	return serveBlastRepairs(ctx, batcher, peer, runID, history, stats)
}

func serviceBlastRepairRequests(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, history *blastRepairHistory, stats *TransferStats, deduper *blastRepairDeduper, readBufs []batchReadBuffer, timeout time.Duration, control *blastSendControl) (bool, error) {
	if batcher == nil || history == nil || len(readBufs) == 0 {
		return false, nil
	}
	n, err := batcher.ReadBatch(ctx, timeout, readBufs)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if isNetTimeout(err) {
			return false, nil
		}
		if errors.Is(err, net.ErrClosed) {
			return false, err
		}
		return false, nil
	}
	repaired := false
	now := time.Now()
	for i := 0; i < n; i++ {
		packetType, payload, packetRunID, _, _, ok := decodeBlastPacketFull(readBufs[i].Bytes[:readBufs[i].N])
		if !ok || packetRunID != runID {
			continue
		}
		switch packetType {
		case PacketTypeRepairRequest:
			repaired = true
			retransmits, err := sendBlastRepairs(ctx, batcher, peer, history, payload, stats, deduper, now)
			if err != nil {
				return repaired, err
			}
			if control != nil && retransmits > 0 {
				control.ObserveRepairPressure(now, retransmits)
			}
		case PacketTypeStats:
			if control != nil {
				sessionTracef("blast stats receive rx_payload_len=%d", len(payload))
				control.ObserveReceiverStats(payload, now)
			}
		}
	}
	return repaired, nil
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
	readBufs := make([]batchReadBuffer, lane.batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, 64<<10)
	}
	for {
		n, err := lane.batcher.ReadBatch(ctx, blastRepairInterval, readBufs)
		now := time.Now()
		if err != nil {
			if ctx.Err() != nil || isNetTimeout(err) {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				select {
				case events <- blastParallelSendControlEvent{lane: lane, event: blastSendControlEvent{err: err, receivedAt: now}}:
				case <-ctx.Done():
				}
				return
			}
			continue
		}
		for i := 0; i < n; i++ {
			packetType, payload, packetRunID, _, _, ok := decodeBlastPacketFull(readBufs[i].Bytes[:readBufs[i].N])
			if !ok || packetRunID != runID {
				continue
			}
			stripeID := binary.BigEndian.Uint16(readBufs[i].Bytes[2:4])
			switch packetType {
			case PacketTypeRepairComplete, PacketTypeRepairRequest, PacketTypeStats:
				if packetType == PacketTypeStats && lane.history != nil && lane.history.streamReplay != nil {
					if stats, ok := unmarshalBlastStatsPayload(payload); ok {
						lane.history.AckFloor(stats.AckFloor)
					}
				}
				eventPayload := append([]byte(nil), payload...)
				select {
				case events <- blastParallelSendControlEvent{lane: lane, event: blastSendControlEvent{typ: packetType, stripe: stripeID, payload: eventPayload, receivedAt: now}}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func blastParallelRepairHistoryForLane(global *blastRepairHistory, lane *blastParallelSendLane) *blastRepairHistory {
	if lane != nil && lane.history != nil {
		return lane.history
	}
	return global
}

func SendBlastParallel(ctx context.Context, conns []net.PacketConn, remoteAddrs []string, src io.Reader, cfg SendConfig) (TransferStats, error) {
	if len(conns) == 0 {
		return TransferStats{}, errors.New("no packet conns")
	}
	if len(conns) != len(remoteAddrs) {
		return TransferStats{}, fmt.Errorf("packet conn count %d does not match remote addr count %d", len(conns), len(remoteAddrs))
	}
	if len(conns) == 1 {
		stats, err := Send(ctx, conns[0], remoteAddrs[0], src, cfg)
		if stats.Lanes == 0 {
			stats.Lanes = 1
		}
		return stats, err
	}
	if src == nil {
		return TransferStats{}, errors.New("nil source reader")
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = defaultChunkSize
	}
	runID := cfg.RunID
	var err error
	if isZeroRunID(runID) {
		runID, err = newRunID()
		if err != nil {
			return TransferStats{}, err
		}
	}

	stats := TransferStats{StartedAt: time.Now()}
	stats.observePeakGoodput(stats.StartedAt, 0)
	stripedBlast := cfg.StripedBlast
	lanes := make([]*blastParallelSendLane, 0, len(conns))
	handshakeTimeout := cfg.ParallelHandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = 1500 * time.Millisecond
	}
	var skippedHandshakeErr error
	for i, conn := range conns {
		if conn == nil {
			return TransferStats{}, fmt.Errorf("nil packet conn at lane %d", i)
		}
		peer, err := net.ResolveUDPAddr("udp", remoteAddrs[i])
		if err != nil {
			return TransferStats{}, err
		}
		batcher := newPacketBatcher(conn, cfg.Transport)
		if len(lanes) == 0 {
			stats.Transport = batcher.Capabilities()
		}
		handshakeCtx := ctx
		var cancelHandshake context.CancelFunc
		if cfg.AllowPartialParallel {
			handshakeCtx, cancelHandshake = context.WithTimeout(ctx, handshakeTimeout)
		}
		handshakeStripeID := uint16(0)
		handshakeTotalStripes := uint16(1)
		if stripedBlast {
			handshakeStripeID = uint16(i)
			handshakeTotalStripes = uint16(len(conns))
		}
		sessionTracef("parallel hello start lane=%d local=%s peer=%s run=%x stripe=%d total=%d", i, conn.LocalAddr(), peer, runID[:4], handshakeStripeID, handshakeTotalStripes)
		_, err = performHelloHandshake(handshakeCtx, conn, peer, runID, handshakeStripeID, handshakeTotalStripes, &stats)
		if cancelHandshake != nil {
			cancelHandshake()
		}
		if err != nil {
			sessionTracef("parallel hello fail lane=%d local=%s peer=%s run=%x stripe=%d err=%v", i, conn.LocalAddr(), peer, runID[:4], handshakeStripeID, err)
			if cfg.AllowPartialParallel {
				skippedHandshakeErr = err
				continue
			}
			return TransferStats{}, err
		}
		sessionTracef("parallel hello ok lane=%d local=%s peer=%s run=%x stripe=%d", i, conn.LocalAddr(), peer, runID[:4], handshakeStripeID)
		if shouldUseConnectedBatcherForParallelSend(batcher, len(conns), cfg) {
			if connectedBatcher, ok := newConnectedUDPBatcher(conn, peer, cfg.Transport); ok {
				batcher = connectedBatcher
				if len(lanes) == 0 {
					stats.Transport = batcher.Capabilities()
				}
			}
		}
		lane := &blastParallelSendLane{
			conn:       conn,
			peer:       peer,
			batcher:    batcher,
			stripeID:   uint16(i),
			runID:      runID,
			sendConfig: cfg,
		}
		chunkSize := cfg.ChunkSize
		lane.payloadPool.New = func() any {
			buf := make([]byte, chunkSize)
			return &buf
		}
		lanes = append(lanes, lane)
	}
	if len(lanes) == 0 {
		if skippedHandshakeErr != nil {
			return TransferStats{}, skippedHandshakeErr
		}
		return TransferStats{}, errors.New("no parallel blast lanes completed handshake")
	}
	if stripedBlast {
		finalStripes := uint16(len(lanes))
		for i, lane := range lanes {
			lane.stripeID = uint16(i)
		}
		if cfg.AllowPartialParallel && len(lanes) != len(conns) {
			for _, lane := range lanes {
				if _, err := performHelloHandshakeBatch(ctx, lane.batcher, lane.peer, runID, lane.stripeID, finalStripes, &stats); err != nil {
					return TransferStats{}, err
				}
			}
		}
	}
	stats.Lanes = len(lanes)
	controlCeilingMbps := cfg.RateCeilingMbps
	if cfg.RateExplorationCeilingMbps > controlCeilingMbps {
		controlCeilingMbps = cfg.RateExplorationCeilingMbps
	}
	control := newBlastSendControlWithInitialLossCeiling(cfg.RateMbps, controlCeilingMbps, cfg.RateCeilingMbps, time.Now())
	activeLanes := parallelActiveLanesForConfig(control.RateMbps(), len(lanes), stripedBlast, cfg.MinActiveLanes, cfg.MaxActiveLanes)
	if activeLanes == 0 {
		return TransferStats{}, errors.New("no active parallel blast lanes")
	}
	laneRate := parallelLaneRateMbps(control.RateMbps(), activeLanes)
	sendStartedAt := time.Now()
	for i, lane := range lanes {
		rate := 0
		if i < activeLanes {
			rate = laneRate
		}
		_ = setSocketPacing(lane.conn, laneRate)
		buildBatchLimit := lane.batcher.MaxBatch()
		if buildBatchLimit < 128 {
			buildBatchLimit = 128
		}
		lane.batchLimit = pacedBatchLimit(buildBatchLimit, cfg.ChunkSize, blastParallelLaneBatchRateMbps(laneRate, controlCeilingMbps, activeLanes))
		lane.ch = make(chan blastParallelSendItem, blastParallelLaneQueueCapacity(lane.batchLimit, stripedBlast))
		lane.setRateMbps(rate)
		lane.pacer = newBlastPacer(sendStartedAt)
	}

	streamReplayEnabled := cfg.RepairPayloads && (cfg.RateCeilingMbps > 0 || cfg.StreamReplayWindowBytes > 0)
	replayBytes := cfg.StreamReplayWindowBytes
	if streamReplayEnabled && replayBytes == 0 {
		replayBytes = defaultStreamReplayWindowBytes
	}
	retainHistoryPayloads := (cfg.RepairPayloads || cfg.TailReplayBytes > 0) && !streamReplayEnabled
	history, err := newBlastRepairHistory(runID, cfg.ChunkSize, retainHistoryPayloads, cfg.PacketAEAD)
	if err != nil {
		return TransferStats{}, err
	}
	if streamReplayEnabled {
		history.streamReplay = newStreamReplayWindow(runID, cfg.ChunkSize, replayBytes, cfg.PacketAEAD)
	}
	defer history.Close()
	if stripedBlast {
		for _, lane := range lanes {
			laneRetainPayloads := true
			if streamReplayEnabled {
				laneRetainPayloads = false
			}
			lane.history, err = newBlastRepairHistory(runID, cfg.ChunkSize, laneRetainPayloads, cfg.PacketAEAD)
			if err != nil {
				return TransferStats{}, err
			}
			if streamReplayEnabled {
				laneReplayBytes := replayBytes / uint64(len(lanes))
				if laneReplayBytes == 0 {
					laneReplayBytes = replayBytes
				}
				lane.history.streamReplay = newStreamReplayWindow(runID, cfg.ChunkSize, laneReplayBytes, cfg.PacketAEAD)
			}
			lane.fec = newBlastFECGroupForStripe(runID, lane.stripeID, cfg.ChunkSize, cfg.FECGroupSize, cfg.PacketAEAD)
			defer lane.history.Close()
		}
	}
	fec := newBlastFECGroup(runID, cfg.ChunkSize, cfg.FECGroupSize, cfg.PacketAEAD)
	if stripedBlast {
		fec = nil
	}

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
	updateLaneRates := func() {
		activeLanes = parallelActiveLanesForConfig(control.RateMbps(), len(lanes), stripedBlast, cfg.MinActiveLanes, cfg.MaxActiveLanes)
		rate := parallelLaneRateMbps(control.RateMbps(), activeLanes)
		for i, lane := range lanes {
			if i >= activeLanes {
				lane.setRateMbps(0)
				continue
			}
			lane.setRateMbps(rate)
		}
	}
	applyControlAck := func() {
		history.AckFloor(control.AckFloor())
		stats.MaxReplayBytes = max(stats.MaxReplayBytes, history.MaxReplayBytes())
		if stripedBlast {
			for _, lane := range lanes {
				if lane.history != nil {
					lane.history.AckFloor(control.AckFloor())
					stats.MaxReplayBytes = max(stats.MaxReplayBytes, lane.history.MaxReplayBytes())
				}
			}
		}
	}
	drainControlEvents := func() (bool, error) {
		if !control.Adaptive() {
			return false, nil
		}
		complete := false
		beforeRate := control.RateMbps()
		for {
			select {
			case event := <-controlEvents:
				if event.lane == nil || event.lane.batcher == nil {
					continue
				}
				eventHistory := blastParallelRepairHistoryForLane(history, event.lane)
				if stripedBlast && event.event.typ == PacketTypeStats && eventHistory != nil && eventHistory != history {
					if control != nil {
						sessionTracef("blast stats receive stripe=%d rx_payload_len=%d", event.event.stripe, len(event.event.payload))
					}
					if !observeStripedBlastStatsEvent(&stats, eventHistory, control, event.event) {
						continue
					}
					continue
				}
				eventComplete, _, err := handleBlastSendControlEvent(ctx, event.lane.batcher, event.lane.peer, eventHistory, &stats, blastRepairDeduperForLane(repairDeduper, event.lane), control, event.event)
				if err != nil {
					return complete, err
				}
				complete = complete || eventComplete
			default:
				applyControlAck()
				if control.RateMbps() != beforeRate {
					updateLaneRates()
				}
				return complete, nil
			}
		}
	}
	errCh := make(chan error, len(lanes))
	var wg sync.WaitGroup
	for _, lane := range lanes {
		wg.Add(1)
		go func(lane *blastParallelSendLane) {
			defer wg.Done()
			if err := runBlastParallelSendLane(sendCtx, lane); err != nil {
				select {
				case errCh <- err:
				default:
				}
				sendCancel()
			}
		}(lane)
	}

	var seq uint64
	var offset uint64
	readBatch := make([]byte, parallelBlastReadBatchSize(len(lanes), cfg.ChunkSize))
	readErr := error(nil)
	addParallelPacket := func(packetHistory *blastRepairHistory, stripeID uint16, packetSeq uint64, packetOffset uint64, payload []byte) ([]byte, error) {
		for {
			wire, err := blastParallelDataPacket(packetHistory, runID, stripeID, packetSeq, packetOffset, payload, cfg)
			if !errors.Is(err, errStreamReplayWindowFull) {
				return wire, err
			}
			control.SetSentPayloadBytes(offset)
			if complete, err := drainControlEvents(); err != nil {
				return nil, err
			} else if complete {
				sessionTracef("blast repair complete received while parallel replay window was full run=%x", runID[:4])
			}
			if packetHistory == nil || packetHistory.streamReplay == nil || packetHistory.streamReplay.RetainedBytes() < packetHistory.streamReplay.MaxBytes() {
				continue
			}
			waitStart := time.Now()
			if control.Adaptive() {
				control.ObserveReplayPressure(waitStart, packetHistory.streamReplay.RetainedBytes(), packetHistory.streamReplay.MaxBytes())
				updateLaneRates()
			}
			if err := sleepWithContext(ctx, blastRepairInterval); err != nil {
				return nil, err
			}
			recordReplayWindowFullWait(&stats, packetHistory.streamReplay.RetainedBytes(), time.Since(waitStart))
		}
	}
	for readErr == nil {
		var n int
		n, readErr = src.Read(readBatch)
		if n > 0 {
			remaining := readBatch[:n]
			for len(remaining) > 0 {
				payloadLen := cfg.ChunkSize
				if payloadLen > len(remaining) {
					payloadLen = len(remaining)
				}
				laneIndex := int(seq % uint64(activeLanes))
				if stripedBlast {
					laneIndex = blastParallelLaneIndexForOffset(offset, activeLanes, cfg.ChunkSize)
				}
				lane := lanes[laneIndex]
				packetSeq := seq
				packetHistory := history
				stripeID := uint16(0)
				if stripedBlast {
					packetSeq = lane.nextSeq
					lane.nextSeq++
					packetHistory = lane.history
					stripeID = lane.stripeID
				}
				if stripedBlast {
					progressWhileQueued := func() error {
						if control.Adaptive() {
							control.SetSentPayloadBytes(offset)
						}
						if complete, err := drainControlEvents(); err != nil {
							return err
						} else if complete {
							sessionTracef("blast repair complete received while parallel lane queue was full run=%x", runID[:4])
						}
						if control.Adaptive() {
							observeBlastParallelQueueReplayPressure(control, packetHistory, time.Now())
							updateLaneRates()
						}
						return nil
					}
					if err := enqueueBlastParallelPayloadWithProgress(sendCtx, lane, packetHistory, stripeID, packetSeq, offset, remaining[:payloadLen], progressWhileQueued); err != nil {
						readErr = err
						break
					}
				} else {
					wire, err := addParallelPacket(packetHistory, stripeID, packetSeq, offset, remaining[:payloadLen])
					if err != nil {
						readErr = err
						break
					}
					if err := enqueueBlastParallelPacket(sendCtx, lane, wire); err != nil {
						readErr = err
						break
					}
				}
				stats.PacketsSent++
				stats.BytesSent += int64(payloadLen)
				if stripedBlast {
					if parity := lane.fec.Record(packetSeq, offset, remaining[:payloadLen]); parity != nil {
						if err := enqueueBlastParallelPacket(sendCtx, lane, parity); err != nil {
							readErr = err
							break
						}
						stats.PacketsSent++
					}
				} else {
					if parity := fec.Record(seq, offset, remaining[:payloadLen]); parity != nil {
						parityLane := lanes[int(seq%uint64(activeLanes))]
						if err := enqueueBlastParallelPacket(sendCtx, parityLane, parity); err != nil {
							readErr = err
							break
						}
						stats.PacketsSent++
					}
				}
				seq++
				offset += uint64(payloadLen)
				remaining = remaining[payloadLen:]
			}
		}
		if n > 0 && control.Adaptive() {
			control.SetSentPayloadBytes(offset)
			if complete, err := drainControlEvents(); err != nil {
				readErr = err
			} else if complete {
				sessionTracef("blast repair complete received before parallel sender EOF run=%x", runID[:4])
			}
		}
		if readErr != nil {
			break
		}
	}
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	if readErr != nil {
		sendCancel()
	}
	if readErr == nil && stripedBlast {
		for _, lane := range lanes {
			if parity := lane.fec.Flush(); parity != nil {
				if err := enqueueBlastParallelPacket(sendCtx, lane, parity); err != nil {
					readErr = err
					sendCancel()
					break
				}
				stats.PacketsSent++
			}
		}
	}
	for _, lane := range lanes {
		close(lane.ch)
	}
	wg.Wait()
	select {
	case err := <-errCh:
		return TransferStats{}, err
	default:
	}
	if readErr != nil {
		return TransferStats{}, readErr
	}
	if control.Adaptive() {
		control.SetSentPayloadBytes(offset)
		if complete, err := drainControlEvents(); err != nil {
			return TransferStats{}, err
		} else if complete {
			stats.markComplete(time.Now())
			return stats, nil
		}
	}

	if stripedBlast {
		for _, lane := range lanes {
			lane.history.MarkComplete(0, lane.nextSeq)
		}
	} else {
		history.MarkComplete(offset, seq)
		if parity := fec.Flush(); parity != nil {
			lane := lanes[int(seq%uint64(activeLanes))]
			if err := writeBlastBatch(ctx, lane.batcher, lane.peer, [][]byte{parity}); err != nil {
				return TransferStats{}, err
			}
			stats.PacketsSent++
		}
		if packets := history.tailPackets(cfg.TailReplayBytes); len(packets) > 0 {
			if err := writeBlastParallelPackets(ctx, lanes, packets); err != nil {
				return TransferStats{}, err
			}
			stats.PacketsSent += int64(len(packets))
			stats.Retransmits += int64(len(packets))
		}
	}
	writeBlastDoneAllBestEffort(ctx, lanes, runID, seq, offset, stripedBlast, &stats)
	lingerUntil := time.Now().Add(blastDoneLinger)
	for time.Now().Before(lingerUntil) {
		if err := sleepWithContext(ctx, blastDoneInterval); err != nil {
			return TransferStats{}, err
		}
		writeBlastDoneAllBestEffort(ctx, lanes, runID, seq, offset, stripedBlast, &stats)
		if control.Adaptive() {
			if complete, err := drainControlEvents(); err != nil {
				return TransferStats{}, err
			} else if complete {
				stats.markComplete(time.Now())
				return stats, nil
			}
		}
	}
	if control.Adaptive() {
		if complete, err := drainControlEvents(); err != nil {
			return TransferStats{}, err
		} else if complete {
			stats.markComplete(time.Now())
			return stats, nil
		}
	}
	stopControlReader()
	resendTerminal := func() {
		writeBlastDoneAllBestEffort(ctx, lanes, runID, seq, offset, stripedBlast, &stats)
	}
	return serveBlastRepairsParallel(ctx, lanes, runID, history, stats, resendTerminal)
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
	rateBasisMbps := cfg.RateCeilingMbps
	if cfg.RateMbps > 0 && (rateBasisMbps <= 0 || cfg.RateMbps < rateBasisMbps) {
		rateBasisMbps = cfg.RateMbps
	}
	if laneCount > 1 {
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
	return rateBasisMbps > 0 && rateBasisMbps <= parallelActiveLaneOneMaxMbps
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

func enqueueBlastParallelPayloadWithProgress(ctx context.Context, lane *blastParallelSendLane, history *blastRepairHistory, stripeID uint16, seq uint64, offset uint64, payload []byte, onWait func() error) error {
	if lane == nil {
		return errors.New("nil blast parallel lane")
	}
	if len(payload) == 0 {
		return errors.New("empty blast payload")
	}
	item := blastParallelSendItem{
		payload:  lane.copyPayload(payload),
		history:  history,
		stripeID: stripeID,
		seq:      seq,
		offset:   offset,
	}
	for {
		select {
		case lane.ch <- item:
			return nil
		default:
		}
		if onWait != nil {
			if err := onWait(); err != nil {
				lane.releasePayload(item.payload)
				return err
			}
		}
		timer := time.NewTimer(blastRepairInterval)
		select {
		case lane.ch <- item:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			lane.releasePayload(item.payload)
			return ctx.Err()
		case <-timer.C:
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
	history := item.history
	if history == nil {
		history = lane.history
	}
	cfg := lane.sendConfig
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = defaultChunkSize
	}
	for {
		wire, err := blastParallelDataPacket(history, lane.runID, item.stripeID, item.seq, item.offset, item.payload, cfg)
		if !errors.Is(err, errStreamReplayWindowFull) {
			return wire, err
		}
		if history == nil || history.streamReplay == nil || history.streamReplay.RetainedBytes() < history.streamReplay.MaxBytes() {
			continue
		}
		if err := sleepWithContext(ctx, blastRepairInterval); err != nil {
			return nil, err
		}
	}
}

func runBlastParallelSendLane(ctx context.Context, lane *blastParallelSendLane) error {
	if lane == nil || lane.batcher == nil {
		return errors.New("nil blast parallel lane")
	}
	if lane.batchLimit <= 0 {
		lane.batchLimit = lane.batcher.MaxBatch()
	}
	if lane.batchLimit <= 0 {
		lane.batchLimit = 1
	}
	pending := make([][]byte, 0, lane.batchLimit)
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		if err := writeBlastBatch(ctx, lane.batcher, lane.peer, pending); err != nil {
			pending = pending[:0]
			return err
		}
		if rateMbps := lane.currentRateMbps(); rateMbps > 0 {
			if lane.pacer == nil {
				lane.pacer = newBlastPacer(time.Now())
			}
			var batchPayloadBytes uint64
			for _, packet := range pending {
				batchPayloadBytes += blastParallelPaceBytes(packet)
			}
			if err := lane.pacer.Pace(ctx, batchPayloadBytes, rateMbps); err != nil {
				pending = pending[:0]
				return err
			}
		}
		pending = pending[:0]
		return nil
	}
	for {
		select {
		case item, ok := <-lane.ch:
			if !ok {
				return flush()
			}
			packet, err := encodeBlastParallelSendItem(ctx, lane, item)
			lane.releasePayload(item.payload)
			if err != nil {
				return err
			}
			pending = append(pending, packet)
			if len(pending) >= lane.batchLimit {
				if err := flush(); err != nil {
					return err
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
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
	var wg sync.WaitGroup
	for _, lane := range lanes {
		wg.Add(1)
		go func(lane *blastParallelSendLane) {
			defer wg.Done()
			readBlastParallelRepairEvents(repairCtx, lane, runID, events)
		}(lane)
	}
	defer wg.Wait()

	quietTimer := time.NewTimer(blastRepairQuietGrace)
	defer quietTimer.Stop()
	doneTicker := time.NewTicker(blastDoneInterval)
	defer doneTicker.Stop()
	hadRepair := false
	quietDeadline := time.Now().Add(blastRepairQuietGrace)
	type repairRequestKey struct {
		stripe  uint16
		payload string
	}
	recentRepairRequests := make(map[repairRequestKey]time.Time)
	resetQuiet := func(retransmits int, chunkSize int) {
		if retransmits <= 0 {
			return
		}
		if !quietTimer.Stop() {
			select {
			case <-quietTimer.C:
			default:
			}
		}
		if chunkSize <= 0 {
			chunkSize = defaultChunkSize
		}
		quietFor := blastRepairQuietGraceForRepairBytes(int64(retransmits * chunkSize))
		quietDeadline = time.Now().Add(quietFor)
		quietTimer.Reset(quietFor)
	}
	deduper := newBlastRepairDeduper()
	for {
		select {
		case <-ctx.Done():
			return TransferStats{}, ctx.Err()
		case <-quietTimer.C:
			stats.markComplete(time.Now())
			cancel()
			return stats, nil
		case <-doneTicker.C:
			if resendTerminal != nil {
				resendTerminal()
			}
		case event := <-events:
			if event.err != nil {
				return TransferStats{}, event.err
			}
			switch event.typ {
			case PacketTypeRepairComplete:
				stats.markComplete(time.Now())
				cancel()
				return stats, nil
			case PacketTypeRepairRequest:
				now := time.Now()
				if now.After(quietDeadline) {
					stats.markComplete(now)
					cancel()
					return stats, nil
				}
				key := repairRequestKey{stripe: event.stripe, payload: string(event.payload)}
				if ignoreUntil, ok := recentRepairRequests[key]; ok && now.Before(ignoreUntil) {
					continue
				}
				recentRepairRequests[key] = now
				repairHistory := history
				if event.lane != nil && event.lane.history != nil && event.stripe == event.lane.stripeID {
					repairHistory = event.lane.history
				}
				hadRepair = hadRepair || repairHistory.CanRepair()
				retransmits, err := sendBlastRepairs(ctx, event.lane.batcher, event.lane.peer, repairHistory, event.payload, &stats, blastRepairDeduperForLane(deduper, event.lane), now)
				if err != nil {
					return TransferStats{}, err
				}
				chunkSize := defaultChunkSize
				if repairHistory != nil {
					chunkSize = repairHistory.chunkSize
				}
				resetQuiet(retransmits, chunkSize)
				if retransmits > 0 {
					recentRepairRequests[key] = quietDeadline
				}
				if retransmits <= 0 && time.Now().After(quietDeadline) {
					stats.markComplete(time.Now())
					cancel()
					return stats, nil
				}
			}
		}
	}
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

func readBlastParallelRepairEvents(ctx context.Context, lane *blastParallelSendLane, runID [16]byte, events chan<- blastParallelRepairEvent) {
	if lane == nil || lane.batcher == nil {
		return
	}
	readBufs := make([]batchReadBuffer, lane.batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, 64<<10)
	}
	for {
		n, err := lane.batcher.ReadBatch(ctx, blastRepairInterval, readBufs)
		if err != nil {
			if ctx.Err() != nil || isNetTimeout(err) {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				select {
				case events <- blastParallelRepairEvent{err: err}:
				case <-ctx.Done():
				}
				return
			}
			continue
		}
		for i := 0; i < n; i++ {
			packetType, payload, packetRunID, _, _, ok := decodeBlastPacketFull(readBufs[i].Bytes[:readBufs[i].N])
			if !ok || packetRunID != runID {
				continue
			}
			stripeID := binary.BigEndian.Uint16(readBufs[i].Bytes[2:4])
			switch packetType {
			case PacketTypeRepairComplete, PacketTypeRepairRequest:
				eventPayload := append([]byte(nil), payload...)
				select {
				case events <- blastParallelRepairEvent{lane: lane, typ: packetType, stripe: stripeID, payload: eventPayload}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
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
	currentFallback := errors.Is(current, context.Canceled) || errors.Is(current, io.ErrClosedPipe) || errors.Is(current, net.ErrClosed)
	candidateFallback := errors.Is(candidate, context.Canceled) || errors.Is(candidate, io.ErrClosedPipe) || errors.Is(candidate, net.ErrClosed)
	if currentFallback && !candidateFallback {
		return candidate
	}
	return current
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
	if h.chunkSize <= 0 {
		return nil
	}
	if len(h.packetSlabs) > 0 {
		if packet := h.packetFromBufferLocked(seq); packet != nil {
			return packet
		}
	}
	if h.packets == 0 || seq >= h.packets {
		return nil
	}
	offset := seq * uint64(h.chunkSize)
	if offset >= h.totalBytes {
		return nil
	}
	payloadLen := h.chunkSize
	if remaining := h.totalBytes - offset; remaining < uint64(payloadLen) {
		payloadLen = int(remaining)
	}
	if !h.retainPayloads && payloadLen > 0 {
		return nil
	}
	if !h.hasPayloadRange(offset, payloadLen) {
		return nil
	}
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		h.readPayloadAt(payload, offset)
	}
	wire, err := marshalBlastPayloadPacket(PacketTypeData, h.runID, 0, seq, offset, 0, 0, payload, h.packetAEAD)
	if err != nil {
		return nil
	}
	return wire
}

func (h *blastRepairHistory) packetBuffer(seq uint64, offset uint64, payloadLen int) ([]byte, error) {
	return h.packetBufferForStripe(0, seq, offset, payloadLen)
}

func (h *blastRepairHistory) packetBufferForStripe(stripeID uint16, seq uint64, offset uint64, payloadLen int) ([]byte, error) {
	if h == nil || !h.retainPayloads || h.chunkSize <= 0 || payloadLen <= 0 {
		return nil, errors.New("invalid blast repair packet buffer")
	}
	if h.packetAEAD != nil {
		return nil, errors.New("encrypted blast repair packets require retained payload assembly")
	}
	if payloadLen > h.chunkSize {
		return nil, errors.New("blast repair packet payload too large")
	}
	if err := h.ensurePacketCapacityForSeq(seq); err != nil {
		return nil, err
	}
	if seq >= uint64(len(h.packetLens)) {
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
	slabIndex, slabOffset := h.packetLocation(seq)
	packet := h.packetSlabs[slabIndex][slabOffset : slabOffset+headerLen+payloadLen]
	encodePacketHeader(packet[:headerLen], PacketTypeData, h.runID, stripeID, seq, offset, 0, 0)
	h.packetLens[seq] = headerLen + payloadLen
	return packet, nil
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
	h.mu.RLock()
	packets := h.packets
	retainPayloads := h.retainPayloads
	streamReplay := h.streamReplay
	h.mu.RUnlock()
	if !retainPayloads && streamReplay == nil || packets == 0 {
		return nil
	}
	count := (bytesBudget + h.chunkSize - 1) / h.chunkSize
	if count <= 0 {
		return nil
	}
	if uint64(count) > packets {
		count = int(packets)
	}
	start := packets - uint64(count)
	out := make([][]byte, 0, count)
	for seq := start; seq < packets; seq++ {
		packet := h.packet(seq)
		if len(packet) == 0 && streamReplay != nil {
			packet = streamReplay.Packet(seq)
		}
		if len(packet) > 0 {
			out = append(out, packet)
		}
	}
	return out
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
	readBufs := make([]batchReadBuffer, batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, 64<<10)
	}
	quietDeadline := time.Time{}
	deduper := newBlastRepairDeduper()
	hadRepair := false
	for {
		complete := history.Complete()
		if complete && quietDeadline.IsZero() {
			quietDeadline = time.Now().Add(blastRepairQuietGraceForExpectedBytes(history.TotalBytes(), hadRepair))
		}
		wait := parallelBlastDataIdle
		if complete {
			wait = time.Until(quietDeadline)
		}
		if wait > blastRepairInterval {
			wait = blastRepairInterval
		}
		if complete && wait <= 0 {
			stats.markComplete(time.Now())
			return stats, nil
		}
		n, err := batcher.ReadBatch(ctx, wait, readBufs)
		if err != nil {
			if ctx.Err() != nil {
				return TransferStats{}, ctx.Err()
			}
			if isNetTimeout(err) {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return TransferStats{}, err
			}
			continue
		}
		for i := 0; i < n; i++ {
			packetType, payload, packetRunID, _, _, ok := decodeBlastPacketFull(readBufs[i].Bytes[:readBufs[i].N])
			if !ok || packetRunID != runID {
				continue
			}
			switch packetType {
			case PacketTypeRepairComplete:
				stats.markComplete(time.Now())
				return stats, nil
			case PacketTypeRepairRequest:
				hadRepair = hadRepair || history.CanRepair()
				if history.Complete() {
					quietDeadline = time.Now().Add(blastRepairQuietGraceForExpectedBytes(history.TotalBytes(), hadRepair))
				}
				if _, err := sendBlastRepairs(ctx, batcher, peer, history, payload, &stats, deduper, time.Now()); err != nil {
					return TransferStats{}, err
				}
			}
		}
	}
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
	pending := make([][]byte, 0, batcher.MaxBatch())
	retransmits := 0
	for len(payload) >= 8 {
		seq := binary.BigEndian.Uint64(payload[:8])
		payload = payload[8:]
		packet := history.packet(seq)
		if packet == nil {
			continue
		}
		if !deduper.ShouldSend(seq, now) {
			continue
		}
		pending = append(pending, packet)
		if len(pending) == batcher.MaxBatch() {
			if err := writeBlastBatch(ctx, batcher, peer, pending); err != nil {
				return retransmits, err
			}
			if stats != nil {
				stats.Retransmits += int64(len(pending))
				stats.PacketsSent += int64(len(pending))
			}
			retransmits += len(pending)
			pending = pending[:0]
		}
	}
	if len(pending) == 0 {
		return retransmits, nil
	}
	if err := writeBlastBatch(ctx, batcher, peer, pending); err != nil {
		return retransmits, err
	}
	if stats != nil {
		stats.Retransmits += int64(len(pending))
		stats.PacketsSent += int64(len(pending))
	}
	retransmits += len(pending)
	return retransmits, nil
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
	if udpConn, ok := conn.(*net.UDPConn); ok && batcher.MaxBatch() == 1 {
		return receiveBlastDataUDP(ctx, udpConn, peer, runID, dst, stats, buf, packetAEAD)
	}
	readBufs := make([]batchReadBuffer, batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, len(buf))
	}
	for {
		n, err := batcher.ReadBatch(ctx, blastReadPoll, readBufs)
		if err != nil {
			if ctx.Err() != nil {
				return TransferStats{}, ctx.Err()
			}
			if isNetTimeout(err) {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return TransferStats{}, err
			}
			continue
		}
		for i := 0; i < n; i++ {
			addr := readBufs[i].Addr
			if peer != nil && !sameAddr(addr, peer) {
				continue
			}
			packetType, payload, packetRunID, ok := decodeBlastPacketWithAEAD(readBufs[i].Bytes[:readBufs[i].N], packetAEAD)
			if !ok || packetRunID != runID {
				continue
			}
			switch packetType {
			case PacketTypeHello:
				if err := sendHelloAck(ctx, conn, addr, runID, 0, 1); err != nil {
					return TransferStats{}, err
				}
			case PacketTypeData:
				if stats.FirstByteAt.IsZero() && len(payload) > 0 {
					stats.FirstByteAt = time.Now()
				}
				written, err := writeBlastPayload(dst, payload)
				if err != nil {
					return TransferStats{}, err
				}
				if written != len(payload) {
					return TransferStats{}, io.ErrShortWrite
				}
				stats.BytesReceived += int64(written)
				stats.observePeakGoodput(time.Now(), stats.BytesReceived)
			case PacketTypeDone:
				if err := sendRepairComplete(ctx, batcher, addr, runID); err != nil {
					return TransferStats{}, err
				}
				stats.markComplete(time.Now())
				return *stats, nil
			}
		}
	}
}

func receiveBlastDataUDP(ctx context.Context, conn *net.UDPConn, peer net.Addr, runID [16]byte, dst io.Writer, stats *TransferStats, buf []byte, packetAEAD cipher.AEAD) (TransferStats, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return TransferStats{}, err
		}
		defer conn.SetReadDeadline(time.Time{})
	} else {
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = conn.SetReadDeadline(time.Now())
			case <-done:
			}
		}()
		defer close(done)
	}
	for {
		n, addrPort, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return TransferStats{}, ctx.Err()
			}
			if isNetTimeout(err) {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return TransferStats{}, err
			}
			continue
		}
		if !udpAddrPortMatchesPeer(addrPort, peer) {
			continue
		}
		packetType, payload, packetRunID, ok := decodeBlastPacketWithAEAD(buf[:n], packetAEAD)
		if !ok || packetRunID != runID {
			continue
		}
		switch packetType {
		case PacketTypeHello:
			if err := sendHelloAck(ctx, conn, net.UDPAddrFromAddrPort(addrPort), runID, 0, 1); err != nil {
				return TransferStats{}, err
			}
		case PacketTypeData:
			if stats.FirstByteAt.IsZero() && len(payload) > 0 {
				stats.FirstByteAt = time.Now()
			}
			written, err := writeBlastPayload(dst, payload)
			if err != nil {
				return TransferStats{}, err
			}
			if written != len(payload) {
				return TransferStats{}, io.ErrShortWrite
			}
			stats.BytesReceived += int64(written)
			stats.observePeakGoodput(time.Now(), stats.BytesReceived)
		case PacketTypeDone:
			if err := sendRepairComplete(ctx, newLegacyBatcher(conn), net.UDPAddrFromAddrPort(addrPort), runID); err != nil {
				return TransferStats{}, err
			}
			stats.markComplete(time.Now())
			return *stats, nil
		}
	}
}

func ReceiveBlastParallelToWriter(ctx context.Context, conns []net.PacketConn, dst io.Writer, cfg ReceiveConfig, expectedBytes int64) (TransferStats, error) {
	if len(conns) == 0 {
		return TransferStats{}, errors.New("no packet conns")
	}
	if dst == nil {
		dst = io.Discard
	}
	startedAt := time.Now()
	done := make(chan struct{})
	errCh := make(chan error, len(conns))
	var doneOnce sync.Once
	var wg sync.WaitGroup
	var bytesReceived atomic.Int64
	var donePackets atomic.Int32
	var lastPacketAt atomic.Int64
	var writeMu sync.Mutex
	firstByteAt := time.Time{}
	var firstByteOnce sync.Once
	var connected atomic.Bool
	var repairActive atomic.Bool
	var incompleteDoneRuns atomic.Int32
	doneTarget := int32(len(conns))
	var terminalGraceOnce sync.Once
	var terminalGraceActive atomic.Bool
	var repairGraceOnce sync.Once
	var repairGraceExpired atomic.Bool
	var repairGraceDeadline atomic.Int64
	var repairGraceExpectedBytes atomic.Int64
	var peakMu sync.Mutex
	var peak intervalStats
	peak.minWindow = blastRateFeedbackInterval
	peak.Observe(startedAt, 0)
	if expectedBytes > 0 {
		repairGraceExpectedBytes.Store(expectedBytes)
	}
	observeRepairGraceExpectedBytes := func(totalBytes uint64) {
		if totalBytes == 0 {
			return
		}
		next := blastRepairSafeExpectedBytes(totalBytes)
		for {
			current := repairGraceExpectedBytes.Load()
			if next <= current {
				return
			}
			if repairGraceExpectedBytes.CompareAndSwap(current, next) {
				return
			}
		}
	}
	repairGrace := func() time.Duration {
		return parallelBlastRepairGraceForExpectedBytes(repairGraceExpectedBytes.Load())
	}
	peakMbps := func() float64 {
		peakMu.Lock()
		defer peakMu.Unlock()
		return peak.PeakMbps()
	}
	closeDone := func() {
		doneOnce.Do(func() {
			close(done)
			for _, conn := range conns {
				_ = conn.SetReadDeadline(time.Now())
			}
		})
	}
	startTerminalGrace := func() {
		terminalGraceOnce.Do(func() {
			terminalGraceActive.Store(true)
			go func() {
				timer := time.NewTimer(parallelBlastDoneGrace)
				defer timer.Stop()
				select {
				case <-timer.C:
					closeDone()
				case <-done:
				}
			}()
		})
	}
	startRepairGrace := func() {
		repairActive.Store(true)
		repairGraceDeadline.Store(time.Now().Add(repairGrace()).UnixNano())
		repairGraceOnce.Do(func() {
			go func() {
				ticker := time.NewTicker(blastRepairInterval)
				defer ticker.Stop()
				select {
				case <-done:
					return
				default:
				}
				for {
					select {
					case <-ticker.C:
						deadline := repairGraceDeadline.Load()
						if !repairActive.Load() || deadline <= 0 {
							continue
						}
						if time.Now().UnixNano() >= deadline {
							repairGraceExpired.Store(true)
							closeDone()
							return
						}
					case <-done:
						return
					}
				}
			}()
		})
	}
	currentStats := func(completedAt time.Time) TransferStats {
		received := bytesReceived.Load()
		firstByte := firstByteAt
		if firstByte.IsZero() && received > 0 {
			firstByte = completedAt
		}
		transport := PreviewTransportCaps(conns[0], cfg.Transport)
		if connected.Load() {
			transport.Connected = true
		}
		out := TransferStats{
			BytesReceived:   received,
			StartedAt:       startedAt,
			FirstByteAt:     firstByte,
			CompletedAt:     completedAt,
			PeakGoodputMbps: peakMbps(),
			Transport:       transport,
		}
		out.markComplete(completedAt)
		return out
	}
	go func() {
		select {
		case <-ctx.Done():
			closeDone()
		case <-done:
		}
	}()
	go func() {
		ticker := time.NewTicker(parallelBlastDataIdle / 4)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if cfg.RequireComplete {
					continue
				}
				if bytesReceived.Load() <= 0 {
					continue
				}
				if terminalGraceActive.Load() {
					continue
				}
				if repairActive.Load() {
					continue
				}
				last := lastPacketAt.Load()
				if last > 0 && time.Since(time.Unix(0, last)) >= parallelBlastDataIdle {
					closeDone()
					return
				}
			case <-done:
				return
			}
		}
	}()
	for _, conn := range conns {
		wg.Add(1)
		go func(conn net.PacketConn) {
			defer wg.Done()
			if err := receiveBlastParallelConn(ctx, conn, dst, cfg, expectedBytes, doneTarget, &bytesReceived, &donePackets, &incompleteDoneRuns, &lastPacketAt, &writeMu, &firstByteOnce, &firstByteAt, &connected, &repairActive, done, closeDone, startTerminalGrace, startRepairGrace, observeRepairGraceExpectedBytes, func(now time.Time, totalBytes int64) {
				peakMu.Lock()
				peak.Observe(now, totalBytes)
				peakMu.Unlock()
			}); err != nil {
				select {
				case errCh <- err:
				default:
				}
				closeDone()
			}
		}(conn)
	}
	wg.Wait()
	select {
	case err := <-errCh:
		received := bytesReceived.Load()
		if expectedBytes > 0 && received < expectedBytes && (ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return currentStats(time.Now()), fmt.Errorf("blast incomplete: received %d bytes, want %d", received, expectedBytes)
		}
		return currentStats(time.Now()), err
	default:
	}
	if repairGraceExpired.Load() && incompleteDoneRuns.Load() > 0 {
		return currentStats(time.Now()), fmt.Errorf("blast incomplete: received %d bytes before repair grace expired", bytesReceived.Load())
	}
	received := bytesReceived.Load()
	sessionTracef("parallel recv return expected=%d received=%d ctx_err=%v repair_expired=%t incomplete_done_runs=%d", expectedBytes, received, ctx.Err(), repairGraceExpired.Load(), incompleteDoneRuns.Load())
	if cfg.RequireComplete && expectedBytes > 0 && received < expectedBytes {
		return currentStats(time.Now()), fmt.Errorf("blast incomplete: received %d bytes, want %d", received, expectedBytes)
	}
	if expectedBytes > 0 && received < expectedBytes && (received == 0 || ctx.Err() != nil) {
		return currentStats(time.Now()), fmt.Errorf("blast incomplete: received %d bytes, want %d", received, expectedBytes)
	}
	return currentStats(time.Now()), nil
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
	if now.IsZero() {
		now = time.Now()
	}
	if !force {
		if last := c.lastStatsAt[runID]; !last.IsZero() && now.Sub(last) < blastRateFeedbackInterval {
			return
		}
	}
	c.lastStatsAt[runID] = now
	stats := blastReceiverStats{
		ReceivedPayloadBytes: c.rateFeedbackPayloadBytesLocked(state),
		ReceivedPackets:      state.seen.Len(),
		MaxSeqPlusOne:        state.maxSeqPlusOne,
		AckFloor:             state.nextWriteSeq,
	}
	for _, lane := range c.lanes {
		if lane == nil || lane.batcher == nil || lane.peer == nil {
			continue
		}
		sendBlastStatsBestEffort(ctx, lane.batcher, lane.peer, runID, stats)
	}
}

func (c *blastStreamReceiveCoordinator) sendStripedStatsFeedbackLocked(ctx context.Context, runID [16]byte, state *blastReceiveRunState, now time.Time, force bool) {
	if c == nil || state == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	if !force {
		if last := c.lastStatsAt[runID]; !last.IsZero() && now.Sub(last) < blastRateFeedbackInterval {
			return
		}
	}
	c.lastStatsAt[runID] = now
	aggregateStats := blastReceiverStats{
		ReceivedPayloadBytes: c.rateFeedbackPayloadBytesLocked(state),
	}
	for _, stripe := range state.stripes {
		if stripe == nil {
			continue
		}
		aggregateStats.ReceivedPackets += stripe.seen.Len()
		aggregateStats.MaxSeqPlusOne += stripe.maxSeqPlusOne
	}
	for stripeID, stripe := range state.stripes {
		if stripe == nil || stripe.lane == nil || stripe.lane.batcher == nil || stripe.lane.peer == nil {
			continue
		}
		stats := aggregateStats
		stats.AckFloor = stripe.expectedSeq
		sendBlastStatsBestEffortStripe(ctx, stripe.lane.batcher, stripe.lane.peer, runID, stripeID, stats)
	}
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
		if len(payload) == 0 {
			return false, nil
		}
		state := c.runState(runID, addr)
		if !state.acceptData(seq) {
			return false, nil
		}
		if c.firstByteAt.IsZero() {
			c.firstByteAt = time.Now()
		}
		state.feedbackBytes += uint64(len(payload))
		c.feedbackBytes += int64(len(payload))
		state.storeFECPayload(c.cfg.FECGroupSize, seq, payload)
		written, err := c.writeGlobalPayloadLocked(state, seq, offset, payload)
		if err != nil {
			return false, err
		}
		c.bytesReceived += int64(written)
		c.observePeak(time.Now(), c.feedbackBytes)
		c.sendStatsFeedbackLocked(ctx, runID, state, time.Now(), false)
		if err := c.recoverFEC(ctx, runID, state); err != nil {
			return false, err
		}
		complete, err := c.completeRun(ctx, runID, state)
		if err != nil {
			return false, err
		}
		if complete || (c.expectedBytes > 0 && c.bytesReceived >= c.expectedBytes && state.done) {
			return true, nil
		}
	case PacketTypeParity:
		if c.cfg.FECGroupSize <= 1 {
			return false, nil
		}
		state := c.runState(runID, addr)
		state.storeFECParity(seq, offset, count, payload)
		if err := c.recoverFEC(ctx, runID, state); err != nil {
			return false, err
		}
	case PacketTypeDone:
		state := c.runState(runID, addr)
		state.markDoneWithTotalBytes(seq, offset, addr)
		if err := c.recoverFEC(ctx, runID, state); err != nil {
			return false, err
		}
		complete, err := c.completeRun(ctx, runID, state)
		if err != nil {
			return false, err
		}
		if complete {
			return true, nil
		}
		c.sendStatsFeedbackLocked(ctx, runID, state, time.Now(), true)
		c.repairDeadline = time.Now().Add(c.repairGraceForState(state))
		if err := c.requestMissingRepairs(ctx, runID, state); err != nil {
			return false, err
		}
	}
	return false, nil
}

func (c *blastStreamReceiveCoordinator) handleStripedPacketLocked(ctx context.Context, lane *blastStreamReceiveLane, stripeID uint16, totalStripes int, packetType PacketType, runID [16]byte, seq uint64, offset uint64, count uint64, payload []byte, addr net.Addr) (bool, error) {
	state := c.runState(runID, addr)
	state.enableStriped(totalStripes)
	stripe := state.stripeState(stripeID, lane, addr)
	switch packetType {
	case PacketTypeHello:
		return false, nil
	case PacketTypeData:
		if len(payload) == 0 {
			return false, nil
		}
		if c.firstByteAt.IsZero() {
			c.firstByteAt = time.Now()
		}
		packet := Packet{
			Version:  ProtocolVersion,
			Type:     PacketTypeData,
			StripeID: stripeID,
			RunID:    runID,
			Seq:      seq,
			Offset:   offset,
			Payload:  payload,
		}
		return c.handleStripedDataOrDoneLocked(ctx, runID, state, stripe, packet)
	case PacketTypeDone:
		packet := Packet{
			Version:  ProtocolVersion,
			Type:     PacketTypeDone,
			StripeID: stripeID,
			RunID:    runID,
			Seq:      seq,
			Offset:   offset,
		}
		complete, err := c.handleStripedDataOrDoneLocked(ctx, runID, state, stripe, packet)
		if err != nil || complete {
			return complete, err
		}
		c.repairDeadline = time.Now().Add(c.repairGraceForState(state))
		if err := c.requestMissingStripedRepairs(ctx, runID, state); err != nil {
			return false, err
		}
		return false, nil
	case PacketTypeParity:
		if c.cfg.FECGroupSize <= 1 || count == 0 || len(payload) == 0 {
			return false, nil
		}
		stripe.storeFECParity(seq, offset, count, payload)
		if err := c.recoverStripedFEC(ctx, runID, state); err != nil {
			return false, err
		}
		return c.stripedCompleteLocked(state), nil
	default:
		return false, nil
	}
}

func (c *blastStreamReceiveCoordinator) handleStripedDataOrDoneLocked(ctx context.Context, runID [16]byte, state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, packet Packet) (bool, error) {
	if state == nil || stripe == nil {
		return false, nil
	}
	if packet.Type == PacketTypeDone {
		stripe.terminalSeen = true
		if packet.Seq > stripe.totalPackets {
			stripe.totalPackets = packet.Seq
		}
	}
	if packet.Seq < stripe.expectedSeq || stripe.seen.Has(packet.Seq) {
		return c.stripedCompleteLocked(state), nil
	}
	if packet.Seq > stripe.expectedSeq {
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
	if !stripe.seen.Add(packet.Seq) {
		return c.stripedCompleteLocked(state), nil
	}
	if packet.Seq+1 > stripe.maxSeqPlusOne {
		stripe.maxSeqPlusOne = packet.Seq + 1
	}
	if packet.Type == PacketTypeData {
		stripe.storeFECPayload(c.cfg.FECGroupSize, packet.Seq, packet.Payload)
	}
	if err := c.acceptStripedSequentialPacketLocked(state, stripe, packet); err != nil {
		return false, err
	}
	for {
		buffered, ok, err := c.popStripedBufferedPacketLocked(state, stripe)
		if err != nil {
			return false, err
		}
		if !ok {
			break
		}
		if err := c.acceptStripedSequentialPacketLocked(state, stripe, buffered); err != nil {
			return false, err
		}
	}
	if err := c.recoverStripedFEC(ctx, runID, state); err != nil {
		return false, err
	}
	if state.completedStripes == state.totalStripes {
		state.done = true
	}
	if c.stripedCompleteLocked(state) {
		if err := c.flushStripedPayloadLocked(state); err != nil {
			return false, err
		}
		if err := sendBlastStreamRepairCompleteAll(ctx, c.lanes, runID); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func (c *blastStreamReceiveCoordinator) acceptStripedSequentialPacketLocked(state *blastReceiveRunState, stripe *blastStreamReceiveStripeState, packet Packet) error {
	switch packet.Type {
	case PacketTypeData:
		if len(packet.Payload) > 0 {
			if stripe == nil || !stripe.feedbackCounted.Has(packet.Seq) {
				c.countStripedPayloadFeedbackLocked(state, packet.Payload)
			}
			if c.dst == io.Discard {
				c.bytesReceived += int64(len(packet.Payload))
			} else if packet.Offset == state.nextOffset {
				if err := c.writeStripedPayloadLocked(state, packet.Payload); err != nil {
					return err
				}
				if err := c.flushStripedPendingPayloadsLocked(state); err != nil {
					return err
				}
			} else if packet.Offset > state.nextOffset {
				if err := c.storeStripedPendingOutputLocked(state, packet.Offset, packet.Payload); err != nil {
					return err
				}
			}
		}
		stripe.expectedSeq++
	case PacketTypeDone:
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
		if err := c.validateFinalTotalLocked("striped blast", state.finalTotal); err != nil {
			return err
		}
		stripe.expectedSeq++
	}
	return nil
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
		if !stripe.seen.Add(packet.Seq) {
			return nil
		}
		if packet.Seq+1 > stripe.maxSeqPlusOne {
			stripe.maxSeqPlusOne = packet.Seq + 1
		}
		stripe.storeBufferedPacket(packet)
		return nil
	}
	if state.canBufferStripedFuturePayload(len(packet.Payload)) {
		if !stripe.seen.Add(packet.Seq) {
			return nil
		}
		if packet.Seq+1 > stripe.maxSeqPlusOne {
			stripe.maxSeqPlusOne = packet.Seq + 1
		}
		stripe.feedbackCounted.Add(packet.Seq)
		c.countStripedPayloadFeedbackLocked(state, packet.Payload)
		stripe.storeBufferedPacket(packet)
		state.stripedFutureBufferedBytes += uint64(len(packet.Payload))
		return nil
	}
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
	if !stripe.seen.Add(packet.Seq) {
		return nil
	}
	if packet.Seq+1 > stripe.maxSeqPlusOne {
		stripe.maxSeqPlusOne = packet.Seq + 1
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
	if state.pendingOutput == nil {
		state.pendingOutput = make(map[uint64][]byte)
	}
	if _, exists := state.pendingOutput[offset]; exists {
		return nil
	}
	if state.pendingOutputSpoolLens != nil {
		if _, exists := state.pendingOutputSpoolLens[offset]; exists {
			return nil
		}
	}
	if state.pendingOutputBytes+uint64(len(payload)) <= stripedBlastPendingOutputLimitBytes {
		state.pendingOutput[offset] = append([]byte(nil), payload...)
		state.pendingOutputBytes += uint64(len(payload))
		return nil
	}
	if offset > uint64(maxInt()) {
		return errors.New("striped pending output offset exceeds spool range")
	}
	spool, err := state.ensureStripedPayloadSpool()
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
	if state.pendingOutputSpoolLens == nil {
		state.pendingOutputSpoolLens = make(map[uint64]int)
	}
	state.pendingOutputSpoolLens[offset] = len(payload)
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
		if state != nil && state.striped {
			if c.stripedCompleteLocked(state) {
				continue
			}
			if state.finalTotalSet {
				if c.repairDeadline.IsZero() {
					c.repairDeadline = now.Add(c.repairGraceForState(state))
				}
				if now.After(c.repairDeadline) {
					return fmt.Errorf("striped blast incomplete: received %d bytes before repair grace expired", c.bytesReceived)
				}
				if err := c.requestFinalTotalStripedRepairs(ctx, runID, state, now); err != nil {
					return err
				}
				continue
			}
			if !state.done {
				continue
			}
			if c.repairDeadline.IsZero() {
				c.repairDeadline = now.Add(c.repairGraceForState(state))
			}
			if now.After(c.repairDeadline) {
				return fmt.Errorf("striped blast incomplete: received %d bytes before repair grace expired", c.bytesReceived)
			}
			if err := c.requestMissingStripedRepairs(ctx, runID, state); err != nil {
				return err
			}
			continue
		}
		if state == nil || !state.done || state.complete() {
			continue
		}
		if c.repairDeadline.IsZero() {
			c.repairDeadline = now.Add(c.repairGraceForState(state))
		}
		if now.After(c.repairDeadline) {
			return fmt.Errorf("blast incomplete: received %d bytes before repair grace expired", c.bytesReceived)
		}
		if err := c.requestMissingRepairs(ctx, runID, state); err != nil {
			return err
		}
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
	chunkSize := state.stripedChunk
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}
	for stripeID, stripe := range state.stripes {
		if stripe == nil || stripe.done {
			continue
		}
		if !stripe.lastRepairRequestAt.IsZero() && now.Sub(stripe.lastRepairRequestAt) < blastRepairInterval {
			continue
		}
		expectedDataPackets := stripedDataPacketsForStripe(state.finalTotal, chunkSize, state.totalStripes, stripeID)
		var missing []uint64
		if stripe.expectedSeq < expectedDataPackets {
			missing = stripe.missingSeqsBefore(expectedDataPackets, maxRepairRequestSeqs)
		} else if c.stripedPayloadCompleteLocked(state) {
			missing = []uint64{stripe.expectedSeq}
		}
		if len(missing) == 0 {
			continue
		}
		stripe.lastRepairRequestAt = now
		if err := sendBlastStreamRepairRequestStripe(ctx, stripe, runID, stripeID, missing); err != nil {
			return err
		}
	}
	return nil
}

func (c *blastStreamReceiveCoordinator) requestKnownRepairs(ctx context.Context, now time.Time) error {
	if c.cfg.DeferKnownGapRepairs {
		return nil
	}
	for runID, state := range c.runs {
		if state != nil && state.striped {
			if err := c.requestKnownStripedRepairs(ctx, runID, state, now); err != nil {
				return err
			}
			continue
		}
		if state == nil || state.done {
			continue
		}
		if !state.lastRepairRequestAt.IsZero() && now.Sub(state.lastRepairRequestAt) < blastRepairInterval {
			continue
		}
		if !state.hasKnownMissingSeqs() {
			state.gapFirstObservedAt = time.Time{}
			continue
		}
		if state.gapFirstObservedAt.IsZero() {
			state.gapFirstObservedAt = now
			continue
		}
		if now.Sub(state.gapFirstObservedAt) < blastKnownGapRepairDelay {
			continue
		}
		batches := state.knownMissingSeqBatches(maxRepairRequestSeqs, maxRepairRequestBatches)
		if len(batches) == 0 {
			state.gapFirstObservedAt = time.Time{}
			continue
		}
		state.lastRepairRequestAt = now
		for _, missing := range batches {
			if err := sendBlastStreamRepairRequestAll(ctx, c.lanes, runID, missing); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *blastStreamReceiveCoordinator) requestKnownStripedRepairs(ctx context.Context, runID [16]byte, state *blastReceiveRunState, now time.Time) error {
	if state == nil || c.stripedCompleteLocked(state) {
		return nil
	}
	for stripeID, stripe := range state.stripes {
		if stripe == nil || stripe.done {
			continue
		}
		if !stripe.lastRepairRequestAt.IsZero() && now.Sub(stripe.lastRepairRequestAt) < blastRepairInterval {
			continue
		}
		if !stripe.hasKnownMissingSeqs() {
			stripe.gapFirstObservedAt = time.Time{}
			continue
		}
		if stripe.gapFirstObservedAt.IsZero() {
			stripe.gapFirstObservedAt = now
			continue
		}
		if now.Sub(stripe.gapFirstObservedAt) < stripedBlastKnownGapRepairDelay {
			continue
		}
		missing := stripe.knownMissingSeqs(maxRepairRequestSeqs)
		if len(missing) == 0 {
			stripe.gapFirstObservedAt = time.Time{}
			continue
		}
		stripe.lastRepairRequestAt = now
		if err := sendBlastStreamRepairRequestStripe(ctx, stripe, runID, stripeID, missing); err != nil {
			return err
		}
	}
	return nil
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
		if err := sendBlastStreamRepairRequestStripe(ctx, stripe, runID, stripeID, missing); err != nil {
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
	if state == nil || c.cfg.FECGroupSize <= 1 {
		return nil
	}
	for {
		recovered := state.recoverFEC(c.expectedBytes)
		if len(recovered) == 0 {
			return nil
		}
		for _, packet := range recovered {
			if !state.acceptData(packet.seq) {
				continue
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
		}
		if _, err := c.completeRun(ctx, runID, state); err != nil {
			return err
		}
	}
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
		type recoveredStripedPacket struct {
			stripe *blastStreamReceiveStripeState
			packet Packet
		}
		knownTotalBytes := uint64(0)
		if state.finalTotalSet {
			knownTotalBytes = state.finalTotal
		} else if c.expectedBytes > 0 {
			knownTotalBytes = uint64(c.expectedBytes)
		}
		chunkSize := state.stripedChunk
		if chunkSize <= 0 {
			chunkSize = defaultChunkSize
		}
		recovered := make([]recoveredStripedPacket, 0, 1)
		for stripeID, stripe := range state.stripes {
			if stripe == nil {
				continue
			}
			for _, packet := range stripe.recoverFEC(c.cfg.FECGroupSize, chunkSize, state.totalStripes, knownTotalBytes) {
				recovered = append(recovered, recoveredStripedPacket{
					stripe: stripe,
					packet: Packet{
						Version:  ProtocolVersion,
						Type:     PacketTypeData,
						StripeID: stripeID,
						RunID:    runID,
						Seq:      packet.seq,
						Offset:   packet.offset,
						Payload:  packet.payload,
					},
				})
			}
		}
		if len(recovered) == 0 {
			return nil
		}
		for _, item := range recovered {
			if _, err := c.handleStripedDataOrDoneLocked(ctx, runID, state, item.stripe, item.packet); err != nil {
				return err
			}
		}
	}
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

	lanes := make([]*blastStreamReceiveLane, len(conns))
	var connected atomic.Bool
	var receiveComplete atomic.Bool
	var wg sync.WaitGroup
	errCh := make(chan error, len(conns)+1)
	for i, conn := range conns {
		if conn == nil {
			return TransferStats{}, fmt.Errorf("nil packet conn at lane %d", i)
		}
		sessionTracef("stream receive lane start lane=%d local=%s run=%x", i, conn.LocalAddr(), cfg.ExpectedRunID[:4])
		lanes[i] = &blastStreamReceiveLane{conn: conn, batcher: newPacketBatcher(conn, cfg.Transport)}
	}
	coordinator := newBlastStreamReceiveCoordinator(receiveCtx, lanes, dst, cfg, expectedBytes, startedAt)
	for i, lane := range lanes {
		wg.Add(1)
		go func(i int, lane *blastStreamReceiveLane) {
			defer wg.Done()
			if err := readBlastStreamReceiveLaneDirect(receiveCtx, i, lane, cfg, coordinator, &connected, &receiveComplete, cancel); err != nil {
				if blastStreamReceiveCompletionCanceled(err, ctx, &receiveComplete) {
					return
				}
				select {
				case errCh <- err:
				default:
				}
				cancel()
			}
		}(i, lane)
	}
	defer coordinator.Close()
	defer wg.Wait()

	repairTicker := time.NewTicker(blastRepairInterval)
	defer repairTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return TransferStats{}, ctx.Err()
		case now := <-repairTicker.C:
			if err := coordinator.handleRepairTick(receiveCtx, now); err != nil {
				if blastStreamReceiveCompletionCanceled(err, ctx, &receiveComplete) {
					return coordinator.stats(conns, connected.Load()), nil
				}
				return TransferStats{}, err
			}
		case err := <-errCh:
			if err != nil {
				if blastStreamReceiveCompletionCanceled(err, ctx, &receiveComplete) {
					return coordinator.stats(conns, connected.Load()), nil
				}
				return TransferStats{}, err
			}
		case <-receiveCtx.Done():
			if ctx.Err() != nil {
				return TransferStats{}, ctx.Err()
			}
			if !receiveComplete.Load() {
				select {
				case err := <-errCh:
					if err != nil {
						return TransferStats{}, err
					}
				default:
				}
				return TransferStats{}, receiveCtx.Err()
			}
			return coordinator.stats(conns, connected.Load()), nil
		}
	}
}

func blastStreamReceiveCompletionCanceled(err error, parent context.Context, receiveComplete *atomic.Bool) bool {
	if err == nil || parent == nil || receiveComplete == nil {
		return false
	}
	return errors.Is(err, context.Canceled) && parent.Err() == nil && receiveComplete.Load()
}

func readBlastStreamReceiveLaneDirect(ctx context.Context, laneIndex int, lane *blastStreamReceiveLane, cfg ReceiveConfig, coordinator *blastStreamReceiveCoordinator, connected *atomic.Bool, receiveComplete *atomic.Bool, cancel context.CancelFunc) error {
	if lane == nil || lane.batcher == nil {
		return nil
	}
	readBufs := make([]batchReadBuffer, lane.batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, 64<<10)
	}
	for {
		n, err := lane.batcher.ReadBatch(ctx, blastReadPoll, readBufs)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isNetTimeout(err) {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			continue
		}
		for i := 0; i < n; i++ {
			packetType, payload, runID, seq, offset, ok := decodeBlastPacketFullWithAEAD(readBufs[i].Bytes[:readBufs[i].N], cfg.PacketAEAD)
			if !ok || !receiveConfigAllowsRunID(cfg, runID) {
				continue
			}
			stripeID := binary.BigEndian.Uint16(readBufs[i].Bytes[2:4])
			totalStripes := 1
			if packetType == PacketTypeHello && seq > 0 && seq <= uint64(maxParallelStripes) {
				totalStripes = int(seq)
			}
			addr := readBufs[i].Addr
			if packetType == PacketTypeHello {
				if lane.batcher.MaxBatch() == 1 && !lane.batcher.Capabilities().Connected {
					if connectedBatcher, ok := newConnectedUDPBatcher(lane.conn, addr, cfg.Transport); ok {
						lane.batcher = connectedBatcher
						if connected != nil {
							connected.Store(true)
						}
					}
				}
				lane.peer = cloneAddr(addr)
				if err := sendHelloAckBatch(ctx, lane.batcher, addr, runID, stripeID, uint16(totalStripes)); err != nil {
					return err
				}
			}
			groupCount := uint64(0)
			if packetType == PacketTypeParity && readBufs[i].N >= headerLen {
				groupCount = binary.BigEndian.Uint64(readBufs[i].Bytes[36:44])
			}
			complete, err := coordinator.handlePacketStripe(ctx, lane, stripeID, totalStripes, packetType, runID, seq, offset, groupCount, payload, addr)
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
			_ = laneIndex
		}
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

func sendBlastStreamRepairRequestStripe(ctx context.Context, stripe *blastStreamReceiveStripeState, runID [16]byte, stripeID uint16, missing []uint64) error {
	if len(missing) == 0 || stripe == nil || stripe.lane == nil || stripe.lane.batcher == nil || stripe.lane.peer == nil {
		return nil
	}
	return sendRepairRequestStripe(ctx, stripe.lane.batcher, stripe.lane.peer, runID, stripeID, missing)
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

	type result struct {
		stats TransferStats
		err   error
	}
	results := make(chan result, len(conns))
	var wg sync.WaitGroup
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		wg.Add(1)
		go func(conn net.PacketConn) {
			defer wg.Done()
			stats, err := ReceiveToWriter(recvCtx, conn, "", receiverDst, cfg)
			if err != nil {
				cancel()
			}
			results <- result{stats: stats, err: err}
		}(conn)
	}
	wg.Wait()
	close(results)

	out := TransferStats{
		StartedAt:       startedAt,
		PeakGoodputMbps: receiverDst.PeakMbps(),
	}
	var receiveErr error
	for result := range results {
		receiveErr = preferInformativeResultError(receiveErr, result.err)
		out.BytesReceived += result.stats.BytesReceived
		out.PacketsSent += result.stats.PacketsSent
		out.PacketsAcked += result.stats.PacketsAcked
		out.Retransmits += result.stats.Retransmits
		if !result.stats.FirstByteAt.IsZero() && (out.FirstByteAt.IsZero() || result.stats.FirstByteAt.Before(out.FirstByteAt)) {
			out.FirstByteAt = result.stats.FirstByteAt
		}
		if out.Transport.Kind == "" {
			out.Transport = result.stats.Transport
		}
	}
	if receiveErr != nil {
		return TransferStats{}, receiveErr
	}
	if expectedBytes > 0 && out.BytesReceived != expectedBytes {
		return TransferStats{}, fmt.Errorf("parallel reliable received %d bytes, want %d", out.BytesReceived, expectedBytes)
	}
	out.markComplete(time.Now())
	return out, nil
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
	if s.nextOffset != 0 || s.finalTotalSet || s.completedStripes != 0 || s.pendingOutputBytes != 0 || s.stripedFutureBufferedBytes != 0 {
		return true
	}
	if len(s.pendingOutput) > 0 || len(s.pendingOutputSpoolLens) > 0 {
		return true
	}
	for _, stripe := range s.stripes {
		if stripe == nil {
			continue
		}
		if stripe.seen.Len() > 0 || stripe.expectedSeq != 0 || stripe.maxSeqPlusOne != 0 || stripe.done || stripe.terminalSeen || stripe.totalPackets != 0 {
			return true
		}
		if len(stripe.buffered) > 0 || len(stripe.bufferedSpool) > 0 {
			return true
		}
	}
	return false
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
	if s == nil || !s.done || batchSize <= 0 {
		return nil
	}
	if batchSize <= 0 || maxBatches <= 0 {
		return nil
	}
	if s.totalPackets == 0 {
		return nil
	}
	start := s.nextRepairSeq
	if start >= s.totalPackets {
		start = 0
	}
	batches := make([][]uint64, 0, maxBatches)
	current := make([]uint64, 0, batchSize)
	maxSeqs := batchSize * maxBatches
	var last uint64
	found := false
	for checked := uint64(0); checked < s.totalPackets && len(batches) < maxBatches; checked++ {
		seq := (start + checked) % s.totalPackets
		if !s.seen.Has(seq) {
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
	}
	if len(current) > 0 && len(batches) < maxBatches {
		batches = append(batches, current)
	}
	if found {
		s.nextRepairSeq = (last + 1) % s.totalPackets
	}
	return batches
}

func (s *blastReceiveRunState) knownMissingSeqBatches(batchSize int, maxBatches int) [][]uint64 {
	if s == nil || batchSize <= 0 || s.maxSeqPlusOne <= s.nextWriteSeq {
		return nil
	}
	if batchSize <= 0 || maxBatches <= 0 {
		return nil
	}
	span := s.maxSeqPlusOne - s.nextWriteSeq
	start := s.nextRepairSeq
	if start < s.nextWriteSeq || start >= s.maxSeqPlusOne {
		start = s.nextWriteSeq
	}
	batches := make([][]uint64, 0, maxBatches)
	current := make([]uint64, 0, batchSize)
	maxSeqs := batchSize * maxBatches
	var last uint64
	found := false
	for checked := uint64(0); checked < span && len(batches) < maxBatches; checked++ {
		seq := s.nextWriteSeq + ((start - s.nextWriteSeq + checked) % span)
		if !s.seen.Has(seq) {
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
	}
	if len(current) > 0 && len(batches) < maxBatches {
		batches = append(batches, current)
	}
	if found {
		s.nextRepairSeq = last + 1
	}
	return batches
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
	out := make([]uint64, 0, limit)
	start := s.nextRepairSeq
	if start >= s.totalPackets {
		start = 0
	}
	var last uint64
	for checked := uint64(0); checked < s.totalPackets && len(out) < limit; checked++ {
		seq := (start + checked) % s.totalPackets
		if !s.seen.Has(seq) {
			out = append(out, seq)
			last = seq
		}
	}
	if len(out) > 0 {
		s.nextRepairSeq = (last + 1) % s.totalPackets
	}
	return out
}

func (s *blastStreamReceiveStripeState) missingSeqsBefore(endSeq uint64, limit int) []uint64 {
	if s == nil || limit <= 0 || endSeq <= s.expectedSeq {
		return nil
	}
	out := make([]uint64, 0, limit)
	span := endSeq - s.expectedSeq
	start := s.nextRepairSeq
	if start < s.expectedSeq || start >= endSeq {
		start = s.expectedSeq
	}
	var last uint64
	for checked := uint64(0); checked < span && len(out) < limit; checked++ {
		seq := s.expectedSeq + ((start - s.expectedSeq + checked) % span)
		if !s.seen.Has(seq) {
			out = append(out, seq)
			last = seq
		}
	}
	if len(out) > 0 {
		s.nextRepairSeq = last + 1
	}
	return out
}

func (s *blastStreamReceiveStripeState) knownMissingSeqs(limit int) []uint64 {
	if s == nil || limit <= 0 || s.maxSeqPlusOne <= s.expectedSeq {
		return nil
	}
	out := make([]uint64, 0, limit)
	span := s.maxSeqPlusOne - s.expectedSeq
	start := s.nextRepairSeq
	if start < s.expectedSeq || start >= s.maxSeqPlusOne {
		start = s.expectedSeq
	}
	var last uint64
	for checked := uint64(0); checked < span && len(out) < limit; checked++ {
		seq := s.expectedSeq + ((start - s.expectedSeq + checked) % span)
		if !s.seen.Has(seq) {
			out = append(out, seq)
			last = seq
		}
	}
	if len(out) > 0 {
		s.nextRepairSeq = last + 1
	}
	return out
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
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}
	if totalStripes <= 0 {
		totalStripes = 1
	}
	recovered := make([]blastRecoveredPacket, 0, 1)
	for startSeq, parity := range s.fecParity {
		if knownTotalBytes == 0 && parity.startSeq+parity.count >= s.maxSeqPlusOne {
			// Sender-side parity is padded to the chunk size, so avoid guessing
			// the current leading edge length until later data or DONE prove it.
			continue
		}
		var missingSeq uint64
		missing := 0
		canRecover := true
		for seq := parity.startSeq; seq < parity.startSeq+parity.count; seq++ {
			if s.seen.Has(seq) {
				continue
			}
			missing++
			missingSeq = seq
			if missing > 1 {
				canRecover = false
				break
			}
		}
		if !canRecover || missing != 1 {
			if missing == 0 {
				s.cleanupFECGroupIfComplete(parity.startSeq, parity.count)
			}
			continue
		}
		group := s.fecGroups[startSeq]
		if group == nil || len(group.xor) == 0 {
			continue
		}
		payload := append([]byte(nil), parity.payload...)
		for i := range group.xor {
			payload[i] ^= group.xor[i]
		}
		offset := stripedFECOffsetForSeq(parity.offset, parity.startSeq, missingSeq, chunkSize, totalStripes)
		if knownTotalBytes > 0 && offset >= knownTotalBytes {
			delete(s.fecParity, startSeq)
			continue
		}
		if knownTotalBytes > offset && knownTotalBytes-offset < uint64(len(payload)) {
			payload = payload[:int(knownTotalBytes-offset)]
		}
		recovered = append(recovered, blastRecoveredPacket{seq: missingSeq, offset: offset, payload: payload})
		delete(s.fecParity, startSeq)
	}
	return recovered
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
	count := (globalPackets / cyclePackets) * blockPackets
	remaining := globalPackets % cyclePackets
	stripeStart := uint64(stripeID) * blockPackets
	if remaining <= stripeStart {
		return count
	}
	stripeRemaining := remaining - stripeStart
	if stripeRemaining > blockPackets {
		stripeRemaining = blockPackets
	}
	return count + stripeRemaining
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

func (s *blastReceiveRunState) recoverFEC(expectedBytes int64) []blastRecoveredPacket {
	if s == nil || len(s.fecParity) == 0 {
		return nil
	}
	knownTotalBytes := uint64(0)
	if s.done {
		knownTotalBytes = s.totalBytes
	} else if expectedBytes > 0 {
		knownTotalBytes = uint64(expectedBytes)
	}
	recovered := make([]blastRecoveredPacket, 0, 1)
	for startSeq, parity := range s.fecParity {
		if knownTotalBytes == 0 && parity.startSeq+parity.count >= s.maxSeqPlusOne {
			// The sender pads parity to chunk size, so recovering the stream's
			// leading edge is unsafe until later data or DONE prove its length.
			continue
		}
		var missingSeq uint64
		missing := 0
		canRecover := true
		for seq := parity.startSeq; seq < parity.startSeq+parity.count; seq++ {
			if s.seen.Has(seq) {
				continue
			}
			missing++
			missingSeq = seq
			if missing > 1 {
				canRecover = false
				break
			}
		}
		if !canRecover || missing != 1 {
			if missing == 0 {
				s.cleanupFECGroupIfComplete(parity.startSeq, parity.count)
			}
			continue
		}
		group := s.fecGroups[startSeq]
		if group == nil || len(group.xor) == 0 {
			continue
		}
		payload := append([]byte(nil), parity.payload...)
		for i := range group.xor {
			payload[i] ^= group.xor[i]
		}
		offset := parity.offset + (missingSeq-parity.startSeq)*uint64(len(parity.payload))
		if knownTotalBytes > 0 && offset >= knownTotalBytes {
			delete(s.fecParity, startSeq)
			continue
		}
		if knownTotalBytes > offset && knownTotalBytes-offset < uint64(len(payload)) {
			payload = payload[:int(knownTotalBytes-offset)]
		}
		recovered = append(recovered, blastRecoveredPacket{seq: missingSeq, offset: offset, payload: payload})
		delete(s.fecParity, startSeq)
	}
	return recovered
}

func receiveBlastParallelConn(ctx context.Context, conn net.PacketConn, dst io.Writer, cfg ReceiveConfig, expectedBytes int64, doneTarget int32, bytesReceived *atomic.Int64, donePackets *atomic.Int32, incompleteDoneRuns *atomic.Int32, lastPacketAt *atomic.Int64, writeMu *sync.Mutex, firstByteOnce *sync.Once, firstByteAt *time.Time, connected *atomic.Bool, repairActive *atomic.Bool, done <-chan struct{}, closeDone func(), startTerminalGrace func(), startRepairGrace func(), observeRepairGraceExpectedBytes func(uint64), observePeak func(time.Time, int64)) error {
	traceEnabled := sessionTraceEnabled()
	tracePacketsEnabled := sessionPacketTraceEnabled()
	batcher := newPacketBatcher(conn, cfg.Transport)
	readBufs := make([]batchReadBuffer, batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, 64<<10)
	}
	seenDoneRuns := make(map[[16]byte]bool)
	runs := make(map[[16]byte]*blastReceiveRunState)
	lastStatsAt := make(map[[16]byte]time.Time)
	var feedbackBytes atomic.Int64
	runState := func(runID [16]byte, addr net.Addr) *blastReceiveRunState {
		state := runs[runID]
		if state == nil {
			state = newBlastReceiveRunState(addr)
			runs[runID] = state
		}
		if state.addr == nil && addr != nil {
			state.addr = cloneAddr(addr)
		}
		return state
	}
	sendStatsFeedback := func(runID [16]byte, state *blastReceiveRunState, now time.Time, force bool) {
		if state == nil || state.addr == nil {
			return
		}
		if now.IsZero() {
			now = time.Now()
		}
		if !force {
			if last := lastStatsAt[runID]; !last.IsZero() && now.Sub(last) < blastRateFeedbackInterval {
				return
			}
		}
		lastStatsAt[runID] = now
		sendBlastStatsBestEffort(ctx, batcher, state.addr, runID, blastReceiverStats{
			ReceivedPayloadBytes: state.feedbackBytes,
			ReceivedPackets:      state.seen.Len(),
			MaxSeqPlusOne:        state.maxSeqPlusOne,
			AckFloor:             state.nextWriteSeq,
		})
	}
	sendStatsFeedbackForAll := func(now time.Time) {
		for runID, state := range runs {
			sendStatsFeedback(runID, state, now, true)
		}
	}
	requestRepairs := func() error {
		for runID, state := range runs {
			if state == nil || !state.repairPending {
				continue
			}
			if err := sendRepairRequestBatches(ctx, batcher, state.addr, runID, 0, state.missingSeqBatches(maxRepairRequestSeqs, maxRepairRequestBatches)); err != nil {
				return err
			}
		}
		return nil
	}
	requestKnownRepairs := func(runID [16]byte, state *blastReceiveRunState, now time.Time) error {
		if state == nil || !cfg.RequireComplete {
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
		batches := state.knownMissingSeqBatches(maxRepairRequestSeqs, maxRepairRequestBatches)
		if len(batches) == 0 {
			state.gapFirstObservedAt = time.Time{}
			return nil
		}
		state.lastRepairRequestAt = now
		if repairActive != nil {
			repairActive.Store(true)
		}
		return sendRepairRequestBatches(ctx, batcher, state.addr, runID, 0, batches)
	}
	requestKnownRepairsForAll := func(now time.Time) error {
		for runID, state := range runs {
			if err := requestKnownRepairs(runID, state, now); err != nil {
				return err
			}
		}
		return nil
	}
	fastIncompleteDoneError := func() error {
		if cfg.RequireComplete || expectedBytes > 0 {
			return nil
		}
		for _, state := range runs {
			if state == nil || !state.done || state.totalBytes == 0 || state.doneAt.IsZero() {
				continue
			}
			received := state.receivedBytes
			if received >= state.totalBytes {
				continue
			}
			if time.Since(state.doneAt) >= parallelBlastDataIdle {
				return fmt.Errorf("blast incomplete: received %d bytes, want %d", received, state.totalBytes)
			}
		}
		return nil
	}
	fastMode := func() bool {
		return expectedBytes <= 0 && !cfg.RequireComplete
	}
	markDoneRun := func(runID [16]byte) {
		if donePackets == nil || seenDoneRuns[runID] {
			return
		}
		seenDoneRuns[runID] = true
		donePackets.Add(1)
	}
	fastAllDone := func() bool {
		return donePackets == nil || doneTarget <= 1 || donePackets.Load() >= doneTarget
	}
	maybeFinishFastRun := func(runID [16]byte, state *blastReceiveRunState) (bool, error) {
		if state == nil || !state.done {
			return false, nil
		}
		if state.totalBytes > 0 && state.receivedBytes < state.totalBytes {
			return false, nil
		}
		if state.repairPending {
			state.repairPending = false
			if incompleteDoneRuns != nil {
				incompleteDoneRuns.Add(-1)
			}
		}
		if err := sendRepairComplete(ctx, batcher, state.addr, runID); err != nil {
			return false, err
		}
		markDoneRun(runID)
		if repairActive != nil && incompleteDoneRuns != nil && incompleteDoneRuns.Load() == 0 {
			repairActive.Store(false)
		}
		if !fastAllDone() {
			return false, nil
		}
		closeDone()
		return true, nil
	}
	maybeFinishRun := func(runID [16]byte, state *blastReceiveRunState) error {
		if state == nil || !state.complete() {
			return nil
		}
		if cfg.RequireComplete {
			if err := flushOrderedParallelBlastPayload(dst, state, writeMu); err != nil {
				return err
			}
		}
		if state.repairPending {
			state.repairPending = false
			if incompleteDoneRuns != nil {
				incompleteDoneRuns.Add(-1)
			}
		}
		if err := sendRepairComplete(ctx, batcher, state.addr, runID); err != nil {
			return err
		}
		if repairActive != nil && incompleteDoneRuns != nil && incompleteDoneRuns.Load() == 0 {
			repairActive.Store(false)
		}
		if expectedBytes > 0 && bytesReceived.Load() >= expectedBytes {
			closeDone()
			return nil
		}
		if expectedBytes <= 0 && cfg.RequireComplete && state.done && bytesReceived.Load() >= int64(state.totalBytes) {
			closeDone()
			return nil
		}
		if donePackets != nil && incompleteDoneRuns != nil && donePackets.Load() >= doneTarget && incompleteDoneRuns.Load() == 0 && startTerminalGrace != nil {
			startTerminalGrace()
		}
		return nil
	}
	recoverFEC := func(runID [16]byte, state *blastReceiveRunState) error {
		if state == nil || !cfg.RequireComplete || cfg.FECGroupSize <= 1 {
			return nil
		}
		for {
			recovered := state.recoverFEC(expectedBytes)
			if len(recovered) == 0 {
				return nil
			}
			for _, packet := range recovered {
				if !state.acceptData(packet.seq) {
					continue
				}
				state.storeFECPayload(cfg.FECGroupSize, packet.seq, packet.payload)
				written, err := writeOrderedParallelBlastPayload(dst, state, packet.seq, packet.payload, writeMu)
				if err != nil {
					return err
				}
				received := bytesReceived.Add(int64(written))
				if expectedBytes > 0 && received >= expectedBytes {
					if err := flushOrderedParallelBlastPayload(dst, state, writeMu); err != nil {
						return err
					}
					if err := sendRepairComplete(ctx, batcher, state.addr, runID); err != nil {
						return err
					}
					closeDone()
					return nil
				}
			}
			if err := maybeFinishRun(runID, state); err != nil {
				return err
			}
		}
	}
	for {
		select {
		case <-done:
			return nil
		default:
		}
		n, err := batcher.ReadBatch(ctx, blastReadPoll, readBufs)
		if err != nil {
			select {
			case <-done:
				return nil
			default:
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if isNetTimeout(err) {
				sendStatsFeedbackForAll(time.Now())
				if err := fastIncompleteDoneError(); err != nil {
					return err
				}
				if err := requestRepairs(); err != nil {
					return err
				}
				if err := requestKnownRepairsForAll(time.Now()); err != nil {
					return err
				}
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			continue
		}
		for i := 0; i < n; i++ {
			packetType, payload, runID, seq, offset, ok := decodeBlastPacketFullWithAEAD(readBufs[i].Bytes[:readBufs[i].N], cfg.PacketAEAD)
			if !ok {
				continue
			}
			if !receiveConfigAllowsRunID(cfg, runID) {
				continue
			}
			stripeID := binary.BigEndian.Uint16(readBufs[i].Bytes[2:4])
			totalStripes := uint16(1)
			if packetType == PacketTypeHello && seq > 0 && seq <= uint64(maxParallelStripes) {
				totalStripes = uint16(seq)
			}
			now := time.Now()
			if lastPacketAt != nil {
				lastPacketAt.Store(now.UnixNano())
			}
			addr := readBufs[i].Addr
			switch packetType {
			case PacketTypeHello:
				if traceEnabled {
					sessionTracef("parallel recv hello local=%s from=%s run=%x", conn.LocalAddr(), addr, runID[:4])
				}
				if batcher.MaxBatch() == 1 && !batcher.Capabilities().Connected {
					if connectedBatcher, ok := newConnectedUDPBatcher(conn, addr, cfg.Transport); ok {
						batcher = connectedBatcher
						if connected != nil {
							connected.Store(true)
						}
					}
				}
				if err := sendHelloAckBatch(ctx, batcher, addr, runID, stripeID, totalStripes); err != nil {
					return err
				}
				runState(runID, addr)
			case PacketTypeData:
				if len(payload) == 0 {
					continue
				}
				state := runState(runID, addr)
				if !state.acceptData(seq) {
					continue
				}
				state.feedbackBytes += uint64(len(payload))
				totalFeedback := feedbackBytes.Add(int64(len(payload)))
				if tracePacketsEnabled {
					sessionTracef("parallel recv data local=%s from=%s bytes=%d run=%x", conn.LocalAddr(), addr, len(payload), runID[:4])
				}
				firstByteOnce.Do(func() {
					*firstByteAt = now
				})
				var written int
				var err error
				if cfg.RequireComplete {
					state.storeFECPayload(cfg.FECGroupSize, seq, payload)
					written, err = writeOrderedParallelBlastPayload(dst, state, seq, payload, writeMu)
				} else {
					written, err = writeParallelBlastPayload(dst, payload, writeMu)
				}
				if err != nil {
					return err
				}
				if !cfg.RequireComplete && written != len(payload) {
					return io.ErrShortWrite
				}
				if written > 0 {
					state.receivedBytes += uint64(written)
				}
				totalReceived := bytesReceived.Add(int64(written))
				if cfg.RequireComplete {
					if err := recoverFEC(runID, state); err != nil {
						return err
					}
				}
				if cfg.RequireComplete && state.done && state.repairPending && !state.complete() {
					startRepairGrace()
				}
				if observePeak != nil {
					observePeak(now, totalFeedback)
				}
				if fastMode() && state.done && state.totalBytes > 0 && state.receivedBytes >= state.totalBytes {
					done, err := maybeFinishFastRun(runID, state)
					if err != nil {
						return err
					}
					if done {
						return nil
					}
				}
				if expectedBytes > 0 && totalReceived >= expectedBytes {
					if cfg.RequireComplete {
						if err := recoverFEC(runID, state); err != nil {
							return err
						}
						if err := flushOrderedParallelBlastPayload(dst, state, writeMu); err != nil {
							return err
						}
					}
					if err := sendRepairComplete(ctx, batcher, state.addr, runID); err != nil {
						return err
					}
					if err := maybeFinishRun(runID, state); err != nil {
						return err
					}
					closeDone()
					return nil
				}
				if err := maybeFinishRun(runID, state); err != nil {
					return err
				}
				sendStatsFeedback(runID, state, now, false)
				if err := requestKnownRepairs(runID, state, now); err != nil {
					return err
				}
			case PacketTypeParity:
				if cfg.FECGroupSize <= 1 {
					continue
				}
				state := runState(runID, addr)
				groupCount := binary.BigEndian.Uint64(readBufs[i].Bytes[36:44])
				state.storeFECParity(seq, offset, groupCount, payload)
				if err := recoverFEC(runID, state); err != nil {
					return err
				}
				if cfg.RequireComplete && state.done && state.repairPending && !state.complete() {
					startRepairGrace()
				}
			case PacketTypeDone:
				state := runState(runID, addr)
				state.markDoneWithTotalBytes(seq, offset, addr)
				if observeRepairGraceExpectedBytes != nil {
					observeRepairGraceExpectedBytes(state.totalBytes)
				}
				sendStatsFeedback(runID, state, now, true)
				if err := recoverFEC(runID, state); err != nil {
					return err
				}
				if fastMode() || donePackets == nil {
					if !cfg.RequireComplete && offset > 0 && state.receivedBytes < offset {
						state.doneAt = now
						if !state.repairPending {
							state.repairPending = true
							if incompleteDoneRuns != nil {
								incompleteDoneRuns.Add(1)
							}
							if startRepairGrace != nil {
								startRepairGrace()
							} else if repairActive != nil {
								repairActive.Store(true)
							}
						}
						if err := requestRepairs(); err != nil {
							return err
						}
						continue
					}
					done, err := maybeFinishFastRun(runID, state)
					if err != nil {
						return err
					}
					if done {
						return nil
					}
					continue
				}
				if !seenDoneRuns[runID] {
					seenDoneRuns[runID] = true
					donePackets.Add(1)
				}
				if state.complete() {
					if err := maybeFinishRun(runID, state); err != nil {
						return err
					}
					continue
				}
				if !state.repairPending {
					state.repairPending = true
					if incompleteDoneRuns != nil {
						incompleteDoneRuns.Add(1)
					}
					if startRepairGrace != nil {
						startRepairGrace()
					}
				}
				if err := requestRepairs(); err != nil {
					return err
				}
				if donePackets.Load() >= doneTarget && incompleteDoneRuns != nil && incompleteDoneRuns.Load() == 0 && startTerminalGrace != nil {
					startTerminalGrace()
				}
			}
		}
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
		if state.pending == nil {
			state.pending = make(map[uint64][]byte)
		}
		state.pending[seq] = append([]byte(nil), payload...)
		return 0, nil
	}
	if seq < state.nextWriteSeq {
		return 0, nil
	}
	if dst == io.Discard {
		total := len(payload)
		state.nextWriteSeq++
		for {
			next, ok := state.pending[state.nextWriteSeq]
			if !ok {
				return total, nil
			}
			total += len(next)
			delete(state.pending, state.nextWriteSeq)
			state.nextWriteSeq++
		}
	}

	writeMu.Lock()
	defer writeMu.Unlock()
	if err := bufferOrderedParallelBlastPayload(dst, state, payload); err != nil {
		return 0, err
	}
	total := len(payload)
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
	fmt.Fprintf(os.Stderr, "probe-session-trace: "+format+"\n", args...)
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
	hello, err := MarshalPacket(Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeHello,
		StripeID: stripeID,
		RunID:    runID,
		Seq:      uint64(totalStripes),
	}, nil)
	if err != nil {
		return 0, err
	}

	buf := make([]byte, 64<<10)
	for {
		sentAt := time.Now()
		if _, err := writeWithContext(ctx, conn, peer, hello); err != nil {
			return 0, err
		}
		stats.PacketsSent++

		if err := setReadDeadline(ctx, conn, defaultRetryInterval); err != nil {
			return 0, err
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			if isNetTimeout(err) {
				continue
			}
			return 0, err
		}
		if !sameAddr(addr, peer) {
			continue
		}
		packet, err := UnmarshalPacket(buf[:n], nil)
		if err != nil {
			continue
		}
		if packet.Type != PacketTypeHelloAck || packet.RunID != runID || packet.StripeID != stripeID {
			continue
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return 0, err
		}
		sessionTracef("hello ack local=%s peer=%s from=%s run=%x", conn.LocalAddr(), peer, addr, runID[:4])
		return sessionRetryInterval(time.Since(sentAt)), nil
	}
}

func performHelloHandshakeBatch(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, stripeID uint16, totalStripes uint16, stats *TransferStats) (time.Duration, error) {
	if batcher == nil {
		return 0, errors.New("nil hello batcher")
	}
	hello, err := MarshalPacket(Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeHello,
		StripeID: stripeID,
		RunID:    runID,
		Seq:      uint64(totalStripes),
	}, nil)
	if err != nil {
		return 0, err
	}

	readBufs := make([]batchReadBuffer, batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, 64<<10)
	}
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
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			if isNetTimeout(err) {
				continue
			}
			return 0, err
		}
		for i := 0; i < n; i++ {
			if readBufs[i].Addr != nil && peer != nil && !sameAddr(readBufs[i].Addr, peer) {
				continue
			}
			packet, err := UnmarshalPacket(readBufs[i].Bytes[:readBufs[i].N], nil)
			if err != nil {
				continue
			}
			if packet.Type != PacketTypeHelloAck || packet.RunID != runID || packet.StripeID != stripeID {
				continue
			}
			sessionTracef("hello ack peer=%s run=%x stripe=%d total=%d", peer, runID[:4], stripeID, totalStripes)
			return sessionRetryInterval(time.Since(sentAt)), nil
		}
	}
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
	var pending []*outboundPacket
	for sendWindowHasCapacity(state) && !state.doneQueued {
		packet, err := nextOutboundPacket(state)
		if err != nil {
			return err
		}
		if packet == nil {
			break
		}
		state.inFlight[packet.seq] = packet
		pending = append(pending, packet)
	}
	if len(pending) == 0 {
		return nil
	}
	wires := make([][]byte, len(pending))
	for i, packet := range pending {
		wires[i] = packet.wire
	}
	if _, err := batcher.WriteBatch(ctx, peer, wires); err != nil {
		return err
	}
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
	if state.doneQueued {
		return nil, nil
	}
	if state.pendingErr != nil {
		return nil, nil
	}
	if state.eof {
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

	buf := make([]byte, state.chunkSize)
	n, readErr := state.src.Read(buf)
	if n > 0 {
		payload := append([]byte(nil), buf[:n]...)
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
			payload:    n,
		}
		state.nextSeq++
		state.offset += uint64(n)
		state.zeroReads = 0
		if errors.Is(readErr, io.EOF) {
			state.eof = true
		} else if readErr != nil {
			state.pendingErr = readErr
		}
		return packet, nil
	}
	if errors.Is(readErr, io.EOF) {
		state.eof = true
		return nextOutboundPacket(state)
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
		switch packet.Type {
		case PacketTypeData:
			if stats != nil && stats.FirstByteAt.IsZero() && len(packet.Payload) > 0 {
				stats.FirstByteAt = time.Now()
			}
			n, err := dst.Write(packet.Payload)
			if err != nil {
				return expectedSeq, false, err
			}
			if n != len(packet.Payload) {
				return expectedSeq, false, io.ErrShortWrite
			}
			if stats != nil {
				stats.BytesReceived += int64(n)
				stats.observePeakGoodput(time.Now(), stats.BytesReceived)
			}
			expectedSeq++
		case PacketTypeDone:
			return expectedSeq + 1, true, nil
		default:
			return expectedSeq, false, nil
		}
	}
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
	for bit := 0; bit < maxAckMaskBits; bit++ {
		if ackMask&(uint64(1)<<bit) == 0 {
			continue
		}
		seq := ackFloor + uint64(bit) + 1
		if seq >= nextSeq {
			return false
		}
	}
	for byteIndex, b := range ackPayload {
		if b == 0 {
			continue
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
	if a == nil || b == nil {
		return a == b
	}
	ua, aok := a.(*net.UDPAddr)
	ub, bok := b.(*net.UDPAddr)
	if aok && bok {
		if ua.Port != ub.Port || ua.Zone != ub.Zone {
			return false
		}
		return ua.IP.Equal(ub.IP)
	}
	return a.String() == b.String()
}

func lingerTerminalAcks(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, expectedSeq uint64) error {
	lingerDeadline := time.Now().Add(terminalAckLinger)
	buf := make([]byte, 64<<10)
	for {
		if time.Now().After(lingerDeadline) {
			return nil
		}
		if err := setReadDeadlineAbsolute(ctx, conn, lingerDeadline); err != nil {
			return err
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isNetTimeout(err) {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !sameAddr(addr, peer) {
			continue
		}
		packet, err := UnmarshalPacket(buf[:n], nil)
		if err != nil {
			continue
		}
		if packet.RunID != runID {
			continue
		}
		switch packet.Type {
		case PacketTypeHello:
			if err := sendHelloAck(ctx, conn, addr, runID, packet.StripeID, 1); err != nil {
				return err
			}
		case PacketTypeData, PacketTypeDone:
			if err := sendAck(ctx, conn, addr, runID, packet.StripeID, expectedSeq, 0, nil); err != nil {
				return err
			}
		}
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
		deadline, err := writeDeadline(ctx)
		if err != nil {
			return 0, err
		}
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return 0, err
		}
		n, writeErr := conn.WriteTo(packet, peer)
		clearErr := conn.SetWriteDeadline(time.Time{})
		if writeErr == nil {
			if clearErr != nil {
				return n, clearErr
			}
			return n, nil
		}
		if !isNoBufferSpace(writeErr) {
			return n, writeErr
		}
		if clearErr != nil {
			return n, clearErr
		}
		if err := sleepWithContext(ctx, 250*time.Microsecond); err != nil {
			return n, err
		}
	}
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
