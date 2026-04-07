package probe

import (
	"bytes"
	"context"
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
	defaultChunkSize                = 1400
	defaultWindowSize               = 4096
	defaultRetryInterval            = 20 * time.Millisecond
	minRetryInterval                = 50 * time.Millisecond
	maxRetryInterval                = 250 * time.Millisecond
	terminalAckLinger               = 3 * defaultRetryInterval
	terminalDoneGrace               = 500 * time.Millisecond
	terminalDoneAttempts            = 4
	delayedAckInterval              = 1 * time.Millisecond
	delayedAckPackets               = 16
	blastReceiveWriteBuffer         = 4 << 20
	zeroReadRetryDelay              = 1 * time.Millisecond
	blastDoneLinger                 = 5 * defaultRetryInterval
	blastDoneInterval               = defaultRetryInterval
	parallelBlastDoneGrace          = 10 * blastDoneLinger
	parallelBlastRepairGrace        = 3 * time.Second
	blastRepairQuietGrace           = 500 * time.Millisecond
	blastRepairResendInterval       = 2 * blastRepairInterval
	blastKnownGapRepairDelay        = 10 * time.Millisecond
	stripedBlastKnownGapRepairDelay = 250 * time.Millisecond
	parallelBlastDataIdle           = 500 * time.Millisecond
	blastReadPoll                   = 250 * time.Millisecond
	blastRepairInterval             = defaultRetryInterval
	blastRepairMemorySlab           = 4 << 20
	parallelBlastStripeBlockPackets = 128
	maxRepairRequestSeqs            = 128
	maxAckMaskBits                  = 64
	extendedAckBits                 = 4096
	extendedAckBytes                = extendedAckBits / 8
	maxBufferedPackets              = 4096
	defaultSocketBuffer             = 8 << 20
)

type SendConfig struct {
	Raw                      bool
	Blast                    bool
	Transport                string
	ChunkSize                int
	WindowSize               int
	Parallel                 int
	RateMbps                 int
	RunID                    [16]byte
	RepairPayloads           bool
	TailReplayBytes          int
	FECGroupSize             int
	StripedBlast             bool
	AllowPartialParallel     bool
	ParallelHandshakeTimeout time.Duration
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
}

type TransferStats struct {
	BytesSent     int64
	BytesReceived int64
	PacketsSent   int64
	PacketsAcked  int64
	Retransmits   int64
	Lanes         int
	StartedAt     time.Time
	CompletedAt   time.Time
	FirstByteAt   time.Time
	Transport     TransportCaps
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
		if batcher.MaxBatch() == 1 {
			if connectedBatcher, ok := newConnectedUDPBatcher(conn, peer, cfg.Transport); ok {
				batcher = connectedBatcher
			}
		}
		return sendBlast(ctx, batcher, conn, peer, state.runID, src, cfg.ChunkSize, cfg.RateMbps, cfg.RepairPayloads, cfg.TailReplayBytes, cfg.FECGroupSize, stats)
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
			stats.CompletedAt = time.Now()
			return stats, nil
		}
		if state.doneQueued && donePacketSettled(state.inFlight) {
			stats.CompletedAt = time.Now()
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
					return receiveBlastData(ctx, conn, cloneAddr(addr), runID, dst, &stats, buf)
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
					stats.CompletedAt = time.Now()
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
					stats.CompletedAt = time.Now()
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
					stats.CompletedAt = time.Now()
					if err := lingerTerminalAcks(ctx, conn, addr, runID, expectedSeq); err != nil {
						return TransferStats{}, err
					}
					return stats, nil
				}
			}
		}
	}
}

func sendBlast(ctx context.Context, batcher packetBatcher, conn net.PacketConn, peer net.Addr, runID [16]byte, src io.Reader, chunkSize int, rateMbps int, repairPayloads bool, tailReplayBytes int, fecGroupSize int, stats TransferStats) (TransferStats, error) {
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}
	if batcher == nil {
		batcher = newPacketBatcher(conn, stats.Transport.RequestedKind)
	}
	stats.Transport = batcher.Capabilities()
	_ = setSocketPacing(conn, rateMbps)
	buildBatchLimit := batcher.MaxBatch()
	if buildBatchLimit < 128 {
		buildBatchLimit = 128
	}
	batchLimit := pacedBatchLimit(buildBatchLimit, chunkSize, rateMbps)
	wireBatch := make([][]byte, batchLimit)
	packetBatch := make([][]byte, 0, batchLimit)
	readBatch := make([]byte, batchLimit*chunkSize)
	for i := range wireBatch {
		wireBatch[i] = make([]byte, headerLen+chunkSize)
	}
	history, err := newBlastRepairHistory(runID, chunkSize, repairPayloads || tailReplayBytes > 0)
	if err != nil {
		return TransferStats{}, err
	}
	defer history.Close()
	fec := newBlastFECGroup(runID, chunkSize, fecGroupSize)
	var seq uint64
	var offset uint64
	startedAt := time.Now()
	for {
		packetBatch = packetBatch[:0]
		wireIndex := 0
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
				if repairPayloads {
					var err error
					wire, err = history.packetBuffer(seq, offset, payloadLen)
					if err != nil {
						return TransferStats{}, err
					}
					payloadBuf = wire[headerLen:]
				} else {
					wire = wireBatch[wireIndex]
					wireIndex++
					payloadBuf = wire[headerLen : headerLen+payloadLen]
					encodePacketHeader(wire[:headerLen], PacketTypeData, runID, 0, seq, offset, 0, 0)
				}
				copy(payloadBuf, remaining[:payloadLen])
				if !repairPayloads {
					if err := history.Record(seq, payloadBuf); err != nil {
						return TransferStats{}, err
					}
				}
				packet := wire[:headerLen+payloadLen]
				packetBatch = append(packetBatch, packet)
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
			if err := writeBlastBatch(ctx, batcher, peer, packetBatch); err != nil {
				return TransferStats{}, err
			}
			if err := paceBlastSend(ctx, startedAt, offset, rateMbps); err != nil {
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
	}
	return serveBlastRepairs(ctx, batcher, peer, runID, history, stats)
}

type blastParallelSendLane struct {
	conn       net.PacketConn
	peer       net.Addr
	batcher    packetBatcher
	batchLimit int
	ch         chan []byte
	stripeID   uint16
	nextSeq    uint64
	history    *blastRepairHistory
	deduper    *blastRepairDeduper
}

func SendBlastParallel(ctx context.Context, conns []net.PacketConn, remoteAddrs []string, src io.Reader, cfg SendConfig) (TransferStats, error) {
	if len(conns) == 0 {
		return TransferStats{}, errors.New("no packet conns")
	}
	if len(conns) != len(remoteAddrs) {
		return TransferStats{}, fmt.Errorf("packet conn count %d does not match remote addr count %d", len(conns), len(remoteAddrs))
	}
	if len(conns) == 1 {
		return Send(ctx, conns[0], remoteAddrs[0], src, cfg)
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
		_, err = performHelloHandshake(handshakeCtx, conn, peer, runID, handshakeStripeID, handshakeTotalStripes, &stats)
		if cancelHandshake != nil {
			cancelHandshake()
		}
		if err != nil {
			if cfg.AllowPartialParallel {
				skippedHandshakeErr = err
				continue
			}
			return TransferStats{}, err
		}
		if batcher.MaxBatch() == 1 {
			if connectedBatcher, ok := newConnectedUDPBatcher(conn, peer, cfg.Transport); ok {
				batcher = connectedBatcher
				if len(lanes) == 0 {
					stats.Transport = batcher.Capabilities()
				}
			}
		}
		lanes = append(lanes, &blastParallelSendLane{
			conn:     conn,
			peer:     peer,
			batcher:  batcher,
			stripeID: uint16(i),
		})
	}
	if len(lanes) == 0 {
		if skippedHandshakeErr != nil {
			return TransferStats{}, skippedHandshakeErr
		}
		return TransferStats{}, errors.New("no parallel blast lanes completed handshake")
	}
	stats.Lanes = len(lanes)
	laneRate := parallelLaneRateMbps(cfg.RateMbps, len(lanes))
	for _, lane := range lanes {
		_ = setSocketPacing(lane.conn, laneRate)
		buildBatchLimit := lane.batcher.MaxBatch()
		if buildBatchLimit < 128 {
			buildBatchLimit = 128
		}
		lane.batchLimit = pacedBatchLimit(buildBatchLimit, cfg.ChunkSize, laneRate)
		lane.ch = make(chan []byte, lane.batchLimit*2)
	}

	history, err := newBlastRepairHistory(runID, cfg.ChunkSize, cfg.RepairPayloads || cfg.TailReplayBytes > 0)
	if err != nil {
		return TransferStats{}, err
	}
	defer history.Close()
	if stripedBlast {
		for _, lane := range lanes {
			lane.history, err = newBlastRepairHistory(runID, cfg.ChunkSize, true)
			if err != nil {
				return TransferStats{}, err
			}
			defer lane.history.Close()
		}
	}
	fec := newBlastFECGroup(runID, cfg.ChunkSize, cfg.FECGroupSize)
	if stripedBlast {
		fec = nil
	}

	sendCtx, sendCancel := context.WithCancel(ctx)
	defer sendCancel()
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
	startedAt := time.Now()
	readErr := error(nil)
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
				laneIndex := int(seq % uint64(len(lanes)))
				if stripedBlast {
					laneIndex = blastParallelLaneIndexForOffset(offset, len(lanes), cfg.ChunkSize)
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
				wire, err := blastParallelDataPacket(packetHistory, runID, stripeID, packetSeq, offset, remaining[:payloadLen], cfg)
				if err != nil {
					readErr = err
					break
				}
				if err := enqueueBlastParallelPacket(sendCtx, lane, wire); err != nil {
					readErr = err
					break
				}
				stats.PacketsSent++
				stats.BytesSent += int64(payloadLen)
				if parity := fec.Record(seq, offset, wire[headerLen:]); parity != nil {
					parityLane := lanes[int(seq%uint64(len(lanes)))]
					if err := enqueueBlastParallelPacket(sendCtx, parityLane, parity); err != nil {
						readErr = err
						break
					}
					stats.PacketsSent++
				}
				seq++
				offset += uint64(payloadLen)
				remaining = remaining[payloadLen:]
			}
			if err := paceBlastSend(ctx, startedAt, offset, cfg.RateMbps); err != nil && readErr == nil {
				readErr = err
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

	if stripedBlast {
		for _, lane := range lanes {
			lane.history.MarkComplete(0, lane.nextSeq)
		}
	} else {
		history.MarkComplete(offset, seq)
		if parity := fec.Flush(); parity != nil {
			lane := lanes[int(seq%uint64(len(lanes)))]
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
	}
	return serveBlastRepairsParallel(ctx, lanes, runID, history, stats)
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

func blastParallelDataPacket(history *blastRepairHistory, runID [16]byte, stripeID uint16, seq uint64, offset uint64, payload []byte, cfg SendConfig) ([]byte, error) {
	payloadLen := len(payload)
	if payloadLen == 0 {
		return nil, errors.New("empty blast payload")
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
	case lane.ch <- packet:
		return nil
	case <-ctx.Done():
		return ctx.Err()
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
		err := writeBlastBatch(ctx, lane.batcher, lane.peer, pending)
		pending = pending[:0]
		return err
	}
	for {
		select {
		case packet, ok := <-lane.ch:
			if !ok {
				return flush()
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
		encodePacketHeader(donePacket, PacketTypeDone, runID, stripeID, doneSeq, offset, 0, 0)
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

func serveBlastRepairsParallel(ctx context.Context, lanes []*blastParallelSendLane, runID [16]byte, history *blastRepairHistory, stats TransferStats) (TransferStats, error) {
	if len(lanes) == 0 {
		stats.CompletedAt = time.Now()
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
	resetQuiet := func() {
		if !quietTimer.Stop() {
			select {
			case <-quietTimer.C:
			default:
			}
		}
		quietTimer.Reset(blastRepairQuietGrace)
	}
	deduper := newBlastRepairDeduper()
	for {
		select {
		case <-ctx.Done():
			return TransferStats{}, ctx.Err()
		case <-quietTimer.C:
			stats.CompletedAt = time.Now()
			cancel()
			return stats, nil
		case event := <-events:
			if event.err != nil {
				return TransferStats{}, event.err
			}
			switch event.typ {
			case PacketTypeRepairComplete:
				stats.CompletedAt = time.Now()
				cancel()
				return stats, nil
			case PacketTypeRepairRequest:
				resetQuiet()
				repairHistory := history
				if event.lane != nil && event.lane.history != nil && event.stripe == event.lane.stripeID {
					repairHistory = event.lane.history
				}
				if err := sendBlastRepairs(ctx, event.lane.batcher, event.lane.peer, repairHistory, event.payload, &stats, blastRepairDeduperForLane(deduper, event.lane), time.Now()); err != nil {
					return TransferStats{}, err
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
	chunkSize  int
	groupSize  int
	startSeq   uint64
	startOff   uint64
	count      int
	parity     []byte
	seenPacket bool
}

func newBlastFECGroup(runID [16]byte, chunkSize int, groupSize int) *blastFECGroup {
	if chunkSize <= 0 || groupSize <= 1 {
		return nil
	}
	return &blastFECGroup{
		runID:     runID,
		chunkSize: chunkSize,
		groupSize: groupSize,
		parity:    make([]byte, chunkSize),
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
	wire := make([]byte, headerLen+len(g.parity))
	encodePacketHeader(wire[:headerLen], PacketTypeParity, g.runID, 0, g.startSeq, g.startOff, uint64(g.count), 0)
	copy(wire[headerLen:], g.parity)
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
}

func newBlastRepairHistory(runID [16]byte, chunkSize int, retainPayloads bool) (*blastRepairHistory, error) {
	return &blastRepairHistory{runID: runID, chunkSize: chunkSize, retainPayloads: retainPayloads}, nil
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
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.chunkSize <= 0 || seq >= h.packets {
		return nil
	}
	if len(h.packetSlabs) > 0 {
		return h.packetFromBufferLocked(seq)
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
	wire := make([]byte, headerLen+payloadLen)
	encodePacketHeader(wire[:headerLen], PacketTypeData, h.runID, 0, seq, offset, 0, 0)
	if payloadLen > 0 {
		h.readPayloadAt(wire[headerLen:], offset)
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
	return headerLen + h.chunkSize
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
	h.mu.RUnlock()
	if !retainPayloads || packets == 0 {
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
		stats.CompletedAt = time.Now()
		return stats, nil
	}
	readBufs := make([]batchReadBuffer, batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, 64<<10)
	}
	quietDeadline := time.Time{}
	deduper := newBlastRepairDeduper()
	for {
		complete := history.Complete()
		if complete && quietDeadline.IsZero() {
			quietDeadline = time.Now().Add(blastRepairQuietGrace)
		}
		wait := parallelBlastDataIdle
		if complete {
			wait = time.Until(quietDeadline)
		}
		if wait > blastRepairInterval {
			wait = blastRepairInterval
		}
		if complete && wait <= 0 {
			stats.CompletedAt = time.Now()
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
				stats.CompletedAt = time.Now()
				return stats, nil
			case PacketTypeRepairRequest:
				if history.Complete() {
					quietDeadline = time.Now().Add(blastRepairQuietGrace)
				}
				if err := sendBlastRepairs(ctx, batcher, peer, history, payload, &stats, deduper, time.Now()); err != nil {
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

func sendBlastRepairs(ctx context.Context, batcher packetBatcher, peer net.Addr, history *blastRepairHistory, payload []byte, stats *TransferStats, deduper *blastRepairDeduper, now time.Time) error {
	if len(payload) < 8 {
		return nil
	}
	pending := make([][]byte, 0, batcher.MaxBatch())
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
				return err
			}
			if stats != nil {
				stats.Retransmits += int64(len(pending))
				stats.PacketsSent += int64(len(pending))
			}
			pending = pending[:0]
		}
	}
	if len(pending) == 0 {
		return nil
	}
	if err := writeBlastBatch(ctx, batcher, peer, pending); err != nil {
		return err
	}
	if stats != nil {
		stats.Retransmits += int64(len(pending))
		stats.PacketsSent += int64(len(pending))
	}
	return nil
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

func receiveBlastData(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, dst io.Writer, stats *TransferStats, buf []byte) (TransferStats, error) {
	batcher := newPacketBatcher(conn, stats.Transport.RequestedKind)
	stats.Transport = batcher.Capabilities()
	if udpConn, ok := conn.(*net.UDPConn); ok && batcher.MaxBatch() == 1 {
		return receiveBlastDataUDP(ctx, udpConn, peer, runID, dst, stats, buf)
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
			packetType, payload, packetRunID, ok := decodeBlastPacket(readBufs[i].Bytes[:readBufs[i].N])
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
			case PacketTypeDone:
				if err := sendRepairComplete(ctx, batcher, addr, runID); err != nil {
					return TransferStats{}, err
				}
				stats.CompletedAt = time.Now()
				return *stats, nil
			}
		}
	}
}

func receiveBlastDataUDP(ctx context.Context, conn *net.UDPConn, peer net.Addr, runID [16]byte, dst io.Writer, stats *TransferStats, buf []byte) (TransferStats, error) {
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
		packetType, payload, packetRunID, ok := decodeBlastPacket(buf[:n])
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
		case PacketTypeDone:
			if err := sendRepairComplete(ctx, newLegacyBatcher(conn), net.UDPAddrFromAddrPort(addrPort), runID); err != nil {
				return TransferStats{}, err
			}
			stats.CompletedAt = time.Now()
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
		repairGraceOnce.Do(func() {
			go func() {
				timer := time.NewTimer(parallelBlastRepairGrace)
				defer timer.Stop()
				select {
				case <-timer.C:
					repairGraceExpired.Store(true)
					closeDone()
				case <-done:
				}
			}()
		})
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
				if cfg.RequireComplete && expectedBytes <= 0 {
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
			if err := receiveBlastParallelConn(ctx, conn, dst, cfg, expectedBytes, doneTarget, &bytesReceived, &donePackets, &incompleteDoneRuns, &lastPacketAt, &writeMu, &firstByteOnce, &firstByteAt, &connected, &repairActive, done, closeDone, startTerminalGrace, startRepairGrace); err != nil {
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
			return TransferStats{}, fmt.Errorf("blast incomplete: received %d bytes, want %d", received, expectedBytes)
		}
		return TransferStats{}, err
	default:
	}
	if repairGraceExpired.Load() && incompleteDoneRuns.Load() > 0 {
		return TransferStats{}, fmt.Errorf("blast incomplete: received %d bytes before repair grace expired", bytesReceived.Load())
	}
	received := bytesReceived.Load()
	sessionTracef("parallel recv return expected=%d received=%d ctx_err=%v repair_expired=%t incomplete_done_runs=%d", expectedBytes, received, ctx.Err(), repairGraceExpired.Load(), incompleteDoneRuns.Load())
	if expectedBytes > 0 && received < expectedBytes && (received == 0 || ctx.Err() != nil) {
		return TransferStats{}, fmt.Errorf("blast incomplete: received %d bytes, want %d", received, expectedBytes)
	}
	completedAt := time.Now()
	if firstByteAt.IsZero() && received > 0 {
		firstByteAt = completedAt
	}
	transport := PreviewTransportCaps(conns[0], cfg.Transport)
	if connected.Load() {
		transport.Connected = true
	}
	return TransferStats{
		BytesReceived: received,
		StartedAt:     startedAt,
		FirstByteAt:   firstByteAt,
		CompletedAt:   completedAt,
		Transport:     transport,
	}, nil
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
	firstByteAt    time.Time
	repairDeadline time.Time
	writeMu        sync.Mutex
}

func newBlastStreamReceiveCoordinator(ctx context.Context, lanes []*blastStreamReceiveLane, dst io.Writer, cfg ReceiveConfig, expectedBytes int64, startedAt time.Time) *blastStreamReceiveCoordinator {
	if dst == nil {
		dst = io.Discard
	}
	cfg.RequireComplete = true
	return &blastStreamReceiveCoordinator{
		lanes:         lanes,
		dst:           dst,
		cfg:           cfg,
		expectedBytes: expectedBytes,
		startedAt:     startedAt,
		runs:          make(map[[16]byte]*blastReceiveRunState),
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
		state.storeFECPayload(c.cfg.FECGroupSize, seq, payload)
		written, err := c.writeGlobalPayloadLocked(state, seq, offset, payload)
		if err != nil {
			return false, err
		}
		c.bytesReceived += int64(written)
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
		c.repairDeadline = time.Now().Add(parallelBlastRepairGrace)
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
		c.repairDeadline = time.Now().Add(parallelBlastRepairGrace)
		if err := c.requestMissingStripedRepairs(ctx, runID, state); err != nil {
			return false, err
		}
		return false, nil
	case PacketTypeParity:
		_ = count
		return false, nil
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
	if packet.Seq < stripe.expectedSeq || !stripe.seen.Add(packet.Seq) {
		return c.stripedCompleteLocked(state), nil
	}
	if packet.Seq+1 > stripe.maxSeqPlusOne {
		stripe.maxSeqPlusOne = packet.Seq + 1
	}
	if packet.Seq > stripe.expectedSeq {
		if stripe.buffered == nil {
			stripe.buffered = make(map[uint64]Packet)
		}
		stripe.buffered[packet.Seq] = clonePacket(packet)
		return c.stripedCompleteLocked(state), nil
	}
	if err := c.acceptStripedSequentialPacketLocked(state, stripe, packet); err != nil {
		return false, err
	}
	for {
		buffered, ok := stripe.buffered[stripe.expectedSeq]
		if !ok {
			break
		}
		delete(stripe.buffered, stripe.expectedSeq)
		if err := c.acceptStripedSequentialPacketLocked(state, stripe, buffered); err != nil {
			return false, err
		}
	}
	if state.completedStripes == state.totalStripes {
		state.done = true
	}
	if c.stripedCompleteLocked(state) {
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
				if state.pendingOutput == nil {
					state.pendingOutput = make(map[uint64][]byte)
				}
				if _, exists := state.pendingOutput[packet.Offset]; !exists {
					state.pendingOutput[packet.Offset] = append([]byte(nil), packet.Payload...)
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
		stripe.expectedSeq++
	}
	return nil
}

func (c *blastStreamReceiveCoordinator) stripedCompleteLocked(state *blastReceiveRunState) bool {
	if state == nil || !state.finalTotalSet || state.totalStripes <= 0 || state.completedStripes != state.totalStripes {
		return false
	}
	if c.dst == io.Discard {
		return c.bytesReceived >= int64(state.finalTotal)
	}
	return state.nextOffset == state.finalTotal
}

func (c *blastStreamReceiveCoordinator) writeStripedPayloadLocked(state *blastReceiveRunState, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	if c.dst != io.Discard {
		c.writeMu.Lock()
		err := writeFullPayload(c.dst, payload)
		c.writeMu.Unlock()
		if err != nil {
			return err
		}
	}
	state.nextOffset += uint64(len(payload))
	c.bytesReceived += int64(len(payload))
	return nil
}

func (c *blastStreamReceiveCoordinator) flushStripedPendingPayloadsLocked(state *blastReceiveRunState) error {
	for {
		payload, ok := state.pendingOutput[state.nextOffset]
		if !ok {
			return nil
		}
		delete(state.pendingOutput, state.nextOffset)
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
	for runID, state := range c.runs {
		if state != nil && state.striped {
			if !state.done || c.stripedCompleteLocked(state) {
				continue
			}
			if c.repairDeadline.IsZero() {
				c.repairDeadline = now.Add(parallelBlastRepairGrace)
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
			c.repairDeadline = now.Add(parallelBlastRepairGrace)
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

func (c *blastStreamReceiveCoordinator) requestMissingRepairs(ctx context.Context, runID [16]byte, state *blastReceiveRunState) error {
	missing := state.missingSeqs(maxRepairRequestSeqs)
	if len(missing) == 0 {
		return nil
	}
	return sendBlastStreamRepairRequestAll(ctx, c.lanes, runID, missing)
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
		missing := state.knownMissingSeqs(maxRepairRequestSeqs)
		if len(missing) == 0 {
			state.gapFirstObservedAt = time.Time{}
			continue
		}
		state.lastRepairRequestAt = now
		if err := sendBlastStreamRepairRequestAll(ctx, c.lanes, runID, missing); err != nil {
			return err
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
	if err := c.flushGlobalPayload(state); err != nil {
		return false, err
	}
	if err := sendBlastStreamRepairCompleteAll(ctx, c.lanes, runID); err != nil {
		return false, err
	}
	return true, nil
}

func (c *blastStreamReceiveCoordinator) recoverFEC(ctx context.Context, runID [16]byte, state *blastReceiveRunState) error {
	if state == nil || c.cfg.FECGroupSize <= 1 {
		return nil
	}
	for {
		recovered := state.recoverFEC()
		if len(recovered) == 0 {
			return nil
		}
		for _, packet := range recovered {
			if !state.acceptData(packet.seq) {
				continue
			}
			state.storeFECPayload(c.cfg.FECGroupSize, packet.seq, packet.payload)
			written, err := c.writeGlobalPayloadLocked(state, packet.seq, packet.offset, packet.payload)
			if err != nil {
				return err
			}
			c.bytesReceived += int64(written)
		}
		if _, err := c.completeRun(ctx, runID, state); err != nil {
			return err
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
	return TransferStats{
		BytesReceived: c.bytesReceived,
		Lanes:         len(conns),
		StartedAt:     c.startedAt,
		FirstByteAt:   firstByteAt,
		CompletedAt:   completedAt,
		Transport:     transport,
	}
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
	var wg sync.WaitGroup
	errCh := make(chan error, len(conns)+1)
	for i, conn := range conns {
		if conn == nil {
			return TransferStats{}, fmt.Errorf("nil packet conn at lane %d", i)
		}
		lanes[i] = &blastStreamReceiveLane{conn: conn, batcher: newPacketBatcher(conn, cfg.Transport)}
	}
	coordinator := newBlastStreamReceiveCoordinator(receiveCtx, lanes, dst, cfg, expectedBytes, startedAt)
	for i, lane := range lanes {
		wg.Add(1)
		go func(i int, lane *blastStreamReceiveLane) {
			defer wg.Done()
			if err := readBlastStreamReceiveLaneDirect(receiveCtx, i, lane, cfg, coordinator, &connected, cancel); err != nil {
				select {
				case errCh <- err:
				default:
				}
				cancel()
			}
		}(i, lane)
	}
	defer wg.Wait()

	repairTicker := time.NewTicker(blastRepairInterval)
	defer repairTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return TransferStats{}, ctx.Err()
		case now := <-repairTicker.C:
			if err := coordinator.handleRepairTick(receiveCtx, now); err != nil {
				return TransferStats{}, err
			}
		case err := <-errCh:
			if err != nil {
				return TransferStats{}, err
			}
		case <-receiveCtx.Done():
			if ctx.Err() != nil {
				return TransferStats{}, ctx.Err()
			}
			return coordinator.stats(conns, connected.Load()), nil
		}
	}
}

func readBlastStreamReceiveLaneDirect(ctx context.Context, laneIndex int, lane *blastStreamReceiveLane, cfg ReceiveConfig, coordinator *blastStreamReceiveCoordinator, connected *atomic.Bool, cancel context.CancelFunc) error {
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
			packetType, payload, runID, seq, offset, ok := decodeBlastPacketFull(readBufs[i].Bytes[:readBufs[i].N])
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
				if lane.batcher.MaxBatch() == 1 {
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
	var writeMu sync.Mutex
	receiverDst := dst
	if dst != io.Discard {
		receiverDst = lockedWriter{w: dst, mu: &writeMu}
	}

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

	out := TransferStats{StartedAt: startedAt}
	for result := range results {
		if result.err != nil {
			return TransferStats{}, result.err
		}
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
	if expectedBytes > 0 && out.BytesReceived != expectedBytes {
		return TransferStats{}, fmt.Errorf("parallel reliable received %d bytes, want %d", out.BytesReceived, expectedBytes)
	}
	out.CompletedAt = time.Now()
	return out, nil
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

type blastReceiveRunState struct {
	addr                net.Addr
	seen                blastSeqSet
	pending             map[uint64][]byte
	fecGroups           map[uint64]*blastFECReceiveGroup
	fecParity           map[uint64]blastFECParity
	writeBuf            []byte
	nextWriteSeq        uint64
	maxSeqPlusOne       uint64
	done                bool
	doneAt              time.Time
	totalPackets        uint64
	totalBytes          uint64
	repairPending       bool
	nextRepairSeq       uint64
	gapFirstObservedAt  time.Time
	lastRepairRequestAt time.Time
	receivedBytes       uint64
	striped             bool
	totalStripes        int
	stripes             map[uint16]*blastStreamReceiveStripeState
	pendingOutput       map[uint64][]byte
	nextOffset          uint64
	finalTotal          uint64
	finalTotalSet       bool
	completedStripes    int
	spool               *os.File
	spoolPath           string
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
	expectedSeq         uint64
	maxSeqPlusOne       uint64
	done                bool
	terminalSeen        bool
	totalPackets        uint64
	nextRepairSeq       uint64
	gapFirstObservedAt  time.Time
	lastRepairRequestAt time.Time
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
	if totalStripes > s.totalStripes {
		s.totalStripes = totalStripes
	}
	if s.stripes == nil {
		s.stripes = make(map[uint16]*blastStreamReceiveStripeState, totalStripes)
	}
	if s.pendingOutput == nil {
		s.pendingOutput = make(map[uint64][]byte)
	}
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

func (s *blastReceiveRunState) missingSeqs(limit int) []uint64 {
	batches := s.missingSeqBatches(limit, 1)
	if len(batches) == 0 {
		return nil
	}
	return batches[0]
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

func (s *blastReceiveRunState) knownMissingSeqs(limit int) []uint64 {
	batches := s.knownMissingSeqBatches(limit, 1)
	if len(batches) == 0 {
		return nil
	}
	return batches[0]
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

func (s *blastReceiveRunState) recoverFEC() []blastRecoveredPacket {
	if s == nil || len(s.fecParity) == 0 {
		return nil
	}
	recovered := make([]blastRecoveredPacket, 0, 1)
	for startSeq, parity := range s.fecParity {
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
		if s.done && s.totalBytes > offset && s.totalBytes-offset < uint64(len(payload)) {
			payload = payload[:int(s.totalBytes-offset)]
		}
		recovered = append(recovered, blastRecoveredPacket{seq: missingSeq, offset: offset, payload: payload})
		delete(s.fecParity, startSeq)
	}
	return recovered
}

func receiveBlastParallelConn(ctx context.Context, conn net.PacketConn, dst io.Writer, cfg ReceiveConfig, expectedBytes int64, doneTarget int32, bytesReceived *atomic.Int64, donePackets *atomic.Int32, incompleteDoneRuns *atomic.Int32, lastPacketAt *atomic.Int64, writeMu *sync.Mutex, firstByteOnce *sync.Once, firstByteAt *time.Time, connected *atomic.Bool, repairActive *atomic.Bool, done <-chan struct{}, closeDone func(), startTerminalGrace func(), startRepairGrace func()) error {
	traceEnabled := sessionTraceEnabled()
	tracePacketsEnabled := sessionPacketTraceEnabled()
	batcher := newPacketBatcher(conn, cfg.Transport)
	readBufs := make([]batchReadBuffer, batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, 64<<10)
	}
	seenDoneRuns := make(map[[16]byte]bool)
	runs := make(map[[16]byte]*blastReceiveRunState)
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
	requestRepairs := func() error {
		for runID, state := range runs {
			if state == nil || !state.repairPending {
				continue
			}
			missing := state.missingSeqs(maxRepairRequestSeqs)
			if len(missing) == 0 {
				continue
			}
			if err := sendRepairRequest(ctx, batcher, state.addr, runID, missing); err != nil {
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
		missing := state.knownMissingSeqs(maxRepairRequestSeqs)
		if len(missing) == 0 {
			state.gapFirstObservedAt = time.Time{}
			return nil
		}
		state.lastRepairRequestAt = now
		if repairActive != nil {
			repairActive.Store(true)
		}
		return sendRepairRequest(ctx, batcher, state.addr, runID, missing)
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
			recovered := state.recoverFEC()
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
				bytesReceived.Add(int64(written))
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
			packetType, payload, runID, seq, offset, ok := decodeBlastPacketFull(readBufs[i].Bytes[:readBufs[i].N])
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
				if batcher.MaxBatch() == 1 {
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
				received := bytesReceived.Add(int64(written))
				if cfg.RequireComplete {
					if err := recoverFEC(runID, state); err != nil {
						return err
					}
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
				if expectedBytes > 0 && received >= expectedBytes {
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
			case PacketTypeDone:
				state := runState(runID, addr)
				state.markDoneWithTotalBytes(seq, offset, addr)
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

func writeFullPayload(dst io.Writer, payload []byte) error {
	written, err := dst.Write(payload)
	if err != nil {
		return err
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}
	return nil
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
		spool, err := os.CreateTemp("", "derpcat-blast-spool-*")
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

func sessionTracef(format string, args ...any) {
	if !sessionTraceEnabled() {
		return
	}
	fmt.Fprintf(os.Stderr, "probe-session-trace: "+format+"\n", args...)
}

func sessionTraceEnabled() bool {
	return strings.TrimSpace(os.Getenv("DERPCAT_PROBE_TRACE")) != ""
}

func sessionPacketTraceEnabled() bool {
	return strings.TrimSpace(os.Getenv("DERPCAT_PROBE_TRACE_PACKETS")) != ""
}

func decodeBlastPacket(buf []byte) (PacketType, []byte, [16]byte, bool) {
	packetType, payload, runID, _, _, ok := decodeBlastPacketFull(buf)
	return packetType, payload, runID, ok
}

func decodeBlastPacketFull(buf []byte) (PacketType, []byte, [16]byte, uint64, uint64, bool) {
	if len(buf) < headerLen || buf[0] != ProtocolVersion {
		return 0, nil, [16]byte{}, 0, 0, false
	}
	var runID [16]byte
	copy(runID[:], buf[4:20])
	seq := binary.BigEndian.Uint64(buf[20:28])
	offset := binary.BigEndian.Uint64(buf[28:36])
	return PacketType(buf[1]), buf[headerLen:], runID, seq, offset, true
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
	_, err = batcher.WriteBatch(ctx, peer, [][]byte{packet})
	return err
}

func sendRepairRequest(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, seqs []uint64) error {
	return sendRepairRequestStripe(ctx, batcher, peer, runID, 0, seqs)
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
	_, err = batcher.WriteBatch(ctx, peer, [][]byte{packet})
	return err
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
	_, err = batcher.WriteBatch(ctx, peer, [][]byte{packet})
	return err
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
	deadline, err := writeDeadline(ctx)
	if err != nil {
		return 0, err
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	n, writeErr := conn.WriteTo(packet, peer)
	clearErr := conn.SetWriteDeadline(time.Time{})
	if writeErr != nil {
		return n, writeErr
	}
	if clearErr != nil {
		return n, clearErr
	}
	return n, nil
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
