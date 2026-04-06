package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

const (
	defaultChunkSize     = 1400
	defaultWindowSize    = 4096
	defaultRetryInterval = 20 * time.Millisecond
	minRetryInterval     = 50 * time.Millisecond
	maxRetryInterval     = 250 * time.Millisecond
	terminalAckLinger    = 3 * defaultRetryInterval
	terminalDoneGrace    = 500 * time.Millisecond
	terminalDoneAttempts = 4
	delayedAckInterval   = 1 * time.Millisecond
	delayedAckPackets    = 16
	zeroReadRetryDelay   = 1 * time.Millisecond
	blastDoneLinger      = 5 * defaultRetryInterval
	blastDoneInterval    = defaultRetryInterval
	blastReadPoll        = 250 * time.Millisecond
	maxAckMaskBits       = 64
	maxBufferedPackets   = 4096
	defaultSocketBuffer  = 8 << 20
)

type SendConfig struct {
	Raw        bool
	Blast      bool
	Transport  string
	ChunkSize  int
	WindowSize int
	RunID      [16]byte
}

type ReceiveConfig struct {
	Raw           bool
	Blast         bool
	Transport     string
	ExpectedRunID [16]byte
}

type TransferStats struct {
	BytesSent     int64
	BytesReceived int64
	PacketsSent   int64
	PacketsAcked  int64
	Retransmits   int64
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

	buf := make([]byte, 64<<10)
	readBufs := make([]batchReadBuffer, batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, len(buf))
	}
	state := senderState{
		src:       src,
		chunkSize: cfg.ChunkSize,
		window:    cfg.WindowSize,
		nextSeq:   0,
		offset:    0,
		runID:     runID,
		inFlight:  make(map[uint64]*outboundPacket, cfg.WindowSize),
	}
	retryInterval, err := performHelloHandshake(ctx, conn, peer, state.runID, &stats)
	if err != nil {
		return TransferStats{}, err
	}
	if cfg.Blast {
		return sendBlast(ctx, batcher, conn, peer, state.runID, src, cfg.ChunkSize, stats)
	}

	for {
		if err := fillSendWindow(ctx, batcher, peer, &state, &stats); err != nil {
			return TransferStats{}, err
		}
		if len(state.inFlight) == 0 && !state.doneQueued {
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
		for i := 0; i < n; i++ {
			addr := readBufs[i].Addr
			if addr == nil || addr.String() != peer.String() {
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
			if !ackIsPlausible(state.nextSeq, packet.AckFloor, packet.AckMask) {
				continue
			}

			stats.PacketsAcked += int64(applyAck(state.inFlight, packet.AckFloor, packet.AckMask))
		}
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
		if err := sendAck(ctx, conn, addr, runID, expectedSeq, ackMaskFor(buffered, expectedSeq)); err != nil {
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
			if peer != nil && (addr == nil || addr.String() != peer.String()) {
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
				if err := sendHelloAck(ctx, conn, addr, runID); err != nil {
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
				if err := sendHelloAck(ctx, conn, addr, runID); err != nil {
					return TransferStats{}, err
				}
				continue
			}

			switch packet.Type {
			case PacketTypeData:
				expectedBefore := expectedSeq
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
				if packet.Seq >= expectedSeq && packet.Seq <= expectedSeq+maxBufferedPackets {
					buffered[packet.Seq] = clonePacket(packet)
				}
				var complete bool
				expectedSeq, complete, err = advanceReceiveWindow(dst, buffered, expectedSeq, &stats)
				if err != nil {
					return TransferStats{}, err
				}
				ackDirty = true
				packetsSinceAck++
				forceAck := packet.Seq > expectedBefore
				if forceAck || packetsSinceAck >= delayedAckPackets || time.Since(lastAckAt) >= delayedAckInterval {
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
				if packet.Seq >= expectedSeq && packet.Seq <= expectedSeq+maxBufferedPackets {
					buffered[packet.Seq] = clonePacket(packet)
				}
				var complete bool
				expectedSeq, complete, err = advanceReceiveWindow(dst, buffered, expectedSeq, &stats)
				if err != nil {
					return TransferStats{}, err
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

func sendBlast(ctx context.Context, batcher packetBatcher, conn net.PacketConn, peer net.Addr, runID [16]byte, src io.Reader, chunkSize int, stats TransferStats) (TransferStats, error) {
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}
	if batcher == nil {
		batcher = newPacketBatcher(conn, stats.Transport.RequestedKind)
	}
	stats.Transport = batcher.Capabilities()
	wireBatch := make([][]byte, batcher.MaxBatch())
	packetBatch := make([][]byte, 0, batcher.MaxBatch())
	for i := range wireBatch {
		wireBatch[i] = make([]byte, headerLen+chunkSize)
	}
	var seq uint64
	var offset uint64
	eof := false
	for {
		packetBatch = packetBatch[:0]
		for len(packetBatch) < cap(packetBatch) {
			if err := ctx.Err(); err != nil {
				return TransferStats{}, err
			}
			wire := wireBatch[len(packetBatch)]
			payloadBuf := wire[headerLen:]
			n, err := src.Read(payloadBuf)
			if n > 0 {
				encodePacketHeader(wire[:headerLen], PacketTypeData, runID, seq, offset, 0, 0)
				packetBatch = append(packetBatch, wire[:headerLen+n])
				stats.PacketsSent++
				stats.BytesSent += int64(n)
				seq++
				offset += uint64(n)
			}
			if errors.Is(err, io.EOF) {
				eof = true
				break
			}
			if err != nil {
				return TransferStats{}, err
			}
			if n == 0 {
				break
			}
		}
		if len(packetBatch) > 0 {
			if _, err := batcher.WriteBatch(ctx, peer, packetBatch); err != nil {
				return TransferStats{}, err
			}
		}
		if eof {
			break
		}
	}
	donePacket := make([]byte, headerLen)
	encodePacketHeader(donePacket, PacketTypeDone, runID, seq, offset, 0, 0)
	if _, err := batcher.WriteBatch(ctx, peer, [][]byte{donePacket}); err != nil {
		return TransferStats{}, err
	}
	stats.PacketsSent++
	lingerUntil := time.Now().Add(blastDoneLinger)
	for time.Now().Before(lingerUntil) {
		if err := sleepWithContext(ctx, blastDoneInterval); err != nil {
			return TransferStats{}, err
		}
		if _, err := batcher.WriteBatch(ctx, peer, [][]byte{donePacket}); err != nil {
			return TransferStats{}, err
		}
		stats.PacketsSent++
	}
	stats.CompletedAt = time.Now()
	return stats, nil
}

func receiveBlastData(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, dst io.Writer, stats *TransferStats, buf []byte) (TransferStats, error) {
	batcher := newPacketBatcher(conn, stats.Transport.RequestedKind)
	stats.Transport = batcher.Capabilities()
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
			if peer != nil && addr != nil && addr.String() != peer.String() {
				continue
			}
			packetType, payload, packetRunID, ok := decodeBlastPacket(readBufs[i].Bytes[:readBufs[i].N])
			if !ok || packetRunID != runID {
				continue
			}
			switch packetType {
			case PacketTypeHello:
				if err := sendHelloAck(ctx, conn, addr, runID); err != nil {
					return TransferStats{}, err
				}
			case PacketTypeData:
				if stats.FirstByteAt.IsZero() && len(payload) > 0 {
					stats.FirstByteAt = time.Now()
				}
				written, err := dst.Write(payload)
				if err != nil {
					return TransferStats{}, err
				}
				if written != len(payload) {
					return TransferStats{}, io.ErrShortWrite
				}
				stats.BytesReceived += int64(written)
			case PacketTypeDone:
				stats.CompletedAt = time.Now()
				return *stats, nil
			}
		}
	}
}

func encodePacketHeader(dst []byte, packetType PacketType, runID [16]byte, seq, offset, ackFloor, ackMask uint64) {
	if len(dst) < headerLen {
		return
	}
	clear(dst[:headerLen])
	dst[0] = ProtocolVersion
	dst[1] = byte(packetType)
	copy(dst[4:20], runID[:])
	binary.BigEndian.PutUint64(dst[20:28], seq)
	binary.BigEndian.PutUint64(dst[28:36], offset)
	binary.BigEndian.PutUint64(dst[36:44], ackFloor)
	binary.BigEndian.PutUint64(dst[44:52], ackMask)
}

func decodeBlastPacket(buf []byte) (PacketType, []byte, [16]byte, bool) {
	if len(buf) < headerLen || buf[0] != ProtocolVersion {
		return 0, nil, [16]byte{}, false
	}
	var runID [16]byte
	copy(runID[:], buf[4:20])
	return PacketType(buf[1]), buf[headerLen:], runID, true
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

func sendAck(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, ackFloor, ackMask uint64) error {
	packet, err := MarshalPacket(Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeAck,
		RunID:    runID,
		AckFloor: ackFloor,
		AckMask:  ackMask,
	}, nil)
	if err != nil {
		return err
	}
	_, err = writeWithContext(ctx, conn, peer, packet)
	return err
}

func performHelloHandshake(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, stats *TransferStats) (time.Duration, error) {
	hello, err := MarshalPacket(Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeHello,
		RunID:   runID,
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
		if addr.String() != peer.String() {
			continue
		}
		packet, err := UnmarshalPacket(buf[:n], nil)
		if err != nil {
			continue
		}
		if packet.Type != PacketTypeHelloAck || packet.RunID != runID {
			continue
		}
		return sessionRetryInterval(time.Since(sentAt)), nil
	}
}

func sendHelloAck(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte) error {
	packet, err := MarshalPacket(Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeHelloAck,
		RunID:   runID,
	}, nil)
	if err != nil {
		return err
	}
	_, err = writeWithContext(ctx, conn, peer, packet)
	return err
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
	nextSeq    uint64
	offset     uint64
	runID      [16]byte
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
	for len(state.inFlight) < state.window && !state.doneQueued {
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
	return nil
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
			Version: ProtocolVersion,
			Type:    PacketTypeDone,
			RunID:   state.runID,
			Seq:     state.nextSeq,
			Offset:  state.offset,
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
			Version: ProtocolVersion,
			Type:    PacketTypeData,
			RunID:   state.runID,
			Seq:     state.nextSeq,
			Offset:  state.offset,
			Payload: payload,
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

func applyAck(packets map[uint64]*outboundPacket, ackFloor, ackMask uint64) int {
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

func ackIsPlausible(nextSeq, ackFloor, ackMask uint64) bool {
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
		if addr.String() != peer.String() {
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
			if err := sendHelloAck(ctx, conn, addr, runID); err != nil {
				return err
			}
		case PacketTypeData, PacketTypeDone:
			if err := sendAck(ctx, conn, addr, runID, expectedSeq, 0); err != nil {
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
	return conn.WriteTo(packet, peer)
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
