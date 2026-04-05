package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"time"
)

const (
	defaultChunkSize     = 1200
	defaultWindowSize    = 8
	defaultRetryInterval = 20 * time.Millisecond
	zeroReadRetryDelay   = 1 * time.Millisecond
	maxAckMaskBits       = 64
)

type SendConfig struct {
	Raw        bool
	ChunkSize  int
	WindowSize int
}

type ReceiveConfig struct {
	Raw bool
}

type TransferStats struct {
	BytesSent     int64
	BytesReceived int64
	PacketsSent   int64
	PacketsAcked  int64
	StartedAt     time.Time
	CompletedAt   time.Time
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
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = defaultWindowSize
	}
	if cfg.WindowSize > maxAckMaskBits+1 {
		cfg.WindowSize = maxAckMaskBits + 1
	}

	peer, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return TransferStats{}, err
	}

	stats := TransferStats{StartedAt: time.Now()}
	runID, err := newRunID()
	if err != nil {
		return TransferStats{}, err
	}

	buf := make([]byte, 64<<10)
	state := senderState{
		src:       src,
		chunkSize: cfg.ChunkSize,
		window:    cfg.WindowSize,
		nextSeq:   0,
		offset:    0,
		runID:     runID,
		inFlight:  make(map[uint64]*outboundPacket, cfg.WindowSize),
	}
	if err := performHelloHandshake(ctx, conn, peer, state.runID, &stats); err != nil {
		return TransferStats{}, err
	}

	for {
		if err := fillSendWindow(ctx, conn, peer, &state, &stats); err != nil {
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

		if err := setReadDeadline(ctx, conn, nextRetransmitDeadline(ctx, state.inFlight)); err != nil {
			return TransferStats{}, err
		}

		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return TransferStats{}, ctx.Err()
			}
			if isNetTimeout(err) {
				if err := retransmitExpired(ctx, conn, peer, state.inFlight, &stats); err != nil {
					return TransferStats{}, err
				}
				continue
			}
			return TransferStats{}, err
		}
		if addr.String() != peer.String() {
			continue
		}

		packet, err := UnmarshalPacket(buf[:n], nil)
		if err != nil {
			return TransferStats{}, err
		}
		if packet.Type != PacketTypeAck {
			continue
		}
		if packet.RunID != state.runID {
			continue
		}

		stats.PacketsAcked += int64(applyAck(state.inFlight, packet.AckFloor, packet.AckMask))
	}
}

func Receive(ctx context.Context, conn net.PacketConn, remoteAddr string, cfg ReceiveConfig) ([]byte, error) {
	if conn == nil {
		return nil, errors.New("nil packet conn")
	}

	peer, err := resolveRemoteAddr(remoteAddr)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	buf := make([]byte, 64<<10)
	var expectedSeq uint64
	buffered := make(map[uint64]Packet)
	var runID [16]byte
	var runIDSet bool

	for {
		if err := setReadDeadline(ctx, conn, defaultRetryInterval); err != nil {
			return nil, err
		}

		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if isNetTimeout(err) {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil, err
			}
			continue
		}
		if peer != nil && addr.String() != peer.String() {
			continue
		}

		packet, err := UnmarshalPacket(buf[:n], nil)
		if err != nil {
			return nil, err
		}
		if isZeroRunID(packet.RunID) {
			continue
		}
		if !runIDSet {
			if packet.Type != PacketTypeHello {
				continue
			}
			runID = packet.RunID
			runIDSet = true
			if err := sendHelloAck(ctx, conn, addr, runID); err != nil {
				return nil, err
			}
			continue
		}
		if packet.RunID != runID {
			continue
		}
		if packet.Type == PacketTypeHello {
			if err := sendHelloAck(ctx, conn, addr, runID); err != nil {
				return nil, err
			}
			continue
		}

		switch packet.Type {
		case PacketTypeData:
			if packet.Seq >= expectedSeq && packet.Seq <= expectedSeq+maxAckMaskBits {
				buffered[packet.Seq] = clonePacket(packet)
			}
			var complete bool
			expectedSeq, complete, err = advanceReceiveWindow(&out, buffered, expectedSeq)
			if err != nil {
				return nil, err
			}
			if err := sendAck(ctx, conn, addr, runID, expectedSeq, ackMaskFor(buffered, expectedSeq)); err != nil {
				return nil, err
			}
			if complete {
				return out.Bytes(), nil
			}
		case PacketTypeDone:
			if packet.Seq >= expectedSeq && packet.Seq <= expectedSeq+maxAckMaskBits {
				buffered[packet.Seq] = clonePacket(packet)
			}
			var complete bool
			expectedSeq, complete, err = advanceReceiveWindow(&out, buffered, expectedSeq)
			if err != nil {
				return nil, err
			}
			if err := sendAck(ctx, conn, addr, runID, expectedSeq, ackMaskFor(buffered, expectedSeq)); err != nil {
				return nil, err
			}
			if complete {
				return out.Bytes(), nil
			}
		}
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

func performHelloHandshake(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, stats *TransferStats) error {
	hello, err := MarshalPacket(Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeHello,
		RunID:   runID,
	}, nil)
	if err != nil {
		return err
	}

	buf := make([]byte, 64<<10)
	for {
		if _, err := writeWithContext(ctx, conn, peer, hello); err != nil {
			return err
		}
		stats.PacketsSent++

		if err := setReadDeadline(ctx, conn, defaultRetryInterval); err != nil {
			return err
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if isNetTimeout(err) {
				continue
			}
			return err
		}
		if addr.String() != peer.String() {
			continue
		}
		packet, err := UnmarshalPacket(buf[:n], nil)
		if err != nil {
			return err
		}
		if packet.Type != PacketTypeHelloAck || packet.RunID != runID {
			continue
		}
		return nil
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
	seq     uint64
	wire    []byte
	sentAt  time.Time
	payload int
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

func sendOutbound(ctx context.Context, conn net.PacketConn, peer net.Addr, packet *outboundPacket, stats *TransferStats) error {
	_, err := writeWithContext(ctx, conn, peer, packet.wire)
	if err != nil {
		return err
	}
	packet.sentAt = time.Now()
	stats.PacketsSent++
	return nil
}

func fillSendWindow(ctx context.Context, conn net.PacketConn, peer net.Addr, state *senderState, stats *TransferStats) error {
	if len(state.inFlight) == 0 && state.pendingErr != nil {
		return state.pendingErr
	}
	for len(state.inFlight) < state.window && !state.doneQueued {
		packet, err := nextOutboundPacket(state)
		if err != nil {
			return err
		}
		if packet == nil {
			return nil
		}
		state.inFlight[packet.seq] = packet
		if err := sendOutbound(ctx, conn, peer, packet, stats); err != nil {
			return err
		}
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
		packet := &outboundPacket{seq: state.nextSeq, wire: wire}
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
			seq:     state.nextSeq,
			wire:    wire,
			payload: n,
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

func retransmitExpired(ctx context.Context, conn net.PacketConn, peer net.Addr, packets map[uint64]*outboundPacket, stats *TransferStats) error {
	now := time.Now()
	for _, packet := range packets {
		if packet.sentAt.IsZero() {
			continue
		}
		if now.Sub(packet.sentAt) < defaultRetryInterval {
			continue
		}
		if err := sendOutbound(ctx, conn, peer, packet, stats); err != nil {
			return err
		}
	}
	return nil
}

func nextRetransmitDeadline(ctx context.Context, packets map[uint64]*outboundPacket) time.Duration {
	wait := defaultRetryInterval
	now := time.Now()
	for _, packet := range packets {
		if packet.sentAt.IsZero() {
			continue
		}
		deadline := packet.sentAt.Add(defaultRetryInterval)
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

func advanceReceiveWindow(out *bytes.Buffer, buffered map[uint64]Packet, expectedSeq uint64) (uint64, bool, error) {
	for {
		packet, ok := buffered[expectedSeq]
		if !ok {
			return expectedSeq, false, nil
		}
		delete(buffered, expectedSeq)
		switch packet.Type {
		case PacketTypeData:
			if _, err := out.Write(packet.Payload); err != nil {
				return expectedSeq, false, err
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
