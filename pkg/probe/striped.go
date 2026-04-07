package probe

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

const maxParallelStripes = 16

type stripedSourceState struct {
	src        io.Reader
	offset     uint64
	eof        bool
	pendingErr error
	zeroReads  int
}

type receiveStripeState struct {
	expectedSeq     uint64
	buffered        map[uint64]Packet
	lastAckAt       time.Time
	packetsSinceAck int
	ackDirty        bool
	done            bool
}

func sendStriped(ctx context.Context, conn net.PacketConn, peer net.Addr, src io.Reader, runID [16]byte, cfg SendConfig) (TransferStats, error) {
	parallel := cfg.Parallel
	if parallel < 2 {
		parallel = 2
	}
	if parallel > maxParallelStripes {
		parallel = maxParallelStripes
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = defaultChunkSize
	}
	cfg.WindowSize = effectiveWindowSize(cfg.WindowSize)

	stats := TransferStats{StartedAt: time.Now()}
	batcher := newPacketBatcher(conn, cfg.Transport)
	stats.Transport = batcher.Capabilities()

	totalStripes := uint16(parallel)
	retryInterval := minRetryInterval
	states := make([]*senderState, parallel)
	for i := 0; i < parallel; i++ {
		stripeID := uint16(i)
		stripeRetry, err := performHelloHandshake(ctx, conn, peer, runID, stripeID, totalStripes, &stats)
		if err != nil {
			return TransferStats{}, err
		}
		if stripeRetry > retryInterval {
			retryInterval = stripeRetry
		}
		states[i] = &senderState{
			chunkSize: cfg.ChunkSize,
			window:    cfg.WindowSize,
			stripeID:  stripeID,
			runID:     runID,
			inFlight:  make(map[uint64]*outboundPacket, cfg.WindowSize),
		}
	}

	source := &stripedSourceState{src: src}
	readBufs := make([]batchReadBuffer, batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, 64<<10)
	}

	for {
		if source.pendingErr != nil && stripedInFlightEmpty(states) {
			return TransferStats{}, source.pendingErr
		}
		if err := fillStripedSendWindows(ctx, batcher, peer, states, source, &stats); err != nil {
			return TransferStats{}, err
		}
		if stripedAllDoneQueued(states) && stripedInFlightEmpty(states) {
			stats.CompletedAt = time.Now()
			return stats, nil
		}
		if stripedAllDoneQueued(states) && stripedDonePacketsSettled(states) {
			stats.CompletedAt = time.Now()
			return stats, nil
		}
		if stripedInFlightEmpty(states) && !source.eof {
			if err := waitZeroReadRetry(ctx, source.zeroReads); err != nil {
				return TransferStats{}, err
			}
			continue
		}

		n, err := batcher.ReadBatch(ctx, stripedNextRetransmitDeadline(ctx, states, retryInterval), readBufs)
		if err != nil {
			if ctx.Err() != nil {
				return TransferStats{}, ctx.Err()
			}
			if isNetTimeout(err) {
				if err := retransmitExpiredStripes(ctx, batcher, peer, states, retryInterval, &stats); err != nil {
					return TransferStats{}, err
				}
				continue
			}
			return TransferStats{}, err
		}
		for i := 0; i < n; i++ {
			addr := readBufs[i].Addr
			if !sameAddr(addr, peer) {
				continue
			}
			packet, err := UnmarshalPacket(readBufs[i].Bytes[:readBufs[i].N], nil)
			if err != nil || packet.Type != PacketTypeAck || packet.RunID != runID {
				continue
			}
			if int(packet.StripeID) >= len(states) {
				continue
			}
			state := states[packet.StripeID]
			if !ackIsPlausible(state.nextSeq, packet.AckFloor, packet.AckMask, packet.Payload) {
				continue
			}
			stats.PacketsAcked += int64(applyAck(state.inFlight, packet.AckFloor, packet.AckMask, packet.Payload))
		}
	}
}

func fillStripedSendWindows(ctx context.Context, batcher packetBatcher, peer net.Addr, states []*senderState, source *stripedSourceState, stats *TransferStats) error {
	var pending []*outboundPacket
	for {
		progress := false
		for _, state := range states {
			if state == nil || state.doneQueued || len(state.inFlight) >= state.window {
				continue
			}
			packet, err := nextStripedOutboundPacket(state, source)
			if err != nil {
				return err
			}
			if packet == nil {
				continue
			}
			state.inFlight[packet.seq] = packet
			pending = append(pending, packet)
			progress = true
		}
		if !progress {
			break
		}
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

func nextStripedOutboundPacket(state *senderState, source *stripedSourceState) (*outboundPacket, error) {
	if state.doneQueued || source.pendingErr != nil {
		return nil, nil
	}
	if source.eof {
		wire, err := MarshalPacket(Packet{
			Version:  ProtocolVersion,
			Type:     PacketTypeDone,
			StripeID: state.stripeID,
			RunID:    state.runID,
			Seq:      state.nextSeq,
			Offset:   source.offset,
		}, nil)
		if err != nil {
			return nil, err
		}
		packet := &outboundPacket{seq: state.nextSeq, packetType: PacketTypeDone, wire: wire}
		state.nextSeq++
		state.doneQueued = true
		return packet, nil
	}

	buf := make([]byte, state.chunkSize)
	n, readErr := source.src.Read(buf)
	if n > 0 {
		payload := append([]byte(nil), buf[:n]...)
		packetOffset := source.offset
		wire, err := MarshalPacket(Packet{
			Version:  ProtocolVersion,
			Type:     PacketTypeData,
			StripeID: state.stripeID,
			RunID:    state.runID,
			Seq:      state.nextSeq,
			Offset:   packetOffset,
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
		source.offset += uint64(n)
		source.zeroReads = 0
		if errors.Is(readErr, io.EOF) {
			source.eof = true
		} else if readErr != nil {
			source.pendingErr = readErr
		}
		return packet, nil
	}
	if errors.Is(readErr, io.EOF) {
		source.eof = true
		return nextStripedOutboundPacket(state, source)
	}
	if readErr != nil {
		return nil, readErr
	}
	source.zeroReads++
	return nil, nil
}

func retransmitExpiredStripes(ctx context.Context, batcher packetBatcher, peer net.Addr, states []*senderState, retryInterval time.Duration, stats *TransferStats) error {
	for _, state := range states {
		if state == nil {
			continue
		}
		if err := retransmitExpired(ctx, batcher, peer, state.inFlight, retryInterval, stats); err != nil {
			return err
		}
	}
	return nil
}

func stripedNextRetransmitDeadline(ctx context.Context, states []*senderState, retryInterval time.Duration) time.Duration {
	wait := retryInterval
	for _, state := range states {
		if state == nil || len(state.inFlight) == 0 {
			continue
		}
		stateWait := nextRetransmitDeadline(ctx, state.inFlight, retryInterval)
		if stateWait < wait {
			wait = stateWait
		}
	}
	return wait
}

func stripedInFlightEmpty(states []*senderState) bool {
	for _, state := range states {
		if state != nil && len(state.inFlight) != 0 {
			return false
		}
	}
	return true
}

func stripedAllDoneQueued(states []*senderState) bool {
	for _, state := range states {
		if state == nil || !state.doneQueued {
			return false
		}
	}
	return true
}

func stripedDonePacketsSettled(states []*senderState) bool {
	for _, state := range states {
		if state == nil || !donePacketSettled(state.inFlight) {
			return false
		}
	}
	return true
}

func receiveStripedFromFirstHello(ctx context.Context, conn net.PacketConn, batcher packetBatcher, peer net.Addr, runID [16]byte, firstHello Packet, dst io.Writer, stats *TransferStats, buf []byte) (TransferStats, error) {
	totalStripes := int(firstHello.Seq)
	if totalStripes < 1 {
		totalStripes = 1
	}
	if totalStripes > maxParallelStripes {
		return TransferStats{}, errors.New("too many stripes")
	}
	if int(firstHello.StripeID) >= totalStripes {
		return TransferStats{}, errors.New("stripe id outside announced stripe count")
	}
	if batcher == nil {
		batcher = newPacketBatcher(conn, stats.Transport.RequestedKind)
		stats.Transport = batcher.Capabilities()
	}
	readBufs := make([]batchReadBuffer, batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, len(buf))
	}

	states := make([]*receiveStripeState, totalStripes)
	for i := range states {
		states[i] = &receiveStripeState{buffered: make(map[uint64]Packet)}
	}
	pendingOutput := make(map[uint64][]byte)
	var nextOffset uint64
	var finalTotal uint64
	var finalTotalSet bool
	completedStripes := 0

	if err := sendHelloAck(ctx, conn, peer, runID, firstHello.StripeID, uint16(totalStripes)); err != nil {
		return TransferStats{}, err
	}

	for {
		n, err := batcher.ReadBatch(ctx, defaultRetryInterval, readBufs)
		if err != nil {
			if ctx.Err() != nil {
				return TransferStats{}, ctx.Err()
			}
			if isNetTimeout(err) {
				if err := sendStripedPendingAcks(ctx, conn, peer, runID, states); err != nil {
					return TransferStats{}, err
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
			if !sameAddr(addr, peer) {
				continue
			}
			packet, err := UnmarshalPacket(readBufs[i].Bytes[:readBufs[i].N], nil)
			if err != nil || packet.RunID != runID {
				continue
			}
			if int(packet.StripeID) >= totalStripes {
				continue
			}
			switch packet.Type {
			case PacketTypeHello:
				if err := sendHelloAck(ctx, conn, addr, runID, packet.StripeID, uint16(totalStripes)); err != nil {
					return TransferStats{}, err
				}
			case PacketTypeData, PacketTypeDone:
				complete, err := processStripedReceivePacket(
					dst,
					states[packet.StripeID],
					packet,
					pendingOutput,
					&nextOffset,
					&finalTotal,
					&finalTotalSet,
					&completedStripes,
					totalStripes,
					stats,
				)
				if err != nil {
					return TransferStats{}, err
				}
				if states[packet.StripeID].packetsSinceAck >= delayedAckPackets || time.Since(states[packet.StripeID].lastAckAt) >= delayedAckInterval {
					if err := sendStripedPendingAck(ctx, conn, addr, runID, packet.StripeID, states[packet.StripeID]); err != nil {
						return TransferStats{}, err
					}
				}
				if complete {
					if err := sendStripedPendingAcks(ctx, conn, addr, runID, states); err != nil {
						return TransferStats{}, err
					}
					stats.CompletedAt = time.Now()
					return *stats, nil
				}
			}
		}
	}
}

func processStripedReceivePacket(dst io.Writer, state *receiveStripeState, packet Packet, pendingOutput map[uint64][]byte, nextOffset *uint64, finalTotal *uint64, finalTotalSet *bool, completedStripes *int, totalStripes int, stats *TransferStats) (bool, error) {
	markAck := func() {
		state.ackDirty = true
		state.packetsSinceAck++
	}
	if packet.Seq == state.expectedSeq {
		complete, err := acceptStripedReceivePacket(dst, state, packet, pendingOutput, nextOffset, finalTotal, finalTotalSet, completedStripes, totalStripes, stats)
		if err != nil {
			return false, err
		}
		if complete {
			markAck()
			return complete, err
		}
		for {
			buffered, ok := state.buffered[state.expectedSeq]
			if !ok {
				break
			}
			delete(state.buffered, state.expectedSeq)
			complete, err = acceptStripedReceivePacket(dst, state, buffered, pendingOutput, nextOffset, finalTotal, finalTotalSet, completedStripes, totalStripes, stats)
			if err != nil {
				return false, err
			}
			if complete {
				markAck()
				return complete, err
			}
		}
	} else if packet.Seq > state.expectedSeq && packet.Seq <= state.expectedSeq+maxBufferedPackets {
		state.buffered[packet.Seq] = clonePacket(packet)
	}
	markAck()
	return stripedReceiveComplete(*finalTotalSet, *finalTotal, *nextOffset, *completedStripes, totalStripes), nil
}

func acceptStripedReceivePacket(dst io.Writer, state *receiveStripeState, packet Packet, pendingOutput map[uint64][]byte, nextOffset *uint64, finalTotal *uint64, finalTotalSet *bool, completedStripes *int, totalStripes int, stats *TransferStats) (bool, error) {
	switch packet.Type {
	case PacketTypeData:
		if len(packet.Payload) > 0 {
			if stats.FirstByteAt.IsZero() {
				stats.FirstByteAt = time.Now()
			}
			if packet.Offset == *nextOffset {
				if err := writeStripedPayload(dst, packet.Payload, nextOffset, stats); err != nil {
					return false, err
				}
				if err := flushStripedPendingPayloads(dst, pendingOutput, nextOffset, stats); err != nil {
					return false, err
				}
			} else if packet.Offset > *nextOffset {
				if _, exists := pendingOutput[packet.Offset]; !exists {
					pendingOutput[packet.Offset] = append([]byte(nil), packet.Payload...)
				}
			}
		}
		state.expectedSeq++
	case PacketTypeDone:
		if !state.done {
			state.done = true
			*completedStripes++
		}
		if !*finalTotalSet {
			*finalTotal = packet.Offset
			*finalTotalSet = true
		} else if *finalTotal != packet.Offset {
			return false, errors.New("striped done packets disagree on final size")
		}
		state.expectedSeq++
	}
	return stripedReceiveComplete(*finalTotalSet, *finalTotal, *nextOffset, *completedStripes, totalStripes), nil
}

func writeStripedPayload(dst io.Writer, payload []byte, nextOffset *uint64, stats *TransferStats) error {
	n, err := dst.Write(payload)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return io.ErrShortWrite
	}
	*nextOffset += uint64(n)
	stats.BytesReceived += int64(n)
	return nil
}

func flushStripedPendingPayloads(dst io.Writer, pendingOutput map[uint64][]byte, nextOffset *uint64, stats *TransferStats) error {
	for {
		payload, ok := pendingOutput[*nextOffset]
		if !ok {
			return nil
		}
		delete(pendingOutput, *nextOffset)
		if err := writeStripedPayload(dst, payload, nextOffset, stats); err != nil {
			return err
		}
	}
}

func stripedReceiveComplete(finalTotalSet bool, finalTotal, nextOffset uint64, completedStripes, totalStripes int) bool {
	return finalTotalSet && completedStripes == totalStripes && nextOffset == finalTotal
}

func sendStripedPendingAcks(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, states []*receiveStripeState) error {
	for i, state := range states {
		if state == nil {
			continue
		}
		if err := sendStripedPendingAck(ctx, conn, peer, runID, uint16(i), state); err != nil {
			return err
		}
	}
	return nil
}

func sendStripedPendingAck(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, stripeID uint16, state *receiveStripeState) error {
	if state == nil || !state.ackDirty || peer == nil {
		return nil
	}
	if err := sendAck(ctx, conn, peer, runID, stripeID, state.expectedSeq, ackMaskFor(state.buffered, state.expectedSeq), extendedAckPayloadFor(state.buffered, state.expectedSeq)); err != nil {
		return err
	}
	state.ackDirty = false
	state.packetsSinceAck = 0
	state.lastAckAt = time.Now()
	return nil
}
