// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	cfg, parallel := normalizeStripedSendConfig(cfg)

	stats := TransferStats{StartedAt: time.Now()}
	batcher := newPacketBatcher(conn, cfg.Transport)
	stats.Transport = batcher.Capabilities()

	totalStripes := uint16(parallel)
	states, retryInterval, err := newStripedSenderStates(ctx, conn, peer, runID, totalStripes, cfg, &stats)
	if err != nil {
		return TransferStats{}, err
	}

	source := &stripedSourceState{src: src}
	readBufs := newBatchReadBuffers(batcher.MaxBatch(), 64<<10)
	return runStripedSendLoop(ctx, batcher, peer, runID, states, source, readBufs, retryInterval, &stats)
}

func normalizeStripedSendConfig(cfg SendConfig) (SendConfig, int) {
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
	return cfg, parallel
}

func newStripedSenderStates(ctx context.Context, conn net.PacketConn, peer net.Addr, runID [16]byte, totalStripes uint16, cfg SendConfig, stats *TransferStats) ([]*senderState, time.Duration, error) {
	retryInterval := minRetryInterval
	states := make([]*senderState, int(totalStripes))
	for i := range states {
		stripeID := uint16(i)
		stripeRetry, err := performHelloHandshake(ctx, conn, peer, runID, stripeID, totalStripes, stats)
		if err != nil {
			return nil, 0, err
		}
		if stripeRetry > retryInterval {
			retryInterval = stripeRetry
		}
		states[i] = newStripedSenderState(runID, stripeID, cfg)
	}
	return states, retryInterval, nil
}

func newStripedSenderState(runID [16]byte, stripeID uint16, cfg SendConfig) *senderState {
	return &senderState{
		chunkSize: cfg.ChunkSize,
		window:    cfg.WindowSize,
		stripeID:  stripeID,
		runID:     runID,
		inFlight:  make(map[uint64]*outboundPacket, cfg.WindowSize),
	}
}

func newBatchReadBuffers(count int, size int) []batchReadBuffer {
	readBufs := make([]batchReadBuffer, count)
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, size)
	}
	return readBufs
}

func runStripedSendLoop(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, states []*senderState, source *stripedSourceState, readBufs []batchReadBuffer, retryInterval time.Duration, stats *TransferStats) (TransferStats, error) {
	for {
		if source.pendingErr != nil && stripedInFlightEmpty(states) {
			return TransferStats{}, source.pendingErr
		}
		if err := fillStripedSendWindows(ctx, batcher, peer, states, source, stats); err != nil {
			return TransferStats{}, err
		}
		if stripedSendComplete(states) {
			stats.CompletedAt = time.Now()
			return *stats, nil
		}
		if stripedInFlightEmpty(states) && !source.eof {
			if err := waitZeroReadRetry(ctx, source.zeroReads); err != nil {
				return TransferStats{}, err
			}
			continue
		}
		if err := readStripedSenderAcks(ctx, batcher, peer, runID, states, readBufs, retryInterval, stats); err != nil {
			return TransferStats{}, err
		}
	}
}

func stripedSendComplete(states []*senderState) bool {
	if !stripedAllDoneQueued(states) {
		return false
	}
	return stripedInFlightEmpty(states) || stripedDonePacketsSettled(states)
}

func readStripedSenderAcks(ctx context.Context, batcher packetBatcher, peer net.Addr, runID [16]byte, states []*senderState, readBufs []batchReadBuffer, retryInterval time.Duration, stats *TransferStats) error {
	n, err := batcher.ReadBatch(ctx, stripedNextRetransmitDeadline(ctx, states, retryInterval), readBufs)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !isNetTimeout(err) {
			return err
		}
		if err := retransmitExpiredStripes(ctx, batcher, peer, states, retryInterval, stats); err != nil {
			return err
		}
		return nil
	}
	applyStripedSenderAcks(peer, runID, states, readBufs[:n], stats)
	return nil
}

func applyStripedSenderAcks(peer net.Addr, runID [16]byte, states []*senderState, readBufs []batchReadBuffer, stats *TransferStats) {
	for _, readBuf := range readBufs {
		applyStripedSenderAck(peer, runID, states, readBuf, stats)
	}
}

func applyStripedSenderAck(peer net.Addr, runID [16]byte, states []*senderState, readBuf batchReadBuffer, stats *TransferStats) {
	if !sameAddr(readBuf.Addr, peer) {
		return
	}
	packet, err := UnmarshalPacket(readBuf.Bytes[:readBuf.N], nil)
	if err != nil || packet.Type != PacketTypeAck || packet.RunID != runID {
		return
	}
	if int(packet.StripeID) >= len(states) {
		return
	}
	state := states[packet.StripeID]
	if !ackIsPlausible(state.nextSeq, packet.AckFloor, packet.AckMask, packet.Payload) {
		return
	}
	stats.PacketsAcked += int64(applyAck(state.inFlight, packet.AckFloor, packet.AckMask, packet.Payload))
}

func fillStripedSendWindows(ctx context.Context, batcher packetBatcher, peer net.Addr, states []*senderState, source *stripedSourceState, stats *TransferStats) error {
	pending, err := collectStripedPendingPackets(states, source)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}
	return sendStripedPendingPackets(ctx, batcher, peer, pending, stats)
}

func collectStripedPendingPackets(states []*senderState, source *stripedSourceState) ([]*outboundPacket, error) {
	var pending []*outboundPacket
	for {
		progress := false
		for _, state := range states {
			if state == nil || state.doneQueued || len(state.inFlight) >= state.window {
				continue
			}
			packet, err := nextStripedOutboundPacket(state, source)
			if err != nil {
				return nil, err
			}
			if packet == nil {
				continue
			}
			state.inFlight[packet.seq] = packet
			pending = append(pending, packet)
			progress = true
		}
		if !progress {
			return pending, nil
		}
	}
}

func sendStripedPendingPackets(ctx context.Context, batcher packetBatcher, peer net.Addr, pending []*outboundPacket, stats *TransferStats) error {
	wires := make([][]byte, len(pending))
	for i, packet := range pending {
		wires[i] = packet.wire
	}
	if _, err := batcher.WriteBatch(ctx, peer, wires); err != nil {
		return err
	}
	now := time.Now()
	for _, packet := range pending {
		markStripedPacketSent(packet, now, stats)
	}
	return nil
}

func markStripedPacketSent(packet *outboundPacket, now time.Time, stats *TransferStats) {
	packet.attempts++
	if packet.firstSentAt.IsZero() {
		packet.firstSentAt = now
	}
	packet.sentAt = now
	stats.PacketsSent++
	stats.BytesSent += int64(packet.payload)
}

func nextStripedOutboundPacket(state *senderState, source *stripedSourceState) (*outboundPacket, error) {
	if state.doneQueued || source.pendingErr != nil {
		return nil, nil
	}
	if source.eof {
		return nextStripedDonePacket(state, source.offset)
	}
	return nextStripedDataPacket(state, source)
}

func nextStripedDonePacket(state *senderState, offset uint64) (*outboundPacket, error) {
	wire, err := MarshalPacket(Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeDone,
		StripeID: state.stripeID,
		RunID:    state.runID,
		Seq:      state.nextSeq,
		Offset:   offset,
	}, nil)
	if err != nil {
		return nil, err
	}
	packet := &outboundPacket{seq: state.nextSeq, packetType: PacketTypeDone, wire: wire}
	state.nextSeq++
	state.doneQueued = true
	return packet, nil
}

func nextStripedDataPacket(state *senderState, source *stripedSourceState) (*outboundPacket, error) {
	buf := make([]byte, state.chunkSize)
	n, readErr := source.src.Read(buf)
	if n > 0 {
		return buildStripedDataPacket(state, source, buf[:n], readErr)
	}
	if errors.Is(readErr, io.EOF) {
		source.eof = true
		return nextStripedDonePacket(state, source.offset)
	}
	if readErr != nil {
		return nil, readErr
	}
	source.zeroReads++
	return nil, nil
}

func buildStripedDataPacket(state *senderState, source *stripedSourceState, data []byte, readErr error) (*outboundPacket, error) {
	payload := append([]byte(nil), data...)
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
		payload:    len(data),
	}
	state.nextSeq++
	source.offset += uint64(len(data))
	source.zeroReads = 0
	rememberStripedReadErr(source, readErr)
	return packet, nil
}

func rememberStripedReadErr(source *stripedSourceState, readErr error) {
	switch {
	case errors.Is(readErr, io.EOF):
		source.eof = true
	case readErr != nil:
		source.pendingErr = readErr
	}
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
	totalStripes, err := validateStripedFirstHello(firstHello)
	if err != nil {
		return TransferStats{}, err
	}
	if batcher == nil {
		batcher = newPacketBatcher(conn, stats.Transport.RequestedKind)
		stats.Transport = batcher.Capabilities()
	}
	if err := sendHelloAck(ctx, conn, peer, runID, firstHello.StripeID, uint16(totalStripes)); err != nil {
		return TransferStats{}, err
	}
	run := newStripedReceiveRun(ctx, conn, batcher, peer, runID, dst, stats, len(buf), totalStripes)
	return run.loop()
}

func validateStripedFirstHello(firstHello Packet) (int, error) {
	totalStripes := int(firstHello.Seq)
	if totalStripes < 1 {
		totalStripes = 1
	}
	if totalStripes > maxParallelStripes {
		return 0, errors.New("too many stripes")
	}
	if int(firstHello.StripeID) >= totalStripes {
		return 0, errors.New("stripe id outside announced stripe count")
	}
	return totalStripes, nil
}

type stripedReceiveRun struct {
	ctx              context.Context
	conn             net.PacketConn
	batcher          packetBatcher
	peer             net.Addr
	runID            [16]byte
	dst              io.Writer
	stats            *TransferStats
	readBufs         []batchReadBuffer
	states           []*receiveStripeState
	pendingOutput    map[uint64][]byte
	nextOffset       uint64
	finalTotal       uint64
	finalTotalSet    bool
	completedStripes int
	totalStripes     int
}

func newStripedReceiveRun(ctx context.Context, conn net.PacketConn, batcher packetBatcher, peer net.Addr, runID [16]byte, dst io.Writer, stats *TransferStats, readSize int, totalStripes int) *stripedReceiveRun {
	states := make([]*receiveStripeState, totalStripes)
	for i := range states {
		states[i] = &receiveStripeState{buffered: make(map[uint64]Packet)}
	}
	return &stripedReceiveRun{
		ctx:           ctx,
		conn:          conn,
		batcher:       batcher,
		peer:          peer,
		runID:         runID,
		dst:           dst,
		stats:         stats,
		readBufs:      newBatchReadBuffers(batcher.MaxBatch(), readSize),
		states:        states,
		pendingOutput: make(map[uint64][]byte),
		totalStripes:  totalStripes,
	}
}

func (r *stripedReceiveRun) loop() (TransferStats, error) {
	for {
		n, err := r.batcher.ReadBatch(r.ctx, defaultRetryInterval, r.readBufs)
		if err != nil {
			if err := r.handleReadErr(err); err != nil {
				return TransferStats{}, err
			}
			continue
		}
		complete, err := r.processReadBatch(n)
		if err != nil {
			return TransferStats{}, err
		}
		if complete {
			r.stats.CompletedAt = time.Now()
			return *r.stats, nil
		}
	}
}

func (r *stripedReceiveRun) handleReadErr(err error) error {
	if r.ctx.Err() != nil {
		return r.ctx.Err()
	}
	if isNetTimeout(err) {
		return sendStripedPendingAcks(r.ctx, r.conn, r.peer, r.runID, r.states)
	}
	if errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (r *stripedReceiveRun) processReadBatch(n int) (bool, error) {
	for i := 0; i < n; i++ {
		complete, err := r.processReadBuffer(r.readBufs[i])
		if err != nil || complete {
			return complete, err
		}
	}
	return false, nil
}

func (r *stripedReceiveRun) processReadBuffer(readBuf batchReadBuffer) (bool, error) {
	if !sameAddr(readBuf.Addr, r.peer) {
		return false, nil
	}
	packet, err := UnmarshalPacket(readBuf.Bytes[:readBuf.N], nil)
	if err != nil || packet.RunID != r.runID {
		return false, nil
	}
	if int(packet.StripeID) >= r.totalStripes {
		return false, nil
	}
	return r.processPacket(readBuf.Addr, packet)
}

func (r *stripedReceiveRun) processPacket(addr net.Addr, packet Packet) (bool, error) {
	switch packet.Type {
	case PacketTypeHello:
		return false, sendHelloAck(r.ctx, r.conn, addr, r.runID, packet.StripeID, uint16(r.totalStripes))
	case PacketTypeData, PacketTypeDone:
		return r.processDataOrDone(addr, packet)
	default:
		return false, nil
	}
}

func (r *stripedReceiveRun) processDataOrDone(addr net.Addr, packet Packet) (bool, error) {
	state := r.states[packet.StripeID]
	complete, err := processStripedReceivePacket(
		r.dst,
		state,
		packet,
		r.pendingOutput,
		&r.nextOffset,
		&r.finalTotal,
		&r.finalTotalSet,
		&r.completedStripes,
		r.totalStripes,
		r.stats,
	)
	if err != nil {
		return false, err
	}
	if err := r.flushAckIfNeeded(addr, packet.StripeID, state); err != nil {
		return false, err
	}
	if !complete {
		return false, nil
	}
	return true, sendStripedPendingAcks(r.ctx, r.conn, addr, r.runID, r.states)
}

func (r *stripedReceiveRun) flushAckIfNeeded(addr net.Addr, stripeID uint16, state *receiveStripeState) error {
	if state.packetsSinceAck < delayedAckPackets && time.Since(state.lastAckAt) < delayedAckInterval {
		return nil
	}
	return sendStripedPendingAck(r.ctx, r.conn, addr, r.runID, stripeID, state)
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
		if err := acceptStripedDataPacket(dst, packet, pendingOutput, nextOffset, stats); err != nil {
			return false, err
		}
		state.expectedSeq++
	case PacketTypeDone:
		if err := acceptStripedDonePacket(state, packet, finalTotal, finalTotalSet, completedStripes); err != nil {
			return false, err
		}
	}
	return stripedReceiveComplete(*finalTotalSet, *finalTotal, *nextOffset, *completedStripes, totalStripes), nil
}

func acceptStripedDataPacket(dst io.Writer, packet Packet, pendingOutput map[uint64][]byte, nextOffset *uint64, stats *TransferStats) error {
	if len(packet.Payload) == 0 {
		return nil
	}
	if stats.FirstByteAt.IsZero() {
		stats.FirstByteAt = time.Now()
	}
	if packet.Offset == *nextOffset {
		if err := writeStripedPayload(dst, packet.Payload, nextOffset, stats); err != nil {
			return err
		}
		return flushStripedPendingPayloads(dst, pendingOutput, nextOffset, stats)
	}
	if packet.Offset > *nextOffset {
		storeStripedPendingPayload(packet, pendingOutput)
	}
	return nil
}

func storeStripedPendingPayload(packet Packet, pendingOutput map[uint64][]byte) {
	if _, exists := pendingOutput[packet.Offset]; exists {
		return
	}
	pendingOutput[packet.Offset] = append([]byte(nil), packet.Payload...)
}

func acceptStripedDonePacket(state *receiveStripeState, packet Packet, finalTotal *uint64, finalTotalSet *bool, completedStripes *int) error {
	if !state.done {
		state.done = true
		(*completedStripes)++
	}
	if !*finalTotalSet {
		*finalTotal = packet.Offset
		*finalTotalSet = true
	} else if *finalTotal != packet.Offset {
		return errors.New("striped done packets disagree on final size")
	}
	state.expectedSeq++
	return nil
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
