package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

type blastSendControlEvent struct {
	typ        PacketType
	stripe     uint16
	payload    []byte
	err        error
	receivedAt time.Time
}

func startBlastSendControlReader(ctx context.Context, batcher packetBatcher, runID [16]byte) (<-chan blastSendControlEvent, func()) {
	events := make(chan blastSendControlEvent, blastSendControlEventBuffer(batcher))
	controlCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		readBlastSendControlEvents(controlCtx, batcher, runID, events)
	}()
	stop := func() {
		cancel()
		wg.Wait()
	}
	return events, stop
}

func blastSendControlEventBuffer(batcher packetBatcher) int {
	if batcher == nil || batcher.MaxBatch() <= 0 {
		return 1024
	}
	n := batcher.MaxBatch() * 32
	if n < 1024 {
		return 1024
	}
	return n
}

func readBlastSendControlEvents(ctx context.Context, batcher packetBatcher, runID [16]byte, events chan<- blastSendControlEvent) {
	if batcher == nil {
		return
	}
	readBufs := make([]batchReadBuffer, batcher.MaxBatch())
	for i := range readBufs {
		readBufs[i].Bytes = make([]byte, 64<<10)
	}
	for {
		n, err := batcher.ReadBatch(ctx, blastRepairInterval, readBufs)
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
				case events <- blastSendControlEvent{err: err, receivedAt: now}:
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
				eventPayload := append([]byte(nil), payload...)
				select {
				case events <- blastSendControlEvent{typ: packetType, stripe: stripeID, payload: eventPayload, receivedAt: now}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func drainBlastSendControlEvents(ctx context.Context, batcher packetBatcher, peer net.Addr, history *blastRepairHistory, stats *TransferStats, deduper *blastRepairDeduper, control *blastSendControl, events <-chan blastSendControlEvent) (bool, error) {
	complete := false
	for {
		select {
		case event := <-events:
			eventComplete, _, err := handleBlastSendControlEvent(ctx, batcher, peer, history, stats, deduper, control, event)
			if err != nil {
				return complete, err
			}
			complete = complete || eventComplete
		default:
			return complete, nil
		}
	}
}

func handleBlastSendControlEvent(ctx context.Context, batcher packetBatcher, peer net.Addr, history *blastRepairHistory, stats *TransferStats, deduper *blastRepairDeduper, control *blastSendControl, event blastSendControlEvent) (bool, bool, error) {
	if event.err != nil {
		return false, false, event.err
	}
	if event.receivedAt.IsZero() {
		event.receivedAt = time.Now()
	}
	switch event.typ {
	case PacketTypeRepairComplete:
		return true, false, nil
	case PacketTypeRepairRequest:
		if batcher == nil || stats == nil {
			return false, false, nil
		}
		retransmits, err := sendBlastRepairs(ctx, batcher, peer, history, event.payload, stats, deduper, event.receivedAt)
		if err != nil {
			return false, false, err
		}
		if control != nil && retransmits > 0 {
			control.ObserveRepairPressure(event.receivedAt, retransmits)
		}
		return false, true, nil
	case PacketTypeStats:
		if control != nil {
			sessionTracef("blast stats receive rx_payload_len=%d", len(event.payload))
			control.ObserveReceiverStats(event.payload, event.receivedAt)
		}
		if stats != nil {
			if receiverStats, ok := unmarshalBlastStatsPayload(event.payload); ok {
				stats.observePeakGoodput(event.receivedAt, int64(receiverStats.ReceivedPayloadBytes))
			}
		}
	}
	return false, false, nil
}

func observeStripedBlastStatsEvent(stats *TransferStats, history *blastRepairHistory, control *blastSendControl, event blastSendControlEvent) bool {
	if event.typ != PacketTypeStats {
		return false
	}
	receiverStats, ok := unmarshalBlastStatsPayload(event.payload)
	if !ok {
		return false
	}
	if history != nil {
		history.AckFloor(receiverStats.AckFloor)
		if stats != nil {
			stats.MaxReplayBytes = max(stats.MaxReplayBytes, history.MaxReplayBytes())
		}
	}
	if control != nil {
		control.ObserveReceiverStatsPayload(receiverStats, event.receivedAt, false)
	}
	if stats != nil {
		stats.observePeakGoodput(event.receivedAt, int64(receiverStats.ReceivedPayloadBytes))
	}
	return true
}
