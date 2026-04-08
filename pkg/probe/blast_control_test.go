package probe

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestReadBlastSendControlEventsEmitsReceiverStats(t *testing.T) {
	runID := [16]byte{1, 2, 3, 4}
	statsPacket, err := MarshalPacket(Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeStats,
		RunID:   runID,
		Payload: marshalBlastStatsPayload(blastReceiverStats{
			ReceivedPayloadBytes: 1234,
			ReceivedPackets:      5,
			MaxSeqPlusOne:        6,
		}),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherRunPacket, err := MarshalPacket(Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeStats,
		RunID:   [16]byte{9},
		Payload: marshalBlastStatsPayload(blastReceiverStats{
			ReceivedPayloadBytes: 9999,
		}),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	batcher := &queuedControlBatcher{packets: [][]byte{otherRunPacket, statsPacket}}
	events := make(chan blastSendControlEvent, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go readBlastSendControlEvents(ctx, batcher, runID, events)

	event := receiveBlastSendControlEventForTest(t, events)
	if event.typ != PacketTypeStats {
		t.Fatalf("event type = %d, want stats", event.typ)
	}
	got, ok := unmarshalBlastStatsPayload(event.payload)
	if !ok {
		t.Fatal("stats payload did not unmarshal")
	}
	if got.ReceivedPayloadBytes != 1234 || got.ReceivedPackets != 5 || got.MaxSeqPlusOne != 6 {
		t.Fatalf("stats = %+v, want receiver progress", got)
	}
}

func receiveBlastSendControlEventForTest(t *testing.T, events <-chan blastSendControlEvent) blastSendControlEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for blast send control event")
	}
	return blastSendControlEvent{}
}

type queuedControlBatcher struct {
	packets [][]byte
}

func (b *queuedControlBatcher) Capabilities() TransportCaps { return TransportCaps{} }
func (b *queuedControlBatcher) MaxBatch() int               { return 8 }

func (b *queuedControlBatcher) WriteBatch(context.Context, net.Addr, [][]byte) (int, error) {
	return 0, nil
}

func (b *queuedControlBatcher) ReadBatch(ctx context.Context, timeout time.Duration, bufs []batchReadBuffer) (int, error) {
	deadline := time.NewTimer(timeout)
	if timeout <= 0 {
		deadline.Stop()
	}
	for len(b.packets) == 0 {
		if timeout <= 0 {
			return 0, controlTestTimeoutError{}
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-deadline.C:
			return 0, controlTestTimeoutError{}
		}
	}
	if timeout > 0 {
		deadline.Stop()
	}
	n := 0
	for n < len(bufs) && len(b.packets) > 0 {
		packet := b.packets[0]
		b.packets = b.packets[1:]
		bufs[n].N = copy(bufs[n].Bytes, packet)
		bufs[n].Addr = controlTestAddr("control")
		n++
	}
	return n, nil
}

func TestHandleBlastSendControlEventUpdatesAdaptiveRate(t *testing.T) {
	now := time.Unix(10, 0)
	control := newBlastSendControl(100, 400, now)
	control.SetSentPayloadBytes(1_000_000)
	history, err := newBlastRepairHistory([16]byte{1}, defaultChunkSize, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	stats := TransferStats{}
	deduper := newBlastRepairDeduper()
	event := blastSendControlEvent{
		typ:        PacketTypeStats,
		payload:    marshalBlastStatsPayload(blastReceiverStats{ReceivedPayloadBytes: 1_000_000, ReceivedPackets: 100, MaxSeqPlusOne: 100}),
		receivedAt: now.Add(blastRateHoldAfterDecrease + blastRateFeedbackInterval),
	}

	complete, repaired, err := handleBlastSendControlEvent(context.Background(), nil, controlTestAddr("peer"), history, &stats, deduper, control, event)
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("stats event completed repair loop")
	}
	if repaired {
		t.Fatal("stats event reported a repair")
	}
	if got := control.RateMbps(); got <= 100 {
		t.Fatalf("rate = %d, want increase above 100", got)
	}
}

func TestReadBlastSendControlEventsEmitsRepairComplete(t *testing.T) {
	runID := [16]byte{5}
	repairComplete, err := MarshalPacket(Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeRepairComplete,
		RunID:   runID,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	batcher := &queuedControlBatcher{packets: [][]byte{repairComplete}}
	events := make(chan blastSendControlEvent, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go readBlastSendControlEvents(ctx, batcher, runID, events)

	event := receiveBlastSendControlEventForTest(t, events)
	if event.typ != PacketTypeRepairComplete {
		t.Fatalf("event type = %d, want repair complete", event.typ)
	}
	if len(event.payload) != 0 {
		t.Fatalf("repair complete payload = %q, want empty", event.payload)
	}
}

func TestDrainBlastSendControlEventsReportsRepairComplete(t *testing.T) {
	runID := [16]byte{6}
	history, err := newBlastRepairHistory(runID, defaultChunkSize, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	stats := TransferStats{}
	deduper := newBlastRepairDeduper()
	events := make(chan blastSendControlEvent, 1)
	events <- blastSendControlEvent{typ: PacketTypeRepairComplete, receivedAt: time.Now()}

	complete, err := drainBlastSendControlEvents(context.Background(), nil, controlTestAddr("peer"), history, &stats, deduper, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("drainBlastSendControlEvents() complete = false, want true")
	}
}

type controlTestAddr string

func (a controlTestAddr) Network() string { return "test" }
func (a controlTestAddr) String() string  { return string(a) }

type controlTestTimeoutError struct{}

func (controlTestTimeoutError) Error() string   { return "timeout" }
func (controlTestTimeoutError) Timeout() bool   { return true }
func (controlTestTimeoutError) Temporary() bool { return true }

func TestReadBlastSendControlEventsIgnoresDataPackets(t *testing.T) {
	runID := [16]byte{7}
	dataPacket, err := MarshalPacket(Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		RunID:   runID,
		Seq:     1,
		Payload: []byte("data"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	batcher := &queuedControlBatcher{packets: [][]byte{dataPacket}}
	events := make(chan blastSendControlEvent, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go readBlastSendControlEvents(ctx, batcher, runID, events)

	select {
	case event := <-events:
		t.Fatalf("unexpected event for data packet: %+v", event)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestQueuedControlBatcherCopiesPackets(t *testing.T) {
	packet := []byte("control packet")
	batcher := &queuedControlBatcher{packets: [][]byte{packet}}
	bufs := []batchReadBuffer{{Bytes: make([]byte, 64)}}
	n, err := batcher.ReadBatch(context.Background(), time.Second, bufs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("ReadBatch() = %d, want 1", n)
	}
	if !bytes.Equal(bufs[0].Bytes[:bufs[0].N], packet) {
		t.Fatalf("packet = %q, want %q", bufs[0].Bytes[:bufs[0].N], packet)
	}
}
