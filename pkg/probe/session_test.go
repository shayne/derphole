package probe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestTransferCompletesAcrossLoopback(t *testing.T) {
	src := bytes.Repeat([]byte("derpcat"), 1<<17)
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := Receive(ctx, b, a.LocalAddr().String(), ReceiveConfig{Raw: true})
		done <- err
	}()

	stats, err := Send(ctx, a, b.LocalAddr().String(), bytes.NewReader(src), SendConfig{Raw: true})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if stats.BytesSent != int64(len(src)) {
		t.Fatalf("BytesSent = %d, want %d", stats.BytesSent, len(src))
	}
	if err := <-done; err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
}

type lossyPacketConn struct {
	net.PacketConn
	dropEvery int

	mu     sync.Mutex
	writes int
}

func (l *lossyPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	l.mu.Lock()
	l.writes++
	writeNum := l.writes
	l.mu.Unlock()

	if l.dropEvery > 0 && writeNum%l.dropEvery == 0 {
		return len(p), nil
	}
	return l.PacketConn.WriteTo(p, addr)
}

func TestTransferSurvivesDroppedPackets(t *testing.T) {
	src := bytes.Repeat([]byte("udp-proof"), 1<<16)
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	lossy := &lossyPacketConn{PacketConn: a, dropEvery: 7}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan []byte, 1)
	errs := make(chan error, 1)
	go func() {
		got, err := Receive(ctx, b, "", ReceiveConfig{Raw: true})
		if err != nil {
			errs <- err
			return
		}
		done <- got
	}()

	if _, err := Send(ctx, lossy, b.LocalAddr().String(), bytes.NewReader(src), SendConfig{Raw: true, ChunkSize: 1200}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case err := <-errs:
		t.Fatalf("Receive() error = %v", err)
	case got := <-done:
		if !bytes.Equal(got, src) {
			t.Fatal("received payload mismatch")
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}

type reorderPacketConn struct {
	net.PacketConn

	mu         sync.Mutex
	heldPacket []byte
	heldAddr   net.Addr
	reordered  bool
}

func (r *reorderPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	packet, err := UnmarshalPacket(p, nil)
	if err != nil {
		return 0, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.reordered && packet.Type == PacketTypeData {
		switch packet.Seq {
		case 0:
			r.heldPacket = append([]byte(nil), p...)
			r.heldAddr = addr
			return len(p), nil
		case 1:
			r.reordered = true
			if _, err := r.PacketConn.WriteTo(p, addr); err != nil {
				return 0, err
			}
			if _, err := r.PacketConn.WriteTo(r.heldPacket, r.heldAddr); err != nil {
				return 0, err
			}
			r.heldPacket = nil
			r.heldAddr = nil
			return len(p), nil
		}
	}

	return r.PacketConn.WriteTo(p, addr)
}

func TestReceiveAckSignalsOutOfOrderPackets(t *testing.T) {
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan []byte, 1)
	errs := make(chan error, 1)
	go func() {
		got, err := Receive(ctx, b, a.LocalAddr().String(), ReceiveConfig{Raw: true})
		if err != nil {
			errs <- err
			return
		}
		done <- got
	}()

	writePacket := func(seq uint64, kind PacketType, payload []byte) {
		t.Helper()
		wire, err := MarshalPacket(Packet{
			Version: ProtocolVersion,
			Type:    kind,
			Seq:     seq,
			Payload: payload,
		}, nil)
		if err != nil {
			t.Fatalf("MarshalPacket() error = %v", err)
		}
		if _, err := a.WriteTo(wire, b.LocalAddr()); err != nil {
			t.Fatalf("WriteTo() error = %v", err)
		}
	}

	readAck := func() Packet {
		t.Helper()
		buf := make([]byte, 64<<10)
		if err := a.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		n, _, err := a.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom() error = %v", err)
		}
		packet, err := UnmarshalPacket(buf[:n], nil)
		if err != nil {
			t.Fatalf("UnmarshalPacket() error = %v", err)
		}
		if packet.Type != PacketTypeAck {
			t.Fatalf("packet type = %v, want ACK", packet.Type)
		}
		return packet
	}

	writePacket(1, PacketTypeData, []byte("b"))
	ack := readAck()
	if ack.AckFloor != 0 {
		t.Fatalf("AckFloor after out-of-order packet = %d, want 0", ack.AckFloor)
	}
	if ack.AckMask != 1 {
		t.Fatalf("AckMask after out-of-order packet = %064b, want %064b", ack.AckMask, uint64(1))
	}

	writePacket(0, PacketTypeData, []byte("a"))
	ack = readAck()
	if ack.AckFloor != 2 {
		t.Fatalf("AckFloor after filling gap = %d, want 2", ack.AckFloor)
	}
	if ack.AckMask != 0 {
		t.Fatalf("AckMask after filling gap = %064b, want 0", ack.AckMask)
	}

	writePacket(2, PacketTypeDone, nil)
	ack = readAck()
	if ack.AckFloor != 3 {
		t.Fatalf("AckFloor after done = %d, want 3", ack.AckFloor)
	}

	select {
	case err := <-errs:
		t.Fatalf("Receive() error = %v", err)
	case got := <-done:
		if !bytes.Equal(got, []byte("ab")) {
			t.Fatalf("payload = %q, want %q", got, []byte("ab"))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}

func TestReceiveAckSignalsAckMaskBoundaryAtPlus64(t *testing.T) {
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errs := make(chan error, 1)
	go func() {
		_, err := Receive(ctx, b, a.LocalAddr().String(), ReceiveConfig{Raw: true})
		errs <- err
	}()

	wire, err := MarshalPacket(Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		Seq:     64,
		Payload: []byte("z"),
	}, nil)
	if err != nil {
		t.Fatalf("MarshalPacket() error = %v", err)
	}
	if _, err := a.WriteTo(wire, b.LocalAddr()); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	buf := make([]byte, 64<<10)
	if err := a.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	n, _, err := a.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	ack, err := UnmarshalPacket(buf[:n], nil)
	if err != nil {
		t.Fatalf("UnmarshalPacket() error = %v", err)
	}
	if ack.AckFloor != 0 {
		t.Fatalf("AckFloor = %d, want 0", ack.AckFloor)
	}
	if ack.AckMask != uint64(1)<<63 {
		t.Fatalf("AckMask = %064b, want %064b", ack.AckMask, uint64(1)<<63)
	}

	cancel()
	if err := <-errs; !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Receive() error = %v, want context cancellation", err)
	}
}

var errReaderBoom = errors.New("synthetic reader failure")

type errAfterReader struct {
	chunk   []byte
	okReads int
	reads   int
}

func (r *errAfterReader) Read(p []byte) (int, error) {
	if r.reads >= r.okReads {
		return 0, errReaderBoom
	}

	n := copy(p, r.chunk)
	r.reads++
	return n, nil
}

type zeroThenDataReader struct {
	chunk []byte
	zeros int
}

func (r *zeroThenDataReader) Read(p []byte) (int, error) {
	if r.zeros > 0 {
		r.zeros--
		return 0, nil
	}
	n := copy(p, r.chunk)
	return n, io.EOF
}

type finalChunkErrorReader struct {
	chunk []byte
	stage int
}

func (r *finalChunkErrorReader) Read(p []byte) (int, error) {
	switch r.stage {
	case 0:
		r.stage++
		n := copy(p, r.chunk)
		return n, errReaderBoom
	default:
		return 0, io.EOF
	}
}

type sackSelectiveRetransmitConn struct {
	net.PacketConn

	mu          sync.Mutex
	droppedBase bool
	writeCounts map[uint64]int
}

func newSackSelectiveRetransmitConn(conn net.PacketConn) *sackSelectiveRetransmitConn {
	return &sackSelectiveRetransmitConn{
		PacketConn:  conn,
		writeCounts: make(map[uint64]int),
	}
}

func (c *sackSelectiveRetransmitConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	packet, err := UnmarshalPacket(p, nil)
	if err != nil {
		return 0, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if packet.Type == PacketTypeData || packet.Type == PacketTypeDone {
		c.writeCounts[packet.Seq]++
		if packet.Type == PacketTypeData && packet.Seq == 0 && !c.droppedBase {
			c.droppedBase = true
			return len(p), nil
		}
	}
	return c.PacketConn.WriteTo(p, addr)
}

type countingPacketConn struct {
	net.PacketConn

	mu     sync.Mutex
	writes int
}

func (c *countingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.writes++
	c.mu.Unlock()
	return c.PacketConn.WriteTo(p, addr)
}

func TestSendStreamsBeforeSourceEOF(t *testing.T) {
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	conn := &countingPacketConn{PacketConn: a}
	reader := &errAfterReader{
		chunk:   bytes.Repeat([]byte("stream-first"), 100),
		okReads: 2,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errs := make(chan error, 1)
	go func() {
		_, err := Receive(ctx, b, "", ReceiveConfig{Raw: true})
		errs <- err
	}()

	_, err = Send(ctx, conn, b.LocalAddr().String(), reader, SendConfig{Raw: true, ChunkSize: len(reader.chunk), WindowSize: 4})
	if !errors.Is(err, errReaderBoom) {
		t.Fatalf("Send() error = %v, want %v", err, errReaderBoom)
	}

	conn.mu.Lock()
	writes := conn.writes
	conn.mu.Unlock()
	if writes == 0 {
		t.Fatal("sender wrote 0 packets before reader failure, want streaming writes")
	}

	cancel()
	if err := <-errs; !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Receive() error = %v, want context cancellation", err)
	}
}

func TestSendRetriesAfterZeroProgressRead(t *testing.T) {
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	reader := &zeroThenDataReader{chunk: bytes.Repeat([]byte("zero-progress"), 80), zeros: 8}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan []byte, 1)
	errs := make(chan error, 1)
	go func() {
		got, err := Receive(ctx, b, "", ReceiveConfig{Raw: true})
		if err != nil {
			errs <- err
			return
		}
		done <- got
	}()

	stats, err := Send(ctx, a, b.LocalAddr().String(), reader, SendConfig{Raw: true, ChunkSize: len(reader.chunk), WindowSize: 2})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if stats.BytesSent != int64(len(reader.chunk)) {
		t.Fatalf("BytesSent = %d, want %d", stats.BytesSent, len(reader.chunk))
	}

	select {
	case err := <-errs:
		t.Fatalf("Receive() error = %v", err)
	case got := <-done:
		if !bytes.Equal(got, reader.chunk) {
			t.Fatal("received payload mismatch")
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}

func TestSendReturnsPartialReadErrorBeforeDone(t *testing.T) {
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	reader := &finalChunkErrorReader{chunk: bytes.Repeat([]byte("partial-fail"), 90)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errs := make(chan error, 1)
	go func() {
		_, err := Receive(ctx, b, "", ReceiveConfig{Raw: true})
		errs <- err
	}()

	_, err = Send(ctx, a, b.LocalAddr().String(), reader, SendConfig{Raw: true, ChunkSize: len(reader.chunk), WindowSize: 2})
	if !errors.Is(err, errReaderBoom) {
		t.Fatalf("Send() error = %v, want %v", err, errReaderBoom)
	}

	cancel()
	if err := <-errs; !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Receive() error = %v, want context cancellation", err)
	}
}

func TestSendUsesSelectiveRetransmitForMissingBasePacket(t *testing.T) {
	src := bytes.Repeat([]byte("sack-window"), 700)
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	conn := newSackSelectiveRetransmitConn(a)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan []byte, 1)
	errs := make(chan error, 1)
	go func() {
		got, err := Receive(ctx, b, "", ReceiveConfig{Raw: true})
		if err != nil {
			errs <- err
			return
		}
		done <- got
	}()

	if _, err := Send(ctx, conn, b.LocalAddr().String(), bytes.NewReader(src), SendConfig{Raw: true, ChunkSize: 1200, WindowSize: 4}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case err := <-errs:
		t.Fatalf("Receive() error = %v", err)
	case got := <-done:
		if !bytes.Equal(got, src) {
			t.Fatal("received payload mismatch")
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.writeCounts[0] < 2 {
		t.Fatalf("seq 0 writes = %d, want retransmit", conn.writeCounts[0])
	}
	for seq := uint64(1); seq < 4; seq++ {
		if conn.writeCounts[seq] != 1 {
			t.Fatalf("seq %d writes = %d, want 1 with SACK", seq, conn.writeCounts[seq])
		}
	}
}

func TestTransferSurvivesReorderedPackets(t *testing.T) {
	src := bytes.Repeat([]byte("reorder-proof"), 1<<15)
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	reordered := &reorderPacketConn{PacketConn: a}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan []byte, 1)
	errs := make(chan error, 1)
	go func() {
		got, err := Receive(ctx, b, "", ReceiveConfig{Raw: true})
		if err != nil {
			errs <- err
			return
		}
		done <- got
	}()

	if _, err := Send(ctx, reordered, b.LocalAddr().String(), bytes.NewReader(src), SendConfig{Raw: true, ChunkSize: 1200, WindowSize: 4}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case err := <-errs:
		t.Fatalf("Receive() error = %v", err)
	case got := <-done:
		if !bytes.Equal(got, src) {
			t.Fatal("received payload mismatch")
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}
