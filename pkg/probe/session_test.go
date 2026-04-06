package probe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testRunID(seed byte) [16]byte {
	var runID [16]byte
	runID[0] = seed
	return runID
}

func writeProbePacket(t *testing.T, conn net.PacketConn, dst net.Addr, packet Packet) {
	t.Helper()
	wire, err := MarshalPacket(packet, nil)
	if err != nil {
		t.Fatalf("MarshalPacket() error = %v", err)
	}
	if _, err := conn.WriteTo(wire, dst); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
}

func readProbePacket(t *testing.T, conn net.PacketConn, timeout time.Duration) Packet {
	t.Helper()
	buf := make([]byte, 64<<10)
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	packet, err := UnmarshalPacket(buf[:n], nil)
	if err != nil {
		t.Fatalf("UnmarshalPacket() error = %v", err)
	}
	return packet
}

func expectProbeTimeout(t *testing.T, conn net.PacketConn, timeout time.Duration) {
	t.Helper()
	buf := make([]byte, 64<<10)
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	_, _, err := conn.ReadFrom(buf)
	if err == nil {
		t.Fatal("ReadFrom() error = nil, want timeout")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("ReadFrom() error = %v, want timeout", err)
	}
}

func establishReceiveSession(t *testing.T, conn net.PacketConn, dst net.Addr, runID [16]byte) {
	t.Helper()
	writeProbePacket(t, conn, dst, Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeHello,
		RunID:   runID,
	})
	packet := readProbePacket(t, conn, 500*time.Millisecond)
	if packet.Type != PacketTypeHelloAck {
		t.Fatalf("packet type = %v, want HELLO_ACK", packet.Type)
	}
	if packet.RunID != runID {
		t.Fatalf("packet RunID = %x, want %x", packet.RunID, runID)
	}
}

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

func TestTransferStatsCaptureFirstByte(t *testing.T) {
	src := bytes.Repeat([]byte("derpcat"), 1<<12)
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

	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveToWriter(ctx, b, a.LocalAddr().String(), io.Discard, ReceiveConfig{Raw: true})
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	if _, err := Send(ctx, a, b.LocalAddr().String(), bytes.NewReader(src), SendConfig{Raw: true}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.FirstByteAt.IsZero() {
			t.Fatal("FirstByteAt is zero, want first byte timestamp")
		}
		if stats.CompletedAt.Before(stats.FirstByteAt) {
			t.Fatalf("CompletedAt = %v, want after FirstByteAt = %v", stats.CompletedAt, stats.FirstByteAt)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive stats: %v", ctx.Err())
	}
}

func TestEffectiveWindowSizeAllowsLargerThanAckMask(t *testing.T) {
	if got := effectiveWindowSize(4096); got != 4096 {
		t.Fatalf("effectiveWindowSize(4096) = %d, want 4096", got)
	}
	if got := effectiveWindowSize(0); got != defaultWindowSize {
		t.Fatalf("effectiveWindowSize(0) = %d, want defaultWindowSize=%d", got, defaultWindowSize)
	}
}

func TestBlastTransferCompletesAcrossLoopback(t *testing.T) {
	src := bytes.Repeat([]byte("blast"), 1<<15)
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

	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveToWriter(ctx, b, a.LocalAddr().String(), io.Discard, ReceiveConfig{Blast: true})
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	sendStats, err := Send(ctx, a, b.LocalAddr().String(), bytes.NewReader(src), SendConfig{Blast: true})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if sendStats.BytesSent != int64(len(src)) {
		t.Fatalf("BytesSent = %d, want %d", sendStats.BytesSent, len(src))
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for blast receive: %v", ctx.Err())
	}
}

func TestBlastTransferCompletesWhenFirstDonePacketIsDropped(t *testing.T) {
	src := bytes.Repeat([]byte("blast"), 1<<15)
	aBase, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer aBase.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	a := &dropFirstDoneConn{PacketConn: aBase}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveToWriter(ctx, b, a.LocalAddr().String(), io.Discard, ReceiveConfig{Blast: true})
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	sendStats, err := Send(ctx, a, b.LocalAddr().String(), bytes.NewReader(src), SendConfig{Blast: true})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if sendStats.BytesSent != int64(len(src)) {
		t.Fatalf("BytesSent = %d, want %d", sendStats.BytesSent, len(src))
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for blast receive after dropped DONE: %v", ctx.Err())
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

type dropFirstDoneConn struct {
	net.PacketConn

	mu      sync.Mutex
	dropped bool
}

func (d *dropFirstDoneConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	packet, err := UnmarshalPacket(p, nil)
	if err != nil {
		return 0, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.dropped && packet.Type == PacketTypeDone {
		d.dropped = true
		return len(p), nil
	}
	return d.PacketConn.WriteTo(p, addr)
}

type dropMatchingAckConn struct {
	net.PacketConn
	matchAckFloor uint64

	mu      sync.Mutex
	dropped bool
}

func (d *dropMatchingAckConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	packet, err := UnmarshalPacket(p, nil)
	if err != nil {
		return 0, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.dropped && packet.Type == PacketTypeAck && packet.AckFloor == d.matchAckFloor {
		d.dropped = true
		return len(p), nil
	}
	return d.PacketConn.WriteTo(p, addr)
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

	stats, err := Send(ctx, lossy, b.LocalAddr().String(), bytes.NewReader(src), SendConfig{Raw: true, ChunkSize: 1200})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if stats.Retransmits == 0 {
		t.Fatal("Send() retransmits = 0, want retransmits on lossy path")
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

func TestTransferSurvivesDroppedFinalAck(t *testing.T) {
	src := bytes.Repeat([]byte("final-ack"), 256)
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	bBase, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bBase.Close()

	b := &dropMatchingAckConn{PacketConn: bBase, matchAckFloor: 2}
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

	if _, err := Send(ctx, a, b.LocalAddr().String(), bytes.NewReader(src), SendConfig{Raw: true, ChunkSize: 1200, WindowSize: 2}); err != nil {
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
		writeProbePacket(t, a, b.LocalAddr(), Packet{
			Version: ProtocolVersion,
			Type:    kind,
			RunID:   testRunID(1),
			Seq:     seq,
			Payload: payload,
		})
	}

	readAck := func() Packet {
		t.Helper()
		packet := readProbePacket(t, a, 500*time.Millisecond)
		if packet.Type != PacketTypeAck {
			t.Fatalf("packet type = %v, want ACK", packet.Type)
		}
		if packet.RunID != testRunID(1) {
			t.Fatalf("ack RunID = %x, want %x", packet.RunID, testRunID(1))
		}
		return packet
	}

	establishReceiveSession(t, a, b.LocalAddr(), testRunID(1))

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

	establishReceiveSession(t, a, b.LocalAddr(), testRunID(2))
	writeProbePacket(t, a, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		RunID:   testRunID(2),
		Seq:     64,
		Payload: []byte("z"),
	})

	ack := readProbePacket(t, a, 500*time.Millisecond)
	if ack.AckFloor != 0 {
		t.Fatalf("AckFloor = %d, want 0", ack.AckFloor)
	}
	if ack.AckMask != uint64(1)<<63 {
		t.Fatalf("AckMask = %064b, want %064b", ack.AckMask, uint64(1)<<63)
	}
	if ack.RunID != testRunID(2) {
		t.Fatalf("ack RunID = %x, want %x", ack.RunID, testRunID(2))
	}

	cancel()
	if err := <-errs; !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Receive() error = %v, want context cancellation", err)
	}
}

func TestReceiveIgnoresStaleFirstPacketBeforeHello(t *testing.T) {
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

	writeProbePacket(t, a, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		RunID:   testRunID(7),
		Seq:     0,
		Payload: []byte("stale"),
	})
	expectProbeTimeout(t, a, 100*time.Millisecond)

	establishReceiveSession(t, a, b.LocalAddr(), testRunID(8))
	writeProbePacket(t, a, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		RunID:   testRunID(8),
		Seq:     0,
		Payload: []byte("fresh"),
	})
	packet := readProbePacket(t, a, 500*time.Millisecond)
	if packet.Type != PacketTypeAck || packet.RunID != testRunID(8) {
		t.Fatalf("ack = %#v, want ACK for established run", packet)
	}
	writeProbePacket(t, a, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeDone,
		RunID:   testRunID(8),
		Seq:     1,
	})
	_ = readProbePacket(t, a, 500*time.Millisecond)

	select {
	case err := <-errs:
		t.Fatalf("Receive() error = %v", err)
	case got := <-done:
		if !bytes.Equal(got, []byte("fresh")) {
			t.Fatalf("payload = %q, want %q", got, []byte("fresh"))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}

func TestReceiveIgnoresStaleDoneBeforeHello(t *testing.T) {
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

	writeProbePacket(t, a, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeDone,
		RunID:   testRunID(11),
		Seq:     0,
	})
	expectProbeTimeout(t, a, 100*time.Millisecond)

	establishReceiveSession(t, a, b.LocalAddr(), testRunID(12))
	writeProbePacket(t, a, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		RunID:   testRunID(12),
		Seq:     0,
		Payload: []byte("ok"),
	})
	_ = readProbePacket(t, a, 500*time.Millisecond)
	writeProbePacket(t, a, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeDone,
		RunID:   testRunID(12),
		Seq:     1,
	})
	_ = readProbePacket(t, a, 500*time.Millisecond)

	select {
	case err := <-errs:
		t.Fatalf("Receive() error = %v", err)
	case got := <-done:
		if !bytes.Equal(got, []byte("ok")) {
			t.Fatalf("payload = %q, want %q", got, []byte("ok"))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
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

type countingZeroReader struct {
	releaseAt time.Time
	chunk     []byte
	calls     atomic.Int64
	delivered atomic.Bool
}

func (r *countingZeroReader) Read(p []byte) (int, error) {
	r.calls.Add(1)
	if time.Now().Before(r.releaseAt) {
		return 0, nil
	}
	if !r.delivered.CompareAndSwap(false, true) {
		return 0, io.EOF
	}
	n := copy(p, r.chunk)
	return n, io.EOF
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
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
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

func TestReceiveCoalescesRawAcks(t *testing.T) {
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

	receiverConn := &countingPacketConn{PacketConn: b}
	chunkSize := 256
	packetCount := delayedAckPackets * 4
	payload := bytes.Repeat([]byte("a"), chunkSize*packetCount)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := Receive(ctx, receiverConn, "", ReceiveConfig{Raw: true})
		errCh <- err
	}()

	if _, err := Send(ctx, a, b.LocalAddr().String(), bytes.NewReader(payload), SendConfig{
		Raw:        true,
		ChunkSize:  chunkSize,
		WindowSize: defaultWindowSize,
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Receive() error = %v", err)
	}

	receiverConn.mu.Lock()
	writes := receiverConn.writes
	receiverConn.mu.Unlock()
	if writes >= packetCount {
		t.Fatalf("receiver ack writes = %d, want fewer than data packets %d", writes, packetCount)
	}
}

func TestSessionRetryIntervalClampsToRTT(t *testing.T) {
	if got := sessionRetryInterval(0); got != minRetryInterval {
		t.Fatalf("sessionRetryInterval(0) = %v, want %v", got, minRetryInterval)
	}
	if got := sessionRetryInterval(5 * time.Millisecond); got != minRetryInterval {
		t.Fatalf("sessionRetryInterval(5ms) = %v, want %v", got, minRetryInterval)
	}
	if got := sessionRetryInterval(30 * time.Millisecond); got != 120*time.Millisecond {
		t.Fatalf("sessionRetryInterval(30ms) = %v, want %v", got, 120*time.Millisecond)
	}
	if got := sessionRetryInterval(200 * time.Millisecond); got != maxRetryInterval {
		t.Fatalf("sessionRetryInterval(200ms) = %v, want %v", got, maxRetryInterval)
	}
}

func TestSendBacksOffRepeatedZeroProgressReads(t *testing.T) {
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

	reader := &countingZeroReader{
		releaseAt: time.Now().Add(8 * time.Millisecond),
		chunk:     bytes.Repeat([]byte("zero-backoff"), 80),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
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

	if _, err := Send(ctx, a, b.LocalAddr().String(), reader, SendConfig{Raw: true, ChunkSize: len(reader.chunk), WindowSize: 2}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if calls := reader.calls.Load(); calls > 50 {
		t.Fatalf("zero-progress Read calls = %d, want bounded retries", calls)
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

func TestReceiveToWriterStreamsPayload(t *testing.T) {
	src := bytes.Repeat([]byte("stream-writer"), 1<<14)
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

	var got bytes.Buffer
	statsCh := make(chan TransferStats, 1)
	errs := make(chan error, 1)
	go func() {
		stats, err := ReceiveToWriter(ctx, b, a.LocalAddr().String(), &got, ReceiveConfig{Raw: true})
		if err != nil {
			errs <- err
			return
		}
		statsCh <- stats
	}()

	sendStats, err := Send(ctx, a, b.LocalAddr().String(), bytes.NewReader(src), SendConfig{Raw: true, ChunkSize: 1200, WindowSize: 4})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if sendStats.BytesSent != int64(len(src)) {
		t.Fatalf("BytesSent = %d, want %d", sendStats.BytesSent, len(src))
	}

	select {
	case err := <-errs:
		t.Fatalf("ReceiveToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
		if stats.FirstByteAt.IsZero() {
			t.Fatal("FirstByteAt is zero, want first-byte timing")
		}
		if stats.CompletedAt.Before(stats.FirstByteAt) {
			t.Fatalf("CompletedAt = %v before FirstByteAt = %v", stats.CompletedAt, stats.FirstByteAt)
		}
		if !bytes.Equal(got.Bytes(), src) {
			t.Fatal("received payload mismatch")
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for ReceiveToWriter: %v", ctx.Err())
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

func TestSendIgnoresAckWithWrongRunID(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	conn := &countingPacketConn{PacketConn: a}
	src := bytes.NewReader(bytes.Repeat([]byte("wrong-ack"), 100))

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64<<10)
		var runID [16]byte
		for {
			if err := b.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
				done <- err
				return
			}
			n, addr, err := b.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
					done <- nil
					return
				}
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					if ctx.Err() != nil {
						done <- nil
						return
					}
					continue
				}
				done <- err
				return
			}
			packet, err := UnmarshalPacket(buf[:n], nil)
			if err != nil {
				done <- err
				return
			}
			if isZeroRunID(runID) {
				runID = packet.RunID
				if isZeroRunID(runID) {
					done <- errors.New("sender used zero RunID")
					return
				}
			}
			switch packet.Type {
			case PacketTypeHello:
				ack, err := MarshalPacket(Packet{
					Version: ProtocolVersion,
					Type:    PacketTypeHelloAck,
					RunID:   runID,
				}, nil)
				if err != nil {
					done <- err
					return
				}
				if _, err := b.WriteTo(ack, addr); err != nil {
					done <- err
					return
				}
			case PacketTypeData, PacketTypeDone:
				badRunID := runID
				badRunID[15] ^= 0xff
				ack, err := MarshalPacket(Packet{
					Version:  ProtocolVersion,
					Type:     PacketTypeAck,
					RunID:    badRunID,
					AckFloor: math.MaxUint64,
				}, nil)
				if err != nil {
					done <- err
					return
				}
				if _, err := b.WriteTo(ack, addr); err != nil {
					done <- err
					return
				}
			}
		}
	}()

	if _, err := Send(ctx, conn, b.LocalAddr().String(), src, SendConfig{Raw: true, ChunkSize: 1200, WindowSize: 2}); err == nil || (!errors.Is(err, context.DeadlineExceeded) && !isNetTimeout(err)) {
		t.Fatalf("Send() error = %v, want timeout", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("spoof ACK loop error = %v", err)
	}
}

func TestSendIgnoresImpossibleAckRange(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	src := bytes.NewReader(bytes.Repeat([]byte("impossible-ack"), 100))
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64<<10)
		var runID [16]byte
		for {
			if err := b.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
				done <- err
				return
			}
			n, addr, err := b.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					done <- nil
					return
				}
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					continue
				}
				done <- err
				return
			}
			packet, err := UnmarshalPacket(buf[:n], nil)
			if err != nil {
				done <- err
				return
			}
			if isZeroRunID(runID) {
				runID = packet.RunID
			}
			switch packet.Type {
			case PacketTypeHello:
				writeProbePacket(t, b, addr, Packet{
					Version: ProtocolVersion,
					Type:    PacketTypeHelloAck,
					RunID:   runID,
				})
			case PacketTypeData, PacketTypeDone:
				writeProbePacket(t, b, addr, Packet{
					Version:  ProtocolVersion,
					Type:     PacketTypeAck,
					RunID:    runID,
					AckFloor: math.MaxUint64,
				})
			}
		}
	}()

	if _, err := Send(ctx, a, b.LocalAddr().String(), src, SendConfig{Raw: true, ChunkSize: 1200, WindowSize: 2}); err == nil || (!errors.Is(err, context.DeadlineExceeded) && !isNetTimeout(err)) {
		t.Fatalf("Send() error = %v, want timeout", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("peer loop error = %v", err)
	}
}

func TestReceiveIgnoresPacketsWithWrongRunIDAfterEstablishingSession(t *testing.T) {
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

	write := func(runID [16]byte, seq uint64, kind PacketType, payload []byte) {
		t.Helper()
		wire, err := MarshalPacket(Packet{
			Version: ProtocolVersion,
			Type:    kind,
			RunID:   runID,
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

	readAck := func(expectTimeout bool) Packet {
		t.Helper()
		buf := make([]byte, 64<<10)
		if err := a.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		n, _, err := a.ReadFrom(buf)
		if expectTimeout {
			if err == nil {
				t.Fatal("ReadFrom() error = nil, want timeout")
			}
			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				t.Fatalf("ReadFrom() error = %v, want timeout", err)
			}
			return Packet{}
		}
		if err != nil {
			t.Fatalf("ReadFrom() error = %v", err)
		}
		packet, err := UnmarshalPacket(buf[:n], nil)
		if err != nil {
			t.Fatalf("UnmarshalPacket() error = %v", err)
		}
		return packet
	}

	goodRunID := testRunID(9)
	badRunID := testRunID(10)

	establishReceiveSession(t, a, b.LocalAddr(), goodRunID)

	write(goodRunID, 0, PacketTypeData, []byte("a"))
	if ack := readAck(false); ack.RunID != goodRunID {
		t.Fatalf("ack RunID = %x, want %x", ack.RunID, goodRunID)
	}

	write(badRunID, 1, PacketTypeData, []byte("x"))
	_ = readAck(true)

	write(goodRunID, 1, PacketTypeDone, nil)
	if ack := readAck(false); ack.RunID != goodRunID {
		t.Fatalf("ack RunID = %x, want %x", ack.RunID, goodRunID)
	}

	select {
	case err := <-errs:
		t.Fatalf("Receive() error = %v", err)
	case got := <-done:
		if !bytes.Equal(got, []byte("a")) {
			t.Fatalf("payload = %q, want %q", got, []byte("a"))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}

func TestReceiveIgnoresMalformedPacketBeforeHello(t *testing.T) {
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

	if _, err := a.WriteTo([]byte{1, 2, 3}, b.LocalAddr()); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	expectProbeTimeout(t, a, 100*time.Millisecond)

	establishReceiveSession(t, a, b.LocalAddr(), testRunID(13))
	writeProbePacket(t, a, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		RunID:   testRunID(13),
		Seq:     0,
		Payload: []byte("ok"),
	})
	_ = readProbePacket(t, a, 500*time.Millisecond)
	writeProbePacket(t, a, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeDone,
		RunID:   testRunID(13),
		Seq:     1,
	})
	_ = readProbePacket(t, a, 500*time.Millisecond)

	select {
	case err := <-errs:
		t.Fatalf("Receive() error = %v", err)
	case got := <-done:
		if !bytes.Equal(got, []byte("ok")) {
			t.Fatalf("payload = %q, want %q", got, []byte("ok"))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}

func TestSendIgnoresMalformedPacketDuringHandshake(t *testing.T) {
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

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64<<10)
		var runID [16]byte
		for {
			if err := b.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
				done <- err
				return
			}
			n, addr, err := b.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					done <- nil
					return
				}
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					continue
				}
				done <- err
				return
			}
			packet, err := UnmarshalPacket(buf[:n], nil)
			if err != nil {
				done <- err
				return
			}
			if packet.Type == PacketTypeHello {
				runID = packet.RunID
				if _, err := b.WriteTo([]byte{1, 2, 3}, addr); err != nil {
					done <- err
					return
				}
				writeProbePacket(t, b, addr, Packet{
					Version: ProtocolVersion,
					Type:    PacketTypeHelloAck,
					RunID:   runID,
				})
				continue
			}
			if packet.RunID != runID {
				continue
			}
			switch packet.Type {
			case PacketTypeData, PacketTypeDone:
				writeProbePacket(t, b, addr, Packet{
					Version:  ProtocolVersion,
					Type:     PacketTypeAck,
					RunID:    runID,
					AckFloor: packet.Seq + 1,
				})
				if packet.Type == PacketTypeDone {
					done <- nil
					return
				}
			}
		}
	}()

	if _, err := Send(ctx, a, b.LocalAddr().String(), bytes.NewReader([]byte("ok")), SendConfig{Raw: true, ChunkSize: 1200, WindowSize: 1}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("peer loop error = %v", err)
	}
}

func TestReceivePinsPeerAfterHello(t *testing.T) {
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	intruder, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer intruder.Close()

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
		got, err := Receive(ctx, b, "", ReceiveConfig{Raw: true})
		if err != nil {
			errs <- err
			return
		}
		done <- got
	}()

	runID := testRunID(14)
	establishReceiveSession(t, a, b.LocalAddr(), runID)

	writeProbePacket(t, intruder, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		RunID:   runID,
		Seq:     0,
		Payload: []byte("bad"),
	})
	expectProbeTimeout(t, intruder, 100*time.Millisecond)

	writeProbePacket(t, a, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		RunID:   runID,
		Seq:     0,
		Payload: []byte("good"),
	})
	_ = readProbePacket(t, a, 500*time.Millisecond)
	writeProbePacket(t, a, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeDone,
		RunID:   runID,
		Seq:     1,
	})
	_ = readProbePacket(t, a, 500*time.Millisecond)

	select {
	case err := <-errs:
		t.Fatalf("Receive() error = %v", err)
	case got := <-done:
		if !bytes.Equal(got, []byte("good")) {
			t.Fatalf("payload = %q, want %q", got, []byte("good"))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}

func TestReceiveRequiresExpectedRunIDForHello(t *testing.T) {
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	bad, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	expectedRunID := testRunID(15)
	done := make(chan []byte, 1)
	errs := make(chan error, 1)
	go func() {
		got, err := Receive(ctx, b, "", ReceiveConfig{Raw: true, ExpectedRunID: expectedRunID})
		if err != nil {
			errs <- err
			return
		}
		done <- got
	}()

	writeProbePacket(t, bad, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeHello,
		RunID:   testRunID(16),
	})
	expectProbeTimeout(t, bad, 100*time.Millisecond)

	establishReceiveSession(t, a, b.LocalAddr(), expectedRunID)

	writeProbePacket(t, a, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		RunID:   expectedRunID,
		Seq:     0,
		Payload: []byte("ok"),
	})
	_ = readProbePacket(t, a, 500*time.Millisecond)
	writeProbePacket(t, a, b.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeDone,
		RunID:   expectedRunID,
		Seq:     1,
	})
	_ = readProbePacket(t, a, 500*time.Millisecond)

	select {
	case err := <-errs:
		t.Fatalf("Receive() error = %v", err)
	case got := <-done:
		if !bytes.Equal(got, []byte("ok")) {
			t.Fatalf("payload = %q, want %q", got, []byte("ok"))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}

func TestTransferCompletesWithConfiguredRunID(t *testing.T) {
	src := bytes.Repeat([]byte("configured-run-id"), 256)
	runID := testRunID(17)

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

	done := make(chan []byte, 1)
	errs := make(chan error, 1)
	go func() {
		got, err := Receive(ctx, b, "", ReceiveConfig{Raw: true, ExpectedRunID: runID})
		if err != nil {
			errs <- err
			return
		}
		done <- got
	}()

	stats, err := Send(ctx, a, b.LocalAddr().String(), bytes.NewReader(src), SendConfig{
		Raw:        true,
		ChunkSize:  1200,
		WindowSize: 4,
		RunID:      runID,
	})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if stats.BytesSent != int64(len(src)) {
		t.Fatalf("BytesSent = %d, want %d", stats.BytesSent, len(src))
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
