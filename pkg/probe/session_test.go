package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

type notifyingWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	wrote chan struct{}
}

func (w *notifyingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buf.Write(p)
	w.mu.Unlock()
	select {
	case w.wrote <- struct{}{}:
	default:
	}
	return n, err
}

type pacedReader struct {
	chunks [][]byte
	pause  time.Duration
	index  int
}

func (r *pacedReader) Read(p []byte) (int, error) {
	if r.index >= len(r.chunks) {
		return 0, io.EOF
	}
	if r.index > 0 && r.pause > 0 {
		time.Sleep(r.pause)
	}
	n := copy(p, r.chunks[r.index])
	r.index++
	return n, nil
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

func TestStripedRawTransferCompletesAcrossLoopback(t *testing.T) {
	src := bytes.Repeat([]byte("striped-raw"), 1<<14)
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
		got, err := Receive(ctx, b, a.LocalAddr().String(), ReceiveConfig{Raw: true})
		if err != nil {
			errs <- err
			return
		}
		done <- got
	}()

	stats, err := Send(ctx, a, b.LocalAddr().String(), bytes.NewReader(src), SendConfig{
		Raw:        true,
		ChunkSize:  512,
		WindowSize: 8,
		Parallel:   4,
	})
	if err != nil {
		select {
		case recvErr := <-errs:
			t.Fatalf("Send() error = %v; Receive() error = %v", err, recvErr)
		case got := <-done:
			t.Fatalf("Send() error = %v; Receive() completed with %d bytes", err, len(got))
		default:
		}
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
		t.Fatalf("timed out waiting for striped receive: %v", ctx.Err())
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

func TestTransferStatsCapturePeakGoodputAcrossLoopback(t *testing.T) {
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

	payload := [][]byte{
		bytes.Repeat([]byte("a"), 1024),
		bytes.Repeat([]byte("b"), 1024),
	}
	src := &pacedReader{chunks: payload, pause: 5 * time.Millisecond}

	recvStatsCh := make(chan TransferStats, 1)
	recvErrCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveToWriter(ctx, b, a.LocalAddr().String(), io.Discard, ReceiveConfig{Raw: true})
		if err != nil {
			recvErrCh <- err
			return
		}
		recvStatsCh <- stats
	}()

	sendStats, err := Send(ctx, a, b.LocalAddr().String(), src, SendConfig{
		Raw:       true,
		ChunkSize: 1024,
	})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if sendStats.BytesSent != 2*1024 {
		t.Fatalf("send BytesSent = %d, want %d", sendStats.BytesSent, 2*1024)
	}

	select {
	case err := <-recvErrCh:
		t.Fatalf("ReceiveToWriter() error = %v", err)
	case recvStats := <-recvStatsCh:
		if recvStats.PeakGoodputMbps <= 0 {
			t.Fatalf("receive PeakGoodputMbps = %f, want > 0", recvStats.PeakGoodputMbps)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive stats: %v", ctx.Err())
	}
}

func TestPeakTrackingWriterTracksAggregatePeak(t *testing.T) {
	started := time.Unix(300, 0)
	writer := newPeakTrackingWriter(io.Discard, started)
	times := []time.Time{
		started.Add(100 * time.Millisecond),
		started.Add(200 * time.Millisecond),
	}
	writer.now = func() time.Time {
		now := times[0]
		times = times[1:]
		return now
	}

	if _, err := writer.Write(bytes.Repeat([]byte("a"), 1024)); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	if _, err := writer.Write(bytes.Repeat([]byte("b"), 2048)); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}

	want := float64(2048*8) / 0.1 / 1_000_000
	if got := writer.PeakMbps(); !almostEqual(got, want) {
		t.Fatalf("PeakMbps() = %f, want %f", got, want)
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
	if !sendStats.Transport.Connected {
		t.Fatalf("send transport = %#v, want connected UDP fast path", sendStats.Transport)
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

func TestUDPAddrPortMatchesPeer(t *testing.T) {
	addrPort := netip.MustParseAddrPort("203.0.113.10:4242")
	peer := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 4242}
	if addrPort.Port() != uint16(peer.Port) {
		t.Fatalf("test setup port = %d, want %d", addrPort.Port(), peer.Port)
	}
	if !udpAddrPortMatchesPeer(addrPort, peer) {
		t.Fatal("udpAddrPortMatchesPeer() = false, want true")
	}
	if udpAddrPortMatchesPeer(addrPort, &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 4243}) {
		t.Fatal("udpAddrPortMatchesPeer() = true for different port, want false")
	}
	if udpAddrPortMatchesPeer(addrPort, &net.UDPAddr{IP: net.ParseIP("203.0.113.11"), Port: 4242}) {
		t.Fatal("udpAddrPortMatchesPeer() = true for different IP, want false")
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

func TestReceiveBlastParallelToWriterAggregatesReusePortFlows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverA, err := ListenPacketReusePort(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()

	serverB, err := ListenPacketReusePort(ctx, "udp4", serverA.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()

	clientA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	clientB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	srcA := bytes.Repeat([]byte("a"), 1<<15)
	srcB := bytes.Repeat([]byte("b"), 1<<15)
	total := int64(len(srcA) + len(srcB))
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, ReceiveConfig{Blast: true}, total)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := Send(ctx, clientA, serverA.LocalAddr().String(), bytes.NewReader(srcA), SendConfig{Blast: true}); err != nil {
			errCh <- err
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := Send(ctx, clientB, serverA.LocalAddr().String(), bytes.NewReader(srcB), SendConfig{Blast: true}); err != nil {
			errCh <- err
		}
	}()
	wg.Wait()

	select {
	case err := <-errCh:
		t.Fatalf("parallel blast error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != total {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, total)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for parallel blast receive: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterEchoesStripedHelloAckMetadata(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x5d)
	errCh := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{
			Blast:         true,
			ExpectedRunID: runID,
		}, 0)
		errCh <- err
	}()

	writeProbePacket(t, client, server.LocalAddr(), Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeHello,
		StripeID: 3,
		RunID:    runID,
		Seq:      4,
	})
	packet := readProbePacket(t, client, 500*time.Millisecond)
	if packet.Type != PacketTypeHelloAck {
		t.Fatalf("packet type = %v, want HELLO_ACK", packet.Type)
	}
	if packet.RunID != runID {
		t.Fatalf("packet RunID = %x, want %x", packet.RunID, runID)
	}
	if packet.StripeID != 3 {
		t.Fatalf("packet StripeID = %d, want 3", packet.StripeID)
	}
	if packet.Seq != 4 {
		t.Fatalf("packet Seq = %d, want total stripes 4", packet.Seq)
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for receiver to stop")
	}
}

func TestReceiveBlastParallelRequireCompleteExpectedBytesRejectsPartialIdle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x5e)
	payload := []byte("partial")
	errCh := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{
			Blast:           true,
			ExpectedRunID:   runID,
			RequireComplete: true,
		}, int64(len(payload)+1))
		errCh <- err
	}()

	establishReceiveSession(t, client, server.LocalAddr(), runID)
	writeProbePacket(t, client, server.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		RunID:   runID,
		Payload: payload,
	})

	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "blast incomplete") {
			t.Fatalf("ReceiveBlastParallelToWriter() error = %v, want blast incomplete", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for incomplete receive error")
	}
}

func TestBlastParallelStreamPreservesOrderAcrossLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()

	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()

	clientA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	clientB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	src := bytes.Repeat([]byte("ordered-parallel-blast-"), 1<<13)
	var got bytes.Buffer
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 2)
	runID := testRunID(0xa7)
	go func() {
		stats, err := ReceiveBlastStreamParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, &got, ReceiveConfig{
			Blast:           true,
			ExpectedRunID:   runID,
			RequireComplete: true,
		}, 0)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	sendStats, err := SendBlastParallel(ctx, []net.PacketConn{clientA, clientB}, []string{serverA.LocalAddr().String(), serverB.LocalAddr().String()}, bytes.NewReader(src), SendConfig{
		Blast:          true,
		ChunkSize:      512,
		RunID:          runID,
		RepairPayloads: true,
	})
	if err != nil {
		t.Fatalf("SendBlastParallel() error = %v", err)
	}
	if sendStats.BytesSent != int64(len(src)) {
		t.Fatalf("BytesSent = %d, want %d", sendStats.BytesSent, len(src))
	}

	select {
	case err := <-errCh:
		t.Fatalf("parallel ordered blast error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for ordered parallel blast: %v", ctx.Err())
	}
	if !bytes.Equal(got.Bytes(), src) {
		t.Fatalf("parallel ordered payload mismatch: got %d bytes, want %d", got.Len(), len(src))
	}
}

func TestBlastParallelStreamPreservesOrderWithStripedLanesAcrossLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()

	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()

	clientA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	clientB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	src := bytes.Repeat([]byte("striped-parallel-blast-"), 1<<13)
	var got bytes.Buffer
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 2)
	runID := testRunID(0xa8)
	go func() {
		stats, err := ReceiveBlastStreamParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, &got, ReceiveConfig{
			Blast:           true,
			ExpectedRunID:   runID,
			RequireComplete: true,
		}, 0)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	sendStats, err := SendBlastParallel(ctx, []net.PacketConn{clientA, clientB}, []string{serverA.LocalAddr().String(), serverB.LocalAddr().String()}, bytes.NewReader(src), SendConfig{
		Blast:          true,
		ChunkSize:      512,
		RunID:          runID,
		RepairPayloads: true,
		StripedBlast:   true,
	})
	if err != nil {
		t.Fatalf("SendBlastParallel() error = %v", err)
	}
	if sendStats.BytesSent != int64(len(src)) {
		t.Fatalf("BytesSent = %d, want %d", sendStats.BytesSent, len(src))
	}

	select {
	case err := <-errCh:
		t.Fatalf("parallel striped blast error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for striped parallel blast: %v", ctx.Err())
	}
	if !bytes.Equal(got.Bytes(), src) {
		t.Fatalf("parallel striped payload mismatch: got %d bytes, want %d", got.Len(), len(src))
	}
}

func TestSendBlastParallelSkipsUnreachableOptionalLane(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()

	senderA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderA.Close()

	senderB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderB.Close()

	payload := bytes.Repeat([]byte("optional-lane-"), 4096)
	var got bytes.Buffer
	receiveErr := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastStreamParallelToWriter(ctx, []net.PacketConn{receiver}, &got, ReceiveConfig{
			Blast:           true,
			Transport:       "legacy",
			RequireComplete: true,
		}, int64(len(payload)))
		receiveErr <- err
	}()

	stats, err := SendBlastParallel(ctx, []net.PacketConn{senderA, senderB}, []string{
		receiver.LocalAddr().String(),
		"127.0.0.1:1",
	}, bytes.NewReader(payload), SendConfig{
		Blast:                    true,
		Transport:                "legacy",
		ChunkSize:                512,
		AllowPartialParallel:     true,
		ParallelHandshakeTimeout: 50 * time.Millisecond,
		StripedBlast:             true,
	})
	if err != nil {
		t.Fatalf("SendBlastParallel() error = %v", err)
	}
	if stats.BytesSent != int64(len(payload)) {
		t.Fatalf("BytesSent = %d, want %d", stats.BytesSent, len(payload))
	}

	select {
	case err := <-receiveErr:
		if err != nil {
			t.Fatalf("ReceiveBlastStreamParallelToWriter() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("payload mismatch after optional-lane skip")
	}
}

func TestSendBlastParallelRetriesTransientNoBufferSpaceDuringStripedRehandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()

	senderABase, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderABase.Close()

	senderA := &failWriteOnNthPacketConn{
		PacketConn: senderABase,
		failAt:     2,
		failErr:    syscall.ENOBUFS,
	}

	senderB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderB.Close()

	payload := bytes.Repeat([]byte("optional-lane-rehandshake-"), 4096)
	var got bytes.Buffer
	receiveErr := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastStreamParallelToWriter(ctx, []net.PacketConn{receiver}, &got, ReceiveConfig{
			Blast:           true,
			Transport:       "legacy",
			RequireComplete: true,
		}, int64(len(payload)))
		receiveErr <- err
	}()

	stats, err := SendBlastParallel(ctx, []net.PacketConn{senderA, senderB}, []string{
		receiver.LocalAddr().String(),
		"127.0.0.1:1",
	}, bytes.NewReader(payload), SendConfig{
		Blast:                    true,
		Transport:                "legacy",
		ChunkSize:                512,
		AllowPartialParallel:     true,
		ParallelHandshakeTimeout: 50 * time.Millisecond,
		StripedBlast:             true,
	})
	if err != nil {
		t.Fatalf("SendBlastParallel() error = %v", err)
	}
	if stats.BytesSent != int64(len(payload)) {
		t.Fatalf("BytesSent = %d, want %d", stats.BytesSent, len(payload))
	}

	select {
	case err := <-receiveErr:
		if err != nil {
			t.Fatalf("ReceiveBlastStreamParallelToWriter() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("payload mismatch after transient striped rehandshake ENOBUFS")
	}
}

func TestWriteOrderedParallelBlastPayloadTracksOrderForDiscard(t *testing.T) {
	state := newBlastReceiveRunState(nil)
	var writeMu sync.Mutex

	written, err := writeOrderedParallelBlastPayload(io.Discard, state, 1, []byte("bb"), &writeMu)
	if err != nil {
		t.Fatalf("writeOrderedParallelBlastPayload() error = %v", err)
	}
	if written != 0 {
		t.Fatalf("out-of-order discard write = %d, want 0", written)
	}
	if state.nextWriteSeq != 0 {
		t.Fatalf("nextWriteSeq after out-of-order discard = %d, want 0", state.nextWriteSeq)
	}

	written, err = writeOrderedParallelBlastPayload(io.Discard, state, 0, []byte("aa"), &writeMu)
	if err != nil {
		t.Fatalf("writeOrderedParallelBlastPayload() in-order error = %v", err)
	}
	if written != 4 {
		t.Fatalf("in-order discard write = %d, want 4", written)
	}
	if state.nextWriteSeq != 2 {
		t.Fatalf("nextWriteSeq after discard flush = %d, want 2", state.nextWriteSeq)
	}
}

func TestBlastStreamReceiveCoordinatorWritesOrderedAcrossLanes(t *testing.T) {
	runID := testRunID(0xb3)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	lanes := []*blastStreamReceiveLane{
		{batcher: &capturingBatcher{}, peer: peer},
		{batcher: &capturingBatcher{}, peer: peer},
	}
	var got bytes.Buffer
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), lanes, &got, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
	}, 0, time.Now())

	complete, err := coordinator.handlePacket(context.Background(), lanes[1], PacketTypeData, runID, 1, 2, 0, []byte("bb"), peer)
	if err != nil {
		t.Fatalf("handlePacket(seq=1) error = %v", err)
	}
	if complete {
		t.Fatal("handlePacket(seq=1) complete = true, want false")
	}
	if got.Len() != 0 {
		t.Fatalf("buffer after out-of-order packet = %q, want empty", got.String())
	}

	complete, err = coordinator.handlePacket(context.Background(), lanes[0], PacketTypeData, runID, 0, 0, 0, []byte("aa"), peer)
	if err != nil {
		t.Fatalf("handlePacket(seq=0) error = %v", err)
	}
	if complete {
		t.Fatal("handlePacket(seq=0) complete = true before DONE")
	}

	complete, err = coordinator.handlePacket(context.Background(), lanes[0], PacketTypeDone, runID, 2, 4, 0, nil, peer)
	if err != nil {
		t.Fatalf("handlePacket(DONE) error = %v", err)
	}
	if !complete {
		t.Fatal("handlePacket(DONE) complete = false, want true")
	}
	if got.String() != "aabb" {
		t.Fatalf("ordered payload = %q, want aabb", got.String())
	}
}

func TestBlastStreamReceiveCoordinatorSpoolsOrderedOutputUntilComplete(t *testing.T) {
	runID := testRunID(0xba)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	lanes := []*blastStreamReceiveLane{
		{batcher: &capturingBatcher{}, peer: peer},
		{batcher: &capturingBatcher{}, peer: peer},
	}
	var got bytes.Buffer
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), lanes, &got, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
		SpoolOutput:     true,
	}, 0, time.Now())

	if complete, err := coordinator.handlePacket(context.Background(), lanes[1], PacketTypeData, runID, 1, 2, 0, []byte("bb"), peer); err != nil || complete {
		t.Fatalf("handlePacket(seq=1) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacket(context.Background(), lanes[0], PacketTypeData, runID, 0, 0, 0, []byte("aa"), peer); err != nil || complete {
		t.Fatalf("handlePacket(seq=0) complete=%v err=%v, want false nil", complete, err)
	}
	if got.Len() != 0 {
		t.Fatalf("spooled output before DONE = %q, want empty", got.String())
	}
	if state := coordinator.runs[runID]; state == nil || state.nextWriteSeq != 2 {
		t.Fatalf("spooled nextWriteSeq = %v, want 2", state)
	}

	complete, err := coordinator.handlePacket(context.Background(), lanes[0], PacketTypeDone, runID, 2, 4, 0, nil, peer)
	if err != nil {
		t.Fatalf("handlePacket(DONE) error = %v", err)
	}
	if !complete {
		t.Fatal("handlePacket(DONE) complete = false, want true")
	}
	if got.String() != "aabb" {
		t.Fatalf("spooled output = %q, want aabb", got.String())
	}
}

func TestBlastStreamReceiveCoordinatorWritesOrderedStripedLaneSequences(t *testing.T) {
	runID := testRunID(0xb6)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	lanes := []*blastStreamReceiveLane{
		{batcher: &capturingBatcher{}, peer: peer},
		{batcher: &capturingBatcher{}, peer: peer},
	}
	var got bytes.Buffer
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), lanes, &got, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
	}, 0, time.Now())

	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeHello, runID, 0, 0, 0, nil, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(hello stripe 1) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[0], 0, 2, PacketTypeHello, runID, 0, 0, 0, nil, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(hello stripe 0) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeData, runID, 0, 2, 0, []byte("bb"), peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(data stripe 1) complete=%v err=%v, want false nil", complete, err)
	}
	if got.Len() != 0 {
		t.Fatalf("buffer after later offset = %q, want empty", got.String())
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[0], 0, 2, PacketTypeData, runID, 0, 0, 0, []byte("aa"), peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(data stripe 0) complete=%v err=%v, want false nil", complete, err)
	}
	if got.Len() != 0 {
		t.Fatalf("ordered payload before done = %q, want buffered output", got.String())
	}
	state := coordinator.runs[runID]
	if state == nil {
		t.Fatal("missing receive state")
	}
	if string(state.writeBuf) != "aabb" {
		t.Fatalf("buffered striped payload = %q, want aabb", state.writeBuf)
	}
	complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeDone, runID, 1, 4, 0, nil, peer)
	if err != nil {
		t.Fatalf("handlePacketStripe(done stripe 1) error = %v", err)
	}
	if !complete {
		t.Fatal("handlePacketStripe(done stripe 1) complete = false, want true after final size is known and payload is complete")
	}
	if got.String() != "aabb" {
		t.Fatalf("ordered payload after done = %q, want aabb", got.String())
	}
}

func TestBlastStreamReceiveCoordinatorRecoversStripedFECWithGlobalOffsetStride(t *testing.T) {
	runID := testRunID(0xbe)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	lanes := []*blastStreamReceiveLane{
		{batcher: &capturingBatcher{}, peer: peer},
		{batcher: &capturingBatcher{}, peer: peer},
	}
	var got bytes.Buffer
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), lanes, &got, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		FECGroupSize:    2,
		ExpectedRunID:   runID,
	}, 8, time.Now())

	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[0], 0, 2, PacketTypeHello, runID, 0, 0, 0, nil, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(hello stripe 0) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeHello, runID, 0, 0, 0, nil, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(hello stripe 1) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[0], 0, 2, PacketTypeData, runID, 0, 0, 0, []byte("aa"), peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(data stripe 0 seq 0) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[0], 0, 2, PacketTypeData, runID, 2, 4, 0, []byte("dd"), peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(data stripe 0 seq 2) complete=%v err=%v, want false nil", complete, err)
	}

	parity := []byte{'a' ^ 'c', 'a' ^ 'c'}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[0], 0, 2, PacketTypeParity, runID, 0, 0, 2, parity, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(parity stripe 0) complete=%v err=%v, want false nil", complete, err)
	}
	state := coordinator.runs[runID]
	if state == nil {
		t.Fatal("missing receive state")
	}
	if string(state.writeBuf) != "aaccdd" {
		t.Fatalf("striped FEC write buffer = %q, want aaccdd", state.writeBuf)
	}
}

func TestBlastFECGroupForStripeMarksParityStripe(t *testing.T) {
	runID := testRunID(0xbf)
	fec := newBlastFECGroupForStripe(runID, 3, 2, 2, nil)
	if packet := fec.Record(0, 0, []byte("aa")); packet != nil {
		t.Fatalf("first FEC packet = %x, want nil", packet)
	}
	wire := fec.Record(1, 2, []byte("cc"))
	if wire == nil {
		t.Fatal("second FEC packet = nil, want parity packet")
	}
	packet, err := UnmarshalPacket(wire, nil)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Type != PacketTypeParity {
		t.Fatalf("parity packet type = %v, want %v", packet.Type, PacketTypeParity)
	}
	if packet.StripeID != 3 {
		t.Fatalf("parity stripe = %d, want 3", packet.StripeID)
	}
	if packet.Seq != 0 || packet.Offset != 0 || packet.AckFloor != 2 {
		t.Fatalf("parity header seq=%d offset=%d count=%d, want seq=0 offset=0 count=2", packet.Seq, packet.Offset, packet.AckFloor)
	}
	if !bytes.Equal(packet.Payload, []byte{2, 2}) {
		t.Fatalf("parity payload = %v, want xor payload [2 2]", packet.Payload)
	}
}

func TestStreamReplayWindowStoresStripedDoneForRepair(t *testing.T) {
	runID := testRunID(0xc0)
	window := newStreamReplayWindow(runID, 1400, 64<<10, nil)

	wire, err := window.AddPacket(PacketTypeDone, 2, 7, 1234, nil)
	if err != nil {
		t.Fatalf("AddPacket(DONE) error = %v", err)
	}
	if !bytes.Equal(window.Packet(7), wire) {
		t.Fatal("replayed DONE packet did not match stored wire packet")
	}
	packet, err := UnmarshalPacket(window.Packet(7), nil)
	if err != nil {
		t.Fatalf("UnmarshalPacket(DONE) error = %v", err)
	}
	if packet.Type != PacketTypeDone || packet.StripeID != 2 || packet.Seq != 7 || packet.Offset != 1234 {
		t.Fatalf("replayed DONE packet = type %v stripe %d seq %d offset %d, want DONE stripe 2 seq 7 offset 1234", packet.Type, packet.StripeID, packet.Seq, packet.Offset)
	}
}

func TestBlastStreamReceiveCoordinatorCompletesWhenPayloadCompleteAfterAnyStripedDone(t *testing.T) {
	runID := testRunID(0xc1)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	batcher0 := &capturingBatcher{}
	batcher1 := &capturingBatcher{}
	lanes := []*blastStreamReceiveLane{
		{batcher: batcher0, peer: peer},
		{batcher: batcher1, peer: peer},
	}
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), lanes, io.Discard, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
	}, 0, time.Now())

	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[0], 0, 2, PacketTypeHello, runID, 0, 0, 0, nil, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(hello stripe 0) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeHello, runID, 0, 0, 0, nil, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(hello stripe 1) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[0], 0, 2, PacketTypeData, runID, 0, 0, 0, []byte("aa"), peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(data stripe 0) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeData, runID, 0, 2, 0, []byte("bb"), peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(data stripe 1) complete=%v err=%v, want false nil", complete, err)
	}
	complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeDone, runID, 1, 4, 0, nil, peer)
	if err != nil {
		t.Fatalf("handlePacketStripe(done stripe 1) error = %v", err)
	}
	if !complete {
		t.Fatal("handlePacketStripe(done stripe 1) complete = false, want true after final size is known and payload is complete")
	}
	if got := countPacketsOfType(t, batcher0.writes, PacketTypeRepairRequest) + countPacketsOfType(t, batcher1.writes, PacketTypeRepairRequest); got != 0 {
		t.Fatalf("repair writes after payload-complete DONE = %d, want 0", got)
	}
}

func TestBlastStreamReceiveCoordinatorRequestsFinalTotalStripedSuffixRepairs(t *testing.T) {
	runID := testRunID(0xc2)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	batcher0 := &capturingBatcher{}
	batcher1 := &capturingBatcher{}
	lanes := []*blastStreamReceiveLane{
		{batcher: batcher0, peer: peer},
		{batcher: batcher1, peer: peer},
	}
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), lanes, io.Discard, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
	}, 0, time.Now())
	chunkSize := 2
	finalTotal := uint64((parallelBlastStripeBlockPackets + 1) * chunkSize)

	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[0], 0, 2, PacketTypeHello, runID, 0, 0, 0, nil, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(hello stripe 0) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeHello, runID, 0, 0, 0, nil, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(hello stripe 1) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[0], 0, 2, PacketTypeData, runID, 0, 0, 0, []byte("aa"), peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(data stripe 0) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeData, runID, 0, uint64(parallelBlastStripeBlockPackets*chunkSize), 0, []byte("bb"), peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(data stripe 1) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeDone, runID, 1, finalTotal, 0, nil, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(done stripe 1) complete=%v err=%v, want false nil", complete, err)
	}

	if err := coordinator.handleRepairTick(context.Background(), time.Now()); err != nil {
		t.Fatalf("handleRepairTick() error = %v", err)
	}
	if got := countPacketsOfType(t, batcher1.writes, PacketTypeRepairRequest); got != 0 {
		t.Fatalf("stripe 1 repair writes = %d, want 0 because stripe 1 is complete", got)
	}
	if got := countPacketsOfType(t, batcher0.writes, PacketTypeRepairRequest); got != 1 {
		t.Fatalf("stripe 0 suffix repair writes = %d, want 1", got)
	}
	packet := firstPacketOfType(t, batcher0.writes, PacketTypeRepairRequest)
	if packet.Type != PacketTypeRepairRequest {
		t.Fatalf("repair packet type = %v, want %v", packet.Type, PacketTypeRepairRequest)
	}
	if packet.StripeID != 0 {
		t.Fatalf("repair packet StripeID = %d, want 0", packet.StripeID)
	}
	if len(packet.Payload) < 8 || binary.BigEndian.Uint64(packet.Payload[:8]) != 1 {
		t.Fatalf("repair payload = %x, want first missing suffix seq 1", packet.Payload)
	}
}

func TestBlastReceiveRunStateCanCompactStripedHandshakeBeforeData(t *testing.T) {
	state := newBlastReceiveRunState(nil)
	state.enableStriped(8)
	state.enableStriped(4)
	if state.totalStripes != 4 {
		t.Fatalf("totalStripes after compacted handshake = %d, want 4", state.totalStripes)
	}
}

func TestBlastStreamReceiveCoordinatorDiscardCompletesStripedOutOfGlobalOrder(t *testing.T) {
	runID := testRunID(0xbc)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	lanes := []*blastStreamReceiveLane{
		{batcher: &capturingBatcher{}, peer: peer},
		{batcher: &capturingBatcher{}, peer: peer},
	}
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), lanes, io.Discard, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
	}, 0, time.Now())

	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeHello, runID, 0, 0, 0, nil, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(hello stripe 1) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[0], 0, 2, PacketTypeHello, runID, 0, 0, 0, nil, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(hello stripe 0) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeData, runID, 0, 2, 0, []byte("bb"), peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(data stripe 1) complete=%v err=%v, want false nil", complete, err)
	}
	state := coordinator.runs[runID]
	if state == nil {
		t.Fatal("missing receive state")
	}
	if got := len(state.pendingOutput); got != 0 {
		t.Fatalf("discard pendingOutput after out-of-global-order packet = %d, want 0", got)
	}
	if got, want := coordinator.bytesReceived, int64(2); got != want {
		t.Fatalf("discard bytesReceived = %d, want %d", got, want)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[0], 0, 2, PacketTypeData, runID, 0, 0, 0, []byte("aa"), peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(data stripe 0) complete=%v err=%v, want false nil", complete, err)
	}
	complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeDone, runID, 1, 4, 0, nil, peer)
	if err != nil {
		t.Fatalf("handlePacketStripe(done stripe 1) error = %v", err)
	}
	if !complete {
		t.Fatal("handlePacketStripe(done stripe 1) complete = false, want true after final size is known and payload is complete")
	}
}

func TestBlastStreamReceiveCoordinatorRequestsStripedKnownGapOnLane(t *testing.T) {
	runID := testRunID(0xb7)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	batcher0 := &capturingBatcher{}
	batcher1 := &capturingBatcher{}
	lanes := []*blastStreamReceiveLane{
		{batcher: batcher0, peer: peer},
		{batcher: batcher1, peer: peer},
	}
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), lanes, io.Discard, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
	}, 0, time.Now())

	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeHello, runID, 0, 0, 0, nil, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(hello stripe 1) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeData, runID, 1, 2, 0, []byte("bb"), peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(data stripe 1 seq 1) complete=%v err=%v, want false nil", complete, err)
	}

	observedAt := time.Now()
	if err := coordinator.handleRepairTick(context.Background(), observedAt); err != nil {
		t.Fatalf("first handleRepairTick() error = %v", err)
	}
	if err := coordinator.handleRepairTick(context.Background(), observedAt.Add(stripedBlastKnownGapRepairDelay/2)); err != nil {
		t.Fatalf("early handleRepairTick() error = %v", err)
	}
	if got := countPacketsOfType(t, batcher1.writes, PacketTypeRepairRequest); got != 0 {
		t.Fatalf("stripe 1 repair writes before delay = %d, want 0", got)
	}
	if err := coordinator.handleRepairTick(context.Background(), observedAt.Add(stripedBlastKnownGapRepairDelay)); err != nil {
		t.Fatalf("delayed handleRepairTick() error = %v", err)
	}
	if got := countPacketsOfType(t, batcher0.writes, PacketTypeRepairRequest); got != 0 {
		t.Fatalf("stripe 0 repair writes = %d, want 0", got)
	}
	if got := countPacketsOfType(t, batcher1.writes, PacketTypeRepairRequest); got != 1 {
		t.Fatalf("stripe 1 repair writes = %d, want 1", got)
	}
	packet := firstPacketOfType(t, batcher1.writes, PacketTypeRepairRequest)
	if packet.Type != PacketTypeRepairRequest {
		t.Fatalf("repair packet type = %v, want %v", packet.Type, PacketTypeRepairRequest)
	}
	if packet.StripeID != 1 {
		t.Fatalf("repair packet StripeID = %d, want 1", packet.StripeID)
	}
	if len(packet.Payload) != 8 || binary.BigEndian.Uint64(packet.Payload) != 0 {
		t.Fatalf("repair payload = %x, want missing seq 0", packet.Payload)
	}
}

func TestBlastStreamReceiveCoordinatorCanDeferStripedKnownGapRepairs(t *testing.T) {
	runID := testRunID(0xbd)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	batcher0 := &capturingBatcher{}
	batcher1 := &capturingBatcher{}
	lanes := []*blastStreamReceiveLane{
		{batcher: batcher0, peer: peer},
		{batcher: batcher1, peer: peer},
	}
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), lanes, io.Discard, ReceiveConfig{
		Blast:                true,
		RequireComplete:      true,
		ExpectedRunID:        runID,
		DeferKnownGapRepairs: true,
	}, 0, time.Now())

	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeHello, runID, 0, 0, 0, nil, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(hello stripe 1) complete=%v err=%v, want false nil", complete, err)
	}
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeData, runID, 1, 2, 0, []byte("bb"), peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(data stripe 1 seq 1) complete=%v err=%v, want false nil", complete, err)
	}

	if err := coordinator.handleRepairTick(context.Background(), time.Now().Add(stripedBlastKnownGapRepairDelay)); err != nil {
		t.Fatalf("handleRepairTick() error = %v", err)
	}
	if got := countPacketsOfType(t, batcher0.writes, PacketTypeRepairRequest) + countPacketsOfType(t, batcher1.writes, PacketTypeRepairRequest); got != 0 {
		t.Fatalf("deferred known-gap repair writes = %d, want 0", got)
	}

	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeDone, runID, 2, 4, 0, nil, peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(done stripe 1) complete=%v err=%v, want false nil", complete, err)
	}
	if err := coordinator.handleRepairTick(context.Background(), time.Now()); err != nil {
		t.Fatalf("handleRepairTick() after DONE error = %v", err)
	}
	if got := countPacketsOfType(t, batcher1.writes, PacketTypeRepairRequest); got != 1 {
		t.Fatalf("DONE-time repair writes = %d, want 1", got)
	}
	packet := firstPacketOfType(t, batcher1.writes, PacketTypeRepairRequest)
	if packet.Type != PacketTypeRepairRequest {
		t.Fatalf("repair packet type = %v, want %v", packet.Type, PacketTypeRepairRequest)
	}
	if packet.StripeID != 1 {
		t.Fatalf("repair packet StripeID = %d, want 1", packet.StripeID)
	}
	if len(packet.Payload) != 8 || binary.BigEndian.Uint64(packet.Payload) != 0 {
		t.Fatalf("repair payload = %x, want missing seq 0", packet.Payload)
	}
}

func TestBlastRepairDeduperForLaneScopesStripedLaneHistories(t *testing.T) {
	global := newBlastRepairDeduper()
	laneA := &blastParallelSendLane{history: &blastRepairHistory{}}
	laneB := &blastParallelSendLane{history: &blastRepairHistory{}}

	deduperA := blastRepairDeduperForLane(global, laneA)
	deduperB := blastRepairDeduperForLane(global, laneB)
	if deduperA == nil || deduperB == nil {
		t.Fatal("lane deduper is nil")
	}
	if deduperA == global || deduperB == global {
		t.Fatal("striped lane histories used global deduper")
	}
	if deduperA == deduperB {
		t.Fatal("striped lanes shared a repair deduper")
	}
	if got := blastRepairDeduperForLane(global, &blastParallelSendLane{}); got != global {
		t.Fatal("non-striped lane did not use global deduper")
	}
}

func TestBlastParallelLaneIndexForOffsetUsesContiguousBlocks(t *testing.T) {
	chunkSize := 10
	blockBytes := uint64(parallelBlastStripeBlockPackets * chunkSize)

	tests := []struct {
		name   string
		offset uint64
		want   int
	}{
		{name: "first block start", offset: 0, want: 0},
		{name: "first block end", offset: blockBytes - 1, want: 0},
		{name: "second block start", offset: blockBytes, want: 1},
		{name: "third block start", offset: blockBytes * 2, want: 2},
		{name: "wraps after all lanes", offset: blockBytes * 4, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := blastParallelLaneIndexForOffset(tt.offset, 4, chunkSize); got != tt.want {
				t.Fatalf("blastParallelLaneIndexForOffset(%d, 4, %d) = %d, want %d", tt.offset, chunkSize, got, tt.want)
			}
		})
	}
}

func TestBlastParallelLaneQueueCapacityKeepsStripedBlockNonBlocking(t *testing.T) {
	if got, want := blastParallelLaneQueueCapacity(5, true), parallelBlastStripeBlockPackets*2; got != want {
		t.Fatalf("blastParallelLaneQueueCapacity(striped) = %d, want %d", got, want)
	}
	if got, want := blastParallelLaneQueueCapacity(5, false), 10; got != want {
		t.Fatalf("blastParallelLaneQueueCapacity(unstriped) = %d, want %d", got, want)
	}
}

func TestEnqueueBlastParallelPayloadRunsProgressWhenLaneQueueIsFull(t *testing.T) {
	lane := &blastParallelSendLane{ch: make(chan blastParallelSendItem, 1)}
	lane.ch <- blastParallelSendItem{wire: []byte("blocked")}

	progressCalls := 0
	err := enqueueBlastParallelPayloadWithProgress(context.Background(), lane, nil, 3, 7, 11, []byte("payload"), func() error {
		progressCalls++
		if progressCalls == 1 {
			<-lane.ch
		}
		return nil
	})
	if err != nil {
		t.Fatalf("enqueueBlastParallelPayloadWithProgress() error = %v", err)
	}
	if progressCalls == 0 {
		t.Fatal("progress callback was not called while lane queue was full")
	}

	item := <-lane.ch
	if item.stripeID != 3 || item.seq != 7 || item.offset != 11 || string(item.payload) != "payload" {
		t.Fatalf("queued item = stripe %d seq %d offset %d payload %q", item.stripeID, item.seq, item.offset, item.payload)
	}
}

func TestBlastParallelLaneBatchRateUsesHighCeilingForBurstSize(t *testing.T) {
	if got, want := blastParallelLaneBatchRateMbps(44, 2250, 8), 44; got != want {
		t.Fatalf("blastParallelLaneBatchRateMbps(low live lane rate) = %d, want %d", got, want)
	}
	if got, want := blastParallelLaneBatchRateMbps(175, 2250, 4), 175; got != want {
		t.Fatalf("blastParallelLaneBatchRateMbps(sub-threshold live lane rate) = %d, want %d", got, want)
	}
	if got, want := blastParallelLaneBatchRateMbps(225, 2250, 4), 562; got != want {
		t.Fatalf("blastParallelLaneBatchRateMbps(high ceiling) = %d, want %d", got, want)
	}
	if got, want := blastParallelLaneBatchRateMbps(175, 700, 4), 175; got != want {
		t.Fatalf("blastParallelLaneBatchRateMbps(medium ceiling) = %d, want %d", got, want)
	}
	if got, want := blastParallelLaneBatchRateMbps(700, 2250, 4), 700; got != want {
		t.Fatalf("blastParallelLaneBatchRateMbps(already above ceiling lane rate) = %d, want %d", got, want)
	}
}

func TestBlastStreamReceiveCoordinatorAcksStoredStripedPendingOutput(t *testing.T) {
	runID := testRunID(0xbe)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	batcher0 := &capturingBatcher{}
	batcher1 := &capturingBatcher{}
	lanes := []*blastStreamReceiveLane{
		{batcher: batcher0},
		{batcher: batcher1, peer: peer},
	}
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), lanes, io.Discard, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
	}, 0, time.Now())

	blockBytes := uint64(parallelBlastStripeBlockPackets * defaultChunkSize)
	if complete, err := coordinator.handlePacketStripe(context.Background(), lanes[1], 1, 2, PacketTypeData, runID, 0, blockBytes, 0, []byte("stripe-one"), peer); err != nil || complete {
		t.Fatalf("handlePacketStripe(data stripe 1) complete=%v err=%v, want false nil", complete, err)
	}
	if err := coordinator.handleRepairTick(context.Background(), time.Now()); err != nil {
		t.Fatalf("handleRepairTick() error = %v", err)
	}

	packet := firstPacketOfType(t, batcher1.writes, PacketTypeStats)
	if packet.StripeID != 1 {
		t.Fatalf("stats packet StripeID = %d, want 1", packet.StripeID)
	}
	stats, ok := unmarshalBlastStatsPayload(packet.Payload)
	if !ok {
		t.Fatalf("failed to unmarshal striped stats payload")
	}
	if stats.AckFloor != 1 {
		t.Fatalf("striped stats AckFloor = %d, want 1 after pending output is stored", stats.AckFloor)
	}
	if stats.ReceivedPackets != 1 || stats.MaxSeqPlusOne != 1 {
		t.Fatalf("striped stats packets=(%d,%d), want received=1 max=1", stats.ReceivedPackets, stats.MaxSeqPlusOne)
	}
	if got := len(batcher0.writes); got != 0 {
		t.Fatalf("stripe 0 writes = %d, want 0 because no stripe 0 peer has been observed", got)
	}
}

func BenchmarkBlastStreamReceiveCoordinatorStripedDiscard(b *testing.B) {
	runID := testRunID(0xbd)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	lanes := make([]*blastStreamReceiveLane, 8)
	for i := range lanes {
		lanes[i] = &blastStreamReceiveLane{batcher: &capturingBatcher{}, peer: peer}
	}
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), lanes, io.Discard, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
	}, 0, time.Now())
	payload := bytes.Repeat([]byte("x"), defaultChunkSize)
	seqs := make([]uint64, len(lanes))
	var offset uint64

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		laneIndex := blastParallelLaneIndexForOffset(offset, len(lanes), len(payload))
		seq := seqs[laneIndex]
		seqs[laneIndex]++
		complete, err := coordinator.handlePacketStripe(context.Background(), lanes[laneIndex], uint16(laneIndex), len(lanes), PacketTypeData, runID, seq, offset, 0, payload, peer)
		if err != nil {
			b.Fatal(err)
		}
		if complete {
			b.Fatal("striped discard benchmark completed before DONE")
		}
		offset += uint64(len(payload))
	}
}

func BenchmarkBlastStreamReceiveCoordinatorStripedDiscardParallel(b *testing.B) {
	runID := testRunID(0xbd)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	lanes := make([]*blastStreamReceiveLane, 8)
	for i := range lanes {
		lanes[i] = &blastStreamReceiveLane{batcher: &capturingBatcher{}, peer: peer}
	}
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), lanes, io.Discard, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
	}, 0, time.Now())
	payload := bytes.Repeat([]byte("x"), defaultChunkSize)
	seqs := make([]atomic.Uint64, len(lanes))
	var nextLane atomic.Uint64

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		laneIndex := int(nextLane.Add(1)-1) % len(lanes)
		lane := lanes[laneIndex]
		stripeID := uint16(laneIndex)
		for pb.Next() {
			seq := seqs[laneIndex].Add(1) - 1
			complete, err := coordinator.handlePacketStripe(context.Background(), lane, stripeID, len(lanes), PacketTypeData, runID, seq, 0, 0, payload, peer)
			if err != nil {
				b.Fatal(err)
			}
			if complete {
				b.Fatal("striped discard benchmark completed before DONE")
			}
		}
	})
}

func TestBlastStreamReceiveCoordinatorSpoolsStripedExpectedPacketWhenPendingOutputFull(t *testing.T) {
	runID := testRunID(0xbf)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	lane := &blastStreamReceiveLane{batcher: &capturingBatcher{}, peer: peer}
	var got bytes.Buffer
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), []*blastStreamReceiveLane{lane}, &got, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
	}, 0, time.Now())
	state := newBlastReceiveRunState(peer)
	state.enableStriped(2)
	state.pendingOutputBytes = stripedBlastPendingOutputLimitBytes
	stripe := state.stripeState(1, lane, peer)

	complete, err := coordinator.handleStripedDataOrDoneLocked(context.Background(), runID, state, stripe, Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeData,
		StripeID: 1,
		RunID:    runID,
		Seq:      0,
		Offset:   uint64(parallelBlastStripeBlockPackets * defaultChunkSize),
		Payload:  []byte("future"),
	})
	if err != nil || complete {
		t.Fatalf("handleStripedDataOrDoneLocked() complete=%v err=%v, want false nil", complete, err)
	}
	if stripe.expectedSeq != 1 {
		t.Fatalf("stripe.expectedSeq = %d, want 1 after spooling pending output", stripe.expectedSeq)
	}
	if !stripe.seen.Has(0) {
		t.Fatal("stripe did not mark spooled packet seen")
	}
	if got := len(state.pendingOutput); got != 0 {
		t.Fatalf("memory pending output entries = %d, want 0", got)
	}

	state.nextOffset = uint64(parallelBlastStripeBlockPackets * defaultChunkSize)
	if err := coordinator.flushStripedPendingPayloadsLocked(state); err != nil {
		t.Fatalf("flushStripedPendingPayloadsLocked() error = %v", err)
	}
	if err := coordinator.flushStripedPayloadLocked(state); err != nil {
		t.Fatalf("flushStripedPayloadLocked() error = %v", err)
	}
	if got.String() != "future" {
		t.Fatalf("spooled pending output = %q, want future", got.String())
	}
}

func TestStripedPendingOutputLimitMatchesStreamReplayWindow(t *testing.T) {
	if stripedBlastPendingOutputLimitBytes < 256<<20 {
		t.Fatalf("stripedBlastPendingOutputLimitBytes = %d, want at least 256MiB to match stream replay runway", stripedBlastPendingOutputLimitBytes)
	}
}

func TestBlastStreamReceiveCoordinatorBuffersStripedFarFuturePacketWithinBudget(t *testing.T) {
	runID := testRunID(0xc0)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	lane := &blastStreamReceiveLane{batcher: &capturingBatcher{}, peer: peer}
	var got bytes.Buffer
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), []*blastStreamReceiveLane{lane}, &got, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
	}, 0, time.Now())
	state := newBlastReceiveRunState(peer)
	state.enableStriped(1)
	stripe := state.stripeState(0, lane, peer)
	farSeq := uint64(maxBufferedPackets + 1)

	complete, err := coordinator.handleStripedDataOrDoneLocked(context.Background(), runID, state, stripe, Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeData,
		StripeID: 0,
		RunID:    runID,
		Seq:      farSeq,
		Offset:   farSeq,
		Payload:  []byte("Z"),
	})
	if err != nil || complete {
		t.Fatalf("handleStripedDataOrDoneLocked() complete=%v err=%v, want false nil", complete, err)
	}
	if !stripe.seen.Has(farSeq) {
		t.Fatal("stripe did not mark far-future packet seen")
	}
	if got := len(stripe.buffered); got != 1 {
		t.Fatalf("stripe in-memory buffered packets = %d, want 1 while within future buffer budget", got)
	}
	for seq := uint64(0); seq < farSeq; seq++ {
		complete, err = coordinator.handleStripedDataOrDoneLocked(context.Background(), runID, state, stripe, Packet{
			Version:  ProtocolVersion,
			Type:     PacketTypeData,
			StripeID: 0,
			RunID:    runID,
			Seq:      seq,
			Offset:   seq,
			Payload:  []byte("a"),
		})
		if err != nil || complete {
			t.Fatalf("handleStripedDataOrDoneLocked(seq=%d) complete=%v err=%v, want false nil", seq, complete, err)
		}
	}
	if err := coordinator.flushStripedPayloadLocked(state); err != nil {
		t.Fatalf("flushStripedPayloadLocked() error = %v", err)
	}
	if got.Len() != int(farSeq)+1 {
		t.Fatalf("received bytes = %d, want %d", got.Len(), farSeq+1)
	}
	if got.Bytes()[farSeq] != 'Z' {
		t.Fatalf("far-future byte = %q, want Z", got.Bytes()[farSeq])
	}
}

func TestBlastStreamReceiveCoordinatorSpoolsStripedFarFuturePacketAfterBudget(t *testing.T) {
	runID := testRunID(0xc1)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	lane := &blastStreamReceiveLane{batcher: &capturingBatcher{}, peer: peer}
	var got bytes.Buffer
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), []*blastStreamReceiveLane{lane}, &got, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
	}, 0, time.Now())
	state := newBlastReceiveRunState(peer)
	state.enableStriped(1)
	state.stripedFutureBufferedBytes = stripedBlastFutureBufferLimitBytes
	stripe := state.stripeState(0, lane, peer)
	farSeq := uint64(maxBufferedPackets + 1)

	complete, err := coordinator.handleStripedDataOrDoneLocked(context.Background(), runID, state, stripe, Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeData,
		StripeID: 0,
		RunID:    runID,
		Seq:      farSeq,
		Offset:   farSeq,
		Payload:  []byte("Z"),
	})
	if err != nil || complete {
		t.Fatalf("handleStripedDataOrDoneLocked() complete=%v err=%v, want false nil", complete, err)
	}
	if !stripe.seen.Has(farSeq) {
		t.Fatal("stripe did not mark spooled far-future packet seen")
	}
	if got := len(stripe.buffered); got != 0 {
		t.Fatalf("stripe in-memory buffered packets = %d, want 0 after future buffer budget is exhausted", got)
	}
	for seq := uint64(0); seq < farSeq; seq++ {
		complete, err = coordinator.handleStripedDataOrDoneLocked(context.Background(), runID, state, stripe, Packet{
			Version:  ProtocolVersion,
			Type:     PacketTypeData,
			StripeID: 0,
			RunID:    runID,
			Seq:      seq,
			Offset:   seq,
			Payload:  []byte("a"),
		})
		if err != nil || complete {
			t.Fatalf("handleStripedDataOrDoneLocked(seq=%d) complete=%v err=%v, want false nil", seq, complete, err)
		}
	}
	if err := coordinator.flushStripedPayloadLocked(state); err != nil {
		t.Fatalf("flushStripedPayloadLocked() error = %v", err)
	}
	if got.Len() != int(farSeq)+1 {
		t.Fatalf("received bytes = %d, want %d", got.Len(), farSeq+1)
	}
	if got.Bytes()[farSeq] != 'Z' {
		t.Fatalf("far-future byte = %q, want Z", got.Bytes()[farSeq])
	}
}

func TestBlastStreamReceiveCoordinatorCompletesStripedKnownLengthWithoutDone(t *testing.T) {
	runID := testRunID(0xc2)
	peerA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12001}
	peerB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12002}
	laneA := &blastStreamReceiveLane{batcher: &capturingBatcher{}, peer: peerA}
	laneB := &blastStreamReceiveLane{batcher: &capturingBatcher{}, peer: peerB}
	var got bytes.Buffer
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), []*blastStreamReceiveLane{laneA, laneB}, &got, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
	}, 2, time.Now())
	state := newBlastReceiveRunState(peerA)
	state.enableStriped(2)
	stripe0 := state.stripeState(0, laneA, peerA)
	stripe1 := state.stripeState(1, laneB, peerB)

	complete, err := coordinator.handleStripedDataOrDoneLocked(context.Background(), runID, state, stripe0, Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeData,
		StripeID: 0,
		RunID:    runID,
		Seq:      0,
		Offset:   0,
		Payload:  []byte("a"),
	})
	if err != nil || complete {
		t.Fatalf("handleStripedDataOrDoneLocked(first packet) complete=%v err=%v, want false nil", complete, err)
	}
	if state.finalTotalSet {
		t.Fatal("finalTotalSet = true before any DONE packet, want false")
	}

	complete, err = coordinator.handleStripedDataOrDoneLocked(context.Background(), runID, state, stripe1, Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeData,
		StripeID: 1,
		RunID:    runID,
		Seq:      0,
		Offset:   1,
		Payload:  []byte("b"),
	})
	if err != nil {
		t.Fatalf("handleStripedDataOrDoneLocked(last data packet) error = %v", err)
	}
	if !complete {
		t.Fatal("handleStripedDataOrDoneLocked(last data packet) complete = false, want true once expected bytes are written")
	}
	if got.String() != "ab" {
		t.Fatalf("received payload = %q, want ab", got.String())
	}
}

func TestBlastStreamReceiveCoordinatorRequestsKnownGapOnNextRepairTick(t *testing.T) {
	runID := testRunID(0xb4)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	batcher := &capturingBatcher{}
	lane := &blastStreamReceiveLane{batcher: batcher, peer: peer}
	coordinator := newBlastStreamReceiveCoordinator(context.Background(), []*blastStreamReceiveLane{lane}, io.Discard, ReceiveConfig{
		Blast:           true,
		RequireComplete: true,
		ExpectedRunID:   runID,
	}, 0, time.Now())
	repairWrites := func() [][]byte {
		var repairs [][]byte
		for _, write := range batcher.writes {
			packet, err := UnmarshalPacket(write, nil)
			if err != nil {
				t.Fatalf("UnmarshalPacket(write) error = %v", err)
			}
			if packet.Type == PacketTypeRepairRequest {
				repairs = append(repairs, write)
			}
		}
		return repairs
	}

	complete, err := coordinator.handlePacket(context.Background(), lane, PacketTypeData, runID, 1, 2, 0, []byte("bb"), peer)
	if err != nil {
		t.Fatalf("handlePacket(seq=1) error = %v", err)
	}
	if complete {
		t.Fatal("handlePacket(seq=1) complete = true, want false")
	}

	observedAt := time.Now()
	if err := coordinator.handleRepairTick(context.Background(), observedAt); err != nil {
		t.Fatalf("first handleRepairTick() error = %v", err)
	}
	if got := len(repairWrites()); got != 0 {
		t.Fatalf("repair writes after first tick = %d, want 0", got)
	}

	if err := coordinator.handleRepairTick(context.Background(), observedAt.Add(blastRateFeedbackInterval)); err != nil {
		t.Fatalf("early handleRepairTick() error = %v", err)
	}
	repairs := repairWrites()
	if got := len(repairs); got != 1 {
		t.Fatalf("repair writes by next rate feedback window = %d, want 1", got)
	}
	packet, err := UnmarshalPacket(repairs[0], nil)
	if err != nil {
		t.Fatalf("UnmarshalPacket(repair request) error = %v", err)
	}
	if packet.Type != PacketTypeRepairRequest {
		t.Fatalf("repair packet type = %v, want %v", packet.Type, PacketTypeRepairRequest)
	}
	if packet.RunID != runID {
		t.Fatalf("repair RunID = %x, want %x", packet.RunID, runID)
	}
	if len(packet.Payload) != 8 || binary.BigEndian.Uint64(packet.Payload) != 0 {
		t.Fatalf("repair payload = %x, want missing seq 0", packet.Payload)
	}
}

func TestReceiveBlastParallelToWriterUsesConnectedUDPAfterHello(t *testing.T) {
	switch runtime.GOOS {
	case "darwin", "linux":
	default:
		t.Skipf("connected UDP batcher unsupported on %s", runtime.GOOS)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	src := bytes.Repeat([]byte("connected-receiver"), 1<<12)
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true}, int64(len(src)))
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	serverAddr := server.LocalAddr().(*net.UDPAddr)
	remoteAddr := (&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverAddr.Port}).String()
	if _, err := Send(ctx, client, remoteAddr, bytes.NewReader(src), SendConfig{Blast: true}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
		if !stats.Transport.Connected {
			t.Fatalf("receive transport = %#v, want connected UDP fast path", stats.Transport)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for connected receiver: %v", ctx.Err())
	}
}

func TestSendBlastParallelSingleLaneReportsLaneCount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	src := bytes.Repeat([]byte("single-lane-parallel"), 1<<12)
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true}, int64(len(src)))
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	sendStats, err := SendBlastParallel(ctx, []net.PacketConn{client}, []string{server.LocalAddr().String()}, bytes.NewReader(src), SendConfig{Blast: true})
	if err != nil {
		t.Fatalf("SendBlastParallel() error = %v", err)
	}
	if sendStats.Lanes != 1 {
		t.Fatalf("send Lanes = %d, want 1", sendStats.Lanes)
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for single-lane receive: %v", ctx.Err())
	}
}

func TestSendBlastParallelSingleLaneBatchedUsesConnectedUDP(t *testing.T) {
	switch runtime.GOOS {
	case "darwin", "linux":
	default:
		t.Skipf("connected UDP batcher unsupported on %s", runtime.GOOS)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	src := bytes.Repeat([]byte("single-lane-batched-connected"), 1<<12)
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true}, int64(len(src)))
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	sendStats, err := SendBlastParallel(ctx, []net.PacketConn{client}, []string{server.LocalAddr().String()}, bytes.NewReader(src), SendConfig{
		Blast:           true,
		Transport:       probeTransportBatched,
		RateCeilingMbps: 700,
	})
	if err != nil {
		t.Fatalf("SendBlastParallel() error = %v", err)
	}
	if sendStats.Transport.RequestedKind != probeTransportBatched {
		t.Fatalf("send requested transport = %q, want %q", sendStats.Transport.RequestedKind, probeTransportBatched)
	}
	if sendStats.Transport.Kind != probeTransportLegacy && sendStats.Transport.Kind != probeTransportBatched {
		t.Fatalf("send transport kind = %q, want %q or %q", sendStats.Transport.Kind, probeTransportLegacy, probeTransportBatched)
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for single-lane batched receive: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterRepairsDroppedDataPacket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientBase, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientBase.Close()

	client := &dropFirstBlastDataConn{PacketConn: clientBase}
	src := bytes.Repeat([]byte("repair-blast"), 1<<12)
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true}, int64(len(src)))
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	if _, err := Send(ctx, client, server.LocalAddr().String(), bytes.NewReader(src), SendConfig{Blast: true, ChunkSize: 512, RepairPayloads: true}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for repaired blast receive: %v", ctx.Err())
	}
}

func TestBlastPacketAEADEncryptsWirePayloadAndRoundTrips(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientBase, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientBase.Close()

	client := &capturePacketConn{PacketConn: &dropFirstBlastDataConn{PacketConn: clientBase}}
	src := bytes.Repeat([]byte("encrypted-blast-payload:"), 512)
	var got bytes.Buffer
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, &got, ReceiveConfig{
			Blast:           true,
			RequireComplete: true,
			PacketAEAD:      testPacketAEAD(t),
		}, int64(len(src)))
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	if _, err := Send(ctx, client, server.LocalAddr().String(), bytes.NewReader(src), SendConfig{
		Blast:          true,
		ChunkSize:      512,
		RepairPayloads: true,
		PacketAEAD:     testPacketAEAD(t),
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for encrypted blast receive: %v", ctx.Err())
	}
	if !bytes.Equal(got.Bytes(), src) {
		t.Fatalf("encrypted blast payload mismatch: got %d bytes, want %d", got.Len(), len(src))
	}
	for _, packet := range client.Packets() {
		if bytes.Contains(packet, []byte("encrypted-blast-payload")) {
			t.Fatal("captured blast packet contains plaintext payload")
		}
	}
}

func TestBlastRepairReplayWindowStaysBoundedAcrossTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	src := bytes.Repeat([]byte("bounded-replay:"), 256<<10)
	replayBudget := uint64(1 << 20)
	receiveErrCh := make(chan error, 1)
	receiveStatsCh := make(chan TransferStats, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{
			Blast:           true,
			RequireComplete: true,
		}, 0)
		if err != nil {
			receiveErrCh <- err
			return
		}
		receiveStatsCh <- stats
	}()

	sendStats, err := Send(ctx, client, server.LocalAddr().String(), bytes.NewReader(src), SendConfig{
		Blast:                   true,
		ChunkSize:               1024,
		RepairPayloads:          true,
		RateMbps:                64,
		RateCeilingMbps:         64,
		StreamReplayWindowBytes: replayBudget,
	})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if sendStats.BytesSent != int64(len(src)) {
		t.Fatalf("send BytesSent = %d, want %d", sendStats.BytesSent, len(src))
	}
	if sendStats.MaxReplayBytes == 0 || sendStats.MaxReplayBytes > replayBudget {
		t.Fatalf("send MaxReplayBytes = %d, want 1..%d", sendStats.MaxReplayBytes, replayBudget)
	}

	select {
	case err := <-receiveErrCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case receiveStats := <-receiveStatsCh:
		if receiveStats.BytesReceived != int64(len(src)) {
			t.Fatalf("receive BytesReceived = %d, want %d", receiveStats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}

func TestBlastParallelStreamReplayWindowStaysBoundedAcrossTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()
	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()

	clientA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()
	clientB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	src := bytes.Repeat([]byte("bounded-parallel-replay:"), 128<<10)
	replayBudget := uint64(1 << 20)
	runID := testRunID(0x74)
	receiveErrCh := make(chan error, 1)
	receiveStatsCh := make(chan TransferStats, 1)
	go func() {
		stats, err := ReceiveBlastStreamParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, ReceiveConfig{
			Blast:           true,
			ExpectedRunID:   runID,
			RequireComplete: true,
		}, 0)
		if err != nil {
			receiveErrCh <- err
			return
		}
		receiveStatsCh <- stats
	}()

	sendStats, err := SendBlastParallel(ctx, []net.PacketConn{clientA, clientB}, []string{
		serverA.LocalAddr().String(),
		serverB.LocalAddr().String(),
	}, bytes.NewReader(src), SendConfig{
		Blast:                   true,
		ChunkSize:               1024,
		RunID:                   runID,
		RepairPayloads:          true,
		RateMbps:                128,
		RateCeilingMbps:         128,
		StreamReplayWindowBytes: replayBudget,
	})
	if err != nil {
		t.Fatalf("SendBlastParallel() error = %v", err)
	}
	if sendStats.BytesSent != int64(len(src)) {
		t.Fatalf("send BytesSent = %d, want %d", sendStats.BytesSent, len(src))
	}
	if sendStats.MaxReplayBytes == 0 || sendStats.MaxReplayBytes > replayBudget {
		t.Fatalf("send MaxReplayBytes = %d, want 1..%d", sendStats.MaxReplayBytes, replayBudget)
	}
	if sendStats.Lanes != 2 {
		t.Fatalf("send Lanes = %d, want 2", sendStats.Lanes)
	}

	select {
	case err := <-receiveErrCh:
		t.Fatalf("ReceiveBlastStreamParallelToWriter() error = %v", err)
	case receiveStats := <-receiveStatsCh:
		if receiveStats.BytesReceived != int64(len(src)) {
			t.Fatalf("receive BytesReceived = %d, want %d", receiveStats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelEmitsPeriodicStatsWhileRunIsOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{
			Blast:           true,
			RequireComplete: true,
		}, 0)
		if err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
	}()

	runID := testRunID(0x73)
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	if packet := readProbePacket(t, client, time.Second); packet.Type != PacketTypeHelloAck {
		t.Fatalf("packet type = %v, want HELLO_ACK", packet.Type)
	}
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 0, Offset: 0, Payload: []byte("first")})
	if packet := readProbePacket(t, client, time.Second); packet.Type != PacketTypeStats {
		t.Fatalf("packet type = %v, want first STATS", packet.Type)
	}
	packet := readProbePacket(t, client, 3*blastRateFeedbackInterval)
	if packet.Type != PacketTypeStats {
		t.Fatalf("packet type = %v, want periodic STATS", packet.Type)
	}
	stats, ok := unmarshalBlastStatsPayload(packet.Payload)
	if !ok {
		t.Fatal("periodic stats payload did not unmarshal")
	}
	if stats.AckFloor != 1 {
		t.Fatalf("periodic stats AckFloor = %d, want 1", stats.AckFloor)
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	default:
	}
}

func TestReceiveBlastParallelToWriterRepairsDroppedDataPacketInOrder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientBase, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientBase.Close()

	client := &dropFirstBlastDataConn{PacketConn: clientBase}
	src := bytes.Repeat([]byte("repair-content-blast"), 1<<12)
	var got bytes.Buffer
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, &got, ReceiveConfig{Blast: true, RequireComplete: true}, 0)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	if _, err := Send(ctx, client, server.LocalAddr().String(), bytes.NewReader(src), SendConfig{Blast: true, ChunkSize: 512, RepairPayloads: true}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for repaired blast receive: %v", ctx.Err())
	}
	if !bytes.Equal(got.Bytes(), src) {
		t.Fatalf("repaired payload mismatch: got %d bytes, want %d", got.Len(), len(src))
	}
}

func TestReceiveBlastParallelToWriterTailReplayRecoversDroppedDataPacketInOrder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientBase, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientBase.Close()

	client := &dropFirstBlastDataConn{PacketConn: clientBase}
	src := bytes.Repeat([]byte("tail-replay-content"), 1<<10)
	var got bytes.Buffer
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, &got, ReceiveConfig{Blast: true, RequireComplete: true}, 0)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	if _, err := Send(ctx, client, server.LocalAddr().String(), bytes.NewReader(src), SendConfig{
		Blast:           true,
		ChunkSize:       512,
		TailReplayBytes: 1 << 15,
		RepairPayloads:  false,
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for tail replay receive: %v", ctx.Err())
	}
	if !bytes.Equal(got.Bytes(), src) {
		t.Fatalf("tail replay payload mismatch: got %d bytes, want %d", got.Len(), len(src))
	}
}

func TestReceiveBlastParallelToWriterFECRecoversDroppedDataPacketInOrder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientBase, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientBase.Close()

	client := &dropFirstBlastDataConn{PacketConn: clientBase}
	src := bytes.Repeat([]byte("fec-replay-content"), 1<<10)
	var got bytes.Buffer
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, &got, ReceiveConfig{
			Blast:           true,
			RequireComplete: true,
			FECGroupSize:    32,
		}, 0)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	if _, err := Send(ctx, client, server.LocalAddr().String(), bytes.NewReader(src), SendConfig{
		Blast:          true,
		ChunkSize:      512,
		FECGroupSize:   32,
		RepairPayloads: false,
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for FEC receive: %v", ctx.Err())
	}
	if !bytes.Equal(got.Bytes(), src) {
		t.Fatalf("FEC payload mismatch: got %d bytes, want %d", got.Len(), len(src))
	}
}

func TestReceiveBlastParallelToWriterTruncatesRecoveredPartialFECTail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x51)
	payload0 := []byte("abcd")
	payload1 := []byte("xyz")
	parity := append([]byte(nil), payload0...)
	for i := range payload1 {
		parity[i] ^= payload1[i]
	}
	totalBytes := uint64(len(payload0) + len(payload1))
	var got bytes.Buffer
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, &got, ReceiveConfig{
			Blast:           true,
			RequireComplete: true,
			FECGroupSize:    4,
		}, 0)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 0, Offset: 0, Payload: payload0})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeParity, RunID: runID, Seq: 0, Offset: 0, AckFloor: 2, Payload: parity})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runID, Seq: 2, Offset: totalBytes})

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(totalBytes) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, totalBytes)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for partial FEC receive: %v", ctx.Err())
	}
	if got.String() != string(payload0)+string(payload1) {
		t.Fatalf("payload = %q (%d bytes), want %q (%d bytes)", got.String(), got.Len(), string(payload0)+string(payload1), totalBytes)
	}
}

func TestReceiveBlastParallelToWriterWaitsForDoneBeforeRecoveringCurrentFECGroup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x52)
	payload0 := []byte("abcd")
	payload1 := []byte("xyz")
	parity := append([]byte(nil), payload0...)
	for i := range payload1 {
		parity[i] ^= payload1[i]
	}
	totalBytes := uint64(len(payload0) + len(payload1))
	var got bytes.Buffer
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, &got, ReceiveConfig{
			Blast:           true,
			RequireComplete: true,
			FECGroupSize:    2,
		}, 0)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 0, Offset: 0, Payload: payload0})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeParity, RunID: runID, Seq: 0, Offset: 0, AckFloor: 2, Payload: parity})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runID, Seq: 2, Offset: totalBytes})

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(totalBytes) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, totalBytes)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for current FEC group receive: %v", ctx.Err())
	}
	if got.String() != string(payload0)+string(payload1) {
		t.Fatalf("payload = %q (%d bytes), want %q (%d bytes)", got.String(), got.Len(), string(payload0)+string(payload1), totalBytes)
	}
}

func TestReceiveBlastParallelToWriterRequireCompleteErrorsWhenRepairCannotRecover(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientBase, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientBase.Close()

	client := &dropFirstBlastDataConn{PacketConn: clientBase}
	src := bytes.Repeat([]byte("missing-strict-content"), 1<<10)
	errCh := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true, RequireComplete: true}, 0)
		errCh <- err
	}()

	if _, err := Send(ctx, client, server.LocalAddr().String(), bytes.NewReader(src), SendConfig{
		Blast:          true,
		ChunkSize:      512,
		RepairPayloads: false,
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ReceiveBlastParallelToWriter() error = nil, want incomplete blast error")
		}
		if !strings.Contains(err.Error(), "blast incomplete") {
			t.Fatalf("ReceiveBlastParallelToWriter() error = %v, want blast incomplete", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for incomplete strict receive: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterRequireCompleteWaitsForDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x4b)
	errCh := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true, RequireComplete: true}, 0)
		errCh <- err
	}()

	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Payload: []byte("strict-data-without-done")})

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() returned before DONE with error %v", err)
	case <-time.After(parallelBlastDataIdle + 250*time.Millisecond):
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for canceled strict receive")
	}
}

func TestReceiveBlastParallelToWriterExtendsRepairGraceOnProgress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x4c)
	payloads := [][]byte{[]byte("seq-0"), []byte("seq-1"), []byte("seq-2")}
	totalBytes := uint64(len(payloads[0]) + len(payloads[1]) + len(payloads[2]))
	errCh := make(chan error, 1)
	statsCh := make(chan TransferStats, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true, RequireComplete: true}, int64(totalBytes))
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	for {
		packet := readProbePacket(t, client, 500*time.Millisecond)
		if packet.Type == PacketTypeHelloAck {
			break
		}
	}
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 0, Offset: 0, Payload: payloads[0]})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runID, Seq: 3, Offset: totalBytes})

	time.Sleep(parallelBlastRepairGrace - 100*time.Millisecond)
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 1, Offset: uint64(len(payloads[0])), Payload: payloads[1]})

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() returned after repair progress with error %v", err)
	case stats := <-statsCh:
		t.Fatalf("ReceiveBlastParallelToWriter() completed after one repair with %d bytes, want wait for remaining repair", stats.BytesReceived)
	case <-time.After(250 * time.Millisecond):
	}

	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 2, Offset: uint64(len(payloads[0]) + len(payloads[1])), Payload: payloads[2]})

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(totalBytes) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, totalBytes)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for repaired receive: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterScalesRepairGraceFromUnknownDoneTotal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x4d)
	errCh := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true, RequireComplete: true}, 0)
		errCh <- err
	}()

	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	for {
		packet := readProbePacket(t, client, 500*time.Millisecond)
		if packet.Type == PacketTypeHelloAck {
			break
		}
	}
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 0, Offset: 0, Payload: []byte("seq-0")})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runID, Seq: 2, Offset: 128 << 20})

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() returned before scaled repair grace with error %v", err)
	case <-time.After(parallelBlastRepairGrace + 500*time.Millisecond):
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for canceled receive")
	}
}

func TestParallelBlastRepairGraceScalesWithExpectedBytes(t *testing.T) {
	if got := parallelBlastRepairGraceForExpectedBytes(15); got != parallelBlastRepairGrace {
		t.Fatalf("small repair grace = %v, want %v", got, parallelBlastRepairGrace)
	}
	if got := parallelBlastRepairGraceForExpectedBytes(128 << 20); got <= parallelBlastRepairGrace {
		t.Fatalf("large repair grace = %v, want more than %v", got, parallelBlastRepairGrace)
	}
	if got := parallelBlastRepairGraceForExpectedBytes(128 << 20); got < 36*time.Second {
		t.Fatalf("large section repair grace = %v, want at least 36s", got)
	}
	if got := parallelBlastRepairGraceForExpectedBytes(2 << 30); got != 60*time.Second {
		t.Fatalf("capped repair grace = %v, want %v", got, parallelBlastRepairGraceMax)
	}
}

func TestBlastRepairQuietGraceScalesAfterRepairs(t *testing.T) {
	if got := blastRepairQuietGraceForExpectedBytes(128<<20, false); got != blastRepairQuietGrace {
		t.Fatalf("quiet grace without repairs = %v, want %v", got, blastRepairQuietGrace)
	}
	if got, want := blastRepairQuietGraceForExpectedBytes(128<<20, true), parallelBlastRepairGraceForExpectedBytes(128<<20); got != want {
		t.Fatalf("quiet grace after repairs = %v, want %v", got, want)
	}
	if got := blastRepairQuietGraceForExpectedBytes(2<<30, true); got != 60*time.Second {
		t.Fatalf("capped active quiet grace = %v, want %v", got, parallelBlastRepairGraceMax)
	}
}

func TestReceiveBlastParallelToWriterRequestsKnownGapAfterDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x4d)
	errCh := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true, RequireComplete: true}, 0)
		errCh <- err
	}()

	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	for {
		packet := readProbePacket(t, client, 500*time.Millisecond)
		if packet.Type == PacketTypeHelloAck {
			break
		}
	}
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 0, Offset: 0, Payload: []byte("seq-0")})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 2, Offset: 10, Payload: []byte("seq-2")})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runID, Seq: 3, Offset: 15})

	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case err := <-errCh:
			t.Fatalf("ReceiveBlastParallelToWriter() returned before repair with error %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for post-DONE repair request")
		default:
		}
		packet := readProbePacket(t, client, 500*time.Millisecond)
		if packet.Type != PacketTypeRepairRequest {
			continue
		}
		if packet.RunID != runID {
			t.Fatalf("repair request RunID = %x, want %x", packet.RunID, runID)
		}
		if len(packet.Payload) < 8 {
			t.Fatalf("repair request payload len = %d, want at least 8", len(packet.Payload))
		}
		if got := binary.BigEndian.Uint64(packet.Payload[:8]); got != 1 {
			t.Fatalf("repair request seq = %d, want 1", got)
		}
		break
	}
}

func TestSendRepairRequestBatchesSplitsLargeGapsIntoMTUSafeRequests(t *testing.T) {
	runID := testRunID(0x53)
	batcher := &capturingBatcher{}
	batches := [][]uint64{
		make([]uint64, maxRepairRequestSeqs),
		make([]uint64, maxRepairRequestSeqs),
		make([]uint64, maxRepairRequestSeqs),
	}
	for batchIndex := range batches {
		for seq := range batches[batchIndex] {
			batches[batchIndex][seq] = uint64(batchIndex*maxRepairRequestSeqs + seq)
		}
	}

	if err := sendRepairRequestBatches(context.Background(), batcher, nil, runID, 0, batches); err != nil {
		t.Fatalf("sendRepairRequestBatches() error = %v", err)
	}
	if got := len(batcher.writes); got != len(batches) {
		t.Fatalf("repair request writes = %d, want %d", got, len(batches))
	}
	for i, wire := range batcher.writes {
		packet, err := UnmarshalPacket(wire, nil)
		if err != nil {
			t.Fatalf("UnmarshalPacket(repair request %d) error = %v", i, err)
		}
		if packet.Type != PacketTypeRepairRequest {
			t.Fatalf("repair request %d type = %v, want %v", i, packet.Type, PacketTypeRepairRequest)
		}
		if packet.RunID != runID {
			t.Fatalf("repair request %d RunID = %x, want %x", i, packet.RunID, runID)
		}
		if len(packet.Payload) != maxRepairRequestSeqs*8 {
			t.Fatalf("repair request %d payload len = %d, want %d", i, len(packet.Payload), maxRepairRequestSeqs*8)
		}
		if len(wire) >= defaultChunkSize {
			t.Fatalf("repair request %d wire len = %d, want below data chunk size %d", i, len(wire), defaultChunkSize)
		}
		if got, want := binary.BigEndian.Uint64(packet.Payload[:8]), batches[i][0]; got != want {
			t.Fatalf("repair request %d first seq = %d, want %d", i, got, want)
		}
	}
}

func TestReceiveBlastParallelToWriterRequestsKnownGapBeforeDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x4e)
	errCh := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true, RequireComplete: true}, 0)
		errCh <- err
	}()

	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	for {
		packet := readProbePacket(t, client, 500*time.Millisecond)
		if packet.Type == PacketTypeHelloAck {
			break
		}
	}
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 0, Offset: 0, Payload: []byte("seq-0")})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 2, Offset: 10, Payload: []byte("seq-2")})

	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case err := <-errCh:
			t.Fatalf("ReceiveBlastParallelToWriter() returned before repair with error %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for pre-DONE repair request")
		default:
		}
		packet := readProbePacket(t, client, 500*time.Millisecond)
		if packet.Type != PacketTypeRepairRequest {
			continue
		}
		if packet.RunID != runID {
			t.Fatalf("repair request RunID = %x, want %x", packet.RunID, runID)
		}
		if len(packet.Payload) < 8 {
			t.Fatalf("repair request payload len = %d, want at least 8", len(packet.Payload))
		}
		if got := binary.BigEndian.Uint64(packet.Payload[:8]); got != 1 {
			t.Fatalf("repair request seq = %d, want 1", got)
		}
		break
	}
}

func TestBlastSendReturnsPromptlyWhenRepairCompleteIsLostWithoutRepairRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverBase, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverBase.Close()
	server := &dropRepairCompleteConn{PacketConn: serverBase}

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	src := bytes.Repeat([]byte("complete-with-lost-repair-complete"), 128)
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true}, int64(len(src)))
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	start := time.Now()
	if _, err := Send(ctx, client, server.LocalAddr().String(), bytes.NewReader(src), SendConfig{Blast: true, ChunkSize: 512}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	elapsed := time.Since(start)
	if elapsed >= parallelBlastRepairGrace/2 {
		t.Fatalf("Send() elapsed = %v, want prompt completion when no repair requests arrive", elapsed)
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receiver: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterBuffersOutOfOrderData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientBase, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientBase.Close()

	client := &reverseFirstTwoBlastDataConn{PacketConn: clientBase}
	src := bytes.Repeat([]byte("ordered-blast"), 1<<12)
	var got bytes.Buffer
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, &got, ReceiveConfig{Blast: true, RequireComplete: true}, 0)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	if _, err := Send(ctx, client, server.LocalAddr().String(), bytes.NewReader(src), SendConfig{Blast: true, ChunkSize: 512, RepairPayloads: true}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(src)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for ordered blast receive: %v", ctx.Err())
	}
	if !bytes.Equal(got.Bytes(), src) {
		t.Fatalf("ordered payload mismatch: got %d bytes, want %d", got.Len(), len(src))
	}
}

func TestReceiveBlastParallelToWriterCompletesOnDoneWithPartialBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()
	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x42)
	payload := []byte("partial-blast")
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, ReceiveConfig{Blast: true}, int64(len(payload)+1))
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Payload: payload})
	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runID})
	writeProbePacket(t, client, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runID})

	select {
	case err := <-errCh:
		t.Fatalf("parallel blast error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(payload)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(payload))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for partial parallel blast receive: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterFastModeWaitsForAllLanesWithoutExpectedBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()
	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()
	clientA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()
	clientB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	runID := testRunID(0x71)
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, ReceiveConfig{Blast: true, ExpectedRunID: runID}, 0)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	payloadA := []byte("lane-a")
	writeProbePacket(t, clientA, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	writeProbePacket(t, clientA, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 0, Offset: 0, Payload: payloadA})
	writeProbePacket(t, clientA, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runID, Seq: 1, Offset: uint64(len(payloadA))})

	select {
	case stats := <-statsCh:
		t.Fatalf("ReceiveBlastParallelToWriter() returned after first lane with %d bytes, want wait for all lanes", stats.BytesReceived)
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error after first lane = %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	payloadB := []byte("lane-bb")
	writeProbePacket(t, clientB, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	writeProbePacket(t, clientB, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 0, Offset: 0, Payload: payloadB})
	writeProbePacket(t, clientB, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runID, Seq: 1, Offset: uint64(len(payloadB))})

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if want := int64(len(payloadA) + len(payloadB)); stats.BytesReceived != want {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, want)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for all lanes: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterFastModeRejectsIncompleteDone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x48)
	payload := []byte("fast-mode-partial-blast")
	errCh := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true}, 0)
		errCh <- err
	}()

	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Payload: payload})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runID, Seq: 2, Offset: uint64(len(payload) + 512)})

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ReceiveBlastParallelToWriter() error = nil, want incomplete blast error")
		}
		if !strings.Contains(err.Error(), "blast incomplete") {
			t.Fatalf("ReceiveBlastParallelToWriter() error = %v, want blast incomplete", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for incomplete blast failure: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterFastModeRejectsIncompleteDonePerLane(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()
	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()
	clientA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()
	clientB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	runID := testRunID(0x72)
	payloadA := bytes.Repeat([]byte("a"), 1024)
	payloadB := []byte("b")
	errCh := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, ReceiveConfig{Blast: true, ExpectedRunID: runID}, 0)
		errCh <- err
	}()

	writeProbePacket(t, clientA, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	writeProbePacket(t, clientA, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 0, Payload: payloadA})
	writeProbePacket(t, clientA, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runID, Seq: 1, Offset: uint64(len(payloadA))})

	writeProbePacket(t, clientB, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	writeProbePacket(t, clientB, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 0, Payload: payloadB})
	writeProbePacket(t, clientB, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runID, Seq: 2, Offset: uint64(len(payloadB) + 512)})

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ReceiveBlastParallelToWriter() error = nil, want incomplete blast error")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("ReceiveBlastParallelToWriter() error = %v, want blast incomplete before context timeout", err)
		}
		if !strings.Contains(err.Error(), "blast incomplete") {
			t.Fatalf("ReceiveBlastParallelToWriter() error = %v, want blast incomplete", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for per-lane incomplete blast failure: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterFastModeWaitsForLateDataAfterDone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x49)
	firstPayload := []byte("first-fast-mode-payload")
	latePayload := []byte("late-fast-mode-payload")
	totalBytes := len(firstPayload) + len(latePayload)
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true}, 0)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 0, Offset: 0, Payload: firstPayload})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runID, Seq: 2, Offset: uint64(totalBytes)})
	time.Sleep(parallelBlastDataIdle / 4)
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 1, Offset: uint64(len(firstPayload)), Payload: latePayload})

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(totalBytes) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, totalBytes)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for late fast-mode data: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterCompletesAfterTerminalGrace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()
	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x43)
	payload := []byte("partial-blast")
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, ReceiveConfig{Blast: true}, int64(len(payload)+1))
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Payload: payload})
	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runID})

	select {
	case err := <-errCh:
		t.Fatalf("parallel blast error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(payload)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(payload))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for terminal grace: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterWaitsForLateDataAfterAllDone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()
	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runA := testRunID(0x45)
	runB := testRunID(0x46)
	payloadA := []byte("early-data")
	payloadB := []byte("late-data")
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, ReceiveConfig{Blast: true}, int64(len(payloadA)+len(payloadB)))
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runA})
	writeProbePacket(t, client, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runB})
	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runA, Payload: payloadA})
	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runA})
	writeProbePacket(t, client, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runB})
	time.Sleep(parallelBlastDoneGrace / 2)
	writeProbePacket(t, client, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runB, Payload: payloadB})

	select {
	case err := <-errCh:
		t.Fatalf("parallel blast error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(payloadA)+len(payloadB)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(payloadA)+len(payloadB))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for late data: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterAcceptsExpectedRunIDSet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()
	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runA := testRunID(0x52)
	runB := testRunID(0x53)
	badRun := testRunID(0x54)
	payloadA := []byte("accepted-a")
	payloadB := []byte("accepted-b")
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, ReceiveConfig{
			Blast:           true,
			ExpectedRunIDs:  [][16]byte{runA, runB},
			RequireComplete: true,
		}, int64(len(payloadA)+len(payloadB)))
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: badRun})
	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: badRun, Payload: []byte("ignored")})
	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runA})
	writeProbePacket(t, client, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runB})
	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runA, Payload: payloadA})
	writeProbePacket(t, client, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runB, Payload: payloadB})

	select {
	case err := <-errCh:
		t.Fatalf("parallel blast error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(payloadA)+len(payloadB)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(payloadA)+len(payloadB))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for expected run ID set: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterDoesNotStartTerminalGraceBeforeAllDone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()
	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runA := testRunID(0x47)
	runB := testRunID(0x48)
	payloadA := []byte("early-data")
	payloadB := []byte("slow-stripe-data")
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, ReceiveConfig{Blast: true}, int64(len(payloadA)+len(payloadB)))
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runA})
	writeProbePacket(t, client, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runB})
	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runA, Payload: payloadA})
	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runA})
	time.Sleep(parallelBlastDataIdle / 2)
	writeProbePacket(t, client, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runB, Payload: payloadB})
	writeProbePacket(t, client, serverB.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: runB})

	select {
	case err := <-errCh:
		t.Fatalf("parallel blast error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(payloadA)+len(payloadB)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(payloadA)+len(payloadB))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for slow stripe data: %v", ctx.Err())
	}
}

func TestWriteBlastPayloadFastPathForDiscard(t *testing.T) {
	payload := []byte("payload")
	n, err := writeBlastPayload(io.Discard, payload)
	if err != nil {
		t.Fatalf("writeBlastPayload() error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("writeBlastPayload() n = %d, want %d", n, len(payload))
	}
}

func TestWriteOrderedParallelBlastPayloadAggregatesBufferedWriter(t *testing.T) {
	var out bytes.Buffer
	buffered := bufio.NewWriterSize(&out, 4096)
	state := newBlastReceiveRunState(nil)

	n, err := writeOrderedParallelBlastPayload(buffered, state, 0, []byte("payload"), &sync.Mutex{})
	if err != nil {
		t.Fatalf("writeOrderedParallelBlastPayload() error = %v", err)
	}
	if n != len("payload") {
		t.Fatalf("writeOrderedParallelBlastPayload() n = %d, want %d", n, len("payload"))
	}
	if len(state.writeBuf) != len("payload") {
		t.Fatalf("state.writeBuf len = %d, want aggregated payload", len(state.writeBuf))
	}
	if out.Len() != 0 {
		t.Fatalf("underlying writer len before ordered flush = %d, want 0", out.Len())
	}
	if err := buffered.Flush(); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("underlying writer len before ordered flush after buffered Flush = %d, want 0", out.Len())
	}
	if err := flushOrderedParallelBlastPayload(buffered, state, &sync.Mutex{}); err != nil {
		t.Fatal(err)
	}
	if err := buffered.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "payload" {
		t.Fatalf("underlying writer = %q, want payload", got)
	}
}

func TestBlastSeqSetTracksDenseAndSparseSequences(t *testing.T) {
	var set blastSeqSet
	for seq := uint64(0); seq < 130; seq++ {
		if !set.Add(seq) {
			t.Fatalf("Add(%d) = false, want first insert", seq)
		}
	}
	if set.Add(64) {
		t.Fatal("Add(64) duplicate = true, want false")
	}
	for _, seq := range []uint64{0, 63, 64, 129} {
		if !set.Has(seq) {
			t.Fatalf("Has(%d) = false, want true", seq)
		}
	}
	if set.Has(130) {
		t.Fatal("Has(130) = true, want false")
	}
	sparse := uint64(1 << 40)
	if !set.Add(sparse) {
		t.Fatal("Add(sparse) = false, want true")
	}
	if !set.Has(sparse) {
		t.Fatal("Has(sparse) = false, want true")
	}
	if set.Len() != 131 {
		t.Fatalf("Len() = %d, want 131", set.Len())
	}
}

func TestWriteBlastBatchRetriesNoBufferSpace(t *testing.T) {
	batcher := &transientNoBufferBatcher{}
	packet := []byte("packet")

	if err := writeBlastBatch(context.Background(), batcher, nil, [][]byte{packet}); err != nil {
		t.Fatalf("writeBlastBatch() error = %v", err)
	}
	if batcher.calls != 2 {
		t.Fatalf("calls = %d, want 2", batcher.calls)
	}
}

func TestBlastSendReadsSourceInBatches(t *testing.T) {
	src := bytes.Repeat([]byte("x"), 256*defaultChunkSize)
	reader := &countingReader{r: bytes.NewReader(src)}
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
	errCh := make(chan error, 1)
	go func() {
		_, err := ReceiveToWriter(ctx, b, a.LocalAddr().String(), io.Discard, ReceiveConfig{Blast: true})
		errCh <- err
	}()

	if _, err := Send(ctx, a, b.LocalAddr().String(), reader, SendConfig{Blast: true}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ReceiveToWriter() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
	if reader.reads > 8 {
		t.Fatalf("source reads = %d, want batched reads", reader.reads)
	}
}

func TestBlastRepairHistorySynthesizesLastPacketSize(t *testing.T) {
	runID := testRunID(0x49)
	history, err := newBlastRepairHistory(runID, 8, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	if err := history.Record(0, []byte("12345678")); err != nil {
		t.Fatal(err)
	}
	if err := history.Record(1, []byte("abcdefgh")); err != nil {
		t.Fatal(err)
	}
	if err := history.Record(2, []byte("xy")); err != nil {
		t.Fatal(err)
	}
	history.totalBytes = 18
	history.packets = 3

	packet, err := UnmarshalPacket(history.packet(2), nil)
	if err != nil {
		t.Fatalf("UnmarshalPacket() error = %v", err)
	}
	if packet.Type != PacketTypeData || packet.RunID != runID || packet.Seq != 2 || packet.Offset != 16 {
		t.Fatalf("packet = %+v, want repair data packet at seq 2 offset 16", packet)
	}
	if len(packet.Payload) != 2 {
		t.Fatalf("len(packet.Payload) = %d, want 2", len(packet.Payload))
	}
	if !bytes.Equal(packet.Payload, []byte("xy")) {
		t.Fatalf("packet.Payload = %q, want xy", packet.Payload)
	}
}

func TestBlastRepairHistoryPacketBufferSynthesizesRepairPacket(t *testing.T) {
	runID := testRunID(0x51)
	history, err := newBlastRepairHistory(runID, 4, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()

	packet, err := history.packetBuffer(0, 0, 4)
	if err != nil {
		t.Fatal(err)
	}
	copy(packet[headerLen:], []byte("abcd"))
	history.MarkComplete(4, 1)

	got, err := UnmarshalPacket(history.packet(0), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != PacketTypeData || got.RunID != runID || got.Seq != 0 || got.Offset != 0 {
		t.Fatalf("packet = %+v, want stored data packet", got)
	}
	if string(got.Payload) != "abcd" {
		t.Fatalf("payload = %q, want abcd", got.Payload)
	}
}

func TestBlastRepairHistoryWithoutPayloadsDoesNotSynthesizeData(t *testing.T) {
	history := blastRepairHistory{
		runID:      testRunID(0x4a),
		chunkSize:  8,
		totalBytes: 18,
		packets:    3,
	}

	if packet := history.packet(2); packet != nil {
		t.Fatalf("history.packet(2) = %d bytes, want nil without retained payloads", len(packet))
	}
}

func TestBlastRepairHistoryTailPacketsUseRetainedPayloads(t *testing.T) {
	runID := testRunID(0x50)
	history, err := newBlastRepairHistory(runID, 4, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	for seq, payload := range [][]byte{
		[]byte("0000"),
		[]byte("1111"),
		[]byte("2222"),
		[]byte("3333"),
	} {
		if err := history.Record(uint64(seq), payload); err != nil {
			t.Fatal(err)
		}
	}
	history.MarkComplete(16, 4)

	packets := history.tailPackets(8)
	if len(packets) != 2 {
		t.Fatalf("len(tailPackets) = %d, want 2", len(packets))
	}
	for i, wantSeq := range []uint64{2, 3} {
		packet, err := UnmarshalPacket(packets[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		if packet.Type != PacketTypeData || packet.RunID != runID || packet.Seq != wantSeq {
			t.Fatalf("packet %d = %+v, want data seq %d", i, packet, wantSeq)
		}
	}
}

func TestBlastRepairHistoryTailPacketsUseStreamReplayWindow(t *testing.T) {
	runID := testRunID(0x51)
	history, err := newBlastRepairHistory(runID, 4, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	history.streamReplay = newStreamReplayWindow(runID, 4, 1<<20, nil)
	for seq, payload := range [][]byte{
		[]byte("0000"),
		[]byte("1111"),
		[]byte("2222"),
		[]byte("3333"),
	} {
		if _, err := history.streamReplay.AddPacket(PacketTypeData, 0, uint64(seq), uint64(seq*4), payload); err != nil {
			t.Fatal(err)
		}
	}
	history.MarkComplete(16, 4)

	packets := history.tailPackets(8)
	if len(packets) != 2 {
		t.Fatalf("len(tailPackets) = %d, want 2", len(packets))
	}
	for i, wantSeq := range []uint64{2, 3} {
		packet, err := UnmarshalPacket(packets[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		if packet.Type != PacketTypeData || packet.RunID != runID || packet.Seq != wantSeq {
			t.Fatalf("packet %d = %+v, want data seq %d", i, packet, wantSeq)
		}
	}
}

func TestSendBlastRepairsSuppressesImmediateDuplicateSeqs(t *testing.T) {
	runID := testRunID(0x4f)
	history, err := newBlastRepairHistory(runID, 4, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	if err := history.Record(0, []byte("abcd")); err != nil {
		t.Fatal(err)
	}
	history.MarkComplete(4, 1)

	batcher := &capturingBatcher{}
	stats := TransferStats{}
	deduper := newBlastRepairDeduper()
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, 0)
	now := time.Now()

	if _, err := sendBlastRepairs(context.Background(), batcher, nil, history, payload, &stats, deduper, now); err != nil {
		t.Fatal(err)
	}
	if _, err := sendBlastRepairs(context.Background(), batcher, nil, history, payload, &stats, deduper, now.Add(blastRepairResendInterval/2)); err != nil {
		t.Fatal(err)
	}
	if got := len(batcher.writes); got != 1 {
		t.Fatalf("repair writes after immediate duplicate = %d, want 1", got)
	}
	if stats.Retransmits != 1 {
		t.Fatalf("Retransmits after immediate duplicate = %d, want 1", stats.Retransmits)
	}

	if _, err := sendBlastRepairs(context.Background(), batcher, nil, history, payload, &stats, deduper, now.Add(blastRepairResendInterval+time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if got := len(batcher.writes); got != 2 {
		t.Fatalf("repair writes after resend interval = %d, want 2", got)
	}
	if stats.Retransmits != 2 {
		t.Fatalf("Retransmits after resend interval = %d, want 2", stats.Retransmits)
	}
}

func TestSendBlastServicesRepairRequestsDuringDataPhase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	runID := testRunID(0x52)
	batcher := &inflightRepairBatcher{runID: runID, repairSeq: 0}
	src := bytes.Repeat([]byte("abcd"), 160)

	if _, err := sendBlast(ctx, batcher, nil, nil, runID, bytes.NewReader(src), 4, 0, 0, true, 0, 0, nil, 0, TransferStats{}); err != nil {
		t.Fatalf("sendBlast() error = %v", err)
	}

	repairIndex := -1
	doneIndex := -1
	batcher.mu.Lock()
	for i, packet := range batcher.writes {
		packetType, _, _, seq, _, ok := decodeBlastPacketFull(packet)
		if !ok {
			continue
		}
		if packetType == PacketTypeData && seq == 0 && repairIndex == -1 && i > 0 {
			repairIndex = i
		}
		if packetType == PacketTypeDone && doneIndex == -1 {
			doneIndex = i
		}
	}
	batcher.mu.Unlock()

	if repairIndex == -1 {
		t.Fatal("repair packet was not sent")
	}
	if doneIndex == -1 {
		t.Fatal("done packet was not sent")
	}
	if repairIndex > doneIndex {
		t.Fatalf("repair packet index = %d, want before done index %d", repairIndex, doneIndex)
	}
}

func TestBlastSendControlDecreasesOnReplayPressure(t *testing.T) {
	now := time.Unix(0, 0)
	control := newBlastSendControl(1200, 10_000, now)
	control.ObserveReplayPressure(now.Add(100*time.Millisecond), 200<<20, 256<<20)
	if got := control.RateMbps(); got >= 1200 {
		t.Fatalf("RateMbps() = %d, want decrease below 1200 after replay pressure", got)
	}
}

func TestBlastSendControlCanDecreaseBelowOneMegabytePerSecond(t *testing.T) {
	now := time.Unix(0, 0)
	control := newBlastSendControl(8, 10_000, now)
	for i := 0; i < 10; i++ {
		control.ObserveReplayPressure(now.Add(time.Duration(i+1)*time.Second), 8<<20, 8<<20)
	}
	if got := control.RateMbps(); got >= 8 {
		t.Fatalf("RateMbps() = %d, want below 8 Mbps after repeated pressure", got)
	}
	if got, want := control.RateMbps(), blastRateMinMbps; got != want {
		t.Fatalf("RateMbps() = %d, want floor %d", got, want)
	}
}

func TestBlastParallelQueueWaitOnlyBacksOffAtReplayCapacity(t *testing.T) {
	runID := testRunID(0x79)
	history, err := newBlastRepairHistory(runID, 100, false, nil)
	if err != nil {
		t.Fatalf("newBlastRepairHistory() error = %v", err)
	}
	const payloadLen = 100
	packetBytes := uint64(headerLen + payloadLen)
	history.streamReplay = newStreamReplayWindow(runID, payloadLen, packetBytes*10, nil)

	for seq := uint64(0); seq < 8; seq++ {
		payload := bytes.Repeat([]byte{byte(seq)}, payloadLen)
		if _, err := history.streamReplay.AddPacket(PacketTypeData, 0, seq, seq*payloadLen, payload); err != nil {
			t.Fatalf("AddPacket(%d) error = %v", seq, err)
		}
	}

	now := time.Unix(0, 0)
	control := newBlastSendControl(700, 1800, now)
	if observeBlastParallelQueueReplayPressure(control, history, now.Add(time.Second)) {
		t.Fatal("observeBlastParallelQueueReplayPressure() = true below replay capacity")
	}
	if got := control.RateMbps(); got != 700 {
		t.Fatalf("RateMbps() = %d, want queue wait to preserve 700 below replay capacity", got)
	}

	for seq := uint64(8); seq < 10; seq++ {
		payload := bytes.Repeat([]byte{byte(seq)}, payloadLen)
		if _, err := history.streamReplay.AddPacket(PacketTypeData, 0, seq, seq*payloadLen, payload); err != nil {
			t.Fatalf("AddPacket(%d) error = %v", seq, err)
		}
	}

	if !observeBlastParallelQueueReplayPressure(control, history, now.Add(2*time.Second)) {
		t.Fatal("observeBlastParallelQueueReplayPressure() = false at replay capacity")
	}
	if got := control.RateMbps(); got >= 700 {
		t.Fatalf("RateMbps() = %d, want decrease at replay capacity", got)
	}
}

func TestParallelActiveLanesForRateStartsConservativeAndScales(t *testing.T) {
	tests := []struct {
		name      string
		rateMbps  int
		available int
		striped   bool
		want      int
	}{
		{name: "no lanes", rateMbps: 350, available: 0, want: 0},
		{name: "unknown uses one", rateMbps: 0, available: 8, want: 1},
		{name: "canlxc class starts one", rateMbps: 350, available: 8, want: 1},
		{name: "mid path uses two paced lanes", rateMbps: 700, available: 8, want: 2},
		{name: "gigabit path uses four paced lanes", rateMbps: 1200, available: 8, want: 4},
		{name: "fast path uses all lanes", rateMbps: 1700, available: 8, want: 8},
		{name: "very fast path uses all lanes", rateMbps: 2000, available: 8, want: 8},
		{name: "ktzlxc class uses all lanes", rateMbps: 2250, available: 8, want: 8},
		{name: "clamps available lanes", rateMbps: 2250, available: 3, want: 3},
		{name: "higher than ktzlxc class uses all", rateMbps: 5000, available: 8, want: 8},
		{name: "striped keeps all lanes", rateMbps: 350, available: 8, striped: true, want: 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parallelActiveLanesForRate(tt.rateMbps, tt.available, tt.striped); got != tt.want {
				t.Fatalf("parallelActiveLanesForRate(%d, %d, %t) = %d, want %d", tt.rateMbps, tt.available, tt.striped, got, tt.want)
			}
		})
	}
}

func TestRecordReplayWindowFullWaitUpdatesStats(t *testing.T) {
	var stats TransferStats
	recordReplayWindowFullWait(&stats, 64<<10, 25*time.Millisecond)
	if got, want := stats.ReplayWindowFullWaits, int64(1); got != want {
		t.Fatalf("ReplayWindowFullWaits = %d, want %d", got, want)
	}
	if got, want := stats.ReplayWindowFullWaitDuration, 25*time.Millisecond; got != want {
		t.Fatalf("ReplayWindowFullWaitDuration = %s, want %s", got, want)
	}
	if got, want := stats.MaxReplayBytes, uint64(64<<10); got != want {
		t.Fatalf("MaxReplayBytes = %d, want %d", got, want)
	}
}

func TestBlastSocketPacingUsesCeilingForAdaptiveRamp(t *testing.T) {
	if got, want := blastSocketPacingRateMbps(150, 10_000), 10_000; got != want {
		t.Fatalf("blastSocketPacingRateMbps(150, 10000) = %d, want %d", got, want)
	}
	if got, want := blastSocketPacingRateMbps(150, 0), 150; got != want {
		t.Fatalf("blastSocketPacingRateMbps(150, 0) = %d, want %d", got, want)
	}
	if got, want := blastSocketPacingRateMbps(1200, 700), 1200; got != want {
		t.Fatalf("blastSocketPacingRateMbps(1200, 700) = %d, want %d", got, want)
	}
}

func TestReceiveBlastParallelToWriterCompletesWhenFECReachesExpectedBytesBeforeDone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x92)
	payload0 := []byte("first-fec-packet")
	payload1 := []byte("other-fec-packet")
	parity := append([]byte(nil), payload0...)
	for i := range parity {
		parity[i] ^= payload1[i]
	}
	total := int64(len(payload0) + len(payload1))
	var got bytes.Buffer
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, &got, ReceiveConfig{
			Blast:           true,
			RequireComplete: true,
			FECGroupSize:    2,
		}, total)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Seq: 0, Offset: 0, Payload: payload0})
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeParity, RunID: runID, Seq: 0, Offset: 0, AckFloor: 2, Payload: parity})

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != total {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, total)
		}
		if got.String() != string(payload0)+string(payload1) {
			t.Fatalf("payload = %q, want %q", got.String(), string(payload0)+string(payload1))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for FEC expected-byte completion: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterCompletesAfterDataIdle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()
	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x44)
	payload := []byte("partial-blast")
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, ReceiveConfig{Blast: true}, int64(len(payload)+1))
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	writeProbePacket(t, client, serverA.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Payload: payload})

	select {
	case err := <-errCh:
		t.Fatalf("parallel blast error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(payload)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(payload))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for data idle: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterClearsStaleReadDeadlines(t *testing.T) {
	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()
	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()
	if err := serverA.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := serverB.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}

	clientA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()
	clientB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	srcA := bytes.Repeat([]byte("a"), 1024)
	srcB := bytes.Repeat([]byte("b"), 1024)
	total := int64(len(srcA) + len(srcB))
	recvCtx, recvCancel := context.WithCancel(context.Background())
	defer recvCancel()
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 2)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(recvCtx, []net.PacketConn{serverA, serverB}, io.Discard, ReceiveConfig{Blast: true}, total)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	sendCtx, sendCancel := context.WithTimeout(context.Background(), time.Second)
	defer sendCancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := Send(sendCtx, clientA, serverA.LocalAddr().String(), bytes.NewReader(srcA), SendConfig{Blast: true}); err != nil {
			errCh <- err
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := Send(sendCtx, clientB, serverB.LocalAddr().String(), bytes.NewReader(srcB), SendConfig{Blast: true}); err != nil {
			errCh <- err
		}
	}()
	wg.Wait()

	select {
	case err := <-errCh:
		t.Fatalf("parallel blast error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != total {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, total)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for parallel blast receive")
	}
}

func TestReceiveBlastParallelToWriterErrorsWhenContextEndsBeforeExpectedBytes(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true}, 1024)
		errCh <- err
	}()

	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ReceiveBlastParallelToWriter() error = nil, want incomplete blast error")
		}
		if !strings.Contains(err.Error(), "blast incomplete") {
			t.Fatalf("ReceiveBlastParallelToWriter() error = %v, want blast incomplete", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for context-canceled receive")
	}
}

func TestReceiveBlastParallelToWriterReturnsPartialStatsOnContextError(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := &notifyingWriter{wrote: make(chan struct{}, 1)}
	type receiveResult struct {
		stats TransferStats
		err   error
	}
	resultCh := make(chan receiveResult, 1)
	payload := []byte("partial-before-context-cancel")
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, writer, ReceiveConfig{Blast: true}, int64(len(payload)+1))
		resultCh <- receiveResult{stats: stats, err: err}
	}()

	runID := testRunID(0x51)
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeHello, RunID: runID})
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	ackBuf := make([]byte, 64<<10)
	if _, _, err := client.ReadFrom(ackBuf); err != nil {
		t.Fatalf("waiting for hello ack: %v", err)
	}
	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeData, RunID: runID, Payload: payload})
	select {
	case <-writer.wrote:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for partial write")
	}
	cancel()

	select {
	case result := <-resultCh:
		if result.err == nil {
			t.Fatal("ReceiveBlastParallelToWriter() error = nil, want incomplete blast error")
		}
		if !strings.Contains(result.err.Error(), "blast incomplete") {
			t.Fatalf("ReceiveBlastParallelToWriter() error = %v, want blast incomplete", result.err)
		}
		if result.stats.BytesReceived != int64(len(payload)) {
			t.Fatalf("BytesReceived = %d, want %d", result.stats.BytesReceived, len(payload))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for context-canceled receive")
	}
}

func TestReceiveBlastParallelToWriterErrorsWhenDoneCompletesWithNoExpectedBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{Blast: true}, 1024)
		errCh <- err
	}()

	writeProbePacket(t, client, server.LocalAddr(), Packet{Version: ProtocolVersion, Type: PacketTypeDone, RunID: testRunID(0x50)})

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ReceiveBlastParallelToWriter() error = nil, want incomplete blast error")
		}
		if !strings.Contains(err.Error(), "blast incomplete") {
			t.Fatalf("ReceiveBlastParallelToWriter() error = %v, want blast incomplete", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for incomplete done receive: %v", ctx.Err())
	}
}

func TestReceiveReliableParallelToWriterAggregatesFlows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()
	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()
	clientA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()
	clientB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	srcA := bytes.Repeat([]byte("a"), 1<<15)
	srcB := bytes.Repeat([]byte("b"), 1<<15)
	total := int64(len(srcA) + len(srcB))
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 2)
	go func() {
		stats, err := ReceiveReliableParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, ReceiveConfig{}, total)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := Send(ctx, clientA, serverA.LocalAddr().String(), bytes.NewReader(srcA), SendConfig{}); err != nil {
			errCh <- err
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := Send(ctx, clientB, serverB.LocalAddr().String(), bytes.NewReader(srcB), SendConfig{}); err != nil {
			errCh <- err
		}
	}()
	wg.Wait()

	select {
	case err := <-errCh:
		t.Fatalf("parallel reliable error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != total {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, total)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for parallel reliable receive: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterCapturesPeakOnExactCompletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x71)
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{
			Blast:         true,
			ExpectedRunID: runID,
		}, 1025)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	writeProbePacket(t, client, server.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeHello,
		RunID:   runID,
	})
	writeProbePacket(t, client, server.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		RunID:   runID,
		Seq:     0,
		Payload: []byte("a"),
	})
	time.Sleep(25 * time.Millisecond)
	writeProbePacket(t, client, server.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		RunID:   runID,
		Seq:     1,
		Payload: bytes.Repeat([]byte("b"), 1024),
	})

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != 1025 {
			t.Fatalf("BytesReceived = %d, want 1025", stats.BytesReceived)
		}
		if stats.PeakGoodputMbps <= 0 {
			t.Fatalf("PeakGoodputMbps = %f, want > 0", stats.PeakGoodputMbps)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for exact-completion receive stats: %v", ctx.Err())
	}
}

func TestReceiveBlastParallelToWriterCapturesPeakOnFastCompletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	runID := testRunID(0x72)
	payload := bytes.Repeat([]byte("c"), 1024)
	statsCh := make(chan TransferStats, 1)
	errCh := make(chan error, 1)
	go func() {
		stats, err := ReceiveBlastParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{
			Blast:         true,
			ExpectedRunID: runID,
		}, 0)
		if err != nil {
			errCh <- err
			return
		}
		statsCh <- stats
	}()

	writeProbePacket(t, client, server.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeHello,
		RunID:   runID,
	})
	writeProbePacket(t, client, server.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeDone,
		RunID:   runID,
		Seq:     1,
		Offset:  uint64(len(payload)),
	})
	time.Sleep(25 * time.Millisecond)
	writeProbePacket(t, client, server.LocalAddr(), Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		RunID:   runID,
		Seq:     0,
		Payload: payload,
	})

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case stats := <-statsCh:
		if stats.BytesReceived != int64(len(payload)) {
			t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(payload))
		}
		if stats.PeakGoodputMbps <= 0 {
			t.Fatalf("PeakGoodputMbps = %f, want > 0", stats.PeakGoodputMbps)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for fast-completion receive stats: %v", ctx.Err())
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

type capturePacketConn struct {
	net.PacketConn

	mu      sync.Mutex
	packets [][]byte
}

func (c *capturePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.packets = append(c.packets, append([]byte(nil), p...))
	c.mu.Unlock()
	return c.PacketConn.WriteTo(p, addr)
}

func (c *capturePacketConn) Packets() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.packets))
	for i := range c.packets {
		out[i] = append([]byte(nil), c.packets[i]...)
	}
	return out
}

func testPacketAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher([]byte("derpcat-test-key"))
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error = %v", err)
	}
	return aead
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

type dropFirstBlastDataConn struct {
	net.PacketConn

	mu      sync.Mutex
	dropped bool
}

func (d *dropFirstBlastDataConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	packet, err := UnmarshalPacket(p, nil)
	if err != nil {
		return 0, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.dropped && packet.Type == PacketTypeData {
		d.dropped = true
		return len(p), nil
	}
	return d.PacketConn.WriteTo(p, addr)
}

type dropRepairCompleteConn struct {
	net.PacketConn
}

func (d *dropRepairCompleteConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	packet, err := UnmarshalPacket(p, nil)
	if err != nil {
		return 0, err
	}
	if packet.Type == PacketTypeRepairComplete {
		return len(p), nil
	}
	return d.PacketConn.WriteTo(p, addr)
}

type reverseFirstTwoBlastDataConn struct {
	net.PacketConn

	mu     sync.Mutex
	first  []byte
	second []byte
}

func (d *reverseFirstTwoBlastDataConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	packet, err := UnmarshalPacket(p, nil)
	if err != nil {
		return 0, err
	}
	if packet.Type != PacketTypeData {
		return d.PacketConn.WriteTo(p, addr)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case d.first == nil:
		d.first = append([]byte(nil), p...)
		return len(p), nil
	case d.second == nil:
		d.second = append([]byte(nil), p...)
		if _, err := d.PacketConn.WriteTo(d.second, addr); err != nil {
			return 0, err
		}
		if _, err := d.PacketConn.WriteTo(d.first, addr); err != nil {
			return 0, err
		}
		return len(p), nil
	default:
		return d.PacketConn.WriteTo(p, addr)
	}
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

type transientNoBufferBatcher struct {
	calls int
}

func (b *transientNoBufferBatcher) Capabilities() TransportCaps { return TransportCaps{} }
func (b *transientNoBufferBatcher) MaxBatch() int               { return 1 }

func (b *transientNoBufferBatcher) WriteBatch(context.Context, net.Addr, [][]byte) (int, error) {
	b.calls++
	if b.calls == 1 {
		return 0, syscall.ENOBUFS
	}
	return 1, nil
}

func (b *transientNoBufferBatcher) ReadBatch(context.Context, time.Duration, []batchReadBuffer) (int, error) {
	return 0, syscall.ENOBUFS
}

type failWriteOnNthPacketConn struct {
	net.PacketConn

	mu      sync.Mutex
	writes  int
	failAt  int
	failErr error
}

func (c *failWriteOnNthPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.failAt > 0 && c.writes == c.failAt {
		return 0, c.failErr
	}
	return c.PacketConn.WriteTo(p, addr)
}

func TestWriteWithContextRetriesTransientNoBufferSpace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	clientBase, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientBase.Close()

	clientConn := &failWriteOnNthPacketConn{
		PacketConn: clientBase,
		failAt:     1,
		failErr:    syscall.ENOBUFS,
	}

	received := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 2048)
		_ = serverConn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := serverConn.ReadFrom(buf)
		if err != nil {
			received <- nil
			return
		}
		received <- append([]byte(nil), buf[:n]...)
	}()

	payload := []byte("hello-no-buffer")
	n, err := writeWithContext(ctx, clientConn, serverConn.LocalAddr(), payload)
	if err != nil {
		t.Fatalf("writeWithContext() error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("writeWithContext() bytes = %d, want %d", n, len(payload))
	}
	if got := <-received; !bytes.Equal(got, payload) {
		t.Fatalf("server payload = %q, want %q", got, payload)
	}
}

type countingReader struct {
	r     *bytes.Reader
	reads int
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.reads++
	return r.r.Read(p)
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

func TestExtendedAckPayloadAcknowledgesBeyondAckMask(t *testing.T) {
	buffered := map[uint64]Packet{
		70:  {Type: PacketTypeData},
		300: {Type: PacketTypeData},
	}
	payload := extendedAckPayloadFor(buffered, 1)
	if len(payload) != extendedAckBytes {
		t.Fatalf("extended ack payload len = %d, want %d", len(payload), extendedAckBytes)
	}

	inFlight := map[uint64]*outboundPacket{
		70:  {seq: 70},
		300: {seq: 300},
		500: {seq: 500},
	}
	if got := applyAck(inFlight, 1, 0, payload); got != 2 {
		t.Fatalf("applyAck() = %d, want 2", got)
	}
	if _, ok := inFlight[70]; ok {
		t.Fatal("seq 70 still in flight")
	}
	if _, ok := inFlight[300]; ok {
		t.Fatal("seq 300 still in flight")
	}
	if _, ok := inFlight[500]; !ok {
		t.Fatal("seq 500 was unexpectedly acked")
	}
}

func TestFillSendWindowRespectsAckFloorSpanAfterSACK(t *testing.T) {
	batcher := &capturingBatcher{}
	state := senderState{
		src:       bytes.NewReader([]byte("abcdefgh")),
		chunkSize: 1,
		window:    4,
		runID:     testRunID(21),
		inFlight:  make(map[uint64]*outboundPacket),
	}
	stats := TransferStats{}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	if err := fillSendWindow(context.Background(), batcher, peer, &state, &stats); err != nil {
		t.Fatalf("fillSendWindow() error = %v", err)
	}
	if state.nextSeq != 4 {
		t.Fatalf("nextSeq after initial fill = %d, want 4", state.nextSeq)
	}

	if got := applyAck(state.inFlight, 0, 0b111, nil); got != 3 {
		t.Fatalf("applyAck() = %d, want 3 SACKed packets", got)
	}
	if err := fillSendWindow(context.Background(), batcher, peer, &state, &stats); err != nil {
		t.Fatalf("fillSendWindow() after SACK error = %v", err)
	}
	if state.nextSeq != 4 {
		t.Fatalf("nextSeq after SACKed gap = %d, want 4 until cumulative ACK advances", state.nextSeq)
	}

	state.ackFloor = 4
	if err := fillSendWindow(context.Background(), batcher, peer, &state, &stats); err != nil {
		t.Fatalf("fillSendWindow() after ACK floor advance error = %v", err)
	}
	if state.nextSeq != 8 {
		t.Fatalf("nextSeq after ACK floor advance = %d, want 8", state.nextSeq)
	}
}

func TestFillSendWindowPacesReliableWrites(t *testing.T) {
	batcher := &capturingBatcher{}
	state := senderState{
		src:       bytes.NewReader(bytes.Repeat([]byte("x"), 1000)),
		chunkSize: 1000,
		window:    1,
		runID:     testRunID(22),
		rateMbps:  1,
		inFlight:  make(map[uint64]*outboundPacket),
	}
	stats := TransferStats{StartedAt: time.Now()}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	startedAt := time.Now()
	if err := fillSendWindow(context.Background(), batcher, peer, &state, &stats); err != nil {
		t.Fatalf("fillSendWindow() error = %v", err)
	}
	if elapsed := time.Since(startedAt); elapsed < 2*time.Millisecond {
		t.Fatalf("fillSendWindow() elapsed = %v, want pacing delay", elapsed)
	}
}

func TestRunBlastParallelSendLanePacesBatches(t *testing.T) {
	batcher := &capturingBatcher{}
	packet := make([]byte, headerLen+1000)
	encodePacketHeader(packet[:headerLen], PacketTypeData, testRunID(31), 0, 0, 0, 0, 0)
	lane := &blastParallelSendLane{
		peer:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
		batcher:    batcher,
		batchLimit: 1,
		ch:         make(chan blastParallelSendItem, 1),
		pacer:      newBlastPacer(time.Now()),
	}
	lane.setRateMbps(1)
	lane.ch <- blastParallelSendItem{wire: packet}
	close(lane.ch)

	startedAt := time.Now()
	if err := runBlastParallelSendLane(context.Background(), lane); err != nil {
		t.Fatalf("runBlastParallelSendLane() error = %v", err)
	}
	if elapsed := time.Since(startedAt); elapsed < 2*time.Millisecond {
		t.Fatalf("runBlastParallelSendLane() elapsed = %v, want pacing delay", elapsed)
	}
}

func TestRunBlastParallelSendLaneEncodesQueuedPayloads(t *testing.T) {
	batcher := &capturingBatcher{}
	runID := testRunID(0xd1)
	aead := testPacketAEAD(t)
	history, err := newBlastRepairHistory(runID, 16, false, aead)
	if err != nil {
		t.Fatal(err)
	}
	history.streamReplay = newStreamReplayWindow(runID, 16, 1<<20, aead)
	payload := []byte("parallel-lane")
	lane := &blastParallelSendLane{
		peer:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
		batcher:    batcher,
		batchLimit: 1,
		ch:         make(chan blastParallelSendItem, 1),
		runID:      runID,
		sendConfig: SendConfig{ChunkSize: 16, PacketAEAD: aead},
	}
	lane.ch <- blastParallelSendItem{
		history:  history,
		stripeID: 3,
		seq:      7,
		offset:   112,
		payload:  append([]byte(nil), payload...),
	}
	close(lane.ch)

	if err := runBlastParallelSendLane(context.Background(), lane); err != nil {
		t.Fatalf("runBlastParallelSendLane() error = %v", err)
	}
	if len(batcher.writes) != 1 {
		t.Fatalf("writes = %d, want 1", len(batcher.writes))
	}
	packetOut, err := UnmarshalPacket(batcher.writes[0], aead)
	if err != nil {
		t.Fatalf("UnmarshalPacket() error = %v", err)
	}
	if packetOut.Type != PacketTypeData || packetOut.StripeID != 3 || packetOut.Seq != 7 || packetOut.Offset != 112 {
		t.Fatalf("packet metadata = type %d stripe %d seq %d offset %d", packetOut.Type, packetOut.StripeID, packetOut.Seq, packetOut.Offset)
	}
	if !bytes.Equal(packetOut.Payload, payload) {
		t.Fatalf("payload = %q, want %q", packetOut.Payload, payload)
	}
}

func TestBlastParallelSendLaneCopyPayloadUsesWarmPool(t *testing.T) {
	lane := &blastParallelSendLane{}
	lane.payloadPool.New = func() any {
		return make([]byte, 1400)
	}
	payload := bytes.Repeat([]byte("x"), 1400)
	buf := lane.copyPayload(payload)
	lane.releasePayload(buf)

	allocs := testing.AllocsPerRun(100, func() {
		buf := lane.copyPayload(payload)
		lane.releasePayload(buf)
	})
	if allocs >= 2 {
		t.Fatalf("copyPayload warm-pool allocations = %.2f, want fewer than 2", allocs)
	}
}

func TestServeBlastRepairsParallelUsesRepairPayloadQuietGrace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	runID := testRunID(0xb6)
	history, err := newBlastRepairHistory(runID, 1400, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	payload := bytes.Repeat([]byte("x"), 1400)
	if err := history.Record(0, payload); err != nil {
		t.Fatal(err)
	}
	history.MarkComplete(uint64(len(payload)), 1)

	batcher := &singleRepairRequestBatcher{runID: runID, seq: 0}
	lane := &blastParallelSendLane{
		batcher: batcher,
		peer:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
	}
	stats, err := serveBlastRepairsParallel(ctx, []*blastParallelSendLane{lane}, runID, history, TransferStats{BytesSent: 1 << 30}, nil)
	if err != nil {
		t.Fatalf("serveBlastRepairsParallel() error = %v", err)
	}
	if stats.Retransmits != 1 {
		t.Fatalf("Retransmits = %d, want 1", stats.Retransmits)
	}
}

func TestServeBlastRepairsParallelDuplicateRequestsDoNotDelayCompletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	runID := testRunID(0xb7)
	history, err := newBlastRepairHistory(runID, 1400, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	payload := bytes.Repeat([]byte("x"), 1400)
	if err := history.Record(0, payload); err != nil {
		t.Fatal(err)
	}
	history.MarkComplete(uint64(len(payload)), 1)

	batcher := &repeatingRepairRequestBatcher{runID: runID, seq: 0, delay: 10 * time.Millisecond}
	lane := &blastParallelSendLane{
		batcher: batcher,
		peer:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
	}
	start := time.Now()
	stats, err := serveBlastRepairsParallel(ctx, []*blastParallelSendLane{lane}, runID, history, TransferStats{BytesSent: 1 << 30}, nil)
	if err != nil {
		t.Fatalf("serveBlastRepairsParallel() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Fatalf("serveBlastRepairsParallel() elapsed = %v, want duplicate repair requests to stop extending completion beyond 1s", elapsed)
	}
	if stats.Retransmits != 1 {
		t.Fatalf("Retransmits = %d, want 1 despite repeated duplicate requests", stats.Retransmits)
	}
}

type capturingBatcher struct {
	mu     sync.Mutex
	writes [][]byte
}

func (b *capturingBatcher) Capabilities() TransportCaps { return TransportCaps{Kind: "test"} }
func (b *capturingBatcher) MaxBatch() int               { return 128 }

func (b *capturingBatcher) WriteBatch(ctx context.Context, peer net.Addr, packets [][]byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, packet := range packets {
		b.writes = append(b.writes, append([]byte(nil), packet...))
	}
	return len(packets), ctx.Err()
}

func (b *capturingBatcher) ReadBatch(ctx context.Context, timeout time.Duration, bufs []batchReadBuffer) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return 0, testTimeoutError{}
}

func firstPacketOfType(t *testing.T, packets [][]byte, typ PacketType) Packet {
	t.Helper()
	for _, wire := range packets {
		packet, err := UnmarshalPacket(wire, nil)
		if err != nil {
			t.Fatalf("UnmarshalPacket() error = %v", err)
		}
		if packet.Type == typ {
			return packet
		}
	}
	t.Fatalf("no packet of type %v in %d writes", typ, len(packets))
	return Packet{}
}

func countPacketsOfType(t *testing.T, packets [][]byte, typ PacketType) int {
	t.Helper()
	count := 0
	for _, wire := range packets {
		packet, err := UnmarshalPacket(wire, nil)
		if err != nil {
			t.Fatalf("UnmarshalPacket() error = %v", err)
		}
		if packet.Type == typ {
			count++
		}
	}
	return count
}

type singleRepairRequestBatcher struct {
	capturingBatcher
	runID [16]byte
	seq   uint64
	sent  bool
}

func (b *singleRepairRequestBatcher) ReadBatch(ctx context.Context, timeout time.Duration, bufs []batchReadBuffer) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if b.sent || len(bufs) == 0 {
		return 0, testTimeoutError{}
	}
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, b.seq)
	packet, err := MarshalPacket(Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeRepairRequest,
		RunID:   b.runID,
		Payload: payload,
	}, nil)
	if err != nil {
		return 0, err
	}
	copy(bufs[0].Bytes, packet)
	bufs[0].N = len(packet)
	b.sent = true
	return 1, nil
}

type repeatingRepairRequestBatcher struct {
	capturingBatcher
	runID [16]byte
	seq   uint64
	delay time.Duration
}

func (b *repeatingRepairRequestBatcher) ReadBatch(ctx context.Context, timeout time.Duration, bufs []batchReadBuffer) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(bufs) == 0 {
		return 0, testTimeoutError{}
	}
	if b.delay > 0 {
		timer := time.NewTimer(b.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-timer.C:
		}
	}
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, b.seq)
	packet, err := MarshalPacket(Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeRepairRequest,
		RunID:   b.runID,
		Payload: payload,
	}, nil)
	if err != nil {
		return 0, err
	}
	copy(bufs[0].Bytes, packet)
	bufs[0].N = len(packet)
	return 1, nil
}

type inflightRepairBatcher struct {
	mu          sync.Mutex
	runID       [16]byte
	repairSeq   uint64
	queued      bool
	delivered   bool
	writes      [][]byte
	repairIndex int
}

func (b *inflightRepairBatcher) Capabilities() TransportCaps { return TransportCaps{Kind: "test"} }
func (b *inflightRepairBatcher) MaxBatch() int               { return 128 }

func (b *inflightRepairBatcher) WriteBatch(ctx context.Context, peer net.Addr, packets [][]byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, packet := range packets {
		packetCopy := append([]byte(nil), packet...)
		packetType, _, runID, seq, _, ok := decodeBlastPacketFull(packetCopy)
		if ok && packetType == PacketTypeData && runID == b.runID && seq == b.repairSeq && !b.queued {
			b.queued = true
			b.repairIndex = len(b.writes)
		}
		b.writes = append(b.writes, packetCopy)
	}
	return len(packets), ctx.Err()
}

func (b *inflightRepairBatcher) ReadBatch(ctx context.Context, timeout time.Duration, bufs []batchReadBuffer) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.queued || b.delivered || len(bufs) == 0 {
		return 0, testTimeoutError{}
	}
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, b.repairSeq)
	packet, err := MarshalPacket(Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeRepairRequest,
		RunID:   b.runID,
		Payload: payload,
	}, nil)
	if err != nil {
		return 0, err
	}
	copy(bufs[0].Bytes, packet)
	bufs[0].N = len(packet)
	b.delivered = true
	return 1, nil
}

type testTimeoutError struct{}

func (testTimeoutError) Error() string   { return "synthetic timeout" }
func (testTimeoutError) Timeout() bool   { return true }
func (testTimeoutError) Temporary() bool { return true }

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

type writeDeadlineRecordingPacketConn struct {
	net.PacketConn

	mu        sync.Mutex
	deadlines []time.Time
}

func (c *writeDeadlineRecordingPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, t)
	c.mu.Unlock()
	return c.PacketConn.SetWriteDeadline(t)
}

func (c *writeDeadlineRecordingPacketConn) writeDeadlines() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.deadlines...)
}

type readDeadlineRecordingPacketConn struct {
	net.PacketConn

	mu        sync.Mutex
	deadlines []time.Time
}

func (c *readDeadlineRecordingPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, t)
	c.mu.Unlock()
	return c.PacketConn.SetReadDeadline(t)
}

func (c *readDeadlineRecordingPacketConn) readDeadlines() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.deadlines...)
}

func TestWriteWithContextClearsWriteDeadline(t *testing.T) {
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

	conn := &writeDeadlineRecordingPacketConn{PacketConn: a}
	if _, err := writeWithContext(context.Background(), conn, b.LocalAddr(), []byte("hello")); err != nil {
		t.Fatalf("writeWithContext() error = %v", err)
	}

	deadlines := conn.writeDeadlines()
	if len(deadlines) != 2 {
		t.Fatalf("SetWriteDeadline calls = %d, want 2 (%v)", len(deadlines), deadlines)
	}
	if deadlines[0].IsZero() {
		t.Fatalf("first write deadline is zero, want bounded deadline")
	}
	if !deadlines[1].IsZero() {
		t.Fatalf("last write deadline = %v, want zero deadline reset", deadlines[1])
	}
}

func TestPerformHelloHandshakeClearsReadDeadline(t *testing.T) {
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	runID := testRunID(0x91)
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 64<<10)
		n, addr, err := server.ReadFrom(buf)
		if err != nil {
			errCh <- err
			return
		}
		packet, err := UnmarshalPacket(buf[:n], nil)
		if err != nil {
			errCh <- err
			return
		}
		if packet.Type != PacketTypeHello {
			errCh <- errors.New("expected hello packet")
			return
		}
		errCh <- sendHelloAck(context.Background(), server, addr, runID, 0, 1)
	}()

	conn := &readDeadlineRecordingPacketConn{PacketConn: client}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var stats TransferStats
	if _, err := performHelloHandshake(ctx, conn, server.LocalAddr(), runID, 0, 1, &stats); err != nil {
		t.Fatalf("performHelloHandshake() error = %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server handshake error = %v", err)
	}

	deadlines := conn.readDeadlines()
	if len(deadlines) < 2 {
		t.Fatalf("SetReadDeadline calls = %d, want at least 2 (%v)", len(deadlines), deadlines)
	}
	if deadlines[len(deadlines)-2].IsZero() {
		t.Fatalf("penultimate read deadline is zero, want bounded handshake deadline (%v)", deadlines)
	}
	if !deadlines[len(deadlines)-1].IsZero() {
		t.Fatalf("last read deadline = %v, want zero deadline reset", deadlines[len(deadlines)-1])
	}
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
