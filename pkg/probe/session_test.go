package probe

import (
	"bytes"
	"context"
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
