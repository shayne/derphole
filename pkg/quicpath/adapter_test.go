package quicpath

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
)

type fakePeerDatagramConn struct {
	sendCh   chan []byte
	recvCh   chan []byte
	doneCh   chan struct{}
	local    net.Addr
	remote   net.Addr
	recvAddr net.Addr
}

func newFakePeerDatagramConn() *fakePeerDatagramConn {
	return &fakePeerDatagramConn{
		sendCh: make(chan []byte, 1),
		recvCh: make(chan []byte, 1),
		doneCh: make(chan struct{}),
		local:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1111},
		remote: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222},
	}
}

func (f *fakePeerDatagramConn) SendDatagram(p []byte) error {
	f.sendCh <- append([]byte(nil), p...)
	return nil
}

func (f *fakePeerDatagramConn) RecvDatagram(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case p := <-f.recvCh:
		if f.recvAddr != nil {
			return append([]byte(nil), p...), f.recvAddr, nil
		}
		return append([]byte(nil), p...), f.remote, nil
	case <-f.doneCh:
		return nil, nil, context.Canceled
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func (f *fakePeerDatagramConn) LocalAddr() net.Addr  { return f.local }
func (f *fakePeerDatagramConn) RemoteAddr() net.Addr { return f.remote }
func (f *fakePeerDatagramConn) Close() error {
	select {
	case <-f.doneCh:
	default:
		close(f.doneCh)
	}
	return nil
}

func TestAdapterDeliversInboundPackets(t *testing.T) {
	peer := newFakePeerDatagramConn()
	conn := NewAdapter(peer)
	t.Cleanup(func() { _ = conn.Close() })

	peer.recvCh <- []byte("payload")

	buf := make([]byte, 32)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if got := string(buf[:n]); got != "payload" {
		t.Fatalf("ReadFrom() payload = %q, want %q", got, "payload")
	}
	if got := addr.String(); got != peer.remote.String() {
		t.Fatalf("ReadFrom() addr = %q, want %q", got, peer.remote.String())
	}
}

func TestAdapterReadFromUsesStableRemoteAddr(t *testing.T) {
	peer := newFakePeerDatagramConn()
	peer.recvAddr = &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 4242}
	conn := NewAdapter(peer)
	t.Cleanup(func() { _ = conn.Close() })

	peer.recvCh <- []byte("payload")

	buf := make([]byte, 32)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if got := string(buf[:n]); got != "payload" {
		t.Fatalf("ReadFrom() payload = %q, want %q", got, "payload")
	}
	if got := addr.String(); got != peer.remote.String() {
		t.Fatalf("ReadFrom() addr = %q, want stable peer addr %q", got, peer.remote.String())
	}
}

func TestAdapterWriteToUsesTransportSend(t *testing.T) {
	peer := newFakePeerDatagramConn()
	conn := NewAdapter(peer)
	t.Cleanup(func() { _ = conn.Close() })

	n, err := conn.WriteTo([]byte("hello"), peer.remote)
	if err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	if n != len("hello") {
		t.Fatalf("WriteTo() n = %d, want %d", n, len("hello"))
	}

	select {
	case sent := <-peer.sendCh:
		if got := string(sent); got != "hello" {
			t.Fatalf("transport payload = %q, want %q", got, "hello")
		}
	case <-time.After(time.Second):
		t.Fatal("transport did not receive datagram")
	}
}

func TestAdapterCloseUnblocksReaders(t *testing.T) {
	peer := newFakePeerDatagramConn()
	conn := NewAdapter(peer)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		_, _, err := conn.ReadFrom(buf)
		errCh <- err
	}()

	time.Sleep(20 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ReadFrom() error = nil, want net.ErrClosed")
		}
		if err != net.ErrClosed {
			t.Fatalf("ReadFrom() error = %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadFrom() remained blocked after Close()")
	}
}

type syscallPeerDatagramConn struct {
	*fakePeerDatagramConn
	conn *net.UDPConn
}

func (p *syscallPeerDatagramConn) SyscallConn() (syscall.RawConn, error) {
	return p.conn.SyscallConn()
}

func TestAdapterDoesNotExposeSyscallConnEvenWhenPeerDoes(t *testing.T) {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })

	conn := NewAdapter(&syscallPeerDatagramConn{
		fakePeerDatagramConn: newFakePeerDatagramConn(),
		conn:                 udpConn,
	})
	t.Cleanup(func() { _ = conn.Close() })

	sysConn, ok := any(conn).(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if ok {
		rawConn, err := sysConn.SyscallConn()
		t.Fatalf("NewAdapter() exposes SyscallConn = (%v, %v), want no SyscallConn", rawConn, err)
	}
}
