package quicpath

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derphole/pkg/transport"
)

type relayPipe struct {
	inbound chan []byte
	peer    *relayPipe
	addr    net.Addr
}

func newRelayPipePair() (*relayPipe, *relayPipe) {
	a := &relayPipe{
		inbound: make(chan []byte, 256),
		addr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
	}
	b := &relayPipe{
		inbound: make(chan []byte, 256),
		addr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2},
	}
	a.peer = b
	b.peer = a
	return a, b
}

func (p *relayPipe) send(_ context.Context, payload []byte) error {
	p.peer.inbound <- append([]byte(nil), payload...)
	return nil
}

func (p *relayPipe) receive(ctx context.Context) ([]byte, error) {
	select {
	case payload := <-p.inbound:
		return append([]byte(nil), payload...), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestQUICStreamSurvivesRelayToDirectUpgrade(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relayA, relayB := newRelayPipePair()
	directA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(directA) error = %v", err)
	}
	defer directA.Close()
	directB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(directB) error = %v", err)
	}
	defer directB.Close()

	managerA := transport.NewManager(transport.ManagerConfig{
		RelaySend:          relayA.send,
		ReceiveRelay:       relayA.receive,
		RelayAddr:          relayA.addr,
		DirectConn:         directA,
		DisableDirectReads: false,
		DiscoveryInterval:  100 * time.Millisecond,
		DirectStaleTimeout: 5 * time.Second,
	})
	managerB := transport.NewManager(transport.ManagerConfig{
		RelaySend:          relayB.send,
		ReceiveRelay:       relayB.receive,
		RelayAddr:          relayB.addr,
		DirectConn:         directB,
		DisableDirectReads: false,
		DiscoveryInterval:  100 * time.Millisecond,
		DirectStaleTimeout: 5 * time.Second,
	})
	if err := managerA.Start(ctx); err != nil {
		t.Fatalf("managerA.Start() error = %v", err)
	}
	if err := managerB.Start(ctx); err != nil {
		t.Fatalf("managerB.Start() error = %v", err)
	}

	serverIdentity, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	serverAdapter := NewAdapter(managerB.PeerDatagramConn(ctx))
	defer serverAdapter.Close()
	listener, err := quic.Listen(serverAdapter, ServerTLSConfig(serverIdentity, clientIdentity.Public), DefaultQUICConfig())
	if err != nil {
		t.Fatalf("quic.Listen() error = %v", err)
	}
	defer listener.Close()

	initialReceived := make(chan struct{}, 1)
	directReceived := make(chan struct{}, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.CloseWithError(0, "")
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		defer stream.Close()

		initial := make([]byte, len("relay"))
		if _, err := io.ReadFull(stream, initial); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(initial, []byte("relay")) {
			serverErr <- err
			return
		}
		initialReceived <- struct{}{}

		direct := make([]byte, len("direct"))
		if _, err := io.ReadFull(stream, direct); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(direct, []byte("direct")) {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		directReceived <- struct{}{}

		buf := make([]byte, 1)
		n, err := stream.Read(buf)
		if err != io.EOF {
			serverErr <- err
			return
		}
		if n != 0 {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		serverErr <- nil
	}()

	clientAdapter := NewAdapter(managerA.PeerDatagramConn(ctx))
	defer clientAdapter.Close()
	clientConn, err := quic.Dial(ctx, clientAdapter, managerA.PeerDatagramConn(ctx).RemoteAddr(), ClientTLSConfig(clientIdentity, serverIdentity.Public), DefaultQUICConfig())
	if err != nil {
		t.Fatalf("quic.Dial() error = %v", err)
	}
	defer clientConn.CloseWithError(0, "")
	stream, err := clientConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync() error = %v", err)
	}

	if _, err := stream.Write([]byte("relay")); err != nil {
		t.Fatalf("stream.Write(relay) error = %v", err)
	}
	select {
	case <-initialReceived:
	case err := <-serverErr:
		t.Fatalf("server error before upgrade = %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for relay payload")
	}

	managerA.SeedRemoteCandidates(ctx, []net.Addr{directB.LocalAddr()})
	managerB.SeedRemoteCandidates(ctx, []net.Addr{directA.LocalAddr()})
	waitForPathState(t, managerA, transport.PathDirect, 2*time.Second)
	waitForPathState(t, managerB, transport.PathDirect, 2*time.Second)

	if _, err := stream.Write([]byte("direct")); err != nil {
		t.Fatalf("stream.Write(direct) error = %v", err)
	}
	select {
	case <-directReceived:
	case err := <-serverErr:
		t.Fatalf("server error after direct payload = %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for direct payload")
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("stream.Close() error = %v", err)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for server result")
	}
}

func TestQUICDialRejectsMismatchedPinnedServerIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	relayA, relayB := newRelayPipePair()
	directA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(directA) error = %v", err)
	}
	defer directA.Close()
	directB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(directB) error = %v", err)
	}
	defer directB.Close()
	managerA := transport.NewManager(transport.ManagerConfig{
		RelaySend:          relayA.send,
		ReceiveRelay:       relayA.receive,
		RelayAddr:          relayA.addr,
		DirectConn:         directA,
		DisableDirectReads: false,
		DiscoveryInterval:  time.Second,
		DirectStaleTimeout: 5 * time.Second,
	})
	managerB := transport.NewManager(transport.ManagerConfig{
		RelaySend:          relayB.send,
		ReceiveRelay:       relayB.receive,
		RelayAddr:          relayB.addr,
		DirectConn:         directB,
		DisableDirectReads: false,
		DiscoveryInterval:  time.Second,
		DirectStaleTimeout: 5 * time.Second,
	})
	if err := managerA.Start(ctx); err != nil {
		t.Fatalf("managerA.Start() error = %v", err)
	}
	if err := managerB.Start(ctx); err != nil {
		t.Fatalf("managerB.Start() error = %v", err)
	}

	serverIdentity, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}
	wrongServerIdentity, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(wrong server) error = %v", err)
	}

	serverAdapter := NewAdapter(managerB.PeerDatagramConn(ctx))
	defer serverAdapter.Close()
	listener, err := quic.Listen(serverAdapter, ServerTLSConfig(serverIdentity, clientIdentity.Public), DefaultQUICConfig())
	if err != nil {
		t.Fatalf("quic.Listen() error = %v", err)
	}
	defer listener.Close()

	clientAdapter := NewAdapter(managerA.PeerDatagramConn(ctx))
	defer clientAdapter.Close()
	_, err = quic.Dial(ctx, clientAdapter, managerA.PeerDatagramConn(ctx).RemoteAddr(), ClientTLSConfig(clientIdentity, wrongServerIdentity.Public), DefaultQUICConfig())
	if err == nil {
		t.Fatal("quic.Dial() error = nil, want peer identity mismatch")
	}
}

func waitForPathState(t *testing.T, mgr *transport.Manager, want transport.Path, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if mgr.PathState() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("PathState() = %v, want %v", mgr.PathState(), want)
}
