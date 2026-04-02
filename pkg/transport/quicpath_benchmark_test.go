package transport

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derpcat/pkg/quicpath"
)

const quicLoopbackChunkSize = 32 << 10

func BenchmarkNativeQUICLoopback(b *testing.B) {
	serverUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("ListenPacket(server) error = %v", err)
	}
	defer serverUDP.Close()

	clientUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("ListenPacket(client) error = %v", err)
	}
	defer clientUDP.Close()

	serverConn, clientConn, serverStream, clientStream := benchmarkQUICStreams(b, serverUDP, clientUDP, serverUDP.LocalAddr())
	benchmarkQUICStreamWrites(b, serverConn, clientConn, serverStream, clientStream)
}

func BenchmarkManagerQUICLoopback(b *testing.B) {
	serverUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("ListenPacket(server) error = %v", err)
	}
	defer serverUDP.Close()

	clientUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("ListenPacket(client) error = %v", err)
	}
	defer clientUDP.Close()

	serverMgr := newBenchmarkDirectManager(serverUDP, clientUDP.LocalAddr())
	clientMgr := newBenchmarkDirectManager(clientUDP, serverUDP.LocalAddr())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := serverMgr.Start(ctx); err != nil {
		b.Fatalf("Start(server) error = %v", err)
	}
	if err := clientMgr.Start(ctx); err != nil {
		b.Fatalf("Start(client) error = %v", err)
	}

	serverAdapter := quicpath.NewAdapter(serverMgr.PeerDatagramConn(ctx))
	clientAdapter := quicpath.NewAdapter(clientMgr.PeerDatagramConn(ctx))
	defer serverAdapter.Close()
	defer clientAdapter.Close()

	serverConn, clientConn, serverStream, clientStream := benchmarkQUICStreams(b, serverAdapter, clientAdapter, serverAdapter.LocalAddr())
	benchmarkQUICStreamWrites(b, serverConn, clientConn, serverStream, clientStream)
}

func BenchmarkManagerQUICLoopbackRelayAddrAlias(b *testing.B) {
	serverUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("ListenPacket(server) error = %v", err)
	}
	defer serverUDP.Close()

	clientUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("ListenPacket(client) error = %v", err)
	}
	defer clientUDP.Close()

	relayAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	serverMgr := newBenchmarkDirectManagerWithRelayAddr(serverUDP, clientUDP.LocalAddr(), relayAddr)
	clientMgr := newBenchmarkDirectManagerWithRelayAddr(clientUDP, serverUDP.LocalAddr(), relayAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := serverMgr.Start(ctx); err != nil {
		b.Fatalf("Start(server) error = %v", err)
	}
	if err := clientMgr.Start(ctx); err != nil {
		b.Fatalf("Start(client) error = %v", err)
	}

	serverPeerConn := serverMgr.PeerDatagramConn(ctx)
	clientPeerConn := clientMgr.PeerDatagramConn(ctx)
	serverAdapter := quicpath.NewAdapter(serverPeerConn)
	clientAdapter := quicpath.NewAdapter(clientPeerConn)
	defer serverAdapter.Close()
	defer clientAdapter.Close()

	serverConn, clientConn, serverStream, clientStream := benchmarkQUICStreams(b, serverAdapter, clientAdapter, clientPeerConn.RemoteAddr())
	benchmarkQUICStreamWrites(b, serverConn, clientConn, serverStream, clientStream)
}

func newBenchmarkDirectManager(conn net.PacketConn, peerAddr net.Addr) *Manager {
	return newBenchmarkDirectManagerWithRelayAddr(conn, peerAddr, nil)
}

func newBenchmarkDirectManagerWithRelayAddr(conn net.PacketConn, peerAddr, relayAddr net.Addr) *Manager {
	mgr := NewManager(ManagerConfig{
		RelayAddr:          relayAddr,
		DirectConn:         conn,
		DisableDirectReads: false,
		Clock:              realClock{},
		DirectStaleTimeout: time.Minute,
	})
	mgr.mu.Lock()
	mgr.state.endpoints[peerAddr.String()] = peerAddr
	mgr.state.current = PathDirect
	mgr.state.bestEndpoint = peerAddr.String()
	mgr.state.lastDirectAt = mgr.now()
	mgr.mu.Unlock()
	return mgr
}

func benchmarkQUICStreams(b *testing.B, serverPacketConn, clientPacketConn net.PacketConn, serverAddr net.Addr) (*quic.Conn, *quic.Conn, *quic.Stream, *quic.Stream) {
	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		b.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		b.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	listener, err := quic.Listen(serverPacketConn, quicpath.ServerTLSConfig(serverIdentity, clientIdentity.Public), quicpath.DefaultQUICConfig())
	if err != nil {
		b.Fatalf("quic.Listen() error = %v", err)
	}
	b.Cleanup(func() { _ = listener.Close() })

	acceptedConnCh := make(chan *quic.Conn, 1)
	acceptErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			acceptErrCh <- err
			return
		}
		acceptedConnCh <- conn
	}()

	clientConn, err := quic.Dial(context.Background(), clientPacketConn, serverAddr, quicpath.ClientTLSConfig(clientIdentity, serverIdentity.Public), quicpath.DefaultQUICConfig())
	if err != nil {
		b.Fatalf("quic.Dial() error = %v", err)
	}
	b.Cleanup(func() { _ = clientConn.CloseWithError(0, "") })

	var serverConn *quic.Conn
	select {
	case serverConn = <-acceptedConnCh:
	case err := <-acceptErrCh:
		b.Fatalf("listener.Accept() error = %v", err)
	case <-time.After(5 * time.Second):
		b.Fatal("listener.Accept() timed out")
	}
	b.Cleanup(func() { _ = serverConn.CloseWithError(0, "") })

	serverStreamCh := make(chan *quic.Stream, 1)
	streamErrCh := make(chan error, 1)
	go func() {
		stream, err := serverConn.AcceptStream(context.Background())
		if err != nil {
			streamErrCh <- err
			return
		}
		serverStreamCh <- stream
	}()

	clientStream, err := clientConn.OpenStreamSync(context.Background())
	if err != nil {
		b.Fatalf("OpenStreamSync() error = %v", err)
	}
	b.Cleanup(func() { _ = clientStream.Close() })
	if _, err := clientStream.Write([]byte{0}); err != nil {
		b.Fatalf("priming Write() error = %v", err)
	}

	var serverStream *quic.Stream
	select {
	case serverStream = <-serverStreamCh:
	case err := <-streamErrCh:
		b.Fatalf("AcceptStream() error = %v", err)
	case <-time.After(5 * time.Second):
		b.Fatal("AcceptStream() timed out")
	}
	b.Cleanup(func() { _ = serverStream.Close() })
	if _, err := io.ReadFull(serverStream, make([]byte, 1)); err != nil {
		b.Fatalf("priming Read() error = %v", err)
	}

	return serverConn, clientConn, serverStream, clientStream
}

func benchmarkQUICStreamWrites(b *testing.B, _ *quic.Conn, _ *quic.Conn, serverStream, clientStream *quic.Stream) {
	payload := make([]byte, quicLoopbackChunkSize)
	drainDone := make(chan error, 1)
	totalBytes := int64(b.N * len(payload))

	go func() {
		var received int64
		buf := make([]byte, quicLoopbackChunkSize)
		for received < totalBytes {
			n, err := serverStream.Read(buf)
			received += int64(n)
			if err != nil {
				if err == io.EOF && received == totalBytes {
					drainDone <- nil
					return
				}
				drainDone <- err
				return
			}
		}
		drainDone <- nil
	}()

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := clientStream.Write(payload); err != nil {
			b.Fatalf("Write() error = %v", err)
		}
	}
	if err := clientStream.Close(); err != nil && err != io.EOF && err != net.ErrClosed {
		b.Fatalf("client stream Close() error = %v", err)
	}
	if err := <-drainDone; err != nil {
		b.Fatalf("server stream Read() error = %v", err)
	}
}
