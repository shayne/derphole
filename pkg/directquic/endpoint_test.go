// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package directquic

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/quicpath"
)

func TestEndpointTransfersOneUnidirectionalStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(server) error = %v", err)
	}
	defer serverPacketConn.Close()

	clientPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(client) error = %v", err)
	}
	defer clientPacketConn.Close()

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	serverCh := make(chan *Endpoint, 1)
	serverErr := make(chan error, 1)
	go func() {
		endpoint, err := Listen(ctx, ListenConfig{
			PacketConn: serverPacketConn,
			Identity:   serverIdentity,
			PeerPublic: clientIdentity.Public,
		})
		if err != nil {
			serverErr <- err
			return
		}
		serverCh <- endpoint
	}()

	client, err := Dial(ctx, DialConfig{
		PacketConn: clientPacketConn,
		RemoteAddr: serverPacketConn.LocalAddr(),
		Identity:   clientIdentity,
		PeerPublic: serverIdentity.Public,
	})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	var server *Endpoint
	select {
	case server = <-serverCh:
	case err := <-serverErr:
		t.Fatalf("Listen() error = %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for server endpoint")
	}
	defer server.Close()

	payload := []byte("direct-quic payload")
	send, err := client.OpenSendStream(ctx)
	if err != nil {
		t.Fatalf("OpenSendStream() error = %v", err)
	}
	if _, err := send.Write(payload); err != nil {
		t.Fatalf("send.Write() error = %v", err)
	}
	if err := send.Close(); err != nil {
		t.Fatalf("send.Close() error = %v", err)
	}

	receive, err := server.AcceptReceiveStream(ctx)
	if err != nil {
		t.Fatalf("AcceptReceiveStream() error = %v", err)
	}
	defer receive.Close()

	var got bytes.Buffer
	if _, err := io.Copy(&got, receive); err != nil {
		t.Fatalf("io.Copy() error = %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("payload = %q, want %q", got.Bytes(), payload)
	}
}

func TestEndpointTransfersMultipleUnidirectionalStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(server) error = %v", err)
	}
	defer serverPacketConn.Close()

	clientPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(client) error = %v", err)
	}
	defer clientPacketConn.Close()

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	serverCh := make(chan *Endpoint, 1)
	serverErr := make(chan error, 1)
	go func() {
		endpoint, err := Listen(ctx, ListenConfig{
			PacketConn: serverPacketConn,
			Identity:   serverIdentity,
			PeerPublic: clientIdentity.Public,
		})
		if err != nil {
			serverErr <- err
			return
		}
		serverCh <- endpoint
	}()

	client, err := Dial(ctx, DialConfig{
		PacketConn: clientPacketConn,
		RemoteAddr: serverPacketConn.LocalAddr(),
		Identity:   clientIdentity,
		PeerPublic: serverIdentity.Public,
	})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	var server *Endpoint
	select {
	case server = <-serverCh:
	case err := <-serverErr:
		t.Fatalf("Listen() error = %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for server endpoint")
	}
	defer server.Close()

	sendStreams, err := client.OpenSendStreams(ctx, 3)
	if err != nil {
		t.Fatalf("OpenSendStreams() error = %v", err)
	}
	for i, stream := range sendStreams {
		payload := []byte{byte('a' + i)}
		if _, err := stream.Write(payload); err != nil {
			t.Fatalf("send stream %d Write() error = %v", i, err)
		}
		if err := stream.Close(); err != nil {
			t.Fatalf("send stream %d Close() error = %v", i, err)
		}
	}
	receiveStreams, err := server.AcceptReceiveStreams(ctx, 3)
	if err != nil {
		t.Fatalf("AcceptReceiveStreams() error = %v", err)
	}
	defer closeReadClosers(receiveStreams)

	for i, stream := range receiveStreams {
		var got [1]byte
		if _, err := io.ReadFull(stream, got[:]); err != nil {
			t.Fatalf("receive stream %d ReadFull() error = %v", i, err)
		}
		if want := byte('a' + i); got[0] != want {
			t.Fatalf("receive stream %d byte = %q, want %q", i, got[0], want)
		}
	}
}

func TestEndpointStatsAggregateMultipleConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(server) error = %v", err)
	}
	defer serverPacketConn.Close()

	clientPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(client) error = %v", err)
	}
	defer clientPacketConn.Close()

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	const connCount = 3
	serverCh := make(chan *Endpoint, 1)
	serverErr := make(chan error, 1)
	go func() {
		endpoint, err := ListenConnectionsWithReady(ctx, ListenConfig{
			PacketConn: serverPacketConn,
			Identity:   serverIdentity,
			PeerPublic: clientIdentity.Public,
		}, connCount, nil)
		if err != nil {
			serverErr <- err
			return
		}
		serverCh <- endpoint
	}()

	client, err := DialConnections(ctx, DialConfig{
		PacketConn: clientPacketConn,
		RemoteAddr: serverPacketConn.LocalAddr(),
		Identity:   clientIdentity,
		PeerPublic: serverIdentity.Public,
	}, connCount)
	if err != nil {
		t.Fatalf("DialConnections() error = %v", err)
	}
	defer client.Close()

	var server *Endpoint
	select {
	case server = <-serverCh:
	case err := <-serverErr:
		t.Fatalf("ListenConnectionsWithReady() error = %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for server endpoint")
	}
	defer server.Close()

	sendStreams, err := client.OpenSendStreams(ctx, connCount)
	if err != nil {
		t.Fatalf("OpenSendStreams() error = %v", err)
	}
	for i, stream := range sendStreams {
		payload := []byte{byte('A' + i)}
		if _, err := stream.Write(payload); err != nil {
			t.Fatalf("send stream %d Write() error = %v", i, err)
		}
		if err := stream.Close(); err != nil {
			t.Fatalf("send stream %d Close() error = %v", i, err)
		}
	}
	receiveStreams, err := server.AcceptReceiveStreams(ctx, connCount)
	if err != nil {
		t.Fatalf("AcceptReceiveStreams() error = %v", err)
	}
	defer closeReadClosers(receiveStreams)

	seen := make(map[byte]bool, connCount)
	for i, stream := range receiveStreams {
		var got [1]byte
		if _, err := io.ReadFull(stream, got[:]); err != nil {
			t.Fatalf("receive stream %d ReadFull() error = %v", i, err)
		}
		if got[0] < 'A' || got[0] >= 'A'+connCount {
			t.Fatalf("receive stream %d byte = %q, want one of A-C", i, got[0])
		}
		if seen[got[0]] {
			t.Fatalf("receive stream %d byte = %q, duplicate payload", i, got[0])
		}
		seen[got[0]] = true
	}
	for i := range connCount {
		if !seen[byte('A'+i)] {
			t.Fatalf("missing payload %q from receive streams", byte('A'+i))
		}
	}

	clientStats := client.Stats()
	if !clientStats.TelemetryPresent {
		t.Fatalf("client mechanism evidence is absent: %+v", clientStats)
	}
	if clientStats.Connections != connCount || clientStats.Streams != connCount {
		t.Fatalf("client mechanism counts = connections:%d streams:%d, want %d/%d", clientStats.Connections, clientStats.Streams, connCount, connCount)
	}
	if clientStats.PacketsSent == 0 || clientStats.WireBytesSent == 0 || clientStats.Version == "" {
		t.Fatalf("client mechanism stats are incomplete: %+v", clientStats)
	}
	if clientStats.RawSocketBackend == "" || clientStats.NativeSendBackend == "" || clientStats.NativeReceiveBackend == "" || clientStats.NativeGSO == "" || clientStats.NativeReceiveBatch == "" {
		t.Fatalf("client backend identity is incomplete: %+v", clientStats)
	}
	serverStats := server.Stats()
	if !serverStats.TelemetryPresent {
		t.Fatalf("server mechanism evidence is absent: %+v", serverStats)
	}
	if serverStats.Connections != connCount || serverStats.Streams != connCount || serverStats.PacketsReceived == 0 {
		t.Fatalf("server mechanism stats are incomplete: %+v", serverStats)
	}
}

func TestEndpointWaitClosedReturnsForNilAndClosedEndpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var nilEndpoint *Endpoint
	if err := nilEndpoint.WaitClosed(ctx); err != nil {
		t.Fatalf("nil WaitClosed() error = %v", err)
	}
	if err := (&Endpoint{}).WaitClosed(ctx); err != nil {
		t.Fatalf("empty WaitClosed() error = %v", err)
	}

	serverPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(server) error = %v", err)
	}
	defer serverPacketConn.Close()
	clientPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(client) error = %v", err)
	}
	defer clientPacketConn.Close()

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	serverCh := make(chan *Endpoint, 1)
	serverErr := make(chan error, 1)
	go func() {
		endpoint, err := Listen(ctx, ListenConfig{
			PacketConn: serverPacketConn,
			Identity:   serverIdentity,
			PeerPublic: clientIdentity.Public,
		})
		if err != nil {
			serverErr <- err
			return
		}
		serverCh <- endpoint
	}()

	client, err := Dial(ctx, DialConfig{
		PacketConn: clientPacketConn,
		RemoteAddr: serverPacketConn.LocalAddr(),
		Identity:   clientIdentity,
		PeerPublic: serverIdentity.Public,
	})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	var server *Endpoint
	select {
	case server = <-serverCh:
	case err := <-serverErr:
		t.Fatalf("Listen() error = %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for server endpoint")
	}
	defer server.Close()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Millisecond)
	if err := client.WaitClosed(waitCtx); err == nil {
		t.Fatal("WaitClosed(open) error = nil, want context deadline")
	}
	waitCancel()

	if err := client.Close(); err != nil {
		t.Fatalf("client Close() error = %v", err)
	}
	if err := client.WaitClosed(ctx); err != nil {
		t.Fatalf("WaitClosed(closed) error = %v", err)
	}
}

func TestListenWithReadyRunsBeforeAccept(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(server) error = %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(client) error = %v", err)
	}
	defer clientConn.Close()

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	ready := make(chan struct{})
	serverCh := make(chan *Endpoint, 1)
	serverErr := make(chan error, 1)
	go func() {
		server, err := ListenWithReady(ctx, ListenConfig{
			PacketConn: serverConn,
			Identity:   serverIdentity,
			PeerPublic: clientIdentity.Public,
		}, func() error {
			close(ready)
			return nil
		})
		if err != nil {
			serverErr <- err
			return
		}
		serverCh <- server
	}()

	select {
	case <-ready:
	case err := <-serverErr:
		t.Fatalf("ListenWithReady() error before ready = %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for ready callback")
	}

	client, err := Dial(ctx, DialConfig{
		PacketConn: clientConn,
		RemoteAddr: serverConn.LocalAddr(),
		Identity:   clientIdentity,
		PeerPublic: serverIdentity.Public,
	})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	select {
	case server := <-serverCh:
		defer server.Close()
	case err := <-serverErr:
		t.Fatalf("ListenWithReady() error = %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for server accept")
	}
}

func TestDialRejectsUnexpectedPeerIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(server) error = %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(client) error = %v", err)
	}
	defer clientConn.Close()

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}
	wrongServerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(wrong) error = %v", err)
	}

	serverErr := make(chan error, 1)
	go func() {
		server, err := Listen(ctx, ListenConfig{
			PacketConn: serverConn,
			Identity:   serverIdentity,
			PeerPublic: clientIdentity.Public,
		})
		if server != nil {
			defer server.Close()
		}
		serverErr <- err
	}()

	client, err := Dial(ctx, DialConfig{
		PacketConn: clientConn,
		RemoteAddr: serverConn.LocalAddr(),
		Identity:   clientIdentity,
		PeerPublic: wrongServerIdentity.Public,
	})
	if err == nil {
		_ = client.Close()
		t.Fatal("Dial() error = nil, want peer identity mismatch")
	}
	cancel()
	select {
	case err := <-serverErr:
		if err == nil {
			t.Fatal("Listen() error = nil, want handshake or context cancellation error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server Listen() to exit")
	}
}

func TestStatsRecordBytesAndCloseReason(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(server) error = %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(client) error = %v", err)
	}
	defer clientConn.Close()

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	serverReady := make(chan *Endpoint, 1)
	serverDone := make(chan error, 1)
	go func() {
		server, err := Listen(ctx, ListenConfig{PacketConn: serverConn, Identity: serverIdentity, PeerPublic: clientIdentity.Public})
		if err != nil {
			serverDone <- err
			return
		}
		serverReady <- server
		stream, err := server.AcceptReceiveStream(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		_, err = io.Copy(io.Discard, stream)
		_ = stream.Close()
		serverDone <- err
	}()

	client, err := Dial(ctx, DialConfig{PacketConn: clientConn, RemoteAddr: serverConn.LocalAddr(), Identity: clientIdentity, PeerPublic: serverIdentity.Public})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	stream, err := client.OpenSendStream(ctx)
	if err != nil {
		t.Fatalf("OpenSendStream() error = %v", err)
	}
	if _, err := stream.Write([]byte("abcdef")); err != nil {
		t.Fatalf("stream.Write() error = %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("stream.Close() error = %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("serverDone error = %v", err)
	}
	server := <-serverReady
	if err := client.CloseWithError(7, "test-close"); err != nil {
		t.Fatalf("CloseWithError(client) error = %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close(server) error = %v", err)
	}

	clientStats := client.Stats()
	if clientStats.BytesSent != 6 {
		t.Fatalf("client BytesSent = %d, want 6", clientStats.BytesSent)
	}
	if clientStats.CloseReason != "test-close" {
		t.Fatalf("client CloseReason = %q, want test-close", clientStats.CloseReason)
	}
	serverStats := server.Stats()
	if serverStats.BytesReceived != 6 {
		t.Fatalf("server BytesReceived = %d, want 6", serverStats.BytesReceived)
	}
}
