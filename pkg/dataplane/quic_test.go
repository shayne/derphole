// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dataplane

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/transport"
)

type relayPipe struct {
	inbound chan []byte
	peer    *relayPipe
	addr    net.Addr
}

func newRelayPipePair() (*relayPipe, *relayPipe) {
	a := &relayPipe{inbound: make(chan []byte, 256), addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001}}
	b := &relayPipe{inbound: make(chan []byte, 256), addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10002}}
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

func TestQUICDataPlaneCopiesOverRelayManager(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relayA, relayB := newRelayPipePair()
	relayConnA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(relayConnA) error = %v", err)
	}
	defer relayConnA.Close()
	relayConnB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(relayConnB) error = %v", err)
	}
	defer relayConnB.Close()
	managerA := transport.NewManager(transport.ManagerConfig{RelayConn: relayConnA, RelaySend: relayA.send, ReceiveRelay: relayA.receive, RelayAddr: relayA.addr})
	managerB := transport.NewManager(transport.ManagerConfig{RelayConn: relayConnB, RelaySend: relayB.send, ReceiveRelay: relayB.receive, RelayAddr: relayB.addr})
	if err := managerA.Start(ctx); err != nil {
		t.Fatalf("managerA.Start() error = %v", err)
	}
	if err := managerB.Start(ctx); err != nil {
		t.Fatalf("managerB.Start() error = %v", err)
	}
	t.Cleanup(func() {
		cancel()
		managerA.Wait()
		managerB.Wait()
	})

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	var got bytes.Buffer
	recvErr := make(chan error, 1)
	go func() {
		dp := NewQUICServer(managerB, serverIdentity, clientIdentity.Public)
		stream, err := dp.Accept(ctx)
		if err != nil {
			recvErr <- err
			return
		}
		_, copyErr := io.Copy(&got, stream)
		closeErr := stream.Close()
		if copyErr != nil {
			recvErr <- copyErr
			return
		}
		recvErr <- closeErr
	}()

	dp := NewQUICClient(managerA, clientIdentity, serverIdentity.Public)
	stream, err := dp.Open(ctx)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := stream.Write([]byte("payload")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-recvErr; err != nil {
		t.Fatalf("receive error = %v", err)
	}
	if got.String() != "payload" {
		t.Fatalf("received = %q, want payload", got.String())
	}
	if dp.Stats().BytesSent == 0 {
		t.Fatal("Stats().BytesSent = 0, want positive")
	}
}

func TestQUICStatsAggregateAcrossEndpoints(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const streams = 2
	serverConns := make([]net.PacketConn, 0, streams)
	clientConns := make([]net.PacketConn, 0, streams)
	remotes := make([]net.Addr, 0, streams)
	for range streams {
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
		serverConns = append(serverConns, serverConn)
		clientConns = append(clientConns, clientConn)
		remotes = append(remotes, serverConn.LocalAddr())
	}

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	server := NewQUICServerOnPacketConns(serverConns, serverIdentity, clientIdentity.Public)
	ready := make(chan struct{})
	recvErr := make(chan error, 1)
	var got bytes.Buffer
	go func() {
		readers, err := server.AcceptStreamsWithReady(ctx, streams, func() error {
			close(ready)
			return nil
		})
		if err != nil {
			recvErr <- err
			return
		}
		for _, reader := range readers {
			if _, err := io.Copy(&got, reader); err != nil {
				recvErr <- err
				return
			}
			_ = reader.Close()
		}
		recvErr <- nil
	}()

	select {
	case <-ready:
	case err := <-recvErr:
		t.Fatalf("AcceptStreamsWithReady() error before ready = %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for packet listeners")
	}

	client := NewQUICClientOnPacketConns(clientConns, remotes, clientIdentity, serverIdentity.Public)
	writers, err := client.OpenStreams(ctx, streams)
	if err != nil {
		t.Fatalf("OpenStreams() error = %v", err)
	}
	for i, writer := range writers {
		if _, err := writer.Write([]byte{byte('a' + i)}); err != nil {
			t.Fatalf("writer %d Write() error = %v", i, err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("writer %d Close() error = %v", i, err)
		}
	}
	if err := <-recvErr; err != nil {
		t.Fatalf("receive error = %v", err)
	}
	if got.String() != "ab" {
		t.Fatalf("received = %q, want ab", got.String())
	}
	clientStats := client.Stats()
	serverStats := server.Stats()
	if !clientStats.TelemetryPresent || !serverStats.TelemetryPresent {
		t.Fatalf("aggregate mechanism evidence is absent: client=%+v server=%+v", clientStats, serverStats)
	}
	if clientStats.BytesSent == 0 || serverStats.BytesReceived == 0 {
		t.Fatalf("stats not populated: client=%+v server=%+v", clientStats, serverStats)
	}
	if clientStats.Connections != streams || clientStats.Streams != streams || clientStats.PacketsSent == 0 || clientStats.WireBytesSent == 0 {
		t.Fatalf("client aggregate is incomplete: %+v", clientStats)
	}
	if serverStats.Connections != streams || serverStats.Streams != streams || serverStats.PacketsReceived == 0 {
		t.Fatalf("server aggregate is incomplete: %+v", serverStats)
	}
	if clientStats.Version == "" || clientStats.RawSocketBackend == "" || clientStats.NativeSendBackend == "" || clientStats.NativeReceiveBackend == "" || clientStats.NativeGSO == "" || clientStats.NativeReceiveBatch == "" {
		t.Fatalf("client aggregate backend identity is incomplete: %+v", clientStats)
	}
	if err := client.CloseWithError(7, "test-close"); err != nil {
		t.Fatalf("client CloseWithError() error = %v", err)
	}
	if err := server.CloseWithError(0, ""); err != nil {
		t.Fatalf("server CloseWithError() error = %v", err)
	}
}

func TestEndpointConnectionCountUsesOneConnectionPerPacketPath(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()

	if got := endpointConnectionCount(packetPath{conn: conn}, 4); got != 1 {
		t.Fatalf("endpointConnectionCount(raw packet path) = %d, want 1", got)
	}
}

func TestEndpointConnectionCountUsesStreamCountForManagerAdapter(t *testing.T) {
	path := packetPath{adapter: &quicpath.Adapter{}, managerConnections: 4}

	if got := endpointConnectionCount(path, 4); got != 4 {
		t.Fatalf("endpointConnectionCount(manager adapter, 4) = %d, want 4", got)
	}
	if got := endpointConnectionCount(path, 0); got != 1 {
		t.Fatalf("endpointConnectionCount(manager adapter, 0) = %d, want 1", got)
	}
	if got := endpointConnectionCount(packetPath{adapter: &quicpath.Adapter{}, managerConnections: 8}, 4); got != 4 {
		t.Fatalf("endpointConnectionCount(manager adapter, 8 connections, 4 streams) = %d, want 4", got)
	}
}

func TestEndpointConnectionCountKeepsSingleConnectionForDefaultManagerAdapter(t *testing.T) {
	path := packetPath{adapter: &quicpath.Adapter{}}

	if got := endpointConnectionCount(path, 4); got != 1 {
		t.Fatalf("endpointConnectionCount(default manager adapter, 4) = %d, want 1", got)
	}
}
