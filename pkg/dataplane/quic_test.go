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
