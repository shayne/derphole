// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transport"
)

type directQUICRelayPipe struct {
	inbound chan []byte
	peer    *directQUICRelayPipe
	addr    net.Addr
}

func newDirectQUICRelayPipePair() (*directQUICRelayPipe, *directQUICRelayPipe) {
	a := &directQUICRelayPipe{
		inbound: make(chan []byte, 256),
		addr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
	}
	b := &directQUICRelayPipe{
		inbound: make(chan []byte, 256),
		addr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2},
	}
	a.peer = b
	b.peer = a
	return a, b
}

func (p *directQUICRelayPipe) send(_ context.Context, payload []byte) error {
	p.peer.inbound <- append([]byte(nil), payload...)
	return nil
}

func (p *directQUICRelayPipe) receive(ctx context.Context) ([]byte, error) {
	select {
	case payload := <-p.inbound:
		return append([]byte(nil), payload...), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestDirectQUICCopiesPayloadOverTransportManager(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relayA, relayB := newDirectQUICRelayPipePair()
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
		DiscoveryInterval:  100 * time.Millisecond,
		DirectStaleTimeout: 5 * time.Second,
	})
	managerB := transport.NewManager(transport.ManagerConfig{
		RelaySend:          relayB.send,
		ReceiveRelay:       relayB.receive,
		RelayAddr:          relayB.addr,
		DirectConn:         directB,
		DiscoveryInterval:  100 * time.Millisecond,
		DirectStaleTimeout: 5 * time.Second,
	})
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
	managerA.SeedRemoteCandidates(ctx, []net.Addr{directB.LocalAddr()})
	managerB.SeedRemoteCandidates(ctx, []net.Addr{directA.LocalAddr()})

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	var received bytes.Buffer
	receiveErr := make(chan error, 1)
	go func() {
		receiveErr <- externalDirectQUICReceiveOverManager(ctx, &received, managerB, serverIdentity, clientIdentity.Public)
	}()

	if err := externalDirectQUICSendOverManager(ctx, bytes.NewBufferString("payload"), managerA, clientIdentity, serverIdentity.Public); err != nil {
		t.Fatalf("externalDirectQUICSendOverManager() error = %v", err)
	}
	select {
	case err := <-receiveErr:
		if err != nil {
			t.Fatalf("externalDirectQUICReceiveOverManager() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
	if got := received.String(); got != "payload" {
		t.Fatalf("received = %q, want %q", got, "payload")
	}
}

func TestExternalSendReceiveViaDirectQUICRoundTrip(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv("DERPHOLE_DIRECT_TRANSPORT", "quic")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const payload = "external direct quic payload"
	var received bytes.Buffer
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := listenExternal(ctx, ListenConfig{
			TokenSink:     tokenSink,
			StdioOut:      &received,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	var tok string
	select {
	case tok = <-tokenSink:
	case err := <-listenErr:
		t.Fatalf("listenExternal() returned before publishing token: %v", err)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for listener token: %v", ctx.Err())
	}
	tokValue, err := token.Decode(tok, time.Now())
	if err != nil {
		t.Fatalf("token.Decode() error = %v", err)
	}
	if tokValue.Capabilities&token.CapabilityDirectQUIC == 0 {
		t.Fatalf("token capabilities = %08b, want direct QUIC bit set", tokValue.Capabilities)
	}

	if err := sendExternal(ctx, SendConfig{
		Token:         tok,
		StdioIn:       strings.NewReader(payload),
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("sendExternal() error = %v", err)
	}

	select {
	case err := <-listenErr:
		if err != nil {
			t.Fatalf("listenExternal() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for listener: %v", ctx.Err())
	}

	if got := received.String(); got != payload {
		t.Fatalf("received = %q, want %q", got, payload)
	}
}

func TestExternalDirectQUICTokenValidationSeparatesBlastAndQUIC(t *testing.T) {
	base := token.Token{
		Version:         token.SupportedVersion,
		ExpiresUnix:     time.Now().Add(time.Minute).Unix(),
		BootstrapRegion: 1,
		DERPPublic:      [32]byte{1},
		QUICPublic:      [32]byte{2},
		BearerSecret:    [32]byte{3},
	}

	quicTok := base
	quicTok.Capabilities = token.CapabilityStdio | token.CapabilityDirectQUIC
	rawQUIC, err := token.Encode(quicTok)
	if err != nil {
		t.Fatalf("token.Encode(quic) error = %v", err)
	}
	if _, err := decodeExternalDirectUDPSendToken(rawQUIC); !errors.Is(err, errExternalDirectQUICTokenRequiresQUIC) {
		t.Fatalf("decodeExternalDirectUDPSendToken(quic) error = %v, want %v", err, errExternalDirectQUICTokenRequiresQUIC)
	}
	if _, err := decodeExternalDirectQUICSendToken(rawQUIC); err != nil {
		t.Fatalf("decodeExternalDirectQUICSendToken(quic) error = %v", err)
	}

	blastTok := base
	blastTok.Capabilities = token.CapabilityStdio
	rawBlast, err := token.Encode(blastTok)
	if err != nil {
		t.Fatalf("token.Encode(blast) error = %v", err)
	}
	if _, err := decodeExternalDirectUDPSendToken(rawBlast); err != nil {
		t.Fatalf("decodeExternalDirectUDPSendToken(blast) error = %v", err)
	}
	if _, err := decodeExternalDirectQUICSendToken(rawBlast); !errors.Is(err, errExternalDirectQUICTokenUnsupported) {
		t.Fatalf("decodeExternalDirectQUICSendToken(blast) error = %v, want %v", err, errExternalDirectQUICTokenUnsupported)
	}
}
