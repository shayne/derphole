package session

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/rendezvous"
	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/derpcat/pkg/token"
	wgtransport "github.com/shayne/derpcat/pkg/wg"
	"go4.org/mem"
	"tailscale.com/types/key"
)

func keyNodePublicFromRaw32(raw [32]byte) key.NodePublic {
	return key.NodePublicFromRaw32(mem.B(raw[:]))
}

func TestExternalWGTunnelDialListenRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listenerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerPacketConn.Close()

	senderPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderPacketConn.Close()

	var sessionID [16]byte
	sessionID[0] = 42

	listenerPrivate, listenerPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	senderPrivate, senderPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	listenerTunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:      sessionID,
		Role:           externalWGRoleListener,
		PacketConn:     listenerPacketConn,
		Transport:      "udp",
		DirectEndpoint: senderPacketConn.LocalAddr().String(),
		PrivateKey:     listenerPrivate,
		PeerPublicKey:  senderPublic,
	})
	if err != nil {
		t.Fatalf("newExternalWGTunnel(listener) error = %v", err)
	}
	defer listenerTunnel.Close()

	senderTunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:      sessionID,
		Role:           externalWGRoleSender,
		PacketConn:     senderPacketConn,
		Transport:      "udp",
		DirectEndpoint: listenerPacketConn.LocalAddr().String(),
		PrivateKey:     senderPrivate,
		PeerPublicKey:  listenerPublic,
	})
	if err != nil {
		t.Fatalf("newExternalWGTunnel(sender) error = %v", err)
	}
	defer senderTunnel.Close()

	ln, err := listenerTunnel.ListenTCP(7000)
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer ln.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := acceptNetListener(ctx, ln)
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()

		payload, err := io.ReadAll(conn)
		if err != nil {
			accepted <- err
			return
		}
		if got := string(payload); got != "hello-over-wg" {
			accepted <- io.ErrUnexpectedEOF
			return
		}
		accepted <- nil
	}()

	conn, err := senderTunnel.DialTCP(ctx, 7000)
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	if _, err := conn.Write([]byte("hello-over-wg")); err != nil {
		conn.Close()
		t.Fatalf("Write() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if err := <-accepted; err != nil {
		t.Fatalf("accepted error = %v", err)
	}
}

func TestExternalWGTunnelStripedCopyOverDERP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := newSessionTestDERPServer(t)
	node := firstDERPNode(srv.Map, 1)
	if node == nil {
		t.Fatal("firstDERPNode() = nil")
	}

	listenerDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(listener) error = %v", err)
	}
	defer listenerDERP.Close()

	senderDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(sender) error = %v", err)
	}
	defer senderDERP.Close()

	listenerPacketConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("ListenPacket(listener) error = %v", err)
	}
	defer listenerPacketConn.Close()

	senderPacketConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("ListenPacket(sender) error = %v", err)
	}
	defer senderPacketConn.Close()

	var sessionID [16]byte
	sessionID[0] = 43

	listenerPrivate, listenerPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	senderPrivate, senderPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	listenerTunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:     sessionID,
		Role:          externalWGRoleListener,
		PacketConn:    listenerPacketConn,
		Transport:     externalWGTransportLabel,
		DERPClient:    listenerDERP,
		PeerDERP:      senderDERP.PublicKey(),
		PrivateKey:    listenerPrivate,
		PeerPublicKey: senderPublic,
	})
	if err != nil {
		t.Fatalf("newExternalWGTunnel(listener) error = %v", err)
	}
	defer listenerTunnel.Close()

	senderTunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:     sessionID,
		Role:          externalWGRoleSender,
		PacketConn:    senderPacketConn,
		Transport:     externalWGTransportLabel,
		DERPClient:    senderDERP,
		PeerDERP:      listenerDERP.PublicKey(),
		PrivateKey:    senderPrivate,
		PeerPublicKey: listenerPublic,
	})
	if err != nil {
		t.Fatalf("newExternalWGTunnel(sender) error = %v", err)
	}
	defer senderTunnel.Close()

	ln, err := listenerTunnel.ListenTCP(externalWGStdioPort)
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer ln.Close()

	var received bytes.Buffer
	recvErr := make(chan error, 1)
	go func() {
		conns, err := acceptExternalWGConns(ctx, ln, 1)
		if err != nil {
			recvErr <- err
			return
		}
		recvErr <- receiveExternalNativeTCPDirect(ctx, nopWriteCloser{Writer: &received}, conns)
	}()

	conns, err := dialExternalWGConns(ctx, senderTunnel, externalWGStdioPort, 1)
	if err != nil {
		t.Fatalf("dialExternalWGConns() error = %v", err)
	}
	if err := sendExternalNativeTCPDirect(ctx, strings.NewReader("hello-striped-over-derp"), conns); err != nil {
		t.Fatalf("sendExternalNativeTCPDirect() error = %v", err)
	}

	if err := <-recvErr; err != nil {
		t.Fatalf("receiveExternalNativeTCPDirect() error = %v", err)
	}
	if got := received.String(); got != "hello-striped-over-derp" {
		t.Fatalf("received = %q, want %q", got, "hello-striped-over-derp")
	}
}

func TestExternalWGTunnelStripedCopyOverDERPWithTransportManager(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := newSessionTestDERPServer(t)
	node := firstDERPNode(srv.Map, 1)
	if node == nil {
		t.Fatal("firstDERPNode() = nil")
	}

	listenerDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(listener) error = %v", err)
	}
	defer listenerDERP.Close()

	senderDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(sender) error = %v", err)
	}
	defer senderDERP.Close()

	listenerPacketConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("ListenPacket(listener) error = %v", err)
	}
	defer listenerPacketConn.Close()

	senderPacketConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("ListenPacket(sender) error = %v", err)
	}
	defer senderPacketConn.Close()

	listenerManager, listenerCleanup, err := startExternalWGTransportManager(ctx, listenerPacketConn, srv.Map, listenerDERP, senderDERP.PublicKey(), nil, nil, true)
	if err != nil {
		t.Fatalf("startExternalWGTransportManager(listener) error = %v", err)
	}
	defer listenerCleanup()

	senderManager, senderCleanup, err := startExternalWGTransportManager(ctx, senderPacketConn, srv.Map, senderDERP, listenerDERP.PublicKey(), nil, nil, true)
	if err != nil {
		t.Fatalf("startExternalWGTransportManager(sender) error = %v", err)
	}
	defer senderCleanup()

	var sessionID [16]byte
	sessionID[0] = 44

	listenerPrivate, listenerPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	senderPrivate, senderPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	listenerTunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:     sessionID,
		Role:          externalWGRoleListener,
		PacketConn:    listenerPacketConn,
		Transport:     externalWGTransportLabel,
		DERPClient:    listenerDERP,
		PeerDERP:      senderDERP.PublicKey(),
		PathSelector:  listenerManager,
		PrivateKey:    listenerPrivate,
		PeerPublicKey: senderPublic,
	})
	if err != nil {
		t.Fatalf("newExternalWGTunnel(listener) error = %v", err)
	}
	defer listenerTunnel.Close()

	senderTunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:     sessionID,
		Role:          externalWGRoleSender,
		PacketConn:    senderPacketConn,
		Transport:     externalWGTransportLabel,
		DERPClient:    senderDERP,
		PeerDERP:      listenerDERP.PublicKey(),
		PathSelector:  senderManager,
		PrivateKey:    senderPrivate,
		PeerPublicKey: listenerPublic,
	})
	if err != nil {
		t.Fatalf("newExternalWGTunnel(sender) error = %v", err)
	}
	defer senderTunnel.Close()

	ln, err := listenerTunnel.ListenTCP(externalWGStdioPort)
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer ln.Close()

	var received bytes.Buffer
	recvErr := make(chan error, 1)
	go func() {
		conns, err := acceptExternalWGConns(ctx, ln, 1)
		if err != nil {
			recvErr <- err
			return
		}
		recvErr <- receiveExternalNativeTCPDirect(ctx, nopWriteCloser{Writer: &received}, conns)
	}()

	conns, err := dialExternalWGConns(ctx, senderTunnel, externalWGStdioPort, 1)
	if err != nil {
		t.Fatalf("dialExternalWGConns() error = %v", err)
	}
	if err := sendExternalNativeTCPDirect(ctx, strings.NewReader("hello-derp-manager"), conns); err != nil {
		t.Fatalf("sendExternalNativeTCPDirect() error = %v", err)
	}

	if err := <-recvErr; err != nil {
		t.Fatalf("receiveExternalNativeTCPDirect() error = %v", err)
	}
	if got := received.String(); got != "hello-derp-manager" {
		t.Fatalf("received = %q, want %q", got, "hello-derp-manager")
	}
}

func TestExternalWGTunnelStripedCopyAfterClaimDecisionPrelude(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := newSessionTestDERPServer(t)
	node := firstDERPNode(srv.Map, 1)
	if node == nil {
		t.Fatal("firstDERPNode() = nil")
	}

	listenerDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(listener) error = %v", err)
	}
	defer listenerDERP.Close()

	senderDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(sender) error = %v", err)
	}
	defer senderDERP.Close()

	listenerPacketConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("ListenPacket(listener) error = %v", err)
	}
	defer listenerPacketConn.Close()

	senderPacketConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("ListenPacket(sender) error = %v", err)
	}
	defer senderPacketConn.Close()

	var sessionID [16]byte
	sessionID[0] = 45
	var bearerSecret [32]byte
	bearerSecret[0] = 1

	listenerPrivate, listenerPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	senderPrivate, senderPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	claimCh, unsubscribeClaims := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()

	decisionDone := make(chan error, 1)
	go func() {
		pkt, err := receiveSubscribedPacket(ctx, claimCh)
		if err != nil {
			decisionDone <- err
			return
		}
		env, err := decodeEnvelope(pkt.Payload)
		if err != nil || env.Claim == nil {
			decisionDone <- io.ErrUnexpectedEOF
			return
		}
		gate := rendezvous.NewGate(token.Token{
			Version:      token.SupportedVersion,
			SessionID:    sessionID,
			ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
			BearerSecret: bearerSecret,
			Capabilities: token.CapabilityStdio,
		})
		decision, err := gate.Accept(time.Now(), *env.Claim)
		if err != nil && !decision.Accepted {
			decisionDone <- err
			return
		}
		decisionDone <- sendEnvelope(ctx, listenerDERP, senderDERP.PublicKey(), envelope{
			Type:     envelopeDecision,
			Decision: &decision,
		})
	}()

	claim := rendezvous.Claim{
		Version:      token.SupportedVersion,
		SessionID:    sessionID,
		DERPPublic:   derpPublicKeyRaw32(senderDERP.PublicKey()),
		QUICPublic:   senderPublic,
		Parallel:     1,
		Capabilities: token.CapabilityStdio,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(bearerSecret, claim)
	decision, err := sendClaimAndReceiveDecision(ctx, senderDERP, listenerDERP.PublicKey(), claim)
	if err != nil {
		t.Fatalf("sendClaimAndReceiveDecision() error = %v", err)
	}
	if !decision.Accepted {
		t.Fatalf("decision.Accepted = false")
	}
	if err := <-decisionDone; err != nil {
		t.Fatalf("listener decision send error = %v", err)
	}

	listenerTunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:     sessionID,
		Role:          externalWGRoleListener,
		PacketConn:    listenerPacketConn,
		Transport:     externalWGTransportLabel,
		DERPClient:    listenerDERP,
		PeerDERP:      senderDERP.PublicKey(),
		PrivateKey:    listenerPrivate,
		PeerPublicKey: senderPublic,
	})
	if err != nil {
		t.Fatalf("newExternalWGTunnel(listener) error = %v", err)
	}
	defer listenerTunnel.Close()

	senderTunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:     sessionID,
		Role:          externalWGRoleSender,
		PacketConn:    senderPacketConn,
		Transport:     externalWGTransportLabel,
		DERPClient:    senderDERP,
		PeerDERP:      listenerDERP.PublicKey(),
		PrivateKey:    senderPrivate,
		PeerPublicKey: listenerPublic,
	})
	if err != nil {
		t.Fatalf("newExternalWGTunnel(sender) error = %v", err)
	}
	defer senderTunnel.Close()

	ln, err := listenerTunnel.ListenTCP(externalWGStdioPort)
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer ln.Close()

	var received bytes.Buffer
	recvErr := make(chan error, 1)
	go func() {
		conns, err := acceptExternalWGConns(ctx, ln, 1)
		if err != nil {
			recvErr <- err
			return
		}
		recvErr <- receiveExternalNativeTCPDirect(ctx, nopWriteCloser{Writer: &received}, conns)
	}()

	conns, err := dialExternalWGConns(ctx, senderTunnel, externalWGStdioPort, 1)
	if err != nil {
		t.Fatalf("dialExternalWGConns() error = %v", err)
	}
	if err := sendExternalNativeTCPDirect(ctx, strings.NewReader("hello-after-claim"), conns); err != nil {
		t.Fatalf("sendExternalNativeTCPDirect() error = %v", err)
	}

	if err := <-recvErr; err != nil {
		t.Fatalf("receiveExternalNativeTCPDirect() error = %v", err)
	}
	if got := received.String(); got != "hello-after-claim" {
		t.Fatalf("received = %q, want %q", got, "hello-after-claim")
	}
}

func TestExternalWGTunnelStripedCopyAfterClaimDecisionPreludeWithTransportManager(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := newSessionTestDERPServer(t)
	node := firstDERPNode(srv.Map, 1)
	if node == nil {
		t.Fatal("firstDERPNode() = nil")
	}

	listenerDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(listener) error = %v", err)
	}
	defer listenerDERP.Close()

	senderDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(sender) error = %v", err)
	}
	defer senderDERP.Close()

	listenerPacketConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("ListenPacket(listener) error = %v", err)
	}
	defer listenerPacketConn.Close()

	senderPacketConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("ListenPacket(sender) error = %v", err)
	}
	defer senderPacketConn.Close()

	var sessionID [16]byte
	sessionID[0] = 46
	var bearerSecret [32]byte
	bearerSecret[0] = 2

	listenerPrivate, listenerPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	senderPrivate, senderPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	claimCh, unsubscribeClaims := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()

	decisionDone := make(chan error, 1)
	go func() {
		pkt, err := receiveSubscribedPacket(ctx, claimCh)
		if err != nil {
			decisionDone <- err
			return
		}
		env, err := decodeEnvelope(pkt.Payload)
		if err != nil || env.Claim == nil {
			decisionDone <- io.ErrUnexpectedEOF
			return
		}
		gate := rendezvous.NewGate(token.Token{
			Version:      token.SupportedVersion,
			SessionID:    sessionID,
			ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
			BearerSecret: bearerSecret,
			Capabilities: token.CapabilityStdio,
		})
		decision, err := gate.Accept(time.Now(), *env.Claim)
		if err != nil && !decision.Accepted {
			decisionDone <- err
			return
		}
		decisionDone <- sendEnvelope(ctx, listenerDERP, senderDERP.PublicKey(), envelope{
			Type:     envelopeDecision,
			Decision: &decision,
		})
	}()

	claim := rendezvous.Claim{
		Version:      token.SupportedVersion,
		SessionID:    sessionID,
		DERPPublic:   derpPublicKeyRaw32(senderDERP.PublicKey()),
		QUICPublic:   senderPublic,
		Parallel:     1,
		Capabilities: token.CapabilityStdio,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(bearerSecret, claim)
	decision, err := sendClaimAndReceiveDecision(ctx, senderDERP, listenerDERP.PublicKey(), claim)
	if err != nil {
		t.Fatalf("sendClaimAndReceiveDecision() error = %v", err)
	}
	if !decision.Accepted {
		t.Fatalf("decision.Accepted = false")
	}
	if err := <-decisionDone; err != nil {
		t.Fatalf("listener decision send error = %v", err)
	}

	listenerManager, listenerCleanup, err := startExternalWGTransportManager(ctx, listenerPacketConn, srv.Map, listenerDERP, senderDERP.PublicKey(), nil, nil, true)
	if err != nil {
		t.Fatalf("startExternalWGTransportManager(listener) error = %v", err)
	}
	defer listenerCleanup()

	senderManager, senderCleanup, err := startExternalWGTransportManager(ctx, senderPacketConn, srv.Map, senderDERP, listenerDERP.PublicKey(), nil, nil, true)
	if err != nil {
		t.Fatalf("startExternalWGTransportManager(sender) error = %v", err)
	}
	defer senderCleanup()

	listenerTunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:     sessionID,
		Role:          externalWGRoleListener,
		PacketConn:    listenerPacketConn,
		Transport:     externalWGTransportLabel,
		DERPClient:    listenerDERP,
		PeerDERP:      senderDERP.PublicKey(),
		PathSelector:  listenerManager,
		PrivateKey:    listenerPrivate,
		PeerPublicKey: senderPublic,
	})
	if err != nil {
		t.Fatalf("newExternalWGTunnel(listener) error = %v", err)
	}
	defer listenerTunnel.Close()

	senderTunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:     sessionID,
		Role:          externalWGRoleSender,
		PacketConn:    senderPacketConn,
		Transport:     externalWGTransportLabel,
		DERPClient:    senderDERP,
		PeerDERP:      listenerDERP.PublicKey(),
		PathSelector:  senderManager,
		PrivateKey:    senderPrivate,
		PeerPublicKey: listenerPublic,
	})
	if err != nil {
		t.Fatalf("newExternalWGTunnel(sender) error = %v", err)
	}
	defer senderTunnel.Close()

	ln, err := listenerTunnel.ListenTCP(externalWGStdioPort)
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer ln.Close()

	var received bytes.Buffer
	recvErr := make(chan error, 1)
	go func() {
		conns, err := acceptExternalWGConns(ctx, ln, 1)
		if err != nil {
			recvErr <- err
			return
		}
		recvErr <- receiveExternalNativeTCPDirect(ctx, nopWriteCloser{Writer: &received}, conns)
	}()

	conns, err := dialExternalWGConns(ctx, senderTunnel, externalWGStdioPort, 1)
	if err != nil {
		t.Fatalf("dialExternalWGConns() error = %v", err)
	}
	if err := sendExternalNativeTCPDirect(ctx, strings.NewReader("hello-derp-prelude-manager"), conns); err != nil {
		t.Fatalf("sendExternalNativeTCPDirect() error = %v", err)
	}

	if err := <-recvErr; err != nil {
		t.Fatalf("receiveExternalNativeTCPDirect() error = %v", err)
	}
	if got := received.String(); got != "hello-derp-prelude-manager" {
		t.Fatalf("received = %q, want %q", got, "hello-derp-prelude-manager")
	}
}

func TestExternalWGTunnelIssuedPublicSessionPiecesWithTransportManager(t *testing.T) {
	runExternalWGTunnelIssuedPublicSessionPiecesWithTransportManager(t, false, nil)
}

func TestExternalWGTunnelIssuedPublicSessionPiecesWithSenderPortmap(t *testing.T) {
	runExternalWGTunnelIssuedPublicSessionPiecesWithTransportManager(t, true, nil)
}

func TestExternalWGTunnelIssuedPublicSessionPiecesWithSenderPortmapVerboseEmitter(t *testing.T) {
	var senderStatus bytes.Buffer
	runExternalWGTunnelIssuedPublicSessionPiecesWithTransportManager(t, true, telemetry.New(&senderStatus, telemetry.LevelVerbose))
}

func TestSendExternalViaWGTunnelAgainstManualListener(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tokStr, session, err := issuePublicSession(ctx)
	if err != nil {
		t.Fatalf("issuePublicSession() error = %v", err)
	}
	defer deleteRelayMailbox(tokStr, session)
	defer closePublicSessionTransport(session)
	defer session.derp.Close()

	claimCh, unsubscribeClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()

	var received bytes.Buffer
	listenerErr := make(chan error, 1)
	go func() {
		pkt, err := receiveSubscribedPacket(ctx, claimCh)
		if err != nil {
			listenerErr <- err
			return
		}
		env, err := decodeEnvelope(pkt.Payload)
		if err != nil || env.Type != envelopeClaim || env.Claim == nil {
			listenerErr <- io.ErrUnexpectedEOF
			return
		}

		decision, err := session.gate.Accept(time.Now(), *env.Claim)
		if err != nil && !decision.Accepted {
			listenerErr <- err
			return
		}
		if decision.Accept == nil {
			listenerErr <- io.ErrUnexpectedEOF
			return
		}
		decision.Accept.Parallel = 1
		decision.Accept.Candidates = publicInitialProbeCandidates(session.probeConn, publicSessionPortmap(session))

		listenerManager, listenerCleanup, err := startExternalWGTransportManager(
			ctx,
			session.probeConn,
			session.derpMap,
			session.derp,
			keyNodePublicFromRaw32(env.Claim.DERPPublic),
			parseCandidateStrings(decision.Accept.Candidates),
			publicSessionPortmap(session),
			true,
		)
		if err != nil {
			listenerErr <- err
			return
		}
		defer listenerCleanup()
		seedAcceptedClaimCandidates(ctx, listenerManager, *env.Claim)

		listenerTunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
			SessionID:     session.token.SessionID,
			Role:          externalWGRoleListener,
			PacketConn:    session.probeConn,
			Transport:     externalWGTransportLabel,
			DERPClient:    session.derp,
			PeerDERP:      keyNodePublicFromRaw32(env.Claim.DERPPublic),
			PathSelector:  listenerManager,
			PrivateKey:    session.wgPrivate,
			PeerPublicKey: env.Claim.QUICPublic,
		})
		if err != nil {
			listenerErr <- err
			return
		}
		defer listenerTunnel.Close()

		ln, err := listenerTunnel.ListenTCP(externalWGStdioPort)
		if err != nil {
			listenerErr <- err
			return
		}
		defer ln.Close()

		if err := sendEnvelope(ctx, session.derp, keyNodePublicFromRaw32(env.Claim.DERPPublic), envelope{
			Type:     envelopeDecision,
			Decision: &decision,
		}); err != nil {
			listenerErr <- err
			return
		}

		conns, err := acceptExternalWGConns(ctx, ln, decision.Accept.Parallel)
		if err != nil {
			listenerErr <- err
			return
		}
		if err := receiveExternalNativeTCPDirect(ctx, nopWriteCloser{Writer: &received}, conns); err != nil {
			listenerErr <- err
			return
		}
		listenerErr <- sendPeerAck(ctx, session.derp, keyNodePublicFromRaw32(env.Claim.DERPPublic), int64(received.Len()))
	}()

	if err := sendExternalViaWGTunnel(ctx, SendConfig{
		Token:          tokStr,
		StdioIn:        strings.NewReader("hello-exact-send"),
		ForceRelay:     true,
		ParallelPolicy: FixedParallelPolicy(1),
	}); err != nil {
		t.Fatalf("sendExternalViaWGTunnel() error = %v", err)
	}

	if err := <-listenerErr; err != nil {
		t.Fatalf("listener error = %v", err)
	}
	if got := received.String(); got != "hello-exact-send" {
		t.Fatalf("received = %q, want %q", got, "hello-exact-send")
	}
}

func TestListenExternalViaWGTunnelAgainstManualSender(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := listenExternalViaWGTunnel(ctx, ListenConfig{
			TokenSink:  tokenSink,
			StdioOut:   &listenerOut,
			ForceRelay: true,
		})
		listenErr <- err
	}()

	tokStr := <-tokenSink
	tok, err := token.Decode(tokStr, time.Now())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		t.Fatalf("FetchMap() error = %v", err)
	}
	node := firstDERPNode(dm, int(tok.BootstrapRegion))
	if node == nil {
		t.Fatal("firstDERPNode() = nil")
	}
	senderDERP, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		t.Fatalf("NewClient(sender) error = %v", err)
	}
	defer senderDERP.Close()

	senderPacketConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("ListenPacket(sender) error = %v", err)
	}
	defer senderPacketConn.Close()

	senderPrivate, senderPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(senderDERP.PublicKey()),
		QUICPublic:   senderPublic,
		Parallel:     1,
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	decision, err := sendClaimAndReceiveDecision(ctx, senderDERP, keyNodePublicFromRaw32(tok.DERPPublic), claim)
	if err != nil {
		t.Fatalf("sendClaimAndReceiveDecision() error = %v", err)
	}
	if !decision.Accepted || decision.Accept == nil {
		t.Fatalf("decision = %#v, want accepted", decision)
	}

	senderManager, senderCleanup, err := startExternalWGTransportManager(
		ctx,
		senderPacketConn,
		dm,
		senderDERP,
		keyNodePublicFromRaw32(tok.DERPPublic),
		nil,
		nil,
		true,
	)
	if err != nil {
		t.Fatalf("startExternalWGTransportManager(sender) error = %v", err)
	}
	defer senderCleanup()
	seedAcceptedDecisionCandidates(ctx, senderManager, decision)

	senderTunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:     tok.SessionID,
		Role:          externalWGRoleSender,
		PacketConn:    senderPacketConn,
		Transport:     externalWGTransportLabel,
		DERPClient:    senderDERP,
		PeerDERP:      keyNodePublicFromRaw32(tok.DERPPublic),
		PathSelector:  senderManager,
		PrivateKey:    senderPrivate,
		PeerPublicKey: tok.QUICPublic,
	})
	if err != nil {
		t.Fatalf("newExternalWGTunnel(sender) error = %v", err)
	}
	defer senderTunnel.Close()

	conns, err := dialExternalWGConns(ctx, senderTunnel, externalWGStdioPort, decision.Accept.Parallel)
	if err != nil {
		t.Fatalf("dialExternalWGConns() error = %v", err)
	}
	if err := sendExternalNativeTCPDirect(ctx, strings.NewReader("hello-exact-listen"), conns); err != nil {
		t.Fatalf("sendExternalNativeTCPDirect() error = %v", err)
	}

	if err := <-listenErr; err != nil {
		t.Fatalf("listenExternalViaWGTunnel() error = %v", err)
	}
	if got := listenerOut.String(); got != "hello-exact-listen" {
		t.Fatalf("listener output = %q, want %q", got, "hello-exact-listen")
	}
}

func runExternalWGTunnelIssuedPublicSessionPiecesWithTransportManager(t *testing.T, senderPortmap bool, senderEmitter *telemetry.Emitter) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tokStr, session, err := issuePublicSession(ctx)
	if err != nil {
		t.Fatalf("issuePublicSession() error = %v", err)
	}
	defer deleteRelayMailbox(tokStr, session)
	defer closePublicSessionTransport(session)
	defer session.derp.Close()

	tok, err := token.Decode(tokStr, time.Now())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	node := firstDERPNode(session.derpMap, int(tok.BootstrapRegion))
	if node == nil {
		t.Fatal("firstDERPNode() = nil")
	}
	senderDERP, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		t.Fatalf("NewClient(sender) error = %v", err)
	}
	defer senderDERP.Close()

	senderPacketConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("ListenPacket(sender) error = %v", err)
	}
	defer senderPacketConn.Close()
	var senderPM publicPortmap
	if senderPortmap {
		senderPM = newBoundPublicPortmap(senderPacketConn, senderEmitter)
		defer senderPM.Close()
	}

	senderPrivate, senderPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	claimCh, unsubscribeClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()

	var received bytes.Buffer
	listenerErr := make(chan error, 1)
	go func() {
		pkt, err := receiveSubscribedPacket(ctx, claimCh)
		if err != nil {
			listenerErr <- err
			return
		}
		env, err := decodeEnvelope(pkt.Payload)
		if err != nil || env.Type != envelopeClaim || env.Claim == nil {
			listenerErr <- io.ErrUnexpectedEOF
			return
		}

		decision, err := session.gate.Accept(time.Now(), *env.Claim)
		if err != nil && !decision.Accepted {
			listenerErr <- err
			return
		}
		if decision.Accept == nil {
			listenerErr <- io.ErrUnexpectedEOF
			return
		}
		decision.Accept.Parallel = 1
		decision.Accept.Candidates = publicInitialProbeCandidates(session.probeConn, publicSessionPortmap(session))

		listenerManager, listenerCleanup, err := startExternalWGTransportManager(
			ctx,
			session.probeConn,
			session.derpMap,
			session.derp,
			senderDERP.PublicKey(),
			parseCandidateStrings(decision.Accept.Candidates),
			publicSessionPortmap(session),
			true,
		)
		if err != nil {
			listenerErr <- err
			return
		}
		defer listenerCleanup()
		seedAcceptedClaimCandidates(ctx, listenerManager, *env.Claim)

		listenerTunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
			SessionID:     session.token.SessionID,
			Role:          externalWGRoleListener,
			PacketConn:    session.probeConn,
			Transport:     externalWGTransportLabel,
			DERPClient:    session.derp,
			PeerDERP:      senderDERP.PublicKey(),
			PathSelector:  listenerManager,
			PrivateKey:    session.wgPrivate,
			PeerPublicKey: env.Claim.QUICPublic,
		})
		if err != nil {
			listenerErr <- err
			return
		}
		defer listenerTunnel.Close()

		ln, err := listenerTunnel.ListenTCP(externalWGStdioPort)
		if err != nil {
			listenerErr <- err
			return
		}
		defer ln.Close()

		if err := sendEnvelope(ctx, session.derp, senderDERP.PublicKey(), envelope{
			Type:     envelopeDecision,
			Decision: &decision,
		}); err != nil {
			listenerErr <- err
			return
		}

		conns, err := acceptExternalWGConns(ctx, ln, decision.Accept.Parallel)
		if err != nil {
			listenerErr <- err
			return
		}
		if err := receiveExternalNativeTCPDirect(ctx, nopWriteCloser{Writer: &received}, conns); err != nil {
			listenerErr <- err
			return
		}
		listenerErr <- sendPeerAck(ctx, session.derp, senderDERP.PublicKey(), int64(received.Len()))
	}()

	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(senderDERP.PublicKey()),
		QUICPublic:   senderPublic,
		Parallel:     1,
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	decision, err := sendClaimAndReceiveDecision(ctx, senderDERP, session.derp.PublicKey(), claim)
	if err != nil {
		t.Fatalf("sendClaimAndReceiveDecision() error = %v", err)
	}
	if !decision.Accepted || decision.Accept == nil {
		t.Fatalf("decision = %#v, want accepted", decision)
	}

	senderManager, senderCleanup, err := startExternalWGTransportManager(
		ctx,
		senderPacketConn,
		session.derpMap,
		senderDERP,
		session.derp.PublicKey(),
		nil,
		senderPM,
		true,
	)
	if err != nil {
		t.Fatalf("startExternalWGTransportManager(sender) error = %v", err)
	}
	defer senderCleanup()
	seedAcceptedDecisionCandidates(ctx, senderManager, decision)

	senderTunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:     tok.SessionID,
		Role:          externalWGRoleSender,
		PacketConn:    senderPacketConn,
		Transport:     externalWGTransportLabel,
		DERPClient:    senderDERP,
		PeerDERP:      session.derp.PublicKey(),
		PathSelector:  senderManager,
		PrivateKey:    senderPrivate,
		PeerPublicKey: tok.QUICPublic,
	})
	if err != nil {
		t.Fatalf("newExternalWGTunnel(sender) error = %v", err)
	}
	defer senderTunnel.Close()

	conns, err := dialExternalWGConns(ctx, senderTunnel, externalWGStdioPort, decision.Accept.Parallel)
	if err != nil {
		t.Fatalf("dialExternalWGConns() error = %v", err)
	}
	if err := sendExternalNativeTCPDirect(ctx, strings.NewReader("hello-issued-public-session"), conns); err != nil {
		t.Fatalf("sendExternalNativeTCPDirect() error = %v", err)
	}

	if err := <-listenerErr; err != nil {
		t.Fatalf("listener error = %v", err)
	}
	if got := received.String(); got != "hello-issued-public-session" {
		t.Fatalf("received = %q, want %q", got, "hello-issued-public-session")
	}
}
