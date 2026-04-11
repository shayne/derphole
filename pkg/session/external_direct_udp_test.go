package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/probe"
	"github.com/shayne/derpcat/pkg/rendezvous"
	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/derpcat/pkg/token"
	"github.com/shayne/derpcat/pkg/transport"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestExternalDirectUDPDefaultUsesStripedStreamLanes(t *testing.T) {
	if got, want := externalDirectUDPParallelism, 8; got != want {
		t.Fatalf("externalDirectUDPParallelism = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPMaxRateMbps, 10_000; got != want {
		t.Fatalf("externalDirectUDPMaxRateMbps = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPInitialProbeFallbackMbps, 150; got != want {
		t.Fatalf("externalDirectUDPInitialProbeFallbackMbps = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPRateProbeMinMbps, 1; got != want {
		t.Fatalf("externalDirectUDPRateProbeMinMbps = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPTransportLabel, "batched"; got != want {
		t.Fatalf("externalDirectUDPTransportLabel = %q, want %q", got, want)
	}
	if got, want := externalDirectUDPFECGroupSize, 32; got != want {
		t.Fatalf("externalDirectUDPFECGroupSize = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPStreamFECGroupSize, 0; got != want {
		t.Fatalf("externalDirectUDPStreamFECGroupSize = %d, want %d", got, want)
	}
	if !externalDirectUDPStripedBlast {
		t.Fatal("externalDirectUDPStripedBlast = false, want true")
	}
}

func TestExternalDirectUDPWaitCoversPunchHandshakeWindow(t *testing.T) {
	minWait := 5 * time.Second
	if externalDirectUDPWait < minWait {
		t.Fatalf("externalDirectUDPWait = %v, want at least %v", externalDirectUDPWait, minWait)
	}
}

func writeExternalDirectUDPProbePacket(t *testing.T, conn net.PacketConn, dst net.Addr, packet probe.Packet) {
	t.Helper()
	wire, err := probe.MarshalPacket(packet, nil)
	if err != nil {
		t.Fatalf("MarshalPacket() error = %v", err)
	}
	if _, err := conn.WriteTo(wire, dst); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
}

func readExternalDirectUDPProbePacket(t *testing.T, conn net.PacketConn, timeout time.Duration) probe.Packet {
	t.Helper()
	buf := make([]byte, 64<<10)
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	packet, err := probe.UnmarshalPacket(buf[:n], nil)
	if err != nil {
		t.Fatalf("UnmarshalPacket() error = %v", err)
	}
	return packet
}

func TestWaitForPeerAckWithTimeoutReturnsWhenPeerNeverAcks(t *testing.T) {
	ackCh := make(chan derpbind.Packet)
	start := time.Now()

	err := waitForPeerAckWithTimeout(context.Background(), ackCh, 25*time.Millisecond)
	if err == nil {
		t.Fatal("waitForPeerAckWithTimeout() error = nil, want timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitForPeerAckWithTimeout() error = %v, want %v", err, context.DeadlineExceeded)
	}
	if elapsed := time.Since(start); elapsed < 25*time.Millisecond {
		t.Fatalf("waitForPeerAckWithTimeout() returned after %v, want to wait for timeout", elapsed)
	}
}

func TestSendExternalHandoffDERPStopUsesReceiverHandoffAckBelowReadBoundary(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	node := srv.Map.Regions[1].Nodes[0]
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

	relayFrames, unsubscribe := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == senderDERP.PublicKey() && externalRelayPrefixDERPFrameKindOf(pkt.Payload) != 0
	})
	defer unsubscribe()

	spool, err := newExternalHandoffSpool(strings.NewReader("abcdefghijklmnop"), 4, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	stopCh := make(chan struct{})
	errCh := make(chan error, 1)
	metrics := newExternalTransferMetrics(time.Now())
	go func() {
		errCh <- sendExternalHandoffDERP(ctx, senderDERP, listenerDERP.PublicKey(), spool, stopCh, metrics)
	}()

	for dataFrames := 0; dataFrames < 2; {
		select {
		case pkt := <-relayFrames:
			if externalRelayPrefixDERPFrameKindOf(pkt.Payload) == externalRelayPrefixDERPFrameData {
				dataFrames++
			}
		case err := <-errCh:
			t.Fatalf("sendExternalHandoffDERP() returned before stop: %v", err)
		case <-time.After(500 * time.Millisecond):
			t.Fatal("timed out waiting for DERP prefix data frames before stop")
		}
	}

	close(stopCh)

	var handoffOffset int64 = -1
	var sendErr error
	sendReturned := false
	for handoffOffset < 0 {
		select {
		case pkt := <-relayFrames:
			if externalRelayPrefixDERPFrameKindOf(pkt.Payload) != externalRelayPrefixDERPFrameHandoff {
				continue
			}
			handoffOffset, err = externalRelayPrefixDERPDecodeOffset(pkt.Payload)
			if err != nil {
				t.Fatal(err)
			}
		case err := <-errCh:
			sendErr = err
			sendReturned = true
		case <-time.After(500 * time.Millisecond):
			t.Fatal("timed out waiting for DERP prefix handoff after stop")
		}
	}
	if handoffOffset != 8 {
		t.Fatalf("handoff offset = %d, want sent read boundary 8", handoffOffset)
	}
	if err := externalRelayPrefixDERPSendHandoffAck(ctx, listenerDERP, senderDERP.PublicKey(), 4); err != nil {
		t.Fatal(err)
	}

	if sendReturned {
		if sendErr != nil {
			t.Fatalf("sendExternalHandoffDERP() error = %v", sendErr)
		}
	} else {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("sendExternalHandoffDERP() error = %v", err)
			}
		case <-time.After(200 * time.Millisecond):
			t.Fatal("sendExternalHandoffDERP() blocked waiting for unACKed relay-prefix bytes after stop")
		}
	}
	if got := metrics.RelayBytes(); got == 0 {
		t.Fatal("relay bytes = 0, want relay-prefix progress to be tracked")
	}
}

func TestReceiveExternalViaDirectUDPOnlyLetsPrepareConsumeReady(t *testing.T) {
	origWaitReady := externalDirectUDPWaitReadyFn
	origPrepare := externalPrepareDirectUDPReceiveFn
	origExecute := externalExecutePreparedDirectUDPReceiveFn
	t.Cleanup(func() {
		externalDirectUDPWaitReadyFn = origWaitReady
		externalPrepareDirectUDPReceiveFn = origPrepare
		externalExecutePreparedDirectUDPReceiveFn = origExecute
	})

	waitReadyCalled := false
	prepareCalled := false
	executeCalled := false
	externalDirectUDPWaitReadyFn = func(context.Context, <-chan derpbind.Packet) error {
		waitReadyCalled = true
		return errors.New("unexpected direct UDP ready wait")
	}
	externalPrepareDirectUDPReceiveFn = func(ctx context.Context, dst io.Writer, tok token.Token, derpClient *derpbind.Client, peerDERP key.NodePublic, peerAddr net.Addr, probeConns []net.PacketConn, remoteCandidates []net.Addr, decision rendezvous.Decision, readyCh <-chan derpbind.Packet, startCh <-chan derpbind.Packet, cfg ListenConfig) (externalDirectUDPReceivePlan, error) {
		prepareCalled = true
		return externalDirectUDPReceivePlan{}, nil
	}
	externalExecutePreparedDirectUDPReceiveFn = func(ctx context.Context, plan externalDirectUDPReceivePlan, tok token.Token, cfg ListenConfig, metrics *externalTransferMetrics) error {
		executeCalled = true
		return nil
	}

	manager := transport.NewManager(transport.ManagerConfig{})
	if err := receiveExternalViaDirectUDPOnly(context.Background(), io.Discard, token.Token{}, nil, key.NodePublic{}, manager, nil, nil, nil, nil, nil, rendezvous.Decision{}, nil, nil, ListenConfig{}); err != nil {
		t.Fatalf("receiveExternalViaDirectUDPOnly() error = %v", err)
	}
	if waitReadyCalled {
		t.Fatal("receiveExternalViaDirectUDPOnly() called externalDirectUDPWaitReadyFn, want prepare function to consume the ready envelope")
	}
	if !prepareCalled {
		t.Fatal("receiveExternalViaDirectUDPOnly() did not call externalPrepareDirectUDPReceiveFn")
	}
	if !executeCalled {
		t.Fatal("receiveExternalViaDirectUDPOnly() did not call externalExecutePreparedDirectUDPReceiveFn")
	}
}

func TestSendExternalHandoffDERPStopBeforeRelayProgressStillStartsRelayData(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	node := srv.Map.Regions[1].Nodes[0]
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

	relayFrames, unsubscribe := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == senderDERP.PublicKey() && externalRelayPrefixDERPFrameKindOf(pkt.Payload) != 0
	})
	defer unsubscribe()

	spool, err := newExternalHandoffSpool(strings.NewReader("abcdefghijklmnop"), 4, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	stopCh := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- sendExternalHandoffDERP(ctx, senderDERP, listenerDERP.PublicKey(), spool, stopCh, nil)
	}()
	close(stopCh)

	var (
		firstKind externalRelayPrefixDERPFrameKind
		watermark int64
	)
	for {
		select {
		case pkt := <-relayFrames:
			kind := externalRelayPrefixDERPFrameKindOf(pkt.Payload)
			if firstKind == 0 {
				firstKind = kind
			}
			switch kind {
			case externalRelayPrefixDERPFrameData:
				chunk, err := externalRelayPrefixDERPDecodeChunk(pkt.Payload)
				if err != nil {
					t.Fatal(err)
				}
				watermark = max(watermark, chunk.Offset+int64(len(chunk.Payload)))
				if err := externalRelayPrefixDERPSendAck(ctx, listenerDERP, senderDERP.PublicKey(), watermark); err != nil {
					t.Fatal(err)
				}
			case externalRelayPrefixDERPFrameHandoff:
				if err := externalRelayPrefixDERPSendHandoffAck(ctx, listenerDERP, senderDERP.PublicKey(), watermark); err != nil {
					t.Fatal(err)
				}
			}
		case err := <-errCh:
			if err != nil {
				t.Fatalf("sendExternalHandoffDERP() error = %v", err)
			}
			if firstKind != externalRelayPrefixDERPFrameData {
				t.Fatalf("first relay frame kind = %v, want %v", firstKind, externalRelayPrefixDERPFrameData)
			}
			if watermark == 0 {
				t.Fatal("relay prefix sent no acknowledged data before handoff")
			}
			return
		case <-time.After(500 * time.Millisecond):
			t.Fatal("timed out waiting for relay-prefix frames")
		}
	}
}

func TestReceiveExternalHandoffDERPReturnsCurrentWatermarkOnHandoffBelowBoundary(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	node := srv.Map.Regions[1].Nodes[0]
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

	relayFrames, unsubscribeRelay := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == senderDERP.PublicKey() && externalRelayPrefixDERPFrameKindOf(pkt.Payload) != 0
	})
	defer unsubscribeRelay()
	ackFrames, unsubscribeAck := senderDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP.PublicKey() && externalRelayPrefixDERPFrameKindOf(pkt.Payload) == externalRelayPrefixDERPFrameAck
	})
	defer unsubscribeAck()

	var out bytes.Buffer
	rx := newExternalHandoffReceiver(&out, 32)
	metrics := newExternalTransferMetrics(time.Now())
	errCh := make(chan error, 1)
	go func() {
		errCh <- receiveExternalHandoffDERP(ctx, listenerDERP, senderDERP.PublicKey(), rx, relayFrames, metrics)
	}()

	if err := externalRelayPrefixDERPSendChunk(ctx, senderDERP, listenerDERP.PublicKey(), externalHandoffChunk{Offset: 0, Payload: []byte("abcd")}); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-ackFrames:
		ack, err := externalRelayPrefixDERPDecodeAck(pkt.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if ack != 4 {
			t.Fatalf("data ack = %d, want 4", ack)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for DERP prefix data ACK")
	}

	if err := externalRelayPrefixDERPSendHandoff(ctx, senderDERP, listenerDERP.PublicKey(), 8); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, errExternalHandoffCarrierHandoff) {
			t.Fatalf("receiveExternalHandoffDERP() error = %v, want %v", err, errExternalHandoffCarrierHandoff)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("receiveExternalHandoffDERP() blocked waiting for handoff boundary instead of returning current watermark")
	}
	if got := out.String(); got != "abcd" {
		t.Fatalf("receiver output = %q, want %q", got, "abcd")
	}
	if got := metrics.RelayBytes(); got != 4 {
		t.Fatalf("relay bytes = %d, want 4", got)
	}
}

func TestReceiveExternalHandoffDERPTracksOnlyDeliveredRelayBytes(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	node := srv.Map.Regions[1].Nodes[0]
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

	relayFrames, unsubscribeRelay := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == senderDERP.PublicKey() && externalRelayPrefixDERPFrameKindOf(pkt.Payload) != 0
	})
	defer unsubscribeRelay()
	ackFrames, unsubscribeAck := senderDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP.PublicKey() && externalRelayPrefixDERPFrameKindOf(pkt.Payload) == externalRelayPrefixDERPFrameAck
	})
	defer unsubscribeAck()

	var out bytes.Buffer
	rx := newExternalHandoffReceiver(&out, 32)
	metrics := newExternalTransferMetrics(time.Now())
	errCh := make(chan error, 1)
	go func() {
		errCh <- receiveExternalHandoffDERP(ctx, listenerDERP, senderDERP.PublicKey(), rx, relayFrames, metrics)
	}()

	if err := externalRelayPrefixDERPSendChunk(ctx, senderDERP, listenerDERP.PublicKey(), externalHandoffChunk{Offset: 0, Payload: []byte("abcd")}); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-ackFrames:
		ack, err := externalRelayPrefixDERPDecodeAck(pkt.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if ack != 4 {
			t.Fatalf("first ack = %d, want 4", ack)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for first DERP prefix ACK")
	}

	if err := externalRelayPrefixDERPSendChunk(ctx, senderDERP, listenerDERP.PublicKey(), externalHandoffChunk{Offset: 2, Payload: []byte("cdef")}); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-ackFrames:
		ack, err := externalRelayPrefixDERPDecodeAck(pkt.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if ack != 6 {
			t.Fatalf("second ack = %d, want 6", ack)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for second DERP prefix ACK")
	}

	if err := externalRelayPrefixDERPSendHandoff(ctx, senderDERP, listenerDERP.PublicKey(), 6); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, errExternalHandoffCarrierHandoff) {
			t.Fatalf("receiveExternalHandoffDERP() error = %v, want %v", err, errExternalHandoffCarrierHandoff)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for DERP prefix handoff")
	}

	if got := out.String(); got != "abcdef" {
		t.Fatalf("receiver output = %q, want %q", got, "abcdef")
	}
	if got := metrics.RelayBytes(); got != 6 {
		t.Fatalf("relay bytes = %d, want 6", got)
	}
}

func TestSendExternalViaRelayPrefixThenDirectUDPCompletesSmallPayloadBeforeSlowDirectSend(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	node := srv.Map.Regions[1].Nodes[0]
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

	relayFrames, unsubscribe := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == senderDERP.PublicKey() && externalRelayPrefixDERPFrameKindOf(pkt.Payload) != 0
	})
	defer unsubscribe()

	payloadSeed := []byte("relay-before-direct-ready:")
	payload := bytes.Repeat(payloadSeed, (1<<20)/len(payloadSeed)+1)
	payload = payload[:1<<20]

	var out bytes.Buffer
	receiveErrCh := make(chan error, 1)
	go func() {
		rx := newExternalHandoffReceiver(&out, externalHandoffMaxUnackedBytes)
		receiveErrCh <- receiveExternalHandoffDERP(ctx, listenerDERP, senderDERP.PublicKey(), rx, relayFrames, nil)
	}()

	prevWaitDirectUDPAddr := waitExternalDirectUDPAddr
	waitExternalDirectUDPAddr = func(context.Context, net.PacketConn, *transport.Manager) (net.Addr, error) {
		return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}, nil
	}
	t.Cleanup(func() { waitExternalDirectUDPAddr = prevWaitDirectUDPAddr })

	prevPrepareDirectUDPSend := externalPrepareDirectUDPSendFn
	externalPrepareDirectUDPSendFn = func(ctx context.Context, tok token.Token, derpClient *derpbind.Client, listenerDERP key.NodePublic, peerAddr net.Addr, probeConns []net.PacketConn, remoteCandidates []net.Addr, readyAckCh <-chan derpbind.Packet, startAckCh <-chan derpbind.Packet, rateProbeCh <-chan derpbind.Packet, cfg SendConfig) (externalDirectUDPSendPlan, error) {
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return externalDirectUDPSendPlan{}, ctx.Err()
		}
		return externalDirectUDPSendPlan{}, nil
	}
	t.Cleanup(func() { externalPrepareDirectUDPSendFn = prevPrepareDirectUDPSend })

	prevExecutePreparedDirectUDPSend := externalExecutePreparedDirectUDPSendFn
	directInvoked := make(chan struct{}, 1)
	externalExecutePreparedDirectUDPSendFn = func(ctx context.Context, src io.Reader, plan externalDirectUDPSendPlan, cfg SendConfig, metrics *externalTransferMetrics) error {
		select {
		case directInvoked <- struct{}{}:
		default:
		}
		return errors.New("prepared direct send should not be needed for small relay-first payload")
	}
	t.Cleanup(func() { externalExecutePreparedDirectUDPSendFn = prevExecutePreparedDirectUDPSend })

	var status bytes.Buffer
	start := time.Now()
	err = sendExternalViaRelayPrefixThenDirectUDP(ctx, externalRelayPrefixSendConfig{
		src:          bytes.NewReader(payload),
		decision:     rendezvous.Decision{Accept: &rendezvous.AcceptInfo{}},
		derpClient:   senderDERP,
		listenerDERP: listenerDERP.PublicKey(),
		cfg:          SendConfig{Emitter: telemetry.New(&status, telemetry.LevelVerbose)},
	})
	if err != nil {
		t.Fatalf("sendExternalViaRelayPrefixThenDirectUDP() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("sendExternalViaRelayPrefixThenDirectUDP() took %v, want relay completion before slow direct send", elapsed)
	}
	select {
	case <-directInvoked:
		t.Fatal("sendExternalViaRelayPrefixThenDirectUDP() invoked direct send for small relay-first payload")
	default:
	}
	if err := <-receiveErrCh; err != nil {
		t.Fatalf("receiveExternalHandoffDERP() error = %v", err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("receiver output length = %d, want %d", out.Len(), len(payload))
	}
	for _, needle := range []string{
		"udp-send-wall-duration-ms=",
		"udp-send-relay-bytes=1048576",
		"udp-send-direct-bytes=0",
		"udp-send-peak-goodput-mbps=0.00",
	} {
		if !strings.Contains(status.String(), needle) {
			t.Fatalf("status output missing %q in %q", needle, status.String())
		}
	}
}

func TestExternalDirectUDPBufferedWriterUsesDiscardForNullDevice(t *testing.T) {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile(os.DevNull) error = %v", err)
	}
	defer devNull.Close()

	writer, flush := externalDirectUDPBufferedWriter(nopWriteCloser{Writer: devNull})
	if writer != io.Discard {
		t.Fatalf("externalDirectUDPBufferedWriter(/dev/null) writer = %T, want io.Discard", writer)
	}
	if err := flush(); err != nil {
		t.Fatalf("flush() error = %v", err)
	}
}

func TestEmitExternalDirectUDPStatsIncludesDataGoodputFromFirstByte(t *testing.T) {
	var buf bytes.Buffer
	emitter := telemetry.New(&buf, telemetry.LevelVerbose)
	startedAt := time.Unix(0, 0)
	firstByteAt := startedAt.Add(500 * time.Millisecond)
	completedAt := startedAt.Add(1500 * time.Millisecond)

	emitExternalDirectUDPStats(emitter, "udp-receive", 125_000_000, startedAt, firstByteAt, completedAt)

	got := buf.String()
	for _, want := range []string{
		"udp-receive-duration-ms=1500\n",
		"udp-receive-goodput-mbps=666.67\n",
		"udp-receive-first-byte-ms=500\n",
		"udp-receive-data-duration-ms=1000\n",
		"udp-receive-data-goodput-mbps=1000.00\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("emitted stats = %q, want %q", got, want)
		}
	}
}

func TestEmitExternalDirectUDPStatsIncludesDataGoodputWithoutFirstByte(t *testing.T) {
	var buf bytes.Buffer
	emitter := telemetry.New(&buf, telemetry.LevelVerbose)
	startedAt := time.Unix(0, 0)
	completedAt := startedAt.Add(1 * time.Second)

	emitExternalDirectUDPStats(emitter, "udp-send", 125_000_000, startedAt, time.Time{}, completedAt)

	got := buf.String()
	for _, want := range []string{
		"udp-send-duration-ms=1000\n",
		"udp-send-goodput-mbps=1000.00\n",
		"udp-send-first-byte-ms=0\n",
		"udp-send-data-duration-ms=1000\n",
		"udp-send-data-goodput-mbps=1000.00\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("emitted stats = %q, want %q", got, want)
		}
	}
}

func TestEmitExternalDirectUDPSendStatsIncludesReplayPressure(t *testing.T) {
	var buf bytes.Buffer
	emitter := telemetry.New(&buf, telemetry.LevelVerbose)
	stats := probe.TransferStats{
		MaxReplayBytes:               64 << 20,
		ReplayWindowFullWaits:        7,
		ReplayWindowFullWaitDuration: 250 * time.Millisecond,
	}

	emitExternalDirectUDPSendReplayStats(emitter, stats)

	got := buf.String()
	for _, want := range []string{
		"udp-send-max-replay-bytes=67108864\n",
		"udp-send-replay-window-full-waits=7\n",
		"udp-send-replay-window-full-wait-ms=250\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("emitted stats = %q, want %q", got, want)
		}
	}
}

func TestExternalExecutePreparedDirectUDPSendEmitsSessionMetrics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	runID := [16]byte{0x91}
	payload := bytes.Repeat([]byte("direct-session-metrics"), 1<<16)

	recvCh := make(chan error, 1)
	go func() {
		_, err := probe.ReceiveBlastParallelToWriter(ctx, []net.PacketConn{serverConn}, io.Discard, probe.ReceiveConfig{
			Blast:           true,
			Transport:       externalDirectUDPTransportLabel,
			ExpectedRunID:   runID,
			RequireComplete: true,
		}, int64(len(payload)))
		recvCh <- err
	}()

	var buf bytes.Buffer
	emitter := telemetry.New(&buf, telemetry.LevelVerbose)
	metrics := newExternalTransferMetrics(time.Now())
	err = externalExecutePreparedDirectUDPSend(ctx, bytes.NewReader(payload), externalDirectUDPSendPlan{
		probeConns:  []net.PacketConn{clientConn},
		remoteAddrs: []string{serverConn.LocalAddr().String()},
		sendCfg: probe.SendConfig{
			Blast:          true,
			Transport:      externalDirectUDPTransportLabel,
			ChunkSize:      externalDirectUDPChunkSize,
			RateMbps:       0,
			RunID:          runID,
			RepairPayloads: true,
		},
	}, SendConfig{Emitter: emitter}, metrics)
	if err != nil {
		t.Fatalf("externalExecutePreparedDirectUDPSend() error = %v", err)
	}
	select {
	case recvErr := <-recvCh:
		if recvErr != nil {
			t.Fatalf("ReceiveBlastParallelToWriter() error = %v", recvErr)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}

	got := buf.String()
	for _, want := range []string{
		"udp-send-wall-duration-ms=",
		"udp-send-session-first-byte-ms=",
		"udp-send-relay-bytes=0",
		"udp-send-direct-bytes=",
		"udp-send-peak-goodput-mbps=",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("emitted metrics missing %q in %q", want, got)
		}
	}
}

func TestExternalExecutePreparedDirectUDPReceiveEmitsSessionMetrics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	runID := [16]byte{0x92}
	payload := bytes.Repeat([]byte("direct-receive-session-metrics"), 1<<16)

	sendCh := make(chan error, 1)
	go func() {
		_, err := probe.SendBlastParallel(ctx, []net.PacketConn{clientConn}, []string{serverConn.LocalAddr().String()}, bytes.NewReader(payload), probe.SendConfig{
			Blast:          true,
			Transport:      externalDirectUDPTransportLabel,
			ChunkSize:      externalDirectUDPChunkSize,
			RateMbps:       0,
			RunID:          runID,
			RepairPayloads: true,
		})
		sendCh <- err
	}()

	var buf bytes.Buffer
	emitter := telemetry.New(&buf, telemetry.LevelVerbose)
	metrics := newExternalTransferMetrics(time.Now())
	err = externalExecutePreparedDirectUDPReceive(ctx, externalDirectUDPReceivePlan{
		probeConns:  []net.PacketConn{serverConn},
		receiveDst:  io.Discard,
		flushDst:    func() error { return nil },
		receiveCfg:  externalDirectUDPFastDiscardReceiveConfig(),
		fastDiscard: true,
		start:       directUDPStart{ExpectedBytes: int64(len(payload))},
	}, token.Token{SessionID: runID}, ListenConfig{Emitter: emitter}, metrics)
	if err != nil {
		t.Fatalf("externalExecutePreparedDirectUDPReceive() error = %v", err)
	}
	select {
	case sendErr := <-sendCh:
		if sendErr != nil {
			t.Fatalf("SendBlastParallel() error = %v", sendErr)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for send: %v", ctx.Err())
	}

	got := buf.String()
	for _, want := range []string{
		"udp-receive-wall-duration-ms=",
		"udp-receive-session-first-byte-ms=",
		"udp-receive-relay-bytes=0",
		"udp-receive-direct-bytes=",
		"udp-receive-peak-goodput-mbps=",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("emitted metrics missing %q in %q", want, got)
		}
	}
}

func TestExternalDirectUDPConnsUseDedicatedBlastSockets(t *testing.T) {
	base, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()

	conns, _, cleanup, err := externalDirectUDPConns(base, nil, 2, nil)
	if err != nil {
		t.Fatalf("externalDirectUDPConns() error = %v", err)
	}
	defer cleanup()

	if len(conns) != 2 {
		t.Fatalf("len(conns) = %d, want 2", len(conns))
	}
	for i, conn := range conns {
		if conn == base {
			t.Fatalf("conns[%d] reuses the transport-manager socket; want a dedicated blast socket", i)
		}
	}
}

func TestExternalDirectUDPConnsUseProbeCompatibleDualStackSockets(t *testing.T) {
	conns, _, cleanup, err := externalDirectUDPConns(nil, nil, 1, nil)
	if err != nil {
		t.Fatalf("externalDirectUDPConns() error = %v", err)
	}
	defer cleanup()

	udpAddr, ok := conns[0].LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr() = %T, want *net.UDPAddr", conns[0].LocalAddr())
	}
	if udpAddr.IP == nil || udpAddr.IP.To4() != nil {
		t.Fatalf("LocalAddr() = %v, want dual-stack UDP wildcard like the probe benchmark", conns[0].LocalAddr())
	}
}

func TestExternalDirectUDPConnsUseLoopbackIPv4SocketsForFakeTransport(t *testing.T) {
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")

	conns, _, cleanup, err := externalDirectUDPConns(nil, nil, 1, nil)
	if err != nil {
		t.Fatalf("externalDirectUDPConns() error = %v", err)
	}
	defer cleanup()

	udpAddr, ok := conns[0].LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr() = %T, want *net.UDPAddr", conns[0].LocalAddr())
	}
	if !udpAddr.IP.IsLoopback() || udpAddr.IP.To4() == nil {
		t.Fatalf("LocalAddr() = %v, want IPv4 loopback for fake transport", conns[0].LocalAddr())
	}
}

func TestExternalDirectUDPConnsPrimeBlastSockets(t *testing.T) {
	oldPreview := externalDirectUDPPreviewTransportCaps
	defer func() { externalDirectUDPPreviewTransportCaps = oldPreview }()

	var calls int
	externalDirectUDPPreviewTransportCaps = func(conn net.PacketConn, requested string) probe.TransportCaps {
		calls++
		if conn == nil {
			t.Fatal("primed nil packet conn")
		}
		if requested != externalDirectUDPTransportLabel {
			t.Fatalf("requested transport = %q, want %q", requested, externalDirectUDPTransportLabel)
		}
		return probe.TransportCaps{Kind: "test", RequestedKind: requested}
	}

	_, _, cleanup, err := externalDirectUDPConns(nil, nil, 2, nil)
	if err != nil {
		t.Fatalf("externalDirectUDPConns() error = %v", err)
	}
	defer cleanup()

	if calls != 2 {
		t.Fatalf("prime calls = %d, want 2", calls)
	}
}

func TestExternalDirectUDPFastDiscardReceiveConfigAcceptsDiscoveredRuns(t *testing.T) {
	cfg := externalDirectUDPFastDiscardReceiveConfig()
	if !cfg.Blast {
		t.Fatal("Blast = false, want true")
	}
	if cfg.Transport != externalDirectUDPTransportLabel {
		t.Fatalf("Transport = %q, want %q", cfg.Transport, externalDirectUDPTransportLabel)
	}
	if cfg.RequireComplete {
		t.Fatal("RequireComplete = true, want false for probe-style fast-discard receive")
	}
	if len(cfg.ExpectedRunIDs) != 0 {
		t.Fatalf("ExpectedRunIDs = %d entries, want probe-compatible discovered run IDs", len(cfg.ExpectedRunIDs))
	}
}

func TestWaitForDirectUDPReadyAckReturnsFastDiscard(t *testing.T) {
	payload, err := json.Marshal(envelope{
		Type:              envelopeDirectUDPReadyAck,
		DirectUDPReadyAck: &directUDPReadyAck{FastDiscard: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	readyAckCh := make(chan derpbind.Packet, 1)
	readyAckCh <- derpbind.Packet{
		From:    key.NodePublic{},
		Payload: payload,
	}

	got, err := waitForDirectUDPReadyAck(context.Background(), readyAckCh)
	if err != nil {
		t.Fatalf("waitForDirectUDPReadyAck() error = %v", err)
	}
	if !got.FastDiscard {
		t.Fatalf("waitForDirectUDPReadyAck() FastDiscard = false, want true")
	}
}

func TestWaitForDirectUDPStartReturnsExpectedBytes(t *testing.T) {
	payload, err := json.Marshal(envelope{
		Type: envelopeDirectUDPStart,
		DirectUDPStart: &directUDPStart{
			ExpectedBytes: 12345,
			SectionSizes:  []int64{6173, 6172},
			SectionAddrs:  []string{"68.20.14.192:38183", "68.20.14.192:34375"},
			Stream:        true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	startCh := make(chan derpbind.Packet, 1)
	startCh <- derpbind.Packet{
		From:    key.NodePublic{},
		Payload: payload,
	}

	got, err := waitForDirectUDPStart(context.Background(), startCh)
	if err != nil {
		t.Fatalf("waitForDirectUDPStart() error = %v", err)
	}
	if got.ExpectedBytes != 12345 {
		t.Fatalf("waitForDirectUDPStart() ExpectedBytes = %d, want 12345", got.ExpectedBytes)
	}
	if fmt.Sprint(got.SectionSizes) != fmt.Sprint([]int64{6173, 6172}) {
		t.Fatalf("waitForDirectUDPStart() SectionSizes = %v, want [6173 6172]", got.SectionSizes)
	}
	if fmt.Sprint(got.SectionAddrs) != fmt.Sprint([]string{"68.20.14.192:38183", "68.20.14.192:34375"}) {
		t.Fatalf("waitForDirectUDPStart() SectionAddrs = %v, want selected section addresses", got.SectionAddrs)
	}
	if !got.Stream {
		t.Fatal("waitForDirectUDPStart() Stream = false, want true")
	}
}

func TestWaitForDirectUDPStartAckAcceptsStartAck(t *testing.T) {
	payload, err := json.Marshal(envelope{Type: envelopeDirectUDPStartAck})
	if err != nil {
		t.Fatal(err)
	}
	startAckCh := make(chan derpbind.Packet, 1)
	startAckCh <- derpbind.Packet{
		From:    key.NodePublic{},
		Payload: payload,
	}

	if err := waitForDirectUDPStartAck(context.Background(), startAckCh); err != nil {
		t.Fatalf("waitForDirectUDPStartAck() error = %v", err)
	}
	if !isDirectUDPStartAckPayload(payload) {
		t.Fatal("isDirectUDPStartAckPayload() = false, want true")
	}
}

func TestEmitExternalDirectUDPReceiveDebugIncludesExpectedAndResultBytes(t *testing.T) {
	var buf bytes.Buffer
	emitter := telemetry.New(&buf, telemetry.LevelVerbose)

	emitExternalDirectUDPReceiveStartDebug(emitter, 12345)
	emitExternalDirectUDPReceiveResultDebug(emitter, probe.TransferStats{BytesReceived: 67890}, nil)

	got := buf.String()
	if !strings.Contains(got, "udp-fast-discard-expected-bytes=12345\n") {
		t.Fatalf("receive start debug = %q, want expected byte line", got)
	}
	if !strings.Contains(got, "udp-receive-bytes=67890\n") {
		t.Fatalf("receive result debug = %q, want receive byte line", got)
	}
}

func TestExternalDirectUDPSpoolDiscardLanesSplitsAndRewinds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	src := []byte("abcdefghij")
	spool, err := externalDirectUDPSpoolDiscardLanes(ctx, bytes.NewReader(src), 3, 1)
	if err != nil {
		t.Fatalf("externalDirectUDPSpoolDiscardLanes() error = %v", err)
	}
	defer spool.Close()

	if spool.TotalBytes != int64(len(src)) {
		t.Fatalf("TotalBytes = %d, want %d", spool.TotalBytes, len(src))
	}
	if got, want := spool.Sizes[0], int64(4); got != want {
		t.Fatalf("lane 0 size = %d, want %d", got, want)
	}
	if got, want := spool.Sizes[1], int64(3); got != want {
		t.Fatalf("lane 1 size = %d, want %d", got, want)
	}
	if got, want := spool.Sizes[2], int64(3); got != want {
		t.Fatalf("lane 2 size = %d, want %d", got, want)
	}
	wantChunks := [][]byte{[]byte("abcd"), []byte("efg"), []byte("hij")}
	for i, want := range wantChunks {
		got := make([]byte, len(want))
		if _, err := spool.File.ReadAt(got, spool.Offsets[i]); err != nil {
			t.Fatalf("ReadAt(lane %d) error = %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("lane %d contents = %q, want %q", i, got, want)
		}
	}
}

func TestExternalDirectUDPReceiveSectionLayoutUsesSenderSizes(t *testing.T) {
	sizes, offsets, err := externalDirectUDPReceiveSectionLayout(10, 3, []int64{7, 3})
	if err != nil {
		t.Fatalf("externalDirectUDPReceiveSectionLayout() error = %v", err)
	}
	if fmt.Sprint(sizes) != fmt.Sprint([]int64{7, 3}) {
		t.Fatalf("sizes = %v, want [7 3]", sizes)
	}
	if fmt.Sprint(offsets) != fmt.Sprint([]int64{0, 7}) {
		t.Fatalf("offsets = %v, want [0 7]", offsets)
	}
}

func TestExternalDirectUDPReceiveSectionTargetUsesRegularFileDirectly(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "derpcat-section-target-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	target, copyToDst, cleanup, err := externalDirectUDPReceiveSectionTarget(file, 64)
	if err != nil {
		t.Fatalf("externalDirectUDPReceiveSectionTarget() error = %v", err)
	}
	defer cleanup()
	if target != file {
		t.Fatal("externalDirectUDPReceiveSectionTarget() did not use regular file directly")
	}
	if copyToDst {
		t.Fatal("externalDirectUDPReceiveSectionTarget() copyToDst = true, want false for regular file")
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 64 {
		t.Fatalf("direct target size = %d, want 64", info.Size())
	}
}

func TestExternalDirectUDPReceiveSectionTargetUsesWrappedRegularFileDirectly(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "derpcat-section-target-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	target, copyToDst, cleanup, err := externalDirectUDPReceiveSectionTarget(nopWriteCloser{Writer: file}, 64)
	if err != nil {
		t.Fatalf("externalDirectUDPReceiveSectionTarget() error = %v", err)
	}
	defer cleanup()
	if target != file {
		t.Fatal("externalDirectUDPReceiveSectionTarget() did not use wrapped regular file directly")
	}
	if copyToDst {
		t.Fatal("externalDirectUDPReceiveSectionTarget() copyToDst = true, want false for wrapped regular file")
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 64 {
		t.Fatalf("direct target size = %d, want 64", info.Size())
	}
}

func TestExternalDirectUDPSectionWriterForTargetBypassesBufferForRegularFiles(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "derpcat-section-target-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	buffered := bufio.NewWriter(file)

	target, flush := externalDirectUDPSectionWriterForTarget(file, buffered, buffered.Flush)
	if target != file {
		t.Fatal("externalDirectUDPSectionWriterForTarget() did not use the raw regular file")
	}
	if err := flush(); err != nil {
		t.Fatalf("flush() error = %v", err)
	}
}

func TestExternalDirectUDPSectionWriterForTargetBypassesBufferForWrappedRegularFiles(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "derpcat-section-target-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	buffered := bufio.NewWriter(file)

	target, flush := externalDirectUDPSectionWriterForTarget(nopWriteCloser{Writer: file}, buffered, buffered.Flush)
	if target != file {
		t.Fatal("externalDirectUDPSectionWriterForTarget() did not use the wrapped raw regular file")
	}
	if err := flush(); err != nil {
		t.Fatalf("flush() error = %v", err)
	}
}

func TestExternalDirectUDPReceiveSectionTargetSpoolsNonFiles(t *testing.T) {
	var dst bytes.Buffer

	target, copyToDst, cleanup, err := externalDirectUDPReceiveSectionTarget(&dst, 64)
	if err != nil {
		t.Fatalf("externalDirectUDPReceiveSectionTarget() error = %v", err)
	}
	defer cleanup()
	if target == nil {
		t.Fatal("externalDirectUDPReceiveSectionTarget() target = nil")
	}
	if !copyToDst {
		t.Fatal("externalDirectUDPReceiveSectionTarget() copyToDst = false, want true for non-file writer")
	}
}

func TestExternalDirectUDPFinishSectionTargetSeeksDirectFileToEnd(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "derpcat-section-target-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if _, err := file.WriteAt([]byte("abc"), 0); err != nil {
		t.Fatal(err)
	}
	if err := externalDirectUDPFinishSectionTarget(file, false, file, 3); err != nil {
		t.Fatalf("externalDirectUDPFinishSectionTarget() error = %v", err)
	}
	if _, err := file.WriteString("d"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcd" {
		t.Fatalf("file contents = %q, want %q", got, "abcd")
	}
}

func TestExternalDirectUDPParallelCandidateStringsPreferEstablishedPeerAddr(t *testing.T) {
	peer, err := net.ResolveUDPAddr("udp", "127.0.0.1:44321")
	if err != nil {
		t.Fatal(err)
	}

	got := externalDirectUDPParallelCandidateStringsForPeer(parseCandidateStrings([]string{
		"10.0.1.254:11111",
		"10.0.1.254:22222",
		"127.0.0.1:11111",
		"127.0.0.1:22222",
	}), 2, peer)
	want := []string{"127.0.0.1:11111", "127.0.0.1:22222"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPParallelCandidateStringsForPeer() = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPParallelCandidateStringsPreferLoopbackForFakeTransport(t *testing.T) {
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")
	peer, err := net.ResolveUDPAddr("udp", "10.0.1.254:44321")
	if err != nil {
		t.Fatal(err)
	}

	got := externalDirectUDPParallelCandidateStringsForPeer(parseCandidateStrings([]string{
		"10.0.1.254:11111",
		"10.0.1.254:22222",
		"127.0.0.1:11111",
		"127.0.0.1:22222",
	}), 2, peer)
	want := []string{"127.0.0.1:11111", "127.0.0.1:22222"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPParallelCandidateStringsForPeer(fake) = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPSelectRemoteAddrsByConnLeavesUnverifiedLanesBlank(t *testing.T) {
	observedByConn := [][]net.Addr{
		parseCandidateStrings([]string{"198.51.100.1:10001"}),
		parseCandidateStrings([]string{"198.51.100.1:10001"}),
		parseCandidateStrings([]string{"198.51.100.1:10003"}),
		nil,
	}

	got := externalDirectUDPSelectRemoteAddrsByConn(observedByConn, 4, nil)
	want := []string{"198.51.100.1:10001", "", "198.51.100.1:10003", ""}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPSelectRemoteAddrsByConn() = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPFillMissingSelectedAddrsBackfillsUnusedFallback(t *testing.T) {
	selected := []string{
		"198.51.100.1:10001",
		"",
		"198.51.100.1:10003",
	}
	fallback := []string{
		"203.0.113.1:10001",
		"203.0.113.1:10002",
		"203.0.113.1:10003",
	}

	got := externalDirectUDPFillMissingSelectedAddrs(selected, fallback)
	want := []string{
		"198.51.100.1:10001",
		"203.0.113.1:10002",
		"198.51.100.1:10003",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPFillMissingSelectedAddrs() = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPRateMbpsForLanesScalesToVerifiedLaneCount(t *testing.T) {
	tests := []struct {
		name  string
		rate  int
		lanes int
		want  int
	}{
		{name: "disabled", rate: 0, lanes: 4, want: 0},
		{name: "none", rate: externalDirectUDPMaxRateMbps, lanes: 0, want: 0},
		{name: "one", rate: externalDirectUDPMaxRateMbps, lanes: 1, want: 1250},
		{name: "four", rate: externalDirectUDPMaxRateMbps, lanes: 4, want: 5000},
		{name: "full", rate: externalDirectUDPMaxRateMbps, lanes: externalDirectUDPParallelism, want: externalDirectUDPMaxRateMbps},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := externalDirectUDPRateMbpsForLanes(tt.rate, tt.lanes); got != tt.want {
				t.Fatalf("externalDirectUDPRateMbpsForLanes(%d, %d) = %d, want %d", tt.rate, tt.lanes, got, tt.want)
			}
		})
	}
}

func TestExternalDirectUDPActiveLanesForRateScalesDownSlowPaths(t *testing.T) {
	tests := []struct {
		name      string
		rateMbps  int
		available int
		want      int
	}{
		{name: "no sockets", rateMbps: 350, available: 0, want: 0},
		{name: "unknown uses one", rateMbps: 0, available: externalDirectUDPParallelism, want: 1},
		{name: "few mbps uses one", rateMbps: 8, available: externalDirectUDPParallelism, want: 1},
		{name: "canlxc class uses one", rateMbps: 350, available: externalDirectUDPParallelism, want: 1},
		{name: "mid path uses two paced lanes", rateMbps: 700, available: externalDirectUDPParallelism, want: 2},
		{name: "gigabit class uses four paced lanes", rateMbps: 1200, available: externalDirectUDPParallelism, want: 4},
		{name: "fast path keeps all paced lanes", rateMbps: 1700, available: externalDirectUDPParallelism, want: externalDirectUDPParallelism},
		{name: "very fast path keeps all paced lanes", rateMbps: 2000, available: externalDirectUDPParallelism, want: externalDirectUDPParallelism},
		{name: "two gigabit class keeps all paced lanes", rateMbps: 2250, available: externalDirectUDPParallelism, want: externalDirectUDPParallelism},
		{name: "clamps to available", rateMbps: 2250, available: 3, want: 3},
		{name: "higher than two gigabit class keeps all", rateMbps: 5000, available: externalDirectUDPParallelism, want: externalDirectUDPParallelism},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := externalDirectUDPActiveLanesForRate(tt.rateMbps, tt.available); got != tt.want {
				t.Fatalf("externalDirectUDPActiveLanesForRate(%d, %d) = %d, want %d", tt.rateMbps, tt.available, got, tt.want)
			}
		})
	}
}

func TestExternalDirectUDPRetainedLanesForRateKeepsStripedHeadroom(t *testing.T) {
	tests := []struct {
		name      string
		rateMbps  int
		available int
		striped   bool
		want      int
	}{
		{name: "non-striped seven hundred stays on two lanes", rateMbps: 700, available: externalDirectUDPParallelism, want: 2},
		{name: "striped seven hundred keeps four lanes warm", rateMbps: 700, available: externalDirectUDPParallelism, striped: true, want: 4},
		{name: "striped seven hundred respects smaller pools", rateMbps: 700, available: 2, striped: true, want: 2},
		{name: "striped gigabit tier keeps four lanes", rateMbps: 1200, available: externalDirectUDPParallelism, striped: true, want: 4},
		{name: "striped top tier keeps all lanes", rateMbps: 2250, available: externalDirectUDPParallelism, striped: true, want: externalDirectUDPParallelism},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := externalDirectUDPRetainedLanesForRate(tt.rateMbps, tt.available, tt.striped); got != tt.want {
				t.Fatalf("externalDirectUDPRetainedLanesForRate(%d, %d, %t) = %d, want %d", tt.rateMbps, tt.available, tt.striped, got, tt.want)
			}
		})
	}
}

func TestExternalDirectUDPDataLaneRateBasisUsesMeasuredProbeTierForUnlockedCeiling(t *testing.T) {
	rates := []int{8, 25, 75, 150, 350, 700, 1200, 2250}

	if got, want := externalDirectUDPDataLaneRateBasisMbps(2183, 10_000, rates), 2250; got != want {
		t.Fatalf("externalDirectUDPDataLaneRateBasisMbps(clean capped top) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPActiveLanesForRate(externalDirectUDPDataLaneRateBasisMbps(2183, 10_000, rates), 8), externalDirectUDPParallelism; got != want {
		t.Fatalf("active lanes for clean capped top = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataLaneRateBasisMbps(600, 700, rates), 700; got != want {
		t.Fatalf("externalDirectUDPDataLaneRateBasisMbps(slow ceiling) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataLaneRateBasisMbps(700, 1800, rates), externalDirectUDPDataStartHighMbps; got != want {
		t.Fatalf("externalDirectUDPDataLaneRateBasisMbps(medium start with sub-top adaptive ceiling) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataLaneRateBasisMbps(1200, 1800, rates), externalDirectUDPDataStartHighMbps; got != want {
		t.Fatalf("externalDirectUDPDataLaneRateBasisMbps(gigabit start with sub-top adaptive ceiling) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataLaneRateBasisMbps(700, 2250, rates), externalDirectUDPActiveLaneFourMaxMbps; got != want {
		t.Fatalf("externalDirectUDPDataLaneRateBasisMbps(clean medium start with high adaptive ceiling) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataLaneRateBasisMbps(1200, 2250, rates), externalDirectUDPActiveLaneFourMaxMbps; got != want {
		t.Fatalf("externalDirectUDPDataLaneRateBasisMbps(gigabit start with high adaptive ceiling) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataLaneRateBasisMbps(2183, 0, nil), 2183; got != want {
		t.Fatalf("externalDirectUDPDataLaneRateBasisMbps(no ceiling) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataLaneRateBasisMbps(150, 10_000, nil), 150; got != want {
		t.Fatalf("externalDirectUDPDataLaneRateBasisMbps(unprobed unlocked ceiling) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPDataRateCeilingCapsPartialLaneSlowPaths(t *testing.T) {
	tests := []struct {
		name         string
		probeCeil    int
		selectedRate int
		activeLanes  int
		want         int
	}{
		{name: "single paced lane caps to one-lane class", probeCeil: 700, selectedRate: 350, activeLanes: 1, want: externalDirectUDPActiveLaneOneMaxMbps},
		{name: "single lane high ceiling is bounded to one-lane class", probeCeil: 2250, selectedRate: 350, activeLanes: 1, want: externalDirectUDPActiveLaneOneMaxMbps},
		{name: "two lane medium path can still ramp", probeCeil: 2250, selectedRate: 700, activeLanes: 2, want: 2250},
		{name: "four lane gigabit class can still ramp", probeCeil: 2250, selectedRate: 1200, activeLanes: 4, want: 2250},
		{name: "full lane ktzlxc class keeps probe ceiling", probeCeil: 10_000, selectedRate: 2250, activeLanes: externalDirectUDPParallelism, want: 10_000},
		{name: "disabled probe ceiling stays disabled", probeCeil: 0, selectedRate: 350, activeLanes: 1, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := externalDirectUDPDataRateCeilingMbps(tt.probeCeil, tt.selectedRate, tt.activeLanes); got != tt.want {
				t.Fatalf("externalDirectUDPDataRateCeilingMbps(%d, %d, %d) = %d, want %d", tt.probeCeil, tt.selectedRate, tt.activeLanes, got, tt.want)
			}
		})
	}
}

func TestExternalDirectUDPShouldUseStripedBlast(t *testing.T) {
	tests := []struct {
		name           string
		availableLanes int
		fastDiscard    bool
		want           bool
	}{
		{name: "fast discard disables striping", availableLanes: 8, fastDiscard: true, want: false},
		{name: "single lane keeps simpler unstriped path", availableLanes: 1, want: false},
		{name: "two lanes enable striped path", availableLanes: 2, want: true},
		{name: "four lanes enable striped path", availableLanes: 4, want: true},
		{name: "eight lanes enable striped path", availableLanes: 8, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := externalDirectUDPShouldUseStripedBlast(tt.availableLanes, tt.fastDiscard); got != tt.want {
				t.Fatalf("externalDirectUDPShouldUseStripedBlast(%d, %t) = %t, want %t", tt.availableLanes, tt.fastDiscard, got, tt.want)
			}
		})
	}
}

func TestExternalDirectUDPDataStartRateBoundsFalseCleanHighProbe(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_401_032, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_002_352, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 40_826_616, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_401_032, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 30_002_352, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 40_826_616, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected <= externalDirectUDPDataStartMaxMbps {
		t.Fatalf("selected rate = %d, want a high false-clean probe sample above data start cap", selected)
	}
	if got, want := externalDirectUDPDataStartRateMbps(selected), externalDirectUDPDataStartHighMbps; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbps(%d) = %d, want %d", selected, got, want)
	}
	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received), 2250; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(false-clean top probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPDataStartRateUsesBoundedHighStartForHighConfidenceProbe(t *testing.T) {
	if got, want := externalDirectUDPDataStartRateMbps(2425), externalDirectUDPRateProbeDefaultMaxMbps; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbps(top-tier selected probe) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataStartRateMbps(2098), externalDirectUDPDataStartHighMbps; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbps(high-confidence probe) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataStartRateMbps(1200), externalDirectUDPDataStartHighMbps; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbps(near-clean gigabit probe) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataStartRateMbps(700), 700; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbps(clean medium probe) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataStartRateMbps(600), externalDirectUDPDataStartMaxMbps; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbps(mid probe) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataStartRateMbps(150), 150; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbps(low probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPDataStartRateUsesHighCeilingForSenderLimitedProbe(t *testing.T) {
	if got, want := externalDirectUDPDataStartRateMbpsForCeiling(1826, 2250), 1826; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForCeiling(high selected high ceiling) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataStartRateMbpsForCeiling(700, 2250), 700; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForCeiling(clean selected high ceiling) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataStartRateMbpsForCeiling(700, 1200), 700; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForCeiling(clean selected gigabit ceiling) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataStartRateMbpsForCeiling(350, 2250), 350; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForCeiling(sender-limited high ceiling) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataStartRateMbpsForCeiling(350, 700), 350; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForCeiling(medium ceiling) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataStartRateMbpsForCeiling(150, 2250), 150; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForCeiling(low selected high ceiling) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPStartBudgetScalesDownForSlowCeilings(t *testing.T) {
	tests := []struct {
		name          string
		rateCeiling   int
		wantRateMbps  int
		wantLanes     int
		wantReplayWin uint64
	}{
		{name: "zero", rateCeiling: 0, wantRateMbps: externalDirectUDPRateProbeMinMbps, wantLanes: 1, wantReplayWin: 16 << 20},
		{name: "eighty five", rateCeiling: 85, wantRateMbps: 85, wantLanes: 1, wantReplayWin: 16 << 20},
		{name: "three hundred fifty", rateCeiling: 350, wantRateMbps: 250, wantLanes: 1, wantReplayWin: 32 << 20},
		{name: "seven hundred", rateCeiling: 700, wantRateMbps: 525, wantLanes: 2, wantReplayWin: 64 << 20},
		{name: "twelve hundred", rateCeiling: 1200, wantRateMbps: 900, wantLanes: 2, wantReplayWin: 64 << 20},
		{name: "eighteen hundred", rateCeiling: 1800, wantRateMbps: 1200, wantLanes: 4, wantReplayWin: 128 << 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := externalDirectUDPStartBudget(tt.rateCeiling)
			if got.RateMbps != tt.wantRateMbps {
				t.Fatalf("RateMbps = %d, want %d", got.RateMbps, tt.wantRateMbps)
			}
			if got.ActiveLanes != tt.wantLanes {
				t.Fatalf("ActiveLanes = %d, want %d", got.ActiveLanes, tt.wantLanes)
			}
			if got.ReplayWindowBytes != tt.wantReplayWin {
				t.Fatalf("ReplayWindowBytes = %d, want %d", got.ReplayWindowBytes, tt.wantReplayWin)
			}
		})
	}
}

func TestExternalDirectUDPStartBudgetPreservesHighCeilingShape(t *testing.T) {
	got := externalDirectUDPStartBudget(2250)
	if got.ActiveLanes != 8 {
		t.Fatalf("ActiveLanes = %d, want 8", got.ActiveLanes)
	}
	if got.RateMbps < 1000 {
		t.Fatalf("RateMbps = %d, want at least 1000", got.RateMbps)
	}
	if got.ReplayWindowBytes != externalDirectUDPStreamReplayBytes {
		t.Fatalf("ReplayWindowBytes = %d, want %d", got.ReplayWindowBytes, externalDirectUDPStreamReplayBytes)
	}
}

func TestExternalDirectUDPDataStartRateKeepsCleanSelectedTierDuringBufferedCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_746_880, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_680, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_968, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 112_500_000, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 125_000_000, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 140_625_000, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_746_880, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_500_680, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 30_000_968, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 69_714_848, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 19_039_688, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 15_392_848, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 1200 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live canlxc buffered collapse) = %d, want 1200", selected)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != selected {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live canlxc buffered collapse) = %d, want selected tier %d", ceiling, selected)
	}
	if got, want := externalDirectUDPDataStartRateMbpsForProbeSamples(selected, ceiling, sent, received), selected; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForProbeSamples(clean selected tier during buffered collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPDataStartRateKeepsLiveKtzlxcReverseSustainedGain(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 624_184, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_868_400, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_738_184, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_746_880, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_488_224, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_960_832, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 111_803_280, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 125_237_095, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 140_464_656, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 624_184, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_868_400, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_738_184, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_746_880, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_488_224, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_960_832, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 90_560_656, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 81_404_112, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 85_683_440, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 1200 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live ktzlxc reverse sustained gain) = %d, want 1200", selected)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling < 1800 {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live ktzlxc reverse sustained gain) = %d, want at least 1800", ceiling)
	}
	if got, want := externalDirectUDPDataStartRateMbpsForProbeSamples(selected, ceiling, sent, received), externalDirectUDPDataStartHighMbps; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForProbeSamples(live ktzlxc reverse sustained gain) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPDataStartRateKeepsCleanSelectedTierDuringHigherTierThroughputCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_868_400, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_319_224, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 13_613_024, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_999_584, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 66_653_440, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 74_475_808, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 62_805_920, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_868_400, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_319_224, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 13_613_024, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_999_584, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 66_653_440, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 74_475_808, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 50_244_736, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 1200 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live canlxc clean collapse) = %d, want 1200", selected)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != selected {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live canlxc clean collapse) = %d, want selected tier %d", ceiling, selected)
	}
	if got, want := externalDirectUDPDataStartRateMbpsForProbeSamples(selected, ceiling, sent, received), selected; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForProbeSamples(clean selected tier during higher-tier throughput collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPDataStartRateGuardsLiveCanlxcLossyBufferedHighTierCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_680, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_994_048, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 112_500_000, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 125_000_000, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 140_625_000, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_500_680, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_994_048, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 102_190_408, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 16_686_888, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 0, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 1800 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live canlxc lossy buffered high tier collapse) = %d, want 1800", selected)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != selected {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live canlxc lossy buffered high tier collapse) = %d, want selected tier %d", ceiling, selected)
	}
	if got, want := externalDirectUDPDataStartRateMbpsForProbeSamples(selected, ceiling, sent, received), externalDirectUDPDataStartMaxMbps; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForProbeSamples(live canlxc lossy buffered high tier collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPDataStartRateKeepsCleanSelectedCeilingDuringTopTierCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_739_960, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 16_577_552, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_982_976, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 81_357_056, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 76_244_560, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 55_227_063, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_739_960, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 16_577_552, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_982_976, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 81_357_056, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 76_244_560, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 41_972_568, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 1200 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live canlxc selected ceiling top collapse) = %d, want 1200", selected)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != selected {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live canlxc selected ceiling top collapse) = %d, want selected tier %d", ceiling, selected)
	}
	if got, want := externalDirectUDPDataStartRateMbpsForProbeSamples(selected, ceiling, sent, received), selected; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForProbeSamples(clean selected ceiling during top-tier collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPDataStartRateGuardsInefficientCleanHighSelectedTier(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_709_512, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_169_904, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_976_056, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 89_248_624, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 71_681_512, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 36_890_520, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_709_512, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_169_904, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_976_056, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 89_248_624, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 71_681_512, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 36_890_520, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 1800 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(inefficient clean high selected tier) = %d, want 1800", selected)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != 1800 {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(inefficient clean high selected tier) = %d, want 1800", ceiling)
	}
	if got, want := externalDirectUDPDataStartRateMbpsForProbeSamples(selected, ceiling, sent, received), externalDirectUDPDataStartHighMbps; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForProbeSamples(inefficient clean high selected tier) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPDataExplorationCeilingOpensHighCleanSelectedTier(t *testing.T) {
	if got, want := externalDirectUDPDataExplorationCeilingMbps(10_000, 1200, 1200), 2100; got != want {
		t.Fatalf("externalDirectUDPDataExplorationCeilingMbps(high clean tier) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPDataExplorationCeilingOpensCleanSevenHundredKnee(t *testing.T) {
	if got, want := externalDirectUDPDataExplorationCeilingMbps(10_000, 700, 1200), 2100; got != want {
		t.Fatalf("externalDirectUDPDataExplorationCeilingMbps(clean 700 knee) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPDataExplorationCeilingKeepsMediumTierCapped(t *testing.T) {
	if got, want := externalDirectUDPDataExplorationCeilingMbps(10_000, 600, 700), 700; got != want {
		t.Fatalf("externalDirectUDPDataExplorationCeilingMbps(medium tier) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateUsesHighGoodputCappedTopProbe(t *testing.T) {
	sent := ktzlxcHighGoodputCappedTopProbeSentSamples()
	received := ktzlxcHighGoodputCappedTopProbeReceivedSamples()

	if got, want := externalDirectUDPSelectInitialRateMbps(10_000, sent, received), 2081; got != want {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(ktzlxc high-goodput capped top probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateKeepsCleanKtzlxcReverseTierBeforeTopCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 608_960, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_804_736, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_597_016, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_360_896, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_005_120, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 608_960, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_804_736, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_597_016, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_360_896, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 30_005_120, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 23_414_512, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 1200 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(ktzlxc reverse clean 1200 before top collapse) = %d, want 1200", selected)
	}
	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received), 1200; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(ktzlxc reverse clean 1200 before top collapse) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataStartRateMbpsForProbeSamples(selected, 1200, sent, received), selected; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForProbeSamples(ktzlxc reverse clean 1200 before top collapse) = %d, want %d", got, want)
	}
	basis := externalDirectUDPDataLaneRateBasisMbps(selected, 1200, externalDirectUDPRateProbeRates(10_000, -1))
	if got, want := externalDirectUDPActiveLanesForRate(basis, 8), 4; got != want {
		t.Fatalf("externalDirectUDPActiveLanesForRate(ktzlxc reverse clean 1200 before top collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateKeepsNearCleanKtzlxcReverseTierBeforeTopCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 608_960, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_793_664, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_587_328, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_558_656, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_316_608, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_005_120, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 608_960, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_793_664, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_587_328, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_558_656, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_316_608, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_259_144, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 24_110_664, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 1200 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(ktzlxc reverse near-clean 1200 before top collapse) = %d, want 1200", selected)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != 2250 {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(ktzlxc reverse near-clean 1200 before top collapse) = %d, want 2250", ceiling)
	}
	basis := externalDirectUDPDataLaneRateBasisMbps(selected, ceiling, externalDirectUDPRateProbeRates(10_000, -1))
	if got, want := externalDirectUDPActiveLanesForRate(basis, 8), externalDirectUDPParallelism; got != want {
		t.Fatalf("externalDirectUDPActiveLanesForRate(ktzlxc reverse near-clean 1200 before top collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingCapsHighSelectedLossyImprovingTopProbeToObservedGoodput(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 210_368, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 597_888, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_793_664, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_569_728, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_360_896, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_916_544, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 210_368, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 597_888, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_793_664, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_569_728, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_360_896, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_916_544, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 34_244_312, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 1200 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(high selected lossy improving top probe) = %d, want 1200", selected)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	wantCeiling := int(externalDirectUDPSampleGoodputMbps(34_244_312, 200) + 0.5)
	if ceiling != wantCeiling {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(high selected lossy improving top probe) = %d, want %d", ceiling, wantCeiling)
	}
	basis := externalDirectUDPDataLaneRateBasisMbps(selected, ceiling, externalDirectUDPRateProbeRates(10_000, -1))
	if got, want := externalDirectUDPActiveLanesForRate(basis, 8), 4; got != want {
		t.Fatalf("externalDirectUDPActiveLanesForRate(high selected lossy improving top probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingAllowsHighGoodputCappedTopProbe(t *testing.T) {
	sent := ktzlxcHighGoodputCappedTopProbeSentSamples()
	received := ktzlxcHighGoodputCappedTopProbeReceivedSamples()

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 2081, sent, received), 2250; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(ktzlxc high-goodput capped top probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingAllowsAdaptiveLossyButImprovingHighCeiling(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 210_368, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 600_656, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_800_584, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_558_656, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_349_824, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 210_368, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 600_656, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_800_584, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_558_656, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_349_824, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 19_068_752, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 23_298_256, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received), externalDirectUDPRateProbeDefaultMaxMbps; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(lossy but improving high ceiling) = %d, want %d; selected=%d", got, want, selected)
	}
}

func TestExternalDirectUDPSelectInitialRateKeepsLiveKtzlxcForwardSenderLimitedGain(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 210_368, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 608_960, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_804_736, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_566_960, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_088_248, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 21_497_672, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 17_947_712, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 210_368, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 608_960, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_804_736, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_566_960, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_088_248, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 21_497_672, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 17_947_712, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected < externalDirectUDPActiveLaneTwoMaxMbps {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live ktzlxc forward) = %d, want at least %d after 1200 Mbps probe beats 700 Mbps", selected, externalDirectUDPActiveLaneTwoMaxMbps)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != 2250 {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live ktzlxc forward) = %d, want 2250", ceiling)
	}
	basis := externalDirectUDPDataLaneRateBasisMbps(externalDirectUDPDataStartRateMbps(selected), ceiling, externalDirectUDPRateProbeRates(10_000, -1))
	if got, want := externalDirectUDPActiveLanesForRate(basis, 8), externalDirectUDPParallelism; got != want {
		t.Fatalf("externalDirectUDPActiveLanesForRate(live ktzlxc forward) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingKeepsLiveKtzlxcForwardCleanThroughputCollapseAtBestTier(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_680, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_999_584, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 103_372_344, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 69_173_704, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 67_535_048, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_500_680, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_999_584, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 103_372_344, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 69_173_704, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 67_535_048, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 1800 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live ktzlxc forward clean collapse) = %d, want 1800", selected)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != selected {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live ktzlxc forward clean collapse) = %d, want selected tier %d", ceiling, selected)
	}
	if got, want := externalDirectUDPDataExplorationCeilingMbps(10_000, selected, ceiling), externalDirectUDPDataExplorationDefaultMaxMbps; got != want {
		t.Fatalf("externalDirectUDPDataExplorationCeilingMbps(live ktzlxc forward clean collapse) = %d, want guarded exploration ceiling %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateKeepsLiveKtzlxcReverseLossyGain(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 597_888, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_804_736, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_609_472, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_596_024, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_255_712, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_048_370, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_477_086, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 597_888, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_804_736, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_609_472, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_596_024, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_255_712, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 24_038_696, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 15_813_584, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected < 1200 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live ktzlxc reverse) = %d, want at least 1200 after lossy 1200 Mbps probe still improves goodput", selected)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != 1200 {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live ktzlxc reverse) = %d, want 1200", ceiling)
	}
	basis := externalDirectUDPDataLaneRateBasisMbps(externalDirectUDPDataStartRateMbps(selected), ceiling, externalDirectUDPRateProbeRates(10_000, -1))
	if got, want := externalDirectUDPActiveLanesForRate(basis, 8), 4; got != want {
		t.Fatalf("externalDirectUDPActiveLanesForRate(live ktzlxc reverse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectCeilingCapsLiveKtzlxcReverseLossyRecovery(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 608_960, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_804_736, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_609_472, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_564_192, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_316_608, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_891_789, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_777_831, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 608_960, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_804_736, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_609_472, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_564_192, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_316_608, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 15_842_648, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 25_550_024, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected < externalDirectUDPActiveLaneTwoMaxMbps {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live ktzlxc reverse lossy recovery) = %d, want at least 700 to avoid collapsing to 350 after later recovery", selected)
	}
	if got, want := externalDirectUDPDataStartRateMbps(selected), externalDirectUDPActiveLaneTwoMaxMbps; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbps(live ktzlxc reverse lossy recovery) = %d, want %d", got, want)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != externalDirectUDPRateProbeDefaultMaxMbps {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live ktzlxc reverse lossy recovery) = %d, want %d", ceiling, externalDirectUDPRateProbeDefaultMaxMbps)
	}
	basis := externalDirectUDPDataLaneRateBasisMbps(externalDirectUDPDataStartRateMbps(selected), ceiling, externalDirectUDPRateProbeRates(10_000, -1))
	if got, want := externalDirectUDPActiveLanesForRate(basis, 8), externalDirectUDPParallelism; got != want {
		t.Fatalf("externalDirectUDPActiveLanesForRate(live ktzlxc reverse lossy recovery) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectCeilingUsesLaterKtzlxcReverseRecovery(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_867_016, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_736_800, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_719_200, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_424_560, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_994_496, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 45_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_867_016, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_736_800, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_719_200, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_424_560, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 17_572_648, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 10_954_360, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 25_967_992, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != externalDirectUDPActiveLaneTwoMaxMbps {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(later ktzlxc reverse recovery) = %d, want %d", selected, externalDirectUDPActiveLaneTwoMaxMbps)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != externalDirectUDPRateProbeDefaultMaxMbps {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(later ktzlxc reverse recovery) = %d, want %d", ceiling, externalDirectUDPRateProbeDefaultMaxMbps)
	}
	basis := externalDirectUDPDataLaneRateBasisMbps(externalDirectUDPDataStartRateMbps(selected), ceiling, externalDirectUDPRateProbeRates(10_000, -1))
	if got, want := externalDirectUDPActiveLanesForRate(basis, 8), externalDirectUDPParallelism; got != want {
		t.Fatalf("externalDirectUDPActiveLanesForRate(later ktzlxc reverse recovery) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateKeepsCleanKtzlxcSevenHundredBeforeLossyHigherGain(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_869_784, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_715_048, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_449_472, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_994_496, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 45_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_869_784, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_715_048, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_449_472, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 19_676_328, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 11_552_248, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 23_314_864, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected < externalDirectUDPActiveLaneTwoMaxMbps {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live ktzlxc clean 700 before lossy higher gain) = %d, want at least %d", selected, externalDirectUDPActiveLaneTwoMaxMbps)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != externalDirectUDPRateProbeDefaultMaxMbps {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live ktzlxc clean 700 before lossy higher gain) = %d, want %d", ceiling, externalDirectUDPRateProbeDefaultMaxMbps)
	}
	basis := externalDirectUDPDataLaneRateBasisMbps(externalDirectUDPDataStartRateMbps(selected), ceiling, externalDirectUDPRateProbeRates(10_000, -1))
	if got, want := externalDirectUDPActiveLanesForRate(basis, 8), externalDirectUDPParallelism; got != want {
		t.Fatalf("externalDirectUDPActiveLanesForRate(live ktzlxc clean 700 before lossy higher gain) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingUsesBestObservedTierAfterNoisyTop(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 624_184, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_739_568, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_706_744, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_490_992, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_005_120, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 45_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 624_184, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_739_568, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_706_744, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_490_992, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 22_066_496, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 17_717_968, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 14_725_760, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != externalDirectUDPActiveLaneTwoMaxMbps {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(noisy top ktzlxc probe) = %d, want %d", selected, externalDirectUDPActiveLaneTwoMaxMbps)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != 1200 {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(noisy top ktzlxc probe) = %d, want 1200", ceiling)
	}
	basis := externalDirectUDPDataLaneRateBasisMbps(externalDirectUDPDataStartRateMbps(selected), ceiling, externalDirectUDPRateProbeRates(10_000, -1))
	if got, want := externalDirectUDPActiveLanesForRate(basis, 8), 4; got != want {
		t.Fatalf("externalDirectUDPActiveLanesForRate(noisy top ktzlxc probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectCeilingUsesBestObservedKtzlxcReverseRecovery(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 624_184, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_869_784, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_746_488, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_716_432, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_448_088, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_994_496, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 45_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 624_184, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_869_784, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_746_488, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_716_432, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_448_088, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 20_427_840, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 15_759_608, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 18_458_408, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != externalDirectUDPActiveLaneTwoMaxMbps {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(best observed ktzlxc reverse recovery) = %d, want %d", selected, externalDirectUDPActiveLaneTwoMaxMbps)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != 1200 {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(best observed ktzlxc reverse recovery) = %d, want 1200", ceiling)
	}
	basis := externalDirectUDPDataLaneRateBasisMbps(externalDirectUDPDataStartRateMbps(selected), ceiling, externalDirectUDPRateProbeRates(10_000, -1))
	if got, want := externalDirectUDPActiveLanesForRate(basis, 8), 4; got != want {
		t.Fatalf("externalDirectUDPActiveLanesForRate(best observed ktzlxc reverse recovery) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingCapsLossyTopProbeToObservedGoodputForReliableStream(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_000, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_000, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_000, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_000, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_750_000, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_000, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 186_840, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 582_664, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_756_296, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_540_272, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_411_952, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 16_035_024, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 26_208_808, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 34_223_552, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected < 1200 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(lossy top reliable stream) = %d, want at least 1200", selected)
	}
	wantCeiling := int(externalDirectUDPSampleGoodputMbps(34_223_552, 200) + 0.5)
	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received), wantCeiling; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(lossy top reliable stream) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateKeepsNearThresholdKtzlxcReverseGigabitProbe(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 622_800, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_873_936, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_736_800, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_723_352, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_460_544, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_980_032, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 622_800, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_873_936, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_736_800, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_723_352, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_460_544, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 23_529_384, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 20_256_224, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 1200 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(near-threshold ktzlxc reverse gigabit probe) = %d, want 1200", selected)
	}
	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received), 1200; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(near-threshold ktzlxc reverse gigabit probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateKeepsCleanKtzlxcReverseGigabitProbeBeforeModerateTopLoss(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 624_184, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_743_720, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_737_192, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_407_952, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_976_056, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 624_184, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_743_720, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_737_192, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_407_952, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_976_056, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 41_056_360, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 1200 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(clean ktzlxc reverse gigabit probe before moderate top loss) = %d, want 1200", selected)
	}
	wantCeiling := int(externalDirectUDPSampleGoodputMbps(41_056_360, 200) + 0.5)
	if got := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received); got != wantCeiling {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(clean ktzlxc reverse gigabit probe before moderate top loss) = %d, want %d", got, wantCeiling)
	}
}

func TestExternalDirectUDPSelectInitialRateUsesCleanMidHighProbeBeforeLossyTop(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 624_184, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_716_432, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_403_800, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_955_296, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 43_053_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 624_184, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_716_432, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_403_800, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_955_296, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 43_053_000, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 34_215_248, DurationMillis: 200},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 1800 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(clean mid-high before lossy top) = %d, want 1800", selected)
	}
	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received), 1800; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(clean mid-high before lossy top) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingUsesCleanTwoGigabitAfterNoisyEighteenHundred(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_000, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_000, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_000, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_000, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_750_000, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_000, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 112_500_000, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 125_000_000, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 140_625_000, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_000, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_000, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_000, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_000, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_750_000, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_500_000, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 30_000_000, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 80_000_000, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 125_000_000, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 80_000_000, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected < 1200 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(noisy 1800 clean 2000) = %d, want at least 1200", selected)
	}
	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received), 2000; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(noisy 1800 clean 2000) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateKeepsLiveKtzlxcReverseSevenHundredBeforeLossyHighTiers(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_750, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_000, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_000, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_000, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_750_000, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_750, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 112_500_000, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 125_000_000, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 140_625_000, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_750, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 622_750, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_872_500, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_738_250, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_749_750, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_500_750, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 17_510_250, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 37_892_500, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 37_573_125, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 41_841_250, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != externalDirectUDPActiveLaneTwoMaxMbps {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live ktzlxc reverse 700 before lossy high tiers) = %d, want %d", selected, externalDirectUDPActiveLaneTwoMaxMbps)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling != externalDirectUDPActiveLaneTwoMaxMbps {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live ktzlxc reverse 700 before lossy high tiers) = %d, want %d", ceiling, externalDirectUDPActiveLaneTwoMaxMbps)
	}
	start := externalDirectUDPDataStartRateMbpsForCeiling(selected, ceiling)
	if start != externalDirectUDPActiveLaneTwoMaxMbps {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForCeiling(live ktzlxc reverse 700 before lossy high tiers) = %d, want %d", start, externalDirectUDPActiveLaneTwoMaxMbps)
	}
	basis := externalDirectUDPDataLaneRateBasisMbps(start, ceiling, externalDirectUDPRateProbeRates(10_000, -1))
	if got, want := externalDirectUDPActiveLanesForRate(basis, 8), 2; got != want {
		t.Fatalf("externalDirectUDPActiveLanesForRate(live ktzlxc reverse 700 before lossy high tiers) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateKeepsLiveKtzlxcForwardBestCleanHighTierBeforeSenderLimitedTop(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_680, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_968, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 101_007_088, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 69_328_712, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 74_507_640, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_500_680, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 30_000_968, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 101_007_088, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 69_328_712, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 74_507_640, DurationMillis: 500},
	}

	rawSelected := externalDirectUDPSelectRateFromProbeSamples(10_000, sent, received)
	if rawSelected != 1800 {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(live ktzlxc forward sender-limited top) = %d, want 1800", rawSelected)
	}
	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 1800 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live ktzlxc forward sender-limited top) = %d, want 1800", selected)
	}
	if got, want := externalDirectUDPDataStartRateMbpsForCeiling(selected, externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)), 1800; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForCeiling(live ktzlxc forward sender-limited top) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateKeepsLiveKtzlxcForwardCleanSenderLimitedTwoGigabitTier(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_871_168, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_729_880, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 7_224_480, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 12_760_480, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 22_292_088, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 59_174_304, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 73_051_672, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 40_458_472, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_871_168, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_729_880, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 7_224_480, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 12_760_480, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 22_292_088, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 59_174_304, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 73_051_672, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 40_458_472, DurationMillis: 500},
	}

	rawSelected := externalDirectUDPSelectRateFromProbeSamples(externalDirectUDPRateProbeDefaultMaxMbps, sent, received)
	if rawSelected != 2000 {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(live ktzlxc clean sender-limited two-gigabit tier) = %d, want 2000", rawSelected)
	}
	selected := externalDirectUDPSelectInitialRateMbps(externalDirectUDPRateProbeDefaultMaxMbps, sent, received)
	if selected != 2000 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live ktzlxc clean sender-limited two-gigabit tier) = %d, want 2000", selected)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(externalDirectUDPRateProbeDefaultMaxMbps, selected, sent, received)
	if ceiling != 2000 {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live ktzlxc clean sender-limited two-gigabit tier) = %d, want 2000", ceiling)
	}
	if got, want := externalDirectUDPDataExplorationCeilingMbps(externalDirectUDPRateProbeDefaultMaxMbps, selected, ceiling), externalDirectUDPDataExplorationDefaultMaxMbps; got != want {
		t.Fatalf("externalDirectUDPDataExplorationCeilingMbps(live ktzlxc clean sender-limited two-gigabit tier) = %d, want %d", got, want)
	}
	start := externalDirectUDPDataStartRateMbpsForProbeSamples(selected, ceiling, sent, received)
	if start != 2000 {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForProbeSamples(live ktzlxc clean sender-limited two-gigabit tier) = %d, want 2000", start)
	}
}

func ktzlxcHighGoodputCappedTopProbeSentSamples() []directUDPRateProbeSample {
	return []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_000, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_000, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_000, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_000, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_750_000, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_000, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
}

func ktzlxcHighGoodputCappedTopProbeReceivedSamples() []directUDPRateProbeSample {
	return []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 608_960, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_793_664, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_587_328, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_349_824, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_982_976, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 45_238_808, DurationMillis: 200},
	}
}

func TestExternalDirectUDPRateProbeRatesScaleUpToMax(t *testing.T) {
	got := externalDirectUDPRateProbeRates(10_000, 1<<30)
	want := []int{8, 25, 75, 150, 350, 700, 1200, 1800, 2000, 2250}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPRateProbeRates() = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPRateProbeRatesCoverSlowAndTenGigabitUnknownStreams(t *testing.T) {
	got := externalDirectUDPRateProbeRates(10_000, -1)
	want := []int{8, 25, 75, 150, 350, 700, 1200, 1800, 2000, 2250}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPRateProbeRates(unknown) = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPRateProbeDurationsConfirmHighTiers(t *testing.T) {
	if got, want := externalDirectUDPRateProbeDurationForRate(1200), externalDirectUDPRateProbeDuration; got != want {
		t.Fatalf("externalDirectUDPRateProbeDurationForRate(1200) = %v, want %v", got, want)
	}
	if got := externalDirectUDPRateProbeDurationForRate(1800); got <= externalDirectUDPRateProbeDuration {
		t.Fatalf("externalDirectUDPRateProbeDurationForRate(1800) = %v, want longer than %v", got, externalDirectUDPRateProbeDuration)
	}
	if got := externalDirectUDPRateProbeDurationForRate(2000); got != externalDirectUDPRateProbeDurationForRate(2250) {
		t.Fatalf("externalDirectUDPRateProbeDurationForRate(2000) = %v, want same confirmation as 2250 %v", got, externalDirectUDPRateProbeDurationForRate(2250))
	}
}

func TestExternalDirectUDPRateProbeRatesIncludeNonTierMaxBelowProbeCap(t *testing.T) {
	got := externalDirectUDPRateProbeRates(1000, -1)
	want := []int{8, 25, 75, 150, 350, 700, 1000}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPRateProbeRates(1000) = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPRateProbeRatesSkipSmallTransfers(t *testing.T) {
	if got := externalDirectUDPRateProbeRates(10_000, 64<<20); len(got) != 0 {
		t.Fatalf("externalDirectUDPRateProbeRates(small) = %v, want none", got)
	}
}

func TestExternalDirectUDPRateProbePayloadEncodesIndex(t *testing.T) {
	payload, err := externalDirectUDPRateProbePayload(3, 128)
	if err != nil {
		t.Fatalf("externalDirectUDPRateProbePayload() error = %v", err)
	}
	if len(payload) != 128 {
		t.Fatalf("payload len = %d, want 128", len(payload))
	}
	index, ok := externalDirectUDPRateProbeIndex(payload, 10)
	if !ok {
		t.Fatal("externalDirectUDPRateProbeIndex() did not recognize payload")
	}
	if index != 3 {
		t.Fatalf("probe index = %d, want 3", index)
	}
}

func TestExternalDirectUDPRateProbeDoesNotStopAfterSenderOnlyPlateau(t *testing.T) {
	prev := directUDPRateProbeSample{RateMbps: 700, BytesSent: 17_351_208, DurationMillis: 200}
	current := directUDPRateProbeSample{RateMbps: 1200, BytesSent: 17_700_000, DurationMillis: 200}

	if externalDirectUDPRateProbeShouldStopAfterSent(prev, current) {
		t.Fatal("externalDirectUDPRateProbeShouldStopAfterSent() = true, want false because sender-only plateau does not prove receiver loss")
	}
}

func TestExternalDirectUDPRateProbeShouldContinueWhenSentThroughputScales(t *testing.T) {
	prev := directUDPRateProbeSample{RateMbps: 700, BytesSent: 17_500_000, DurationMillis: 200}
	current := directUDPRateProbeSample{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200}

	if externalDirectUDPRateProbeShouldStopAfterSent(prev, current) {
		t.Fatal("externalDirectUDPRateProbeShouldStopAfterSent() = true, want false while probe send throughput scales")
	}
}

func TestExternalDirectUDPRateProbeActiveLanesUsesExtraBurstLanesAtTopTiers(t *testing.T) {
	tests := []struct {
		rate     int
		maxLanes int
		want     int
	}{
		{rate: 8, maxLanes: 8, want: 1},
		{rate: 350, maxLanes: 8, want: 1},
		{rate: 700, maxLanes: 8, want: 2},
		{rate: 1200, maxLanes: 8, want: 4},
		{rate: 1800, maxLanes: 8, want: 8},
		{rate: 2250, maxLanes: 8, want: 8},
		{rate: 5000, maxLanes: 8, want: 8},
		{rate: 2250, maxLanes: 2, want: 2},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%dMbps_%dlanes", tt.rate, tt.maxLanes), func(t *testing.T) {
			if got := externalDirectUDPRateProbeActiveLanes(tt.rate, tt.maxLanes); got != tt.want {
				t.Fatalf("externalDirectUDPRateProbeActiveLanes(%d, %d) = %d, want %d", tt.rate, tt.maxLanes, got, tt.want)
			}
		})
	}
}

func TestExternalDirectUDPSendRateProbesWritesSyntheticPackets(t *testing.T) {
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

	rates := []int{8, 25}
	readCh := make(chan int, 16)
	go func() {
		defer close(readCh)
		buf := make([]byte, 2048)
		deadline := time.Now().Add(1200 * time.Millisecond)
		_ = server.SetReadDeadline(deadline)
		for {
			n, _, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			index, ok := externalDirectUDPRateProbeIndex(buf[:n], len(rates))
			if ok {
				readCh <- index
			}
		}
	}()

	sent, err := externalDirectUDPSendRateProbes(ctx, client, server.LocalAddr().String(), rates)
	if err != nil {
		t.Fatalf("externalDirectUDPSendRateProbes() error = %v", err)
	}
	if len(sent) != len(rates) {
		t.Fatalf("sent samples len = %d, want %d", len(sent), len(rates))
	}
	for i, sample := range sent {
		if sample.RateMbps != rates[i] {
			t.Fatalf("sent[%d].RateMbps = %d, want %d", i, sample.RateMbps, rates[i])
		}
		if sample.BytesSent <= 0 {
			t.Fatalf("sent[%d].BytesSent = %d, want > 0", i, sample.BytesSent)
		}
	}
	seen := map[int]bool{}
	for index := range readCh {
		seen[index] = true
		if len(seen) == len(rates) {
			break
		}
	}
	for i := range rates {
		if !seen[i] {
			t.Fatalf("probe index %d was not observed; seen=%v", i, seen)
		}
	}
}

func TestExternalDirectUDPSendRateProbesParallelUsesActiveLaneSubset(t *testing.T) {
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

	readOne := func(conn net.PacketConn, ch chan<- bool) {
		defer close(ch)
		buf := make([]byte, 2048)
		_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, ok := externalDirectUDPRateProbeIndex(buf[:n], 1); ok {
				ch <- true
				return
			}
		}
	}

	seenA := make(chan bool, 1)
	seenB := make(chan bool, 1)
	go readOne(serverA, seenA)
	go readOne(serverB, seenB)

	sent, err := externalDirectUDPSendRateProbesParallel(ctx, []net.PacketConn{clientA, clientB}, []string{serverA.LocalAddr().String(), serverB.LocalAddr().String()}, []int{8})
	if err != nil {
		t.Fatalf("externalDirectUDPSendRateProbesParallel() error = %v", err)
	}
	if len(sent) != 1 || sent[0].BytesSent <= 0 {
		t.Fatalf("sent samples = %#v, want one sample with bytes", sent)
	}
	if !<-seenA {
		t.Fatal("lane A did not receive a rate probe packet")
	}
	if <-seenB {
		t.Fatal("lane B received a low-rate probe packet, want low probe to use one active lane")
	}
}

func TestIsDirectUDPRateProbePayloadAcceptsRateProbeEnvelope(t *testing.T) {
	payload, err := json.Marshal(envelope{
		Type: envelopeDirectUDPRateProbe,
		DirectUDPRateProbe: &directUDPRateProbeResult{
			Samples: []directUDPRateProbeSample{{RateMbps: 150, BytesReceived: 1, DurationMillis: 200}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !isDirectUDPRateProbePayload(payload) {
		t.Fatal("isDirectUDPRateProbePayload() = false, want true")
	}
}

func TestWaitForDirectUDPRateProbeReturnsSamples(t *testing.T) {
	payload, err := json.Marshal(envelope{
		Type: envelopeDirectUDPRateProbe,
		DirectUDPRateProbe: &directUDPRateProbeResult{
			Samples: []directUDPRateProbeSample{{RateMbps: 350, BytesReceived: 8_000_000, DurationMillis: 200}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan derpbind.Packet, 1)
	ch <- derpbind.Packet{Payload: payload}

	got, err := waitForDirectUDPRateProbe(context.Background(), ch)
	if err != nil {
		t.Fatalf("waitForDirectUDPRateProbe() error = %v", err)
	}
	if len(got.Samples) != 1 || got.Samples[0].RateMbps != 350 {
		t.Fatalf("waitForDirectUDPRateProbe() = %#v, want 350 Mbps sample", got)
	}
}

func TestExternalDirectUDPSelectInitialRateUsesProbeSamples(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_000, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_000, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_000, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_000, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_750_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_000, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_000, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_000, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_700_000, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 1_000_000, DurationMillis: 200},
	}
	got := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if got <= 0 || got > 150 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps() = %d, want safe rate <= 150", got)
	}
}

func TestExternalDirectUDPSelectInitialRateAddsHeadroomAtLowBandwidthKnee(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 624_184, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_865_632, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_000, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_750_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 199_296, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 624_184, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_865_632, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 2_405_392, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 1_831_032, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectInitialRateMbps(10_000, sent, received), 56; got != want {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(low-bandwidth knee) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateAddsHeadroomAtCollapsedProbeKnee(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_749_256, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_749_648, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_000, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_749_256, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_749_648, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 11_492_736, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 5_315_944, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectInitialRateMbps(10_000, sent, received), 263; got != want {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(collapsed knee) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateAddsHeadroomAtLossyProbeKnee(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_746_880, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_495_000, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_746_880, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 15_113_280, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 9_117_792, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectInitialRateMbps(10_000, sent, received), 263; got != want {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(lossy knee) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateAddsHeadroomAtCleanInefficientProbeKnee(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_680, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 21_839_520, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 22_575_808, DurationMillis: 200},
		{RateMbps: 5000, BytesSent: 21_007_736, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_500_680, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 21_839_520, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 22_575_808, DurationMillis: 200},
		{RateMbps: 5000, BytesReceived: 21_007_736, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectInitialRateMbps(10_000, sent, received), 350; got != want {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(clean inefficient knee) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateKeepsSenderLimitedCleanHighProbe(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_724_736, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_468_848, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_948_376, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 83_797_048, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 61_708_408, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 55_703_232, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_724_736, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_468_848, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_948_376, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 83_797_048, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 61_708_408, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 55_703_232, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected < 1200 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(sender-limited clean high probe) = %d, want at least 1200", selected)
	}
	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received), selected; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(sender-limited clean high probe) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataExplorationCeilingMbps(10_000, selected, selected), externalDirectUDPDataExplorationDefaultMaxMbps; got != want {
		t.Fatalf("externalDirectUDPDataExplorationCeilingMbps(sender-limited clean high probe) = %d, want guarded exploration ceiling %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateUsesCleanTwoGigabitRecoveryAfterSenderLimitedDip(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_611_248, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 14_037_912, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 24_523_096, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 51_075_136, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 70_979_824, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 43_072_848, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_611_248, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 14_037_912, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 24_523_096, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 51_075_136, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 70_979_824, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 43_072_848, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected != 2000 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(clean 2000 recovery) = %d, want 2000", selected)
	}
	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received), selected; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(clean 2000 recovery) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPDataExplorationCeilingMbps(10_000, selected, selected), externalDirectUDPDataExplorationDefaultMaxMbps; got != want {
		t.Fatalf("externalDirectUDPDataExplorationCeilingMbps(clean 2000 recovery) = %d, want guarded exploration ceiling %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateKeepsStrongCleanGainBeforeInefficientKnee(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_749_648, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 14_412_976, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 13_477_392, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_749_648, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 14_412_976, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 13_477_392, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectInitialRateMbps(10_000, sent, received), 350; got != want {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(strong clean gain) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateUsesHeadroomForNearCleanEfficientProbe(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_709_512, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_000, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_709_512, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 16_749_168, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 11_967_448, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectInitialRateMbps(10_000, sent, received), 350; got != want {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(near-clean efficient probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateUsesHeadroomForMildLossEfficientProbe(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_726_120, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_000, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_726_120, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 15_874_480, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 11_477_512, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectInitialRateMbps(10_000, sent, received), 350; got != want {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(mild-loss efficient probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateUsesAggregateTopProbeGoodput(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_345_672, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_847_344, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 41_658_400, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_345_672, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_847_344, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 41_658_400, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectInitialRateMbps(10_000, sent, received), 1916; got != want {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(aggregate top probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateBacksOffBufferedAggregateCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_401_032, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_002_352, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 47_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_401_032, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 30_002_352, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 26_772_096, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectInitialRateMbps(10_000, sent, received), 350; got != want {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(buffered aggregate collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingStopsAtCleanTierBeforeCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_732_648, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_748_264, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 16_440_536, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_732_648, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_748_264, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 16_440_536, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 8_829_920, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 350, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps() = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingAllowsCleanButInefficientFirstProbeTier(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 13_736_200, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 13_730_664, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 13_736_200, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 13_730_664, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 350, sent, received), 1200; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(clean inefficient first probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingAllowsCleanSenderLimitedProbeTier(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 13_808_168, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 14_365_920, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 13_808_168, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 14_365_920, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 350, sent, received), 1200; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(clean sender-limited probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingAllowsNearCleanKneeBeforeCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_748_264, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_000, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_951_848, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_467_976, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_748_264, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 16_393_480, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 10_371_696, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 9_062_432, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 350, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(near-clean knee before collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingAllowsMeaningfulLossyHigherProbe(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_746_880, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_495_000, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_746_880, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 15_113_280, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 9_117_792, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 350, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(meaningful lossy higher probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingRejectsLowDeliveryHigherProbe(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_749_256, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_749_648, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_000, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_749_256, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_749_648, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 10_242_984, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 7_146_976, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 8_997_384, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 263, sent, received), 350; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(low-delivery higher probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingAllowsNearCleanEfficientProbeBeforeCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_709_512, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_000, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_709_512, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 16_749_168, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 11_967_448, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 350, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(near-clean efficient probe before collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingAllowsMildLossEfficientProbeBeforeCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_726_120, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_000, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_726_120, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 15_874_480, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 11_477_512, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 350, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(mild-loss efficient probe before collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingRejectsInefficientHigherProbe(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_749_648, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 15_802_512, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_749_648, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 15_802_512, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 7_500_000, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 700, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(inefficient higher probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingAllowsOneHigherTierAboveCleanKnee(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_683_216, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_000, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_683_216, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 16_515_272, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 11_901_016, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 2_000_000, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 350, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(one higher tier above clean knee) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingAllowsModestCleanHigherProbeImprovement(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 700, BytesSent: 17_374_750, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 18_118_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 18_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 700, BytesReceived: 17_374_750, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 18_118_000, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 18_000_000, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 700, sent, received), 2250; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(modest clean higher probe improvement) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingCapsLowSelectedSenderLimitedHigherProbePlateau(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_749_648, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 14_054_520, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 13_744_504, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 1_384, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_749_648, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 14_054_520, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 13_744_504, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 0, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 350, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(low-selected sender-limited higher probe plateau) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingAllowsCleanSenderLimitedTopProbePlateau(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_749_648, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_680, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 16_826_672, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 16_852_968, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_749_648, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_500_680, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 16_826_672, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 16_852_968, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 350, sent, received), 2250; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(clean sender-limited top probe plateau) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingCapsFalseCleanCanlxcProbeAtKnee(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_401_032, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_912_392, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 40_198_448, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_401_032, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_912_392, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 32_962_728, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 600, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(false-clean canlxc probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingCapsCleanSenderLimitedCanlxcProbeAtKnee(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_295_848, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 24_049_768, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 23_516_928, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_295_848, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 24_049_768, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 23_516_928, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 600, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(clean sender-limited canlxc probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingCapsLiveCanlxcSenderLimitedHighProbe(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_699_824, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 14_221_984, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_959_448, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 78_947_512, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 69_577_996, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 62_499_133, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 197_912, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_699_824, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 14_221_984, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_959_448, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 78_947_512, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 64_707_536, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 29_999_584, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if got, want := selected, 1200; got != want {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live canlxc high probe) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received), 1200; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live canlxc high probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateCapsLiveCanlxcCleanSenderLimitedPlateau(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_873_936, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_723_352, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_420_408, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_511_032, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 64_293_720, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 76_146_296, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 55_156_552, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_873_936, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_723_352, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_420_408, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_511_032, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 64_293_720, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 76_146_296, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 55_156_552, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if got, want := selected, 1200; got != want {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live canlxc sender-limited plateau) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received), 1200; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live canlxc sender-limited plateau) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateKeepsLiveKtzlxcRecoveryAfterLossy700Tier(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 16_483_897, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 24_791_511, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 82_898_624, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 72_427_370, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 56_776_050, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 12_857_360, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 21_072_784, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 77_095_720, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 68_081_728, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 53_937_248, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if selected < externalDirectUDPDataStartHighMbps {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live ktzlxc recovery after lossy 700 tier) = %d, want at least %d after higher tiers recover above 1 Gbps", selected, externalDirectUDPDataStartHighMbps)
	}
	ceiling := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received)
	if ceiling < externalDirectUDPRateProbeConfirmMinMbps {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live ktzlxc recovery after lossy 700 tier) = %d, want at least %d", ceiling, externalDirectUDPRateProbeConfirmMinMbps)
	}
	basis := externalDirectUDPDataLaneRateBasisMbps(externalDirectUDPDataStartRateMbps(selected), ceiling, externalDirectUDPRateProbeRates(10_000, -1))
	if got, want := externalDirectUDPActiveLanesForRate(basis, externalDirectUDPParallelism), 4; got != want {
		t.Fatalf("externalDirectUDPActiveLanesForRate(live ktzlxc recovery after lossy 700 tier) = %d, want %d active lanes", got, want)
	}
}

func TestExternalDirectUDPSelectInitialRateKeepsLiveKtzlxcClean1200NearClean1800BeforeTopCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_477_152, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_839_040, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 103_603_806, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 72_294_443, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 62_602_443, DurationMillis: 500},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_750_640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_751_032, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_477_152, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_839_040, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 94_279_464, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 66_510_888, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 58_846_296, DurationMillis: 500},
	}

	selected := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if got, want := selected, 1800; got != want {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps(live ktzlxc clean 1200 near-clean 1800 before top collapse) = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, selected, sent, received), selected; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(live ktzlxc clean 1200 near-clean 1800 before top collapse) = %d, want %d", got, want)
	}
	start := externalDirectUDPDataStartRateMbpsForProbeSamples(selected, selected, sent, received)
	if got, want := start, selected; got != want {
		t.Fatalf("externalDirectUDPDataStartRateMbpsForProbeSamples(live ktzlxc clean 1200 near-clean 1800 before top collapse) = %d, want %d", got, want)
	}
	basis := externalDirectUDPDataLaneRateBasisMbps(start, selected, externalDirectUDPRateProbeRates(10_000, -1))
	if got, want := externalDirectUDPActiveLanesForRate(basis, externalDirectUDPParallelism), externalDirectUDPParallelism; got != want {
		t.Fatalf("externalDirectUDPActiveLanesForRate(live ktzlxc clean 1200 near-clean 1800 before top collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingCapsLowSelectedCanlxcProbeAtOneSafeTier(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_402_416, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_987_128, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 41_724_400, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_402_416, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_987_128, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 27_116_712, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 350, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(low-selected canlxc probe) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingKeepsLowKneeBelowLossyTier(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 75, BytesSent: 1_865_632, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 75, BytesReceived: 1_865_632, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 2_405_392, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 56, sent, received), 75; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(low knee) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingKeepsMaxWhenTopProbeIsClean(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
		{RateMbps: 5000, BytesSent: 125_000_000, DurationMillis: 200},
		{RateMbps: 10000, BytesSent: 250_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 2250, BytesReceived: 56_250_000, DurationMillis: 200},
		{RateMbps: 5000, BytesReceived: 125_000_000, DurationMillis: 200},
		{RateMbps: 10000, BytesReceived: 250_000_000, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 2250, sent, received), 10_000; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(clean top) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateCeilingCapsAtHighestProbedRateWhenCappedTopProbeIsEfficient(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 8_750_000, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_500_000, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_250_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_750_000, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_500_000, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 30_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 56_250_000, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateCeilingMbps(10_000, 2250, sent, received), 2250; got != want {
		t.Fatalf("externalDirectUDPSelectRateCeilingMbps(clean capped top) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPStreamStartRequestsProbeRatesForUnknownStreams(t *testing.T) {
	got := externalDirectUDPStreamStart(externalDirectUDPMaxRateMbps, -1)
	wantRates := []int{8, 25, 75, 150, 350, 700, 1200, 1800, 2000, 2250}
	if !got.Stream {
		t.Fatal("externalDirectUDPStreamStart().Stream = false, want true")
	}
	if fmt.Sprint(got.ProbeRates) != fmt.Sprint(wantRates) {
		t.Fatalf("externalDirectUDPStreamStart().ProbeRates = %v, want %v", got.ProbeRates, wantRates)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesUsesDeliveredGoodput(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 9_000_000, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 18_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_500_000, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 9_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 4_000_000, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 350; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples() = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffAtRateCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_606_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_601_600, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_403_400, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_600, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 52_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_606_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_601_600, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_403_400, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 30_000_600, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 10_021_200, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffOneTierAtMidProbeLoss(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_606_704, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_348_440, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_803_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 47_925_152, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_606_704, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_348_440, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 22_650_544, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 11_981_288, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(mid-probe loss) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffOneTierAtMidProbeCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_587_328, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_569_728, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_401_032, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_949_760, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 57_384_100, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_587_328, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_569_728, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_401_032, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 14_974_880, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 9_181_456, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(mid-probe collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffTwoTiersAtTopProbeCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_591_872, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_394_112, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_854_264, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 55_990_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_591_872, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_394_112, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_854_264, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 34_154_352, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(top-probe collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffAtLossyHighThroughputKnee(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_595_200, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_590_500, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_337_500, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_971_250, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_230_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_595_200, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_590_500, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_337_500, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_971_250, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 44_984_750, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(lossy high-throughput knee) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesUsesCleanTopProbeObservedCeiling(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_395_496, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_968, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 40_189_976, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_395_496, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 30_000_968, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 40_189_976, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 1849; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(clean top probe observed ceiling) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffAtLossyTopProbeEvenWhenGoodputIsHigh(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_558_656, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_348_440, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_815_512, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 55_808_070, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_558_656, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_348_440, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_815_512, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 44_646_456, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(lossy top probe high goodput) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesUsesObservedCeilingWhenTopProbeStillGains(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_597_000, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_603_000, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_384_500, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_988_500, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 42_790_500, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_597_000, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_603_000, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_384_500, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_988_500, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 42_790_500, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 1968; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(observed ceiling) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffMarginalHighRateGain(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_606_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_601_600, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_403_400, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_600, DurationMillis: 200},
		{RateMbps: 1967, BytesSent: 43_723_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_606_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_601_600, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_403_400, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_971_250, DurationMillis: 200},
		{RateMbps: 1967, BytesReceived: 38_450_000, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(1967, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(marginal high-rate gain) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffBelowCeilingBurst(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_606_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_601_600, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_403_400, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_600, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 45_995_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_606_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_601_600, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_403_400, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 30_000_600, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 43_695_400, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(below-ceiling burst) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPFlattenCandidateSetsRoundRobinsAlternatesAcrossLanes(t *testing.T) {
	sets := make([][]string, 8)
	for i := range sets {
		port := 60000 + i
		sets[i] = []string{
			fmt.Sprintf("10.0.1.254:%d", port),
			fmt.Sprintf("127.0.0.1:%d", port),
			fmt.Sprintf("10.0.4.184:%d", port),
			fmt.Sprintf("[fd37:89f2:37b4:4af8::%x]:%d", i+1, port),
			fmt.Sprintf("[fd37:89f2:37b4:4af9::%x]:%d", i+1, port),
			fmt.Sprintf("[::1]:%d", port),
		}
	}

	got := externalDirectUDPFlattenCandidateSets(sets)
	for _, want := range []string{"127.0.0.1:60006", "127.0.0.1:60007"} {
		if !slices.Contains(got, want) {
			t.Fatalf("externalDirectUDPFlattenCandidateSets() missing %q in %v", want, got)
		}
	}
}

func TestExternalDirectUDPOrderConnsForSectionsUsesSelectedEndpoints(t *testing.T) {
	connA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	connB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer connB.Close()
	connC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer connC.Close()

	conns := []net.PacketConn{connA, connB, connC}
	ordered, err := externalDirectUDPOrderConnsForSections(conns, []string{
		"108.18.210.19:38183",
		"108.18.210.19:34375",
		"108.18.210.19:44442",
		"10.0.1.254:38183",
		"10.0.1.254:34375",
		"10.0.1.254:44442",
	}, []string{
		"68.20.14.192:44442",
		"68.20.14.192:38183",
	})
	if err != nil {
		t.Fatalf("externalDirectUDPOrderConnsForSections() error = %v", err)
	}
	if len(ordered) != 2 {
		t.Fatalf("ordered conns length = %d, want 2", len(ordered))
	}
	if ordered[0] != connC || ordered[1] != connA {
		t.Fatalf("ordered conns = [%v %v], want [%v %v]", ordered[0].LocalAddr(), ordered[1].LocalAddr(), connC.LocalAddr(), connA.LocalAddr())
	}
}

func TestExternalDirectUDPDiscardLaneRunIDLeavesZeroForProbeGeneratedRuns(t *testing.T) {
	if got := externalDirectUDPDiscardLaneRunID([16]byte{}, 2); got != ([16]byte{}) {
		t.Fatalf("externalDirectUDPDiscardLaneRunID(zero) = %x, want zero", got)
	}
}

func TestExternalDirectUDPDiscardLaneRunIDDerivesNonZeroBase(t *testing.T) {
	var runID [16]byte
	runID[15] = 0x10

	got := externalDirectUDPDiscardLaneRunID(runID, 2)
	want := externalDirectUDPLaneRunID(runID, 2)
	if got != want {
		t.Fatalf("externalDirectUDPDiscardLaneRunID(non-zero) = %x, want %x", got, want)
	}
}

func TestExternalDirectUDPDiscardParallelSendsIndependentLanes(t *testing.T) {
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

	runID := [16]byte{0x42}
	src := bytes.Repeat([]byte("x"), 4<<20)
	receiveCh := make(chan probe.TransferStats, 1)
	errCh := make(chan error, 2)
	go func() {
		stats, err := probe.ReceiveBlastParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, probe.ReceiveConfig{
			Blast:          true,
			Transport:      externalDirectUDPTransportLabel,
			ExpectedRunIDs: externalDirectUDPLaneRunIDs(runID, 2),
		}, 0)
		if err != nil {
			errCh <- err
			return
		}
		receiveCh <- stats
	}()

	sendStats, err := externalDirectUDPSendDiscardParallel(ctx, []net.PacketConn{clientA, clientB}, []string{serverA.LocalAddr().String(), serverB.LocalAddr().String()}, bytes.NewReader(src), probe.SendConfig{
		Blast:          true,
		Transport:      externalDirectUDPTransportLabel,
		ChunkSize:      externalDirectUDPChunkSize,
		RateMbps:       0,
		RunID:          runID,
		RepairPayloads: true,
	})
	if err != nil {
		t.Fatalf("externalDirectUDPSendDiscardParallel() error = %v", err)
	}
	if sendStats.BytesSent != int64(len(src)) {
		t.Fatalf("send BytesSent = %d, want %d", sendStats.BytesSent, len(src))
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case receiveStats := <-receiveCh:
		if receiveStats.BytesReceived != int64(len(src)) {
			t.Fatalf("receive BytesReceived = %d, want %d", receiveStats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}

func TestExternalDirectUDPDiscardSpoolParallelSendsIndependentLanes(t *testing.T) {
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

	runID := [16]byte{0x43}
	src := bytes.Repeat([]byte("y"), 4<<20)
	spool, err := externalDirectUDPSpoolDiscardLanes(ctx, bytes.NewReader(src), 2, externalDirectUDPChunkSize)
	if err != nil {
		t.Fatalf("externalDirectUDPSpoolDiscardLanes() error = %v", err)
	}
	defer spool.Close()

	receiveCh := make(chan probe.TransferStats, 1)
	errCh := make(chan error, 2)
	go func() {
		stats, err := probe.ReceiveBlastParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, probe.ReceiveConfig{
			Blast:          true,
			Transport:      externalDirectUDPTransportLabel,
			ExpectedRunIDs: externalDirectUDPLaneRunIDs(runID, 2),
		}, int64(len(src)))
		if err != nil {
			errCh <- err
			return
		}
		receiveCh <- stats
	}()

	sendStats, err := externalDirectUDPSendDiscardSpoolParallel(ctx, []net.PacketConn{clientA, clientB}, []string{serverA.LocalAddr().String(), serverB.LocalAddr().String()}, spool, probe.SendConfig{
		Blast:          true,
		Transport:      externalDirectUDPTransportLabel,
		ChunkSize:      externalDirectUDPChunkSize,
		RateMbps:       0,
		RunID:          runID,
		RepairPayloads: true,
	})
	if err != nil {
		t.Fatalf("externalDirectUDPSendDiscardSpoolParallel() error = %v", err)
	}
	if sendStats.BytesSent != int64(len(src)) {
		t.Fatalf("send BytesSent = %d, want %d", sendStats.BytesSent, len(src))
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case receiveStats := <-receiveCh:
		if receiveStats.BytesReceived != int64(len(src)) {
			t.Fatalf("receive BytesReceived = %d, want %d", receiveStats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}

func TestExternalDirectUDPCandidateSetsGatherPerConnAndInferWANPerPort(t *testing.T) {
	connA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	connB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer connB.Close()

	portA := connA.LocalAddr().(*net.UDPAddr).Port
	portB := connB.LocalAddr().(*net.UDPAddr).Port
	prev := externalDirectUDPProbeCandidates
	externalDirectUDPProbeCandidates = func(_ context.Context, conn net.PacketConn, _ *tailcfg.DERPMap, _ publicPortmap) []string {
		port := conn.LocalAddr().(*net.UDPAddr).Port
		if port == portA {
			return []string{
				fmt.Sprintf("68.20.14.192:%d", portA),
				fmt.Sprintf("10.0.4.184:%d", portA),
			}
		}
		return []string{fmt.Sprintf("10.0.4.184:%d", port)}
	}
	t.Cleanup(func() { externalDirectUDPProbeCandidates = prev })

	sets := externalDirectUDPCandidateSets(context.Background(), []net.PacketConn{connA, connB}, nil, nil)
	flat := externalDirectUDPFlattenCandidateSets(sets)
	for _, want := range []string{
		fmt.Sprintf("68.20.14.192:%d", portA),
		fmt.Sprintf("68.20.14.192:%d", portB),
	} {
		if !slices.Contains(flat, want) {
			t.Fatalf("externalDirectUDPCandidateSets() flattened = %v, want %q", flat, want)
		}
	}
}

func TestExternalDirectUDPSectionSpoolRoundTripsAcrossLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const lanes = 8
	serverConns := make([]net.PacketConn, 0, lanes)
	clientConns := make([]net.PacketConn, 0, lanes)
	defer func() {
		for _, conn := range serverConns {
			_ = conn.Close()
		}
		for _, conn := range clientConns {
			_ = conn.Close()
		}
	}()
	for i := 0; i < lanes; i++ {
		server, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		serverConns = append(serverConns, server)
		client, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		clientConns = append(clientConns, client)
	}

	src := bytes.Repeat([]byte("sectioned-loopback-"), 1<<13)
	spool, err := externalDirectUDPSpoolDiscardLanes(ctx, bytes.NewReader(src), lanes, externalDirectUDPChunkSize)
	if err != nil {
		t.Fatalf("externalDirectUDPSpoolDiscardLanes() error = %v", err)
	}
	defer spool.Close()

	var got bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		_, err := externalDirectUDPReceiveSectionSpoolParallel(ctx, serverConns, &got, probe.ReceiveConfig{
			Blast:           true,
			Transport:       externalDirectUDPTransportLabel,
			RequireComplete: true,
			FECGroupSize:    externalDirectUDPFECGroupSize,
			ExpectedRunID:   [16]byte{},
			ExpectedRunIDs:  nil,
		}, int64(len(src)), spool.Sizes)
		errCh <- err
	}()

	remoteAddrs := make([]string, 0, lanes)
	for _, conn := range serverConns {
		remoteAddrs = append(remoteAddrs, conn.LocalAddr().String())
	}
	sendStats, err := externalDirectUDPSendDiscardSpoolParallel(ctx, clientConns, remoteAddrs, spool, probe.SendConfig{
		Blast:                    true,
		Transport:                externalDirectUDPTransportLabel,
		ChunkSize:                externalDirectUDPChunkSize,
		RateMbps:                 0,
		RepairPayloads:           true,
		TailReplayBytes:          externalDirectUDPTailReplayBytes,
		FECGroupSize:             externalDirectUDPFECGroupSize,
		ParallelHandshakeTimeout: externalDirectUDPHandshakeWait,
	})
	if err != nil {
		t.Fatalf("externalDirectUDPSendDiscardSpoolParallel() error = %v", err)
	}
	if sendStats.BytesSent != int64(len(src)) {
		t.Fatalf("send BytesSent = %d, want %d", sendStats.BytesSent, len(src))
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("externalDirectUDPReceiveSectionSpoolParallel() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for sectioned receive: %v", ctx.Err())
	}
	if !bytes.Equal(got.Bytes(), src) {
		t.Fatalf("received bytes length=%d want=%d equal=%t", got.Len(), len(src), bytes.Equal(got.Bytes(), src))
	}
}

func TestExternalDirectUDPReceiveSectionSpoolParallelReturnsPartialStatsOnReceiveError(t *testing.T) {
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
	type receiveResult struct {
		stats probe.TransferStats
		err   error
	}
	resultCh := make(chan receiveResult, 1)
	payload := []byte("section-partial-before-cancel")
	pending := []byte("held-pending-gap")
	totalBytes := len(payload) + 1 + len(pending)
	go func() {
		stats, err := externalDirectUDPReceiveSectionSpoolParallel(ctx, []net.PacketConn{server}, io.Discard, probe.ReceiveConfig{
			Blast:     true,
			Transport: externalDirectUDPTransportLabel,
		}, int64(totalBytes), nil)
		resultCh <- receiveResult{stats: stats, err: err}
	}()

	runID := [16]byte{0x53}
	writeExternalDirectUDPProbePacket(t, client, server.LocalAddr(), probe.Packet{Version: probe.ProtocolVersion, Type: probe.PacketTypeHello, RunID: runID})
	for {
		packet := readExternalDirectUDPProbePacket(t, client, 500*time.Millisecond)
		if packet.Type == probe.PacketTypeHelloAck {
			break
		}
	}
	writeExternalDirectUDPProbePacket(t, client, server.LocalAddr(), probe.Packet{Version: probe.ProtocolVersion, Type: probe.PacketTypeData, RunID: runID, Seq: 0, Offset: 0, Payload: payload})
	writeExternalDirectUDPProbePacket(t, client, server.LocalAddr(), probe.Packet{Version: probe.ProtocolVersion, Type: probe.PacketTypeData, RunID: runID, Seq: 2, Offset: uint64(len(payload) + 1), Payload: pending})
	writeExternalDirectUDPProbePacket(t, client, server.LocalAddr(), probe.Packet{Version: probe.ProtocolVersion, Type: probe.PacketTypeDone, RunID: runID, Seq: 3, Offset: uint64(totalBytes)})
	for {
		packet := readExternalDirectUDPProbePacket(t, client, time.Second)
		if packet.Type == probe.PacketTypeRepairRequest {
			break
		}
	}

	cancel()
	select {
	case result := <-resultCh:
		if result.err == nil {
			t.Fatal("externalDirectUDPReceiveSectionSpoolParallel() error = nil, want incomplete blast error")
		}
		if !strings.Contains(result.err.Error(), "blast incomplete") {
			t.Fatalf("externalDirectUDPReceiveSectionSpoolParallel() error = %v, want blast incomplete", result.err)
		}
		if result.stats.BytesReceived != int64(len(payload)) {
			t.Fatalf("BytesReceived = %d, want %d", result.stats.BytesReceived, len(payload))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for canceled section receive")
	}
}

func TestExternalDirectUDPDistributeDiscardStreamDoesNotBlockOtherLanesBehindSlowLane(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	readerA, writerA := io.Pipe()
	defer readerA.Close()
	defer writerA.Close()
	readerB, writerB := io.Pipe()
	defer readerB.Close()
	defer writerB.Close()

	errCh := make(chan error, 1)
	go func() {
		src := bytes.NewReader(bytes.Repeat([]byte("x"), 256))
		errCh <- externalDirectUDPDistributeDiscardStream(ctx, src, []*io.PipeWriter{writerA, writerB}, 1)
	}()

	readB := make(chan int, 1)
	go func() {
		buf := make([]byte, 128)
		n, _ := io.ReadFull(readerB, buf)
		readB <- n
	}()

	select {
	case got := <-readB:
		if got != 128 {
			t.Fatalf("lane B read = %d, want 128", got)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("lane B did not receive data while lane A was blocked")
	}

	drainA := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, readerA)
		close(drainA)
	}()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("externalDirectUDPDistributeDiscardStream() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for distributor: %v", ctx.Err())
	}
	_ = writerA.Close()
	<-drainA
}
