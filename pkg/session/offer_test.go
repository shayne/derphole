// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/probe"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transfertrace"
	"github.com/shayne/derphole/pkg/transport"
	"tailscale.com/types/key"
)

func TestPublicRelayOnlyOfferedStdioRoundTrip(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:     tokenSink,
			StdioIn:       strings.NewReader("public offered payload"),
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		offerErr <- err
	}()

	token := <-tokenSink
	var receiverOut bytes.Buffer
	if err := Receive(ctx, ReceiveConfig{
		Token:         token,
		Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		StdioOut:      &receiverOut,
		ForceRelay:    true,
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}

	if err := <-offerErr; err != nil {
		t.Fatalf("Offer() error = %v", err)
	}
	if got := receiverOut.String(); got != "public offered payload" {
		t.Fatalf("receiver output = %q, want %q", got, "public offered payload")
	}
}

func TestPublicRelayOnlyOfferExitsWhenReceiverCancels(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var senderStatus syncBuffer
	var receiverStatus syncBuffer
	pipeReader, pipeWriter := io.Pipe()
	writeDone := make(chan error, 1)
	go func() {
		chunk := bytes.Repeat([]byte("receiver-cancel-offer:"), 32*1024/len("receiver-cancel-offer:"))
		for {
			if _, err := pipeWriter.Write(chunk); err != nil {
				if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, context.Canceled) {
					writeDone <- nil
					return
				}
				writeDone <- err
				return
			}
		}
	}()
	defer func() {
		_ = pipeWriter.CloseWithError(context.Canceled)
		_ = pipeReader.Close()
		select {
		case err := <-writeDone:
			if err != nil {
				t.Errorf("pipe writer error = %v", err)
			}
		case <-time.After(time.Second):
			t.Errorf("pipe writer did not exit")
		}
	}()

	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioIn:       pipeReader,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		offerErr <- err
	}()

	var tok string
	select {
	case tok = <-tokenSink:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for offered token: %v; sender=%q receiver=%q", ctx.Err(), senderStatus.String(), receiverStatus.String())
	}

	receiveCtx, cancelReceive := context.WithCancel(ctx)
	receiveErr := make(chan error, 1)
	go func() {
		receiveErr <- Receive(receiveCtx, ReceiveConfig{
			Token:         tok,
			Emitter:       telemetry.New(&receiverStatus, telemetry.LevelVerbose),
			StdioOut:      io.Discard,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	if err := waitForSessionTestStatusContains(waitCtx, &receiverStatus, string(StateRelay)); err != nil {
		waitCancel()
		t.Fatalf("receiver did not reach relay before cancellation: %v; sender=%q receiver=%q", err, senderStatus.String(), receiverStatus.String())
	}
	waitCancel()

	cancelReceive()

	select {
	case err := <-receiveErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Receive() error = %v, want %v; sender=%q receiver=%q", err, context.Canceled, senderStatus.String(), receiverStatus.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Receive() did not exit after cancellation; sender=%q receiver=%q", senderStatus.String(), receiverStatus.String())
	}

	select {
	case err := <-offerErr:
		if !errors.Is(err, ErrPeerAborted) {
			t.Fatalf("Offer() error = %v, want %v; sender=%q receiver=%q", err, ErrPeerAborted, senderStatus.String(), receiverStatus.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Offer() did not exit after receiver cancellation; sender=%q receiver=%q", senderStatus.String(), receiverStatus.String())
	}
}

func TestPublicRelayOnlyOfferedTraceCompletesAfterPeerAck(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var traceOut bytes.Buffer
	trace, err := transfertrace.NewRecorder(&traceOut, transfertrace.RoleSend, time.Unix(100, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	payload := "public offered trace payload"
	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:     tokenSink,
			StdioIn:       strings.NewReader(payload),
			ForceRelay:    true,
			UsePublicDERP: true,
			Trace:         trace,
		})
		offerErr <- err
	}()

	token := <-tokenSink
	var receiverOut bytes.Buffer
	if err := Receive(ctx, ReceiveConfig{
		Token:         token,
		Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		StdioOut:      &receiverOut,
		ForceRelay:    true,
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if err := <-offerErr; err != nil {
		t.Fatalf("Offer() error = %v", err)
	}
	if err := trace.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	rows := readTransferTraceRows(t, traceOut.String())
	row := rows[len(rows)-1]
	if row["phase"] != string(transfertrace.PhaseComplete) ||
		row["app_bytes"] != strconv.Itoa(len(payload)) ||
		row["peer_received_bytes"] != strconv.Itoa(len(payload)) {
		t.Fatalf("final trace row = %#v, want receiver-ACK anchored complete", row)
	}
}

func TestExternalOfferSendConfigPreservesProgress(t *testing.T) {
	progressCalled := make(chan [2]int64, 1)
	cfg := externalOfferSendConfig(OfferConfig{
		Progress: func(bytesReceived int64, transferElapsedMS int64) {
			progressCalled <- [2]int64{bytesReceived, transferElapsedMS}
		},
	})

	if cfg.Progress == nil {
		t.Fatal("external offer send config dropped progress callback")
	}
	cfg.Progress(1234, 567)
	select {
	case got := <-progressCalled:
		if got != [2]int64{1234, 567} {
			t.Fatalf("progress callback got %v, want [1234 567]", got)
		}
	default:
		t.Fatal("progress callback was not invoked")
	}
}

func TestExternalOfferPeerChannelsReceiveProgressPackets(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	node := srv.Map.Regions[1].Nodes[0]

	offerDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(offer) error = %v", err)
	}
	defer offerDERP.Close()
	peerDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(peer) error = %v", err)
	}
	defer peerDERP.Close()

	channels := subscribeExternalOfferPeerChannels(&relaySession{derp: offerDERP}, peerDERP.PublicKey())
	defer channels.cleanup()
	payload, err := json.Marshal(envelope{
		Type:     envelopeProgress,
		Progress: newPeerProgress(1234, 567, 8),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !isProgressPayload(payload) {
		t.Fatal("progress payload was not recognized")
	}
	if err := sendPeerProgress(ctx, peerDERP, offerDERP.PublicKey(), 1234, 567, 8, externalPeerControlAuth{}); err != nil {
		t.Fatalf("sendPeerProgress() error = %v", err)
	}

	select {
	case pkt := <-channels.progressCh:
		if pkt.From != peerDERP.PublicKey() {
			t.Fatalf("progress From = %v, want %v", pkt.From, peerDERP.PublicKey())
		}
		if !isProgressPayload(pkt.Payload) {
			t.Fatalf("subscription delivered non-progress payload %q", pkt.Payload)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestExternalOfferPayloadPassesProgressToRelayPrefixSend(t *testing.T) {
	origSendDirect := externalSendDirectUDPOnlyFn
	t.Cleanup(func() {
		externalSendDirectUDPOnlyFn = origSendDirect
	})

	progressCh := make(chan derpbind.Packet)
	progressCalled := make(chan [2]int64, 1)
	externalSendDirectUDPOnlyFn = func(ctx context.Context, src io.Reader, tok token.Token, derpClient *derpbind.Client, listenerDERP key.NodePublic, transportManager *transport.Manager, pathEmitter *transportPathEmitter, punchCancel context.CancelFunc, probeConn net.PacketConn, probeConns []net.PacketConn, remoteCandidates []net.Addr, readyAckCh <-chan derpbind.Packet, startAckCh <-chan derpbind.Packet, rateProbeCh <-chan derpbind.Packet, gotProgressCh <-chan derpbind.Packet, cfg SendConfig) error {
		if gotProgressCh != (<-chan derpbind.Packet)(progressCh) {
			t.Fatalf("progress channel = %v, want offer peer progress channel", gotProgressCh)
		}
		if cfg.Progress == nil {
			t.Fatal("relay-prefix send config dropped offer progress callback")
		}
		cfg.Progress(4321, 765)
		return nil
	}

	err := sendExternalOfferPayload(
		context.Background(),
		&relaySession{},
		nil,
		externalOfferDirectRuntime{},
		externalOfferPeerChannels{progressCh: progressCh},
		&externalOfferTransportRuntime{ctx: context.Background()},
		key.NodePublic{},
		nil,
		OfferConfig{Progress: func(bytesReceived int64, transferElapsedMS int64) {
			progressCalled <- [2]int64{bytesReceived, transferElapsedMS}
		}},
	)
	if err != nil {
		t.Fatalf("sendExternalOfferPayload() error = %v", err)
	}

	select {
	case got := <-progressCalled:
		if got != [2]int64{4321, 765} {
			t.Fatalf("progress callback got %v, want [4321 765]", got)
		}
	default:
		t.Fatal("progress callback was not invoked")
	}
}

func TestRelayOnlyOfferSendPeerProgressWatcherPreservesProgressCallback(t *testing.T) {
	origProbeSend := externalDirectUDPProbeSendFn
	t.Cleanup(func() { externalDirectUDPProbeSendFn = origProbeSend })

	tok := testExternalSessionToken(0x96)
	auth := externalPeerControlAuthForToken(tok)
	payload, err := marshalAuthenticatedEnvelope(envelope{
		Type:     envelopeProgress,
		Progress: newPeerProgress(32768, 550, 1),
	}, auth)
	if err != nil {
		t.Fatal(err)
	}
	progressCh := make(chan derpbind.Packet, 1)
	progressCh <- derpbind.Packet{Payload: payload}
	progressCalled := make(chan [2]int64, 1)

	externalDirectUDPProbeSendFn = func(ctx context.Context, conn net.PacketConn, remoteAddr string, src io.Reader, cfg probe.SendConfig) (probe.TransferStats, error) {
		select {
		case got := <-progressCalled:
			if got != [2]int64{32768, 550} {
				t.Fatalf("progress callback got %v, want [32768 550]", got)
			}
			return probe.TransferStats{}, nil
		case <-ctx.Done():
			return probe.TransferStats{}, ctx.Err()
		case <-time.After(time.Second):
			return probe.TransferStats{}, fmt.Errorf("timed out waiting for relay-only offer peer progress")
		}
	}
	manager := transport.NewManager(transport.ManagerConfig{
		RelaySend: func(context.Context, []byte) error { return nil },
	})

	err = sendExternalOfferPayload(
		context.Background(),
		&relaySession{token: tok},
		newByteCountingReadCloser(nopReadCloser{Reader: bytes.NewReader([]byte("relay-only-offer-progress"))}),
		externalOfferDirectRuntime{relayOnly: true},
		externalOfferPeerChannels{progressCh: progressCh},
		&externalOfferTransportRuntime{ctx: context.Background(), manager: manager},
		key.NodePublic{},
		nil,
		OfferConfig{Progress: func(bytesReceived int64, transferElapsedMS int64) {
			progressCalled <- [2]int64{bytesReceived, transferElapsedMS}
		}},
	)
	if err != nil {
		t.Fatalf("sendExternalOfferPayload() error = %v", err)
	}
}

func TestPublicRelayOnlyOfferedStdioRoundTripWhenOnlyOfferForcesRelay(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	var senderStatus syncBuffer
	var receiverStatus syncBuffer
	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioIn:       strings.NewReader("sender-forced relay payload"),
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		offerErr <- err
	}()

	var token string
	select {
	case token = <-tokenSink:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for offered token: %v; sender=%q receiver=%q", ctx.Err(), senderStatus.String(), receiverStatus.String())
	}

	var receiverOut bytes.Buffer
	if err := Receive(ctx, ReceiveConfig{
		Token:         token,
		Emitter:       telemetry.New(&receiverStatus, telemetry.LevelVerbose),
		StdioOut:      &receiverOut,
		UsePublicDERP: true,
	}); err != nil {
		cancel()
		select {
		case <-offerErr:
		case <-time.After(time.Second):
		}
		t.Fatalf("Receive() error = %v; sender=%q receiver=%q", err, senderStatus.String(), receiverStatus.String())
	}

	if err := <-offerErr; err != nil {
		t.Fatalf("Offer() error = %v; sender=%q receiver=%q", err, senderStatus.String(), receiverStatus.String())
	}
	if got := receiverOut.String(); got != "sender-forced relay payload" {
		t.Fatalf("receiver output = %q, want %q", got, "sender-forced relay payload")
	}
	if got := senderStatus.String(); !strings.Contains(got, "udp-relay=true") {
		t.Fatalf("sender status = %q, want UDP relay path", got)
	}
	if got := receiverStatus.String(); !strings.Contains(got, "udp-relay=true") || strings.Contains(got, "udp-handoff-receive-prepare-error") {
		t.Fatalf("receiver status = %q, want UDP relay path without direct handoff prepare", got)
	}
}

func TestPublicRelayOnlyOfferedStdioRoundTripWhenOnlyReceiveForcesRelay(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	var senderStatus syncBuffer
	var receiverStatus syncBuffer
	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioIn:       strings.NewReader("receiver-forced relay payload"),
			UsePublicDERP: true,
		})
		offerErr <- err
	}()

	var token string
	select {
	case token = <-tokenSink:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for offered token: %v; sender=%q receiver=%q", ctx.Err(), senderStatus.String(), receiverStatus.String())
	}

	var receiverOut bytes.Buffer
	if err := Receive(ctx, ReceiveConfig{
		Token:         token,
		Emitter:       telemetry.New(&receiverStatus, telemetry.LevelVerbose),
		StdioOut:      &receiverOut,
		ForceRelay:    true,
		UsePublicDERP: true,
	}); err != nil {
		cancel()
		select {
		case <-offerErr:
		case <-time.After(time.Second):
		}
		t.Fatalf("Receive() error = %v; sender=%q receiver=%q", err, senderStatus.String(), receiverStatus.String())
	}

	if err := <-offerErr; err != nil {
		t.Fatalf("Offer() error = %v; sender=%q receiver=%q", err, senderStatus.String(), receiverStatus.String())
	}
	if got := receiverOut.String(); got != "receiver-forced relay payload" {
		t.Fatalf("receiver output = %q, want %q", got, "receiver-forced relay payload")
	}
	if got := senderStatus.String(); !strings.Contains(got, "udp-relay=true") {
		t.Fatalf("sender status = %q, want UDP relay path", got)
	}
	if got := receiverStatus.String(); !strings.Contains(got, "udp-relay=true") || strings.Contains(got, "udp-handoff-receive-prepare-error") {
		t.Fatalf("receiver status = %q, want UDP relay path without direct handoff prepare", got)
	}
}

func TestOfferedStdioStartsRelayPayloadBeforeDelayedDirectPromotion(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", strconv.FormatInt(time.Now().Add(24*time.Hour).UnixNano(), 10))

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:     tokenSink,
			StdioIn:       strings.NewReader("relay-first offered payload"),
			UsePublicDERP: true,
		})
		offerErr <- err
	}()

	token := <-tokenSink
	var receiverOut bytes.Buffer
	start := time.Now()
	if err := Receive(ctx, ReceiveConfig{
		Token:         token,
		Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		StdioOut:      &receiverOut,
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed >= 3*time.Second {
		t.Fatalf("Receive() elapsed = %v, want relay payload before delayed direct promotion", elapsed)
	}

	if err := <-offerErr; err != nil {
		t.Fatalf("Offer() error = %v", err)
	}
	if got := receiverOut.String(); got != "relay-first offered payload" {
		t.Fatalf("receiver output = %q, want %q", got, "relay-first offered payload")
	}
}

func TestExternalOfferReceiveDirectUDPPromotionDoesNotEmitRelayRegression(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")

	prevTCPAddrAllowed := externalNativeTCPAddrAllowed
	externalNativeTCPAddrAllowed = func(net.Addr) bool { return false }
	t.Cleanup(func() { externalNativeTCPAddrAllowed = prevTCPAddrAllowed })

	prevInterfaceAddrs := publicInterfaceAddrs
	publicInterfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{
				IP:   net.IPv4(127, 0, 0, 1),
				Mask: net.CIDRMask(8, 32),
			},
		}, nil
	}
	t.Cleanup(func() { publicInterfaceAddrs = prevInterfaceAddrs })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte("offered-native-quic-direct:"), (4*externalCopyBufferSize)/len("offered-native-quic-direct:"))
	var receiverOut bytes.Buffer
	var receiverStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	midpoint := len(payload) / 2
	stdinReader := &sessionTestGatedReader{payload: payload, gateAt: midpoint, gate: func() error {
		gateCtx, gateCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer gateCancel()
		if err := waitForSessionTestStatusContains(gateCtx, &senderStatus, string(StateTryingDirect)); err != nil {
			return fmt.Errorf("waiting for offered sender direct UDP attempt: %w; receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
		}
		if err := waitForSessionTestStatusContains(gateCtx, &receiverStatus, string(StateTryingDirect)); err != nil {
			return fmt.Errorf("waiting for offered receiver direct UDP attempt: %w; receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
		}
		return nil
	}}

	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioIn:       stdinReader,
			UsePublicDERP: true,
		})
		offerErr <- err
	}()

	token := <-tokenSink
	receiveErr := make(chan error, 1)
	go func() {
		receiveErr <- Receive(ctx, ReceiveConfig{
			Token:         token,
			Emitter:       telemetry.New(&receiverStatus, telemetry.LevelVerbose),
			StdioOut:      &receiverOut,
			UsePublicDERP: true,
		})
	}()

	if err := <-receiveErr; err != nil {
		t.Fatalf("Receive() error = %v receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
	}
	if err := <-offerErr; err != nil {
		t.Fatalf("Offer() error = %v receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
	}

	if !bytes.Equal(receiverOut.Bytes(), payload) {
		t.Fatalf("receiver output length = %d, want %d", receiverOut.Len(), len(payload))
	}

	if got := sessionStatusLines(senderStatus.String()); hasSessionStatusPrefix(got, []string{string(StateWaiting), string(StateClaimed), string(StateRelay), string(StateDirect), string(StateRelay)}) {
		t.Fatalf("sender status lines = %q, want no relay regression after direct handoff", got)
	}
	if got := sessionStatusLines(receiverStatus.String()); hasSessionStatusPrefix(got, []string{string(StateProbing), string(StateRelay), string(StateDirect), string(StateRelay)}) {
		t.Fatalf("receiver status lines = %q, want no relay regression after direct handoff", got)
	}
}

func TestExternalOfferReceiveDirectUDPPromotionWithPipeSourceDoesNotStall(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")

	prevTCPAddrAllowed := externalNativeTCPAddrAllowed
	externalNativeTCPAddrAllowed = func(net.Addr) bool { return false }
	t.Cleanup(func() { externalNativeTCPAddrAllowed = prevTCPAddrAllowed })

	prevInterfaceAddrs := publicInterfaceAddrs
	publicInterfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{
				IP:   net.IPv4(127, 0, 0, 1),
				Mask: net.CIDRMask(8, 32),
			},
		}, nil
	}
	t.Cleanup(func() { publicInterfaceAddrs = prevInterfaceAddrs })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte("offered-pipe-native-quic-direct:"), (4*externalCopyBufferSize)/len("offered-pipe-native-quic-direct:"))
	var receiverOut bytes.Buffer
	var receiverStatus syncBuffer
	var senderStatus syncBuffer

	pipeReader, pipeWriter := io.Pipe()
	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioIn:       pipeReader,
			UsePublicDERP: true,
		})
		offerErr <- err
	}()

	writeErr := make(chan error, 1)
	go func() {
		midpoint := len(payload) / 2
		if _, err := pipeWriter.Write(payload[:midpoint]); err != nil {
			writeErr <- err
			return
		}
		gateCtx, gateCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer gateCancel()
		if err := waitForSessionTestStatusContains(gateCtx, &senderStatus, string(StateTryingDirect)); err != nil {
			writeErr <- fmt.Errorf("waiting for offered pipe sender direct UDP attempt: %w; receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
			return
		}
		if _, err := pipeWriter.Write(payload[midpoint:]); err != nil {
			writeErr <- err
			return
		}
		writeErr <- pipeWriter.Close()
	}()

	token := <-tokenSink
	if err := Receive(ctx, ReceiveConfig{
		Token:         token,
		Emitter:       telemetry.New(&receiverStatus, telemetry.LevelVerbose),
		StdioOut:      &receiverOut,
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("Receive() error = %v receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("pipe write error = %v receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
	}
	if err := <-offerErr; err != nil {
		t.Fatalf("Offer() error = %v receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
	}

	if !bytes.Equal(receiverOut.Bytes(), payload) {
		t.Fatalf("receiver output length = %d, want %d", receiverOut.Len(), len(payload))
	}
	if !strings.Contains(senderStatus.String(), string(StateTryingDirect)) {
		t.Fatalf("sender statuses = %q, want %q", senderStatus.String(), StateTryingDirect)
	}
	if !strings.Contains(receiverStatus.String(), string(StateTryingDirect)) {
		t.Fatalf("receiver statuses = %q, want %q", receiverStatus.String(), StateTryingDirect)
	}
}
