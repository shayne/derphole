// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/portmap"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transport"
	"github.com/shayne/derphole/pkg/traversal"
	"go4.org/mem"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/portmapper/portmappertype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestDERPPublicKeyRaw32RoundTrip(t *testing.T) {
	want := [32]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}

	pub := key.NodePublicFromRaw32(mem.B(want[:]))
	if got := derpPublicKeyRaw32(pub); got != want {
		t.Fatalf("derpPublicKeyRaw32() = %x, want %x", got, want)
	}
}

func TestDirectUDPReadyAckPayloadIsControl(t *testing.T) {
	payload, err := json.Marshal(envelope{Type: envelopeDirectUDPReadyAck})
	if err != nil {
		t.Fatal(err)
	}
	if !isDirectUDPReadyAckPayload(payload) {
		t.Fatalf("isDirectUDPReadyAckPayload(%s) = false, want true", payload)
	}
	if isTransportDataPayload(payload) {
		t.Fatalf("isTransportDataPayload(%s) = true, want false for direct UDP ready ack", payload)
	}
}

func TestDirectUDPHandshakePayloadsAreControl(t *testing.T) {
	tests := []struct {
		name    string
		env     envelope
		matches func([]byte) bool
	}{
		{
			name:    "ready",
			env:     envelope{Type: envelopeDirectUDPReady},
			matches: isDirectUDPReadyPayload,
		},
		{
			name: "start",
			env: envelope{
				Type:           envelopeDirectUDPStart,
				DirectUDPStart: &directUDPStart{ExpectedBytes: 123},
			},
			matches: isDirectUDPStartPayload,
		},
		{
			name:    "start_ack",
			env:     envelope{Type: envelopeDirectUDPStartAck},
			matches: isDirectUDPStartAckPayload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := json.Marshal(tt.env)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.matches(payload) {
				t.Fatalf("direct UDP %s matcher = false, want true", tt.name)
			}
			if isTransportDataPayload(payload) {
				t.Fatalf("isTransportDataPayload(%s) = true, want false for direct UDP %s", payload, tt.name)
			}
		})
	}
}

func TestDirectUDPRateProbePayloadIsControl(t *testing.T) {
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
		t.Fatalf("isDirectUDPRateProbePayload(%s) = false, want true", payload)
	}
	if isTransportDataPayload(payload) {
		t.Fatalf("isTransportDataPayload(%s) = true, want false for direct UDP rate probe", payload)
	}
}

func TestRelayOnlyStdioRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var senderIn bytes.Buffer
	senderIn.WriteString("hello over derp")

	listenerReady := make(chan string, 1)
	go func() {
		token, err := Listen(ctx, ListenConfig{
			Emitter:   telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink: listenerReady,
			StdioOut:  &listenerOut,
		})
		if err != nil || token == "" {
			t.Errorf("Listen() err=%v token=%q", err, token)
		}
	}()

	token := <-listenerReady
	if err := Send(ctx, SendConfig{
		Token:      token,
		StdioIn:    &senderIn,
		Emitter:    telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		ForceRelay: true,
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if got := listenerOut.String(); got != "hello over derp" {
		t.Fatalf("listener output = %q, want %q", got, "hello over derp")
	}
}

func TestPublicRelayOnlyStdioRoundTrip(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var listenerStatus bytes.Buffer
	var senderStatus bytes.Buffer
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	if err := Send(ctx, SendConfig{
		Token:         token,
		Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
		StdioIn:       strings.NewReader("public relay payload"),
		ForceRelay:    true,
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("Send() error = %v; listener status=%q sender status=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v; listener status=%q sender status=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if got := listenerOut.String(); got != "public relay payload" {
		t.Fatalf("listener output = %q, want %q; listener status=%q sender status=%q", got, "public relay payload", listenerStatus.String(), senderStatus.String())
	}
}

func TestPublicRelayOnlyStdioRoundTripWhenOnlySenderForcesRelay(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	var token string
	select {
	case token = <-tokenSink:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for listener token: %v; listener=%q sender=%q", ctx.Err(), listenerStatus.String(), senderStatus.String())
	}

	if err := Send(ctx, SendConfig{
		Token:         token,
		Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
		StdioIn:       strings.NewReader("sender-forced relay payload"),
		ForceRelay:    true,
		UsePublicDERP: true,
	}); err != nil {
		cancel()
		select {
		case <-listenErr:
		case <-time.After(time.Second):
		}
		t.Fatalf("Send() error = %v; listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v; listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if got := listenerOut.String(); got != "sender-forced relay payload" {
		t.Fatalf("listener output = %q, want %q", got, "sender-forced relay payload")
	}
	if got := senderStatus.String(); !strings.Contains(got, "udp-relay=true") {
		t.Fatalf("sender status = %q, want UDP relay path", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, "udp-relay=true") || strings.Contains(got, "udp-handoff-receive-prepare-error") {
		t.Fatalf("listener status = %q, want UDP relay path without direct handoff prepare", got)
	}
}

func TestPublicRelayOnlyStdioRoundTripWhenOnlyListenerForcesRelay(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	var token string
	select {
	case token = <-tokenSink:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for listener token: %v; listener=%q sender=%q", ctx.Err(), listenerStatus.String(), senderStatus.String())
	}

	if err := Send(ctx, SendConfig{
		Token:         token,
		Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
		StdioIn:       strings.NewReader("listener-forced relay payload"),
		UsePublicDERP: true,
	}); err != nil {
		cancel()
		select {
		case <-listenErr:
		case <-time.After(time.Second):
		}
		t.Fatalf("Send() error = %v; listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v; listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if got := listenerOut.String(); got != "listener-forced relay payload" {
		t.Fatalf("listener output = %q, want %q", got, "listener-forced relay payload")
	}
	if got := senderStatus.String(); !strings.Contains(got, "udp-relay=true") {
		t.Fatalf("sender status = %q, want UDP relay path", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, "udp-relay=true") || strings.Contains(got, "udp-handoff-receive-prepare-error") {
		t.Fatalf("listener status = %q, want UDP relay path without direct handoff prepare", got)
	}
}

func TestPublicRelayOnlyStdioRoundTripSingleStripe(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	if err := Send(ctx, SendConfig{
		Token:          token,
		Emitter:        telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		StdioIn:        strings.NewReader("public relay payload"),
		ForceRelay:     true,
		UsePublicDERP:  true,
		ParallelPolicy: FixedParallelPolicy(1),
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	if got := listenerOut.String(); got != "public relay payload" {
		t.Fatalf("listener output = %q, want %q", got, "public relay payload")
	}
}

func TestPublicRelayOnlyListenerExitsWhenSenderCancels(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	sendCtx, cancelSend := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(sendCtx, SendConfig{
			Token:         token,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:       pr,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	if err := waitForSessionTestStatusContains(waitCtx, &senderStatus, string(StateRelay)); err != nil {
		waitCancel()
		t.Fatalf("sender did not reach relay before cancellation: %v; listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	waitCancel()

	cancelSend()
	_ = pw.CloseWithError(context.Canceled)
	_ = pr.Close()

	select {
	case err := <-sendErr:
		if err == nil {
			t.Fatal("Send() error = nil, want cancellation error")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Send() did not exit after cancellation; listener=%q sender=%q", listenerStatus.String(), senderStatus.String())
	}

	select {
	case err := <-listenErr:
		if !errors.Is(err, ErrPeerAborted) {
			t.Fatalf("Listen() error = %v, want %v; listener=%q sender=%q", err, ErrPeerAborted, listenerStatus.String(), senderStatus.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Listen() did not exit after sender cancellation; listener=%q sender=%q", listenerStatus.String(), senderStatus.String())
	}
}

func TestSessionPromotesDirectStateWhenProbeSucceeds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var listenerOut syncBuffer
	var senderIn bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer
	senderIn.WriteString("hello direct")

	listenerReady := make(chan string, 1)
	go func() {
		token, err := Listen(ctx, ListenConfig{
			Emitter:   telemetry.New(&listenerStatus, telemetry.LevelDefault),
			TokenSink: listenerReady,
			StdioOut:  &listenerOut,
		})
		if err != nil || token == "" {
			t.Errorf("Listen() err=%v token=%q", err, token)
		}
	}()

	token := <-listenerReady
	if err := Send(ctx, SendConfig{
		Token:   token,
		StdioIn: &senderIn,
		Emitter: telemetry.New(&senderStatus, telemetry.LevelDefault),
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if !strings.Contains(listenerStatus.String(), string(StateDirect)) {
		t.Fatalf("listener statuses = %q, want %q", listenerStatus.String(), StateDirect)
	}
	if !strings.Contains(senderStatus.String(), string(StateDirect)) {
		t.Fatalf("sender statuses = %q, want %q", senderStatus.String(), StateDirect)
	}
	if got := listenerOut.String(); got != "hello direct" {
		t.Fatalf("listener output = %q, want %q", got, "hello direct")
	}
}

func TestSendListenExternalStartsRelayPayloadBeforeNativeModeTimeout(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", strconv.FormatInt(time.Now().Add(24*time.Hour).UnixNano(), 10))

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	start := time.Now()
	if err := Send(ctx, SendConfig{
		Token:         token,
		Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		StdioIn:       strings.NewReader("relay-first payload"),
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed >= 3*time.Second {
		t.Fatalf("Send() elapsed = %v, want relay payload before native mode timeout", elapsed)
	}

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	if got := listenerOut.String(); got != "relay-first payload" {
		t.Fatalf("listener output = %q, want %q", got, "relay-first payload")
	}
}

func TestShareOpenUsesEphemeralLocalBind(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backendAddr, backendDone := startEchoServer(t, ctx)

	tokenSink := make(chan string, 1)
	shareErr := make(chan error, 1)
	go func() {
		_, err := Share(ctx, ShareConfig{
			Emitter:    telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:  tokenSink,
			TargetAddr: backendAddr,
		})
		shareErr <- err
	}()

	tok := <-tokenSink
	bindSink := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- Open(ctx, OpenConfig{
			Token:        tok,
			BindAddrSink: bindSink,
			Emitter:      telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		})
	}()

	bindAddr := <-bindSink
	if !strings.HasPrefix(bindAddr, "127.0.0.1:") {
		t.Fatalf("bindAddr = %q, want ephemeral localhost listener", bindAddr)
	}
	if strings.HasSuffix(bindAddr, ":0") {
		t.Fatalf("bindAddr = %q, want assigned port", bindAddr)
	}

	cancel()
	waitNoErr(t, <-openErr)
	waitNoErr(t, <-shareErr)
	backendDone()
}

func TestDecodeEnvelopeRejectsOversizedPayload(t *testing.T) {
	payload := make([]byte, maxEnvelopeBytes+1)
	if _, err := decodeEnvelope(payload); err == nil {
		t.Fatal("decodeEnvelope() error = nil, want invalid envelope size")
	}
}

func TestWaitInitialExternalNativeDirectModeAllowsDirectStart(t *testing.T) {
	t.Setenv("DERPHOLE_NATIVE_TCP_DIRECT_START", "1")

	ch := make(chan externalNativeDirectModeResult, 1)
	want := externalNativeDirectModeResult{nativeTCPConns: []net.Conn{&net.TCPConn{}}}
	ch <- want

	got, ok := waitInitialExternalNativeDirectMode(context.Background(), ch, time.Second)
	if !ok {
		t.Fatal("waitInitialExternalNativeDirectMode() ok = false, want true")
	}
	if len(got.nativeTCPConns) != len(want.nativeTCPConns) {
		t.Fatalf("nativeTCPConns len = %d, want %d", len(got.nativeTCPConns), len(want.nativeTCPConns))
	}
}

func TestShareOpenForwardsSequentialConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backendAddr, backendDone := startEchoServer(t, ctx)
	openAddr, stop, shareErr, openErr := startSharedSession(t, ctx, backendAddr, "")

	for _, payload := range []string{"alpha", "beta", "gamma"} {
		reply, err := roundTripTCP(ctx, openAddr, payload)
		if err != nil {
			t.Fatalf("roundTripTCP() error = %v", err)
		}
		if reply != payload {
			t.Fatalf("reply = %q, want %q", reply, payload)
		}
	}

	stop()
	waitNoErr(t, <-openErr)
	waitNoErr(t, <-shareErr)
	backendDone()
}

func TestShareOpenForwardsConcurrentConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backendAddr, backendDone := startEchoServer(t, ctx)
	openAddr, stop, shareErr, openErr := startSharedSession(t, ctx, backendAddr, "")

	payloads := []string{"one", "two", "three", "four", "five"}
	var wg sync.WaitGroup
	errCh := make(chan error, len(payloads))
	for _, payload := range payloads {
		wg.Add(1)
		go func(payload string) {
			defer wg.Done()
			reply, err := roundTripTCP(ctx, openAddr, payload)
			if err != nil {
				errCh <- err
				return
			}
			if reply != payload {
				errCh <- errors.New("reply mismatch: payload=" + payload + " reply=" + reply)
			}
		}(payload)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	stop()
	waitNoErr(t, <-openErr)
	waitNoErr(t, <-shareErr)
	backendDone()
}

func TestShareTokenAllowsOneClaimer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backendAddr, backendDone := startEchoServer(t, ctx)

	tokenSink := make(chan string, 1)
	shareErr := make(chan error, 1)
	go func() {
		_, err := Share(ctx, ShareConfig{
			Emitter:    telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:  tokenSink,
			TargetAddr: backendAddr,
		})
		shareErr <- err
	}()

	tok := <-tokenSink
	bindSink := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- Open(ctx, OpenConfig{
			Token:        tok,
			BindAddrSink: bindSink,
			Emitter:      telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		})
	}()
	<-bindSink

	err := Open(ctx, OpenConfig{
		Token:   tok,
		Emitter: telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
	})
	if !errors.Is(err, ErrSessionClaimed) {
		t.Fatalf("Open() error = %v, want %v", err, ErrSessionClaimed)
	}

	cancel()
	waitNoErr(t, <-openErr)
	waitNoErr(t, <-shareErr)
	backendDone()
}

func TestShareOpenExternalAllowsOneClaimerUnderContention(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	backendAddr, backendDone := startEchoServer(t, ctx)
	defer backendDone()

	tokenSink := make(chan string, 1)
	shareErr := make(chan error, 1)
	go func() {
		_, err := Share(ctx, ShareConfig{
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:     tokenSink,
			TargetAddr:    backendAddr,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		shareErr <- err
	}()

	tok := <-tokenSink
	bindSink := make(chan string, 1)
	firstOpenErr := make(chan error, 1)
	go func() {
		firstOpenErr <- Open(ctx, OpenConfig{
			Token:         tok,
			BindAddrSink:  bindSink,
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			ForceRelay:    true,
			UsePublicDERP: true,
		})
	}()

	openAddr := <-bindSink
	reply, err := roundTripTCP(ctx, openAddr, "claimed")
	if err != nil {
		t.Fatalf("roundTripTCP() error = %v", err)
	}
	if reply != "claimed" {
		t.Fatalf("reply = %q, want %q", reply, "claimed")
	}

	const contenders = 18
	errCh := make(chan error, contenders)
	for i := 0; i < contenders; i++ {
		go func() {
			secondCtx, secondCancel := context.WithTimeout(ctx, 15*time.Second)
			defer secondCancel()
			errCh <- Open(secondCtx, OpenConfig{
				Token:         tok,
				Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
				ForceRelay:    true,
				UsePublicDERP: true,
			})
		}()
	}

	for i := 0; i < contenders; i++ {
		err := <-errCh
		if err == nil {
			t.Fatal("contending Open() error = nil, want rejection")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("contending Open() error = %v, want deterministic rejection", err)
		}
		if !strings.Contains(err.Error(), "session already claimed") {
			t.Fatalf("contending Open() error = %v, want session already claimed", err)
		}
	}

	cancel()
	waitNoErr(t, <-firstOpenErr)
	waitNoErr(t, <-shareErr)
}

func TestShareOpenExternalClaimPressureDoesNotStallAcceptedRelaySession(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	backendAddr, backendDone := startEchoServer(t, ctx)
	defer backendDone()

	tokenSink := make(chan string, 1)
	shareErr := make(chan error, 1)
	go func() {
		_, err := Share(ctx, ShareConfig{
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:     tokenSink,
			TargetAddr:    backendAddr,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		shareErr <- err
	}()

	tok := <-tokenSink
	bindSink := make(chan string, 1)
	firstOpenErr := make(chan error, 1)
	go func() {
		firstOpenErr <- Open(ctx, OpenConfig{
			Token:         tok,
			BindAddrSink:  bindSink,
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			ForceRelay:    true,
			UsePublicDERP: true,
		})
	}()

	openAddr := <-bindSink
	if reply, err := roundTripTCP(ctx, openAddr, "accepted-before-pressure"); err != nil {
		t.Fatalf("initial roundTripTCP() error = %v", err)
	} else if reply != "accepted-before-pressure" {
		t.Fatalf("initial reply = %q, want %q", reply, "accepted-before-pressure")
	}

	const contenders = 96
	start := make(chan struct{})
	errCh := make(chan error, contenders)
	for i := 0; i < contenders; i++ {
		go func() {
			<-start
			secondCtx, secondCancel := context.WithTimeout(ctx, 15*time.Second)
			defer secondCancel()
			errCh <- Open(secondCtx, OpenConfig{
				Token:         tok,
				Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
				ForceRelay:    true,
				UsePublicDERP: true,
			})
		}()
	}
	close(start)

	responsiveCtx, responsiveCancel := context.WithTimeout(ctx, 5*time.Second)
	reply, err := roundTripTCP(responsiveCtx, openAddr, "accepted-under-pressure")
	responsiveCancel()
	if err != nil {
		t.Fatalf("roundTripTCP() under claim pressure error = %v", err)
	}
	if reply != "accepted-under-pressure" {
		t.Fatalf("reply under claim pressure = %q, want %q", reply, "accepted-under-pressure")
	}

	for i := 0; i < contenders; i++ {
		err := <-errCh
		if err == nil {
			t.Fatal("contending Open() error = nil, want rejection")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("contending Open() error = %v, want deterministic rejection", err)
		}
		if !strings.Contains(err.Error(), "session already claimed") {
			t.Fatalf("contending Open() error = %v, want session already claimed", err)
		}
	}

	cancel()
	waitNoErr(t, <-firstOpenErr)
	waitNoErr(t, <-shareErr)
}

func TestShareOpenExternalCanUpgradeAfterRelayStartAndServeConnections(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")

	result := runExternalShareOpenSession(t, shareOpenRoundTripConfig{
		relayPayload:    "relay-first",
		upgradePayloads: []string{"direct-one", "direct-two", "direct-three"},
	})

	if !result.SeenRelay || !result.SeenDirect {
		t.Fatalf("SeenRelay=%v SeenDirect=%v share=%q open=%q", result.SeenRelay, result.SeenDirect, result.ShareStatus, result.OpenStatus)
	}
	if got := result.RelayReply; got != "relay-first" {
		t.Fatalf("relay reply = %q, want %q", got, "relay-first")
	}
	if !strings.Contains(result.ShareStatus, string(StateClaimed)) {
		t.Fatalf("ShareStatus = %q, want %q", result.ShareStatus, StateClaimed)
	}
	for _, payload := range []string{"direct-one", "direct-two", "direct-three"} {
		if got := result.UpgradeReplies[payload]; got != payload {
			t.Fatalf("upgrade reply for %q = %q, want %q", payload, got, payload)
		}
	}
}

func TestExternalListenSendUsesRelayUDPWhenDirectNeverBecomesReady(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", strconv.FormatInt(time.Now().Add(24*time.Hour).UnixNano(), 10))

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

	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:         token,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:       bytes.NewReader([]byte("native-direct")),
			UsePublicDERP: true,
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if got := listenerOut.String(); got != "native-direct" {
		t.Fatalf("listener output = %q, want %q", got, "native-direct")
	}
	if got := senderStatus.String(); !strings.Contains(got, string(StateRelay)) || strings.Contains(got, "udp-relay=true") || strings.Contains(got, string(StateDirect)) || strings.Contains(got, "udp-stream=true") {
		t.Fatalf("sender status = %q, want relay-prefix completion without UDP fallback or direct promotion", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, string(StateRelay)) || strings.Contains(got, "udp-relay=true") || strings.Contains(got, string(StateDirect)) || strings.Contains(got, "udp-stream=true") {
		t.Fatalf("listener status = %q, want relay-prefix completion without UDP fallback or direct promotion", got)
	}
}

func TestExternalListenSendSmallRelayPayloadDoesNotWaitForDelayedNativeMode(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", strconv.FormatInt(time.Now().Add(24*time.Hour).UnixNano(), 10))

	prevTCPAddrAllowed := externalNativeTCPAddrAllowed
	externalNativeTCPAddrAllowed = func(net.Addr) bool { return false }
	t.Cleanup(func() { externalNativeTCPAddrAllowed = prevTCPAddrAllowed })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	start := time.Now()
	if err := Send(ctx, SendConfig{
		Token:         token,
		Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
		StdioIn:       bytes.NewReader(bytes.Repeat([]byte("relay-now"), 1024)),
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("small relay transfer took %v, want < 2s without waiting for native mode timeout; listener=%q sender=%q", elapsed, listenerStatus.String(), senderStatus.String())
	}
	if got := listenerOut.String(); got != strings.Repeat("relay-now", 1024) {
		t.Fatalf("listener output length = %d, want %d", len(got), len(strings.Repeat("relay-now", 1024)))
	}
}

func TestExternalListenSendSmallPayloadFinishesOverRelayBeforeDelayedDirectUDP(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")

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

	prevWaitDirectUDPAddr := waitExternalDirectUDPAddr
	waitExternalDirectUDPAddr = func(ctx context.Context, conn net.PacketConn, manager *transport.Manager) (net.Addr, error) {
		select {
		case <-time.After(1500 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return prevWaitDirectUDPAddr(ctx, conn, manager)
	}
	t.Cleanup(func() { waitExternalDirectUDPAddr = prevWaitDirectUDPAddr })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte("relay-prefix-now"), 1024)
	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	start := time.Now()
	if err := Send(ctx, SendConfig{
		Token:         token,
		Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
		StdioIn:       bytes.NewReader(payload),
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if elapsed := time.Since(start); elapsed > externalDirectUDPWait+2*time.Second {
		t.Fatalf("small payload took %v, want relay completion without long direct UDP wait; listener=%q sender=%q", elapsed, listenerStatus.String(), senderStatus.String())
	}
	if !bytes.Equal(listenerOut.Bytes(), payload) {
		t.Fatalf("listener output length = %d, want %d", listenerOut.Len(), len(payload))
	}
	if got := senderStatus.String(); !strings.Contains(got, "udp-handoff-finished-on-relay=true") || strings.Contains(got, "udp-stream=true") {
		t.Fatalf("sender status = %q, want relay completion before direct UDP stream starts", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, "udp-handoff-finished-on-relay=true") || strings.Contains(got, "udp-stream=true") {
		t.Fatalf("listener status = %q, want relay completion before direct UDP stream starts", got)
	}
}

func TestExternalListenSendSmallPayloadFinishesOverRelayWhileDirectReadyAckIsDelayed(t *testing.T) {
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

	prevWaitReadyAck := externalDirectUDPWaitReadyAckFn
	externalDirectUDPWaitReadyAckFn = func(ctx context.Context, readyAckCh <-chan derpbind.Packet, authOpt ...externalPeerControlAuth) (directUDPReadyAck, error) {
		select {
		case <-time.After(1500 * time.Millisecond):
		case <-ctx.Done():
			return directUDPReadyAck{}, ctx.Err()
		}
		return prevWaitReadyAck(ctx, readyAckCh, authOpt...)
	}
	t.Cleanup(func() { externalDirectUDPWaitReadyAckFn = prevWaitReadyAck })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	payloadSeed := []byte("relay-ready-ack-delay:")
	payload := bytes.Repeat(payloadSeed, (1<<20)/len(payloadSeed)+1)
	payload = payload[:1<<20]

	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	start := time.Now()
	if err := Send(ctx, SendConfig{
		Token:         token,
		Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
		StdioIn:       bytes.NewReader(payload),
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if elapsed := time.Since(start); elapsed > externalDirectUDPWait+2*time.Second {
		t.Fatalf("small payload took %v, want relay completion without long direct UDP wait; listener=%q sender=%q", elapsed, listenerStatus.String(), senderStatus.String())
	}
	if !bytes.Equal(listenerOut.Bytes(), payload) {
		t.Fatalf("listener output length = %d, want %d", listenerOut.Len(), len(payload))
	}
	if got := senderStatus.String(); !strings.Contains(got, "udp-handoff-finished-on-relay=true") || strings.Contains(got, "udp-stream=true") {
		t.Fatalf("sender status = %q, want relay completion before direct UDP stream starts", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, "udp-handoff-finished-on-relay=true") || strings.Contains(got, "udp-stream=true") {
		t.Fatalf("listener status = %q, want relay completion before direct UDP stream starts", got)
	}
}

func TestExternalListenSendSmallRelayPayloadDoesNotStallWhenSenderSkipsNativeQUICSetup(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", strconv.FormatInt(time.Now().Add(250*time.Millisecond).UnixNano(), 10))
	t.Setenv("DERPHOLE_NATIVE_QUIC_CONNS", "4")
	const nativeQUICCandidateDelay = 10 * time.Second

	prevTCPAddrAllowed := externalNativeTCPAddrAllowed
	externalNativeTCPAddrAllowed = func(net.Addr) bool { return false }
	t.Cleanup(func() { externalNativeTCPAddrAllowed = prevTCPAddrAllowed })

	prevStripeCandidates := externalNativeQUICStripeProbeCandidates
	externalNativeQUICStripeProbeCandidates = func(ctx context.Context, packetConn net.PacketConn, _ *tailcfg.DERPMap, _ publicPortmap) []string {
		select {
		case <-time.After(nativeQUICCandidateDelay):
		case <-ctx.Done():
			return nil
		}
		udpAddr := packetConn.LocalAddr().(*net.UDPAddr)
		return []string{net.JoinHostPort("127.0.0.1", fmt.Sprint(udpAddr.Port))}
	}
	t.Cleanup(func() { externalNativeQUICStripeProbeCandidates = prevStripeCandidates })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte("short-relay-tail"), 5<<17)
	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	start := time.Now()
	if err := Send(ctx, SendConfig{
		Token:         token,
		Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
		StdioIn:       bytes.NewReader(payload),
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if elapsed := time.Since(start); elapsed > nativeQUICCandidateDelay/2 {
		t.Fatalf("small relay transfer took %v, want < %v when sender skips native QUIC setup; listener=%q sender=%q", elapsed, nativeQUICCandidateDelay/2, listenerStatus.String(), senderStatus.String())
	}
	if !bytes.Equal(listenerOut.Bytes(), payload) {
		t.Fatalf("listener output length = %d, want %d", listenerOut.Len(), len(payload))
	}
	if got := senderStatus.String(); strings.Contains(got, "sender-quic-direct") || strings.Contains(got, "sender-tcp-direct") {
		t.Fatalf("sender status = %q, want relay completion without native handoff", got)
	}
}

func TestExternalListenSendPromotesToDirectUDPWhenBothSidesAreDirectReady(t *testing.T) {
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

	payload := bytes.Repeat([]byte("native-quic-direct:"), (2<<20)/len("native-quic-direct:"))
	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	midpoint := len(payload) / 2
	stdinReader, stdinWriter := io.Pipe()
	writerErr := make(chan error, 1)
	go func() {
		const upgradeStatusTimeout = 20 * time.Second

		defer stdinWriter.Close()
		if _, err := stdinWriter.Write(payload[:midpoint]); err != nil {
			writerErr <- err
			return
		}

		gateCtx, gateCancel := context.WithTimeout(context.Background(), upgradeStatusTimeout)
		defer gateCancel()
		if err := waitForSessionTestStatusContains(gateCtx, &listenerStatus, "udp-stream=true"); err != nil {
			writerErr <- fmt.Errorf("waiting for listener UDP stream: %w; listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
			return
		}

		_, err := stdinWriter.Write(payload[midpoint:])
		writerErr <- err
	}()

	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:         token,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:       stdinReader,
			UsePublicDERP: true,
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-writerErr; err != nil {
		t.Fatalf("stdin writer error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if !bytes.Equal(listenerOut.Bytes(), payload) {
		t.Fatalf("listener output length = %d, want %d", listenerOut.Len(), len(payload))
	}
	if got := senderStatus.String(); !strings.Contains(got, string(StateDirect)) || !strings.Contains(got, "udp-blast=true") || !strings.Contains(got, "udp-repair-payloads=true") || !strings.Contains(got, "udp-fec-group-size=0") || strings.Contains(got, "sender-tcp-direct") {
		t.Fatalf("sender status = %q, want direct UDP promotion", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, string(StateDirect)) || !strings.Contains(got, "udp-blast=true") || !strings.Contains(got, "udp-stream=true") || !strings.Contains(got, "udp-fec-group-size=0") || strings.Contains(got, "listener-tcp-direct") {
		t.Fatalf("listener status = %q, want direct UDP promotion", got)
	}
	if got := countSessionStatus(sessionStatusLines(senderStatus.String()), StateComplete); got != 1 {
		t.Fatalf("sender stream-complete count = %d, want 1; sender=%q", got, senderStatus.String())
	}
	if got := countSessionStatus(sessionStatusLines(listenerStatus.String()), StateComplete); got != 1 {
		t.Fatalf("listener stream-complete count = %d, want 1; listener=%q", got, listenerStatus.String())
	}
}

func TestExternalListenSendDirectUDPPromotionDoesNotEmitRelayRegression(t *testing.T) {
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

	payload := bytes.Repeat([]byte("native-quic-direct:"), (4*externalCopyBufferSize)/len("native-quic-direct:"))
	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	midpoint := len(payload) / 2
	stdinReader := &sessionTestGatedReader{payload: payload, gateAt: midpoint, gate: func() error {
		gateCtx, gateCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer gateCancel()
		if err := waitForSessionTestStatusContains(gateCtx, &senderStatus, string(StateDirect)); err != nil {
			return fmt.Errorf("waiting for sender direct UDP promotion: %w; listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
		}
		if err := waitForSessionTestStatusContains(gateCtx, &listenerStatus, string(StateDirect)); err != nil {
			return fmt.Errorf("waiting for listener direct UDP promotion: %w; listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
		}
		return nil
	}}

	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:         token,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:       stdinReader,
			UsePublicDERP: true,
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if !bytes.Equal(listenerOut.Bytes(), payload) {
		t.Fatalf("listener output length = %d, want %d", listenerOut.Len(), len(payload))
	}

	if got := sessionStatusLines(senderStatus.String()); hasSessionStatusPrefix(got, []string{string(StateProbing), string(StateRelay), string(StateDirect), string(StateRelay)}) {
		t.Fatalf("sender status lines = %q, want no relay regression after direct handoff", got)
	}
	if got := sessionStatusLines(listenerStatus.String()); hasSessionStatusPrefix(got, []string{string(StateWaiting), string(StateClaimed), string(StateRelay), string(StateDirect), string(StateRelay)}) {
		t.Fatalf("listener status lines = %q, want no relay regression after direct handoff", got)
	}
}

func TestExternalListenSendIgnoresLegacyParallelPolicyForDirectUDP(t *testing.T) {
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

	payload := bytes.Repeat([]byte("native-quic-parallel:"), (8*externalCopyBufferSize)/len("native-quic-parallel:"))
	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	midpoint := len(payload) / 2
	stdinReader := &sessionTestGatedReader{payload: payload, gateAt: midpoint, gate: func() error {
		for _, wait := range []struct {
			status *syncBuffer
			needle string
		}{
			{status: &senderStatus, needle: "udp-blast=true"},
			{status: &senderStatus, needle: string(StateDirect)},
			{status: &listenerStatus, needle: "udp-blast=true"},
			{status: &listenerStatus, needle: string(StateDirect)},
		} {
			if err := waitForSessionTestStatusContains(ctx, wait.status, wait.needle); err != nil {
				return fmt.Errorf("waiting for %q: %w; listener=%q sender=%q", wait.needle, err, listenerStatus.String(), senderStatus.String())
			}
		}
		return nil
	}}
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:          token,
			Emitter:        telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:        stdinReader,
			UsePublicDERP:  true,
			ParallelPolicy: FixedParallelPolicy(8),
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if !bytes.Equal(listenerOut.Bytes(), payload) {
		t.Fatalf("listener output length = %d, want %d", listenerOut.Len(), len(payload))
	}
	if got := senderStatus.String(); !strings.Contains(got, "udp-blast=true") {
		t.Fatalf("sender status = %q, want udp-blast=true", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, "udp-blast=true") {
		t.Fatalf("listener status = %q, want udp-blast=true", got)
	}
}

func TestExternalListenSendCompletesWhenDirectUDPSetupOverlapsTransfer(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")
	t.Setenv("DERPHOLE_NATIVE_QUIC_CONNS", "4")

	prevTCPAddrAllowed := externalNativeTCPAddrAllowed
	externalNativeTCPAddrAllowed = func(net.Addr) bool { return false }
	t.Cleanup(func() { externalNativeTCPAddrAllowed = prevTCPAddrAllowed })

	prevStripeCandidates := externalNativeQUICStripeProbeCandidates
	externalNativeQUICStripeProbeCandidates = func(ctx context.Context, packetConn net.PacketConn, _ *tailcfg.DERPMap, _ publicPortmap) []string {
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
			return nil
		}
		udpAddr := packetConn.LocalAddr().(*net.UDPAddr)
		return []string{net.JoinHostPort("127.0.0.1", fmt.Sprint(udpAddr.Port))}
	}
	t.Cleanup(func() { externalNativeQUICStripeProbeCandidates = prevStripeCandidates })

	prevLocalAddrCandidate := externalNativeQUICStripeCanUseLocalAddrCandidate
	externalNativeQUICStripeCanUseLocalAddrCandidate = func(net.Addr, net.Addr) bool {
		return false
	}
	t.Cleanup(func() { externalNativeQUICStripeCanUseLocalAddrCandidate = prevLocalAddrCandidate })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	payloadChunk := bytes.Repeat([]byte("relay-first-then-native-quic"), 1<<12)
	const chunkCount = 24
	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	payload := bytes.Repeat(payloadChunk, chunkCount)
	stdinReader := &sessionTestGatedReader{payload: payload, gateAt: len(payloadChunk), gate: func() error {
		if err := waitForSessionTestStatusContains(ctx, &senderStatus, string(StateDirect)); err != nil {
			return fmt.Errorf("waiting for sender direct state: %w; listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
		}
		return nil
	}}

	start := time.Now()
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:         token,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:       stdinReader,
			UsePublicDERP: true,
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if elapsed := time.Since(start); elapsed >= 7500*time.Millisecond {
		t.Fatalf("Send() elapsed = %v, want completion before context deadline while direct UDP setup overlaps transfer; listener=%q sender=%q", elapsed, listenerStatus.String(), senderStatus.String())
	}

	if got := listenerOut.Len(); got != len(payload) {
		t.Fatalf("listener output length = %d, want %d", got, len(payload))
	}
}

func waitForSessionTestStatusContains(ctx context.Context, status *syncBuffer, needle string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if strings.Contains(status.String(), needle) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type sessionTestGatedReader struct {
	payload []byte
	gateAt  int
	pos     int
	gated   bool
	gate    func() error
}

func (r *sessionTestGatedReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.payload) {
		return 0, io.EOF
	}
	if !r.gated && r.pos >= r.gateAt {
		if r.gate != nil {
			if err := r.gate(); err != nil {
				return 0, err
			}
		}
		r.gated = true
	}
	end := len(r.payload)
	if !r.gated && end > r.gateAt {
		end = r.gateAt
	}
	n := copy(p, r.payload[r.pos:end])
	r.pos += n
	return n, nil
}

func TestExternalListenSendUsesDirectUDPEvenWhenNativeTCPWouldBeAllowed(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")

	prevTCPAddrAllowed := externalNativeTCPAddrAllowed
	externalNativeTCPAddrAllowed = func(net.Addr) bool { return true }
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

	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer
	payload := bytes.Repeat([]byte("native-tcp-direct:"), 1<<16)

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	stdinReader, stdinWriter := io.Pipe()
	writerErr := make(chan error, 1)
	go func() {
		defer stdinWriter.Close()
		midpoint := len(payload) / 2
		if _, err := stdinWriter.Write(payload[:midpoint]); err != nil {
			writerErr <- err
			return
		}
		for _, wait := range []struct {
			status *syncBuffer
			needle string
		}{
			{status: &senderStatus, needle: "udp-blast=true"},
			{status: &senderStatus, needle: string(StateDirect)},
			{status: &listenerStatus, needle: "udp-blast=true"},
			{status: &listenerStatus, needle: string(StateDirect)},
		} {
			if err := waitForSessionTestStatusContains(ctx, wait.status, wait.needle); err != nil {
				writerErr <- fmt.Errorf("waiting for %q: %w; listener=%q sender=%q", wait.needle, err, listenerStatus.String(), senderStatus.String())
				return
			}
		}
		_, err := stdinWriter.Write(payload[midpoint:])
		writerErr <- err
	}()
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:         token,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:       stdinReader,
			UsePublicDERP: true,
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-writerErr; err != nil {
		t.Fatalf("stdin writer error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if !bytes.Equal(listenerOut.Bytes(), payload) {
		t.Fatalf("listener output length = %d, want %d", listenerOut.Len(), len(payload))
	}
	if got := senderStatus.String(); !strings.Contains(got, string(StateDirect)) || !strings.Contains(got, "udp-blast=true") || strings.Contains(got, "sender-tcp-direct") {
		t.Fatalf("sender status = %q, want direct UDP without native TCP direct", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, string(StateDirect)) || !strings.Contains(got, "udp-blast=true") || strings.Contains(got, "listener-tcp-direct") {
		t.Fatalf("listener status = %q, want direct UDP without native TCP direct", got)
	}
}

func TestExternalListenSendIgnoresRequestedParallelPolicyForDirectUDP(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")
	prevTCPAddrAllowed := externalNativeTCPAddrAllowed
	externalNativeTCPAddrAllowed = func(net.Addr) bool { return true }
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

	payload := bytes.Repeat([]byte("striped-native-tcp:"), 1<<15)
	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	stdinReader, stdinWriter := io.Pipe()
	writerErr := make(chan error, 1)
	go func() {
		defer stdinWriter.Close()
		midpoint := len(payload) / 2
		if _, err := stdinWriter.Write(payload[:midpoint]); err != nil {
			writerErr <- err
			return
		}
		for _, wait := range []struct {
			status *syncBuffer
			needle string
		}{
			{status: &senderStatus, needle: "udp-blast=true"},
			{status: &senderStatus, needle: string(StateDirect)},
			{status: &listenerStatus, needle: "udp-blast=true"},
			{status: &listenerStatus, needle: string(StateDirect)},
		} {
			if err := waitForSessionTestStatusContains(ctx, wait.status, wait.needle); err != nil {
				writerErr <- fmt.Errorf("waiting for %q: %w; listener=%q sender=%q", wait.needle, err, listenerStatus.String(), senderStatus.String())
				return
			}
		}
		_, err := stdinWriter.Write(payload[midpoint:])
		writerErr <- err
	}()
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:          token,
			Emitter:        telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:        stdinReader,
			UsePublicDERP:  true,
			ParallelPolicy: FixedParallelPolicy(4),
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-writerErr; err != nil {
		t.Fatalf("stdin writer error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if !bytes.Equal(listenerOut.Bytes(), payload) {
		t.Fatalf("listener output length = %d, want %d", listenerOut.Len(), len(payload))
	}
	if got := senderStatus.String(); !strings.Contains(got, "udp-blast=true") {
		t.Fatalf("sender status = %q, want udp-blast=true", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, "udp-blast=true") {
		t.Fatalf("listener status = %q, want udp-blast=true", got)
	}
}

func TestExternalListenSendUsesRelayUDPWhenDirectPromotionIsTooLate(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", strconv.FormatInt(time.Now().Add(externalDirectUDPWait+time.Second).UnixNano(), 10))

	prevTCPAddrAllowed := externalNativeTCPAddrAllowed
	externalNativeTCPAddrAllowed = func(net.Addr) bool { return false }
	t.Cleanup(func() { externalNativeTCPAddrAllowed = prevTCPAddrAllowed })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:         token,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:       bytes.NewReader([]byte("delayed-native-direct")),
			UsePublicDERP: true,
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if got := listenerOut.String(); got != "delayed-native-direct" {
		t.Fatalf("listener output = %q, want %q", got, "delayed-native-direct")
	}
	if got := senderStatus.String(); !strings.Contains(got, string(StateRelay)) || strings.Contains(got, "udp-relay=true") || strings.Contains(got, string(StateDirect)) || strings.Contains(got, "udp-stream=true") {
		t.Fatalf("sender status = %q, want relay-prefix completion without UDP fallback or direct promotion", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, string(StateRelay)) || strings.Contains(got, "udp-relay=true") || strings.Contains(got, string(StateDirect)) || strings.Contains(got, "udp-stream=true") {
		t.Fatalf("listener status = %q, want relay-prefix completion without UDP fallback or direct promotion", got)
	}
}

func TestExternalListenSendLargeRelayPayloadDoesNotStallWhenDirectPromotionTimesOut(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", strconv.FormatInt(time.Now().Add(externalDirectUDPWait+time.Second).UnixNano(), 10))

	prevTCPAddrAllowed := externalNativeTCPAddrAllowed
	externalNativeTCPAddrAllowed = func(net.Addr) bool { return false }
	t.Cleanup(func() { externalNativeTCPAddrAllowed = prevTCPAddrAllowed })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	payloadSize := externalHandoffMaxUnackedBytes + (16 << 20)
	payloadSeed := []byte("relay-prefix-large-delayed-direct:")
	payload := bytes.Repeat(payloadSeed, payloadSize/len(payloadSeed)+1)
	payload = payload[:payloadSize]

	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:         token,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:       bytes.NewReader(payload),
			UsePublicDERP: true,
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if !bytes.Equal(listenerOut.Bytes(), payload) {
		t.Fatalf("listener output length = %d, want %d", listenerOut.Len(), len(payload))
	}
	if got := senderStatus.String(); !strings.Contains(got, string(StateRelay)) || strings.Contains(got, "udp-relay=true") || strings.Contains(got, string(StateDirect)) || strings.Contains(got, "udp-stream=true") {
		t.Fatalf("sender status = %q, want relay-prefix completion without UDP fallback or direct promotion", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, string(StateRelay)) || strings.Contains(got, "udp-relay=true") || strings.Contains(got, string(StateDirect)) || strings.Contains(got, "udp-stream=true") {
		t.Fatalf("listener status = %q, want relay-prefix completion without UDP fallback or direct promotion", got)
	}
}

func TestTransportPathEmitterCompletionIsTerminal(t *testing.T) {
	var status bytes.Buffer
	emitter := newTransportPathEmitter(telemetry.New(&status, telemetry.LevelDefault))

	emitter.Handle(transport.PathRelay)
	emitter.Complete(nil)
	emitter.Handle(transport.PathDirect)
	emitter.Emit(StateDirect)

	if got := sessionStatusLines(status.String()); len(got) != 2 || got[0] != string(StateRelay) || got[1] != string(StateComplete) {
		t.Fatalf("status lines = %q, want [%q %q]", got, StateRelay, StateComplete)
	}
}

func TestTransportPathEmitterCanSuppressTemporaryRelayRegression(t *testing.T) {
	var status bytes.Buffer
	emitter := newTransportPathEmitter(telemetry.New(&status, telemetry.LevelDefault))

	emitter.Handle(transport.PathRelay)
	emitter.Handle(transport.PathDirect)
	emitter.SuppressRelayRegression()
	emitter.Handle(transport.PathRelay)

	if got := sessionStatusLines(status.String()); len(got) != 2 || got[0] != string(StateRelay) || got[1] != string(StateDirect) {
		t.Fatalf("status lines = %q, want [%q %q] while relay regression suppressed", got, StateRelay, StateDirect)
	}

	emitter.ResumeRelayRegression()
	emitter.Handle(transport.PathRelay)

	if got := sessionStatusLines(status.String()); len(got) != 3 || got[0] != string(StateRelay) || got[1] != string(StateDirect) || got[2] != string(StateRelay) {
		t.Fatalf("status lines = %q, want [%q %q %q] after suppression lifted", got, StateRelay, StateDirect, StateRelay)
	}
}

func TestTransportPathEmitterCanSuppressWatcherDirectUntilExplicitEmit(t *testing.T) {
	var status bytes.Buffer
	emitter := newTransportPathEmitter(telemetry.New(&status, telemetry.LevelDefault))

	emitter.Handle(transport.PathRelay)
	emitter.SuppressWatcherDirect()
	emitter.Handle(transport.PathDirect)
	if got := sessionStatusLines(status.String()); len(got) != 1 || got[0] != string(StateRelay) {
		t.Fatalf("status lines = %q, want [%q] while watcher direct is suppressed", got, StateRelay)
	}

	emitter.Emit(StateDirect)
	if got := sessionStatusLines(status.String()); len(got) != 2 || got[0] != string(StateRelay) || got[1] != string(StateDirect) {
		t.Fatalf("status lines = %q, want [%q %q] after explicit direct emit", got, StateRelay, StateDirect)
	}

	emitter.ResumeWatcherDirect()
	emitter.Handle(transport.PathRelay)
	emitter.Handle(transport.PathDirect)
	if got := sessionStatusLines(status.String()); len(got) != 4 || got[2] != string(StateRelay) || got[3] != string(StateDirect) {
		t.Fatalf("status lines = %q, want relay/direct watcher updates after resume", got)
	}
}

func TestTransportPathEmitterCompleteDoesNotSynthesizeDirectWhileWatcherDirectSuppressed(t *testing.T) {
	var status bytes.Buffer
	emitter := newTransportPathEmitter(telemetry.New(&status, telemetry.LevelDefault))

	emitter.Handle(transport.PathRelay)
	emitter.SuppressWatcherDirect()
	manager := transport.NewManager(transport.ManagerConfig{})
	forceTransportManagerPathState(t, manager, transport.PathDirect)

	emitter.Complete(manager)

	if got := sessionStatusLines(status.String()); len(got) != 2 || got[0] != string(StateRelay) || got[1] != string(StateComplete) {
		t.Fatalf("status lines = %q, want [%q %q] without synthesized direct on completion", got, StateRelay, StateComplete)
	}
}

func forceTransportManagerPathState(t *testing.T, manager *transport.Manager, path transport.Path) {
	t.Helper()
	if manager == nil {
		t.Fatal("forceTransportManagerPathState() manager = nil")
	}

	stateField := reflect.ValueOf(manager).Elem().FieldByName("state")
	currentField := stateField.FieldByName("current")
	reflect.NewAt(currentField.Type(), unsafe.Pointer(currentField.UnsafeAddr())).Elem().SetInt(int64(path))
}

func TestPublicProbeCandidatesIncludesMappedCandidate(t *testing.T) {
	ctx := context.Background()
	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
	mapped := netip.MustParseAddrPort("198.51.100.10:54321")
	pm := portmap.NewForTest(&sessionFakePortmapMapper{have: true, external: mapped}, telemetry.New(io.Discard, telemetry.LevelVerbose))
	pm.SetLocalPort(4242)
	if changed := pm.Refresh(time.Now()); !changed {
		t.Fatal("initial portmap Refresh() changed = false, want true")
	}

	prev := gatherTraversalCandidates
	t.Cleanup(func() {
		gatherTraversalCandidates = prev
	})
	gatherTraversalCandidates = func(_ context.Context, gotConn net.PacketConn, _ *tailcfg.DERPMap, mappedFn func() (netip.AddrPort, bool)) ([]string, error) {
		if gotConn != conn {
			t.Fatalf("gatherTraversalCandidates() conn = %v, want live probe conn %v", gotConn, conn)
		}
		gotMapped, ok := mappedFn()
		if !ok {
			t.Fatal("gatherTraversalCandidates() mapped callback = false, want true")
		}
		if gotMapped != mapped {
			t.Fatalf("gatherTraversalCandidates() mapped callback = %v, want %v", gotMapped, mapped)
		}
		return []string{"100.64.0.11:5555", "203.0.113.11:5555", gotMapped.String(), "not-an-endpoint"}, nil
	}

	got := publicProbeCandidates(ctx, conn, &tailcfg.DERPMap{}, pm)
	if containsString(got, "100.64.0.11:5555") {
		t.Fatalf("publicProbeCandidates() = %v, want no default Tailscale CGNAT candidate", got)
	}
	if !containsString(got, "203.0.113.11:5555") {
		t.Fatalf("publicProbeCandidates() = %v, want gathered host:port candidate", got)
	}
	if !containsString(got, mapped.String()) {
		t.Fatalf("publicProbeCandidates() = %v, want mapped candidate %q", got, mapped)
	}
}

func TestPublicInitialProbeCandidatesDoesNotSynchronouslyGatherTraversalCandidates(t *testing.T) {
	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
	mapped := netip.MustParseAddrPort("198.51.100.10:54321")
	pm := &sessionLifecyclePortmap{have: true, snapshot: mapped}
	prevInterfaceAddrs := publicInterfaceAddrs
	publicInterfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.IPv4(203, 0, 113, 5), Mask: net.CIDRMask(24, 32)},
		}, nil
	}

	called := false
	prev := gatherTraversalCandidates
	gatherTraversalCandidates = func(context.Context, net.PacketConn, *tailcfg.DERPMap, func() (netip.AddrPort, bool)) ([]string, error) {
		called = true
		return []string{"203.0.113.10:4242"}, nil
	}
	t.Cleanup(func() {
		gatherTraversalCandidates = prev
		publicInterfaceAddrs = prevInterfaceAddrs
	})

	got := publicInitialProbeCandidates(conn, pm)
	if called {
		t.Fatal("publicInitialProbeCandidates() synchronously called gatherTraversalCandidates")
	}
	if !containsString(got, "203.0.113.5:4242") {
		t.Fatalf("publicInitialProbeCandidates() = %v, want public interface candidate", got)
	}
	if !containsString(got, mapped.String()) {
		t.Fatalf("publicInitialProbeCandidates() = %v, want mapped candidate %q", got, mapped)
	}
	if containsString(got, "203.0.113.10:4242") {
		t.Fatalf("publicInitialProbeCandidates() = %v, want no gathered traversal candidate", got)
	}
}

func TestPublicInitialProbeCandidatesKeepsPrivateInterfaceCandidates(t *testing.T) {
	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
	mapped := netip.MustParseAddrPort("198.51.100.10:54321")
	pm := &sessionLifecyclePortmap{have: true, snapshot: mapped}

	prevInterfaceAddrs := publicInterfaceAddrs
	publicInterfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.IPv4(10, 0, 4, 2), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.IPv4(172, 17, 0, 1), Mask: net.CIDRMask(16, 32)},
			&net.IPNet{IP: net.IPv4(192, 168, 1, 9), Mask: net.CIDRMask(24, 32)},
		}, nil
	}
	t.Cleanup(func() { publicInterfaceAddrs = prevInterfaceAddrs })

	got := publicInitialProbeCandidates(conn, pm)
	if containsString(got, "127.0.0.1:4242") {
		t.Fatalf("publicInitialProbeCandidates() = %v, want loopback excluded", got)
	}
	if !containsString(got, "10.0.4.2:4242") || !containsString(got, "172.17.0.1:4242") || !containsString(got, "192.168.1.9:4242") {
		t.Fatalf("publicInitialProbeCandidates() = %v, want private interface candidates preserved for same-LAN direct paths", got)
	}
	if !containsString(got, mapped.String()) {
		t.Fatalf("publicInitialProbeCandidates() = %v, want mapped candidate %q", got, mapped)
	}
}

func TestPublicInitialProbeCandidatesKeepsLoopbackForFakeTransport(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")

	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}

	prevInterfaceAddrs := publicInterfaceAddrs
	publicInterfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)},
		}, nil
	}
	t.Cleanup(func() { publicInterfaceAddrs = prevInterfaceAddrs })

	got := publicInitialProbeCandidates(conn, nil)
	if !containsString(got, "127.0.0.1:4242") {
		t.Fatalf("publicInitialProbeCandidates() = %v, want loopback preserved for fake transport direct candidates", got)
	}
}

func TestPublicCandidateSourceRefreshesDynamicProbeCandidatesForRealSessions(t *testing.T) {
	ctx := context.Background()
	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
	localCandidates := []net.Addr{&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}

	call := 0
	prev := gatherTraversalCandidates
	gatherTraversalCandidates = func(context.Context, net.PacketConn, *tailcfg.DERPMap, func() (netip.AddrPort, bool)) ([]string, error) {
		call++
		if call == 1 {
			return []string{"203.0.113.10:4242"}, nil
		}
		return []string{"203.0.113.11:4242"}, nil
	}
	t.Cleanup(func() {
		gatherTraversalCandidates = prev
	})

	source := publicCandidateSource(conn, &tailcfg.DERPMap{}, nil, localCandidates, nil)
	first := source(ctx)
	second := source(ctx)

	if !containsAddrString(first, "203.0.113.10:4242") {
		t.Fatalf("first publicCandidateSource() = %v, want refreshed candidate 203.0.113.10:4242", first)
	}
	if containsAddrString(first, "203.0.113.11:4242") {
		t.Fatalf("first publicCandidateSource() = %v, want no second refresh candidate", first)
	}
	if !containsAddrString(second, "203.0.113.11:4242") {
		t.Fatalf("second publicCandidateSource() = %v, want refreshed candidate 203.0.113.11:4242", second)
	}
}

func TestPublicCandidateSourceRefreshesTraversalCandidatesFromSTUNPackets(t *testing.T) {
	ctx := context.Background()
	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
	localCandidates := []net.Addr{&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
	stunPackets := make(chan traversal.STUNPacket, 1)

	directGatherCalled := false
	prevDirectGather := gatherTraversalCandidates
	gatherTraversalCandidates = func(context.Context, net.PacketConn, *tailcfg.DERPMap, func() (netip.AddrPort, bool)) ([]string, error) {
		directGatherCalled = true
		return nil, errors.New("unexpected direct traversal gather")
	}
	t.Cleanup(func() {
		gatherTraversalCandidates = prevDirectGather
	})

	prevSTUNGather := gatherTraversalCandidatesFromSTUNPackets
	gatherTraversalCandidatesFromSTUNPackets = func(
		gotCtx context.Context,
		gotConn net.PacketConn,
		_ *tailcfg.DERPMap,
		_ func() (netip.AddrPort, bool),
		gotPackets <-chan traversal.STUNPacket,
	) ([]string, error) {
		deadline, ok := gotCtx.Deadline()
		if !ok {
			t.Fatal("gatherTraversalCandidatesFromSTUNPackets() ctx has no deadline, want bounded timeout context")
		}
		if remaining := time.Until(deadline); remaining <= 0 || remaining > externalPublicCandidateRefreshWait {
			t.Fatalf("gatherTraversalCandidatesFromSTUNPackets() deadline in %s, want <= %s", remaining, externalPublicCandidateRefreshWait)
		}
		if gotConn != conn {
			t.Fatalf("gatherTraversalCandidatesFromSTUNPackets() conn = %v, want %v", gotConn, conn)
		}
		if gotPackets != stunPackets {
			t.Fatalf("gatherTraversalCandidatesFromSTUNPackets() packets = %v, want %v", gotPackets, stunPackets)
		}
		return []string{"203.0.113.12:4242"}, nil
	}
	t.Cleanup(func() {
		gatherTraversalCandidatesFromSTUNPackets = prevSTUNGather
	})

	source := publicCandidateSource(conn, &tailcfg.DERPMap{}, nil, localCandidates, stunPackets)
	got := source(ctx)

	if directGatherCalled {
		t.Fatal("publicCandidateSource() called direct traversal gather with STUN packet channel present")
	}
	if !containsAddrString(got, "203.0.113.12:4242") {
		t.Fatalf("publicCandidateSource() = %v, want STUN packet gathered candidate 203.0.113.12:4242", got)
	}
}

func TestPublicCandidateSourceAllowsLongEnoughTraversalGatherWindow(t *testing.T) {
	ctx := context.Background()
	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
	localCandidates := []net.Addr{&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
	stunPackets := make(chan traversal.STUNPacket, 1)

	prevSTUNGather := gatherTraversalCandidatesFromSTUNPackets
	gatherTraversalCandidatesFromSTUNPackets = func(
		gotCtx context.Context,
		gotConn net.PacketConn,
		_ *tailcfg.DERPMap,
		_ func() (netip.AddrPort, bool),
		gotPackets <-chan traversal.STUNPacket,
	) ([]string, error) {
		deadline, ok := gotCtx.Deadline()
		if !ok {
			t.Fatal("gatherTraversalCandidatesFromSTUNPackets() ctx has no deadline, want bounded timeout context")
		}
		if remaining := time.Until(deadline); remaining < 500*time.Millisecond {
			t.Fatalf("gatherTraversalCandidatesFromSTUNPackets() deadline in %s, want at least 500ms for traversal gather", remaining)
		}
		if gotConn != conn {
			t.Fatalf("gatherTraversalCandidatesFromSTUNPackets() conn = %v, want %v", gotConn, conn)
		}
		if gotPackets != stunPackets {
			t.Fatalf("gatherTraversalCandidatesFromSTUNPackets() packets = %v, want %v", gotPackets, stunPackets)
		}
		return []string{"203.0.113.12:4242"}, nil
	}
	t.Cleanup(func() {
		gatherTraversalCandidatesFromSTUNPackets = prevSTUNGather
	})

	source := publicCandidateSource(conn, &tailcfg.DERPMap{}, nil, localCandidates, stunPackets)
	got := source(ctx)

	if !containsAddrString(got, "203.0.113.12:4242") {
		t.Fatalf("publicCandidateSource() = %v, want STUN packet gathered candidate 203.0.113.12:4242", got)
	}
}

func TestPublicCandidateSourceReturnsQuicklyWhenSTUNGatherBlocks(t *testing.T) {
	parentCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
	localCandidates := []net.Addr{&net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 4242}}
	stunPackets := make(chan traversal.STUNPacket)

	prevInterfaceAddrs := publicInterfaceAddrs
	publicInterfaceAddrs = func() ([]net.Addr, error) { return nil, nil }
	t.Cleanup(func() { publicInterfaceAddrs = prevInterfaceAddrs })

	prevSTUNGather := gatherTraversalCandidatesFromSTUNPackets
	gatherTraversalCandidatesFromSTUNPackets = func(
		gotCtx context.Context,
		_ net.PacketConn,
		_ *tailcfg.DERPMap,
		_ func() (netip.AddrPort, bool),
		_ <-chan traversal.STUNPacket,
	) ([]string, error) {
		<-gotCtx.Done()
		return nil, gotCtx.Err()
	}
	t.Cleanup(func() {
		gatherTraversalCandidatesFromSTUNPackets = prevSTUNGather
	})

	source := publicCandidateSource(conn, &tailcfg.DERPMap{}, nil, localCandidates, stunPackets)
	started := time.Now()
	resultCh := make(chan []net.Addr, 1)
	go func() {
		resultCh <- source(parentCtx)
	}()

	select {
	case got := <-resultCh:
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("publicCandidateSource() took %s, want sub-second fallback when STUN gather blocks", elapsed)
		}
		if !containsAddrString(got, "203.0.113.10:4242") {
			t.Fatalf("publicCandidateSource() = %v, want fallback public candidate 203.0.113.10:4242", got)
		}
	case <-time.After(time.Second):
		cancel()
		<-resultCh
		t.Fatal("publicCandidateSource() blocked for >=1s while STUN gather was stalled")
	}
}

func TestPublicProbeCandidatesSkipsTailscaleCGNATInInternetOnlyTestMode(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES", "1")

	ctx := context.Background()
	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}

	prev := gatherTraversalCandidates
	t.Cleanup(func() {
		gatherTraversalCandidates = prev
	})
	gatherTraversalCandidates = func(context.Context, net.PacketConn, *tailcfg.DERPMap, func() (netip.AddrPort, bool)) ([]string, error) {
		return []string{
			"100.64.0.11:5555",
			"100.125.235.82:4242",
			"192.0.2.10:5555",
		}, nil
	}

	got := publicProbeCandidates(ctx, conn, &tailcfg.DERPMap{}, nil)
	if containsCGNATCandidate(got) {
		t.Fatalf("publicProbeCandidates() = %v, want no 100.64.0.0/10 candidates", got)
	}
	if !containsString(got, "192.0.2.10:5555") {
		t.Fatalf("publicProbeCandidates() = %v, want non-CGNAT gathered candidate", got)
	}
}

func TestPublicProbeCandidateAllowedSkipsTailscaleByDefault(t *testing.T) {
	if publicProbeCandidateAllowed(netip.MustParseAddr("100.125.235.82")) {
		t.Fatal("publicProbeCandidateAllowed(100.125.235.82) = true, want false by default")
	}
	if publicProbeCandidateAllowed(netip.MustParseAddr("fd7a:115c:a1e0::1")) {
		t.Fatal("publicProbeCandidateAllowed(fd7a:115c:a1e0::1) = true, want false by default")
	}
	if !publicProbeCandidateAllowed(netip.MustParseAddr("203.0.113.10")) {
		t.Fatal("publicProbeCandidateAllowed(203.0.113.10) = false, want true")
	}
}

func TestPublicProbeCandidateAllowedCanEnableTailscaleExplicitly(t *testing.T) {
	t.Setenv("DERPHOLE_ENABLE_TAILSCALE_CANDIDATES", "1")

	if !publicProbeCandidateAllowed(netip.MustParseAddr("100.125.235.82")) {
		t.Fatal("publicProbeCandidateAllowed(100.125.235.82) = false, want true when DERPHOLE_ENABLE_TAILSCALE_CANDIDATES=1")
	}
	if !publicProbeCandidateAllowed(netip.MustParseAddr("fd7a:115c:a1e0::1")) {
		t.Fatal("publicProbeCandidateAllowed(fd7a:115c:a1e0::1) = false, want true when DERPHOLE_ENABLE_TAILSCALE_CANDIDATES=1")
	}
}

func TestIssuePublicSessionAttachesAndClosesPortmap(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	prevCtor := newPublicPortmap
	fake := &sessionLifecyclePortmap{
		have:     true,
		snapshot: netip.MustParseAddrPort("198.51.100.10:54321"),
	}
	newPublicPortmap = func(*telemetry.Emitter) publicPortmap { return fake }
	t.Cleanup(func() { newPublicPortmap = prevCtor })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, session, err := issuePublicSession(ctx)
	if err != nil {
		t.Fatalf("issuePublicSession() error = %v", err)
	}
	defer session.derp.Close()

	pm := publicSessionPortmap(session)
	if pm == nil {
		t.Fatal("publicSessionPortmap() = nil, want attached portmap")
	}
	if pm != fake {
		t.Fatalf("publicSessionPortmap() = %T, want fake portmap", pm)
	}

	wantPort := uint16(session.probeConn.LocalAddr().(*net.UDPAddr).Port)
	if got := fake.localPort; got != wantPort {
		t.Fatalf("SetLocalPort() = %d, want %d", got, wantPort)
	}

	closePublicSessionTransport(session)
	closePublicSessionTransport(session)

	if got, want := fake.closeCalls, 1; got != want {
		t.Fatalf("Close() calls = %d, want %d", got, want)
	}
	if publicSessionPortmap(session) != nil {
		t.Fatal("publicSessionPortmap() after close = non-nil, want nil")
	}
}

func TestIssuePublicShareSessionUsesQUICIdentityInToken(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tokStr, session, err := issuePublicShareSession(ctx, ShareConfig{})
	if err != nil {
		t.Fatalf("issuePublicShareSession() error = %v", err)
	}
	defer session.derp.Close()
	defer closePublicSessionTransport(session)

	tok, err := token.Decode(tokStr, time.Now())
	if err != nil {
		t.Fatalf("token.Decode() error = %v", err)
	}
	if tok.QUICPublic != session.quicIdentity.Public {
		t.Fatalf("token QUIC public = %x, want quic identity %x", tok.QUICPublic, session.quicIdentity.Public)
	}
}

func TestNewBoundPublicPortmapDoesNotSynchronouslyRefresh(t *testing.T) {
	prevCtor := newPublicPortmap
	fake := &sessionLifecyclePortmap{refreshDelay: 250 * time.Millisecond}
	newPublicPortmap = func(*telemetry.Emitter) publicPortmap { return fake }
	t.Cleanup(func() { newPublicPortmap = prevCtor })

	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
	started := time.Now()
	pm := newBoundPublicPortmap(conn, telemetry.New(io.Discard, telemetry.LevelVerbose))
	if pm == nil {
		t.Fatal("newBoundPublicPortmap() = nil, want portmap")
	}

	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("newBoundPublicPortmap() took %s, want non-blocking startup", elapsed)
	}
	if got := fake.localPort; got != 4242 {
		t.Fatalf("SetLocalPort() = %d, want 4242", got)
	}
}

func TestExternalNativeQUICConnCountUsesEnvOverride(t *testing.T) {
	t.Setenv("DERPHOLE_NATIVE_QUIC_CONNS", "8")

	if got := externalNativeQUICConnCount(); got != 8 {
		t.Fatalf("externalNativeQUICConnCount() = %d, want 8", got)
	}
}

func TestExternalNativeQUICConnCountIgnoresInvalidEnvOverride(t *testing.T) {
	t.Setenv("DERPHOLE_NATIVE_QUIC_CONNS", "0")

	if got := externalNativeQUICConnCount(); got != defaultExternalNativeQUICConns {
		t.Fatalf("externalNativeQUICConnCount() = %d, want %d", got, defaultExternalNativeQUICConns)
	}
}

func TestExternalNativeQUICConnCountKeepsFakeTransportSingleConn(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_NATIVE_QUIC_CONNS", "8")

	if got := externalNativeQUICConnCount(); got != 1 {
		t.Fatalf("externalNativeQUICConnCount() = %d, want 1", got)
	}
}

func TestExternalNativeQUICConnCountForPeerKeepsStripingForPublicPeer(t *testing.T) {
	peerAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 3478}

	if got := externalNativeQUICConnCountForPeer(peerAddr, 4); got != 4 {
		t.Fatalf("externalNativeQUICConnCountForPeer() = %d, want 4", got)
	}
}

func TestExternalNativeQUICConnCountForPeerKeepsStripingForRouteLocalPeer(t *testing.T) {
	peerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}

	if got := externalNativeQUICConnCountForPeer(peerAddr, 4); got != 4 {
		t.Fatalf("externalNativeQUICConnCountForPeer() = %d, want 4", got)
	}
}

func TestExternalNativeTCPConnCountUsesEnvOverride(t *testing.T) {
	t.Setenv("DERPHOLE_NATIVE_TCP_CONNS", "4")

	if got := externalNativeTCPConnCount(); got != 4 {
		t.Fatalf("externalNativeTCPConnCount() = %d, want 4", got)
	}
}

func TestExternalNativeTCPConnCountDefaultsToTwo(t *testing.T) {
	t.Setenv("DERPHOLE_NATIVE_TCP_CONNS", "")

	if got := externalNativeTCPConnCount(); got != 2 {
		t.Fatalf("externalNativeTCPConnCount() = %d, want 2", got)
	}
}

func TestExternalNativeTCPConnCountIgnoresInvalidEnvOverride(t *testing.T) {
	t.Setenv("DERPHOLE_NATIVE_TCP_CONNS", "0")

	if got := externalNativeTCPConnCount(); got != defaultExternalNativeTCPConns {
		t.Fatalf("externalNativeTCPConnCount() = %d, want %d", got, defaultExternalNativeTCPConns)
	}
}

func TestExternalNativeTCPHandshakeConnCountNegotiatesMinimumPositive(t *testing.T) {
	t.Parallel()

	if got := externalNativeTCPHandshakeConnCount(1, 2); got != 1 {
		t.Fatalf("externalNativeTCPHandshakeConnCount(1, 2) = %d, want 1", got)
	}
	if got := externalNativeTCPHandshakeConnCount(4, 2); got != 2 {
		t.Fatalf("externalNativeTCPHandshakeConnCount(4, 2) = %d, want 2", got)
	}
	if got := externalNativeTCPHandshakeConnCount(0, 2); got != 2 {
		t.Fatalf("externalNativeTCPHandshakeConnCount(0, 2) = %d, want 2", got)
	}
	if got := externalNativeTCPHandshakeConnCount(-1, 2); got != 2 {
		t.Fatalf("externalNativeTCPHandshakeConnCount(-1, 2) = %d, want 2", got)
	}
	if got := externalNativeTCPHandshakeConnCount(2, 0); got != 1 {
		t.Fatalf("externalNativeTCPHandshakeConnCount(2, 0) = %d, want 1", got)
	}
}

func TestExternalNativeTCPPassiveConnCountFollowsPeerRequestByDefault(t *testing.T) {
	t.Setenv("DERPHOLE_NATIVE_TCP_CONNS", "")

	if got := externalNativeTCPPassiveConnCount(8); got != 8 {
		t.Fatalf("externalNativeTCPPassiveConnCount(8) = %d, want 8", got)
	}
	if got := externalNativeTCPPassiveConnCount(12); got != 12 {
		t.Fatalf("externalNativeTCPPassiveConnCount(12) = %d, want 12", got)
	}
}

func TestExternalNativeTCPPassiveConnCountCapsAtLocalOverride(t *testing.T) {
	t.Setenv("DERPHOLE_NATIVE_TCP_CONNS", "6")

	if got := externalNativeTCPPassiveConnCount(8); got != 6 {
		t.Fatalf("externalNativeTCPPassiveConnCount(8) = %d, want 6", got)
	}
}

func TestExternalNativeTCPPassiveConnCountCapsAtMaxParallelStripes(t *testing.T) {
	t.Setenv("DERPHOLE_NATIVE_TCP_CONNS", "")

	if got := externalNativeTCPPassiveConnCount(MaxParallelStripes + 4); got != MaxParallelStripes {
		t.Fatalf("externalNativeTCPPassiveConnCount(%d) = %d, want %d", MaxParallelStripes+4, got, MaxParallelStripes)
	}
}

func TestExternalNativeTCPPassiveConnCountDefaultsForLegacyPeer(t *testing.T) {
	t.Setenv("DERPHOLE_NATIVE_TCP_CONNS", "")

	if got := externalNativeTCPPassiveConnCount(0); got != defaultExternalNativeTCPConns {
		t.Fatalf("externalNativeTCPPassiveConnCount(0) = %d, want %d", got, defaultExternalNativeTCPConns)
	}
}

func TestExternalNativeTCPAddrAllowedDefaultAcceptsRouteLocalAndPublicAddresses(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want bool
	}{
		{name: "loopback", addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}, want: true},
		{name: "private", addr: &net.UDPAddr{IP: net.IPv4(10, 0, 4, 2), Port: 12345}, want: true},
		{name: "tailscale-cgnat", addr: &net.UDPAddr{IP: net.IPv4(100, 88, 145, 8), Port: 12345}, want: true},
		{name: "public-internet", addr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 12345}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := externalNativeTCPAddrAllowedDefault(tt.addr); got != tt.want {
				t.Fatalf("externalNativeTCPAddrAllowedDefault(%v) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestListenExternalNativeTCPOnCandidatesPrefersTailscaleCandidate(t *testing.T) {
	prevListen := externalNativeTCPListen
	externalNativeTCPListen = func(addr net.Addr, _ *tls.Config) (net.Listener, error) {
		tcpAddr, _, ok := externalNativeTCPAddr(addr)
		if !ok {
			return nil, errors.New("native tcp direct address unavailable")
		}
		return &testAddrListener{addr: tcpAddr}, nil
	}
	t.Cleanup(func() {
		externalNativeTCPListen = prevListen
	})

	ln, ok := listenExternalNativeTCPOnCandidates([]net.Addr{
		&net.UDPAddr{IP: net.IPv4(10, 0, 1, 254), Port: 12345},
		&net.UDPAddr{IP: net.IPv4(100, 125, 235, 82), Port: 12345},
	}, nil)
	if !ok {
		t.Fatal("listenExternalNativeTCPOnCandidates() ok = false, want true")
	}
	defer ln.Close()

	got := ln.Addr().(*net.TCPAddr)
	if got.IP.String() != "100.125.235.82" {
		t.Fatalf("listenExternalNativeTCPOnCandidates() addr = %v, want 100.125.235.82", got)
	}
}

func TestListenExternalNativeTCPOnCandidatesPrefersPrivateCandidateOverLoopback(t *testing.T) {
	prevListen := externalNativeTCPListen
	externalNativeTCPListen = func(addr net.Addr, _ *tls.Config) (net.Listener, error) {
		tcpAddr, _, ok := externalNativeTCPAddr(addr)
		if !ok {
			return nil, errors.New("native tcp direct address unavailable")
		}
		return &testAddrListener{addr: tcpAddr}, nil
	}
	t.Cleanup(func() {
		externalNativeTCPListen = prevListen
	})

	ln, ok := listenExternalNativeTCPOnCandidates([]net.Addr{
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
		&net.UDPAddr{IP: net.IPv4(10, 0, 4, 184), Port: 12345},
	}, nil)
	if !ok {
		t.Fatal("listenExternalNativeTCPOnCandidates() ok = false, want true")
	}
	defer ln.Close()

	got := ln.Addr().(*net.TCPAddr)
	if got.IP.String() != "10.0.4.184" {
		t.Fatalf("listenExternalNativeTCPOnCandidates() addr = %v, want 10.0.4.184", got)
	}
}

func TestListenExternalNativeTCPOnCandidatesFallsBackWhenPreferredPortIsBusy(t *testing.T) {
	busy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer busy.Close()

	busyPort := busy.Addr().(*net.TCPAddr).Port
	ln, ok := listenExternalNativeTCPOnCandidates([]net.Addr{
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: busyPort},
	}, nil)
	if !ok {
		t.Fatal("listenExternalNativeTCPOnCandidates() ok = false, want true")
	}
	defer ln.Close()

	got := ln.Addr().(*net.TCPAddr)
	if !got.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("listenExternalNativeTCPOnCandidates() IP = %v, want 127.0.0.1", got.IP)
	}
	if got.Port == busyPort {
		t.Fatalf("listenExternalNativeTCPOnCandidates() port = %d, want fallback away from busy port %d", got.Port, busyPort)
	}
}

func TestListenExternalNativeTCPOnCandidatesUsesBindOverride(t *testing.T) {
	prevListen := externalNativeTCPListen
	externalNativeTCPListen = func(addr net.Addr, _ *tls.Config) (net.Listener, error) {
		tcpAddr, _, ok := externalNativeTCPAddr(addr)
		if !ok {
			return nil, errors.New("native tcp direct address unavailable")
		}
		return &testAddrListener{addr: tcpAddr}, nil
	}
	t.Cleanup(func() {
		externalNativeTCPListen = prevListen
	})
	t.Setenv(externalNativeTCPBindAddrEnv, "127.0.0.1:8321")

	ln, ok := listenExternalNativeTCPOnCandidates([]net.Addr{
		&net.UDPAddr{IP: net.IPv4(10, 0, 4, 184), Port: 12345},
	}, nil)
	if !ok {
		t.Fatal("listenExternalNativeTCPOnCandidates() ok = false, want true")
	}
	defer ln.Close()

	got := ln.Addr().(*net.TCPAddr)
	if got.String() != "127.0.0.1:8321" {
		t.Fatalf("listenExternalNativeTCPOnCandidates() addr = %v, want 127.0.0.1:8321", got)
	}
}

type testAddrListener struct {
	net.Listener
	addr net.Addr
}

func (l *testAddrListener) Accept() (net.Conn, error) {
	return nil, net.ErrClosed
}

func (l *testAddrListener) Close() error {
	return nil
}

func (l *testAddrListener) Addr() net.Addr {
	return l.addr
}

func TestSelectExternalNativeTCPResponseAddrPrefersRequestRoute(t *testing.T) {
	got := selectExternalNativeTCPResponseAddr(
		&net.UDPAddr{IP: net.IPv4(100, 125, 235, 82), Port: 53600},
		&net.UDPAddr{IP: net.IPv4(10, 0, 1, 254), Port: 61216},
		[]net.Addr{
			&net.UDPAddr{IP: net.IPv4(10, 0, 4, 2), Port: 41678},
			&net.UDPAddr{IP: net.IPv4(100, 88, 145, 8), Port: 41678},
		},
	)
	if got == nil {
		t.Fatal("selectExternalNativeTCPResponseAddr() = nil, want 100.88.145.8:41678")
	}
	if got.String() != "100.88.145.8:41678" {
		t.Fatalf("selectExternalNativeTCPResponseAddr() = %v, want 100.88.145.8:41678", got)
	}
}

func TestSelectExternalNativeTCPResponseAddrRejectsLoopbackRequestWithoutLoopbackPeerRoute(t *testing.T) {
	got := selectExternalNativeTCPResponseAddr(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53600},
		&net.UDPAddr{IP: net.IPv4(68, 20, 14, 192), Port: 61216},
		[]net.Addr{
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41678},
			&net.UDPAddr{IP: net.IPv4(192, 168, 1, 143), Port: 41678},
		},
	)
	if got != nil {
		t.Fatalf("selectExternalNativeTCPResponseAddr() = %v, want nil", got)
	}
}

func TestSelectExternalNativeTCPResponseAddrPrefersSamePrivateSubnetAsRequest(t *testing.T) {
	got := selectExternalNativeTCPResponseAddr(
		&net.UDPAddr{IP: net.IPv4(10, 0, 4, 2), Port: 37672},
		nil,
		[]net.Addr{
			&net.UDPAddr{IP: net.IPv4(10, 0, 1, 254), Port: 53246},
			&net.UDPAddr{IP: net.IPv4(10, 0, 4, 184), Port: 53246},
		},
	)
	if got == nil {
		t.Fatal("selectExternalNativeTCPResponseAddr() = nil, want 10.0.4.184:53246")
	}
	if got.String() != "10.0.4.184:53246" {
		t.Fatalf("selectExternalNativeTCPResponseAddr() = %v, want 10.0.4.184:53246", got)
	}
}

func TestSelectExternalNativeTCPResponseAddrPrefersPublicPeerRouteOverPrivateRequestRoute(t *testing.T) {
	got := selectExternalNativeTCPResponseAddr(
		&net.UDPAddr{IP: net.IPv4(10, 0, 1, 254), Port: 54321},
		&net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4433},
		[]net.Addr{
			&net.UDPAddr{IP: net.IPv4(172, 17, 0, 1), Port: 45000},
			&net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 45001},
		},
	)
	if got == nil {
		t.Fatal("selectExternalNativeTCPResponseAddr() = nil, want 198.51.100.10:45001")
	}
	if got.String() != "198.51.100.10:45001" {
		t.Fatalf("selectExternalNativeTCPResponseAddr() = %v, want 198.51.100.10:45001", got)
	}
}

func TestSelectExternalNativeTCPOfferAddrUsesBindOverride(t *testing.T) {
	t.Setenv(externalNativeTCPBindAddrEnv, "127.0.0.1:8321")

	got := selectExternalNativeTCPOfferAddr([]net.Addr{
		&net.UDPAddr{IP: net.IPv4(10, 0, 4, 184), Port: 45001},
	})
	if got == nil {
		t.Fatal("selectExternalNativeTCPOfferAddr() = nil, want override address")
	}
	if got.String() != "127.0.0.1:8321" {
		t.Fatalf("selectExternalNativeTCPOfferAddr() = %v, want 127.0.0.1:8321", got)
	}
}

func TestSelectExternalNativeTCPOfferAddrFallsBackToCandidates(t *testing.T) {
	got := selectExternalNativeTCPOfferAddr([]net.Addr{
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45001},
		&net.UDPAddr{IP: net.IPv4(10, 0, 4, 184), Port: 45001},
	})
	if got == nil {
		t.Fatal("selectExternalNativeTCPOfferAddr() = nil, want candidate address")
	}
	if got.String() != "10.0.4.184:45001" {
		t.Fatalf("selectExternalNativeTCPOfferAddr() = %v, want 10.0.4.184:45001", got)
	}
}

func TestExternalNativeTCPAdvertiseAddrUsesOverride(t *testing.T) {
	t.Setenv(externalNativeTCPAdvertiseAddrEnv, "108.18.210.19:8321")

	got := externalNativeTCPAdvertiseAddr(
		&net.TCPAddr{IP: net.IPv4(192, 168, 4, 29), Port: 8321},
		&net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4433},
	)
	if got == nil {
		t.Fatal("externalNativeTCPAdvertiseAddr() = nil, want override address")
	}
	if got.String() != "108.18.210.19:8321" {
		t.Fatalf("externalNativeTCPAdvertiseAddr() = %v, want 108.18.210.19:8321", got)
	}
}

func TestExternalNativeTCPAdvertiseAddrFallsBackToBoundAddr(t *testing.T) {
	got := externalNativeTCPAdvertiseAddr(
		&net.TCPAddr{IP: net.IPv4(192, 168, 4, 29), Port: 8321},
		&net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4433},
	)
	if got == nil {
		t.Fatal("externalNativeTCPAdvertiseAddr() = nil, want bound address")
	}
	if got.String() != "192.168.4.29:8321" {
		t.Fatalf("externalNativeTCPAdvertiseAddr() = %v, want 192.168.4.29:8321", got)
	}
}

func TestExternalNativeTCPCopyChunkSizeUsesEnvOverride(t *testing.T) {
	t.Setenv("DERPHOLE_NATIVE_TCP_CHUNK_SIZE", "262144")

	if got := externalNativeTCPCopyChunkSize(); got != 262144 {
		t.Fatalf("externalNativeTCPCopyChunkSize() = %d, want 262144", got)
	}
}

func TestExternalNativeTCPCopyChunkSizeFallsBackOnInvalidOverride(t *testing.T) {
	t.Setenv("DERPHOLE_NATIVE_TCP_CHUNK_SIZE", "nope")

	if got := externalNativeTCPCopyChunkSize(); got != externalNativeTCPCopyBufferSizeDefault {
		t.Fatalf("externalNativeTCPCopyChunkSize() = %d, want %d", got, externalNativeTCPCopyBufferSizeDefault)
	}
}

func TestSelectExternalQUICModeResponseAddrReturnsNilWhenNoRouteCompatibleOrPublicCandidateExists(t *testing.T) {
	got := selectExternalQUICModeResponseAddr(
		&net.UDPAddr{IP: net.IPv4(68, 20, 14, 192), Port: 53412},
		[]net.Addr{
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41757},
			&net.UDPAddr{IP: net.IPv4(192, 168, 1, 143), Port: 41757},
		},
	)
	if got != nil {
		t.Fatalf("selectExternalQUICModeResponseAddr() = %v, want nil", got)
	}
}

func TestConnectExternalNativeTCPConnsEstablishesStripedConnectionsWithBidirectionalFallback(t *testing.T) {
	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(sender) error = %v", err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(listener) error = %v", err)
	}

	senderListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(sender) error = %v", err)
	}
	defer senderListener.Close()
	senderListener = tls.NewListener(senderListener, quicpath.ServerTLSConfig(senderIdentity, listenerIdentity.Public))

	listenerListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(listener) error = %v", err)
	}
	defer listenerListener.Close()
	listenerListener = tls.NewListener(listenerListener, quicpath.ServerTLSConfig(listenerIdentity, senderIdentity.Public))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	senderResult := make(chan []net.Conn, 1)
	senderErr := make(chan error, 1)
	go func() {
		conns, err := connectExternalNativeTCPConns(
			ctx,
			senderListener,
			listenerListener.Addr(),
			quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public),
			externalNativeTCPAuth{},
			0,
			4,
		)
		senderResult <- conns
		senderErr <- err
	}()

	listenerResult := make(chan []net.Conn, 1)
	listenerErr := make(chan error, 1)
	go func() {
		conns, err := connectExternalNativeTCPConns(
			ctx,
			listenerListener,
			senderListener.Addr(),
			quicpath.ClientTLSConfig(listenerIdentity, senderIdentity.Public),
			externalNativeTCPAuth{},
			25*time.Millisecond,
			4,
		)
		listenerResult <- conns
		listenerErr <- err
	}()

	senderConns := <-senderResult
	defer closeExternalNativeTCPConns(senderConns)
	if err := <-senderErr; err != nil {
		t.Fatalf("connectExternalNativeTCPConns(sender) error = %v", err)
	}
	if got := len(senderConns); got != 4 {
		t.Fatalf("connectExternalNativeTCPConns(sender) len = %d, want 4", got)
	}

	listenerConns := <-listenerResult
	defer closeExternalNativeTCPConns(listenerConns)
	if err := <-listenerErr; err != nil {
		t.Fatalf("connectExternalNativeTCPConns(listener) error = %v", err)
	}
	if got := len(listenerConns); got != 4 {
		t.Fatalf("connectExternalNativeTCPConns(listener) len = %d, want 4", got)
	}

	payload := []byte("x")
	for i := range senderConns {
		if _, err := senderConns[i].Write(payload); err != nil {
			t.Fatalf("senderConns[%d].Write() error = %v", i, err)
		}
	}
	for i := range listenerConns {
		var got [1]byte
		if _, err := io.ReadFull(listenerConns[i], got[:]); err != nil {
			t.Fatalf("listenerConns[%d] ReadFull() error = %v", i, err)
		}
		if got[0] != payload[0] {
			t.Fatalf("listenerConns[%d] payload = %q, want %q", i, got[:], payload)
		}
	}
}

func TestExternalNativeTCPBootstrapConnsNegotiateRequestedCount(t *testing.T) {
	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(sender) error = %v", err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(listener) error = %v", err)
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()
	ln = tls.NewListener(ln, quicpath.DefaultTLSConfig(listenerIdentity.Certificate, quicpath.ServerName))

	var sessionID [16]byte
	copy(sessionID[:], []byte("bootstrap-session"))
	var bearerSecret [32]byte
	copy(bearerSecret[:], []byte("bootstrap-bearer-secret"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listenerResult := make(chan []net.Conn, 1)
	listenerErr := make(chan error, 1)
	go func() {
		conns, err := acceptExternalNativeTCPBootstrapConns(
			ctx,
			ln,
			externalNativeTCPAuth{
				Enabled:      true,
				SessionID:    sessionID,
				BearerSecret: bearerSecret,
				LocalPublic:  listenerIdentity.Public,
			},
			4,
		)
		listenerResult <- conns
		listenerErr <- err
	}()

	senderConns, err := dialExternalNativeTCPBootstrapConns(
		ctx,
		ln.Addr(),
		quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public),
		externalNativeTCPAuth{
			Enabled:      true,
			SessionID:    sessionID,
			BearerSecret: bearerSecret,
			PeerPublic:   listenerIdentity.Public,
		},
		6,
	)
	if err != nil {
		t.Fatalf("dialExternalNativeTCPBootstrapConns() error = %v", err)
	}
	defer closeExternalNativeTCPConns(senderConns)
	if got := len(senderConns); got != 4 {
		t.Fatalf("dialExternalNativeTCPBootstrapConns() len = %d, want 4", got)
	}

	listenerConns := <-listenerResult
	defer closeExternalNativeTCPConns(listenerConns)
	if err := <-listenerErr; err != nil {
		t.Fatalf("acceptExternalNativeTCPBootstrapConns() error = %v", err)
	}
	if got := len(listenerConns); got != 4 {
		t.Fatalf("acceptExternalNativeTCPBootstrapConns() len = %d, want 4", got)
	}

	payload := []byte("x")
	for i := range senderConns {
		if _, err := senderConns[i].Write(payload); err != nil {
			t.Fatalf("senderConns[%d].Write() error = %v", i, err)
		}
	}
	for i := range listenerConns {
		var got [1]byte
		if _, err := io.ReadFull(listenerConns[i], got[:]); err != nil {
			t.Fatalf("listenerConns[%d] ReadFull() error = %v", i, err)
		}
		if got[0] != payload[0] {
			t.Fatalf("listenerConns[%d] payload = %q, want %q", i, got[:], payload)
		}
	}
}

func TestExternalSendIgnoresTokenNativeTCPBootstrapHint(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var out bytes.Buffer
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:     tokenSink,
			StdioOut:      &out,
			UsePublicDERP: true,
			ForceRelay:    true,
		})
		listenErr <- err
	}()

	tok, err := token.Decode(<-tokenSink, time.Now())
	if err != nil {
		t.Fatalf("token.Decode() error = %v", err)
	}
	tok.SetNativeTCPBootstrapAddr(netip.MustParseAddrPort("127.0.0.1:1"))
	mutatedTok, err := token.Encode(tok)
	if err != nil {
		t.Fatalf("token.Encode() error = %v", err)
	}

	payload := bytes.Repeat([]byte("ignore-bootstrap:"), 1<<10)
	if err := Send(ctx, SendConfig{
		Token:          mutatedTok,
		UsePublicDERP:  true,
		ForceRelay:     true,
		ParallelPolicy: FixedParallelPolicy(4),
		Emitter:        telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		StdioIn:        bytes.NewReader(payload),
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	if got := out.Bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("receiver payload len = %d, want %d", len(got), len(payload))
	}
}

func TestExternalRoundTripUsesSessionPortmapLifecycle(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	fakes := []*sessionLifecyclePortmap{
		{have: true, snapshot: netip.MustParseAddrPort("198.51.100.10:54321")},
		{have: true, snapshot: netip.MustParseAddrPort("198.51.100.11:54322")},
	}
	var ctorMu sync.Mutex
	var ctorCalls int
	prevCtor := newPublicPortmap
	newPublicPortmap = func(*telemetry.Emitter) publicPortmap {
		ctorMu.Lock()
		defer ctorMu.Unlock()
		if ctorCalls >= len(fakes) {
			return &sessionLifecyclePortmap{}
		}
		pm := fakes[ctorCalls]
		ctorCalls++
		return pm
	}
	t.Cleanup(func() { newPublicPortmap = prevCtor })

	seenPortmaps := make(chan publicPortmap, len(fakes))
	prevTransportCtor := newTransportManager
	newTransportManager = func(cfg transport.ManagerConfig) *transport.Manager {
		if cfg.Portmap != nil {
			if pm, ok := cfg.Portmap.(publicPortmap); ok {
				select {
				case seenPortmaps <- pm:
				default:
				}
			}
		}
		return prevTransportCtor(cfg)
	}
	t.Cleanup(func() { newTransportManager = prevTransportCtor })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var senderIn bytes.Buffer
	senderIn.WriteString("hello over public session")
	listenerReady := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			ForceRelay:    true,
			TokenSink:     listenerReady,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-listenerReady
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:         token,
			ForceRelay:    true,
			StdioIn:       &senderIn,
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			UsePublicDERP: true,
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if got := listenerOut.String(); got != "hello over public session" {
		t.Fatalf("listener output = %q, want %q", got, "hello over public session")
	}

	gotPortmaps := make(map[publicPortmap]int)
	for i := 0; i < len(fakes); i++ {
		pm := <-seenPortmaps
		gotPortmaps[pm]++
	}
	close(seenPortmaps)

	if got, want := ctorCalls, len(fakes); got != want {
		t.Fatalf("portmap ctor calls = %d, want %d", got, want)
	}
	for i, pm := range fakes {
		pm.mu.Lock()
		localPort := pm.localPort
		closeCalls := pm.closeCalls
		pm.mu.Unlock()

		if localPort == 0 {
			t.Fatalf("fake portmap %d localPort = 0, want bound port", i)
		}
		if gotPortmaps[pm] == 0 {
			t.Fatalf("fake portmap %d was not threaded into transport manager", i)
		}
		if closeCalls != 1 {
			t.Fatalf("fake portmap %d Close() calls = %d, want 1", i, closeCalls)
		}
	}
}

type sessionFakePortmapMapper struct {
	localPort uint16
	external  netip.AddrPort
	have      bool
	closed    int
}

func (m *sessionFakePortmapMapper) SetLocalPort(p uint16) { m.localPort = p }

func (m *sessionFakePortmapMapper) SetGatewayLookupFunc(func() (gw, myIP netip.Addr, ok bool)) {}

func (m *sessionFakePortmapMapper) Probe(context.Context) (portmappertype.ProbeResult, error) {
	return portmappertype.ProbeResult{}, nil
}

func (m *sessionFakePortmapMapper) HaveMapping() bool { return m.have }

func (m *sessionFakePortmapMapper) GetCachedMappingOrStartCreatingOne() (netip.AddrPort, bool) {
	if !m.have {
		return netip.AddrPort{}, false
	}
	return m.external, true
}

func (m *sessionFakePortmapMapper) Close() error {
	m.closed++
	return nil
}

type sessionLifecyclePortmap struct {
	mu                 sync.Mutex
	localPort          uint16
	snapshot           netip.AddrPort
	have               bool
	refreshDelay       time.Duration
	refreshCalls       int
	snapshotAddrsCalls int
	closeCalls         int
}

func (m *sessionLifecyclePortmap) SetLocalPort(p uint16) {
	m.mu.Lock()
	m.localPort = p
	m.mu.Unlock()
}

func (m *sessionLifecyclePortmap) SetGatewayLookupFunc(func() (gw, myIP netip.Addr, ok bool)) {}

func (m *sessionLifecyclePortmap) Probe(context.Context) (portmappertype.ProbeResult, error) {
	return portmappertype.ProbeResult{}, nil
}

func (m *sessionLifecyclePortmap) HaveMapping() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.have
}

func (m *sessionLifecyclePortmap) GetCachedMappingOrStartCreatingOne() (netip.AddrPort, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.have {
		return netip.AddrPort{}, false
	}
	return m.snapshot, true
}

func (m *sessionLifecyclePortmap) Snapshot() (netip.AddrPort, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.have {
		return netip.AddrPort{}, false
	}
	return m.snapshot, true
}

func (m *sessionLifecyclePortmap) SnapshotAddrs() []net.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshotAddrsCalls++
	if !m.have || !m.snapshot.Addr().IsValid() || m.snapshot.Port() == 0 {
		return nil
	}
	return []net.Addr{&net.UDPAddr{
		IP:   append(net.IP(nil), m.snapshot.Addr().AsSlice()...),
		Port: int(m.snapshot.Port()),
		Zone: m.snapshot.Addr().Zone(),
	}}
}

func (m *sessionLifecyclePortmap) Refresh(time.Time) bool {
	if m.refreshDelay > 0 {
		time.Sleep(m.refreshDelay)
	}
	m.mu.Lock()
	m.refreshCalls++
	m.mu.Unlock()
	return true
}

func (m *sessionLifecyclePortmap) Close() error {
	m.mu.Lock()
	m.closeCalls++
	m.mu.Unlock()
	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsAddrString(values []net.Addr, target string) bool {
	for _, value := range values {
		if value != nil && value.String() == target {
			return true
		}
	}
	return false
}

func containsCGNATCandidate(values []string) bool {
	tailscaleCGNAT := netip.MustParsePrefix("100.64.0.0/10")
	for _, value := range values {
		addrPort, err := netip.ParseAddrPort(value)
		if err != nil {
			continue
		}
		if tailscaleCGNAT.Contains(addrPort.Addr()) {
			return true
		}
	}
	return false
}

func TestSeedAcceptedDecisionCandidatesUsesAcceptCandidates(t *testing.T) {
	ctx := context.Background()
	decision := rendezvous.Decision{
		Accepted: true,
		Accept: &rendezvous.AcceptInfo{
			Candidates: []string{
				"100.64.0.10:12345",
				"[2001:db8::10]:23456",
				"not-an-addr",
			},
		},
	}
	seeder := &captureCandidateSeeder{}

	seedAcceptedDecisionCandidates(ctx, seeder, decision)

	if seeder.calls != 1 {
		t.Fatalf("SeedRemoteCandidates() calls = %d, want 1", seeder.calls)
	}
	if got := len(seeder.candidates); got != 2 {
		t.Fatalf("seeded candidates = %#v, want 2 parsed candidates", seeder.candidates)
	}
	if got := seeder.candidates[0].String(); got != "100.64.0.10:12345" {
		t.Fatalf("first seeded candidate = %q, want %q", got, "100.64.0.10:12345")
	}
	if got := seeder.candidates[1].String(); got != "[2001:db8::10]:23456" {
		t.Fatalf("second seeded candidate = %q, want %q", got, "[2001:db8::10]:23456")
	}
}

func TestSeedAcceptedDecisionCandidatesFiltersUnsafeCandidates(t *testing.T) {
	ctx := context.Background()
	decision := rendezvous.Decision{
		Accepted: true,
		Accept: &rendezvous.AcceptInfo{
			Candidates: []string{
				"127.0.0.1:1",
				"203.0.113.10:12345",
				"203.0.113.10:12345",
				"bad",
			},
		},
	}
	seeder := &captureCandidateSeeder{}

	seedAcceptedDecisionCandidates(ctx, seeder, decision)

	if seeder.calls != 1 {
		t.Fatalf("SeedRemoteCandidates() calls = %d, want 1", seeder.calls)
	}
	if got := len(seeder.candidates); got != 1 {
		t.Fatalf("seeded candidates = %#v, want 1 filtered candidate", seeder.candidates)
	}
	if got := seeder.candidates[0].String(); got != "203.0.113.10:12345" {
		t.Fatalf("seeded candidate = %q, want %q", got, "203.0.113.10:12345")
	}
}

func TestSeedAcceptedClaimCandidatesUsesClaimCandidates(t *testing.T) {
	ctx := context.Background()
	claim := rendezvous.Claim{
		Candidates: []string{
			"192.0.2.20:2345",
			"not-an-addr",
		},
	}
	seeder := &captureCandidateSeeder{}

	seedAcceptedClaimCandidates(ctx, seeder, claim)

	if seeder.calls != 1 {
		t.Fatalf("SeedRemoteCandidates() calls = %d, want 1", seeder.calls)
	}
	if got := len(seeder.candidates); got != 1 {
		t.Fatalf("seeded candidates = %#v, want 1 parsed candidate", seeder.candidates)
	}
	if got := seeder.candidates[0].String(); got != "192.0.2.20:2345" {
		t.Fatalf("first seeded candidate = %q, want %q", got, "192.0.2.20:2345")
	}
}

func TestSeedAcceptedClaimCandidatesFiltersUnsafeCandidates(t *testing.T) {
	ctx := context.Background()
	claim := rendezvous.Claim{
		Candidates: []string{
			"127.0.0.1:1",
			"203.0.113.10:12345",
			"203.0.113.10:12345",
			"bad",
		},
	}
	seeder := &captureCandidateSeeder{}

	seedAcceptedClaimCandidates(ctx, seeder, claim)

	if seeder.calls != 1 {
		t.Fatalf("SeedRemoteCandidates() calls = %d, want 1", seeder.calls)
	}
	if got := len(seeder.candidates); got != 1 {
		t.Fatalf("seeded candidates = %#v, want 1 filtered candidate", seeder.candidates)
	}
	if got := seeder.candidates[0].String(); got != "203.0.113.10:12345" {
		t.Fatalf("seeded candidate = %q, want %q", got, "203.0.113.10:12345")
	}
}

func TestParseRemoteCandidateStringsRejectsLoopbackWithoutFakeTransport(t *testing.T) {
	got := parseRemoteCandidateStrings([]string{
		"127.0.0.1:1",
		"203.0.113.10:12345",
	})
	if len(got) != 1 {
		t.Fatalf("parseRemoteCandidateStrings() = %#v, want 1 candidate", got)
	}
	if got[0].String() != "203.0.113.10:12345" {
		t.Fatalf("candidate = %v, want 203.0.113.10:12345", got[0])
	}
}

func TestParseRemoteCandidateStringsAllowsLoopbackForFakeTransport(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	remote := parseRemoteCandidateStrings([]string{"127.0.0.1:1"})
	if len(remote) != 1 {
		t.Fatalf("parseRemoteCandidateStrings(fake) = %#v, want loopback accepted", remote)
	}
	if remote[0].String() != "127.0.0.1:1" {
		t.Fatalf("remote candidate = %v, want 127.0.0.1:1", remote[0])
	}
	local := parseCandidateStrings([]string{"127.0.0.1:1"})
	if len(local) != 1 {
		t.Fatalf("parseCandidateStrings(fake) = %#v, want loopback accepted locally", local)
	}
	if local[0].String() != "127.0.0.1:1" {
		t.Fatalf("local candidate = %v, want 127.0.0.1:1", local[0])
	}
}

type shareOpenRoundTripConfig struct {
	relayPayload    string
	upgradePayloads []string
}

type shareOpenRoundTripResult struct {
	RelayReply     string
	UpgradeReplies map[string]string
	ShareStatus    string
	OpenStatus     string
	SeenRelay      bool
	SeenDirect     bool
}

type captureCandidateSeeder struct {
	calls      int
	candidates []net.Addr
}

type stubPacketConn struct {
	localAddr net.Addr
}

func (c *stubPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *stubPacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, net.ErrClosed }
func (c *stubPacketConn) Close() error                           { return nil }
func (c *stubPacketConn) LocalAddr() net.Addr                    { return c.localAddr }
func (c *stubPacketConn) SetDeadline(time.Time) error            { return nil }
func (c *stubPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (c *stubPacketConn) SetWriteDeadline(time.Time) error       { return nil }

func (c *captureCandidateSeeder) SeedRemoteCandidates(_ context.Context, candidates []net.Addr) {
	c.calls++
	c.candidates = append([]net.Addr(nil), candidates...)
}

func runExternalShareOpenSession(t *testing.T, cfg shareOpenRoundTripConfig) shareOpenRoundTripResult {
	t.Helper()

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", strconv.FormatInt(time.Now().Add(24*time.Hour).UnixNano(), 10))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backendAddr, backendDone := startEchoServer(t, ctx)
	defer backendDone()

	var shareStatus syncBuffer
	var openStatus syncBuffer

	tokenSink := make(chan string, 1)
	shareErr := make(chan error, 1)
	go func() {
		_, err := Share(ctx, ShareConfig{
			Emitter:       telemetry.New(&shareStatus, telemetry.LevelDefault),
			TokenSink:     tokenSink,
			TargetAddr:    backendAddr,
			UsePublicDERP: true,
		})
		shareErr <- err
	}()

	tok := <-tokenSink
	bindSink := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- Open(ctx, OpenConfig{
			Token:         tok,
			BindAddrSink:  bindSink,
			Emitter:       telemetry.New(&openStatus, telemetry.LevelDefault),
			UsePublicDERP: true,
		})
	}()

	openAddr := <-bindSink
	relayReply, err := roundTripTCP(ctx, openAddr, cfg.relayPayload)
	if err != nil {
		t.Fatalf("relay roundTripTCP() error = %v", err)
	}

	waitForStatusPrefixBuffer(t, &shareStatus, 20*time.Second, string(StateWaiting), string(StateClaimed), string(StateRelay))
	waitForStatusPrefixBuffer(t, &openStatus, 20*time.Second, string(StateProbing), string(StateRelay))
	if err := os.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0"); err != nil {
		t.Fatalf("Setenv(enable direct) error = %v", err)
	}
	waitForStatusPrefixBuffer(t, &shareStatus, 20*time.Second, string(StateWaiting), string(StateClaimed), string(StateRelay), string(StateDirect))
	waitForStatusPrefixBuffer(t, &openStatus, 20*time.Second, string(StateProbing), string(StateRelay), string(StateDirect))

	replies := make(map[string]string, len(cfg.upgradePayloads))
	var mu sync.Mutex
	var wg sync.WaitGroup
	errCh := make(chan error, len(cfg.upgradePayloads))
	for _, payload := range cfg.upgradePayloads {
		wg.Add(1)
		go func(payload string) {
			defer wg.Done()
			reply, err := roundTripTCP(ctx, openAddr, payload)
			if err != nil {
				errCh <- err
				return
			}
			mu.Lock()
			replies[payload] = reply
			mu.Unlock()
		}(payload)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("post-upgrade roundTripTCP() error = %v", err)
		}
	}

	cancel()
	waitNoErr(t, <-openErr)
	waitNoErr(t, <-shareErr)

	shareStatuses := shareStatus.String()
	openStatuses := openStatus.String()
	return shareOpenRoundTripResult{
		RelayReply:     relayReply,
		UpgradeReplies: replies,
		ShareStatus:    shareStatuses,
		OpenStatus:     openStatuses,
		SeenRelay:      strings.Contains(shareStatuses, string(StateRelay)) && strings.Contains(openStatuses, string(StateRelay)),
		SeenDirect:     strings.Contains(shareStatuses, string(StateDirect)) && strings.Contains(openStatuses, string(StateDirect)),
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func waitForStatusPrefixBuffer(t *testing.T, buf interface{ String() string }, timeout time.Duration, want ...string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if hasSessionStatusPrefix(sessionStatusLines(buf.String()), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("statuses = %q, want prefix %v", buf.String(), want)
}

func hasSessionStatusPrefix(got, want []string) bool {
	if len(got) < len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func sessionStatusLines(got string) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(got, "\n") {
		line = strings.TrimSpace(line)
		switch line {
		case string(StateWaiting), string(StateClaimed), string(StateProbing), string(StateRelay), string(StateDirect), string(StateComplete):
			lines = append(lines, line)
		}
	}
	return lines
}

func countSessionStatus(lines []string, want State) int {
	count := 0
	for _, line := range lines {
		if line == string(want) {
			count++
		}
	}
	return count
}

type sessionTestDERPServer struct {
	MapURL  string
	DERPURL string
	Map     *tailcfg.DERPMap
}

func newSessionTestDERPServer(t *testing.T) *sessionTestDERPServer {
	t.Helper()

	server := derpserver.New(key.NewNode(), t.Logf)
	t.Cleanup(func() {
		_ = server.Close()
	})

	derpHTTP := httptest.NewServer(derpserver.Handler(server))
	t.Cleanup(derpHTTP.Close)

	dm := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				RegionName: "Session Test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "session-test-1",
						RegionID: 1,
						HostName: "127.0.0.1",
						IPv4:     "127.0.0.1",
						STUNPort: -1,
						DERPPort: 0,
					},
				},
			},
		},
	}

	mapHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(dm)
	}))
	t.Cleanup(mapHTTP.Close)

	return &sessionTestDERPServer{
		MapURL:  mapHTTP.URL,
		DERPURL: derpHTTP.URL + "/derp",
		Map:     dm,
	}
}

func connectWithRetry(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func startEchoServer(t *testing.T, ctx context.Context) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := acceptNetListener(ctx, listener)
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func startSharedSession(t *testing.T, ctx context.Context, backendAddr, bindAddr string) (string, func(), <-chan error, <-chan error) {
	t.Helper()

	sessionCtx, cancel := context.WithCancel(ctx)
	tokenSink := make(chan string, 1)
	shareErr := make(chan error, 1)
	go func() {
		_, err := Share(sessionCtx, ShareConfig{
			Emitter:    telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:  tokenSink,
			TargetAddr: backendAddr,
		})
		shareErr <- err
	}()

	tok := <-tokenSink
	bindSink := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- Open(sessionCtx, OpenConfig{
			Token:        tok,
			BindAddr:     bindAddr,
			BindAddrSink: bindSink,
			Emitter:      telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		})
	}()

	return <-bindSink, cancel, shareErr, openErr
}

func roundTripTCP(ctx context.Context, addr, payload string) (string, error) {
	conn, err := connectWithRetry(ctx, addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, payload); err != nil {
		return "", err
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func waitNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExternalDirectUDPDedupeAndFillKeepsManagerAddr(t *testing.T) {
	selected := []string{
		"68.20.14.192:50001",
		"10.0.1.254:50001",
		"68.20.14.192:50003",
		"",
	}
	fallback := []string{
		"10.0.1.254:50001",
		"10.0.1.254:50002",
		"10.0.1.254:50003",
		"10.0.1.254:50004",
	}

	got := externalDirectUDPDedupeAndFill(selected, fallback)
	want := []string{
		"68.20.14.192:50001",
		"10.0.1.254:50002",
		"68.20.14.192:50003",
		"10.0.1.254:50004",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPDedupeAndFill() = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPDedupeAndFillPreservesObservedCandidateForEndpoint(t *testing.T) {
	selected := []string{"10.0.1.254:50001"}
	fallback := []string{"108.18.210.19:50001"}

	got := externalDirectUDPDedupeAndFill(selected, fallback)
	want := []string{"10.0.1.254:50001"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPDedupeAndFill() = %v, want observed candidate %v", got, want)
	}
}

func TestExternalDirectUDPParallelCandidatesPreferWANForSameEndpoint(t *testing.T) {
	candidates := []net.Addr{
		&net.UDPAddr{IP: net.IPv4(10, 0, 1, 254), Port: 50001},
		&net.UDPAddr{IP: net.IPv4(108, 18, 210, 19), Port: 50001},
		&net.UDPAddr{IP: net.IPv4(10, 0, 1, 254), Port: 50002},
		&net.UDPAddr{IP: net.IPv4(108, 18, 210, 19), Port: 50002},
	}

	got := externalDirectUDPParallelCandidateStrings(candidates, 2)
	want := []string{"108.18.210.19:50001", "108.18.210.19:50002"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPParallelCandidateStrings() = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPParallelCandidatesPreserveWANLaneOrder(t *testing.T) {
	candidates := []net.Addr{
		&net.UDPAddr{IP: net.IPv4(108, 18, 210, 19), Port: 54908},
		&net.UDPAddr{IP: net.IPv4(108, 18, 210, 19), Port: 51051},
		&net.UDPAddr{IP: net.IPv4(108, 18, 210, 19), Port: 63793},
		&net.UDPAddr{IP: net.IPv4(108, 18, 210, 19), Port: 49808},
	}

	got := externalDirectUDPParallelCandidateStrings(candidates, 4)
	want := []string{
		"108.18.210.19:54908",
		"108.18.210.19:51051",
		"108.18.210.19:63793",
		"108.18.210.19:49808",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPParallelCandidateStrings() = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPSelectRemoteAddrsByConnKeepsObservedLaneEndpoint(t *testing.T) {
	observedByConn := [][]net.Addr{
		{&net.UDPAddr{IP: net.IPv4(68, 20, 14, 192), Port: 38183}},
		{&net.UDPAddr{IP: net.IPv4(68, 20, 14, 192), Port: 34375}},
		{
			&net.UDPAddr{IP: net.IPv4(68, 20, 14, 192), Port: 40282},
			&net.UDPAddr{IP: net.IPv4(68, 20, 14, 192), Port: 44442},
		},
		{
			&net.UDPAddr{IP: net.IPv4(68, 20, 14, 192), Port: 44442},
			&net.UDPAddr{IP: net.IPv4(68, 20, 14, 192), Port: 40282},
		},
	}

	got := externalDirectUDPSelectRemoteAddrsByConn(observedByConn, 4, nil)
	want := []string{
		"68.20.14.192:38183",
		"68.20.14.192:34375",
		"68.20.14.192:40282",
		"68.20.14.192:44442",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPSelectRemoteAddrsByConn() = %v, want observed reachable endpoints %v", got, want)
	}
}

func TestExternalDirectUDPInferWANPerPortForPrivateOnlyLanes(t *testing.T) {
	sets := [][]string{
		{"68.20.14.192:50001", "10.0.1.254:50001"},
		{"10.0.1.254:50002"},
		{"10.0.1.254:50003"},
	}

	got := externalDirectUDPInferWANPerPort(sets)
	want := [][]string{
		{"68.20.14.192:50001", "10.0.1.254:50001"},
		{"68.20.14.192:50002", "10.0.1.254:50002"},
		{"68.20.14.192:50003", "10.0.1.254:50003"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPInferWANPerPort() = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPPreferWANStringsFeedsFirstPerLaneCandidate(t *testing.T) {
	candidates := []string{
		"10.0.1.254:50001",
		"10.0.4.184:50001",
		"68.20.14.192:50001",
		"127.0.0.1:50001",
	}

	got := externalDirectUDPPreferWANStrings(candidates)
	if got[0] != "68.20.14.192:50001" {
		t.Fatalf("externalDirectUDPPreferWANStrings()[0] = %q, want WAN candidate", got[0])
	}
}
