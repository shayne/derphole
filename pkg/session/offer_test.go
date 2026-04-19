package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/telemetry"
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
		if err := waitForSessionTestStatusContains(gateCtx, &senderStatus, string(StateDirect)); err != nil {
			return fmt.Errorf("waiting for offered sender direct UDP promotion: %w; receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
		}
		if err := waitForSessionTestStatusContains(gateCtx, &receiverStatus, string(StateDirect)); err != nil {
			return fmt.Errorf("waiting for offered receiver direct UDP promotion: %w; receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
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
		if err := waitForSessionTestStatusContains(gateCtx, &senderStatus, string(StateDirect)); err != nil {
			writeErr <- fmt.Errorf("waiting for offered pipe sender direct UDP promotion: %w; receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
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
	if !strings.Contains(senderStatus.String(), string(StateDirect)) {
		t.Fatalf("sender statuses = %q, want %q", senderStatus.String(), StateDirect)
	}
	if !strings.Contains(receiverStatus.String(), string(StateDirect)) {
		t.Fatalf("receiver statuses = %q, want %q", receiverStatus.String(), StateDirect)
	}
}
