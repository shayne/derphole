// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/transfertrace"
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
	if got := senderStatus.String(); !strings.Contains(got, string(StateRelay)) || strings.Contains(got, "v2-data-plane=raw-direct") {
		t.Fatalf("sender status = %q, want v2 relay path", got)
	}
	if got := receiverStatus.String(); !strings.Contains(got, string(StateRelay)) || strings.Contains(got, "udp-handoff-receive-prepare-error") || strings.Contains(got, "v2-data-plane=raw-direct") {
		t.Fatalf("receiver status = %q, want v2 relay path without direct handoff prepare", got)
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
	if got := senderStatus.String(); !strings.Contains(got, string(StateRelay)) || strings.Contains(got, "v2-data-plane=raw-direct") {
		t.Fatalf("sender status = %q, want v2 relay path", got)
	}
	if got := receiverStatus.String(); !strings.Contains(got, string(StateRelay)) || strings.Contains(got, "udp-handoff-receive-prepare-error") || strings.Contains(got, "v2-data-plane=raw-direct") {
		t.Fatalf("receiver status = %q, want v2 relay path without direct handoff prepare", got)
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
