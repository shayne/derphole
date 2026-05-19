// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transfertrace"
)

func TestExternalV2SendReceiveRoundTrip(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "v2")

	const payload = "external v2 payload"
	if received := runExternalV2RoundTrip(t, payload, nil, nil); received != payload {
		t.Fatalf("received = %q, want %q", received, payload)
	}
}

func TestExternalV2ReceiverCancelAbortsSender(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "v2")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	receiveCtx, cancelReceive := context.WithCancel(ctx)

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := listenExternal(receiveCtx, ListenConfig{
			TokenSink:     tokenSink,
			StdioOut:      &cancelOnWrite{cancel: cancelReceive},
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	var raw string
	select {
	case raw = <-tokenSink:
	case err := <-listenErr:
		t.Fatalf("listenExternal() returned before token: %v", err)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for token: %v", ctx.Err())
	}

	sendErr := make(chan error, 1)
	go func() {
		sendErr <- sendExternal(ctx, SendConfig{
			Token:         raw,
			StdioIn:       io.LimitReader(zeroReader{}, 32<<20),
			UsePublicDERP: true,
		})
	}()

	select {
	case err := <-sendErr:
		if !errors.Is(err, ErrPeerAborted) {
			t.Fatalf("sendExternal() error = %v, want %v", err, ErrPeerAborted)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for sender abort: %v", ctx.Err())
	}

	select {
	case <-listenErr:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for listener exit: %v", ctx.Err())
	}
}

func TestExternalV2TransferTraceCompletes(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "v2")

	var sendOut bytes.Buffer
	sendTrace, err := transfertrace.NewRecorder(&sendOut, transfertrace.RoleSend, time.Unix(100, 0))
	if err != nil {
		t.Fatalf("NewRecorder(send) error = %v", err)
	}
	var receiveOut bytes.Buffer
	receiveTrace, err := transfertrace.NewRecorder(&receiveOut, transfertrace.RoleReceive, time.Unix(100, 0))
	if err != nil {
		t.Fatalf("NewRecorder(receive) error = %v", err)
	}

	payload := strings.Repeat("x", 4096)
	if received := runExternalV2RoundTrip(t, payload, sendTrace, receiveTrace); received != payload {
		t.Fatalf("received = %q, want %q", received, payload)
	}
	if err := sendTrace.Close(); err != nil {
		t.Fatalf("send trace Close() error = %v", err)
	}
	if err := receiveTrace.Close(); err != nil {
		t.Fatalf("receive trace Close() error = %v", err)
	}
	if _, err := transfertrace.Check(strings.NewReader(sendOut.String()), transfertrace.Options{
		Role:             transfertrace.RoleSend,
		ExpectedBytes:    int64(len(payload)),
		ExpectedBytesSet: true,
	}); err != nil {
		t.Fatalf("send trace check error = %v\n%s", err, sendOut.String())
	}
	if _, err := transfertrace.Check(strings.NewReader(receiveOut.String()), transfertrace.Options{
		Role:             transfertrace.RoleReceive,
		ExpectedBytes:    int64(len(payload)),
		ExpectedBytesSet: true,
	}); err != nil {
		t.Fatalf("receive trace check error = %v\n%s", err, receiveOut.String())
	}
}

func TestExternalV2PromotesToDirectWhenBothSidesReady(t *testing.T) {
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

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "v2")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte("external-v2-direct:"), (4<<20)/len("external-v2-direct:"))
	var received bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := listenExternal(ctx, ListenConfig{
			TokenSink:     tokenSink,
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			StdioOut:      &received,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	var raw string
	select {
	case raw = <-tokenSink:
	case err := <-listenErr:
		t.Fatalf("listenExternal() returned before token: %v", err)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for token: %v", ctx.Err())
	}

	stdin := &sessionTestGatedReader{
		payload: payload,
		gateAt:  len(payload) / 4,
		gate: func() error {
			gateCtx, gateCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer gateCancel()
			if err := waitForSessionTestStatusContains(gateCtx, &senderStatus, string(StateDirect)); err != nil {
				return fmt.Errorf("waiting for v2 sender direct path: %w; listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
			}
			if err := waitForSessionTestStatusContains(gateCtx, &listenerStatus, string(StateDirect)); err != nil {
				return fmt.Errorf("waiting for v2 listener direct path: %w; listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
			}
			return nil
		},
	}
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- sendExternal(ctx, SendConfig{
			Token:         raw,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:       stdin,
			UsePublicDERP: true,
		})
	}()

	select {
	case err := <-sendErr:
		if err != nil {
			t.Fatalf("sendExternal() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for sender: %v; listener=%q sender=%q", ctx.Err(), listenerStatus.String(), senderStatus.String())
	}
	select {
	case err := <-listenErr:
		if err != nil {
			t.Fatalf("listenExternal() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for listener: %v; listener=%q sender=%q", ctx.Err(), listenerStatus.String(), senderStatus.String())
	}

	if !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("listener output length = %d, want %d", received.Len(), len(payload))
	}
	if got := senderStatus.String(); !strings.Contains(got, string(StateTryingDirect)) || !strings.Contains(got, string(StateDirect)) {
		t.Fatalf("sender status = %q, want v2 direct promotion", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, string(StateTryingDirect)) || !strings.Contains(got, string(StateDirect)) {
		t.Fatalf("listener status = %q, want v2 direct promotion", got)
	}
}

func runExternalV2RoundTrip(t *testing.T, payload string, sendTrace *transfertrace.Recorder, receiveTrace *transfertrace.Recorder) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var received bytes.Buffer
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := listenExternal(ctx, ListenConfig{
			TokenSink:     tokenSink,
			StdioOut:      &received,
			UsePublicDERP: true,
			Trace:         receiveTrace,
		})
		listenErr <- err
	}()

	var raw string
	select {
	case raw = <-tokenSink:
	case err := <-listenErr:
		t.Fatalf("listenExternal() returned before token: %v", err)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for token: %v", ctx.Err())
	}
	tok, err := token.Decode(raw, time.Now())
	if err != nil {
		t.Fatalf("token.Decode() error = %v", err)
	}
	if tok.Capabilities&token.CapabilityTransferV2 == 0 {
		t.Fatalf("token capabilities = %08b, want transfer v2", tok.Capabilities)
	}

	if err := sendExternal(ctx, SendConfig{
		Token:         raw,
		StdioIn:       strings.NewReader(payload),
		UsePublicDERP: true,
		Trace:         sendTrace,
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
	return received.String()
}

type cancelOnWrite struct {
	once   sync.Once
	cancel context.CancelFunc
}

func (w *cancelOnWrite) Write(p []byte) (int, error) {
	w.once.Do(w.cancel)
	return 0, context.Canceled
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
