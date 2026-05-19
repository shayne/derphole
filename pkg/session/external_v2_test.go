// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

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
