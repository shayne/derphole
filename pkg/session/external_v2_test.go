// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"strings"
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
