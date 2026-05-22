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
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/telemetry"
)

type failingOfferReader struct {
	err error
}

func (r failingOfferReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestLocalOfferReceiveStdioRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	var senderStatus bytes.Buffer
	var receiverStatus bytes.Buffer

	go func() {
		_, err := Offer(ctx, OfferConfig{
			Emitter:   telemetry.New(&senderStatus, telemetry.LevelDefault),
			TokenSink: tokenSink,
			StdioIn:   strings.NewReader("local offered payload"),
		})
		offerErr <- err
	}()

	var tok string
	select {
	case tok = <-tokenSink:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for local offer token: %v", ctx.Err())
	}

	var out bytes.Buffer
	if err := Receive(ctx, ReceiveConfig{
		Token:    tok,
		Emitter:  telemetry.New(&receiverStatus, telemetry.LevelDefault),
		StdioOut: &out,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if err := <-offerErr; err != nil {
		t.Fatalf("Offer() error = %v", err)
	}
	if got := out.String(); got != "local offered payload" {
		t.Fatalf("receiver output = %q, want payload", got)
	}
	if got := sessionStatusLines(senderStatus.String()); !hasSessionStatusPrefix(got, []string{string(StateWaiting), string(StateDirect), string(StateComplete)}) {
		t.Fatalf("sender statuses = %q, want waiting/direct/complete", got)
	}
	if got := sessionStatusLines(receiverStatus.String()); !hasSessionStatusPrefix(got, []string{string(StateDirect), string(StateComplete)}) {
		t.Fatalf("receiver statuses = %q, want direct/complete", got)
	}
}

func TestReceiveUnknownLocalOfferReturnsUnknownSession(t *testing.T) {
	if err := Receive(context.Background(), ReceiveConfig{Token: "missing"}); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("Receive(missing local token) error = %v, want %v", err, ErrUnknownSession)
	}
}

func TestWaitLocalOfferAcceptedHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	session := &offerSession{accepted: make(chan struct{})}
	if err := waitLocalOfferAccepted(ctx, session); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitLocalOfferAccepted(canceled) = %v, want context.Canceled", err)
	}
}

func TestStreamLocalOfferClosesWriterWithCopyError(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	accepted := make(chan struct{})
	close(accepted)

	wantErr := errors.New("offer source failed")
	session := &offerSession{accepted: accepted, reader: reader, writer: writer}
	if err := streamLocalOffer(context.Background(), OfferConfig{}, session, failingOfferReader{err: wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("streamLocalOffer() error = %v, want %v", err, wantErr)
	}
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, wantErr) {
		t.Fatalf("offer session reader error = %v, want %v", err, wantErr)
	}
}
