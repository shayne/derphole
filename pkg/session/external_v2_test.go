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

func TestExternalV2StreamOpenBudgetsAreIndependent(t *testing.T) {
	if got, want := externalV2QUICStreamOpenWait, 10*time.Second; got != want {
		t.Fatalf("QUIC stream-open budget = %s, want %s", got, want)
	}
	if got, want := externalV2BulkPacketHelloWait, 2*time.Second; got != want {
		t.Fatalf("bulk-packet HELLO budget = %s, want %s", got, want)
	}
}

func TestRunExternalV2QUICStreamOpenAllowsWANDelayBeyondTwoSeconds(t *testing.T) {
	started := time.Now()
	got, err := runExternalV2QUICStreamOpen(context.Background(), true, func(ctx context.Context) (string, error) {
		timer := time.NewTimer(2100 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			return "opened", nil
		case <-ctx.Done():
			return "", context.Cause(ctx)
		}
	})
	if err != nil || got != "opened" {
		t.Fatalf("delayed QUIC stream open = (%q, %v), want (opened, nil)", got, err)
	}
	if elapsed := time.Since(started); elapsed < 2*time.Second || elapsed >= externalV2QUICStreamOpenWait {
		t.Fatalf("delayed QUIC stream open elapsed = %s, want [2s, %s)", elapsed, externalV2QUICStreamOpenWait)
	}
}

func TestRunExternalV2QUICStreamOpenPreservesParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := runExternalV2QUICStreamOpen(ctx, true, func(openCtx context.Context) (struct{}, error) {
			close(started)
			<-openCtx.Done()
			return struct{}{}, context.Cause(openCtx)
		})
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled QUIC stream open error = %v, want canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("QUIC stream open ignored parent cancellation")
	}
}

func TestWaitExternalV2BulkPacketHelloWithinRetainsPeerDisconnectTimeout(t *testing.T) {
	started := time.Now()
	err := waitExternalV2BulkPacketHelloWithin(context.Background(), make(chan struct{}), make(chan error), 25*time.Millisecond)
	if !errors.Is(err, ErrPeerDisconnected) {
		t.Fatalf("bulk-packet HELLO timeout error = %v, want peer disconnected", err)
	}
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond || elapsed >= time.Second {
		t.Fatalf("bulk-packet HELLO timeout elapsed = %s, want short injected budget", elapsed)
	}
}

func TestExternalV2SendReceiveRoundTrip(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	const payload = "external v2 payload"
	if received := runExternalV2RoundTrip(t, payload, nil, nil); received != payload {
		t.Fatalf("received = %q, want %q", received, payload)
	}
}

func TestExternalV2OfferReceiveRoundTrip(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const payload = "external v2 offered payload"
	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			TokenSink:     tokenSink,
			StdioIn:       strings.NewReader(payload),
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		offerErr <- err
	}()

	var raw string
	select {
	case raw = <-tokenSink:
	case err := <-offerErr:
		t.Fatalf("Offer() returned before token: %v", err)
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
	if tok.Capabilities&token.CapabilityStdioOffer == 0 {
		t.Fatalf("token capabilities = %08b, want stdio offer", tok.Capabilities)
	}

	var received bytes.Buffer
	if err := Receive(ctx, ReceiveConfig{
		Token:         raw,
		StdioOut:      &received,
		ForceRelay:    true,
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if err := <-offerErr; err != nil {
		t.Fatalf("Offer() error = %v", err)
	}
	if got := received.String(); got != payload {
		t.Fatalf("received = %q, want %q", got, payload)
	}
}

func TestExternalV2OfferReceivePromotesToDirectWhenBothSidesReady(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	testExternalV2OfferReceivePromotesToDirectWhenBothSidesReady(t)
}

func testExternalV2OfferReceivePromotesToDirectWhenBothSidesReady(t *testing.T) {
	t.Helper()
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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte("external-v2-offer-direct:"), (4<<20)/len("external-v2-offer-direct:"))
	var received bytes.Buffer
	var receiverStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	stdin := &sessionTestGatedReader{
		payload: payload,
		gateAt:  len(payload) / 4,
		gate: func() error {
			gateCtx, gateCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer gateCancel()
			if err := waitForSessionTestStatusContains(gateCtx, &senderStatus, string(StateDirect)); err != nil {
				return fmt.Errorf("waiting for v2 offer sender direct path: %w; receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
			}
			if err := waitForSessionTestStatusContains(gateCtx, &receiverStatus, string(StateDirect)); err != nil {
				return fmt.Errorf("waiting for v2 offer receiver direct path: %w; receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
			}
			return nil
		},
	}
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			TokenSink:     tokenSink,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:       stdin,
			UsePublicDERP: true,
		})
		offerErr <- err
	}()

	var raw string
	select {
	case raw = <-tokenSink:
	case err := <-offerErr:
		t.Fatalf("Offer() returned before token: %v", err)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for token: %v; receiver=%q sender=%q", ctx.Err(), receiverStatus.String(), senderStatus.String())
	}
	tok, err := token.Decode(raw, time.Now())
	if err != nil {
		t.Fatalf("token.Decode() error = %v", err)
	}
	if tok.Capabilities&token.CapabilityTransferV2 == 0 {
		t.Fatalf("token capabilities = %08b, want transfer v2; sender=%q", tok.Capabilities, senderStatus.String())
	}

	receiveErr := make(chan error, 1)
	go func() {
		receiveErr <- Receive(ctx, ReceiveConfig{
			Token:         raw,
			Emitter:       telemetry.New(&receiverStatus, telemetry.LevelVerbose),
			StdioOut:      &received,
			UsePublicDERP: true,
		})
	}()

	select {
	case err := <-receiveErr:
		if err != nil {
			t.Fatalf("Receive() error = %v receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receiver: %v; receiver=%q sender=%q", ctx.Err(), receiverStatus.String(), senderStatus.String())
	}
	select {
	case err := <-offerErr:
		if err != nil {
			t.Fatalf("Offer() error = %v receiver=%q sender=%q", err, receiverStatus.String(), senderStatus.String())
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for sender: %v; receiver=%q sender=%q", ctx.Err(), receiverStatus.String(), senderStatus.String())
	}

	if !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("receiver output length = %d, want %d", received.Len(), len(payload))
	}
	if got := senderStatus.String(); !strings.Contains(got, string(StateTryingDirect)) || !strings.Contains(got, string(StateDirect)) {
		t.Fatalf("sender status = %q, want v2 offer direct promotion", got)
	}
	if got := receiverStatus.String(); !strings.Contains(got, string(StateTryingDirect)) || !strings.Contains(got, string(StateDirect)) {
		t.Fatalf("receiver status = %q, want v2 offer direct promotion", got)
	}
}

func TestExternalV2ReceiverCancelAbortsSender(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

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

func TestExternalV2SenderCancelAbortsReceiver(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sendCtx, cancelSend := context.WithCancel(ctx)

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	wrote := make(chan struct{})
	go func() {
		_, err := listenExternal(ctx, ListenConfig{
			TokenSink:     tokenSink,
			StdioOut:      &cancelPeerOnWrite{cancel: cancelSend, wrote: wrote},
			ForceRelay:    true,
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
		sendErr <- sendExternal(sendCtx, SendConfig{
			Token:          raw,
			StdioIn:        &cancelablePrefixReader{ctx: sendCtx, limit: 2 << 20},
			ForceRelay:     true,
			UsePublicDERP:  true,
			ParallelPolicy: FixedParallelPolicy(1),
		})
	}()

	select {
	case <-wrote:
	case err := <-listenErr:
		t.Fatalf("listenExternal() returned before canceling sender: %v", err)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receiver write: %v", ctx.Err())
	}

	select {
	case err := <-listenErr:
		if !errors.Is(err, ErrPeerAborted) {
			t.Fatalf("listenExternal() error = %v, want %v", err, ErrPeerAborted)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for listener abort: %v", ctx.Err())
	}

	select {
	case err := <-sendErr:
		if err == nil {
			t.Fatalf("sendExternal() error = nil, want cancellation")
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for sender exit: %v", ctx.Err())
	}
}

func TestExternalV2TransferTraceCompletes(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

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

type cancelPeerOnWrite struct {
	once   sync.Once
	cancel context.CancelFunc
	wrote  chan<- struct{}
}

func (w *cancelPeerOnWrite) Write(p []byte) (int, error) {
	w.once.Do(func() {
		if w.wrote != nil {
			close(w.wrote)
		}
		w.cancel()
	})
	return len(p), nil
}

type cancelablePrefixReader struct {
	ctx   context.Context
	limit int
	read  int
}

func (r *cancelablePrefixReader) Read(p []byte) (int, error) {
	if r.read < r.limit {
		remaining := r.limit - r.read
		if remaining < len(p) {
			p = p[:remaining]
		}
		clear(p)
		r.read += len(p)
		return len(p), nil
	}
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
