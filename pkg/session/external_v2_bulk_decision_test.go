// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/telemetry"
	"tailscale.com/types/key"
)

type externalV2BulkTestWire struct {
	send   func(context.Context, externalV2BulkControl) error
	events <-chan externalV2BulkControlEvent
	close  func()
}

func (w externalV2BulkTestWire) Send(ctx context.Context, message externalV2BulkControl) error {
	return w.send(ctx, message)
}
func (w externalV2BulkTestWire) Events() <-chan externalV2BulkControlEvent { return w.events }
func (w externalV2BulkTestWire) Close()                                    { w.close() }

func newExternalV2BulkTestWirePair(t *testing.T, drop func(bool, externalV2BulkControl) bool) (externalV2BulkControlWire, externalV2BulkControlWire) {
	t.Helper()
	left := make(chan externalV2BulkControlEvent, 32)
	right := make(chan externalV2BulkControlEvent, 32)
	makeWire := func(fromSender bool, outbound chan<- externalV2BulkControlEvent, inbound <-chan externalV2BulkControlEvent) externalV2BulkControlWire {
		return externalV2BulkTestWire{
			send: func(ctx context.Context, message externalV2BulkControl) error {
				if drop != nil && drop(fromSender, message) {
					return nil
				}
				select {
				case outbound <- externalV2BulkControlEvent{Control: message}:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
			events: inbound,
			close:  func() {},
		}
	}
	return makeWire(true, right, left), makeWire(false, left, right)
}

func newExternalV2BulkTestCoordinator(ctx context.Context, wire externalV2BulkControlWire, emitter *telemetry.Emitter) *externalV2BulkDecisionCoordinator {
	c := newExternalV2BulkDecisionCoordinatorWithWireAndBarrier(ctx, wire, emitter, 250*time.Millisecond)
	c.retry = 25 * time.Millisecond
	c.readyWait = 75 * time.Millisecond
	return c
}

func newExternalV2BulkTestCoordinatorWithBarrier(ctx context.Context, wire externalV2BulkControlWire, barrierWait time.Duration) *externalV2BulkDecisionCoordinator {
	c := newExternalV2BulkDecisionCoordinatorWithWireAndBarrier(ctx, wire, nil, barrierWait)
	c.retry = 25 * time.Millisecond
	c.readyWait = 75 * time.Millisecond
	return c
}

type externalV2BulkReceiverResult struct {
	probe      externalV2BulkPacketProbeResult
	decision   externalV2BulkDecision
	cleanupErr error
	err        error
}

func resolveExternalV2BulkReceiver(
	ctx context.Context,
	c *externalV2BulkDecisionCoordinator,
	result externalV2BulkPacketProbeResult,
	err error,
) <-chan externalV2BulkReceiverResult {
	resultCh := make(chan externalV2BulkReceiverResult, 1)
	go func() {
		probe, decision, cleanupErr, resolveErr := c.ResolveReceiver(ctx, func(context.Context) (externalV2BulkPacketProbeResult, error) {
			return result, err
		})
		resultCh <- externalV2BulkReceiverResult{probe: probe, decision: decision, cleanupErr: cleanupErr, err: resolveErr}
	}()
	return resultCh
}

func TestExternalV2BulkDecisionCoordinatorSelectsBulkAfterBothReady(t *testing.T) {
	ctx := context.Background()
	senderWire, receiverWire := newExternalV2BulkTestWirePair(t, nil)
	sender := newExternalV2BulkTestCoordinator(ctx, senderWire, nil)
	receiver := newExternalV2BulkTestCoordinator(ctx, receiverWire, nil)
	defer sender.Close()
	defer receiver.Close()

	receiverCh := resolveExternalV2BulkReceiver(ctx, receiver, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 800}, nil)
	senderDecision, err := sender.ResolveSender(ctx, 77, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 900}, nil)
	if err != nil {
		t.Fatal(err)
	}
	received := <-receiverCh
	if received.err != nil {
		t.Fatal(received.err)
	}
	want := externalV2BulkDecision{Mode: externalV2BulkModeBulk, ProbeRunID: 77, SelectedMbps: 800, Reason: externalV2BulkReasonBothAccepted}
	if senderDecision != want || received.decision != want {
		t.Fatalf("decisions = (sender %+v, receiver %+v), want %+v", senderDecision, received.decision, want)
	}
	if received.probe.RunID != 77 || received.probe.SelectedMbps != 800 {
		t.Fatalf("receiver probe = %+v", received.probe)
	}
}

func TestExternalV2BulkDecisionCoordinatorRejectsLocalCleanupBeforeReadiness(t *testing.T) {
	var sends atomic.Int32
	receiver := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
		send: func(context.Context, externalV2BulkControl) error {
			sends.Add(1)
			return nil
		},
		events: make(chan externalV2BulkControlEvent),
		close:  func() {},
	}, nil)
	defer receiver.Close()

	cleanupFault := errors.New("receiver probe cleanup failed")
	receiverCh := resolveExternalV2BulkReceiver(
		context.Background(),
		receiver,
		externalV2BulkPacketProbeResult{RunID: 77},
		errors.Join(errExternalV2BulkPacketProbeRejected, newExternalV2BulkPacketProbeCleanupError(cleanupFault)),
	)
	var received externalV2BulkReceiverResult
	select {
	case received = <-receiverCh:
	case <-time.After(time.Second):
		t.Fatal("receiver did not reject cleanup failure")
	}
	if !errors.Is(received.cleanupErr, cleanupFault) {
		t.Fatalf("receiver cleanup error = %v, want %v", received.cleanupErr, cleanupFault)
	}
	if !errors.Is(received.err, cleanupFault) {
		t.Fatalf("receiver decision error = %v, want cleanup fault %v", received.err, cleanupFault)
	}
	if received.decision != (externalV2BulkDecision{}) {
		t.Fatalf("receiver decision = %+v, want zero decision", received.decision)
	}
	if sends.Load() != 0 {
		t.Fatalf("receiver control sends = %d, want 0 after cleanup failure", sends.Load())
	}
}

func TestExternalV2BulkDecisionCoordinatorProbeVetoesSelectQUIC(t *testing.T) {
	tests := []struct {
		name        string
		senderErr   error
		receiverErr error
		wantMode    string
		wantReason  string
	}{
		{"sender-rejects", errExternalV2BulkPacketProbeRejected, nil, externalV2BulkModeQUIC, externalV2BulkReasonSenderProbeRejected},
		{"receiver-rejects", nil, errExternalV2BulkPacketProbeRejected, externalV2BulkModeQUIC, externalV2BulkReasonReceiverProbeRejected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			senderWire, receiverWire := newExternalV2BulkTestWirePair(t, nil)
			sender := newExternalV2BulkTestCoordinator(ctx, senderWire, nil)
			receiver := newExternalV2BulkTestCoordinator(ctx, receiverWire, nil)
			defer sender.Close()
			defer receiver.Close()

			receiverCh := resolveExternalV2BulkReceiver(ctx, receiver, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 800}, tt.receiverErr)
			senderDecision, err := sender.ResolveSender(ctx, 77, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 900}, tt.senderErr)
			if err != nil {
				t.Fatal(err)
			}
			received := <-receiverCh
			if received.err != nil {
				t.Fatal(received.err)
			}
			want := externalV2BulkDecision{Mode: tt.wantMode, ProbeRunID: 77, Reason: tt.wantReason}
			if senderDecision != want || received.decision != want {
				t.Fatalf("decisions = (sender %+v, receiver %+v), want %+v", senderDecision, received.decision, want)
			}
		})
	}
}

func TestExternalV2BulkDecisionCoordinatorAcceptsCleanReceiverRejection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	senderWire, receiverWire := newExternalV2BulkTestWirePair(t, nil)
	sender := newExternalV2BulkTestCoordinator(ctx, senderWire, nil)
	receiver := newExternalV2BulkTestCoordinator(ctx, receiverWire, nil)
	defer sender.Close()
	defer receiver.Close()

	wantProbe := externalV2BulkPacketProbeResult{
		RunID:          77,
		RejectStage:    "selector",
		RejectTrain:    2,
		RejectRateMbps: 1000,
		HandoffDrain:   externalV2BulkPacketHandoffDrainResult{Lanes: 4, Datagrams: 9, Duration: time.Millisecond},
	}
	receiverCh := resolveExternalV2BulkReceiver(ctx, receiver, wantProbe, errExternalV2BulkPacketProbeRejected)
	decision, err := sender.ResolveSender(ctx, 77, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 900}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var received externalV2BulkReceiverResult
	select {
	case received = <-receiverCh:
	case <-ctx.Done():
		t.Fatalf("receiver did not negotiate clean ordinary rejection: %v", ctx.Err())
	}
	if received.err != nil || received.cleanupErr != nil {
		t.Fatalf("receiver errors = decision:%v cleanup:%v", received.err, received.cleanupErr)
	}
	if received.probe.RunID != wantProbe.RunID || received.probe.RejectStage != wantProbe.RejectStage ||
		received.probe.RejectTrain != wantProbe.RejectTrain || received.probe.RejectRateMbps != wantProbe.RejectRateMbps ||
		received.probe.HandoffDrain != wantProbe.HandoffDrain {
		t.Fatalf("receiver probe = %+v, want %+v", received.probe, wantProbe)
	}
	wantDecision := externalV2BulkDecision{
		Mode: externalV2BulkModeQUIC, ProbeRunID: 77, Reason: externalV2BulkReasonReceiverProbeRejected,
	}
	if decision != wantDecision || received.decision != wantDecision {
		t.Fatalf("decisions = (sender %+v, receiver %+v), want %+v", decision, received.decision, wantDecision)
	}
}

func TestExternalV2BulkPacketProbeDecisionFailureRequiresExactCancellationShape(t *testing.T) {
	operationalFault := errors.New("injected probe I/O failure")
	cleanupFault := errors.New("injected probe cleanup failure")
	exactCanceled := errors.Join(errExternalV2BulkPacketProbeRejected, context.Canceled)
	for _, tt := range []struct {
		name          string
		err           error
		allowCanceled bool
		wantAllowed   bool
	}{
		{name: "nil", allowCanceled: true, wantAllowed: true},
		{name: "ordinary-rejection", err: errExternalV2BulkPacketProbeRejected, wantAllowed: true},
		{name: "direct-canceled", err: context.Canceled, allowCanceled: true, wantAllowed: true},
		{name: "exact-receiver-canceled", err: exactCanceled, allowCanceled: true, wantAllowed: true},
		{name: "canceled-not-allowed", err: exactCanceled},
		{name: "wrapped-canceled", err: fmt.Errorf("wrapped cancellation: %w", context.Canceled), allowCanceled: true},
		{name: "wrapped-exact", err: fmt.Errorf("wrapped receiver cancellation: %w", exactCanceled), allowCanceled: true},
		{name: "one-child-join", err: errors.Join(context.Canceled), allowCanceled: true},
		{name: "nested-join", err: errors.Join(errExternalV2BulkPacketProbeRejected, errors.Join(context.Canceled)), allowCanceled: true},
		{name: "mixed-nested-operational", err: errors.Join(errExternalV2BulkPacketProbeRejected, errors.Join(context.Canceled, operationalFault)), allowCanceled: true},
		{name: "extra-operational-leaf", err: errors.Join(errExternalV2BulkPacketProbeRejected, context.Canceled, operationalFault), allowCanceled: true},
		{name: "reordered", err: errors.Join(context.Canceled, errExternalV2BulkPacketProbeRejected), allowCanceled: true},
		{name: "cleanup-failure", err: errors.Join(errExternalV2BulkPacketProbeRejected, context.Canceled, newExternalV2BulkPacketProbeCleanupError(cleanupFault)), allowCanceled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := externalV2BulkPacketProbeDecisionFailure(tt.err, tt.allowCanceled)
			if tt.wantAllowed {
				if got != nil {
					t.Fatalf("decision failure = %v, want allowed", got)
				}
				return
			}
			if got != tt.err {
				t.Fatalf("decision failure = %#v, want original fatal error %#v", got, tt.err)
			}
		})
	}
}

func TestExternalV2BulkDecisionCoordinatorRejectsMixedCancellationBeforeAcknowledgement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	events := make(chan externalV2BulkControlEvent, 1)
	var sends atomic.Int32
	var status syncBuffer
	receiver := newExternalV2BulkTestCoordinator(ctx, externalV2BulkTestWire{
		send: func(context.Context, externalV2BulkControl) error {
			sends.Add(1)
			return nil
		},
		events: events,
		close:  func() {},
	}, telemetry.New(&status, telemetry.LevelVerbose))
	defer receiver.Close()

	probeStarted := make(chan struct{})
	probeCanceled := make(chan struct{})
	operationalFault := errors.New("injected mixed probe I/O failure")
	resultCh := resolveExternalV2BulkReceiverWithProbe(ctx, receiver, func(probeCtx context.Context) (externalV2BulkPacketProbeResult, error) {
		close(probeStarted)
		<-probeCtx.Done()
		close(probeCanceled)
		return externalV2BulkPacketProbeResult{RunID: 77}, errors.Join(
			errExternalV2BulkPacketProbeRejected,
			errors.Join(context.Canceled, operationalFault),
		)
	})
	select {
	case <-probeStarted:
	case <-ctx.Done():
		t.Fatalf("receiver probe did not start: %v", ctx.Err())
	}
	events <- externalV2BulkControlEvent{Control: externalV2BulkDecision{
		Mode: externalV2BulkModeQUIC, ProbeRunID: 77, Reason: externalV2BulkReasonSenderProbeRejected,
	}.control(externalV2BulkPhaseDecision)}
	select {
	case <-probeCanceled:
	case <-ctx.Done():
		t.Fatalf("receiver probe was not canceled by early QUIC decision: %v", ctx.Err())
	}

	var got externalV2BulkReceiverResult
	select {
	case got = <-resultCh:
	case <-ctx.Done():
		t.Fatalf("receiver did not reject mixed cancellation: %v", ctx.Err())
	}
	if !errors.Is(got.err, operationalFault) {
		t.Fatalf("receiver decision error = %v, want operational fault %v", got.err, operationalFault)
	}
	if got.cleanupErr != nil {
		t.Fatalf("receiver cleanup error = %v, want nil", got.cleanupErr)
	}
	if got.decision != (externalV2BulkDecision{}) {
		t.Fatalf("receiver decision = %+v, want zero decision", got.decision)
	}
	if sends.Load() != 0 {
		t.Fatalf("receiver control sends = %d, want zero ACK/readiness sends", sends.Load())
	}
	if got := status.String(); got != "" {
		t.Fatalf("receiver emitted decision/fallback progress for fatal mixed probe outcome: %q", got)
	}
}

func TestExternalV2BulkDecisionCoordinatorRetriesDroppedTransitions(t *testing.T) {
	var mu sync.Mutex
	counts := make(map[string]int)
	drop := func(fromSender bool, message externalV2BulkControl) bool {
		mu.Lock()
		defer mu.Unlock()
		key := message.Phase
		counts[key]++
		return counts[key] == 1
	}
	ctx := context.Background()
	senderWire, receiverWire := newExternalV2BulkTestWirePair(t, drop)
	sender := newExternalV2BulkTestCoordinator(ctx, senderWire, nil)
	receiver := newExternalV2BulkTestCoordinator(ctx, receiverWire, nil)
	defer sender.Close()
	defer receiver.Close()

	receiverCh := resolveExternalV2BulkReceiver(ctx, receiver, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 800}, nil)
	if _, err := sender.ResolveSender(ctx, 77, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 900}, nil); err != nil {
		t.Fatal(err)
	}
	if received := <-receiverCh; received.err != nil {
		t.Fatal(received.err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, phase := range []string{externalV2BulkPhaseReady, externalV2BulkPhaseDecision, externalV2BulkPhaseAck} {
		if counts[phase] < 2 {
			t.Fatalf("%s sends = %d, want retry", phase, counts[phase])
		}
	}
}

func TestExternalV2BulkDecisionCoordinatorIgnoresExactDuplicates(t *testing.T) {
	left := make(chan externalV2BulkControlEvent, 32)
	right := make(chan externalV2BulkControlEvent, 32)
	makeWire := func(outbound chan<- externalV2BulkControlEvent, inbound <-chan externalV2BulkControlEvent) externalV2BulkControlWire {
		return externalV2BulkTestWire{
			send: func(ctx context.Context, message externalV2BulkControl) error {
				for range 2 {
					select {
					case outbound <- externalV2BulkControlEvent{Control: message}:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			},
			events: inbound,
			close:  func() {},
		}
	}
	var senderLog, receiverLog bytes.Buffer
	ctx := context.Background()
	sender := newExternalV2BulkTestCoordinator(ctx, makeWire(right, left), telemetry.New(&senderLog, telemetry.LevelVerbose))
	receiver := newExternalV2BulkTestCoordinator(ctx, makeWire(left, right), telemetry.New(&receiverLog, telemetry.LevelVerbose))
	defer sender.Close()
	defer receiver.Close()

	receiverCh := resolveExternalV2BulkReceiver(ctx, receiver, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 800}, nil)
	if _, err := sender.ResolveSender(ctx, 77, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 900}, nil); err != nil {
		t.Fatal(err)
	}
	if received := <-receiverCh; received.err != nil {
		t.Fatal(received.err)
	}
	for name, log := range map[string]string{"sender": senderLog.String(), "receiver": receiverLog.String()} {
		for _, transition := range []string{"v2-bulk-ready=", "v2-bulk-decision=", "v2-bulk-decision-ack="} {
			if got := strings.Count(log, transition); got != 1 {
				t.Fatalf("%s %s count = %d, want 1, log %q", name, transition, got, log)
			}
		}
	}
}

func TestExternalV2BulkDecisionCoordinatorNeverChangesDecisionWithoutAck(t *testing.T) {
	var mu sync.Mutex
	var decisions []externalV2BulkControl
	drop := func(fromSender bool, message externalV2BulkControl) bool {
		mu.Lock()
		defer mu.Unlock()
		if fromSender && message.Phase == externalV2BulkPhaseDecision {
			decisions = append(decisions, message)
		}
		return !fromSender && message.Phase == externalV2BulkPhaseAck
	}
	ctx := context.Background()
	senderWire, receiverWire := newExternalV2BulkTestWirePair(t, drop)
	sender := newExternalV2BulkTestCoordinator(ctx, senderWire, nil)
	receiver := newExternalV2BulkTestCoordinator(ctx, receiverWire, nil)
	defer sender.Close()
	defer receiver.Close()

	receiverCh := resolveExternalV2BulkReceiver(ctx, receiver, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 800}, nil)
	_, err := sender.ResolveSender(ctx, 77, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 900}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("sender error = %v, want deadline exceeded", err)
	}
	if received := <-receiverCh; received.err != nil {
		t.Fatal(received.err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(decisions) < 2 {
		t.Fatalf("decision sends = %d, want retries", len(decisions))
	}
	for _, decision := range decisions[1:] {
		if decision != decisions[0] {
			t.Fatalf("decision changed from %+v to %+v", decisions[0], decision)
		}
	}
}

func TestExternalV2BulkDecisionCoordinatorRejectsConflictingRunIDs(t *testing.T) {
	ready := externalV2BulkControl{Protocol: externalV2Protocol, Phase: externalV2BulkPhaseReady, ProbeRunID: 88, Mode: externalV2BulkModeBulk, SelectedMbps: 800, Reason: externalV2BulkReasonProbeAccepted}
	decision := externalV2BulkDecision{Mode: externalV2BulkModeBulk, ProbeRunID: 77, SelectedMbps: 800, Reason: externalV2BulkReasonBothAccepted}.control(externalV2BulkPhaseDecision)

	senderEvents := make(chan externalV2BulkControlEvent, 1)
	senderEvents <- externalV2BulkControlEvent{Control: ready}
	sender := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
		send: func(context.Context, externalV2BulkControl) error { return nil }, events: senderEvents, close: func() {},
	}, nil)
	defer sender.Close()
	if _, err := sender.ResolveSender(context.Background(), 77, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 900}, nil); !errors.Is(err, errExternalV2BulkDecisionProtocol) {
		t.Fatalf("sender error = %v, want protocol error", err)
	}

	receiverEvents := make(chan externalV2BulkControlEvent, 1)
	receiverEvents <- externalV2BulkControlEvent{Control: decision}
	receiver := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
		send: func(context.Context, externalV2BulkControl) error { return nil }, events: receiverEvents, close: func() {},
	}, nil)
	defer receiver.Close()
	_, _, _, err := receiver.ResolveReceiver(context.Background(), func(context.Context) (externalV2BulkPacketProbeResult, error) {
		return externalV2BulkPacketProbeResult{RunID: 88, SelectedMbps: 800}, nil
	})
	if !errors.Is(err, errExternalV2BulkDecisionProtocol) {
		t.Fatalf("receiver error = %v, want protocol error", err)
	}
}

func TestExternalV2BulkDecisionCoordinatorRejectsMismatchedSenderProbeRunID(t *testing.T) {
	events := make(chan externalV2BulkControlEvent, 2)
	events <- externalV2BulkControlEvent{Control: externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseReady,
		ProbeRunID: 77, Mode: externalV2BulkModeBulk, SelectedMbps: 800, Reason: externalV2BulkReasonProbeAccepted,
	}}
	c := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
		send: func(_ context.Context, message externalV2BulkControl) error {
			if message.Phase == externalV2BulkPhaseDecision {
				events <- externalV2BulkControlEvent{Control: externalV2BulkDecisionFromControl(message).control(externalV2BulkPhaseAck)}
			}
			return nil
		},
		events: events, close: func() {},
	}, nil)
	defer c.Close()
	_, err := c.ResolveSender(context.Background(), 77, externalV2BulkPacketProbeResult{RunID: 88, SelectedMbps: 900}, nil)
	if !errors.Is(err, errExternalV2BulkDecisionProtocol) {
		t.Fatalf("error = %v, want protocol error", err)
	}
}

func TestExternalV2BulkDecisionCoordinatorRejectsContradictoryReadiness(t *testing.T) {
	events := make(chan externalV2BulkControlEvent, 2)
	events <- externalV2BulkControlEvent{Control: externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseReady,
		ProbeRunID: 77, Mode: externalV2BulkModeBulk, SelectedMbps: 800, Reason: externalV2BulkReasonProbeAccepted,
	}}
	events <- externalV2BulkControlEvent{Control: externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseReady,
		ProbeRunID: 77, Mode: externalV2BulkModeQUIC, Reason: externalV2BulkReasonReceiverProbeRejected,
	}}
	c := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
		send: func(context.Context, externalV2BulkControl) error { return nil }, events: events, close: func() {},
	}, nil)
	defer c.Close()
	if _, err := c.ResolveSender(context.Background(), 77, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 900}, nil); !errors.Is(err, errExternalV2BulkDecisionProtocol) {
		t.Fatalf("error = %v, want protocol error", err)
	}
}

func TestExternalV2BulkDecisionCoordinatorRejectsMismatchedAcknowledgement(t *testing.T) {
	events := make(chan externalV2BulkControlEvent, 2)
	events <- externalV2BulkControlEvent{Control: externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseReady,
		ProbeRunID: 77, Mode: externalV2BulkModeBulk, SelectedMbps: 800, Reason: externalV2BulkReasonProbeAccepted,
	}}
	c := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
		send: func(_ context.Context, message externalV2BulkControl) error {
			if message.Phase == externalV2BulkPhaseDecision {
				ack := externalV2BulkDecisionFromControl(message).control(externalV2BulkPhaseAck)
				ack.SelectedMbps++
				events <- externalV2BulkControlEvent{Control: ack}
			}
			return nil
		},
		events: events, close: func() {},
	}, nil)
	defer c.Close()

	_, err := c.ResolveSender(context.Background(), 77, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 900}, nil)
	if !errors.Is(err, errExternalV2BulkDecisionProtocol) || err.Error() != "bulk decision protocol error: acknowledgement does not match decision" {
		t.Fatalf("error = %v, want exact acknowledgement mismatch protocol error", err)
	}
}

func TestExternalV2BulkDecisionCoordinatorAcceptsLateReadinessBeforeAcknowledgement(t *testing.T) {
	events := make(chan externalV2BulkControlEvent, 2)
	c := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
		send: func(_ context.Context, message externalV2BulkControl) error {
			if message.Phase == externalV2BulkPhaseDecision {
				events <- externalV2BulkControlEvent{Control: externalV2BulkControl{
					Protocol: externalV2Protocol, Phase: externalV2BulkPhaseReady,
					ProbeRunID: 77, Mode: externalV2BulkModeBulk, SelectedMbps: 800, Reason: externalV2BulkReasonProbeAccepted,
				}}
				events <- externalV2BulkControlEvent{Control: externalV2BulkDecisionFromControl(message).control(externalV2BulkPhaseAck)}
			}
			return nil
		},
		events: events, close: func() {},
	}, nil)
	c.readyWait = time.Millisecond
	defer c.Close()

	decision, err := c.ResolveSender(context.Background(), 77, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 900}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := externalV2BulkDecision{Mode: externalV2BulkModeQUIC, ProbeRunID: 77, Reason: externalV2BulkReasonReadinessTimeout}
	if decision != want {
		t.Fatalf("decision = %+v, want %+v", decision, want)
	}
}

func TestExternalV2BulkDecisionCoordinatorRejectsSecondDifferentDecision(t *testing.T) {
	events := make(chan externalV2BulkControlEvent, 2)
	first := externalV2BulkDecision{Mode: externalV2BulkModeBulk, ProbeRunID: 77, SelectedMbps: 800, Reason: externalV2BulkReasonBothAccepted}
	second := externalV2BulkDecision{Mode: externalV2BulkModeQUIC, ProbeRunID: 77, Reason: externalV2BulkReasonSenderProbeRejected}
	c := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
		send: func(_ context.Context, message externalV2BulkControl) error {
			if message.Phase == externalV2BulkPhaseReady {
				events <- externalV2BulkControlEvent{Control: first.control(externalV2BulkPhaseDecision)}
				events <- externalV2BulkControlEvent{Control: second.control(externalV2BulkPhaseDecision)}
			}
			return nil
		},
		events: events, close: func() {},
	}, nil)
	defer c.Close()
	_, _, _, err := c.ResolveReceiver(context.Background(), func(context.Context) (externalV2BulkPacketProbeResult, error) {
		return externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 800}, nil
	})
	if !errors.Is(err, errExternalV2BulkDecisionProtocol) {
		t.Fatalf("error = %v, want protocol error", err)
	}
}

func TestExternalV2BulkDecisionCoordinatorSurfacesLateDifferentDecision(t *testing.T) {
	events := make(chan externalV2BulkControlEvent, 4)
	sent := make(chan externalV2BulkControl, 4)
	c := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
		send: func(ctx context.Context, message externalV2BulkControl) error {
			select {
			case sent <- message:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		events: events, close: func() {},
	}, nil)
	defer c.Close()

	resultCh := resolveExternalV2BulkReceiver(context.Background(), c, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 800}, nil)
	if ready := <-sent; ready.Phase != externalV2BulkPhaseReady {
		t.Fatalf("first send = %+v, want readiness", ready)
	}
	first := externalV2BulkDecision{Mode: externalV2BulkModeBulk, ProbeRunID: 77, SelectedMbps: 800, Reason: externalV2BulkReasonBothAccepted}
	events <- externalV2BulkControlEvent{Control: first.control(externalV2BulkPhaseDecision)}
	if ack := <-sent; ack != first.control(externalV2BulkPhaseAck) {
		t.Fatalf("acknowledgement = %+v, want %+v", ack, first.control(externalV2BulkPhaseAck))
	}
	if result := <-resultCh; result.err != nil || result.decision != first {
		t.Fatalf("receiver result = %+v", result)
	}

	second := externalV2BulkDecision{Mode: externalV2BulkModeQUIC, ProbeRunID: 77, Reason: externalV2BulkReasonSenderProbeRejected}
	events <- externalV2BulkControlEvent{Control: second.control(externalV2BulkPhaseDecision)}
	select {
	case <-c.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("coordinator context was not canceled by late conflicting decision")
	}
	if cause := context.Cause(c.Context()); !errors.Is(cause, errExternalV2BulkDecisionProtocol) {
		t.Fatalf("coordinator cause = %v, want protocol error", cause)
	}
}

func TestExternalV2BulkDecisionCoordinatorBarrierExpiryLeavesTransferContextAliveAndStopsResponder(t *testing.T) {
	events := make(chan externalV2BulkControlEvent, 4)
	sent := make(chan externalV2BulkControl, 4)
	wireClosed := make(chan struct{}, 2)
	const barrierWait = 75 * time.Millisecond
	c := newExternalV2BulkTestCoordinatorWithBarrier(context.Background(), externalV2BulkTestWire{
		send: func(ctx context.Context, message externalV2BulkControl) error {
			select {
			case sent <- message:
				return nil
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		},
		events: events,
		close:  func() { wireClosed <- struct{}{} },
	}, barrierWait)
	t.Cleanup(c.Close)

	resultCh := resolveExternalV2BulkReceiver(context.Background(), c, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 800}, nil)
	if ready := <-sent; ready.Phase != externalV2BulkPhaseReady {
		t.Fatalf("first send = %+v, want readiness", ready)
	}
	decision := externalV2BulkDecision{Mode: externalV2BulkModeBulk, ProbeRunID: 77, SelectedMbps: 800, Reason: externalV2BulkReasonBothAccepted}
	events <- externalV2BulkControlEvent{Control: decision.control(externalV2BulkPhaseDecision)}
	if ack := <-sent; ack != decision.control(externalV2BulkPhaseAck) {
		t.Fatalf("acknowledgement = %+v, want %+v", ack, decision.control(externalV2BulkPhaseAck))
	}
	if result := <-resultCh; result.err != nil || result.decision != decision {
		t.Fatalf("receiver result = %+v", result)
	}

	select {
	case <-wireClosed:
	case <-time.After(2 * barrierWait):
		t.Fatal("control wire remained subscribed after agreement barrier expired")
	}
	if err := c.Context().Err(); err != nil {
		t.Fatalf("transfer context after agreement barrier = %v (cause %v), want alive", err, context.Cause(c.Context()))
	}
	events <- externalV2BulkControlEvent{Control: decision.control(externalV2BulkPhaseDecision)}
	select {
	case message := <-sent:
		t.Fatalf("duplicate acknowledgement after agreement barrier = %+v", message)
	case <-time.After(3 * c.retry):
	}
	c.Close()
	select {
	case <-wireClosed:
		t.Fatal("control wire closed more than once")
	case <-time.After(3 * c.retry):
	}
}

func TestExternalV2BulkDecisionCoordinatorBarrierExpiryClosesProductionWireOnceWithoutTransferError(t *testing.T) {
	wireCtx, cancelWire := context.WithCancel(context.Background())
	packets := make(chan derpbind.Packet)
	var unsubscribeCalls atomic.Int32
	wire := &externalV2BulkDERPControlWire{
		ctx: wireCtx, cancel: cancelWire,
		events: make(chan externalV2BulkControlEvent, 1),
		unsubscribe: func() {
			unsubscribeCalls.Add(1)
			close(packets)
		},
	}
	readDone := make(chan struct{})
	go func() {
		wire.readLoop(packets)
		close(readDone)
	}()

	c := newExternalV2BulkDecisionCoordinatorWithWireAndBarrier(context.Background(), wire, nil, 50*time.Millisecond)
	t.Cleanup(c.Close)
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("production control wire reader remained alive after agreement barrier")
	}
	if got := unsubscribeCalls.Load(); got != 1 {
		t.Fatalf("unsubscribe calls after agreement barrier = %d, want 1", got)
	}
	if err := c.Context().Err(); err != nil {
		t.Fatalf("transfer context after production wire close = %v (cause %v), want alive", err, context.Cause(c.Context()))
	}
	select {
	case event := <-wire.Events():
		t.Fatalf("production wire emitted terminal event during ordinary barrier expiry: %+v", event)
	default:
	}
	c.Close()
	if got := unsubscribeCalls.Load(); got != 1 {
		t.Fatalf("unsubscribe calls after coordinator Close = %d, want 1", got)
	}
}

func TestExternalV2BulkDecisionCoordinatorTransferContextCancellation(t *testing.T) {
	newCoordinator := func(ctx context.Context) (*externalV2BulkDecisionCoordinator, <-chan struct{}) {
		closed := make(chan struct{})
		return newExternalV2BulkTestCoordinatorWithBarrier(ctx, externalV2BulkTestWire{
			send:   func(context.Context, externalV2BulkControl) error { return nil },
			events: make(chan externalV2BulkControlEvent),
			close:  func() { close(closed) },
		}, time.Second), closed
	}

	t.Run("close", func(t *testing.T) {
		c, wireClosed := newCoordinator(context.Background())
		c.Close()
		select {
		case <-c.Context().Done():
		case <-time.After(time.Second):
			t.Fatal("transfer context remained alive after Close")
		}
		if cause := context.Cause(c.Context()); !errors.Is(cause, context.Canceled) {
			t.Fatalf("transfer context cause = %v, want canceled", cause)
		}
		select {
		case <-wireClosed:
		case <-time.After(time.Second):
			t.Fatal("control wire remained open after Close")
		}
	})

	t.Run("parent", func(t *testing.T) {
		parent, cancel := context.WithCancelCause(context.Background())
		c, wireClosed := newCoordinator(parent)
		defer c.Close()
		want := errors.New("parent canceled transfer")
		cancel(want)
		select {
		case <-c.Context().Done():
		case <-time.After(time.Second):
			t.Fatal("transfer context remained alive after parent cancellation")
		}
		if cause := context.Cause(c.Context()); !errors.Is(cause, want) {
			t.Fatalf("transfer context cause = %v, want %v", cause, want)
		}
		select {
		case <-wireClosed:
		case <-time.After(time.Second):
			t.Fatal("control wire remained open after parent cancellation")
		}
	})
}

func TestExternalV2BulkDecisionCoordinatorReportsClosedWire(t *testing.T) {
	events := make(chan externalV2BulkControlEvent)
	close(events)
	c := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
		send: func(context.Context, externalV2BulkControl) error { return nil }, events: events, close: func() {},
	}, nil)
	defer c.Close()
	if _, err := c.ResolveSender(context.Background(), 77, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 900}, nil); !errors.Is(err, ErrPeerDisconnected) {
		t.Fatalf("error = %v, want peer disconnected", err)
	}
}

func TestExternalV2BulkDecisionCoordinatorDERPWirePrioritizesTerminalEventWhenFull(t *testing.T) {
	newSaturatedWire := func(t *testing.T) (*externalV2BulkDERPControlWire, func()) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		wire := &externalV2BulkDERPControlWire{
			ctx: ctx, cancel: cancel, auth: externalPeerControlAuth{EnvelopeKey: [32]byte{1}},
			events: make(chan externalV2BulkControlEvent, 2), unsubscribe: func() {},
		}
		wire.events <- externalV2BulkControlEvent{Control: externalV2BulkControl{Phase: "ordinary-1"}}
		wire.events <- externalV2BulkControlEvent{Control: externalV2BulkControl{Phase: "ordinary-2"}}
		return wire, cancel
	}
	assertTerminal := func(t *testing.T, wire *externalV2BulkDERPControlWire, want error) {
		t.Helper()
		for range cap(wire.events) {
			event := <-wire.events
			if errors.Is(event.Err, want) {
				return
			}
		}
		t.Fatalf("saturated event buffer did not contain terminal error %v", want)
	}

	t.Run("authenticated-protocol-error", func(t *testing.T) {
		wire, cancel := newSaturatedWire(t)
		defer cancel()
		invalid := externalV2BulkControl{
			Protocol: externalV2Protocol, Phase: externalV2BulkPhaseDecision,
			ProbeRunID: 77, Mode: externalV2BulkModeBulk, SelectedMbps: 1, Reason: externalV2BulkReasonBothAccepted,
		}
		payload, err := marshalAuthenticatedEnvelope(envelope{Type: envelopeV2BulkControl, V2BulkControl: &invalid}, wire.auth)
		if err != nil {
			t.Fatal(err)
		}
		packets := make(chan derpbind.Packet, 1)
		packets <- derpbind.Packet{Payload: payload}
		done := make(chan struct{})
		go func() {
			wire.readLoop(packets)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("wire blocked reporting authenticated protocol error")
		}
		assertTerminal(t, wire, errExternalV2BulkDecisionProtocol)
	})

	t.Run("closed-subscription", func(t *testing.T) {
		wire, cancel := newSaturatedWire(t)
		defer cancel()
		packets := make(chan derpbind.Packet)
		close(packets)
		done := make(chan struct{})
		go func() {
			wire.readLoop(packets)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("wire blocked reporting closed subscription")
		}
		assertTerminal(t, wire, ErrPeerDisconnected)
	})

	t.Run("concurrent-drain", func(t *testing.T) {
		const attempts = 10_000
		for attempt := range attempts {
			ctx, cancel := context.WithCancel(context.Background())
			wire := &externalV2BulkDERPControlWire{
				ctx: ctx, cancel: cancel,
				events: make(chan externalV2BulkControlEvent, 1), unsubscribe: func() {},
			}
			wire.events <- externalV2BulkControlEvent{Control: externalV2BulkControl{Phase: "ordinary"}}
			start := make(chan struct{})
			reportDone := make(chan struct{})
			observed := make(chan bool, 1)
			go func() {
				<-start
				wire.reportTerminal(ErrPeerDisconnected)
				close(reportDone)
			}()
			go func() {
				<-start
				first := <-wire.events
				if errors.Is(first.Err, ErrPeerDisconnected) {
					observed <- true
					return
				}
				select {
				case event := <-wire.events:
					observed <- errors.Is(event.Err, ErrPeerDisconnected)
				case <-time.After(25 * time.Millisecond):
					observed <- false
				}
			}()
			close(start)
			if terminal := <-observed; !terminal {
				cancel()
				<-reportDone
				t.Fatalf("attempt %d lost terminal event during concurrent drain", attempt)
			}
			select {
			case <-reportDone:
			case <-time.After(25 * time.Millisecond):
				cancel()
				<-reportDone
				t.Fatalf("attempt %d blocked terminal reporter", attempt)
			}
			cancel()
		}
	})
}

func TestExternalV2BulkDecisionCoordinatorSenderVetoCancelsReceiverProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	probeStarted := make(chan struct{})
	drainStarted := make(chan struct{})
	drainRelease := make(chan struct{})
	var drainStartOnce sync.Once
	var drainReleaseOnce sync.Once
	releaseDrain := func() { drainReleaseOnce.Do(func() { close(drainRelease) }) }
	t.Cleanup(releaseDrain)
	previousDrain := externalV2BulkPacketDrainForHandoff
	externalV2BulkPacketDrainForHandoff = func(context.Context, externalV2BulkPacketPath) (externalV2BulkPacketHandoffDrainResult, error) {
		drainStartOnce.Do(func() { close(drainStarted) })
		select {
		case <-drainRelease:
			return externalV2BulkPacketHandoffDrainResult{Lanes: 1}, nil
		case <-time.After(2 * time.Second):
			return externalV2BulkPacketHandoffDrainResult{Lanes: 1}, errors.New("timed out waiting to release receiver handoff drain")
		}
	}
	t.Cleanup(func() { externalV2BulkPacketDrainForHandoff = previousDrain })

	receiverAcks := make(chan externalV2BulkControl, 4)
	observe := func(fromSender bool, message externalV2BulkControl) bool {
		if !fromSender && message.Phase == externalV2BulkPhaseAck {
			select {
			case receiverAcks <- message:
			default:
			}
		}
		return false
	}
	senderWire, receiverWire := newExternalV2BulkTestWirePair(t, observe)
	sender := newExternalV2BulkTestCoordinator(ctx, senderWire, nil)
	receiver := newExternalV2BulkTestCoordinator(ctx, receiverWire, nil)
	defer sender.Close()
	defer receiver.Close()

	senders, receiverConns := listenExternalV2BulkPacketTestConns(t, 1)
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	receiverCh := make(chan externalV2BulkReceiverResult, 1)
	go func() {
		probe, decision, cleanupErr, err := receiver.ResolveReceiver(ctx, func(probeCtx context.Context) (externalV2BulkPacketProbeResult, error) {
			close(probeStarted)
			return receiveExternalV2BulkPacketProbe(
				probeCtx,
				externalV2BulkPacketPath{Conns: receiverConns, Addrs: externalV2BulkPacketTestAddrs(senders)},
				auth,
				1,
				receiver,
			)
		})
		receiverCh <- externalV2BulkReceiverResult{probe: probe, decision: decision, cleanupErr: cleanupErr, err: err}
	}()
	select {
	case <-probeStarted:
	case <-ctx.Done():
		t.Fatalf("receiver probe did not start: %v", ctx.Err())
	}

	type senderResult struct {
		decision externalV2BulkDecision
		err      error
	}
	senderCh := make(chan senderResult, 1)
	go func() {
		decision, err := sender.ResolveSender(ctx, 77, externalV2BulkPacketProbeResult{RunID: 77}, errExternalV2BulkPacketProbeRejected)
		senderCh <- senderResult{decision: decision, err: err}
	}()
	select {
	case <-drainStarted:
	case <-ctx.Done():
		t.Fatalf("receiver handoff drain did not start: %v", ctx.Err())
	}
	select {
	case ack := <-receiverAcks:
		t.Fatalf("receiver acknowledged before handoff drain completed: %+v", ack)
	default:
	}
	releaseDrain()
	wantAck := externalV2BulkDecision{
		Mode: externalV2BulkModeQUIC, ProbeRunID: 77, Reason: externalV2BulkReasonSenderProbeRejected,
	}.control(externalV2BulkPhaseAck)
	select {
	case ack := <-receiverAcks:
		if ack != wantAck {
			t.Fatalf("receiver acknowledgement = %+v, want %+v", ack, wantAck)
		}
	case <-ctx.Done():
		t.Fatalf("receiver acknowledgement did not follow handoff drain: %v", ctx.Err())
	}
	var sent senderResult
	select {
	case sent = <-senderCh:
	case <-ctx.Done():
		t.Fatalf("sender did not return after receiver acknowledgement: %v", ctx.Err())
	}
	if sent.err != nil {
		t.Fatal(sent.err)
	}
	var received externalV2BulkReceiverResult
	select {
	case received = <-receiverCh:
	case <-ctx.Done():
		t.Fatalf("receiver did not return after acknowledgement: %v", ctx.Err())
	}
	if received.err != nil {
		t.Fatal(received.err)
	}
	if sent.decision.Mode != externalV2BulkModeQUIC || received.decision != sent.decision {
		t.Fatalf("decisions = (sender %+v, receiver %+v)", sent.decision, received.decision)
	}
}

func TestExternalV2BulkDecisionCoordinatorReadinessTimeoutSelectsQUIC(t *testing.T) {
	events := make(chan externalV2BulkControlEvent, 4)
	wire := externalV2BulkTestWire{
		send: func(ctx context.Context, message externalV2BulkControl) error {
			if message.Phase == externalV2BulkPhaseDecision {
				events <- externalV2BulkControlEvent{Control: externalV2BulkDecision{
					Mode: message.Mode, ProbeRunID: message.ProbeRunID, SelectedMbps: message.SelectedMbps, Reason: message.Reason,
				}.control(externalV2BulkPhaseAck)}
			}
			return nil
		},
		events: events,
		close:  func() {},
	}
	c := newExternalV2BulkTestCoordinator(context.Background(), wire, nil)
	defer c.Close()
	decision, err := c.ResolveSender(context.Background(), 77, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 900}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := externalV2BulkDecision{Mode: externalV2BulkModeQUIC, ProbeRunID: 77, Reason: externalV2BulkReasonReadinessTimeout}
	if decision != want {
		t.Fatalf("decision = %+v, want %+v", decision, want)
	}
}

func TestExternalV2BulkDecisionCoordinatorCloseStopsAcknowledgementResponder(t *testing.T) {
	receiverEvents := make(chan externalV2BulkControlEvent, 8)
	sent := make(chan externalV2BulkControl, 8)
	wire := externalV2BulkTestWire{
		send: func(ctx context.Context, message externalV2BulkControl) error {
			select {
			case sent <- message:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		events: receiverEvents,
		close:  func() {},
	}
	receiver := newExternalV2BulkTestCoordinator(context.Background(), wire, nil)

	resultCh := resolveExternalV2BulkReceiver(context.Background(), receiver, externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 800}, nil)
	ready := <-sent
	if ready.Phase != externalV2BulkPhaseReady {
		t.Fatalf("first send = %+v, want readiness", ready)
	}
	decision := externalV2BulkDecision{Mode: externalV2BulkModeBulk, ProbeRunID: 77, SelectedMbps: 800, Reason: externalV2BulkReasonBothAccepted}.control(externalV2BulkPhaseDecision)
	receiverEvents <- externalV2BulkControlEvent{Control: decision}
	ack := <-sent
	if ack.Phase != externalV2BulkPhaseAck {
		t.Fatalf("second send = %+v, want acknowledgement", ack)
	}
	if received := <-resultCh; received.err != nil {
		t.Fatal(received.err)
	}
	receiver.Close()
	receiverEvents <- externalV2BulkControlEvent{Control: decision}
	time.Sleep(50 * time.Millisecond)
	select {
	case message := <-sent:
		t.Fatalf("send after Close = %+v", message)
	default:
	}
}

func TestExternalV2BulkControlAuthenticatedRoundTrip(t *testing.T) {
	auth := externalPeerControlAuth{EnvelopeKey: [32]byte{1}}
	want := externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseDecision,
		ProbeRunID: 77, Mode: externalV2BulkModeBulk,
		SelectedMbps: 900, Reason: externalV2BulkReasonBothAccepted,
	}
	payload, err := marshalAuthenticatedEnvelope(envelope{Type: envelopeV2BulkControl, V2BulkControl: &want}, auth)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := externalV2BulkControlFromPayload(payload, auth)
	if err != nil || !ok || got != want {
		t.Fatalf("decode = (%+v, %t, %v), want %+v", got, ok, err, want)
	}
	forgedAuth := externalPeerControlAuth{EnvelopeKey: [32]byte{2}}
	forgedPayload, err := marshalAuthenticatedEnvelope(envelope{Type: envelopeV2BulkControl, V2BulkControl: &want}, forgedAuth)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := externalV2BulkControlFromPayload(forgedPayload, auth); err != nil || ok {
		t.Fatalf("forged control = (ok=%t, err=%v), want ignored", ok, err)
	}
}

func TestValidateExternalV2BulkControl(t *testing.T) {
	valid := externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseDecision,
		ProbeRunID: 77, Mode: externalV2BulkModeBulk,
		SelectedMbps: 900, Reason: externalV2BulkReasonBothAccepted,
	}
	tests := []struct {
		name string
		edit func(*externalV2BulkControl)
	}{
		{"protocol", func(m *externalV2BulkControl) { m.Protocol = "old" }},
		{"phase", func(m *externalV2BulkControl) { m.Phase = "maybe" }},
		{"mode", func(m *externalV2BulkControl) { m.Mode = "guess" }},
		{"zero-decision-run", func(m *externalV2BulkControl) { m.ProbeRunID = 0 }},
		{"bulk-rate-low", func(m *externalV2BulkControl) { m.SelectedMbps = 127 }},
		{"bulk-rate-high", func(m *externalV2BulkControl) { m.SelectedMbps = 2401 }},
		{"quic-rate", func(m *externalV2BulkControl) { m.Mode, m.SelectedMbps = externalV2BulkModeQUIC, 1 }},
		{"readiness-reason", func(m *externalV2BulkControl) {
			m.Phase, m.Reason = externalV2BulkPhaseReady, externalV2BulkReasonBothAccepted
		}},
		{"reason", func(m *externalV2BulkControl) { m.Reason = "raw error text" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := valid
			tt.edit(&message)
			if err := validateExternalV2BulkControl(message); !errors.Is(err, errExternalV2BulkDecisionProtocol) {
				t.Fatalf("validation error = %v, want protocol error", err)
			}
		})
	}
}

func TestValidateExternalV2BulkControlRejectsDecisionModeReasonMismatch(t *testing.T) {
	tests := []struct {
		name    string
		message externalV2BulkControl
		want    string
	}{
		{
			name: "bulk decision with QUIC reason",
			message: externalV2BulkControl{Protocol: externalV2Protocol, Phase: externalV2BulkPhaseDecision,
				ProbeRunID: 77, Mode: externalV2BulkModeBulk, SelectedMbps: 800, Reason: externalV2BulkReasonSenderProbeRejected},
			want: `bulk decision protocol error: decision reason "sender-probe-rejected" is invalid for bulk-packets-v1`,
		},
		{
			name: "QUIC decision with bulk reason",
			message: externalV2BulkControl{Protocol: externalV2Protocol, Phase: externalV2BulkPhaseDecision,
				ProbeRunID: 77, Mode: externalV2BulkModeQUIC, Reason: externalV2BulkReasonBothAccepted},
			want: `bulk decision protocol error: decision reason "both-probes-accepted" is invalid for quic`,
		},
		{
			name: "bulk acknowledgement with QUIC reason",
			message: externalV2BulkControl{Protocol: externalV2Protocol, Phase: externalV2BulkPhaseAck,
				ProbeRunID: 77, Mode: externalV2BulkModeBulk, SelectedMbps: 800, Reason: externalV2BulkReasonReceiverProbeRejected},
			want: `bulk decision protocol error: acknowledgement reason "receiver-probe-rejected" is invalid for bulk-packets-v1`,
		},
		{
			name: "QUIC acknowledgement with bulk reason",
			message: externalV2BulkControl{Protocol: externalV2Protocol, Phase: externalV2BulkPhaseAck,
				ProbeRunID: 77, Mode: externalV2BulkModeQUIC, Reason: externalV2BulkReasonBothAccepted},
			want: `bulk decision protocol error: acknowledgement reason "both-probes-accepted" is invalid for quic`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExternalV2BulkControl(tt.message)
			if !errors.Is(err, errExternalV2BulkDecisionProtocol) || err.Error() != tt.want {
				t.Fatalf("validation error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateExternalV2BulkControlAcceptsProtocolVariants(t *testing.T) {
	tests := []struct {
		name    string
		message externalV2BulkControl
	}{
		{
			name: "bulk readiness",
			message: externalV2BulkControl{Protocol: externalV2Protocol, Phase: externalV2BulkPhaseReady,
				ProbeRunID: 77, Mode: externalV2BulkModeBulk, SelectedMbps: 800, Reason: externalV2BulkReasonProbeAccepted},
		},
		{
			name: "quic readiness before run observation",
			message: externalV2BulkControl{Protocol: externalV2Protocol, Phase: externalV2BulkPhaseReady,
				Mode: externalV2BulkModeQUIC, Reason: externalV2BulkReasonReceiverProbeRejected},
		},
		{
			name: "bulk acknowledgement",
			message: externalV2BulkControl{Protocol: externalV2Protocol, Phase: externalV2BulkPhaseAck,
				ProbeRunID: 77, Mode: externalV2BulkModeBulk, SelectedMbps: 800, Reason: externalV2BulkReasonBothAccepted},
		},
		{
			name: "quic decision",
			message: externalV2BulkControl{Protocol: externalV2Protocol, Phase: externalV2BulkPhaseDecision,
				ProbeRunID: 77, Mode: externalV2BulkModeQUIC, Reason: externalV2BulkReasonSenderProbeRejected},
		},
		{
			name: "quic acknowledgement",
			message: externalV2BulkControl{Protocol: externalV2Protocol, Phase: externalV2BulkPhaseAck,
				ProbeRunID: 77, Mode: externalV2BulkModeQUIC, Reason: externalV2BulkReasonReceiverProbeRejected},
		},
		{
			name: "quic readiness-timeout decision",
			message: externalV2BulkControl{Protocol: externalV2Protocol, Phase: externalV2BulkPhaseDecision,
				ProbeRunID: 77, Mode: externalV2BulkModeQUIC, Reason: externalV2BulkReasonReadinessTimeout},
		},
		{
			name: "quic readiness-timeout acknowledgement",
			message: externalV2BulkControl{Protocol: externalV2Protocol, Phase: externalV2BulkPhaseAck,
				ProbeRunID: 77, Mode: externalV2BulkModeQUIC, Reason: externalV2BulkReasonReadinessTimeout},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateExternalV2BulkControl(tt.message); err != nil {
				t.Fatalf("validateExternalV2BulkControl() error = %v", err)
			}
		})
	}
}
