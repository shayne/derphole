// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func resolveExternalV2BulkReceiverWithProbe(
	ctx context.Context,
	c *externalV2BulkDecisionCoordinator,
	probe func(context.Context) (externalV2BulkPacketProbeResult, error),
) <-chan externalV2BulkReceiverResult {
	resultCh := make(chan externalV2BulkReceiverResult, 1)
	go func() {
		result, decision, cleanupErr, err := c.ResolveReceiver(ctx, probe)
		resultCh <- externalV2BulkReceiverResult{probe: result, decision: decision, cleanupErr: cleanupErr, err: err}
	}()
	return resultCh
}

func awaitExternalV2BulkReceiverResult(t *testing.T, resultCh <-chan externalV2BulkReceiverResult) externalV2BulkReceiverResult {
	t.Helper()
	select {
	case result := <-resultCh:
		return result
	case <-time.After(time.Second):
		t.Fatal("receiver did not return")
		return externalV2BulkReceiverResult{}
	}
}

func awaitExternalV2BulkReceiverSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("receiver did not %s", description)
	}
}

func assertExternalV2BulkReceiverFailure(
	t *testing.T,
	got externalV2BulkReceiverResult,
	wantProbe externalV2BulkPacketProbeResult,
	wantCleanupErr error,
	wantDecisionErr error,
) {
	t.Helper()
	if !reflect.DeepEqual(got.probe, wantProbe) {
		t.Fatalf("probe result = %+v, want %+v", got.probe, wantProbe)
	}
	if got.decision != (externalV2BulkDecision{}) {
		t.Fatalf("decision = %+v, want zero decision", got.decision)
	}
	if !errors.Is(got.cleanupErr, wantCleanupErr) {
		t.Fatalf("cleanup error = %v, want %v", got.cleanupErr, wantCleanupErr)
	}
	if !errors.Is(got.err, wantDecisionErr) {
		t.Fatalf("decision error = %v, want %v", got.err, wantDecisionErr)
	}
}

type gatedExternalV2BulkReceiverProbe struct {
	result     externalV2BulkPacketProbeResult
	cleanupErr error
	started    chan struct{}
	canceled   chan struct{}
	release    chan struct{}
	drained    chan struct{}
}

func newGatedExternalV2BulkReceiverProbe(result externalV2BulkPacketProbeResult, cleanupErr error) *gatedExternalV2BulkReceiverProbe {
	return &gatedExternalV2BulkReceiverProbe{
		result: result, cleanupErr: cleanupErr,
		started: make(chan struct{}), canceled: make(chan struct{}),
		release: make(chan struct{}), drained: make(chan struct{}),
	}
}

func (p *gatedExternalV2BulkReceiverProbe) run(ctx context.Context) (externalV2BulkPacketProbeResult, error) {
	close(p.started)
	<-ctx.Done()
	close(p.canceled)
	<-p.release
	close(p.drained)
	return p.result, errors.Join(ctx.Err(), newExternalV2BulkPacketProbeCleanupError(p.cleanupErr))
}

const externalV2BulkReceiverEarlyReturnWindow = 10 * time.Millisecond

func assertExternalV2BulkReceiverWaitsForProbeDrain(t *testing.T, resultCh <-chan externalV2BulkReceiverResult) {
	t.Helper()
	timer := time.NewTimer(externalV2BulkReceiverEarlyReturnWindow)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		t.Fatalf("receiver returned during %s probe-drain observation window before release: %+v", externalV2BulkReceiverEarlyReturnWindow, result)
	case <-timer.C:
	}
}

func assertExternalV2BulkReceiverProbeDrained(t *testing.T, drained <-chan struct{}) {
	t.Helper()
	select {
	case <-drained:
	default:
		t.Fatal("receiver returned before canceled probe finished draining")
	}
}

func TestExternalV2BulkDecisionCoordinatorReceiverCancellationDrainsProbe(t *testing.T) {
	callerCancellation := errors.New("caller canceled active receiver probe")
	agreementCancellation := errors.New("agreement canceled active receiver probe")
	for _, tt := range []struct {
		name        string
		newContexts func() (context.Context, context.Context, func())
		wantErr     error
	}{
		{
			name: "caller",
			newContexts: func() (context.Context, context.Context, func()) {
				ctx, cancel := context.WithCancelCause(context.Background())
				return context.Background(), ctx, func() { cancel(callerCancellation) }
			},
			wantErr: callerCancellation,
		},
		{
			name: "agreement",
			newContexts: func() (context.Context, context.Context, func()) {
				ctx, cancel := context.WithCancelCause(context.Background())
				return ctx, context.Background(), func() { cancel(agreementCancellation) }
			},
			wantErr: agreementCancellation,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			events := make(chan externalV2BulkControlEvent)
			coordinatorCtx, roleCtx, cancel := tt.newContexts()
			coordinator := newExternalV2BulkTestCoordinatorWithBarrier(coordinatorCtx, externalV2BulkTestWire{
				send:   func(context.Context, externalV2BulkControl) error { return nil },
				events: events,
				close:  func() {},
			}, time.Second)
			defer coordinator.Close()

			wantProbe := externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 800}
			cleanupFault := errors.New("injected cancellation cleanup failure")
			probe := newGatedExternalV2BulkReceiverProbe(wantProbe, cleanupFault)
			resultCh := resolveExternalV2BulkReceiverWithProbe(roleCtx, coordinator, probe.run)
			awaitExternalV2BulkReceiverSignal(t, probe.started, "start probe")
			cancel()
			awaitExternalV2BulkReceiverSignal(t, probe.canceled, "cancel probe")
			assertExternalV2BulkReceiverWaitsForProbeDrain(t, resultCh)
			close(probe.release)

			got := awaitExternalV2BulkReceiverResult(t, resultCh)
			assertExternalV2BulkReceiverProbeDrained(t, probe.drained)
			assertExternalV2BulkReceiverFailure(t, got, wantProbe, cleanupFault, tt.wantErr)
			if got.err != tt.wantErr {
				t.Fatalf("decision error = %v, want exact cancellation cause %v", got.err, tt.wantErr)
			}
		})
	}
}

func TestExternalV2BulkDecisionCoordinatorReceiverWireFailureDrainsProbe(t *testing.T) {
	for _, tt := range []struct {
		name      string
		event     externalV2BulkControlEvent
		closeWire bool
		wantErr   error
	}{
		{name: "closed-wire", closeWire: true, wantErr: ErrPeerDisconnected},
		{name: "authentication", event: externalV2BulkControlEvent{Err: errUnauthenticatedEnvelope}, wantErr: errUnauthenticatedEnvelope},
		{name: "terminal", event: externalV2BulkControlEvent{Err: ErrPeerDisconnected}, wantErr: ErrPeerDisconnected},
		{
			name: "protocol",
			event: externalV2BulkControlEvent{Control: externalV2BulkControl{
				Protocol: "wrong", Phase: externalV2BulkPhaseDecision,
				ProbeRunID: 77, Mode: externalV2BulkModeQUIC, Reason: externalV2BulkReasonSenderProbeRejected,
			}},
			wantErr: errExternalV2BulkDecisionProtocol,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			events := make(chan externalV2BulkControlEvent, 1)
			coordinator := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
				send:   func(context.Context, externalV2BulkControl) error { return nil },
				events: events,
				close:  func() {},
			}, nil)
			defer coordinator.Close()

			wantProbe := externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 800}
			cleanupFault := errors.New("injected wire cleanup failure")
			probe := newGatedExternalV2BulkReceiverProbe(wantProbe, cleanupFault)
			resultCh := resolveExternalV2BulkReceiverWithProbe(context.Background(), coordinator, probe.run)
			awaitExternalV2BulkReceiverSignal(t, probe.started, "start probe")
			if tt.closeWire {
				close(events)
			} else {
				events <- tt.event
			}
			awaitExternalV2BulkReceiverSignal(t, probe.canceled, "cancel probe")
			assertExternalV2BulkReceiverWaitsForProbeDrain(t, resultCh)
			close(probe.release)

			got := awaitExternalV2BulkReceiverResult(t, resultCh)
			assertExternalV2BulkReceiverProbeDrained(t, probe.drained)
			assertExternalV2BulkReceiverFailure(t, got, wantProbe, cleanupFault, tt.wantErr)
		})
	}
}

func TestExternalV2BulkDecisionCoordinatorReceiverRejectsDecisionWhileProbing(t *testing.T) {
	for _, tt := range []struct {
		name         string
		message      externalV2BulkControl
		probeRunID   uint64
		sendErr      error
		wantErr      error
		wantMessage  string
		cleanupFatal bool
	}{
		{
			name: "non-QUIC",
			message: externalV2BulkDecision{
				Mode: externalV2BulkModeBulk, ProbeRunID: 77, SelectedMbps: 800, Reason: externalV2BulkReasonBothAccepted,
			}.control(externalV2BulkPhaseDecision),
			probeRunID: 77, wantErr: errExternalV2BulkDecisionProtocol, wantMessage: "only QUIC decision",
		},
		{
			name: "mismatched-run-ID",
			message: externalV2BulkDecision{
				Mode: externalV2BulkModeQUIC, ProbeRunID: 77, Reason: externalV2BulkReasonSenderProbeRejected,
			}.control(externalV2BulkPhaseDecision),
			probeRunID: 88, cleanupFatal: true,
		},
		{
			name: "acknowledgement-send",
			message: externalV2BulkDecision{
				Mode: externalV2BulkModeQUIC, ProbeRunID: 77, Reason: externalV2BulkReasonSenderProbeRejected,
			}.control(externalV2BulkPhaseDecision),
			probeRunID: 77, sendErr: errors.New("injected probing acknowledgement failure"), cleanupFatal: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			events := make(chan externalV2BulkControlEvent, 1)
			var sends atomic.Int32
			coordinator := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
				send: func(context.Context, externalV2BulkControl) error {
					sends.Add(1)
					return tt.sendErr
				},
				events: events,
				close:  func() {},
			}, nil)
			defer coordinator.Close()

			wantProbe := externalV2BulkPacketProbeResult{RunID: tt.probeRunID, SelectedMbps: 800}
			cleanupFault := errors.New("injected decision cleanup failure")
			probe := newGatedExternalV2BulkReceiverProbe(wantProbe, cleanupFault)
			resultCh := resolveExternalV2BulkReceiverWithProbe(context.Background(), coordinator, probe.run)
			awaitExternalV2BulkReceiverSignal(t, probe.started, "start probe")
			events <- externalV2BulkControlEvent{Control: tt.message}
			awaitExternalV2BulkReceiverSignal(t, probe.canceled, "cancel probe")
			assertExternalV2BulkReceiverWaitsForProbeDrain(t, resultCh)
			close(probe.release)

			got := awaitExternalV2BulkReceiverResult(t, resultCh)
			assertExternalV2BulkReceiverProbeDrained(t, probe.drained)
			wantErr := tt.wantErr
			if tt.cleanupFatal {
				wantErr = cleanupFault
			}
			assertExternalV2BulkReceiverFailure(t, got, wantProbe, cleanupFault, wantErr)
			if tt.cleanupFatal && sends.Load() != 0 {
				t.Fatalf("decision acknowledgement sends = %d, want 0 after cleanup failure", sends.Load())
			}
			if tt.wantMessage != "" && !strings.Contains(got.err.Error(), tt.wantMessage) {
				t.Fatalf("decision error = %v, want text %q", got.err, tt.wantMessage)
			}
		})
	}
}

func TestExternalV2BulkDecisionCoordinatorReceiverReadinessFailures(t *testing.T) {
	t.Run("validation", func(t *testing.T) {
		coordinator := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
			send:   func(context.Context, externalV2BulkControl) error { t.Fatal("invalid readiness was sent"); return nil },
			events: make(chan externalV2BulkControlEvent), close: func() {},
		}, nil)
		defer coordinator.Close()

		wantProbe := externalV2BulkPacketProbeResult{SelectedMbps: 800}
		got := awaitExternalV2BulkReceiverResult(t, resolveExternalV2BulkReceiver(context.Background(), coordinator, wantProbe, nil))
		assertExternalV2BulkReceiverFailure(t, got, wantProbe, nil, errExternalV2BulkDecisionProtocol)
	})

	t.Run("initial-send", func(t *testing.T) {
		sendFault := errors.New("injected readiness send failure")
		coordinator := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
			send:   func(context.Context, externalV2BulkControl) error { return sendFault },
			events: make(chan externalV2BulkControlEvent), close: func() {},
		}, nil)
		defer coordinator.Close()

		wantProbe := externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 800}
		got := awaitExternalV2BulkReceiverResult(t, resolveExternalV2BulkReceiver(context.Background(), coordinator, wantProbe, nil))
		assertExternalV2BulkReceiverFailure(t, got, wantProbe, nil, sendFault)
	})

	t.Run("cleanup-fails-before-send", func(t *testing.T) {
		var sends atomic.Int32
		coordinator := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
			send: func(context.Context, externalV2BulkControl) error {
				sends.Add(1)
				return nil
			},
			events: make(chan externalV2BulkControlEvent), close: func() {},
		}, nil)
		defer coordinator.Close()

		cleanupFault := errors.New("injected completed probe cleanup failure")
		probeErr := errors.Join(errExternalV2BulkPacketProbeRejected, newExternalV2BulkPacketProbeCleanupError(cleanupFault))
		wantProbe := externalV2BulkPacketProbeResult{RunID: 77}
		got := awaitExternalV2BulkReceiverResult(t, resolveExternalV2BulkReceiver(context.Background(), coordinator, wantProbe, probeErr))
		assertExternalV2BulkReceiverFailure(t, got, wantProbe, cleanupFault, cleanupFault)
		if sends.Load() != 0 {
			t.Fatalf("readiness sends = %d, want 0 after cleanup failure", sends.Load())
		}
	})

	t.Run("retry-send", func(t *testing.T) {
		retryFault := errors.New("injected readiness retry failure")
		var sends atomic.Int32
		coordinator := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
			send: func(context.Context, externalV2BulkControl) error {
				if sends.Add(1) == 1 {
					return nil
				}
				return retryFault
			},
			events: make(chan externalV2BulkControlEvent), close: func() {},
		}, nil)
		coordinator.retry = time.Millisecond
		defer coordinator.Close()

		wantProbe := externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 800}
		got := awaitExternalV2BulkReceiverResult(t, resolveExternalV2BulkReceiver(context.Background(), coordinator, wantProbe, nil))
		assertExternalV2BulkReceiverFailure(t, got, wantProbe, nil, retryFault)
		if got := sends.Load(); got != 2 {
			t.Fatalf("readiness sends = %d, want initial send and one retry", got)
		}
	})
}

func TestExternalV2BulkDecisionCoordinatorReceiverDecisionFailures(t *testing.T) {
	for _, tt := range []struct {
		name        string
		cleanupErr  error
		event       externalV2BulkControlEvent
		closeWire   bool
		ackErr      error
		wantErr     error
		wantMessage string
	}{
		{name: "closed-wire", closeWire: true, wantErr: ErrPeerDisconnected},
		{name: "terminal", event: externalV2BulkControlEvent{Err: ErrPeerDisconnected}, wantErr: ErrPeerDisconnected},
		{
			name: "protocol",
			event: externalV2BulkControlEvent{Control: externalV2BulkControl{
				Protocol: "wrong", Phase: externalV2BulkPhaseDecision,
				ProbeRunID: 77, Mode: externalV2BulkModeQUIC, Reason: externalV2BulkReasonSenderProbeRejected,
			}},
			wantErr: errExternalV2BulkDecisionProtocol,
		},
		{
			name: "wrong-phase",
			event: externalV2BulkControlEvent{Control: externalV2BulkControl{
				Protocol: externalV2Protocol, Phase: externalV2BulkPhaseReady,
				ProbeRunID: 77, Mode: externalV2BulkModeBulk, SelectedMbps: 800, Reason: externalV2BulkReasonProbeAccepted,
			}},
			wantErr: errExternalV2BulkDecisionProtocol, wantMessage: "expected decision",
		},
		{
			name: "mismatched-run-ID",
			event: externalV2BulkControlEvent{Control: externalV2BulkDecision{
				Mode: externalV2BulkModeQUIC, ProbeRunID: 88, Reason: externalV2BulkReasonSenderProbeRejected,
			}.control(externalV2BulkPhaseDecision)},
			wantErr: errExternalV2BulkDecisionProtocol, wantMessage: "readiness run ID",
		},
		{
			name:       "bulk-after-rejected-probe",
			cleanupErr: errors.New("injected rejected probe cleanup failure"),
		},
		{
			name: "acknowledgement-send",
			event: externalV2BulkControlEvent{Control: externalV2BulkDecision{
				Mode: externalV2BulkModeQUIC, ProbeRunID: 77, Reason: externalV2BulkReasonSenderProbeRejected,
			}.control(externalV2BulkPhaseDecision)},
			ackErr: errors.New("injected decision acknowledgement failure"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			events := make(chan externalV2BulkControlEvent, 1)
			readinessSent := make(chan struct{}, 1)
			coordinator := newExternalV2BulkTestCoordinator(context.Background(), externalV2BulkTestWire{
				send: func(_ context.Context, message externalV2BulkControl) error {
					if message.Phase == externalV2BulkPhaseReady {
						readinessSent <- struct{}{}
						return nil
					}
					return tt.ackErr
				},
				events: events, close: func() {},
			}, nil)
			defer coordinator.Close()

			var probeErr error
			if tt.cleanupErr != nil {
				probeErr = errors.Join(errExternalV2BulkPacketProbeRejected, newExternalV2BulkPacketProbeCleanupError(tt.cleanupErr))
			}
			wantProbe := externalV2BulkPacketProbeResult{RunID: 77, SelectedMbps: 800}
			resultCh := resolveExternalV2BulkReceiver(context.Background(), coordinator, wantProbe, probeErr)
			if tt.cleanupErr != nil {
				got := awaitExternalV2BulkReceiverResult(t, resultCh)
				assertExternalV2BulkReceiverFailure(t, got, wantProbe, tt.cleanupErr, tt.cleanupErr)
				select {
				case <-readinessSent:
					t.Fatal("readiness was sent after cleanup failure")
				default:
				}
				return
			}
			select {
			case <-readinessSent:
			case <-time.After(time.Second):
				t.Fatal("readiness was not sent")
			}
			if tt.closeWire {
				close(events)
			} else {
				events <- tt.event
			}

			got := awaitExternalV2BulkReceiverResult(t, resultCh)
			wantErr := tt.wantErr
			if tt.ackErr != nil {
				wantErr = tt.ackErr
			}
			assertExternalV2BulkReceiverFailure(t, got, wantProbe, tt.cleanupErr, wantErr)
			if tt.wantMessage != "" && !strings.Contains(got.err.Error(), tt.wantMessage) {
				t.Fatalf("decision error = %v, want text %q", got.err, tt.wantMessage)
			}
		})
	}
}
