// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/telemetry"
	"tailscale.com/types/key"
)

func TestApplyExternalV2BulkPacketSenderProbeTestOutcome(t *testing.T) {
	base := externalV2BulkPacketProbeResult{
		RunID:        77,
		SelectedMbps: 900,
		Duration:     125 * time.Millisecond,
		Trains: []externalV2BulkPacketProbeTrainResult{{
			RateMbps: 1000, Sent: 100, Received: 99, Pressure: true,
		}},
	}
	probeFailure := errors.New("probe failed")
	protocolFailure := fmt.Errorf("%w: probe protocol failed", errExternalV2BulkDecisionProtocol)
	cleanupFailure := errors.New("probe cleanup failed")
	wrappedRejection := fmt.Errorf("wrapped rejection: %w", errExternalV2BulkPacketProbeRejected)
	joinedRejection := errors.Join(errExternalV2BulkPacketProbeRejected, probeFailure)
	wrappedForcedRejection := fmt.Errorf(
		"wrapped forced rejection: %w",
		errors.Join(errExternalV2BulkPacketProbeRejected, errExternalV2BulkPacketProbeForcedSenderReject),
	)
	joinedForcedRejectionAndCleanup := errors.Join(
		errExternalV2BulkPacketProbeRejected,
		errExternalV2BulkPacketProbeForcedSenderReject,
		newExternalV2BulkPacketProbeCleanupError(cleanupFailure),
	)
	joinedCleanupRejection := errors.Join(
		errExternalV2BulkPacketProbeRejected,
		newExternalV2BulkPacketProbeCleanupError(cleanupFailure),
	)
	selectorRejection := &externalV2BulkPacketProbeRejection{
		Stage: "selector", Train: 3, RateMbps: 1600, cause: errExternalV2BulkPacketProbeRejected,
	}
	forced := externalV2BulkPacketProbeResult{
		RunID: 77, Duration: 125 * time.Millisecond, Trains: base.Trains,
	}
	tests := []struct {
		name         string
		value        string
		configured   bool
		inputErr     error
		want         externalV2BulkPacketProbeResult
		wantErrs     []error
		wantExactErr error
		wantInvalid  bool
		wantText     string
	}{
		{name: "unset", want: base},
		{name: "unset natural rejection", inputErr: errExternalV2BulkPacketProbeRejected, want: base,
			wantExactErr: errExternalV2BulkPacketProbeRejected},
		{name: "sender reject", value: "sender-reject", configured: true,
			want: forced, wantErrs: []error{errExternalV2BulkPacketProbeRejected, errExternalV2BulkPacketProbeForcedSenderReject}},
		{name: "sender reject after natural rejection", value: "sender-reject", configured: true,
			inputErr: errExternalV2BulkPacketProbeRejected, want: forced,
			wantErrs: []error{errExternalV2BulkPacketProbeRejected, errExternalV2BulkPacketProbeForcedSenderReject}},
		{name: "explicit empty", configured: true, want: base,
			wantInvalid: true, wantText: `DERPHOLE_TEST_BULK_PROBE_OUTCOME must be unset or "sender-reject" (got "")`},
		{name: "explicit empty after natural rejection", configured: true,
			inputErr: errExternalV2BulkPacketProbeRejected, want: base,
			wantInvalid: true, wantText: `DERPHOLE_TEST_BULK_PROBE_OUTCOME must be unset or "sender-reject" (got "")`},
		{name: "unsupported", value: "receiver-reject", configured: true, want: base,
			wantInvalid: true, wantText: `DERPHOLE_TEST_BULK_PROBE_OUTCOME must be unset or "sender-reject" (got "receiver-reject")`},
		{name: "unsupported after natural rejection", value: "receiver-reject", configured: true,
			inputErr: errExternalV2BulkPacketProbeRejected, want: base,
			wantInvalid: true, wantText: `DERPHOLE_TEST_BULK_PROBE_OUTCOME must be unset or "sender-reject" (got "receiver-reject")`},
		{name: "probe error wins", value: "receiver-reject", configured: true, inputErr: probeFailure,
			want: base, wantExactErr: probeFailure},
		{name: "probe error wins over sender reject", value: "sender-reject", configured: true, inputErr: probeFailure,
			want: base, wantExactErr: probeFailure},
		{name: "caller cancellation wins over sender reject", value: "sender-reject", configured: true, inputErr: context.Canceled,
			want: base, wantExactErr: context.Canceled},
		{name: "protocol error wins over sender reject", value: "sender-reject", configured: true, inputErr: protocolFailure,
			want: base, wantExactErr: protocolFailure},
		{name: "cleanup error joined with rejection wins over sender reject", value: "sender-reject", configured: true, inputErr: joinedCleanupRejection,
			want: base, wantExactErr: joinedCleanupRejection},
		{name: "sender reject after selector rejection", value: "sender-reject", configured: true,
			inputErr: selectorRejection, want: forced,
			wantErrs: []error{errExternalV2BulkPacketProbeRejected, errExternalV2BulkPacketProbeForcedSenderReject}},
		{name: "wrapped rejection wins", value: "sender-reject", configured: true, inputErr: wrappedRejection,
			want: base, wantExactErr: wrappedRejection},
		{name: "wrapped forced rejection wins", value: "sender-reject", configured: true, inputErr: wrappedForcedRejection,
			want: base, wantExactErr: wrappedForcedRejection},
		{name: "joined rejection and probe error wins", value: "sender-reject", configured: true, inputErr: joinedRejection,
			want: base, wantExactErr: joinedRejection},
		{name: "joined forced rejection and cleanup wins", value: "sender-reject", configured: true,
			inputErr: joinedForcedRejectionAndCleanup, want: base, wantExactErr: joinedForcedRejectionAndCleanup},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := applyExternalV2BulkPacketSenderProbeTestOutcome(base, tt.inputErr, tt.value, tt.configured)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("result = %#v, want %#v", got, tt.want)
			}
			for _, wantErr := range tt.wantErrs {
				if !errors.Is(err, wantErr) {
					t.Fatalf("error = %v, want errors.Is(_, %v)", err, wantErr)
				}
			}
			if tt.wantExactErr != nil && err != tt.wantExactErr {
				t.Fatalf("error = %v (%p), want exact %v (%p)", err, err, tt.wantExactErr, tt.wantExactErr)
			}
			if gotInvalid := externalV2BulkPacketProbeTestOutcomeInvalid(err); gotInvalid != tt.wantInvalid {
				t.Fatalf("invalid outcome error = %t, want %t: %v", gotInvalid, tt.wantInvalid, err)
			}
			if tt.wantText != "" && (err == nil || err.Error() != tt.wantText) {
				t.Fatalf("error = %v, want %q", err, tt.wantText)
			}
			if len(tt.wantErrs) == 0 && tt.wantExactErr == nil && tt.wantText == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestExternalV2BulkPacketProbeDirtyRateEnvironment(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		configured bool
		role       externalV2BulkPacketProbeRole
		wantRate   int
		wantSet    bool
		wantErr    string
	}{
		{name: "unset", role: externalV2BulkPacketProbeReceiver},
		{name: "empty", configured: true, role: externalV2BulkPacketProbeReceiver, wantErr: "must be unset or one configured probe rate"},
		{name: "non-numeric", value: "fast", configured: true, role: externalV2BulkPacketProbeReceiver, wantErr: "must be unset or one configured probe rate"},
		{name: "unknown rate", value: "900", configured: true, role: externalV2BulkPacketProbeReceiver, wantErr: "must be unset or one configured probe rate"},
		{name: "non-canonical decimal", value: "01000", configured: true, role: externalV2BulkPacketProbeReceiver, wantErr: "must be unset or one configured probe rate"},
		{name: "sender presence", value: "1000", configured: true, role: externalV2BulkPacketProbeSender, wantErr: "is receiver-only"},
		{name: "valid receiver rate", value: "1000", configured: true, role: externalV2BulkPacketProbeReceiver, wantRate: 1000, wantSet: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rate, configured, err := parseExternalV2BulkPacketProbeDirtyRate(test.value, test.configured, test.role)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("parse error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if rate != test.wantRate || configured != test.wantSet {
				t.Fatalf("parse = (%d, %t), want (%d, %t)", rate, configured, test.wantRate, test.wantSet)
			}
		})
	}
}

func TestExternalV2BulkPacketProbeDirtyRateExcludesEveryTenthValidDatagram(t *testing.T) {
	seen := make(map[uint32]struct{})
	var runID uint64
	for sequence := uint32(0); sequence < 100; sequence++ {
		collectExternalV2BulkPacketProbeData(externalV2BulkPacketProbeEvent{
			header: externalV2BulkPacketHeader{kind: externalV2BulkPacketProbeData, runID: 77},
			prefix: externalV2BulkPacketProbePrefix{Train: 2, RateMbps: 1000, Sequence: sequence},
		}, 2, 1000, 1000, &runID, nil, seen)
	}
	if runID != 77 {
		t.Fatalf("run ID = %d, want 77", runID)
	}
	if len(seen) != 90 {
		t.Fatalf("counted datagrams = %d, want 90 of 100 consumed", len(seen))
	}
	for sequence := uint32(0); sequence < 100; sequence += 10 {
		if _, ok := seen[sequence]; ok {
			t.Fatalf("sequence %d was counted at injected dirty rate", sequence)
		}
	}
}

func newExternalV2BulkPacketProbeTestCoordinator(t *testing.T, ctx context.Context, barrier time.Duration) *externalV2BulkDecisionCoordinator {
	t.Helper()
	wire := externalV2BulkTestWire{
		send:   func(context.Context, externalV2BulkControl) error { return nil },
		events: make(chan externalV2BulkControlEvent),
		close:  func() {},
	}
	coordinator := newExternalV2BulkTestCoordinatorWithBarrier(ctx, wire, barrier)
	t.Cleanup(coordinator.Close)
	return coordinator
}

func TestSendExternalV2BulkPacketProbePreservesControlTimeout(t *testing.T) {
	t.Setenv(externalV2BulkPacketProbeTestOutcomeEnv, externalV2BulkPacketProbeTestOutcomeSenderReject)
	previousRates := append([]int(nil), externalV2BulkPacketProbeRatesMbps...)
	externalV2BulkPacketProbeRatesMbps = []int{128}
	t.Cleanup(func() { externalV2BulkPacketProbeRatesMbps = previousRates })

	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	sender := newExternalV2BulkPacketSender(
		context.Background(),
		&BlockSource{Payload: bytes.NewReader([]byte{0x5a}), PayloadSize: 1},
		externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receivers)},
		auth,
		nil,
	)

	coordinator := newExternalV2BulkPacketProbeTestCoordinator(t, context.Background(), 25*time.Millisecond)
	result, err := sendExternalV2BulkPacketProbe(context.Background(), sender, coordinator)
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errExternalV2BulkPacketProbeRejected) ||
		errors.Is(err, errExternalV2BulkPacketProbeForcedSenderReject) {
		t.Fatalf("probe error = %v, want fatal control deadline", err)
	}
	if result.RunID != sender.runID || result.RejectStage != "" {
		t.Fatalf("failure result = %+v, want run ID without capacity rejection", result)
	}
}

func TestSendExternalV2BulkPacketProbePreservesFatalErrors(t *testing.T) {
	t.Setenv(externalV2BulkPacketProbeTestOutcomeEnv, externalV2BulkPacketProbeTestOutcomeSenderReject)
	previousRates := append([]int(nil), externalV2BulkPacketProbeRatesMbps...)
	externalV2BulkPacketProbeRatesMbps = []int{128}
	t.Cleanup(func() { externalV2BulkPacketProbeRatesMbps = previousRates })

	newSender := func(t *testing.T, ctx context.Context) *externalV2BulkPacketSender {
		t.Helper()
		senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
		auth, err := externalV2BulkPacketAuthForToken(
			testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
		)
		if err != nil {
			t.Fatal(err)
		}
		return newExternalV2BulkPacketSender(
			ctx,
			&BlockSource{Payload: bytes.NewReader([]byte{0x5a}), PayloadSize: 1},
			externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receivers)},
			auth,
			nil,
		)
	}

	t.Run("packet write", func(t *testing.T) {
		writeErr := errors.New("injected probe packet write failure")
		sender := newSender(t, context.Background())
		sender.batchConns[0] = fatalExternalV2BulkPacketProbeBatchConn{err: writeErr}
		coordinator := newExternalV2BulkPacketProbeTestCoordinator(t, context.Background(), time.Second)
		_, err := sendExternalV2BulkPacketProbe(context.Background(), sender, coordinator)
		if err != writeErr || errors.Is(err, errExternalV2BulkPacketProbeRejected) ||
			errors.Is(err, errExternalV2BulkPacketProbeForcedSenderReject) {
			t.Fatalf("probe error = %v (%p), want exact write error %v (%p)", err, err, writeErr, writeErr)
		}
	})

	t.Run("caller cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		sender := newSender(t, ctx)
		coordinator := newExternalV2BulkPacketProbeTestCoordinator(t, ctx, time.Second)
		_, err := sendExternalV2BulkPacketProbe(ctx, sender, coordinator)
		if err != context.Canceled || errors.Is(err, errExternalV2BulkPacketProbeRejected) ||
			errors.Is(err, errExternalV2BulkPacketProbeForcedSenderReject) {
			t.Fatalf("probe error = %v, want exact context cancellation", err)
		}
	})
}

type fatalExternalV2BulkPacketProbeBatchConn struct {
	err error
}

func (c fatalExternalV2BulkPacketProbeBatchConn) WriteBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, c.err
}

func (fatalExternalV2BulkPacketProbeBatchConn) ReadBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, errors.New("unexpected probe packet read")
}

func (fatalExternalV2BulkPacketProbeBatchConn) Stats() externalV2BulkPacketBatchStats {
	return externalV2BulkPacketBatchStats{Backend: "fatal-probe-test"}
}

func TestSelectExternalV2BulkPacketSenderProbeAppliesOutcomeAfterSelector(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_BULK_PROBE_OUTCOME", "sender-reject")
	previous := externalV2BulkPacketSenderProbeSelector
	t.Cleanup(func() { externalV2BulkPacketSenderProbeSelector = previous })
	trains := []externalV2BulkPacketProbeTrainResult{{RateMbps: 1000, Sent: 10, Received: 10}}
	for _, selectorErr := range []error{nil, errExternalV2BulkPacketProbeRejected} {
		name := "accepted"
		if selectorErr != nil {
			name = "naturally rejected"
		}
		t.Run(name, func(t *testing.T) {
			called := false
			externalV2BulkPacketSenderProbeSelector = func(gotTrains []externalV2BulkPacketProbeTrainResult) (externalV2BulkPacketProbeResult, error) {
				called = true
				return externalV2BulkPacketProbeResult{
					RunID:        77,
					SelectedMbps: 900,
					Duration:     125 * time.Millisecond,
					Trains:       append([]externalV2BulkPacketProbeTrainResult(nil), gotTrains...),
				}, selectorErr
			}
			got, err := selectExternalV2BulkPacketSenderProbe(trains)
			if !called || !errors.Is(err, errExternalV2BulkPacketProbeRejected) ||
				!errors.Is(err, errExternalV2BulkPacketProbeForcedSenderReject) {
				t.Fatalf("selector called=%t error=%v, want ordinary and forced rejection", called, err)
			}
			want := externalV2BulkPacketProbeResult{
				RunID: 77, Duration: 125 * time.Millisecond, Trains: trains,
			}
			if selectorErr != nil {
				want.RejectStage = "selector"
				want.RejectTrain = 0
				want.RejectRateMbps = 1000
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("controlled result = %#v, want %#v", got, want)
			}
		})
	}
}

func TestExternalV2BulkPacketProbeFailurePreservesRunID(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sender := newExternalV2BulkPacketSender(
		ctx,
		&BlockSource{Payload: bytes.NewReader([]byte{0x5a}), PayloadSize: 1},
		externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receivers)},
		auth,
		nil,
	)

	coordinator := newExternalV2BulkPacketProbeTestCoordinator(t, ctx, 25*time.Millisecond)
	result, err := sendExternalV2BulkPacketProbe(ctx, sender, coordinator)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("probe error = %v, want control deadline", err)
	}
	if sender.runID == 0 || result.RunID != sender.runID {
		t.Fatalf("failure run ID = %d, want sender run ID %d", result.RunID, sender.runID)
	}
}

func TestExternalV2BulkPacketReceiverProbeFailurePreservesObservedRunID(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	interruptFault := errors.New("injected receiver probe interrupt failure")
	drainFault := errors.New("injected receiver probe handoff drain failure")
	wantDrain := externalV2BulkPacketHandoffDrainResult{Lanes: 1, Datagrams: 3, Duration: time.Millisecond}
	previousInterrupt := externalV2BulkPacketProbeInterruptReads
	previousDrain := externalV2BulkPacketDrainForHandoff
	externalV2BulkPacketProbeInterruptReads = func(path externalV2BulkPacketPath, deadline time.Time) error {
		return errors.Join(interruptExternalV2BulkPacketReads(path, deadline), interruptFault)
	}
	externalV2BulkPacketDrainForHandoff = func(context.Context, externalV2BulkPacketPath) (externalV2BulkPacketHandoffDrainResult, error) {
		return wantDrain, drainFault
	}
	t.Cleanup(func() {
		externalV2BulkPacketProbeInterruptReads = previousInterrupt
		externalV2BulkPacketDrainForHandoff = previousDrain
	})
	observedRunID := make(chan uint64, 1)
	coordinator := newExternalV2BulkPacketProbeTestCoordinator(t, ctx, time.Second)
	resultCh := make(chan struct {
		result externalV2BulkPacketProbeResult
		err    error
	}, 1)
	go func() {
		result, probeErr := receiveExternalV2BulkPacketProbeWithRunObserver(
			ctx,
			externalV2BulkPacketPath{Conns: receivers, Addrs: externalV2BulkPacketTestAddrs(senders)},
			auth,
			1,
			coordinator,
			func(runID uint64) { observedRunID <- runID },
		)
		resultCh <- struct {
			result externalV2BulkPacketProbeResult
			err    error
		}{result: result, err: probeErr}
	}()

	const runID = uint64(77)
	prefix := encodeExternalV2BulkPacketProbePrefix(externalV2BulkPacketProbePrefix{
		Train: 0, Sequence: 0, Expected: externalV2BulkPacketProbeDatagramCount(externalV2BulkPacketProbeRatesMbps[0]), RateMbps: uint32(externalV2BulkPacketProbeRatesMbps[0]),
	})
	packet, err := sealExternalV2BulkPacket(auth.control, externalV2BulkPacketHeader{
		kind: externalV2BulkPacketProbeData, runID: runID, index: 1, total: 1,
	}, prefix[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := senders[0].WriteTo(packet, externalV2BulkPacketTestAddrs(receivers)[0]); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-observedRunID:
		if got != runID {
			t.Fatalf("observed run ID = %d, want %d", got, runID)
		}
	case <-time.After(time.Second):
		t.Fatal("receiver probe did not consume authenticated event")
	}
	cancel()

	select {
	case got := <-resultCh:
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("probe error = %v, want cancellation", got.err)
		}
		if !errors.Is(got.err, interruptFault) || !errors.Is(got.err, drainFault) {
			t.Fatalf("probe error = %v, want interrupt and drain failures", got.err)
		}
		if got.result.RunID != runID {
			t.Fatalf("failure run ID = %d, want observed run ID %d", got.result.RunID, runID)
		}
		if got.result.HandoffDrain != wantDrain {
			t.Fatalf("handoff drain result = %+v, want %+v", got.result.HandoffDrain, wantDrain)
		}
	case <-time.After(time.Second):
		t.Fatal("receiver probe did not stop after cancellation")
	}
}

func TestExternalV2BulkPacketProbeSelectsNinetyPercentOfHighestCleanTrain(t *testing.T) {
	result, err := selectExternalV2BulkPacketProbe([]externalV2BulkPacketProbeTrainResult{
		{RateMbps: 128, Sent: 560, Received: 560},
		{RateMbps: 512, Sent: 2241, Received: 2200},
		{RateMbps: 1000, Sent: 4377, Received: 4230},
		{RateMbps: 1600, Sent: 7003, Received: 6400, Pressure: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.SelectedMbps != 900 {
		t.Fatalf("selected = %d, want 900", result.SelectedMbps)
	}
	if result.StopReason != externalV2BulkPacketProbeStopPressure {
		t.Fatalf("stop reason = %q, want pressure", result.StopReason)
	}
}

func TestExternalV2BulkPacketProbeDiagnosticsMarkers(t *testing.T) {
	var output bytes.Buffer
	result := externalV2BulkPacketProbeResult{
		SelectedMbps: 460,
		StopReason:   externalV2BulkPacketProbeStopDirty,
		Trains: []externalV2BulkPacketProbeTrainResult{
			{RateMbps: 128, Sent: 560, Received: 560},
			{RateMbps: 512, Sent: 2241, Received: 2241},
			{RateMbps: 1000, Sent: 4377, Received: 3939},
		},
	}
	emitExternalV2BulkPacketProbeDiagnostics(telemetry.New(&output, telemetry.LevelVerbose), result)
	for _, marker := range []string{
		"v2-bulk-probe-result=train:2 rate_mbps:1000 sent:4377 received:3939 pressure:false final:true",
		"v2-bulk-probe-selected=selected_mbps:460 highest_clean_mbps:512 trains:3",
	} {
		if !strings.Contains(output.String(), marker) {
			t.Fatalf("verbose output missing %q:\n%s", marker, output.String())
		}
	}
}

func TestExternalV2BulkPacketProbeUsesIntermediateTwoGigabitTrain(t *testing.T) {
	result, err := selectExternalV2BulkPacketProbe([]externalV2BulkPacketProbeTrainResult{
		{RateMbps: 1600, Sent: 7003, Received: 7003},
		{RateMbps: 2000, Sent: 8753, Received: 8700},
		{RateMbps: 2200, Sent: 9628, Received: 9500},
		{RateMbps: 2400, Sent: 10504, Received: 8500},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.SelectedMbps != 1980 {
		t.Fatalf("selected = %d, want 1980", result.SelectedMbps)
	}
}

func TestExternalV2BulkPacketProbeRejectsWithoutCleanTrain(t *testing.T) {
	_, err := selectExternalV2BulkPacketProbe([]externalV2BulkPacketProbeTrainResult{{RateMbps: 128, Sent: 560, Received: 400}})
	if !errors.Is(err, errExternalV2BulkPacketProbeRejected) {
		t.Fatalf("error = %v, want probe rejection", err)
	}
}

func TestExternalV2BulkPacketProbeTrainsAreBounded(t *testing.T) {
	for _, rateMbps := range externalV2BulkPacketProbeRatesMbps {
		packets := externalV2BulkPacketProbeDatagramCount(rateMbps)
		wireBytes := int64(packets) * int64(externalV2BulkPacketIPv4WireBytes(externalV2BulkPacketMaxSize))
		if packets == 0 || wireBytes > externalV2BulkPacketProbeMaxBytes {
			t.Fatalf("rate %d packets=%d wire_bytes=%d exceeds cap", rateMbps, packets, wireBytes)
		}
		atRate := time.Duration(wireBytes * 8 * int64(time.Second) / int64(rateMbps*1_000_000))
		if atRate > externalV2BulkPacketProbeDuration+time.Millisecond {
			t.Fatalf("rate %d train duration = %s, want <= %s", rateMbps, atRate, externalV2BulkPacketProbeDuration)
		}
	}
}

func TestExternalV2BulkPacketGroupedProbeUsesAuthenticatedBlockTag(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	prefix := externalV2BulkPacketProbePrefix{
		Train: 2, Sequence: 499, Expected: externalV2BulkPacketProbeDatagramCount(1000), RateMbps: 1000,
	}
	packet, err := encodeExternalV2BulkPacketTaggedProbeData(auth, externalV2BulkPacketHeader{
		kind: externalV2BulkPacketProbeTaggedData, runID: 99, index: 7, total: 500,
	}, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != externalV2BulkPacketMaxSize {
		t.Fatalf("tagged probe bytes = %d, want %d", len(packet), externalV2BulkPacketMaxSize)
	}
	event, ok := decodeExternalV2BulkPacketProbeEvent(auth, 500, externalV2BulkPacketBatchMessage{Buffers: [][]byte{packet}, N: len(packet)})
	if !ok || event.header.kind != externalV2BulkPacketProbeTaggedData || event.prefix != prefix {
		t.Fatalf("tagged probe decode = %#v ok=%t, want prefix %#v", event, ok, prefix)
	}
	for _, offset := range []int{externalV2BulkPacketHeaderSize, externalV2BulkPacketHeaderSize + externalV2BulkPacketProbeTagSize} {
		forged := append([]byte(nil), packet...)
		forged[offset] ^= 0xff
		if _, ok := decodeExternalV2BulkPacketProbeEvent(auth, 500, externalV2BulkPacketBatchMessage{Buffers: [][]byte{forged}, N: len(forged)}); ok {
			t.Fatalf("forged tagged probe at byte %d authenticated", offset)
		}
	}
}

func TestSendExternalV2BulkPacketProbeRetainsCleanTierAfterDirtyResult(t *testing.T) {
	previousRates := append([]int(nil), externalV2BulkPacketProbeRatesMbps...)
	externalV2BulkPacketProbeRatesMbps = []int{128, 512, 1000}
	t.Cleanup(func() { externalV2BulkPacketProbeRatesMbps = previousRates })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 4)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	sender := newExternalV2BulkPacketSender(
		ctx,
		&BlockSource{Payload: bytes.NewReader([]byte{0x5a}), PayloadSize: 1},
		externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receivers)},
		auth,
		nil,
	)
	senderWire, receiverWire := newExternalV2BulkTestWirePair(t, nil)
	senderCoordinator := newExternalV2BulkTestCoordinatorWithBarrier(ctx, senderWire, 2*time.Second)
	receiverCoordinator := newExternalV2BulkTestCoordinatorWithBarrier(ctx, receiverWire, 2*time.Second)
	defer senderCoordinator.Close()
	defer receiverCoordinator.Close()

	responderErr := make(chan error, 1)
	go func() {
		for train := 0; train < 3; train++ {
			select {
			case event := <-receiverCoordinator.probeControlEvents():
				end, eventErr := externalV2BulkControlFromEvent(event, true)
				if eventErr != nil {
					responderErr <- eventErr
					return
				}
				result := end
				result.Phase = externalV2BulkPhaseProbeResult
				probe := *end.Probe
				probe.Received = probe.Sent
				if train == 2 {
					probe.Received = probe.Sent * 9 / 10
					probe.Final = true
				}
				result.Probe = &probe
				if sendErr := receiverCoordinator.sendProbeResult(ctx, result); sendErr != nil {
					responderErr <- sendErr
					return
				}
			case <-ctx.Done():
				responderErr <- ctx.Err()
				return
			}
		}
		responderErr <- nil
	}()

	result, err := sendExternalV2BulkPacketProbe(ctx, sender, senderCoordinator)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-responderErr; err != nil {
		t.Fatal(err)
	}
	if result.SelectedMbps != 460 {
		t.Fatalf("selected rate = %d, want 460", result.SelectedMbps)
	}
	if len(result.Trains) != 3 || result.Trains[2].Received != result.Trains[2].Sent*9/10 {
		t.Fatalf("probe trains = %+v, want two clean and one 90%% dirty", result.Trains)
	}
}

type dropExternalV2BulkProbeRatePacketConn struct {
	net.PacketConn
	auth         externalV2BulkPacketAuth
	totalPackets uint32
	rateMbps     int
}

func (c *dropExternalV2BulkProbeRatePacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(buffer)
		if err != nil {
			return n, addr, err
		}
		event, ok := decodeExternalV2BulkPacketProbeEvent(c.auth, c.totalPackets, externalV2BulkPacketBatchMessage{
			Buffers: [][]byte{buffer[:n]}, N: n,
		})
		if ok && event.prefix.RateMbps == uint32(c.rateMbps) && event.prefix.Sequence%10 == 0 {
			continue
		}
		return n, addr, nil
	}
}

func TestReceiveExternalV2BulkPacketProbeRetainsCleanTierAfterDirtyResult(t *testing.T) {
	previousRates := append([]int(nil), externalV2BulkPacketProbeRatesMbps...)
	externalV2BulkPacketProbeRatesMbps = []int{128, 512, 1000}
	t.Cleanup(func() { externalV2BulkPacketProbeRatesMbps = previousRates })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	senders, receiverSockets := listenExternalV2BulkPacketTestConns(t, 4)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	receivers := make([]net.PacketConn, len(receiverSockets))
	for lane, conn := range receiverSockets {
		receivers[lane] = &dropExternalV2BulkProbeRatePacketConn{
			PacketConn: conn, auth: auth, totalPackets: 1, rateMbps: 1000,
		}
	}
	sender := newExternalV2BulkPacketSender(
		ctx,
		&BlockSource{Payload: bytes.NewReader([]byte{0x5a}), PayloadSize: 1},
		externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receiverSockets)},
		auth,
		nil,
	)
	senderWire, receiverWire := newExternalV2BulkTestWirePair(t, nil)
	senderCoordinator := newExternalV2BulkTestCoordinatorWithBarrier(ctx, senderWire, 4*time.Second)
	receiverCoordinator := newExternalV2BulkTestCoordinatorWithBarrier(ctx, receiverWire, 4*time.Second)
	defer senderCoordinator.Close()
	defer receiverCoordinator.Close()

	receiverResult := make(chan struct {
		result externalV2BulkPacketProbeResult
		err    error
	}, 1)
	go func() {
		result, receiveErr := receiveExternalV2BulkPacketProbe(
			ctx,
			externalV2BulkPacketPath{Conns: receivers, Addrs: externalV2BulkPacketTestAddrs(senders)},
			auth,
			1,
			receiverCoordinator,
		)
		receiverResult <- struct {
			result externalV2BulkPacketProbeResult
			err    error
		}{result: result, err: receiveErr}
	}()

	sendResult, sendErr := sendExternalV2BulkPacketProbe(ctx, sender, senderCoordinator)
	if sendErr != nil {
		t.Fatal(sendErr)
	}
	received := <-receiverResult
	if received.err != nil {
		t.Fatal(received.err)
	}
	for role, result := range map[string]externalV2BulkPacketProbeResult{
		"sender": sendResult, "receiver": received.result,
	} {
		if result.SelectedMbps != 460 || len(result.Trains) != 3 {
			t.Fatalf("%s result = %+v, want three trains selected at 460 Mbps", role, result)
		}
		if result.Trains[2].Received*100 >= result.Trains[2].Sent*95 {
			t.Fatalf("%s final train = %+v, want dirty", role, result.Trains[2])
		}
	}
}
