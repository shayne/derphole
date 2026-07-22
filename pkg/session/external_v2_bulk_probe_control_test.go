// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidateExternalV2BulkControlProbePhases(t *testing.T) {
	sent := externalV2BulkPacketProbeDatagramCount(1000)
	end := externalV2BulkControl{
		Protocol:   externalV2Protocol,
		Phase:      externalV2BulkPhaseProbeEnd,
		ProbeRunID: 77,
		Mode:       externalV2BulkModeBulk,
		Probe: &externalV2BulkProbeControl{
			Train: 2, RateMbps: 1000, Sent: sent,
		},
	}
	result := end
	result.Phase = externalV2BulkPhaseProbeResult
	result.Probe = &externalV2BulkProbeControl{
		Train: 2, RateMbps: 1000, Sent: sent, Received: sent * 9 / 10, Final: true,
	}
	for name, message := range map[string]externalV2BulkControl{
		"end":    end,
		"result": result,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateExternalV2BulkControl(message); err != nil {
				t.Fatalf("validateExternalV2BulkControl() error = %v", err)
			}
		})
	}
}

func TestValidateExternalV2BulkControlRejectsInvalidProbeFields(t *testing.T) {
	sent := externalV2BulkPacketProbeDatagramCount(1000)
	validEnd := externalV2BulkControl{
		Protocol:   externalV2Protocol,
		Phase:      externalV2BulkPhaseProbeEnd,
		ProbeRunID: 77,
		Mode:       externalV2BulkModeBulk,
		Probe: &externalV2BulkProbeControl{
			Train: 2, RateMbps: 1000, Sent: sent,
		},
	}
	validResult := validEnd
	validResult.Phase = externalV2BulkPhaseProbeResult
	validResult.Probe = &externalV2BulkProbeControl{
		Train: 2, RateMbps: 1000, Sent: sent, Received: sent * 9 / 10, Final: true,
	}
	tests := []struct {
		name    string
		message externalV2BulkControl
	}{
		{name: "end without probe", message: func() externalV2BulkControl {
			message := validEnd
			message.Probe = nil
			return message
		}()},
		{name: "probe on decision", message: func() externalV2BulkControl {
			return externalV2BulkControl{
				Protocol: externalV2Protocol, Phase: externalV2BulkPhaseDecision,
				ProbeRunID: 77, Mode: externalV2BulkModeBulk, SelectedMbps: 900,
				Reason: externalV2BulkReasonBothAccepted, Probe: validEnd.Probe,
			}
		}()},
		{name: "zero run", message: func() externalV2BulkControl {
			message := validEnd
			message.ProbeRunID = 0
			return message
		}()},
		{name: "wrong train rate", message: func() externalV2BulkControl {
			message := validEnd
			probe := *message.Probe
			probe.RateMbps = 512
			message.Probe = &probe
			return message
		}()},
		{name: "zero sent", message: func() externalV2BulkControl {
			message := validEnd
			probe := *message.Probe
			probe.Sent = 0
			message.Probe = &probe
			return message
		}()},
		{name: "received on end", message: func() externalV2BulkControl {
			message := validEnd
			probe := *message.Probe
			probe.Received = 1
			message.Probe = &probe
			return message
		}()},
		{name: "received greater than sent", message: func() externalV2BulkControl {
			message := validResult
			probe := *message.Probe
			probe.Received = probe.Sent + 1
			message.Probe = &probe
			return message
		}()},
		{name: "selected rate", message: func() externalV2BulkControl {
			message := validEnd
			message.SelectedMbps = 128
			return message
		}()},
		{name: "reason", message: func() externalV2BulkControl {
			message := validEnd
			message.Reason = externalV2BulkReasonProbeAccepted
			return message
		}()},
		{name: "end impossible final", message: func() externalV2BulkControl {
			message := validEnd
			probe := *message.Probe
			probe.Final = true
			message.Probe = &probe
			return message
		}()},
		{name: "dirty result not final", message: func() externalV2BulkControl {
			message := validResult
			probe := *message.Probe
			probe.Final = false
			message.Probe = &probe
			return message
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateExternalV2BulkControl(test.message); !errors.Is(err, errExternalV2BulkDecisionProtocol) {
				t.Fatalf("validation error = %v, want protocol error", err)
			}
		})
	}
}

func TestExternalV2BulkProbeControlRetriesDroppedBoundaryAndPreservesReadiness(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var endSends atomic.Int32
	senderWire, receiverWire := newExternalV2BulkTestWirePair(t, func(fromSender bool, message externalV2BulkControl) bool {
		return fromSender && message.Phase == externalV2BulkPhaseProbeEnd && endSends.Add(1) == 1
	})
	sender := newExternalV2BulkTestCoordinatorWithBarrier(ctx, senderWire, time.Second)
	receiver := newExternalV2BulkTestCoordinatorWithBarrier(ctx, receiverWire, time.Second)
	sender.retry = 5 * time.Millisecond
	receiver.retry = 5 * time.Millisecond
	defer sender.Close()
	defer receiver.Close()

	sent := externalV2BulkPacketProbeDatagramCount(128)
	end := externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseProbeEnd,
		ProbeRunID: 77, Mode: externalV2BulkModeBulk,
		Probe: &externalV2BulkProbeControl{Train: 0, RateMbps: 128, Sent: sent},
	}
	result := end
	result.Phase = externalV2BulkPhaseProbeResult
	result.Probe = &externalV2BulkProbeControl{Train: 0, RateMbps: 128, Sent: sent, Received: sent}
	ready := externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseReady,
		ProbeRunID: 77, Mode: externalV2BulkModeBulk,
		SelectedMbps: 128, Reason: externalV2BulkReasonProbeAccepted,
	}

	receiverErr := make(chan error, 1)
	go func() {
		if err := receiver.send(ctx, ready); err != nil {
			receiverErr <- err
			return
		}
		select {
		case event := <-receiver.probeControlEvents():
			message, err := externalV2BulkControlFromEvent(event, true)
			if err != nil {
				receiverErr <- err
				return
			}
			if !externalV2BulkControlsEqual(message, end) {
				receiverErr <- errors.New("receiver got wrong probe boundary")
				return
			}
			receiverErr <- receiver.sendProbeResult(ctx, result)
		case <-ctx.Done():
			receiverErr <- ctx.Err()
		}
	}()

	got, err := sender.sendProbeEndAndWaitResult(ctx, end)
	if err != nil {
		t.Fatal(err)
	}
	if !externalV2BulkControlsEqual(got, result) {
		t.Fatalf("probe result = %+v, want %+v", got, result)
	}
	if endSends.Load() < 2 {
		t.Fatalf("probe end sends = %d, want retry", endSends.Load())
	}
	gotReady, timedOut, err := sender.waitForReadiness(ctx, 77)
	if err != nil || timedOut || !externalV2BulkControlsEqual(gotReady, ready) {
		t.Fatalf("readiness = (%+v, timedOut=%t, err=%v), want %+v", gotReady, timedOut, err, ready)
	}
	if err := <-receiverErr; err != nil {
		t.Fatal(err)
	}
}

func TestExternalV2BulkProbeControlResendsFinalResultForDuplicateBoundary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	senderWire, receiverWire := newExternalV2BulkTestWirePair(t, nil)
	sender := newExternalV2BulkTestCoordinatorWithBarrier(ctx, senderWire, time.Second)
	receiver := newExternalV2BulkTestCoordinatorWithBarrier(ctx, receiverWire, time.Second)
	defer sender.Close()
	defer receiver.Close()

	sent := externalV2BulkPacketProbeDatagramCount(128)
	end := externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseProbeEnd,
		ProbeRunID: 77, Mode: externalV2BulkModeBulk,
		Probe: &externalV2BulkProbeControl{
			Train: 0, RateMbps: 128, Sent: sent, Pressure: true, Final: true,
		},
	}
	result := end
	result.Phase = externalV2BulkPhaseProbeResult
	result.Probe = &externalV2BulkProbeControl{
		Train: 0, RateMbps: 128, Sent: sent, Received: sent, Pressure: true, Final: true,
	}

	receiver.respondToDuplicateProbeEnds(end, result)
	got, err := sender.sendProbeEndAndWaitResult(ctx, end)
	if err != nil {
		t.Fatal(err)
	}
	if !externalV2BulkControlsEqual(got, result) {
		t.Fatalf("duplicate probe result = %+v, want %+v", got, result)
	}
}

func TestExternalV2BulkControlsEqualComparesProbeValues(t *testing.T) {
	sent := externalV2BulkPacketProbeDatagramCount(128)
	left := externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseProbeResult,
		ProbeRunID: 77, Mode: externalV2BulkModeBulk,
		Probe: &externalV2BulkProbeControl{Train: 0, RateMbps: 128, Sent: sent, Received: sent},
	}
	right := left
	probe := *left.Probe
	right.Probe = &probe
	if !externalV2BulkControlsEqual(left, right) {
		t.Fatal("equal probe values with distinct pointers compared different")
	}
	right.Probe.Received--
	if externalV2BulkControlsEqual(left, right) {
		t.Fatal("different probe values compared equal")
	}
}

func TestExternalV2BulkProbeControlRejectsContradictoryPriorResult(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	senderWire, receiverWire := newExternalV2BulkTestWirePair(t, nil)
	sender := newExternalV2BulkTestCoordinatorWithBarrier(ctx, senderWire, time.Second)
	receiver := newExternalV2BulkTestCoordinatorWithBarrier(ctx, receiverWire, time.Second)
	defer sender.Close()
	defer receiver.Close()

	makeEnd := func(train int) externalV2BulkControl {
		rateMbps := externalV2BulkPacketProbeRatesMbps[train]
		return externalV2BulkControl{
			Protocol: externalV2Protocol, Phase: externalV2BulkPhaseProbeEnd,
			ProbeRunID: 77, Mode: externalV2BulkModeBulk,
			Probe: &externalV2BulkProbeControl{
				Train: train, RateMbps: rateMbps,
				Sent: externalV2BulkPacketProbeDatagramCount(rateMbps),
			},
		}
	}
	firstEnd := makeEnd(0)
	firstResult := firstEnd
	firstResult.Phase = externalV2BulkPhaseProbeResult
	firstProbe := *firstEnd.Probe
	firstProbe.Received = firstProbe.Sent
	firstResult.Probe = &firstProbe
	secondEnd := makeEnd(1)

	receiverErr := make(chan error, 1)
	go func() {
		select {
		case <-receiver.probeControlEvents():
		case <-ctx.Done():
			receiverErr <- ctx.Err()
			return
		}
		receiverErr <- receiver.sendProbeResult(ctx, firstResult)
	}()

	if _, err := sender.sendProbeEndAndWaitResult(ctx, firstEnd); err != nil {
		t.Fatal(err)
	}
	if err := <-receiverErr; err != nil {
		t.Fatal(err)
	}
	contradictory := firstResult
	contradictoryProbe := *firstResult.Probe
	contradictoryProbe.Received--
	contradictory.Probe = &contradictoryProbe
	// Send the contradictory prior result directly before the receiver handles train 1.
	if err := receiver.sendProbeResult(ctx, contradictory); err != nil {
		t.Fatal(err)
	}
	if _, err := sender.sendProbeEndAndWaitResult(ctx, secondEnd); !errors.Is(err, errExternalV2BulkDecisionProtocol) {
		t.Fatalf("probe error = %v, want protocol error", err)
	}
}

func TestExternalV2BulkDecisionCoordinatorRoutesTerminalToProbeAndDecisionWaiters(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	events := make(chan externalV2BulkControlEvent, 1)
	wantErr := errors.New("injected control failure")
	wire := externalV2BulkTestWire{
		send:   func(context.Context, externalV2BulkControl) error { return nil },
		events: events,
		close:  func() {},
	}
	coordinator := newExternalV2BulkTestCoordinatorWithBarrier(ctx, wire, time.Second)
	defer coordinator.Close()
	sent := externalV2BulkPacketProbeDatagramCount(128)
	end := externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseProbeEnd,
		ProbeRunID: 77, Mode: externalV2BulkModeBulk,
		Probe: &externalV2BulkProbeControl{Train: 0, RateMbps: 128, Sent: sent},
	}
	probeErr := make(chan error, 1)
	decisionErr := make(chan error, 1)
	go func() {
		_, err := coordinator.sendProbeEndAndWaitResult(ctx, end)
		probeErr <- err
	}()
	go func() {
		_, _, err := coordinator.waitForReadiness(ctx, 77)
		decisionErr <- err
	}()
	events <- externalV2BulkControlEvent{Err: wantErr}
	for name, errCh := range map[string]<-chan error{"probe": probeErr, "decision": decisionErr} {
		t.Run(name, func(t *testing.T) {
			select {
			case err := <-errCh:
				if err != wantErr {
					t.Fatalf("error = %v, want exact %v", err, wantErr)
				}
			case <-ctx.Done():
				t.Fatalf("waiter did not receive terminal event: %v", ctx.Err())
			}
		})
	}
}
