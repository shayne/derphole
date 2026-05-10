// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/probe"
)

func TestExternalDirectUDPAdditionalPolicyHelpers(t *testing.T) {
	if !externalDirectUDPLowTotalCeiling(externalDirectUDPDataStartHighMbps) {
		t.Fatal("externalDirectUDPLowTotalCeiling(data start) = false, want true")
	}
	if externalDirectUDPLowTotalCeiling(0) {
		t.Fatal("externalDirectUDPLowTotalCeiling(0) = true, want false")
	}
	if !externalDirectUDPLowSelectedAndActiveRates(externalDirectUDPActiveLaneTwoMaxMbps-1, externalDirectUDPActiveLaneTwoMaxMbps-1) {
		t.Fatal("externalDirectUDPLowSelectedAndActiveRates(low rates) = false, want true")
	}
	if externalDirectUDPLowSelectedAndActiveRates(externalDirectUDPActiveLaneTwoMaxMbps, 1) {
		t.Fatal("externalDirectUDPLowSelectedAndActiveRates(at threshold) = true, want false")
	}
	if !externalDirectUDPLegacySenderCanRetainLanes(probe.TransportCaps{Kind: "legacy"}, 10, 10) {
		t.Fatal("legacy sender retain = false, want true")
	}
	if !externalDirectUDPBatchedSenderCanRetainLanes(probe.TransportCaps{Kind: "batched", RXQOverflow: true}, 10, 10, 0, 0) {
		t.Fatal("batched sender retain with overflow = false, want true")
	}

	caps := externalDirectUDPEffectiveSenderCaps(
		probe.TransportCaps{Kind: "batched", BatchSize: 0, TXOffload: true, RXQOverflow: true},
		directUDPReadyAck{TransportKind: "batched", TransportBatchSize: 64},
	)
	if caps.Kind != "batched" || caps.BatchSize != 64 || caps.TXOffload || caps.RXQOverflow {
		t.Fatalf("externalDirectUDPEffectiveSenderCaps() = %+v, want remote batched caps", caps)
	}
	caps = externalDirectUDPEffectiveSenderCaps(probe.TransportCaps{Kind: "batched"}, directUDPReadyAck{TransportKind: "legacy"})
	if caps.Kind != "legacy" {
		t.Fatalf("legacy ready ack caps kind = %q, want legacy", caps.Kind)
	}

	spool := &externalHandoffSpool{eof: true, sourceOffset: externalRelayPrefixSkipDirectTail + 10, ackedWatermark: 10}
	if !externalRelayPrefixShouldFinishRelay(spool) {
		t.Fatal("externalRelayPrefixShouldFinishRelay(tail within skip) = false, want true")
	}
	spool.ackedWatermark = 0
	if externalRelayPrefixShouldFinishRelay(spool) {
		t.Fatal("externalRelayPrefixShouldFinishRelay(tail too large) = true, want false")
	}
}

func TestExternalDirectUDPRateProbeFormattingAndSelectorHelpers(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 100, BytesSent: 1000},
		{RateMbps: 200, BytesSent: 2000},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 100, BytesReceived: 500, DurationMillis: 100},
		{RateMbps: 200, BytesReceived: 1000},
	}
	out := externalDirectUDPFormatRateProbeSamples(sent, received)
	if !strings.Contains(out, "100:rx=500:goodput=0.04:delivery=0.50") {
		t.Fatalf("formatted samples = %q, want 100 Mbps sample", out)
	}
	if !strings.Contains(out, "200:rx=1000:") || !strings.Contains(out, ":delivery=0.50") {
		t.Fatalf("formatted samples = %q, want 200 Mbps delivery", out)
	}
	if got := externalDirectUDPProbeDurationMillis(directUDPRateProbeSample{}); got != externalDirectUDPRateProbeDuration.Milliseconds() {
		t.Fatalf("default probe duration = %d, want %d", got, externalDirectUDPRateProbeDuration.Milliseconds())
	}
	if got := externalDirectUDPRateProbeDelivery(directUDPRateProbeSample{RateMbps: 1, BytesReceived: 1}, nil); got != 0 {
		t.Fatalf("delivery without sent sample = %f, want 0", got)
	}
	if !externalDirectUDPHasPositiveProbeProgress(received) {
		t.Fatal("externalDirectUDPHasPositiveProbeProgress() = false, want true")
	}

	ceiling := &externalDirectUDPRateCeilingSelector{
		maxRateMbps:      1000,
		selected:         externalDirectUDPRateProbeCollapseMinMbps,
		ceiling:          externalDirectUDPRateProbeCollapseMinMbps,
		ceilingGoodput:   500,
		highestProbeRate: 900,
	}
	obs := externalDirectUDPRateProbeObservation{
		rate:       900,
		goodput:    950,
		delivery:   externalDirectUDPRateProbeClean,
		efficiency: externalDirectUDPRateProbeEfficient,
	}
	if !ceiling.highThroughputKnee(obs) {
		t.Fatal("rate ceiling highThroughputKnee() = false, want true")
	}
	if !ceiling.meaningfulNextTier(externalDirectUDPRateProbeObservation{rate: 1200, goodput: 400, delivery: externalDirectUDPRateProbeCeilingDelivery}) {
		t.Fatal("meaningfulNextTier() = false, want true")
	}
	if ceiling.stopAfterAcceptedUnclean(obs) {
		t.Fatal("stopAfterAcceptedUnclean(clean obs) = true, want false")
	}
	if !ceiling.stopAfterAcceptedUnclean(externalDirectUDPRateProbeObservation{rate: 1200, goodput: 150, delivery: 0.5, efficiency: 0.1}) {
		t.Fatal("stopAfterAcceptedUnclean(weak obs) = false, want true")
	}

	knee := &externalDirectUDPProbeKneeHeadroomSelector{
		maxRateMbps:      1000,
		selected:         externalDirectUDPRateProbeCollapseMinMbps,
		selectedGoodput:  300,
		prevGoodput:      200,
		highestProbeRate: 900,
	}
	if !knee.highThroughputKnee(externalDirectUDPProbeKneeObservation{goodput: 950}) {
		t.Fatal("knee highThroughputKnee() = false, want true")
	}
	if got := knee.rateForNearCleanHigherProbe(externalDirectUDPProbeKneeObservation{rate: 100}); got < externalDirectUDPRateProbeMinMbps {
		t.Fatalf("rateForNearCleanHigherProbe() = %d, want at least minimum", got)
	}
	knee.selectedProbeViable = true
	knee.prevBelowSelectedRate = externalDirectUDPActiveLaneTwoMaxMbps
	rate, ok := knee.rateForBufferedCollapse(externalDirectUDPProbeKneeObservation{delivery: 0.1, sentEfficiency: externalDirectUDPRateProbeCeilingEfficient})
	if !ok || rate != knee.selected {
		t.Fatalf("rateForBufferedCollapse() = (%d, %t), want selected true", rate, ok)
	}
}

func TestExternalDirectUDPWaitAndDistributorHelpers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	if err := waitExternalDirectUDPAddrTick(ctx, ticker); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitExternalDirectUDPAddrTick(canceled) = %v, want context.Canceled", err)
	}
	if !externalDirectUDPWaitCanFallback(context.Background(), context.DeadlineExceeded) {
		t.Fatal("externalDirectUDPWaitCanFallback(deadline) = false, want true")
	}
	canceledCtx, cancelCanceled := context.WithCancel(context.Background())
	cancelCanceled()
	if externalDirectUDPWaitCanFallback(canceledCtx, context.DeadlineExceeded) {
		t.Fatal("externalDirectUDPWaitCanFallback(canceled ctx) = true, want false")
	}
	_, writer := io.Pipe()
	distributor := newExternalDirectUDPDiscardDistributor(context.Background(), strings.NewReader(""), []*io.PipeWriter{writer}, 4)
	if err := distributor.waitForProgress(); err != nil {
		t.Fatalf("waitForProgress(active) error = %v", err)
	}
	distributor.startWriters()
	wantErr := errors.New("writer failed")
	distributor.setWriterErr(wantErr)
	if got := distributor.currentWriterErr(); !errors.Is(got, wantErr) {
		t.Fatalf("currentWriterErr() = %v, want %v", got, wantErr)
	}
	if err := distributor.waitForProgress(); !errors.Is(err, wantErr) {
		t.Fatalf("waitForProgress() = %v, want writer err", err)
	}
	_ = writer.Close()
}

func TestExternalNativeTCPRaceErrorHelpers(t *testing.T) {
	firstErr := errors.New("first")
	resultErr := errors.New("result")
	connA, connB := net.Pipe()
	defer connA.Close()

	if err := externalNativeTCPFirstRaceErr(firstErr, externalNativeTCPConnResult{conn: connB, err: resultErr}); !errors.Is(err, firstErr) {
		t.Fatalf("externalNativeTCPFirstRaceErr(first) = %v, want %v", err, firstErr)
	}
	if _, err := connB.Write([]byte("x")); err == nil {
		t.Fatal("closed race-loser conn Write() error = nil, want closed pipe")
	}
	if err := externalNativeTCPFirstRaceErr(nil, externalNativeTCPConnResult{err: resultErr}); !errors.Is(err, resultErr) {
		t.Fatalf("externalNativeTCPFirstRaceErr(result) = %v, want %v", err, resultErr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := externalNativeTCPConnRaceDoneErr(ctx, firstErr); !errors.Is(err, firstErr) {
		t.Fatalf("externalNativeTCPConnRaceDoneErr(first) = %v, want %v", err, firstErr)
	}
	if err := externalNativeTCPConnRaceDoneErr(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("externalNativeTCPConnRaceDoneErr(ctx) = %v, want context.Canceled", err)
	}
}
