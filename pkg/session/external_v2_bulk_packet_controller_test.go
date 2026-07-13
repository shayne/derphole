// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"testing"
	"time"
)

func TestExternalV2BulkPacketInitialWireMbpsFromEnvironment(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
	}{
		{name: "unset", raw: "", want: 1000},
		{name: "eight hundred", raw: "800", want: 800},
		{name: "nine hundred", raw: "900", want: 900},
		{name: "minimum", raw: "128", want: 128},
		{name: "ceiling", raw: "2400", want: 2400},
		{name: "below minimum", raw: "127", want: 1000},
		{name: "above ceiling", raw: "2401", want: 1000},
		{name: "invalid", raw: "fast", want: 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(externalV2BulkPacketInitialWireMbpsEnv, tt.raw)
			if got := externalV2BulkPacketInitialWireMbps(); got != tt.want {
				t.Fatalf("initial wire Mbps = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestExternalV2BulkPacketControllerUsesSuppliedInitialTarget(t *testing.T) {
	for _, initial := range []int{800, 900, 1000} {
		controller := newExternalV2BulkPacketController(initial)
		decision := controller.Observe(externalV2BulkPacketControllerSample{At: time.Unix(240, 0)})
		if decision.TargetMbps != initial || decision.Reason != "initial-target" {
			t.Fatalf("initial %d decision = %#v", initial, decision)
		}
	}
}

func TestExternalV2BulkPacketIPv4WireBytes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		datagram int
		want     int
	}{
		{datagram: 0, want: 0},
		{datagram: 1400, want: 1428},
		{datagram: 42, want: 70},
	} {
		if got := externalV2BulkPacketIPv4WireBytes(tc.datagram); got != tc.want {
			t.Fatalf("wire bytes for datagram %d = %d, want %d", tc.datagram, got, tc.want)
		}
	}
}

func observeExternalV2BulkPacketController(
	t *testing.T,
	primaryWireBytes int64,
	repairWireBytes int64,
	peerBytes int64,
) externalV2BulkPacketControllerDecision {
	t.Helper()
	controller := newExternalV2BulkPacketController(externalV2BulkPacketDefaultInitialWireMbps)
	start := time.Unix(200, 0)
	controller.Observe(externalV2BulkPacketControllerSample{
		At:           start,
		PeerProgress: true,
	})
	return controller.Observe(externalV2BulkPacketControllerSample{
		At:                    start.Add(externalV2BulkPacketControllerInterval),
		PrimaryWireBytes:      primaryWireBytes,
		RepairWireBytes:       repairWireBytes,
		PeerBytes:             peerBytes,
		PeerTransferElapsedMS: externalV2BulkPacketControllerInterval.Milliseconds(),
		PeerProgress:          true,
	})
}

type externalV2BulkPacketControllerTestSeries struct {
	controller *externalV2BulkPacketController
	sample     externalV2BulkPacketControllerSample
}

func newExternalV2BulkPacketControllerTestSeries(at time.Time) *externalV2BulkPacketControllerTestSeries {
	controller := newExternalV2BulkPacketController(externalV2BulkPacketDefaultInitialWireMbps)
	sample := externalV2BulkPacketControllerSample{
		At:           at,
		PeerProgress: true,
	}
	controller.Observe(sample)
	return &externalV2BulkPacketControllerTestSeries{
		controller: controller,
		sample:     sample,
	}
}

func (s *externalV2BulkPacketControllerTestSeries) observe(
	primaryWireDelta int64,
	repairWireDelta int64,
	peerBytesDelta int64,
	peerProgress bool,
) externalV2BulkPacketControllerDecision {
	s.sample.At = s.sample.At.Add(externalV2BulkPacketControllerInterval)
	s.sample.PrimaryWireBytes += primaryWireDelta
	s.sample.RepairWireBytes += repairWireDelta
	s.sample.PeerProgress = peerProgress
	if peerProgress {
		s.sample.PeerBytes += peerBytesDelta
		s.sample.PeerTransferElapsedMS += externalV2BulkPacketControllerInterval.Milliseconds()
	}
	return s.controller.Observe(s.sample)
}

func TestExternalV2BulkPacketControllerPolicy(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		primary    int64
		repair     int64
		peer       int64
		wantTarget int
		wantAction string
		wantReason string
	}{
		{
			name:       "clean delivery explores",
			primary:    60_000_000,
			peer:       56_250_000,
			wantTarget: 1064,
			wantAction: "increase",
			wantReason: "clean-delivery",
		},
		{
			name:       "exact healthy threshold explores",
			primary:    60_000_000,
			peer:       53_492_648,
			wantTarget: 1064,
			wantAction: "increase",
			wantReason: "clean-delivery",
		},
		{
			name:       "moderate repair holds a productive target",
			primary:    57_300_000,
			repair:     2_700_000,
			peer:       56_125_000,
			wantTarget: 1000,
			wantAction: "hold",
			wantReason: "repair-hold",
		},
		{
			name:       "first repair plus low delivery waits for confirmation",
			primary:    57_600_000,
			repair:     2_400_000,
			peer:       50_000_000,
			wantTarget: 1000,
			wantAction: "hold",
			wantReason: "repair-pressure-pending",
		},
		{
			name:       "hard repair with healthy delivery holds",
			primary:    54_600_000,
			repair:     5_400_000,
			peer:       56_125_000,
			wantTarget: 1000,
			wantAction: "hold",
			wantReason: "repair-hold",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := observeExternalV2BulkPacketController(t, tc.primary, tc.repair, tc.peer)
			if got.TargetMbps != tc.wantTarget ||
				got.Action != tc.wantAction ||
				got.Reason != tc.wantReason {
				t.Fatalf("decision = %#v, want target=%d action=%q reason=%q",
					got,
					tc.wantTarget,
					tc.wantAction,
					tc.wantReason,
				)
			}
		})
	}
}

func TestExternalV2BulkPacketControllerHoldsAfterBackoff(t *testing.T) {
	t.Parallel()

	series := newExternalV2BulkPacketControllerTestSeries(time.Unix(210, 0))
	first := series.observe(54_600_000, 5_400_000, 40_000_000, true)
	if first.Action != "hold" ||
		first.Reason != "repair-pressure-pending" ||
		first.TargetMbps != 1000 {
		t.Fatalf("first decision = %#v, want pending hold at 1000", first)
	}

	second := series.observe(54_600_000, 5_400_000, 40_000_000, true)
	if second.Action != "decrease" ||
		second.Reason != "hard-repair-pressure" ||
		second.TargetMbps != 850 {
		t.Fatalf("second decision = %#v, want confirmed decrease to 850", second)
	}

	third := series.observe(60_000_000, 0, 50_000_000, true)
	if third.Action != "hold" ||
		third.Reason != "backoff-cooldown" ||
		third.TargetMbps != 850 {
		t.Fatalf("third decision = %#v, want cooldown hold at 850", third)
	}
}

func TestExternalV2BulkPacketControllerConfirmsSoftPressureBeforeDecrease(t *testing.T) {
	t.Parallel()

	series := newExternalV2BulkPacketControllerTestSeries(time.Unix(211, 0))
	first := series.observe(57_600_000, 2_400_000, 50_000_000, true)
	if first.Action != "hold" ||
		first.Reason != "repair-pressure-pending" ||
		first.TargetMbps != 1000 {
		t.Fatalf("first decision = %#v, want pending hold at 1000", first)
	}

	second := series.observe(57_600_000, 2_400_000, 50_000_000, true)
	if second.Action != "decrease" ||
		second.Reason != "repair-and-delivery-drop" ||
		second.TargetMbps != 850 {
		t.Fatalf("second decision = %#v, want confirmed soft decrease to 850", second)
	}
}

func TestExternalV2BulkPacketControllerHealthyHardRepairResetsPressure(t *testing.T) {
	t.Parallel()

	series := newExternalV2BulkPacketControllerTestSeries(time.Unix(212, 0))
	first := series.observe(57_600_000, 2_400_000, 50_000_000, true)
	if first.Reason != "repair-pressure-pending" {
		t.Fatalf("first decision = %#v, want pending pressure", first)
	}

	healthy := series.observe(54_600_000, 5_400_000, 56_125_000, true)
	if healthy.Action != "hold" ||
		healthy.Reason != "repair-hold" ||
		healthy.TargetMbps != 1000 {
		t.Fatalf("healthy hard-repair decision = %#v, want repair hold at 1000", healthy)
	}

	afterReset := series.observe(57_600_000, 2_400_000, 50_000_000, true)
	if afterReset.Action != "hold" ||
		afterReset.Reason != "repair-pressure-pending" ||
		afterReset.TargetMbps != 1000 {
		t.Fatalf("decision after healthy reset = %#v, want fresh pending hold", afterReset)
	}
}

func TestExternalV2BulkPacketControllerLowRepairInterruptsPressure(t *testing.T) {
	t.Parallel()

	series := newExternalV2BulkPacketControllerTestSeries(time.Unix(213, 0))
	first := series.observe(57_600_000, 2_400_000, 50_000_000, true)
	if first.Reason != "repair-pressure-pending" {
		t.Fatalf("first decision = %#v, want pending pressure", first)
	}

	interrupted := series.observe(60_000_000, 0, 45_000_000, true)
	if interrupted.Action != "hold" ||
		interrupted.Reason != "receiver-limited-pending" ||
		interrupted.TargetMbps != 1000 {
		t.Fatalf("low-repair decision = %#v, want pending receiver-limited hold", interrupted)
	}

	afterReset := series.observe(57_600_000, 2_400_000, 50_000_000, true)
	if afterReset.Action != "hold" ||
		afterReset.Reason != "repair-pressure-pending" ||
		afterReset.TargetMbps != 1000 {
		t.Fatalf("decision after interrupted pressure = %#v, want fresh pending hold", afterReset)
	}
}

func TestExternalV2BulkPacketControllerSustainedPressureDecreasesDuringCooldown(t *testing.T) {
	t.Parallel()

	series := newExternalV2BulkPacketControllerTestSeries(time.Unix(214, 0))
	wantTargets := []int{1000, 850, 850, 722}
	wantActions := []string{"hold", "decrease", "hold", "decrease"}
	wantReasons := []string{
		"repair-pressure-pending",
		"hard-repair-pressure",
		"repair-pressure-pending",
		"hard-repair-pressure",
	}
	for i := range wantTargets {
		got := series.observe(54_600_000, 5_400_000, 40_000_000, true)
		if got.TargetMbps != wantTargets[i] ||
			got.Action != wantActions[i] ||
			got.Reason != wantReasons[i] {
			t.Fatalf("decision %d = %#v, want target=%d action=%q reason=%q",
				i+1,
				got,
				wantTargets[i],
				wantActions[i],
				wantReasons[i],
			)
		}
	}
}

func TestExternalV2BulkPacketControllerNoPeerProgressResetsPressure(t *testing.T) {
	t.Parallel()

	series := newExternalV2BulkPacketControllerTestSeries(time.Unix(215, 0))
	first := series.observe(54_600_000, 5_400_000, 40_000_000, true)
	if first.Reason != "repair-pressure-pending" {
		t.Fatalf("first decision = %#v, want pending pressure", first)
	}

	withoutPeer := series.observe(54_600_000, 5_400_000, 0, false)
	if withoutPeer.Action != "hold" ||
		withoutPeer.Reason != "awaiting-peer-progress" ||
		withoutPeer.TargetMbps != 1000 {
		t.Fatalf("no-peer hard-repair decision = %#v, want awaiting-peer hold", withoutPeer)
	}

	reestablished := series.observe(54_600_000, 5_400_000, 40_000_000, true)
	if reestablished.Action != "hold" ||
		reestablished.Reason != "awaiting-peer-progress" ||
		reestablished.TargetMbps != 1000 {
		t.Fatalf("first decision after peer reset = %#v, want peer-progress hold", reestablished)
	}

	afterReset := series.observe(54_600_000, 5_400_000, 40_000_000, true)
	if afterReset.Action != "hold" ||
		afterReset.Reason != "repair-pressure-pending" ||
		afterReset.TargetMbps != 1000 {
		t.Fatalf("second decision after peer reset = %#v, want fresh pending hold", afterReset)
	}
}

func TestExternalV2BulkPacketControllerBacksOffSustainedReceiverLimitAcrossProgressGap(t *testing.T) {
	series := newExternalV2BulkPacketControllerTestSeries(time.Unix(226, 0))
	first := series.observe(135_000_000, 0, 25_000_000, true)
	if first.Action != "hold" || first.Reason != "receiver-limited-pending" || first.TargetMbps != 1000 {
		t.Fatalf("first receiver-limited decision = %#v", first)
	}

	series.sample.At = series.sample.At.Add(externalV2BulkPacketControllerInterval)
	series.sample.PrimaryWireBytes += 135_000_000
	gap := series.controller.Observe(series.sample)
	if gap.Action != "hold" || gap.Reason != "awaiting-peer-progress" || gap.TargetMbps != 1000 {
		t.Fatalf("progress-gap decision = %#v", gap)
	}

	confirmed := series.observe(135_000_000, 0, 25_000_000, true)
	if confirmed.Action != "decrease" || confirmed.Reason != "receiver-limited" || confirmed.TargetMbps != 850 {
		t.Fatalf("confirmed receiver-limited decision = %#v", confirmed)
	}
}

func TestExternalV2BulkPacketControllerDoesNotBackOffReceiveWindowFlowControl(t *testing.T) {
	controller := newExternalV2BulkPacketController(2160)
	start := time.Unix(227, 0)
	controller.Observe(externalV2BulkPacketControllerSample{At: start, PeerProgress: true})
	for window := 1; window <= 3; window++ {
		decision := controller.Observe(externalV2BulkPacketControllerSample{
			At:                    start.Add(time.Duration(window) * externalV2BulkPacketControllerInterval),
			PrimaryWireBytes:      int64(window) * 128_000_000,
			PeerBytes:             int64(window) * 90_000_000,
			PeerTransferElapsedMS: int64(window) * externalV2BulkPacketControllerInterval.Milliseconds(),
			PeerProgress:          true,
			ReceiveWindowBlocked:  true,
		})
		if decision.TargetMbps != 2160 || decision.Action != "hold" || decision.Reason != "receive-window" {
			t.Fatalf("window %d decision = %#v, want receive-window hold at probe target", window, decision)
		}
	}
}

func TestExternalV2BulkPacketControllerInsufficientSampleDoesNotAdvanceOrClearPressure(t *testing.T) {
	t.Parallel()

	t.Run("does not advance", func(t *testing.T) {
		series := newExternalV2BulkPacketControllerTestSeries(time.Unix(216, 0))
		insufficient := series.observe(4<<20, 1<<20, 1<<20, true)
		if insufficient.Reason != "insufficient-wire-sample" {
			t.Fatalf("insufficient decision = %#v", insufficient)
		}
		accepted := series.observe(5<<20, 1<<20, 1<<20, true)
		if accepted.Action != "hold" ||
			accepted.Reason != "repair-pressure-pending" ||
			accepted.TargetMbps != 1000 {
			t.Fatalf("first accepted pressure = %#v, want pending hold", accepted)
		}
	})

	t.Run("does not clear", func(t *testing.T) {
		series := newExternalV2BulkPacketControllerTestSeries(time.Unix(217, 0))
		first := series.observe(9<<20, 1<<20, 1<<20, true)
		if first.Reason != "repair-pressure-pending" {
			t.Fatalf("first decision = %#v, want pending pressure", first)
		}
		insufficient := series.observe(4<<20, 0, 0, true)
		if insufficient.Reason != "insufficient-wire-sample" {
			t.Fatalf("insufficient decision = %#v", insufficient)
		}
		confirmed := series.observe(5<<20, 1<<20, 1<<20, true)
		if confirmed.Action != "decrease" || confirmed.TargetMbps != 850 {
			t.Fatalf("pressure after insufficient sample = %#v, want confirmed decrease", confirmed)
		}
	})
}

func TestExternalV2BulkPacketControllerCounterResetClearsPressure(t *testing.T) {
	t.Parallel()

	series := newExternalV2BulkPacketControllerTestSeries(time.Unix(218, 0))
	first := series.observe(54_600_000, 5_400_000, 40_000_000, true)
	if first.Reason != "repair-pressure-pending" {
		t.Fatalf("first decision = %#v, want pending pressure", first)
	}

	series.sample.At = series.sample.At.Add(externalV2BulkPacketControllerInterval)
	series.sample.PrimaryWireBytes = 1
	series.sample.RepairWireBytes = 0
	series.sample.PeerBytes = 0
	series.sample.PeerTransferElapsedMS = 0
	reset := series.controller.Observe(series.sample)
	if reset.Reason != "counter-reset" {
		t.Fatalf("counter reset decision = %#v", reset)
	}

	afterReset := series.observe(54_600_000, 5_400_000, 40_000_000, true)
	if afterReset.Action != "hold" ||
		afterReset.Reason != "repair-pressure-pending" ||
		afterReset.TargetMbps != 1000 {
		t.Fatalf("decision after counter reset = %#v, want fresh pending hold", afterReset)
	}
}

func TestExternalV2BulkPacketControllerFastRunOneReplayAvoidsCompoundedCollapse(t *testing.T) {
	t.Parallel()

	const mib = int64(1 << 20)
	series := newExternalV2BulkPacketControllerTestSeries(time.Unix(219, 0))
	windows := []struct {
		primary int64
		repair  int64
		peer    int64
		target  int
		action  string
		reason  string
	}{
		{primary: 46 * mib, repair: 9 * mib, peer: 3 * mib, target: 1000, action: "hold", reason: "repair-pressure-pending"},
		{primary: 28 * mib, repair: 21 * mib, peer: 5 * mib / 2, target: 850, action: "decrease", reason: "hard-repair-pressure"},
		{primary: 25 * mib, repair: 16 * mib, peer: 34 * mib, target: 850, action: "hold", reason: "repair-pressure-pending"},
		{primary: 26 * mib, repair: 9 * mib, peer: 46 * mib, target: 850, action: "hold", reason: "repair-hold"},
		{primary: 26 * mib, repair: 7 * mib / 2, peer: 111 * mib / 2, target: 850, action: "hold", reason: "repair-hold"},
	}
	for i, window := range windows {
		got := series.observe(window.primary, window.repair, window.peer, true)
		if got.TargetMbps != window.target ||
			got.Action != window.action ||
			got.Reason != window.reason {
			t.Fatalf("replay decision %d = %#v, want target=%d action=%q reason=%q",
				i+1,
				got,
				window.target,
				window.action,
				window.reason,
			)
		}
	}
}

func TestExternalV2BulkPacketControllerNeedsEnoughTrafficAndPeerProgress(t *testing.T) {
	t.Parallel()

	controller := newExternalV2BulkPacketController(externalV2BulkPacketDefaultInitialWireMbps)
	start := time.Unix(220, 0)
	if got := controller.Observe(externalV2BulkPacketControllerSample{At: start}); got.Reason != "initial-target" {
		t.Fatalf("initial decision = %#v, want initial-target", got)
	}
	if got := controller.Observe(externalV2BulkPacketControllerSample{
		At:               start.Add(500 * time.Millisecond),
		PrimaryWireBytes: 4 << 20,
	}); got.Reason != "insufficient-wire-sample" {
		t.Fatalf("small-sample decision = %#v, want insufficient-wire-sample", got)
	}
	if got := controller.Observe(externalV2BulkPacketControllerSample{
		At:               start.Add(time.Second),
		PrimaryWireBytes: 64 << 20,
	}); got.Reason != "awaiting-peer-progress" {
		t.Fatalf("no-peer decision = %#v, want awaiting-peer-progress", got)
	}
}

func TestExternalV2BulkPacketControllerAccumulatesFloorRateSamples(t *testing.T) {
	t.Parallel()

	controller := newExternalV2BulkPacketController(externalV2BulkPacketDefaultInitialWireMbps)
	controller.targetMbps = externalV2BulkPacketMinimumWireMbps
	start := time.Unix(223, 0)
	controller.Observe(externalV2BulkPacketControllerSample{
		At:           start,
		PeerProgress: true,
	})

	first := controller.Observe(externalV2BulkPacketControllerSample{
		At:                    start.Add(externalV2BulkPacketControllerInterval),
		PrimaryWireBytes:      8_000_000,
		PeerBytes:             7_607_844,
		PeerTransferElapsedMS: externalV2BulkPacketControllerInterval.Milliseconds(),
		PeerProgress:          true,
	})
	if first.TargetMbps != externalV2BulkPacketMinimumWireMbps ||
		first.Action != "hold" ||
		first.Reason != "insufficient-wire-sample" {
		t.Fatalf("first decision = %#v, want insufficient hold at minimum", first)
	}

	second := controller.Observe(externalV2BulkPacketControllerSample{
		At:                    start.Add(2 * externalV2BulkPacketControllerInterval),
		PrimaryWireBytes:      16_000_000,
		PeerBytes:             15_215_688,
		PeerTransferElapsedMS: 2 * externalV2BulkPacketControllerInterval.Milliseconds(),
		PeerProgress:          true,
	})
	if second.TargetMbps != externalV2BulkPacketMinimumWireMbps+externalV2BulkPacketIncreaseWireMbps ||
		second.Action != "increase" ||
		second.Reason != "clean-delivery" {
		t.Fatalf("second decision = %#v, want accumulated clean delivery to increase", second)
	}
}

func TestExternalV2BulkPacketControllerResetsAfterObservedCounterRegression(t *testing.T) {
	t.Parallel()

	controller := newExternalV2BulkPacketController(externalV2BulkPacketDefaultInitialWireMbps)
	start := time.Unix(224, 0)
	controller.Observe(externalV2BulkPacketControllerSample{At: start})

	acceptedPrimary := int64(externalV2BulkPacketMinimumSampleWire)
	accepted := controller.Observe(externalV2BulkPacketControllerSample{
		At:               start.Add(externalV2BulkPacketControllerInterval),
		PrimaryWireBytes: acceptedPrimary,
	})
	if accepted.Reason != "awaiting-peer-progress" {
		t.Fatalf("accepted decision = %#v, want awaiting-peer-progress", accepted)
	}

	insufficient := controller.Observe(externalV2BulkPacketControllerSample{
		At:               start.Add(2 * externalV2BulkPacketControllerInterval),
		PrimaryWireBytes: acceptedPrimary + 4<<20,
	})
	if insufficient.Reason != "insufficient-wire-sample" {
		t.Fatalf("insufficient decision = %#v", insufficient)
	}

	regressedPrimary := acceptedPrimary + 2<<20
	regressed := controller.Observe(externalV2BulkPacketControllerSample{
		At:               start.Add(3 * externalV2BulkPacketControllerInterval),
		PrimaryWireBytes: regressedPrimary,
	})
	if regressed.Reason != "counter-reset" {
		t.Fatalf("regressed decision = %#v, want counter-reset", regressed)
	}

	afterReset := controller.Observe(externalV2BulkPacketControllerSample{
		At:               start.Add(4 * externalV2BulkPacketControllerInterval),
		PrimaryWireBytes: regressedPrimary + 7<<20,
	})
	if afterReset.Reason != "insufficient-wire-sample" {
		t.Fatalf("after-reset decision = %#v, want fresh accumulation", afterReset)
	}
}

func TestExternalV2BulkPacketControllerClampsTargets(t *testing.T) {
	t.Parallel()

	start := time.Unix(225, 0)
	ceiling := newExternalV2BulkPacketController(externalV2BulkPacketDefaultInitialWireMbps)
	ceiling.targetMbps = externalV2BulkPacketCeilingWireMbps
	ceiling.Observe(externalV2BulkPacketControllerSample{
		At:           start,
		PeerProgress: true,
	})
	gotCeiling := ceiling.Observe(externalV2BulkPacketControllerSample{
		At:                    start.Add(500 * time.Millisecond),
		PrimaryWireBytes:      150_000_000,
		PeerBytes:             135_000_000,
		PeerTransferElapsedMS: 500,
		PeerProgress:          true,
	})
	if gotCeiling.TargetMbps != externalV2BulkPacketCeilingWireMbps ||
		gotCeiling.Action != "hold" ||
		gotCeiling.Reason != "ceiling" {
		t.Fatalf("ceiling decision = %#v", gotCeiling)
	}

	floor := newExternalV2BulkPacketController(externalV2BulkPacketDefaultInitialWireMbps)
	floor.targetMbps = externalV2BulkPacketMinimumWireMbps
	floor.Observe(externalV2BulkPacketControllerSample{At: start, PeerProgress: true})
	firstFloor := floor.Observe(externalV2BulkPacketControllerSample{
		At:                    start.Add(500 * time.Millisecond),
		PrimaryWireBytes:      9 << 20,
		RepairWireBytes:       1 << 20,
		PeerBytes:             1 << 20,
		PeerTransferElapsedMS: 500,
		PeerProgress:          true,
	})
	if firstFloor.TargetMbps != externalV2BulkPacketMinimumWireMbps ||
		firstFloor.Action != "hold" ||
		firstFloor.Reason != "repair-pressure-pending" {
		t.Fatalf("first minimum decision = %#v, want pending hold", firstFloor)
	}

	gotFloor := floor.Observe(externalV2BulkPacketControllerSample{
		At:                    start.Add(time.Second),
		PrimaryWireBytes:      18 << 20,
		RepairWireBytes:       2 << 20,
		PeerBytes:             2 << 20,
		PeerTransferElapsedMS: 1000,
		PeerProgress:          true,
	})
	if gotFloor.TargetMbps != externalV2BulkPacketMinimumWireMbps ||
		gotFloor.Action != "hold" ||
		gotFloor.Reason != "minimum" {
		t.Fatalf("minimum decision = %#v", gotFloor)
	}
}
