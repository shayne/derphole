// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"testing"
	"time"
)

func TestExternalV2BulkPacketReceiveRateUsesTimeBasedTrail(t *testing.T) {
	tests := []struct {
		name string
		pps  uint32
		want uint32
	}{
		{name: "500 Mbps class", pps: 44_000, want: 8_192},
		{name: "1 Gbps class", pps: 88_000, want: 8_192},
		{name: "2.4 Gbps ceiling", pps: 210_000, want: 15_750},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rate externalV2BulkPacketReceiveRate
			rate.update(tt.pps, time.Second)
			if got := rate.trailPackets(); got != tt.want {
				t.Fatalf("trail packets = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestExternalV2BulkPacketActiveRepairTrailFitsInsideDirectWindow(t *testing.T) {
	trailBytes := int64(externalV2BulkPacketMaximumActiveRepairTrail) * externalV2BulkPacketPayloadSize
	if trailBytes >= externalV2BulkPacketDirectReceiveWindow {
		t.Fatalf("maximum repair trail = %d bytes, must fit inside direct receive window %d", trailBytes, externalV2BulkPacketDirectReceiveWindow)
	}
}

func TestExternalV2BulkPacketReceiveRateUsesMinimumBeforeSample(t *testing.T) {
	var rate externalV2BulkPacketReceiveRate
	if got := rate.trailPackets(); got != externalV2BulkPacketMinimumActiveRepairTrail {
		t.Fatalf("initial trail = %d", got)
	}
}

func TestExternalV2BulkPacketReceiveRateBoundsDecrease(t *testing.T) {
	var rate externalV2BulkPacketReceiveRate
	rate.update(210_000, time.Second)
	before := rate.trailPackets()
	rate.update(1_000, time.Second)
	after := rate.trailPackets()
	maximumDrop := max(uint32(1024), before/8)
	if before-after > maximumDrop {
		t.Fatalf("trail dropped from %d to %d, maximum drop %d", before, after, maximumDrop)
	}
}

func TestExternalV2BulkPacketReceiveRateClampsCeiling(t *testing.T) {
	var rate externalV2BulkPacketReceiveRate
	rate.update(^uint32(0), time.Nanosecond)
	if got := rate.trailPackets(); got != externalV2BulkPacketMaximumActiveRepairTrail {
		t.Fatalf("ceiling trail = %d", got)
	}
}

func TestExternalV2BulkPacketReceiveRateObservesElapsedArrivalTime(t *testing.T) {
	var rate externalV2BulkPacketReceiveRate
	started := time.Unix(60, 0)
	rate.observe(time.Time{})
	rate.observe(started)
	rate.observe(started.Add(50 * time.Millisecond))
	if got := rate.packetsPerSecond(); got != 0 {
		t.Fatalf("early packets per second = %d, want 0", got)
	}
	rate.observe(started.Add(100 * time.Millisecond))
	if got := rate.packetsPerSecond(); got != 30 {
		t.Fatalf("packets per second = %d, want 30", got)
	}
}

func TestExternalV2BulkPacketReceiveRateObserveNMatchesIndividualPackets(t *testing.T) {
	started := time.Unix(70, 0)
	var individual, batched externalV2BulkPacketReceiveRate
	individual.observe(started)
	individual.observe(started.Add(50 * time.Millisecond))
	individual.observe(started.Add(100 * time.Millisecond))
	batched.observeN(started, 1)
	batched.observeN(started.Add(50*time.Millisecond), 1)
	batched.observeN(started.Add(100*time.Millisecond), 1)
	if individual.packetsPerSecond() != batched.packetsPerSecond() || individual.trailPackets() != batched.trailPackets() {
		t.Fatalf("individual pps/trail=%d/%d batch=%d/%d", individual.packetsPerSecond(), individual.trailPackets(), batched.packetsPerSecond(), batched.trailPackets())
	}
}

func TestExternalV2BulkPacketMissingTrackerScansEachIndexOnce(t *testing.T) {
	seen := []bool{true, false, true, true, false, true, true, true}
	tracker := newExternalV2BulkPacketMissingTracker(uint32(len(seen)))

	tracker.advance(seen, 5)
	tracker.advance(seen, 8)
	tracker.advance(seen, 8)

	got := tracker.stats()
	if got.ScanChecks != 8 {
		t.Fatalf("scan checks = %d, want 8", got.ScanChecks)
	}
	if got.Pending != 2 || got.PendingPeak != 2 {
		t.Fatalf("pending stats = %#v, want two gaps", got)
	}
}

func TestExternalV2BulkPacketMissingTrackerResolvesLateOriginal(t *testing.T) {
	seen := []bool{true, false, true}
	tracker := newExternalV2BulkPacketMissingTracker(3)
	tracker.advance(seen, 3)

	seen[1] = true
	tracker.resolve(1)
	if tracker.stats().Pending != 0 {
		t.Fatalf("pending before compaction = %d, want 0", tracker.stats().Pending)
	}
	batches := tracker.batches(seen, time.Unix(10, 0), true)
	if len(batches) != 0 {
		t.Fatalf("batches = %v, want no repair for late original", batches)
	}
	if tracker.stats().Pending != 0 {
		t.Fatalf("pending = %d, want 0", tracker.stats().Pending)
	}
}

func TestExternalV2BulkPacketMissingTrackerIgnoresAuthenticatedArrivalsWaitingForAssembly(t *testing.T) {
	seen := []bool{false, false, false}
	arrivals := newExternalV2BulkPacketArrivalTracker(uint32(len(seen)))
	arrivals.mark(1)
	tracker := newExternalV2BulkPacketMissingTracker(uint32(len(seen)), arrivals)

	tracker.advance(seen, uint32(len(seen)))
	got := tracker.batches(seen, time.Unix(15, 0), true)
	if len(got) != 1 || len(got[0]) != 2 || got[0][0] != 0 || got[0][1] != 2 {
		t.Fatalf("repair batches = %v, want only packets not seen or waiting for assembly", got)
	}
	if arrivals.highestPlusOne() != 2 {
		t.Fatalf("highest authenticated arrival = %d, want 2", arrivals.highestPlusOne())
	}
}

func TestExternalV2BulkPacketArrivalCreditCountsUniqueAuthenticatedPayload(t *testing.T) {
	arrivals := newExternalV2BulkPacketArrivalTracker(3)
	arrivals.markData(externalV2BulkPacketHeader{index: 2, total: 3, length: 100})
	arrivals.markData(externalV2BulkPacketHeader{index: 2, total: 3, length: 100})
	arrivals.markData(externalV2BulkPacketHeader{index: 0, total: 3, length: 200})
	arrivals.markData(externalV2BulkPacketHeader{index: 1, total: 4, length: 250})

	if got := arrivals.payloadBytes(); got != 300 {
		t.Fatalf("authenticated arrival credit = %d, want 300 unique bytes", got)
	}
}

func TestExternalV2BulkPacketArrivalTrackerSerializesDirectDecryptClaims(t *testing.T) {
	tracker := newExternalV2BulkPacketArrivalTracker(2)
	if !tracker.tryClaim(1) {
		t.Fatal("first direct decrypt claim was rejected")
	}
	if tracker.tryClaim(1) {
		t.Fatal("concurrent direct decrypt claim was accepted")
	}
	tracker.finishClaim(externalV2BulkPacketHeader{index: 1, total: 2, length: 17}, false)
	if !tracker.tryClaim(1) {
		t.Fatal("failed authentication did not release direct decrypt claim")
	}
	tracker.finishClaim(externalV2BulkPacketHeader{index: 1, total: 2, length: 17}, true)
	if !tracker.contains(1) || tracker.payloadBytes() != 17 {
		t.Fatalf("successful claim was not recorded: present=%t payload=%d", tracker.contains(1), tracker.payloadBytes())
	}
	if tracker.tryClaim(1) {
		t.Fatal("authenticated packet accepted another direct decrypt claim")
	}
}

func TestExternalV2BulkPacketMissingTrackerPreservesActiveRepairCadenceAndBatchLimit(t *testing.T) {
	seen := make([]bool, 605)
	tracker := newExternalV2BulkPacketMissingTracker(uint32(len(seen)))
	tracker.advance(seen, uint32(len(seen)))
	start := time.Unix(20, 0)

	first := tracker.batches(seen, start, false)
	if len(first) != 3 || len(first[0]) != 300 || len(first[1]) != 300 || len(first[2]) != 5 {
		t.Fatalf("first batches = lens %v, want 300,300,5", externalV2BulkPacketBatchLengths(first))
	}
	if got := tracker.batches(seen, start.Add(externalV2BulkPacketActiveRequestInterval-time.Millisecond), false); len(got) != 0 {
		t.Fatalf("early repeat batches = %v, want none", got)
	}
	if got := tracker.batches(seen, start.Add(externalV2BulkPacketActiveRequestInterval), false); len(got) != 3 {
		t.Fatalf("due repeat batch count = %d, want 3", len(got))
	}
	stats := tracker.stats()
	if stats.RequestedPackets != 1210 || stats.RequestBatches != 6 {
		t.Fatalf("request stats = %#v", stats)
	}
}

func TestExternalV2BulkPacketMissingTrackerForceBypassesCadence(t *testing.T) {
	seen := []bool{false}
	tracker := newExternalV2BulkPacketMissingTracker(1)
	tracker.advance(seen, 1)
	start := time.Unix(30, 0)
	_ = tracker.batches(seen, start, false)
	if got := tracker.batches(seen, start.Add(time.Millisecond), true); len(got) != 1 {
		t.Fatalf("forced batches = %v, want immediate retry", got)
	}
}

func TestExternalV2BulkPacketMissingTrackerDefersCompactionUntilDueOrForced(t *testing.T) {
	for _, test := range []struct {
		name  string
		force bool
		at    time.Duration
	}{
		{name: "due", at: externalV2BulkPacketActiveRequestInterval},
		{name: "forced", force: true, at: time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			seen := []bool{false, false}
			tracker := newExternalV2BulkPacketMissingTracker(2)
			tracker.advance(seen, 2)
			start := time.Unix(40, 0)
			_ = tracker.batches(seen, start, false)
			tracker.resolve(0)

			for _, early := range []time.Duration{time.Millisecond, 2 * time.Millisecond} {
				if got := tracker.batches(seen, start.Add(early), false); len(got) != 0 {
					t.Fatalf("early batches = %v, want none", got)
				}
				if got := len(tracker.pending); got != 2 {
					t.Fatalf("pending entries after suppressed call = %d, want deferred compaction", got)
				}
			}

			got := tracker.batches(seen, start.Add(test.at), test.force)
			if len(got) != 1 || len(got[0]) != 1 || got[0][0] != 1 {
				t.Fatalf("due batches = %v, want [[1]]", got)
			}
			if got := len(tracker.pending); got != 1 {
				t.Fatalf("pending entries after request = %d, want compacted entry", got)
			}
		})
	}
}

func TestExternalV2BulkPacketMissingTrackerPreservesPendingOutsideShortSeenSlice(t *testing.T) {
	seen := []bool{false, false, false}
	tracker := newExternalV2BulkPacketMissingTracker(3)
	tracker.advance(seen, 3)
	tracker.resolve(1)

	_ = tracker.batches(seen[:1], time.Unix(50, 0), true)
	if got := tracker.stats().Pending; got != 2 {
		t.Fatalf("pending count = %d, want 2", got)
	}
	if len(tracker.pending) != 2 || tracker.pending[0] != 0 || tracker.pending[1] != 2 {
		t.Fatalf("pending entries = %v, want [0 2]", tracker.pending)
	}
	if !tracker.pendingFlags[0] || tracker.pendingFlags[1] || !tracker.pendingFlags[2] {
		t.Fatalf("pending flags = %v, want [true false true]", tracker.pendingFlags)
	}

	got := tracker.batches(seen, time.Unix(50, 0), true)
	if len(got) != 1 || len(got[0]) != 2 || got[0][0] != 0 || got[0][1] != 2 {
		t.Fatalf("full-slice batches = %v, want [[0 2]]", got)
	}
}

func externalV2BulkPacketBatchLengths(batches [][]uint32) []int {
	lengths := make([]int, len(batches))
	for i := range batches {
		lengths[i] = len(batches[i])
	}
	return lengths
}
