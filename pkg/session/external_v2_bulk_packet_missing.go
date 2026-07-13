// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"math"
	"sync/atomic"
	"time"
)

const (
	externalV2BulkPacketActiveRequestInterval    = 50 * time.Millisecond
	externalV2BulkPacketRateSampleInterval       = 100 * time.Millisecond
	externalV2BulkPacketReorderWindow            = 75 * time.Millisecond
	externalV2BulkPacketMinimumActiveRepairTrail = uint32(8192)
	externalV2BulkPacketMaximumActiveRepairTrail = uint32(16384)
	externalV2BulkPacketReceiveRateAlpha         = 0.25
)

// externalV2BulkPacketArrivalTracker records authenticated packets as soon as
// decryption finishes. Assembly and disk writes can lag behind the socket
// readers, so using only the assembled bitmap would mistake queued packets for
// loss and request needless repairs.
type externalV2BulkPacketArrivalTracker struct {
	total          uint32
	words          []atomic.Uint64
	claims         []atomic.Uint32
	highestArrival atomic.Uint32
	lastActivityNS atomic.Int64
	payload        atomic.Int64
}

func newExternalV2BulkPacketArrivalTracker(total uint32) *externalV2BulkPacketArrivalTracker {
	return &externalV2BulkPacketArrivalTracker{
		total:  total,
		words:  make([]atomic.Uint64, (uint64(total)+63)/64),
		claims: make([]atomic.Uint32, total),
	}
}

func (t *externalV2BulkPacketArrivalTracker) mark(index uint32) bool {
	if t == nil || index >= t.total {
		return false
	}
	mask := uint64(1) << (index % 64)
	if t.words[index/64].Or(mask)&mask != 0 {
		return false
	}
	externalV2BulkPacketAtomicMaxUint32(&t.highestArrival, index+1)
	return true
}

func (t *externalV2BulkPacketArrivalTracker) markData(header externalV2BulkPacketHeader) {
	if t == nil || header.total != t.total {
		return
	}
	if t.mark(header.index) {
		t.payload.Add(int64(header.length))
	}
	t.claims[header.index].Store(2)
}

func (t *externalV2BulkPacketArrivalTracker) tryClaim(index uint32) bool {
	if t == nil || index >= t.total || t.contains(index) {
		return false
	}
	return t.claims[index].CompareAndSwap(0, 1)
}

func (t *externalV2BulkPacketArrivalTracker) finishClaim(header externalV2BulkPacketHeader, authenticated bool) {
	if t == nil || header.total != t.total || header.index >= t.total {
		return
	}
	if !authenticated {
		t.claims[header.index].CompareAndSwap(1, 0)
		return
	}
	t.markData(header)
}

func (t *externalV2BulkPacketArrivalTracker) markGroupedFragment(header externalV2BulkPacketHeader) bool {
	if t == nil || header.total != t.total || header.index >= t.total {
		return false
	}
	return t.mark(header.index)
}

func (t *externalV2BulkPacketArrivalTracker) addAuthenticatedPayload(bytes int) {
	if t != nil && bytes > 0 {
		t.payload.Add(int64(bytes))
	}
}

func (t *externalV2BulkPacketArrivalTracker) contains(index uint32) bool {
	if t == nil || index >= t.total {
		return false
	}
	return t.words[index/64].Load()&(uint64(1)<<(index%64)) != 0
}

func (t *externalV2BulkPacketArrivalTracker) highestPlusOne() uint32 {
	if t == nil {
		return 0
	}
	return t.highestArrival.Load()
}

func (t *externalV2BulkPacketArrivalTracker) observeActivity(at time.Time) {
	if t != nil && !at.IsZero() {
		t.lastActivityNS.Store(at.UnixNano())
	}
}

func (t *externalV2BulkPacketArrivalTracker) lastActivity() time.Time {
	if t == nil {
		return time.Time{}
	}
	nanos := t.lastActivityNS.Load()
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos)
}

func (t *externalV2BulkPacketArrivalTracker) payloadBytes() int64 {
	if t == nil {
		return 0
	}
	return t.payload.Load()
}

type externalV2BulkPacketReceiveRate struct {
	sampleStarted time.Time
	samplePackets uint32
	ewmaPPS       float64
	trail         uint32
}

func (r *externalV2BulkPacketReceiveRate) observe(at time.Time) {
	r.observeN(at, 1)
}

func (r *externalV2BulkPacketReceiveRate) observeN(at time.Time, packets uint32) {
	if at.IsZero() || packets == 0 {
		return
	}
	if r.sampleStarted.IsZero() {
		r.sampleStarted = at
	}
	r.samplePackets += packets
	elapsed := at.Sub(r.sampleStarted)
	if elapsed < externalV2BulkPacketRateSampleInterval {
		return
	}
	r.update(r.samplePackets, elapsed)
	r.sampleStarted = at
	r.samplePackets = 0
}

func (r *externalV2BulkPacketReceiveRate) update(packets uint32, elapsed time.Duration) {
	if packets == 0 || elapsed <= 0 {
		return
	}
	pps := float64(packets) / elapsed.Seconds()
	if r.ewmaPPS == 0 {
		r.ewmaPPS = pps
	} else {
		r.ewmaPPS = externalV2BulkPacketReceiveRateAlpha*pps + (1-externalV2BulkPacketReceiveRateAlpha)*r.ewmaPPS
	}
	candidate := uint32(min(float64(externalV2BulkPacketMaximumActiveRepairTrail), max(
		float64(externalV2BulkPacketMinimumActiveRepairTrail),
		math.Ceil(r.ewmaPPS*externalV2BulkPacketReorderWindow.Seconds()),
	)))
	if r.trail > 0 && candidate < r.trail {
		maximumDrop := max(uint32(1024), r.trail/8)
		candidate = max(candidate, r.trail-maximumDrop)
	}
	r.trail = candidate
}

func (r *externalV2BulkPacketReceiveRate) trailPackets() uint32 {
	if r.trail < externalV2BulkPacketMinimumActiveRepairTrail {
		return externalV2BulkPacketMinimumActiveRepairTrail
	}
	return min(r.trail, externalV2BulkPacketMaximumActiveRepairTrail)
}

func (r *externalV2BulkPacketReceiveRate) packetsPerSecond() uint32 {
	if r.ewmaPPS <= 0 {
		return 0
	}
	return uint32(min(r.ewmaPPS, float64(^uint32(0))))
}

type externalV2BulkPacketMissingStats struct {
	ScanChecks       uint64
	Pending          uint32
	PendingPeak      uint32
	RequestedPackets uint64
	RequestBatches   uint64
}

type externalV2BulkPacketMissingTracker struct {
	scanCursor       uint32
	pending          []uint32
	pendingFlags     []bool
	pendingCount     uint32
	lastRequestAt    time.Time
	scanChecks       uint64
	pendingPeak      uint32
	requestedPackets uint64
	requestBatches   uint64
	arrivals         *externalV2BulkPacketArrivalTracker
}

func newExternalV2BulkPacketMissingTracker(total uint32, arrivals ...*externalV2BulkPacketArrivalTracker) *externalV2BulkPacketMissingTracker {
	tracker := &externalV2BulkPacketMissingTracker{
		pendingFlags: make([]bool, total),
	}
	if len(arrivals) > 0 {
		tracker.arrivals = arrivals[0]
	}
	return tracker
}

func (t *externalV2BulkPacketMissingTracker) advance(seen []bool, limit uint32) {
	if t == nil {
		return
	}
	limit = min(limit, uint32(len(seen)), uint32(len(t.pendingFlags)))
	if limit <= t.scanCursor {
		return
	}
	for index := t.scanCursor; index < limit; index++ {
		t.scanChecks++
		if t.present(seen, index) || t.pendingFlags[index] {
			continue
		}
		t.pendingFlags[index] = true
		t.pending = append(t.pending, index)
		t.pendingCount++
	}
	t.scanCursor = limit
	t.pendingPeak = max(t.pendingPeak, t.pendingCount)
}

func (t *externalV2BulkPacketMissingTracker) resolve(index uint32) {
	if t == nil || index >= uint32(len(t.pendingFlags)) {
		return
	}
	if t.pendingFlags[index] {
		t.pendingFlags[index] = false
		t.pendingCount--
	}
}

func (t *externalV2BulkPacketMissingTracker) batches(seen []bool, at time.Time, force bool) [][]uint32 {
	if t == nil {
		return nil
	}
	if !force && !t.lastRequestAt.IsZero() && at.Sub(t.lastRequestAt) < externalV2BulkPacketActiveRequestInterval {
		return nil
	}
	t.compact(seen)
	if len(t.pending) == 0 {
		return nil
	}
	t.lastRequestAt = at
	batches := make([][]uint32, 0, (len(t.pending)+externalV2BulkPacketMaxMissing-1)/externalV2BulkPacketMaxMissing)
	for start := 0; start < len(t.pending); start += externalV2BulkPacketMaxMissing {
		end := min(start+externalV2BulkPacketMaxMissing, len(t.pending))
		batches = append(batches, append([]uint32(nil), t.pending[start:end]...))
	}
	t.requestedPackets += uint64(len(t.pending))
	t.requestBatches += uint64(len(batches))
	return batches
}

func (t *externalV2BulkPacketMissingTracker) compact(seen []bool) {
	kept := t.pending[:0]
	for _, index := range t.pending {
		if !t.pendingFlags[index] {
			continue
		}
		if index >= uint32(len(seen)) && !t.arrivals.contains(index) {
			kept = append(kept, index)
			continue
		}
		if t.present(seen, index) {
			t.pendingFlags[index] = false
			t.pendingCount--
			continue
		}
		kept = append(kept, index)
	}
	t.pending = kept
}

func (t *externalV2BulkPacketMissingTracker) present(seen []bool, index uint32) bool {
	return (index < uint32(len(seen)) && seen[index]) || t.arrivals.contains(index)
}

func (t *externalV2BulkPacketMissingTracker) stats() externalV2BulkPacketMissingStats {
	if t == nil {
		return externalV2BulkPacketMissingStats{}
	}
	return externalV2BulkPacketMissingStats{
		ScanChecks:       t.scanChecks,
		Pending:          t.pendingCount,
		PendingPeak:      t.pendingPeak,
		RequestedPackets: t.requestedPackets,
		RequestBatches:   t.requestBatches,
	}
}
