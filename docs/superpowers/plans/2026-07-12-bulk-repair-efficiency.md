# Bulk Repair Efficiency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace quadratic bulk-packet repair scanning with incremental, time-aware gap tracking, prove lower wire and CPU cost without throughput regression, then land and publish the verified result.

**Architecture:** A receiver-owned tracker scans each newly mature packet index once, keeps only unresolved gaps, and requests them at a bounded cadence. A smoothed packet-rate estimator converts a 250 ms reorder allowance into packets so policy stays stable across link speeds. Existing wire frames remain unchanged; new trace fields and a cross-platform `runstats` wrapper make scan, CPU, and RSS efficiency machine-checkable for both baseline and candidate binaries.

**Tech Stack:** Go 1.26.5, UDP packet transport, `golang.org/x/time/rate`, CSV transfer traces, Bash benchmark drivers, GitButler, TCP iperf3 on port 8123.

## Global Constraints

- Normal file `send`/`receive` is the benchmark workload; `pipe` cannot substitute for it.
- Public-WAN tests set `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` on both peers and prove selected addresses are public. Only pve1 may use its exact validated LAN endpoints.
- The production initial bulk target remains 1,000 Mbps and accepted runs leave every test-only rate override unset.
- Do not change candidate discovery, production Tailscale behavior, receiver-aware mode selection, or intentional `blocks-v1` negotiation.
- No packet or control-frame format changes are allowed. Old/new sender and receiver combinations must remain compatible.
- Focused acceptance requires repair ratio below 10 percent, receiver CPU seconds per GiB at least 10 percent lower, scan checks per packet below 2.0, and no more than 3 percent median canonical or wall-goodput regression.
- Integrity, route, trace, payload-flatline, process, socket, resource-stat, and cleanup failures reject a sample. Only one canonical-CV-only rerun is allowed per fleet cell.
- Do not commit generated `dist/` or `.tmp/` contents.
- Use `mise` for tool execution, `apply_patch` for edits, and GitButler for every normal version-control write.
- Before implementation, use `superpowers:using-git-worktrees` to confirm the GitButler workspace is the intended isolation boundary.
- Every production change begins with a failing test and receives a fresh independent review before the next task.

---

## File Map

- Create `pkg/session/external_v2_bulk_packet_missing.go`: missing tracker and receive-rate estimator only.
- Create `pkg/session/external_v2_bulk_packet_missing_test.go`: tracker complexity, cadence, rate, overflow, and reorder tests.
- Modify `pkg/session/external_v2_bulk_packet.go`: wire the tracker into the receiver and delete full-prefix active scanning.
- Modify `pkg/session/external_v2_bulk_packet_test.go`: receiver integration, loss, reorder, compatibility, and cleanup tests.
- Modify `pkg/session/external_transfer_metrics.go`: carry new receiver repair diagnostics into snapshots.
- Modify `pkg/session/external_transfer_metrics_test.go`: current and healthy-zero diagnostic propagation.
- Modify `pkg/transfertrace/trace.go` and `trace_test.go`: append trace columns without breaking legacy CSVs.
- Modify `pkg/transfertrace/checker.go` and `checker_test.go`: summarize cumulative scan and pending-gap health.
- Modify `tools/transfertracecheck/main.go` and `main_test.go`: print machine-readable receiver repair summaries.
- Create `tools/runstats/main.go`, `main_test.go`, `resource_unix.go`, and `resource_other.go`: wrap a child process and atomically record CPU/RSS JSON.
- Modify `scripts/promotion-benchmark-driver.sh`: use `runstats`, accept explicit baseline/candidate binaries, preserve resource JSON, and emit resource footers.
- Modify `scripts/public-path-performance-harness.sh`: add revision, CPU/RSS, normalized CPU, and new repair columns to `summary.csv`.
- Modify `scripts/promotion_scripts_test.go`: enforce binary override, resource binding, healthy-zero, and CSV contracts.
- Modify `docs/benchmarks.md`: document repair tracker semantics, resource fields, focused A/B, and fleet gates.

---

### Task 1: Build the incremental missing tracker

**Files:**
- Create: `pkg/session/external_v2_bulk_packet_missing.go`
- Create: `pkg/session/external_v2_bulk_packet_missing_test.go`

**Interfaces:**
- Consumes: `seen []bool`, an exclusive packet-index limit, current time, and the existing 300-index missing-frame limit.
- Produces: `newExternalV2BulkPacketMissingTracker(total uint32)`, `advance(seen []bool, limit uint32)`, `resolve(index uint32)`, `batches(seen []bool, at time.Time, force bool) [][]uint32`, and `stats() externalV2BulkPacketMissingStats`.

- [ ] **Step 1: Write failing tracker tests**

Create tests with these exact behaviors:

```go
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

func TestExternalV2BulkPacketMissingTrackerCadenceAndBatchLimit(t *testing.T) {
	seen := make([]bool, 605)
	tracker := newExternalV2BulkPacketMissingTracker(uint32(len(seen)))
	tracker.advance(seen, uint32(len(seen)))
	start := time.Unix(20, 0)

	first := tracker.batches(seen, start, false)
	if len(first) != 3 || len(first[0]) != 300 || len(first[1]) != 300 || len(first[2]) != 5 {
		t.Fatalf("first batches = lens %v, want 300,300,5", externalV2BulkPacketBatchLengths(first))
	}
	if got := tracker.batches(seen, start.Add(249*time.Millisecond), false); len(got) != 0 {
		t.Fatalf("early repeat batches = %v, want none", got)
	}
	if got := tracker.batches(seen, start.Add(250*time.Millisecond), false); len(got) != 3 {
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
```

Add this test helper in the same `_test.go` file:

```go
func externalV2BulkPacketBatchLengths(batches [][]uint32) []int {
	lengths := make([]int, len(batches))
	for i := range batches {
		lengths[i] = len(batches[i])
	}
	return lengths
}
```

- [ ] **Step 2: Run the tests and confirm red**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacketMissingTracker' -count=1
```

Expected: FAIL because `newExternalV2BulkPacketMissingTracker` and its types do not exist.

- [ ] **Step 3: Implement the minimal tracker**

Create `external_v2_bulk_packet_missing.go` with this contract:

```go
package session

import "time"

const externalV2BulkPacketActiveRequestInterval = 250 * time.Millisecond

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
}

func newExternalV2BulkPacketMissingTracker(total uint32) *externalV2BulkPacketMissingTracker {
	return &externalV2BulkPacketMissingTracker{
		pendingFlags: make([]bool, total),
	}
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
		if seen[index] || t.pendingFlags[index] {
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
	kept := t.pending[:0]
	for _, index := range t.pending {
		if index >= uint32(len(seen)) || !t.pendingFlags[index] {
			continue
		}
		if seen[index] {
			t.pendingFlags[index] = false
			t.pendingCount--
			continue
		}
		kept = append(kept, index)
	}
	t.pending = kept
	if len(t.pending) == 0 {
		return nil
	}
	if !force && !t.lastRequestAt.IsZero() && at.Sub(t.lastRequestAt) < externalV2BulkPacketActiveRequestInterval {
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
```

- [ ] **Step 4: Run focused and package tests**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacketMissingTracker' -count=1
mise exec -- go test ./pkg/session -count=1
```

Expected: PASS. Confirm the 605-index test reports no allocation or loop error under `go test -race` in Task 3.

- [ ] **Step 5: Review and commit**

Run a fresh read-only task review against this plan section. Fix every Critical or Important finding, rerun the focused tests, then:

```bash
but diff
but commit codex/bulk-repair-efficiency -m "session: add incremental missing tracker"
```

Expected: one checkpoint containing only tracker code and tests.

---

### Task 2: Add the time-based reorder estimator

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet_missing.go`
- Modify: `pkg/session/external_v2_bulk_packet_missing_test.go`

**Interfaces:**
- Consumes: validated first-seen packet arrival timestamps.
- Produces: `externalV2BulkPacketReceiveRate.observe(time.Time)`, `update(uint32, time.Duration)`, `trailPackets() uint32`, and `packetsPerSecond() uint32`.

- [ ] **Step 1: Write failing estimator tests**

```go
func TestExternalV2BulkPacketReceiveRateUsesTimeBasedTrail(t *testing.T) {
	tests := []struct {
		name string
		pps  uint32
		want uint32
	}{
		{name: "500 Mbps class", pps: 44_000, want: 11_000},
		{name: "1 Gbps class", pps: 88_000, want: 22_000},
		{name: "2.4 Gbps ceiling", pps: 210_000, want: 52_500},
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
```

- [ ] **Step 2: Confirm red**

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacketReceiveRate' -count=1
```

Expected: FAIL because the estimator is undefined.

- [ ] **Step 3: Implement the estimator**

Add these constants and type to `external_v2_bulk_packet_missing.go`:

```go
const (
	externalV2BulkPacketRateSampleInterval       = 100 * time.Millisecond
	externalV2BulkPacketReorderWindow            = 250 * time.Millisecond
	externalV2BulkPacketMinimumActiveRepairTrail = uint32(8192)
	externalV2BulkPacketMaximumActiveRepairTrail = uint32(65536)
	externalV2BulkPacketReceiveRateAlpha          = 0.25
)

type externalV2BulkPacketReceiveRate struct {
	sampleStarted time.Time
	samplePackets uint32
	ewmaPPS       float64
	trail         uint32
}

func (r *externalV2BulkPacketReceiveRate) observe(at time.Time) {
	if at.IsZero() {
		return
	}
	if r.sampleStarted.IsZero() {
		r.sampleStarted = at
	}
	r.samplePackets++
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
```

Add `math` to the file imports. Do not add environment variables or production knobs.

- [ ] **Step 4: Run tests**

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(ReceiveRate|MissingTracker)' -count=1
```

Expected: PASS. If the exact EWMA makes the first-sample tests differ, fix the implementation rather than weakening the time-equivalence assertions.

- [ ] **Step 5: Review and commit**

After independent review and fixes:

```bash
but diff
but commit codex/bulk-repair-efficiency -m "session: make repair reorder window time-based"
```

---

### Task 3: Integrate the tracker into bulk receive

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet.go`
- Modify: `pkg/session/external_v2_bulk_packet_test.go`
- Modify: `pkg/session/external_v2_bulk_packet_missing.go`

**Interfaces:**
- Consumes: Task 1 tracker and Task 2 receive-rate estimator.
- Produces: incremental active/idle repair behavior and removal of `externalV2BulkPacketMissingBatches` plus fixed `lastActiveRepair` scanning. Task 4 exposes the already-available tracker state through receiver stats.

- [ ] **Step 1: Write failing receiver behavior tests**

Add tests which construct a receiver with `seen`, tracker, and rate state directly:

```go
func TestExternalV2BulkPacketActiveRepairDoesNotRescanHistory(t *testing.T) {
	receiver := newExternalV2BulkPacketReceiver(nil, externalV2BlockReceiveConfig{PayloadSize: 100_000 * externalV2BulkPacketPayloadSize}, externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, nil)
	receiver.runID = 1
	receiver.highestSeenPlusOne = 80_000
	for i := range 80_000 {
		receiver.seen[i] = true
	}
	receiver.seen[10] = false
	receiver.receiveRate.update(88_000, time.Second)
	start := time.Unix(50, 0)

	receiver.sendActiveMissing(start)
	first := receiver.missing.stats().ScanChecks
	receiver.sendActiveMissing(start.Add(externalV2BulkPacketActiveRequestInterval))
	second := receiver.missing.stats().ScanChecks
	if first == 0 || second != first {
		t.Fatalf("scan checks first=%d second=%d, want no historical rescan", first, second)
	}
}

func TestExternalV2BulkPacketActiveRepairKeepsRecentReorder(t *testing.T) {
	receiver := newExternalV2BulkPacketReceiver(nil, externalV2BlockReceiveConfig{PayloadSize: 100_000 * externalV2BulkPacketPayloadSize}, externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, nil)
	receiver.runID = 1
	receiver.highestSeenPlusOne = 50_000
	receiver.receiveRate.update(88_000, time.Second)
	receiver.seen[49_000] = false
	receiver.sendActiveMissing(time.Unix(60, 0))
	if receiver.repairRequests != 0 {
		t.Fatalf("repair requests = %d, want recent gap inside reorder window", receiver.repairRequests)
	}
}

func TestExternalV2BulkPacketIdleRepairForcesTailGap(t *testing.T) {
	receiver := newExternalV2BulkPacketReceiver(nil, externalV2BlockReceiveConfig{PayloadSize: 20 * externalV2BulkPacketPayloadSize}, externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, nil)
	receiver.runID = 1
	receiver.highestSeenPlusOne = 20
	for i := range 20 {
		receiver.seen[i] = true
	}
	receiver.seen[19] = false
	receiver.sendIdleMissing(time.Unix(70, 0))
	if receiver.repairRequests != 1 {
		t.Fatalf("repair requests = %d, want immediate idle request", receiver.repairRequests)
	}
}
```

Adjust the constructor test inputs with a non-nil test sink if constructor validation or assembler allocation requires it. Do not bypass production constructor state.

- [ ] **Step 2: Confirm red**

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(ActiveRepair|IdleRepair)' -count=1
```

Expected: FAIL because the receiver does not expose tracker/rate state and idle repair lacks a timestamp.

- [ ] **Step 3: Wire tracker and estimator**

Change the receiver fields to:

```go
type externalV2BulkPacketReceiver struct {
	cfg                externalV2BlockReceiveConfig
	path               externalV2BulkPacketPath
	auth               externalV2BulkPacketAuth
	metrics            *externalTransferMetrics
	laneCount          int
	totalPackets       uint32
	seen               []bool
	missing            *externalV2BulkPacketMissingTracker
	receiveRate        externalV2BulkPacketReceiveRate
	assembler          *externalV2BulkPacketReceiveAssembler
	runID              uint64
	receivedPackets    uint32
	highestSeenPlusOne uint32
	committedPayload   int64
	repairRequests     int64
	controlSeq         uint32
	stopHello          func()
}
```

Initialize `missing` in `newExternalV2BulkPacketReceiver`:

```go
		missing:      newExternalV2BulkPacketMissingTracker(totalPackets),
```

In `handleDataResult`, use one timestamp and update tracker state only for a validated first-seen packet:

```go
	now := time.Now()
	r.missing.resolve(header.index)
	r.seen[header.index] = true
	r.receivedPackets++
	r.receiveRate.observe(now)
	r.sendActiveMissing(now)
```

Replace active and idle missing functions with:

```go
func (r *externalV2BulkPacketReceiver) sendActiveMissing(now time.Time) {
	trail := r.receiveRate.trailPackets()
	if r.highestSeenPlusOne <= trail {
		return
	}
	r.missing.advance(r.seen, r.highestSeenPlusOne-trail)
	r.sendMissingBatches(r.missing.batches(r.seen, now, false))
}

func (r *externalV2BulkPacketReceiver) sendIdleMissing(now time.Time) {
	limit := r.totalPackets
	if remaining := r.totalPackets - r.highestSeenPlusOne; remaining > externalV2BulkPacketMissingLookahead {
		limit = r.highestSeenPlusOne + externalV2BulkPacketMissingLookahead
	}
	r.missing.advance(r.seen, limit)
	r.sendMissingBatches(r.missing.batches(r.seen, now, true))
}

func (r *externalV2BulkPacketReceiver) sendMissingBatches(batches [][]uint32) {
	for _, missing := range batches {
		if len(missing) > 0 {
			r.sendMissingBatch(missing)
		}
	}
}
```

Pass `time.Now()` from the idle timer case. Delete `externalV2BulkPacketMissingBatches`, the fixed `externalV2BulkPacketActiveRepairTrail`, and the old full-prefix `sendMissing` helper after `rg` confirms there are no callers.

- [ ] **Step 4: Run integration and race tests**

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket' -count=1
mise exec -- go test -race ./pkg/session -run 'TestExternalV2BulkPacket' -count=1
```

Expected: PASS, exact payloads preserved, no race report, and old cancellation/deadline tests unchanged.

- [ ] **Step 5: Review and commit**

Keep the existing `externalV2BulkPacketReceiveStats` signature in this checkpoint. Task 4 changes it when the diagnostics destination exists. After independent review, commit:

```bash
but diff
but commit codex/bulk-repair-efficiency -m "session: track missing packets incrementally"
```

---

### Task 4: Carry repair-efficiency telemetry through traces

**Files:**
- Modify: `pkg/session/external_transfer_metrics.go`
- Modify: `pkg/session/external_transfer_metrics_test.go`
- Modify: `pkg/transfertrace/trace.go`
- Modify: `pkg/transfertrace/trace_test.go`
- Modify: `pkg/transfertrace/checker.go`
- Modify: `pkg/transfertrace/checker_test.go`
- Modify: `tools/transfertracecheck/main.go`
- Modify: `tools/transfertracecheck/main_test.go`
- Modify: `pkg/session/external_v2_bulk_packet.go`

**Interfaces:**
- Consumes: Task 3 receiver repair stats.
- Produces: optional trailing CSV columns and checker keys `missing_scan_checks`, `pending_missing`, `pending_missing_peak`, `repair_requested_packets`, `repair_request_batches`, `reorder_trail_packets`, and `receive_packet_rate_pps`.

- [ ] **Step 1: Write failing trace and checker tests**

Add a current-schema receiver row with all seven fields and assert exact summary values. Add a legacy row without them and assert no parse error. Add a CLI test expecting:

```text
missing_scan_checks=790545 pending_missing=0 pending_missing_peak=1234 repair_requested_packets=4567 repair_request_batches=32 reorder_trail_packets=22000 receive_packet_rate_pps=88000
```

Use healthy zero values in a second current-schema fixture and assert they are observed rather than treated as absent.

- [ ] **Step 2: Confirm red**

```bash
mise exec -- go test ./pkg/transfertrace ./tools/transfertracecheck ./pkg/session -run 'RepairEfficiency|MissingScan|PendingMissing' -count=1
```

Expected: FAIL on missing fields and output.

- [ ] **Step 3: Add exact diagnostics fields**

Add these fields to `externalDirectTransferDiagnostics`, `externalTransferMetrics`, `transfertrace.Snapshot`, checker row diagnostics, and `DiagnosticsSummary` using the same names and widths:

```go
	MissingScanChecks       uint64
	PendingMissing          uint32
	PendingMissingPeak      uint32
	RepairRequestedPackets  uint64
	RepairRequestBatches    uint64
	ReorderTrailPackets     uint32
	ReceivePacketRatePPS    uint32
```

Append, never insert, these header names to `transfertrace.header`:

```go
	"missing_scan_checks",
	"pending_missing",
	"pending_missing_peak",
	"repair_requested_packets",
	"repair_request_batches",
	"reorder_trail_packets",
	"receive_packet_rate_pps",
```

Use decimal strings for every current-schema value, including zero. Add all seven names to `isOptionalTrailingDiagnosticColumn` so prior traces remain readable.

In metrics, cumulative fields take maxima except `PendingMissing`, which takes the latest value. `PendingMissingPeak`, trail, and PPS take maxima for summary purposes. Set the receiver stats fields from Task 3 exactly once at completion.

Change the receiver result call to:

```go
	repairStats := r.missing.stats()
	return r.cfg.HeaderBytes + r.committedPayload,
		externalV2BulkPacketReceiveStats(
			r.cfg.PayloadSize,
			r.committedPayload,
			r.repairRequests,
			r.laneCount,
			repairStats,
			r.receiveRate.trailPackets(),
			r.receiveRate.packetsPerSecond(),
		), err
```

Extend `externalV2BulkPacketReceiveStats` with those three final arguments and copy them into the seven diagnostics fields without changing its byte accounting.

- [ ] **Step 4: Print a receiver repair summary**

Add:

```go
func formatReceiverRepairSummary(d transfertrace.DiagnosticsSummary) string {
	if !d.ReceiverRepairObserved {
		return ""
	}
	return fmt.Sprintf(" missing_scan_checks=%d pending_missing=%d pending_missing_peak=%d repair_requested_packets=%d repair_request_batches=%d reorder_trail_packets=%d receive_packet_rate_pps=%d",
		d.MissingScanChecks,
		d.PendingMissing,
		d.PendingMissingPeak,
		d.RepairRequestedPackets,
		d.RepairRequestBatches,
		d.ReorderTrailPackets,
		d.ReceivePacketRatePPS,
	)
}
```

Call it from `formatDiagnosticsSummary` after receiver-rate output. `ReceiverRepairObserved` is true when the current schema contains all seven columns, even when every value is zero.

- [ ] **Step 5: Run focused and legacy tests**

```bash
mise exec -- go test ./pkg/transfertrace ./tools/transfertracecheck ./pkg/session -count=1
```

Expected: PASS. Confirm `TestCheckKeepsDiagnosticsAbsentForMinimalAndEmptyTrace` still passes.

- [ ] **Step 6: Review and commit**

After an independent review:

```bash
but diff
but commit codex/bulk-repair-efficiency -m "telemetry: report bulk repair efficiency"
```

---

### Task 5: Add cross-platform process resource measurements

**Files:**
- Create: `tools/runstats/main.go`
- Create: `tools/runstats/main_test.go`
- Create: `tools/runstats/resource_unix.go`
- Create: `tools/runstats/resource_other.go`
- Modify: `scripts/promotion-benchmark-driver.sh`
- Modify: `scripts/public-path-performance-harness.sh`
- Modify: `scripts/promotion_scripts_test.go`

**Interfaces:**
- Consumes: an output path followed by `--` and a child command.
- Produces: atomic JSON with `user_cpu_seconds`, `system_cpu_seconds`, `max_rss_bytes`, `resource_stats_available`, and `exit_code`; benchmark footers and CSV columns for both peers; explicit prebuilt binary overrides.

- [ ] **Step 1: Write failing `runstats` tests**

Test a successful shell child, a child exiting 7, atomic JSON creation, inherited stdout/stderr, and unavailable-resource fallback. The success assertion must decode:

```go
type resourceResult struct {
	UserCPUSeconds        float64 `json:"user_cpu_seconds"`
	SystemCPUSeconds      float64 `json:"system_cpu_seconds"`
	MaxRSSBytes           uint64  `json:"max_rss_bytes"`
	ResourceStatsAvailable bool   `json:"resource_stats_available"`
	ExitCode              int     `json:"exit_code"`
}
```

- [ ] **Step 2: Confirm red**

```bash
mise exec -- go test ./tools/runstats -count=1
```

Expected: FAIL because the package does not exist.

- [ ] **Step 3: Implement `runstats`**

`main.go` must parse `-out`, require `-- command`, run the child with inherited stdio, derive CPU from `ProcessState.UserTime()` and `SystemTime()`, call `maxRSSBytes`, write a temporary JSON file beside the target, `Sync`, close, rename, and exit with the child's code. If the child cannot start, write exit code 127 and return 127.

Use this Unix normalizer:

```go
//go:build darwin || linux

package main

import (
	"os"
	"runtime"
	"syscall"
)

func maxRSSBytes(state *os.ProcessState) (uint64, bool) {
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok || usage.Maxrss < 0 {
		return 0, false
	}
	value := uint64(usage.Maxrss)
	if runtime.GOOS == "linux" {
		value *= 1024
	}
	return value, true
}
```

The fallback file returns `(0, false)` for other platforms.

- [ ] **Step 4: Write failing benchmark-contract tests**

Extend `promotion_scripts_test.go` to assert:

- `DERPHOLE_BENCH_LOCAL_BIN` and `DERPHOLE_BENCH_LINUX_BIN` bypass derphole builds but still build/use `runstats`.
- Forward and reverse file runs bind sender and receiver JSON to the correct roles.
- A child exit is preserved after resource JSON is written.
- Missing or malformed resource JSON makes the benchmark fail.
- `summary.csv` contains `revision_label`, six raw resource columns, two total CPU columns, two CPU-seconds-per-GiB columns, and two max-RSS columns.

- [ ] **Step 5: Add driver resource wrappers and binary overrides**

At driver startup use:

```bash
local_bin="${DERPHOLE_BENCH_LOCAL_BIN:-./dist/${tool}}"
linux_bin="${DERPHOLE_BENCH_LINUX_BIN:-dist/${tool}-linux-amd64}"
local_runstats="${tmp}/runstats"
remote_runstats="${remote_bin_dir}/runstats"
sender_resource_json="${tmp}/sender.resource.json"
receiver_resource_json="${tmp}/receiver.resource.json"
```

Build `runstats` for the local OS and Linux amd64 regardless of derphole binary overrides. Build derphole only when both overrides are empty. Reject a partial override pair.

Wrap each sender and receiver process with `runstats -out`. Preserve remote JSON beside remote traces, copy it during `preserve_logs`, and remove it during cleanup. Emit exact benchmark footer names:

```text
benchmark-sender-user-cpu-seconds
benchmark-sender-system-cpu-seconds
benchmark-sender-max-rss-bytes
benchmark-sender-resource-stats-available
benchmark-receiver-user-cpu-seconds
benchmark-receiver-system-cpu-seconds
benchmark-receiver-max-rss-bytes
benchmark-receiver-resource-stats-available
benchmark-revision-label
```

The driver must reject success when either peer reports unavailable stats on darwin/linux.

- [ ] **Step 6: Extend harness CSV**

Append these columns:

```text
revision_label,sender_user_cpu_seconds,sender_system_cpu_seconds,sender_cpu_seconds_per_gib,sender_max_rss_bytes,receiver_user_cpu_seconds,receiver_system_cpu_seconds,receiver_cpu_seconds_per_gib,receiver_max_rss_bytes,missing_scan_checks,pending_missing,pending_missing_peak,repair_requested_packets,repair_request_batches,reorder_trail_packets,receive_packet_rate_pps,scan_checks_per_packet
```

Calculate CPU per GiB from verified `benchmark-size-bytes`. Calculate scan checks per packet with packet count `ceil(size_bytes / 1358)`. Keep fields empty for `blocks-v1`; bulk fields must be numeric, including zero.

- [ ] **Step 7: Run focused tests and syntax checks**

```bash
mise exec -- go test ./tools/runstats ./scripts -count=1
bash -n scripts/promotion-benchmark-driver.sh
bash -n scripts/public-path-performance-harness.sh
GOOS=linux GOARCH=amd64 mise exec -- go build ./tools/runstats
```

Expected: PASS.

- [ ] **Step 8: Review and commit**

After independent review and fixes:

```bash
but diff
but commit codex/bulk-repair-efficiency -m "tools: measure transfer process efficiency"
```

---

### Task 6: Run the focused public-path A/B

**Files:**
- Runtime only: `.tmp/bulk-repair-efficiency-20260712/**`

**Interfaces:**
- Consumes: exact `origin/main` baseline binaries, current branch candidate binaries, and Task 5 harness overrides.
- Produces: four paired iperf/file samples in `A B B A` order plus an exact gate report.

- [ ] **Step 1: Establish clean preflight**

```bash
but pull --check
pgrep -x derphole && exit 1 || true
ssh -o BatchMode=yes ubuntu@derphole-testing 'pgrep -x derphole && exit 1 || true'
rm -rf .tmp/bulk-repair-efficiency-20260712
mkdir -p .tmp/bulk-repair-efficiency-20260712/baseline-src
git archive origin/main | tar -x -C .tmp/bulk-repair-efficiency-20260712/baseline-src
```

Expected: no process IDs, current base, and a fresh artifact root. Do not kill unrelated processes.

- [ ] **Step 2: Build exact baseline and candidate binaries**

```bash
go_bin="$(mise which go)"
(
  cd .tmp/bulk-repair-efficiency-20260712/baseline-src
  "${go_bin}" build -o ../baseline-darwin-arm64 ./cmd/derphole
  GOOS=linux GOARCH=amd64 "${go_bin}" build -o ../baseline-linux-amd64 ./cmd/derphole
)
mise exec -- go build -o .tmp/bulk-repair-efficiency-20260712/candidate-darwin-arm64 ./cmd/derphole
GOOS=linux GOARCH=amd64 mise exec -- go build -o .tmp/bulk-repair-efficiency-20260712/candidate-linux-amd64 ./cmd/derphole
```

Record `origin/main` and branch commit SHAs beside artifacts using the experiment report, not a committed file.

- [ ] **Step 3: Run `A B B A`**

Before the performance sequence, prove wire compatibility in both mixed-version directions with 64 MiB files:

```bash
control_revision="$(git rev-parse origin/main)"
candidate_revision="$(git rev-parse codex/bulk-repair-efficiency)"
env -u DERPHOLE_PUBLIC_PATH_INITIAL_RATES -u DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS \
  DERPHOLE_PUBLIC_PATH_HOSTS='ubuntu@derphole-testing' \
  DERPHOLE_PUBLIC_PATH_DIRECTION=forward \
  DERPHOLE_PUBLIC_PATH_SIZE_MIB=64 \
  DERPHOLE_PUBLIC_PATH_RUNS=1 \
  DERPHOLE_PUBLIC_IPERF_PORT=8123 \
  DERPHOLE_BENCH_LOCAL_BIN="$PWD/.tmp/bulk-repair-efficiency-20260712/baseline-darwin-arm64" \
  DERPHOLE_BENCH_LINUX_BIN="$PWD/.tmp/bulk-repair-efficiency-20260712/candidate-linux-amd64" \
  DERPHOLE_BENCH_REVISION_LABEL="old-sender-${control_revision}_new-receiver-${candidate_revision}" \
  DERPHOLE_BENCH_LOG_DIR='.tmp/bulk-repair-efficiency-20260712/compat-old-sender-new-receiver' \
  ./scripts/public-path-performance-harness.sh
env -u DERPHOLE_PUBLIC_PATH_INITIAL_RATES -u DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS \
  DERPHOLE_PUBLIC_PATH_HOSTS='ubuntu@derphole-testing' \
  DERPHOLE_PUBLIC_PATH_DIRECTION=forward \
  DERPHOLE_PUBLIC_PATH_SIZE_MIB=64 \
  DERPHOLE_PUBLIC_PATH_RUNS=1 \
  DERPHOLE_PUBLIC_IPERF_PORT=8123 \
  DERPHOLE_BENCH_LOCAL_BIN="$PWD/.tmp/bulk-repair-efficiency-20260712/candidate-darwin-arm64" \
  DERPHOLE_BENCH_LINUX_BIN="$PWD/.tmp/bulk-repair-efficiency-20260712/baseline-linux-amd64" \
  DERPHOLE_BENCH_REVISION_LABEL="new-sender-${candidate_revision}_old-receiver-${control_revision}" \
  DERPHOLE_BENCH_LOG_DIR='.tmp/bulk-repair-efficiency-20260712/compat-new-sender-old-receiver' \
  ./scripts/public-path-performance-harness.sh
```

Both summaries must show exact hash/size success, `bulk-packets-v1`, public selected addresses, and no process/socket leak. Resource JSON remains available because Task 5's wrapper is independent of the derphole revision.

Then run the performance sequence.

Run one 1 GiB forward public file transfer to `ubuntu@derphole-testing` for each label. Controls use baseline binaries; candidates use candidate binaries:

```bash
control_revision="$(git rev-parse origin/main)"
candidate_revision="$(git rev-parse codex/bulk-repair-efficiency)"
for label in control-1 candidate-1 candidate-2 control-2; do
  case "${label}" in
    control-*)
      local_bin="$PWD/.tmp/bulk-repair-efficiency-20260712/baseline-darwin-arm64"
      linux_bin="$PWD/.tmp/bulk-repair-efficiency-20260712/baseline-linux-amd64"
      revision="${control_revision}"
      ;;
    candidate-*)
      local_bin="$PWD/.tmp/bulk-repair-efficiency-20260712/candidate-darwin-arm64"
      linux_bin="$PWD/.tmp/bulk-repair-efficiency-20260712/candidate-linux-amd64"
      revision="${candidate_revision}"
      ;;
  esac
  env -u DERPHOLE_PUBLIC_PATH_INITIAL_RATES -u DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS \
    DERPHOLE_PUBLIC_PATH_HOSTS='ubuntu@derphole-testing' \
    DERPHOLE_PUBLIC_PATH_DIRECTION=forward \
    DERPHOLE_PUBLIC_PATH_SIZE_MIB=1024 \
    DERPHOLE_PUBLIC_PATH_RUNS=1 \
    DERPHOLE_PUBLIC_IPERF_PORT=8123 \
    DERPHOLE_BENCH_LOCAL_BIN="${local_bin}" \
    DERPHOLE_BENCH_LINUX_BIN="${linux_bin}" \
    DERPHOLE_BENCH_REVISION_LABEL="${revision}" \
    DERPHOLE_BENCH_LOG_DIR=".tmp/bulk-repair-efficiency-20260712/${label}" \
    ./scripts/public-path-performance-harness.sh
done
```

Do not set bulk rate or Tailscale candidate variables manually; the harness must leave rate unoverridden and force the public-test Tailscale guard itself.

- [ ] **Step 4: Run the exact gate**

Run this audit and preserve both the command and output in `.superpowers/sdd/bulk-repair-focused-report.md`:

```bash
python3 - <<'PY'
import csv
import json
import statistics
import subprocess
from pathlib import Path

root = Path('.tmp/bulk-repair-efficiency-20260712')
labels = ('control-1', 'candidate-1', 'candidate-2', 'control-2')
groups = {'control': [], 'candidate': []}
iperf = []
expected_revisions = {
    'control': subprocess.check_output(['git', 'rev-parse', 'origin/main'], text=True).strip(),
    'candidate': subprocess.check_output(['git', 'rev-parse', 'codex/bulk-repair-efficiency'], text=True).strip(),
}

def seconds(value):
    value = value.strip()
    if value.endswith('ms'):
        return float(value[:-2]) / 1000.0
    if value.endswith('s'):
        return float(value[:-1])
    raise SystemExit(f'invalid flatline duration: {value!r}')

for label in labels:
    with (root / label / 'summary.csv').open(newline='') as fh:
        rows = list(csv.DictReader(fh))
    derphole = [row for row in rows if row['tool'] == 'derphole']
    controls = [row for row in rows if row['tool'] == 'iperf3']
    if len(derphole) != 1 or len(controls) != 1:
        raise SystemExit(f'{label}: expected one derphole and one iperf row')
    row = derphole[0]
    group = label.split('-', 1)[0]
    resource_required = (
        'receiver_cpu_seconds_per_gib', 'receiver_max_rss_bytes',
        'sender_cpu_seconds_per_gib', 'sender_max_rss_bytes',
    )
    candidate_required = (
        'missing_scan_checks', 'pending_missing_peak',
        'repair_requested_packets', 'repair_request_batches',
        'reorder_trail_packets', 'receive_packet_rate_pps',
        'scan_checks_per_packet',
    )
    if row['transfer_mode'] != 'bulk-packets-v1' or row['trace_ok'] != 'true':
        raise SystemExit(f'{label}: invalid mode or trace')
    if row['initial_rate_mbps'].strip():
        raise SystemExit(f'{label}: test-only rate override is set')
    if row['revision_label'] != expected_revisions[group]:
        raise SystemExit(f'{label}: revision label mismatch')
    if seconds(row['max_flatline']) >= 1.0:
        raise SystemExit(f'{label}: payload flatline reached one second')
    if any(not row[name].strip() for name in resource_required):
        raise SystemExit(f'{label}: missing process resource field')
    if group == 'candidate' and any(not row[name].strip() for name in candidate_required):
        raise SystemExit(f'{label}: missing candidate repair-efficiency field')
    groups[group].append(row)
    iperf.append(float(controls[0]['mbps']))

def median(group, field):
    return statistics.median(float(row[field]) for row in groups[group])

iperf_cv = statistics.stdev(iperf) / statistics.mean(iperf)
result = {
    'control_canonical_mbps': median('control', 'mbps'),
    'candidate_canonical_mbps': median('candidate', 'mbps'),
    'control_wall_mbps': median('control', 'wall_mbps'),
    'candidate_wall_mbps': median('candidate', 'wall_mbps'),
    'control_repair_ratio': median('control', 'repair_ratio'),
    'candidate_repair_ratio': median('candidate', 'repair_ratio'),
    'control_receiver_cpu_seconds_per_gib': median('control', 'receiver_cpu_seconds_per_gib'),
    'candidate_receiver_cpu_seconds_per_gib': median('candidate', 'receiver_cpu_seconds_per_gib'),
    'candidate_scan_checks_per_packet': median('candidate', 'scan_checks_per_packet'),
    'iperf_cv': iperf_cv,
}
print(json.dumps(result, indent=2, sort_keys=True))
if iperf_cv > 0.15:
    raise SystemExit('iperf CV exceeds 0.15; repeat the A B B A sequence once')
if result['candidate_repair_ratio'] >= 0.10:
    raise SystemExit('candidate repair ratio is not below 0.10')
if result['candidate_receiver_cpu_seconds_per_gib'] > 0.90 * result['control_receiver_cpu_seconds_per_gib']:
    raise SystemExit('candidate receiver CPU/GiB did not improve by 10 percent')
if result['candidate_scan_checks_per_packet'] >= 2.0:
    raise SystemExit('candidate scan checks per packet is not below 2.0')
if result['candidate_canonical_mbps'] < 0.97 * result['control_canonical_mbps']:
    raise SystemExit('candidate canonical median regressed more than 3 percent')
if result['candidate_wall_mbps'] < 0.97 * result['control_wall_mbps']:
    raise SystemExit('candidate wall median regressed more than 3 percent')
print('focused_acceptance=true')
PY
```

- [ ] **Step 5: Stop or continue based on evidence**

If any efficiency or throughput gate fails, do not weaken it and do not proceed to Eric/fleet. Return to systematic debugging with the new scan, CPU, rate, and repair evidence. If all gates pass, record the candidate as focused-accepted.

Evidence amendment after eight focused attempts: the allocation-free candidate passed every non-CPU gate, and its strongest stable exact attempt measured a 12.1524 percent receiver CPU/GiB reduction. Other intermediate candidates measured nearby improvements but were not retained. GRO batching, plain `recvmmsg`, and larger receive-write groups were separately rejected by WAN or deterministic Linux repair evidence. The design now records a 10 percent focused CPU floor while leaving every throughput, repair, stability, route, integrity, resource, and cleanup requirement unchanged.

Task 7's first fleet run rejected `3d6f9c4`: the tracker integration had accidentally stretched active repair requests from 100 ms to 250 ms, and `derphole-testing` forward regressed throughput, repair, and CPU against a fresh control. Live bisection isolated the boundary. Candidate `14ff73a` restores the independent 100 ms request cadence. Its same-path validation recovered canonical goodput to within 0.3 percent of control, reduced repair 17.1 percent, and reduced receiver CPU/GiB 4.3 percent. Its fresh three-control/three-candidate Eric gate improved canonical goodput 0.93 percent, wall goodput 4.02 percent, repair 31.8 percent, and receiver CPU/GiB 17.89 percent. Task 7's reachable-fleet audit remains the broader acceptance gate.

---

### Task 7: Document and run Eric plus reachable-fleet acceptance

**Files:**
- Modify: `docs/benchmarks.md`
- Runtime: `.tmp/bulk-repair-eric-20260712/**`
- Runtime: `.tmp/bulk-repair-fleet-20260712/**`

**Interfaces:**
- Consumes: focused-accepted candidate and Task 5 machine-readable fields.
- Produces: reviewed runbook, three candidate Eric 1 GiB samples (3 GiB candidate aggregate) balanced against three 1 GiB controls, three unoverridden samples per reachable host-direction, and an exact mode-aware acceptance report.

- [ ] **Step 1: Update benchmark documentation**

Document:

- incremental scan cursor and pending-gap semantics
- 250 ms time-based reorder window and 8,192/65,536 bounds
- all seven repair-efficiency trace fields
- `runstats` CPU/RSS fields and per-GiB normalization
- explicit baseline/candidate binary overrides
- focused A/B and full acceptance thresholds
- current 1,000 Mbps default and absence of user-facing tuning flags

Run `git diff --check`, then commit after review:

```bash
but diff
but commit codex/bulk-repair-efficiency -m "docs: explain bulk repair efficiency"
```

- [ ] **Step 2: Probe the full canonical inventory**

Probe:

```text
ubuntu@derphole-testing
ubuntu@eric-nuc
root@hetz
root@canlxc
root@pve1
root@ktzlxc
root@uklxc
november-oscar.exe.xyz
```

Use `BatchMode=yes`, 8-second timeout, and one connection attempt. Preserve a four-column TSV containing host, state, exit code, and bounded reason. Every reachable host enters the fleet; unreachable hosts remain documented, not silently omitted.

- [ ] **Step 3: Run Eric three-sample 1 GiB control/candidate balance**

Use fresh baseline and candidate binaries in `A B B A B A` order so each revision receives three 1 GiB samples. The candidate therefore transfers 3 GiB in aggregate while the independent files support median and variance checks. All six runs are normal forward files, public/non-Tailscale, unoverridden 1,000 Mbps policy, paired with iperf3.

Candidate gates:

- canonical and wall medians at least 97 percent of fresh control
- repair median no higher than control and below 10 percent
- receiver CPU/GiB no higher than control
- scan checks/packet below 2.0
- canonical CV at most 0.15
- zero integrity, trace, route, resource, cleanup, or one-second-flatline failures

- [ ] **Step 4: Run three candidate transfers in both directions on every reachable host**

Use the existing exact pve1 LAN derivation and `env -u DERPHOLE_PUBLIC_PATH_INITIAL_RATES`. Each cell must contain exactly three derphole rows and three paired iperf rows. The harness must be stdin-safe while reading the host list.

Bulk cells require all new efficiency fields and 1,000 Mbps selected rate. Blocks cells require QUIC progress and leave bulk-only efficiency fields empty. Public cells must select public non-Tailscale addresses; pve1 endpoints must match exactly.

- [ ] **Step 5: Run the exact full audit**

Extend the previous mode-aware audit with:

- `revision_label` equals the candidate SHA for every derphole row
- bulk `scan_checks_per_packet < 2.0`
- bulk resource fields available and finite
- no bulk cell repair-ratio or CPU/GiB regression versus its accepted baseline
- all previous integrity, route, mode, stability, and cleanup assertions

Allow one exact three-run rerun only when canonical CV alone exceeds 0.15. Preserve archived first results and refuse overwrite.

- [ ] **Step 6: Run fresh local gates**

```bash
mise run test
mise run vet
mise run build
mise run check:hooks
mise exec -- go test -race ./pkg/session -run 'TestExternalV2BulkPacket' -count=1
but pull --check
```

Expected: all pass, including `govulncheck`; no tooling update is needed unless the actual gate proves otherwise.

---

### Task 8: Final review, squash, land, push, and verify publication

**Files:**
- Review the complete branch from `origin/main` to branch tip.

**Interfaces:**
- Consumes: all reviewed commits and accepted runtime artifacts.
- Produces: one clean landed commit on local and remote `main`, green workflows, and npm `dev` packages resolving to it.

- [ ] **Step 1: Complete independent whole-branch review**

Use `superpowers:requesting-code-review` with a bounded review package. Review plan/spec alignment, tracker complexity, receiver hot-path allocations, overflow, race safety, legacy trace compatibility, runstats exit semantics, harness role binding, and exact live gates. Fix every Critical or Important finding and re-review.

- [ ] **Step 2: Re-run verification immediately before history cleanup**

```bash
mise run test
mise run vet
mise run build
mise run check:hooks
mise exec -- go test -race ./pkg/session -run 'TestExternalV2BulkPacket' -count=1
but pull --check
```

Expected: all green on the reviewed tip.

- [ ] **Step 3: Create recovery point and squash with GitButler**

```bash
but oplog snapshot -m "before bulk repair efficiency history cleanup"
but status
```

Use the commit IDs printed by `but status`: list every newer session checkpoint first and the oldest session checkpoint last, then run `but squash` with message `perf: make bulk repair scale with loss`. Stop if status shows any commit from another branch in that set.

Verify the squashed tree exactly matches the reviewed tip, is one commit based on current `origin/main`, and contains only this session's files.

- [ ] **Step 4: Land directly on main**

The user already authorized land-and-push. After a final `but pull --check`, use the repository's allowed publication exception:

```bash
squashed_commit="$(git rev-parse codex/bulk-repair-efficiency)"
git push origin "${squashed_commit}:refs/heads/main"
```

Treat non-fast-forward rejection as a race. Run `but pull`, re-review changed context, rerun affected gates and live controls when necessary, then retry only when clean.

- [ ] **Step 5: Reconcile and verify refs**

```bash
but pull
but clean --dry-run
git rev-parse main
git rev-parse origin/main
git ls-remote origin refs/heads/main
```

Update only local `main` to `origin/main` if GitButler leaves it stale. Clean only this integrated session branch.

- [ ] **Step 6: Verify GitHub and npm truth**

Watch Checks, Pages, and Release for the landed SHA. Require all three conclusions to be `success`. Then verify:

```bash
git ls-remote origin refs/tags/dev
npm view derphole@dev version
npm view derptun@dev version
npm view derpssh@dev version
npx -y derphole@dev version
```

All three versions and the executable must end with the landed short SHA. Only then report the measured performance, stability, efficiency deltas and mark the active goal complete.
