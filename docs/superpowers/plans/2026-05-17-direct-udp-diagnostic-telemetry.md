# Direct UDP Diagnostic Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add observational direct UDP data-phase diagnostics that explain why full transfers run below probe capacity.

**Architecture:** Extend the existing `pkg/transfertrace` CSV and `pkg/session/externalTransferMetrics` bridge rather than adding a second telemetry system. Carry direct UDP controller state through `probe.TransferStats`, snapshot it in session metrics, and report it through the existing trace checker and live harness logs.

**Tech Stack:** Go, Bash, existing `mise` tasks, existing `transfertrace` CSV recorder, existing direct UDP probe/session code.

---

## File Structure

- Modify `pkg/transfertrace/trace.go`: add CSV fields, snapshot fields, and per-interval diagnostic goodput calculations.
- Modify `pkg/transfertrace/trace_test.go`: verify header stability, diagnostic field emission, and empty role-specific fields.
- Modify `pkg/transfertrace/checker.go`: parse optional diagnostic columns and produce a throughput/backpressure summary.
- Modify `pkg/transfertrace/checker_test.go`: verify diagnostic summary parsing and low-throughput reporting without failing the trace.
- Modify `tools/transfertracecheck/main.go`: print diagnostic summary fields returned by the checker.
- Modify `tools/transfertracecheck/main_test.go`: verify CLI output includes diagnostic summary fields when present.
- Modify `pkg/probe/session.go`: add `TransferDiagnostics` to `TransferStats` and populate data-phase rate, lane, replay, repair, and backlog diagnostics.
- Modify `pkg/probe/blast_rate.go`: expose controller diagnostics without changing rate-control behavior.
- Modify `pkg/probe/blast_control.go`: count repair requests and repair bytes in `TransferStats.Diagnostics`.
- Modify `pkg/probe/session_test.go`: verify progress callbacks receive controller diagnostics.
- Modify `pkg/probe/blast_control_test.go`: verify repair diagnostics are counted.
- Modify `pkg/session/external_transfer_metrics.go`: store and emit new diagnostic fields in transfer snapshots.
- Modify `pkg/session/external_transfer_metrics_test.go`: verify session metrics map probe diagnostics into trace snapshots.
- Modify `pkg/session/external_direct_udp.go`: wire direct UDP send/receive stats and transport queue depth into metrics.
- Modify `pkg/session/external_direct_udp_test.go`: verify direct UDP execution updates the expanded metrics.
- Modify `pkg/transport/manager.go`: expose current peer receive queue depth in addition to max depth.
- Modify `pkg/transport/manager_test.go`: verify current and max peer receive queue depth accessors.
- Create `scripts/direct-udp-diagnostic-benchmark.sh`: run remote-pair iperf3, the transfer stall harness, and extract direct UDP probe samples from logs.
- Create `scripts/direct_udp_diagnostic_benchmark_script_test.go`: static checks for the new script's command shape and log output.
- Modify `docs/benchmarks.md`: document the diagnostic trace fields and comparison script.

---

### Task 1: Extend Transfer Trace Schema

**Files:**
- Modify: `pkg/transfertrace/trace.go`
- Modify: `pkg/transfertrace/trace_test.go`

- [ ] **Step 1: Write failing trace schema tests**

Add these tests to `pkg/transfertrace/trace_test.go`:

```go
func TestRecorderWritesDirectUDPDiagnosticFields(t *testing.T) {
	var out strings.Builder
	start := time.UnixMilli(1_000)
	rec, err := NewRecorder(&out, RoleSend, start)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Observe(Snapshot{
		At:                            start.Add(500 * time.Millisecond),
		Phase:                         PhaseDirectExecute,
		LocalSentBytes:                1_250_000,
		PeerReceivedBytes:             1_000_000,
		RateTargetMbps:                263,
		RateCeilingMbps:               700,
		RateExplorationCeilingMbps:    1200,
		DirectRateSelectedMbps:        263,
		DirectLanesActive:             4,
		DirectLanesAvailable:          7,
		LaneMin:                       4,
		LaneCap:                       4,
		ControllerDecision:            "hold",
		ControllerReason:              "initial-hold",
		ReplayWindowBytes:             33_554_432,
		ReplayBytes:                   2_696_032,
		RetransmitCount:               3600,
		RepairRequests:                12,
		RepairBytes:                   98_304,
		PeerRecvQueueDepth:            512,
		PeerRecvQueueDepthMax:         1069,
		DirectPacketBytes:             1_250_000,
		DirectCommittedBytes:          1_000_000,
		LastState:                     "connected-direct",
	})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	rows := readTraceRows(t, out.String())
	header := rows[0]
	data := rows[1]
	assertTraceField(t, header, data, "rate_target_mbps", "263")
	assertTraceField(t, header, data, "rate_ceiling_mbps", "700")
	assertTraceField(t, header, data, "rate_exploration_ceiling_mbps", "1200")
	assertTraceField(t, header, data, "active_lanes", "4")
	assertTraceField(t, header, data, "available_lanes", "7")
	assertTraceField(t, header, data, "lane_min", "4")
	assertTraceField(t, header, data, "lane_cap", "4")
	assertTraceField(t, header, data, "controller_decision", "hold")
	assertTraceField(t, header, data, "controller_reason", "initial-hold")
	assertTraceField(t, header, data, "send_goodput_mbps", "20.00")
	assertTraceField(t, header, data, "receiver_committed_mbps", "16.00")
	assertTraceField(t, header, data, "replay_bytes", "2696032")
	assertTraceField(t, header, data, "retransmits", "3600")
	assertTraceField(t, header, data, "repair_requests", "12")
	assertTraceField(t, header, data, "repair_bytes", "98304")
	assertTraceField(t, header, data, "peer_recv_queue_depth", "512")
	assertTraceField(t, header, data, "peer_recv_queue_depth_max", "1069")
	assertTraceField(t, header, data, "direct_packet_bytes", "1250000")
	assertTraceField(t, header, data, "direct_committed_bytes", "1000000")
}

func TestRecorderLeavesRoleSpecificDiagnosticFieldsEmpty(t *testing.T) {
	var out strings.Builder
	start := time.UnixMilli(1_000)
	rec, err := NewRecorder(&out, RoleReceive, start)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Observe(Snapshot{
		At:                   start.Add(500 * time.Millisecond),
		Phase:                PhaseDirectExecute,
		AppBytes:             1_000_000,
		DirectBytes:          1_250_000,
		DirectCommittedBytes: 1_000_000,
	})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	rows := readTraceRows(t, out.String())
	header := rows[0]
	data := rows[1]
	assertTraceField(t, header, data, "send_goodput_mbps", "")
	assertTraceField(t, header, data, "receive_goodput_mbps", "20.00")
	assertTraceField(t, header, data, "receiver_committed_mbps", "16.00")
	assertTraceField(t, header, data, "controller_decision", "")
	assertTraceField(t, header, data, "controller_reason", "")
}
```

If `readTraceRows` and `assertTraceField` do not exist, add these helpers to the same test file:

```go
func readTraceRows(t *testing.T, text string) [][]string {
	t.Helper()
	rows, err := csv.NewReader(strings.NewReader(text)).ReadAll()
	if err != nil {
		t.Fatalf("ReadAll() error = %v\n%s", err, text)
	}
	return rows
}

func assertTraceField(t *testing.T, header []string, row []string, name string, want string) {
	t.Helper()
	for i, field := range header {
		if field == name {
			if i >= len(row) {
				t.Fatalf("field %s index %d outside row len %d", name, i, len(row))
			}
			if row[i] != want {
				t.Fatalf("%s = %q, want %q", name, row[i], want)
			}
			return
		}
	}
	t.Fatalf("header missing field %s in %v", name, header)
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
go test ./pkg/transfertrace -run 'TestRecorderWritesDirectUDPDiagnosticFields|TestRecorderLeavesRoleSpecificDiagnosticFieldsEmpty' -count=1
```

Expected: fail because the new diagnostic fields are missing.

- [ ] **Step 3: Add trace fields and row output**

In `pkg/transfertrace/trace.go`, append these names to `header` after `last_error`:

```go
	"rate_target_mbps",
	"rate_ceiling_mbps",
	"rate_exploration_ceiling_mbps",
	"rate_selected_mbps",
	"active_lanes",
	"available_lanes",
	"lane_min",
	"lane_cap",
	"controller_decision",
	"controller_reason",
	"send_goodput_mbps",
	"receive_goodput_mbps",
	"receiver_committed_mbps",
	"replay_bytes",
	"retransmits",
	"repair_requests",
	"repair_bytes",
	"peer_recv_queue_depth",
	"peer_recv_queue_depth_max",
	"direct_packet_bytes",
	"direct_committed_bytes",
```

Add these fields to `Snapshot`:

```go
	RateTargetMbps             int
	RateCeilingMbps            int
	RateExplorationCeilingMbps int
	LaneMin                    int
	LaneCap                    int
	ControllerDecision         string
	ControllerReason           string
	ReplayBytes                uint64
	RepairRequests             int64
	RepairBytes                int64
	PeerRecvQueueDepth         int
	PeerRecvQueueDepthMax      int
	DirectPacketBytes          int64
	DirectCommittedBytes       int64
```

Add these fields to `Recorder`:

```go
	lastLocalSent         int64
	lastDirectBytes       int64
	lastPeerReceivedBytes int64
```

In `observeLocked`, compute diagnostic deltas before `r.w.Write`:

```go
	localSentDelta := nonNegativeDelta(snap.LocalSentBytes, r.lastLocalSent)
	directDelta := nonNegativeDelta(snap.DirectBytes, r.lastDirectBytes)
	peerReceivedDelta := nonNegativeDelta(snap.PeerReceivedBytes, r.lastPeerReceivedBytes)
```

Change the row call to:

```go
	if err := r.w.Write(r.row(snap, deltaBytes, deltaMS, localSentDelta, directDelta, peerReceivedDelta)); err != nil {
```

After updating `r.lastApp`, also update:

```go
	r.lastLocalSent = snap.LocalSentBytes
	r.lastDirectBytes = snap.DirectBytes
	r.lastPeerReceivedBytes = snap.PeerReceivedBytes
```

Change the row signature and append the new fields:

```go
func (r *Recorder) row(snap Snapshot, deltaBytes int64, deltaMS int64, localSentDelta int64, directDelta int64, peerReceivedDelta int64) []string {
	sendGoodput := ""
	if r.role == RoleSend {
		sendGoodput = formatMbps(localSentDelta, deltaMS)
	}
	receiveGoodput := ""
	if r.role == RoleReceive {
		receiveGoodput = formatMbps(directDelta, deltaMS)
	}
	receiverCommittedGoodput := ""
	if r.role == RoleReceive {
		receiverCommittedGoodput = formatMbps(deltaBytes, deltaMS)
	} else if snap.PeerReceivedBytes > 0 {
		receiverCommittedGoodput = formatMbps(peerReceivedDelta, deltaMS)
	}

	return []string{
		strconv.FormatInt(snap.At.UnixMilli(), 10),
		strconv.FormatInt(snap.At.Sub(r.start).Milliseconds(), 10),
		string(r.role),
		string(snap.Phase),
		strconv.FormatInt(snap.RelayBytes, 10),
		strconv.FormatInt(snap.DirectBytes, 10),
		strconv.FormatInt(snap.AppBytes, 10),
		strconv.FormatInt(deltaBytes, 10),
		formatMbps(deltaBytes, deltaMS),
		strconv.FormatInt(snap.LocalSentBytes, 10),
		strconv.FormatInt(snap.PeerReceivedBytes, 10),
		formatOptionalInt64(snap.SetupElapsedMS),
		formatOptionalInt64(snap.TransferElapsedMS),
		strconv.FormatBool(snap.DirectValidated),
		snap.FallbackReason,
		formatOptionalInt(snap.DirectRateSelectedMbps),
		formatOptionalInt(snap.DirectRateActiveMbps),
		formatOptionalInt(snap.DirectLanesActive),
		formatOptionalInt(snap.DirectLanesAvailable),
		snap.DirectProbeState,
		snap.DirectProbeSummary,
		formatOptionalUint64(snap.ReplayWindowBytes),
		formatOptionalUint64(snap.RepairQueueBytes),
		formatOptionalInt64(snap.RetransmitCount),
		formatOptionalUint64(snap.OutOfOrderBytes),
		snap.LastState,
		snap.LastError,
		formatOptionalInt(snap.RateTargetMbps),
		formatOptionalInt(snap.RateCeilingMbps),
		formatOptionalInt(snap.RateExplorationCeilingMbps),
		formatOptionalInt(snap.DirectRateSelectedMbps),
		formatOptionalInt(snap.DirectLanesActive),
		formatOptionalInt(snap.DirectLanesAvailable),
		formatOptionalInt(snap.LaneMin),
		formatOptionalInt(snap.LaneCap),
		snap.ControllerDecision,
		snap.ControllerReason,
		sendGoodput,
		receiveGoodput,
		receiverCommittedGoodput,
		formatOptionalUint64(snap.ReplayBytes),
		formatOptionalInt64(snap.RetransmitCount),
		formatOptionalInt64(snap.RepairRequests),
		formatOptionalInt64(snap.RepairBytes),
		formatOptionalInt(snap.PeerRecvQueueDepth),
		formatOptionalInt(snap.PeerRecvQueueDepthMax),
		formatOptionalInt64(snap.DirectPacketBytes),
		formatOptionalInt64(snap.DirectCommittedBytes),
	}
}
```

Add this helper near the existing format helpers:

```go
func nonNegativeDelta(current int64, previous int64) int64 {
	delta := current - previous
	if delta < 0 {
		return 0
	}
	return delta
}
```

- [ ] **Step 4: Run trace tests**

Run:

```bash
go test ./pkg/transfertrace -count=1
```

Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add pkg/transfertrace/trace.go pkg/transfertrace/trace_test.go
git commit -m "trace: add direct udp diagnostic fields"
```

---

### Task 2: Add Checker Diagnostic Summary

**Files:**
- Modify: `pkg/transfertrace/checker.go`
- Modify: `pkg/transfertrace/checker_test.go`
- Modify: `tools/transfertracecheck/main.go`
- Modify: `tools/transfertracecheck/main_test.go`

- [ ] **Step 1: Write failing checker tests**

Add this test to `pkg/transfertrace/checker_test.go`:

```go
func TestCheckReportsDiagnosticSummaryWithoutFailingLowThroughput(t *testing.T) {
	csvText := strings.Join(append(Header, "rate_target_mbps", "receiver_committed_mbps", "replay_bytes", "retransmits", "peer_recv_queue_depth_max"), ",") + "\n" +
		"1000,0,send,direct_execute,0,1024,1024,1024,0.00,1024,1024,,,true,,,,,,,,,,,,connected-direct,,263,1.00,1048576,7,900\n" +
		"1500,500,send,complete,0,2048,2048,1024,16.38,2048,2048,,,true,,,,,,,,,,,,stream-complete,,263,1.00,2097152,9,1069\n"
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleSend, StallWindow: time.Second, ExpectedBytes: 2048, ExpectedBytesSet: true})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Diagnostics.MaxRateTargetMbps != 263 {
		t.Fatalf("MaxRateTargetMbps = %d, want 263", result.Diagnostics.MaxRateTargetMbps)
	}
	if result.Diagnostics.MaxReplayBytes != 2_097_152 {
		t.Fatalf("MaxReplayBytes = %d, want 2097152", result.Diagnostics.MaxReplayBytes)
	}
	if result.Diagnostics.MaxRetransmits != 9 {
		t.Fatalf("MaxRetransmits = %d, want 9", result.Diagnostics.MaxRetransmits)
	}
	if result.Diagnostics.MaxPeerRecvQueueDepth != 1069 {
		t.Fatalf("MaxPeerRecvQueueDepth = %d, want 1069", result.Diagnostics.MaxPeerRecvQueueDepth)
	}
}
```

Add this test to `tools/transfertracecheck/main_test.go`:

```go
func TestRunPrintsDiagnosticSummary(t *testing.T) {
	dir := t.TempDir()
	tracePath := filepath.Join(dir, "trace.csv")
	csvText := strings.Join(append(transfertrace.Header, "rate_target_mbps", "receiver_committed_mbps", "replay_bytes", "retransmits", "peer_recv_queue_depth_max"), ",") + "\n" +
		"1000,0,send,complete,0,1024,1024,1024,0.00,1024,1024,,,true,,,,,,,,,,,,stream-complete,,263,1.00,2097152,9,1069\n"
	if err := os.WriteFile(tracePath, []byte(csvText), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "send", "-expected-bytes", "1024", tracePath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() code = %d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"max_rate_target_mbps=263", "max_replay_bytes=2097152", "max_retransmits=9", "max_peer_recv_queue_depth=1069"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q: %s", want, out)
		}
	}
}
```

Add missing imports in `tools/transfertracecheck/main_test.go`:

```go
import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/transfertrace"
)
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
go test ./pkg/transfertrace ./tools/transfertracecheck -run 'Diagnostic|Summary' -count=1
```

Expected: fail because `Result.Diagnostics` and CLI summary output do not exist.

- [ ] **Step 3: Implement checker diagnostic parsing**

In `pkg/transfertrace/checker.go`, add:

```go
type DiagnosticsSummary struct {
	MaxRateTargetMbps      int
	MaxReplayBytes         uint64
	MaxRetransmits         int64
	MaxPeerRecvQueueDepth  int
	MinReceiverCommitMbps  float64
	MaxReceiverCommitMbps  float64
}
```

Add to `Result`:

```go
	Diagnostics DiagnosticsSummary
```

Add optional indexes to `checkerIndexes`:

```go
	rateTargetMbps        int
	receiverCommittedMbps int
	replayBytes           int
	retransmits           int
	peerRecvQueueDepthMax int
```

Add fields to `checkerRow`:

```go
	rateTargetMbps        int
	receiverCommittedMbps float64
	replayBytes           uint64
	retransmits           int64
	peerRecvQueueDepthMax int
```

In `checkerHeaderIndexes`, populate the optional indexes with `headerIndex(header, "field_name")` for each new field. Keep missing optional fields at `-1`.

In `parseCheckerRow`, parse optional fields with helpers:

```go
	rateTargetMbps:        optionalInt(record, indexes.rateTargetMbps),
	receiverCommittedMbps: optionalFloat(record, indexes.receiverCommittedMbps),
	replayBytes:           optionalUint64(record, indexes.replayBytes),
	retransmits:           optionalInt64(record, indexes.retransmits),
	peerRecvQueueDepthMax: optionalInt(record, indexes.peerRecvQueueDepthMax),
```

Add helpers:

```go
func optionalInt(record []string, index int) int {
	if index < 0 {
		return 0
	}
	value, _ := strconv.Atoi(field(record, index))
	return value
}

func optionalInt64(record []string, index int) int64 {
	if index < 0 {
		return 0
	}
	value, _ := strconv.ParseInt(field(record, index), 10, 64)
	return value
}

func optionalUint64(record []string, index int) uint64 {
	if index < 0 {
		return 0
	}
	value, _ := strconv.ParseUint(field(record, index), 10, 64)
	return value
}

func optionalFloat(record []string, index int) float64 {
	if index < 0 {
		return 0
	}
	value, _ := strconv.ParseFloat(field(record, index), 64)
	return value
}
```

In `checker.consume`, after `validateCheckerRowStatus`, call:

```go
	c.recordDiagnostics(row)
```

Add:

```go
func (c *checker) recordDiagnostics(row checkerRow) {
	if row.rateTargetMbps > c.result.Diagnostics.MaxRateTargetMbps {
		c.result.Diagnostics.MaxRateTargetMbps = row.rateTargetMbps
	}
	if row.replayBytes > c.result.Diagnostics.MaxReplayBytes {
		c.result.Diagnostics.MaxReplayBytes = row.replayBytes
	}
	if row.retransmits > c.result.Diagnostics.MaxRetransmits {
		c.result.Diagnostics.MaxRetransmits = row.retransmits
	}
	if row.peerRecvQueueDepthMax > c.result.Diagnostics.MaxPeerRecvQueueDepth {
		c.result.Diagnostics.MaxPeerRecvQueueDepth = row.peerRecvQueueDepthMax
	}
	if row.receiverCommittedMbps > 0 {
		if c.result.Diagnostics.MinReceiverCommitMbps == 0 || row.receiverCommittedMbps < c.result.Diagnostics.MinReceiverCommitMbps {
			c.result.Diagnostics.MinReceiverCommitMbps = row.receiverCommittedMbps
		}
		if row.receiverCommittedMbps > c.result.Diagnostics.MaxReceiverCommitMbps {
			c.result.Diagnostics.MaxReceiverCommitMbps = row.receiverCommittedMbps
		}
	}
}
```

- [ ] **Step 4: Implement CLI summary output**

In `tools/transfertracecheck/main.go`, build a diagnostic summary string after the pair summary:

```go
	diagnosticSummary := fmt.Sprintf(
		" max_rate_target_mbps=%d max_replay_bytes=%d max_retransmits=%d max_peer_recv_queue_depth=%d receiver_commit_mbps_min=%.2f receiver_commit_mbps_max=%.2f",
		result.Diagnostics.MaxRateTargetMbps,
		result.Diagnostics.MaxReplayBytes,
		result.Diagnostics.MaxRetransmits,
		result.Diagnostics.MaxPeerRecvQueueDepth,
		result.Diagnostics.MinReceiverCommitMbps,
		result.Diagnostics.MaxReceiverCommitMbps,
	)
```

Change the final print to:

```go
	_, _ = fmt.Fprintf(stdout, "trace-ok rows=%d final_app_bytes=%d max_flatline=%s%s%s\n", result.Rows, result.FinalAppBytes, result.MaxFlatline, pairSummary, diagnosticSummary)
```

- [ ] **Step 5: Run checker tests**

Run:

```bash
go test ./pkg/transfertrace ./tools/transfertracecheck -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add pkg/transfertrace/checker.go pkg/transfertrace/checker_test.go tools/transfertracecheck/main.go tools/transfertracecheck/main_test.go
git commit -m "trace: summarize direct udp diagnostics"
```

---

### Task 3: Add Probe Data-Phase Diagnostics

**Files:**
- Modify: `pkg/probe/session.go`
- Modify: `pkg/probe/blast_rate.go`
- Modify: `pkg/probe/blast_control.go`
- Modify: `pkg/probe/session_test.go`
- Modify: `pkg/probe/blast_control_test.go`

- [ ] **Step 1: Write failing probe diagnostics tests**

Add this test to `pkg/probe/session_test.go`:

```go
func TestSendBlastParallelProgressIncludesControllerDiagnostics(t *testing.T) {
	sender, receiver, cleanup := newUDPConnPair(t)
	defer cleanup()

	payload := bytes.Repeat([]byte("x"), 2<<20)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	recvErr := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastStreamParallelToWriter(ctx, []net.PacketConn{receiver}, io.Discard, ReceiveConfig{
			RequireComplete: true,
			Progress:       func(TransferStats) {},
		}, int64(len(payload)))
		recvErr <- err
	}()

	var sawRate bool
	var sawLane bool
	stats, err := SendBlastParallel(ctx, []net.PacketConn{sender}, []string{receiver.LocalAddr().String()}, bytes.NewReader(payload), SendConfig{
		Blast:                     true,
		RateMbps:                  100,
		RateCeilingMbps:           700,
		RateExplorationCeilingMbps: 1200,
		RepairPayloads:            true,
		StreamReplayWindowBytes:   8 << 20,
		Progress: func(stats TransferStats) {
			if stats.Diagnostics.RateTargetMbps > 0 {
				sawRate = true
			}
			if stats.Diagnostics.ActiveLanes > 0 && stats.Diagnostics.AvailableLanes > 0 {
				sawLane = true
			}
		},
	})
	if err != nil {
		t.Fatalf("SendBlastParallel() error = %v", err)
	}
	if err := <-recvErr; err != nil {
		t.Fatalf("ReceiveBlastStreamParallelToWriter() error = %v", err)
	}
	if stats.Diagnostics.RateTargetMbps == 0 {
		t.Fatalf("final RateTargetMbps = 0, want controller rate")
	}
	if stats.Diagnostics.RateCeilingMbps != 700 {
		t.Fatalf("RateCeilingMbps = %d, want 700", stats.Diagnostics.RateCeilingMbps)
	}
	if stats.Diagnostics.RateExplorationCeilingMbps != 1200 {
		t.Fatalf("RateExplorationCeilingMbps = %d, want 1200", stats.Diagnostics.RateExplorationCeilingMbps)
	}
	if !sawRate || !sawLane {
		t.Fatalf("progress sawRate=%v sawLane=%v, want both true", sawRate, sawLane)
	}
}
```

If `newUDPConnPair` is not available in this file, add:

```go
func newUDPConnPair(t *testing.T) (net.PacketConn, net.PacketConn, func()) {
	t.Helper()
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(a) error = %v", err)
	}
	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = a.Close()
		t.Fatalf("ListenPacket(b) error = %v", err)
	}
	return a, b, func() {
		_ = a.Close()
		_ = b.Close()
	}
}
```

Add this test to `pkg/probe/blast_control_test.go`:

```go
func TestHandleBlastRepairRequestEventCountsDiagnostics(t *testing.T) {
	ctx := context.Background()
	batcher := &recordingPacketBatcher{maxBatch: 16}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	runID := [16]byte{1, 2, 3}
	history, err := newBlastRepairHistory(runID, defaultChunkSize, true, nil)
	if err != nil {
		t.Fatalf("newBlastRepairHistory() error = %v", err)
	}
	defer func() {
		_ = history.Close()
	}()
	packet := bytes.Repeat([]byte("r"), defaultChunkSize)
	if err := history.Remember(7, 7*defaultChunkSize, packet); err != nil {
		t.Fatalf("Remember() error = %v", err)
	}
	payload := marshalRepairRequestPayload([]uint64{7})
	stats := &TransferStats{}

	_, handled, err := handleBlastRepairRequestEvent(ctx, batcher, peer, history, stats, newBlastRepairDeduper(), nil, blastSendControlEvent{
		typ:        PacketTypeRepairRequest,
		payload:    payload,
		receivedAt: time.Now(),
	}, nil)
	if err != nil {
		t.Fatalf("handleBlastRepairRequestEvent() error = %v", err)
	}
	if !handled {
		t.Fatalf("handled = false, want true")
	}
	if stats.Diagnostics.RepairRequests != 1 {
		t.Fatalf("RepairRequests = %d, want 1", stats.Diagnostics.RepairRequests)
	}
	if stats.Diagnostics.RepairBytes == 0 {
		t.Fatalf("RepairBytes = 0, want repaired payload bytes")
	}
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
go test ./pkg/probe -run 'TestSendBlastParallelProgressIncludesControllerDiagnostics|TestHandleBlastRepairRequestEventCountsDiagnostics' -count=1
```

Expected: fail because `TransferStats.Diagnostics` does not exist.

- [ ] **Step 3: Add diagnostics types**

In `pkg/probe/session.go`, add:

```go
type TransferDiagnostics struct {
	RateTargetMbps             int
	RateCeilingMbps            int
	RateExplorationCeilingMbps int
	ActiveLanes                int
	AvailableLanes             int
	LaneMin                    int
	LaneCap                    int
	ControllerDecision         string
	ControllerReason           string
	ReplayWindowBytes          uint64
	ReplayBytes                uint64
	RepairRequests             int64
	RepairBytes                int64
	PeerRecvQueueDepth         int
	PeerRecvQueueDepthMax      int
	DirectPacketBytes          int64
	DirectCommittedBytes       int64
}
```

Add this field to `TransferStats`:

```go
	Diagnostics TransferDiagnostics
```

- [ ] **Step 4: Expose control diagnostics**

In `pkg/probe/blast_rate.go`, add:

```go
func (c *blastSendControl) Diagnostics(activeLanes int, availableLanes int, cfg SendConfig, decision string, reason string) TransferDiagnostics {
	if c == nil || c.controller == nil {
		return TransferDiagnostics{}
	}
	return TransferDiagnostics{
		RateTargetMbps:             c.controller.RateMbps(),
		RateCeilingMbps:            cfg.RateCeilingMbps,
		RateExplorationCeilingMbps: cfg.RateExplorationCeilingMbps,
		ActiveLanes:                activeLanes,
		AvailableLanes:             availableLanes,
		LaneMin:                    cfg.MinActiveLanes,
		LaneCap:                    cfg.MaxActiveLanes,
		ControllerDecision:         decision,
		ControllerReason:           reason,
		PeerRecvQueueDepth:         int(c.ReceiverBacklogBytes()),
		DirectCommittedBytes:       int64(c.receiverCommittedBytes),
	}
}
```

Use `PeerRecvQueueDepth` here as receiver backlog bytes because the probe package does not know `transport.Manager` queue depth. The session layer will overwrite it with transport queue depth when available.

- [ ] **Step 5: Populate diagnostics during parallel send**

In `pkg/probe/session.go`, add this method near `blastParallelSendControlRuntime`:

```go
func (r *blastParallelSendControlRuntime) emitDiagnostics(decision string, reason string) {
	if r == nil || r.stats == nil {
		return
	}
	diagnostics := r.control.Diagnostics(*r.activeLanes, len(r.lanes), r.cfg, decision, reason)
	diagnostics.ReplayWindowBytes = r.cfg.StreamReplayWindowBytes
	diagnostics.ReplayBytes = r.stats.MaxReplayBytes
	diagnostics.DirectPacketBytes = r.stats.BytesSent
	diagnostics.DirectCommittedBytes = diagnostics.DirectCommittedBytes
	diagnostics.RepairRequests = r.stats.Diagnostics.RepairRequests
	diagnostics.RepairBytes = r.stats.Diagnostics.RepairBytes
	r.stats.Diagnostics = diagnostics
	emitProbeProgress(r.progress, *r.stats)
}
```

Call it in these places:

```go
// At the end of updateLaneRates:
r.emitDiagnostics("rate-change", "controller-rate")

// At the end of observeReceiverBacklog after ObserveReceiverBacklogPressure:
r.emitDiagnostics("decrease", "receiver-backlog")

// At the end of sleepForReplayWindow after recordReplayWindowFullWait:
r.emitDiagnostics("decrease", "replay-window-full")

// At the end of applyControlAck when MaxReplayBytes changed:
r.emitDiagnostics("ack", "receiver-stats")

// In configure path after controlRuntime is constructed:
controlRuntime.emitDiagnostics("start", "direct-execute")
```

Before `SendBlastParallel` returns, ensure final stats carry the current diagnostics. In `blastParallelSendCompletion.completedStats`, add before returning:

```go
	if c.controlRuntime != nil {
		c.controlRuntime.emitDiagnostics("complete", "send-complete")
	}
```

- [ ] **Step 6: Count repair diagnostics**

In `pkg/probe/blast_control.go`, update `handleBlastRepairRequestEvent` after `sendBlastRepairs` succeeds:

```go
	if retransmits > 0 {
		stats.Diagnostics.RepairRequests++
		stats.Diagnostics.RepairBytes += int64(retransmits * defaultChunkSize)
	}
```

Keep the existing `control.ObserveRepairPressure` call unchanged.

- [ ] **Step 7: Run probe tests**

Run:

```bash
go test ./pkg/probe -run 'TestSendBlastParallelProgressIncludesControllerDiagnostics|TestHandleBlastRepairRequestEventCountsDiagnostics' -count=1
go test ./pkg/probe -count=1
```

Expected: pass.

- [ ] **Step 8: Commit**

```bash
git add pkg/probe/session.go pkg/probe/blast_rate.go pkg/probe/blast_control.go pkg/probe/session_test.go pkg/probe/blast_control_test.go
git commit -m "probe: emit direct udp controller diagnostics"
```

---

### Task 4: Map Probe Diagnostics Into Session Metrics

**Files:**
- Modify: `pkg/session/external_transfer_metrics.go`
- Modify: `pkg/session/external_transfer_metrics_test.go`
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Write failing session metrics tests**

Add this test to `pkg/session/external_transfer_metrics_test.go`:

```go
func TestExternalTransferMetricsMapsProbeDiagnosticsToTrace(t *testing.T) {
	var out strings.Builder
	start := time.UnixMilli(1_000)
	trace, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, start)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	metrics := newExternalTransferMetricsWithTrace(start, trace, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct-execute")
	metrics.SetDirectLimits(700, 1200, 4, 4)
	metrics.SetProbeStats(probe.TransferStats{
		BytesSent:      1_250_000,
		Retransmits:    9,
		MaxReplayBytes: 2_097_152,
		Diagnostics: probe.TransferDiagnostics{
			RateTargetMbps:       263,
			ActiveLanes:          4,
			AvailableLanes:       7,
			ControllerDecision:   "hold",
			ControllerReason:     "initial-hold",
			ReplayBytes:          2_097_152,
			RepairRequests:       2,
			RepairBytes:          16_384,
			DirectPacketBytes:    1_250_000,
			DirectCommittedBytes: 1_000_000,
		},
	})
	metrics.Tick(start.Add(500 * time.Millisecond))
	if err := trace.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	rows := readSessionTraceRows(t, out.String())
	header := rows[0]
	data := rows[len(rows)-1]
	assertSessionTraceField(t, header, data, "rate_target_mbps", "263")
	assertSessionTraceField(t, header, data, "rate_ceiling_mbps", "700")
	assertSessionTraceField(t, header, data, "rate_exploration_ceiling_mbps", "1200")
	assertSessionTraceField(t, header, data, "active_lanes", "4")
	assertSessionTraceField(t, header, data, "available_lanes", "7")
	assertSessionTraceField(t, header, data, "lane_min", "4")
	assertSessionTraceField(t, header, data, "lane_cap", "4")
	assertSessionTraceField(t, header, data, "controller_decision", "hold")
	assertSessionTraceField(t, header, data, "controller_reason", "initial-hold")
	assertSessionTraceField(t, header, data, "replay_bytes", "2097152")
	assertSessionTraceField(t, header, data, "repair_requests", "2")
	assertSessionTraceField(t, header, data, "repair_bytes", "16384")
	assertSessionTraceField(t, header, data, "direct_packet_bytes", "1250000")
	assertSessionTraceField(t, header, data, "direct_committed_bytes", "1000000")
}
```

Add helpers if needed:

```go
func readSessionTraceRows(t *testing.T, text string) [][]string {
	t.Helper()
	rows, err := csv.NewReader(strings.NewReader(text)).ReadAll()
	if err != nil {
		t.Fatalf("ReadAll() error = %v\n%s", err, text)
	}
	return rows
}

func assertSessionTraceField(t *testing.T, header []string, row []string, name string, want string) {
	t.Helper()
	for i, field := range header {
		if field == name {
			if row[i] != want {
				t.Fatalf("%s = %q, want %q", name, row[i], want)
			}
			return
		}
	}
	t.Fatalf("missing header %s", name)
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
go test ./pkg/session -run TestExternalTransferMetricsMapsProbeDiagnosticsToTrace -count=1
```

Expected: fail because `SetDirectLimits` and mapped diagnostic fields do not exist.

- [ ] **Step 3: Extend session metrics state**

In `pkg/session/external_transfer_metrics.go`, add fields to `externalTransferMetrics`:

```go
	directRateTargetMbps        int
	directRateCeilingMbps       int
	directRateExplorationMbps   int
	directLaneMin               int
	directLaneCap               int
	controllerDecision          string
	controllerReason            string
	replayBytes                 uint64
	repairRequests             int64
	repairBytes                 int64
	peerRecvQueueDepth          int
	peerRecvQueueDepthMax       int
	directPacketBytes           int64
	directCommittedBytes        int64
```

Add:

```go
func (m *externalTransferMetrics) SetDirectLimits(rateCeiling int, explorationCeiling int, laneMin int, laneCap int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.directRateCeilingMbps = rateCeiling
	m.directRateExplorationMbps = explorationCeiling
	m.directLaneMin = laneMin
	m.directLaneCap = laneCap
	trace, snap, ok := m.updateTraceLocked(time.Now())
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) SetPeerRecvQueueDepth(current int, maxDepth int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.peerRecvQueueDepth = current
	if maxDepth > m.peerRecvQueueDepthMax {
		m.peerRecvQueueDepthMax = maxDepth
	}
	trace, snap, ok := m.updateTraceLocked(time.Now())
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}
```

In `setProbeStats`, map diagnostics:

```go
	diag := stats.Diagnostics
	if diag.RateTargetMbps > 0 {
		m.directRateTargetMbps = diag.RateTargetMbps
	}
	if diag.RateCeilingMbps > 0 {
		m.directRateCeilingMbps = diag.RateCeilingMbps
	}
	if diag.RateExplorationCeilingMbps > 0 {
		m.directRateExplorationMbps = diag.RateExplorationCeilingMbps
	}
	if diag.ActiveLanes > 0 {
		m.directLanesActive = diag.ActiveLanes
	}
	if diag.AvailableLanes > 0 {
		m.directLanesAvailable = diag.AvailableLanes
	}
	if diag.LaneMin > 0 {
		m.directLaneMin = diag.LaneMin
	}
	if diag.LaneCap > 0 {
		m.directLaneCap = diag.LaneCap
	}
	if diag.ControllerDecision != "" {
		m.controllerDecision = diag.ControllerDecision
		m.controllerReason = diag.ControllerReason
	}
	if diag.ReplayWindowBytes > 0 {
		m.replayWindowBytes = diag.ReplayWindowBytes
	}
	if diag.ReplayBytes > 0 {
		m.replayBytes = diag.ReplayBytes
	}
	if diag.RepairRequests > 0 {
		m.repairRequests = diag.RepairRequests
	}
	if diag.RepairBytes > 0 {
		m.repairBytes = diag.RepairBytes
	}
	if diag.DirectPacketBytes > 0 {
		m.directPacketBytes = diag.DirectPacketBytes
	}
	if diag.DirectCommittedBytes > 0 {
		m.directCommittedBytes = diag.DirectCommittedBytes
	}
```

In `updateTraceLocked`, set the matching `transfertrace.Snapshot` fields:

```go
		RateTargetMbps:             m.directRateTargetMbps,
		RateCeilingMbps:            m.directRateCeilingMbps,
		RateExplorationCeilingMbps: m.directRateExplorationMbps,
		LaneMin:                    m.directLaneMin,
		LaneCap:                    m.directLaneCap,
		ControllerDecision:         m.controllerDecision,
		ControllerReason:           m.controllerReason,
		ReplayBytes:                m.replayBytes,
		RepairRequests:             m.repairRequests,
		RepairBytes:                m.repairBytes,
		PeerRecvQueueDepth:         m.peerRecvQueueDepth,
		PeerRecvQueueDepthMax:      m.peerRecvQueueDepthMax,
		DirectPacketBytes:          m.directPacketBytes,
		DirectCommittedBytes:       m.directCommittedBytes,
```

- [ ] **Step 4: Wire direct UDP plan limits**

In `pkg/session/external_direct_udp.go`, after the `metrics.SetDirectPlan(plan.selectedRateMbps, plan.startRateMbps, len(plan.probeConns), availableLanes)` call in `externalExecutePreparedDirectUDPSend`, add:

```go
	metrics.SetDirectLimits(plan.sendCfg.RateCeilingMbps, plan.sendCfg.RateExplorationCeilingMbps, plan.sendCfg.MinActiveLanes, plan.sendCfg.MaxActiveLanes)
```

In `externalDirectUDPExecuteReceivePlan`, set receive-side limits from `receiveCfg` only when values exist. Receive config does not have rate limits, so do not invent sender values on receive.

- [ ] **Step 5: Run session tests**

Run:

```bash
go test ./pkg/session -run 'TestExternalTransferMetricsMapsProbeDiagnosticsToTrace|TestExternalDirectUDP' -count=1
go test ./pkg/session -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add pkg/session/external_transfer_metrics.go pkg/session/external_transfer_metrics_test.go pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go
git commit -m "session: map direct udp diagnostics into transfer traces"
```

---

### Task 5: Add Transport Queue Depth Sampling

**Files:**
- Modify: `pkg/transport/manager.go`
- Modify: `pkg/transport/manager_test.go`
- Modify: `pkg/session/external_transfer_metrics.go`
- Modify: `pkg/session/external_direct_udp.go`

- [ ] **Step 1: Write failing transport queue accessor test**

Add this test to `pkg/transport/manager_test.go`:

```go
func TestManagerPeerRecvQueueDepthAccessors(t *testing.T) {
	mgr := NewManager(Config{})
	mgr.notePeerRecvDepth(3)
	if got := mgr.PeerRecvQueueDepth(); got != 3 {
		t.Fatalf("PeerRecvQueueDepth() = %d, want 3", got)
	}
	if got := mgr.MaxPeerRecvQueueDepth(); got != 3 {
		t.Fatalf("MaxPeerRecvQueueDepth() = %d, want 3", got)
	}
	mgr.notePeerRecvDepth(1)
	if got := mgr.PeerRecvQueueDepth(); got != 1 {
		t.Fatalf("PeerRecvQueueDepth() after lower depth = %d, want 1", got)
	}
	if got := mgr.MaxPeerRecvQueueDepth(); got != 3 {
		t.Fatalf("MaxPeerRecvQueueDepth() after lower depth = %d, want 3", got)
	}
}
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
go test ./pkg/transport -run TestManagerPeerRecvQueueDepthAccessors -count=1
```

Expected: fail because `PeerRecvQueueDepth` does not exist.

- [ ] **Step 3: Implement current queue depth accessor**

In `pkg/transport/manager.go`, add a field:

```go
	peerRecvQueueDepth int
```

Update `notePeerRecvDepth`:

```go
func (m *Manager) notePeerRecvDepth(depth int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerRecvQueueDepth = depth
	if depth > m.maxPeerRecvQueueDepth {
		m.maxPeerRecvQueueDepth = depth
	}
}
```

Add:

```go
func (m *Manager) PeerRecvQueueDepth() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.peerRecvQueueDepth
}
```

- [ ] **Step 4: Sample queue depth in session metrics**

In `pkg/session/external_transfer_metrics.go`, import `github.com/shayne/derphole/pkg/transport` and add:

```go
	transportManager *transport.Manager
```

Add:

```go
func (m *externalTransferMetrics) AttachTransportManager(manager *transport.Manager) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.transportManager = manager
	m.mu.Unlock()
}
```

At the start of `Tick`, before `updateTraceLocked`, sample the manager:

```go
	if m.transportManager != nil {
		m.peerRecvQueueDepth = m.transportManager.PeerRecvQueueDepth()
		if maxDepth := m.transportManager.MaxPeerRecvQueueDepth(); maxDepth > m.peerRecvQueueDepthMax {
			m.peerRecvQueueDepthMax = maxDepth
		}
	}
```

In `pkg/session/external_direct_udp.go`, after creating metrics in relay-prefix send and receive runtimes, add:

```go
	metrics.AttachTransportManager(rcfg.transportManager)
```

Also add this in direct-UDP-only send and receive paths where `transportManager` is available and metrics are created.

- [ ] **Step 5: Run transport and session tests**

Run:

```bash
go test ./pkg/transport ./pkg/session -run 'PeerRecvQueueDepth|ExternalTransferMetrics' -count=1
go test ./pkg/transport ./pkg/session -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add pkg/transport/manager.go pkg/transport/manager_test.go pkg/session/external_transfer_metrics.go pkg/session/external_direct_udp.go
git commit -m "transport: expose peer receive queue depth to traces"
```

---

### Task 6: Add Diagnostic Benchmark Comparison Script

**Files:**
- Create: `scripts/direct-udp-diagnostic-benchmark.sh`
- Create: `scripts/direct_udp_diagnostic_benchmark_script_test.go`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Write failing script static test**

Create `scripts/direct_udp_diagnostic_benchmark_script_test.go`:

```go
// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectUDPDiagnosticBenchmarkScriptShape(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "direct-udp-diagnostic-benchmark.sh"))
	if err != nil {
		t.Fatalf("read script: %v", err)
	}
	body := string(data)
	for _, want := range []string{
		"usage: $0 <sender-host> <receiver-host> [size-mib]",
		"DERPHOLE_DIAG_LOG_DIR",
		"diagnostic-summary.env",
		"iperf3",
		"transfer-stall-harness.sh",
		"udp-rate-probe-samples",
		"diagnostic-iperf-goodput-mbps=",
		"diagnostic-transfer-sender-goodput-mbps=",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("script missing %q", want)
		}
	}
}
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
go test ./scripts -run TestDirectUDPDiagnosticBenchmarkScriptShape -count=1
```

Expected: fail because the script does not exist.

- [ ] **Step 3: Create benchmark comparison script**

Create `scripts/direct-udp-diagnostic-benchmark.sh`:

```bash
#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

usage() {
  echo "usage: $0 <sender-host> <receiver-host> [size-mib]" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

sender_host="${1:?missing sender host}"
receiver_host="${2:?missing receiver host}"
size_mib="${3:-1024}"
size_bytes="$((size_mib * 1048576))"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
log_dir="${DERPHOLE_DIAG_LOG_DIR:-/tmp/derphole-direct-udp-diagnostic-${stamp}}"
iperf_port="${DERPHOLE_IPERF_PORT:-8321}"
iperf_parallel="${DERPHOLE_IPERF_PARALLEL:-4}"
receiver_iperf_host="${DERPHOLE_DIAG_IPERF_HOST:-${receiver_host#*@}}"

mkdir -p "${log_dir}/iperf" "${log_dir}/transfer"

normalize_target() {
  local target="$1"
  if [[ "${target}" == *"@"* ]]; then
    printf '%s\n' "${target}"
    return 0
  fi
  printf '%s@%s\n' "${DERPHOLE_REMOTE_USER:-root}" "${target}"
}

remote_sh() {
  local target="$1"
  local script="$2"
  LC_ALL=C LANG=C ssh "${target}" 'bash -se' <<<"${script}"
}

sender_target="$(normalize_target "${sender_host}")"
receiver_target="$(normalize_target "${receiver_host}")"

cleanup() {
  if [[ -n "${iperf_server_pid:-}" ]]; then
    remote_sh "${receiver_target}" "kill '${iperf_server_pid}' 2>/dev/null || true" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

remote_sh "${receiver_target}" "
set -euo pipefail
iperf_bin=\"\$(command -v /usr/bin/iperf3 2>/dev/null || command -v iperf3)\"
\"\${iperf_bin}\" -s -4 -p '${iperf_port}' -1 >'/tmp/derphole-diag-iperf-server.log' 2>&1 &
echo \$!
" >"${log_dir}/iperf/server.pid"
iperf_server_pid="$(tr -d '\r\n' <"${log_dir}/iperf/server.pid")"
sleep 1

remote_sh "${sender_target}" "
set -euo pipefail
iperf_bin=\"\$(command -v /usr/bin/iperf3 2>/dev/null || command -v iperf3)\"
\"\${iperf_bin}\" -4 -J -c '${receiver_iperf_host}' -p '${iperf_port}' -n '${size_bytes}' -P '${iperf_parallel}'
" >"${log_dir}/iperf/client.json"
iperf_server_pid=""

remote_sh "${receiver_target}" "cat /tmp/derphole-diag-iperf-server.log 2>/dev/null || true" >"${log_dir}/iperf/server.log"

iperf_goodput="$(python3 - <<'PY' "${log_dir}/iperf/client.json"
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
summary = data.get("end", {}).get("sum_received") or data.get("end", {}).get("sum_sent") or {}
print(f"{float(summary.get('bits_per_second', 0.0)) / 1_000_000.0:.2f}")
PY
)"

DERPHOLE_STALL_LOG_DIR="${log_dir}/transfer" \
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES="${DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES:-1}" \
./scripts/transfer-stall-harness.sh "${sender_host}" "${receiver_host}" "${size_mib}" | tee "${log_dir}/transfer/harness.out"

probe_samples="$(grep -h 'udp-rate-probe-samples=' "${log_dir}/transfer"/sender/* "${log_dir}/transfer"/receiver/* 2>/dev/null | tail -1 | sed 's/^.*udp-rate-probe-samples=//')"
sender_goodput="$(awk -F= '/udp-send-goodput-mbps=/ { value=$2 } END { print value+0 }' "${log_dir}/transfer"/sender/* 2>/dev/null)"
receiver_goodput="$(awk -F= '/udp-receive-goodput-mbps=/ { value=$2 } END { print value+0 }' "${log_dir}/transfer"/receiver/* 2>/dev/null)"

{
  echo "diagnostic-log-dir=${log_dir}"
  echo "diagnostic-size-bytes=${size_bytes}"
  echo "diagnostic-iperf-goodput-mbps=${iperf_goodput}"
  echo "diagnostic-transfer-sender-goodput-mbps=${sender_goodput}"
  echo "diagnostic-transfer-receiver-goodput-mbps=${receiver_goodput}"
  echo "diagnostic-probe-samples=${probe_samples}"
} | tee "${log_dir}/diagnostic-summary.env"
```

Make it executable:

```bash
chmod 0755 scripts/direct-udp-diagnostic-benchmark.sh
```

- [ ] **Step 4: Document the script**

Add this section to `docs/benchmarks.md`:

```markdown
## Direct UDP Diagnostic Comparison

Use `scripts/direct-udp-diagnostic-benchmark.sh` when a transfer completes but runs below expected line rate.

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/direct-udp-diagnostic-benchmark.sh <sender-host> <receiver-host> 1024
```

The script writes `diagnostic-summary.env` with:

- `diagnostic-iperf-goodput-mbps`
- `diagnostic-transfer-sender-goodput-mbps`
- `diagnostic-transfer-receiver-goodput-mbps`
- `diagnostic-probe-samples`

Interpretation:

- high iperf and low probe points at packet engine or UDP socket behavior
- high probe and low transfer points at stream, replay, repair, queue, or controller behavior
- low sender and receiver transfer goodput with high queue depth points at backpressure
```
```

- [ ] **Step 5: Run script tests**

Run:

```bash
go test ./scripts -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add scripts/direct-udp-diagnostic-benchmark.sh scripts/direct_udp_diagnostic_benchmark_script_test.go docs/benchmarks.md
git commit -m "bench: add direct udp diagnostic comparison"
```

---

### Task 7: Full Verification And Live Evidence

**Files:**
- No source edits expected unless verification exposes a bug.

- [ ] **Step 1: Run focused package tests**

Run:

```bash
go test ./pkg/transfertrace ./tools/transfertracecheck ./pkg/probe ./pkg/session ./pkg/transport ./scripts -count=1
```

Expected: pass.

- [ ] **Step 2: Run repository check gate**

Run:

```bash
mise run check
```

Expected: pass.

- [ ] **Step 3: Run one live direct transfer with expanded traces**

Run:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPHOLE_STALL_TIMEOUT_SEC=30 ./scripts/transfer-stall-harness.sh <sender-host> <receiver-host> 1024
```

Also run a second independent live target when available:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPHOLE_STALL_TIMEOUT_SEC=30 ./scripts/transfer-stall-harness.sh <sender-host> <independent-receiver-host> 1024
```

Expected:

- sender status `0`
- receiver status `0`
- source and sink sizes match
- SHA-256 values match
- sender and receiver trace checks pass
- sender trace contains `rate_target_mbps`
- sender trace contains `peer_recv_queue_depth_max`
- receiver trace contains `receiver_committed_mbps`

- [ ] **Step 4: Run diagnostic comparison when iperf3 is available**

Run:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/direct-udp-diagnostic-benchmark.sh <sender-host> <receiver-host> 1024
```

Also run a second independent live target when available:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/direct-udp-diagnostic-benchmark.sh <sender-host> <independent-receiver-host> 1024
```

Expected:

- `diagnostic-summary.env` exists in the log directory
- `diagnostic-iperf-goodput-mbps` is present
- `diagnostic-probe-samples` is present
- `diagnostic-transfer-sender-goodput-mbps` is present
- `diagnostic-transfer-receiver-goodput-mbps` is present

If the iperf step fails because the remote pair cannot route the chosen iperf host or firewall rules block the port, keep the transfer-stall-harness evidence and record the iperf failure in the final verification summary.

- [ ] **Step 5: Inspect trace diagnostic fields**

Run this against the latest stall harness log directory:

```bash
log_dir="$(ls -td /tmp/derphole-stall-* | head -1)"
head -1 "${log_dir}/sender/send.trace.csv" | tr ',' '\n' | rg 'rate_target_mbps|receiver_committed_mbps|peer_recv_queue_depth_max|replay_bytes|repair_requests'
tail -5 "${log_dir}/sender/send.trace.csv"
tail -5 "${log_dir}/receiver/receive.trace.csv"
```

Expected:

- all diagnostic column names are present
- terminal rows have `complete` phase
- diagnostic columns are populated on sender where sender knows the values
- role-specific unknowns are empty instead of fabricated

- [ ] **Step 6: Commit final verification notes if docs changed**

If verification requires updating `docs/benchmarks.md`, commit that doc update:

```bash
git add docs/benchmarks.md
git commit -m "docs: document direct udp diagnostic verification"
```

If no docs changed, do not create an empty commit.

- [ ] **Step 7: Push**

Run:

```bash
git status --short --branch
git push
```

Expected: `main` pushes cleanly to `origin/main`.
