# Wormhole-Informed Benchmark Gate And Dynamic Direct UDP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reproducible benchmark gate for this Mac plus `ktzlxc`, `canlxc`, `uklxc`, and `orange-india.exe.xyz`, then harden derphole's relay-first/direct-UDP path so total wall time improves, peak throughput stays near WAN ceiling, and slower WAN links stop failing under default settings.

**Architecture:** Keep derphole's current DERP-coordinated relay-first startup and direct-UDP fast path. Borrow from magic-wormhole only the disciplined parts: explicit contender/winner reasoning, delayed fallback, bounded backpressure, and durable telemetry. Extend the existing probe/session stats with interval-based metrics, feed those metrics into the current adaptive blast controller, and add a Go-driven benchmark matrix that compares baseline vs candidate across all four remotes in both directions.

**Tech Stack:** Go, bash, existing `cmd/derphole-probe`, `pkg/probe`, `pkg/session`, `mise`, `nix run nixpkgs#iperf3`, Ookla `speedtest`

---

## File Map

- Create: `pkg/probe/benchmark_matrix.go`
  Purpose: summarize repeated benchmark runs by host/direction and compare baseline vs candidate.
- Create: `pkg/probe/benchmark_matrix_test.go`
  Purpose: unit tests for aggregate totals, averages, peaks, and regression verdicts.
- Create: `pkg/probe/interval_stats.go`
  Purpose: interval-based throughput trackers for peak and sustained rate measurements.
- Create: `pkg/probe/interval_stats_test.go`
  Purpose: unit tests for interval accounting and peak-rate tracking.
- Modify: `pkg/probe/report.go`
  Purpose: add per-run fields needed by the benchmark gate without breaking existing JSON consumers.
- Modify: `pkg/probe/report_test.go`
  Purpose: lock JSON/markdown output and make sure sensitive command details stay excluded.
- Modify: `pkg/probe/blast_control.go`
  Purpose: let the existing adaptive controller use interval and replay-pressure signals instead of only final counters.
- Modify: `pkg/probe/blast_control_test.go`
  Purpose: verify rate growth, backoff, and slow-link behavior.
- Modify: `pkg/probe/session.go`
  Purpose: record per-run peak throughput, ACK progress, replay pressure, and interval snapshots.
- Modify: `pkg/probe/session_test.go`
  Purpose: benchmark and unit-test the new probe metrics without regressing the hot path.
- Create: `pkg/session/external_transfer_metrics.go`
  Purpose: session-wide wall-clock metrics spanning relay-prefix bytes and direct-UDP suffix bytes.
- Create: `pkg/session/external_transfer_metrics_test.go`
  Purpose: unit tests for total wall time, first-byte delay, relay/direct byte splits, and emitted summary lines.
- Modify: `pkg/session/external_direct_udp.go`
  Purpose: emit session-wide summary metrics and tighten dynamic start/rate/window decisions.
- Modify: `pkg/session/external_direct_udp_test.go`
  Purpose: verify ktzlxc-style high-ceiling behavior is preserved while slower links scale down cleanly.
- Create: `cmd/derphole-probe/matrix.go`
  Purpose: run the 10x both-direction benchmark matrix over the production `promotion-test` harnesses and write JSON/markdown artifacts.
- Create: `cmd/derphole-probe/matrix_test.go`
  Purpose: test host iteration, output parsing, and baseline-vs-candidate verdicts with fake command runners.
- Modify: `cmd/derphole-probe/root.go`
  Purpose: register the new `matrix` subcommand.
- Modify: `scripts/promotion-test.sh`
  Purpose: append a stable `benchmark-*` key/value footer after SHA and cleanup verification.
- Modify: `scripts/promotion-test-reverse.sh`
  Purpose: append the same `benchmark-*` footer for reverse runs.
- Modify: `scripts/promotion-matrix-no-tailscale.sh`
  Purpose: switch to the four remote hosts used by the benchmark gate.
- Modify: `docs/benchmarks.md`
  Purpose: document the new matrix runner, host set, baseline commands, and regression gate.
- Create: `docs/benchmarks/2026-04-11-wormhole-audit-baseline.md`
  Purpose: store the pre-change baseline and the post-change comparison in one checked-in note.

### Task 1: Add Benchmark Summaries And Regression Verdicts

**Files:**
- Create: `pkg/probe/benchmark_matrix.go`
- Create: `pkg/probe/benchmark_matrix_test.go`
- Modify: `pkg/probe/report.go`
- Modify: `pkg/probe/report_test.go`

- [ ] **Step 1: Write the failing tests**

```go
package probe

import "testing"

func TestSummarizeRunsComputesWallPeakAverageAndFailures(t *testing.T) {
	runs := []RunReport{
		{Host: "ktzlxc", Direction: "forward", SizeBytes: 1 << 30, BytesReceived: 1 << 30, DurationMS: 4200, GoodputMbps: 2045.0, PeakGoodputMbps: 2220.0, Success: true},
		{Host: "ktzlxc", Direction: "forward", SizeBytes: 1 << 30, BytesReceived: 1 << 30, DurationMS: 4700, GoodputMbps: 1828.0, PeakGoodputMbps: 2140.0, Success: true},
		{Host: "ktzlxc", Direction: "forward", SizeBytes: 1 << 30, BytesReceived: 0, DurationMS: 30000, GoodputMbps: 0, PeakGoodputMbps: 0, Success: false, Error: "timed out"},
	}

	got := SummarizeRuns("ktzlxc", "forward", runs)
	if got.Runs != 3 || got.Successes != 2 || got.Failures != 1 {
		t.Fatalf("summary counts = %+v", got)
	}
	if got.TotalDurationMS != 38900 {
		t.Fatalf("TotalDurationMS = %d, want 38900", got.TotalDurationMS)
	}
	if got.PeakGoodputMbps != 2220.0 {
		t.Fatalf("PeakGoodputMbps = %.1f, want 2220.0", got.PeakGoodputMbps)
	}
	if got.AverageGoodputMbps <= 1900 || got.AverageGoodputMbps >= 1950 {
		t.Fatalf("AverageGoodputMbps = %.2f, want weighted average between 1900 and 1950", got.AverageGoodputMbps)
	}
}

func TestCompareSummariesRejectsWallTimeAndFailureRegression(t *testing.T) {
	baseline := SeriesSummary{
		Host:               "canlxc",
		Direction:          "reverse",
		Runs:               10,
		Successes:          10,
		Failures:           0,
		TotalDurationMS:    92000,
		AverageGoodputMbps: 910.0,
		PeakGoodputMbps:    1080.0,
	}
	candidate := SeriesSummary{
		Host:               "canlxc",
		Direction:          "reverse",
		Runs:               10,
		Successes:          8,
		Failures:           2,
		TotalDurationMS:    118000,
		AverageGoodputMbps: 702.0,
		PeakGoodputMbps:    1110.0,
	}

	got := CompareSummaries(baseline, candidate)
	if got.Pass {
		t.Fatalf("CompareSummaries() = %+v, want failing regression result", got)
	}
	if len(got.Reasons) < 2 {
		t.Fatalf("Reasons = %#v, want wall-time and failure reasons", got.Reasons)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./pkg/probe -run 'TestSummarizeRunsComputesWallPeakAverageAndFailures|TestCompareSummariesRejectsWallTimeAndFailureRegression' -count=1`

Expected: FAIL with undefined `SummarizeRuns`, `SeriesSummary`, `CompareSummaries`, and missing `PeakGoodputMbps` / `Success` fields on `RunReport`.

- [ ] **Step 3: Write the minimal implementation**

```go
package probe

type RunReport struct {
	Host             string        `json:"host"`
	Mode             string        `json:"mode"`
	Transport        string        `json:"transport,omitempty"`
	Direction        string        `json:"direction"`
	SizeBytes        int64         `json:"size_bytes"`
	BytesReceived    int64         `json:"bytes_received"`
	DurationMS       int64         `json:"duration_ms"`
	GoodputMbps      float64       `json:"goodput_mbps"`
	PeakGoodputMbps  float64       `json:"peak_goodput_mbps,omitempty"`
	Direct           bool          `json:"direct"`
	FirstByteMS      int64         `json:"first_byte_ms"`
	LossRate         float64       `json:"loss_rate"`
	Retransmits      int64         `json:"retransmits"`
	Success          bool          `json:"success"`
	Error            string        `json:"error,omitempty"`
	Local            TransportCaps `json:"local,omitempty"`
	Remote           TransportCaps `json:"remote,omitempty"`
}

type SeriesSummary struct {
	Host               string   `json:"host"`
	Direction          string   `json:"direction"`
	Runs               int      `json:"runs"`
	Successes          int      `json:"successes"`
	Failures           int      `json:"failures"`
	TotalDurationMS    int64    `json:"total_duration_ms"`
	AverageGoodputMbps float64  `json:"average_goodput_mbps"`
	PeakGoodputMbps    float64  `json:"peak_goodput_mbps"`
	FailureMessages    []string `json:"failure_messages,omitempty"`
}

type RegressionResult struct {
	Pass    bool     `json:"pass"`
	Reasons []string `json:"reasons,omitempty"`
}

func SummarizeRuns(host, direction string, runs []RunReport) SeriesSummary {
	out := SeriesSummary{Host: host, Direction: direction, Runs: len(runs)}
	var weightedMbps float64
	var weightedDuration float64
	for _, run := range runs {
		out.TotalDurationMS += run.DurationMS
		if run.Success {
			out.Successes++
			weightedMbps += run.GoodputMbps * float64(run.DurationMS)
			weightedDuration += float64(run.DurationMS)
		} else {
			out.Failures++
			if run.Error != "" {
				out.FailureMessages = append(out.FailureMessages, run.Error)
			}
		}
		if run.PeakGoodputMbps > out.PeakGoodputMbps {
			out.PeakGoodputMbps = run.PeakGoodputMbps
		}
	}
	if weightedDuration > 0 {
		out.AverageGoodputMbps = weightedMbps / weightedDuration
	}
	return out
}

func CompareSummaries(baseline, candidate SeriesSummary) RegressionResult {
	out := RegressionResult{Pass: true}
	if candidate.Failures > baseline.Failures {
		out.Pass = false
		out.Reasons = append(out.Reasons, "failure count regressed")
	}
	if candidate.TotalDurationMS > baseline.TotalDurationMS {
		out.Pass = false
		out.Reasons = append(out.Reasons, "total wall time regressed")
	}
	if candidate.AverageGoodputMbps < baseline.AverageGoodputMbps {
		out.Pass = false
		out.Reasons = append(out.Reasons, "average throughput regressed")
	}
	return out
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./pkg/probe -run 'TestSummarizeRunsComputesWallPeakAverageAndFailures|TestCompareSummariesRejectsWallTimeAndFailureRegression|TestMarkdownReportIncludesCoreMetrics|TestRunReportJSONEncodesCoreMetrics' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/probe/report.go pkg/probe/report_test.go pkg/probe/benchmark_matrix.go pkg/probe/benchmark_matrix_test.go
git commit -m "probe: add benchmark summary and regression types"
```

### Task 2: Record Interval-Based Peak Throughput In The Probe Data Plane

**Files:**
- Create: `pkg/probe/interval_stats.go`
- Create: `pkg/probe/interval_stats_test.go`
- Modify: `pkg/probe/session.go`
- Modify: `pkg/probe/session_test.go`
- Modify: `pkg/probe/blast_control.go`
- Modify: `pkg/probe/blast_control_test.go`

- [ ] **Step 1: Write the failing tests**

```go
package probe

import (
	"testing"
	"time"
)

func TestIntervalStatsTracksPeakRateAcrossBursts(t *testing.T) {
	start := time.Unix(0, 0)
	stats := newIntervalStats(100 * time.Millisecond)

	stats.Observe(start, 0)
	stats.Observe(start.Add(100*time.Millisecond), 12_500_000)
	stats.Observe(start.Add(200*time.Millisecond), 18_750_000)

	if got := stats.PeakMbps(); got < 900 || got > 1100 {
		t.Fatalf("PeakMbps() = %.2f, want about 1000 Mbps", got)
	}
}

func TestTransferStatsExposePeakGoodputFromSendLoop(t *testing.T) {
	ts := TransferStats{}
	ts.RecordSendSample(time.Unix(0, 0), 0)
	ts.RecordSendSample(time.Unix(0, int64(100*time.Millisecond)), 25_000_000)
	if ts.PeakGoodputMbps < 1900 || ts.PeakGoodputMbps > 2100 {
		t.Fatalf("PeakGoodputMbps = %.2f, want about 2000 Mbps", ts.PeakGoodputMbps)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./pkg/probe -run 'TestIntervalStatsTracksPeakRateAcrossBursts|TestTransferStatsExposePeakGoodputFromSendLoop' -count=1`

Expected: FAIL with undefined `newIntervalStats`, `PeakMbps`, and `RecordSendSample`.

- [ ] **Step 3: Write the minimal implementation**

```go
package probe

import "time"

type intervalStats struct {
	interval   time.Duration
	lastAt     time.Time
	lastBytes  int64
	peakMbps   float64
}

func newIntervalStats(interval time.Duration) *intervalStats {
	return &intervalStats{interval: interval}
}

func (s *intervalStats) Observe(now time.Time, totalBytes int64) float64 {
	if s.lastAt.IsZero() {
		s.lastAt = now
		s.lastBytes = totalBytes
		return 0
	}
	deltaT := now.Sub(s.lastAt)
	if deltaT <= 0 {
		return 0
	}
	deltaB := totalBytes - s.lastBytes
	if deltaB < 0 {
		deltaB = 0
	}
	mbps := float64(deltaB*8) / deltaT.Seconds() / 1_000_000
	if mbps > s.peakMbps {
		s.peakMbps = mbps
	}
	s.lastAt = now
	s.lastBytes = totalBytes
	return mbps
}

func (s *intervalStats) PeakMbps() float64 {
	if s == nil {
		return 0
	}
	return s.peakMbps
}

type TransferStats struct {
	BytesSent                    int64
	BytesReceived                int64
	PacketsSent                  int64
	PacketsAcked                 int64
	Retransmits                  int64
	Lanes                        int
	StartedAt                    time.Time
	CompletedAt                  time.Time
	FirstByteAt                  time.Time
	Transport                    TransportCaps
	MaxReplayBytes               uint64
	ReplayWindowFullWaits        int64
	ReplayWindowFullWaitDuration time.Duration
	PeakGoodputMbps              float64

	sendIntervals *intervalStats
	recvIntervals *intervalStats
}

func (s *TransferStats) RecordSendSample(now time.Time, totalBytes int64) {
	if s.sendIntervals == nil {
		s.sendIntervals = newIntervalStats(100 * time.Millisecond)
	}
	mbps := s.sendIntervals.Observe(now, totalBytes)
	if mbps > s.PeakGoodputMbps {
		s.PeakGoodputMbps = mbps
	}
}

func (s *TransferStats) RecordReceiveSample(now time.Time, totalBytes int64) {
	if s.recvIntervals == nil {
		s.recvIntervals = newIntervalStats(100 * time.Millisecond)
	}
	mbps := s.recvIntervals.Observe(now, totalBytes)
	if mbps > s.PeakGoodputMbps {
		s.PeakGoodputMbps = mbps
	}
}
```

- [ ] **Step 4: Run the tests and the hot-path benchmarks**

Run: `go test ./pkg/probe -run 'TestIntervalStatsTracksPeakRateAcrossBursts|TestTransferStatsExposePeakGoodputFromSendLoop|TestHandleBlastSendControlEventUpdatesAdaptiveRate' -count=1`

Expected: PASS

Run: `go test ./pkg/probe -bench 'BenchmarkStreamReplayWindowAddAck|BenchmarkBlastStreamReceiveCoordinatorStripedDiscardParallel' -benchmem -count=1`

Expected: PASS, with no material allocation regression versus the current branch.

- [ ] **Step 5: Commit**

```bash
git add pkg/probe/interval_stats.go pkg/probe/interval_stats_test.go pkg/probe/session.go pkg/probe/session_test.go pkg/probe/blast_control.go pkg/probe/blast_control_test.go
git commit -m "probe: track interval peak throughput"
```

### Task 3: Emit Session-Wide Wall-Clock Metrics Across Relay Prefix And Direct UDP

**Files:**
- Create: `pkg/session/external_transfer_metrics.go`
- Create: `pkg/session/external_transfer_metrics_test.go`
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Write the failing tests**

```go
package session

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/probe"
	"github.com/shayne/derphole/pkg/telemetry"
)

func TestExternalTransferMetricsTrackRelayAndDirectBytes(t *testing.T) {
	start := time.Unix(0, 0)
	m := newExternalTransferMetrics(start)
	m.RecordRelayWrite(32<<10, start.Add(20*time.Millisecond))
	m.RecordDirectWrite(1<<20, start.Add(450*time.Millisecond))
	m.Complete(start.Add(1450 * time.Millisecond))

	if got := m.TotalDurationMS(); got != 1450 {
		t.Fatalf("TotalDurationMS() = %d, want 1450", got)
	}
	if got := m.FirstByteMS(); got != 20 {
		t.Fatalf("FirstByteMS() = %d, want 20", got)
	}
	if got := m.DirectBytes(); got != 1<<20 {
		t.Fatalf("DirectBytes() = %d, want %d", got, 1<<20)
	}
}

func TestEmitExternalTransferMetricsIncludesWallAndPeakValues(t *testing.T) {
	start := time.Unix(0, 0)
	m := newExternalTransferMetrics(start)
	m.RecordRelayWrite(64<<10, start.Add(15*time.Millisecond))
	m.RecordDirectWrite(1<<20, start.Add(300*time.Millisecond))
	m.Complete(start.Add(1300 * time.Millisecond))

	var buf bytes.Buffer
	emitter := telemetry.New(&buf, telemetry.LevelVerbose)
	m.Emit(emitter, "udp-send", probe.TransferStats{PeakGoodputMbps: 2011.4})

	got := buf.String()
	for _, needle := range []string{
		"udp-send-wall-duration-ms=1300",
		"udp-send-session-first-byte-ms=15",
		"udp-send-relay-bytes=65536",
		"udp-send-direct-bytes=1048576",
		"udp-send-peak-goodput-mbps=2011.40",
	} {
		if !strings.Contains(got, needle) {
			t.Fatalf("metrics output missing %q in %q", needle, got)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./pkg/session -run 'TestExternalTransferMetricsTrackRelayAndDirectBytes|TestEmitExternalTransferMetricsIncludesWallAndPeakValues' -count=1`

Expected: FAIL with undefined `newExternalTransferMetrics`, `RecordRelayWrite`, `RecordDirectWrite`, and `Emit`.

- [ ] **Step 3: Write the minimal implementation**

```go
package session

import (
	"strconv"
	"time"

	"github.com/shayne/derphole/pkg/probe"
	"github.com/shayne/derphole/pkg/telemetry"
)

type externalTransferMetrics struct {
	startedAt        time.Time
	completedAt      time.Time
	firstByteAt      time.Time
	relayBytes       int64
	directBytes      int64
}

func newExternalTransferMetrics(startedAt time.Time) *externalTransferMetrics {
	return &externalTransferMetrics{startedAt: startedAt}
}

func (m *externalTransferMetrics) RecordRelayWrite(n int64, at time.Time) {
	if n <= 0 {
		return
	}
	m.relayBytes += n
	if m.firstByteAt.IsZero() || at.Before(m.firstByteAt) {
		m.firstByteAt = at
	}
}

func (m *externalTransferMetrics) RecordDirectWrite(n int64, at time.Time) {
	if n <= 0 {
		return
	}
	m.directBytes += n
	if m.firstByteAt.IsZero() || at.Before(m.firstByteAt) {
		m.firstByteAt = at
	}
}

func (m *externalTransferMetrics) Complete(at time.Time) {
	m.completedAt = at
}

func (m *externalTransferMetrics) TotalDurationMS() int64 {
	return m.completedAt.Sub(m.startedAt).Milliseconds()
}

func (m *externalTransferMetrics) FirstByteMS() int64 {
	if m.firstByteAt.IsZero() {
		return 0
	}
	return m.firstByteAt.Sub(m.startedAt).Milliseconds()
}

func (m *externalTransferMetrics) DirectBytes() int64 {
	return m.directBytes
}

func (m *externalTransferMetrics) Emit(emitter *telemetry.Emitter, prefix string, stats probe.TransferStats) {
	if emitter == nil {
		return
	}
	emitter.Debug(prefix + "-wall-duration-ms=" + strconv.FormatInt(m.TotalDurationMS(), 10))
	emitter.Debug(prefix + "-session-first-byte-ms=" + strconv.FormatInt(m.FirstByteMS(), 10))
	emitter.Debug(prefix + "-relay-bytes=" + strconv.FormatInt(m.relayBytes, 10))
	emitter.Debug(prefix + "-direct-bytes=" + strconv.FormatInt(m.directBytes, 10))
	emitter.Debug(prefix + "-peak-goodput-mbps=" + strconv.FormatFloat(stats.PeakGoodputMbps, 'f', 2, 64))
}
```

- [ ] **Step 4: Wire the helper into the stdio send/receive path and run tests**

Run: `go test ./pkg/session -run 'TestExternalTransferMetricsTrackRelayAndDirectBytes|TestEmitExternalTransferMetricsIncludesWallAndPeakValues|TestSendExternalHandoffDERPStopBeforeRelayProgressStillStartsRelayData|TestExternalDirectUDPDefaultUsesStripedStreamLanes' -count=1`

Expected: PASS

Run: `go test ./pkg/session -bench BenchmarkExternalStripedCopy256MiB4Stripes -benchmem -count=1`

Expected: PASS, with no material allocation regression.

- [ ] **Step 5: Commit**

```bash
git add pkg/session/external_transfer_metrics.go pkg/session/external_transfer_metrics_test.go pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go
git commit -m "session: emit wall clock direct udp metrics"
```

### Task 4: Add A Go-Driven 10x Matrix Runner For The Production Harness

**Files:**
- Create: `cmd/derphole-probe/matrix.go`
- Create: `cmd/derphole-probe/matrix_test.go`
- Modify: `cmd/derphole-probe/root.go`
- Modify: `scripts/promotion-test.sh`
- Modify: `scripts/promotion-test-reverse.sh`
- Modify: `scripts/promotion-matrix-no-tailscale.sh`

- [ ] **Step 1: Write the failing tests**

```go
package main

import (
	"context"
	"strings"
	"testing"
)

func TestParsePromotionSummaryReadsBenchmarkFooter(t *testing.T) {
	raw := strings.Join([]string{
		"target=ktzlxc",
		"size_mib=1024",
		"benchmark-host=ktzlxc",
		"benchmark-direction=forward",
		"benchmark-size-bytes=1073741824",
		"benchmark-total-duration-ms=4210",
		"benchmark-goodput-mbps=2039.1",
		"benchmark-peak-goodput-mbps=2210.4",
		"benchmark-first-byte-ms=18",
		"benchmark-success=true",
	}, "\n")

	got, err := parsePromotionSummary([]byte(raw))
	if err != nil {
		t.Fatalf("parsePromotionSummary() error = %v", err)
	}
	if got.Host != "ktzlxc" || got.Direction != "forward" || got.PeakGoodputMbps != 2210.4 || !got.Success {
		t.Fatalf("parsePromotionSummary() = %+v", got)
	}
}

func TestRunMatrixIteratesAllHostsDirectionsAndIterations(t *testing.T) {
	var calls []string
	runMatrixCommand = func(_ context.Context, script string, host string, sizeMiB int) ([]byte, error) {
		calls = append(calls, script+":"+host)
		return []byte(strings.Join([]string{
			"benchmark-host=" + host,
			"benchmark-direction=forward",
			"benchmark-size-bytes=1073741824",
			"benchmark-total-duration-ms=5000",
			"benchmark-goodput-mbps=1700.0",
			"benchmark-peak-goodput-mbps=2000.0",
			"benchmark-success=true",
		}, "\n")), nil
	}

	_, err := runMatrix(context.Background(), matrixConfig{
		Hosts:      []string{"ktzlxc", "canlxc"},
		Iterations: 2,
		SizeMiB:    1024,
	})
	if err != nil {
		t.Fatalf("runMatrix() error = %v", err)
	}
	if got, want := len(calls), 8; got != want {
		t.Fatalf("len(calls) = %d, want %d", got, want)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/derphole-probe -run 'TestParsePromotionSummaryReadsBenchmarkFooter|TestRunMatrixIteratesAllHostsDirectionsAndIterations' -count=1`

Expected: FAIL with undefined `parsePromotionSummary`, `runMatrix`, `matrixConfig`, and `runMatrixCommand`.

- [ ] **Step 3: Write the minimal implementation**

```go
package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/shayne/derphole/pkg/probe"
)

type matrixConfig struct {
	Hosts      []string
	Iterations int
	SizeMiB    int
}

var runMatrixCommand = func(ctx context.Context, script string, host string, sizeMiB int) ([]byte, error) {
	cmd := exec.CommandContext(ctx, script, host, strconv.Itoa(sizeMiB))
	return cmd.CombinedOutput()
}

func parsePromotionSummary(raw []byte) (probe.RunReport, error) {
	var out probe.RunReport
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		text := string(bytes.TrimSpace(line))
		switch {
		case strings.HasPrefix(text, "benchmark-host="):
			out.Host = strings.TrimPrefix(text, "benchmark-host=")
		case strings.HasPrefix(text, "benchmark-direction="):
			out.Direction = strings.TrimPrefix(text, "benchmark-direction=")
		case strings.HasPrefix(text, "benchmark-size-bytes="):
			out.SizeBytes, _ = strconv.ParseInt(strings.TrimPrefix(text, "benchmark-size-bytes="), 10, 64)
		case strings.HasPrefix(text, "benchmark-total-duration-ms="):
			out.DurationMS, _ = strconv.ParseInt(strings.TrimPrefix(text, "benchmark-total-duration-ms="), 10, 64)
		case strings.HasPrefix(text, "benchmark-goodput-mbps="):
			out.GoodputMbps, _ = strconv.ParseFloat(strings.TrimPrefix(text, "benchmark-goodput-mbps="), 64)
		case strings.HasPrefix(text, "benchmark-peak-goodput-mbps="):
			out.PeakGoodputMbps, _ = strconv.ParseFloat(strings.TrimPrefix(text, "benchmark-peak-goodput-mbps="), 64)
		case strings.HasPrefix(text, "benchmark-first-byte-ms="):
			out.FirstByteMS, _ = strconv.ParseInt(strings.TrimPrefix(text, "benchmark-first-byte-ms="), 10, 64)
		case strings.HasPrefix(text, "benchmark-success="):
			out.Success = strings.TrimPrefix(text, "benchmark-success=") == "true"
		case strings.HasPrefix(text, "benchmark-error="):
			out.Error = strings.TrimPrefix(text, "benchmark-error=")
		}
	}
	if out.Host == "" || out.Direction == "" {
		return probe.RunReport{}, fmt.Errorf("missing benchmark footer in output")
	}
	return out, nil
}

func runMatrix(ctx context.Context, cfg matrixConfig) ([]probe.RunReport, error) {
	var out []probe.RunReport
	for _, host := range cfg.Hosts {
		for i := 0; i < cfg.Iterations; i++ {
			for _, tc := range []struct {
				script    string
				direction string
			}{
				{script: "./scripts/promotion-test.sh", direction: "forward"},
				{script: "./scripts/promotion-test-reverse.sh", direction: "reverse"},
			} {
				raw, err := runMatrixCommand(ctx, tc.script, host, cfg.SizeMiB)
				if err != nil {
					return nil, err
				}
				report, err := parsePromotionSummary(raw)
				if err != nil {
					return nil, err
				}
				report.Direction = tc.direction
				out = append(out, report)
			}
		}
	}
	return out, nil
}
```

- [ ] **Step 4: Add the benchmark footer and run the tests**

```bash
sender_goodput_mbps="$(sed -n 's/^udp-send-goodput-mbps=//p' "${send_log}" | tail -n 1)"
sender_peak_goodput_mbps="$(sed -n 's/^udp-send-peak-goodput-mbps=//p' "${send_log}" | tail -n 1)"
sender_first_byte_ms="$(sed -n 's/^udp-send-session-first-byte-ms=//p' "${send_log}" | tail -n 1)"

echo "benchmark-host=${target}"
echo "benchmark-direction=forward"
echo "benchmark-size-bytes=${expected_size}"
echo "benchmark-total-duration-ms=$((duration * 1000))"
echo "benchmark-goodput-mbps=${sender_goodput_mbps}"
echo "benchmark-peak-goodput-mbps=${sender_peak_goodput_mbps}"
echo "benchmark-first-byte-ms=${sender_first_byte_ms}"
echo "benchmark-success=true"
```

Run: `go test ./cmd/derphole-probe -run 'TestParsePromotionSummaryReadsBenchmarkFooter|TestRunMatrixIteratesAllHostsDirectionsAndIterations' -count=1`

Expected: PASS

Run: `bash -n scripts/promotion-test.sh scripts/promotion-test-reverse.sh scripts/promotion-matrix-no-tailscale.sh`

Expected: PASS with no shell syntax errors.

- [ ] **Step 5: Commit**

```bash
git add cmd/derphole-probe/matrix.go cmd/derphole-probe/matrix_test.go cmd/derphole-probe/root.go scripts/promotion-test.sh scripts/promotion-test-reverse.sh scripts/promotion-matrix-no-tailscale.sh
git commit -m "probe: add production benchmark matrix runner"
```

### Task 5: Tighten Dynamic Rate And Window Scaling For Slow WAN Links Without Regressing ktzlxc

**Files:**
- Modify: `pkg/probe/blast_control.go`
- Modify: `pkg/probe/blast_control_test.go`
- Modify: `pkg/probe/session.go`
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Write the failing tests**

```go
package session

import (
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/probe"
)

func TestExternalDirectUDPStartBudgetScalesDownForSlowCeilings(t *testing.T) {
	got := externalDirectUDPStartBudget(85)
	if got.RateMbps != 85 || got.ActiveLanes != 1 {
		t.Fatalf("externalDirectUDPStartBudget(85) = %+v, want rate=85 lanes=1", got)
	}
}

func TestExternalDirectUDPStartBudgetPreservesHighCeilingShape(t *testing.T) {
	got := externalDirectUDPStartBudget(2250)
	if got.ActiveLanes != 8 {
		t.Fatalf("externalDirectUDPStartBudget(2250) lanes = %d, want 8", got.ActiveLanes)
	}
	if got.RateMbps < 1000 {
		t.Fatalf("externalDirectUDPStartBudget(2250) rate = %d, want aggressive high-ceiling start", got.RateMbps)
	}
}

func TestBlastSendControlBacksOffOnReplayPressureBeforeTimeout(t *testing.T) {
	now := time.Unix(0, 0)
	control := probe.NewBlastSendControlForTest(900, 1200, now)
	before := control.RateMbps()
	control.ObserveReplayPressure(now.Add(2*time.Second), 96<<20, 128<<20)
	if control.RateMbps() >= before {
		t.Fatalf("RateMbps() = %d, want lower than %d after replay pressure", control.RateMbps(), before)
	}
}

func TestBlastSendControlRegrowsWithinCleanWindow(t *testing.T) {
	now := time.Unix(0, 0)
	control := probe.NewBlastSendControlForTest(250, 900, now)
	control.ObserveReceiverStatsPayload(probe.BlastReceiverStatsForTest(32<<20, 24000, 24032, 24032), now.Add(100*time.Millisecond), true)
	control.ObserveReceiverStatsPayload(probe.BlastReceiverStatsForTest(64<<20, 48000, 48032, 48032), now.Add(2500*time.Millisecond), true)
	if control.RateMbps() <= 250 {
		t.Fatalf("RateMbps() = %d, want clean regrowth above start rate", control.RateMbps())
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./pkg/session -run 'TestExternalDirectUDPStartBudgetScalesDownForSlowCeilings|TestExternalDirectUDPStartBudgetPreservesHighCeilingShape' -count=1`

Expected: FAIL with undefined `externalDirectUDPStartBudget`.

Run: `go test ./pkg/probe -run 'TestHandleBlastSendControlEventUpdatesAdaptiveRate|TestHandleBlastSendControlEventRepairRequestBacksOffAdaptiveRate' -count=1`

Expected: either FAIL after you add the new assertions, or PASS for the old behavior but without the new floor/ceiling logic.

- [ ] **Step 3: Write the minimal implementation**

```go
package session

type externalDirectUDPBudget struct {
	RateMbps         int
	ActiveLanes      int
	ReplayWindowBytes uint64
}

func externalDirectUDPStartBudget(rateCeilingMbps int) externalDirectUDPBudget {
	if rateCeilingMbps <= 0 {
		return externalDirectUDPBudget{RateMbps: externalDirectUDPRateProbeMinMbps, ActiveLanes: 1, ReplayWindowBytes: 16 << 20}
	}
	switch {
	case rateCeilingMbps <= 100:
		return externalDirectUDPBudget{RateMbps: rateCeilingMbps, ActiveLanes: 1, ReplayWindowBytes: 16 << 20}
	case rateCeilingMbps <= 350:
		return externalDirectUDPBudget{RateMbps: min(rateCeilingMbps, 250), ActiveLanes: 1, ReplayWindowBytes: 32 << 20}
	case rateCeilingMbps <= 700:
		return externalDirectUDPBudget{RateMbps: min(rateCeilingMbps, 525), ActiveLanes: 2, ReplayWindowBytes: 64 << 20}
	case rateCeilingMbps <= 1200:
		return externalDirectUDPBudget{RateMbps: min(rateCeilingMbps, 900), ActiveLanes: 4, ReplayWindowBytes: 96 << 20}
	default:
		return externalDirectUDPBudget{RateMbps: min(rateCeilingMbps, externalDirectUDPDataStartHighMbps), ActiveLanes: 8, ReplayWindowBytes: externalDirectUDPStreamReplayBytes}
	}
}
```

```go
package probe

import "time"

func NewBlastSendControlForTest(rateMbps int, ceilingMbps int, now time.Time) *blastSendControl {
	return newBlastSendControl(rateMbps, ceilingMbps, now)
}

func BlastReceiverStatsForTest(bytes uint64, packets uint64, maxSeq uint64, ackFloor uint64) blastReceiverStats {
	return blastReceiverStats{
		ReceivedPayloadBytes: bytes,
		ReceivedPackets:      packets,
		MaxSeqPlusOne:        maxSeq,
		AckFloor:             ackFloor,
	}
}
```

- [ ] **Step 4: Run the package tests and targeted live check**

Run: `go test ./pkg/probe ./pkg/session -run 'TestExternalDirectUDPStartBudgetScalesDownForSlowCeilings|TestExternalDirectUDPStartBudgetPreservesHighCeilingShape|TestHandleBlastSendControlEventUpdatesAdaptiveRate|TestHandleBlastSendControlEventRepairRequestBacksOffAdaptiveRate' -count=1`

Expected: PASS

Run: `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh ktzlxc 1024`

Expected: PASS with `connected-relay` then `connected-direct`, no SHA mismatch, no leaked sockets, and `benchmark-success=true`.

- [ ] **Step 5: Commit**

```bash
git add pkg/probe/blast_control.go pkg/probe/blast_control_test.go pkg/probe/session.go pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go
git commit -m "session: scale direct udp rate and lanes dynamically"
```

### Task 6: Capture The Baseline, Run The 10x Matrix, And Update The Runbook

**Files:**
- Create: `docs/benchmarks/2026-04-11-wormhole-audit-baseline.md`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Record the pre-change baseline**

````markdown
# Wormhole Audit Baseline

Date: 2026-04-11

Remote hosts:
- ktzlxc
- canlxc
- uklxc
- orange-india.exe.xyz

Commands:

```sh
nix run nixpkgs#iperf3 -- -s -p 8321 -1
./dist/derphole-probe matrix --hosts ktzlxc,canlxc,uklxc,orange-india.exe.xyz --iterations 10 --size-mib 1024 --out docs/benchmarks/2026-04-11-baseline.json
speedtest
ssh root@ktzlxc '~/speedtest --accept-license --accept-gdpr'
ssh root@canlxc '~/speedtest --accept-license --accept-gdpr'
ssh root@uklxc '~/speedtest --accept-license --accept-gdpr'
ssh root@orange-india.exe.xyz '~/speedtest --accept-license --accept-gdpr'
```
````

- [ ] **Step 2: Run the matrix and save the output**

Run: `./dist/derphole-probe matrix --hosts ktzlxc,canlxc,uklxc,orange-india.exe.xyz --iterations 10 --size-mib 1024 --out docs/benchmarks/2026-04-11-baseline.json`

Expected: PASS, with one JSON artifact and one markdown summary that include:
- total wall time per host/direction
- average throughput per host/direction
- peak throughput per host/direction
- success/failure counts
- failure reasons if any run fails

- [ ] **Step 3: Update the runbook**

````md
## Benchmark Gate

Use the Go matrix runner for repeatable 10x both-direction validation:

```sh
./dist/derphole-probe matrix \
  --hosts ktzlxc,canlxc,uklxc,orange-india.exe.xyz \
  --iterations 10 \
  --size-mib 1024 \
  --out docs/benchmarks/latest.json
```

The gate fails when any host/direction:
- increases total wall time
- lowers average throughput
- increases failure count
- regresses ktzlxc peak throughput below the current WAN ceiling envelope
````

- [ ] **Step 4: Run the full verification suite**

Run: `go test ./...`

Expected: PASS

Run: `mise run check`

Expected: PASS

Run: `./dist/derphole-probe matrix --hosts ktzlxc,canlxc,uklxc,orange-india.exe.xyz --iterations 10 --size-mib 1024 --baseline docs/benchmarks/2026-04-11-baseline.json --out docs/benchmarks/2026-04-11-candidate.json`

Expected: PASS, with no regression verdicts and ktzlxc staying near the forwarded-port iperf ceiling.

- [ ] **Step 5: Commit**

```bash
git add docs/benchmarks.md docs/benchmarks/2026-04-11-wormhole-audit-baseline.md
git commit -m "docs: add four-host benchmark gate runbook"
```

## Self-Review Notes

- Spec coverage: this plan covers the wormhole-informed audit outcome, the new benchmark gate, total/average/peak throughput tracking, and the direct-UDP stability work needed for slower WAN links without regressing ktzlxc.
- Placeholder scan: no `TODO`, `TBD`, or “write tests” placeholders remain; every task includes concrete files, commands, and code snippets.
- Type consistency: `RunReport`, `SeriesSummary`, `RegressionResult`, `intervalStats`, `externalTransferMetrics`, and `externalDirectUDPBudget` are named consistently across tasks.
