# Transfer Telemetry And Smooth Direct Handoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add true in-process transfer CSV telemetry, use it to prove the relay-to-direct stall, then keep relay flowing until direct payload progress is proven.

**Architecture:** Add a small `pkg/transfertrace` package for CSV recording and trace checking. Thread an optional recorder from CLI config through `pkg/derphole` into `pkg/session`, update it from existing transfer metrics and direct UDP phases, then add probe progress callbacks so the sender can retire relay based on real direct committed progress. Smooth handoff uses independent spool cursors for direct reads and an offset writer on the receiver so relay and direct can overlap safely.

**Tech Stack:** Go, existing `pkg/session` relay-prefix/direct UDP handoff, existing `pkg/probe` blast stream stats, `encoding/csv`, `mise` quality gates, live SSH harness against `canlxc` and `hetz`.

---

## File Structure

- Create `pkg/transfertrace/trace.go`: transfer trace roles, phases, row schema, CSV recorder.
- Create `pkg/transfertrace/trace_test.go`: CSV header, escaping, snapshot math, terminal rows.
- Create `pkg/transfertrace/checker.go`: trace CSV parser and stall checker.
- Create `pkg/transfertrace/checker_test.go`: checker pass/fail cases for stalls, terminal errors, byte mismatch.
- Create `tools/transfertracecheck/main.go`: CLI wrapper for the checker so scripts can fail on bad traces.
- Create `cmd/derphole/transfer_trace.go`: opens `DERPHOLE_TRANSFER_TRACE_CSV` for send/receive commands.
- Modify `cmd/derphole/send.go`, `cmd/derphole/receive.go`: create and close trace recorders.
- Modify `cmd/derphole/send_test.go`, `cmd/derphole/receive_test.go`: verify trace config plumbing.
- Modify `pkg/derphole/transfer.go`: add `Trace *transfertrace.Recorder` to send/receive configs and pass it into session configs.
- Modify `pkg/session/types.go`: add optional `Trace *transfertrace.Recorder` to `SendConfig`, `OfferConfig`, and `ReceiveConfig`.
- Modify `pkg/session/external_transfer_metrics.go`: integrate transfer metrics with trace snapshots.
- Modify `pkg/session/external_direct_udp.go`: set phases, update direct rate/lane fields, wire trace through relay-prefix send/receive runtimes.
- Modify `pkg/session/external_handoff.go`: add independent spool cursors and receiver offset writer.
- Modify `pkg/session/external_handoff_test.go`: test concurrent relay/direct overlap primitives.
- Modify `pkg/probe/session.go`: add progress callbacks from direct sender/receiver stats.
- Modify `pkg/probe/session_test.go`: test progress callbacks and committed progress reporting.
- Modify `scripts/transfer-stall-harness.sh`: enable in-process traces, fetch them, run `transfertracecheck`.
- Modify `scripts/stall_harness_script_test.go`: static coverage for trace env and checker invocation.
- Update `docs/benchmarks.md`: document in-process trace collection and checker use.

## Task 1: Transfer Trace Recorder

**Files:**
- Create: `pkg/transfertrace/trace.go`
- Create: `pkg/transfertrace/trace_test.go`

- [ ] **Step 1: Write failing recorder tests**

Create `pkg/transfertrace/trace_test.go` with:

```go
package transfertrace

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRecorderWritesHeaderAndEscapedRows(t *testing.T) {
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleSend, time.Unix(100, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Observe(Snapshot{
		At:                     time.Unix(100, int64(500*time.Millisecond)),
		Phase:                  PhaseDirectProbe,
		RelayBytes:             1024,
		DirectBytes:            2048,
		AppBytes:               3072,
		DirectRateSelectedMbps: 350,
		DirectRateActiveMbps:   100,
		DirectLanesActive:      2,
		DirectLanesAvailable:   8,
		DirectProbeState:       "running",
		DirectProbeSummary:     "8:rx=199296,350:rx=8749648",
		LastState:              "connected-direct",
		LastError:              "quoted \" value, comma",
	})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if got, want := lines[0], HeaderLine; got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
	if !strings.Contains(lines[1], `"quoted "" value, comma"`) {
		t.Fatalf("row did not CSV-escape quoted error: %q", lines[1])
	}
	if !strings.Contains(lines[1], ",send,direct_probe,") {
		t.Fatalf("row missing role/phase: %q", lines[1])
	}
	if !strings.Contains(lines[1], ",500,") {
		t.Fatalf("row missing elapsed ms: %q", lines[1])
	}
}

func TestRecorderComputesDeltaAndMbps(t *testing.T) {
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleReceive, time.Unix(200, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Observe(Snapshot{At: time.Unix(200, 0), Phase: PhaseRelay, AppBytes: 1 << 20})
	rec.Observe(Snapshot{At: time.Unix(201, 0), Phase: PhaseRelay, AppBytes: 2 << 20})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	rows := strings.Split(strings.TrimSpace(out.String()), "\n")
	if !strings.Contains(rows[2], ",1048576,8.39,") {
		t.Fatalf("second row missing delta/rate: %q", rows[2])
	}
}

func TestRecorderErrorAndCompleteRows(t *testing.T) {
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleSend, time.Unix(300, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Error(time.Unix(300, int64(250*time.Millisecond)), "write udp: message too long")
	rec.Complete(time.Unix(301, 0))
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	body := out.String()
	if !strings.Contains(body, ",error,") || !strings.Contains(body, "message too long") {
		t.Fatalf("missing terminal error row:\n%s", body)
	}
	if !strings.Contains(body, ",complete,") {
		t.Fatalf("missing complete row:\n%s", body)
	}
}
```

- [ ] **Step 2: Run tests and verify failure**

```bash
mise exec -- go test ./pkg/transfertrace -count=1
```

Expected: fail because `pkg/transfertrace` does not exist.

- [ ] **Step 3: Implement the recorder**

Create `pkg/transfertrace/trace.go` with:

```go
package transfertrace

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
)

type Role string

const (
	RoleSend    Role = "send"
	RoleReceive Role = "receive"
)

type Phase string

const (
	PhaseClaim         Phase = "claim"
	PhaseRelay         Phase = "relay"
	PhaseDirectPrepare Phase = "direct_prepare"
	PhaseDirectProbe   Phase = "direct_probe"
	PhaseDirectExecute Phase = "direct_execute"
	PhaseOverlap       Phase = "overlap"
	PhaseComplete      Phase = "complete"
	PhaseError         Phase = "error"
)

var Header = []string{
	"timestamp_unix_ms",
	"elapsed_ms",
	"role",
	"phase",
	"relay_bytes",
	"direct_bytes",
	"app_bytes",
	"delta_app_bytes",
	"app_mbps",
	"direct_rate_selected_mbps",
	"direct_rate_active_mbps",
	"direct_lanes_active",
	"direct_lanes_available",
	"direct_probe_state",
	"direct_probe_summary",
	"replay_window_bytes",
	"repair_queue_bytes",
	"retransmit_count",
	"out_of_order_bytes",
	"last_state",
	"last_error",
}

const HeaderLine = "timestamp_unix_ms,elapsed_ms,role,phase,relay_bytes,direct_bytes,app_bytes,delta_app_bytes,app_mbps,direct_rate_selected_mbps,direct_rate_active_mbps,direct_lanes_active,direct_lanes_available,direct_probe_state,direct_probe_summary,replay_window_bytes,repair_queue_bytes,retransmit_count,out_of_order_bytes,last_state,last_error"

type Snapshot struct {
	At                     time.Time
	Phase                  Phase
	RelayBytes             int64
	DirectBytes            int64
	AppBytes               int64
	DirectRateSelectedMbps int
	DirectRateActiveMbps   int
	DirectLanesActive      int
	DirectLanesAvailable   int
	DirectProbeState       string
	DirectProbeSummary     string
	ReplayWindowBytes      uint64
	RepairQueueBytes       uint64
	RetransmitCount         int64
	OutOfOrderBytes        uint64
	LastState              string
	LastError              string
}

type Recorder struct {
	mu          sync.Mutex
	role        Role
	startedAt   time.Time
	writer      *csv.Writer
	lastAt      time.Time
	lastApp     int64
	current     Snapshot
	closed      bool
}

func NewRecorder(w io.Writer, role Role, startedAt time.Time) (*Recorder, error) {
	if w == nil {
		return nil, fmt.Errorf("nil transfer trace writer")
	}
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	r := &Recorder{role: role, startedAt: startedAt, writer: csv.NewWriter(w)}
	if err := r.writer.Write(Header); err != nil {
		return nil, err
	}
	r.writer.Flush()
	return r, r.writer.Error()
}

func (r *Recorder) Update(fn func(*Snapshot)) {
	if r == nil || fn == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	fn(&r.current)
}

func (r *Recorder) Observe(s Snapshot) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.observeLocked(s)
}

func (r *Recorder) Tick(at time.Time) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	s := r.current
	s.At = at
	r.observeLocked(s)
}

func (r *Recorder) Error(at time.Time, msg string) {
	r.Update(func(s *Snapshot) {
		s.At = at
		s.Phase = PhaseError
		s.LastError = msg
	})
	r.Tick(at)
}

func (r *Recorder) Complete(at time.Time) {
	r.Update(func(s *Snapshot) {
		s.At = at
		s.Phase = PhaseComplete
	})
	r.Tick(at)
}

func (r *Recorder) Run(ctxDone <-chan struct{}, interval time.Duration, now func() time.Time) {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	if now == nil {
		now = time.Now
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctxDone:
			return
		case at := <-ticker.C:
			if at.IsZero() {
				at = now()
			}
			r.Tick(at)
		}
	}
}

func (r *Recorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.writer.Flush()
	return r.writer.Error()
}

func (r *Recorder) observeLocked(s Snapshot) {
	if s.At.IsZero() {
		s.At = time.Now()
	}
	deltaBytes := s.AppBytes - r.lastApp
	if deltaBytes < 0 {
		deltaBytes = 0
	}
	deltaMS := int64(0)
	if !r.lastAt.IsZero() && s.At.After(r.lastAt) {
		deltaMS = s.At.Sub(r.lastAt).Milliseconds()
	}
	rate := 0.0
	if deltaMS > 0 {
		rate = float64(deltaBytes*8) / float64(deltaMS*1000)
	}
	_ = r.writer.Write([]string{
		strconv.FormatInt(s.At.UnixMilli(), 10),
		strconv.FormatInt(s.At.Sub(r.startedAt).Milliseconds(), 10),
		string(r.role),
		string(s.Phase),
		strconv.FormatInt(s.RelayBytes, 10),
		strconv.FormatInt(s.DirectBytes, 10),
		strconv.FormatInt(s.AppBytes, 10),
		strconv.FormatInt(deltaBytes, 10),
		strconv.FormatFloat(rate, 'f', 2, 64),
		intField(s.DirectRateSelectedMbps),
		intField(s.DirectRateActiveMbps),
		intField(s.DirectLanesActive),
		intField(s.DirectLanesAvailable),
		s.DirectProbeState,
		s.DirectProbeSummary,
		uintField(s.ReplayWindowBytes),
		uintField(s.RepairQueueBytes),
		int64Field(s.RetransmitCount),
		uintField(s.OutOfOrderBytes),
		s.LastState,
		s.LastError,
	})
	r.writer.Flush()
	r.lastAt = s.At
	r.lastApp = s.AppBytes
	r.current = s
}

func intField(v int) string {
	if v == 0 {
		return ""
	}
	return strconv.Itoa(v)
}

func int64Field(v int64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatInt(v, 10)
}

func uintField(v uint64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatUint(v, 10)
}
```

- [ ] **Step 4: Run targeted tests**

```bash
mise exec -- go test ./pkg/transfertrace -count=1
```

Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add pkg/transfertrace/trace.go pkg/transfertrace/trace_test.go
PATH="$(dirname "$(mise which go)"):$PATH" git commit -m "telemetry: add transfer trace recorder"
```

## Task 2: Transfer Trace Checker

**Files:**
- Create: `pkg/transfertrace/checker.go`
- Create: `pkg/transfertrace/checker_test.go`
- Create: `tools/transfertracecheck/main.go`

- [ ] **Step 1: Write failing checker tests**

Create `pkg/transfertrace/checker_test.go` with:

```go
package transfertrace

import (
	"strings"
	"testing"
	"time"
)

func TestCheckPassesSmoothCompleteTransfer(t *testing.T) {
	csvText := HeaderLine + "\n" +
		"1000,0,receive,relay,1024,0,1024,1024,0.00,,,,,,,,,,,connected-relay,\n" +
		"1500,500,receive,overlap,2048,1024,2048,1024,16.38,,,,,,,,,,,connected-direct,\n" +
		"2000,1000,receive,complete,2048,4096,4096,2048,32.77,,,,,,,,,,,stream-complete,\n"
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, StallWindow: time.Second, ExpectedBytes: 4096})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Rows != 3 || result.FinalAppBytes != 4096 {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckFailsApplicationFlatline(t *testing.T) {
	csvText := HeaderLine + "\n" +
		"1000,0,receive,relay,1024,0,1024,1024,0.00,,,,,,,,,,,connected-relay,\n" +
		"1500,500,receive,direct_probe,1024,0,1024,0,0.00,,,,,,,,,,,connected-direct,\n" +
		"2501,1501,receive,direct_probe,1024,0,1024,0,0.00,,,,,,,,,,,connected-direct,\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, StallWindow: time.Second})
	if err == nil || !strings.Contains(err.Error(), "app bytes stalled") {
		t.Fatalf("Check() error = %v, want app bytes stalled", err)
	}
}

func TestCheckFailsTerminalError(t *testing.T) {
	csvText := HeaderLine + "\n" +
		"1000,0,send,error,0,0,0,0,0.00,,,,,,,,,,,connected-direct,message too long\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleSend, StallWindow: time.Second})
	if err == nil || !strings.Contains(err.Error(), "message too long") {
		t.Fatalf("Check() error = %v, want terminal error", err)
	}
}

func TestCheckFailsExpectedByteMismatch(t *testing.T) {
	csvText := HeaderLine + "\n" +
		"1000,0,receive,complete,0,0,1024,1024,0.00,,,,,,,,,,,stream-complete,\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, StallWindow: time.Second, ExpectedBytes: 2048})
	if err == nil || !strings.Contains(err.Error(), "final app bytes") {
		t.Fatalf("Check() error = %v, want byte mismatch", err)
	}
}
```

- [ ] **Step 2: Run tests and verify failure**

```bash
mise exec -- go test ./pkg/transfertrace -run Check -count=1
```

Expected: fail because `Check` is undefined.

- [ ] **Step 3: Implement checker**

Create `pkg/transfertrace/checker.go` with:

```go
package transfertrace

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type Options struct {
	Role          Role
	StallWindow   time.Duration
	ExpectedBytes int64
}

type Result struct {
	Rows          int
	FinalAppBytes int64
	FinalPhase    Phase
	MaxFlatline   time.Duration
}

type parsedRow struct {
	timestampMS int64
	role        Role
	phase       Phase
	appBytes    int64
	lastError   string
}

func Check(r io.Reader, opts Options) (Result, error) {
	if opts.StallWindow <= 0 {
		opts.StallWindow = time.Second
	}
	rows, err := readRows(r)
	if err != nil {
		return Result{}, err
	}
	var result Result
	var lastAdvanceMS int64
	var lastApp int64
	for i, row := range rows {
		if opts.Role != "" && row.role != opts.Role {
			continue
		}
		result.Rows++
		result.FinalAppBytes = row.appBytes
		result.FinalPhase = row.phase
		if row.lastError != "" {
			return result, fmt.Errorf("trace terminal error at row %d: %s", i+2, row.lastError)
		}
		if result.Rows == 1 || row.appBytes > lastApp {
			lastAdvanceMS = row.timestampMS
			lastApp = row.appBytes
			continue
		}
		if activePhase(row.phase) && row.appBytes > 0 {
			flat := time.Duration(row.timestampMS-lastAdvanceMS) * time.Millisecond
			if flat > result.MaxFlatline {
				result.MaxFlatline = flat
			}
			if flat > opts.StallWindow {
				return result, fmt.Errorf("app bytes stalled for %s at row %d phase=%s app_bytes=%d", flat, i+2, row.phase, row.appBytes)
			}
		}
	}
	if result.Rows == 0 {
		return result, fmt.Errorf("no rows matched role %q", opts.Role)
	}
	if opts.ExpectedBytes > 0 && result.FinalAppBytes != opts.ExpectedBytes {
		return result, fmt.Errorf("final app bytes = %d, want %d", result.FinalAppBytes, opts.ExpectedBytes)
	}
	if result.FinalPhase != PhaseComplete {
		return result, fmt.Errorf("final phase = %s, want %s", result.FinalPhase, PhaseComplete)
	}
	return result, nil
}

func readRows(r io.Reader) ([]parsedRow, error) {
	cr := csv.NewReader(r)
	records, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("empty trace")
	}
	index := map[string]int{}
	for i, h := range records[0] {
		index[h] = i
	}
	var rows []parsedRow
	for _, record := range records[1:] {
		row, err := parseRow(record, index)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func parseRow(record []string, index map[string]int) (parsedRow, error) {
	timestampMS, err := parseInt(record, index, "timestamp_unix_ms")
	if err != nil {
		return parsedRow{}, err
	}
	appBytes, err := parseInt(record, index, "app_bytes")
	if err != nil {
		return parsedRow{}, err
	}
	return parsedRow{
		timestampMS: timestampMS,
		role:        Role(field(record, index, "role")),
		phase:       Phase(field(record, index, "phase")),
		appBytes:    appBytes,
		lastError:   field(record, index, "last_error"),
	}, nil
}

func parseInt(record []string, index map[string]int, name string) (int64, error) {
	value := field(record, index, name)
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s=%q: %w", name, value, err)
	}
	return parsed, nil
}

func field(record []string, index map[string]int, name string) string {
	i, ok := index[name]
	if !ok || i < 0 || i >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[i])
}

func activePhase(phase Phase) bool {
	switch phase {
	case PhaseRelay, PhaseDirectPrepare, PhaseDirectProbe, PhaseDirectExecute, PhaseOverlap:
		return true
	default:
		return false
	}
}
```

- [ ] **Step 4: Add CLI wrapper**

Create `tools/transfertracecheck/main.go` with:

```go
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/shayne/derphole/pkg/transfertrace"
)

func main() {
	role := flag.String("role", "", "trace role to validate: send or receive")
	expected := flag.Int64("expected-bytes", 0, "expected final app bytes")
	stall := flag.Duration("stall-window", time.Second, "maximum allowed application-byte flatline")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: transfertracecheck -role receive [-expected-bytes N] trace.csv")
		os.Exit(2)
	}
	f, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	result, err := transfertrace.Check(f, transfertrace.Options{
		Role:          transfertrace.Role(*role),
		ExpectedBytes: *expected,
		StallWindow:   *stall,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("trace-ok rows=%d final_app_bytes=%d max_flatline=%s\n", result.Rows, result.FinalAppBytes, result.MaxFlatline)
}
```

- [ ] **Step 5: Run targeted tests**

```bash
mise exec -- go test ./pkg/transfertrace ./tools/transfertracecheck -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add pkg/transfertrace/checker.go pkg/transfertrace/checker_test.go tools/transfertracecheck/main.go
PATH="$(dirname "$(mise which go)"):$PATH" git commit -m "telemetry: add transfer trace checker"
```

## Task 3: CLI And Config Plumbing

**Files:**
- Create: `cmd/derphole/transfer_trace.go`
- Modify: `cmd/derphole/send.go`
- Modify: `cmd/derphole/receive.go`
- Modify: `cmd/derphole/send_test.go`
- Modify: `cmd/derphole/receive_test.go`
- Modify: `pkg/derphole/transfer.go`
- Modify: `pkg/session/types.go`

- [ ] **Step 1: Add failing CLI plumbing tests**

In `cmd/derphole/send_test.go`, add:

```go
func TestRunSendPassesTransferTraceFromEnvironment(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_TRACE_CSV", filepath.Join(t.TempDir(), "send.csv"))
	prev := runSendTransfer
	defer func() { runSendTransfer = prev }()
	var got *transfertrace.Recorder
	runSendTransfer = func(_ context.Context, cfg pkgderphole.SendConfig) error {
		got = cfg.Trace
		return nil
	}
	if code := runSend([]string{"hello", "--hide-progress"}, telemetry.LevelQuiet, strings.NewReader(""), io.Discard, io.Discard); code != 0 {
		t.Fatalf("runSend() code = %d, want 0", code)
	}
	if got == nil {
		t.Fatal("Trace was nil")
	}
}
```

In `cmd/derphole/receive_test.go`, add the matching receive test:

```go
func TestRunReceivePassesTransferTraceFromEnvironment(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_TRACE_CSV", filepath.Join(t.TempDir(), "receive.csv"))
	prev := runReceiveTransfer
	defer func() { runReceiveTransfer = prev }()
	var got *transfertrace.Recorder
	runReceiveTransfer = func(_ context.Context, cfg pkgderphole.ReceiveConfig) error {
		got = cfg.Trace
		return nil
	}
	if code := runReceive([]string{"abc", "--hide-progress"}, telemetry.LevelQuiet, strings.NewReader(""), io.Discard, io.Discard); code != 0 {
		t.Fatalf("runReceive() code = %d, want 0", code)
	}
	if got == nil {
		t.Fatal("Trace was nil")
	}
}
```

Add imports needed by those tests: `context`, `io`, `path/filepath`, `strings`, and `github.com/shayne/derphole/pkg/transfertrace`.

- [ ] **Step 2: Run tests and verify failure**

```bash
mise exec -- go test ./cmd/derphole -run TransferTrace -count=1
```

Expected: fail because config fields and helper do not exist.

- [ ] **Step 3: Add config fields**

In `pkg/derphole/transfer.go`, import `github.com/shayne/derphole/pkg/transfertrace` and add to both `SendConfig` and `ReceiveConfig`:

```go
Trace *transfertrace.Recorder
```

In `pkg/session/types.go`, import `github.com/shayne/derphole/pkg/transfertrace` and add:

```go
Trace *transfertrace.Recorder
```

to `SendConfig`, `OfferConfig`, and `ReceiveConfig`.

In `pkg/derphole/transfer.go`, pass the recorder through every session config used by `send`, `offer`, and `receive`:

```go
Trace: cfg.Trace,
```

- [ ] **Step 4: Add CLI helper**

Create `cmd/derphole/transfer_trace.go`:

```go
package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/shayne/derphole/pkg/transfertrace"
)

const transferTraceCSVEnv = "DERPHOLE_TRANSFER_TRACE_CSV"

func openTransferTraceFromEnv(role transfertrace.Role, stderr io.Writer) (*transfertrace.Recorder, func(), bool) {
	path := os.Getenv(transferTraceCSVEnv)
	if path == "" {
		return nil, func() {}, true
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "open %s: %v\n", transferTraceCSVEnv, err)
		return nil, func() {}, false
	}
	rec, err := transfertrace.NewRecorder(f, role, time.Now())
	if err != nil {
		_ = f.Close()
		_, _ = fmt.Fprintf(stderr, "initialize %s: %v\n", transferTraceCSVEnv, err)
		return nil, func() {}, false
	}
	return rec, func() {
		_ = rec.Close()
		_ = f.Close()
	}, true
}
```

- [ ] **Step 5: Wire `send` and `receive`**

In `cmd/derphole/send.go`, before building `pkgderphole.SendConfig`, add:

```go
trace, closeTrace, ok := openTransferTraceFromEnv(transfertrace.RoleSend, stderr)
if !ok {
	return 1
}
defer closeTrace()
```

and pass:

```go
Trace: trace,
```

In `cmd/derphole/receive.go`, use `transfertrace.RoleReceive` and pass:

```go
Trace: trace,
```

- [ ] **Step 6: Run targeted tests**

```bash
mise exec -- go test ./cmd/derphole ./pkg/derphole ./pkg/session -run TransferTrace -count=1
```

Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add cmd/derphole pkg/derphole/transfer.go pkg/session/types.go
PATH="$(dirname "$(mise which go)"):$PATH" git commit -m "cli: wire transfer trace csv"
```

## Task 4: Session Metrics And Phase Telemetry

**Files:**
- Modify: `pkg/session/external_transfer_metrics.go`
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_transfer_metrics_test.go`

- [ ] **Step 1: Add failing metrics trace test**

In `pkg/session/external_transfer_metrics_test.go`, add:

```go
func TestExternalTransferMetricsUpdatesTrace(t *testing.T) {
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, time.Unix(10, 0))
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(10, 0), rec, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseRelay, "connected-relay")
	metrics.RecordRelayWrite(1024, time.Unix(10, int64(500*time.Millisecond)))
	metrics.Tick(time.Unix(10, int64(500*time.Millisecond)))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if !strings.Contains(body, ",send,relay,1024,0,1024,1024,") {
		t.Fatalf("trace body missing relay progress:\n%s", body)
	}
}
```

Add imports: `bytes`, `strings`, `time`, and `github.com/shayne/derphole/pkg/transfertrace`.

- [ ] **Step 2: Run test and verify failure**

```bash
mise exec -- go test ./pkg/session -run TestExternalTransferMetricsUpdatesTrace -count=1
```

Expected: fail because `newExternalTransferMetricsWithTrace` and trace methods do not exist.

- [ ] **Step 3: Extend transfer metrics**

In `pkg/session/external_transfer_metrics.go`, import `github.com/shayne/derphole/pkg/transfertrace`. Extend `externalTransferMetrics`:

```go
trace *transfertrace.Recorder
role  transfertrace.Role
phase transfertrace.Phase
lastState string
lastError string
directRateSelectedMbps int
directRateActiveMbps int
directLanesActive int
directLanesAvailable int
directProbeState string
directProbeSummary string
replayWindowBytes uint64
repairQueueBytes uint64
retransmitCount int64
outOfOrderBytes uint64
```

Add constructor and methods:

```go
func newExternalTransferMetricsWithTrace(startedAt time.Time, trace *transfertrace.Recorder, role transfertrace.Role) *externalTransferMetrics {
	m := newExternalTransferMetrics(startedAt)
	m.trace = trace
	m.role = role
	return m
}

func (m *externalTransferMetrics) SetPhase(phase transfertrace.Phase, state string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.phase = phase
	m.lastState = state
	m.updateTraceLocked(time.Now())
}

func (m *externalTransferMetrics) SetError(err error) {
	if m == nil || err == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.phase = transfertrace.PhaseError
	m.lastError = err.Error()
	m.updateTraceLocked(time.Now())
}

func (m *externalTransferMetrics) SetDirectPlan(selectedRate int, activeRate int, activeLanes int, availableLanes int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.directRateSelectedMbps = selectedRate
	m.directRateActiveMbps = activeRate
	m.directLanesActive = activeLanes
	m.directLanesAvailable = availableLanes
	m.updateTraceLocked(time.Now())
}

func (m *externalTransferMetrics) SetProbeSummary(state string, summary string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.directProbeState = state
	m.directProbeSummary = summary
	m.updateTraceLocked(time.Now())
}

func (m *externalTransferMetrics) Tick(at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateTraceLocked(at)
}

func (m *externalTransferMetrics) updateTraceLocked(at time.Time) {
	if m.trace == nil {
		return
	}
	m.trace.Observe(transfertrace.Snapshot{
		At:                     at,
		Phase:                  m.phase,
		RelayBytes:             m.relayBytes,
		DirectBytes:            m.directBytes,
		AppBytes:               m.relayBytes + m.directBytes,
		DirectRateSelectedMbps: m.directRateSelectedMbps,
		DirectRateActiveMbps:   m.directRateActiveMbps,
		DirectLanesActive:      m.directLanesActive,
		DirectLanesAvailable:   m.directLanesAvailable,
		DirectProbeState:       m.directProbeState,
		DirectProbeSummary:     m.directProbeSummary,
		ReplayWindowBytes:      m.replayWindowBytes,
		RepairQueueBytes:       m.repairQueueBytes,
		RetransmitCount:        m.retransmitCount,
		OutOfOrderBytes:        m.outOfOrderBytes,
		LastState:              m.lastState,
		LastError:              m.lastError,
	})
}
```

In `recordWrite`, after updating bytes and first byte time, call `m.updateTraceLocked(at)`.

- [ ] **Step 4: Wire metrics construction**

In `newExternalRelayPrefixSendRuntime`, replace:

```go
metrics := newExternalTransferMetrics(time.Now())
```

with:

```go
metrics := newExternalTransferMetricsWithTrace(time.Now(), rcfg.cfg.Trace, transfertrace.RoleSend)
metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))
```

In `newExternalRelayPrefixReceiveRuntime`, use:

```go
metrics := newExternalTransferMetricsWithTrace(time.Now(), rcfg.cfg.Trace, transfertrace.RoleReceive)
metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))
```

Import `pkg/transfertrace` in `pkg/session/external_direct_udp.go`.

- [ ] **Step 5: Update phases around direct UDP**

Set phases in `pkg/session/external_direct_udp.go`:

```go
metrics.SetPhase(transfertrace.PhaseDirectPrepare, "direct-prepare")
metrics.SetPhase(transfertrace.PhaseDirectProbe, "direct-probe")
metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct-execute")
metrics.SetPhase(transfertrace.PhaseComplete, string(StateComplete))
```

When a direct error occurs before return:

```go
metrics.SetError(err)
```

When rate probe samples are formatted, also call:

```go
metrics.SetProbeSummary("done", externalDirectUDPFormatRateProbeSamples(rateState.sentProbeSamples, rateState.probeResult.Samples))
```

- [ ] **Step 6: Run targeted tests**

```bash
mise exec -- go test ./pkg/session -run 'ExternalTransferMetrics|RelayPrefix' -count=1
```

Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add pkg/session/external_transfer_metrics.go pkg/session/external_transfer_metrics_test.go pkg/session/external_direct_udp.go
PATH="$(dirname "$(mise which go)"):$PATH" git commit -m "session: emit transfer trace phases"
```

## Task 5: Probe Progress Callbacks

**Files:**
- Modify: `pkg/probe/session.go`
- Modify: `pkg/probe/session_test.go`
- Modify: `pkg/session/external_direct_udp.go`

- [ ] **Step 1: Add failing probe progress tests**

In `pkg/probe/session_test.go`, add:

```go
func TestSendBlastParallelReportsProgressCallback(t *testing.T) {
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var got atomic.Int64
	recvDone := make(chan error, 1)
	go func() {
		_, err := ReceiveBlastStreamParallelToWriter(ctx, []net.PacketConn{server}, io.Discard, ReceiveConfig{
			RequireComplete: true,
			ExpectedRunID:   [16]byte{7},
		}, 1024*1024)
		recvDone <- err
	}()
	_, err = SendBlastParallel(ctx, []net.PacketConn{client}, []string{server.LocalAddr().String()}, bytes.NewReader(bytes.Repeat([]byte("x"), 1024*1024)), SendConfig{
		Blast:         true,
		StripedBlast:  true,
		RunID:         [16]byte{7},
		RateMbps:      25,
		ChunkSize:     1200,
		Progress: func(stats TransferStats) {
			got.Store(stats.BytesSent)
		},
	})
	if err != nil {
		t.Fatalf("SendBlastParallel() error = %v", err)
	}
	if err := <-recvDone; err != nil {
		t.Fatalf("ReceiveBlastStreamParallelToWriter() error = %v", err)
	}
	if got.Load() == 0 {
		t.Fatal("progress callback was not called with sent bytes")
	}
}
```

- [ ] **Step 2: Run test and verify failure**

```bash
mise exec -- go test ./pkg/probe -run TestSendBlastParallelReportsProgressCallback -count=1
```

Expected: fail because `SendConfig.Progress` does not exist.

- [ ] **Step 3: Add progress callbacks to configs**

In `pkg/probe/session.go`, add to both `SendConfig` and `ReceiveConfig`:

```go
Progress func(TransferStats)
```

Add helper:

```go
func emitProbeProgress(cb func(TransferStats), stats TransferStats) {
	if cb != nil {
		cb(stats)
	}
}
```

Call it from `SendBlastParallel` whenever `stats.BytesSent`, `stats.Retransmits`, `stats.MaxReplayBytes`, or `stats.ReplayWindowFullWaits` changes. Call it from receive state after committed bytes advance.

- [ ] **Step 4: Wire session trace updates**

In `externalDirectUDPNewSendConfig` call sites, set:

```go
sendCfg.Progress = func(stats probe.TransferStats) {
	metrics.SetProbeStats(stats)
}
```

Add `SetProbeStats` to `externalTransferMetrics`:

```go
func (m *externalTransferMetrics) SetProbeStats(stats probe.TransferStats) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retransmitCount = stats.Retransmits
	m.replayWindowBytes = stats.MaxReplayBytes
	m.updateTraceLocked(time.Now())
}
```

For receive plans, wrap `plan.receiveDst` with `externalTransferMetricsWriter{w: plan.receiveDst, record: metrics.RecordDirectWrite}` before calling `probe.ReceiveBlastStreamParallelToWriter` so committed output writes update `direct_bytes` and `app_bytes` live.

- [ ] **Step 5: Run targeted tests**

```bash
mise exec -- go test ./pkg/probe ./pkg/session -run 'Progress|TransferMetrics' -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add pkg/probe/session.go pkg/probe/session_test.go pkg/session/external_direct_udp.go pkg/session/external_transfer_metrics.go
PATH="$(dirname "$(mise which go)"):$PATH" git commit -m "probe: report transfer progress snapshots"
```

## Task 6: Harness Uses In-Process Traces And Proves Current Stall

**Files:**
- Modify: `scripts/transfer-stall-harness.sh`
- Modify: `scripts/stall_harness_script_test.go`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Add failing script static test**

In `scripts/stall_harness_script_test.go`, extend `required` with:

```go
"DERPHOLE_TRANSFER_TRACE_CSV",
"send.trace.csv",
"receive.trace.csv",
"transfertracecheck",
"-stall-window",
```

- [ ] **Step 2: Run test and verify failure**

```bash
mise exec -- go test ./scripts -run TestTransferStallHarnessCapturesProgressAndCounters -count=1
```

Expected: fail because the harness does not enable in-process traces or checker.

- [ ] **Step 3: Enable traces in harness**

In `scripts/transfer-stall-harness.sh`, define:

```bash
sender_trace="${sender_dir}/send.trace.csv"
receiver_trace="${receiver_dir}/receive.trace.csv"
trace_stall_window="${DERPHOLE_TRANSFER_TRACE_STALL_WINDOW:-1s}"
```

Add to the sender remote command environment:

```bash
DERPHOLE_TRANSFER_TRACE_CSV=$(quote "${sender_trace}")
```

Add to the receiver remote command environment:

```bash
DERPHOLE_TRANSFER_TRACE_CSV=$(quote "${receiver_trace}")
```

After copying remote dirs back and verifying SHA, run:

```bash
mise exec -- go run ./tools/transfertracecheck -role send -expected-bytes "${expected_size}" -stall-window "${trace_stall_window}" "${log_dir}/sender/send.trace.csv"
mise exec -- go run ./tools/transfertracecheck -role receive -expected-bytes "${expected_size}" -stall-window "${trace_stall_window}" "${log_dir}/receiver/receive.trace.csv"
```

For Phase 1 only, allow a diagnostic mode to prove the current stall without failing the whole harness:

```bash
if [[ "${DERPHOLE_TRANSFER_TRACE_EXPECT_STALL:-0}" == "1" ]]; then
  if mise exec -- go run ./tools/transfertracecheck -role receive -expected-bytes "${expected_size}" -stall-window "${trace_stall_window}" "${log_dir}/receiver/receive.trace.csv"; then
    echo "stall-proof-error=expected-stall-but-checker-passed" >&2
    exit 1
  fi
else
  mise exec -- go run ./tools/transfertracecheck -role receive -expected-bytes "${expected_size}" -stall-window "${trace_stall_window}" "${log_dir}/receiver/receive.trace.csv"
fi
```

- [ ] **Step 4: Document usage**

In `docs/benchmarks.md`, add a short section under "Baseline Comparisons":

```markdown
For handoff diagnostics, prefer in-process transfer traces over SSH polling:

```bash
DERPHOLE_TRANSFER_TRACE_CSV=/tmp/send.csv derphole send ...
DERPHOLE_TRANSFER_TRACE_CSV=/tmp/receive.csv derphole receive ...
mise exec -- go run ./tools/transfertracecheck -role receive -expected-bytes <bytes> /tmp/receive.csv
```

The stall harness enables these traces automatically and keeps the outer `samples.csv` only as a process watchdog.
```

- [ ] **Step 5: Run targeted tests**

```bash
bash -n scripts/transfer-stall-harness.sh
mise exec -- go test ./scripts ./tools/transfertracecheck -count=1
```

Expected: pass.

- [ ] **Step 6: Run Phase 1 live proof against canlxc and hetz**

```bash
DERPHOLE_TRANSFER_TRACE_EXPECT_STALL=1 DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh canlxc hetz 1024
DERPHOLE_TRANSFER_TRACE_EXPECT_STALL=1 DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh hetz canlxc 1024
```

Expected: transfers complete and SHA checks pass, but the receive trace checker reports the pre-fix application-byte flatline. Record the two `stall-harness-log-dir=...` paths in the implementation notes.

- [ ] **Step 7: Commit**

```bash
git add scripts/transfer-stall-harness.sh scripts/stall_harness_script_test.go docs/benchmarks.md
PATH="$(dirname "$(mise which go)"):$PATH" git commit -m "scripts: collect in-process transfer traces"
```

## Task 7: Smooth Relay-To-Direct Overlap Handoff

**Files:**
- Modify: `pkg/session/external_handoff.go`
- Modify: `pkg/session/external_handoff_test.go`
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Add failing spool cursor test**

In `pkg/session/external_handoff_test.go`, add:

```go
func TestExternalHandoffSpoolCursorDoesNotAdvanceRelayReadOffset(t *testing.T) {
	spool, err := newExternalHandoffSpool(strings.NewReader("abcdefghijklmnop"), 4, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	chunk, err := spool.NextChunk()
	if err != nil {
		t.Fatal(err)
	}
	if string(chunk.Payload) != "abcd" {
		t.Fatalf("first relay chunk = %q", chunk.Payload)
	}
	cursor := newExternalHandoffSpoolCursor(spool, 0)
	buf := make([]byte, 6)
	n, err := cursor.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "abcdef" {
		t.Fatalf("cursor read = %q", buf[:n])
	}
	next, err := spool.NextChunk()
	if err != nil {
		t.Fatal(err)
	}
	if next.Offset != 4 || string(next.Payload) != "efgh" {
		t.Fatalf("relay read advanced unexpectedly: offset=%d payload=%q", next.Offset, next.Payload)
	}
}
```

- [ ] **Step 2: Add failing offset writer test**

In `pkg/session/external_handoff_test.go`, add:

```go
func TestExternalHandoffOffsetWriterDeduplicatesOverlap(t *testing.T) {
	var out bytes.Buffer
	rx := newExternalHandoffReceiver(&out, 64)
	if err := rx.AcceptChunk(externalHandoffChunk{Offset: 0, Payload: []byte("hello ")}); err != nil {
		t.Fatal(err)
	}
	w := newExternalHandoffOffsetWriter(rx, 3, nil)
	if _, err := w.Write([]byte("lo world")); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "hello world"; got != want {
		t.Fatalf("out = %q, want %q", got, want)
	}
}
```

- [ ] **Step 3: Run tests and verify failure**

```bash
mise exec -- go test ./pkg/session -run 'SpoolCursor|OffsetWriter' -count=1
```

Expected: fail because cursor and offset writer do not exist.

- [ ] **Step 4: Implement independent spool cursor**

Add to `pkg/session/external_handoff.go`:

```go
type externalHandoffSpoolCursor struct {
	spool  *externalHandoffSpool
	offset int64
}

func newExternalHandoffSpoolCursor(spool *externalHandoffSpool, offset int64) *externalHandoffSpoolCursor {
	if offset < 0 {
		offset = 0
	}
	return &externalHandoffSpoolCursor{spool: spool, offset: offset}
}

func (c *externalHandoffSpoolCursor) Read(p []byte) (int, error) {
	if c == nil || c.spool == nil {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.spool.mu.Lock()
		if c.spool.closed {
			c.spool.mu.Unlock()
			return 0, net.ErrClosed
		}
		if c.offset < c.spool.sourceOffset {
			available := c.spool.sourceOffset - c.offset
			if int64(len(p)) > available {
				p = p[:available]
			}
			n, err := c.spool.file.ReadAt(p, c.offset)
			c.offset += int64(n)
			c.spool.mu.Unlock()
			return n, errExceptEOFWhenBytesRead(n, err)
		}
		if c.spool.eof {
			c.spool.mu.Unlock()
			return 0, io.EOF
		}
		c.spool.cond.Wait()
		c.spool.mu.Unlock()
	}
}

func errExceptEOFWhenBytesRead(n int, err error) error {
	if n > 0 && errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
```

- [ ] **Step 5: Implement receiver offset writer**

Add to `pkg/session/external_handoff.go`:

```go
type externalHandoffOffsetWriter struct {
	rx     *externalHandoffReceiver
	offset int64
	record func(int64, time.Time)
}

func newExternalHandoffOffsetWriter(rx *externalHandoffReceiver, offset int64, record func(int64, time.Time)) *externalHandoffOffsetWriter {
	if offset < 0 {
		offset = 0
	}
	return &externalHandoffOffsetWriter{rx: rx, offset: offset, record: record}
}

func (w *externalHandoffOffsetWriter) Write(p []byte) (int, error) {
	if w == nil || w.rx == nil {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	before := w.rx.Watermark()
	chunk := externalHandoffChunk{Offset: w.offset, Payload: append([]byte(nil), p...)}
	w.offset += int64(len(p))
	if err := w.rx.AcceptChunk(chunk); err != nil {
		return 0, err
	}
	if w.record != nil {
		if delivered := w.rx.Watermark() - before; delivered > 0 {
			w.record(delivered, time.Now())
		}
	}
	return len(p), nil
}
```

- [ ] **Step 6: Run primitive tests**

```bash
mise exec -- go test ./pkg/session -run 'SpoolCursor|OffsetWriter|ExternalHandoffReceiver' -count=1
```

Expected: pass.

- [ ] **Step 7: Change sender runtime to overlap relay and direct**

In `externalRelayPrefixSendRuntime`, add fields:

```go
overlapBoundary int64
directProgressCh chan struct{}
```

Initialize:

```go
directProgressCh: make(chan struct{}, 1),
```

In `startPrepare`, choose an overlap boundary without stopping relay:

```go
boundary := rt.spool.AckedWatermark()
if boundary < 0 {
	boundary = 0
}
rt.overlapBoundary = boundary
sendCfg := rt.rcfg.cfg
sendCfg.skipDirectUDPRateProbes = externalRelayPrefixShouldSkipDirectUDPRateProbes(sendCfg.StdioExpectedBytes)
sendCfg.Trace = rt.rcfg.cfg.Trace
```

Replace the handoff wait path so `externalDirectUDPSendWaitHandoffExpectedBytes` no longer blocks relay. Add a context value for overlap boundary and have `externalDirectUDPSendWaitHandoffExpectedBytes` return `externalDirectUDPRemainingExpectedBytes(expectedBytes, boundary)` immediately for relay-prefix overlap mode.

In `executePrepared`, use the independent cursor:

```go
reader := newExternalHandoffSpoolCursor(rt.spool, rt.overlapBoundary)
cfg := rt.rcfg.cfg
cfg.Trace = rt.rcfg.cfg.Trace
return externalExecutePreparedDirectUDPSendFn(rt.ctx, reader, plan, cfg, rt.metrics)
```

Set `probe.SendConfig.Progress` so direct committed progress signals relay retirement:

```go
plan.sendCfg.Progress = func(stats probe.TransferStats) {
	rt.metrics.SetProbeStats(stats)
	if stats.PacketsAcked > 0 || stats.BytesSent > 0 {
		select {
		case rt.directProgressCh <- struct{}{}:
		default:
		}
	}
}
```

When `directProgressCh` fires after direct execute starts, call:

```go
rt.stopRelay()
```

This sends the existing handoff frame and lets the relay receive side retire while direct continues.

- [ ] **Step 8: Change receiver runtime to allow direct before relay handoff**

In `externalRelayPrefixReceiveRuntime`, store `rx *externalHandoffReceiver` as a field. Build relay receiver with that `rx`, not a local variable only.

When direct prepare completes, do not wait for `errExternalHandoffCarrierHandoff`. Instead, wrap direct receive output:

```go
boundary := rt.rx.Watermark()
prep.plan.receiveDst = newExternalHandoffOffsetWriter(rt.rx, boundary, rt.metrics.RecordDirectWrite)
rt.activateDirect()
directErr := externalExecutePreparedDirectUDPReceiveFn(rt.ctx, prep.plan, rt.rcfg.tok, rt.rcfg.cfg, rt.metrics)
```

If direct succeeds, close or stop relay through the existing handoff path. If relay finishes first, cancel direct prepare/execution and finish on relay.

- [ ] **Step 9: Add package tests for relay-through-probe**

In `pkg/session/external_direct_udp_test.go`, add tests that inject fake prepare channels and assert:

```go
// relay is not stopped when direct handoff-ready fires
// relay is still running while prepare/rate probe is pending
// relay stop happens only after direct progress signal
```

Use existing fake hooks in the file for `externalPrepareDirectUDPSendFn`, `externalExecutePreparedDirectUDPSendFn`, and `externalSendExternalHandoffDERPFn`.

- [ ] **Step 10: Run targeted tests**

```bash
mise exec -- go test ./pkg/session -run 'RelayPrefix|SpoolCursor|OffsetWriter|DirectUDP' -count=1
```

Expected: pass.

- [ ] **Step 11: Commit**

```bash
git add pkg/session/external_handoff.go pkg/session/external_handoff_test.go pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go
PATH="$(dirname "$(mise which go)"):$PATH" git commit -m "session: keep relay live through direct handoff"
```

## Task 8: Live Validation And Quality Gates

**Files:**
- Modify: `scripts/transfer-stall-harness.sh`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Run full local checks**

```bash
mise run check
```

Expected: pass.

- [ ] **Step 2: Run quality goal**

```bash
mise run quality:goal
```

Expected: pass with current goals: coverage at or above `80%`, CRAP over threshold `0`, golangci issues `0`, fuzz targets complete, mutation score at or above configured threshold.

- [ ] **Step 3: Run live canlxc to hetz**

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh canlxc hetz 1024
```

Expected:

```text
source-size-bytes=1073741824
sink-size-bytes=1073741824
sender-status=0
receiver-status=0
stall-harness-success=true
```

The copied `receiver/receive.trace.csv` must pass:

```bash
mise exec -- go run ./tools/transfertracecheck -role receive -expected-bytes 1073741824 -stall-window 1s /tmp/<run>/receiver/receive.trace.csv
```

- [ ] **Step 4: Run live hetz to canlxc**

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh hetz canlxc 1024
```

Expected: same success lines and checker pass.

- [ ] **Step 5: Inspect traces for smooth promotion**

For each run:

```bash
rg -n 'message too long|context canceled|peer disconnected' /tmp/<run> || true
awk -F, 'NR == 1 || /direct_probe|direct_execute|overlap|complete/' /tmp/<run>/receiver/receive.trace.csv | sed -n '1,40p'
```

Expected: no error strings. During `direct_probe`, receiver `app_bytes` continues advancing through relay. During `direct_execute` or `overlap`, direct bytes begin increasing without an application-byte flatline longer than `1s`.

- [ ] **Step 6: Verify final validation artifacts and committed state**

Run:

```bash
ls -lh /tmp/<run>/sender/send.trace.csv /tmp/<run>/receiver/receive.trace.csv
git status --short --branch
```

Expected: both trace files exist and the working tree is clean because each implementation task committed its changes before live validation.

- [ ] **Step 7: Push main**

```bash
git status --short --branch
git push origin main
git rev-list --left-right --count main...origin/main
```

Expected: clean worktree and `0 0` after push.

## Self-Review Checklist

- Spec coverage: Tasks 1-6 implement and prove in-process telemetry; Task 7 implements smooth overlap handoff; Task 8 validates locally and live against `canlxc` and `hetz`.
- No vague steps: every task has concrete files, snippets, commands, and expected results.
- Type consistency: `transfertrace.Recorder`, `transfertrace.Snapshot`, `externalTransferMetrics`, and `probe.TransferStats` names are consistent across tasks.
- Scope: this plan does not implement the broader direct UDP runtime guardrail controller; it focuses on telemetry and relay-to-direct handoff smoothness.
