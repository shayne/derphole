# Public Bulk Throughput Defaults Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make no-flag derphole bulk transfers automatically approach same-path `iperf3` throughput on public Internet paths.

**Architecture:** Treat `iperf3` as the per-run baseline, add a four-host public-path benchmark matrix, instrument the current QUIC copy pipeline, and change the default policy so users do not need performance flags. Prefer the simplest QUIC path that passes the matrix before designing a custom UDP bulk protocol.

**Tech Stack:** Go, quic-go through `pkg/dataplane` and `pkg/directquic`, derphole v2 transfer code in `pkg/session`, transfer CSVs in `pkg/transfertrace`, shell harnesses under `scripts/`, GitButler for commits.

---

This plan supersedes `docs/superpowers/plans/2026-07-02-derphole-public-path-performance-reliability.md` for the throughput-defaults work. That earlier plan was based on a single-host startup hypothesis. This plan starts from the four-host Mac-to-remote matrix in `docs/superpowers/specs/2026-07-02-public-bulk-throughput-defaults-design.md`.

## File Structure

- Modify `scripts/public-path-performance-harness.sh`: make the public-path matrix run Mac-to-remote 1 GiB tests by default across `derphole-testing`, `eric-nuc`, `hetz`, and `canlxc`, with three `iperf3` and three derphole no-flag samples per host.
- Modify `scripts/promotion-benchmark-driver.sh`: accept a main-disk remote output root and an optional diagnostic parallel policy env var for controlled experiments.
- Modify `scripts/promotion_scripts_test.go`: lock in the matrix defaults, public-only test env, main-disk output root, and no-flag product run behavior.
- Modify `docs/benchmarks.md`: document the four-host matrix, pass criteria, and diagnostic policy runs.
- Modify `pkg/transfertrace/trace.go`: add copy-pipeline diagnostic columns for blocked writer time and receive reorder backlog.
- Modify `pkg/transfertrace/checker.go`: include max copy-pipeline diagnostics in trace summaries.
- Modify `tools/transfertracecheck/main.go`: print the new diagnostics in `trace-ok` output.
- Modify `pkg/session/external_transfer_metrics.go`: store and emit the new copy-pipeline diagnostics.
- Modify `pkg/session/external_transfer_metrics_test.go`: verify trace rows expose the new diagnostics.
- Modify `pkg/session/external_striped.go`: add copy observer hooks, measure sender writer blocking, and bound receive reorder backlog.
- Modify `pkg/session/external_striped_test.go`: prove ordering, blocking visibility, bounded backlog, and cancellation behavior.
- Modify `pkg/session/parallel.go`: make the default no-flag policy automatic and start from one stream so normal transfers avoid the current fixed four-stripe ordered-copy head-of-line behavior.
- Modify `pkg/session/parallel_test.go`: lock in the default automatic policy.
- Modify `pkg/session/external_v2_protocol_test.go`: lock in v2 policy defaulting and diagnostic override behavior.
- Create `cmd/derphole/parse_helpers_test.go`: prove empty `--parallel` input resolves to the no-flag automatic policy while explicit `-P` remains a diagnostic override.

## Required Execution Setup

- [ ] **Step 1: Confirm branch and base**

Run:

```bash
but status -fv
but pull --check
```

Expected: the active branch is `codex/public-bulk-throughput-defaults`, the latest commit is the approved spec or this plan, there are no unrelated uncommitted changes, and `but pull --check` reports `Up to date`.

- [ ] **Step 2: Install hooks**

Run:

```bash
mise run install-githooks
```

Expected: exit code 0.

---

### Task 1: Make The Public-Path Matrix First-Class

**Files:**
- Modify: `scripts/public-path-performance-harness.sh`
- Modify: `scripts/promotion-benchmark-driver.sh`
- Modify: `scripts/promotion_scripts_test.go`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Write the failing script tests**

In `scripts/promotion_scripts_test.go`, replace `TestPublicPathPerformanceHarnessDocumentsBaselineMatrix` with this test:

```go
func TestPublicPathPerformanceHarnessRunsForwardFourHostMatrix(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "public-path-performance-harness.sh"))
	if err != nil {
		t.Fatalf("read public-path-performance-harness.sh: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		`DERPHOLE_PUBLIC_PATH_HOSTS:-ubuntu@derphole-testing ubuntu@eric-nuc root@hetz root@canlxc`,
		`DERPHOLE_PUBLIC_PATH_SIZE_MIB:-1024`,
		`DERPHOLE_PUBLIC_PATH_RUNS:-3`,
		`DERPHOLE_PUBLIC_IPERF_PORT:-8123`,
		`DERPHOLE_PUBLIC_PATH_DIRECTION:-forward`,
		`DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`,
		`DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT=`,
		`promotion-test.sh`,
		`transfertracecheck`,
		`summary.csv`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("public-path-performance-harness.sh missing %q", want)
		}
	}
}
```

Add this test below it:

```go
func TestPromotionBenchmarkDriverSupportsRemoteOutputRootAndDiagnosticParallel(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		`DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT`,
		`DERPHOLE_BENCH_PARALLEL`,
		`parallel_args=()`,
		`--parallel "${DERPHOLE_BENCH_PARALLEL}"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("promotion-benchmark-driver.sh missing %q", want)
		}
	}
}
```

- [ ] **Step 2: Run the failing script tests**

Run:

```bash
go test ./scripts -run 'TestPublicPathPerformanceHarnessRunsForwardFourHostMatrix|TestPromotionBenchmarkDriverSupportsRemoteOutputRootAndDiagnosticParallel' -count=1
```

Expected: FAIL because the existing harness defaults to port `8321`, 128 MiB, one target argument, and reverse-oriented cases.

- [ ] **Step 3: Update the public-path harness defaults**

In `scripts/public-path-performance-harness.sh`, make these defaults appear near the top:

```bash
hosts_raw="${DERPHOLE_PUBLIC_PATH_HOSTS:-ubuntu@derphole-testing ubuntu@eric-nuc root@hetz root@canlxc}"
size_mib="${DERPHOLE_PUBLIC_PATH_SIZE_MIB:-1024}"
runs="${DERPHOLE_PUBLIC_PATH_RUNS:-3}"
iperf_port="${DERPHOLE_PUBLIC_IPERF_PORT:-8123}"
direction="${DERPHOLE_PUBLIC_PATH_DIRECTION:-forward}"
log_dir="${DERPHOLE_BENCH_LOG_DIR:-.tmp/public-path-performance}"
remote_output_root="${DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT:-derphole-bench/public-path}"
summary_csv="${log_dir}/summary.csv"
```

Use the first positional argument only as an optional host override:

```bash
if [[ "${1:-}" != "" ]]; then
  hosts_raw="$1"
fi
```

Initialize `summary.csv` with:

```bash
printf 'host,run,tool,direction,mbps,ratio_to_iperf,trace_ok,max_peer_recv_queue_depth,max_flatline,log_dir\n' >"${summary_csv}"
```

- [ ] **Step 4: Make `iperf3` measure this Mac sending to the remote**

Keep the local `iperf3` server because port `8123` is forwarded from the Mac WAN to this Mac. Rename the helper to `run_iperf_forward_sample` and make it write one JSON file per host and run:

```bash
run_iperf_forward_sample() {
  local remote="$1"
  local host_label="$2"
  local run="$3"
  local ip="$4"
  local out="${log_dir}/${host_label}/iperf3-run-${run}.json"

  mkdir -p "$(dirname "${out}")"
  iperf3 -s -4 -p "${iperf_port}" --one-off --forceflush >"${log_dir}/${host_label}/iperf3-server-${run}.log" 2>&1 &
  local server_pid="$!"
  trap 'kill "${server_pid}" 2>/dev/null || true' RETURN
  sleep 1
  ssh -o BatchMode=yes "${remote}" "iperf3 -4 -J -c '${ip}' -p '${iperf_port}' -t 20 -P 4" >"${out}"
  wait "${server_pid}" || true
  trap - RETURN

  python3 - "${out}" <<'PY'
import json
import sys

with open(sys.argv[1]) as fh:
    payload = json.load(fh)
bits = payload["end"]["sum_received"]["bits_per_second"]
print(f"{bits / 1_000_000:.2f}")
PY
}
```

- [ ] **Step 5: Make the derphole sample use no product tuning flags by default**

Add this helper. It must call `promotion-test.sh` for Mac-to-remote transfer and pass the public-only test env, but it must not pass `--parallel` unless `DERPHOLE_BENCH_PARALLEL` is set for a diagnostic run.

```bash
run_derphole_forward_sample() {
  local remote="$1"
  local host_label="$2"
  local run="$3"
  local case_log_dir="${log_dir}/${host_label}/derphole-run-${run}"
  local target="${remote}"

  mkdir -p "${case_log_dir}"
  DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
  DERPHOLE_BENCH_DIRECTION="${direction}" \
  DERPHOLE_BENCH_LOG_DIR="${case_log_dir}" \
  DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT="${remote_output_root}/${host_label}/run-${run}" \
    ./scripts/promotion-test.sh "${target}" "${size_mib}"
}
```

- [ ] **Step 6: Add summary extraction**

After each derphole run, read `result.env` or the existing promotion output file that contains `sender_goodput_mbps`, `trace_average_mbps`, and tracecheck output. Append one row per sample:

```bash
append_summary_row() {
  local host_label="$1"
  local run="$2"
  local tool="$3"
  local mbps="$4"
  local iperf_mbps="$5"
  local trace_ok="$6"
  local max_queue="$7"
  local max_flatline="$8"
  local sample_log_dir="$9"

  python3 - "${summary_csv}" "${host_label}" "${run}" "${tool}" "${direction}" "${mbps}" "${iperf_mbps}" "${trace_ok}" "${max_queue}" "${max_flatline}" "${sample_log_dir}" <<'PY'
import csv
import sys

path, host, run, tool, direction, mbps, iperf_mbps, trace_ok, max_queue, max_flatline, log_dir = sys.argv[1:]
ratio = ""
if float(iperf_mbps) > 0:
    ratio = f"{float(mbps) / float(iperf_mbps):.3f}"
with open(path, "a", newline="") as fh:
    csv.writer(fh).writerow([host, run, tool, direction, mbps, ratio, trace_ok, max_queue, max_flatline, log_dir])
PY
}
```

- [ ] **Step 7: Teach the promotion driver the remote output root**

In `scripts/promotion-benchmark-driver.sh`, find the remote output path setup and derive it from this env var:

```bash
remote_output_root="${DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT:-derphole-bench/promotion}"
```

Use `${remote_output_root}` for remote payload/output directories instead of `/tmp` or a hard-coded temp directory. Keep any local temporary files under `.tmp`.

- [ ] **Step 8: Teach the promotion driver the diagnostic parallel override**

In `scripts/promotion-benchmark-driver.sh`, add:

```bash
parallel_args=()
if [[ "${DERPHOLE_BENCH_PARALLEL:-}" != "" ]]; then
  parallel_args=(--parallel "${DERPHOLE_BENCH_PARALLEL}")
fi
```

Use `"${parallel_args[@]}"` only on commands that already support the `--parallel` diagnostic flag. No-flag product runs leave `DERPHOLE_BENCH_PARALLEL` unset.

- [ ] **Step 9: Run the script tests**

Run:

```bash
go test ./scripts -run 'TestPublicPathPerformanceHarnessRunsForwardFourHostMatrix|TestPromotionBenchmarkDriverSupportsRemoteOutputRootAndDiagnosticParallel|TestPromotionBenchmarkDriverPropagatesTransportExperimentEnv' -count=1
```

Expected: PASS.

- [ ] **Step 10: Update benchmark docs**

In `docs/benchmarks.md`, update the public-path section to state:

```markdown
The public-path throughput gate is Mac -> remote by default:

DERPHOLE_PUBLIC_PATH_HOSTS='ubuntu@derphole-testing ubuntu@eric-nuc root@hetz root@canlxc' \
DERPHOLE_PUBLIC_PATH_SIZE_MIB=1024 \
DERPHOLE_PUBLIC_PATH_RUNS=3 \
DERPHOLE_PUBLIC_IPERF_PORT=8123 \
./scripts/public-path-performance-harness.sh

The harness sets DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 for derphole runs so the measurement stays on the public Internet path. This is a test-only guard; production defaults still allow Tailscale candidates.
```

Document the pass condition:

```markdown
The primary pass condition is eric-nuc Mac -> remote derphole average within 10-15 percent of same-run iperf3, with zero steady direct-phase transfertracecheck stalls over 1s. The other hosts must not regress against the July 2 baseline matrix.
```

- [ ] **Step 11: Checkpoint**

Run:

```bash
but diff
but commit codex/public-bulk-throughput-defaults -m "test: add public throughput matrix harness" --changes <ids>
```

Use the file IDs for `scripts/public-path-performance-harness.sh`, `scripts/promotion-benchmark-driver.sh`, `scripts/promotion_scripts_test.go`, and `docs/benchmarks.md`.

---

### Task 2: Add Copy-Pipeline Trace Diagnostics

**Files:**
- Modify: `pkg/transfertrace/trace.go`
- Modify: `pkg/transfertrace/checker.go`
- Modify: `tools/transfertracecheck/main.go`
- Modify: `pkg/session/external_transfer_metrics.go`
- Modify: `pkg/session/external_transfer_metrics_test.go`

- [ ] **Step 1: Write a failing metrics trace test**

Add this test to `pkg/session/external_transfer_metrics_test.go`:

```go
func TestTransferTraceIncludesStripedCopyDiagnostics(t *testing.T) {
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleReceive, time.Unix(80, 0))
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(80, 0), rec, transfertrace.RoleReceive)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct")
	metrics.RecordStripedReceiveBacklog(7, 7340032, time.Unix(80, 1))
	metrics.RecordStripedSendBlocked(250*time.Millisecond, time.Unix(80, 2))
	metrics.Tick(time.Unix(80, 3))

	rows := readTransferTraceRows(t, out.String())
	row := rows[len(rows)-1]
	if row["striped_send_blocked_ms"] != "250" ||
		row["striped_receive_pending_chunks"] != "7" ||
		row["striped_receive_pending_bytes"] != "7340032" ||
		row["striped_receive_pending_chunks_max"] != "7" ||
		row["striped_receive_pending_bytes_max"] != "7340032" {
		t.Fatalf("trace row missing striped diagnostics: %#v", row)
	}
}
```

- [ ] **Step 2: Run the failing metrics test**

Run:

```bash
go test ./pkg/session -run TestTransferTraceIncludesStripedCopyDiagnostics -count=1
```

Expected: FAIL because the fields and metric methods do not exist.

- [ ] **Step 3: Add transfertrace fields**

In `pkg/transfertrace/trace.go`, append these column names to `header` after `peer_recv_queue_depth_max`:

```go
"striped_send_blocked_ms",
"striped_receive_pending_chunks",
"striped_receive_pending_chunks_max",
"striped_receive_pending_bytes",
"striped_receive_pending_bytes_max",
```

Add these fields to `Snapshot`:

```go
StripedSendBlockedMS             int64
StripedReceivePendingChunks      int
StripedReceivePendingChunksMax   int
StripedReceivePendingBytes       int64
StripedReceivePendingBytesMax    int64
```

Add these values in `Recorder.row` in the same order as the headers:

```go
strconv.FormatInt(snap.StripedSendBlockedMS, 10),
strconv.Itoa(snap.StripedReceivePendingChunks),
strconv.Itoa(snap.StripedReceivePendingChunksMax),
strconv.FormatInt(snap.StripedReceivePendingBytes, 10),
strconv.FormatInt(snap.StripedReceivePendingBytesMax, 10),
```

- [ ] **Step 4: Add external metrics storage and methods**

In `pkg/session/external_transfer_metrics.go`, add fields to `externalTransferMetrics`:

```go
stripedSendBlockedMS           int64
stripedReceivePendingChunks    int
stripedReceivePendingChunksMax int
stripedReceivePendingBytes     int64
stripedReceivePendingBytesMax  int64
```

Add methods:

```go
func (m *externalTransferMetrics) RecordStripedSendBlocked(d time.Duration, at time.Time) {
	if m == nil || d <= 0 {
		return
	}
	m.mu.Lock()
	m.stripedSendBlockedMS += d.Milliseconds()
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) RecordStripedReceiveBacklog(chunks int, bytes int64, at time.Time) {
	if m == nil {
		return
	}
	if chunks < 0 {
		chunks = 0
	}
	if bytes < 0 {
		bytes = 0
	}
	m.mu.Lock()
	m.stripedReceivePendingChunks = chunks
	m.stripedReceivePendingBytes = bytes
	if chunks > m.stripedReceivePendingChunksMax {
		m.stripedReceivePendingChunksMax = chunks
	}
	if bytes > m.stripedReceivePendingBytesMax {
		m.stripedReceivePendingBytesMax = bytes
	}
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}
```

In `updateTraceLocked`, set:

```go
StripedSendBlockedMS:           m.stripedSendBlockedMS,
StripedReceivePendingChunks:    m.stripedReceivePendingChunks,
StripedReceivePendingChunksMax: m.stripedReceivePendingChunksMax,
StripedReceivePendingBytes:     m.stripedReceivePendingBytes,
StripedReceivePendingBytesMax:  m.stripedReceivePendingBytesMax,
```

- [ ] **Step 5: Add checker summary fields**

In `pkg/transfertrace/checker.go`, extend `DiagnosticsSummary`:

```go
MaxStripedSendBlockedMS           int64
MaxStripedReceivePendingChunks    int
MaxStripedReceivePendingBytes     int64
```

In the row diagnostics accumulation, read these columns with the existing integer helpers:

```go
summary.MaxStripedSendBlockedMS = max(summary.MaxStripedSendBlockedMS, parseInt64Cell(row, "striped_send_blocked_ms"))
summary.MaxStripedReceivePendingChunks = max(summary.MaxStripedReceivePendingChunks, parseIntCell(row, "striped_receive_pending_chunks_max"))
summary.MaxStripedReceivePendingBytes = max(summary.MaxStripedReceivePendingBytes, parseInt64Cell(row, "striped_receive_pending_bytes_max"))
```

- [ ] **Step 6: Print the new summary**

In `tools/transfertracecheck/main.go`, extend `formatDiagnosticsSummary`:

```go
if diagnostics.MaxStripedSendBlockedMS > 0 {
	summary += fmt.Sprintf(" max_striped_send_blocked_ms=%d", diagnostics.MaxStripedSendBlockedMS)
}
if diagnostics.MaxStripedReceivePendingChunks > 0 {
	summary += fmt.Sprintf(" max_striped_receive_pending_chunks=%d", diagnostics.MaxStripedReceivePendingChunks)
}
if diagnostics.MaxStripedReceivePendingBytes > 0 {
	summary += fmt.Sprintf(" max_striped_receive_pending_bytes=%d", diagnostics.MaxStripedReceivePendingBytes)
}
```

- [ ] **Step 7: Run focused tests**

Run:

```bash
go test ./pkg/transfertrace ./pkg/session ./tools/transfertracecheck -run 'TestTransferTraceIncludesStripedCopyDiagnostics|TestCheckReportsDiagnosticsSummaryFromDirectPathFields|Test' -count=1
```

Expected: PASS.

- [ ] **Step 8: Checkpoint**

Run:

```bash
but diff
but commit codex/public-bulk-throughput-defaults -m "trace: add copy pipeline diagnostics" --changes <ids>
```

Use the file IDs for `pkg/transfertrace/trace.go`, `pkg/transfertrace/checker.go`, `tools/transfertracecheck/main.go`, `pkg/session/external_transfer_metrics.go`, and `pkg/session/external_transfer_metrics_test.go`.

---

### Task 3: Instrument And Bound The Striped Copy Pipeline

**Files:**
- Modify: `pkg/session/external_striped.go`
- Modify: `pkg/session/external_striped_test.go`
- Modify: `pkg/session/external_v2.go`
- Modify: `pkg/session/external_v2_offer.go`

- [ ] **Step 1: Write failing observer and backlog tests**

Add these tests to `pkg/session/external_striped_test.go`:

```go
func TestExternalStripedCopyObserverRecordsBlockedSend(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	release := make(chan struct{})
	slowWriter := &blockingWriteCloser{release: release}
	fastWriter := &countingWriteCloser{}
	var blocked atomic.Int64
	observer := externalStripedCopyObserver{
		SendBlocked: func(d time.Duration) {
			blocked.Add(d.Milliseconds())
		},
	}
	done := make(chan error, 1)

	go func() {
		done <- sendExternalStripedCopyWithObserver(ctx, bytes.NewReader(bytes.Repeat([]byte("x"), 8)), []io.WriteCloser{slowWriter, fastWriter}, 1, observer)
	}()

	time.Sleep(50 * time.Millisecond)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if blocked.Load() == 0 {
		t.Fatal("blocked send duration was not recorded")
	}
}

func TestExternalStripedReceiveBacklogObserverTracksPending(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var maxChunks atomic.Int64
	var maxBytes atomic.Int64
	observer := externalStripedCopyObserver{
		ReceiveBacklog: func(chunks int, bytes int64) {
			for {
				old := maxChunks.Load()
				if int64(chunks) <= old || maxChunks.CompareAndSwap(old, int64(chunks)) {
					break
				}
			}
			for {
				old := maxBytes.Load()
				if bytes <= old || maxBytes.CompareAndSwap(old, bytes) {
					break
				}
			}
		},
	}

	pairs := newStripedPipeStreamPairs(t, 2)
	defer closeStripedPipeStreamPairs(pairs)
	errCh := make(chan error, 2)
	var got bytes.Buffer

	go func() {
		readers := []io.ReadCloser{pairs[0].listener, pairs[1].listener}
		errCh <- receiveExternalStripedCopyWithObserver(ctx, &got, readers, 4, observer)
	}()
	go func() {
		defer func() {
			_ = pairs[0].sender.Close()
			_ = pairs[1].sender.Close()
		}()
		if err := writeExternalStripedChunk(pairs[1].sender, externalStripedChunk{seq: 1, data: []byte("bbbb")}); err != nil {
			errCh <- err
			return
		}
		time.Sleep(50 * time.Millisecond)
		if err := writeExternalStripedChunk(pairs[0].sender, externalStripedChunk{seq: 0, data: []byte("aaaa")}); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if got.String() != "aaaabbbb" {
		t.Fatalf("got %q, want aaaabbbb", got.String())
	}
	if maxChunks.Load() == 0 || maxBytes.Load() == 0 {
		t.Fatalf("observer max chunks=%d bytes=%d, want backlog", maxChunks.Load(), maxBytes.Load())
	}
}
```

- [ ] **Step 2: Run the failing striped tests**

Run:

```bash
go test ./pkg/session -run 'TestExternalStripedCopyObserverRecordsBlockedSend|TestExternalStripedReceiveBacklogObserverTracksPending' -count=1
```

Expected: FAIL because `externalStripedCopyObserver`, `sendExternalStripedCopyWithObserver`, and `receiveExternalStripedCopyWithObserver` do not exist.

- [ ] **Step 3: Add observer types**

In `pkg/session/external_striped.go`, add:

```go
type externalStripedCopyObserver struct {
	SendBlocked    func(time.Duration)
	ReceiveBacklog func(chunks int, bytes int64)
}

func (o externalStripedCopyObserver) recordSendBlocked(d time.Duration) {
	if o.SendBlocked != nil && d > 0 {
		o.SendBlocked(d)
	}
}

func (o externalStripedCopyObserver) recordReceiveBacklog(chunks int, bytes int64) {
	if o.ReceiveBacklog != nil {
		o.ReceiveBacklog(chunks, bytes)
	}
}
```

Add `time` to the imports.

- [ ] **Step 4: Add observer wrappers and preserve existing API**

Change the existing functions to delegate:

```go
func sendExternalStripedCopy(ctx context.Context, src io.Reader, writers []io.WriteCloser, chunkSize int) error {
	return sendExternalStripedCopyWithObserver(ctx, src, writers, chunkSize, externalStripedCopyObserver{})
}

func sendExternalStripedCopyWithObserver(ctx context.Context, src io.Reader, writers []io.WriteCloser, chunkSize int, observer externalStripedCopyObserver) error {
	// existing sendExternalStripedCopy body, passing observer into sendExternalStripedChunks
}

func receiveExternalStripedCopy(ctx context.Context, dst io.Writer, readers []io.ReadCloser, chunkSize int) error {
	return receiveExternalStripedCopyWithObserver(ctx, dst, readers, chunkSize, externalStripedCopyObserver{})
}

func receiveExternalStripedCopyWithObserver(ctx context.Context, dst io.Writer, readers []io.ReadCloser, chunkSize int, observer externalStripedCopyObserver) error {
	// existing receiveExternalStripedCopy body, passing observer into receiveExternalStripedResults
}
```

- [ ] **Step 5: Record send blocking**

Change `sendExternalStripedChunkJob` to accept the observer:

```go
func sendExternalStripedChunkJob(ctx context.Context, jobs chan<- externalStripedChunk, errCh <-chan error, chunkPool *sync.Pool, seq uint64, data []byte, buf []byte, observer externalStripedCopyObserver) (uint64, error) {
	start := time.Now()
	select {
	case jobs <- externalStripedChunk{seq: seq, data: data}:
		observer.recordSendBlocked(time.Since(start))
		return seq + 1, nil
	case writeErr := <-errCh:
		putExternalStripedBuffer(chunkPool, buf)
		return seq, writeErr
	case <-ctx.Done():
		putExternalStripedBuffer(chunkPool, buf)
		return seq, ctx.Err()
	}
}
```

Pass `observer` from `sendExternalStripedChunks`.

- [ ] **Step 6: Record receive backlog**

Add a helper:

```go
func externalStripedPendingBytes(pending map[uint64][]byte) int64 {
	var total int64
	for _, chunk := range pending {
		total += int64(len(chunk))
	}
	return total
}
```

Call the observer after buffering and after flushing:

```go
observer.recordReceiveBacklog(len(pending), externalStripedPendingBytes(pending))
```

Pass `observer` into `receiveExternalStripedResults`, `flushExternalStripedPending`, and `handleExternalStripedReadResult`.

- [ ] **Step 7: Connect observer to metrics in v2 copy**

In `pkg/session/external_v2.go`, create the observer near `copyExternalV2SendStreams` and `copyExternalV2ReceiveStreams`:

```go
func externalV2StripedObserver(metrics *externalTransferMetrics) externalStripedCopyObserver {
	if metrics == nil {
		return externalStripedCopyObserver{}
	}
	return externalStripedCopyObserver{
		SendBlocked: func(d time.Duration) {
			metrics.RecordStripedSendBlocked(d, time.Now())
		},
		ReceiveBacklog: func(chunks int, bytes int64) {
			metrics.RecordStripedReceiveBacklog(chunks, bytes, time.Now())
		},
	}
}
```

Use it in both multi-stream calls:

```go
return sendExternalStripedCopyWithObserver(ctx, src, writers, externalV2CopyBufferSize, externalV2StripedObserver(metrics))
```

```go
err := receiveExternalStripedCopyWithObserver(ctx, recordDst, streams, externalV2CopyBufferSize, externalV2StripedObserver(metrics))
```

`pkg/session/external_v2_offer.go` uses these shared copy helpers, so no separate observer wiring is needed there unless the helper signature changes.

- [ ] **Step 8: Run focused copy tests**

Run:

```bash
go test ./pkg/session -run 'TestExternalStripedCopy|TestTransferTraceIncludesStripedCopyDiagnostics' -count=1
```

Expected: PASS.

- [ ] **Step 9: Checkpoint**

Run:

```bash
but diff
but commit codex/public-bulk-throughput-defaults -m "trace: instrument striped copy pipeline" --changes <ids>
```

Use the file IDs for `pkg/session/external_striped.go`, `pkg/session/external_striped_test.go`, `pkg/session/external_v2.go`, and `pkg/session/external_v2_offer.go` when changed.

---

### Task 4: Make No-Flag Transfers Use An Automatic Single-Stream Starting Policy

**Files:**
- Modify: `pkg/session/parallel.go`
- Modify: `pkg/session/parallel_test.go`
- Modify: `pkg/session/external_v2_protocol_test.go`
- Create: `cmd/derphole/parse_helpers_test.go`
- Modify: `cmd/derphole/receive_test.go`

- [ ] **Step 1: Write the failing default-policy test**

In `pkg/session/parallel_test.go`, replace `TestDefaultParallelPolicyUsesInitialStripeCount` with:

```go
func TestDefaultParallelPolicyUsesAutomaticSingleStreamStart(t *testing.T) {
	got := DefaultParallelPolicy()
	want := ParallelPolicy{
		Mode:    ParallelModeAuto,
		Initial: 1,
		Cap:     MaxParallelStripes,
	}
	if got != want {
		t.Fatalf("DefaultParallelPolicy() = %#v, want %#v", got, want)
	}
}
```

Add:

```go
func TestAutoParallelPolicyStartsWithOneStream(t *testing.T) {
	got := AutoParallelPolicy()
	if got.Mode != ParallelModeAuto || got.Initial != 1 || got.Cap != MaxParallelStripes {
		t.Fatalf("AutoParallelPolicy() = %#v, want auto initial=1 cap=%d", got, MaxParallelStripes)
	}
}
```

- [ ] **Step 2: Run the failing default-policy test**

Run:

```bash
go test ./pkg/session -run 'TestDefaultParallelPolicyUsesAutomaticSingleStreamStart|TestAutoParallelPolicyStartsWithOneStream|TestExternalV2ParallelPolicyDefaultsAndRoundTrips' -count=1
```

Expected: FAIL because the current default is fixed four and auto starts at four.

- [ ] **Step 3: Change the default policy**

In `pkg/session/parallel.go`, change:

```go
const (
	DefaultParallelInitial     = 1
	MaxParallelStripes         = 16
	AutoParallelSamplePeriod   = 500 * time.Millisecond
	AutoParallelGrowthStep     = 2
	AutoParallelTargetFloor    = 4
	AutoParallelHoldSamples    = 4
	AutoParallelMinGainMbps    = 50
	AutoParallelMinGainPercent = 10
)
```

Change `DefaultParallelPolicy`:

```go
func DefaultParallelPolicy() ParallelPolicy {
	return AutoParallelPolicy()
}
```

Keep `FixedParallelPolicy` unchanged so `-P 4` and `-P 8` remain diagnostic overrides.

- [ ] **Step 4: Update v2 protocol expectations**

In `pkg/session/external_v2_protocol_test.go`, keep the default round-trip assertion against `DefaultParallelPolicy()` and add:

```go
func TestExternalV2DefaultPolicyStartsOneStream(t *testing.T) {
	policy := externalV2ParallelPolicy(externalV2Claim{})
	if got := externalV2StreamCount(policy); got != 1 {
		t.Fatalf("externalV2StreamCount(default) = %d, want 1", got)
	}
}
```

Keep the existing fixed-policy assertion:

```go
mode, initial, cap := externalV2SetParallelPolicy(FixedParallelPolicy(8))
accept := externalV2Accept{ParallelMode: mode, ParallelInitial: initial, ParallelCap: cap}
if got, want := externalV2StreamCount(externalV2ParallelPolicy(accept)), 8; got != want {
	t.Fatalf("accept stream count = %d, want %d", got, want)
}
```

- [ ] **Step 5: Preserve CLI diagnostic override behavior**

Create `cmd/derphole/parse_helpers_test.go` with:

```go
package main

import (
	"io"
	"testing"

	"github.com/shayne/derphole/pkg/session"
)

func TestParseParallelPolicyEmptyUsesDefault(t *testing.T) {
	policy, code, failed := parseParallelPolicy("", io.Discard, func() string { return "" })
	if failed || code != 0 || policy != session.DefaultParallelPolicy() {
		t.Fatalf("empty parallel policy = %#v code=%d failed=%v, want default", policy, code, failed)
	}
}

func TestParseParallelPolicyFixedValueIsDiagnosticOverride(t *testing.T) {
	policy, code, failed := parseParallelPolicy("8", io.Discard, func() string { return "" })
	if failed || code != 0 || policy != session.FixedParallelPolicy(8) {
		t.Fatalf("parallel 8 policy = %#v code=%d failed=%v, want fixed 8", policy, code, failed)
	}
}
```

- [ ] **Step 6: Run focused policy tests**

Run:

```bash
go test ./pkg/session ./cmd/derphole -run 'TestDefaultParallelPolicy|TestAutoParallelPolicy|TestExternalV2DefaultPolicy|TestExternalV2ParallelPolicy|TestParseParallelPolicy|TestRunReceiveWithoutCodeAllocatesTransfer|TestRunReceiveWithCodeInvokesTransfer' -count=1
```

Expected: PASS.

- [ ] **Step 7: Checkpoint**

Run:

```bash
but diff
but commit codex/public-bulk-throughput-defaults -m "perf: default bulk transfers to automatic policy" --changes <ids>
```

Use the file IDs for `pkg/session/parallel.go`, `pkg/session/parallel_test.go`, `pkg/session/external_v2_protocol_test.go`, `cmd/derphole/parse_helpers_test.go`, and `cmd/derphole/receive_test.go`.

---

### Task 5: Run Diagnostic Policy Matrix And Decide Whether Single-Stream Default Holds

**Files:**
- Modify: `docs/benchmarks.md`
- Modify: `docs/superpowers/specs/2026-07-02-public-bulk-throughput-defaults-design.md` only if the evidence contradicts the approved success criteria.

- [ ] **Step 1: Build the current binary**

Run:

```bash
mise run build
```

Expected: `dist/derphole` exists and exits successfully with `dist/derphole version`.

- [ ] **Step 2: Run the no-flag four-host matrix**

Run:

```bash
DERPHOLE_PUBLIC_PATH_HOSTS='ubuntu@derphole-testing ubuntu@eric-nuc root@hetz root@canlxc' \
DERPHOLE_PUBLIC_PATH_SIZE_MIB=1024 \
DERPHOLE_PUBLIC_PATH_RUNS=3 \
DERPHOLE_PUBLIC_IPERF_PORT=8123 \
./scripts/public-path-performance-harness.sh
```

Expected: `summary.csv` contains 12 `iperf3` rows and 12 derphole no-flag rows. Every derphole row shows public direct path proof, byte count and SHA success, and zero remote bench files left after cleanup.

- [ ] **Step 3: Run fixed-policy diagnostic comparisons**

Run:

```bash
for p in 1 4 8; do
  DERPHOLE_BENCH_PARALLEL="${p}" \
  DERPHOLE_PUBLIC_PATH_HOSTS='ubuntu@derphole-testing ubuntu@eric-nuc root@hetz root@canlxc' \
  DERPHOLE_PUBLIC_PATH_SIZE_MIB=1024 \
  DERPHOLE_PUBLIC_PATH_RUNS=3 \
  DERPHOLE_PUBLIC_IPERF_PORT=8123 \
  DERPHOLE_BENCH_LOG_DIR=".tmp/public-path-performance-P${p}" \
  ./scripts/public-path-performance-harness.sh
done
```

Expected: each run produces its own `summary.csv`. These runs are diagnostic; they do not change the product UX.

- [ ] **Step 4: Apply the decision rule**

Use this rule:

- Keep the automatic one-stream start when no-flag derphole is within 10-15 percent of `iperf3` on `eric-nuc` and has no average throughput regression on the other hosts.
- Keep the automatic one-stream start when it is the best or tied-best derphole policy on at least three of four hosts and is the only policy that eliminates steady direct-phase trace stalls.
- If fixed `4` or fixed `8` beats no-flag by more than 15 percent on two or more hosts without reintroducing stalls, keep `DefaultParallelPolicy()` as `AutoParallelPolicy()` but change `AutoParallelPolicy().Initial` to the winning fixed count and document the evidence in `docs/benchmarks.md`.
- If none of the policies reaches at least 85 percent of `iperf3` on `eric-nuc`, keep the least-stalling no-flag policy and continue to Task 6 before claiming success.

- [ ] **Step 5: Document the evidence**

Append a dated subsection to `docs/benchmarks.md`:

```markdown
### 2026-07-02 Public Bulk Default Policy Matrix

The no-flag default was compared against diagnostic `DERPHOLE_BENCH_PARALLEL=1`, `4`, and `8` runs on `derphole-testing`, `eric-nuc`, `hetz`, and `canlxc`.

| Host | iperf3 avg Mbps | no-flag avg Mbps | no-flag ratio | best diagnostic policy | selected default reason |
| --- | ---: | ---: | ---: | --- | --- |
```

Generate the table rows with:

```bash
python3 - <<'PY'
import csv
from pathlib import Path

runs = {
    "no-flag": Path(".tmp/public-path-performance/summary.csv"),
    "P1": Path(".tmp/public-path-performance-P1/summary.csv"),
    "P4": Path(".tmp/public-path-performance-P4/summary.csv"),
    "P8": Path(".tmp/public-path-performance-P8/summary.csv"),
}
hosts = ["ubuntu_derphole-testing", "ubuntu_eric-nuc", "root_hetz", "root_canlxc"]

def rows(path):
    with path.open() as fh:
        return list(csv.DictReader(fh))

def avg(values):
    return sum(values) / len(values) if values else 0.0

payload = {name: rows(path) for name, path in runs.items()}
for host in hosts:
    iperf = avg(float(r["mbps"]) for r in payload["no-flag"] if r["host"] == host and r["tool"] == "iperf3")
    noflag = avg(float(r["mbps"]) for r in payload["no-flag"] if r["host"] == host and r["tool"] == "derphole")
    best_name = "no-flag"
    best_mbps = noflag
    for name in ["P1", "P4", "P8"]:
        value = avg(float(r["mbps"]) for r in payload[name] if r["host"] == host and r["tool"] == "derphole")
        if value > best_mbps:
            best_name = name
            best_mbps = value
    ratio = noflag / iperf if iperf else 0.0
    reason = "kept no-flag" if best_name == "no-flag" else f"diagnostic {best_name} led by {(best_mbps / noflag - 1) * 100:.1f}%"
    print(f"| `{host}` | {iperf:.2f} | {noflag:.2f} | {ratio:.3f} | {best_name} ({best_mbps:.2f} Mbps) | {reason} |")
PY
```

Paste the printed rows under the table header. Do not include raw local paths in the table.

- [ ] **Step 6: Checkpoint**

Run:

```bash
but diff
but commit codex/public-bulk-throughput-defaults -m "docs: record public throughput policy matrix" --changes <ids>
```

Use the file IDs for `docs/benchmarks.md` and any spec update made by the decision rule.

---

### Task 6: Tune The Remaining Bottleneck Exposed By Diagnostics

**Files:**
- Modify: `pkg/session/external_striped.go`
- Modify: `pkg/session/external_striped_test.go`
- Modify: `pkg/session/external_transfer_metrics.go`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Choose the bottleneck from trace evidence**

Use the first matching condition:

- When `max_striped_receive_pending_chunks` or `max_striped_receive_pending_bytes` grows while app bytes stall, tune receive reorder bounds in this task.
- When `max_striped_send_blocked_ms` grows while receiver backlog stays low, tune sender source-read and write scheduling in this task.
- When copy-pipeline diagnostics stay low but `peer_recv_queue_depth_max` grows, investigate `transport.Manager` receive queue in a follow-up plan.
- When copy-pipeline and manager diagnostics stay low but throughput remains far below `iperf3`, collect qlog and CPU profiles before changing QUIC config.

Record the selected condition in `docs/benchmarks.md` under the dated matrix section.

- [ ] **Step 2: Add receive backlog bounds when reorder is the bottleneck**

Add constants to `pkg/session/external_striped.go`:

```go
const (
	externalStripedMaxPendingChunks = 64
	externalStripedMaxPendingBytes  = 64 << 20
)
```

Add helper:

```go
func externalStripedPendingOverLimit(pending map[uint64][]byte) bool {
	return len(pending) >= externalStripedMaxPendingChunks ||
		externalStripedPendingBytes(pending) >= externalStripedMaxPendingBytes
}
```

In `receiveExternalStripedResults`, when no contiguous chunk can flush and pending is over limit, continue flushing only after the missing sequence arrives by blocking on `results` without reading unlimited fast-stripe chunks into memory. Preserve context cancellation.

- [ ] **Step 3: Add a test for bounded pending**

Add to `pkg/session/external_striped_test.go`:

```go
func TestExternalStripedReceiveDoesNotGrowPendingBeyondLimit(t *testing.T) {
	pending := make(map[uint64][]byte)
	for i := uint64(1); i <= externalStripedMaxPendingChunks; i++ {
		pending[i] = []byte("x")
	}
	if !externalStripedPendingOverLimit(pending) {
		t.Fatal("pending limit was not detected")
	}
}
```

- [ ] **Step 4: Run focused tests**

Run:

```bash
go test ./pkg/session -run 'TestExternalStripedReceiveDoesNotGrowPendingBeyondLimit|TestExternalStripedCopy' -count=1
```

Expected: PASS.

- [ ] **Step 5: Re-run the smallest live confirmation**

Run:

```bash
DERPHOLE_PUBLIC_PATH_HOSTS='ubuntu@eric-nuc' \
DERPHOLE_PUBLIC_PATH_SIZE_MIB=1024 \
DERPHOLE_PUBLIC_PATH_RUNS=3 \
DERPHOLE_PUBLIC_IPERF_PORT=8123 \
./scripts/public-path-performance-harness.sh
```

Expected: no-flag derphole improves or remains equal, `transfertracecheck` stalls do not increase, and new copy-pipeline diagnostics explain the result.

- [ ] **Step 6: Checkpoint**

Run:

```bash
but diff
but commit codex/public-bulk-throughput-defaults -m "perf: bound striped copy backlog" --changes <ids>
```

Use the file IDs for changed `pkg/session` files and `docs/benchmarks.md`.

---

### Task 7: Full Verification And Final Performance Gate

**Files:**
- Modify only files required by failures found in this task.

- [ ] **Step 1: Run focused package tests**

Run:

```bash
go test ./pkg/session ./pkg/transfertrace ./tools/transfertracecheck ./cmd/derphole ./scripts -count=1
```

Expected: PASS.

- [ ] **Step 2: Run full test suite**

Run:

```bash
mise run test
```

Expected: PASS.

- [ ] **Step 3: Run local smoke when transport behavior changed**

Run:

```bash
mise run smoke-local
```

Expected: PASS with byte count and hash verification.

- [ ] **Step 4: Run the four-host final gate**

Run:

```bash
DERPHOLE_PUBLIC_PATH_HOSTS='ubuntu@derphole-testing ubuntu@eric-nuc root@hetz root@canlxc' \
DERPHOLE_PUBLIC_PATH_SIZE_MIB=1024 \
DERPHOLE_PUBLIC_PATH_RUNS=3 \
DERPHOLE_PUBLIC_IPERF_PORT=8123 \
./scripts/public-path-performance-harness.sh
```

Expected:

- `eric-nuc` no-flag derphole average is at least 85 percent of same-run `iperf3`, or the diagnostics prove a specific external limit.
- `derphole-testing`, `hetz`, and `canlxc` no-flag derphole averages do not regress against the July 2 baseline matrix.
- sender and receiver `transfertracecheck` pass with `-stall-window 1s`.
- traces show public direct path for public-path claims.
- byte counts and SHA-256 checks pass.
- cleanup leaves no remote derphole processes, no lingering benchmark files, and no local listeners.

- [ ] **Step 5: Run pre-commit checks**

Run:

```bash
mise run check:hooks
```

Expected: PASS.

- [ ] **Step 6: Final checkpoint or amend**

Run:

```bash
but status -fv
```

If verification fixes produced uncommitted changes, commit them:

```bash
but diff
but commit codex/public-bulk-throughput-defaults -m "test: verify public bulk throughput defaults" --changes <ids>
```

Expected: GitButler shows no unrelated uncommitted changes.
