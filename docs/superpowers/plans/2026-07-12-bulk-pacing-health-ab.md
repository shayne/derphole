# Bulk Pacing Health Instrumentation and A/B Tuning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make local UDP buffer pressure visible in transfer traces, add a safe test-only bulk initial-rate control, and select the fastest healthy default that remains scalable, stable, and efficient across every reachable test network without hiding loss behind repair traffic.

**Architecture:** Count macOS `ENOBUFS` events only on the existing transient-error branch, publish cumulative pressure counters through the existing direct diagnostics and transfer-trace pipeline, and leave successful packet writes on the current hot path. Add a test-only initial-rate environment override that feeds the existing controller and pacer while preserving the production default when unset. Extend the existing trace checker and public-path harness so Eric's balanced 1,000/900/800 Mbps schedule selects a candidate, apply paired A/B rejection to reachable host-directions that negotiate bulk packets, then run mode-aware three-transfer acceptance on every reachable host-direction before promoting a production default.

**Tech Stack:** Go 1.26.5 through `mise`, `net.PacketConn`, atomics, CSV transfer traces, Bash, GitButler, SSH, normal file `send`/`receive`, and TCP `iperf3` through forwarded port 8123.

## Global Constraints

- The primary tuning workload is a normal 3 GiB file `send`/`receive` from this Mac to `ubuntu@eric-nuc`; do not use `listen`/`pipe` as product acceptance.
- The fleet gate uses normal 1 GiB file transfers in both directions on every reachable host in the canonical inventory: `ubuntu@derphole-testing`, `ubuntu@eric-nuc`, `root@hetz`, `root@canlxc`, `root@ktzlxc`, `root@uklxc`, `november-oscar.exe.xyz`, and `root@pve1`.
- Probe the full canonical inventory immediately before the fleet gate. Record unreachable hosts and their SSH failure status in the run artifact; never silently remove a host from the matrix.
- Normalize performance to same-host, same-direction `iperf3` and each host's own 1,000 Mbps-control rows. Absolute Mbps is evidence, not a cross-host pass threshold.
- `pve1` is a labeled same-LAN case. All other accepted fleet rows must demonstrate a public non-Tailscale path.
- Every public-path experiment sets `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` on both peers. Production candidate discovery remains unchanged.
- Users receive no new performance flag. `DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS` is test-only and defaults to the current 1,000 Mbps policy when unset or invalid.
- Preserve the current `bulk-packets-v1` wire format and cross-version compatibility.
- Continue retrying only `errors.Is(err, syscall.ENOBUFS)`. Permanent UDP errors, short writes, and context cancellation retain their current behavior.
- Do not log each `ENOBUFS` event. The hot error branch updates atomics; the existing 500 ms trace publisher reads them.
- Append CSV columns instead of renaming or reordering existing columns.
- Do not change the production initial rate until Eric's balanced tuning matrix and every applicable reachable-fleet bulk A/B cell pass, followed by mode-aware forward/reverse acceptance on every reachable host with integrity, trace, route, cleanup, capacity-normalized performance, stability, and efficiency gates.
- Top performance is the primary decision criterion. When median goodput is statistically indistinguishable within 3 percent, prefer lower repair overhead and a higher receiver p10 rate.
- Every production change follows red-green-refactor. Run each named test and observe the expected failure before implementing its change.
- Use GitButler for normal version-control writes. Preserve unrelated user and agent work, and stop if `but pull --check` reports overlap or conflicts.

---

## File Structure

### Modify

- `pkg/session/external_v2_bulk_packet.go` — count local `ENOBUFS` retries and wait time, select the test-only initial rate, and publish both through terminal and periodic direct diagnostics.
- `pkg/session/external_v2_bulk_packet_test.go` — retry-pressure accounting, cancellation accounting, selected-rate, and terminal-diagnostics coverage.
- `pkg/session/external_v2_bulk_packet_controller.go` — distinguish the production default from a supplied per-sender initial target.
- `pkg/session/external_v2_bulk_packet_controller_test.go` — controller initialization at 1,000, 900, and 800 Mbps while preserving all existing decisions.
- `pkg/session/external_transfer_metrics.go` — monotonic storage and snapshot projection for local buffer-pressure diagnostics.
- `pkg/session/external_transfer_metrics_test.go` — trace propagation and non-regression tests for the new counters.
- `pkg/transfertrace/trace.go` — append local `ENOBUFS` columns to the trace schema and serialize them.
- `pkg/transfertrace/trace_test.go` — exact header and row serialization coverage.
- `pkg/transfertrace/checker.go` — compute rate-target, repair, local-pressure, and receiver interval-rate health summaries.
- `pkg/transfertrace/checker_test.go` — percentile, coefficient-of-variation, low-window, controller-decrease, and pressure-counter tests.
- `tools/transfertracecheck/main.go` — print stable machine-readable health keys in the existing one-line summary.
- `tools/transfertracecheck/main_test.go` — exact summary-output coverage.
- `scripts/promotion-benchmark-driver.sh` — validate and propagate the test-only initial target to the active peer and remote process environment.
- `scripts/public-path-performance-harness.sh` — execute balanced initial-rate schedules in forward or reverse direction and add health columns to `summary.csv`.
- `scripts/promotion_scripts_test.go` — source-contract tests for propagation, schedule validation, and summary schema.
- `docs/benchmarks.md` — document the counters, schedule, decision gate, and exact public-path command.

### Do Not Create

- Do not create a second packet engine, protocol version, transfer mode, or public-path harness.
- Do not commit generated `dist/` output or machine-specific benchmark payloads.
- Keep live run artifacts under `.tmp/bulk-pacing-ab-20260712/`.

---

### Task 0: Checkpoint the approved plan on its own branch

**Files:**

- Create: `docs/superpowers/plans/2026-07-12-bulk-pacing-health-ab.md`

**Interfaces:**

- Consumes: this reviewed implementation plan.
- Produces: GitButler branch `codex/bulk-pacing-health` with the plan isolated from unrelated workspace changes.

- [ ] **Step 1: Verify the base and plan-only diff**

Run:

```bash
but pull --check
but diff
```

Expected: the base is current and the only uncommitted file is `docs/superpowers/plans/2026-07-12-bulk-pacing-health-ab.md`. Stop if any unrelated file is present.

- [ ] **Step 2: Commit the plan and create the branch**

Run:

```bash
but commit codex/bulk-pacing-health -c -m "docs: plan bulk pacing health experiment"
```

Expected: a plan-only commit on `codex/bulk-pacing-health` and no remaining uncommitted changes.

---

### Task 1: Trace local `ENOBUFS` pressure end to end

**Files:**

- Modify: `pkg/session/external_v2_bulk_packet.go:249-378,492-529`
- Modify: `pkg/session/external_v2_bulk_packet_test.go:151-242,570-615`
- Modify: `pkg/session/external_transfer_metrics.go:100-121,645-810`
- Modify: `pkg/session/external_transfer_metrics_test.go:370-445`
- Modify: `pkg/transfertrace/trace.go:28-151,380-430`
- Modify: `pkg/transfertrace/trace_test.go:180-320`

**Interfaces:**

- Consumes: the existing `errors.Is(err, syscall.ENOBUFS)` retry branch and `externalDirectTransferDiagnostics` publication path.
- Produces: cumulative `LocalENOBUFSRetries`, `LocalENOBUFSWaitUS`, and `LocalENOBUFSMaxConsecutive` diagnostics plus CSV columns `local_enobufs_retries`, `local_enobufs_wait_us`, and `local_enobufs_max_consecutive`.

- [ ] **Step 1: Write failing sender pressure tests**

Add these assertions to `pkg/session/external_v2_bulk_packet_test.go` after the existing transient retry test. Reuse `transientWriteFailureBulkPacketConn` so the error shape remains `net.OpError -> os.SyscallError -> syscall.ENOBUFS`:

```go
func TestExternalV2BulkPacketSendPacketCountsLocalENOBUFSPressure(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn := &transientWriteFailureBulkPacketConn{PacketConn: senders[0]}
	conn.remaining.Store(3)
	sender := newExternalV2BulkPacketSender(
		context.Background(),
		&BlockSource{Payload: bytes.NewReader([]byte{0x5a}), PayloadSize: 1},
		externalV2BulkPacketPath{
			Conns: []net.PacketConn{conn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		},
		auth,
		nil,
	)
	sender.pacer = rate.NewLimiter(0, externalV2BulkPacketPaceBurstBytes)

	if err := sender.sendPacket(0, 0, false); err != nil {
		t.Fatal(err)
	}
	if got := sender.localENOBUFSRetries.Load(); got != 3 {
		t.Fatalf("local ENOBUFS retries = %d, want 3", got)
	}
	if got := sender.localENOBUFSMaxConsecutive.Load(); got != 3 {
		t.Fatalf("max consecutive local ENOBUFS = %d, want 3", got)
	}
	if got := sender.localENOBUFSWaitNanos.Load(); got <= 0 {
		t.Fatalf("local ENOBUFS wait nanos = %d, want positive", got)
	}
}

func TestExternalV2BulkPacketCancellationPublishesENOBUFSEvent(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn := &transientWriteFailureBulkPacketConn{
		PacketConn: senders[0],
		attempted:  make(chan struct{}),
	}
	conn.remaining.Store(3)
	ctx, cancel := context.WithCancel(context.Background())
	sender := newExternalV2BulkPacketSender(
		ctx,
		&BlockSource{Payload: bytes.NewReader([]byte{0x5a}), PayloadSize: 1},
		externalV2BulkPacketPath{
			Conns: []net.PacketConn{conn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		},
		auth,
		nil,
	)
	sender.pacer = rate.NewLimiter(0, externalV2BulkPacketPaceBurstBytes)
	errCh := make(chan error, 1)
	go func() { errCh <- sender.sendPacket(0, 0, false) }()
	<-conn.attempted
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("sendPacket() error = %v, want context canceled", err)
	}
	if got := sender.localENOBUFSRetries.Load(); got != 1 {
		t.Fatalf("local ENOBUFS retries = %d, want 1", got)
	}
}
```

- [ ] **Step 2: Run the sender tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(SendPacketCountsLocalENOBUFSPressure|CancellationPublishesENOBUFSEvent)$' -count=1
```

Expected: build failure because `localENOBUFSRetries`, `localENOBUFSWaitNanos`, and `localENOBUFSMaxConsecutive` do not exist.

- [ ] **Step 3: Implement atomic pressure accounting on the existing error branch**

Add these fields to `externalV2BulkPacketSender`:

```go
	localENOBUFSRetries        atomic.Int64
	localENOBUFSWaitNanos      atomic.Int64
	localENOBUFSMaxConsecutive atomic.Int64
```

Replace `writeExternalV2BulkPacketData` with a sender method and call it from `sendPacket`:

```go
func (s *externalV2BulkPacketSender) writeDataPacket(lane int, packet []byte) (int, error) {
	consecutive := int64(0)
	for {
		n, err := s.path.Conns[lane].WriteTo(packet, s.path.Addrs[lane])
		if !errors.Is(err, syscall.ENOBUFS) {
			return n, err
		}

		consecutive++
		s.localENOBUFSRetries.Add(1)
		updateExternalV2BulkPacketAtomicMax(&s.localENOBUFSMaxConsecutive, consecutive)
		waitStarted := time.Now()
		timer := time.NewTimer(externalV2BulkPacketWriteRetryDelay)
		select {
		case <-timer.C:
			s.localENOBUFSWaitNanos.Add(time.Since(waitStarted).Nanoseconds())
		case <-s.ctx.Done():
			timer.Stop()
			s.localENOBUFSWaitNanos.Add(time.Since(waitStarted).Nanoseconds())
			return 0, s.ctx.Err()
		}
	}
}

func updateExternalV2BulkPacketAtomicMax(counter *atomic.Int64, candidate int64) {
	for {
		current := counter.Load()
		if candidate <= current || counter.CompareAndSwap(current, candidate) {
			return
		}
	}
}

func externalV2BulkPacketRoundedUpMicroseconds(nanos int64) int64 {
	if nanos <= 0 {
		return 0
	}
	return (nanos + int64(time.Microsecond) - 1) / int64(time.Microsecond)
}
```

In `sendPacket`, replace the direct helper call with:

```go
	n, err := s.writeDataPacket(lane, packet)
```

This records only the exceptional branch and does not add an atomic operation to successful writes.

- [ ] **Step 4: Run the sender tests and verify GREEN**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(SendPacketRetriesTransientNoBufferSpace|SendPacketStopsNoBufferSpaceRetriesOnCancellation|SendPacketCountsLocalENOBUFSPressure|CancellationPublishesENOBUFSEvent)$' -count=20
```

Expected: PASS for all 80 test executions.

- [ ] **Step 5: Write failing trace propagation tests**

Append the three new fields to `externalDirectTransferDiagnostics`, `externalTransferMetrics`, and `transfertrace.Snapshot` in the tests first. In `TestExternalTransferMetricsRecordsControllerBeforeCompletion`, include:

```go
	metrics.SetDirectDiagnostics(externalDirectTransferDiagnostics{
		RateTargetMbps:             850,
		ControllerDecision:         "decrease",
		ControllerReason:           "repair-pressure",
		Retransmits:                12,
		RepairRequests:             3,
		RepairBytes:                16_296,
		LocalENOBUFSRetries:        7,
		LocalENOBUFSWaitUS:         913,
		LocalENOBUFSMaxConsecutive: 3,
	}, start.Add(600*time.Millisecond))
```

Extend the row assertions with:

```go
	if rows[1]["local_enobufs_retries"] != "7" ||
		rows[1]["local_enobufs_wait_us"] != "913" ||
		rows[1]["local_enobufs_max_consecutive"] != "3" {
		t.Fatalf("local ENOBUFS trace columns = %#v", rows[1])
	}
```

Add a non-regression case to `TestExternalTransferMetricsDirectCountersNeverRegress` that publishes `7/913/3`, then `2/100/1`, and expects the stored values to remain `7/913/3`.

- [ ] **Step 6: Run the metrics tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalTransferMetrics(RecordsControllerBeforeCompletion|DirectCountersNeverRegress)$' -count=1
```

Expected: build failure because the new diagnostic fields and CSV columns do not exist.

- [ ] **Step 7: Implement diagnostics and append trace columns**

Add these fields to `externalDirectTransferDiagnostics`, `externalTransferMetrics`, and `transfertrace.Snapshot`:

```go
	LocalENOBUFSRetries        int64
	LocalENOBUFSWaitUS         int64
	LocalENOBUFSMaxConsecutive int64
```

Append these names immediately after `repair_bytes` in `pkg/transfertrace/trace.go`:

```go
	"local_enobufs_retries",
	"local_enobufs_wait_us",
	"local_enobufs_max_consecutive",
```

Append the matching row values immediately after `snap.RepairBytes`:

```go
		formatOptionalInt64(snap.LocalENOBUFSRetries),
		formatOptionalInt64(snap.LocalENOBUFSWaitUS),
		formatOptionalInt64(snap.LocalENOBUFSMaxConsecutive),
```

Copy the fields into `updateTraceLocked`, and update them monotonically in `setDirectCounterDiagnosticsLocked`:

```go
	if diagnostics.LocalENOBUFSRetries > m.localENOBUFSRetries {
		m.localENOBUFSRetries = diagnostics.LocalENOBUFSRetries
	}
	if diagnostics.LocalENOBUFSWaitUS > m.localENOBUFSWaitUS {
		m.localENOBUFSWaitUS = diagnostics.LocalENOBUFSWaitUS
	}
	if diagnostics.LocalENOBUFSMaxConsecutive > m.localENOBUFSMaxConsecutive {
		m.localENOBUFSMaxConsecutive = diagnostics.LocalENOBUFSMaxConsecutive
	}
```

Add the same fields to both `publishControllerDiagnostics` and the terminal value returned by `stats`:

```go
		LocalENOBUFSRetries:        s.localENOBUFSRetries.Load(),
		LocalENOBUFSWaitUS:         externalV2BulkPacketRoundedUpMicroseconds(s.localENOBUFSWaitNanos.Load()),
		LocalENOBUFSMaxConsecutive: s.localENOBUFSMaxConsecutive.Load(),
```

- [ ] **Step 8: Run trace and session tests**

Run:

```bash
mise exec -- go test ./pkg/transfertrace ./pkg/session -run 'Test(Trace|ExternalTransferMetrics|ExternalV2BulkPacket)' -count=1
```

Expected: PASS with the three appended columns populated on sender rows and empty or zero on receiver rows.

- [ ] **Step 9: Commit the pressure telemetry**

Run:

```bash
but commit codex/bulk-pacing-health -m "session: trace local udp buffer pressure"
```

Expected: one commit containing only the session, metrics, transfer-trace, and test changes from Task 1.

---

### Task 2: Add a test-only initial bulk pacing target

**Files:**

- Modify: `pkg/session/external_v2_bulk_packet_controller.go:12-67`
- Modify: `pkg/session/external_v2_bulk_packet_controller_test.go:11-540`
- Modify: `pkg/session/external_v2_bulk_packet.go:252-281,493-529,1210-1260`
- Modify: `pkg/session/external_v2_bulk_packet_test.go:20-615`

**Interfaces:**

- Consumes: `DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS`, the 128 Mbps minimum, and the 2,400 Mbps ceiling.
- Produces: `externalV2BulkPacketInitialWireMbps() int`, `newExternalV2BulkPacketController(initialMbps int)`, and sender field `initialPaceMbps int`.

- [ ] **Step 1: Write failing environment and controller tests**

Add to `pkg/session/external_v2_bulk_packet_controller_test.go`:

```go
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
```

- [ ] **Step 2: Run the controller tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(InitialWireMbpsFromEnvironment|ControllerUsesSuppliedInitialTarget)$' -count=1
```

Expected: build failure because the environment constant, parser, and constructor argument do not exist.

- [ ] **Step 3: Implement the parser and supplied controller target**

Add `os`, `strconv`, and `strings` imports to `external_v2_bulk_packet_controller.go`, rename the current default constant, and add:

```go
const (
	externalV2BulkPacketInitialWireMbpsEnv         = "DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS"
	externalV2BulkPacketDefaultInitialWireMbps     = 1000
	externalV2BulkPacketCeilingWireMbps            = 2400
	externalV2BulkPacketMinimumWireMbps            = 128
)

func externalV2BulkPacketInitialWireMbps() int {
	raw := strings.TrimSpace(os.Getenv(externalV2BulkPacketInitialWireMbpsEnv))
	if raw == "" {
		return externalV2BulkPacketDefaultInitialWireMbps
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < externalV2BulkPacketMinimumWireMbps || value > externalV2BulkPacketCeilingWireMbps {
		return externalV2BulkPacketDefaultInitialWireMbps
	}
	return value
}

func newExternalV2BulkPacketController(initialMbps int) *externalV2BulkPacketController {
	return &externalV2BulkPacketController{targetMbps: initialMbps}
}
```

Update existing production and test call sites to pass `externalV2BulkPacketDefaultInitialWireMbps` unless a test explicitly supplies another target.

- [ ] **Step 4: Make sender pacing and diagnostics use the selected target**

Add `initialPaceMbps int` to `externalV2BulkPacketSender`. In `newExternalV2BulkPacketSender`, select once and use it for the controller, limiter, and current target:

```go
	initialPaceMbps := externalV2BulkPacketInitialWireMbps()
	controller := newExternalV2BulkPacketController(initialPaceMbps)
	sender := &externalV2BulkPacketSender{
		ctx:             ctx,
		src:             src,
		path:            path,
		auth:            auth,
		metrics:         metrics,
		initialPaceMbps: initialPaceMbps,
		runID:           randomExternalV2BulkPacketRunID(),
		totalPackets:    externalV2BulkPacketCount(src.PayloadSize),
		laneCount:       min(len(path.Conns), len(path.Addrs)),
		pacer: rate.NewLimiter(
			externalV2BulkPacketRateLimit(initialPaceMbps),
			externalV2BulkPacketPaceBurstBytes,
		),
		controller: controller,
	}
	sender.currentPaceMbps.Store(int64(initialPaceMbps))
```

Use `s.initialPaceMbps` for `RateSelectedMbps` in periodic diagnostics. Add an `initialPaceMbps` argument to `externalV2BulkPacketSendStats` and use it for terminal `RateSelectedMbps`; update the two direct unit-test calls with `1000`.

- [ ] **Step 5: Run controller, sender, and trace tests**

Run:

```bash
mise exec -- go test ./pkg/session ./pkg/transfertrace -run 'TestExternalV2BulkPacket|TestExternalTransferMetrics|TestTrace' -count=1
```

Expected: PASS, with an 800 Mbps environment override appearing as both initial `rate_target_mbps` and `rate_selected_mbps`.

- [ ] **Step 6: Commit the test-only target**

Run:

```bash
but commit codex/bulk-pacing-health -m "session: add test-only bulk initial rate"
```

Expected: a second commit containing only Task 2.

---

### Task 3: Make transfer health machine-readable

**Files:**

- Modify: `pkg/transfertrace/checker.go:20-200,280-350,800-870`
- Modify: `pkg/transfertrace/checker_test.go:250-430`
- Modify: `tools/transfertracecheck/main.go:50-105`
- Modify: `tools/transfertracecheck/main_test.go:45-125`

**Interfaces:**

- Consumes: sender and receiver trace columns already validated by `transfertrace.Check`.
- Produces: health keys `min_rate_target_mbps`, `final_rate_target_mbps`, `controller_decreases`, `final_repair_bytes`, `local_enobufs_retries`, `local_enobufs_wait_us`, `local_enobufs_max_consecutive`, `receiver_rate_p10_mbps`, `receiver_rate_p50_mbps`, `receiver_rate_p90_mbps`, `receiver_rate_cv`, and `receiver_windows_below_500_mbps`.

- [ ] **Step 1: Write a failing checker health test**

Extend `testTraceRowConfig` and `testTraceRow` with `appMbps`, `controllerDecision`, `repairBytes`, and the three local-pressure fields. Then add these two fixtures:

```go
func TestCheckReportsSenderHealthDiagnostics(t *testing.T) {
	csvText := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:            1000,
			role:                   RoleSend,
			phase:                  PhaseDirectExecute,
			appBytes:               1024,
			deltaAppBytes:          1024,
			directValidated:        true,
			lastState:              "connected-direct",
			rateTargetMbps:         1000,
			controllerDecision:     "hold",
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:            1500,
			elapsedMS:              500,
			role:                   RoleSend,
			phase:                  PhaseDirectExecute,
			appBytes:               1536,
			deltaAppBytes:          512,
			directValidated:        true,
			lastState:              "connected-direct",
			rateTargetMbps:         850,
			controllerDecision:     "decrease",
			repairBytes:            256 << 20,
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:            1750,
			elapsedMS:              750,
			role:                   RoleSend,
			phase:                  PhaseDirectExecute,
			appBytes:               1536,
			deltaAppBytes:          0,
			directValidated:        true,
			lastState:              "connected-direct",
			rateTargetMbps:         850,
			controllerDecision:     "decrease",
			repairBytes:            256 << 20,
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:                   2000,
			elapsedMS:                     1000,
			role:                          RoleSend,
			phase:                         PhaseComplete,
			appBytes:                      2048,
			deltaAppBytes:                 512,
			directValidated:               true,
			lastState:                     "stream-complete",
			rateTargetMbps:                722,
			controllerDecision:            "decrease",
			repairBytes:                   512 << 20,
			localENOBUFSRetries:           9,
			localENOBUFSWaitUS:            1400,
			localENOBUFSMaxConsecutive:    4,
		})
	result, err := Check(strings.NewReader(csvText), Options{
		Role: RoleSend, StallWindow: time.Second,
		ExpectedBytes: 2048, ExpectedBytesSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
```

Assert:

```go
	if got := result.Diagnostics.MinRateTargetMbps; got != 722 {
		t.Fatalf("MinRateTargetMbps = %d, want 722", got)
	}
	if got := result.Diagnostics.FinalRateTargetMbps; got != 722 {
		t.Fatalf("FinalRateTargetMbps = %d, want 722", got)
	}
	if got := result.Diagnostics.ControllerDecreases; got != 2 {
		t.Fatalf("ControllerDecreases = %d, want 2", got)
	}
	if got := result.Diagnostics.FinalRepairBytes; got != 512<<20 {
		t.Fatalf("FinalRepairBytes = %d, want %d", got, 512<<20)
	}
	if got := result.Diagnostics.LocalENOBUFSRetries; got != 9 {
		t.Fatalf("LocalENOBUFSRetries = %d, want 9", got)
	}
	if got := result.Diagnostics.LocalENOBUFSWaitUS; got != 1400 {
		t.Fatalf("LocalENOBUFSWaitUS = %d, want 1400", got)
	}
	if got := result.Diagnostics.LocalENOBUFSMaxConsecutive; got != 4 {
		t.Fatalf("LocalENOBUFSMaxConsecutive = %d, want 4", got)
	}
```

Add the receiver-rate fixture and assertions:

```go
	var receiverTrace strings.Builder
	receiverTrace.WriteString(HeaderLine + "\n")
	for index, rate := range []string{"200", "400", "600", "800", "1000"} {
		receiverTrace.WriteString(testTraceRow(testTraceRowConfig{
			timestampMS:     1000 + int64(index)*500,
			elapsedMS:       int64(index) * 500,
			role:            RoleReceive,
			phase:           PhaseDirectExecute,
			appBytes:        int64(index+1) * 1024,
			deltaAppBytes:   1024,
			appMbps:         rate,
			directValidated: true,
			lastState:       "connected-direct",
		}))
	}
	receiverTrace.WriteString(testTraceRow(testTraceRowConfig{
		timestampMS:     3500,
		elapsedMS:       2500,
		role:            RoleReceive,
		phase:           PhaseComplete,
		appBytes:        5120,
		deltaAppBytes:   0,
		directValidated: true,
		lastState:       "stream-complete",
	}))
	result, err = Check(strings.NewReader(receiverTrace.String()), Options{
		Role: RoleReceive, StallWindow: time.Second,
		ExpectedBytes: 5120, ExpectedBytesSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Diagnostics.ReceiverRateP10Mbps; got != 280 {
		t.Fatalf("ReceiverRateP10Mbps = %.2f, want 280", got)
	}
	if got := result.Diagnostics.ReceiverRateP50Mbps; got != 600 {
		t.Fatalf("ReceiverRateP50Mbps = %.2f, want 600", got)
	}
	if got := result.Diagnostics.ReceiverRateP90Mbps; got != 920 {
		t.Fatalf("ReceiverRateP90Mbps = %.2f, want 920", got)
	}
	if got := result.Diagnostics.ReceiverWindowsBelow500Mbps; got != 2 {
		t.Fatalf("ReceiverWindowsBelow500Mbps = %d, want 2", got)
	}
```

- [ ] **Step 2: Run the checker tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/transfertrace -run 'TestCheck.*Health' -count=1
```

Expected: build failure because the health summary fields do not exist.

- [ ] **Step 3: Extend checker indexes and diagnostics**

Add `appMbps` and `controllerDecision` indexes, parse only positive `app_mbps` values from active direct receiver rows, and append these fields to `DiagnosticsSummary`:

```go
	MinRateTargetMbps              int
	FinalRateTargetMbps            int
	ControllerDecreases            int
	FinalRepairBytes               int64
	LocalENOBUFSRetries            int64
	LocalENOBUFSWaitUS             int64
	LocalENOBUFSMaxConsecutive     int64
	ReceiverRateP10Mbps            float64
	ReceiverRateP50Mbps            float64
	ReceiverRateP90Mbps            float64
	ReceiverRateCV                 float64
	ReceiverWindowsBelow500Mbps    int
	ReceiverRateObserved           bool
	SenderHealthObserved           bool
```

Use linear-interpolated percentiles and population standard deviation:

```go
func checkerPercentile(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	slices.Sort(values)
	position := float64(len(values)-1) * percentile
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return values[lower]
	}
	weight := position - float64(lower)
	return values[lower]*(1-weight) + values[upper]*weight
}

func checkerCoefficientOfVariation(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	mean := 0.0
	for _, value := range values {
		mean += value
	}
	mean /= float64(len(values))
	if mean == 0 {
		return 0
	}
	variance := 0.0
	for _, value := range values {
		delta := value - mean
		variance += delta * delta
	}
	return math.Sqrt(variance/float64(len(values))) / mean
}
```

Count distinct decreases in `rate_target_mbps`: compare each sender row's positive target with the previous distinct positive target, and count the row when `controller_decision=decrease` and the target is lower. Consecutive `decision=decrease` rows at different lower targets count separately, while duplicate paired event/tick rows at the same target count once. The fixture's `1000 -> 850 -> 850 -> 722` sequence therefore expects two decreases. Treat the cumulative repair and local-pressure fields as final monotonic counters.

- [ ] **Step 4: Add the new optional numeric columns to checker validation**

Append:

```go
	{name: "local_enobufs_retries", kind: checkerNumericDiagnosticInt64},
	{name: "local_enobufs_wait_us", kind: checkerNumericDiagnosticInt64},
	{name: "local_enobufs_max_consecutive", kind: checkerNumericDiagnosticInt64},
```

Keep older traces valid: absent optional columns must produce zero values and `ReceiverRateObserved=false` where appropriate. Set `SenderHealthObserved=true` only for sender traces whose header contains the current sender-health schema, including the three local `ENOBUFS` columns. A current-schema sender trace with healthy zero counters is observed health, not missing data.

- [ ] **Step 5: Print stable health keys from `transfertracecheck`**

Extend `formatDiagnosticsSummary` so all harness-consumed sender health keys are emitted together whenever `SenderHealthObserved` is true, including numeric zeroes. Remove the earlier conditional `max_retransmits` emission so the key remains unique:

```go
	if diagnostics.SenderHealthObserved {
		summary += fmt.Sprintf(" min_rate_target_mbps=%d final_rate_target_mbps=%d controller_decreases=%d final_repair_bytes=%d max_retransmits=%d local_enobufs_retries=%d local_enobufs_wait_us=%d local_enobufs_max_consecutive=%d",
			diagnostics.MinRateTargetMbps,
			diagnostics.FinalRateTargetMbps,
			diagnostics.ControllerDecreases,
			diagnostics.FinalRepairBytes,
			diagnostics.MaxRetransmits,
			diagnostics.LocalENOBUFSRetries,
			diagnostics.LocalENOBUFSWaitUS,
			diagnostics.LocalENOBUFSMaxConsecutive,
		)
	}
	if diagnostics.ReceiverRateObserved {
		summary += fmt.Sprintf(" receiver_rate_p10_mbps=%.2f receiver_rate_p50_mbps=%.2f receiver_rate_p90_mbps=%.2f receiver_rate_cv=%.3f receiver_windows_below_500_mbps=%d",
			diagnostics.ReceiverRateP10Mbps,
			diagnostics.ReceiverRateP50Mbps,
			diagnostics.ReceiverRateP90Mbps,
			diagnostics.ReceiverRateCV,
			diagnostics.ReceiverWindowsBelow500Mbps,
		)
	}
```

Add an exact zero-case CLI test:

```go
func TestFormatDiagnosticsSummaryPrintsCurrentSenderZeroHealth(t *testing.T) {
	got := formatDiagnosticsSummary(transfertrace.DiagnosticsSummary{SenderHealthObserved: true})
	want := " min_rate_target_mbps=0 final_rate_target_mbps=0 controller_decreases=0 final_repair_bytes=0 max_retransmits=0 local_enobufs_retries=0 local_enobufs_wait_us=0 local_enobufs_max_consecutive=0"
	if got != want {
		t.Fatalf("formatDiagnosticsSummary() = %q, want %q", got, want)
	}
}
```

Legacy traces without the current sender-health columns may omit these keys. Current-schema sender summaries must always contain every key above as a parseable number, including the healthy all-zero case.

- [ ] **Step 6: Run checker and CLI tests**

Run:

```bash
mise exec -- go test ./pkg/transfertrace ./tools/transfertracecheck -count=1
```

Expected: PASS for new, healthy-zero, and legacy trace fixtures; current sender CLI output contains each stable numeric key exactly once, while legacy traces remain compatible.

- [ ] **Step 7: Commit the health summary**

Run:

```bash
but commit codex/bulk-pacing-health -m "tools: summarize transfer trace health"
```

Expected: a third commit containing only Task 3.

---

### Task 4: Run balanced bidirectional rate schedules through the public harness

**Files:**

- Modify: `scripts/promotion-benchmark-driver.sh:60-90`
- Modify: `scripts/public-path-performance-harness.sh:8-120,180-390`
- Modify: `scripts/promotion_scripts_test.go:1180-1260,1360-1410`

**Interfaces:**

- Consumes: `DERPHOLE_PUBLIC_PATH_INITIAL_RATES="1000 900 800"`, `DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS`, and optional `DERPHOLE_PUBLIC_IPERF_SERVER_HOST` for same-LAN baselines.
- Produces: one direction-labeled `summary.csv` with `initial_rate_mbps`, repair, local-pressure, target, controller, and receiver-distribution columns for every iperf/derphole pair; `DERPHOLE_PUBLIC_PATH_DIRECTION=forward|reverse` selects matching file-transfer and iperf direction.

- [ ] **Step 1: Write failing script contract tests**

Extend `TestPromotionBenchmarkDriverPropagatesTransportExperimentEnv` to require `DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS`.

Add a public-harness contract test that requires these exact strings:

```go
	for _, want := range []string{
		"DERPHOLE_PUBLIC_PATH_INITIAL_RATES",
		"DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS",
		"initial_rate_mbps",
		"repair_ratio",
		"local_enobufs_retries",
		"local_enobufs_wait_us",
		"local_enobufs_max_consecutive",
		"min_rate_target_mbps",
		"final_rate_target_mbps",
		"controller_decreases",
		"receiver_rate_p10_mbps",
		"receiver_rate_p50_mbps",
		"receiver_rate_p90_mbps",
		"receiver_rate_cv",
		"promotion-test-reverse.sh",
		"DERPHOLE_PUBLIC_PATH_DIRECTION",
		"DERPHOLE_PUBLIC_IPERF_SERVER_HOST",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("public-path-performance-harness.sh missing %q", want)
		}
	}
```

- [ ] **Step 2: Run script tests and verify RED**

Run:

```bash
mise exec -- go test ./scripts -run 'Test(PromotionBenchmarkDriverPropagatesTransportExperimentEnv|PublicPathPerformanceHarness.*InitialRate)' -count=1
```

Expected: FAIL because the new environment, reverse runner, and summary fields are absent.

- [ ] **Step 3: Validate and propagate the binary environment**

In `promotion-benchmark-driver.sh`, validate before building:

```bash
bulk_initial_rate="${DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS:-}"
if [[ -n "${bulk_initial_rate}" ]]; then
  if [[ ! "${bulk_initial_rate}" =~ ^[0-9]+$ ]] ||
     ((bulk_initial_rate < 128 || bulk_initial_rate > 2400)); then
    echo "DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS must be an integer from 128 through 2400" >&2
    exit 2
  fi
  remote_env+=(DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS="${bulk_initial_rate}")
fi
```

The active local command inherits the same environment. Remote propagation keeps reverse tests and future receiver-role changes honest.

- [ ] **Step 4: Add a validated schedule and direction to the public harness**

Near the existing `runs` variables, add:

```bash
initial_rates_raw="${DERPHOLE_PUBLIC_PATH_INITIAL_RATES:-}"
initial_rates=()
if [[ -n "${initial_rates_raw}" ]]; then
  read -r -a initial_rates <<<"${initial_rates_raw}"
  for initial_rate in "${initial_rates[@]}"; do
    if [[ ! "${initial_rate}" =~ ^[0-9]+$ ]] ||
       ((initial_rate < 128 || initial_rate > 2400)); then
      echo "DERPHOLE_PUBLIC_PATH_INITIAL_RATES contains invalid rate: ${initial_rate}" >&2
      exit 2
    fi
  done
  runs="${#initial_rates[@]}"
else
  for _ in $(seq 1 "${runs}"); do
    initial_rates+=("")
  done
fi
```

Replace the forward-only direction rejection with:

```bash
case "${direction}" in
  forward)
    promotion_script="./scripts/promotion-test.sh"
    iperf_reverse_flag="-R"
    ;;
  reverse)
    promotion_script="./scripts/promotion-test-reverse.sh"
    iperf_reverse_flag=""
    ;;
  *)
    echo "DERPHOLE_PUBLIC_PATH_DIRECTION must be forward or reverse (got: ${direction})" >&2
    exit 2
    ;;
esac
```

Rename the two forward-only sample helpers to direction-neutral `run_iperf_sample` and `run_derphole_sample`. For iperf, keep the Mac as the forwarded server and conditionally include `-R`: forward means Mac sends to remote, reverse means remote sends to Mac. Select `promotion_script` for the matching normal file workload.

Resolve the iperf server address once per harness run:

```bash
iperf_server_host="${DERPHOLE_PUBLIC_IPERF_SERVER_HOST:-}"
if [[ -z "${iperf_server_host}" ]]; then
  iperf_server_host="$(public_ip)"
fi
```

Use that value for every sample. Public hosts leave it unset and reach the forwarded WAN port. The fleet runner derives and supplies the Mac's active LAN address only for `pve1`, avoiding a NAT-hairpin dependency without adding a machine-specific default.

Inside the run loop, select `initial_rate="${initial_rates[run-1]}"` and pass it to `run_derphole_sample`. In that function, build an environment array so an empty rate remains truly unset:

```bash
  local experiment_env=()
  if [[ -n "${initial_rate}" ]]; then
    experiment_env+=(DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS="${initial_rate}")
  fi
  env \
    -u DERPHOLE_V2_RAW_DIRECT \
    -u DERPHOLE_V2_RAW_DIRECT_BUDGET_MS \
    -u DERPHOLE_V2_MANAGER_QUIC_FANOUT \
    "${experiment_env[@]}" \
    DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
    DERPHOLE_BENCH_WORKLOAD=file \
    DERPHOLE_BENCH_DIRECTION="${direction}" \
    DERPHOLE_BENCH_LOG_DIR="${case_log_dir}" \
    DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT="${remote_output_root}/${host_label}/run-${run}" \
      "${promotion_script}" "${target}" "${size_mib}"
```

Build the remote iperf command without interpolating an empty positional argument:

```bash
local remote_cmd=(iperf3 -4 -J)
if [[ -n "${iperf_reverse_flag}" ]]; then
  remote_cmd+=("${iperf_reverse_flag}")
fi
remote_cmd+=(-c "${iperf_server_host}" -p "${iperf_port}" -t 20 -P 4)
printf -v remote_cmd_quoted '%q ' "${remote_cmd[@]}"
ssh -o BatchMode=yes "${remote}" "${remote_cmd_quoted}" >"${out}"
```

The JSON output must still read `end.sum_received.bits_per_second`, because that is the receiving side's delivered rate in both directions.

- [ ] **Step 5: Extend `summary.csv` with health fields**

Append these columns to the header and `append_summary_row` arguments:

```text
initial_rate_mbps,repair_bytes,repair_ratio,retransmits,local_enobufs_retries,local_enobufs_wait_us,local_enobufs_max_consecutive,min_rate_target_mbps,final_rate_target_mbps,controller_decreases,receiver_rate_p10_mbps,receiver_rate_p50_mbps,receiver_rate_p90_mbps,receiver_rate_cv,receiver_windows_below_500_mbps
```

Extend `extract_tracecheck_summary` to extract the stable keys printed in Task 3. Calculate `repair_ratio` as `final_repair_bytes / benchmark-size-bytes`; use an empty value for iperf rows. Verify the first non-empty sender `rate_selected_mbps` equals the requested rate, and fail the sample if it does not.

Use this parsing shape inside the existing Python helper. Empty values are allowed only for iperf rows and legacy traces; current-schema sender rows must retain healthy numeric zeroes instead of becoming empty values:

```python
def metric(text, key):
    match = re.search(rf"(?:^| ){re.escape(key)}=([^ \n]+)", text)
    return match.group(1) if match else ""

keys = [
    "max_peer_recv_queue_depth",
    "max_flatline",
    "sender_mbps",
    "final_repair_bytes",
    "max_retransmits",
    "local_enobufs_retries",
    "local_enobufs_wait_us",
    "local_enobufs_max_consecutive",
    "min_rate_target_mbps",
    "final_rate_target_mbps",
    "controller_decreases",
    "receiver_rate_p10_mbps",
    "receiver_rate_p50_mbps",
    "receiver_rate_p90_mbps",
    "receiver_rate_cv",
    "receiver_windows_below_500_mbps",
]
print("\t".join(metric(combined_text, key) for key in keys))
```

For each derphole sample, inspect the sender trace header. When it contains the current sender-health schema (including `local_enobufs_retries`), require `final_repair_bytes`, `max_retransmits`, all three local-pressure counters, both rate targets, and `controller_decreases` to match a numeric value; fail the sample if any is absent or non-numeric. Legacy traces may leave unavailable fields empty, and iperf rows keep every health field empty.

Calculate the ratio with:

```python
repair_ratio = ""
if repair_bytes and int(benchmark_size_bytes) > 0:
    repair_ratio = f"{int(repair_bytes) / int(benchmark_size_bytes):.4f}"
```

- [ ] **Step 6: Run script tests**

Run:

```bash
mise exec -- go test ./scripts -count=1
```

Expected: PASS, including default runs with no rate schedule, scheduled runs that preserve the requested order, and both accepted directions selecting the matching promotion script and iperf direction.

- [ ] **Step 7: Commit the benchmark schedule**

Run:

```bash
but commit codex/bulk-pacing-health -m "scripts: add bulk pacing experiment schedule"
```

Expected: a fourth commit containing only Task 4.

---

### Task 5: Document and locally verify the experiment

**Files:**

- Modify: `docs/benchmarks.md:65-115`

**Interfaces:**

- Consumes: the Task 1 counters, Task 2 environment, Task 3 health keys, and Task 4 schedule.
- Produces: an exact operator runbook and decision rules usable without reading implementation code.

- [ ] **Step 1: Add the exact experiment command**

Document:

```bash
DERPHOLE_PUBLIC_PATH_HOSTS='ubuntu@eric-nuc' \
DERPHOLE_PUBLIC_PATH_SIZE_MIB=3072 \
DERPHOLE_PUBLIC_PATH_INITIAL_RATES='1000 900 800 800 1000 900 900 800 1000' \
DERPHOLE_PUBLIC_IPERF_PORT=8123 \
DERPHOLE_BENCH_LOG_DIR=.tmp/bulk-pacing-ab-20260712 \
./scripts/public-path-performance-harness.sh
```

Explain that the order rotates all three rates through early, middle, and late path conditions. Define the local-pressure columns and state that `local_enobufs_wait_us / 1000 / benchmark-transfer-elapsed-ms >= 0.01` means local buffer waiting consumed at least one percent of transfer time.

Document the fleet gate separately from Eric's tuning run. For each reachable canonical host, run both `DERPHOLE_PUBLIC_PATH_DIRECTION=forward` and `reverse` with a 1 GiB normal file. The candidate-versus-control order is `1000 C C 1000`, where `C` is Eric's winning candidate. State that `pve1` is the same-LAN topology and that every other host must remain public and non-Tailscale.

- [ ] **Step 2: Document the decision gate**

Add these exact rules:

1. For Eric candidate selection and fleet A/B cells that exercise the bulk controller, reject any rate with a failed SHA, non-public path, transfer mode other than `bulk-packets-v1`, trace failure, flatline of at least one second, or process/socket leak. Final unoverridden fleet acceptance evaluates intentional `blocks-v1` cells under Task 7A's mode-aware rules.
2. Group the three accepted rows per rate and compare median canonical goodput first.
3. A median difference above 3 percent selects the faster rate.
4. Within 3 percent, select the rate with at least 20 percent lower median repair ratio and no lower receiver p10 rate.
5. If neither rule separates the top two and same-run iperf coefficient of variation exceeds 15 percent, rerun only those two rates in `A B B A` order.
6. Keep 1,000 Mbps when no alternative wins. Do not lower the default merely because one run had lower repair traffic.
7. On a host-direction that negotiates `bulk-packets-v1`, a non-1,000 candidate may not regress median canonical goodput or median iperf ratio more than 5 percent from that host-direction's 1,000-control median. An intentional `blocks-v1` cell does not exercise the candidate and moves to final mode-aware acceptance.
8. On each bulk A/B cell, the candidate must have no flatline of at least one second, no higher median receiver-rate CV by more than 0.05, no greater median local `ENOBUFS` wait ratio, and no greater median repair ratio by more than 20 percent relative to the 1,000-control rows.
9. If a bulk A/B cell has iperf CV above 15 percent or only one accepted row at either rate, rerun that host-direction as `1000 C C 1000`; do not waive it from the candidate decision. Final acceptance still covers every reachable host-direction in its intentionally negotiated mode.

- [ ] **Step 3: Run the full local gate**

Run:

```bash
mise run test
mise run vet
mise run build
mise run check:hooks
```

Expected: all commands exit zero. If `check:hooks` must run from the staged GitButler snapshot, let the Task 5 commit invoke the installed hooks and confirm every configured hook passes.

- [ ] **Step 4: Commit the runbook**

Run:

```bash
but commit codex/bulk-pacing-health -m "docs: document bulk pacing health experiments"
```

Expected: a fifth commit containing the runbook and any formatting-only corrections made by the repository hooks.

---

### Task 6: Select a candidate on Eric without changing production

**Files:**

- Runtime artifacts: `.tmp/bulk-pacing-ab-20260712/summary.csv`
- Runtime artifacts: `.tmp/bulk-pacing-ab-20260712/**/sender.trace.csv`
- Runtime artifacts: `.tmp/bulk-pacing-ab-20260712/**/receiver.trace.csv`

**Interfaces:**

- Consumes: the exact Task 5 command and decision gate.
- Produces: an Eric-selected candidate of 1,000, 900, or 800 Mbps plus complete CSV evidence. This task does not change the production default.

- [ ] **Step 1: Check both hosts before the tuning matrix**

Run:

```bash
pgrep -x derphole || true
ssh -o BatchMode=yes ubuntu@eric-nuc 'pgrep -x derphole || true'
but pull --check
```

Expected: no process IDs and an up-to-date, conflict-free base. Record any pre-existing process and stop instead of killing an unrelated session.

- [ ] **Step 2: Run the balanced nine-transfer matrix**

Run:

```bash
DERPHOLE_PUBLIC_PATH_HOSTS='ubuntu@eric-nuc' \
DERPHOLE_PUBLIC_PATH_SIZE_MIB=3072 \
DERPHOLE_PUBLIC_PATH_INITIAL_RATES='1000 900 800 800 1000 900 900 800 1000' \
DERPHOLE_PUBLIC_IPERF_PORT=8123 \
DERPHOLE_BENCH_LOG_DIR=.tmp/bulk-pacing-ab-20260712 \
./scripts/public-path-performance-harness.sh
```

Do not start a manual transfer concurrently. Stop immediately if a sample fails integrity, trace, or cleanup checks.

Expected: nine accepted 3 GiB file rows, nine paired iperf rows, and three accepted samples for each initial rate.

- [ ] **Step 3: Apply the documented decision gate**

For each rate, report:

- median canonical and wall goodput;
- median ratio to same-run iperf;
- median repair ratio and retransmits;
- receiver p10, p50, p90, and rate CV;
- controller decreases and minimum/final target;
- local `ENOBUFS` retry count, wait ratio, and maximum consecutive streak;
- maximum flatline and queue depth.

Use this exact analysis command to print the per-rate medians, worst-case pressure values, and same-run iperf CV from Task 4's exact summary schema:

```bash
python3 - <<'PY'
import csv
import re
import statistics

path = ".tmp/bulk-pacing-ab-20260712/summary.csv"
with open(path, newline="") as handle:
    rows = list(csv.DictReader(handle))

units = {"ns": 1e-9, "us": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0}
def duration_seconds(value):
    parts = re.findall(r"([0-9]+(?:\.[0-9]+)?)(ns|us|ms|s|m|h)", value)
    if not parts:
        raise ValueError(f"invalid duration: {value!r}")
    return sum(float(number) * units[unit] for number, unit in parts)

iperf = [float(row["mbps"]) for row in rows if row["tool"] == "iperf3"]
if len(iperf) != 9:
    raise SystemExit(f"expected 9 iperf rows, got {len(iperf)}")
iperf_cv = statistics.pstdev(iperf) / statistics.fmean(iperf)
print(f"iperf_cv={iperf_cv:.3f}")

for rate in (1000, 900, 800):
    selected = [
        row for row in rows
        if row["tool"] == "derphole" and int(row["initial_rate_mbps"]) == rate
    ]
    if len(selected) != 3:
        raise SystemExit(f"rate {rate}: expected 3 rows, got {len(selected)}")
    def median(name):
        return statistics.median(float(row[name]) for row in selected)
    wait_ratio = statistics.median(
        float(row["local_enobufs_wait_us"]) / 1000.0 / float(row["transfer_elapsed_ms"])
        for row in selected
    )
    max_consecutive = max(float(row["local_enobufs_max_consecutive"]) for row in selected)
    max_flatline_seconds = max(duration_seconds(row["max_flatline"]) for row in selected)
    max_queue_depth = max(float(row["max_peer_recv_queue_depth"]) for row in selected)
    print(
        f"rate={rate} "
        f"canonical_goodput_median_mbps={median('mbps'):.2f} "
        f"wall_goodput_median_mbps={median('wall_mbps'):.2f} "
        f"same_run_iperf_ratio_median={median('ratio_to_iperf'):.3f} "
        f"repair_ratio_median={median('repair_ratio'):.4f} "
        f"retransmits_median={median('retransmits'):.0f} "
        f"receiver_p10_median_mbps={median('receiver_rate_p10_mbps'):.2f} "
        f"receiver_p50_median_mbps={median('receiver_rate_p50_mbps'):.2f} "
        f"receiver_p90_median_mbps={median('receiver_rate_p90_mbps'):.2f} "
        f"receiver_cv_median={median('receiver_rate_cv'):.3f} "
        f"controller_decreases_median={median('controller_decreases'):.0f} "
        f"min_target_median_mbps={median('min_rate_target_mbps'):.0f} "
        f"final_target_median_mbps={median('final_rate_target_mbps'):.0f} "
        f"enobufs_retries_median={median('local_enobufs_retries'):.0f} "
        f"enobufs_wait_ratio_median={wait_ratio:.6f} "
        f"enobufs_max_consecutive={max_consecutive:.0f} "
        f"max_flatline_seconds={max_flatline_seconds:.6f} "
        f"max_queue_depth={max_queue_depth:.0f}"
    )
PY
```

If same-run iperf CV exceeds 15 percent and the top two rates remain within 3 percent, run four more transfers with `DERPHOLE_PUBLIC_PATH_INITIAL_RATES` set to the top-two `A B B A` sequence.

- [ ] **Step 4: Record the candidate and leave production unchanged**

Write the numeric winner to the runtime artifact used by the fleet gate:

```bash
printf '%s\n' "${CANDIDATE_RATE:?set the winning 1000, 900, or 800 rate}" \
  > .tmp/bulk-pacing-ab-20260712/candidate-rate.txt
```

Validate it before continuing:

```bash
case "$(cat .tmp/bulk-pacing-ab-20260712/candidate-rate.txt)" in
  1000|900|800) ;;
  *) echo "invalid candidate rate" >&2; exit 2 ;;
esac
```

Expected: exactly one valid rate. `git diff -- pkg/session/external_v2_bulk_packet_controller.go pkg/session/external_v2_bulk_packet_controller_test.go` remains empty.

---

### Task 7: Disprove the Eric candidate across every reachable test network

**Files:**

- Runtime artifact: `.tmp/bulk-pacing-fleet-20260712/host-reachability.tsv`
- Runtime artifact: `.tmp/bulk-pacing-fleet-20260712/reachable-hosts.txt`
- Runtime artifacts: `.tmp/bulk-pacing-fleet-20260712/<host>/<direction>/summary.csv`
- Runtime artifact: `.tmp/bulk-pacing-fleet-20260712/fleet-analysis.txt`

**Interfaces:**

- Consumes: `.tmp/bulk-pacing-ab-20260712/candidate-rate.txt`, bidirectional Task 4 harness support, and the canonical host inventory.
- Produces: a host-by-direction capacity-normalized A/B verdict. A non-1,000 candidate may advance only if no reachable host-direction rejects it.

- [ ] **Step 1: Probe and record the complete canonical inventory**

Run:

```bash
mkdir -p .tmp/bulk-pacing-fleet-20260712
inventory=(
  ubuntu@derphole-testing
  ubuntu@eric-nuc
  root@hetz
  root@canlxc
  root@ktzlxc
  root@uklxc
  november-oscar.exe.xyz
  root@pve1
)
: > .tmp/bulk-pacing-fleet-20260712/host-reachability.tsv
: > .tmp/bulk-pacing-fleet-20260712/reachable-hosts.txt
for host in "${inventory[@]}"; do
  if ssh_output="$(ssh -o BatchMode=yes -o ConnectTimeout=8 -o ConnectionAttempts=1 \
      "${host}" 'printf reachable' 2>&1)"; then
    printf '%s\treachable\t0\t-\n' "${host}" \
      | tee -a .tmp/bulk-pacing-fleet-20260712/host-reachability.tsv
    printf '%s\n' "${host}" \
      >> .tmp/bulk-pacing-fleet-20260712/reachable-hosts.txt
  else
    ssh_status=$?
    ssh_reason="$(printf '%s' "${ssh_output}" | tr '\t\r\n' ' ' | cut -c1-240)"
    [[ -n "${ssh_reason}" ]] || ssh_reason="-"
    printf '%s\tunreachable\t%d\t%s\n' "${host}" "${ssh_status}" "${ssh_reason}" \
      | tee -a .tmp/bulk-pacing-fleet-20260712/host-reachability.tsv
  fi
done
test -s .tmp/bulk-pacing-fleet-20260712/reachable-hosts.txt
```

Expected: one four-column row (`host`, reachability, SSH exit code, bounded single-line reason) for all eight canonical hosts and at least one reachable host. At plan-writing time, `ubuntu@derphole-testing`, `ubuntu@eric-nuc`, `root@hetz`, `root@canlxc`, and `root@pve1` were reachable; the execution-time probe is authoritative.

- [ ] **Step 2: Verify no reachable host has a pre-existing derphole session**

Run:

```bash
while IFS= read -r host; do
  output="$(ssh -o BatchMode=yes "${host}" 'pgrep -x derphole || true')"
  if [[ -n "${output}" ]]; then
    printf 'pre-existing derphole process on %s: %s\n' "${host}" "${output}" >&2
    exit 1
  fi
done < .tmp/bulk-pacing-fleet-20260712/reachable-hosts.txt
pgrep -x derphole && exit 1 || true
```

Expected: no local or remote process IDs. Do not terminate unrelated processes automatically.

- [ ] **Step 3: Run paired forward and reverse control-versus-candidate schedules**

Read the candidate:

```bash
candidate="$(cat .tmp/bulk-pacing-ab-20260712/candidate-rate.txt)"
```

If `candidate=1000`, skip the redundant A/B rows and continue to Task 8, which still runs three unoverridden transfers per reachable host-direction. Otherwise run:

```bash
while IFS= read -r host; do
  host_label="${host//[^A-Za-z0-9_.-]/_}"
  iperf_host_env=()
  if [[ "${host}" == "root@pve1" ]]; then
    lan_interface="$(route -n get pve1 | awk '/interface:/{print $2; exit}')"
    lan_address="$(ipconfig getifaddr "${lan_interface}")"
    iperf_host_env+=(DERPHOLE_PUBLIC_IPERF_SERVER_HOST="${lan_address}")
  fi
  for direction in forward reverse; do
    env "${iperf_host_env[@]}" \
      DERPHOLE_PUBLIC_PATH_HOSTS="${host}" \
      DERPHOLE_PUBLIC_PATH_DIRECTION="${direction}" \
      DERPHOLE_PUBLIC_PATH_SIZE_MIB=1024 \
      DERPHOLE_PUBLIC_PATH_INITIAL_RATES="1000 ${candidate} ${candidate} 1000" \
      DERPHOLE_PUBLIC_IPERF_PORT=8123 \
      DERPHOLE_BENCH_LOG_DIR=".tmp/bulk-pacing-fleet-20260712/${host_label}/${direction}" \
      ./scripts/public-path-performance-harness.sh
  done
done < .tmp/bulk-pacing-fleet-20260712/reachable-hosts.txt
```

Expected: four accepted normal-file rows plus four same-direction iperf rows per reachable host-direction. `pve1` is labeled `lan`; every other run must show the public non-Tailscale route. Stop on the first integrity, trace, route, or leak failure.

- [ ] **Step 4: Analyze every host-direction against its own control**

Run this exact fleet analysis when the candidate is not 1,000:

```bash
python3 - <<'PY' | tee .tmp/bulk-pacing-fleet-20260712/fleet-analysis.txt
import csv
from pathlib import Path
import re
import statistics

units = {'ns': 1e-9, 'us': 1e-6, 'ms': 1e-3, 's': 1.0, 'm': 60.0, 'h': 3600.0}
def duration_seconds(value):
    return sum(float(number) * units[unit]
               for number, unit in re.findall(r'([0-9]+(?:\.[0-9]+)?)(ns|us|ms|s|m|h)', value))

candidate = int(open('.tmp/bulk-pacing-ab-20260712/candidate-rate.txt').read())
root = Path('.tmp/bulk-pacing-fleet-20260712')
reachable = [line.strip() for line in (root / 'reachable-hosts.txt').read_text().splitlines()
             if line.strip()]
if not reachable:
    raise SystemExit('no reachable hosts; refusing zero-matrix fleet acceptance')
expected_paths = {
    root / re.sub(r'[^A-Za-z0-9_.-]', '_', host) / direction / 'summary.csv'
    for host in reachable
    for direction in ('forward', 'reverse')
}
missing_paths = sorted(path for path in expected_paths if not path.is_file())
if missing_paths:
    raise SystemExit('\n'.join(f'missing host-direction matrix: {path}' for path in missing_paths))

failures = []
for path in sorted(expected_paths):
    with open(path, newline='') as handle:
        rows = list(csv.DictReader(handle))
    derphole = [row for row in rows if row['tool'] == 'derphole']
    iperf = [float(row['mbps']) for row in rows if row['tool'] == 'iperf3']
    if len(derphole) != 4 or len(iperf) != 4:
        failures.append(f'{path}: incomplete rows')
        continue
    iperf_cv = statistics.pstdev(iperf) / statistics.fmean(iperf)
    by_rate = {}
    for rate in (1000, candidate):
        selected = [row for row in derphole if int(row['initial_rate_mbps']) == rate]
        if len(selected) != 2:
            failures.append(f'{path}: rate {rate} has {len(selected)} rows')
            continue
        def median(name):
            return statistics.median(float(row[name]) for row in selected)
        wait_ratio = statistics.median(
            float(row['local_enobufs_wait_us']) / 1000.0 / float(row['transfer_elapsed_ms'])
            for row in selected
        )
        by_rate[rate] = {
            'goodput': median('mbps'),
            'iperf_ratio': median('ratio_to_iperf'),
            'repair_ratio': median('repair_ratio'),
            'receiver_cv': median('receiver_rate_cv'),
            'wait_ratio': wait_ratio,
            'max_flatline': max(duration_seconds(row['max_flatline']) for row in selected),
        }
    if set(by_rate) != {1000, candidate}:
        continue
    control, trial = by_rate[1000], by_rate[candidate]
    goodput_delta = trial['goodput'] / control['goodput'] - 1.0
    ratio_delta = trial['iperf_ratio'] / control['iperf_ratio'] - 1.0
    print(
        f'{path} iperf_cv={iperf_cv:.3f} goodput_delta={goodput_delta:.3f} '
        f'iperf_ratio_delta={ratio_delta:.3f} repair={trial["repair_ratio"]:.4f}/'
        f'{control["repair_ratio"]:.4f} receiver_cv={trial["receiver_cv"]:.3f}/'
        f'{control["receiver_cv"]:.3f} wait={trial["wait_ratio"]:.4f}/'
        f'{control["wait_ratio"]:.4f}'
    )
    if iperf_cv > 0.15:
        failures.append(f'{path}: iperf CV {iperf_cv:.3f} requires rerun')
    if goodput_delta < -0.05 or ratio_delta < -0.05:
        failures.append(f'{path}: candidate throughput regression')
    if trial['max_flatline'] >= 1.0:
        failures.append(f'{path}: candidate flatline')
    if trial['receiver_cv'] > control['receiver_cv'] + 0.05:
        failures.append(f'{path}: candidate stability regression')
    if trial['wait_ratio'] > control['wait_ratio'] + 1e-9:
        failures.append(f'{path}: candidate local pressure regression')
    if trial['repair_ratio'] > control['repair_ratio'] * 1.20 + 1e-9:
        failures.append(f'{path}: candidate repair regression')
if failures:
    raise SystemExit('\n'.join(failures))
print('fleet_candidate_accepted=true')
PY
```

Expected: `fleet_candidate_accepted=true`. Rerun only noisy or incomplete host-directions in the same `1000 C C 1000` order, replace their artifact directory, and rerun the analysis. A repeatable candidate regression makes 1,000 the selected fleet-safe rate even if Eric preferred the candidate.

---

### Task 7A: Align final acceptance with adaptive transfer-mode policy

**Files:**

- Modify: `docs/superpowers/plans/2026-07-12-bulk-pacing-health-ab.md`
- Modify: `docs/benchmarks.md:128-175`

**Interfaces:**

- Consumes: the reviewed Task 7 evidence that rejects 900 Mbps, selects the 1,000 Mbps fallback, and observes intentional `blocks-v1` on a 16-candidate receiver.
- Produces: a mode-aware final acceptance contract that tests every reachable host-direction without removing the approved high-capacity QUIC policy.

- [ ] **Step 1: Record the Task 7 decision and policy boundary**

Document these exact facts:

1. The completed `derphole-testing` forward bulk cell rejected 900 because median ratio to same-run iperf regressed 7.278 percent; production therefore remains 1,000 Mbps.
2. `blocks-v1` for a receiver with five or more non-Tailscale candidates is intentional adaptive policy, not removable legacy. The approved design preserves it because measured QUIC throughput on high-capacity receivers exceeded bulk-packet throughput and because old peers require QUIC fallback.
3. A bulk-rate A/B gate applies only to host-directions that negotiate `bulk-packets-v1`. A host-direction that negotiates `blocks-v1` does not exercise `DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS` and must be judged by unoverridden QUIC integrity, throughput, stability, route, trace, and cleanup evidence.
4. The final selected-default gate still runs three normal 1 GiB file transfers in both directions on every reachable host; no reachable host-direction may be silently omitted.

- [ ] **Step 2: Define mode-aware final acceptance**

For each reachable host-direction, require exactly three derphole rows and three paired iperf rows. Require one consistent transfer mode across the three derphole rows:

- `bulk-packets-v1`: inspect each sender trace and require every non-empty `rate_selected_mbps` value to equal the selected production default of 1,000 Mbps. Require numeric repair, retransmit, controller, receiver-rate, and local-pressure health fields.
- `blocks-v1`: require `direct_transport=quic`, successful direct progress, and no bulk selected-rate assertion. Empty bulk-only health fields are correct because the bulk controller did not run.

Both modes require matching SHA and size, `trace_ok=true`, maximum flatline below one second, no process/socket leak, and public non-Tailscale selected addresses except for the labeled `pve1` LAN path. Report canonical/wall median and CV, paired iperf median and CV, and derphole-to-iperf ratios. A canonical goodput CV above 15 percent triggers one same-host-direction three-run rerun; a repeat CV above 15 percent is a stability failure rather than a waived row.

- [ ] **Step 3: Verify and commit the correction**

Run:

```bash
git diff --check
rg -n '7\.278|five or more|bulk-packets-v1|blocks-v1|rate_selected_mbps|15 percent|every reachable' \
  docs/superpowers/plans/2026-07-12-bulk-pacing-health-ab.md docs/benchmarks.md
```

Expected: no whitespace errors and every adaptive-mode requirement present in both the execution plan and operator runbook.

Commit:

```bash
but commit codex/bulk-pacing-health -m "docs: align fleet gate with adaptive transfer modes"
```

Expected: a documentation-only Task 7A commit.

---

### Task 8A: Make paired sender stall checks peer-authoritative

**Files:**

- Modify: `tools/transfertracecheck/main.go:30-75,190-245`
- Modify: `tools/transfertracecheck/main_test.go`
- Modify: `docs/benchmarks.md:170-185`
- Modify: `docs/superpowers/plans/2026-07-12-bulk-pacing-health-ab.md`

**Interfaces:**

- Consumes: `-peer-trace`, the preserved Task 8 run-2 sender/receiver traces, `transfertrace.Check`, and `transfertrace.CheckPair`.
- Produces: receiver-authoritative payload flatline checking for paired sender traces, `sender_ack_max_flatline=<duration>` as a separate diagnostic, and `max_flatline=<duration>` on failed standalone/peer checks.

- [ ] **Step 1: Write failing paired-semantics tests**

Add CLI tests with real temporary trace CSVs:

```go
func TestRunPairedSenderUsesReceiverForPayloadFlatline(t *testing.T) {
	// Sender app_bytes/peer_received_bytes remain unchanged for 1.5 seconds
	// while local/direct bytes grow. Receiver app_bytes has one 500 ms
	// flatline, then advances again within the configured 999 ms window.
	// Final sender peer progress and receiver app bytes match and rates differ <10%.
	// Expect exit 0, payload max_flatline=500ms from the receiver trace, and
	// sender_ack_max_flatline=1.5s in stdout.
}

func TestRunPairedSenderRejectsReceiverPayloadFlatline(t *testing.T) {
	// Sender ACK progress may be lumpy, but the receiver itself also stops
	// advancing beyond the configured 999 ms window.
	// Expect exit 1 and stderr containing max_flatline=1s or greater.
}

func TestRunStandaloneFailureReportsObservedFlatline(t *testing.T) {
	// A standalone active trace crosses its stall window.
	// Expect exit 1 and stderr containing max_flatline=1s rather than losing
	// the partial Result and causing the harness to record 0s.
}

func TestRunPairedSenderKeepsSenderFailuresFatal(t *testing.T) {
	// Exercise both a sender terminal error and an expected-byte mismatch
	// with -peer-trace. Expect exit 1 and the original sender error in stderr.
}
```

Reuse the existing trace-header/test-row helpers. The paired pass fixture must reproduce the Task 8 shape: receiver rows advance with one real sub-threshold 500 ms flatline while sender-confirmed `app_bytes` is unchanged, and `CheckPair` final/rate consistency passes.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
mise exec -- go test ./tools/transfertracecheck -run 'TestRun(PairedSender|StandaloneFailure)' -count=1
```

Expected: the paired-progress case fails with `app bytes stalled`, and the failure-output test lacks `max_flatline=`.

- [ ] **Step 3: Implement peer-authoritative paired semantics**

Keep standalone behavior unchanged. When `opts.Role == "send"` and `opts.PeerTrace != ""`:

1. Check the sender trace with the stall window set to `time.Duration(math.MaxInt64)` so terminal state, expected bytes, diagnostics, and the complete sender ACK flatline are still collected.
2. Check the peer trace as `transfertrace.RoleReceive` with the user-requested stall window and no sender expected-byte override. A peer receiver stall remains fatal.
3. Run the existing `CheckPair` final-progress/rate consistency check.
4. Set the reported payload `result.MaxFlatline` to the peer receiver result and append `sender_ack_max_flatline=<sender result MaxFlatline>` to the successful summary.

Factor file opening through one helper with this exact responsibility:

```go
func checkTracePath(path string, opts transfertrace.Options) (transfertrace.Result, error)
```

On every `transfertrace.Check` error, retain the returned partial result and print:

```go
fmt.Fprintf(stderr, "transfertracecheck: %v max_flatline=%s\n", err, result.MaxFlatline)
```

Do not suppress terminal errors, final-byte failures, receiver stalls, or `CheckPair` failures. Do not change `pkg/transfertrace` standalone semantics.

- [ ] **Step 4: Run focused and package tests**

Run:

```bash
mise exec -- go test ./tools/transfertracecheck ./pkg/transfertrace -count=1
```

Expected: PASS. The Task 8 run-2 preserved traces pass when invoked as the public harness invokes them:

```bash
case_dir=.tmp/bulk-pacing-default-acceptance-20260712/ubuntu_derphole-testing/forward/ubuntu_derphole-testing/derphole-run-2
sender_trace="$(find "${case_dir}" -name '*sender.trace.csv' -print -quit)"
receiver_trace="$(find "${case_dir}" -name '*receiver.trace.csv' -print -quit)"
mise exec -- go run ./tools/transfertracecheck \
  -role send -stall-window 999ms -peer-trace "${receiver_trace}" "${sender_trace}"
```

Expected for this preserved trace: `trace-ok`, `max_flatline=0s` (receiver payload did not stall), and `sender_ack_max_flatline=1.001s`. The synthetic paired-progress regression above uses a longer 1.5-second ACK batch to keep the semantic boundary explicit.

- [ ] **Step 5: Document the diagnostic boundary**

Document that paired sender checks use peer receiver `app_bytes` for payload-stall health. Sender `app_bytes` are receiver-confirmed ACK progress and may batch; `sender_ack_max_flatline` remains visible for ACK/telemetry health but does not become a payload-stall failure while the receiver trace advances. Standalone sender checks retain the original behavior.

- [ ] **Step 6: Run full gates and commit**

Run:

```bash
mise run test
mise run vet
mise run build
mise run check:hooks
```

Expected: all pass, including govulncheck.

Commit:

```bash
but commit codex/bulk-pacing-health -m "tools: use peer progress for paired stall checks"
```

Expected: one Task 8A commit containing the CLI tests/fix and matching docs/plan correction.

---

### Task 8: Promote the fleet-safe default and run unoverridden acceptance

**Files:**

- Modify conditionally: `pkg/session/external_v2_bulk_packet_controller.go:15-24`
- Modify conditionally: `pkg/session/external_v2_bulk_packet_controller_test.go`
- Runtime artifacts: `.tmp/bulk-pacing-default-acceptance-20260712/**/summary.csv`

**Interfaces:**

- Consumes: the Eric candidate and Task 7 fleet verdict.
- Produces: either a verified new `externalV2BulkPacketDefaultInitialWireMbps` or an explicit decision to retain 1,000 Mbps, followed by three unoverridden normal-file transfers per reachable host-direction.

- [ ] **Step 1: Change the production default only after the fleet verdict**

If 900 or 800 passed Task 7 on every reachable host-direction, change exactly:

```go
	externalV2BulkPacketDefaultInitialWireMbps = 900
```

or:

```go
	externalV2BulkPacketDefaultInitialWireMbps = 800
```

Update the default parser and controller tests to the same value. If 1,000 wins, Eric is inconclusive, or any repeatable fleet regression rejects the candidate, make no production-rate edit.

- [ ] **Step 2: Run focused and full local verification**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket.*Initial|TestExternalV2BulkPacketController.*Initial' -count=1
mise run test
mise run vet
mise run build
```

Expected: all commands exit zero with the unoverridden selected rate reflected in focused tests.

- [ ] **Step 3: Commit a production-rate change only if one was made**

Run only when Step 1 changed the default:

```bash
but commit codex/bulk-pacing-health -m "perf: tune bulk initial wire rate"
```

When 1,000 Mbps remains selected, preserve the instrumentation and harness commits without manufacturing an empty tuning commit.

- [ ] **Step 4: Run three unoverridden transfers on every reachable host-direction**

Run:

```bash
while IFS= read -r host; do
  host_label="${host//[^A-Za-z0-9_.-]/_}"
  iperf_host_env=()
  if [[ "${host}" == "root@pve1" ]]; then
    lan_interface="$(route -n get pve1 | awk '/interface:/{print $2; exit}')"
    lan_address="$(ipconfig getifaddr "${lan_interface}")"
    iperf_host_env+=(DERPHOLE_PUBLIC_IPERF_SERVER_HOST="${lan_address}")
  fi
  for direction in forward reverse; do
    env -u DERPHOLE_PUBLIC_PATH_INITIAL_RATES "${iperf_host_env[@]}" \
      DERPHOLE_PUBLIC_PATH_HOSTS="${host}" \
      DERPHOLE_PUBLIC_PATH_DIRECTION="${direction}" \
      DERPHOLE_PUBLIC_PATH_SIZE_MIB=1024 \
      DERPHOLE_PUBLIC_PATH_RUNS=3 \
      DERPHOLE_PUBLIC_IPERF_PORT=8123 \
      DERPHOLE_BENCH_LOG_DIR=".tmp/bulk-pacing-default-acceptance-20260712/${host_label}/${direction}" \
      ./scripts/public-path-performance-harness.sh
  done
done < .tmp/bulk-pacing-fleet-20260712/reachable-hosts.txt
```

Run the exact mode-aware audit:

```bash
set -o pipefail
python3 - <<'PY' | tee .tmp/bulk-pacing-default-acceptance-20260712/analysis.txt
import csv
import ipaddress
import json
import math
from pathlib import Path
import re
import statistics

root = Path('.tmp/bulk-pacing-default-acceptance-20260712')
reachable = [line.strip() for line in Path(
    '.tmp/bulk-pacing-fleet-20260712/reachable-hosts.txt'
).read_text().splitlines() if line.strip()]
if not reachable:
    raise SystemExit('reachable host list is empty')
if len(reachable) != len(set(reachable)):
    raise SystemExit('reachable host list contains duplicates')
units = {'ns': 1e-9, 'us': 1e-6, 'ms': 1e-3, 's': 1.0, 'm': 60.0, 'h': 3600.0}
def seconds(value):
    parts = re.findall(r'([0-9]+(?:\.[0-9]+)?)(ns|us|ms|s|m|h)', value)
    if not parts or ''.join(number + unit for number, unit in parts) != value:
        raise ValueError(f'invalid duration {value!r}')
    return sum(float(number) * units[unit] for number, unit in parts)

def number(value, field):
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f'{field} is not finite')
    return parsed

def cv(values, field):
    mean = statistics.fmean(values)
    if mean <= 0:
        raise ValueError(f'{field} mean is not positive')
    return statistics.pstdev(values) / mean

def selected_ips(log):
    values = re.findall(r'v2-raw-direct-selected-addrs=([^\s]+)',
                        log.read_text(errors='replace'))
    if not values or values[-1] == 'none':
        raise ValueError('missing selected addresses')
    result = []
    for address in values[-1].split(','):
        host = address[1:address.index(']')] if address.startswith('[') else address.rsplit(':', 1)[0]
        result.append(ipaddress.ip_address(host))
    return result

def is_tailscale(ip):
    return ip in ipaddress.ip_network('100.64.0.0/10') or ip in ipaddress.ip_network('fd7a:115c:a1e0::/48')

def exact_lan_endpoints(iperf_endpoints, selected_endpoints):
    return iperf_endpoints == selected_endpoints

path_labels = [re.sub(r'[^A-Za-z0-9_.-]', '_', host) for host in reachable]
expected_labels = [
    re.sub(r'[^A-Za-z0-9_.-]', '_', host if '@' in host else f'ubuntu@{host}')
    for host in reachable
]
if len(path_labels) != len(set(path_labels)):
    raise SystemExit('reachable hosts collide after path sanitization')
if len(expected_labels) != len(set(expected_labels)):
    raise SystemExit('reachable hosts collide after remote-user resolution')
expected = [
    (root / path_label / direction / 'summary.csv', expected_label, host == 'root@pve1')
    for host, path_label, expected_label in zip(reachable, path_labels, expected_labels)
    for direction in ('forward', 'reverse')
]
missing = sorted(path for path, _, _ in expected if not path.is_file())
if missing:
    raise SystemExit('\n'.join(f'missing acceptance summary: {path}' for path in missing))

failures = []
bulk_health = (
    'repair_bytes', 'repair_ratio', 'retransmits', 'local_enobufs_retries',
    'local_enobufs_wait_us', 'local_enobufs_max_consecutive',
    'min_rate_target_mbps', 'final_rate_target_mbps', 'controller_decreases',
    'receiver_rate_p10_mbps', 'receiver_rate_p50_mbps',
    'receiver_rate_p90_mbps', 'receiver_rate_cv',
    'receiver_windows_below_500_mbps',
)
required = {
    'host', 'run', 'tool', 'direction', 'workload', 'transfer_mode', 'mbps',
    'ratio_to_iperf', 'wall_mbps', 'trace_ok', 'max_flatline', 'log_dir',
    'initial_rate_mbps',
    *bulk_health,
}
for path, expected_label, lan_path in sorted(expected):
    with path.open(newline='') as handle:
        reader = csv.DictReader(handle)
        missing_columns = sorted(required - set(reader.fieldnames or ()))
        rows = list(reader)
    if missing_columns:
        failures.append(f'{path}: missing columns {missing_columns}')
        continue
    derphole = [row for row in rows if row['tool'] == 'derphole']
    iperf_rows = [row for row in rows if row['tool'] == 'iperf3']
    if len(rows) != 6 or len(derphole) != 3 or len(iperf_rows) != 3:
        failures.append(f'{path}: expected 3 derphole and 3 iperf rows')
        continue
    if ({row['run'] for row in derphole} != {'1', '2', '3'} or
            {row['run'] for row in iperf_rows} != {'1', '2', '3'}):
        failures.append(f'{path}: derphole and iperf rows are not paired runs 1-3')
        continue
    if any(row['host'] != expected_label for row in rows):
        failures.append(f'{path}: summary host mismatch, want {expected_label}')
        continue
    if any(row['initial_rate_mbps'].strip() for row in derphole):
        failures.append(f'{path}: acceptance rows contain an initial-rate override')
        continue
    if (any(row['direction'] != path.parent.name for row in rows) or
            any(row['workload'] != 'file' for row in derphole)):
        failures.append(f'{path}: direction or workload metadata mismatch')
        continue
    modes = {row['transfer_mode'] for row in derphole}
    if len(modes) != 1 or next(iter(modes)) not in {'bulk-packets-v1', 'blocks-v1'}:
        failures.append(f'{path}: inconsistent or unsupported modes {sorted(modes)}')
        continue
    mode = next(iter(modes))
    try:
        canonical = [number(row['mbps'], 'mbps') for row in derphole]
        wall = [number(row['wall_mbps'], 'wall_mbps') for row in derphole]
        iperf = [number(row['mbps'], 'iperf mbps') for row in iperf_rows]
        ratios = [number(row['ratio_to_iperf'], 'ratio_to_iperf') for row in derphole]
        canonical_cv = cv(canonical, 'canonical')
        wall_cv = cv(wall, 'wall')
        iperf_cv = cv(iperf, 'iperf')
        flatlines = [seconds(row['max_flatline']) for row in derphole]
    except (TypeError, ValueError, ZeroDivisionError) as error:
        failures.append(f'{path}: invalid numeric evidence: {error}')
        continue
    if any(row['trace_ok'] != 'true' for row in derphole):
        failures.append(f'{path}: trace failure')
    if max(flatlines) >= 1.0:
        failures.append(f'{path}: flatline at least one second')
    if canonical_cv > 0.15:
        archived = root / 'reruns' / path.relative_to(root)
        suffix = 'stability failure after rerun' if archived.is_file() else 'requires one rerun'
        failures.append(f'{path}: canonical CV {canonical_cv:.3f} {suffix}')

    case_dirs = []
    layout_ok = True
    for row in derphole:
        case_dir = Path(row['log_dir']).resolve()
        expected_case_dir = (
            path.parent / expected_label / f'derphole-run-{row["run"]}'
        ).resolve()
        if case_dir != expected_case_dir:
            failures.append(f'{path}: log_dir {case_dir}, want {expected_case_dir}')
            layout_ok = False
        case_dirs.append(case_dir)
    if len(set(case_dirs)) != 3:
        failures.append(f'{path}: derphole rows reuse a log_dir')
        layout_ok = False
    if not layout_ok:
        continue

    sender_traces = []
    selected_addresses = {}
    for row, case_dir in zip(derphole, case_dirs):
        traces = sorted(case_dir.glob('*sender.trace.csv'))
        if len(traces) != 1:
            failures.append(f'{path}: expected one sender trace in {case_dir}')
        else:
            sender_traces.append(traces[0])
        for role in ('sender', 'receiver'):
            logs = sorted(case_dir.glob(f'*-{role}.log'))
            if len(logs) != 1:
                failures.append(f'{path}: expected one {role} log in {case_dir}')
                continue
            try:
                addresses = selected_ips(logs[0])
            except (ValueError, IndexError) as error:
                failures.append(f'{path}: {logs[0]}: {error}')
                continue
            if any(is_tailscale(ip) for ip in addresses):
                failures.append(f'{path}: Tailscale selected address in {logs[0]}')
            if lan_path and any(not ip.is_private or ip.is_loopback or ip.is_link_local for ip in addresses):
                failures.append(f'{path}: non-LAN selected address in {logs[0]}')
            if not lan_path and any(not ip.is_global for ip in addresses):
                failures.append(f'{path}: non-public selected address in {logs[0]}')
            selected_addresses.setdefault(row['run'], set()).update(addresses)
    if lan_path:
        for row in derphole:
            iperf_path = path.parent / expected_label / f'iperf3-run-{row["run"]}.json'
            try:
                payload = json.loads(iperf_path.read_text())
                connections = payload['start']['connected']
                local_hosts = {ipaddress.ip_address(item['local_host']) for item in connections}
                remote_hosts = {ipaddress.ip_address(item['remote_host']) for item in connections}
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                failures.append(f'{path}: invalid paired iperf evidence {iperf_path}: {error}')
                continue
            iperf_endpoints = local_hosts | remote_hosts
            if len(local_hosts) != 1 or len(remote_hosts) != 1 or local_hosts == remote_hosts:
                failures.append(f'{path}: paired iperf does not identify two LAN endpoints')
            if any(is_tailscale(ip) or not ip.is_private or ip.is_loopback or ip.is_link_local
                   for ip in iperf_endpoints):
                failures.append(f'{path}: paired iperf endpoint is not private non-Tailscale LAN')
            if not exact_lan_endpoints(iperf_endpoints, selected_addresses.get(row['run'], set())):
                failures.append(f'{path}: paired iperf endpoints do not match selected transfer addresses')
    if mode == 'bulk-packets-v1':
        try:
            for row in derphole:
                for field in bulk_health:
                    number(row[field], field)
        except (TypeError, ValueError) as error:
            failures.append(f'{path}: missing or invalid numeric bulk health: {error}')
        for trace in sender_traces:
            selected = []
            with trace.open(newline='') as handle:
                for sample in csv.DictReader(handle):
                    value = sample.get('rate_selected_mbps', '').strip()
                    if value:
                        try:
                            selected.append(number(value, 'rate_selected_mbps'))
                        except ValueError as error:
                            failures.append(f'{path}: {trace}: {error}')
            if not selected or any(value != 1000 for value in selected):
                failures.append(f'{path}: {trace}: selected bulk rates {selected}, want only 1000')
    else:
        for trace in sender_traces:
            with trace.open(newline='') as handle:
                samples = list(csv.DictReader(handle))
            transports = {sample.get('direct_transport', '').strip() for sample in samples}
            transports.discard('')
            if transports != {'quic'}:
                failures.append(f'{path}: blocks transport {sorted(transports)}, want quic')
            progress = False
            try:
                progress = any(
                    sample.get('phase') == 'direct_execute' and
                    sample.get('direct_transport') == 'quic' and
                    number(sample.get('direct_bytes') or '0', 'direct_bytes') > 0
                    for sample in samples
                )
            except ValueError as error:
                failures.append(f'{path}: {trace}: {error}')
            if not progress:
                failures.append(f'{path}: {trace}: no QUIC direct progress')
    print(
        f'{path} mode={mode} canonical_median={statistics.median(canonical):.2f} '
        f'canonical_cv={canonical_cv:.3f} wall_median={statistics.median(wall):.2f} '
        f'wall_cv={wall_cv:.3f} '
        f'iperf_median={statistics.median(iperf):.2f} iperf_cv={iperf_cv:.3f} '
        f'ratios={",".join(f"{ratio:.3f}" for ratio in ratios)} '
        f'ratio_median={statistics.median(ratios):.3f}'
    )
if failures:
    raise SystemExit('\n'.join(failures))
print('mode_aware_fleet_acceptance=true')
PY
```

If the only failure for a host-direction is canonical CV above 15 percent, archive its directory at `.tmp/bulk-pacing-default-acceptance-20260712/reruns/<host>/<direction>/`, repeat exactly three runs for that host-direction once at the original path, and rerun the audit. The archived `summary.csv` lets the audit distinguish the one allowed rerun from a second CV failure, which rejects stability. Integrity, mode, route, trace, selected-rate, or cleanup failures are not noise waivers. A `trace_ok=true` derphole row is the harness's composite proof that its benchmark driver also passed SHA, size, direct-path, and process/socket-cleanup checks.

Expected: three successful normal-file transfers and three iperf rows per reachable host-direction, `trace_ok=true`, zero leaks, one consistent negotiated mode, and maximum flatline below one second. For `bulk-packets-v1`, every non-empty sender-trace `rate_selected_mbps` value equals the production default and all bulk health fields are numeric. For intentional `blocks-v1`, traces report QUIC direct transport and no bulk-rate assertion is made. Canonical goodput CV is at most 15 percent after at most one same-cell rerun. Public hosts prove public non-Tailscale addresses; `pve1` is labeled LAN.

- [ ] **Step 5: Run the final three 3 GiB Eric forward transfers**

Run:

```bash
env -u DERPHOLE_PUBLIC_PATH_INITIAL_RATES \
DERPHOLE_PUBLIC_PATH_HOSTS='ubuntu@eric-nuc' \
DERPHOLE_PUBLIC_PATH_DIRECTION=forward \
DERPHOLE_PUBLIC_PATH_SIZE_MIB=3072 \
DERPHOLE_PUBLIC_PATH_RUNS=3 \
DERPHOLE_PUBLIC_IPERF_PORT=8123 \
DERPHOLE_BENCH_LOG_DIR=.tmp/bulk-pacing-eric-final-20260712 \
./scripts/public-path-performance-harness.sh
```

Expected: three successful 3 GiB normal file transfers with the selected 1,000 Mbps production default, matching SHA-256, public non-Tailscale path, `bulk-packets-v1`, trace success, no flatline of at least one second, no leaks, and every sender trace selecting 1,000 Mbps. Compare canonical and capacity-normalized medians to the Task 6 1,000 Mbps group, not the rejected 900 Mbps Eric candidate. If iperf CV exceeds 15 percent, treat normalized ratios as diagnostic and require canonical median within 5 percent of the Task 6 1,000 Mbps median.

- [ ] **Step 6: Final verification and finish-to-main handoff**

Run:

```bash
mise run test
mise run vet
mise run build
mise run check:hooks
but pull --check
but status
```

Expected: all local gates pass; the branch contains only this plan's coherent commits; `.tmp` benchmark artifacts remain uncommitted. Before claiming completion, use `superpowers:verification-before-completion`. The user has already authorized landing and pushing: follow the repository's GitButler finish-to-main procedure, verify local `main`, `origin/main`, and `git ls-remote origin refs/heads/main`, watch Checks/Pages/Release, and verify the resulting `derphole@dev` version resolves to the landed commit.

---

## Self-Review Results

- **Spec coverage:** The plan covers local `ENOBUFS` attribution, a less aggressive test-only initial target, rate/velocity health analysis, paired bidirectional iperf context, Eric candidate selection, every-reachable-host fleet rejection, production-default selection, three-run acceptance, integrity, trace, route, and leak gates.
- **Placeholder scan:** The plan contains no implementation placeholders. Conditional production edits are bounded to the explicit 900, 800, or unchanged 1,000 Mbps outcomes.
- **Type consistency:** The diagnostic field names map consistently from `externalV2BulkPacketSender` through `externalDirectTransferDiagnostics`, `externalTransferMetrics`, `transfertrace.Snapshot`, CSV headers, checker summaries, CLI keys, and harness columns.
