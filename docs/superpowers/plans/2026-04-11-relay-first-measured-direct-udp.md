# Relay-First Measured Direct UDP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `send/listen` start transferring immediately over relay, then promote to direct UDP without stalls while dynamically scaling from slow WAN links up to the current ~2 Gbps ktzlxc ceiling and beyond.

**Architecture:** Keep DERP as the always-available control and initial payload path. Introduce a bounded replayable payload stream above the carrier so relay can start immediately, then switch the same byte stream onto direct UDP once the direct path proves it can carry data. Replace optimistic direct-start geometry with a measured ramp that derives initial sender rate, lane count, and replay window from observed delivery and live transfer feedback.

**Tech Stack:** Go, `pkg/session` transport/session code, current direct-UDP probe heuristics, existing `pkg/probe` reporting, promotion scripts, `derpcat-probe matrix`, live SSH verification against `ktzlxc`, `uklxc`, `canlxc`, and `orange-india.exe.xyz`.

---

## File Structure

- Modify: `pkg/session/external.go`
  - start payload relay immediately after claim acceptance
  - keep direct promotion asynchronous instead of gating first payload bytes
- Modify: `pkg/session/external_direct_udp.go`
  - measured direct-start budget
  - live ramp-up/ramp-down based on delivery and retransmit pressure
  - clean relay/direct handoff control
- Create: `pkg/session/payload_spool.go`
  - bounded replayable chunk spool for seekable and non-seekable sources
- Create: `pkg/session/payload_spool_test.go`
  - spool boundedness, watermark trim, seek/replay coverage
- Modify: `pkg/session/session_test.go`
  - end-to-end relay-first then direct-promotion tests
- Modify: `cmd/derpcat/listen_test.go`
  - CLI-visible startup and completion behavior tests
- Modify: `cmd/derpcat-probe/matrix.go`
  - preserve per-run peak/average/first-byte summaries and baseline comparison output
- Modify: `docs/benchmarks.md`
  - benchmark procedure for relay-first promotion and iperf3 baseline comparison

### Task 1: Restore Relay-First Payload Start

**Files:**
- Modify: `pkg/session/external.go`
- Test: `pkg/session/session_test.go`
- Test: `cmd/derpcat/listen_test.go`

- [ ] **Step 1: Write the failing session test for relay-first startup**

Add a focused test in `pkg/session/session_test.go` near the existing status-stream tests:

```go
func TestSendListenStartsPayloadOnRelayBeforeDirectPromotion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h := newExternalHarness(t)
	h.disableTailscaleCandidates = true
	h.delayDirectUDPReady = 750 * time.Millisecond

	payload := bytes.Repeat([]byte("relay-first-"), 4096)
	result := h.runSendListen(ctx, payload)

	if !bytes.Equal(result.stdout, payload) {
		t.Fatalf("stdout mismatch: got %d bytes want %d", len(result.stdout), len(payload))
	}
	if !result.hasStatus(session.StateRelayConnected) {
		t.Fatalf("statuses missing connected-relay: %q", result.statuses)
	}
	if !result.payloadStartedBeforeStatus(session.StateDirectConnected) {
		t.Fatalf("payload did not start before connected-direct: statuses=%q", result.statuses)
	}
}
```

- [ ] **Step 2: Run the test to verify the current regression**

Run:

```sh
go test ./pkg/session -run TestSendListenStartsPayloadOnRelayBeforeDirectPromotion -count=1
```

Expected: fail because current `send/listen` waits for direct-ready gating before first payload bytes move.

- [ ] **Step 3: Implement relay-first startup in `pkg/session/external.go`**

Adjust the send/listen orchestration so relay payload streaming starts as soon as the claim is accepted and the relay carrier is authenticated. The direct path negotiation must continue in parallel, not as a precondition for starting the byte stream.

Implementation shape:

```go
relayCarrier, relayReady, err := externalOpenRelayCarrier(...)
if err != nil {
	return err
}
if err := relayReady(ctx); err != nil {
	return err
}

payload := newExternalPayloadTransfer(...)
go payload.runRelay(ctx, relayCarrier)
go payload.runDirectPromotion(ctx, directPlanner)

return payload.wait(ctx)
```

The important behavior change is that `runRelay` owns time-to-first-byte, while `runDirectPromotion` may later attach a better carrier.

- [ ] **Step 4: Add the CLI-visible regression test**

In `cmd/derpcat/listen_test.go`, add a case that asserts non-verbose `listen` stays quiet except for the token/status lines and that data still appears before direct promotion completes:

```go
func TestListenRelayFirstPromotionDoesNotDelayStdout(t *testing.T) {
	// Use the same delayed-direct harness as the session test and assert
	// stdout contains payload while status history still includes
	// connected-relay before connected-direct.
}
```

- [ ] **Step 5: Run the relay-first tests**

Run:

```sh
go test ./pkg/session -run TestSendListenStartsPayloadOnRelayBeforeDirectPromotion -count=1
go test ./cmd/derpcat -run TestListenRelayFirstPromotionDoesNotDelayStdout -count=1
```

Expected: both pass.

- [ ] **Step 6: Commit**

```sh
git add pkg/session/external.go pkg/session/session_test.go cmd/derpcat/listen_test.go
git commit -m "session: start send listen payload on relay immediately"
```

### Task 2: Add Bounded Replay Spool for Seamless Handoff

**Files:**
- Create: `pkg/session/payload_spool.go`
- Create: `pkg/session/payload_spool_test.go`
- Modify: `pkg/session/external.go`

- [ ] **Step 1: Write the failing spool tests**

Create `pkg/session/payload_spool_test.go` with:

```go
func TestPayloadSpoolTrimsAckedPrefix(t *testing.T) {
	s := newPayloadSpool(8 << 20)
	id0 := s.append(bytes.Repeat([]byte("a"), 1<<20))
	id1 := s.append(bytes.Repeat([]byte("b"), 1<<20))
	s.ackThrough(id0.endOffset)
	if s.bufferedBytes() >= 2<<20 {
		t.Fatalf("bufferedBytes() = %d, want trimmed prefix", s.bufferedBytes())
	}
	if _, ok := s.readAt(id1.offset, 16); !ok {
		t.Fatal("expected second chunk to remain replayable")
	}
}

func TestPayloadSpoolBackpressuresWhenWindowExceeded(t *testing.T) {
	s := newPayloadSpool(1 << 20)
	s.append(bytes.Repeat([]byte("x"), 1<<20))
	if s.canAccept(1) {
		t.Fatal("canAccept() = true, want false once replay window is full")
	}
}

func TestPayloadSpoolReplaysFromTempFileWithoutRetainingWholeStreamInRAM(t *testing.T) {
	dir := t.TempDir()
	s, err := newPayloadSpool(dir, 1<<20)
	if err != nil {
		t.Fatalf("newPayloadSpool() error = %v", err)
	}
	chunk := bytes.Repeat([]byte("z"), 2<<20)
	meta, err := s.append(chunk)
	if err != nil {
		t.Fatalf("append() error = %v", err)
	}
	if s.bufferedBytes() > 1<<20 {
		t.Fatalf("bufferedBytes() = %d, want capped in-memory window", s.bufferedBytes())
	}
	got, ok := s.readAt(meta.offset, len(chunk))
	if !ok {
		t.Fatal("readAt() = !ok, want replayable chunk")
	}
	if !bytes.Equal(got, chunk) {
		t.Fatal("replayed chunk mismatch")
	}
}
```

- [ ] **Step 2: Run the spool tests and verify failure**

Run:

```sh
go test ./pkg/session -run 'TestPayloadSpool(TrimsAckedPrefix|BackpressuresWhenWindowExceeded)' -count=1
```

Expected: fail because the temp-file-backed spool does not exist yet.

- [ ] **Step 3: Implement the spool**

Create `pkg/session/payload_spool.go`:

```go
type payloadChunk struct {
	offset int64
	size   int
}

type payloadSpool struct {
	file       *os.File
	limitBytes int64
	baseOffset int64
	nextOffset int64
	buffered   int64
	chunks     []payloadChunk
}

func newPayloadSpool(dir string, limitBytes int64) (*payloadSpool, error) { ... }
func (s *payloadSpool) canAccept(n int) bool { ... }
func (s *payloadSpool) append(p []byte) (payloadChunk, error) { ... }
func (s *payloadSpool) ackThrough(offset int64) { ... }
func (s *payloadSpool) readAt(offset int64, n int) ([]byte, bool) { ... }
func (s *payloadSpool) close() error { ... }
func (s *payloadSpool) bufferedBytes() int64 { return s.buffered }
```

Store replay bytes in a temp file immediately and keep only a capped hot window in memory. The sender must be able to stream indefinitely without RAM scaling with transfer size.

- [ ] **Step 4: Wire spool-backed replay into the relay/direct handoff path**

In `pkg/session/external.go`, replace “fire-and-forget current carrier” payload ownership with spool-backed replay:

```go
spool, err := newPayloadSpool("", externalRelayReplayWindowBytes)
if err != nil {
	return err
}
defer spool.close()
for {
	chunk, err := readNextPayloadChunk(src)
	if err == io.EOF {
		break
	}
	for !spool.canAccept(len(chunk)) {
		if err := payload.waitForAck(ctx); err != nil {
			return err
		}
	}
	meta, err := spool.append(chunk)
	if err != nil {
		return err
	}
	if err := relay.send(meta.offset, chunk); err != nil {
		return err
	}
}
```

When the direct carrier comes up, replay from the receiver watermark instead of restarting from zero.

- [ ] **Step 5: Run the spool tests**

Run:

```sh
go test ./pkg/session -run 'TestPayloadSpool(TrimsAckedPrefix|BackpressuresWhenWindowExceeded)' -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

```sh
git add pkg/session/payload_spool.go pkg/session/payload_spool_test.go pkg/session/external.go
git commit -m "session: add bounded replay spool for carrier handoff"
```

### Task 3: Replace Optimistic Direct Starts With Measured Ramp Control

**Files:**
- Modify: `pkg/session/external_direct_udp.go`
- Test: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Write failing tests for measured direct-start budget**

Add or extend tests in `pkg/session/external_direct_udp_test.go`:

```go
func TestExternalDirectUDPDataPathBudgetKeepsLowCeilingSingleLane(t *testing.T) {
	got := externalDirectUDPDataPathBudget(75, 56, 75, 8, false)
	if got.ActiveLanes != 1 {
		t.Fatalf("ActiveLanes = %d, want 1", got.ActiveLanes)
	}
	if got.ReplayWindowBytes > 32<<20 {
		t.Fatalf("ReplayWindowBytes = %d, want <= 32 MiB", got.ReplayWindowBytes)
	}
}

func TestExternalDirectUDPDataStartRateDoesNotUseProbeCeilingAsSteadyState(t *testing.T) {
	got := externalDirectUDPDataStartRateMbpsForProbeSamples(1200, 2250, ktzlxcHighGoodputCappedTopProbeSentSamples(), ktzlxcHighGoodputCappedTopProbeReceivedSamples())
	if got > 1200 {
		t.Fatalf("start rate = %d, want <= selected rate", got)
	}
}
```

- [ ] **Step 2: Run the focused direct-UDP tests**

Run:

```sh
go test ./pkg/session -run 'TestExternalDirectUDP(DataPathBudget|DataStartRate)' -count=1
```

Expected: fail if any path still inherits top-tier replay window or lane count from ceiling-only geometry.

- [ ] **Step 3: Implement measured ramp state**

In `pkg/session/external_direct_udp.go`, introduce a small live controller for the direct data phase:

```go
type externalDirectUDPLiveBudget struct {
	RateMbps          int
	ActiveLanes       int
	ReplayWindowBytes uint64
}

func externalDirectUDPInitialLiveBudget(selectedRateMbps, activeRateMbps, ceilingMbps, lanes int, striped bool) externalDirectUDPLiveBudget {
	b := externalDirectUDPDataPathBudget(selectedRateMbps, activeRateMbps, ceilingMbps, lanes, striped)
	return externalDirectUDPLiveBudget{
		RateMbps:          b.RateMbps,
		ActiveLanes:       b.ActiveLanes,
		ReplayWindowBytes: b.ReplayWindowBytes,
	}
}

func (b *externalDirectUDPLiveBudget) adapt(stats directUDPStats) {
	if stats.RetransmitRate > 0.05 || stats.ReplayFillRatio > 0.80 {
		b.RateMbps = max(externalDirectUDPRateProbeMinMbps, int(float64(b.RateMbps)*0.85))
	}
	if stats.DeliveryRatio > 0.98 && stats.RetransmitRate < 0.01 {
		b.RateMbps = min(externalDirectUDPMaxRateMbps, int(float64(b.RateMbps)*1.10))
	}
}
```

Do not expose this as user-facing config. It is runtime behavior only.

- [ ] **Step 4: Run the session package**

Run:

```sh
go test ./pkg/session -count=1
```

Expected: pass.

- [ ] **Step 5: Commit**

```sh
git add pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go
git commit -m "session: derive direct udp starts from measured path budget"
```

### Task 4: Preserve Benchmark Evidence And Regressions

**Files:**
- Modify: `cmd/derpcat-probe/matrix.go`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Write the failing matrix command test**

In `cmd/derpcat-probe/matrix_test.go`, add:

```go
func TestRunMatrixCmdIncludesPeakAndWallTimeInSummaries(t *testing.T) {
	prev := runMatrixCommand
	defer func() { runMatrixCommand = prev }()

	runMatrixCommand = func(_ context.Context, script string, host string, sizeMiB int) ([]byte, error) {
		return []byte(strings.Join([]string{
			"benchmark-host=" + host,
			"benchmark-direction=forward",
			"benchmark-size-bytes=1073741824",
			"benchmark-total-duration-ms=16000",
			"benchmark-goodput-mbps=1700.0",
			"benchmark-peak-goodput-mbps=1800.0",
			"benchmark-success=true",
		}, "\n")), nil
	}

	var stdout bytes.Buffer
	if code := runMatrixCmd([]string{"--hosts", "ktzlxc", "--iterations", "1", "--size-mib", "1024"}, &stdout, io.Discard); code != 0 {
		t.Fatalf("runMatrixCmd() code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "\"peak_goodput_mbps\": 1800") {
		t.Fatalf("stdout missing peak_goodput_mbps: %s", stdout.String())
	}
}
```

- [ ] **Step 2: Run the matrix tests and verify failure if the summary is incomplete**

Run:

```sh
go test ./cmd/derpcat-probe -run TestRunMatrixCmdIncludesPeakAndWallTimeInSummaries -count=1
```

- [ ] **Step 3: Keep the benchmark docs aligned**

Update `docs/benchmarks.md` so the required evidence for this phase explicitly includes:

```md
- relay first-byte time
- direct promotion time
- average goodput
- peak goodput
- total wall time
- success/failure count per host and direction
- iperf3 forwarded-port baseline for the same host pair where available
```

- [ ] **Step 4: Run the relevant tests**

Run:

```sh
go test ./cmd/derpcat-probe -count=1
```

Expected: pass.

- [ ] **Step 5: Commit**

```sh
git add cmd/derpcat-probe/matrix.go cmd/derpcat-probe/matrix_test.go docs/benchmarks.md
git commit -m "probe: preserve promotion baseline evidence"
```

### Task 5: Live Verification

**Files:**
- Modify: `notes/2026-04-11-transport-audit.md`

- [ ] **Step 1: Capture the fresh no-Tailscale baseline**

Run:

```sh
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./dist/derpcat-probe matrix --hosts ktzlxc,uklxc,canlxc,orange-india.exe.xyz --iterations 1 --size-mib 1024 --out /tmp/derpcat-matrix/four-host-baseline.json
```

Expected: JSON report with one forward and one reverse run per host.

- [ ] **Step 2: Verify targeted ktzlxc performance**

Run:

```sh
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh ktzlxc 1024
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test-reverse.sh ktzlxc 1024
```

Expected: both succeed and remain in the current ~2 Gbps class where WAN allows.

- [ ] **Step 3: Verify slower hosts complete without runaway retransmits**

Run:

```sh
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh uklxc 1024
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test-reverse.sh uklxc 1024
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh canlxc 1024
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test-reverse.sh canlxc 1024
```

Expected: all complete successfully; reverse `uklxc` must not tail-stall and `canlxc` should no longer run far below its WAN ceiling without an explainable network limit.

- [ ] **Step 4: Compare against iperf3 on the forwarded port**

Run:

```sh
nix run nixpkgs#iperf3 -- -c <mac-public-endpoint> -p 8321 -P 4
nix run nixpkgs#iperf3 -- -c <ktzlxc-peer> -p 8321 -P 4 -R
```

Expected: derpcat remains below raw iperf3, but the gap is explainable and the session does not fail on lower-ceiling paths.

- [ ] **Step 5: Record the evidence**

Append the final metrics, artifact paths, and any remaining gap analysis to `notes/2026-04-11-transport-audit.md`.

- [ ] **Step 6: Final verification**

Run:

```sh
mise run test
mise run build
```

Expected: both pass.

- [ ] **Step 7: Commit**

```sh
git add notes/2026-04-11-transport-audit.md
git commit -m "notes: record relay first measured direct udp baseline"
```

## Self-Review

- Spec coverage:
  - relay-first streaming: Task 1
  - bounded replay for non-seekable and seamless handoff: Task 2
  - dynamic scaling from slow to fast WAN ceilings: Task 3
  - benchmark evidence and host matrix: Tasks 4 and 5
- Placeholder scan:
  - no `TODO`/`TBD` markers left
  - commands and target files are explicit
- Type consistency:
  - all new control concepts are scoped to `payloadSpool`, `externalDirectUDPLiveBudget`, and existing matrix reporting types

Plan complete and saved to `docs/superpowers/plans/2026-04-11-relay-first-measured-direct-udp.md`. Two execution options:

1. Subagent-Driven (recommended) - dispatch a fresh subagent per task, review between tasks, fast iteration
2. Inline Execution - execute tasks in this session using executing-plans, batch execution with checkpoints

Given the ongoing benchmark work in this session, inline execution is the practical default unless we explicitly switch.
