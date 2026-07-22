# Bulk Probe Clean Socket Handoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove every raw-direct UDP lane is quiet before QUIC reuses it, while preserving real early probe-rejection evidence and keeping cleanup failures fatal.

**Architecture:** Add one session-owned concurrent drain primitive that consumes queued datagrams through the existing batch abstraction and restores socket deadlines. The receiver completes that drain before acknowledging a QUIC decision; the sender completes it after the decision acknowledgement and before returning the negotiated-fallback sentinel. Probe rejection becomes typed local state so acknowledgement timeout is an ordinary rejection, while cancellation, peer abort, protocol failure, and cleanup failure retain their fatal identities.

**Tech Stack:** Go 1.25, `net.PacketConn`, existing platform batch readers, session decision control messages, transfertrace CSV, Bash 3.2-compatible promotion harness, GitButler.

## Global Constraints

- The production quiet window is exactly 10 milliseconds per read attempt.
- The shared hard drain deadline is exactly 500 milliseconds for all lanes; it must not multiply by lane count.
- Drain all raw-direct lanes concurrently through `externalV2BulkPacketBatchConn`; do not add another platform receive stack.
- Restore zero read and write deadlines on every path, including read failure and hard-deadline failure.
- The receiver must finish reader join, drain, and deadline restoration before sending the QUIC decision acknowledgement.
- The sender must finish writer/control-reader join, drain, and deadline restoration before opening QUIC.
- Socket cleanup failure is fatal and must never satisfy `externalV2NegotiatedBulkPacketFallback`.
- `DERPHOLE_TEST_BULK_PROBE_OUTCOME=sender-reject` may control accepted selections and ordinary capacity rejections only; explicit empty and unknown values remain fatal.
- Keep the wire reason `quic/sender-probe-rejected`; rejection stage remains local diagnostics.
- Emit `v2-bulk-probe-rejected=stage:<stage> train:<train> rate_mbps:<rate>` only when local rejection metadata exists.
- Emit one `v2-bulk-handoff-drain=lanes:<lanes> datagrams:<count> duration_ms:<ms>` line on each peer before QUIC opens.
- Add trace columns `bulk_probe_reject_stage`, `bulk_handoff_drained_datagrams`, and `bulk_handoff_drain_duration_ms`.
- Add no user-facing option, benchmark flag, probe-rate change, or compatibility shim for old clients.
- During live acceptance, stage under a capacity-checked home or data filesystem. Use `/tmp` only when measured free space covers payload plus working overhead, and remove every task-owned staging/output path afterward.
- Do not run `mise run check` during implementation. Run it exactly once after freezing the final acceptance head.

---

## File Structure

- Create `pkg/session/external_v2_bulk_packet_handoff.go`: concurrent lane drain, quiet-window detection, hard deadline, deadline restoration, and structured result.
- Create `pkg/session/external_v2_bulk_packet_handoff_test.go`: deterministic batch-reader tests for queue consumption, concurrency, hard timeout, read failure, and restoration failure.
- Modify `pkg/session/external_v2_bulk_packet_probe.go`: typed ordinary rejection metadata, early acknowledgement-timeout control, receiver cleanup/drain, and result diagnostics.
- Modify `pkg/session/external_v2_bulk_packet_probe_test.go`: early-rejection and forced-outcome identity tests.
- Modify `pkg/session/external_v2_bulk_packet.go`: sender handoff cleanup, fatal/ordinary error separation, and result propagation.
- Modify `pkg/session/external_v2_bulk_packet_test.go`: sender cleanup ordering, acknowledgement-loss diagnostics, and no-QUIC-on-drain-failure tests.
- Modify `pkg/session/external_v2_bulk_decision.go`: reject fatal probe/cleanup outcomes before readiness or acknowledgement.
- Modify `pkg/session/external_v2_bulk_decision_test.go`: receiver acknowledgement ordering and fatal outcome tests.
- Modify `pkg/session/external_transfer_metrics.go` and `pkg/session/external_transfer_metrics_test.go`: persist rejection/drain state and expose a read-only fallback diagnostic snapshot.
- Modify `pkg/transfertrace/trace.go`, `pkg/transfertrace/trace_test.go`, `pkg/transfertrace/checker.go`, and `pkg/transfertrace/checker_test.go`: serialize and validate the three new trace fields.
- Modify `pkg/session/external_v2.go`, `pkg/session/external_v2_offer.go`, and `pkg/session/external_v2_block.go`: emit rejection/drain markers before the existing fallback marker in all sender/receiver topologies.
- Modify `pkg/session/external_v2_block_test.go`: byte-exact QUIC fallback with deliberately queued stale datagrams and marker/fatal-error assertions.
- Modify `scripts/promotion-benchmark-driver.sh` and `scripts/promotion_scripts_test.go`: require exactly one drain marker per role during the controlled fallback acceptance path.

---

### Task 1: Build the bounded concurrent drain primitive

**Files:**
- Create: `pkg/session/external_v2_bulk_packet_handoff.go`
- Create: `pkg/session/external_v2_bulk_packet_handoff_test.go`

**Interfaces:**
- Consumes: `externalV2BulkPacketPath`, `externalV2BulkPacketBatchConn`, `newExternalV2BulkPacketReadMessages()`, and `clearExternalV2BulkPacketDeadlines()`.
- Produces: `externalV2BulkPacketHandoffDrainResult`, `drainExternalV2BulkPacketHandoff(context.Context, externalV2BulkPacketPath)`, and the replaceable `externalV2BulkPacketDrainForHandoff` function used by later ordering tests.

- [ ] **Step 1: Write deterministic failing drain tests**

Create these deterministic test doubles so production timeouts are never slept:

```go
type handoffDeadlineConn struct {
	net.PacketConn
	mu    sync.Mutex
	read  time.Time
	write time.Time
	clearErr error
}

func (c *handoffDeadlineConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.read = deadline
	if deadline.IsZero() {
		return c.clearErr
	}
	return nil
}

func (c *handoffDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.write = deadline
	if deadline.IsZero() {
		return c.clearErr
	}
	return nil
}

func (c *handoffDeadlineConn) SetDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		return c.clearErr
	}
	return nil
}

func (c *handoffDeadlineConn) Close() error { return nil }

func (c *handoffDeadlineConn) assertCleared(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.read.IsZero() || !c.write.IsZero() {
		t.Fatalf("deadlines = read:%v write:%v, want zero", c.read, c.write)
	}
}

type handoffReadStep struct {
	count int
	err   error
}

type handoffScriptedBatchConn struct {
	mu    sync.Mutex
	steps []handoffReadStep
	calls int
	read  func(context.Context, []externalV2BulkPacketBatchMessage) (int, error)
}

func (c *handoffScriptedBatchConn) WriteBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, errors.New("unexpected handoff test write")
}

func (c *handoffScriptedBatchConn) ReadBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	if c.read != nil {
		return c.read(ctx, messages)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if len(c.steps) == 0 {
		return 0, errors.New("handoff test exhausted read script")
	}
	step := c.steps[0]
	c.steps = c.steps[1:]
	return step.count, step.err
}

func (*handoffScriptedBatchConn) Stats() externalV2BulkPacketBatchStats { return externalV2BulkPacketBatchStats{} }
```

Then add the queue-consumption test:

```go
func TestDrainExternalV2BulkPacketHandoffConsumesUntilQuiet(t *testing.T) {
	conn := &handoffDeadlineConn{}
	reader := &handoffScriptedBatchConn{steps: []handoffReadStep{
		{count: 3}, {count: 2}, {err: context.DeadlineExceeded},
	}}
	path := externalV2BulkPacketPath{Conns: []net.PacketConn{conn}}
	got, err := drainExternalV2BulkPacketHandoffWithDeps(context.Background(), path, externalV2BulkPacketHandoffDrainDeps{
		quietWindow: time.Millisecond,
		hardTimeout: 50 * time.Millisecond,
		newBatchConn: func(net.PacketConn) externalV2BulkPacketBatchConn { return reader },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Lanes != 1 || got.Datagrams != 5 || got.Duration <= 0 {
		t.Fatalf("drain result = %+v, want one lane and five datagrams", got)
	}
	if reader.calls != 3 {
		t.Fatalf("read calls = %d, want 3", reader.calls)
	}
	conn.assertCleared(t)
}

func TestDrainExternalV2BulkPacketHandoffRunsLanesConcurrently(t *testing.T) {
	release := make(chan struct{})
	started := make(chan int, 2)
	conns := []net.PacketConn{&handoffDeadlineConn{}, &handoffDeadlineConn{}}
	readers := map[net.PacketConn]externalV2BulkPacketBatchConn{}
	for lane, conn := range conns {
		lane := lane
		calls := 0
		readers[conn] = &handoffScriptedBatchConn{read: func(ctx context.Context, _ []externalV2BulkPacketBatchMessage) (int, error) {
			calls++
			if calls == 1 {
				started <- lane
				select {
				case <-release:
					return 1, nil
				case <-ctx.Done():
					return 0, ctx.Err()
				}
			}
			return 0, context.DeadlineExceeded
		}}
	}
	path := externalV2BulkPacketPath{Conns: conns}
	done := make(chan error, 1)
	go func() {
		_, err := drainExternalV2BulkPacketHandoffWithDeps(context.Background(), path, externalV2BulkPacketHandoffDrainDeps{
			quietWindow: time.Millisecond,
			hardTimeout: 50 * time.Millisecond,
			newBatchConn: func(conn net.PacketConn) externalV2BulkPacketBatchConn { return readers[conn] },
		})
		done <- err
	}()
	seen := map[int]bool{<-started: true, <-started: true}
	if !seen[0] || !seen[1] {
		t.Fatalf("started lanes = %v, want 0 and 1", seen)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDrainExternalV2BulkPacketHandoffHardDeadlineIsFatal(t *testing.T) {
	conn := &handoffDeadlineConn{}
	reader := &handoffScriptedBatchConn{read: func(ctx context.Context, _ []externalV2BulkPacketBatchMessage) (int, error) {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
			return 1, nil
		}
	}}
	path := externalV2BulkPacketPath{Conns: []net.PacketConn{conn}}
	_, err := drainExternalV2BulkPacketHandoffWithDeps(context.Background(), path, externalV2BulkPacketHandoffDrainDeps{
		quietWindow: time.Millisecond,
		hardTimeout: 5 * time.Millisecond,
		newBatchConn: func(net.PacketConn) externalV2BulkPacketBatchConn { return reader },
	})
	if err == nil || !strings.Contains(err.Error(), "bulk packet handoff lane 0 hard deadline") {
		t.Fatalf("drain error = %v, want lane hard-deadline failure", err)
	}
	conn.assertCleared(t)
}
```

Add separate cases where `ReadBatch` returns `injected handoff read failure` and where zero-deadline restoration returns `injected handoff deadline restoration failure`. Require lane numbers and operation names in both errors, and require all other lanes to join before the helper returns.

- [ ] **Step 2: Run the tests and verify the missing-helper failure**

Run:

```bash
mise exec -- go test ./pkg/session -run '^TestDrainExternalV2BulkPacketHandoff' -count=1
```

Expected: FAIL to compile because `externalV2BulkPacketHandoffDrainResult` and `drainExternalV2BulkPacketHandoffWithDeps` do not exist.

- [ ] **Step 3: Implement the drain primitive**

Use these production types and constants:

```go
const (
	externalV2BulkPacketHandoffQuietWindow = 10 * time.Millisecond
	externalV2BulkPacketHandoffHardTimeout = 500 * time.Millisecond
)

type externalV2BulkPacketHandoffDrainResult struct {
	Lanes     int
	Datagrams uint64
	Duration  time.Duration
}

type externalV2BulkPacketHandoffDrainDeps struct {
	quietWindow time.Duration
	hardTimeout time.Duration
	newBatchConn func(net.PacketConn) externalV2BulkPacketBatchConn
}

var externalV2BulkPacketDrainForHandoff = drainExternalV2BulkPacketHandoff
```

`drainExternalV2BulkPacketHandoff` must supply the two production durations and `newExternalV2BulkPacketBatchConn`. `drainExternalV2BulkPacketHandoffWithDeps` must:

```go
started := time.Now()
drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deps.hardTimeout)
defer cancel()

results := make(chan externalV2BulkPacketHandoffLaneResult, len(path.Conns))
for lane, conn := range path.Conns {
	go func() {
		count, err := drainExternalV2BulkPacketHandoffLane(drainCtx, deps.quietWindow, deps.newBatchConn(conn))
		if err != nil {
			err = fmt.Errorf("bulk packet handoff lane %d: %w", lane, err)
		}
		results <- externalV2BulkPacketHandoffLaneResult{datagrams: count, err: err}
	}()
}
```

Each lane repeatedly creates `context.WithTimeout(drainCtx, quietWindow)`, reads a full `newExternalV2BulkPacketReadMessages()` batch, and counts every returned datagram. A zero-count `context.DeadlineExceeded` while `drainCtx.Err() == nil` is success. A zero-count nil error is `io.ErrNoProgress`. If `drainCtx.Err() != nil`, return `hard deadline: %w`. Any other error is `read queued datagrams: %w`.

After collecting every lane result, call `clearExternalV2BulkPacketDeadlines(path)` exactly once and join it as `restore deadlines: %w`. Return the structured counts even on error. Validate non-empty paths and positive dependency durations before launching goroutines.

- [ ] **Step 4: Run focused normal and race tests**

Run:

```bash
mise exec -- go test ./pkg/session -run '^TestDrainExternalV2BulkPacketHandoff' -count=1
mise exec -- go test -race ./pkg/session -run '^TestDrainExternalV2BulkPacketHandoff' -count=1
```

Expected: PASS; the concurrency test observes both lanes blocked before release, and every error test confirms zero deadlines were attempted.

- [ ] **Step 5: Review and checkpoint the drain primitive**

Run `but diff` and confirm only the two handoff files changed. Run `but pull --check`, then:

```bash
but commit codex/bulk-probe-decision-barrier -m "session: drain bulk sockets before handoff"
```

Expected: one checkpoint commit containing only the drain primitive and its tests.

---

### Task 2: Model ordinary probe rejection without hiding fatal errors

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet_probe.go:23-177,219-258,349-363`
- Modify: `pkg/session/external_v2_bulk_packet_probe_test.go:19-158`

**Interfaces:**
- Consumes: the stable `errExternalV2BulkPacketProbeRejected` sentinel and existing forced-outcome marker error.
- Produces: typed `externalV2BulkPacketProbeRejection`, result fields `RejectStage`, `RejectTrain`, and `RejectRateMbps`, plus `externalV2BulkPacketProbeOrdinaryRejection(error) bool`.

- [ ] **Step 1: Add failing error-boundary and early-timeout tests**

Extend `TestApplyExternalV2BulkPacketSenderProbeTestOutcome` with exact cases for `context.Canceled`, a protocol error, a joined cleanup error, an acknowledgement-timeout rejection, and a selector rejection. Only the last two may acquire `errExternalV2BulkPacketProbeForcedSenderReject`.

Add this sender-path test using a one-train rate table and an empty acknowledgement channel:

```go
func TestSendExternalV2BulkPacketProbeForcesRealAcknowledgementTimeout(t *testing.T) {
	t.Setenv(externalV2BulkPacketProbeTestOutcomeEnv, externalV2BulkPacketProbeTestOutcomeSenderReject)
	previousRates := append([]int(nil), externalV2BulkPacketProbeRatesMbps...)
	externalV2BulkPacketProbeRatesMbps = []int{128}
	t.Cleanup(func() { externalV2BulkPacketProbeRatesMbps = previousRates })

	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	sender := newExternalV2BulkPacketSender(
		context.Background(),
		&BlockSource{Payload: bytes.NewReader([]byte{0x5a}), PayloadSize: 1},
		externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receivers)},
		auth,
		nil,
	)

	result, err := sendExternalV2BulkPacketProbe(context.Background(), sender, make(chan externalV2BulkPacketProbeAckFrame))
	if !errors.Is(err, errExternalV2BulkPacketProbeRejected) ||
		!errors.Is(err, errExternalV2BulkPacketProbeForcedSenderReject) {
		t.Fatalf("probe error = %v, want controlled ordinary rejection", err)
	}
	if result.RejectStage != "ack-timeout" || result.RejectTrain != 0 || result.RejectRateMbps != 128 {
		t.Fatalf("rejection metadata = %+v", result)
	}
	if len(result.Trains) != 1 || result.Trains[0].Sent == 0 || result.Trains[0].Received != 0 {
		t.Fatalf("probe trains = %+v, want real unacknowledged train", result.Trains)
	}
}
```

Also prove an injected packet write error and caller cancellation return their exact original errors without either rejection sentinel.

- [ ] **Step 2: Run the tests and verify they fail on the current early return**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestApplyExternalV2BulkPacketSenderProbeTestOutcome|TestSendExternalV2BulkPacketProbe' -count=1
```

Expected: FAIL because acknowledgement timeout returns before the test outcome is applied and rejection metadata is absent.

- [ ] **Step 3: Implement typed ordinary rejection and one outcome-application exit**

Add:

```go
type externalV2BulkPacketProbeRejection struct {
	Stage    string
	Train    int
	RateMbps int
	cause    error
}

func (e *externalV2BulkPacketProbeRejection) Error() string {
	return fmt.Sprintf("bulk packet capacity probe rejected at %s train %d rate %d Mbps: %v", e.Stage, e.Train, e.RateMbps, e.cause)
}

func (e *externalV2BulkPacketProbeRejection) Unwrap() error { return e.cause }
func (e *externalV2BulkPacketProbeRejection) Is(target error) bool {
	return target == errExternalV2BulkPacketProbeRejected
}

func externalV2BulkPacketProbeOrdinaryRejection(err error) bool {
	if err == errExternalV2BulkPacketProbeRejected {
		return true
	}
	if _, ok := err.(*externalV2BulkPacketProbeRejection); ok {
		return true
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return false
	}
	errs := joined.Unwrap()
	return len(errs) == 2 &&
		externalV2BulkPacketProbeOrdinaryRejection(errs[0]) &&
		errs[1] == errExternalV2BulkPacketProbeForcedSenderReject
}
```

This deliberately rejects arbitrary wrappers and joins: a cleanup or protocol error joined beside an ordinary rejection is fatal. Add `RejectStage string`, `RejectTrain int`, and `RejectRateMbps int` to `externalV2BulkPacketProbeResult`. Change `externalV2BulkPacketProbeRatesMbps` from a fixed array to a slice with the same seven production values so tests can temporarily install a one-train table and restore it with `t.Cleanup`. Replace the acknowledgement timeout string with a private sentinel and wrap only that sentinel as stage `ack-timeout`. Wrap selector rejection as stage `selector`. Append the fully sent but unacknowledged train before returning the timeout result.

Move environment lookup and `applyExternalV2BulkPacketSenderProbeTestOutcome` into one finalizer called by accepted selection and every ordinary-rejection return. Its guard must be:

```go
if selectionErr != nil && !externalV2BulkPacketProbeOrdinaryRejection(selectionErr) {
	return result, selectionErr
}
```

Packet encoding, packet write, `context.Canceled`, `context.DeadlineExceeded`, peer abort, cleanup error, and protocol error must bypass the finalizer unchanged. Keep explicit empty and unsupported test values fatal.

- [ ] **Step 4: Run focused normal and race tests**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestApplyExternalV2BulkPacketSenderProbeTestOutcome|TestSelectExternalV2BulkPacketSenderProbe|TestSendExternalV2BulkPacketProbe|TestExternalV2BulkPacketProbeFailurePreservesRunID' -count=1
mise exec -- go test -race ./pkg/session -run 'TestApplyExternalV2BulkPacketSenderProbeTestOutcome|TestSendExternalV2BulkPacketProbe' -count=1
```

Expected: PASS with real sent-count and acknowledgement-timeout metadata preserved.

- [ ] **Step 5: Review and checkpoint rejection classification**

Run `but diff`, confirm only probe implementation/tests changed, then run `but pull --check` and:

```bash
but commit codex/bulk-probe-decision-barrier -m "session: classify bulk probe rejection"
```

Expected: one checkpoint commit that changes no wire reason or probe rate.

---

### Task 3: Put the drain inside the authenticated decision barrier

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet_probe.go:366-468`
- Modify: `pkg/session/external_v2_bulk_packet.go:303-421,920-990`
- Modify: `pkg/session/external_v2_bulk_decision.go:387-489`
- Modify: `pkg/session/external_v2_bulk_packet_test.go:1751-1890`
- Modify: `pkg/session/external_v2_bulk_decision_test.go:761-798`
- Modify: `pkg/session/external_v2_block_test.go:934-1058`

**Interfaces:**
- Consumes: `externalV2BulkPacketDrainForHandoff` and typed ordinary rejection from Tasks 1-2.
- Produces: receiver cleanup whose return gates decision acknowledgement, sender QUIC-fallback cleanup whose return gates QUIC open, and fatal decision-error filtering.

- [ ] **Step 1: Write failing receiver acknowledgement and sender handoff-order tests**

Strengthen `TestExternalV2BulkDecisionCoordinatorSenderVetoCancelsReceiverProbe` so the probe callback blocks in a fake drain after observing cancellation. Capture receiver wire sends and assert no `externalV2BulkPhaseAck` appears before the drain release, then require the exact matching acknowledgement after release.

Add a sender cleanup test that blocks `externalV2BulkPacketDrainForHandoff` after control readers and the write-deadline worker join:

```go
func TestExternalV2BulkPacketSenderFallbackWaitsForHandoffDrain(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	previousDrain := externalV2BulkPacketDrainForHandoff
	externalV2BulkPacketDrainForHandoff = func(context.Context, externalV2BulkPacketPath) (externalV2BulkPacketHandoffDrainResult, error) {
		close(started)
		<-release
		return externalV2BulkPacketHandoffDrainResult{Lanes: 1, Duration: time.Millisecond}, nil
	}
	t.Cleanup(func() { externalV2BulkPacketDrainForHandoff = previousDrain })

	ctx, cancel := context.WithCancel(context.Background())
	sender := &externalV2BulkPacketSender{
		ctx: ctx,
		src: &BlockSource{},
		batchConns: []externalV2BulkPacketBatchConn{staticExternalV2BulkPacketBatchConn{}},
		laneCount: 1,
		probeResult: externalV2BulkPacketProbeResult{RunID: 77},
	}
	writeDeadlineDone := make(chan error, 1)
	writeDeadlineDone <- nil
	close(writeDeadlineDone)
	controlDone := make(chan struct{})
	close(controlDone)
	type cleanupResult struct {
		stats externalDirectTransferStats
		err   error
	}
	done := make(chan cleanupResult, 1)
	go func() {
		stats, err := cleanupExternalV2BulkPacketSenderForQUICFallback(
			sender, cancel, writeDeadlineDone, controlDone,
			externalV2BulkPacketPath{Conns: []net.PacketConn{&writeDeadlineStateBulkPacketConn{}}},
			errExternalV2BulkPacketProbeRejected,
		)
		done <- cleanupResult{stats: stats, err: err}
	}()

	<-started
	select {
	case result := <-done:
		t.Fatalf("cleanup returned before drain release: %+v", result)
	default:
	}
	close(release)
	result := <-done
	if !externalV2NegotiatedBulkPacketFallback(result.err) {
		t.Fatalf("cleanup error = %v, want negotiated fallback", result.err)
	}
	if result.stats.Diagnostics.BulkHandoffLanes != 1 || result.stats.Diagnostics.BulkHandoffDrainDurationMS != 1 {
		t.Fatalf("cleanup diagnostics = %+v", result.stats.Diagnostics)
	}
}
```

Extend the two-topology cleanup failure test with a `drain` case and require both peers to avoid the fallback marker and QUIC open observer.

- [ ] **Step 2: Run the ordering tests and observe premature acknowledgement/return**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkDecisionCoordinatorSenderVetoCancelsReceiverProbe|TestExternalV2BulkPacketSenderFallbackWaitsForHandoffDrain|TestExternalV2ReceiverProbeCleanupFailureDoesNotOpenQUIC' -count=1
```

Expected: FAIL because current cleanup only joins goroutines and clears deadlines; it does not drain queues.

- [ ] **Step 3: Centralize receiver probe shutdown and drain before return**

Add a single helper used by every receiver probe exit:

```go
func finishExternalV2BulkPacketReceiverProbe(
	ctx context.Context,
	path externalV2BulkPacketPath,
	cancel context.CancelFunc,
	done <-chan struct{},
) (externalV2BulkPacketHandoffDrainResult, error) {
	cancel()
	interruptErr := externalV2BulkPacketProbeInterruptReads(path, time.Now())
	<-done
	drain, drainErr := externalV2BulkPacketDrainForHandoff(ctx, path)
	return drain, newExternalV2BulkPacketProbeCleanupError(interruptErr, drainErr)
}
```

The drain helper already restores deadlines, so remove the separate receiver `externalV2BulkPacketProbeClearDeadlines` call. Store the drain result in `externalV2BulkPacketProbeResult.HandoffDrain` before returning. Continue attempting the drain after an interrupt error so all cleanup evidence is returned together.

Add the field explicitly with the probe result diagnostics:

```go
type externalV2BulkPacketProbeResult struct {
	RunID         uint64
	SelectedMbps  int
	Duration      time.Duration
	Trains        []externalV2BulkPacketProbeTrainResult
	RejectStage   string
	RejectTrain   int
	RejectRateMbps int
	HandoffDrain externalV2BulkPacketHandoffDrainResult
}
```

On the completed-probe path, call the shutdown/drain helper before the final probe acknowledgement. On the early-decision path, `ResolveReceiver` already waits for the probe callback; the callback must not return until this helper finishes.

- [ ] **Step 4: Split sender abort cleanup from QUIC-handoff cleanup**

Keep `cleanupExternalV2BulkPacketSenderBeforePayload` for fatal abort paths: disarm, cancel, join, then clear deadlines. Add `cleanupExternalV2BulkPacketSenderForQUICFallback` with this order:

```go
disarmExternalV2BulkPacketWriteCancellations(sender.batchConns)
cancel()
deadlineErr := <-writeDeadlineDone
<-controlDone
drain, drainErr := externalV2BulkPacketDrainForHandoff(sender.ctx, path)
sender.probeResult.HandoffDrain = drain
return sender.stats(false), errors.Join(cause, deadlineErr, drainErr)
```

Call it only for `decision.Mode == externalV2BulkModeQUIC`. Any `deadlineErr` or `drainErr` must remain joined beside the negotiated cause so `externalV2NegotiatedBulkPacketFallback` rejects it. Fatal hello and decision failures use the abort cleanup and never advertise fallback.

- [ ] **Step 5: Make decision coordination reject fatal outcomes before readiness or ACK**

Add:

```go
func externalV2BulkPacketProbeDecisionFailure(err error, allowCanceled bool) error {
	if err == nil || externalV2BulkPacketProbeOrdinaryRejection(err) {
		return nil
	}
	if allowCanceled && errors.Is(err, context.Canceled) && externalV2BulkPacketProbeCleanupFailure(err) == nil {
		return nil
	}
	return err
}
```

In `resolveExternalV2BulkPacketSenderDecision`, return this fatal error before `ResolveSender`. In `resolveReceiverDecisionDuringProbe`, cancel and join the probe, then check the outcome before emitting or sending the ACK. In `resolveReceiverAfterProbe`, send QUIC readiness only for an ordinary receiver rejection; return operational and cleanup errors directly.

Preserve context/peer-abort priority through the existing `externalV2PreferPeerAbort` wrappers. The receiver's coordinator-initiated cancellation is allowed only in the early QUIC-decision branch after cleanup succeeds.

- [ ] **Step 6: Run focused normal and race tests**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkDecisionCoordinator|TestExternalV2BulkPacket(SenderFallback|FinalProbeAckLoss|PrePayloadCleanup)|TestExternalV2ReceiverProbeCleanupFailureDoesNotOpenQUIC' -count=1
mise exec -- go test -race ./pkg/session -run 'TestExternalV2BulkDecisionCoordinatorSenderVetoCancelsReceiverProbe|TestExternalV2BulkPacketSenderFallbackWaitsForHandoffDrain|TestExternalV2ReceiverProbeCleanupFailureDoesNotOpenQUIC' -count=1
```

Expected: PASS; ACK and sender return remain blocked until drain completes, while injected drain failure opens no QUIC endpoint.

- [ ] **Step 7: Review and checkpoint the barrier integration**

Run `but diff`, verify only Task 3 files changed, run `but pull --check`, then:

```bash
but commit codex/bulk-probe-decision-barrier -m "protocol: require clean bulk socket handoff"
```

Expected: one checkpoint commit with no fallback on cleanup or operational failure.

---

### Task 4: Carry rejection and drain evidence through logs and traces

**Files:**
- Modify: `pkg/session/external_transfer_metrics.go`
- Modify: `pkg/session/external_transfer_metrics_test.go`
- Modify: `pkg/session/external_v2_bulk_packet_probe.go:49-61,204-217`
- Modify: `pkg/session/external_v2.go:376-405`
- Modify: `pkg/session/external_v2_offer.go:310-323`
- Modify: `pkg/session/external_v2_block.go:348-392,458-470`
- Modify: `pkg/transfertrace/trace.go`
- Modify: `pkg/transfertrace/trace_test.go`
- Modify: `pkg/transfertrace/checker.go`
- Modify: `pkg/transfertrace/checker_test.go`

**Interfaces:**
- Consumes: rejection and handoff fields stored in `externalV2BulkPacketProbeResult` and `externalDirectTransferStats`.
- Produces: `externalV2BulkPacketFallbackDiagnostics`, the three trace columns, strict checker parsing, and topology-independent verbose marker emission.

- [ ] **Step 1: Write failing metrics and trace serialization tests**

Add metrics round-trip assertions for:

```go
externalDirectTransferDiagnostics{
	BulkProbeRejectStage:          "ack-timeout",
	BulkProbeRejectTrain:          5,
	BulkProbeRejectRateMbps:       2200,
	BulkHandoffLanes:              8,
	BulkHandoffDrainedDatagrams:   9628,
	BulkHandoffDrainDurationMS:    17,
}
```

Extend `TestRecorderWritesAllColumns` to require exact CSV values:

```text
bulk_probe_reject_stage=ack-timeout
bulk_handoff_drained_datagrams=9628
bulk_handoff_drain_duration_ms=17
```

Add checker cases rejecting non-decimal drain counts/durations, an unknown rejection stage, and a QUIC bulk decision with a zero handoff duration.

- [ ] **Step 2: Run metrics/trace tests and verify missing-field failures**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalTransferMetrics.*Bulk' -count=1
mise exec -- go test ./pkg/transfertrace -run 'TestRecorder.*Bulk|TestCheck.*Bulk' -count=1
```

Expected: FAIL because the diagnostics and CSV schema do not contain the new fields.

- [ ] **Step 3: Extend session diagnostics and expose an immutable fallback snapshot**

Add these fields to `externalDirectTransferDiagnostics`, `externalTransferMetrics`, and the trace snapshot mapping:

```go
BulkProbeRejectStage        string
BulkProbeRejectTrain        int
BulkProbeRejectRateMbps     int
BulkHandoffLanes            int
BulkHandoffDrainedDatagrams uint64
BulkHandoffDrainDurationMS  int64
```

`setExternalV2BulkPacketProbeDiagnostics` copies rejection fields and the handoff result, using `max(int64(1), duration.Milliseconds())` when a successful drain duration is non-zero. `setDirectDiagnosticsLocked` preserves the first non-empty rejection stage and takes maxima for drain count/duration/lanes.

Add a locked getter returning:

```go
type externalV2BulkPacketFallbackDiagnostics struct {
	RejectStage      string
	RejectTrain      int
	RejectRateMbps   int
	HandoffLanes     int
	DrainedDatagrams uint64
	DrainDurationMS  int64
}

func (m *externalTransferMetrics) BulkPacketFallbackDiagnostics() externalV2BulkPacketFallbackDiagnostics {
	if m == nil {
		return externalV2BulkPacketFallbackDiagnostics{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return externalV2BulkPacketFallbackDiagnostics{
		RejectStage: m.bulkProbeRejectStage,
		RejectTrain: m.bulkProbeRejectTrain,
		RejectRateMbps: m.bulkProbeRejectRateMbps,
		HandoffLanes: m.bulkHandoffLanes,
		DrainedDatagrams: m.bulkHandoffDrainedDatagrams,
		DrainDurationMS: m.bulkHandoffDrainDurationMS,
	}
}
```

- [ ] **Step 4: Add trace columns and checker validation**

Append the three approved columns to `pkg/transfertrace/trace.go`'s stable header and `Snapshot`. Serialize the stage as a string and both drain values as unsigned/decimal numbers.

Add all three names to `checkerBulkEvidenceColumns`; parse `bulk_probe_reject_stage` with the string fields and the drain fields with uint fields. Accept only `ack-timeout` and `selector` when the stage is non-empty. When the final bulk decision is QUIC, require a positive `bulk_handoff_drain_duration_ms`; allow zero drained datagrams because an already-quiet queue is healthy.

- [ ] **Step 5: Emit ordered verbose markers in every topology**

Change the common helper signature to:

```go
func emitExternalV2BulkPacketProbeFallback(
	emitter *telemetry.Emitter,
	metrics *externalTransferMetrics,
	err error,
)
```

Emit in this exact order when fields are present:

```go
diagnostics := metrics.BulkPacketFallbackDiagnostics()
if diagnostics.RejectStage != "" {
	emitExternalV2Debug(emitter, fmt.Sprintf(
		"v2-bulk-probe-rejected=stage:%s train:%d rate_mbps:%d",
		diagnostics.RejectStage, diagnostics.RejectTrain, diagnostics.RejectRateMbps,
	))
}
if diagnostics.HandoffLanes > 0 && diagnostics.DrainDurationMS > 0 {
	emitExternalV2Debug(emitter, fmt.Sprintf(
		"v2-bulk-handoff-drain=lanes:%d datagrams:%d duration_ms:%d",
		diagnostics.HandoffLanes, diagnostics.DrainedDatagrams, diagnostics.DrainDurationMS,
	))
}
if outcome := externalV2BulkPacketProbeTestOutcome(err); outcome != "" {
	emitExternalV2Debug(emitter, "v2-bulk-probe-test-outcome="+outcome)
}
emitExternalV2Debug(emitter, "v2-bulk-probe=fallback-before-payload")
```

Use this helper from both send runtimes and both receive runtimes, passing their metrics. Never emit a drain marker if the drain failed or did not run; those paths are fatal before this helper.

- [ ] **Step 6: Run focused normal and race tests**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalTransferMetrics.*Bulk|TestExternalV2.*ProbeFallback' -count=1
mise exec -- go test ./pkg/transfertrace -count=1
mise exec -- go test -race ./pkg/session -run 'TestExternalTransferMetrics.*Bulk|TestExternalV2.*ProbeFallback' -count=1
```

Expected: PASS with stable CSV header length and one ordered marker set per role.

- [ ] **Step 7: Review and checkpoint diagnostics**

Run `but diff`, verify only Task 4 files changed, run `but pull --check`, then:

```bash
but commit codex/bulk-probe-decision-barrier -m "telemetry: record bulk socket handoff"
```

Expected: one checkpoint commit covering metrics, logs, trace, and checker together.

---

### Task 5: Prove stale datagrams cannot poison QUIC fallback

**Files:**
- Modify: `pkg/session/external_v2_block_test.go:701-834`
- Modify: `pkg/session/external_v2_bulk_packet_test.go:1802-1890`
- Modify: `scripts/promotion-benchmark-driver.sh:1504-1527`
- Modify: `scripts/promotion_scripts_test.go:236-330,773-840`

**Interfaces:**
- Consumes: exact ordered verbose markers and controlled early acknowledgement-timeout behavior.
- Produces: byte-exact in-process regression coverage and an acceptance harness that rejects missing/duplicate drain evidence.

- [ ] **Step 1: Make the full fallback test queue stale datagrams before each real drain**

Wrap `externalV2BulkPacketDrainForHandoff` inside `TestExternalV2ProbeFallbackCompletesThroughQUICBeforePayload`. Before calling the real drain, send at least one UDP datagram to every `path.Conns[lane].LocalAddr()` from a task-owned ephemeral UDP socket. Close every injector immediately. Count injections atomically and require both sender and receiver drains to report positive discarded counts.

Keep the existing gated sink, decision/ACK ordering, sender-only forced marker count, log-quiescence check, and byte equality. Add marker order assertions:

```text
v2-bulk-decision-ack=mode:quic
v2-bulk-handoff-drain=lanes:
v2-bulk-probe-test-outcome=sender-reject   # sender only
v2-bulk-probe=fallback-before-payload
```

The receiver omits the forced marker but must contain exactly one drain marker before fallback.

- [ ] **Step 2: Strengthen the real acknowledgement-loss regression**

Set `DERPHOLE_TEST_BULK_PROBE_OUTCOME=sender-reject` in `TestExternalV2BulkPacketFinalProbeAckLossNegotiatesQUIC`. Require sender stats to retain `ack-timeout`, the failed train/rate, all sent datagrams, a successful handoff duration, and both ordinary/forced sentinels. Require receiver stats to contain a successful handoff and no forced sentinel.

- [ ] **Step 3: Run the in-process tests and verify stale-queue failure before final wiring**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2ProbeFallbackCompletesThroughQUICBeforePayload|TestExternalV2BulkPacketFinalProbeAckLossNegotiatesQUIC' -count=1
```

Expected before completing this task: FAIL if either peer skips the drain, emits it twice, loses timeout metadata, or allows stale datagrams to reach QUIC.

- [ ] **Step 4: Gate acceptance logs on exactly one successful drain marker per role**

Add to the driver:

```bash
require_bulk_handoff_drain_markers() {
  [[ "${bulk_probe_outcome_configured}" == true ]] || return 0
  local marker='v2-bulk-handoff-drain='
  local sender_count receiver_count
  sender_count="$(grep -Fc "${marker}" "${sender_log}" || true)"
  receiver_count="$(grep -Fc "${marker}" "${receiver_log}" || true)"
  [[ "${sender_count}" == "1" ]] || { echo "sender bulk handoff drain marker count = ${sender_count}, want 1" >&2; return 1; }
  [[ "${receiver_count}" == "1" ]] || { echo "receiver bulk handoff drain marker count = ${receiver_count}, want 1" >&2; return 1; }
}
```

Call it beside `require_bulk_probe_outcome_marker`. Extend the fake sender and receiver to print valid drain markers by default for the controlled QUIC decision, with independent skip/duplicate knobs. Add table tests covering missing and duplicate markers for both roles and both transfer directions. Keep sender-only environment injection assertions unchanged.

- [ ] **Step 5: Run focused session, script, and race tests**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2ProbeFallbackCompletesThroughQUICBeforePayload|TestExternalV2BulkPacketFinalProbeAckLossNegotiatesQUIC|TestExternalV2NegotiatedBulkPacketFallback' -count=1
mise exec -- go test ./scripts -run 'TestPromotionBenchmark.*BulkProbe|TestPromotionBenchmark.*Handoff' -count=1
mise exec -- go test -race ./pkg/session -run 'TestExternalV2ProbeFallbackCompletesThroughQUICBeforePayload|TestExternalV2BulkPacketFinalProbeAckLossNegotiatesQUIC' -count=1
```

Expected: PASS; payload is byte-exact, the forced marker remains sender-only, and each role emits exactly one successful drain marker.

- [ ] **Step 6: Run the repository implementation-loop baseline**

Run:

```bash
mise exec -- go test ./pkg/session ./pkg/transfertrace ./scripts -count=1
mise run check:fast
```

Expected: PASS. Do not run `mise run check` yet.

- [ ] **Step 7: Review and checkpoint the end-to-end gate**

Run `but diff`, verify only Task 5 files changed, run `but pull --check`, then:

```bash
but commit codex/bulk-probe-decision-barrier -m "test: gate clean bulk fallback handoff"
```

Expected: one checkpoint commit with the regression and promotion gate.

---

### Task 6: Freeze and execute final acceptance

**Files:**
- Read: `docs/benchmarks.md`
- Read: final GitButler branch stack and exact archived-tree build inputs
- Create only ignored evidence under `.tmp/` locally and a unique capacity-checked task directory under the remote user's home/data filesystem

**Interfaces:**
- Consumes: a clean, committed candidate head after Tasks 1-5.
- Produces: exact-head build hashes, repository gate evidence, three immutable live sample records, integrity proof, and cleanup proof.

- [ ] **Step 1: Perform final self-review and freeze the candidate head**

Run:

```bash
but status -fv
but diff
git diff --check
but pull --check
```

Expected: no uncommitted changes, no conflicts, and no incoming `origin/main` change. Record `git rev-parse HEAD` as the immutable acceptance revision. If any tracked content changes afterward, discard the acceptance evidence and start Task 6 again on a new head.

- [ ] **Step 2: Run the exhaustive gate exactly once**

Run:

```bash
mise run check
```

Expected: PASS on the frozen head. Do not rerun merely to improve the report; any failure returns the work to implementation and creates a new frozen head.

- [ ] **Step 3: Build exact archived-tree Darwin and Linux binaries**

Export the frozen commit with `git archive`, extract into a task-owned local evidence directory, build Darwin and Linux artifacts through `mise`, and record SHA-256 for the archive and both binaries. Verify `go version -m`/embedded VCS evidence corresponds to the frozen source input. Do not use uncommitted workspace binaries.

Expected: both artifacts build from identical archived source and their hashes are recorded before remote staging.

- [ ] **Step 4: Capacity-check and stage the remote batch outside `/tmp`**

On the configured remote host, create one unique directory beneath the remote user's home or approved data root. Measure available bytes with `df -Pk` before copying. Require enough free space for the 3 GiB source, 3 GiB receive output, binaries, traces, logs, and working overhead. If the selected root lacks capacity, stop before transfer and choose another measured user-owned data filesystem.

Expected: recorded filesystem, free-byte count, unique path, and uploaded Linux binary hash matching the local artifact.

- [ ] **Step 5: Run three fresh immutable forward samples**

For sample ordinals 1, 2, and 3, run the promotion driver with the exact Darwin/Linux binary pair, exact hashes, public-path Tailscale-candidate disable, `DERPHOLE_TEST_BULK_PROBE_OUTCOME=sender-reject`, 3072 MiB file workload, and the frozen revision label.

Each sample must independently prove:

```text
connected-direct with 8 active raw lanes
v2-bulk-probe-rejected=stage:ack-timeout (when the natural timeout occurs)
identical quic/sender-probe-rejected decision and ACK tuples
one v2-bulk-handoff-drain marker on each peer
one sender-only v2-bulk-probe-test-outcome=sender-reject marker
v2-bulk-probe=fallback-before-payload before QUIC payload
quic-blocks-v1 / blocks-v1
exact 3221225472-byte sink
matching source and sink SHA-256
trace checker success and no >=1s flatline
no process, socket, or output leak
```

Do not retry a failed ordinal on the same head. On the first failed sample, stop remaining samples, preserve that ordinal's evidence, diagnose, and return to implementation.

- [ ] **Step 6: Audit evidence and clean every task-owned artifact**

Verify the three accepted rows all name the frozen revision and exact binary hashes. Capture concise sender/receiver marker order, decision tuple, drain counts/durations, payload size/hash, QUIC engine, trace result, and cleanup result for each ordinal.

Then remove the unique remote staging directory and local task-owned payload/output/socket/process artifacts. Recheck the remote path is absent, local and remote task processes are absent, and task-owned `/tmp` matches are absent. Keep only the small ignored evidence bundle needed for the final report.

- [ ] **Step 7: Hand off without publishing**

Run `but status` and report separately:

- the frozen local commit hash;
- focused/race/check:fast results;
- the single exhaustive `mise run check` result;
- archived-tree binary hashes;
- all three live sample outcomes;
- local/remote cleanup proof;
- branch publication state.

Expected: work is committed only on `codex/bulk-probe-decision-barrier`; nothing is pushed, landed on `origin/main`, tagged, or released unless the user separately asks.
