# Reliable Bulk Capacity Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace lossy UDP probe acknowledgements with authenticated DERP train coordination so a dirty higher tier preserves clean lower-tier capacity and healthy transfers remain on `bulk-packets-v1`.

**Architecture:** Keep UDP exclusively as the authenticated capacity-sample path. Route `probe-end` and `probe-result` phases through the existing DERP bulk-control wire, with probe traffic separated from readiness/decision/ack traffic inside the coordinator. The sender owns train pacing and final transport selection; the receiver owns sample accounting, deterministic dirty-tier injection, socket drain, and readiness publication.

**Tech Stack:** Go, authenticated DERP envelopes, UDP packet batching, `testing`, Bash 3.2-compatible benchmark scripts, GitButler, `mise`.

## Global Constraints

- Mixed old and new clients are unsupported; delete the UDP end/ack protocol instead of retaining compatibility code.
- Preserve the existing decision/ack payload barrier and bounded raw-socket handoff drain.
- UDP carries authenticated capacity samples only; DERP carries train boundaries, results, and completion.
- A clean train has non-zero sent count, at least 95 percent received, and no pressure.
- Stop at the first dirty or pressured train while preserving earlier clean trains.
- Seed bulk at 90 percent of the lower peer's highest clean tier, clamped to 128 through 2,400 Mbps.
- Missing or malformed DERP control, cancellation, peer disconnect, encoding failure, and socket cleanup failure are fatal session errors.
- `DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS` is receiver-only, accepts one configured rate, excludes every tenth valid datagram from accounting, and is fatal when empty, unknown, or present on the sender.
- Do not modify payload framing, lane count, grouping, encryption, repair behavior, or steady-state pacing.
- Preserve unrelated uncommitted edits in `pkg/transfertrace/{checker,checker_test,trace,trace_test}.go`; commit only this plan's hunks.

---

## File Map

- Create `pkg/session/external_v2_bulk_probe_control.go`: probe control construction, validation, retry, duplicate handling, and coordinator routing helpers.
- Create `pkg/session/external_v2_bulk_probe_control_test.go`: exact wire-shape, router, retry, duplicate, mismatch, timeout, and disconnect tests.
- Modify `pkg/session/external_v2_bulk_decision.go`: add probe phases/payload and route control events into separate probe and decision streams.
- Modify `pkg/session/external_v2_bulk_decision_test.go`: validate probe phases and prove non-probe phases reject probe data.
- Modify `pkg/session/external_v2_bulk_packet_probe.go`: make sender/receiver probe state machines use DERP coordination and remove UDP end/ack machinery.
- Modify `pkg/session/external_v2_bulk_packet_probe_test.go`: policy, sender, receiver, test-seam, fatal-control, and cleanup coverage.
- Modify `pkg/session/external_v2_bulk_packet.go`: remove UDP probe kinds/channel plumbing and pass the coordinator to both probe roles.
- Modify `pkg/session/external_v2_bulk_packet_test.go`: replace final-UDP-ack fallback coverage with reliable-control and dirty-higher-tier end-to-end cases.
- Modify `pkg/session/external_v2_bulk_packet_batched_receiver_test.go`: retain UDP-loss measurement coverage under DERP boundaries.
- Modify `pkg/session/external_transfer_metrics.go` and `pkg/session/external_transfer_metrics_test.go`: publish stop reason and stable per-train/selected diagnostics.
- Modify `pkg/transfertrace/trace.go`, `pkg/transfertrace/trace_test.go`, `pkg/transfertrace/checker.go`, and `pkg/transfertrace/checker_test.go`: add and validate `bulk_probe_stop_reason` without disturbing the existing reviewer fixes.
- Modify `scripts/promotion-benchmark-driver.sh` and `scripts/promotion_scripts_test.go`: validate, isolate, propagate, and verify the receiver-only dirty-rate environment variable.
- Modify `docs/benchmarks.md`: document the deterministic dirty-tier acceptance command and cleanup rules.

---

### Task 1: Route and validate reliable probe control

**Files:**
- Create: `pkg/session/external_v2_bulk_probe_control.go`
- Create: `pkg/session/external_v2_bulk_probe_control_test.go`
- Modify: `pkg/session/external_v2_bulk_decision.go:19-48,158-218,291-372,417-627,680-769`
- Modify: `pkg/session/external_v2_bulk_decision_test.go:23-73,1101-1248`

**Interfaces:**
- Produces: `externalV2BulkProbeControl`, `externalV2BulkControl.Probe`, `externalV2BulkPhaseProbeEnd`, `externalV2BulkPhaseProbeResult`.
- Produces: `(*externalV2BulkDecisionCoordinator).sendProbeEndAndWaitResult(context.Context, externalV2BulkControl) (externalV2BulkControl, error)`.
- Produces: `(*externalV2BulkDecisionCoordinator).sendProbeResult(context.Context, externalV2BulkControl) error` and `probeControlEvents() <-chan externalV2BulkControlEvent`.
- Preserves: all current readiness, decision, acknowledgement, retry, and responder behavior on the decision event stream.

- [ ] **Step 1: Write failing probe-envelope validation tests**

Add table tests whose valid messages are:

```go
end := externalV2BulkControl{
	Protocol: externalV2Protocol,
	Phase: externalV2BulkPhaseProbeEnd,
	ProbeRunID: 77,
	Mode: externalV2BulkModeBulk,
	Probe: &externalV2BulkProbeControl{
		Train: 2, RateMbps: 1000, Sent: 4377,
	},
}
result := end
result.Phase = externalV2BulkPhaseProbeResult
result.Probe = &externalV2BulkProbeControl{
	Train: 2, RateMbps: 1000, Sent: 4377, Received: 4200, Final: true,
}
```

The table must reject nil probe payloads, probe payloads on `ready`/`decision`/`ack`, zero run ID, wrong train/rate pairing, zero sent, `Received > Sent`, non-zero `Received` on `probe-end`, selected rate/reason on probe phases, impossible `Final`, and contradictory duplicates.

- [ ] **Step 2: Run the validation tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestValidateExternalV2Bulk(ControlProbe|ControlRejectsProbe)' -count=1
```

Expected: compilation fails because the probe phases, payload, and validator do not exist.

- [ ] **Step 3: Add the wire types and exact validation**

Add:

```go
const (
	externalV2BulkPhaseProbeEnd    = "probe-end"
	externalV2BulkPhaseProbeResult = "probe-result"
)

type externalV2BulkProbeControl struct {
	Train     int    `json:"train"`
	RateMbps  int    `json:"rate_mbps"`
	Sent      uint32 `json:"sent"`
	Received  uint32 `json:"received"`
	Pressure  bool   `json:"pressure"`
	Final     bool   `json:"final"`
}
```

Add `Probe *externalV2BulkProbeControl `json:"probe,omitempty"`` to `externalV2BulkControl`. Split validation so probe phases require bulk mode, zero selected rate, empty reason, a non-nil payload, an exact ladder index/rate pair, and phase-specific count/final semantics. Non-probe phases require `Probe == nil` and retain their existing rules.

- [ ] **Step 4: Run the validation tests and verify GREEN**

Run the Step 2 command. Expected: PASS.

- [ ] **Step 5: Write failing router and retry tests**

Use `newExternalV2BulkTestWirePair` to prove:

```go
// Probe traffic must not be consumed by waitForReadiness or decision responders.
// Decision traffic must not be consumed by the probe exchange.
// Dropping the first probe-end causes an identical 250 ms retry.
// An identical duplicate result is ignored idempotently.
// A changed duplicate and a future train are protocol errors.
// A terminal wire event reaches both a blocked probe exchange and decision wait.
```

Set the test coordinator retry to 5 ms and use bounded contexts; compare the complete control value, including the nested payload.

- [ ] **Step 6: Run router tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2Bulk(ProbeControl|DecisionCoordinatorRoutes)' -count=1
```

Expected: FAIL because the coordinator still exposes one shared event stream and has no reliable probe exchange.

- [ ] **Step 7: Implement the coordinator event router and retry exchange**

Give the coordinator separate buffered streams and make one goroutine the sole reader of `wire.Events()`:

```go
type externalV2BulkDecisionCoordinator struct {
	ctx             context.Context
	agreementCtx    context.Context
	cancel          context.CancelCauseFunc
	agreementCancel context.CancelFunc
	wire            externalV2BulkControlWire
	emitter         *telemetry.Emitter
	retry           time.Duration
	readyWait       time.Duration
	closeOnce       sync.Once
	wireCloseOnce   sync.Once
	probeEvents    chan externalV2BulkControlEvent
	decisionEvents chan externalV2BulkControlEvent
}

func (c *externalV2BulkDecisionCoordinator) routeControlEvents() {
	for {
		select {
		case <-c.agreementCtx.Done():
			return
		case event, ok := <-c.wire.Events():
			if !ok || event.Err != nil {
				terminal := externalV2BulkControlEvent{Err: ErrPeerDisconnected}
				if ok && event.Err != nil { terminal.Err = event.Err }
				c.deliverTerminal(terminal)
				return
			}
			target := c.decisionEvents
			if event.Control.Phase == externalV2BulkPhaseProbeEnd || event.Control.Phase == externalV2BulkPhaseProbeResult {
				target = c.probeEvents
			}
			select {
			case target <- event:
			case <-c.agreementCtx.Done(): return
			}
		}
	}
}
```

Replace every current decision-state read from `c.wire.Events()` with `c.decisionEvents`. Add `externalV2BulkControlsEqual(a, b externalV2BulkControl) bool` so nested probe values are compared by content rather than pointer identity, and use it for every duplicate/contradiction check. Implement `sendProbeEndAndWaitResult` with an immediate send, a retry ticker using `c.retry`, an absolute agreement context, exact matching, idempotent prior-result handling, and fatal protocol errors for contradictions or future trains.

- [ ] **Step 8: Run the focused control suite and race detector**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2Bulk(ProbeControl|DecisionCoordinator|Control)' -count=1
mise exec -- go test -race ./pkg/session -run 'TestExternalV2Bulk(ProbeControl|DecisionCoordinatorRoutes)' -count=1
```

Expected: PASS with no race report.

- [ ] **Step 9: Commit Task 1**

Use `but diff`, select only Task 1 file/hunk IDs, and commit to `codex/bulk-probe-decision-barrier` with:

```text
protocol: route reliable bulk probe control
```

---

### Task 2: Replace UDP train completion with reliable sender/receiver state machines

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet_probe.go:23-46,241-249,289-805`
- Modify: `pkg/session/external_v2_bulk_packet_probe_test.go:136-541`
- Modify: `pkg/session/external_v2_bulk_packet.go:59-72,316-397,1747-1815`

**Interfaces:**
- Consumes: Task 1 probe control messages and coordinator probe event stream.
- Produces: `sendExternalV2BulkPacketProbe(context.Context, *externalV2BulkPacketSender, *externalV2BulkDecisionCoordinator)`.
- Produces: `receiveExternalV2BulkPacketProbe(context.Context, externalV2BulkPacketPath, externalV2BulkPacketAuth, uint32, *externalV2BulkDecisionCoordinator)`.
- Produces: ordered identical `externalV2BulkPacketProbeTrainResult` slices on both peers.

- [ ] **Step 1: Write failing sender tests for clean-lower/dirty-higher selection**

Build a fake control pair whose receiver replies with these exact results:

```go
[]externalV2BulkProbeControl{
	{Train: 0, RateMbps: 128, Sent: 560, Received: 560},
	{Train: 1, RateMbps: 512, Sent: 2241, Received: 2241},
	{Train: 2, RateMbps: 1000, Sent: 4377, Received: 3939, Final: true},
}
```

Assert that the sender stops before 1,600 Mbps, returns three trains, selects 460 Mbps, and emits no UDP probe-end packet.

- [ ] **Step 2: Run sender tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestSendExternalV2BulkPacketProbe(RetainsCleanTier|StopsAfterDirtyResult)' -count=1
```

Expected: compilation or assertion failure because sender completion still depends on `probeAckCh` and UDP end frames.

- [ ] **Step 3: Implement sender DERP boundaries**

Change the train function to emit data only and return the actual sent/pressure result. After each train construct:

```go
end := externalV2BulkControl{
	Protocol: externalV2Protocol,
	Phase: externalV2BulkPhaseProbeEnd,
	ProbeRunID: sender.runID,
	Mode: externalV2BulkModeBulk,
	Probe: &externalV2BulkProbeControl{
		Train: trainIndex, RateMbps: rateMbps,
		Sent: train.Sent, Pressure: train.Pressure,
		Final: train.Pressure || trainIndex == len(externalV2BulkPacketProbeRatesMbps)-1,
	},
}
```

Wait through `sendProbeEndAndWaitResult`, append the returned measurement, and stop when `Final` is true. Run the existing selector over all completed results so a dirty final tier does not erase clean earlier tiers.

- [ ] **Step 4: Run sender tests and verify GREEN**

Run the Step 2 command. Expected: PASS.

- [ ] **Step 5: Write failing receiver tests for reliable boundaries and retries**

Feed authenticated UDP data events separately from DERP boundary controls and prove:

```go
// Missing UDP samples lower Received but do not block completion.
// Duplicate sequence numbers count once.
// A repeated identical boundary resends the identical result.
// A contradictory boundary is a protocol error.
// The receiver retries the current result until the next boundary.
// The final result responder remains active while readiness/decision/ack completes.
```

The 128/512/1000 case must return 460 Mbps after a 90-percent 1,000 Mbps tier.

- [ ] **Step 6: Run receiver tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestReceiveExternalV2BulkPacketProbe(ReliableBoundary|RetriesResult|FinalResponder|RetainsCleanTier)' -count=1
```

Expected: FAIL because the receiver waits for UDP end frames and sends UDP acknowledgements.

- [ ] **Step 7: Implement receiver accounting around DERP boundaries**

Keep UDP readers active from before the first train through cleanup. Count authenticated `(runID, train, rate, sequence)` samples. For each ordered `probe-end`, collect queued matching samples, wait 10 ms while still consuming them, then build:

```go
measured := externalV2BulkPacketProbeTrainResult{
	RateMbps: end.Probe.RateMbps,
	Sent: end.Probe.Sent,
	Received: uint32(len(seen)),
	Pressure: end.Probe.Pressure,
}
dirty := measured.Sent == 0 || uint64(measured.Received)*100 < uint64(measured.Sent)*95
result := end
result.Phase = externalV2BulkPhaseProbeResult
result.Probe = &externalV2BulkProbeControl{
	Train: end.Probe.Train, RateMbps: measured.RateMbps,
	Sent: measured.Sent, Received: measured.Received,
	Pressure: measured.Pressure,
	Final: dirty || measured.Pressure || end.Probe.Final,
}
```

Retry the exact result every `c.retry` until the next boundary. Cache completed boundary/result pairs for idempotency. After the final result, keep the responder alive under `agreementCtx`, then stop readers, interrupt them, drain queues, run the selector, and publish readiness through the unchanged decision flow.

- [ ] **Step 8: Delete the legacy UDP control path**

Remove:

```text
externalV2BulkPacketProbeEnd
externalV2BulkPacketProbeAck
externalV2BulkPacketProbeAckFrame
externalV2BulkPacketProbeAckTimeout
externalV2BulkPacketProbeEndRepeats
externalV2BulkPacketProbeAckRepeats
waitExternalV2BulkPacketProbeAck
sendExternalV2BulkPacketProbeAck
probeAckCh and every parameter carrying it
```

Restrict `decodeExternalV2BulkPacketProbeEvent` to authenticated data/tagged-data kinds. Preserve payload hello, repair, done, and receive-ack control handling.

- [ ] **Step 9: Run probe and packet-control tests**

Run:

```bash
mise exec -- go test ./pkg/session -run 'Test(Send|Receive|Select|ExternalV2BulkPacketProbe|ExternalV2BulkPacketControl)' -count=1
mise exec -- go test -race ./pkg/session -run 'Test(SendExternalV2BulkPacketProbe|ReceiveExternalV2BulkPacketProbe)' -count=1
```

Expected: PASS; `rg 'ProbeAck|ProbeEnd|probeAckCh' pkg/session` finds only DERP phase names and test descriptions, not UDP kinds or channels.

- [ ] **Step 10: Commit Task 2**

Commit only Task 2 changes with:

```text
protocol: coordinate bulk capacity probes over DERP
```

---

### Task 3: Add deterministic receiver dirty-tier injection and diagnostics

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet_probe.go:23-115,259-287,562-643`
- Modify: `pkg/session/external_v2_bulk_packet_probe_test.go`
- Modify: `pkg/session/external_v2.go:380-405`
- Modify: `pkg/session/external_transfer_metrics.go:200-250,1070-1095,1168-1240`
- Modify: `pkg/session/external_transfer_metrics_test.go:1460-1540`
- Modify: `pkg/transfertrace/trace.go:160-190,280-320,580-700`
- Modify: `pkg/transfertrace/trace_test.go:200-325`
- Modify: `pkg/transfertrace/checker.go:440-475,560-610,850-890`
- Modify: `pkg/transfertrace/checker_test.go:660-850,1060-1160`

**Interfaces:**
- Produces: `DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS` parsing and receiver-only application.
- Produces: stop reasons `dirty`, `pressure`, and `ladder-complete`.
- Produces: verbose marker families `v2-bulk-probe-result=` and `v2-bulk-probe-selected=`.
- Produces: trace column `bulk_probe_stop_reason`.

- [ ] **Step 1: Write failing environment-seam tests**

Test unset, empty, non-numeric, unknown rate, sender presence, and valid receiver rate. For a valid 1,000 Mbps setting, feed sequence numbers 0 through 99 and assert 90 are counted while all 100 are consumed.

- [ ] **Step 2: Run the seam tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacketProbeDirtyRate' -count=1
```

Expected: FAIL because the environment parser and receiver accounting filter do not exist.

- [ ] **Step 3: Implement strict receiver-only injection**

Add:

```go
const externalV2BulkPacketProbeDirtyRateEnv = "DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS"

type externalV2BulkPacketProbeDirtyRateError struct { value, role string }
```

Parse once before payload/probe activity. Reject presence on the sender. On the receiver, require an exact decimal member of `externalV2BulkPacketProbeRatesMbps`. During accounting, exclude `sequence%10 == 0` only at that configured rate and emit exactly one marker:

```text
v2-bulk-probe-test-dirty-rate-mbps=1000
```

- [ ] **Step 4: Run seam tests and verify GREEN**

Run the Step 2 command. Expected: PASS.

- [ ] **Step 5: Write failing diagnostics and trace tests**

Assert exact markers:

```text
v2-bulk-probe-result=train:2 rate_mbps:1000 sent:4377 received:3939 pressure:false final:true
v2-bulk-probe-selected=selected_mbps:460 highest_clean_mbps:512 trains:3
```

Assert `bulk_probe_stop_reason=dirty` is present in the CSV snapshot and that the checker allows only `dirty`, `pressure`, or `ladder-complete` when bulk probe diagnostics exist.

- [ ] **Step 6: Run diagnostics tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session ./pkg/transfertrace -run 'Test.*BulkProbe.*(Diagnostics|StopReason|Marker)' -count=1
```

Expected: FAIL because stop reason and stable result/selection markers are absent.

- [ ] **Step 7: Implement diagnostics without overwriting unrelated edits**

Add `StopReason` to `externalV2BulkPacketProbeResult`, derive it exactly where probing stops, and thread `BulkProbeStopReason` through session metrics and transfertrace snapshots. Add the CSV column adjacent to other probe fields. Update checker validation while retaining all current uncommitted reviewer-fix hunks in the same files.

- [ ] **Step 8: Run diagnostics tests and verify GREEN**

Run the Step 6 command. Expected: PASS.

- [ ] **Step 9: Commit Task 3 selectively**

Run `but diff`, identify only this task's hunks in the four already-dirty transfertrace files, and commit those plus the clean Task 3 files with:

```text
telemetry: report reliable bulk probe outcomes
```

Leave the preexisting reviewer hunks uncommitted.

---

### Task 4: Prove transport behavior end to end and wire the benchmark seam

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet_test.go:1900-2040,3020-3155`
- Modify: `pkg/session/external_v2_bulk_packet_batched_receiver_test.go:450-590`
- Modify: `pkg/session/external_v2_block_test.go:760-930`
- Modify: `scripts/promotion-benchmark-driver.sh:19-60,220-260` and all file workload launch sites
- Modify: `scripts/promotion_scripts_test.go:250-320,560-850,2320-2445`
- Modify: `docs/benchmarks.md:60-115,410-470`

**Interfaces:**
- Consumes: reliable probe controls and receiver dirty-rate environment seam.
- Produces: deterministic 128/512-clean then 1,000-dirty bulk selection at 460 Mbps.
- Produces: benchmark propagation to the receiver process only in both forward and reverse directions.

- [ ] **Step 1: Replace the obsolete final-UDP-ack test with failing reliable-control cases**

Delete `dropFinalBulkProbeAckConn` and its QUIC expectation. Add end-to-end cases that:

```go
// Drop UDP data at the 1,000 Mbps tier but keep DERP control intact.
// Require both peers to decide bulk at 460 Mbps.
// Verify payload bytes and SHA-256 parity.
// Verify zero payload bytes before decision acknowledgement.
// Verify first-tier dirty data negotiates QUIC and leaves bulk sink empty.
// Verify a closed control wire aborts both peers instead of selecting QUIC.
```

- [ ] **Step 2: Run end-to-end tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(ReliableProbe|DirtyHigherTier|DirtyFirstTier|ProbeControlFailure)' -count=1
```

Expected: FAIL before all end-to-end semantics are connected.

- [ ] **Step 3: Complete call-site wiring and make end-to-end tests GREEN**

Pass the existing coordinator into both probe roles. Ensure the receiver subscribes before UDP traffic, the sender never advances payload counters before decision ack, bulk replaces probe batch conns only after the decision, and QUIC fallback occurs only after receiver/sender handoff drains complete.

Run the Step 2 command. Expected: PASS.

- [ ] **Step 4: Write failing benchmark-driver tests**

Cover:

```text
unset: neither endpoint receives DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS
empty/non-numeric/unknown: driver exits 2
forward: only remote receiver receives the value
reverse: only local receiver receives the value
sender contamination: test fails
configured run: exactly one receiver marker is required
```

Run:

```bash
mise exec -- go test ./scripts -run 'TestPromotionBenchmark.*BulkProbeDirtyRate' -count=1
```

Expected: FAIL because the driver does not recognize or isolate the variable.

- [ ] **Step 5: Implement Bash 3.2-compatible receiver-only propagation**

Validate before unsetting the ambient variable:

```bash
bulk_probe_dirty_rate="${DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS-}"
bulk_probe_dirty_rate_configured=false
if [[ "${DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS+x}" == x ]]; then
  bulk_probe_dirty_rate_configured=true
  if [[ ! "${bulk_probe_dirty_rate}" =~ ^(128|512|1000|1600|2000|2200|2400)$ ]]; then
    echo "DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS must be one configured probe rate" >&2
    exit 2
  fi
fi
unset DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS
```

Build local-array and remote-prefix receiver environments separately from the existing sender-only outcome seam. Require one receiver marker and no sender marker.

- [ ] **Step 6: Run script tests and system Bash syntax checks**

Run:

```bash
mise exec -- go test ./scripts -run 'TestPromotionBenchmark.*(BulkProbeDirtyRate|SystemBash)' -count=1
/bin/bash -n scripts/promotion-benchmark-driver.sh
```

Expected: PASS.

- [ ] **Step 7: Document the acceptance invocation and cleanup contract**

Add one example using:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS=1000 \
DERPHOLE_BENCH_EXPECT_TRANSFER_MODE=bulk-packets-v1 \
./scripts/promotion-test.sh "$REMOTE_HOST" 1024
```

State that the harness injects the variable into the receiver only, a successful run must select 460 Mbps after the dirty tier, remote storage must be preflighted outside `/tmp` when necessary, and all task-owned payload/build/staging paths must be removed.

- [ ] **Step 8: Run package tests, race tests, and fast build gate**

Run:

```bash
mise exec -- go test ./pkg/session ./pkg/transfertrace ./scripts -count=1
mise exec -- go test -race ./pkg/session -run 'TestExternalV2Bulk(Packet|Decision|Probe)' -count=1
mise run check:fast
```

Expected: PASS.

- [ ] **Step 9: Commit Task 4**

Commit only Task 4 changes with:

```text
test: cover reliable bulk probe selection
```

---

### Task 5: Final repository and live acceptance

**Files:**
- Verification only; edit production files only in response to a newly reproduced failing test.

**Interfaces:**
- Consumes: the frozen candidate commit stack and npm release `v0.17.0`.
- Produces: correctness, trace, resource, cleanup, and paired performance evidence.

- [ ] **Step 1: Check branch synchronization before the final gate**

Run:

```bash
but pull --check
```

If clean and limited to this branch, run `but pull`; if it overlaps another active branch, stop and report the overlap.

- [ ] **Step 2: Run the exhaustive repository gate once on the stable stack**

Run:

```bash
mise run check
```

Expected: PASS. If hooks modify tracked files, absorb only this session's changes into their owning unpublished commit and rerun `mise run check`.

- [ ] **Step 3: Freeze exact release and candidate binaries**

Record candidate commit SHA, release version `v0.17.0`, binary hashes, direction, remote host, payload hash, lane count, and test environment. Preflight the remote output filesystem for the 1 GiB payload plus working overhead; do not assume `/tmp` is large enough.

- [ ] **Step 4: Run one deterministic dirty-tier candidate transfer**

Set `DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS=1000` on the receiver through the harness. Require eight-lane public raw-direct, initial bulk policy, clean 128/512 results, dirty 1,000 result, 460 Mbps selection on both peers, exact decision/ack, `bulk-packets-v1`, exact size/hash parity, valid traces, and no leak.

- [ ] **Step 5: Run three ordinary candidate transfers**

Unset the dirty-rate seam. All three 1 GiB runs must select `bulk-packets-v1`, complete with exact parity, and pass trace/process/socket/output/cleanup checks.

- [ ] **Step 6: Run three adjacent interleaved release/candidate pairs**

Use the same payload, direction, lane count, binaries, and path-capacity controls. Stop as inconclusive if any paired capacity control differs by more than 15 percent; do not start an unbounded retry loop.

- [ ] **Step 7: Evaluate performance gates**

Require candidate median canonical goodput at least 95 percent of release, candidate median repair-byte ratio at most 110 percent of release, and candidate receiver CPU/GiB at most 110 percent of release.

- [ ] **Step 8: Clean task-owned artifacts**

Remove exact local payload/build/staging paths and exact remote output/staging paths. Verify those targets are absent while preserving all unrelated `/tmp`, home, repository, and user data.

- [ ] **Step 9: Report landed state accurately**

Report local uncommitted reviewer edits separately from session commits, branch publication, and `origin/main`. Do not push or land because the user has not requested publication.
