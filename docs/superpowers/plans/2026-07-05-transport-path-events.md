# Rich Transport Path Events Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add richer path events and snapshots to `pkg/transport.Manager` without breaking the existing `Updates(ctx)` path-only API.

**Architecture:** Keep `Updates(ctx) <-chan Update` compatible and path-deduped. Add a separate observability surface for current snapshots and event history: `PathSnapshot()`, `PathSnapshots(ctx)`, and `PathEvents(ctx)`. Transport owns event creation because it already serializes path state; session metrics consume the richer data without changing transfer trace schema in this branch.

**Tech Stack:** Go, `pkg/transport`, existing fake-clock/fake-packet tests, `pkg/session` metrics, `mise`, GitButler.

---

## Branch

Use GitButler branch `codex/transport-path-events`.

Run before editing:

```bash
but status -fv
but pull --check
mise run install-githooks
```

Expected: no active branch owns `pkg/transport/manager.go`, `pkg/transport/state.go`, `pkg/transport/disco.go`, `pkg/transport/control.go`, `pkg/session/external_path_metrics.go`, or `pkg/session/external_transfer_metrics.go`.

Use `but diff` before each checkpoint commit, then commit only this task's file or hunk IDs with branch-specific commands. If `codex/transport-path-events` does not exist yet, create it with the first checkpoint command:

```bash
but commit codex/transport-path-events -c -m "transport: add path snapshots" --changes <ids from but diff>
```

For later checkpoints, omit `-c`:

```bash
but commit codex/transport-path-events -m "<checkpoint message>" --changes <ids from but diff>
```

## File Structure

- Create `pkg/transport/path_events.go`: exported `PathSnapshot`, `PathCandidateSnapshot`, `PathEvent`, event type, reason, source constants, bounded log helpers.
- Modify `pkg/transport/state.go`: snapshot extraction with cloned addresses, selected RTT, candidates, pending probe markers, upgrade/fallback counts.
- Modify `pkg/transport/manager.go`: path event log, `PathSnapshot`, `PathSnapshots`, `PathEvents`, nonblocking fan-out, lag handling.
- Modify `pkg/transport/disco.go`: emit probe sent, probe failed, probe succeeded/selected events.
- Modify `pkg/transport/control.go`: annotate candidate events by source (`seed`, `remote-control`) and reason.
- Modify `pkg/transport/manager_test.go`: event, snapshot, fallback, probe, lag, and `Updates(ctx)` compatibility tests.
- Modify `pkg/session/external_path_metrics.go`: consume richer events for direct validation.
- Modify `pkg/session/external_transfer_metrics.go` and `pkg/session/external_transfer_metrics_test.go`: record latest transport path metadata internally.

## Task 1: Snapshots

**Files:**
- Create: `pkg/transport/path_events.go`
- Modify: `pkg/transport/state.go`
- Modify: `pkg/transport/manager.go`
- Test: `pkg/transport/manager_test.go`

- [ ] **Step 1: Write the failing snapshot test**

Add `TestManagerPathSnapshotIncludesSelectedAddrRTTAndCandidates` in `pkg/transport/manager_test.go`. Set up a manager with relay and direct, seed two remote candidates, send and consume a direct probe, promote direct, then assert:

```go
snapshot := mgr.PathSnapshot()
if snapshot.Path != PathDirect {
	t.Fatalf("snapshot.Path = %v, want %v", snapshot.Path, PathDirect)
}
if snapshot.SelectedAddr.String() != selected.String() {
	t.Fatalf("snapshot.SelectedAddr = %v, want %v", snapshot.SelectedAddr, selected)
}
if snapshot.SelectedRTT != 42*time.Millisecond {
	t.Fatalf("snapshot.SelectedRTT = %v, want %v", snapshot.SelectedRTT, 42*time.Millisecond)
}
if len(snapshot.Candidates) != 2 {
	t.Fatalf("len(snapshot.Candidates) = %d, want 2", len(snapshot.Candidates))
}
```

Also assert the selected candidate is marked `Selected`, has the measured RTT, and is not probe-pending.

- [ ] **Step 2: Verify red**

Run:

```bash
mise exec -- go test ./pkg/transport -run TestManagerPathSnapshotIncludesSelectedAddrRTTAndCandidates -count=1
```

Expected: FAIL to compile because `PathSnapshot`, `PathCandidateSnapshot`, and `Manager.PathSnapshot` do not exist.

- [ ] **Step 3: Add snapshot types**

Create `pkg/transport/path_events.go` with exported snapshot and event types. Required public shape:

```go
type PathEventType string
type PathEventReason string
type PathEventSource string

type PathCandidateSnapshot struct {
	Addr net.Addr
	RTT time.Duration
	Selected bool
	ProbePending bool
	ProbeSentAt time.Time
}

type PathSnapshot struct {
	At time.Time
	Path Path
	SelectedAddr net.Addr
	SelectedRTT time.Duration
	Candidates []PathCandidateSnapshot
	Upgrades int
	Fallbacks int
}
```

Define event types for `candidates-changed`, `probe-sent`, `probe-failed`, `probe-succeeded`, `selected`, `fallback`, and `lagged`.

- [ ] **Step 4: Implement snapshot extraction**

Add `func (s pathState) snapshot(now time.Time) PathSnapshot` in `pkg/transport/state.go`. It must clone `net.Addr` values, sort candidates by address string, mark selected and pending probes, and use `endpointLatency[bestEndpoint]` for selected RTT.

- [ ] **Step 5: Add manager API**

Add:

```go
func (m *Manager) PathSnapshot() PathSnapshot {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.snapshot(now)
}
```

- [ ] **Step 6: Verify green and checkpoint**

Run:

```bash
mise exec -- go test ./pkg/transport -run TestManagerPathSnapshotIncludesSelectedAddrRTTAndCandidates -count=1
but status -fv
but diff
but commit codex/transport-path-events -c -m "transport: add path snapshots" --changes <ids from but diff>
```

Expected: PASS, and the checkpoint contains only snapshot types/tests and snapshot API changes.

## Task 2: Event Streams

**Files:**
- Modify: `pkg/transport/path_events.go`
- Modify: `pkg/transport/manager.go`
- Test: `pkg/transport/manager_test.go`

- [ ] **Step 1: Write failing event tests**

Add:

```go
func TestManagerPathEventsReportCandidateProbeAndSelection(t *testing.T)
func TestManagerPathEventsReportFallbackWithPreviousAddr(t *testing.T)
```

The first test must subscribe to `mgr.PathEvents(ctx)`, seed a candidate, observe `PathEventCandidatesChanged`, send a probe, observe `PathEventProbeSent`, promote direct, and observe `PathEventSelected` with previous path `PathRelay`, selected direct address, reason `probe-ack`, source `direct-probe`, and measured RTT.

The second test must promote direct, call `MarkDirectBroken`, and observe `PathEventFallback` with previous path `PathDirect`, path `PathRelay`, previous direct addr, nil selected addr, reason `direct-broken`, source `manual`.

- [ ] **Step 2: Verify red**

Run:

```bash
mise exec -- go test ./pkg/transport -run 'TestManagerPathEventsReportCandidateProbeAndSelection|TestManagerPathEventsReportFallbackWithPreviousAddr' -count=1
```

Expected: FAIL to compile because `PathEvents` and event log helpers do not exist.

- [ ] **Step 3: Implement bounded event log**

Add manager fields:

```go
pathNotify chan struct{}
pathEventSeq uint64
pathEvents []sequencedPathEvent
```

Initialize `pathNotify` in `NewManager`. Add locked helpers to append events, cap the log at 256 entries, clone event addresses through snapshots, return events since a cursor, and signal subscribers by closing/replacing `pathNotify`.

- [ ] **Step 4: Add stream APIs**

Add:

```go
func (m *Manager) PathEvents(ctx context.Context) <-chan PathEvent
func (m *Manager) PathSnapshots(ctx context.Context) <-chan PathSnapshot
```

`PathEvents` must not hold `m.mu` while sending. If a subscriber falls behind the bounded log, emit `PathEventLagged` with the current snapshot. `PathSnapshots` emits the initial snapshot, then deduped snapshots after path-event notifications.

- [ ] **Step 5: Verify green and checkpoint**

Run:

```bash
mise exec -- go test ./pkg/transport -run 'TestManagerPathEventsReportCandidateProbeAndSelection|TestManagerPathEventsReportFallbackWithPreviousAddr' -count=1
but status -fv
but diff
but commit codex/transport-path-events -m "transport: publish path events" --changes <ids from but diff>
```

Expected: PASS.

## Task 3: Reasons And Sources

**Files:**
- Modify: `pkg/transport/manager.go`
- Modify: `pkg/transport/disco.go`
- Modify: `pkg/transport/control.go`
- Modify: `pkg/transport/state.go`
- Test: `pkg/transport/manager_test.go`

- [ ] **Step 1: Write failing reason/source test**

Add `TestManagerPathEventsReportProbeFailureAndStaleFallback`. It must verify:

- probe write failure emits `probe-failed` with target addr, reason `probe-write-failed`, source `discovery`
- stale direct demotion emits `fallback` with reason `direct-stale`, source `stale-check`, and previous direct addr

- [ ] **Step 2: Verify red**

Run:

```bash
mise exec -- go test ./pkg/transport -run TestManagerPathEventsReportProbeFailureAndStaleFallback -count=1
```

Expected: FAIL because existing mutation paths do not annotate events.

- [ ] **Step 3: Thread candidate sources**

Change `applyRemoteCandidates` to accept a `PathEventSource`. Use `seed` for `SeedRemoteCandidates` and `remote-control` for control messages. Emit `candidates-changed` on candidate map changes. If candidate loss causes fallback, emit fallback with reason `candidate-lost`.

- [ ] **Step 4: Thread fallback reasons**

Change relay demotion helpers to carry reason/source. Use:

- `MarkDirectBroken`: `direct-broken` / `manual`
- `StopDirect`: `stop-direct` / `stop-direct`
- stale demotion from `DirectPath`, `DirectAddr`, `DirectPacketConn`: `direct-stale` / `stale-check`

- [ ] **Step 5: Emit probe lifecycle**

Emit:

- `probe-sent` from `noteProbeSentIfCurrent`
- `probe-failed` from `noteProbeFailedIfCurrent`
- `selected` from `tryPromoteDirect` when path or selected addr changes
- `probe-succeeded` when ACK is valid but selector keeps the existing selected path

- [ ] **Step 6: Verify and flake guard**

Run:

```bash
mise exec -- go test ./pkg/transport -run 'TestManagerPathEventsReport|TestManagerFallsBackToRelayAndRetriesDiscovery|TestManagerDemotesStaleDirectPathWhenReadForSend|TestManagerKeepsActiveDirectPathWhenCandidateSetReplacesEndpoint' -count=1
mise exec -- go test ./pkg/transport -run TestManagerPromotesDirectWithMACBoundAck -count=100
but status -fv
but diff
but commit codex/transport-path-events -m "transport: annotate path event reasons" --changes <ids from but diff>
```

Expected: all PASS.

## Task 4: Preserve `Updates(ctx)`

**Files:**
- Modify: `pkg/transport/manager.go`
- Test: `pkg/transport/manager_test.go`

- [ ] **Step 1: Write compatibility test**

Add `TestManagerUpdatesIgnoreCandidateAndProbeOnlyEvents`. It must subscribe to `Updates(ctx)`, observe the initial relay update, then cause candidate/probe events and assert no `Update` arrives until direct promotion changes `Path`.

- [ ] **Step 2: Verify**

Run:

```bash
mise exec -- go test ./pkg/transport -run TestManagerUpdatesIgnoreCandidateAndProbeOnlyEvents -count=1
rg -n "Updates\\(|Update\\{" --glob '!dist/**' --glob '!node_modules/**' .
```

Expected: test PASS; existing call sites still compile with `Update{Path: PathRelay}` and `update.Path`.

- [ ] **Step 3: Checkpoint**

Run:

```bash
mise exec -- go test ./pkg/transport -count=1
but status -fv
but diff
but commit codex/transport-path-events -m "transport: keep path updates compatible" --changes <ids from but diff>
```

Expected: PASS.

## Task 5: Session Metrics Bridge

**Files:**
- Modify: `pkg/session/external_path_metrics.go`
- Modify: `pkg/session/external_transfer_metrics.go`
- Test: `pkg/session/external_transfer_metrics_test.go`

- [ ] **Step 1: Write failing metrics test**

Add `TestExternalTransferMetricsRecordsTransportPathEvents`. It must call `metrics.RecordTransportPathEvent` with a selected direct event and assert direct validation plus stored path, selected addr, previous addr, reason, source, and RTT milliseconds. Then record fallback and assert `fallbackReason` and path are relay.

- [ ] **Step 2: Verify red**

Run:

```bash
mise exec -- go test ./pkg/session -run TestExternalTransferMetricsRecordsTransportPathEvents -count=1
```

Expected: FAIL to compile because metrics methods/fields do not exist.

- [ ] **Step 3: Add internal metric fields and methods**

Add internal fields for latest transport path, selected addr, previous addr, reason, source, RTT ms. Add:

```go
func (m *externalTransferMetrics) RecordTransportPathEvent(event transport.PathEvent)
func (m *externalTransferMetrics) RecordTransportPathSnapshot(snapshot transport.PathSnapshot)
```

Selected direct events should behave like current `MarkDirectValidated`. Fallback events with a reason should set `fallbackReason`.

- [ ] **Step 4: Update watcher**

Update `watchExternalDirectPath` to record the initial `PathSnapshot`, consume `PathEvents(ctx)`, record each event, and return when it sees selected direct.

- [ ] **Step 5: Verify and checkpoint**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalTransferMetricsRecordsTransportPathEvents|TestExternalTransferMetricsDirectValidationMovesTraceToDirect' -count=1
mise exec -- go test ./pkg/session -run 'ExternalTransferMetrics|WatchExternalDirectPath' -count=1
but status -fv
but diff
but commit codex/transport-path-events -m "session: record transport path events" --changes <ids from but diff>
```

Expected: PASS.

## Final Verification

Run:

```bash
mise exec -- go test ./pkg/transport -run 'TestManagerPath|TestManagerUpdates|TestManagerPromotesDirectWithMACBoundAck|TestPathState' -count=1
mise exec -- go test ./pkg/session -run 'ExternalTransferMetrics' -count=1
mise exec -- go test ./pkg/transport -run TestManagerPromotesDirectWithMACBoundAck -count=100
mise run test
mise run check
but status -fv
```

Expected: all tests/checks PASS, no `dist/` edits, only `codex/transport-path-events` contains this branch's changes.

## Acceptance Criteria

- Existing `Updates(ctx)` API remains compatible.
- Candidate-only and probe-only changes do not emit path-only updates.
- Snapshots include current path, selected addr, selected RTT, candidates, pending probes, upgrades, and fallbacks.
- Events include candidate, probe, selected, fallback, and lagged states with reason/source/RTT where available.
- Slow event subscribers cannot block manager state mutation.
- Session metrics consume events internally without changing public CLI output or transfer trace CSV schema.

## Self-Review Notes

- Spec coverage: snapshots, event streams, reasons/sources, compatibility, and metrics bridge are each mapped to tasks.
- Red-flag scan: clean for unresolved markers, ellipses, and incomplete implementation steps.
- Type consistency: `PathSnapshot`, `PathCandidateSnapshot`, `PathEvent`, event type/reason/source constants are introduced before use.
