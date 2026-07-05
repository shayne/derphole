# Transport Candidate Lifecycle Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded candidate lifecycle tracking in `pkg/transport` so direct discovery avoids repeatedly probing bad endpoints while preserving healthy active direct paths.

**Architecture:** Keep `Manager` and `pathState` as the relay/direct authority, but split candidate bookkeeping into a private helper file modeled after iroh path states: pending, open, inactive, unusable. `pathState.endpoints` remains the selectable address map; lifecycle tracks status, timestamps, suppression, and pruning.

**Tech Stack:** Go, `pkg/transport`, `pkg/candidate` constants, existing fake-clock/fake-packet tests, `mise`, GitButler.

---

## Branch

Use GitButler branch `codex/transport-candidate-lifecycle`.

Stack this branch after `codex/transport-path-selector-hysteresis` if the transport stack is applied.

Run before editing:

```bash
but status -fv
but pull --check
but branch new codex/transport-candidate-lifecycle
```

Expected: no active unrelated branch owns `pkg/transport/state.go`, `pkg/transport/disco.go`, `pkg/transport/manager.go`, `pkg/transport/peer.go`, `pkg/transport/state_test.go`, or `pkg/transport/manager_test.go`.

## File Structure

- Create `pkg/transport/candidate_state.go`: private statuses, lifecycle struct, constants, suppression, pruning.
- Modify `pkg/transport/state.go`: lifecycle map, candidate merge, probe target filtering, probe send/fail/consume updates, open/inactive transitions.
- Modify `pkg/transport/manager.go`: pass probe timeout into planning, suppress failed probe/write candidates.
- Modify `pkg/transport/disco.go`: call lifecycle-aware probe failure hook.
- Modify `pkg/transport/peer.go`: suppress failed direct endpoint when falling back to relay after data write failure.
- Modify `pkg/transport/state_test.go`: lifecycle/suppression/pruning tests.
- Modify `pkg/transport/manager_test.go`: manager suppression and MAC-bound regression tests.

## Constants

Use private constants:

```go
const (
	maxTrackedNonRelayCandidates = maxControlCandidates
	maxInactiveNonRelayCandidates = 10
	defaultCandidateSuppressPeriod = 5 * time.Second
)
```

The active direct endpoint may be retained in addition to the non-active cap.

## Task 1: Lifecycle Types

**Files:**
- Create: `pkg/transport/candidate_state.go`
- Modify: `pkg/transport/state.go`
- Test: `pkg/transport/state_test.go`

- [ ] **Step 1: Write failing tests**

Add:

```go
func TestCandidateStatusString(t *testing.T)
func TestPathStateInitializesCandidateLifecycle(t *testing.T)
```

`TestCandidateStatusString` must assert `pending`, `open`, `inactive`, `unusable`, and unknown fallback. `TestPathStateInitializesCandidateLifecycle` must assert `newPathState(time.Now(), true, true).candidateLifecycle != nil`.

- [ ] **Step 2: Verify red**

Run:

```bash
go test ./pkg/transport -run 'TestCandidateStatusString|TestPathStateInitializesCandidateLifecycle' -count=1
```

Expected: FAIL to compile because lifecycle types do not exist.

- [ ] **Step 3: Add types**

Create `candidate_state.go`:

```go
type candidateStatus uint8

const (
	candidatePending candidateStatus = iota
	candidateOpen
	candidateInactive
	candidateUnusable
)

type directCandidateState struct {
	addr net.Addr
	status candidateStatus
	firstSeenAt time.Time
	lastSeenAt time.Time
	lastProbeAt time.Time
	lastOpenedAt time.Time
	lastClosedAt time.Time
	suppressUntil time.Time
}
```

Add `String()`, `newDirectCandidateState`, and `suppressed(now)`.

- [ ] **Step 4: Initialize map**

Add `candidateLifecycle map[string]directCandidateState` to `pathState` and initialize it in `newPathState`.

- [ ] **Step 5: Verify and checkpoint**

Run:

```bash
gofmt -w pkg/transport/candidate_state.go pkg/transport/state.go pkg/transport/state_test.go
go test ./pkg/transport -run 'TestCandidateStatusString|TestPathStateInitializesCandidateLifecycle' -count=1
but status -fv
but commit -m "transport: add candidate lifecycle state"
```

Expected: PASS.

## Task 2: Pending/Open/Inactive

**Files:**
- Modify: `pkg/transport/state.go`
- Test: `pkg/transport/state_test.go`

- [ ] **Step 1: Write failing transition tests**

Add:

```go
func TestPathStateTracksCandidateLifecycleTransitions(t *testing.T)
func TestPathStateKeepsOpenCandidateAcrossReplacement(t *testing.T)
```

The first test seeds public and CGNAT candidates, promotes public, then promotes CGNAT and asserts public becomes inactive and CGNAT open. The second promotes an active endpoint, replaces candidate controls with a new endpoint, and asserts the active direct endpoint remains tracked and open.

- [ ] **Step 2: Verify red**

Run:

```bash
go test ./pkg/transport -run 'TestPathStateTracksCandidateLifecycleTransitions|TestPathStateKeepsOpenCandidateAcrossReplacement' -count=1
```

Expected: FAIL because statuses are not updated.

- [ ] **Step 3: Merge candidate lifecycle**

Update `noteCandidates` to call `noteCandidateSeen` for each candidate, preserve the active direct endpoint if missing from the new set, and call `pruneEndpointState(now)`.

Add helpers:

```go
func (s *pathState) noteCandidateSeen(now time.Time, key string, addr net.Addr)
func (s *pathState) markCandidateOpen(now time.Time, key string, addr net.Addr)
func (s *pathState) markCandidateInactive(now time.Time, key string)
```

Update `noteDirect` so the selected endpoint becomes open and the previous selected endpoint becomes inactive.

- [ ] **Step 4: Add temporary pruning hook**

Change `pruneEndpointState` to accept `now time.Time`, prune missing pending/latency entries, and call `pruneTrackedCandidates(now)`. Add a temporary no-op `pruneTrackedCandidates` in `candidate_state.go`.

- [ ] **Step 5: Verify and checkpoint**

Run:

```bash
gofmt -w pkg/transport/state.go pkg/transport/candidate_state.go pkg/transport/state_test.go
go test ./pkg/transport -run 'TestPathStateTracksCandidateLifecycleTransitions|TestPathStateKeepsOpenCandidateAcrossReplacement|TestPathStateKeepsPrivateEndpointWhenPublicProbeArrivesSlightlyLater|TestPathStatePrefersCGNATEndpointOverPublicEndpointWhenLatencyIsClose' -count=1
but status -fv
but commit -m "transport: track candidate lifecycle transitions"
```

Expected: PASS.

## Task 3: Suppression

**Files:**
- Modify: `pkg/transport/state.go`
- Modify: `pkg/transport/manager.go`
- Modify: `pkg/transport/disco.go`
- Test: `pkg/transport/state_test.go`

- [ ] **Step 1: Write failing suppression tests**

Add:

```go
func TestPathStateSuppressesFailedProbeTargetsBriefly(t *testing.T)
func TestPathStateExpiresPendingProbeAsUnusable(t *testing.T)
```

The first test must assert a failed probe suppresses the candidate for 5s and then allows retry. The second must assert an expired pending probe becomes unusable and is skipped immediately after expiry.

- [ ] **Step 2: Verify red**

Run:

```bash
go test ./pkg/transport -run 'TestPathStateSuppressesFailedProbeTargetsBriefly|TestPathStateExpiresPendingProbeAsUnusable' -count=1
```

Expected: FAIL because suppression APIs and timeout-aware discovery planning do not exist.

- [ ] **Step 3: Make discovery planning timeout-aware**

Change `pathState.discoveryPlan` to accept `probeTimeout time.Duration`, expire pending probes before building the plan, and call `probeTargets(now)`. `probeTargets` must skip entries with outstanding pending probes and suppressed lifecycle state.

- [ ] **Step 4: Add failure/expiry methods**

Add:

```go
func (s *pathState) noteProbeFailed(now time.Time, addr net.Addr, token directProbeToken, suppressFor time.Duration)
func (s *pathState) expirePendingProbes(now time.Time, maxAge, suppressFor time.Duration)
func (s *pathState) markCandidateUnusable(now time.Time, key string, suppressFor time.Duration)
```

Update `noteProbeSent` to mark lifecycle pending and `lastProbeAt`.

- [ ] **Step 5: Wire manager/discovery**

Update `snapshotDiscoveryPlan` to pass `m.discoveryInterval()` as probe timeout. Update `noteProbeFailedIfCurrent` to accept `now`, then call `state.noteProbeFailed`. Update `sendDirectProbes` write-failure path accordingly.

- [ ] **Step 6: Verify and checkpoint**

Run:

```bash
gofmt -w pkg/transport/state.go pkg/transport/manager.go pkg/transport/disco.go pkg/transport/state_test.go
go test ./pkg/transport -run 'TestPathStateSuppressesFailedProbeTargetsBriefly|TestPathStateExpiresPendingProbeAsUnusable|TestManagerIgnoresAckWithoutOutstandingProbe' -count=1
but status -fv
but commit -m "transport: suppress failed direct candidates"
```

Expected: PASS.

## Task 4: Pruning

**Files:**
- Modify: `pkg/transport/candidate_state.go`
- Test: `pkg/transport/state_test.go`

- [ ] **Step 1: Write failing pruning tests**

Add:

```go
func TestPathStatePrunesUnusableBeforePendingAndKeepsActiveDirect(t *testing.T)
func TestPathStatePruneKeepsRecentInactiveCandidates(t *testing.T)
```

The first test must create more than `maxTrackedNonRelayCandidates` non-active candidates and assert the active direct endpoint remains. The second must assert inactive lifecycle entries are capped at `maxInactiveNonRelayCandidates`.

- [ ] **Step 2: Verify red**

Run:

```bash
go test ./pkg/transport -run 'TestPathStatePrunesUnusableBeforePendingAndKeepsActiveDirect|TestPathStatePruneKeepsRecentInactiveCandidates' -count=1
```

Expected: FAIL because pruning is still no-op.

- [ ] **Step 3: Implement pruning**

Replace the temporary helper with deterministic pruning:

- keep active direct key
- remove unusable first
- keep only the newest 10 inactive candidates
- remove oldest pending entries last
- delete matching `endpoints`, `endpointLatency`, `pendingProbes`, and `candidateLifecycle`

Use stable sorting by lifecycle timestamps so tests do not flake.

- [ ] **Step 4: Verify and checkpoint**

Run:

```bash
gofmt -w pkg/transport/candidate_state.go pkg/transport/state_test.go
go test ./pkg/transport -run 'TestPathStatePrunesUnusableBeforePendingAndKeepsActiveDirect|TestPathStatePruneKeepsRecentInactiveCandidates|TestPathStateKeepsOpenCandidateAcrossReplacement' -count=1
but status -fv
but commit -m "transport: cap tracked direct candidates"
```

Expected: PASS.

## Task 5: Manager Integration

**Files:**
- Modify: `pkg/transport/manager.go`
- Modify: `pkg/transport/peer.go`
- Test: `pkg/transport/manager_test.go`

- [ ] **Step 1: Write failing manager tests**

Add:

```go
func TestManagerSuppressesRepeatedFailedCandidateProbe(t *testing.T)
func TestManagerRetriesSuppressedCandidateWithMACBoundProbe(t *testing.T)
```

Assert a failed direct probe is not retried during suppression, is retried after suppression expires, and MAC-bound probe format is preserved when `DiscoveryKey` is configured.

- [ ] **Step 2: Verify red**

Run:

```bash
go test ./pkg/transport -run 'TestManagerSuppressesRepeatedFailedCandidateProbe|TestManagerRetriesSuppressedCandidateWithMACBoundProbe' -count=1
```

Expected: FAIL because failed candidates are retried immediately.

- [ ] **Step 3: Suppress data-write failures**

Add private helper:

```go
func (m *Manager) noteRelayAfterDirectWriteFailure(now time.Time, addr net.Addr)
```

It increments discovery generation, marks the failed direct endpoint unusable for `defaultCandidateSuppressPeriod`, and falls back to relay if configured.

Use this helper from `pkg/transport/peer.go` when direct data writes fail with relay fallback available. Preserve `EMSGSIZE` behavior.

- [ ] **Step 4: Verify and checkpoint**

Run:

```bash
gofmt -w pkg/transport/manager.go pkg/transport/peer.go pkg/transport/manager_test.go
go test ./pkg/transport -run 'TestManagerSuppressesRepeatedFailedCandidateProbe|TestManagerRetriesSuppressedCandidateWithMACBoundProbe|TestManagerReturnsEMSGSIZEAndKeepsDirectPathWithoutRelayFallback|TestManagerFallsBackToRelayAndRetriesDiscovery' -count=1
but status -fv
but commit -m "transport: suppress failed direct probe retries"
```

Expected: PASS.

## Task 6: Regression Guard

**Files:**
- Test: `pkg/transport/manager_test.go`
- Test: `pkg/transport/disco_mac_test.go`
- Test: `pkg/transport/state_test.go`

- [ ] **Step 1: Run MAC/direct regression suite**

Run:

```bash
go test ./pkg/transport -run 'TestDiscoveryMAC|TestManagerSendsMACBoundDirectProbeWhenDiscoveryKeyConfigured|TestManagerPromotesDirectWithMACBoundAck|TestManagerRejectsStaticAckWhenDiscoveryKeyConfigured|TestManagerRespondsToMACBoundInboundProbe|TestManagerHandleDirectPacketRequiresMACWhenDiscoveryKeyConfigured|TestManagerKeepsActiveDirectPathWhenCandidateSetReplacesEndpoint|TestPathStateKeepsOpenCandidateAcrossReplacement' -count=1
go test ./pkg/transport -run 'TestManagerDirectAddrDoesNotAllocate|TestManagerNoteDirectActivityDoesNotAllocate|TestManagerShouldAcceptDirectPayloadDoesNotAllocate' -count=1
go test ./pkg/transport -count=1
```

Expected: PASS.

- [ ] **Step 2: Checkpoint only if fixes were needed**

Run:

```bash
but status -fv
```

Expected: no new changes. If regression fixes were needed, commit them with `transport: preserve authenticated direct discovery`.

## Final Verification

Run:

```bash
go test ./pkg/candidate ./pkg/transport -count=1
mise run test
mise run vet
mise run check:hooks
mise run check
but status -fv
```

Expected: all PASS; only this branch's candidate lifecycle files changed.

## Acceptance Criteria

- Candidates have private statuses: pending, open, inactive, unusable.
- Pending probes suppress duplicate probes.
- Failed and expired probes suppress retries for 5s.
- Non-active tracked direct candidates are capped at `candidate.MaxCount`.
- Active direct endpoint survives candidate replacement.
- Recent inactive candidates are retained up to 10.
- MAC-bound direct discovery and `EMSGSIZE` behavior are unchanged.

## Self-Review Notes

- Spec coverage: status tracking, suppression, pruning, active retention, manager integration, and MAC regression are covered.
- Red-flag scan: clean for unresolved markers, ellipses, and incomplete implementation steps.
- Type consistency: lifecycle types/constants are introduced before use.
