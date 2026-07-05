# Path Selector Hysteresis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an independently testable transport path selector that keeps direct paths primary, relay as backup, preserves private/CGNAT preference, and prevents close RTT changes from flapping the selected direct endpoint.

**Architecture:** Extract endpoint scoring out of `pathState` into an internal selector inspired by iroh's biased RTT selector. Rank by path tier first, then biased RTT, then require a minimum same-tier improvement before switching. Keep manager public APIs stable.

**Tech Stack:** Go, `pkg/transport.Manager`, existing fake-clock/fake-packet tests, `mise`, GitButler.

---

## Branch

Use GitButler branch `codex/transport-path-selector-hysteresis`.

Stack this branch after `codex/transport-path-events` if that branch is present and applied.

Run before editing:

```bash
but status -fv
but pull --check
but branch new codex/transport-path-selector-hysteresis
```

Expected: no active branch owns `pkg/transport/state.go`, `pkg/transport/state_test.go`, `pkg/transport/manager.go`, or `pkg/transport/manager_test.go`, except the applied path-events dependency if this branch is stacked on it.

## File Structure

- Create `pkg/transport/path_selector.go`: private selector policy, direct-vs-relay tiers, direct address RTT advantage, same-tier hysteresis.
- Create `pkg/transport/path_selector_test.go`: unit tests for policy without manager goroutines.
- Modify `pkg/transport/state.go`: initialize selector and replace `betterDirectAddr` usage.
- Modify `pkg/transport/state_test.go`: state-level hysteresis tests.
- Modify `pkg/transport/manager_test.go`: manager-level regression tests.

## Task 1: Selector Unit

**Files:**
- Create: `pkg/transport/path_selector.go`
- Create: `pkg/transport/path_selector_test.go`

- [ ] **Step 1: Write failing tests**

Create tests:

```go
func TestPathSelectorPrefersDirectOverRelayRegardlessOfRTT(t *testing.T)
func TestPathSelectorKeepsCurrentDirectWhenRTTImprovementIsBelowHysteresis(t *testing.T)
func TestPathSelectorSwitchesDirectWhenRTTImprovementMeetsHysteresis(t *testing.T)
func TestPathSelectorPrefersPrivateAndCGNATWhenRTTIsClose(t *testing.T)
func TestPathSelectorKeepsCurrentWhenNoBetterCandidateExists(t *testing.T)
```

Concrete cases:

- relay RTT `1ms`, public direct RTT `1000ms` => direct wins
- current public `20ms`, candidate public `16ms` => keep current
- current public `20ms`, candidate public `15ms` => switch
- current public `5ms`, CGNAT/private `6ms` => switch to CGNAT/private
- current CGNAT `5ms`, public `8ms` => keep CGNAT

- [ ] **Step 2: Verify red**

Run:

```bash
go test ./pkg/transport -run 'TestPathSelector' -count=1
```

Expected: FAIL because selector types do not exist.

- [ ] **Step 3: Implement selector**

Add private types:

```go
const defaultPathSwitchHysteresis = 5 * time.Millisecond

type selectablePath struct {
	path Path
	key string
	addr net.Addr
	rtt time.Duration
}

type pathSelection struct {
	path Path
	key string
}

type pathSelector struct {
	switchHysteresis time.Duration
}
```

Implement `defaultPathSelector()` and `selectPath(current selectablePath, hasCurrent bool, candidates []selectablePath) (pathSelection, bool)`. Direct tier beats relay tier. Same-tier switching requires candidate biased RTT plus hysteresis to be less than or equal to current biased RTT.

- [ ] **Step 4: Verify green and checkpoint**

Run:

```bash
gofmt -w pkg/transport/path_selector.go pkg/transport/path_selector_test.go
go test ./pkg/transport -run 'TestPathSelector' -count=1
but status -fv
but commit -m "transport: add path selector policy"
```

Expected: PASS.

## Task 2: State Integration

**Files:**
- Modify: `pkg/transport/state.go`
- Modify: `pkg/transport/state_test.go`

- [ ] **Step 1: Write failing state tests**

Add:

```go
func TestPathStateKeepsCurrentDirectEndpointWhenRTTImprovementIsBelowHysteresis(t *testing.T)
func TestPathStateSwitchesDirectEndpointWhenRTTImprovementMeetsHysteresis(t *testing.T)
```

Use `noteCandidates`, `noteProbeSent`, `consumeProbe`, and `noteDirect`. Assert a 4ms public-to-public RTT improvement keeps the current endpoint and a 5ms improvement switches.

- [ ] **Step 2: Verify red**

Run:

```bash
go test ./pkg/transport -run 'TestPathState(KeepsCurrentDirectEndpointWhenRTTImprovementIsBelowHysteresis|SwitchesDirectEndpointWhenRTTImprovementMeetsHysteresis|KeepsPrivateEndpoint|PrefersCGNAT)' -count=1
```

Expected: new hysteresis test fails under current scoring.

- [ ] **Step 3: Wire selector**

Add `selector pathSelector` to `pathState`, initialize it in `newPathState`, and replace `shouldSelectDirectEndpoint` with selector-driven comparison. Preserve:

- `lastDirectAt` update on valid direct ACK even if endpoint does not change
- `upgrades` increment only when moving from non-direct to direct
- immediate relay fallback for stale/broken direct
- current private/CGNAT preference tests

Remove `betterDirectAddr` and `directAddrPreferencePoints` once no longer used.

- [ ] **Step 4: Verify green and checkpoint**

Run:

```bash
rg -n 'betterDirectAddr|directAddrPreferencePoints' pkg/transport
gofmt -w pkg/transport/state.go pkg/transport/state_test.go
go test ./pkg/transport -run 'TestPathState' -count=1
but status -fv
but commit -m "transport: apply selector hysteresis to path state"
```

Expected: `rg` has no output; tests PASS.

## Task 3: Manager Regression Coverage

**Files:**
- Modify: `pkg/transport/manager_test.go`

- [ ] **Step 1: Add manager tests**

Add:

```go
func TestManagerKeepsCurrentDirectPathWhenCandidateRTTImprovementIsBelowHysteresis(t *testing.T)
func TestManagerSwitchesDirectPathWhenCandidateRTTImprovementMeetsHysteresis(t *testing.T)
func TestManagerRelayFallbackBypassesDirectSwitchHysteresis(t *testing.T)
```

Assert through `mgr.DirectPath()` and `mgr.PathState()`, not a new public selector API.

- [ ] **Step 2: Verify**

Run:

```bash
go test ./pkg/transport -run 'TestManager(KeepsCurrentDirectPathWhenCandidateRTTImprovementIsBelowHysteresis|SwitchesDirectPathWhenCandidateRTTImprovementMeetsHysteresis|RelayFallbackBypassesDirectSwitchHysteresis|FallsBackToRelayAndRetriesDiscovery|PromotesDirectWithMACBoundAck|ExposesDirectPathSnapshot)' -count=1
go test ./pkg/transport -run 'TestManager(DirectAddrDoesNotAllocate|NoteDirectActivityDoesNotAllocate|ShouldAcceptDirectPayloadDoesNotAllocate)' -count=1
```

Expected: PASS. Selector must not add allocations to hot read paths.

- [ ] **Step 3: Checkpoint**

Run:

```bash
gofmt -w pkg/transport/manager_test.go
but status -fv
but commit -m "test: cover manager path selector hysteresis"
```

Expected: checkpoint contains manager tests only.

## Final Verification

Run:

```bash
go test ./pkg/transport -run 'Test(PathSelector|PathState)' -count=1
go test ./pkg/transport -count=1
mise run test
mise run vet
mise run check
but status -fv
```

Expected: all PASS, no public manager API changes, only this branch's selector files and tests changed.

## Acceptance Criteria

- Direct paths are primary over relay.
- Relay fallback is never delayed by direct endpoint hysteresis.
- Same-tier direct switching requires at least a 5ms biased RTT improvement.
- Private/CGNAT close-RTT preference remains intact.
- Selector is private and unit-testable.

## Self-Review Notes

- Spec coverage: direct primary, relay backup, private/CGNAT preference, hysteresis, public API stability, and tests are covered.
- Red-flag scan: clean for unresolved markers, ellipses, and incomplete implementation steps.
- Type consistency: selector types are introduced before state/manager usage.
