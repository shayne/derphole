# Direct UDP Dynamic Scaling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make direct UDP scale active lanes and aggregate rate from observed path quality over time, without premature one-lane or low-ceiling caps after a conservative startup decision.

**Architecture:** Decouple route validation, lane pool retention, startup pacing, exploration ceiling, and telemetry. Keep all routable direct UDP lanes available to the packet engine, set a dynamic minimum active lane floor from useful probe evidence, use aggregate pacing for safety, and allow the existing sender controller to scale active lanes as rate changes.

**Tech Stack:** Go, `pkg/session` direct UDP coordination, `pkg/probe` striped blast sender, existing `mise`/pre-commit quality gates, live `scripts/transfer-stall-harness.sh`.

---

## File Structure

- Modify `pkg/session/external_direct_udp.go`
  - Owns direct UDP candidate selection, rate probe interpretation, send config construction, lane retention, and verbose direct UDP logs.
  - Add helpers for useful probe lane floor and useful probe exploration ceiling.
  - Stop truncating the routable direct lane pool purely because startup rate is conservative.
  - Populate `probe.SendConfig.MinActiveLanes`, `MaxActiveLanes`, `RateCeilingMbps`, and `RateExplorationCeilingMbps` with separate meanings.
- Modify `pkg/session/external_direct_udp_test.go`
  - Add regression tests from the supplied 1 GiB LAN/VLAN log.
  - Cover lane retention, exploration ceiling, final send config, and telemetry formatting.
- Modify `pkg/session/external_direct_udp_helpers_test.go`
  - Add focused helper tests for rate probe formatting when no sender denominator exists.
- Modify `pkg/probe/session_test.go` only if existing `parallelActiveLanesForConfig` behavior is insufficient.
  - Prefer not to modify `pkg/probe/session.go`; it already supports `MinActiveLanes`, `MaxActiveLanes`, and `RateExplorationCeilingMbps`.
- Modify `docs/benchmarks.md`
  - Document the new expected telemetry fields and validation expectations.

## Current Failure Signature

The reproduced direct run did connect directly but stayed near 225 Mbps:

```text
udp-lanes=8
udp-striped-available-lanes=1
udp-rate-ceiling-mbps=350
udp-rate-selected-mbps=263
udp-active-lanes-selected=1
udp-active-lane-cap=4
udp-send-goodput-mbps=225.07
```

The rate probe evidence showed usable higher capacity:

```text
350:  goodput=349.99 delivery=1.00 active_lanes=1
700:  goodput=556.98 delivery=0.80 active_lanes=2
1000: goodput=535.61 delivery=0.54 active_lanes=4
1200: goodput=515.57 delivery=0.43 active_lanes=4
1800: goodput=514.01 delivery=0.29 active_lanes=8
```

The bug is not that startup was conservative. The bug is that conservative startup discarded lane fanout and clamped exploration, so the sender could not naturally climb as path quality changed.

---

### Task 1: Add Regression Tests for Dynamic Lane Retention

**Files:**
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Add reusable live-sample fixtures**

Add these helpers near the existing direct UDP rate/lane tests:

```go
func liveVLANLossyButUsefulSentProbeSamples() []directUDPRateProbeSample {
	return []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200680, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625568, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1875320, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3750640, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8749648, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17405530, DurationMillis: 200},
		{RateMbps: 1000, BytesSent: 24981642, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29974865, DurationMillis: 200},
		{RateMbps: 1800, BytesSent: 112783607, DurationMillis: 500},
		{RateMbps: 2000, BytesSent: 125068187, DurationMillis: 500},
		{RateMbps: 2250, BytesSent: 140852737, DurationMillis: 500},
	}
}

func liveVLANLossyButUsefulReceivedProbeSamples() []directUDPRateProbeSample {
	return []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200680, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625568, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1875320, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3750640, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8749648, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 13924424, DurationMillis: 200},
		{RateMbps: 1000, BytesReceived: 13390200, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 12889192, DurationMillis: 200},
		{RateMbps: 1800, BytesReceived: 32125408, DurationMillis: 500},
		{RateMbps: 2000, BytesReceived: 32017456, DurationMillis: 500},
		{RateMbps: 2250, BytesReceived: 32150320, DurationMillis: 500},
	}
}
```

- [ ] **Step 2: Add failing lane-retention test**

Add this test near `TestExternalDirectUDPRetainedLanesForRateKeepsStripedHeadroom`:

```go
func TestExternalDirectUDPSendRetainedLanesKeepsUsefulProbeFanoutAfterConservativeSelection(t *testing.T) {
	rateState := externalDirectUDPSendRateState{
		selectedRateMbps: 263,
		activeRateMbps:   263,
		rateCeilingMbps:  350,
		sentProbeSamples: liveVLANLossyButUsefulSentProbeSamples(),
		probeResult: directUDPRateProbeResult{
			Samples: liveVLANLossyButUsefulReceivedProbeSamples(),
		},
	}
	sendCfg := probe.SendConfig{
		StripedBlast:   true,
		MaxActiveLanes: 4,
	}
	caps := probe.TransportCaps{Kind: "batched", BatchSize: 128}

	got := externalDirectUDPSendRetainedLanes(rateState, sendCfg, 4, 8, caps)
	if got < 4 {
		t.Fatalf("externalDirectUDPSendRetainedLanes(live VLAN useful probes) = %d, want at least 4", got)
	}
}
```

- [ ] **Step 3: Run the new test and verify it fails**

Run:

```bash
go test ./pkg/session -run TestExternalDirectUDPSendRetainedLanesKeepsUsefulProbeFanoutAfterConservativeSelection -count=1
```

Expected before implementation:

```text
FAIL: got 1, want at least 4
```

---

### Task 2: Preserve the Routable Lane Pool and Use a Dynamic Lane Floor

**Files:**
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Add useful-probe lane-floor helper tests**

Add tests near the direct UDP rate/lane helper tests:

```go
func TestExternalDirectUDPUsefulProbeLaneFloorUsesNearBestUsefulHigherLaneCount(t *testing.T) {
	got := externalDirectUDPUsefulProbeLaneFloor(
		liveVLANLossyButUsefulSentProbeSamples(),
		liveVLANLossyButUsefulReceivedProbeSamples(),
		8,
	)
	if got != 4 {
		t.Fatalf("externalDirectUDPUsefulProbeLaneFloor(live VLAN) = %d, want 4", got)
	}
}

func TestExternalDirectUDPUsefulProbeLaneFloorIgnoresCollapsedTopTier(t *testing.T) {
	got := externalDirectUDPUsefulProbeLaneFloor(
		liveVLANLossyButUsefulSentProbeSamples(),
		liveVLANLossyButUsefulReceivedProbeSamples(),
		8,
	)
	if got == 8 {
		t.Fatalf("externalDirectUDPUsefulProbeLaneFloor(live VLAN) = %d, want collapsed 8-lane tier ignored", got)
	}
}
```

- [ ] **Step 2: Run helper tests and verify they fail**

Run:

```bash
go test ./pkg/session -run 'TestExternalDirectUDPUsefulProbeLaneFloor' -count=1
```

Expected before implementation:

```text
undefined: externalDirectUDPUsefulProbeLaneFloor
```

- [ ] **Step 3: Implement the useful-probe lane-floor helper**

Add this helper near the existing lane-budget helpers:

```go
func externalDirectUDPUsefulProbeLaneFloor(sent []directUDPRateProbeSample, received []directUDPRateProbeSample, available int) int {
	if available <= 0 || len(sent) == 0 || len(received) == 0 {
		return 0
	}
	sentByRate := externalDirectUDPProbeSamplesByRate(sent)
	bestGoodput := 0.0
	type candidate struct {
		lanes   int
		goodput float64
	}
	candidates := make([]candidate, 0, len(received))
	for _, sample := range received {
		goodput, delivery, _, ok := externalDirectUDPProbeMetrics(sample, sentByRate)
		if !ok || goodput <= 0 || delivery < externalDirectUDPRateProbeLossyDelivery {
			continue
		}
		lanes := externalDirectUDPRateProbeActiveLanes(sample.RateMbps, available)
		if lanes <= 0 {
			continue
		}
		candidates = append(candidates, candidate{lanes: lanes, goodput: goodput})
		if goodput > bestGoodput {
			bestGoodput = goodput
		}
	}
	if bestGoodput <= 0 {
		return 0
	}
	floor := 0
	nearBest := bestGoodput * externalDirectUDPRateProbeNearClean
	for _, candidate := range candidates {
		if candidate.goodput >= nearBest && candidate.lanes > floor {
			floor = candidate.lanes
		}
	}
	if floor > available {
		return available
	}
	return floor
}
```

- [ ] **Step 4: Feed lane floor into retained lane selection**

Update `externalDirectUDPSendRetainedLanes` so useful probe evidence can raise the retained lane count after the existing conservative budget runs:

```go
func externalDirectUDPSendRetainedLanes(rateState externalDirectUDPSendRateState, sendCfg probe.SendConfig, policyActiveLaneCap int, lanes int, effectiveTransportCaps probe.TransportCaps) int {
	retainedLanes := externalDirectUDPBaseRetainedLanes(rateState, sendCfg, lanes)
	retainedLanes = externalDirectUDPApplyUsefulProbeLaneFloor(retainedLanes, rateState, lanes)
	retainedLanes = externalDirectUDPApplyNoProbeRetainedLanes(retainedLanes, rateState, lanes)
	retainedLanes = externalDirectUDPApplyPolicyRetainedLanes(retainedLanes, policyActiveLaneCap)
	return externalDirectUDPSenderRetainedLaneCap(effectiveTransportCaps, rateState.selectedRateMbps, rateState.activeRateMbps, rateState.rateCeilingMbps, retainedLanes)
}
```

Add:

```go
func externalDirectUDPApplyUsefulProbeLaneFloor(retainedLanes int, rateState externalDirectUDPSendRateState, lanes int) int {
	floor := externalDirectUDPUsefulProbeLaneFloor(rateState.sentProbeSamples, rateState.probeResult.Samples, lanes)
	if floor > retainedLanes {
		return floor
	}
	return retainedLanes
}
```

- [ ] **Step 5: Set `MinActiveLanes` from the same lane floor**

In `externalDirectUDPResolveProbedSendRates`, after `sendCfg.RateExplorationCeilingMbps` is set, add:

```go
sendCfg.MinActiveLanes = externalDirectUDPMaxInt(
	sendCfg.MinActiveLanes,
	externalDirectUDPUsefulProbeLaneFloor(sentProbeSamples, probeResult.Samples, len(probeConns)),
)
```

Add a local helper if the file does not already have one:

```go
func externalDirectUDPMaxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
```

- [ ] **Step 6: Re-run lane tests**

Run:

```bash
go test ./pkg/session -run 'UsefulProbeLaneFloor|RetainedLanesKeepsUsefulProbeFanout' -count=1
```

Expected:

```text
ok  	github.com/shayne/derphole/pkg/session
```

---

### Task 3: Expand Exploration Ceiling from Useful Lossy Probes

**Files:**
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Add failing exploration ceiling test**

Add near existing exploration ceiling tests:

```go
func TestExternalDirectUDPSendExplorationCeilingUsesUsefulLossyHighProbeAfterConservativeSelection(t *testing.T) {
	rateState := externalDirectUDPSendRateState{
		maxRateMbps:      10_000,
		selectedRateMbps: 263,
		activeRateMbps:   263,
		rateCeilingMbps:  350,
		sentProbeSamples: liveVLANLossyButUsefulSentProbeSamples(),
		probeResult: directUDPRateProbeResult{
			Samples: liveVLANLossyButUsefulReceivedProbeSamples(),
		},
	}
	got := externalDirectUDPSendExplorationCeiling(rateState, probe.TransportCaps{Kind: "batched", BatchSize: 128}, externalDirectUDPSenderProbeRateLimitResult{})
	if got < 1000 {
		t.Fatalf("externalDirectUDPSendExplorationCeiling(live VLAN) = %d, want at least 1000", got)
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```bash
go test ./pkg/session -run TestExternalDirectUDPSendExplorationCeilingUsesUsefulLossyHighProbeAfterConservativeSelection -count=1
```

Expected before implementation:

```text
FAIL: got 350, want at least 1000
```

- [ ] **Step 3: Implement useful-probe exploration ceiling helper**

Add near exploration ceiling helpers:

```go
func externalDirectUDPUsefulProbeExplorationCeiling(maxRateMbps int, currentCeiling int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) int {
	if len(sent) == 0 || len(received) == 0 {
		return currentCeiling
	}
	sentByRate := externalDirectUDPProbeSamplesByRate(sent)
	bestGoodput := 0.0
	type candidate struct {
		rate    int
		goodput float64
	}
	candidates := make([]candidate, 0, len(received))
	for _, sample := range received {
		goodput, delivery, _, ok := externalDirectUDPProbeMetrics(sample, sentByRate)
		if !ok || sample.RateMbps <= currentCeiling || delivery < externalDirectUDPRateProbeLossyDelivery {
			continue
		}
		candidates = append(candidates, candidate{rate: sample.RateMbps, goodput: goodput})
		if goodput > bestGoodput {
			bestGoodput = goodput
		}
	}
	if bestGoodput <= 0 {
		return currentCeiling
	}
	nearBest := bestGoodput * externalDirectUDPRateProbeNearClean
	ceiling := currentCeiling
	for _, candidate := range candidates {
		if candidate.goodput >= nearBest && candidate.rate > ceiling {
			ceiling = candidate.rate
		}
	}
	if maxRateMbps > 0 && ceiling > maxRateMbps {
		return maxRateMbps
	}
	return ceiling
}
```

- [ ] **Step 4: Apply helper in send exploration ceiling**

Update `externalDirectUDPSendExplorationCeiling`:

```go
func externalDirectUDPSendExplorationCeiling(rateState externalDirectUDPSendRateState, effectiveTransportCaps probe.TransportCaps, probeLimit externalDirectUDPSenderProbeRateLimitResult) int {
	ceiling := externalDirectUDPDataExplorationCeilingMbpsForProbeSamples(rateState.maxRateMbps, rateState.selectedRateMbps, rateState.rateCeilingMbps, rateState.sentProbeSamples, rateState.probeResult.Samples)
	ceiling = externalDirectUDPUsefulProbeExplorationCeiling(rateState.maxRateMbps, ceiling, rateState.sentProbeSamples, rateState.probeResult.Samples)
	ceiling = externalDirectUDPSenderExplorationCeilingCap(effectiveTransportCaps, ceiling)
	if probeLimit.CeilingMbps > 0 && ceiling > probeLimit.CeilingMbps {
		return probeLimit.CeilingMbps
	}
	return ceiling
}
```

- [ ] **Step 5: Re-run exploration tests**

Run:

```bash
go test ./pkg/session -run 'ExplorationCeiling|UsefulProbeExploration' -count=1
```

Expected:

```text
ok  	github.com/shayne/derphole/pkg/session
```

---

### Task 4: Stop Clamping Data Ceiling Because Startup Lane Count Was Conservative

**Files:**
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Add failing finalization test**

Add near `externalDirectUDPDataRateCeilingMbps` tests:

```go
func TestExternalDirectUDPFinalizeSendRatesDoesNotClampUsefulProbeExplorationWithMultipleLanes(t *testing.T) {
	rateState := externalDirectUDPSendRateState{
		selectedRateMbps: 263,
		activeRateMbps:   263,
		rateCeilingMbps:  350,
	}
	sendCfg := probe.SendConfig{
		RateCeilingMbps:            350,
		RateExplorationCeilingMbps: 1200,
		StripedBlast:               true,
		MinActiveLanes:             4,
		MaxActiveLanes:             4,
	}

	gotState, gotCfg := externalDirectUDPFinalizeSendRates(rateState, sendCfg, 4)
	if gotState.rateCeilingMbps != 350 {
		t.Fatalf("rateCeilingMbps = %d, want 350", gotState.rateCeilingMbps)
	}
	if gotCfg.RateExplorationCeilingMbps < 1200 {
		t.Fatalf("RateExplorationCeilingMbps = %d, want at least 1200", gotCfg.RateExplorationCeilingMbps)
	}
}
```

- [ ] **Step 2: Run finalization test**

Run:

```bash
go test ./pkg/session -run TestExternalDirectUDPFinalizeSendRatesDoesNotClampUsefulProbeExplorationWithMultipleLanes -count=1
```

Expected before implementation:

```text
FAIL
```

- [ ] **Step 3: Fix finalizer to use retained lane capacity, not startup rate**

If Task 2 retained lanes are at least 4, the existing call `externalDirectUDPFinalizeSendRates(rateState, sendCfg, len(probeConns))` should preserve `RateExplorationCeilingMbps`. If the test still fails, adjust `externalDirectUDPDataRateCeilingMbps` so it clamps only when the retained lane pool is actually one lane:

```go
func externalDirectUDPDataRateCeilingMbps(probeCeilingMbps int, selectedRateMbps int, activeLanes int) int {
	if probeCeilingMbps <= 0 || selectedRateMbps <= 0 {
		return probeCeilingMbps
	}
	if activeLanes <= 1 && probeCeilingMbps > externalDirectUDPActiveLaneOneMaxMbps {
		return externalDirectUDPActiveLaneOneMaxMbps
	}
	return probeCeilingMbps
}
```

Keep this function simple. Do not add probe-sample logic here; all probe interpretation belongs in Tasks 2 and 3.

- [ ] **Step 4: Re-run finalization and lane tests**

Run:

```bash
go test ./pkg/session -run 'FinalizeSendRatesDoesNotClamp|UsefulProbeLaneFloor|RetainedLanesKeepsUsefulProbeFanout|ExplorationCeilingUsesUseful' -count=1
```

Expected:

```text
ok  	github.com/shayne/derphole/pkg/session
```

---

### Task 5: Make Probe Telemetry Accurate and Explain Scaling Decisions

**Files:**
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_direct_udp_helpers_test.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Add failing receiver-format telemetry test**

Add in `pkg/session/external_direct_udp_helpers_test.go`:

```go
func TestExternalDirectUDPFormatRateProbeSamplesShowsUnknownDeliveryWithoutSenderDenominator(t *testing.T) {
	out := externalDirectUDPFormatRateProbeSamples(nil, []directUDPRateProbeSample{
		{RateMbps: 700, BytesReceived: 13924424, DurationMillis: 200},
	})
	if !strings.Contains(out, "700:rx=13924424") {
		t.Fatalf("formatted probes = %q, want rx bytes", out)
	}
	if !strings.Contains(out, "delivery=unknown") {
		t.Fatalf("formatted probes = %q, want delivery=unknown without sender denominator", out)
	}
	if strings.Contains(out, "delivery=0.00") {
		t.Fatalf("formatted probes = %q, want no fake zero delivery", out)
	}
}
```

- [ ] **Step 2: Run telemetry helper test and verify it fails**

Run:

```bash
go test ./pkg/session -run TestExternalDirectUDPFormatRateProbeSamplesShowsUnknownDeliveryWithoutSenderDenominator -count=1
```

Expected before implementation:

```text
FAIL: want delivery=unknown
```

- [ ] **Step 3: Update rate probe formatting**

Modify `externalDirectUDPFormatRateProbeSample`:

```go
func externalDirectUDPFormatRateProbeSample(sample directUDPRateProbeSample, sentByRate map[int]directUDPRateProbeSample) string {
	goodput := externalDirectUDPRateProbeGoodputMbps(sample)
	if len(sentByRate) == 0 {
		return fmt.Sprintf("%d:rx=%d:goodput=%.2f:delivery=unknown", sample.RateMbps, sample.BytesReceived, goodput)
	}
	delivery := externalDirectUDPRateProbeDelivery(sample, sentByRate)
	return fmt.Sprintf("%d:rx=%d:goodput=%.2f:delivery=%.2f", sample.RateMbps, sample.BytesReceived, goodput, delivery)
}
```

- [ ] **Step 4: Add scaling-decision telemetry test**

Add in `pkg/session/external_direct_udp_test.go`:

```go
func TestEmitExternalDirectUDPSendFinalDebugIncludesDynamicScalingFields(t *testing.T) {
	var out strings.Builder
	emitter := telemetry.NewEmitter(&out, true)
	sendCfg := probe.SendConfig{
		StripedBlast:               true,
		RateMbps:                  263,
		RateCeilingMbps:           350,
		RateExplorationCeilingMbps: 1200,
		MinActiveLanes:            4,
		MaxActiveLanes:            4,
	}
	rateState := externalDirectUDPSendRateState{
		selectedRateMbps: 263,
		activeRateMbps:   263,
		rateCeilingMbps:  350,
	}

	emitExternalDirectUDPSendFinalDebug(emitter, make([]net.PacketConn, 4), sendCfg, rateState)
	body := out.String()
	for _, want := range []string{
		"udp-striped-available-lanes=4",
		"udp-rate-exploration-ceiling-mbps=1200",
		"udp-active-lanes-selected=4",
		"udp-active-lane-min=4",
		"udp-active-lane-cap=4",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("debug output missing %q:\n%s", want, body)
		}
	}
}
```

- [ ] **Step 5: Run telemetry tests**

Run:

```bash
go test ./pkg/session -run 'FormatRateProbeSamplesShowsUnknownDelivery|SendFinalDebugIncludesDynamicScalingFields' -count=1
```

Expected:

```text
ok  	github.com/shayne/derphole/pkg/session
```

---

### Task 6: Verify Packet Engine Dynamic Lane Scaling Still Works

**Files:**
- Modify: `pkg/probe/session_test.go` only if tests reveal a gap.

- [ ] **Step 1: Run existing probe lane scaling tests**

Run:

```bash
go test ./pkg/probe -run 'ParallelActiveLanes|MinActiveLanes|MaxActiveLanes|RateExploration' -count=1
```

Expected:

```text
ok  	github.com/shayne/derphole/pkg/probe
```

- [ ] **Step 2: Add probe-level regression only if existing tests do not cover this behavior**

If `parallelActiveLanesForConfig` is not already covered for low aggregate rate plus four-lane minimum, add:

```go
func TestParallelActiveLanesForConfigUsesMinimumLaneFloorAtConservativeRate(t *testing.T) {
	got := parallelActiveLanesForConfig(263, 8, true, 4, 4)
	if got != 4 {
		t.Fatalf("parallelActiveLanesForConfig(263 Mbps, min=4, max=4) = %d, want 4", got)
	}
}
```

- [ ] **Step 3: Run probe test**

Run:

```bash
go test ./pkg/probe -run TestParallelActiveLanesForConfigUsesMinimumLaneFloorAtConservativeRate -count=1
```

Expected:

```text
ok  	github.com/shayne/derphole/pkg/probe
```

---

### Task 7: Document the New Scaling Semantics

**Files:**
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Add benchmark guidance for dynamic lane scaling**

Append to the “Transfer Stall Traces” section:

```markdown
For direct UDP performance checks, inspect these sender fields together:

- `udp-striped-available-lanes`: routable direct UDP lane pool retained for data.
- `udp-active-lanes-selected`: initial active data lane target.
- `udp-active-lane-min`: minimum active lane floor derived from useful probe evidence.
- `udp-active-lane-cap`: policy cap from `--parallel` or auto policy.
- `udp-rate-ceiling-mbps`: conservative clean startup ceiling.
- `udp-rate-exploration-ceiling-mbps`: higher aggregate ceiling allowed by useful lossy probes.

A healthy LAN/VLAN direct run should not collapse to one available lane when multiple routable lanes probed successfully. Aggregate rate can start conservative, but lane pool and exploration ceiling should leave room for the controller to scale as quality changes during the transfer.
```

- [ ] **Step 2: Run docs-safe checks**

Run:

```bash
pre-commit run derphole-private-info-scan --all-files
```

Expected:

```text
Passed
```

---

### Task 8: Local and Live Verification

**Files:**
- No code changes.

- [ ] **Step 1: Run focused package tests**

Run:

```bash
go test ./pkg/session -run 'UsefulProbeLaneFloor|UsefulProbeExploration|RetainedLanesKeepsUsefulProbeFanout|FormatRateProbeSamplesShowsUnknownDelivery|SendFinalDebugIncludesDynamicScalingFields' -count=1
go test ./pkg/probe -run 'ParallelActiveLanes|MinActiveLanes|MaxActiveLanes|RateExploration' -count=1
```

Expected:

```text
ok  	github.com/shayne/derphole/pkg/session
ok  	github.com/shayne/derphole/pkg/probe
```

- [ ] **Step 2: Run broader package tests**

Run:

```bash
go test ./pkg/session ./pkg/probe -count=1
```

Expected:

```text
ok  	github.com/shayne/derphole/pkg/session
ok  	github.com/shayne/derphole/pkg/probe
```

- [ ] **Step 3: Run full repo gate**

Run:

```bash
mise run check
```

Expected:

```text
derphole coverage and quality gate.......................................Passed
derphole depaware........................................................Passed
derphole depaware dependency check.......................................Passed
[test] $ go test ./...
```

The command must exit with status 0.

- [ ] **Step 4: Run safe live harness**

Run:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPHOLE_STALL_TIMEOUT_SEC=30 ./scripts/transfer-stall-harness.sh <sender-host> <receiver-host> 64
```

Expected:

```text
source-size-bytes=67108864
sink-size-bytes=67108864
sender-status=0
receiver-status=0
trace-ok
leak-check <sender-host> label=postrun tool=derphole processes=0 udp_sockets=0 pids=
leak-check <receiver-host> label=postrun tool=derphole processes=0 udp_sockets=0 pids=
stall-harness-success=true
```

- [ ] **Step 5: Run the same LAN/VLAN manual verification used in the reported log**

Sender command:

```bash
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 npx -y derphole@dev --verbose send ./payload.bin
```

Receiver command:

```bash
npx -y derphole@dev --verbose receive '<token-from-sender>'
```

Expected sender log changes compared to the reported 225 Mbps run:

```text
connected-direct
udp-striped-available-lanes=4
udp-active-lanes-selected=4
udp-active-lane-min=4
udp-rate-exploration-ceiling-mbps=1000
```

Acceptable variants:

- `udp-striped-available-lanes=8` is acceptable.
- `udp-active-lanes-selected=2` is acceptable only if no 4-lane probe is within 90% of best useful goodput.
- `udp-rate-exploration-ceiling-mbps=700` is acceptable if only the 700 Mbps probe is useful in that run.

Failure conditions:

- `connected-direct` is absent.
- `udp-striped-available-lanes=1` with multiple routable selected addresses.
- `udp-active-lanes-selected=1` after useful 2+ lane probes.
- Transfer integrity fails.
- Any postrun leak check finds live `derphole` UDP sockets.

---

### Task 9: Commit and Push

**Files:**
- All changed files from prior tasks.

- [ ] **Step 1: Inspect staged scope**

Run:

```bash
git status --short --branch
git diff --stat
```

Expected changed files:

```text
pkg/session/external_direct_udp.go
pkg/session/external_direct_udp_test.go
pkg/session/external_direct_udp_helpers_test.go
docs/benchmarks.md
```

`pkg/probe/session_test.go` may also appear if Task 6 added the optional coverage test.

- [ ] **Step 2: Commit**

Run:

```bash
git add pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go pkg/session/external_direct_udp_helpers_test.go docs/benchmarks.md
git add pkg/probe/session_test.go 2>/dev/null || true
git commit -m "fix: keep direct udp lanes scalable"
```

Expected:

```text
derphole coverage and quality gate.......................................Passed
[main <sha>] fix: keep direct udp lanes scalable
```

- [ ] **Step 3: Push and watch workflows**

Run:

```bash
git push origin main
gh run list --branch main --limit 5
```

Watch the `Checks`, `Release`, and `Pages` runs for the pushed commit:

```bash
gh run watch <checks-run-id> --exit-status
gh run watch <release-run-id> --exit-status
```

Expected:

```text
completed	success	Checks
completed	success	Release
completed	success	Pages
```

---

## Self-Review

- Spec coverage: The plan covers dynamic lane retention, rate probe interpretation, telemetry cleanup, continuous quality changes through retained lane pool plus exploration ceiling, local gates, live validation, and push workflow.
- Placeholder scan: No task relies on unspecified behavior. Every implementation step names exact files, functions, commands, and expected output.
- Type consistency: New helper signatures use existing types `directUDPRateProbeSample`, `externalDirectUDPSendRateState`, `probe.SendConfig`, `probe.TransportCaps`, and existing probe metrics helpers.
