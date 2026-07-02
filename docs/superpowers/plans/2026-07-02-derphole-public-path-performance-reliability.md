# Derphole Public Path Performance Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make derphole public-Internet transfers approach `iperf3` baseline throughput on the same path, while preserving normal Tailscale-capable product behavior.

**Architecture:** Treat `iperf3` as the external baseline for what the public WAN path can do, then compare derphole raw-direct and manager-backed QUIC against that baseline under the same public-only candidate conditions. First lock in the existing test-only public-path switch and make the selected manager path observable, then tune the manager-backed QUIC path, then add an opt-in startup budget for raw-direct negotiation after the fallback path is measurable. Keep raw-direct bulk copy intact because the UK traces show it is not ACK-gated and is near or above the public WAN baseline once payload starts.

**Tech Stack:** Go, quic-go via `pkg/directquic`, derphole v2 session transport in `pkg/session`, manager path selection in `pkg/transport`, shell benchmark harnesses under `scripts/`, GitButler for checkpoint commits.

---

## Investigation Baseline

Use these facts as the starting hypothesis, not as permanent truth:

- UK host: `ubuntu@derphole-testing`.
- Public WAN RTT from NYC to UK host: about 80-85 ms.
- `iperf3` UK host -> this Mac public WAN port `8321`: about 58 Mbps received.
- derphole reverse raw-direct with `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`: about 49.5 Mbps benchmark goodput for 128 MiB.
- derphole forward raw-direct with `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`: about 115 Mbps benchmark goodput for 128 MiB.
- derphole reverse manager path with Tailscale candidates allowed: 64 MiB showed a roughly 26 second no-progress stall and about 5.7 Mbps from first byte.
- derphole reverse manager path with Tailscale candidates disabled: 64 MiB still bursty, but improved to about 22.4 Mbps from first byte and the longest no-progress window dropped to about 3 seconds.
- Raw-direct bulk transfer is not the same ACK wait issue fixed in derpssh. The payload copy runs over QUIC streams; the visible latency is startup negotiation and manager-path burstiness.

## Performance Target

The throughput target is parity with an `iperf3` baseline on the same public Internet path and direction. For the UK reverse path, raw-direct derphole goodput should be within 20 percent of the `iperf3` received bitrate unless traces show a network-level loss or congestion event that also affects `iperf3`. Manager-backed QUIC should be stable enough to serve as a startup fallback: no multi-second no-progress cliffs, no Tailscale-selected path in public-only benchmark mode, and no sustained goodput below 50 percent of raw-direct without a clear trace reason.

## File Structure

- Modify `pkg/session/session_test.go`: preserve tests that Tailscale is allowed by default and blocked only when `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` is set.
- Modify `pkg/session/external_v2_dataplane_test.go`: preserve raw-direct selection tests that verify public-only test mode filters Tailscale observations.
- Modify `pkg/session/types.go`: emit selected manager direct endpoint and endpoint class in verbose status logs.
- Create `pkg/session/external_path_debug_test.go`: focused tests for endpoint classification and emitter summary behavior.
- Modify `pkg/dataplane/quic.go`: let manager-backed QUIC use multiple connections when multiple v2 streams are requested.
- Create `pkg/dataplane/quic_test.go`: focused tests for manager-adapter connection fanout.
- Modify `pkg/session/external_v2_dataplane.go`: add optional raw-direct negotiation budget only after manager fallback is observable and less bursty.
- Create `pkg/session/external_v2_startup_budget_test.go`: tests for budget parsing and budget-expired fallback selection.
- Modify `scripts/promotion-benchmark-driver.sh`: propagate transport experiment env vars to the remote benchmark process.
- Modify `scripts/promotion_scripts_test.go`: assert promotion benchmarks propagate the public-path and startup-budget env vars.
- Create `scripts/public-path-performance-harness.sh`: repeatable public Internet benchmark matrix using `iperf3` and existing promotion harness scripts.
- Modify `docs/benchmarks.md`: document the public-path harness and expected interpretation.

## Required Execution Setup

- [ ] **Step 1: Start in an isolated workspace**

Run this before implementing tasks:

```bash
but status
but pull --check
but branch new codex/derphole-public-path-performance
```

Expected: `but pull --check` reports no conflicts. If another active branch touches `pkg/session`, `pkg/transport`, `pkg/dataplane`, or `scripts/promotion-benchmark-driver.sh`, stop and report the overlap before editing.

- [ ] **Step 2: Install local hooks if missing**

Run:

```bash
mise run install-githooks
```

Expected: command exits 0.

---

### Task 1: Preserve Product Defaults And Public-Only Test Mode

**Files:**
- Modify: `pkg/session/session_test.go`
- Modify: `pkg/session/external_v2_dataplane_test.go`

- [ ] **Step 1: Lock in Tailscale-allowed default behavior**

In `pkg/session/session_test.go`, make sure this test exists exactly as shown. This is a regression guard against accidentally changing product behavior while improving public-network benchmarks:

```go
func TestPublicProbeCandidateAllowedAllowsTailscaleByDefault(t *testing.T) {
	if !publicProbeCandidateAllowed(netip.MustParseAddr("100.125.235.82")) {
		t.Fatal("publicProbeCandidateAllowed(100.125.235.82) = false, want true by default")
	}
	if !publicProbeCandidateAllowed(netip.MustParseAddr("fd7a:115c:a1e0::1")) {
		t.Fatal("publicProbeCandidateAllowed(fd7a:115c:a1e0::1) = false, want true by default")
	}
	if !publicProbeCandidateAllowed(netip.MustParseAddr("203.0.113.10")) {
		t.Fatal("publicProbeCandidateAllowed(203.0.113.10) = false, want true")
	}
}
```

- [ ] **Step 2: Lock in public-only test mode behavior**

In `pkg/session/session_test.go`, make sure this test exists exactly as shown:

```go
func TestPublicProbeCandidateAllowedSkipsTailscaleInInternetOnlyTestMode(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES", "1")

	if publicProbeCandidateAllowed(netip.MustParseAddr("100.125.235.82")) {
		t.Fatal("publicProbeCandidateAllowed(100.125.235.82) = true, want false when DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1")
	}
	if publicProbeCandidateAllowed(netip.MustParseAddr("fd7a:115c:a1e0::1")) {
		t.Fatal("publicProbeCandidateAllowed(fd7a:115c:a1e0::1) = true, want false when DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1")
	}
	if !publicProbeCandidateAllowed(netip.MustParseAddr("203.0.113.10")) {
		t.Fatal("publicProbeCandidateAllowed(203.0.113.10) = false, want true")
	}
}
```

- [ ] **Step 3: Lock in candidate-list filtering only under public-only test mode**

In `pkg/session/session_test.go`, make sure `TestPublicProbeCandidatesSkipsTailscaleCGNATInInternetOnlyTestMode` contains this body:

```go
func TestPublicProbeCandidatesSkipsTailscaleCGNATInInternetOnlyTestMode(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES", "1")

	ctx := context.Background()
	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}

	prev := gatherTraversalCandidates
	t.Cleanup(func() {
		gatherTraversalCandidates = prev
	})
	gatherTraversalCandidates = func(context.Context, net.PacketConn, *tailcfg.DERPMap, func() (netip.AddrPort, bool)) ([]string, error) {
		return []string{
			"100.64.0.11:5555",
			"100.125.235.82:4242",
			"192.0.2.10:5555",
		}, nil
	}

	got := publicProbeCandidates(ctx, conn, &tailcfg.DERPMap{}, nil)
	if containsCGNATCandidate(got) {
		t.Fatalf("publicProbeCandidates() = %v, want no 100.64.0.0/10 candidates", got)
	}
	if !containsString(got, "192.0.2.10:5555") {
		t.Fatalf("publicProbeCandidates() = %v, want non-CGNAT gathered candidate", got)
	}
}
```

- [ ] **Step 4: Ensure production helper remains test-env scoped**

Do not add a new production opt-in env var. In `pkg/session/external.go`, `publicProbeTailscaleCandidatesDisabled` should remain:

```go
func publicProbeTailscaleCandidatesDisabled() bool {
	return os.Getenv("DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES") == "1"
}
```

- [ ] **Step 5: Verify raw-direct public-only tests remain scoped to the test env**

In `pkg/session/external_v2_dataplane_test.go`, keep these tests scoped to `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`:

```go
func TestSelectExternalV2DataPacketAddrsFiltersObservedTailscaleInInternetOnlyMode(t *testing.T)
func TestSelectExternalV2DataPacketAddrsBySetFiltersObservedTailscaleInInternetOnlyMode(t *testing.T)
```

- [ ] **Step 6: Run focused tests**

Run:

```bash
go test ./pkg/session -run 'TestPublicProbeCandidateAllowed|TestPublicProbeCandidates|TestSelectExternalV2DataPacketAddrs.*Tailscale' -count=1
```

Expected: PASS.

- [ ] **Step 7: Run broader session package tests**

Run:

```bash
go test ./pkg/session -count=1
```

Expected: PASS.

- [ ] **Step 8: Checkpoint with GitButler if tests changed**

Run:

```bash
but status -fv
but commit -m "test: preserve tailscale test-only public mode"
```

Expected: if no files changed because the current tests already encode this behavior, skip the commit. If files changed, commit only `pkg/session/session_test.go` and `pkg/session/external_v2_dataplane_test.go`.

---

### Task 2: Emit Manager-Selected Direct Endpoint Diagnostics

**Files:**
- Modify: `pkg/session/types.go`
- Create: `pkg/session/external_path_debug_test.go`

- [ ] **Step 1: Write endpoint classification tests**

Create `pkg/session/external_path_debug_test.go`:

```go
package session

import "testing"

func TestExternalDirectEndpointClassifiesPublicPrivateAndTailscale(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "public", endpoint: "203.0.113.10:1234", want: "public"},
		{name: "private", endpoint: "192.168.1.10:1234", want: "private"},
		{name: "tailscale-cgnat", endpoint: "100.125.235.82:1234", want: "tailscale"},
		{name: "tailscale-ula", endpoint: "[fd7a:115c:a1e0::1]:1234", want: "tailscale"},
		{name: "invalid", endpoint: "not-an-endpoint", want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := externalDirectEndpointClass(tt.endpoint); got != tt.want {
				t.Fatalf("externalDirectEndpointClass(%q) = %q, want %q", tt.endpoint, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
go test ./pkg/session -run TestExternalDirectEndpointClassifiesPublicPrivateAndTailscale -count=1
```

Expected: FAIL with `undefined: externalDirectEndpointClass`.

- [ ] **Step 3: Implement endpoint classification and summary debug fields**

In `pkg/session/types.go`, add `net/netip` to imports:

```go
import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
```

In `emitTransportManagerSummaryLocked`, after the existing queue-depth debug lines and before the final path-state emission, insert:

```go
	if endpoint, active := manager.DirectPath(); active {
		e.emitter.Debug("transport-direct-path=" + endpoint)
		e.emitter.Debug("transport-direct-path-class=" + externalDirectEndpointClass(endpoint))
	}
```

Add this helper near `emitPositiveIntDebug`:

```go
func externalDirectEndpointClass(endpoint string) string {
	addrPort, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return "unknown"
	}
	addr := addrPort.Addr()
	switch {
	case publicProbeTailscaleCGNATPrefix.Contains(addr) || publicProbeTailscaleULAPrefix.Contains(addr):
		return "tailscale"
	case addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLoopback():
		return "private"
	default:
		return "public"
	}
}
```

- [ ] **Step 4: Run focused test**

Run:

```bash
go test ./pkg/session -run TestExternalDirectEndpointClassifiesPublicPrivateAndTailscale -count=1
```

Expected: PASS.

- [ ] **Step 5: Run session tests**

Run:

```bash
go test ./pkg/session -count=1
```

Expected: PASS.

- [ ] **Step 6: Checkpoint with GitButler**

Run:

```bash
but status -fv
but commit -m "session: report selected direct endpoint class"
```

Expected: checkpoint commit contains `pkg/session/types.go` and `pkg/session/external_path_debug_test.go`.

---

### Task 3: Let Manager-Backed QUIC Use Multiple Connections For Striped Transfers

**Files:**
- Modify: `pkg/dataplane/quic.go`
- Create: `pkg/dataplane/quic_test.go`

- [ ] **Step 1: Write failing fanout tests**

Create `pkg/dataplane/quic_test.go`:

```go
package dataplane

import (
	"testing"

	"github.com/shayne/derphole/pkg/quicpath"
)

func TestEndpointConnectionCountUsesStreamCountForManagerAdapter(t *testing.T) {
	path := packetPath{adapter: &quicpath.Adapter{}}

	if got := endpointConnectionCount(path, 4); got != 4 {
		t.Fatalf("endpointConnectionCount(manager adapter, 4) = %d, want 4", got)
	}
	if got := endpointConnectionCount(path, 0); got != 1 {
		t.Fatalf("endpointConnectionCount(manager adapter, 0) = %d, want 1", got)
	}
}

func TestEndpointConnectionCountKeepsSingleConnectionForDedicatedPacketPath(t *testing.T) {
	path := packetPath{}

	if got := endpointConnectionCount(path, 4); got != 1 {
		t.Fatalf("endpointConnectionCount(raw packet path, 4) = %d, want 1", got)
	}
}
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
go test ./pkg/dataplane -run TestEndpointConnectionCount -count=1
```

Expected: FAIL because `endpointConnectionCount` returns `1` for the manager adapter case.

- [ ] **Step 3: Implement manager adapter fanout**

In `pkg/dataplane/quic.go`, replace `endpointConnectionCount` with:

```go
func endpointConnectionCount(path packetPath, streams int) int {
	if streams < 1 {
		return 1
	}
	if path.adapter != nil {
		return streams
	}
	return 1
}
```

- [ ] **Step 4: Run focused tests**

Run:

```bash
go test ./pkg/dataplane -run TestEndpointConnectionCount -count=1
```

Expected: PASS.

- [ ] **Step 5: Run package tests and existing QUIC benchmarks**

Run:

```bash
go test ./pkg/dataplane ./pkg/transport ./pkg/quicpath -count=1
mise exec -- go test ./pkg/transport -run '^$' -bench 'Benchmark(NativeQUICLoopback|ManagerQUICLoopback)$' -benchtime=2s -count=3
```

Expected: tests PASS. Benchmark output should still include both native and manager loopback numbers; keep the numbers in the task handoff notes.

- [ ] **Step 6: Checkpoint with GitButler**

Run:

```bash
but status -fv
but commit -m "dataplane: fan out manager quic streams"
```

Expected: checkpoint commit contains `pkg/dataplane/quic.go` and `pkg/dataplane/quic_test.go`.

---

### Task 4: Add An Opt-In Raw-Direct Startup Budget

**Files:**
- Modify: `pkg/session/external_v2_dataplane.go`
- Create: `pkg/session/external_v2_startup_budget_test.go`

**Important:** Keep this opt-in first. Do not make it the default until the public WAN harness shows manager fallback is stable enough for the target use case.

- [ ] **Step 1: Write budget parser tests**

Create `pkg/session/external_v2_startup_budget_test.go`:

```go
package session

import (
	"testing"
	"time"
)

func TestExternalV2RawDirectStartupBudgetDefaultsOff(t *testing.T) {
	t.Setenv("DERPHOLE_V2_RAW_DIRECT_BUDGET_MS", "")

	if got := externalV2RawDirectStartupBudget(); got != 0 {
		t.Fatalf("externalV2RawDirectStartupBudget() = %s, want 0", got)
	}
}

func TestExternalV2RawDirectStartupBudgetParsesMilliseconds(t *testing.T) {
	t.Setenv("DERPHOLE_V2_RAW_DIRECT_BUDGET_MS", "850")

	if got, want := externalV2RawDirectStartupBudget(), 850*time.Millisecond; got != want {
		t.Fatalf("externalV2RawDirectStartupBudget() = %s, want %s", got, want)
	}
}

func TestExternalV2RawDirectStartupBudgetIgnoresInvalidValues(t *testing.T) {
	for _, value := range []string{"-1", "0", "abc"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("DERPHOLE_V2_RAW_DIRECT_BUDGET_MS", value)
			if got := externalV2RawDirectStartupBudget(); got != 0 {
				t.Fatalf("externalV2RawDirectStartupBudget() = %s with %q, want 0", got, value)
			}
		})
	}
}
```

- [ ] **Step 2: Run parser tests to verify failure**

Run:

```bash
go test ./pkg/session -run TestExternalV2RawDirectStartupBudget -count=1
```

Expected: FAIL with `undefined: externalV2RawDirectStartupBudget`.

- [ ] **Step 3: Implement parser**

In `pkg/session/external_v2_dataplane.go`, add this helper after `externalV2RawDirectEnabled`:

```go
func externalV2RawDirectStartupBudget() time.Duration {
	raw := strings.TrimSpace(os.Getenv("DERPHOLE_V2_RAW_DIRECT_BUDGET_MS"))
	if raw == "" {
		return 0
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}
```

- [ ] **Step 4: Run parser tests**

Run:

```bash
go test ./pkg/session -run TestExternalV2RawDirectStartupBudget -count=1
```

Expected: PASS.

- [ ] **Step 5: Wire budget into negotiation with safe manager fallback**

In `pkg/session/external_v2_dataplane.go`, add `errors` to imports:

```go
import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
```

Then replace the start of `negotiateExternalV2DirectPacketPath` with this structure. Keep the existing body inside the `negotiate` closure exactly as it is after the initial relay/raw-direct guard:

```go
func negotiateExternalV2DirectPacketPath(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, manager *transport.Manager, dm *tailcfg.DERPMap, auth externalPeerControlAuth, emitter *telemetry.Emitter, streamCount int, punchDelay time.Duration, relayOnly bool) (externalV2DirectPacketPath, error) {
	if relayOnly || !externalV2CanUseRawDirect(manager) {
		emitExternalV2Debug(emitter, "v2-data-plane=manager")
		return externalV2DirectPacketPath{}, nil
	}

	budget := externalV2RawDirectStartupBudget()
	if budget <= 0 {
		return negotiateExternalV2DirectPacketPathUnbounded(ctx, client, peerDERP, manager, dm, auth, emitter, streamCount, punchDelay)
	}

	budgetCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	path, err := negotiateExternalV2DirectPacketPathUnbounded(budgetCtx, client, peerDERP, manager, dm, auth, emitter, streamCount, punchDelay)
	if err == nil {
		return path, nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		emitExternalV2Debug(emitter, "v2-raw-direct-budget-expired-ms="+strconv.Itoa(int(budget/time.Millisecond)))
		emitExternalV2Debug(emitter, "v2-data-plane=manager")
		return externalV2DirectPacketPath{}, nil
	}
	return externalV2DirectPacketPath{}, err
}
```

Add the new helper immediately below it and move the old raw-direct negotiation body into this helper:

```go
func negotiateExternalV2DirectPacketPathUnbounded(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, manager *transport.Manager, dm *tailcfg.DERPMap, auth externalPeerControlAuth, emitter *telemetry.Emitter, streamCount int, punchDelay time.Duration) (externalV2DirectPacketPath, error) {
	var local externalV2DataPacketPath
	localRawDirect := false
	if externalV2RawDirectEnabled() {
		var ok bool
		local, ok = openExternalV2RawDirectLocal(ctx, dm, emitter, streamCount)
		localRawDirect = ok
	} else {
		emitExternalV2Debug(emitter, "v2-raw-direct-local=false disabled=true")
	}
	readyCh, unsubscribe := subscribeExternalV2DataPlaneReady(client, peerDERP)
	defer unsubscribe()

	peerReady, peerCandidates, err := exchangeExternalV2RawDirectPeer(ctx, client, peerDERP, readyCh, localRawDirect, local.candidates, local.candidateSets, auth, emitter)
	if err != nil {
		local.Close()
		return externalV2DirectPacketPath{}, err
	}
	path := selectExternalV2RawDirectPath(ctx, local, peerReady, peerCandidates, emitter, punchDelay)
	peerSelected, err := exchangeExternalV2RawDirectSelection(ctx, client, peerDERP, readyCh, path.raw, auth)
	if err != nil {
		path.Close()
		return externalV2DirectPacketPath{}, err
	}
	return finalizeExternalV2RawDirectPath(path, peerSelected, emitter), nil
}
```

- [ ] **Step 6: Run session tests**

Run:

```bash
go test ./pkg/session -run 'TestExternalV2RawDirectStartupBudget|TestExternalV2DataPlane|TestFinalizeExternalV2RawDirectPath' -count=1
go test ./pkg/session -count=1
```

Expected: PASS.

- [ ] **Step 7: Checkpoint with GitButler**

Run:

```bash
but status -fv
but commit -m "session: add raw direct startup budget"
```

Expected: checkpoint commit contains `pkg/session/external_v2_dataplane.go` and `pkg/session/external_v2_startup_budget_test.go`.

---

### Task 5: Add A Repeatable Public WAN Performance Harness

**Files:**
- Modify: `scripts/promotion-benchmark-driver.sh`
- Modify: `scripts/promotion_scripts_test.go`
- Create: `scripts/public-path-performance-harness.sh`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Write failing promotion driver env propagation test**

In `scripts/promotion_scripts_test.go`, add this test:

```go
func TestPromotionBenchmarkDriverPropagatesTransportExperimentEnv(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		"DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES",
		"DERPHOLE_V2_RAW_DIRECT",
		"DERPHOLE_V2_RAW_DIRECT_BUDGET_MS",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("promotion-benchmark-driver.sh missing remote env propagation for %s", want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
go test ./scripts -run TestPromotionBenchmarkDriverPropagatesTransportExperimentEnv -count=1
```

Expected: FAIL because `DERPHOLE_V2_RAW_DIRECT_BUDGET_MS` is not propagated yet.

- [ ] **Step 3: Propagate transport experiment env vars**

In `scripts/promotion-benchmark-driver.sh`, replace the existing Tailscale-only remote env block:

```bash
if [[ "${DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES:-}" == "1" ]]; then
  remote_env+=(DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1)
fi
```

with:

```bash
if [[ "${DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES:-}" == "1" ]]; then
  remote_env+=(DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1)
fi
if [[ -n "${DERPHOLE_V2_RAW_DIRECT:-}" ]]; then
  remote_env+=(DERPHOLE_V2_RAW_DIRECT="${DERPHOLE_V2_RAW_DIRECT}")
fi
if [[ -n "${DERPHOLE_V2_RAW_DIRECT_BUDGET_MS:-}" ]]; then
  remote_env+=(DERPHOLE_V2_RAW_DIRECT_BUDGET_MS="${DERPHOLE_V2_RAW_DIRECT_BUDGET_MS}")
fi
```

- [ ] **Step 4: Run promotion script test**

Run:

```bash
go test ./scripts -run TestPromotionBenchmarkDriverPropagatesTransportExperimentEnv -count=1
```

Expected: PASS.

- [ ] **Step 5: Create the harness script**

Create `scripts/public-path-performance-harness.sh` with executable permissions:

```bash
#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

target="${1:-derphole-testing}"
remote_user="${DERPHOLE_REMOTE_USER:-ubuntu}"
size_mib="${DERPHOLE_PUBLIC_PATH_SIZE_MIB:-128}"
iperf_port="${DERPHOLE_PUBLIC_IPERF_PORT:-8321}"
log_dir="${DERPHOLE_BENCH_LOG_DIR:-.tmp/public-path-performance}"
remote="${remote_user}@${target}"

mkdir -p "${log_dir}"

public_ip() {
  curl -4fsS --max-time 8 https://ifconfig.me/ip
}

run_iperf_reverse() {
  local ip="$1"
  local out="${log_dir}/iperf3-${target}-to-local.json"
  iperf3 -s -p "${iperf_port}" --one-off --forceflush >"${log_dir}/iperf3-server.log" 2>&1 &
  local server_pid="$!"
  trap 'kill "${server_pid}" 2>/dev/null || true' RETURN
  sleep 1
  ssh -o BatchMode=yes "${remote}" "iperf3 -c '${ip}' -p '${iperf_port}' -t 20 -P 4 --json" >"${out}"
  wait "${server_pid}" || true
  trap - RETURN
  python3 - <<'PY' "${out}"
import json, sys
path = sys.argv[1]
with open(path) as f:
    payload = json.load(f)
bits = payload["end"]["sum_received"]["bits_per_second"]
rtts = [
    stream["sender"].get("mean_rtt", 0)
    for stream in payload["end"]["streams"]
    if stream.get("sender")
]
mean_rtt_ms = (sum(rtts) / len(rtts) / 1000) if rtts else 0
print(f"iperf_reverse_received_mbps={bits / 1_000_000:.2f}")
print(f"iperf_reverse_mean_rtt_ms={mean_rtt_ms:.2f}")
PY
}

run_derphole() {
  local direction="$1"
  local raw_direct="$2"
  local budget_ms="$3"
  local script="./scripts/promotion-test.sh"
  if [[ "${direction}" == "reverse" ]]; then
    script="./scripts/promotion-test-reverse.sh"
  fi

  echo "derphole_direction=${direction} raw_direct=${raw_direct} budget_ms=${budget_ms}"
  DERPHOLE_REMOTE_USER="${remote_user}" \
  DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
  DERPHOLE_V2_RAW_DIRECT="${raw_direct}" \
  DERPHOLE_V2_RAW_DIRECT_BUDGET_MS="${budget_ms}" \
  DERPHOLE_BENCH_LOG_DIR="${log_dir}" \
    "${script}" "${target}" "${size_mib}"
}

main() {
  local ip
  ip="$(public_ip)"
  echo "public_ip=${ip}"
  ssh -o BatchMode=yes "${remote}" "command -v iperf3 >/dev/null || (sudo -n true && sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iperf3)"
  run_iperf_reverse "${ip}"
  run_derphole reverse 1 0
  run_derphole forward 1 0
  run_derphole reverse 0 0
  run_derphole reverse 1 850
}

main "$@"
```

Run:

```bash
chmod +x scripts/public-path-performance-harness.sh
```

- [ ] **Step 6: Run shell syntax check**

Run:

```bash
bash -n scripts/public-path-performance-harness.sh
```

Expected: PASS with no output.

- [ ] **Step 7: Add benchmark docs**

Append this section to `docs/benchmarks.md`:

````markdown
## Public Path Performance Harness

Use this harness when investigating high-RTT derphole transfer performance against the UK test VM:

```bash
DERPHOLE_REMOTE_USER=ubuntu ./scripts/public-path-performance-harness.sh derphole-testing
```

The harness forces public Internet candidates with `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`, runs an `iperf3` reverse baseline against local WAN port `8321`, then runs derphole forward, reverse, forced-manager, and startup-budget cases. Treat raw-direct reverse goodput within roughly 20 percent of the `iperf3` reverse result as healthy for the UK path. Treat manager-path no-progress gaps above 5 seconds or manager goodput below half of the raw-direct reverse result as a regression candidate.
````

- [ ] **Step 8: Run docs and script checks**

Run:

```bash
bash -n scripts/public-path-performance-harness.sh
go test ./scripts -run 'TestPromotionBenchmarkDriverPropagatesTransportExperimentEnv|Test.*Harness|Test.*Script' -count=1
```

Expected: `bash -n` PASS and the selected script tests PASS.

- [ ] **Step 9: Checkpoint with GitButler**

Run:

```bash
but status -fv
but commit -m "scripts: add public path performance harness"
```

Expected: checkpoint commit contains `scripts/promotion-benchmark-driver.sh`, `scripts/promotion_scripts_test.go`, `scripts/public-path-performance-harness.sh`, and `docs/benchmarks.md`.

---

### Task 6: WAN Validation And Release-Gate Verification

**Files:**
- No planned source modifications. Use this task to validate and record results.

- [ ] **Step 1: Run focused package tests**

Run:

```bash
go test ./pkg/session ./pkg/dataplane ./pkg/transport ./pkg/quicpath -count=1
```

Expected: PASS.

- [ ] **Step 2: Run repo test suite**

Run:

```bash
mise run test
```

Expected: PASS.

- [ ] **Step 3: Run hook check**

Run:

```bash
mise run check:hooks
```

Expected: PASS. If hooks fail, fix only files touched by this plan and rerun the failing hook command.

- [ ] **Step 4: Run public WAN harness against the UK VM**

Run:

```bash
DERPHOLE_REMOTE_USER=ubuntu DERPHOLE_BENCH_LOG_DIR=.tmp/public-path-performance ./scripts/public-path-performance-harness.sh derphole-testing
```

Expected:

- `iperf_reverse_received_mbps` is printed.
- Raw-direct reverse selected public endpoints, not `100.64.0.0/10`.
- Raw-direct reverse goodput is in the same broad range as the `iperf3` reverse result.
- Forced-manager reverse does not show a no-progress gap above 5 seconds in sender or receiver traces.
- Startup-budget case prints `v2-raw-direct-budget-expired-ms=850` only when raw-direct negotiation exceeds the configured budget.

- [ ] **Step 5: Summarize trace files**

Run:

```bash
python3 - <<'PY'
import csv, glob, os, re
for path in sorted(glob.glob(".tmp/public-path-performance/*-sender.trace.csv")):
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            row["_elapsed"] = int(row.get("elapsed_ms") or 0)
            row["_app"] = int(row.get("app_bytes") or 0)
            row["_delta"] = int(row.get("delta_app_bytes") or 0)
            row["_mbps"] = float(row.get("app_mbps") or 0)
            rows.append(row)
    first = next((r for r in rows if r["_app"] > 0), None)
    complete = next((r for r in rows if r.get("phase") == "complete"), rows[-1])
    post = [r for r in rows if first and r["_elapsed"] >= first["_elapsed"] and r.get("phase") != "complete"]
    zero_runs, cur = [], []
    for r in post:
        if r["_delta"] == 0:
            cur.append(r)
        elif cur:
            zero_runs.append(cur)
            cur = []
    if cur:
        zero_runs.append(cur)
    longest = max(zero_runs, key=len) if zero_runs else []
    long_sec = 0.0
    if longest:
        long_sec = max(0, longest[-1]["_elapsed"] - longest[0]["_elapsed"]) / 1000.0 + 0.5
    dur_s = max((complete["_elapsed"] - (first["_elapsed"] if first else 0)) / 1000, 0.001)
    avg = (complete["_app"] * 8 / 1_000_000) / dur_s if first else 0
    peak = max((r["_mbps"] for r in post), default=0)
    log = path.replace("-sender.trace.csv", "-sender.log")
    txt = open(log, errors="ignore").read() if os.path.exists(log) else ""
    plane = re.findall(r"v2-data-plane=([^\n]+)", txt)
    direct_class = re.findall(r"transport-direct-path-class=([^\n]+)", txt)
    print(f"{os.path.basename(path)} plane={plane[-1] if plane else '?'} direct_class={direct_class[-1] if direct_class else '?'} avg_from_first={avg:.1f}Mbps peak={peak:.1f}Mbps longest_zero={long_sec:.1f}s")
PY
```

Expected: summary lines for each derphole case. No public-mode line should report `direct_class=tailscale`.

- [ ] **Step 6: Full check**

Run:

```bash
mise run check
```

Expected: PASS.

- [ ] **Step 7: Final GitButler checkpoint**

Run:

```bash
but status -fv
but commit -m "perf: improve derphole public path reliability"
```

Expected: if all previous task checkpoints were already committed, this command should report no new changes or create no new commit. If verification fixes changed tracked files, it creates one final checkpoint containing only those fixes.

## Acceptance Criteria

- Product candidate discovery still allows Tailscale CGNAT and Tailscale ULA by default.
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` remains the test and benchmark switch for forcing public-only behavior.
- Public-path benchmark scripts set `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` locally and on the remote benchmark process.
- Verbose transfer logs include `transport-direct-path=` and `transport-direct-path-class=` when the manager path ends direct.
- Raw-direct verbose logs continue to include `v2-raw-direct-selected-addrs=` and `v2-data-plane=raw-direct`.
- Manager-backed QUIC uses more than one QUIC connection when v2 asks for multiple streams through the manager adapter.
- `DERPHOLE_V2_RAW_DIRECT_BUDGET_MS=850` can reduce startup delay by falling back to manager path if raw-direct negotiation exceeds 850 ms.
- UK public-path harness completes and records `iperf3`, raw-direct forward, raw-direct reverse, forced-manager reverse, and startup-budget reverse cases.
- Raw-direct reverse derphole goodput is at least 80 percent of the same-run `iperf3` reverse received bitrate, or the run records a concrete network-level reason for lower throughput.
- Forced-manager reverse goodput is at least 50 percent of raw-direct reverse goodput and has no sender or receiver no-progress window above 5 seconds.
- No tracked generated `dist/` or `.tmp/` artifacts are committed.

## Self-Review Notes

- Spec coverage: the plan covers the Tailscale public-path requirement, performance/reliability investigation follow-up, a repeatable harness, and validation against `derphole-testing`.
- Placeholder scan: commands use concrete paths and hostnames; code snippets include concrete functions and tests.
- Type consistency: helper names are consistent across tasks: `truthyEnv`, `externalDirectEndpointClass`, `endpointConnectionCount`, and `externalV2RawDirectStartupBudget`.
