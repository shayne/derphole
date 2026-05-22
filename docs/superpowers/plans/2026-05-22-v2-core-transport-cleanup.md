# V2 Core Transport Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the v2 QUIC session transport the only production transport for file transfer and derptun, then delete inferior legacy UDP, native TCP, QUIC-mode, handoff, and WireGuard paths.

**Architecture:** Keep `pkg/transport`, `pkg/quicpath`, `pkg/dataplane`, and the v2 control envelopes as the shared substrate. Route `send/listen/offer/receive` and `derptun` through QUIC streams over that substrate. Remove app-layer transport selectors and old direct transport implementations so relay/direct behavior is owned by one manager-backed or raw-direct QUIC data plane.

**Tech Stack:** Go, quic-go, DERP control through `pkg/derpbind`, direct path management through `pkg/transport`, repo gates through `mise`.

---

## File Structure

- `pkg/session/external.go`: keep shared control envelope auth, candidate gathering, relay-session setup, abort/progress helpers, and public `sendExternal`/`listenExternal`; remove legacy selector constants, legacy envelope fields, native TCP, QUIC-mode, and handoff helpers.
- `pkg/session/external_v2.go`: keep send/listen v2 file transfer over QUIC streams; remove `DERPHOLE_V2_NATIVE_TCP` handling and any call to old QUIC-mode/native TCP negotiation.
- `pkg/session/external_v2_offer.go`: keep offer/receive v2 file transfer over QUIC streams; remove native TCP and QUIC-mode negotiation.
- `pkg/session/external_v2_dataplane.go`: keep raw-direct consensus and manager-backed QUIC fallback; host any v2-specific direct-path watcher currently stranded in old direct QUIC code.
- `pkg/session/external_transfer_metrics.go`: keep v2 metrics and remove old `directquic.Stats` storage if no production v2 path uses it.
- Delete legacy production files once references are gone: `pkg/session/external_direct_transport.go`, `pkg/session/external_transfer_protocol.go`, `pkg/session/external_direct_udp.go`, `pkg/session/external_direct_quic.go`, `pkg/session/external_native_tcp.go`, `pkg/session/external_native_quic.go`, `pkg/session/external_handoff.go`, `pkg/session/external_wg.go`, and tests that only validate those removed paths.
- `pkg/session/derptun.go`: keep QUIC stream tunnel behavior; ensure no WireGuard or netstack import remains in supported derptun commands.
- `pkg/probe`, `cmd/derphole-probe`: remove WireGuard and direct-UDP benchmark modes that only preserve old product paths; keep diagnostics that exercise the current v2/transport/quicpath stack.
- `scripts/transfer-stall-harness.sh`, `scripts/direct-udp-diagnostic-benchmark.sh`, `scripts/*direct_udp*`: remove or rewrite references to `DERPHOLE_DIRECT_TRANSPORT` and old direct UDP product modes.
- `go.mod`, `go.sum`: drop WireGuard/netstack dependencies after imports are removed.
- `docs/benchmarks.md` and release notes if needed: document the supported v2/QUIC gates and remove obsolete selector guidance.

## Task 1: Plan Checkpoint Commit

**Files:**
- Create: `docs/superpowers/plans/2026-05-22-v2-core-transport-cleanup.md`

- [ ] **Step 1: Verify branch and pushed baseline**

Run: `git status --short --branch`

Expected: `## main...origin/main` with no local ahead count before implementation commits.

- [ ] **Step 2: Commit the plan**

Run:

```bash
git add docs/superpowers/plans/2026-05-22-v2-core-transport-cleanup.md
git commit -m "docs: plan v2 core transport cleanup"
git push origin main
```

Expected: commit succeeds and `main` pushes.

## Task 2: Collapse File Transfer Entry Points To V2 Only

**Files:**
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/offer.go`
- Delete: `pkg/session/external_transfer_protocol.go`
- Delete: `pkg/session/external_transfer_protocol_test.go`
- Delete: `pkg/session/external_direct_transport.go`
- Delete: `pkg/session/external_direct_transport_test.go`

- [ ] **Step 1: Write/adjust selector tests**

In the existing session tests that stub `sendExternalViaV2Fn`, `listenExternalViaV2Fn`, `offerExternalViaV2Fn`, and `receiveExternalOfferViaV2Fn`, set `DERPHOLE_TRANSFER_PROTOCOL=legacy` and `DERPHOLE_DIRECT_TRANSPORT=blast` and assert the v2 function is still called. The test body shape should be:

```go
t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "legacy")
t.Setenv("DERPHOLE_DIRECT_TRANSPORT", "blast")
called := false
old := sendExternalViaV2Fn
sendExternalViaV2Fn = func(context.Context, SendConfig) error {
	called = true
	return nil
}
t.Cleanup(func() { sendExternalViaV2Fn = old })
if err := sendExternal(context.Background(), SendConfig{Token: validV2Token}); err != nil {
	t.Fatal(err)
}
if !called {
	t.Fatal("sendExternal did not use v2")
}
```

Use the repository's existing token/test helpers instead of inventing a new token generator.

- [ ] **Step 2: Run the failing selector tests**

Run: `go test ./pkg/session -run 'Test.*External.*V2|Test.*TransferProtocol|Test.*DirectTransport' -count=1`

Expected before implementation: at least one legacy-selector test fails or obsolete tests fail to compile once the deleted behavior is asserted as unsupported.

- [ ] **Step 3: Simplify entry points**

Change `sendExternal`, `listenExternal`, `OfferExternal`, and `ReceiveExternalOffer` so they call only the v2 functions. Remove `externalTransferProtocolFromEnv` and `externalDirectTransportFromEnv` callers. The intended shape is:

```go
func sendExternal(ctx context.Context, cfg SendConfig) error {
	return sendExternalViaV2Fn(ctx, cfg)
}

func listenExternal(ctx context.Context, cfg ListenConfig) (string, error) {
	return listenExternalViaV2Fn(ctx, cfg)
}
```

For offer/receive, preserve existing token routing only if it distinguishes supported v2 offer tokens from unsupported tokens. Do not route to a legacy transfer implementation.

- [ ] **Step 4: Delete selector files**

Run:

```bash
rm pkg/session/external_transfer_protocol.go pkg/session/external_transfer_protocol_test.go
rm pkg/session/external_direct_transport.go pkg/session/external_direct_transport_test.go
```

Expected: `rg 'DERPHOLE_TRANSFER_PROTOCOL|DERPHOLE_DIRECT_TRANSPORT|externalDirectTransport|externalTransferProtocol' pkg/session cmd scripts docs` finds no production selector references except historical specs.

- [ ] **Step 5: Run package tests and commit**

Run:

```bash
go test ./pkg/session -run 'Test.*External.*V2|Test.*Offer|Test.*Receive' -count=1
go test ./cmd/derphole ./cmd/derptun -count=1
```

Expected: tests pass.

Commit:

```bash
git add pkg/session cmd scripts docs
git commit -m "session: make v2 transfer the only entry point"
git push origin main
```

## Task 3: Remove Native TCP And QUIC-Mode Negotiation From V2

**Files:**
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/external_v2.go`
- Modify: `pkg/session/external_v2_offer.go`
- Modify: `pkg/session/external_v2_protocol.go`
- Delete: `pkg/session/external_native_tcp.go`
- Delete: `pkg/session/external_native_tcp_test.go`
- Delete: `pkg/session/external_bootstrap.go`
- Delete: `pkg/session/external_bootstrap_test.go`
- Delete: `pkg/session/external_quic_mode_test.go`

- [ ] **Step 1: Add a regression test for ignored native TCP env**

Add a v2-focused test that sets `DERPHOLE_V2_NATIVE_TCP=1`, stubs the QUIC stream path, and asserts no QUIC-mode subscription/request path is used. The desired assertion is that v2 still chooses `v2-data-plane=raw-direct` or `v2-data-plane=manager`, never `v2-native-tcp=true`.

- [ ] **Step 2: Run the failing test**

Run: `go test ./pkg/session -run 'TestExternalV2.*NativeTCP|TestExternalV2.*DataPlane' -count=1`

Expected before implementation: legacy native TCP tests still compile and the new assertion exposes current native TCP handling.

- [ ] **Step 3: Remove v2 native TCP branches**

In `pkg/session/external_v2.go`, delete:

```go
if handled, err := rt.sendNativeTCP(...); handled || err != nil { ... }
modeCh, unsubscribeMode := rt.subscribeNativeModeRequests(...)
if handled, nativeBytesReceived, err := rt.receiveNativeTCP(...); handled || err != nil { ... }
func (rt *externalV2SendRuntime) sendNativeTCP(...)
func (rt *externalV2ListenRuntime) subscribeNativeModeRequests(...)
func (rt *externalV2ListenRuntime) receiveNativeTCP(...)
func externalV2NativeTCPAuth(...)
func externalV2NativeTCPEnabled() bool
```

In `pkg/session/external_v2_offer.go`, delete equivalent offer/receive native TCP helpers and subscriptions.

- [ ] **Step 4: Remove QUIC-mode and native TCP envelope surface**

From `pkg/session/external.go`, remove:

```go
envelopeQUICModeReq
envelopeQUICModeResp
envelopeQUICModeAck
envelopeQUICModeReady
QUICModeReq *quicModeRequest
QUICModeResp *quicModeResponse
QUICModeAck *quicModeAck
QUICModeReady *quicModeReady
```

Then remove associated functions and types: `quicModeRequest`, `quicModeResponse`, `quicModeAck`, `quicModeReady`, `requestExternalQUICMode`, `requestExternalTCPMode`, `acceptExternalQUICMode`, `receiveQUICMode*`, `isQUICMode*Payload`, and native TCP copy/dial/listen helpers.

- [ ] **Step 5: Delete native TCP files**

Run:

```bash
rm pkg/session/external_native_tcp.go pkg/session/external_native_tcp_test.go
rm pkg/session/external_bootstrap.go pkg/session/external_bootstrap_test.go
rm pkg/session/external_quic_mode_test.go
```

Expected: `rg 'NativeTCP|native_tcp|QUICMode|DERPHOLE_V2_NATIVE_TCP|externalNativeTCP|externalQUICMode' pkg/session` returns no production references.

- [ ] **Step 6: Run package tests and commit**

Run:

```bash
go test ./pkg/session -run 'TestExternalV2|TestDerptun|TestOffer|TestReceive' -count=1
go test ./pkg/dataplane ./pkg/quicpath ./pkg/transport -count=1
```

Expected: tests pass.

Commit:

```bash
git add pkg/session pkg/dataplane pkg/quicpath pkg/transport
git commit -m "session: remove native tcp transfer negotiation"
git push origin main
```

## Task 4: Delete Legacy Direct UDP, Handoff, And Old Direct QUIC Transfer Code

**Files:**
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/external_v2.go`
- Modify: `pkg/session/external_v2_offer.go`
- Modify: `pkg/session/external_v2_dataplane.go`
- Modify: `pkg/session/external_transfer_metrics.go`
- Delete: `pkg/session/external_direct_udp.go`
- Delete: `pkg/session/external_direct_udp_test.go`
- Delete: `pkg/session/external_direct_udp_helpers_test.go`
- Delete: `pkg/session/external_direct_quic.go`
- Delete: `pkg/session/external_direct_quic_test.go`
- Delete: `pkg/session/external_native_quic.go`
- Delete: `pkg/session/external_native_quic_test.go`
- Delete: `pkg/session/external_handoff.go`
- Delete: `pkg/session/external_handoff_test.go`

- [ ] **Step 1: Move the direct-path watcher into v2**

Add this helper to `pkg/session/external_v2_dataplane.go` and replace every `externalDirectQUICWatchDirectPath` call with `externalV2WatchDirectPath`:

```go
func externalV2WatchDirectPath(ctx context.Context, manager *transport.Manager, metrics *externalTransferMetrics) func() {
	if manager == nil || metrics == nil {
		return func() {}
	}
	watchCtx, cancel := context.WithCancel(ctx)
	go func() {
		if manager.PathState() == transport.PathDirect {
			metrics.MarkDirectValidated(time.Now())
			return
		}
		for update := range manager.Updates(watchCtx) {
			if update.Path == transport.PathDirect {
				metrics.MarkDirectValidated(time.Now())
				return
			}
		}
	}()
	return cancel
}
```

Ensure `external_v2_dataplane.go` imports `time` and `github.com/shayne/derphole/pkg/transport` as needed.

- [ ] **Step 2: Remove old direct QUIC stats from metrics**

If `pkg/session/external_transfer_metrics.go` still imports `pkg/directquic`, delete the directquic-specific stats field and the `externalDirectQUICGoodputMbps` helper. Keep v2 QUIC stream byte/rate metrics sourced from `RecordDirectQUICSend`, `RecordDirectQUICReceive`, and `transport.Manager`.

- [ ] **Step 3: Remove legacy envelope fields**

From `pkg/session/external.go`, remove direct UDP and parallel grow envelope constants and struct fields:

```go
envelopeDirectUDPReady
envelopeDirectUDPReadyAck
envelopeDirectUDPStart
envelopeDirectUDPStartAck
envelopeDirectUDPRateProbe
envelopeParallelGrowReq
envelopeParallelGrowAck
envelopeParallelGrowResult
DirectUDPReadyAck
DirectUDPStart
DirectUDPRateProbe
ParallelGrowReq
ParallelGrowAck
ParallelGrowResult
```

Then delete associated payload structs and `isDirectUDP*Payload`/`isParallelGrow*Payload` helpers.

- [ ] **Step 4: Delete legacy direct files**

Run:

```bash
rm pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go pkg/session/external_direct_udp_helpers_test.go
rm pkg/session/external_direct_quic.go pkg/session/external_direct_quic_test.go
rm pkg/session/external_native_quic.go pkg/session/external_native_quic_test.go
rm pkg/session/external_handoff.go pkg/session/external_handoff_test.go
```

Expected: `rg 'DirectUDP|direct_udp|direct-udp|externalDirectUDP|externalDirectQUIC|externalNativeQUIC|externalHandoff|ParallelGrow' pkg/session` returns no production references.

- [ ] **Step 5: Run focused tests and commit**

Run:

```bash
go test ./pkg/session -run 'TestExternalV2|TestDerptun|TestOffer|TestReceive|TestParallel' -count=1
go test ./pkg/dataplane ./pkg/quicpath ./pkg/transport ./pkg/transfertrace -count=1
```

Expected: tests pass.

Commit:

```bash
git add pkg/session pkg/dataplane pkg/quicpath pkg/transport pkg/transfertrace
git commit -m "session: delete legacy direct transfer paths"
git push origin main
```

## Task 5: Remove WireGuard/Netstack Runtime And Old Probe Modes

**Files:**
- Modify: `pkg/probe/*.go`
- Modify: `cmd/derphole-probe/*.go`
- Delete: `pkg/session/external_wg.go`
- Delete: `pkg/session/external_wg_test.go`
- Delete: `pkg/wg/`
- Delete: `pkg/probe/wg*.go`
- Delete or update: `pkg/probe/*wg*_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Verify derptun does not import WireGuard**

Run: `go list -deps ./cmd/derptun | rg 'wireguard|gvisor|pkg/wg'`

Expected before deletion: old diagnostic deps may still appear through probe metadata, but `cmd/derptun` runtime should not require `pkg/wg`.

- [ ] **Step 2: Delete session WG transfer path**

Run:

```bash
rm pkg/session/external_wg.go pkg/session/external_wg_test.go
```

Expected: `rg 'WGTunnel|externalWG|sendExternalViaWGTunnel|listenExternalViaWGTunnel' pkg/session` returns no references.

- [ ] **Step 3: Remove probe WireGuard modes**

Delete `pkg/probe/wg*.go` and remove WireGuard mode options from `cmd/derphole-probe` and `pkg/probe/orchestrator.go`. Keep UDP/TCP/QUIC diagnostics only when they exercise the current manager/raw-direct/v2 stack. The accepted modes after cleanup must not include `wireguard`, `wg`, `wg-os`, or `wg-iperf`.

- [ ] **Step 4: Remove WG package and tidy deps**

Run:

```bash
rm -rf pkg/wg
go mod tidy
```

Expected:

```bash
go list -deps ./... | rg 'github.com/tailscale/wireguard-go|gvisor.dev/gvisor|github.com/shayne/derphole/pkg/wg'
```

returns no output, unless an unrelated upstream dependency still imports a platform-only package that is not linked into derphole.

- [ ] **Step 5: Run probe and derptun tests and commit**

Run:

```bash
go test ./cmd/derphole-probe ./pkg/probe ./cmd/derptun ./pkg/session -count=1
go test ./... -run 'TestDerptun|TestProbe|TestOrchestrate|TestTopology' -count=1
```

Expected: tests pass.

Commit:

```bash
git add cmd/derphole-probe pkg/probe pkg/session pkg/wg go.mod go.sum
git commit -m "probe: remove wireguard legacy modes"
git push origin main
```

## Task 6: Clean Scripts, Dep-Aware Snapshots, And Documentation

**Files:**
- Modify/delete: `scripts/transfer-stall-harness.sh`
- Modify/delete: `scripts/direct-udp-diagnostic-benchmark.sh`
- Modify/delete: `scripts/direct_udp_diagnostic_benchmark_script_test.go`
- Modify: `docs/benchmarks.md`
- Modify: `cmd/derphole/depaware.txt`
- Modify: `cmd/derptun/depaware.txt`
- Modify: `cmd/derphole-probe/depaware.txt`

- [ ] **Step 1: Remove obsolete env and script references**

Run: `rg 'DERPHOLE_DIRECT_TRANSPORT|DERPHOLE_TRANSFER_PROTOCOL|direct_udp|direct-udp|WireGuard|wireguard|externalNativeTCP|DERPHOLE_V2_NATIVE_TCP' scripts docs cmd pkg`

Expected before cleanup: only historical specs and this plan should still mention removed concepts.

- [ ] **Step 2: Update scripts**

Remove old direct UDP benchmark scripts if they cannot target the v2 QUIC transport. Keep transfer harness scripts only if they invoke normal `derphole send/receive`, force relay with the supported flag/env, and emit v2 telemetry.

- [ ] **Step 3: Update dep-aware outputs**

Run the existing dep-aware generator if present. If no generator exists, remove stale `pkg/wg`, WireGuard, gVisor, native TCP, and direct UDP references from `cmd/*/depaware.txt` after validating `go list -deps ./cmd/...`.

- [ ] **Step 4: Run docs/script tests and commit**

Run:

```bash
go test ./scripts ./cmd/derphole ./cmd/derptun ./cmd/derphole-probe -count=1
go test ./pkg/transfertrace ./pkg/session -count=1
```

Expected: tests pass.

Commit:

```bash
git add scripts docs cmd pkg
git commit -m "docs: remove legacy transport guidance"
git push origin main
```

## Task 7: Full Local Verification Gate

**Files:**
- No planned source edits unless verification exposes failures.

- [ ] **Step 1: Run formatting and tidy**

Run:

```bash
gofmt -w cmd pkg
go mod tidy
git diff --check
```

Expected: no whitespace errors.

- [ ] **Step 2: Run quality gates**

Run:

```bash
mise run test
mise run vet
mise run check:hooks
mise run build
mise run smoke-local
```

Expected: all pass. If a gate fails, use systematic debugging: reproduce the smallest failing command, inspect cause, fix, rerun the narrow command, then rerun the failed gate.

- [ ] **Step 3: Commit any verification fixes**

Commit any fixes with scoped messages and push:

```bash
git add .
git commit -m "test: stabilize v2 transport cleanup gates"
git push origin main
```

Skip this step if there are no changes.

## Task 8: Live E2E Verification

**Files:**
- No planned source edits unless live testing exposes failures.

- [ ] **Step 1: Local Mac to pve1 direct transfer**

Run from this Mac and `ssh root@pve1` using the latest local build, with Tailscale candidate filtering enabled only for the test:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./dist/derphole --verbose send ~/1GBFile
./dist/derphole --verbose receive <token>
```

Expected: `v2-data-plane=raw-direct` or `v2-data-plane=manager` with direct bytes increasing; transfer completes; Ctrl-C on either side terminates the peer promptly.

- [ ] **Step 2: pve1 to canlxc benchmark comparison**

Run iperf3 baseline first, then derphole:

```bash
iperf3 -c <canlxc-or-forwarded-host> --port 8321
REMOTE_HOST=<canlxc-host> mise run promotion-1g
```

Expected: derphole completes and telemetry explains any gap versus iperf3 with data-plane, direct bytes, relay bytes, and goodput.

- [ ] **Step 3: Current exe host relay/direct behavior**

Use the current exe test endpoint `ssh lotus-stalemate.exe.xyz` or the latest user-provided replacement if it changes during execution:

```bash
REMOTE_HOST=lotus-stalemate.exe.xyz mise run smoke-remote
REMOTE_HOST=lotus-stalemate.exe.xyz mise run smoke-remote-share
```

Expected: relay fallback works, direct upgrade works when reachable, and failures do not hang.

- [ ] **Step 4: Leak checks**

After live tests, run:

```bash
pgrep -fl 'derphole|derptun'
lsof -nP -iUDP | rg 'derphole|derptun'
```

Expected: no leftover test processes or UDP sockets except commands intentionally still running.

- [ ] **Step 5: Final commit and push**

If live testing required source fixes, commit and push them. Then run:

```bash
git status --short --branch
```

Expected: `## main...origin/main` with a clean worktree.

## Self-Review

- Spec coverage: Tasks 2-4 make v2 the only file-transfer path and delete UDP/native TCP/QUIC-mode/handoff selectors. Task 5 removes WireGuard/netstack runtime and old probe modes. Tasks 7-8 cover local and live E2E gates, abort behavior, and leak checks.
- Placeholder scan: No implementation step depends on "TBD" or unspecified tests; where existing helpers are required, the plan names the exact helper class and expected behavior.
- Type consistency: The plan consistently uses existing `SendConfig`, `ListenConfig`, `OfferConfig`, `ReceiveConfig`, `transport.Manager`, `externalTransferMetrics`, and v2 runtime type names from the current codebase.
