# Send/Receive Public Bulk Throughput Correction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make normal file `send`/`receive` choose the fast bulk packet path for compact long-haul receivers, eliminate abandoned manager traffic after raw-direct activation, correct terminal progress accounting, and prove the result with three public-only 3 GiB file transfers.

**Architecture:** Replace acceptor-based transfer-mode selection with a receiver-aware policy that ignores Tailscale candidates for policy counting but leaves production route discovery unchanged. Give the v2 file transport an idempotent raw-direct activation hook that stops manager probing only after both peers finalize raw-direct. Make the promotion harness default to actual file `send`/`receive`, record the negotiated mode, and retain `listen`/`pipe` as an explicitly labeled stream control.

**Tech Stack:** Go 1.26.5 through `mise`, Bash, GitButler, QUIC via `quic-go`, raw UDP bulk packets, CSV transfer traces, `transfertracecheck`, SSH, and TCP `iperf3` on port 8123.

## Global Constraints

- Normal file `send`/`receive` is the primary product and benchmark workload.
- Production discovery continues to allow Tailscale; only public-Internet acceptance runs set `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` on both peers.
- Users need no performance flags. Existing protocol names `blocks-v1` and `bulk-packets-v1` remain wire-compatible.
- A compact file receiver selects bulk regardless of whether it is claimant or acceptor; a receiver with at least five non-Tailscale candidates keeps QUIC.
- Invalid candidate strings force the conservative QUIC policy.
- Stop manager reads, punches, nudges, and reseeds only after raw-direct is finalized. Preserve manager QUIC fallback when raw-direct is unavailable.
- Remove blast-era or duplicate lifecycle code only when no supported fallback or compatibility path uses it.
- Sender elapsed time and rate use the same clock; never clear a valid receiver clock with a terminal zero-elapsed update.
- Every production change follows red-green-refactor. Run the named failing test before writing its implementation.
- Use GitButler for branch, commit, squash, and branch-push operations. Do not publish until all local and live gates pass.
- Preserve unrelated user or agent work. Stop if `but pull --check` reports overlap or conflicts.

---

## File Structure

### Modify

- `pkg/session/external_v2_block.go` — receiver-aware bulk policy and policy telemetry.
- `pkg/session/external_v2_protocol_test.go` — role-invariant, Tailscale-noise, invalid-candidate, capability, and fast-server policy tests.
- `pkg/session/external_v2.go` — claimant send/listen policy call site and shared file-transport raw activation lifecycle.
- `pkg/session/external_v2_offer.go` — offer send/receive policy call site, raw activation, and terminal progress fix.
- `pkg/session/external_v2_raw_direct.go` — replace blast-era activation wrappers with an idempotent current-v2 activation helper.
- `pkg/session/session_test.go` — activation idempotence and punch-loop cancellation tests.
- `pkg/session/external_v2_block_test.go` — normal offer/receive and inverse-topology transfer-mode integration coverage.
- `pkg/derphole/progress.go` — use external elapsed for both displayed elapsed and rate when it covers the full payload.
- `pkg/derphole/progress_test.go` — coherent final clock and stale-partial fallback tests.
- `scripts/promotion-benchmark-driver.sh` — file workload, stream control workload, mode extraction, and footer fields.
- `scripts/public-path-performance-harness.sh` — workload/mode summary columns and public file defaults.
- `scripts/promotion_scripts_test.go` — executable/source contract tests for the new benchmark topology.
- `docs/benchmarks.md` — distinguish file and stream workloads and document the acceptance commands.
- `docs/superpowers/specs/2026-07-11-send-receive-public-bulk-design.md` — factual correction for malformed candidates.

### Do Not Create

- No new protocol version, CLI flag, package, generated `dist/` file, or long-lived compatibility shim.
- Do not create a second public-path harness; extend the existing driver and summary pipeline.

---

### Task 1: Make block transfer policy receiver-aware

**Files:**

- Modify: `pkg/session/external_v2_block.go:91-110`
- Modify: `pkg/session/external_v2_offer.go:409-427`
- Modify: `pkg/session/external_v2.go:909-926`
- Test: `pkg/session/external_v2_protocol_test.go:76-138`

**Interfaces:**

- Consumes: `externalV2Claim`, `externalV2ClaimRequestsBlockTransfer`, acceptor candidate strings, and the existing Tailscale prefixes.
- Produces: `externalV2BlockTransferPolicy`, `externalV2AcceptedBlockTransferPolicy(claim, blockTransfer, acceptCandidates)`, and `emitExternalV2BlockTransferPolicy(emitter, policy)`.

- [ ] **Step 1: Replace the acceptor-only expectations with failing receiver-role tests**

Replace the two current transfer-mode tests with table-driven coverage containing these cases:

```go
func TestExternalV2BlockTransferPolicyUsesFileReceiverInBothTopologies(t *testing.T) {
	compact := []string{
		"203.0.113.20:20000",
		"203.0.113.20:20001",
		"203.0.113.20:20002",
		"203.0.113.20:20003",
	}
	large := []string{
		"203.0.113.10:10000",
		"203.0.113.10:10001",
		"203.0.113.10:10002",
		"203.0.113.10:10003",
		"203.0.113.10:10004",
	}

	tests := []struct {
		name             string
		claim            externalV2Claim
		acceptCandidates []string
		wantReceiver     string
		wantMode         string
	}{
		{
			name: "receiver is claimant in send receive",
			claim: externalV2Claim{
				BlockCapable:       true,
				BlockPacketCapable: true,
				Candidates:         compact,
			},
			acceptCandidates: large,
			wantReceiver:     "claimant",
			wantMode:         externalV2TransferModeBulkPackets,
		},
		{
			name: "receiver is acceptor in pipe listen",
			claim: externalV2Claim{
				TransferMode:       externalV2TransferModeBlocks,
				BlockSize:          1024,
				BlockChunkSize:     externalV2DefaultBlockChunkSize,
				BlockPacketCapable: true,
				Candidates:         large,
			},
			acceptCandidates: compact,
			wantReceiver:     "acceptor",
			wantMode:         externalV2TransferModeBulkPackets,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := externalV2AcceptedBlockTransferPolicy(tt.claim, true, tt.acceptCandidates)
			if got.Receiver != tt.wantReceiver || got.Mode != tt.wantMode {
				t.Fatalf("policy = %#v, want receiver=%q mode=%q", got, tt.wantReceiver, tt.wantMode)
			}
		})
	}
}
```

Append these table cases:

```go
{
	name: "tailscale noise does not change compact receiver",
	claim: externalV2Claim{
		BlockCapable:       true,
		BlockPacketCapable: true,
		Candidates: append(append([]string{}, compact...),
			"100.91.76.77:30000", "[fd7a:115c:a1e0::1]:30001"),
	},
	acceptCandidates: large,
	wantReceiver:     "claimant",
	wantMode:         externalV2TransferModeBulkPackets,
},
{
	name: "five public receiver candidates keep quic",
	claim: externalV2Claim{
		BlockCapable:       true,
		BlockPacketCapable: true,
		Candidates:         large,
	},
	acceptCandidates: compact,
	wantReceiver:     "claimant",
	wantMode:         externalV2TransferModeBlocks,
},
{
	name: "invalid receiver candidate keeps quic",
	claim: externalV2Claim{
		BlockCapable:       true,
		BlockPacketCapable: true,
		Candidates:         append(append([]string{}, compact...), "not-an-addr-port"),
	},
	acceptCandidates: large,
	wantReceiver:     "claimant",
	wantMode:         externalV2TransferModeBlocks,
},
{
	name: "missing packet capability keeps quic",
	claim: externalV2Claim{
		BlockCapable: true,
		Candidates:   compact,
	},
	acceptCandidates: large,
	wantReceiver:     "claimant",
	wantMode:         externalV2TransferModeBlocks,
},
```

- [ ] **Step 2: Run the policy test and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BlockTransferPolicy' -count=1
```

Expected: build failure because `externalV2BlockTransferPolicy` and `externalV2AcceptedBlockTransferPolicy` do not exist.

- [ ] **Step 3: Implement the receiver-aware policy**

Replace `externalV2AcceptedBlockTransferMode` and `externalV2ClaimPrefersBulkPacketTransfer` with:

```go
type externalV2BlockTransferPolicy struct {
	Mode                       string
	Receiver                   string
	ReceiverCandidates         int
	PolicyCandidates           int
	IgnoredTailscaleCandidates int
	InvalidCandidates          int
}

func externalV2AcceptedBlockTransferPolicy(claim externalV2Claim, blockTransfer bool, acceptCandidates []string) externalV2BlockTransferPolicy {
	policy := externalV2BlockTransferPolicy{Mode: externalV2TransferModeBlocks, Receiver: "unknown"}
	if !blockTransfer {
		policy.Mode = ""
		return policy
	}

	var receiverCandidates []string
	switch {
	case externalV2ClaimRequestsBlockTransfer(claim):
		policy.Receiver = "acceptor"
		receiverCandidates = acceptCandidates
	case claim.BlockCapable:
		policy.Receiver = "claimant"
		receiverCandidates = claim.Candidates
	default:
		return policy
	}

	policy.ReceiverCandidates = len(receiverCandidates)
	for _, candidate := range receiverCandidates {
		addrPort, err := netip.ParseAddrPort(candidate)
		if err != nil {
			policy.InvalidCandidates++
			policy.PolicyCandidates++
			continue
		}
		addr := addrPort.Addr()
		if publicProbeTailscaleCGNATPrefix.Contains(addr) || publicProbeTailscaleULAPrefix.Contains(addr) {
			policy.IgnoredTailscaleCandidates++
			continue
		}
		policy.PolicyCandidates++
	}
	if claim.BlockPacketCapable && policy.InvalidCandidates == 0 && policy.PolicyCandidates <= externalV2BulkPacketCandidateLimit {
		policy.Mode = externalV2TransferModeBulkPackets
	}
	return policy
}

func emitExternalV2BlockTransferPolicy(emitter *telemetry.Emitter, policy externalV2BlockTransferPolicy) {
	emitExternalV2Debug(emitter, fmt.Sprintf(
		"v2-block-policy=mode:%s receiver:%s candidates:%d policy_candidates:%d tailscale_ignored:%d invalid:%d",
		policy.Mode,
		policy.Receiver,
		policy.ReceiverCandidates,
		policy.PolicyCandidates,
		policy.IgnoredTailscaleCandidates,
		policy.InvalidCandidates,
	))
}
```

Add `net/netip` and `github.com/shayne/derphole/pkg/telemetry` imports. In both `sendAccept` call sites, compute the policy, assign `accept.TransferMode = policy.Mode`, and emit the policy before sending the authenticated accept envelope.

- [ ] **Step 4: Run focused policy and protocol tests and verify GREEN**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2(BlockTransferPolicy|BlockTransferMode|Protocol)' -count=1
```

Expected: PASS, including claimant-receiver, acceptor-receiver, Tailscale-noise, invalid-candidate, capability, and five-public-candidate cases.

- [ ] **Step 5: Commit the policy change**

Run:

```bash
but diff
but commit codex/send-receive-public-bulk -m "perf: select bulk mode by file receiver"
```

Expected: one new commit containing only the policy, telemetry, and protocol tests; no uncommitted files remain.

---

### Task 2: Stop obsolete manager activity after raw-direct activation

**Files:**

- Modify: `pkg/session/external_v2.go:75-87, 246-301, 736-750, 853-890`
- Modify: `pkg/session/external_v2_offer.go:262-297, 368-406, 725-775, 828-870`
- Modify: `pkg/session/external_v2_block.go:163-218, 239-287`
- Modify: `pkg/session/external_v2_raw_direct.go:49-64`
- Test: `pkg/session/session_test.go:1012-1032, 1959-1969`

**Interfaces:**

- Consumes: finalized `externalV2DirectPacketPath.raw`, `transport.Manager.StopDirectReads`, and existing punch/nudge/reseed cancellation functions.
- Produces: `newExternalV2RawDirectActivation(pathEmitter, manager, cancels...) func()` and `externalV2ListenTransport.ActivateRawDirect()`.

- [ ] **Step 1: Add failing idempotence and punch-cancellation tests**

Add:

```go
func TestExternalV2RawDirectActivationRunsOnce(t *testing.T) {
	var calls atomic.Int32
	activate := newExternalV2RawDirectActivation(nil, nil,
		func() { calls.Add(1) },
		func() { calls.Add(1) },
		func() { calls.Add(1) },
	)
	activate()
	activate()
	if got := calls.Load(); got != 3 {
		t.Fatalf("cancel calls = %d, want 3 exactly once each", got)
	}
}

func TestExternalV2ListenTransportActivatesRawDirect(t *testing.T) {
	var calls atomic.Int32
	tr := externalV2ListenTransport{activateRawDirect: func() { calls.Add(1) }}
	tr.ActivateRawDirect()
	tr.ActivateRawDirect()
	if got := calls.Load(); got != 2 {
		t.Fatalf("activation forwarding calls = %d, want 2; idempotence belongs to activation closure", got)
	}
}
```

Add this deterministic punch-loop test helper and assertion:

```go
type countingPunchPacketConn struct {
	writes atomic.Int32
}

func (c *countingPunchPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}
func (c *countingPunchPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.writes.Add(1)
	return len(p), nil
}
func (c *countingPunchPacketConn) Close() error                       { return nil }
func (c *countingPunchPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *countingPunchPacketConn) SetDeadline(time.Time) error        { return nil }
func (c *countingPunchPacketConn) SetReadDeadline(time.Time) error    { return nil }
func (c *countingPunchPacketConn) SetWriteDeadline(time.Time) error   { return nil }

func TestExternalV2RawDirectActivationStopsPunchLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	conn := &countingPunchPacketConn{}
	peer := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 8), Port: 9000}
	externalV2RawDirectStartPunching(ctx, []net.PacketConn{conn}, []net.Addr{peer})

	deadline := time.Now().Add(time.Second)
	for conn.writes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if conn.writes.Load() == 0 {
		t.Fatal("punch loop did not write")
	}

	activate := newExternalV2RawDirectActivation(nil, nil, cancel)
	activate()
	before := conn.writes.Load()
	time.Sleep(3 * externalV2RawDirectPunchInterval)
	if got := conn.writes.Load(); got != before {
		t.Fatalf("writes after activation = %d, want stable %d", got, before)
	}
}
```

- [ ] **Step 2: Run activation tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2(RawDirectActivation|ListenTransportActivatesRawDirect)' -count=1
```

Expected: build failure because the activation constructor and transport method do not exist.

- [ ] **Step 3: Replace blast-era activation helpers**

In `external_v2_raw_direct.go`, replace `externalV2RawDirectActivateDirectPath` and `externalV2RawDirectStopPunchingForBlast` with:

```go
func newExternalV2RawDirectActivation(pathEmitter *transportPathEmitter, manager *transport.Manager, cancels ...context.CancelFunc) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			if pathEmitter != nil {
				pathEmitter.SuppressRelayRegression()
				pathEmitter.Emit(StateTryingDirect)
			}
			if manager != nil {
				manager.StopDirectReads()
			}
			for _, cancel := range cancels {
				if cancel != nil {
					cancel()
				}
			}
		})
	}
```

Add an `activateRawDirect func()` field and this method to `externalV2ListenTransport`:

```go
func (tr externalV2ListenTransport) ActivateRawDirect() {
	if tr.activateRawDirect != nil {
		tr.activateRawDirect()
	}
}
```

Every file-transport constructor must create the activation closure with `punchCancel`, `nudgeCancel`, and `reseedCancel`. Deferred cleanup still calls those cancel functions; cancellation remains idempotent.

- [ ] **Step 4: Activate only after finalized raw selection**

Immediately after each successful `negotiateExternalV2DirectPacketPath` call, add:

```go
if rawPath.raw {
	tr.ActivateRawDirect()
}
```

Apply this before opening raw QUIC or bulk endpoints in claimant send, listener receive, offer send, and offer receive. Refactor `externalV2SendRuntime.acceptAndStartTransport` to return `externalV2ListenTransport` so its send path uses the same lifecycle instead of a parallel manager/cleanup tuple.

Do not call activation when `rawPath.raw` is false. That path still needs manager reads and discovery for QUIC relay/direct fallback.

- [ ] **Step 5: Run focused lifecycle and raw-direct integration tests**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2(RawDirectActivation|ListenTransport|RawDirect|BlockTransfer)' -count=1
mise exec -- go test -race ./pkg/session -run 'TestExternalV2(RawDirectActivation|RawDirect|BlockTransfer)' -count=1
```

Expected: PASS under the race detector. The activation test observes no punch writes after activation, while manager fallback tests remain green.

- [ ] **Step 6: Remove dead names and commit**

Run:

```bash
rg -n 'ForBlast|externalV2RawDirectActivateDirectPath|externalV2RawDirectStopPunchingForBlast' pkg/session
```

Expected: no production matches. Then run:

```bash
but diff
but commit codex/send-receive-public-bulk -m "transport: stop manager traffic after raw activation"
```

Expected: one lifecycle commit with tests and no unrelated share/derptun behavior changes.

---

### Task 3: Keep sender progress on one clock

**Files:**

- Modify: `pkg/derphole/progress.go:149-166, 299-309`
- Test: `pkg/derphole/progress_test.go:39-105`
- Modify: `pkg/session/external_v2_offer.go:360-365`
- Create: `pkg/session/external_v2_offer_test.go`

**Interfaces:**

- Consumes: `ProgressReporter.externalElapsed`, `ProgressReporter.externalRate`, and peer progress callbacks.
- Produces: coherent final display time/rate and no terminal callback with elapsed zero.

- [ ] **Step 1: Add failing complete-external-clock test**

Add:

```go
func TestProgressReporterFinishUsesCompleteExternalElapsedForTimeAndRate(t *testing.T) {
	start := time.Unix(0, 0)
	now := start
	prevProgressNow := progressNow
	progressNow = func() time.Time { return now }
	t.Cleanup(func() { progressNow = prevProgressNow })

	var out bytes.Buffer
	progress := NewProgressReporter(&out, 100*1024*1024)
	progress.SetWithElapsed(100*1024*1024, 10*time.Second)
	now = start.Add(20 * time.Second)
	progress.Finish()

	line := lastRawProgressLine(out.String())
	if !strings.Contains(line, "[00:10<00:00, 10.0MiB/s]") {
		t.Fatalf("final progress line = %q, want one receiver clock", line)
	}
}
```

Keep `TestProgressReporterFinishIgnoresStalePartialExternalElapsed`; together they distinguish complete and partial external clocks.

- [ ] **Step 2: Run progress tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/derphole -run 'TestProgressReporterFinish(UsesCompleteExternalElapsedForTimeAndRate|IgnoresStalePartialExternalElapsed)' -count=1
```

Expected: the complete test fails because the displayed elapsed is `00:20` while the rate uses ten seconds; the stale-partial test passes.

- [ ] **Step 3: Use external elapsed for the rendered clock only when valid**

In `renderLocked`, use:

```go
elapsed := progressElapsed(p.start, now)
if p.externalRate && p.externalElapsed > 0 && p.current >= p.total {
	elapsed = p.externalElapsed
}
rate := p.rateLocked(final, now, elapsed)
```

Do not change `Finish` clearing behavior for partial progress.

- [ ] **Step 4: Add and verify a failing terminal-callback test**

Create a minimal fake `externalV2QUICEndpoint` (and add the `pkg/dataplane` test import):

```go
type recordingExternalV2Endpoint struct {
	closeCode   uint64
	closeReason string
}

func (e *recordingExternalV2Endpoint) CloseWithError(code uint64, reason string) error {
	e.closeCode = code
	e.closeReason = reason
	return nil
}

func (*recordingExternalV2Endpoint) Stats() dataplane.Stats {
	return dataplane.Stats{}
}
```

Then add:

```go
func TestExternalV2OfferFinishSendStreamDoesNotPublishZeroElapsed(t *testing.T) {
	var progressCalls int
	rt := &externalV2OfferRuntime{cfg: OfferConfig{
		Progress: func(int64, int64) { progressCalls++ },
	}}
	endpoint := &recordingExternalV2Endpoint{}
	metrics := newExternalTransferMetrics(time.Unix(1, 0))

	if err := rt.finishSendStream(endpoint, externalV2Complete{BytesReceived: 1024}, metrics); err != nil {
		t.Fatal(err)
	}
	if progressCalls != 0 {
		t.Fatalf("terminal progress calls = %d, want 0", progressCalls)
	}
}
```

Run it before implementation and confirm it fails with one callback. Then remove only the `rt.cfg.Progress(complete.BytesReceived, 0)` call from `finishSendStream`; retain monotonic metrics and endpoint close behavior.

- [ ] **Step 5: Run focused and package tests, then commit**

Run:

```bash
mise exec -- go test ./pkg/derphole -run 'TestProgressReporter' -count=1
mise exec -- go test ./pkg/session -run 'TestExternalV2OfferFinishSendStream' -count=1
mise exec -- go test ./pkg/derphole ./pkg/session -count=1
but diff
but commit codex/send-receive-public-bulk -m "ui: keep transfer progress on receiver clock"
```

Expected: all tests pass; the commit contains only progress accounting and its tests.

---

### Task 4: Make the benchmark exercise real file send/receive

**Files:**

- Modify: `scripts/promotion-benchmark-driver.sh:8-73, 177-202, 402-569, 648-668`
- Modify: `scripts/public-path-performance-harness.sh:8-16, 80-179, 293-384`
- Test: `scripts/promotion_scripts_test.go:650-930`

**Interfaces:**

- Consumes: existing build/install, trace, hash, direct-path, timing, preservation, and cleanup helpers.
- Produces: `DERPHOLE_BENCH_WORKLOAD=file|stream`, `benchmark-workload`, `benchmark-transfer-mode`, and matching `workload`/`transfer_mode` summary columns.

- [ ] **Step 1: Add failing benchmark source-contract tests**

Add tests requiring all of these exact fragments:

```go
func TestPromotionBenchmarkDefaultsToFileSendReceive(t *testing.T) {
	body := readPromotionDriver(t)
	for _, want := range []string{
		`workload="${DERPHOLE_BENCH_WORKLOAD:-file}"`,
		`--verbose send "${payload}"`,
		`--verbose receive -o '${remote_base}.out'`,
		`benchmark-workload=${workload}`,
		`benchmark-transfer-mode=${transfer_mode}`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("promotion driver missing %q", want)
		}
	}
}

func TestPromotionStreamWorkloadIsExplicit(t *testing.T) {
	body := readPromotionDriver(t)
	if !strings.Contains(body, `stream) run_forward_derphole_stream ;;`) {
		t.Fatal("promotion driver does not isolate listen/pipe as stream workload")
	}
}
```

Extend the public harness test to require `DERPHOLE_BENCH_WORKLOAD=file` and CSV columns `workload,transfer_mode`.

- [ ] **Step 2: Run script tests and verify RED**

Run:

```bash
mise exec -- go test ./scripts -run 'TestPromotion(BenchmarkDefaultsToFileSendReceive|StreamWorkloadIsExplicit)|TestPublicPathPerformanceHarness' -count=1
```

Expected: failures for missing workload selection, file commands, footer values, and summary columns.

- [ ] **Step 3: Add workload selection and mode extraction**

At driver startup add:

```bash
workload="${DERPHOLE_BENCH_WORKLOAD:-file}"
case "${workload}" in
  file|stream) ;;
  *) echo "DERPHOLE_BENCH_WORKLOAD must be file or stream (got: ${workload})" >&2; exit 2 ;;
esac
if [[ "${workload}" == "file" && -n "${DERPHOLE_BENCH_PARALLEL:-}" ]]; then
  echo "DERPHOLE_BENCH_PARALLEL is only valid for the stream workload" >&2
  exit 2
fi
transfer_mode="unknown"
```

Add footer fields:

```bash
echo "benchmark-workload=${workload}"
echo "benchmark-transfer-mode=${transfer_mode}"
```

After logs are collected, set mode with:

```bash
if grep -Fq 'v2-block-transfer=bulk-packets' "${sender_log}" && grep -Fq 'v2-block-transfer=bulk-packets' "${receiver_log}"; then
  transfer_mode="bulk-packets-v1"
elif grep -Fq 'v2-block-policy=mode:blocks-v1' "${sender_log}" || grep -Fq 'v2-block-policy=mode:blocks-v1' "${receiver_log}"; then
  transfer_mode="blocks-v1"
fi
```

If `DERPHOLE_BENCH_EXPECT_TRANSFER_MODE` is set and differs from `transfer_mode`, fail the sample before preservation.

- [ ] **Step 4: Implement the forward file workload**

Rename the current forward function to `run_forward_derphole_stream`. Add `run_forward_derphole_file` that:

```bash
run_forward_derphole_file() {
  echo "generating ${size_mib} MiB random payload"
  dd if=/dev/urandom of="${payload}" bs=1048576 count="${size_mib}" 2>/dev/null
  source_sha="$(shasum -a 256 "${payload}" | awk '{print $1}')"
  rm -f "${sender_log}" "${sender_trace_csv}"
  remote "rm -f '${remote_base}.pid' '${remote_base}.out' '${remote_base}.err' '${remote_base}.trace.csv'"

  start_ms="$(now_ms)"
  DERPHOLE_TRANSFER_TRACE_CSV="${sender_trace_csv}" "${local_bin}" --verbose send "${payload}" >/dev/null 2>"${sender_log}" &
  send_pid="$!"

  token=""
  for _ in $(seq 1 200); do
    token="$(sed -nE 's/.* receive ([A-Za-z0-9_-]{20,})$/\1/p' "${sender_log}" | head -n 1)"
    [[ -n "${token}" ]] && break
    kill -0 "${send_pid}" 2>/dev/null || break
    sleep 0.1
  done
  [[ -n "${token}" ]] || { echo "failed to capture send token" >&2; exit 1; }

  remote "DERPHOLE_TRANSFER_TRACE_CSV='${remote_base}.trace.csv' '${remote_bin}' --verbose receive -o '${remote_base}.out' '${token}' >/dev/null 2>'${remote_base}.err'"
  wait "${send_pid}"
  send_pid=""
  command_end_ms="$(now_ms)"

  remote "cat '${remote_base}.err'" >"${receiver_log}"
  remote "cat '${remote_base}.trace.csv'" >"${receiver_trace_csv}"
  sink_sha="$(remote "sha256sum '${remote_base}.out' | awk '{print \$1}'")"
  sink_size="$(remote "wc -c < '${remote_base}.out'")"
}
```

Use the same existing cleanup filenames, so failure and success cleanup remain centralized.

- [ ] **Step 5: Implement the reverse file workload and dispatch**

Rename the current reverse function to `run_reverse_derphole_stream`. Add:

```bash
run_reverse_derphole_file() {
  echo "generating ${size_mib} MiB random payload on ${target}"
  remote "dd if=/dev/urandom of='${remote_base}.payload' bs=1048576 count='${size_mib}' 2>/dev/null"
  source_sha="$(remote "sha256sum '${remote_base}.payload' | awk '{print \$1}'")"
  remote "rm -f '${remote_base}.pid' '${remote_base}.out' '${remote_base}.err' '${remote_base}.trace.csv'; nohup env DERPHOLE_TRANSFER_TRACE_CSV='${remote_base}.trace.csv' '${remote_bin}' --verbose send '${remote_base}.payload' >'${remote_base}.out' 2>'${remote_base}.err' </dev/null & echo \$! >'${remote_base}.pid'"

  token=""
  for _ in $(seq 1 200); do
    token="$(remote "sed -nE 's/.* receive ([A-Za-z0-9_-]{20,})$/\\1/p' '${remote_base}.err' | head -n 1")"
    [[ -n "${token}" ]] && break
    sleep 0.1
  done
  [[ -n "${token}" ]] || { echo "failed to capture remote send token" >&2; exit 1; }

  start_ms="$(now_ms)"
  DERPHOLE_TRANSFER_TRACE_CSV="${receiver_trace_csv}" "${local_bin}" --verbose receive -o "${receiver_out}" "${token}" >/dev/null 2>"${receiver_log}"
  wait_remote_pid_exit
  command_end_ms="$(now_ms)"

  remote "cat '${remote_base}.err'" >"${sender_log}"
  remote "cat '${remote_base}.trace.csv'" >"${sender_trace_csv}"
  sink_sha="$(shasum -a 256 "${receiver_out}" | awk '{print $1}')"
  sink_size="$(wc -c < "${receiver_out}" | tr -d '[:space:]')"
}
```

Dispatch with:

```bash
case "${tool}:${direction}:${workload}" in
  derphole:forward:file) run_forward_derphole_file ;;
  derphole:reverse:file) run_reverse_derphole_file ;;
  derphole:forward:stream) run_forward_derphole_stream ;;
  derphole:reverse:stream) run_reverse_derphole_stream ;;
  *) echo "unsupported benchmark mode: ${tool}:${direction}:${workload}" >&2; exit 1 ;;
esac
```

- [ ] **Step 6: Extend summary columns and executable harness tests**

Pass `DERPHOLE_BENCH_WORKLOAD=file` from `run_derphole_forward_sample`. Extract `benchmark-workload` and `benchmark-transfer-mode`, add them to `append_summary_row`, and write this header:

```text
host,run,tool,direction,workload,transfer_mode,mbps,ratio_to_iperf,trace_mbps,wall_mbps,wall_ratio_to_iperf,transfer_elapsed_ms,command_duration_ms,total_duration_ms,trace_ok,max_peer_recv_queue_depth,max_flatline,log_dir
```

Update fake promotion scripts in `promotion_scripts_test.go` to emit both footer fields. Add an executable test that stubs `derphole`, `ssh`, and `scp`, then proves the default branch starts `send` before `receive` and does not invoke `listen` or `pipe`.

- [ ] **Step 7: Run Bash and script-package verification**

Run:

```bash
bash -n scripts/promotion-benchmark-driver.sh scripts/public-path-performance-harness.sh
mise exec -- go test ./scripts -count=1
```

Expected: syntax and all source/executable contract tests pass.

- [ ] **Step 8: Commit the representative benchmark**

Run:

```bash
but diff
but commit codex/send-receive-public-bulk -m "bench: make file transfer the promotion workload"
```

Expected: one benchmark commit containing only driver, harness, and script tests.

---

### Task 5: Add exact normal-flow integration coverage and benchmark documentation

**Files:**

- Modify: `pkg/session/external_v2_block_test.go:260-430`
- Modify: `docs/benchmarks.md:1-220`
- Modify: `docs/superpowers/specs/2026-07-11-send-receive-public-bulk-design.md:83`

**Interfaces:**

- Consumes: fake transport, offer/receive and listen/send helpers, verbose telemetry, block source/sink fixtures, and benchmark environment variables.
- Produces: a durable regression proving the product topology selects bulk and documented file/stream commands.

- [ ] **Step 1: Add a failing normal offer/receive bulk integration test**

Rename `TestExternalV2OfferBlockTransferRoundTrip` to `TestExternalV2OfferReceiveRawDirectBulk` and convert it to a raw-direct version: set `DERPHOLE_FAKE_TRANSPORT=1` and `DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT=0`, install the same loopback `publicInterfaceAddrs` hook used by `TestExternalV2BlockTransferUsesBulkPacketsOnRawDirect`, remove both `ForceRelay` fields, attach verbose `offerStatus` and `receiveStatus` emitters, and retain its existing header, payload, sink, token, and completion checks. Add these assertions:

```go
if !strings.Contains(offerStatus.String(), "v2-block-policy=mode:bulk-packets-v1 receiver:claimant") {
	t.Fatalf("offer status = %q, want claimant receiver bulk policy", offerStatus.String())
}
if !strings.Contains(offerStatus.String(), "v2-block-transfer=bulk-packets") ||
	!strings.Contains(receiveStatus.String(), "v2-block-transfer=bulk-packets") {
	t.Fatalf("missing bulk packet marker: offer=%q receive=%q", offerStatus.String(), receiveStatus.String())
}
if !bytes.Equal(gotPayload, payload) {
	t.Fatal("offer/receive block payload mismatch")
}
```

- [ ] **Step 2: Run the exact integration test and verify the locked behavior**

Run before any test-fixture adaptation:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2OfferReceiveRawDirectBulk' -count=1
```

Expected: PASS because Task 1 already supplied the failing policy test and implementation. This integration test adds end-to-end coverage without another production change.

- [ ] **Step 3: Update benchmark documentation**

Document these exact commands:

```bash
# Primary product file benchmark.
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
DERPHOLE_BENCH_WORKLOAD=file \
./scripts/promotion-test.sh ubuntu@eric-nuc 3072

# Explicit stream control; never report this as file validation.
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
DERPHOLE_BENCH_WORKLOAD=stream \
./scripts/promotion-test.sh ubuntu@eric-nuc 3072
```

State that production leaves the Tailscale guard unset, the primary public harness defaults to file workload, and summaries always record workload and mode.

- [ ] **Step 4: Run focused integration/docs checks and commit**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2.*(Block|Bulk)' -count=1
mise exec -- go test ./scripts -run 'TestBenchmarkDocs|TestPromotion' -count=1
but diff
but commit codex/send-receive-public-bulk -m "test: cover normal raw bulk file flow"
```

Expected: integration and docs-contract tests pass; the factual spec correction is included in this commit.

---

### Task 6: Run full local verification

**Files:**

- Verify only; repair failures in the task that owns the failing behavior.

**Interfaces:**

- Consumes: all implementation commits.
- Produces: a clean local release-grade verification record.

- [ ] **Step 1: Check the branch can still update cleanly**

Run:

```bash
but pull --check
```

Expected: zero new conflicting changes. If the base moved, run `but pull`, rerun all verification below, and do not resolve overlap with another session silently.

- [ ] **Step 2: Run focused race and package tests**

Run:

```bash
mise exec -- go test -race ./pkg/session -run 'ExternalV2.*(Block|Bulk|RawDirect|Activation)' -count=1
mise exec -- go test ./pkg/derphole ./pkg/session ./pkg/transfertrace ./tools/transfertracecheck ./scripts -count=1
```

Expected: PASS with no race reports.

- [ ] **Step 3: Run repository gates**

Run:

```bash
mise run test
mise run vet
mise run smoke-local
mise run check:hooks
mise run release:npm-dry-run
```

Expected: every command exits zero. Preserve complete output for any failing gate and fix it in the owning task before continuing.

- [ ] **Step 4: Create a recovery point and tidy implementation history**

Run:

```bash
but oplog snapshot -m "before send receive bulk history cleanup"
but status
```

Squash only tiny fixup commits into their owning task commits. Keep the design, policy, raw lifecycle, progress, benchmark, and integration/docs changes as coherent review units until live acceptance passes.

---

### Task 7: Prove public file throughput with three 3 GiB runs

**Files:**

- Runtime artifacts only under `.tmp/`; do not commit benchmark output.

**Interfaces:**

- Consumes: the exact local revision built and installed by the promotion driver, public port-forwarded TCP `iperf3` port 8123, and `ubuntu@eric-nuc`.
- Produces: three integrity-gated file samples, stream control, fast-host control, arithmetic means, standard deviations, and ratios.

- [ ] **Step 1: Record the exact candidate revision and preflight cleanup**

Run:

```bash
candidate="$(but show codex/send-receive-public-bulk | awk '/^  [0-9a-f]+ / {print $1; exit}')"
test -n "${candidate}"
ssh ubuntu@eric-nuc "pkill -x derphole 2>/dev/null || true; find \"\$HOME/derphole-bench\" -maxdepth 3 -type f -name 'run.*' -delete 2>/dev/null || true"
```

Expected: a non-empty candidate SHA and no remaining derphole process.

- [ ] **Step 2: Run one 3 GiB public stream control**

Run:

```bash
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
DERPHOLE_BENCH_WORKLOAD=stream \
DERPHOLE_BENCH_EXPECT_TRANSFER_MODE=bulk-packets-v1 \
DERPHOLE_BENCH_LOG_DIR=".tmp/send-receive-bulk-${stamp}/stream-control" \
./scripts/promotion-test.sh ubuntu@eric-nuc 3072 | tee ".tmp/send-receive-bulk-${stamp}/stream-control.out"
```

Expected: public raw lanes, `bulk-packets-v1`, matching size/hash, trace success, and no leaks.

- [ ] **Step 3: Run the primary three-sample public file harness**

Run:

```bash
DERPHOLE_PUBLIC_PATH_HOSTS=ubuntu@eric-nuc \
DERPHOLE_PUBLIC_PATH_SIZE_MIB=3072 \
DERPHOLE_PUBLIC_PATH_RUNS=3 \
DERPHOLE_PUBLIC_IPERF_PORT=8123 \
DERPHOLE_BENCH_WORKLOAD=file \
DERPHOLE_BENCH_EXPECT_TRANSFER_MODE=bulk-packets-v1 \
DERPHOLE_BENCH_LOG_DIR=".tmp/send-receive-bulk-${stamp}/file" \
./scripts/public-path-performance-harness.sh
```

Expected: exactly three `iperf3` and three derphole file rows; every derphole row has `workload=file`, `transfer_mode=bulk-packets-v1`, `trace_ok=true`, public selected lanes, matching SHA/size, and zero postrun leaks.

- [ ] **Step 4: Compute the acceptance report**

Run this read-only calculation over the generated `summary.csv` and stream-control footer:

```bash
summary=".tmp/send-receive-bulk-${stamp}/file/summary.csv"
stream_rate="$(awk -F= '$1 == "benchmark-goodput-mbps" {value=$2} END {print value}' ".tmp/send-receive-bulk-${stamp}/stream-control.out")"
python3 - "${summary}" "${stream_rate}" <<'PY'
import csv
import statistics
import sys

summary_path, stream_text = sys.argv[1:]
with open(summary_path, newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle))

iperf = [float(row["mbps"]) for row in rows if row["tool"] == "iperf3"]
files = [row for row in rows if row["tool"] == "derphole"]
trace = [float(row["trace_mbps"]) for row in files]
wall = [float(row["wall_mbps"]) for row in files]
stream = float(stream_text)

if len(iperf) != 3 or len(files) != 3:
    raise SystemExit(f"expected 3 iperf and 3 derphole rows, got {len(iperf)} and {len(files)}")
for row in files:
    if row["workload"] != "file" or row["transfer_mode"] != "bulk-packets-v1" or row["trace_ok"] != "true":
        raise SystemExit(f"invalid file sample: {row}")

def report(label, values):
    mean = statistics.fmean(values)
    sd = statistics.stdev(values)
    cv = sd / mean
    print(f"{label}: samples={values} mean={mean:.2f} sd={sd:.2f} cv={cv:.3f}")
    return mean, cv

trace_mean, _ = report("file trace Mbps", trace)
wall_mean, _ = report("file wall Mbps", wall)
iperf_mean, iperf_cv = report("iperf Mbps", iperf)
print(f"stream control Mbps: {stream:.2f}")
print(f"file trace / stream: {trace_mean / stream:.3f}")
print(f"file trace / iperf: {trace_mean / iperf_mean:.3f}")
print(f"file wall / iperf: {wall_mean / iperf_mean:.3f}")

if trace_mean < 0.95 * stream:
    raise SystemExit("file trace mean is below 95 percent of stream control")
if iperf_cv <= 0.20 and trace_mean < 0.85 * iperf_mean:
    raise SystemExit("file trace mean is below 85 percent of stable iperf")
PY
```

Then verify the time-series and final progress invariants directly from the preserved artifacts:

```bash
rg -n 'v2-block-policy=|v2-block-transfer=|v2-raw-direct-selected-addrs=|transport-dropped-datagrams=' ".tmp/send-receive-bulk-${stamp}/file"
find ".tmp/send-receive-bulk-${stamp}/file" -name '*transfertracecheck.txt' -type f -exec sh -c 'for path do echo "==> ${path}"; sed -n "1,120p" "${path}"; done' sh {} +
```

Verify:

- file trace mean is at least 95 percent of the stream control rate
- file trace mean is at least 85 percent of the iperf mean when iperf coefficient of variation is at most 20 percent
- receiver recent-rate traces do not reproduce the old sustained 20–28 MiB/s tail
- no sender final line switches to a slower setup-inclusive clock

If a gate fails, do not average away the failure. Preserve the sample and return to the owning task with a new failing test.

- [ ] **Step 5: Run the Hetz fast-host file control**

Run:

```bash
DERPHOLE_PUBLIC_PATH_HOSTS=root@hetz \
DERPHOLE_PUBLIC_PATH_SIZE_MIB=1024 \
DERPHOLE_PUBLIC_PATH_RUNS=3 \
DERPHOLE_PUBLIC_IPERF_PORT=8123 \
DERPHOLE_BENCH_WORKLOAD=file \
DERPHOLE_BENCH_EXPECT_TRANSFER_MODE=blocks-v1 \
DERPHOLE_BENCH_LOG_DIR=".tmp/send-receive-bulk-${stamp}/hetz-file" \
./scripts/public-path-performance-harness.sh
```

Require all samples to keep `blocks-v1` and the mean not to regress more than 5 percent from the accepted same-workload Hetz baseline.

- [ ] **Step 6: Re-run local gates after any live-driven edit**

If live testing caused any code change, repeat Task 6 in full and repeat all three file samples. A mixed-revision average is invalid.

---

### Task 8: Land the verified correction on main and push

**Files:**

- Version-control integration only.

**Interfaces:**

- Consumes: green local gates, green live acceptance, a clean `but pull --check`, and the user's prior explicit land-and-push authorization for this correction sequence.
- Produces: one clean landed commit on local `main` and `origin/main`, with GitButler branch cleanup.

- [ ] **Step 1: Final branch audit**

Run:

```bash
but pull --check
but status -fv
```

Verify the session branch contains only the design and this correction. Create an oplog snapshot before squashing:

```bash
but oplog snapshot -m "before final send receive bulk squash"
```

- [ ] **Step 2: Squash implementation history to a clean final shape**

Keep the design commit separate if useful for history, and squash implementation commits into one scoped commit:

```text
perf: make file transfers select receiver bulk path
```

Resolve current commit IDs from the branch, exclude the design commit by subject, and squash only when there is more than one implementation commit:

```zsh
implementation_ids=("${(@f)$(but show codex/send-receive-public-bulk | awk '/^  [0-9a-f]+ / && $0 !~ /docs: design send receive bulk correction/ {print $1}')}")
if [[ -z "${implementation_ids[1]}" ]]; then
  implementation_ids=()
fi
if (( ${#implementation_ids[@]} > 1 )); then
  target_id="${implementation_ids[-1]}"
  source_ids=("${implementation_ids[1,-2]}")
  but squash "${source_ids[@]}" "${target_id}" -m "perf: make file transfers select receiver bulk path"
fi
```

Do not hardcode commit IDs. Read the mutation output and confirm the design commit remains separate from the single implementation commit.

- [ ] **Step 3: Re-run publication-critical verification**

Run:

```bash
mise run test
mise run vet
mise run check:hooks
mise run release:npm-dry-run
but pull --check
```

Expected: all green and no new upstream commits.

- [ ] **Step 4: Publish directly to main and verify exact refs**

Resolve the session head and use the repository's authorized raw publication exception:

```bash
session_head="$(but show codex/send-receive-public-bulk | awk '/^  [0-9a-f]+ / {print $1; exit}')"
test -n "${session_head}"
git push origin "${session_head}:refs/heads/main"
but pull
but clean --dry-run
but clean
git rev-parse main origin/main
git ls-remote origin refs/heads/main
```

All three main refs must equal `session_head`. If the push rejects non-fast-forward, run `but pull`, recompute `session_head`, rerun publication-critical verification, and retry only when clean.
