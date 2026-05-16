# Public Transport Phase 1 Baseline Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the leak-proof baseline harness required before replacing the public transfer protocol.

**Architecture:** Keep the current product protocol unchanged in Phase 1. Harden the existing live transfer stall harness so every run captures synchronized traces, verifies sender/receiver progress alignment, records configurable iperf baselines, and fails when derphole processes or UDP sockets leak on either endpoint.

**Tech Stack:** Bash harnesses, Go trace checker, `mise`, `go test`, `iperf3`, SSH, Linux `/proc/net/udp`, macOS/Linux process checks.

---

## File Structure

- Modify `scripts/transfer-stall-harness.sh`: add process/UDP leak gates, preflight checks, post-run cleanup assertions, and metadata for iperf baseline parameters.
- Modify `scripts/stall_harness_script_test.go`: require the new leak-gate and iperf metadata behavior in the script.
- Modify `pkg/transfertrace/checker.go`: make pairwise trace checking detect sender progress that leads receiver progress during the run, not only at final completion.
- Modify `pkg/transfertrace/checker_test.go`: add tests for mid-run sender progress lead and tolerance.
- Modify `tools/transfertracecheck/main.go`: expose a `-progress-lead-tolerance` flag.
- Modify `tools/transfertracecheck/main_test.go`: verify the new CLI flag passes and fails as expected.
- Modify `docs/benchmarks.md`: document Phase 1 live gate commands, `DERPHOLE_IPERF_PORT=8123`, and the no-leak requirement.

## Tasks

### Task 1: Add Leak Gates To The Stall Harness

**Files:**
- Modify: `scripts/transfer-stall-harness.sh`
- Modify: `scripts/stall_harness_script_test.go`

- [ ] **Step 1: Write the failing script-structure test**

Add these required strings to `required` in `scripts/stall_harness_script_test.go`:

```go
"DERPHOLE_STALL_TOOL_NAME",
"DERPHOLE_STALL_ASSERT_NO_LEAKS",
"DERPHOLE_STALL_KILL_LEAKS",
"assert_no_remote_leaks",
"remote_leak_snapshot",
"terminate_remote_children",
"preflight sender",
"preflight receiver",
"postrun sender",
"postrun receiver",
"/proc/net/udp6",
"socket:[",
"leak-check",
"DERPHOLE_IPERF_PORT",
"DERPHOLE_IPERF_SERVER_HOST",
```

Add an ordering check near the bottom:

```go
preflightIndex := strings.Index(body, `assert_no_remote_leaks "${sender_target}" "preflight sender"`)
startIndex := strings.Index(body, `remote_sh "${sender_target}" "`)
if preflightIndex < 0 {
	t.Fatalf("transfer-stall-harness.sh missing sender preflight leak gate")
}
if startIndex < 0 {
	t.Fatalf("transfer-stall-harness.sh missing sender start")
}
if preflightIndex > startIndex {
	t.Fatalf("transfer-stall-harness.sh checks leaks after starting sender")
}
```

- [ ] **Step 2: Run the failing test**

Run:

```bash
go test ./scripts -run TestTransferStallHarnessCapturesProgressAndCounters -count=1
```

Expected: FAIL because `transfer-stall-harness.sh` does not yet contain `DERPHOLE_STALL_TOOL_NAME` or the leak-gate functions.

- [ ] **Step 3: Add leak-gate configuration**

In `scripts/transfer-stall-harness.sh`, after `receiver_target="${2:?missing receiver host}"`, add:

```bash
tool_name="${DERPHOLE_STALL_TOOL_NAME:-derphole}"
assert_no_leaks="${DERPHOLE_STALL_ASSERT_NO_LEAKS:-1}"
kill_leaks="${DERPHOLE_STALL_KILL_LEAKS:-1}"
iperf_port="${DERPHOLE_IPERF_PORT:-8321}"
iperf_server_host="${DERPHOLE_IPERF_SERVER_HOST:-}"
```

- [ ] **Step 4: Add remote leak snapshot helpers**

In `scripts/transfer-stall-harness.sh`, after `remote_mktemp()`, add:

```bash
remote_leak_snapshot() {
  local target="$1"
  local label="$2"
  clean_ssh "${target}" 'bash -se' -- "${tool_name}" "${label}" <<'REMOTE_LEAK_SNAPSHOT'
tool_name="$1"
label="$2"
pids="$(pgrep -x "${tool_name}" 2>/dev/null || true)"
process_count=0
udp_count=0
if [[ -n "${pids}" ]]; then
  process_count="$(printf '%s\n' "${pids}" | awk 'NF { count++ } END { print count + 0 }')"
  for pid in ${pids}; do
    fd_dir="/proc/${pid}/fd"
    [[ -d "${fd_dir}" ]] || continue
    while IFS= read -r fd; do
      link="$(readlink "${fd}" 2>/dev/null || true)"
      case "${link}" in
        socket:\[*\])
          inode="${link#socket:[}"
          inode="${inode%]}"
          if awk -v inode="${inode}" 'NR > 1 && $10 == inode { found=1 } END { exit found ? 0 : 1 }' /proc/net/udp /proc/net/udp6 2>/dev/null; then
            udp_count=$((udp_count + 1))
          fi
          ;;
      esac
    done < <(find "${fd_dir}" -maxdepth 1 -type l 2>/dev/null)
  done
fi
printf 'label=%s tool=%s processes=%s udp_sockets=%s pids=%s\n' "${label}" "${tool_name}" "${process_count}" "${udp_count}" "${pids//$'\n'/ }"
REMOTE_LEAK_SNAPSHOT
}

assert_no_remote_leaks() {
  local target="$1"
  local label="$2"
  if [[ "${assert_no_leaks}" != "1" ]]; then
    return 0
  fi
  local snapshot
  snapshot="$(remote_leak_snapshot "${target}" "${label}")"
  echo "leak-check ${target} ${snapshot}" >&2
  local processes
  local udp_sockets
  processes="$(awk -F'processes=' '{ print $2 }' <<<"${snapshot}" | awk '{ print $1 }')"
  udp_sockets="$(awk -F'udp_sockets=' '{ print $2 }' <<<"${snapshot}" | awk '{ print $1 }')"
  if [[ "${processes}" != "0" || "${udp_sockets}" != "0" ]]; then
    echo "stall-harness-error=leak-check-failed label=${label} target=${target} ${snapshot}" >&2
    return 1
  fi
}

terminate_remote_children() {
  local target="$1"
  local dir="$2"
  if [[ -z "${dir}" || "${kill_leaks}" != "1" ]]; then
    return 0
  fi
  remote_sh "${target}" "
for pid_file in $(quote "${dir}")/*.pid; do
  [[ -f \"\${pid_file}\" ]] || continue
  pid=\$(cat \"\${pid_file}\" 2>/dev/null || true)
  [[ -n \"\${pid}\" ]] || continue
  kill -TERM \"\${pid}\" 2>/dev/null || true
done
sleep 1
for pid_file in $(quote "${dir}")/*.pid; do
  [[ -f \"\${pid_file}\" ]] || continue
  pid=\$(cat \"\${pid_file}\" 2>/dev/null || true)
  [[ -n \"\${pid}\" ]] || continue
  kill -KILL \"\${pid}\" 2>/dev/null || true
done
" >/dev/null 2>&1 || true
}
```

- [ ] **Step 5: Wire leak gates into lifecycle**

After `collect_counters "${receiver_target}" "${receiver_dir}" "before"`, add:

```bash
assert_no_remote_leaks "${sender_target}" "preflight sender"
assert_no_remote_leaks "${receiver_target}" "preflight receiver"
```

In `abort_with_dumps()`, before `exit 124`, add:

```bash
terminate_remote_children "${sender_target}" "${sender_dir}"
terminate_remote_children "${receiver_target}" "${receiver_dir}"
```

After the transfer trace checks and before `echo "stall-harness-success=true"`, add:

```bash
assert_no_remote_leaks "${sender_target}" "postrun sender"
assert_no_remote_leaks "${receiver_target}" "postrun receiver"
```

In `finish()`, before `cleanup_remote`, add:

```bash
terminate_remote_children "${sender_target}" "${sender_dir}"
terminate_remote_children "${receiver_target}" "${receiver_dir}"
```

- [ ] **Step 6: Record iperf metadata in samples**

After the `samples.csv` header is written, write a separate metadata file:

```bash
{
  echo "sender_target=${sender_target}"
  echo "receiver_target=${receiver_target}"
  echo "size_mib=${size_mib}"
  echo "sample_interval_sec=${sample_interval_sec}"
  echo "stall_timeout_sec=${stall_timeout_sec}"
  echo "tool_name=${tool_name}"
  echo "iperf_port=${iperf_port}"
  echo "iperf_server_host=${iperf_server_host}"
} >"${log_dir}/metadata.env"
```

- [ ] **Step 7: Run tests**

Run:

```bash
go test ./scripts -run TestTransferStallHarnessCapturesProgressAndCounters -count=1
```

Expected: PASS.

- [ ] **Step 8: Commit**

Run:

```bash
git add scripts/transfer-stall-harness.sh scripts/stall_harness_script_test.go
git commit -m "test: gate stall harness on process cleanup"
```

### Task 2: Detect Mid-Run Sender/Receiver Progress Divergence

**Files:**
- Modify: `pkg/transfertrace/checker.go`
- Modify: `pkg/transfertrace/checker_test.go`
- Modify: `tools/transfertracecheck/main.go`
- Modify: `tools/transfertracecheck/main_test.go`

- [ ] **Step 1: Write failing package tests**

Add to `pkg/transfertrace/checker_test.go`:

```go
func TestCheckPairFailsSenderProgressLeadDuringRun(t *testing.T) {
	sendTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			role:              RoleSend,
			phase:             PhaseRelay,
			appBytes:          8192,
			deltaAppBytes:     8192,
			peerReceivedBytes: 8192,
			transferElapsedMS: 500,
			lastState:         "connected-relay",
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:       2000,
			role:              RoleSend,
			phase:             PhaseComplete,
			appBytes:          8192,
			deltaAppBytes:     0,
			peerReceivedBytes: 8192,
			transferElapsedMS: 1500,
			lastState:         "stream-complete",
		})
	receiveTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			role:              RoleReceive,
			phase:             PhaseRelay,
			appBytes:          1024,
			deltaAppBytes:     1024,
			transferElapsedMS: 500,
			lastState:         "connected-relay",
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:       2000,
			role:              RoleReceive,
			phase:             PhaseComplete,
			appBytes:          8192,
			deltaAppBytes:     7168,
			transferElapsedMS: 1500,
			lastState:         "stream-complete",
		})
	_, err := CheckPair(strings.NewReader(sendTrace), strings.NewReader(receiveTrace), PairOptions{Role: RoleSend})
	if err == nil || !strings.Contains(err.Error(), "sender progress leads receiver") {
		t.Fatalf("CheckPair() error = %v, want sender progress lead", err)
	}
}

func TestCheckPairAllowsConfiguredProgressLeadTolerance(t *testing.T) {
	sendTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			role:              RoleSend,
			phase:             PhaseRelay,
			appBytes:          4096,
			deltaAppBytes:     4096,
			peerReceivedBytes: 4096,
			transferElapsedMS: 500,
			lastState:         "connected-relay",
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:       2000,
			role:              RoleSend,
			phase:             PhaseComplete,
			appBytes:          8192,
			deltaAppBytes:     4096,
			peerReceivedBytes: 8192,
			transferElapsedMS: 1500,
			lastState:         "stream-complete",
		})
	receiveTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			role:              RoleReceive,
			phase:             PhaseRelay,
			appBytes:          1024,
			deltaAppBytes:     1024,
			transferElapsedMS: 500,
			lastState:         "connected-relay",
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:       2000,
			role:              RoleReceive,
			phase:             PhaseComplete,
			appBytes:          8192,
			deltaAppBytes:     7168,
			transferElapsedMS: 1500,
			lastState:         "stream-complete",
		})
	_, err := CheckPair(strings.NewReader(sendTrace), strings.NewReader(receiveTrace), PairOptions{
		Role:                       RoleSend,
		ProgressLeadToleranceBytes: 4096,
	})
	if err != nil {
		t.Fatalf("CheckPair() error = %v", err)
	}
}
```

- [ ] **Step 2: Run failing package tests**

Run:

```bash
go test ./pkg/transfertrace -run 'TestCheckPair(FailsSenderProgressLeadDuringRun|AllowsConfiguredProgressLeadTolerance)' -count=1
```

Expected: FAIL because `PairOptions` has no `ProgressLeadToleranceBytes` field and mid-run lead detection does not exist.

- [ ] **Step 3: Extend pair result and options**

In `pkg/transfertrace/checker.go`, extend `PairOptions` and `PairResult`:

```go
type PairOptions struct {
	Role                       Role
	PeerRole                   Role
	RateTolerance              float64
	ProgressLeadToleranceBytes int64
}

type PairResult struct {
	PrimaryRows          int
	PeerRows             int
	ProgressDeltaBytes   int64
	MaxProgressLeadBytes int64
	SenderRateMbps       float64
	ReceiverRateMbps     float64
}
```

- [ ] **Step 4: Add mid-run lead computation**

In `pkg/transfertrace/checker.go`, add helpers after `senderReceiverRows`:

```go
func maxSenderProgressLead(senderRows []checkerRow, receiverRows []checkerRow) int64 {
	var maxLead int64
	receiverIndex := 0
	var receiverBytes int64
	for _, sender := range senderRows {
		senderElapsed := comparableElapsed(sender)
		for receiverIndex < len(receiverRows) && comparableElapsed(receiverRows[receiverIndex]) <= senderElapsed {
			if receiverRows[receiverIndex].appBytes > receiverBytes {
				receiverBytes = receiverRows[receiverIndex].appBytes
			}
			receiverIndex++
		}
		lead := sender.peerReceivedBytes - receiverBytes
		if lead > maxLead {
			maxLead = lead
		}
	}
	return maxLead
}

func comparableElapsed(row checkerRow) int64 {
	if row.transferElapsedMS > 0 {
		return row.transferElapsedMS
	}
	return row.timestamp.UnixMilli()
}
```

Modify `compareCheckerPair` to set and validate `MaxProgressLeadBytes`:

```go
maxLead := maxSenderProgressLead(senderRows, receiverRows)
result := PairResult{
	PrimaryRows:          len(primaryRows),
	PeerRows:             len(peerRows),
	ProgressDeltaBytes:   delta,
	MaxProgressLeadBytes: maxLead,
	SenderRateMbps:       mbps(senderFinal.peerReceivedBytes, senderFinal.transferElapsedMS),
	ReceiverRateMbps:     mbps(receiverFinal.appBytes, receiverFinal.transferElapsedMS),
}
if maxLead > opts.ProgressLeadToleranceBytes {
	return result, fmt.Errorf("sender progress leads receiver by %d bytes, tolerance=%d", maxLead, opts.ProgressLeadToleranceBytes)
}
```

Keep the final delta check after the mid-run lead check.

- [ ] **Step 5: Expose CLI flag**

In `tools/transfertracecheck/main.go`, add `ProgressLeadToleranceBytes int64` to `options`.

In `parseOptions`, add:

```go
var progressLeadToleranceBytes int64
flags.Int64Var(&progressLeadToleranceBytes, "progress-lead-tolerance", 0, "allowed sender peer progress lead over receiver app bytes")
if progressLeadToleranceBytes < 0 {
	_, _ = fmt.Fprintln(stderr, "progress-lead-tolerance must be non-negative")
	flags.Usage()
	return options{}, errUsage
}
```

Return it in `options`, and pass it in `checkPairPaths`:

```go
ProgressLeadToleranceBytes: opts.ProgressLeadToleranceBytes,
```

- [ ] **Step 6: Add CLI tests**

Add to `tools/transfertracecheck/main_test.go`:

```go
func TestRunRejectsNegativeProgressLeadTolerance(t *testing.T) {
	path := writeTrace(t, "timestamp_unix_ms,role,phase,app_bytes,last_error\n"+
		"1000,receive,complete,0,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "receive", "-progress-lead-tolerance", "-1", path}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "progress-lead-tolerance must be non-negative") {
		t.Fatalf("stderr = %q, want progress-lead-tolerance validation", stderr.String())
	}
}
```

Add a positive CLI case by extending `TestRunChecksPeerTraceSuccess` command args:

```go
code := run([]string{"-role", "send", "-expected-bytes", "1024", "-progress-lead-tolerance", "0", "-peer-trace", receivePath, sendPath}, &stdout, &stderr)
```

- [ ] **Step 7: Run trace checker tests**

Run:

```bash
go test ./pkg/transfertrace ./tools/transfertracecheck -count=1
```

Expected: PASS.

- [ ] **Step 8: Commit**

Run:

```bash
git add pkg/transfertrace/checker.go pkg/transfertrace/checker_test.go tools/transfertracecheck/main.go tools/transfertracecheck/main_test.go
git commit -m "test: detect sender receiver trace divergence"
```

### Task 3: Document Phase 1 Live Gate And Iperf Port

**Files:**
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Add the Phase 1 gate section**

In `docs/benchmarks.md`, after `## Baseline Comparisons`, add:

````markdown
## Phase 1 Public Transport Gate

Before changing the public transport protocol, capture a baseline for each host pair and direction:

```bash
DERPHOLE_IPERF_PORT=8123 DERPHOLE_IPERF_SERVER_HOST="${DERPHOLE_IPERF_SERVER_HOST:?set forwarded Mac iperf host}" ./scripts/iperf-benchmark.sh canlxc 1024
DERPHOLE_IPERF_PORT=8123 DERPHOLE_IPERF_SERVER_HOST="${DERPHOLE_IPERF_SERVER_HOST:?set forwarded Mac iperf host}" ./scripts/iperf-benchmark-reverse.sh canlxc 1024
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh canlxc pouffe-rasp.exe.xyz 1024
```

Use `DERPHOLE_IPERF_PORT=8123` when testing through the Mac port-forwarded iperf endpoint. Use the default `8321` only when both endpoints can reach the local iperf server directly on that port.

Every accepted result must include:

- `stall-harness-success=true`
- matching source and sink SHA-256
- sender and receiver `send.trace.csv` / `receive.trace.csv`
- `transfertracecheck` success for sender and receiver traces
- `leak-check ... processes=0 udp_sockets=0` for preflight and postrun checks
- iperf TCP baseline in both directions, when routing allows it

Do not report a derphole throughput number if any leak check, trace check, or integrity check fails.
````

- [ ] **Step 2: Run docs grep**

Run:

```bash
rg -n "Phase 1 Public Transport Gate|DERPHOLE_IPERF_PORT=8123|leak-check" docs/benchmarks.md
```

Expected: all three patterns are found.

- [ ] **Step 3: Commit**

Run:

```bash
git add docs/benchmarks.md
git commit -m "docs: add phase one transport baseline gate"
```

### Task 4: Verify Phase 1 Locally

**Files:**
- No source changes expected.

- [ ] **Step 1: Run focused tests**

Run:

```bash
go test ./scripts ./pkg/transfertrace ./tools/transfertracecheck -count=1
```

Expected: PASS.

- [ ] **Step 2: Run full unit tests**

Run:

```bash
mise run test
```

Expected: PASS.

- [ ] **Step 3: Run hooks**

Run:

```bash
mise run check:hooks
```

Expected: PASS.

### Task 5: Run Phase 1 Live Baselines

**Files:**
- No source changes expected unless a command exposes a real harness bug.

- [ ] **Step 1: Build local and remote Linux binary**

Run:

```bash
mise run build-linux-amd64
```

Expected: `dist/derphole-linux-amd64` exists.

- [ ] **Step 2: Capture iperf baseline to canlxc**

Run:

```bash
DERPHOLE_IPERF_PORT=8123 DERPHOLE_IPERF_SERVER_HOST="${DERPHOLE_IPERF_SERVER_HOST:-}" ./scripts/iperf-benchmark.sh canlxc 1024
```

Expected: `benchmark-success=true`. If the forwarded hostname is not reachable from `canlxc`, set `DERPHOLE_IPERF_SERVER_HOST` to the host/address that reaches this Mac through the port forward and rerun.

- [ ] **Step 3: Capture iperf reverse baseline to canlxc**

Run:

```bash
DERPHOLE_IPERF_PORT=8123 DERPHOLE_IPERF_SERVER_HOST="${DERPHOLE_IPERF_SERVER_HOST:-}" ./scripts/iperf-benchmark-reverse.sh canlxc 1024
```

Expected: `benchmark-success=true`.

- [ ] **Step 4: Run transfer stall harness on remote pair**

Run:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh canlxc pouffe-rasp.exe.xyz 1024
```

Expected:

- `stall-harness-success=true`
- source and sink SHA-256 match
- postrun leak checks report `processes=0 udp_sockets=0`
- log directory contains `samples.csv`, `metadata.env`, `sender/send.trace.csv`, and `receiver/receive.trace.csv`

- [ ] **Step 5: Run pve1 path if SSH target is available**

Run:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh pve1 canlxc 1024
```

Expected: same success and leak criteria as Step 4. If `pve1` uses a non-root SSH user, set `DERPHOLE_REMOTE_USER` or pass `user@pve1`.

- [ ] **Step 6: Commit live-baseline notes if docs changed**

If a run exposes a missing documented knob and docs were changed, run:

```bash
git add docs/benchmarks.md
git commit -m "docs: clarify live baseline transport knobs"
```

Expected: no commit is created if no docs changed.

### Task 6: Final Verification

**Files:**
- No source changes expected.

- [ ] **Step 1: Run repository check**

Run:

```bash
mise run check
```

Expected: PASS.

- [ ] **Step 2: Confirm clean branch state**

Run:

```bash
git status --short --branch
```

Expected: branch is `main`, ahead of `origin/main` by the new commits, with no unstaged or staged changes.

- [ ] **Step 3: Push**

Run:

```bash
git push origin main
```

Expected: push succeeds.
