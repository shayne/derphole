# Deterministic Bulk Probe Outcome Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a sender-only test outcome that runs the real bulk capacity probe and then deterministically exercises the acknowledged QUIC fallback path in release-binary promotion tests.

**Architecture:** The session package wraps the existing sender probe selector, preserving its real result and errors, then applies one allowlisted environment override only to a successful selection. A typed sentinel survives the negotiated fallback cleanup path so sender runtimes can emit an auditable verbose marker. The promotion driver captures and unsets the variable, re-injects it only into the actual sender process, and refuses successful evidence unless that marker appears exactly once on the sender and never on the receiver.

**Tech Stack:** Go 1.26, Bash, in-package Go tests, promotion-driver integration tests, GitButler, `mise` verification tasks.

## Global Constraints

- The only supported configured value is `DERPHOLE_TEST_BULK_PROBE_OUTCOME=sender-reject`.
- An unset environment variable leaves sender probe selection byte-for-byte unchanged.
- An explicitly empty or unsupported value returns a clear error; it is never treated as unset.
- The underlying real sender probe selector always runs before the controlled outcome is applied.
- Underlying probe, cancellation, and cleanup errors retain priority and are never converted into a controlled rejection.
- Controlled rejection preserves probe trains, run ID, duration, loss, pressure, and sent/received diagnostics, while clearing `SelectedMbps`.
- No receiver outcome override, CLI flag, wire value, production threshold, baseline change, lint suppression, or generated `dist/` edit.
- The promotion driver supports the override only for `tool=derphole` with the `file` workload, in both forward and reverse directions.
- The driver must remove the variable from its ambient environment and explicitly inject it only into the sender process.
- Three final 3 GiB live samples must be fresh, exact-head, deterministic, sequential, and never silently retried or replaced.

---

## File Map

- `pkg/session/external_v2_bulk_packet_probe.go`: define the test outcome contract, apply it after the real sender selector, and expose a typed outcome classifier.
- `pkg/session/external_v2_bulk_packet.go`: retain the controlled-outcome sentinel through negotiated pre-payload cleanup.
- `pkg/session/external_v2.go`: emit the sender-only controlled-outcome marker for claimant-sender fallback.
- `pkg/session/external_v2_offer.go`: emit the same marker for offerer-sender fallback.
- `pkg/session/external_v2_bulk_packet_probe_test.go`: unit-test unset, configured, invalid, and underlying-error priority behavior.
- `pkg/session/external_v2_block_test.go`: exercise the real probe, decision, exact ACK, marker, QUIC fallback, payload, and post-return telemetry lifetime.
- `scripts/promotion-benchmark-driver.sh`: validate, scrub, sender-inject, record, and verify the test outcome.
- `scripts/promotion_scripts_test.go`: test invalid input, forward/reverse sender-only propagation, marker enforcement, and unchanged unset behavior.
- `.superpowers/sdd/deterministic-bulk-probe-outcome-report.md`: ignored execution and live-evidence report; do not commit it.

---

### Task 1: Session-Level Controlled Sender Rejection

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet_probe.go:16-27,162-200`
- Modify: `pkg/session/external_v2_bulk_packet.go:332-343`
- Modify: `pkg/session/external_v2.go:337-382`
- Modify: `pkg/session/external_v2_offer.go:310-323`
- Modify: `pkg/session/external_v2_bulk_packet_probe_test.go`
- Modify: `pkg/session/external_v2_block_test.go:701-801`

**Interfaces:**
- Consumes: `externalV2BulkPacketSenderProbeSelector`, `externalV2BulkPacketProbeResult`, `errExternalV2BulkPacketProbeRejected`, `emitExternalV2Debug`, and negotiated fallback error joining.
- Produces: `externalV2BulkPacketProbeTestOutcomeEnv`, `externalV2BulkPacketProbeTestOutcomeSenderReject`, `errExternalV2BulkPacketProbeForcedSenderReject`, `selectExternalV2BulkPacketSenderProbe`, `applyExternalV2BulkPacketSenderProbeTestOutcome`, `externalV2BulkPacketProbeTestOutcome`, and `emitExternalV2BulkPacketProbeFallback`.

- [ ] **Step 1: Write the failing unit tests for the outcome transformer**

Add `reflect` to the test imports, then add table-driven coverage to `pkg/session/external_v2_bulk_packet_probe_test.go`. The test must use a nontrivial probe result so every preserved field is observable:

```go
func TestApplyExternalV2BulkPacketSenderProbeTestOutcome(t *testing.T) {
	base := externalV2BulkPacketProbeResult{
		RunID:        77,
		SelectedMbps: 900,
		Duration:     125 * time.Millisecond,
		Trains: []externalV2BulkPacketProbeTrainResult{{
			RateMbps: 1000, Sent: 100, Received: 99, Pressure: true,
		}},
	}
	probeFailure := errors.New("probe failed")
	tests := []struct {
		name       string
		value      string
		configured bool
		inputErr   error
		want       externalV2BulkPacketProbeResult
		wantErr    error
		wantText   string
	}{
		{name: "unset", want: base},
		{name: "sender reject", value: "sender-reject", configured: true,
			want: externalV2BulkPacketProbeResult{RunID: 77, Duration: 125 * time.Millisecond, Trains: base.Trains},
			wantErr: errExternalV2BulkPacketProbeForcedSenderReject},
		{name: "explicit empty", configured: true, want: base,
			wantText: `DERPHOLE_TEST_BULK_PROBE_OUTCOME must be unset or "sender-reject" (got "")`},
		{name: "unsupported", value: "receiver-reject", configured: true, want: base,
			wantText: `DERPHOLE_TEST_BULK_PROBE_OUTCOME must be unset or "sender-reject" (got "receiver-reject")`},
		{name: "probe error wins", value: "receiver-reject", configured: true, inputErr: probeFailure,
			want: base, wantErr: probeFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := applyExternalV2BulkPacketSenderProbeTestOutcome(base, tt.inputErr, tt.value, tt.configured)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("result = %#v, want %#v", got, tt.want)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantText != "" && (err == nil || err.Error() != tt.wantText) {
				t.Fatalf("error = %v, want %q", err, tt.wantText)
			}
			if tt.wantErr == nil && tt.wantText == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
```

Add a wrapper test proving that the underlying selector runs before the environment outcome:

```go
func TestSelectExternalV2BulkPacketSenderProbeAppliesOutcomeAfterSelector(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_BULK_PROBE_OUTCOME", "sender-reject")
	previous := externalV2BulkPacketSenderProbeSelector
	t.Cleanup(func() { externalV2BulkPacketSenderProbeSelector = previous })
	called := false
	externalV2BulkPacketSenderProbeSelector = func(trains []externalV2BulkPacketProbeTrainResult) (externalV2BulkPacketProbeResult, error) {
		called = true
		return externalV2BulkPacketProbeResult{SelectedMbps: 900, Trains: append([]externalV2BulkPacketProbeTrainResult(nil), trains...)}, nil
	}
	trains := []externalV2BulkPacketProbeTrainResult{{RateMbps: 1000, Sent: 10, Received: 10}}
	got, err := selectExternalV2BulkPacketSenderProbe(trains)
	if !called || !errors.Is(err, errExternalV2BulkPacketProbeForcedSenderReject) {
		t.Fatalf("selector called=%t error=%v", called, err)
	}
	if got.SelectedMbps != 0 || !reflect.DeepEqual(got.Trains, trains) {
		t.Fatalf("controlled result = %#v, want preserved trains and zero rate", got)
	}
}
```

- [ ] **Step 2: Convert the existing end-to-end fallback test into a failing environment-driven test**

In `TestExternalV2ProbeFallbackCompletesThroughQUICBeforePayload`, remove the `externalV2BulkPacketSenderProbeSelector` replacement and set:

```go
t.Setenv("DERPHOLE_TEST_BULK_PROBE_OUTCOME", "sender-reject")
```

Keep all existing readiness, decision, ACK, fallback, payload, barrier-lifetime, and post-return telemetry assertions. Add sender-only marker assertions:

```go
const forcedMarker = "v2-bulk-probe-test-outcome=sender-reject"
if !strings.Contains(offerStatus.String(), forcedMarker) {
	t.Fatalf("offer status missing %q: %q", forcedMarker, offerStatus.String())
}
if strings.Contains(receiveStatus.String(), forcedMarker) {
	t.Fatalf("receiver status unexpectedly contains %q: %q", forcedMarker, receiveStatus.String())
}
```

- [ ] **Step 3: Run the focused tests and confirm RED for the missing contract**

Run:

```bash
mise exec -- go test ./pkg/session -run 'Test(Apply|Select)ExternalV2BulkPacketSenderProbeTestOutcome|TestSelectExternalV2BulkPacketSenderProbeAppliesOutcomeAfterSelector|TestExternalV2ProbeFallbackCompletesThroughQUICBeforePayload' -count=1
```

Expected: compile failure because the new helper and sentinel do not exist, or the fallback test fails because the environment variable and marker are ignored.

- [ ] **Step 4: Implement the pure outcome contract after the real selector**

Add `os` to `pkg/session/external_v2_bulk_packet_probe.go`, then define:

```go
const (
	externalV2BulkPacketProbeTestOutcomeEnv          = "DERPHOLE_TEST_BULK_PROBE_OUTCOME"
	externalV2BulkPacketProbeTestOutcomeSenderReject = "sender-reject"
)

var errExternalV2BulkPacketProbeForcedSenderReject = errors.New("bulk packet sender probe rejected by test outcome")

func selectExternalV2BulkPacketSenderProbe(trains []externalV2BulkPacketProbeTrainResult) (externalV2BulkPacketProbeResult, error) {
	result, err := externalV2BulkPacketSenderProbeSelector(trains)
	value, configured := os.LookupEnv(externalV2BulkPacketProbeTestOutcomeEnv)
	return applyExternalV2BulkPacketSenderProbeTestOutcome(result, err, value, configured)
}

func applyExternalV2BulkPacketSenderProbeTestOutcome(
	result externalV2BulkPacketProbeResult,
	selectionErr error,
	value string,
	configured bool,
) (externalV2BulkPacketProbeResult, error) {
	if selectionErr != nil || !configured {
		return result, selectionErr
	}
	if value != externalV2BulkPacketProbeTestOutcomeSenderReject {
		return result, fmt.Errorf(
			"%s must be unset or %q (got %q)",
			externalV2BulkPacketProbeTestOutcomeEnv,
			externalV2BulkPacketProbeTestOutcomeSenderReject,
			value,
		)
	}
	result.SelectedMbps = 0
	return result, errors.Join(errExternalV2BulkPacketProbeRejected, errExternalV2BulkPacketProbeForcedSenderReject)
}

func externalV2BulkPacketProbeTestOutcome(err error) string {
	if errors.Is(err, errExternalV2BulkPacketProbeForcedSenderReject) {
		return externalV2BulkPacketProbeTestOutcomeSenderReject
	}
	return ""
}
```

Change `sendExternalV2BulkPacketProbe` to call `selectExternalV2BulkPacketSenderProbe(trains)` instead of the selector variable directly. Keep `RunID` and `Duration` assignment after that call, so the controlled result retains the real run and timing.

- [ ] **Step 5: Preserve the typed outcome through acknowledged fallback cleanup**

In `pkg/session/external_v2_bulk_packet.go`, add:

```go
func externalV2BulkPacketSenderFallbackError(probeErr error) error {
	if errors.Is(probeErr, errExternalV2BulkPacketProbeForcedSenderReject) {
		return errors.Join(errExternalV2BulkPacketProbeRejected, errExternalV2BulkPacketProbeForcedSenderReject)
	}
	return errExternalV2BulkPacketProbeRejected
}
```

Use it only after the coordinator returns an acknowledged QUIC decision:

```go
if decision.Mode == externalV2BulkModeQUIC {
	return cleanupExternalV2BulkPacketSenderBeforePayload(
		sender, cancel, writeDeadlineDone, controlDone, path,
		externalV2BulkPacketSenderFallbackError(probeErr),
	)
}
```

This keeps ordinary rejection behavior unchanged and carries only the test sentinel into runtime telemetry.

- [ ] **Step 6: Emit the marker from both sender runtime topologies**

In `pkg/session/external_v2.go`, define a shared sender-side helper:

```go
func emitExternalV2BulkPacketProbeFallback(emitter *telemetry.Emitter, err error) {
	if outcome := externalV2BulkPacketProbeTestOutcome(err); outcome != "" {
		emitExternalV2Debug(emitter, "v2-bulk-probe-test-outcome="+outcome)
	}
	emitExternalV2Debug(emitter, "v2-bulk-probe=fallback-before-payload")
}
```

Replace only the sender fallback emissions in `externalV2SendRuntime.sendStream` and `externalV2OfferRuntime.tryOfferSendBulkPacketBlock`:

```go
emitExternalV2BulkPacketProbeFallback(rt.cfg.Emitter, err)
```

Do not change the two receiver fallback emissions in `pkg/session/external_v2_block.go`; the marker is sender-only.

- [ ] **Step 7: Run focused, repeated, and race verification**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestApplyExternalV2BulkPacketSenderProbeTestOutcome|TestSelectExternalV2BulkPacketSenderProbeAppliesOutcomeAfterSelector|TestExternalV2ProbeFallbackCompletesThroughQUICBeforePayload' -count=20
mise exec -- go test -race ./pkg/session -run 'TestApplyExternalV2BulkPacketSenderProbeTestOutcome|TestSelectExternalV2BulkPacketSenderProbeAppliesOutcomeAfterSelector|TestExternalV2ProbeFallbackCompletesThroughQUICBeforePayload' -count=10
mise exec -- go test ./pkg/session -run '^TestExternalV2Bulk(Packet|Decision)|^TestExternalV2ProbeFallback' -count=1
mise run check:fast
git diff --check
```

Expected: every command passes; the end-to-end test observes the marker only on the sender, all decision/ACK markers precede fallback, and payload still completes through QUIC.

- [ ] **Step 8: Review and commit Task 1**

Create `.superpowers/sdd/deterministic-bulk-probe-outcome-report.md` with RED/GREEN commands, exact error strings, marker ordering, and file scope. Generate an immutable review package from `df7b1011` to the candidate Task 1 head, obtain independent spec and quality review, fix all Critical/Important findings, and amend until clean.

Commit with GitButler:

```bash
but pull --check
but commit codex/bulk-probe-decision-barrier -m "session: add deterministic bulk probe outcome"
```

Expected: one clean Task 1 commit, no uncommitted files, no push.

---

### Task 2: Promotion Driver Sender-Only Injection and Evidence Gate

**Files:**
- Modify: `scripts/promotion-benchmark-driver.sh:8-37,193-237,339-382,1343-1477,1479-1521`
- Modify: `scripts/promotion_scripts_test.go:70-150, newPromotionDriverTest fake derphole, promotion driver integration tests`

**Interfaces:**
- Consumes: `DERPHOLE_TEST_BULK_PROBE_OUTCOME`, sender marker `v2-bulk-probe-test-outcome=sender-reject`, sender/receiver role logs, and `DERPHOLE_BENCH_EXPECT_TRANSFER_MODE`.
- Produces: validated `bulk_probe_outcome`, `bulk_probe_outcome_configured`, `sender_test_env`, `sender_test_env_remote`, `require_bulk_probe_outcome_marker`, and footer/preflight field `benchmark-test-bulk-probe-outcome`.

- [ ] **Step 1: Extend the fake binary to expose role-specific environment evidence**

In the fake derphole script inside `newPromotionDriverTest`, record the captured value for both file roles and emit the real marker only from `send`:

```bash
case "${command}" in
  send)
    printf 'send-probe-outcome=%s\n' "${DERPHOLE_TEST_BULK_PROBE_OUTCOME-<unset>}" >>"${FAKE_DERPHOLE_STATE}/probe-outcome-events"
    if [[ "${DERPHOLE_TEST_BULK_PROBE_OUTCOME-}" == "sender-reject" && "${FAKE_SKIP_BULK_PROBE_OUTCOME_MARKER:-0}" != "1" ]]; then
      printf 'v2-bulk-probe-test-outcome=sender-reject\n' >&2
    fi
    # retain the existing fake send behavior
    ;;
  receive)
    printf 'receive-probe-outcome=%s\n' "${DERPHOLE_TEST_BULK_PROBE_OUTCOME-<unset>}" >>"${FAKE_DERPHOLE_STATE}/probe-outcome-events"
    # retain the existing fake receive behavior
    ;;
esac
```

- [ ] **Step 2: Write failing validation, propagation, and marker tests**

Add these tests to `scripts/promotion_scripts_test.go`:

```go
func TestPromotionBenchmarkRejectsInvalidBulkProbeOutcome(t *testing.T) {
	for _, value := range []string{"", "receiver-reject"} {
		t.Run(strconv.Quote(value), func(t *testing.T) {
			harness := newPromotionDriverTest(t)
			cmd := harness.command("forward", map[string]string{"DERPHOLE_TEST_BULK_PROBE_OUTCOME": value})
			output, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(output),
				`DERPHOLE_TEST_BULK_PROBE_OUTCOME must be unset or sender-reject`) {
				t.Fatalf("invalid outcome result = %v\n%s", err, output)
			}
		})
	}
}

func TestPromotionBenchmarkPropagatesBulkProbeOutcomeToSenderOnly(t *testing.T) {
	for _, direction := range []string{"forward", "reverse"} {
		t.Run(direction, func(t *testing.T) {
			harness := newPromotionDriverTest(t)
			cmd := harness.command(direction, map[string]string{
				"DERPHOLE_TEST_BULK_PROBE_OUTCOME":   "sender-reject",
				"DERPHOLE_BENCH_EXPECT_TRANSFER_MODE": "blocks-v1",
				"FAKE_BULK_QUIC_DECISION":             "1",
			})
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("controlled benchmark failed: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), "benchmark-test-bulk-probe-outcome=sender-reject") {
				t.Fatalf("missing outcome evidence:\n%s", output)
			}
			events, err := os.ReadFile(filepath.Join(harness.stateDir, "probe-outcome-events"))
			if err != nil {
				t.Fatal(err)
			}
			if got, want := string(events), "send-probe-outcome=sender-reject\nreceive-probe-outcome=<unset>\n"; got != want {
				t.Fatalf("outcome propagation = %q, want %q", got, want)
			}
			harness.assertCleaned(t, direction)
		})
	}
}

func TestPromotionBenchmarkRequiresBulkProbeOutcomeMarker(t *testing.T) {
	harness := newPromotionDriverTest(t)
	cmd := harness.command("forward", map[string]string{
		"DERPHOLE_TEST_BULK_PROBE_OUTCOME":   "sender-reject",
		"DERPHOLE_BENCH_EXPECT_TRANSFER_MODE": "blocks-v1",
		"FAKE_BULK_QUIC_DECISION":             "1",
		"FAKE_SKIP_BULK_PROBE_OUTCOME_MARKER": "1",
	})
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "sender bulk probe outcome marker count = 0, want 1") {
		t.Fatalf("missing-marker result = %v\n%s", err, output)
	}
	harness.assertCleaned(t, "forward")
}
```

Retain the existing default benchmark test as the unset-behavior proof and add an assertion that its output contains `benchmark-test-bulk-probe-outcome=unset`.

- [ ] **Step 3: Run the driver tests and confirm RED**

Run:

```bash
mise exec -- go test ./scripts -run 'TestPromotionBenchmark(RejectsInvalidBulkProbeOutcome|PropagatesBulkProbeOutcomeToSenderOnly|RequiresBulkProbeOutcomeMarker|DefaultExecutesSendBeforeReceive)' -count=1
```

Expected: failures because validation, sender-only scrubbing, evidence output, and marker enforcement are absent.

- [ ] **Step 4: Capture, validate, and scrub the variable at driver startup**

Add immediately after the existing bulk test variables:

```bash
bulk_probe_outcome="${DERPHOLE_TEST_BULK_PROBE_OUTCOME-}"
bulk_probe_outcome_configured=false
if [[ -v DERPHOLE_TEST_BULK_PROBE_OUTCOME ]]; then
  bulk_probe_outcome_configured=true
  if [[ "${bulk_probe_outcome}" != "sender-reject" ]]; then
    echo "DERPHOLE_TEST_BULK_PROBE_OUTCOME must be unset or sender-reject" >&2
    exit 2
  fi
  if [[ "${tool}" != "derphole" || "${workload}" != "file" ]]; then
    echo "DERPHOLE_TEST_BULK_PROBE_OUTCOME requires the derphole file workload" >&2
    exit 2
  fi
fi
unset DERPHOLE_TEST_BULK_PROBE_OUTCOME
bulk_probe_outcome_label="unset"
sender_test_env=()
sender_test_env_remote=""
if [[ "${bulk_probe_outcome_configured}" == true ]]; then
  bulk_probe_outcome_label="${bulk_probe_outcome}"
  sender_test_env+=(DERPHOLE_TEST_BULK_PROBE_OUTCOME="${bulk_probe_outcome}")
  sender_test_env_remote="DERPHOLE_TEST_BULK_PROBE_OUTCOME=sender-reject "
fi
```

The explicit `unset` is mandatory: it prevents the script's local receiver and helper processes from inheriting the test seam.

- [ ] **Step 5: Record the request before the run and in every footer**

After input validation, emit:

```bash
echo "benchmark-test-bulk-probe-outcome=${bulk_probe_outcome_label}"
```

Add the same line to `emit_benchmark_footer`:

```bash
echo "benchmark-test-bulk-probe-outcome=${bulk_probe_outcome_label}"
```

This preserves the request on both success and failure paths.

- [ ] **Step 6: Inject the override only into forward and reverse senders**

Change the forward local sender invocation to start with an explicit environment:

```bash
env "${sender_test_env[@]}" DERPHOLE_TRANSFER_TRACE_CSV="${sender_trace_csv}" \
  "${local_runstats}" -out "${sender_resource_json}" -- \
  "${local_bin}" --verbose send "${direct_tcp_args[@]}" "${payload}" \
  >/dev/null 2>"${sender_log}" &
```

Keep the forward remote receiver command unchanged; `remote_env` must not contain the probe outcome.

In both reverse remote sender command templates, place the fixed allowlisted prefix immediately before `DERPHOLE_TRANSFER_TRACE_CSV`:

```bash
${sender_test_env_remote}DERPHOLE_TRANSFER_TRACE_CSV="${remote_base}.trace.csv"
```

Keep the reverse local receiver invocation unchanged. Because startup scrubbed the ambient variable, it cannot inherit the outcome.

- [ ] **Step 7: Require exactly one sender marker and no receiver marker**

Add:

```bash
require_bulk_probe_outcome_marker() {
  [[ "${bulk_probe_outcome_configured}" == true ]] || return 0
  local marker="v2-bulk-probe-test-outcome=${bulk_probe_outcome}"
  local sender_count
  sender_count="$(grep -Fxc "${marker}" "${sender_log}" || true)"
  if [[ "${sender_count}" != "1" ]]; then
    echo "sender bulk probe outcome marker count = ${sender_count}, want 1" >&2
    return 1
  fi
  if grep -Fq 'v2-bulk-probe-test-outcome=' "${receiver_log}"; then
    echo "receiver unexpectedly emitted a bulk probe outcome marker" >&2
    return 1
  fi
}
```

Call `require_bulk_probe_outcome_marker` at the start of `finalize_run`, after sender and receiver logs have been collected and before transfer-mode classification. The existing expected-mode gate remains independent and follows it.

- [ ] **Step 8: Run driver-focused and full script verification**

Run:

```bash
mise exec -- go test ./scripts -run 'TestPromotionBenchmark' -count=20
mise exec -- go test -race ./scripts -run 'TestPromotionBenchmark' -count=5
mise exec -- go test ./scripts -count=1
mise run check:fast
git diff --check
```

Expected: all pass; forward and reverse events prove the receiver sees `<unset>`, missing markers fail before success, and the default run reports `unset`.

- [ ] **Step 9: Review and commit Task 2**

Append validation, propagation, marker, and cleanup evidence to `.superpowers/sdd/deterministic-bulk-probe-outcome-report.md`. Generate an immutable diff from the Task 1 commit to the Task 2 candidate, obtain independent spec and code-quality review, fix all Critical/Important findings, and amend until clean.

Commit with GitButler:

```bash
but pull --check
but commit codex/bulk-probe-decision-barrier -m "scripts: force deterministic probe fallback evidence"
```

Expected: one clean Task 2 commit, no uncommitted files, no push.

---

### Task 3: Exact-Head Gates and Deterministic Live Acceptance

**Files:**
- Modify locally only: `.superpowers/sdd/deterministic-bulk-probe-outcome-report.md`
- Create ignored artifacts from the resolved commit: `.tmp/task6-verification-final/head-${candidate_short_sha}-forced-sender-reject/`
- Do not modify tracked source after the exhaustive gate begins.

**Interfaces:**
- Consumes: exact Task 2 head, archived-tree release binaries, `DERPHOLE_TEST_BULK_PROBE_OUTCOME=sender-reject`, `DERPHOLE_BENCH_EXPECT_TRANSFER_MODE=blocks-v1`, paired trace checker, and the promotion benchmark driver.
- Produces: three distinct exact-head live evidence bundles and a final independently reviewed branch.

- [ ] **Step 1: Freeze and preflight the final candidate**

Run:

```bash
candidate_sha="$(git rev-parse codex/bulk-probe-decision-barrier)"
candidate_short_sha="${candidate_sha:0:8}"
artifact_root=".tmp/task6-verification-final/head-${candidate_short_sha}-forced-sender-reject"
mkdir -p "${artifact_root}"
but status
but pull --check
git diff --check
git status --short
```

Expected: only `codex/bulk-probe-decision-barrier` is applied, the working tree is clean, and `origin/main` is current.

- [ ] **Step 2: Run compact post-review behavior and race sanity**

Run:

```bash
mise exec -- go test ./pkg/session ./scripts -run 'TestApplyExternalV2BulkPacketSenderProbeTestOutcome|TestSelectExternalV2BulkPacketSenderProbeAppliesOutcomeAfterSelector|TestExternalV2ProbeFallbackCompletesThroughQUICBeforePayload|TestPromotionBenchmark' -count=3
mise exec -- go test -race ./pkg/session ./scripts -run 'TestApplyExternalV2BulkPacketSenderProbeTestOutcome|TestSelectExternalV2BulkPacketSenderProbeAppliesOutcomeAfterSelector|TestExternalV2ProbeFallbackCompletesThroughQUICBeforePayload|TestPromotionBenchmark' -count=1
```

Expected: both commands pass with no race report.

- [ ] **Step 3: Run the one exact exhaustive repository gate**

Run once:

```bash
mise run check
```

Expected: exit 0; coverage/quality, static analysis, vulnerability checks, hooks, and all product builds pass. Immediately confirm `git status --short` is empty. If tracked content changed, stop, review the change, commit it through the task review loop, and rerun the exhaustive gate on the new final head.

- [ ] **Step 4: Build and bind exact archived-tree binaries**

Use the proven archived-tree release procedure from `.superpowers/sdd/task-6-report.md`. Record:

```text
commit SHA
tree SHA
Darwin binary SHA-256
Linux amd64 binary SHA-256
embedded candidate version for derphole, derptun, and derpssh
release manifest/checksum validation
```

Expected: all binaries and npm manifests identify the full final candidate; the remote Linux binary hash matches the archived artifact exactly.

- [ ] **Step 5: Preflight local and `ubuntu@eric-nuc` endpoints**

Verify the remote architecture is `x86_64`, no derphole or iperf3 process remains, no prior benchmark socket/listener remains, Tailscale candidates are disabled, and exact candidate binary/hash overrides are set. Preserve preflight output in the new forced-outcome artifact root.

- [ ] **Step 6: Execute three deterministic samples sequentially**

For each run, invoke one promotion sample with:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
DERPHOLE_TEST_BULK_PROBE_OUTCOME=sender-reject \
DERPHOLE_BENCH_EXPECT_TRANSFER_MODE=blocks-v1 \
DERPHOLE_BENCH_WORKLOAD=file \
DERPHOLE_BENCH_LOCAL_BIN="${darwin_bin}" \
DERPHOLE_BENCH_LINUX_BIN="${linux_bin}" \
DERPHOLE_BENCH_LOCAL_BIN_SHA256="${darwin_sha256}" \
DERPHOLE_BENCH_LINUX_BIN_SHA256="${linux_sha256}" \
DERPHOLE_BENCH_REVISION_LABEL="${candidate_sha}" \
scripts/promotion-test.sh ubuntu@eric-nuc 3072
```

Set `darwin_bin`, `linux_bin`, `darwin_sha256`, and `linux_sha256` directly from the paths and digests produced and recorded by Step 4; do not rebuild or rediscover them between samples.

Run sample 2 only after sample 1 has passed every acceptance check, and sample 3 only after sample 2 has passed. Stop on the first nonzero result. Preserve a failed sample with its ordinal; never rerun or replace it in the three-sample acceptance set.

- [ ] **Step 7: Validate every live sample**

For each sender/receiver pair, require:

```text
exact bytes = 3221225472
source SHA-256 = sink SHA-256
eight unique globally routable raw-direct lanes on both peers
real sender probe train count > 0 and sent/received datagrams > 0
exactly one sender marker v2-bulk-probe-test-outcome=sender-reject
no receiver test-outcome marker
identical decision presence, mode=quic, reason=sender-probe-rejected, and nonzero run ID
decision < exact ACK < fallback < first payload progress
final engine = quic-blocks-v1
trace checker = trace-ok on all six traces
max_flatline = 0s
no peer disconnected, deadline, terminal error, panic, or process/socket leak
benchmark-success = true
benchmark-cleanup-success = true
remote Linux binary SHA-256 = exact archived binary SHA-256
```

Report canonical and wall Mbps plus receiver QUIC handshake milliseconds for all three runs.

- [ ] **Step 8: Audit the final evidence and whole branch**

Append exact commands, hashes, run IDs, metrics, marker counts, trace ordering, cleanup counts, and artifact paths to `.superpowers/sdd/deterministic-bulk-probe-outcome-report.md` and `.superpowers/sdd/task-6-report.md`.

Create immutable review packages for:

```text
Task 2 parent..final head
origin/main merge base..final head
```

Obtain an independent evidence audit and a final whole-branch review. Fix every Critical/Important finding through a new reviewed checkpoint, then repeat the exhaustive gate and all three deterministic live samples on the changed exact head. Finish only when both reviews are clean.

- [ ] **Step 9: Final clean-state handoff**

Run:

```bash
but pull --check
but status
git diff --check
git status --short
```

Expected: clean local GitButler stack on the final commit, no push or landing. Report local checkpoint state separately from `origin/main` publication state and ask for explicit finish-to-main authorization if it has not already been given.
