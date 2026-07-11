# Bulk Packet Wire-Aware Pacing and Benchmark Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Maximize sustained raw-direct bulk-transfer goodput by pacing the actual IPv4-wire cost, adapting from receiver-confirmed delivery and repair pressure, exposing the controller while it runs, verifying effective UDP buffers, and reporting throughput from the correct transfer clock.

**Architecture:** Keep the existing `bulk-packets-v1` protocol and selective-repair data plane intact. Add a pure 500 ms controller whose inputs are cumulative primary-wire bytes, repair-wire bytes, and receiver-confirmed progress; wire it to the existing limiter and trace diagnostics, while the benchmark harness provides an independent arithmetic and integrity oracle. Keep socket-buffer observations in verbose logs and reuse the current trace schema so old trace readers remain compatible.

**Tech Stack:** Go 1.26 through `mise`, `golang.org/x/time/rate`, `golang.org/x/sys/unix`, Bash, CSV transfer traces, `transfertracecheck`, `iperf3`, SSH, GitButler.

## Global Constraints

- Normal transfers remain automatic: no new required CLI flag or environment variable.
- Pin Go 1.26.5 in `.mise.toml`; it is the minimum version containing the standard-library fix required by the repository vulnerability hook.
- Preserve `bulk-packets-v1` framing, negotiation, authentication, lane selection, repair messages, completion messages, and fallback behavior.
- Production raw-direct sockets are `udp4`, so controller rates are aggregate IPv4-wire Mbps and each datagram is charged for 20 IPv4-header bytes plus 8 UDP-header bytes.
- Start at 1000 IPv4-wire Mbps, keep the 2400 Mbps ceiling and 128 Mbps floor, use a 64 KiB limiter burst, increase by 64 Mbps per accepted clean window, and decrease to 85 percent on repair pressure.
- A 500 ms feedback window needs at least 8 MiB of primary wire traffic before it can change the target.
- Repair pressure is soft at 2 percent and hard at 8 percent. Delivery is healthy at or above 90 percent of the current wire target after converting receiver-confirmed payload to estimated IPv4-wire rate.
- After a decrease, hold for four complete feedback windows before allowing another increase.
- Reuse `rate_target_mbps`, `direct_rate_selected_mbps`, `controller_decision`, `controller_reason`, `retransmits`, `repair_requests`, and `repair_bytes`; do not change the transfer-trace CSV schema in this project.
- Effective socket-buffer values are verbose diagnostics. Report raw values returned by the kernel; do not halve Linux values.
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` remains test-only. Production candidate selection is unchanged.
- A performance sample is accepted only after byte count, SHA-256, direct-path evidence, sender and receiver trace checks, zero steady direct-phase stalls of at least one second, and zero process/socket leaks all pass.
- The long-haul change does not pass if its corrected three-run mean is below 95 percent of the recorded 897.78 Mbps baseline, if its same-run derphole-to-iperf ratio falls below 0.90, or if the fast-host control regresses by more than 5 percent.
- Do not change QUIC, manager-path scheduling, candidate selection, the receiver assembler, packet format, protocol capability strings, CLI flags, packaging, version numbers, or release workflows.
- Use GitButler for branch and commit writes. Do not push, open a pull request, or land on `main` unless the user explicitly asks.

---

## File Structure

### Create

- `pkg/session/external_v2_bulk_packet_controller.go` — pure wire-rate feedback controller, byte-cost helpers, constants, and decisions.
- `pkg/session/external_v2_bulk_packet_controller_test.go` — deterministic controller tests with no network or wall-clock dependency.
- `pkg/session/external_socket_buffer.go` — platform-neutral tuning result and the common tuning function.
- `pkg/session/external_socket_buffer_unix.go` — Darwin/Linux `getsockopt` implementation.
- `pkg/session/external_socket_buffer_other.go` — unsupported-platform fallback that preserves builds.
- `pkg/session/external_socket_buffer_test.go` — setter-error and requested-value tests with a fake `net.PacketConn`.
- `pkg/session/external_socket_buffer_unix_test.go` — Darwin/Linux real-UDP verification of kernel-returned values.

### Modify

- `.mise.toml` — move the repository Go toolchain from 1.26.4 to 1.26.5 before any implementation commit.
- `scripts/promotion-benchmark-driver.sh` — separate receiver transfer time, command time, and postflight time; use a run-scoped remote binary.
- `scripts/public-path-performance-harness.sh` — carry corrected footer operands into `summary.csv` and cross-check them against `transfertracecheck`.
- `scripts/promotion_scripts_test.go` — executable and source-order regression tests for the benchmark contract.
- `pkg/session/external_transfer_metrics.go` — receiver-progress snapshot API, diagnostics-only updates, and monotonic cumulative counters.
- `pkg/session/external_transfer_metrics_test.go` — non-terminal controller trace and monotonic-counter tests.
- `pkg/session/external_v2_bulk_packet.go` — controller lifecycle, wire-byte charging, exact primary/repair counters, and live diagnostic publication.
- `pkg/session/external_v2_bulk_packet_test.go` — sender integration, exact repair accounting, and non-terminal trace tests.
- `pkg/session/external.go` — remove the old fire-and-forget socket tuner and consume the shared tuner.
- `pkg/session/external_v2_dataplane.go` — emit requested and effective socket buffers for every raw-direct lane.
- `docs/benchmarks.md` — define timer semantics, controller fields, socket diagnostics, and the A/B acceptance gate.

### Deliberately Unchanged

- `pkg/transfertrace/trace.go` and `pkg/transfertrace/checker.go` — the required controller fields already exist.
- `pkg/session/external_v2_block.go` — block-transfer selection and receiver flow remain unchanged.
- `pkg/session/external_v2_offer.go` and `pkg/session/external_v2.go` — both sender forms already feed peer progress into `externalTransferMetrics`.

---

### Task 0: Upgrade the repository Go toolchain

**Files:**

- Modify: `.mise.toml:2`
- Commit: `docs/superpowers/plans/2026-07-11-bulk-packet-wire-pacing.md`

**Interfaces:**

- Consumes: the existing `tools/hooks/govulncheck` hook, which invokes `mise exec -- govulncheck ./...`.
- Produces: a repository pin on Go 1.26.5 so GO-2026-5856 is absent and normal GitButler commits can run every hook.

- [ ] **Step 1: Reproduce the vulnerability gate with the pinned toolchain**

Run:

```bash
mise current go
mise run vuln
```

Expected: `mise current go` prints `1.26.4`; `mise run vuln` exits 3 and reports GO-2026-5856 in `crypto/tls`, found in Go 1.26.4 and fixed in Go 1.26.5.

- [ ] **Step 2: Change only the Go pin**

In `.mise.toml`, replace:

```toml
go = "1.26.4"
```

with:

```toml
go = "1.26.5"
```

Do not change the Go vulnerability tool, Node, linters, task definitions, Go modules, or generated files.

- [ ] **Step 3: Verify the fixed toolchain and vulnerability scan**

Run:

```bash
mise install
mise current go
mise exec -- go version
mise run vuln
mise run test
```

Expected: both version commands report Go 1.26.5, `mise run vuln` exits 0 with no called vulnerabilities, and `mise run test` exits 0.

- [ ] **Step 4: Checkpoint the plan and commit the toolchain bump separately**

Run `but diff` and confirm the only uncommitted files are the plan and `.mise.toml`. Commit the plan's GitButler change ID first:

```bash
but diff
but commit codex/bulk-packet-pacing-plan --changes ur:8 -m "docs: plan wire-aware bulk packet pacing"
```

Run `but diff` again, use the displayed `.mise.toml` change ID, and commit only that ID:

```bash
but diff
but commit codex/bulk-packet-pacing-plan -m "build: bump mise Go toolchain"
```

Expected: the first commit contains only the plan, the second contains only `.mise.toml`, every normal pre-commit hook passes, and nothing is pushed.

---

### Task 1: Make the benchmark an exact, safe oracle

**Files:**

- Modify: `scripts/promotion-benchmark-driver.sh:15-100, 142-169, 424-525`
- Modify: `scripts/public-path-performance-harness.sh:88-257`
- Modify: `scripts/promotion_scripts_test.go:107-129`

**Interfaces:**

- Consumes: existing sender trace columns `app_bytes`, `transfer_elapsed_ms`, and the existing `transfertracecheck` output key `sender_mbps`.
- Produces: footer keys `benchmark-transfer-elapsed-ms`, `benchmark-command-duration-ms`, `benchmark-total-duration-ms`, `benchmark-goodput-mbps`, and `benchmark-wall-goodput-mbps`; summary columns `trace_mbps`, `wall_mbps`, `wall_ratio_to_iperf`, `transfer_elapsed_ms`, `command_duration_ms`, and `total_duration_ms`.

- [ ] **Step 1: Run the GitButler preflight and create or reuse the session branch**

Run:

```bash
but pull --check
but status
if ! but status | grep -Fq 'codex/bulk-packet-pacing-plan'; then
  but branch new codex/bulk-packet-pacing-plan
fi
```

Expected: `but pull --check` reports that the workspace can update cleanly, and `but status` shows `codex/bulk-packet-pacing-plan` without another agent's changes. Stop if another active branch touches any file listed in this plan.

- [ ] **Step 2: Replace the ambiguous source test and add behavior/order/safety tests**

Replace `TestPromotionDriverReportsAverageTraceGoodput` and add the helpers and tests below in `scripts/promotion_scripts_test.go`. Add `os/exec` to the import list.

```go
func scriptSection(t *testing.T, body, start, end string) string {
	t.Helper()
	startIndex := strings.Index(body, start)
	if startIndex < 0 {
		t.Fatalf("script missing section start %q", start)
	}
	rest := body[startIndex:]
	endIndex := strings.Index(rest, end)
	if endIndex < 0 {
		t.Fatalf("script section %q missing end %q", start, end)
	}
	return rest[:endIndex]
}

func assertScriptOrder(t *testing.T, body string, markers ...string) {
	t.Helper()
	offset := 0
	for _, marker := range markers {
		index := strings.Index(body[offset:], marker)
		if index < 0 {
			t.Fatalf("script section missing ordered marker %q", marker)
		}
		offset += index + len(marker)
	}
}

func TestPromotionDriverReportsReceiverAnchoredGoodput(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		`sender_transfer_elapsed_ms="$(last_trace_value "${sender_trace_csv}" "transfer_elapsed_ms")"`,
		`sender_goodput_mbps="$(trace_transfer_goodput_mbps "${sender_trace_csv}" "${expected_size}")"`,
		`benchmark-transfer-elapsed-ms=`,
		`benchmark-command-duration-ms=`,
		`benchmark-wall-goodput-mbps=`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("promotion driver missing receiver-anchored accounting %q", want)
		}
	}
	for _, forbidden := range []string{
		`"app_bytes" "elapsed_ms"`,
		`sender_goodput_mbps="$(last_trace_value "${sender_trace_csv}" "send_goodput_mbps")"`,
		`sender_goodput_mbps="$(last_trace_value "${sender_trace_csv}" "app_mbps")"`,
		`sender_goodput_mbps="${wall_goodput}"`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("promotion driver retains ambiguous goodput fallback %q", forbidden)
		}
	}
}

func TestPromotionTraceTransferGoodputUsesReceiverClock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	definitions := scriptSection(
		t,
		string(data),
		"goodput_mbps() {",
		"\ntrace_has_direct_bytes() {",
	)

	for _, tc := range []struct {
		name    string
		elapsed string
		want    string
		wantErr bool
	}{
		{name: "receiver anchored", elapsed: "28819", want: "894.19\n"},
		{name: "missing receiver clock", elapsed: "", wantErr: true},
		{name: "zero receiver clock", elapsed: "0", wantErr: true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			trace := filepath.Join(t.TempDir(), "sender.csv")
			content := "app_bytes,elapsed_ms,transfer_elapsed_ms\n" +
				"3221225472,32185," + tc.elapsed + "\n"
			if err := os.WriteFile(trace, []byte(content), 0o600); err != nil {
				t.Fatalf("write trace: %v", err)
			}
			cmd := exec.Command(
				"bash",
				"-c",
				definitions+`\ntrace_transfer_goodput_mbps "$1" 3221225472`,
				"test",
				trace,
			)
			output, err := cmd.CombinedOutput()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("goodput succeeded with invalid transfer clock: %q", output)
				}
				return
			}
			if err != nil {
				t.Fatalf("goodput failed: %v\n%s", err, output)
			}
			if got := string(output); got != tc.want {
				t.Fatalf("goodput = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPromotionDriverStopsCommandClockBeforePostflight(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)

	forward := scriptSection(t, body, "run_forward_derphole() {", "\nrun_reverse_derphole() {")
	assertScriptOrder(t, forward,
		"wait_remote_pid_exit",
		`command_end_ms="$(now_ms)"`,
		`remote "cat '${remote_base}.err'"`,
	)

	reverse := scriptSection(t, body, "run_reverse_derphole() {", "\nfinalize_run() {")
	assertScriptOrder(t, reverse,
		`wait "${listener_pid}"`,
		`listener_pid=""`,
		`command_end_ms="$(now_ms)"`,
		`remote "cat '${remote_base}.err'"`,
	)

	finalize := scriptSection(t, body, "finalize_run() {", "\nbuild_and_install_remote_binary")
	assertScriptOrder(t, finalize,
		`command_duration_ms="$((command_end_ms - start_ms))"`,
		"assert_no_tool_leaks",
		`end_ms="$(now_ms)"`,
		`duration_ms="$((end_ms - start_ms))"`,
	)
}

func TestPromotionDriverUsesRunScopedRemoteBinary(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)

	for _, forbidden := range []string{
		`DERPHOLE_REMOTE_BIN_DIR:-/usr/local/bin`,
		"requested_remote_bin_dir",
		`if [[ '${remote_bin_dir}' != '${requested_remote_bin_dir}' ]]`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("promotion driver retains unsafe remote binary behavior %q", forbidden)
		}
	}
	for _, want := range []string{
		`remote_bin_dir="${remote_run_dir}/bin"`,
		`remote_bin_dir="${DERPHOLE_REMOTE_BIN_DIR%/}/${tool}-promotion${remote_suffix}-$$"`,
		`rm -f '${remote_bin}'`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("promotion driver missing run-scoped remote binary behavior %q", want)
		}
	}
}

func TestPublicPathPerformanceHarnessCarriesBenchmarkOperands(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "public-path-performance-harness.sh"))
	if err != nil {
		t.Fatalf("read public-path-performance-harness.sh: %v", err)
	}
	body := string(data)
	for _, want := range []string{
		"trace_mbps",
		"wall_mbps",
		"wall_ratio_to_iperf",
		"transfer_elapsed_ms",
		"command_duration_ms",
		"total_duration_ms",
		"benchmark accounting mismatch",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("public-path harness missing benchmark operand %q", want)
		}
	}
}
```

In `TestPublicPathPerformanceHarnessRecordsFailedTraceSamples` replace the old short call assertion with:

```go
`append_summary_row "${host_label}" "${run}" "derphole" "${derphole_mbps}" "${iperf_mbps}" "${trace_sender_mbps}" "${wall_mbps}"`,
```

- [ ] **Step 3: Run the focused tests and confirm the old accounting fails**

Run:

```bash
mise exec -- go test ./scripts \
  -run 'TestPromotionDriverReportsReceiverAnchoredGoodput|TestPromotionTraceTransferGoodputUsesReceiverClock|TestPromotionDriverStopsCommandClockBeforePostflight|TestPromotionDriverUsesRunScopedRemoteBinary' \
  -count=1
```

Expected: FAIL because `trace_transfer_goodput_mbps` and the three new timer fields do not exist, the command clock is not stopped before postflight, and the default remote binary path is still `/usr/local/bin`.

- [ ] **Step 4: Implement the three-clock contract and run-scoped binary**

In `scripts/promotion-benchmark-driver.sh` initialize the clocks and outputs:

```bash
start_ms=0
command_end_ms=0
command_duration_ms=0
duration_ms=0
sender_transfer_elapsed_ms=0
wall_goodput=0
```

Replace `wall_goodput_mbps` and `trace_average_mbps` with:

```bash
goodput_mbps() {
  python3 - <<'PY' "$1" "$2"
import sys
size = int(sys.argv[1])
duration_ms = max(int(sys.argv[2]), 1)
print(f"{(size * 8.0) / (duration_ms * 1000.0):.2f}")
PY
}

trace_transfer_goodput_mbps() {
  local file="$1"
  local expected_bytes="$2"
  local transfer_elapsed_ms

  transfer_elapsed_ms="$(last_trace_value "${file}" "transfer_elapsed_ms")"
  if [[ ! "${transfer_elapsed_ms}" =~ ^[1-9][0-9]*$ ]]; then
    return 1
  fi
  goodput_mbps "${expected_bytes}" "${transfer_elapsed_ms}"
}
```

Use a unique executable path for every run:

```bash
remote_bin_dir="${remote_run_dir}/bin"
if [[ -n "${DERPHOLE_REMOTE_BIN_DIR:-}" ]]; then
  remote_bin_dir="${DERPHOLE_REMOTE_BIN_DIR%/}/${tool}-promotion${remote_suffix}-$$"
fi
remote_bin="${remote_bin_dir}/${tool}"
remote_upload="${remote_bin_dir}/${tool}.upload"
```

Create the selected directory before `scp`, install only inside it, and make cleanup unconditional:

```bash
remote "mkdir -p '${remote_run_dir}' '${remote_bin_dir}'"
scp "${linux_bin}" "${remote_target}:${remote_upload}" >/dev/null
if ! install_remote_bin "${remote_bin_dir}"; then
  echo "remote benchmark directory is not writable and executable; set DERPHOLE_REMOTE_BIN_DIR to a writable executable root" >&2
  exit 1
fi
```

```bash
remote "if [[ -f '${remote_base}.pid' ]]; then kill \$(cat '${remote_base}.pid') 2>/dev/null || true; fi; rm -f '${remote_base}.pid' '${remote_base}.payload' '${remote_base}.out' '${remote_base}.err' '${remote_base}.trace.csv' '${remote_upload}' '${remote_bin}'; rmdir '${remote_bin_dir}' '${remote_run_dir}' 2>/dev/null || true" >/dev/null 2>&1 || true
```

Delete `requested_remote_bin_dir`, the stable `/usr/local/bin` default, and the fallback directory loop.

Immediately after both transfer processes exit, record `command_end_ms` before log copies, hashes, sizes, trace checks, or leak checks:

```bash
wait_remote_pid_exit
command_end_ms="$(now_ms)"
```

```bash
wait "${listener_pid}"
listener_pid=""
command_end_ms="$(now_ms)"
```

In `finalize_run` use only the verified payload size and receiver-anchored clock for canonical goodput:

```bash
sender_transfer_elapsed_ms="$(last_trace_value "${sender_trace_csv}" "transfer_elapsed_ms")"
if ! sender_goodput_mbps="$(trace_transfer_goodput_mbps "${sender_trace_csv}" "${expected_size}")"; then
  echo "sender trace missing positive transfer_elapsed_ms" >&2
  exit 1
fi

if [[ "${command_end_ms}" -le "${start_ms}" ]]; then
  echo "invalid benchmark command timing" >&2
  exit 1
fi
command_duration_ms="$((command_end_ms - start_ms))"
wall_goodput="$(goodput_mbps "${expected_size}" "${command_duration_ms}")"

assert_no_tool_leaks

end_ms="$(now_ms)"
duration_ms="$((end_ms - start_ms))"
if [[ "${duration_ms}" -le 0 ]]; then
  duration_ms=1
fi
```

Delete the fallbacks from canonical goodput to `send_goodput_mbps`, `app_mbps`, and wall time. Preserve only the peak-rate fallback. Emit these fields from `emit_benchmark_footer` on success and failure:

```bash
echo "benchmark-size-bytes=${expected_size}"
echo "benchmark-transfer-elapsed-ms=${sender_transfer_elapsed_ms:-0}"
echo "benchmark-command-duration-ms=${command_duration_ms:-0}"
echo "benchmark-total-duration-ms=${duration_ms:-0}"
echo "benchmark-goodput-mbps=${goodput_mbps}"
echo "benchmark-wall-goodput-mbps=${wall_goodput:-0}"
```

- [ ] **Step 5: Carry the operands through the public-path summary and cross-check the trace oracle**

In `scripts/public-path-performance-harness.sh` add:

```bash
extract_benchmark_value() {
  local output="$1"
  local field="$2"
  local default_value="${3:-0}"

  python3 - "${output}" "${field}" "${default_value}" <<'PY'
import sys

path, field, default = sys.argv[1:]
prefix = field + "="
value = ""
with open(path, errors="replace") as fh:
    for line in fh:
        line = line.strip()
        if line.startswith(prefix):
            value = line[len(prefix):]
print(value or default)
PY
}
```

Make `extract_benchmark_goodput` prefer `benchmark-goodput-mbps` and retain `sender_goodput_mbps` only for reading old saved artifacts:

```bash
extract_benchmark_goodput() {
  local output="$1"
  local value

  value="$(extract_benchmark_value "${output}" "benchmark-goodput-mbps")"
  if [[ "${value}" != "0" ]]; then
    printf '%s\n' "${value}"
    return 0
  fi
  extract_benchmark_value "${output}" "sender_goodput_mbps"
}
```

Extend `extract_tracecheck_summary` to parse `sender_mbps` from the sender check and print three tab-separated values:

```python
trace_sender_mbps = ""
for path in sys.argv[1:]:
    with open(path, errors="replace") as fh:
        text = fh.read()
    for match in re.findall(r"max_peer_recv_queue_depth=([0-9]+)", text):
        max_queue = max(max_queue, int(match))
    match = re.search(r"max_flatline=([^ \n]+)", text)
    if match:
        value = match.group(1)
        seconds = duration_seconds(value)
        if seconds > max_flatline_seconds:
            max_flatline = value
            max_flatline_seconds = seconds
    match = re.search(r"sender_mbps=([0-9]+(?:\.[0-9]+)?)", text)
    if match:
        trace_sender_mbps = match.group(1)
print(f"{max_queue}\t{max_flatline}\t{trace_sender_mbps}")
```

Use this exact header:

```bash
printf 'host,run,tool,direction,mbps,ratio_to_iperf,trace_mbps,wall_mbps,wall_ratio_to_iperf,transfer_elapsed_ms,command_duration_ms,total_duration_ms,trace_ok,max_peer_recv_queue_depth,max_flatline,log_dir\n' >"${summary_csv}"
```

Replace `append_summary_row` with:

```bash
append_summary_row() {
  local host_label="$1"
  local run="$2"
  local tool="$3"
  local mbps="$4"
  local iperf_mbps="$5"
  local trace_mbps="$6"
  local wall_mbps="$7"
  local transfer_elapsed_ms="$8"
  local command_duration_ms="$9"
  local total_duration_ms="${10}"
  local trace_ok="${11}"
  local max_queue="${12}"
  local max_flatline="${13}"
  local sample_log_dir="${14}"

  python3 - \
    "${summary_csv}" \
    "${host_label}" \
    "${run}" \
    "${tool}" \
    "${direction}" \
    "${mbps}" \
    "${iperf_mbps}" \
    "${trace_mbps}" \
    "${wall_mbps}" \
    "${transfer_elapsed_ms}" \
    "${command_duration_ms}" \
    "${total_duration_ms}" \
    "${trace_ok}" \
    "${max_queue}" \
    "${max_flatline}" \
    "${sample_log_dir}" <<'PY'
import csv
import sys

(
    path,
    host,
    run,
    tool,
    direction,
    mbps,
    iperf_mbps,
    trace_mbps,
    wall_mbps,
    transfer_elapsed_ms,
    command_duration_ms,
    total_duration_ms,
    trace_ok,
    max_queue,
    max_flatline,
    log_dir,
) = sys.argv[1:]
ratio = ""
wall_ratio = ""
if mbps and float(iperf_mbps) > 0:
    ratio = f"{float(mbps) / float(iperf_mbps):.3f}"
if wall_mbps and float(iperf_mbps) > 0:
    wall_ratio = f"{float(wall_mbps) / float(iperf_mbps):.3f}"
with open(path, "a", newline="") as fh:
    csv.writer(fh).writerow([
        host,
        run,
        tool,
        direction,
        mbps,
        ratio,
        trace_mbps,
        wall_mbps,
        wall_ratio,
        transfer_elapsed_ms,
        command_duration_ms,
        total_duration_ms,
        trace_ok,
        max_queue,
        max_flatline,
        log_dir,
    ])
PY
}
```

For a successful promotion and trace check, require the rounded canonical values to agree:

```bash
if [[ -z "${trace_sender_mbps}" || "${trace_sender_mbps}" != "${derphole_mbps}" ]]; then
  echo "benchmark accounting mismatch: footer=${derphole_mbps} trace=${trace_sender_mbps:-missing}" >&2
  trace_ok="false"
  trace_status=1
fi
```

Extract and append a derphole row with:

```bash
wall_mbps="$(extract_benchmark_value "${promotion_out}" "benchmark-wall-goodput-mbps")"
transfer_elapsed_ms="$(extract_benchmark_value "${promotion_out}" "benchmark-transfer-elapsed-ms")"
command_duration_ms="$(extract_benchmark_value "${promotion_out}" "benchmark-command-duration-ms")"
total_duration_ms="$(extract_benchmark_value "${promotion_out}" "benchmark-total-duration-ms")"
IFS=$'\t' read -r max_queue max_flatline trace_sender_mbps <<<"${trace_summary}"
append_summary_row \
  "${host_label}" \
  "${run}" \
  "derphole" \
  "${derphole_mbps}" \
  "${iperf_mbps}" \
  "${trace_sender_mbps}" \
  "${wall_mbps}" \
  "${transfer_elapsed_ms}" \
  "${command_duration_ms}" \
  "${total_duration_ms}" \
  "${trace_ok}" \
  "${max_queue}" \
  "${max_flatline}" \
  "${case_log_dir}"
```

Append iperf rows with empty derphole-only operands:

```bash
append_summary_row \
  "${host_label}" \
  "${run}" \
  "iperf3" \
  "${iperf_mbps}" \
  "${iperf_mbps}" \
  "" "" "" "" "" "" "" "" \
  "${log_dir}/${host_label}"
```

- [ ] **Step 6: Run syntax and focused tests**

Run:

```bash
bash -n scripts/promotion-benchmark-driver.sh scripts/public-path-performance-harness.sh
mise exec -- go test ./scripts \
  -run 'TestPromotionDriverReportsReceiverAnchoredGoodput|TestPromotionTraceTransferGoodputUsesReceiverClock|TestPromotionDriverStopsCommandClockBeforePostflight|TestPromotionDriverUsesRunScopedRemoteBinary|TestPublicPathPerformanceHarness' \
  -count=1
```

Expected: both Bash files pass syntax checking and the Go package reports `ok`.

- [ ] **Step 7: Commit the benchmark oracle**

Run `but diff` and verify that only the three Task 1 files changed, then run:

```bash
but commit codex/bulk-packet-pacing-plan -m "bench: correct transfer throughput accounting"
```

Expected: one local GitButler commit. Do not push.

- [ ] **Step 8: Capture the pre-controller long-haul control with the corrected oracle**

Run:

```bash
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
env -u DERPHOLE_BENCH_PARALLEL \
  DERPHOLE_PUBLIC_PATH_HOSTS="${DERPHOLE_LONG_HAUL_HOST:?set the Mac-to-remote target}" \
  DERPHOLE_PUBLIC_PATH_SIZE_MIB=3072 \
  DERPHOLE_PUBLIC_PATH_RUNS=3 \
  DERPHOLE_PUBLIC_IPERF_PORT=8123 \
  DERPHOLE_BENCH_LOG_DIR=".tmp/bulk-wire-pacing-before-${stamp}" \
  ./scripts/public-path-performance-harness.sh
```

Expected: exactly three iperf rows and three derphole rows, every derphole row has `trace_ok=true`, canonical footer Mbps equals `sender_mbps`, `total_duration_ms >= command_duration_ms > 0`, and all integrity/direct/trace/leak gates pass. Preserve the `.tmp` directory for the Task 6 A/B report.

---

### Task 2: Expose peer progress and non-terminal controller diagnostics

**Files:**

- Modify: `pkg/session/external_transfer_metrics.go:18-115, 155-174, 422-463, 694-766`
- Modify: `pkg/session/external_transfer_metrics_test.go:340-530`

**Interfaces:**

- Consumes: existing `externalDirectTransferDiagnostics` and `RecordPeerProgress` updates.
- Produces: `externalPeerProgressSnapshot`, `(*externalTransferMetrics).PeerProgressSnapshot()`, and `(*externalTransferMetrics).SetDirectDiagnostics(externalDirectTransferDiagnostics, time.Time)` for Task 4.

- [ ] **Step 1: Write failing metrics tests**

Add:

```go
func TestExternalTransferMetricsPeerProgressSnapshot(t *testing.T) {
	t.Parallel()

	metrics := newExternalTransferMetrics(time.Unix(100, 0))
	if got := metrics.PeerProgressSnapshot(); got.Set {
		t.Fatalf("initial snapshot = %#v, want unset", got)
	}

	metrics.RecordPeerProgress(64<<20, 750, time.Unix(101, 0))
	got := metrics.PeerProgressSnapshot()
	if !got.Set || got.BytesReceived != 64<<20 || got.TransferElapsedMS != 750 {
		t.Fatalf("snapshot = %#v, want bytes=%d elapsed=750 set", got, 64<<20)
	}
}

func TestExternalTransferMetricsRecordsControllerBeforeCompletion(t *testing.T) {
	t.Parallel()

	start := time.Unix(110, 0)
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, start)
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(start, rec, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, string(StateDirect))
	metrics.SetDirectDiagnostics(externalDirectTransferDiagnostics{
		RateSelectedMbps:  1000,
		RateTargetMbps:    1000,
		RateCeilingMbps:   2400,
		ActiveLanes:       8,
		AvailableLanes:    8,
		ControllerDecision: "hold",
		ControllerReason:   "initial-target",
	}, start.Add(100*time.Millisecond))
	metrics.SetDirectDiagnostics(externalDirectTransferDiagnostics{
		RateTargetMbps:     850,
		ControllerDecision: "decrease",
		ControllerReason:   "repair-pressure",
		Retransmits:        12,
		RepairRequests:     3,
		RepairBytes:        16_296,
	}, start.Add(600*time.Millisecond))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	rows := readTransferTraceRows(t, out.String())
	if len(rows) != 2 {
		t.Fatalf("trace rows = %d, want 2\n%s", len(rows), out.String())
	}
	if rows[0]["rate_target_mbps"] != "1000" ||
		rows[0]["controller_decision"] != "hold" ||
		rows[0]["controller_reason"] != "initial-target" {
		t.Fatalf("initial controller row = %#v", rows[0])
	}
	if rows[1]["rate_target_mbps"] != "850" ||
		rows[1]["controller_decision"] != "decrease" ||
		rows[1]["controller_reason"] != "repair-pressure" ||
		rows[1]["retransmits"] != "12" ||
		rows[1]["repair_requests"] != "3" ||
		rows[1]["repair_bytes"] != "16296" {
		t.Fatalf("decrease controller row = %#v", rows[1])
	}
}

func TestExternalTransferMetricsDirectCountersNeverRegress(t *testing.T) {
	t.Parallel()

	metrics := newExternalTransferMetrics(time.Unix(120, 0))
	metrics.SetDirectDiagnostics(externalDirectTransferDiagnostics{
		Retransmits:    12,
		RepairRequests: 3,
		RepairBytes:    16_296,
	}, time.Unix(120, 1))
	metrics.SetDirectDiagnostics(externalDirectTransferDiagnostics{
		Retransmits:    4,
		RepairRequests: 1,
		RepairBytes:    5432,
	}, time.Unix(120, 2))

	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if metrics.retransmitCount != 12 ||
		metrics.repairRequests != 3 ||
		metrics.repairBytes != 16_296 {
		t.Fatalf("counters regressed: retransmits=%d requests=%d bytes=%d",
			metrics.retransmitCount,
			metrics.repairRequests,
			metrics.repairBytes,
		)
	}
}
```

- [ ] **Step 2: Run the focused tests and verify missing APIs**

Run:

```bash
mise exec -- go test ./pkg/session \
  -run 'TestExternalTransferMetrics(PeerProgressSnapshot|RecordsControllerBeforeCompletion|DirectCountersNeverRegress)$' \
  -count=1
```

Expected: FAIL because `PeerProgressSnapshot` and `SetDirectDiagnostics` are undefined.

- [ ] **Step 3: Implement the snapshot and diagnostics-only APIs**

Add:

```go
type externalPeerProgressSnapshot struct {
	BytesReceived     int64
	TransferElapsedMS int64
	Set               bool
}

func (m *externalTransferMetrics) PeerProgressSnapshot() externalPeerProgressSnapshot {
	if m == nil {
		return externalPeerProgressSnapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return externalPeerProgressSnapshot{
		BytesReceived:     m.peerReceivedBytes,
		TransferElapsedMS: m.receiverTransferMS,
		Set:               m.peerProgressSet,
	}
}

func (m *externalTransferMetrics) SetDirectDiagnostics(
	diagnostics externalDirectTransferDiagnostics,
	at time.Time,
) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.setDirectDiagnosticsLocked(diagnostics)
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	recordExternalTransferTrace(trace, snap, ok)
}
```

Change cumulative direct counters to max semantics:

```go
func (m *externalTransferMetrics) setDirectCounterDiagnosticsLocked(diagnostics externalDirectTransferDiagnostics) {
	if diagnostics.ReplayBytes > m.replayBytes {
		m.replayBytes = diagnostics.ReplayBytes
	}
	if diagnostics.Retransmits > m.retransmitCount {
		m.retransmitCount = diagnostics.Retransmits
	}
	if diagnostics.RepairRequests > m.repairRequests {
		m.repairRequests = diagnostics.RepairRequests
	}
	if diagnostics.RepairBytes > m.repairBytes {
		m.repairBytes = diagnostics.RepairBytes
	}
	if diagnostics.DirectPacketBytes > m.directPacketBytes {
		m.directPacketBytes = diagnostics.DirectPacketBytes
	}
	if diagnostics.DirectCommittedBytes > m.directCommittedBytes {
		m.directCommittedBytes = diagnostics.DirectCommittedBytes
	}
	if diagnostics.ReceiverCommittedBytes > 0 &&
		uint64ToInt64Saturating(diagnostics.ReceiverCommittedBytes) > m.directCommittedBytes {
		m.directCommittedBytes = uint64ToInt64Saturating(diagnostics.ReceiverCommittedBytes)
	}
}
```

- [ ] **Step 4: Run focused and race tests**

Run:

```bash
mise exec -- go test ./pkg/session \
  -run 'TestExternalTransferMetrics(PeerProgressSnapshot|RecordsControllerBeforeCompletion|DirectCountersNeverRegress)$' \
  -count=1
mise exec -- go test -race ./pkg/session \
  -run 'TestExternalTransferMetrics(PeerProgressSnapshot|RecordsControllerBeforeCompletion|DirectCountersNeverRegress)$' \
  -count=1
```

Expected: both commands report `ok`.

- [ ] **Step 5: Commit the metrics API**

Run `but diff` and verify only the two Task 2 files changed, then:

```bash
but commit codex/bulk-packet-pacing-plan -m "trace: expose live bulk controller diagnostics"
```

Expected: one new local GitButler commit. Do not push.

---

### Task 3: Build a deterministic delivery-and-repair controller

**Files:**

- Create: `pkg/session/external_v2_bulk_packet_controller.go`
- Create: `pkg/session/external_v2_bulk_packet_controller_test.go`

**Interfaces:**

- Consumes: cumulative byte counters and `externalPeerProgressSnapshot` from Task 2.
- Produces: `newExternalV2BulkPacketController() *externalV2BulkPacketController`, `(*externalV2BulkPacketController).Observe(externalV2BulkPacketControllerSample) externalV2BulkPacketControllerDecision`, `externalV2BulkPacketIPv4WireBytes(int) int`, and the controller constants used by Task 4.

- [ ] **Step 1: Write the wire-accounting and controller-policy tests**

Create `pkg/session/external_v2_bulk_packet_controller_test.go`:

```go
// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"testing"
	"time"
)

func TestExternalV2BulkPacketIPv4WireBytes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		datagram int
		want     int
	}{
		{datagram: 0, want: 0},
		{datagram: 1400, want: 1428},
		{datagram: 42, want: 70},
	} {
		if got := externalV2BulkPacketIPv4WireBytes(tc.datagram); got != tc.want {
			t.Fatalf("wire bytes for datagram %d = %d, want %d", tc.datagram, got, tc.want)
		}
	}
}

func observeExternalV2BulkPacketController(
	t *testing.T,
	primaryWireBytes int64,
	repairWireBytes int64,
	peerBytes int64,
) externalV2BulkPacketControllerDecision {
	t.Helper()
	controller := newExternalV2BulkPacketController()
	start := time.Unix(200, 0)
	controller.Observe(externalV2BulkPacketControllerSample{
		At:           start,
		PeerProgress: true,
	})
	return controller.Observe(externalV2BulkPacketControllerSample{
		At:                    start.Add(externalV2BulkPacketControllerInterval),
		PrimaryWireBytes:      primaryWireBytes,
		RepairWireBytes:       repairWireBytes,
		PeerBytes:             peerBytes,
		PeerTransferElapsedMS: externalV2BulkPacketControllerInterval.Milliseconds(),
		PeerProgress:          true,
	})
}

func TestExternalV2BulkPacketControllerPolicy(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		primary     int64
		repair      int64
		peer        int64
		wantTarget  int
		wantAction  string
		wantReason  string
	}{
		{
			name:       "clean delivery explores",
			primary:    60_000_000,
			peer:       56_250_000,
			wantTarget: 1064,
			wantAction: "increase",
			wantReason: "clean-delivery",
		},
		{
			name:       "moderate repair holds a productive target",
			primary:    57_300_000,
			repair:     2_700_000,
			peer:       56_125_000,
			wantTarget: 1000,
			wantAction: "hold",
			wantReason: "repair-hold",
		},
		{
			name:       "repair plus low delivery backs off",
			primary:    57_600_000,
			repair:     2_400_000,
			peer:       50_000_000,
			wantTarget: 850,
			wantAction: "decrease",
			wantReason: "repair-and-delivery-drop",
		},
		{
			name:       "hard repair pressure backs off",
			primary:    54_600_000,
			repair:     5_400_000,
			peer:       56_125_000,
			wantTarget: 850,
			wantAction: "decrease",
			wantReason: "hard-repair-pressure",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := observeExternalV2BulkPacketController(t, tc.primary, tc.repair, tc.peer)
			if got.TargetMbps != tc.wantTarget ||
				got.Action != tc.wantAction ||
				got.Reason != tc.wantReason {
				t.Fatalf("decision = %#v, want target=%d action=%q reason=%q",
					got,
					tc.wantTarget,
					tc.wantAction,
					tc.wantReason,
				)
			}
		})
	}
}

func TestExternalV2BulkPacketControllerHoldsAfterBackoff(t *testing.T) {
	t.Parallel()

	controller := newExternalV2BulkPacketController()
	start := time.Unix(210, 0)
	controller.Observe(externalV2BulkPacketControllerSample{
		At:           start,
		PeerProgress: true,
	})
	first := controller.Observe(externalV2BulkPacketControllerSample{
		At:                    start.Add(500 * time.Millisecond),
		PrimaryWireBytes:      54_600_000,
		RepairWireBytes:       5_400_000,
		PeerBytes:             56_125_000,
		PeerTransferElapsedMS: 500,
		PeerProgress:          true,
	})
	if first.Action != "decrease" || first.TargetMbps != 850 {
		t.Fatalf("first decision = %#v, want decrease to 850", first)
	}

	second := controller.Observe(externalV2BulkPacketControllerSample{
		At:                    start.Add(time.Second),
		PrimaryWireBytes:      114_600_000,
		RepairWireBytes:       5_400_000,
		PeerBytes:             112_375_000,
		PeerTransferElapsedMS: 1000,
		PeerProgress:          true,
	})
	if second.Action != "hold" ||
		second.Reason != "backoff-cooldown" ||
		second.TargetMbps != 850 {
		t.Fatalf("second decision = %#v, want cooldown hold at 850", second)
	}
}

func TestExternalV2BulkPacketControllerNeedsEnoughTrafficAndPeerProgress(t *testing.T) {
	t.Parallel()

	controller := newExternalV2BulkPacketController()
	start := time.Unix(220, 0)
	if got := controller.Observe(externalV2BulkPacketControllerSample{At: start}); got.Reason != "initial-target" {
		t.Fatalf("initial decision = %#v, want initial-target", got)
	}
	if got := controller.Observe(externalV2BulkPacketControllerSample{
		At:               start.Add(500 * time.Millisecond),
		PrimaryWireBytes: 4 << 20,
	}); got.Reason != "insufficient-wire-sample" {
		t.Fatalf("small-sample decision = %#v, want insufficient-wire-sample", got)
	}
	if got := controller.Observe(externalV2BulkPacketControllerSample{
		At:               start.Add(time.Second),
		PrimaryWireBytes: 64 << 20,
	}); got.Reason != "awaiting-peer-progress" {
		t.Fatalf("no-peer decision = %#v, want awaiting-peer-progress", got)
	}
}

func TestExternalV2BulkPacketControllerClampsTargets(t *testing.T) {
	t.Parallel()

	start := time.Unix(225, 0)
	ceiling := newExternalV2BulkPacketController()
	ceiling.targetMbps = externalV2BulkPacketCeilingWireMbps
	ceiling.Observe(externalV2BulkPacketControllerSample{
		At:           start,
		PeerProgress: true,
	})
	gotCeiling := ceiling.Observe(externalV2BulkPacketControllerSample{
		At:                    start.Add(500 * time.Millisecond),
		PrimaryWireBytes:      150_000_000,
		PeerBytes:             135_000_000,
		PeerTransferElapsedMS: 500,
		PeerProgress:          true,
	})
	if gotCeiling.TargetMbps != externalV2BulkPacketCeilingWireMbps ||
		gotCeiling.Action != "hold" ||
		gotCeiling.Reason != "ceiling" {
		t.Fatalf("ceiling decision = %#v", gotCeiling)
	}

	floor := newExternalV2BulkPacketController()
	floor.targetMbps = externalV2BulkPacketMinimumWireMbps
	floor.Observe(externalV2BulkPacketControllerSample{At: start})
	gotFloor := floor.Observe(externalV2BulkPacketControllerSample{
		At:               start.Add(500 * time.Millisecond),
		PrimaryWireBytes: 9 << 20,
		RepairWireBytes:  1 << 20,
	})
	if gotFloor.TargetMbps != externalV2BulkPacketMinimumWireMbps ||
		gotFloor.Action != "hold" ||
		gotFloor.Reason != "minimum" {
		t.Fatalf("minimum decision = %#v", gotFloor)
	}
}
```

- [ ] **Step 2: Run the controller tests and verify the new types are absent**

Run:

```bash
mise exec -- go test ./pkg/session \
  -run 'TestExternalV2BulkPacket(IPv4WireBytes|ControllerPolicy|ControllerHoldsAfterBackoff|ControllerNeedsEnoughTrafficAndPeerProgress|ControllerClampsTargets)$' \
  -count=1
```

Expected: FAIL with undefined controller types, constants, and functions.

- [ ] **Step 3: Implement the pure controller**

Create `pkg/session/external_v2_bulk_packet_controller.go`:

```go
// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import "time"

const (
	externalV2BulkPacketIPv4HeaderBytes = 20
	externalV2BulkPacketUDPHeaderBytes  = 8

	externalV2BulkPacketInitialWireMbps       = 1000
	externalV2BulkPacketCeilingWireMbps       = 2400
	externalV2BulkPacketMinimumWireMbps       = 128
	externalV2BulkPacketIncreaseWireMbps      = 64
	externalV2BulkPacketBackoffNumerator      = 85
	externalV2BulkPacketBackoffDenominator    = 100
	externalV2BulkPacketPaceBurstBytes        = 64 << 10
	externalV2BulkPacketMinimumSampleWire     = 8 << 20
	externalV2BulkPacketSoftRepairPPM   int64 = 20_000
	externalV2BulkPacketHardRepairPPM   int64 = 80_000
	externalV2BulkPacketHealthyPPM      int64 = 900_000
	externalV2BulkPacketControllerCooldown    = 4

	externalV2BulkPacketControllerInterval = 500 * time.Millisecond
)

type externalV2BulkPacketControllerSample struct {
	At                    time.Time
	PrimaryWireBytes      int64
	RepairWireBytes       int64
	PeerBytes             int64
	PeerTransferElapsedMS int64
	PeerProgress          bool
}

type externalV2BulkPacketControllerDecision struct {
	TargetMbps        int
	Action            string
	Reason            string
	DeliveredWireMbps int
	RepairPPM         int64
}

type externalV2BulkPacketController struct {
	targetMbps int
	cooldown   int
	previous   externalV2BulkPacketControllerSample
	haveSample bool
}

func newExternalV2BulkPacketController() *externalV2BulkPacketController {
	return &externalV2BulkPacketController{
		targetMbps: externalV2BulkPacketInitialWireMbps,
	}
}

func externalV2BulkPacketIPv4WireBytes(datagramBytes int) int {
	if datagramBytes <= 0 {
		return 0
	}
	return datagramBytes +
		externalV2BulkPacketIPv4HeaderBytes +
		externalV2BulkPacketUDPHeaderBytes
}

func (c *externalV2BulkPacketController) Observe(
	sample externalV2BulkPacketControllerSample,
) externalV2BulkPacketControllerDecision {
	if !c.haveSample {
		c.previous = sample
		c.haveSample = true
		return c.decision("hold", "initial-target", 0, 0)
	}
	if sample.PrimaryWireBytes < c.previous.PrimaryWireBytes ||
		sample.RepairWireBytes < c.previous.RepairWireBytes ||
		(sample.PeerProgress && c.previous.PeerProgress &&
			(sample.PeerBytes < c.previous.PeerBytes ||
				sample.PeerTransferElapsedMS < c.previous.PeerTransferElapsedMS)) {
		c.previous = sample
		return c.decision("hold", "counter-reset", 0, 0)
	}

	primaryDelta := sample.PrimaryWireBytes - c.previous.PrimaryWireBytes
	repairDelta := sample.RepairWireBytes - c.previous.RepairWireBytes
	totalDelta := primaryDelta + repairDelta
	peerReady := sample.PeerProgress &&
		c.previous.PeerProgress &&
		sample.PeerTransferElapsedMS > c.previous.PeerTransferElapsedMS
	var deliveredWireMbps int
	if peerReady {
		peerBytesDelta := sample.PeerBytes - c.previous.PeerBytes
		peerElapsedDelta := sample.PeerTransferElapsedMS - c.previous.PeerTransferElapsedMS
		deliveredWireMbps = externalV2BulkPacketDeliveredWireMbps(
			peerBytesDelta,
			peerElapsedDelta,
		)
	}
	c.previous = sample

	if primaryDelta < externalV2BulkPacketMinimumSampleWire {
		return c.decision("hold", "insufficient-wire-sample", deliveredWireMbps, 0)
	}
	repairPPM := externalV2BulkPacketRepairPPM(repairDelta, totalDelta)
	if repairPPM >= externalV2BulkPacketHardRepairPPM {
		return c.decrease("hard-repair-pressure", deliveredWireMbps, repairPPM)
	}
	if !peerReady {
		return c.decision("hold", "awaiting-peer-progress", 0, repairPPM)
	}
	if repairPPM >= externalV2BulkPacketSoftRepairPPM &&
		int64(deliveredWireMbps)*1_000_000 <
			int64(c.targetMbps)*externalV2BulkPacketHealthyPPM {
		return c.decrease("repair-and-delivery-drop", deliveredWireMbps, repairPPM)
	}
	if c.cooldown > 0 {
		c.cooldown--
		return c.decision("hold", "backoff-cooldown", deliveredWireMbps, repairPPM)
	}
	if repairPPM >= externalV2BulkPacketSoftRepairPPM {
		return c.decision("hold", "repair-hold", deliveredWireMbps, repairPPM)
	}
	if int64(deliveredWireMbps)*1_000_000 <
		int64(c.targetMbps)*externalV2BulkPacketHealthyPPM {
		return c.decision("hold", "receiver-limited", deliveredWireMbps, repairPPM)
	}
	if c.targetMbps >= externalV2BulkPacketCeilingWireMbps {
		return c.decision("hold", "ceiling", deliveredWireMbps, repairPPM)
	}
	c.targetMbps = min(
		externalV2BulkPacketCeilingWireMbps,
		c.targetMbps+externalV2BulkPacketIncreaseWireMbps,
	)
	return c.decision("increase", "clean-delivery", deliveredWireMbps, repairPPM)
}

func (c *externalV2BulkPacketController) decrease(
	reason string,
	deliveredWireMbps int,
	repairPPM int64,
) externalV2BulkPacketControllerDecision {
	next := c.targetMbps *
		externalV2BulkPacketBackoffNumerator /
		externalV2BulkPacketBackoffDenominator
	next = max(externalV2BulkPacketMinimumWireMbps, next)
	if next >= c.targetMbps {
		return c.decision("hold", "minimum", deliveredWireMbps, repairPPM)
	}
	c.targetMbps = next
	c.cooldown = externalV2BulkPacketControllerCooldown
	return c.decision("decrease", reason, deliveredWireMbps, repairPPM)
}

func (c *externalV2BulkPacketController) decision(
	action string,
	reason string,
	deliveredWireMbps int,
	repairPPM int64,
) externalV2BulkPacketControllerDecision {
	return externalV2BulkPacketControllerDecision{
		TargetMbps:        c.targetMbps,
		Action:            action,
		Reason:            reason,
		DeliveredWireMbps: deliveredWireMbps,
		RepairPPM:         repairPPM,
	}
}

func externalV2BulkPacketDeliveredWireMbps(peerBytes int64, elapsedMS int64) int {
	if peerBytes <= 0 || elapsedMS <= 0 {
		return 0
	}
	payloadMbps := peerBytes * 8 / elapsedMS / 1000
	return int(payloadMbps *
		int64(externalV2BulkPacketPayloadSize+
			externalV2BulkPacketHeaderSize+
			16+
			externalV2BulkPacketIPv4HeaderBytes+
			externalV2BulkPacketUDPHeaderBytes) /
		externalV2BulkPacketPayloadSize)
}

func externalV2BulkPacketRepairPPM(repairBytes int64, totalBytes int64) int64 {
	if repairBytes <= 0 || totalBytes <= 0 {
		return 0
	}
	return repairBytes * 1_000_000 / totalBytes
}
```

- [ ] **Step 4: Run focused tests and format**

Run:

```bash
mise exec -- gofmt -w \
  pkg/session/external_v2_bulk_packet_controller.go \
  pkg/session/external_v2_bulk_packet_controller_test.go
mise exec -- go test ./pkg/session \
  -run 'TestExternalV2BulkPacket(IPv4WireBytes|ControllerPolicy|ControllerHoldsAfterBackoff|ControllerNeedsEnoughTrafficAndPeerProgress|ControllerClampsTargets)$' \
  -count=1
```

Expected: formatting changes no semantics and the focused tests report `ok`.

- [ ] **Step 5: Commit the pure controller**

Run `but diff` and verify only the two new controller files changed, then:

```bash
but commit codex/bulk-packet-pacing-plan -m "session: add bulk packet feedback controller"
```

Expected: one new local GitButler commit. Do not push.

---

### Task 4: Integrate wire pacing and live controller traces

**Files:**

- Modify: `pkg/session/external_v2_bulk_packet.go:28-50, 119-325, 974-1123`
- Modify: `pkg/session/external_v2_bulk_packet_test.go:1-557`

**Interfaces:**

- Consumes: Task 2 metrics APIs and Task 3 controller APIs.
- Produces: sender pacing that charges `len(sealedDatagram)+28`, exact cumulative primary/repair counters, a 500 ms controller loop, and non-terminal trace updates using existing columns.

- [ ] **Step 1: Write integration tests for wire charging, exact repairs, and time-series publication**

Add:

```go
func TestExternalV2BulkPacketSendPacketChargesIPv4WireBytes(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	payload := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	sender := newExternalV2BulkPacketSender(
		context.Background(),
		&BlockSource{
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
		},
		externalV2BulkPacketPath{
			Conns: senders,
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		},
		auth,
		nil,
	)
	sender.pacer = rate.NewLimiter(0, externalV2BulkPacketPaceBurstBytes)

	if err := sender.sendPacket(0, 0, false); err != nil {
		t.Fatalf("sendPacket() error = %v", err)
	}
	if got, want := sender.primaryWireBytes.Load(), int64(1428); got != want {
		t.Fatalf("primary wire bytes = %d, want %d", got, want)
	}
	if got := sender.repairWireBytes.Load(); got != 0 {
		t.Fatalf("repair wire bytes = %d, want 0", got)
	}
}

func TestExternalV2BulkPacketSendStatsUseExactRepairCounters(t *testing.T) {
	stats := externalV2BulkPacketSendStats(
		4096,
		4,
		3,
		512,
		2,
		1,
		1000,
	)
	if stats.Retransmits != 1 {
		t.Fatalf("Retransmits = %d, want 1", stats.Retransmits)
	}
	if stats.Diagnostics.RepairBytes != 512 {
		t.Fatalf("RepairBytes = %d, want 512", stats.Diagnostics.RepairBytes)
	}
	if stats.Diagnostics.RepairRequests != 2 {
		t.Fatalf("RepairRequests = %d, want 2", stats.Diagnostics.RepairRequests)
	}
}

func TestExternalV2BulkPacketSenderPublishesControllerBeforeCompletion(t *testing.T) {
	start := time.Unix(230, 0)
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, start)
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(start, rec, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, string(StateDirect))
	sender := &externalV2BulkPacketSender{
		metrics:     metrics,
		laneCount:   8,
		pacer:       rate.NewLimiter(externalV2BulkPacketRateLimit(1000), externalV2BulkPacketPaceBurstBytes),
		controller:  newExternalV2BulkPacketController(),
	}
	sender.currentPaceMbps.Store(1000)
	sender.publishControllerDiagnostics(start, externalV2BulkPacketControllerDecision{
		TargetMbps: 1000,
		Action:     "hold",
		Reason:     "initial-target",
	})
	sender.repairPackets.Store(12)
	sender.repairPayloadBytes.Store(16_296)
	sender.repairRequests.Store(3)
	sender.publishControllerDiagnostics(start.Add(600*time.Millisecond), externalV2BulkPacketControllerDecision{
		TargetMbps: 850,
		Action:     "decrease",
		Reason:     "repair-pressure",
	})
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	rows := readTransferTraceRows(t, out.String())
	if len(rows) != 2 ||
		rows[0]["rate_target_mbps"] != "1000" ||
		rows[1]["rate_target_mbps"] != "850" ||
		rows[1]["controller_decision"] != "decrease" ||
		rows[1]["retransmits"] != "12" ||
		rows[1]["repair_bytes"] != "16296" {
		t.Fatalf("controller rows = %#v", rows)
	}
}
```

Add imports for `transfertrace` and retain the existing `rate` import.

- [ ] **Step 2: Run the focused tests and verify the old sender API fails**

Run:

```bash
mise exec -- go test ./pkg/session \
  -run 'TestExternalV2BulkPacket(SendPacketChargesIPv4WireBytes|SendStatsUseExactRepairCounters|SenderPublishesControllerBeforeCompletion)$' \
  -count=1
```

Expected: FAIL because `sendPacket` has no repair flag, the sender lacks controller/wire counters, and `externalV2BulkPacketSendStats` has the old signature.

- [ ] **Step 3: Replace legacy controller constants and sender state**

Remove `externalV2BulkPacketPaceBackoff`, `externalV2BulkPacketBackoffMissing`, `externalV2BulkPacketPaceMbps`, `externalV2BulkPacketPaceCeilingMbps`, `externalV2BulkPacketMinPaceMbps`, `externalV2BulkPacketPaceRecovery`, `externalV2BulkPacketPaceRecoveryStep`, and `externalV2BulkPacketPaceBurst` from `external_v2_bulk_packet.go`. Keep repair timing, queue, lane, and packet-size constants unchanged.

Replace the sender controller fields with:

```go
type externalV2BulkPacketSender struct {
	ctx                context.Context
	src                *BlockSource
	path               externalV2BulkPacketPath
	auth               externalV2BulkPacketAuth
	metrics            *externalTransferMetrics
	runID              uint64
	totalPackets       uint32
	laneCount          int
	pacer              *rate.Limiter
	controller         *externalV2BulkPacketController
	sentPackets        atomic.Uint64
	sentPayload        atomic.Int64
	primaryWireBytes   atomic.Int64
	repairWireBytes    atomic.Int64
	repairPackets      atomic.Int64
	repairPayloadBytes atomic.Int64
	repairRequests     atomic.Int64
	currentPaceMbps    atomic.Int64
}
```

Initialize the sender with the wire-rate constants:

```go
controller := newExternalV2BulkPacketController()
sender := &externalV2BulkPacketSender{
	ctx:          ctx,
	src:          src,
	path:         path,
	auth:         auth,
	metrics:      metrics,
	runID:        randomExternalV2BulkPacketRunID(),
	totalPackets: externalV2BulkPacketCount(src.PayloadSize),
	laneCount:    min(len(path.Conns), len(path.Addrs)),
	pacer: rate.NewLimiter(
		externalV2BulkPacketRateLimit(externalV2BulkPacketInitialWireMbps),
		externalV2BulkPacketPaceBurstBytes,
	),
	controller: controller,
}
sender.currentPaceMbps.Store(externalV2BulkPacketInitialWireMbps)
return sender
```

- [ ] **Step 4: Charge sealed IPv4 packets and count repairs exactly**

Change the initial call to `s.sendPacket(index, lane, false)` and repair calls to `s.sendPacket(index, lane, true)`. Replace `sendPacket` with:

```go
func (s *externalV2BulkPacketSender) sendPacket(index uint32, lane int, repair bool) error {
	data, err := readExternalV2BulkPacketPayload(s.src, index)
	if err != nil {
		return err
	}
	packet, err := sealExternalV2BulkPacket(s.auth.data, externalV2BulkPacketHeader{
		kind:   externalV2BulkPacketData,
		runID:  s.runID,
		index:  index,
		total:  s.totalPackets,
		length: uint16(len(data)),
	}, data)
	if err != nil {
		return err
	}
	wireBytes := externalV2BulkPacketIPv4WireBytes(len(packet))
	if err := s.pacer.WaitN(s.ctx, wireBytes); err != nil {
		return err
	}
	if _, err := s.path.Conns[lane].WriteTo(packet, s.path.Addrs[lane]); err != nil {
		return err
	}
	s.sentPackets.Add(1)
	s.sentPayload.Add(int64(len(data)))
	if repair {
		s.repairWireBytes.Add(int64(wireBytes))
		s.repairPackets.Add(1)
		s.repairPayloadBytes.Add(int64(len(data)))
	} else {
		s.primaryWireBytes.Add(int64(wireBytes))
	}
	if s.metrics != nil {
		s.metrics.RecordDirectPacketSend(int64(len(data)), time.Now())
	}
	return nil
}
```

Remove per-packet recovery and all calls to `externalV2BulkPacketBackoffPace` and `externalV2BulkPacketRecoverPace`. Pass `&sender.repairRequests` to the control readers instead of a local atomic.

- [ ] **Step 5: Add the 500 ms controller loop and publish every decision**

Add:

```go
func (s *externalV2BulkPacketSender) startController(ctx context.Context) {
	s.publishControllerDiagnostics(time.Now(), externalV2BulkPacketControllerDecision{
		TargetMbps: externalV2BulkPacketInitialWireMbps,
		Action:     "hold",
		Reason:     "initial-target",
	})
	go func() {
		ticker := time.NewTicker(externalV2BulkPacketControllerInterval)
		defer ticker.Stop()
		for {
			select {
			case at := <-ticker.C:
				s.observeController(at)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *externalV2BulkPacketSender) observeController(at time.Time) {
	peer := s.metrics.PeerProgressSnapshot()
	decision := s.controller.Observe(externalV2BulkPacketControllerSample{
		At:                    at,
		PrimaryWireBytes:      s.primaryWireBytes.Load(),
		RepairWireBytes:       s.repairWireBytes.Load(),
		PeerBytes:             peer.BytesReceived,
		PeerTransferElapsedMS: peer.TransferElapsedMS,
		PeerProgress:          peer.Set,
	})
	current := int(s.currentPaceMbps.Load())
	if decision.TargetMbps != current {
		s.currentPaceMbps.Store(int64(decision.TargetMbps))
		s.pacer.SetLimitAt(at, externalV2BulkPacketRateLimit(decision.TargetMbps))
	}
	s.publishControllerDiagnostics(at, decision)
}

func (s *externalV2BulkPacketSender) publishControllerDiagnostics(
	at time.Time,
	decision externalV2BulkPacketControllerDecision,
) {
	if s.metrics == nil {
		return
	}
	s.metrics.SetDirectDiagnostics(externalDirectTransferDiagnostics{
		RateSelectedMbps:     externalV2BulkPacketInitialWireMbps,
		RateTargetMbps:       decision.TargetMbps,
		RateCeilingMbps:      externalV2BulkPacketCeilingWireMbps,
		ActiveLanes:          s.laneCount,
		AvailableLanes:       s.laneCount,
		ControllerDecision:   decision.Action,
		ControllerReason:     decision.Reason,
		Retransmits:          s.repairPackets.Load(),
		RepairRequests:       s.repairRequests.Load(),
		RepairBytes:          s.repairPayloadBytes.Load(),
		DirectPacketBytes:    s.sentPayload.Load(),
	}, at)
}
```

`PeerProgressSnapshot` is nil-safe, so both sender forms use the same path. Start the controller after the hello succeeds and before the initial packet pass:

```go
sender.startController(sendCtx)
```

- [ ] **Step 6: Preserve the last live event in terminal stats**

Change `externalV2BulkPacketSendStats` to accept exact repair values:

```go
func externalV2BulkPacketSendStats(
	payloadSize int64,
	sentPackets uint64,
	totalPackets uint32,
	repairBytes int64,
	repairRequests int64,
	lanes int,
	paceMbps int,
) externalDirectTransferStats {
	retransmits := int64(sentPackets) - int64(totalPackets)
	if retransmits < 0 {
		retransmits = 0
	}
	return externalDirectTransferStats{
		BytesSent:   payloadSize,
		Retransmits: retransmits,
		Diagnostics: externalDirectTransferDiagnostics{
			RateSelectedMbps:     externalV2BulkPacketInitialWireMbps,
			RateTargetMbps:       paceMbps,
			RateCeilingMbps:      externalV2BulkPacketCeilingWireMbps,
			ActiveLanes:          lanes,
			AvailableLanes:       lanes,
			Retransmits:          retransmits,
			RepairRequests:       repairRequests,
			RepairBytes:          repairBytes,
			DirectPacketBytes:    payloadSize + repairBytes,
			DirectCommittedBytes: payloadSize,
		},
	}
}
```

Leave `ControllerDecision` and `ControllerReason` empty in terminal stats so `SetDirectStats` retains the last real live decision. Update `s.stats` to pass `s.repairPayloadBytes.Load()` and `s.repairRequests.Load()`.

Remove the local `repairRequests` from `sendExternalV2BulkBlockPackets`, pass `&sender.repairRequests` to `startExternalV2BulkPacketControlReaders`, and use these signatures so no stale counter can be supplied:

```go
func (s *externalV2BulkPacketSender) waitForCompletion(
	doneCh <-chan struct{},
	repairActivityCh <-chan struct{},
	repairErrCh <-chan error,
) (externalDirectTransferStats, error)

func (s *externalV2BulkPacketSender) stats() externalDirectTransferStats {
	return externalV2BulkPacketSendStats(
		s.src.PayloadSize,
		s.sentPackets.Load(),
		s.totalPackets,
		s.repairPayloadBytes.Load(),
		s.repairRequests.Load(),
		s.laneCount,
		int(s.currentPaceMbps.Load()),
	)
}
```

Update all error and completion returns to call `s.stats()`, and call `sender.waitForCompletion(doneCh, repairActivityCh, repairErrCh)` after the initial pass.

- [ ] **Step 7: Run focused, package, and race tests**

Run:

```bash
mise exec -- gofmt -w \
  pkg/session/external_v2_bulk_packet.go \
  pkg/session/external_v2_bulk_packet_test.go
mise exec -- go test ./pkg/session -run '^TestExternalV2BulkPacket' -count=1
mise exec -- go test ./pkg/session \
  -run '^TestExternalV2BlockTransferUsesBulkPacketsOnRawDirect$' \
  -count=1
mise exec -- go test -race ./pkg/session \
  -run 'TestExternalV2BulkPacket(SenderPublishesControllerBeforeCompletion|SendPacketChargesIPv4WireBytes|ControllerPolicy)$' \
  -count=1
```

Expected: all three commands report `ok`. The race run must not report concurrent limiter, counter, or metrics access.

- [ ] **Step 8: Commit the sender integration**

Run `but diff` and verify only the two Task 4 files changed, then:

```bash
but commit codex/bulk-packet-pacing-plan -m "session: pace bulk packets from wire feedback"
```

Expected: one new local GitButler commit. Do not push.

---

### Task 5: Verify and log effective UDP socket buffers

**Files:**

- Create: `pkg/session/external_socket_buffer.go`
- Create: `pkg/session/external_socket_buffer_unix.go`
- Create: `pkg/session/external_socket_buffer_other.go`
- Create: `pkg/session/external_socket_buffer_test.go`
- Create: `pkg/session/external_socket_buffer_unix_test.go`
- Modify: `pkg/session/external.go:306, 322-330`
- Modify: `pkg/session/external_v2_dataplane.go:239-256`

**Interfaces:**

- Consumes: `net.PacketConn` and existing `emitExternalV2Debug`.
- Produces: `tuneExternalPacketConn(net.PacketConn) externalPacketConnSocketBufferStats` and verbose `v2-raw-direct-socket-buffer=...` lines for every raw-direct lane.

- [ ] **Step 1: Write fake and real-socket tests**

Create `pkg/session/external_socket_buffer_test.go` with a complete fake:

```go
// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"errors"
	"net"
	"testing"
	"time"
)

type externalSocketBufferTestConn struct {
	readRequested  int
	writeRequested int
	readErr        error
	writeErr       error
}

func (c *externalSocketBufferTestConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *externalSocketBufferTestConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, net.ErrClosed
}

func (c *externalSocketBufferTestConn) Close() error { return nil }

func (c *externalSocketBufferTestConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *externalSocketBufferTestConn) SetDeadline(time.Time) error {
	return nil
}

func (c *externalSocketBufferTestConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *externalSocketBufferTestConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *externalSocketBufferTestConn) SetReadBuffer(bytes int) error {
	c.readRequested = bytes
	return c.readErr
}

func (c *externalSocketBufferTestConn) SetWriteBuffer(bytes int) error {
	c.writeRequested = bytes
	return c.writeErr
}

func TestTuneExternalPacketConnRequestsBothBuffers(t *testing.T) {
	t.Parallel()

	conn := &externalSocketBufferTestConn{
		readErr:  errors.New("read denied"),
		writeErr: errors.New("write denied"),
	}
	stats := tuneExternalPacketConn(conn)
	if conn.readRequested != externalPacketConnSocketBufferBytes ||
		conn.writeRequested != externalPacketConnSocketBufferBytes {
		t.Fatalf("requested read=%d write=%d, want %d",
			conn.readRequested,
			conn.writeRequested,
			externalPacketConnSocketBufferBytes,
		)
	}
	if stats.RequestedBytes != externalPacketConnSocketBufferBytes ||
		stats.ReadSetError == nil ||
		stats.WriteSetError == nil {
		t.Fatalf("stats = %#v, want requested size and setter errors", stats)
	}
}
```

Create `pkg/session/external_socket_buffer_unix_test.go`:

```go
//go:build darwin || linux

// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"net"
	"testing"
)

func TestTuneExternalPacketConnReportsKernelBuffers(t *testing.T) {
	t.Parallel()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	stats := tuneExternalPacketConn(conn)
	wantRead, wantWrite, err := readExternalPacketConnSocketBuffers(conn)
	if err != nil {
		t.Fatal(err)
	}
	if stats.InspectError != nil ||
		stats.ReadBytes != wantRead ||
		stats.WriteBytes != wantWrite ||
		stats.ReadBytes <= 0 ||
		stats.WriteBytes <= 0 {
		t.Fatalf("stats = %#v, want read=%d write=%d", stats, wantRead, wantWrite)
	}
}
```

- [ ] **Step 2: Run the socket tests and verify the result type is absent**

Run:

```bash
mise exec -- go test ./pkg/session \
  -run 'TestTuneExternalPacketConn(RequestsBothBuffers|ReportsKernelBuffers)$' \
  -count=1
```

Expected: FAIL because the shared stats type and getter do not exist and the current tuner returns no value.

- [ ] **Step 3: Implement the platform-neutral tuner**

Create `pkg/session/external_socket_buffer.go`:

```go
// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import "net"

const externalPacketConnSocketBufferBytes = 8 << 20

type externalPacketConnSocketBufferStats struct {
	RequestedBytes int
	ReadBytes      int
	WriteBytes     int
	ReadSetError   error
	WriteSetError  error
	InspectError   error
}

func tuneExternalPacketConn(conn net.PacketConn) externalPacketConnSocketBufferStats {
	stats := externalPacketConnSocketBufferStats{
		RequestedBytes: externalPacketConnSocketBufferBytes,
	}
	if setter, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
		stats.ReadSetError = setter.SetReadBuffer(externalPacketConnSocketBufferBytes)
	}
	if setter, ok := conn.(interface{ SetWriteBuffer(int) error }); ok {
		stats.WriteSetError = setter.SetWriteBuffer(externalPacketConnSocketBufferBytes)
	}
	stats.ReadBytes, stats.WriteBytes, stats.InspectError =
		readExternalPacketConnSocketBuffers(conn)
	return stats
}
```

Delete the old `tuneExternalPacketConn` definition from `external.go`. Keep its manager-path call and explicitly ignore the diagnostic result:

```go
_ = tuneExternalPacketConn(conn)
```

- [ ] **Step 4: Implement Darwin/Linux inspection and the portable fallback**

Create `pkg/session/external_socket_buffer_unix.go`:

```go
//go:build darwin || linux

// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func readExternalPacketConnSocketBuffers(conn net.PacketConn) (int, int, error) {
	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, 0, fmt.Errorf("%T does not expose syscall.Conn", conn)
	}
	raw, err := sysConn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}

	var readBytes int
	var writeBytes int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		readBytes, socketErr = unix.GetsockoptInt(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_RCVBUF,
		)
		if socketErr != nil {
			return
		}
		writeBytes, socketErr = unix.GetsockoptInt(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_SNDBUF,
		)
	}); err != nil {
		return 0, 0, err
	}
	if socketErr != nil {
		return 0, 0, socketErr
	}
	return readBytes, writeBytes, nil
}
```

Create `pkg/session/external_socket_buffer_other.go`:

```go
//go:build !darwin && !linux

// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"errors"
	"net"
)

func readExternalPacketConnSocketBuffers(net.PacketConn) (int, int, error) {
	return 0, 0, errors.New("UDP socket-buffer inspection is unsupported")
}
```

- [ ] **Step 5: Emit effective values for every raw-direct lane**

In `openExternalV2DataPacketPath` replace the ignored tuner call with:

```go
socketBuffers := tuneExternalPacketConn(conn)
emitExternalV2Debug(emitter, fmt.Sprintf(
	"v2-raw-direct-socket-buffer=lane:%d requested:%d read:%d write:%d read_set_error:%t write_set_error:%t inspect_error:%t",
	len(conns)-1,
	socketBuffers.RequestedBytes,
	socketBuffers.ReadBytes,
	socketBuffers.WriteBytes,
	socketBuffers.ReadSetError != nil,
	socketBuffers.WriteSetError != nil,
	socketBuffers.InspectError != nil,
))
```

The log is verbose-only through the existing emitter. A capped host must show the actual kernel value even when the 8 MiB request returned nil.

- [ ] **Step 6: Format, test, and cross-build**

Run:

```bash
mise exec -- gofmt -w \
  pkg/session/external_socket_buffer.go \
  pkg/session/external_socket_buffer_unix.go \
  pkg/session/external_socket_buffer_other.go \
  pkg/session/external_socket_buffer_test.go \
  pkg/session/external_socket_buffer_unix_test.go \
  pkg/session/external.go \
  pkg/session/external_v2_dataplane.go
mise exec -- go test ./pkg/session \
  -run 'TestTuneExternalPacketConn(RequestsBothBuffers|ReportsKernelBuffers)$' \
  -count=1
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 mise exec -- go build ./pkg/session
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 mise exec -- go build ./pkg/session
```

Expected: tests report `ok` and both package cross-builds exit 0.

- [ ] **Step 7: Commit socket observability**

Run `but diff` and verify only the seven Task 5 files changed, then:

```bash
but commit codex/bulk-packet-pacing-plan -m "session: report effective UDP socket buffers"
```

Expected: one new local GitButler commit. Do not push.

---

### Task 6: Document semantics and prove the change with A/B gates

**Files:**

- Modify: `docs/benchmarks.md:1-170`

**Interfaces:**

- Consumes: Task 1 footer/summary fields, Task 4 controller fields, Task 5 verbose socket line, and the pre-controller `.tmp` artifact.
- Produces: a reproducible benchmark contract and a stored after-change artifact suitable for a landing decision.

- [ ] **Step 1: Add the exact benchmark clock and summary contract**

Add this subsection under `Public Path Performance Harness`:

```markdown
### Throughput clocks

The promotion footer separates three clocks:

- `benchmark-transfer-elapsed-ms` is the receiver-anchored interval from first payload byte through committed completion. `benchmark-goodput-mbps` and summary `mbps` are verified payload bytes divided by this clock.
- `benchmark-command-duration-ms` starts immediately before the active sender command and stops after both transfer processes exit. `benchmark-wall-goodput-mbps` uses this clock and includes command setup and teardown, but excludes postflight.
- `benchmark-total-duration-ms` continues through log and trace collection, SHA and size checks, direct-path checks, and leak validation. It is operational duration, not a throughput denominator.

Accepted derphole rows require the rounded `benchmark-goodput-mbps` footer to equal `transfertracecheck sender_mbps`. The public summary records canonical and wall rates, their same-run iperf ratios, all three timing operands, trace status, maximum peer queue depth, and maximum flatline.

Benchmark binaries are installed under a unique remote run directory. `DERPHOLE_REMOTE_BIN_DIR` selects a writable executable root; the harness still appends a unique run directory and removes it during cleanup. The benchmark must never replace a managed binary at a stable path.
```

- [ ] **Step 2: Document controller and socket interpretation**

Add:

```markdown
### Bulk-packet pacing diagnostics

Bulk-packet pace targets are aggregate IPv4-wire Mbps. A full packet carries 1,358 payload bytes in a 1,400-byte UDP datagram and costs 1,428 bytes after IPv4 and UDP headers. `rate_target_mbps` is the current target; `direct_rate_selected_mbps` is the 1,000 Mbps starting policy.

The 500 ms controller emits:

- `increase / clean-delivery` when repair is below 2 percent and receiver-confirmed delivery reaches at least 90 percent of the target
- `hold / repair-hold` when delivery remains productive but repair is at least 2 percent
- `decrease / repair-and-delivery-drop` when repair is at least 2 percent and delivery falls below 90 percent
- `decrease / hard-repair-pressure` when repair reaches 8 percent
- `hold / backoff-cooldown` for four windows after a decrease

Use `retransmits`, `repair_requests`, and `repair_bytes` with the target and reason. Do not infer a decision from the final trace row alone; controller state must be present in non-terminal rows.

Verbose `v2-raw-direct-socket-buffer` lines report the 8 MiB request and the raw receive/write values returned by the kernel for each lane. Linux may report a doubled kernel accounting value; preserve the returned number when comparing hosts.
```

- [ ] **Step 3: Run the full local verification matrix**

Run:

```bash
bash -n scripts/promotion-benchmark-driver.sh scripts/public-path-performance-harness.sh
mise exec -- go test ./pkg/session ./pkg/transfertrace ./tools/transfertracecheck ./scripts -count=1
mise exec -- go test -race ./pkg/session -run 'BulkPacket|SocketBuffer|ExternalTransferMetrics' -count=1
mise run test
mise run vet
mise run smoke-local
mise run check:hooks
```

Expected: every command exits 0. Record the complete output. If `mise run check:hooks` modifies files, inspect them with `but diff`, rerun the affected focused test, and include only changes belonging to this plan.

- [ ] **Step 4: Capture the after-change three-by-three-gigabyte long-haul sample**

Run:

```bash
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
env -u DERPHOLE_BENCH_PARALLEL \
  DERPHOLE_PUBLIC_PATH_HOSTS="${DERPHOLE_LONG_HAUL_HOST:?set the Mac-to-remote target}" \
  DERPHOLE_PUBLIC_PATH_SIZE_MIB=3072 \
  DERPHOLE_PUBLIC_PATH_RUNS=3 \
  DERPHOLE_PUBLIC_IPERF_PORT=8123 \
  DERPHOLE_BENCH_LOG_DIR=".tmp/bulk-wire-pacing-after-${stamp}" \
  ./scripts/public-path-performance-harness.sh
```

Expected for all three derphole rows:

- `benchmark-success=true` and `trace_ok=true`.
- Size and SHA-256 match.
- `v2-data-plane=raw-direct` and `v2-block-transfer=bulk-packets` appear.
- Sender and receiver `transfertracecheck` pass with no steady direct-phase flatline of at least one second.
- Footer canonical Mbps equals sender `transfertracecheck sender_mbps`.
- `benchmark-total-duration-ms >= benchmark-command-duration-ms > 0`.
- No process, UDP socket, or remote run-directory leak remains.
- Non-terminal trace rows contain `rate_target_mbps`, `controller_decision`, `controller_reason`, and monotonic repair counters.
- Every raw-direct lane logs requested, effective receive, and effective write buffer values.

- [ ] **Step 5: Run the fast-host control**

Run:

```bash
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
env -u DERPHOLE_BENCH_PARALLEL \
  DERPHOLE_PUBLIC_PATH_HOSTS="${DERPHOLE_FAST_HOST:?set a high-capacity public control host}" \
  DERPHOLE_PUBLIC_PATH_SIZE_MIB=1024 \
  DERPHOLE_PUBLIC_PATH_RUNS=3 \
  DERPHOLE_PUBLIC_IPERF_PORT=8123 \
  DERPHOLE_BENCH_LOG_DIR=".tmp/bulk-wire-pacing-fast-control-${stamp}" \
  ./scripts/public-path-performance-harness.sh
```

Expected: the same correctness and cleanup gates pass, the controller can increase above 1000 Mbps on a healthy path, and the corrected three-run derphole-to-iperf ratio is no more than 5 percent below its pre-change control.

- [ ] **Step 6: Calculate the A/B decision from accepted rows only**

Run this command with the before and after summary paths:

```bash
python3 - "${DERPHOLE_BEFORE_SUMMARY:?set before summary.csv}" "${DERPHOLE_AFTER_SUMMARY:?set after summary.csv}" <<'PY'
import csv
import statistics
import sys

def accepted(path):
    with open(path, newline="") as fh:
        rows = [
            row for row in csv.DictReader(fh)
            if row["tool"] == "derphole" and row["trace_ok"] == "true"
        ]
    if len(rows) != 3:
        raise SystemExit(f"{path}: expected 3 accepted derphole rows, got {len(rows)}")
    return rows

before = accepted(sys.argv[1])
after = accepted(sys.argv[2])
before_mbps = statistics.mean(float(row["mbps"]) for row in before)
after_mbps = statistics.mean(float(row["mbps"]) for row in after)
after_ratio = statistics.mean(float(row["ratio_to_iperf"]) for row in after)
print(f"before_mean_mbps={before_mbps:.2f}")
print(f"after_mean_mbps={after_mbps:.2f}")
print(f"after_vs_before={after_mbps / before_mbps:.3f}")
print(f"after_ratio_to_iperf={after_ratio:.3f}")
if after_mbps < 897.78 * 0.95:
    raise SystemExit("after mean is below 95 percent of the recorded 897.78 Mbps baseline")
if after_mbps < before_mbps * 0.95:
    raise SystemExit("after mean regressed by more than 5 percent against the same-session control")
if after_ratio < 0.90:
    raise SystemExit("after derphole-to-iperf ratio is below 0.90")
PY
```

Expected: the script exits 0 and prints all four metrics. If it exits nonzero, do not land the controller defaults; preserve both artifact directories and report which gate failed.

- [ ] **Step 7: Commit documentation and any hook-only formatting**

Run `but pull --check`, then `but diff`. Verify that the diff contains `docs/benchmarks.md` and only plan-owned formatting changes, then:

```bash
but commit codex/bulk-packet-pacing-plan -m "docs: define bulk pacing performance gate"
```

Expected: one new local GitButler commit. Do not push.

- [ ] **Step 8: Final branch audit**

Run:

```bash
but pull --check
but status -fv
but diff
```

Expected: `but pull --check` is clean, the session branch contains only the benchmark, metrics, controller, sender, socket, and documentation commits from this plan, and there are no uncommitted changes. Report the local commit state separately from any future branch push or landing; this plan does not authorize either.

---

## Acceptance Summary

Implementation is ready for a landing decision only when all of these are true:

1. The limiter charges 1,428 tokens for a full 1,400-byte UDP datagram.
2. Trace rate targets mean aggregate IPv4-wire Mbps.
3. Non-terminal rows show controller decisions and monotonic repair counters.
4. The benchmark's canonical rate is verified payload over `transfer_elapsed_ms` and exactly matches `transfertracecheck sender_mbps`.
5. Command-wall throughput excludes log, hash, trace, and leak postflight; total duration still includes them.
6. Remote benchmark binaries are unique and removed after every run.
7. Darwin and Linux builds report raw effective UDP buffer values; other targets still compile.
8. Three 3 GiB long-haul transfers and three 1 GiB fast-host controls pass integrity, path, trace, stall, and cleanup checks.
9. Long-haul corrected mean remains at least 852.89 Mbps, same-session performance remains within 5 percent of control, average ratio to same-run iperf is at least 0.90, and the fast-host control regresses by no more than 5 percent.
10. No wire-protocol, CLI, candidate-selection, QUIC, manager-path, packaging, version, release, or production Tailscale-default change is present.
