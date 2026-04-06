# Batched UDP Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove whether Tailscale-style UDP batching and offload support can make `derpcat-probe` materially outperform current no-Tailscale derpcat on the live host matrix.

**Architecture:** Keep the existing probe protocol and orchestration, but add a focused UDP fast path: pooled buffers, batch send/receive, Linux offload enablement, effective socket-buffer reporting, and benchmark-mode controls so the current probe and the new fast path can be compared directly.

**Tech Stack:** Go, `net`, `golang.org/x/net/ipv4`, `golang.org/x/net/ipv6`, Linux UDP socket options, existing `cmd/derpcat-probe`, existing benchmark shell scripts, SSH orchestration.

---

## File Structure

**Create:**

- `pkg/probe/batching.go` — probe-facing UDP batching interface and portable helpers.
- `pkg/probe/batching_linux.go` — Linux batch send/receive, GSO/GRO, buffer force-set, RX overflow setup.
- `pkg/probe/batching_stub.go` — non-Linux stub that preserves current behavior.
- `pkg/probe/batching_test.go` — interface-level tests for batch splitting and report plumbing.

**Modify:**

- `pkg/probe/session.go` — switch blast/raw data paths from per-packet I/O to batching abstraction.
- `pkg/probe/session_test.go` — cover batch send/receive behavior and reporting.
- `pkg/probe/report.go` — include batching/offload/socket-buffer facts in reports.
- `pkg/probe/report_test.go` — lock the new report fields.
- `cmd/derpcat-probe/orchestrate.go` — add CLI flags for transport mode selection if needed.
- `pkg/probe/orchestrator.go` — collect and aggregate new report fields.
- `pkg/probe/orchestrator_test.go` — verify result parsing/aggregation.
- `scripts/probe-benchmark.sh` — add fast-path mode selection.
- `scripts/probe-benchmark-reverse.sh` — add fast-path mode selection.
- `scripts/probe-matrix.sh` — record both legacy and batched probe runs.
- `docs/benchmarks.md` — document the new probe modes and proof flow.

## Tasks

### Task 1: Add probe UDP batching abstraction

- [ ] Implement a small batching interface in `pkg/probe/batching.go` that can:
  - send multiple datagrams in one call
  - receive multiple datagrams in one call
  - expose effective socket-buffer and offload capabilities for reporting
- [ ] Add a Linux implementation in `pkg/probe/batching_linux.go` using `ipv4.PacketConn` / `ipv6.PacketConn` batch APIs.
- [ ] Add non-Linux stubs in `pkg/probe/batching_stub.go` that preserve current behavior.
- [ ] Add tests in `pkg/probe/batching_test.go` for message packing, report fields, and fallback behavior.
- [ ] Run:

```bash
go test ./pkg/probe -run 'TestBatch' -count=1
```

### Task 2: Move probe hot paths onto batching

- [ ] Update `pkg/probe/session.go` so blast send/receive and any reusable raw-mode loops use the batching abstraction instead of one `WriteTo` / `ReadFrom` per packet.
- [ ] Keep the protocol shape the same so existing orchestrator logic still works.
- [ ] Reuse packet/message buffers instead of allocating a fresh payload wrapper per datagram on the hot path.
- [ ] Expand `pkg/probe/session_test.go` to cover batch-path correctness.
- [ ] Run:

```bash
go test ./pkg/probe -run 'Test(Session|Blast)' -count=1
```

### Task 3: Add Linux offload, buffer, and drop instrumentation

- [ ] In `pkg/probe/batching_linux.go`, attempt:
  - larger read/write socket buffers
  - forced buffer sizing where allowed
  - UDP GSO enablement
  - UDP GRO enablement
  - RX queue overflow reporting
- [ ] Surface the effective result in `pkg/probe/report.go`.
- [ ] Extend orchestrator parsing and tests to preserve those facts in benchmark output.
- [ ] Run:

```bash
go test ./pkg/probe -run 'TestReport' -count=1
go test ./cmd/derpcat-probe -count=1
```

### Task 4: Add benchmark mode controls and baseline comparison

- [ ] Extend benchmark scripts so they can run:
  - legacy probe mode
  - batched probe mode
  - current derpcat baseline
- [ ] Make the matrix runner emit enough detail to compare:
  - goodput
  - time to first byte
  - bytes received
  - socket/offload capability facts
- [ ] Update `docs/benchmarks.md` with the exact commands.
- [ ] Run:

```bash
pre-commit run --files scripts/probe-benchmark.sh scripts/probe-benchmark-reverse.sh scripts/probe-matrix.sh docs/benchmarks.md
```

### Task 5: Prove or falsify on live hosts

- [ ] Run the baseline on `ktzlxc`:
  - Tailscale `iperf3`
  - tuned derpcat no-Tailscale
  - legacy probe
  - batched probe
- [ ] If batched probe does not beat tuned derpcat on `ktzlxc`, stop and write down the evidence.
- [ ] If batched probe wins on `ktzlxc`, widen to:
  - `canlxc`
  - `uklxc`
  - `orange-india.exe.xyz`
- [ ] Record results in benchmark logs and summarize what the remaining bottleneck is on each host.

### Task 6: Finish and publish evidence

- [ ] Run:

```bash
go test ./cmd/derpcat-probe ./pkg/probe -count=1
go test -race ./cmd/derpcat-probe ./pkg/probe
go vet ./cmd/derpcat-probe ./pkg/probe
mise run check
```

- [ ] Commit the probe work with a scoped message.
- [ ] Push `main`.
- [ ] Confirm GitHub `Checks` and `Release` are green.

## Success Criteria

- The probe has a measurable legacy mode and a measurable batched mode.
- The batched mode is live-tested against the host matrix.
- We either prove a real throughput win over tuned derpcat on `ktzlxc`, or we produce hard evidence that batching/offload alone is not enough.
