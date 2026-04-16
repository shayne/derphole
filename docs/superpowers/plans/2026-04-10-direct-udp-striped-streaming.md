# Direct UDP Striped Streaming Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make DERP-rendezvoused direct UDP use stable iperf-style striped lanes by default for reliable streams while preserving relay-first startup, `pv` streaming, bounded memory, and dynamic WAN-rate scaling.

**Architecture:** Keep DERP for rendezvous and direct upgrade coordination. Move the high-throughput reliable stream path from a globally ordered multi-lane stream to hardened striped lanes with per-stripe repair, stats feedback, and bounded output reassembly. Keep section/spool paths for finite known-size use cases, not default stdin/stdout streaming.

**Tech Stack:** Go, `pkg/session` external direct UDP negotiation, `pkg/probe` blast/stream packet engine, repository `mise` build/test tasks.

---

### Task 1: Capture the Current Failure Mode

**Files:**
- Modify: `pkg/probe/session_test.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] Add a test proving the default external direct UDP stream config chooses striped blast when multiple direct lanes are available and fast-discard is false.
- [ ] Add a probe test proving striped receive sends feedback packets carrying stripe identity so sender control can associate ack/repair state with the correct lane.
- [ ] Run the targeted tests and verify they fail for the current implementation.

### Task 2: Harden Striped Stream Control

**Files:**
- Modify: `pkg/probe/session.go`
- Modify: `pkg/probe/blast_control.go` if packet control handling needs stripe metadata
- Modify: `pkg/session/external_direct_udp.go`

- [ ] Enable striped direct UDP streams by default for reliable stream mode, not fast-discard and not section spool.
- [ ] Emit striped receiver stats per stripe/lane, including stripe ID in the control packet header.
- [ ] Teach the send-side parallel control reader to preserve stripe ID for stats and repairs so per-lane replay windows can be acked independently.
- [ ] Keep global mode behavior unchanged for single-lane or non-striped paths.

### Task 3: Bound Streaming Reassembly

**Files:**
- Modify: `pkg/probe/session.go`
- Modify: `pkg/probe/session_test.go`

- [ ] Add a bounded pending-output guard for striped stdout streaming so a missing early block cannot grow memory without limit.
- [ ] On bound pressure, request repairs and backpressure rather than buffering arbitrary future data.
- [ ] Verify the receiver still emits bytes in order and works with unknown expected length.

### Task 4: Verify Against Benchmarks

**Files:**
- Modify tests/docs only if benchmark commands or logs reveal a real repo change.

- [ ] Run focused `go test` for `pkg/probe` and `pkg/session`.
- [ ] Run `mise run build`.
- [ ] Run no-Tailscale derphole 1 GiB forward and reverse against `ktzlxc`.
- [ ] Compare against iperf TCP/UDP `-P 4` baselines over forwarded port `8321` only as a baseline, not as an implementation dependency.
