# Direct UDP Proof Design

## Summary

Build a standalone experimental probe that tests whether a simpler direct UDP data plane can materially outperform derpcat's current no-Tailscale QUIC path on the public Internet. The probe is not a production transport. Its job is to establish evidence. If the probe wins, it becomes the basis for a later derpcat refactor. If it does not, we stop before spending time on the wrong transport rewrite.

This work is intentionally split into two phases:

1. Phase 1: prove the path and the technique with a standalone experimental probe.
2. Phase 2: only if phase 1 wins, integrate the winning technique into derpcat while keeping derpcat's session model, control plane, and security guarantees.

## Goals

- Prove whether a simpler direct UDP transport can beat derpcat's current direct QUIC path.
- Keep the proof apples-to-apples against existing baselines:
  - Tailscale `iperf3`
  - derpcat with `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1`
  - new probe, also not over Tailscale
- Benchmark all required hosts:
  - `ktzlxc`
  - `canlxc`
  - `uklxc`
  - `orange-india.exe.xyz`
- Produce repeatable measurements that show:
  - setup time to first byte
  - large-transfer goodput
  - loss and retransmission behavior
  - whether the path succeeds directly at all
- Preserve a clean decision point before any production refactor.

## Non-Goals

- Replacing derpcat's production transport in this phase.
- Building a full WireGuard replacement or a generic magicsock clone.
- Solving reliable public-Internet direct TCP traversal. TCP probing may exist for diagnostics, but it is not the main plan.
- Matching every derpcat feature in the probe. The probe only needs enough machinery to answer the throughput question.

## Context

derpcat's current public direct fast path is QUIC over UDP, with DERP used for rendezvous, relay fallback, and control. Native TCP exists as a fast path when both sides already have a mutually usable TCP route, but it is not a general TCP NAT traversal system.

The current benchmark picture is mixed:

- `ktzlxc` can get close to line rate with tuned striping, which suggests the path itself is strong.
- `canlxc` and `uklxc` are slower and less consistent, which suggests WAN path quality and host constraints matter.
- QUIC does not reliably reach the WAN ceiling on the best host, which keeps open the possibility that QUIC overhead is leaving performance on the table.

Tailscale's direct path uses UDP, not direct peer TCP. DERP is their TCP relay fallback. That makes a simpler UDP data plane the credible path to investigate first.

## Approaches Considered

### Approach 1: SSH-coordinated standalone UDP probe

Use a separate binary that coordinates both sides over SSH, exchanges public endpoints, performs simultaneous UDP punching, then runs a bulk UDP transfer with minimal reliability.

Pros:

- Fastest path to evidence.
- Minimal coupling to existing derpcat code.
- Easy to compare raw path ceiling versus derpcat and Tailscale.

Cons:

- Lower fidelity to derpcat's production control plane.
- Some code may be discarded if the experiment fails.

### Approach 2: Experimental derpcat data plane behind existing rendezvous/control

Reuse derpcat token flow, DERP control, and candidate exchange, but replace only the direct data plane with an experimental UDP transport.

Pros:

- Best apples-to-apples comparison.
- More code directly reusable if the experiment succeeds.

Cons:

- More code before we know whether the idea is worthwhile.
- Higher risk of conflating control-plane issues with data-plane issues.

### Approach 3: Full production refactor immediately

Refactor derpcat's direct transport now and test as we go.

Pros:

- No throwaway tooling.

Cons:

- Wrong order of operations.
- Too much surface area before we have proof that the new data plane wins.
- High risk of spending time on a transport change that does not move the benchmark.

## Recommendation

Use approach 1 first, then approach 2 only if the results justify it.

The standalone probe should be intentionally small and brutally empirical. Its purpose is to answer one question: does a simpler direct UDP data plane materially outperform derpcat's current direct QUIC path on the same host pairs and payload sizes? If the answer is yes, phase 2 ports the winning ideas into derpcat. If the answer is no, the refactor stops there.

## Phase 1 Architecture

### Binary Layout

Add a standalone debug binary under `cmd/derpcat-probe/` with three modes:

- `server`
- `client`
- `orchestrate`

`orchestrate` runs on the Mac and drives the entire proof workflow. It may SSH into the remote host to deploy or invoke the same binary, start the remote side, exchange endpoint information, trigger simultaneous punching, run benchmark iterations, and collect results.

This is intentionally separate from the main `cmd/derpcat/` CLI so the experiment can change rapidly without destabilizing user-facing behavior.

### Control Path

For phase 1, the control path can be SSH-coordinated rather than DERP-coordinated. That keeps the proof simple and isolates the data-plane question.

The orchestrator will:

1. Start the remote server.
2. Gather each side's local bind address and any discovered public endpoint.
3. Exchange candidate addresses.
4. Trigger a simultaneous punch loop on both sides.
5. Once direct packets are flowing, start a unidirectional or bidirectional throughput test.

This phase does not need to reuse derpcat tokens or DERP control messages yet.

### Data Plane

The data plane should be a simple UDP transport, not QUIC.

Required characteristics:

- Single session per run.
- Fixed packet format.
- No streams.
- No HTTP/3, TLS, or QUIC stack overhead.
- Enough reliability to measure useful goodput rather than raw packet blast only.

Recommended packet types:

- `hello`
- `hello-ack`
- `data`
- `ack`
- `done`
- `stats`

Recommended packet header fields:

- protocol version
- run id
- packet type
- sequence number
- byte offset
- payload length

The sender transmits fixed-size data datagrams. The receiver sends periodic ACK frames containing:

- highest contiguous byte offset
- selective ACK bitmap or short ACK ranges
- receive statistics for that sample window

The sender keeps a bounded retransmit window and limited in-flight budget. The goal is not to build a full congestion controller in phase 1. The goal is to build enough reliability to measure goodput and see whether the simpler data plane is fundamentally faster.

### Security in Phase 1

Phase 1 should start with the simplest configuration that answers the question. That means:

- raw mode first, with a random run id and shared run secret only used to reject unrelated packets
- optional encrypted mode second, using a single per-run AEAD key

Reasoning:

- raw mode establishes the path ceiling
- encrypted mode shows whether a minimal secure transport stays near the raw result
- if encrypted mode collapses performance, that matters for phase 2

The probe does not need derpcat-grade session semantics in phase 1, but it must still reject unrelated traffic and avoid accepting arbitrary packets from the Internet.

### Optional TCP Diagnostic

The probe may include a small TCP diagnostic mode that attempts:

- listen plus dial race
- simultaneous open where feasible
- public and private candidate combinations already known to each side

This is diagnostic only. It should report whether a direct TCP path was viable on the tested pair. It is not the main throughput target and should not block the UDP proof.

## Measurement Plan

### Host Matrix

Run the full comparison against:

- `ktzlxc`
- `canlxc`
- `uklxc`
- `orange-india.exe.xyz`

### Baselines

For each host pair, collect:

1. Tailscale baseline
   - `iperf3`
   - both directions
   - 3 runs per direction

2. Current derpcat baseline
   - `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1`
   - current default settings
   - `--parallel=auto`
   - optional fixed `--parallel=8` where useful for context

3. New probe baseline
   - direct raw UDP mode
   - then encrypted UDP mode if raw mode is promising

### Size Matrix

For derpcat and the new probe:

- `10KB`
- `1MB`
- `10MB`
- `50MB`
- `128MB`
- `1GB`

Small sizes matter because the user experience depends on startup behavior, not just peak throughput. Large sizes matter because they expose whether the path can approach line speed.

### Metrics

Record at least:

- time to first byte
- total duration
- goodput Mbps
- packet loss rate
- retransmit rate
- ACK RTT estimate
- effective payload size
- whether a direct path succeeded
- host WAN ceiling snapshot, using existing speedtest data or fresh spot checks

Store results in:

- host-specific markdown logs similar to the existing benchmark notes
- structured JSON output from the probe so later runs are comparable

## Decision Gates

### Gate A: Does the raw probe beat current derpcat on `ktzlxc`?

If the raw direct UDP probe does not materially beat current derpcat on `ktzlxc`, stop. That means QUIC is probably not the main bottleneck, and a production refactor is not justified yet.

### Gate B: Do the slower hosts show the same effect?

If the raw probe wins strongly on `ktzlxc` but not on `canlxc` or `uklxc`, treat that as evidence that WAN path quality and host limits are dominant on those hosts. That still justifies a refactor for strong paths, but it changes the product claim. The goal becomes "better where the path allows" rather than "fix every slow host."

### Gate C: Does minimal encryption stay close to raw mode?

If the encrypted mode stays close to the raw mode, phase 2 is viable. If encryption collapses throughput, phase 2 must solve that before replacing QUIC.

### Gate D: Is startup behavior acceptable at small sizes?

If the probe only wins on `1GB` but regresses noticeably on `10KB` through `10MB`, the later refactor must be hybrid rather than wholesale. It may still be a viable large-transfer fast path, but not a universal default.

Only after these gates pass should phase 2 begin.

## Phase 2 Direction

If phase 1 succeeds, phase 2 should not be a blind rewrite. It should:

- keep derpcat's session model
- keep DERP rendezvous and relay fallback
- keep the current no-Tailscale validation discipline
- replace only the direct data plane for the relevant session types
- preserve derpcat's security model with proper session authentication and peer binding

The expected shape is:

- keep DERP for control and bootstrap
- keep candidate discovery and direct-path promotion
- replace QUIC data transfer with a simpler encrypted UDP transport modeled on the winning phase 1 probe

## Risks

- Raw mode may overstate real-world wins if encryption later costs more than expected.
- SSH-coordinated orchestration may hide some control-plane costs that phase 2 will need to reintroduce.
- Host-level UDP buffer caps may still dominate results even if QUIC is not ideal.
- `canlxc` and `uklxc` may remain path-limited regardless of transport improvements.

## Validation Strategy

Before phase 2 begins, the proof must show:

- a direct path is consistently established without Tailscale candidates
- the new probe beats current derpcat on `ktzlxc` for large transfers
- the performance picture on `canlxc` and `uklxc` is explained by evidence, not guesswork
- encrypted mode remains close enough to raw mode to be worth productizing

## Open Questions Resolved

- The proof tool will be separate from the current derpcat CLI.
- Phase 1 may use SSH control because it is faster to build and sufficient to answer the question.
- The first target is evidence, not production completeness.
- The benchmark comparison must include all three hosts and must not use Tailscale candidates for derpcat or the new probe.
