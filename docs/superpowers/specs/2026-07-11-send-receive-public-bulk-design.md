# Send/Receive Public Bulk Throughput Correction Design

Date: 2026-07-11

Status: reviewed and approved in session; implementation plan is ready for execution.

## Summary

Make normal file `send`/`receive` transfers select the fastest suitable direct data plane regardless of which peer owns the rendezvous offer. Public-Internet performance tests must exercise that exact file workflow with Tailscale candidates disabled. Production discovery must continue to allow Tailscale, because a Tailscale route can be the best real-world path.

Performance takes priority over preserving obsolete internal paths. Remove code that exists only for a superseded transfer path when it is no longer required for negotiation compatibility, relay fallback, cancellation, or another supported command. The `pipe` workflow remains supported and should also be fast, but it is not a substitute for benchmarking file `send`/`receive`.

## Evidence

A public-only 3 GiB file transfer using the current development build reproduced the reported failure:

- normal `send`/`receive`
- Tailscale candidates disabled on both peers
- eight public raw-direct lanes and zero relay payload
- source and destination hashes matched
- roughly 77.5 MiB/s initial peak
- 235.78 Mbps, or 28.11 MiB/s, receiver-anchored average
- roughly 20.6 MiB/s post-ramp trough

The transfer negotiated `blocks-v1` over raw-direct QUIC. The file receiver advertised four public candidates, but the current policy examined the sender because the sender happened to be the rendezvous acceptor. The sender advertised sixteen candidates, exceeding the hard bulk threshold of four.

The promotion benchmark used `listen`/`pipe`, which reversed the rendezvous roles. In that topology the receiver was the acceptor, so the same policy examined its four candidates and selected `bulk-packets-v1`. Three 3 GiB specialized bulk runs averaged 811.78 Mbps. Those runs prove the bulk engine can perform well on this route, but they do not validate the normal file workflow.

An additional 1 GiB public-only QUIC diagnostic recorded 9,276 sender-side QUIC packet-loss events across eight connections, smoothed RTT as high as 157 ms, and large per-lane congestion-window imbalance. This explains the visible pattern: QUIC begins with a high slow-start burst, then loss recovery and congestion control converge on much lower sustained throughput. The bulk engine's paced, selectively repaired packet transfer is the intended high-throughput path for this kind of long-haul residential receiver.

The full `4096` manager receive queue and `transport-dropped-datagrams` output are a separate cleanup defect. Raw-direct payload bypasses that queue. A legacy manager punch loop continues after raw-direct is finalized, fills the abandoned manager queue, and produces misleading local drop counters. It is not the WAN loss responsible for QUIC's slowdown.

The sender progress line also changes clocks at successful completion. During transfer it uses receiver-confirmed bytes divided by receiver first-byte elapsed time. A terminal callback with elapsed time zero clears that clock, making the final line include offer and setup time. That UI error does not cause the transport slowdown, but it obscures validation.

## Requirements

- Normal file `send`/`receive` is the primary product and benchmark workload.
- Default operation remains automatic. Users must not need transport, parallelism, or tuning flags for high throughput.
- Production candidate discovery continues to allow public, private, and Tailscale candidates.
- Public-Internet benchmarks set `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` on both peers and prove the selected raw lanes are public.
- Transfer-mode selection must describe the file receiver, not the incidental rendezvous claimant or acceptor.
- Tailscale candidate noise must not change the transfer-mode policy. This does not remove Tailscale from route selection.
- The existing high-capacity-server protection remains: receivers with larger non-Tailscale candidate sets keep QUIC when it is the measured faster path.
- A finalized raw-direct path stops obsolete manager reads and punching before payload transfer begins.
- Sender progress uses one coherent transfer clock and does not switch clocks at completion.
- `pipe` remains correct and fast, but has a separate benchmark identity.
- Dead internal code may be removed when tests prove it no longer serves a supported path.

## Considered Approaches

### Receiver-aware policy — selected

Determine which peer receives the file from the negotiated block-transfer shape, then apply the existing compact-candidate policy to that receiver's non-Tailscale candidates.

- When the claim carries the block source, the acceptor is the receiver, so use acceptor candidates.
- When the claim advertises block-receive capability and the acceptor carries the source, the claimant is the receiver, so use claim candidates.
- Ignore Tailscale CGNAT and ULA candidates for this policy count only.

This makes identical sender/receiver pairs choose the same mode regardless of offer ownership. A compact residential receiver selects bulk packets. A public server with a larger candidate set retains QUIC. Actual route selection remains unchanged and may still select Tailscale in production.

### Minimum candidate count across both peers — rejected

Using the smaller peer count would be simple and rendezvous-role invariant, but it can select bulk merely because the sender is compact even when a high-capacity receiver performs better with QUIC. It uses the wrong endpoint as a performance proxy.

### Always use bulk packets for file blocks — rejected

This fixes the long-haul residential case but regresses measured high-capacity-server transfers. Historical tests showed bulk around 632–759 Mbps on a path where QUIC reached roughly 940–987 Mbps. Top performance requires an adaptive choice, not one universal data plane.

## Architecture

### Receiver-Aware Negotiation

Replace the acceptor-count helper with a receiver-aware policy helper. Its inputs remain the authenticated claim and the acceptor candidate list; it derives transfer direction from existing block-source and block-receiver fields.

The helper returns both the selected transfer mode and diagnostic inputs:

- receiver side: claimant or acceptor
- total receiver candidates
- non-Tailscale policy candidates
- ignored Tailscale candidates
- selected mode

Verbose telemetry records those values so future reports can prove why a mode was chosen. Invalid candidate strings count as non-compact and force the conservative QUIC choice rather than silently steering the bulk policy.

No wire-mode names change. Peers still negotiate `blocks-v1` and `bulk-packets-v1` using existing capability fields. A peer without bulk-packet capability stays on QUIC blocks.

### Raw-Direct Activation

Once both peers confirm raw-direct selection, activate that path exactly once:

- suppress obsolete manager path regression events
- stop manager direct reads
- stop the legacy manager punch loop
- open the raw QUIC or bulk endpoint

If raw-direct is unavailable, the manager path remains intact for relay/direct QUIC fallback. There is no supported mid-transfer fallback from an already finalized raw data plane, so keeping its manager receive loop and punch traffic alive serves no recovery purpose.

Rename or remove blast-era helpers as part of this cleanup. Keep only the smallest lifecycle API required by current raw-direct callers.

### Benchmark Workloads

The default derphole promotion workload becomes a real file transfer:

1. Generate a regular file.
2. Start `derphole --verbose send FILE` and capture its token.
3. Run remote `derphole --verbose receive -o FILE TOKEN`.
4. Wait for both commands.
5. Verify size, SHA-256, traces, selected public raw lanes, mode, and cleanup.

Reverse-direction support mirrors those roles with the remote peer running `send` and the local peer running `receive`.

Keep `listen`/`pipe` as an explicitly named stream workload rather than the default file benchmark. Reports must state the workload so a stream result cannot be presented as file-transfer validation.

The primary long-haul gate uses three 3 GiB Mac-to-remote file transfers with Tailscale candidates disabled on both peers. Each run also records a same-direction TCP `iperf3` baseline through port 8123. UDP `iperf3` is diagnostic and may be used to investigate loss, but it is not the canonical capacity comparison.

### Progress Accounting

Do not send a terminal progress update with an elapsed value of zero. Preserve the receiver clock only when receiver-confirmed progress already covers the complete payload. If the latest external progress is partial, finalization falls back to a complete local clock rather than extrapolating a stale receiver sample.

The displayed elapsed time and displayed rate must use the same clock. Receiver progress remains a recent smoothed rate; sender progress remains a receiver-confirmed cumulative rate unless a later product decision changes both intentionally.

## Removal Policy

Implementation should remove code when all of the following are true:

- no supported CLI or library path calls it after the new lifecycle is wired
- it is not required for compatibility with an older peer
- it is not required before raw-direct selection or when raw-direct fails
- focused integration tests cover the surviving fallback

Likely cleanup targets include blast-era naming around raw activation, duplicate punch-stop wrappers, and manager-path state that exists only after a committed raw path. Do not remove the manager transport itself; it is still required for rendezvous-era relay/direct QUIC fallback when raw-direct cannot be established.

## Error Handling

- A capability mismatch falls back to `blocks-v1`; it does not attempt an unsupported bulk transfer.
- If receiver-side candidate classification cannot be derived, use QUIC and emit a clear policy diagnostic.
- Raw-direct activation is idempotent so cancellation and deferred cleanup remain safe.
- A raw endpoint error aborts the transfer and closes all raw sockets, streams, DERP subscriptions, and receiver files.
- Benchmark failures preserve logs and traces, then clean processes, sockets, binaries, and payload files.
- A sample with a hash, size, trace, public-path, mode, process, or socket failure is not included in a performance average.

## Test-Driven Implementation

Write and observe failing tests before each production change.

### Negotiation Tests

- The same compact receiver selects bulk whether it is claimant or acceptor.
- Tailscale candidates remain available to production route selection but do not increase the transfer-policy count.
- A receiver with five or more non-Tailscale candidates keeps QUIC.
- A peer without bulk-packet capability keeps QUIC.
- Stream and file block sources retain correct headers, sizes, and chunking.

### Raw Lifecycle Tests

- A counting packet connection proves legacy punching stops within one punch interval after raw activation.
- Manager queue depth and drop counters stop changing after activation.
- Manager QUIC fallback remains usable when raw-direct negotiation fails.
- Cancellation closes both raw and manager resources without leaks.

### File Workflow Tests

- A normal offer/receive raw-direct integration test asserts `bulk-packets-v1` for a compact receiver.
- The inverse rendezvous topology produces the same mode.
- Successful file transfer verifies size and content hash.
- Sender terminal progress does not clear a valid receiver elapsed clock.
- A stale partial receiver clock is not used as the final rate.

### Benchmark Contract Tests

- The default promotion driver invokes `send FILE` and `receive -o FILE TOKEN`.
- `listen`/`pipe` requires an explicit stream workload.
- Public-path mode propagates the Tailscale-disable guard to both peers.
- Summary output records workload and negotiated transfer mode.
- The long-haul gate rejects a sample that does not show public raw lanes and the expected bulk mode.

## Verification Gate

Local verification includes focused package tests, race tests for changed concurrent transport code, the full test and vet tasks, local smoke tests, and packaging dry-run when command packaging is affected.

Live acceptance requires three public-only 3 GiB normal file `send`/`receive` runs. For every run:

- the exact binary revision is recorded on both peers
- all selected raw data lanes are public
- `bulk-packets-v1` is explicitly observed for the compact long-haul receiver
- source and sink sizes and SHA-256 hashes match
- sender and receiver traces pass the applicable steady-state stall checks
- no transfer processes, UDP sockets, binaries, or payload files leak
- receiver-anchored goodput and command-wall goodput are both reported

Report the individual rates, arithmetic mean, standard deviation, same-run `iperf3` values, and derphole-to-iperf ratios. The change is not complete if normal file throughput still shows the current QUIC peak-to-collapse shape, if the specialized stream workload is used as a substitute, or if a fast-host control regresses materially.

The normal file-transfer mean must be within 5 percent of a same-revision, same-route bulk stream control and at least 85 percent of the same-run TCP `iperf3` mean when the `iperf3` samples are stable. Treat an `iperf3` set with more than 20 percent coefficient of variation as diagnostic rather than the sole release gate. A fast-host control may not regress more than 5 percent from its accepted same-workload baseline.

## Risks

- Candidate count remains a topology proxy rather than direct path-capacity measurement. Keep the decision observable and preserve fast-host controls so a future selector can replace it with measured path feedback.
- Bulk over a selected Tailscale route adds another UDP layer. Production permits it, but public-path acceptance does not measure it; add a separate production-route control if real-world reports show a regression.
- Stopping manager reads too early would remove fallback. Activate only after both peers finalize raw-direct, and retain a failure-path integration test.
- Heavy QUIC metrics can perturb throughput. Use them for diagnosis, not acceptance-rate claims.
- Public Internet variance can hide regressions. Use three runs, same-run capacity baselines, integrity gates, and exact workload labeling.
