# UDP File Transfers Above 2 Gbps

## Summary

The previous acceptance run proved that the Mac and the two-vCPU Hetzner VM can move a 3 GiB file at 2.34 Gbps forward and 2.12 Gbps reverse. It proved that with parallel TLS-over-TCP lanes. That is useful capacity evidence, but it does not satisfy this goal: the file payload itself must travel over one of derphole's UDP data planes.

This design makes the custom `bulk-packets-v1` path batch-native from file read through file commit, adds a short authenticated capacity probe before the first file byte, and lets capable peers prefer the optimized UDP path for large files. QUIC and direct TCP remain compatibility fallbacks. They do not count toward the UDP acceptance result.

The important distinction is not TCP versus UDP as a matter of taste. At 2 Gbps, a 1,358-byte bulk payload produces roughly 184,000 datagrams per second. If each datagram becomes its own allocation, timer lookup, channel handoff, syscall, metrics update, and disk decision, the protocol spends the two-vCPU budget administering packets instead of moving the file. The wire can stay packetized. The implementation cannot.

## Acceptance Contract

The goal is complete only when all of these conditions hold on an exact candidate revision:

- Run three normal 3 GiB `send FILE` / `receive TOKEN` transfers from the Mac to `root@hetz` and three in the reverse direction.
- Use the public Internet with Tailscale candidates disabled for the benchmark. Selected transport addresses must prove the public path.
- Leave all benchmark-only transport and pacing overrides unset for the final runs.
- Negotiate an optimized UDP file mode and record `direct_transport=udp` for every payload trace.
- Reject any run containing `direct-tcp-files-v1`, `tls-tcp`, a QUIC or TCP payload fallback, or payload bytes on the relay.
- Exceed 2.0 Gbps canonical verified-file goodput in every accepted run, not merely in the mean.
- Keep the three-run coefficient of variation at or below 10 percent in each direction. A noisier cell may be rerun once in full after cooldown; individual samples are never cherry-picked.
- Match the exact payload size and SHA-256 digest, record zero peer/application byte delta, and finish without a process or socket leak.
- Record no direct-phase flatline of one second or longer and no steady receiver window below 500 Mbps.
- Keep repair payload below 2 percent of the file and `scan_checks_per_packet` below 2.0.
- Record CPU time, peak RSS, batch sizes, syscall counts, queue peaks, pacing decisions, loss/repair, and platform backend on both peers.
- Keep the Hetzner role below 8.0 total CPU seconds per verified GiB in each direction. At 2 Gbps, two CPUs provide about 8.6 CPU seconds per GiB; the lower gate leaves measurable headroom for the kernel and control plane.
- Confirm the Hetzner VM still has exactly two online CPUs and does not increment its OOM counter.
- Do not stop resident services, add swap, change the CPU allocation, or apply host tuning solely for the benchmark. The implementation and its bounded queues must coexist with the VM's ordinary background load.

Canonical goodput uses the receiver-anchored first-payload-to-committed-completion clock. Command-wall goodput remains a separate reported metric because setup time is real, even when it is not the transfer clock.

## Evidence and Root Cause

The current UDP implementations are well below the target on the same path:

| Data plane | Mac to Hetzner | Hetzner to Mac |
| --- | ---: | ---: |
| QUIC `blocks-v1` | about 1.19 Gbps | about 1.24 to 1.34 Gbps |
| forced custom bulk | about 1.14 Gbps | about 0.58 to 0.61 Gbps |
| gated batched custom bulk | 1.27 Gbps | 1.10 Gbps |

The gated batch prototype already proves several pieces independently:

- Linux GSO sends multiple full UDP datagrams with one syscall.
- Linux `recvmmsg` and Darwin `recvmsg_x` return real receive batches.
- Slab reads and in-place sealing remove the sender's per-packet input and output allocations.
- Asynchronous 256 KiB writes keep the disk syscall out of the packet receive loop.

But batching stops too early. Prepared slabs are still drained serially, one lane at a time. Decrypted datagrams are copied into individual jobs and sent through a shared channel one at a time. A single coordinator then performs validation, `time.Now`, seen/missing tracking, map assembly, metrics, and repair work for every packet. The old receiver profile makes the cost visible: 35 percent of samples were in Linux syscalls, 14 percent in packet authentication, 14 percent in `pwrite`, and the rest included allocation, select, timer, and scheduler overhead. The gated backend reduces syscall and disk pressure, then runs into the next serial queue.

There is also a pacing artifact. Production bulk starts at 1,000 wire Mbps and increases by 64 Mbps every 500 ms. A clean Hetzner path therefore spends a material fraction of a 3 GiB transfer below capacity. Starting every network at 2,400 Mbps is not the answer; Eric already demonstrated what sustained overshoot does to loss, repair, and local buffer pressure.

## Approaches Considered

### Optimize QUIC only

QUIC is already the faster production UDP path on high-capacity receivers, and it provides mature congestion control and recovery. The trouble is that the current implementation is already striped across multiple packet paths and still tops out near 1.3 Gbps under the exact CPU constraint. Closing the remaining gap would require invasive profiling and changes below the file layer, with less control over packet processing and recovery costs.

### Make custom bulk batch-native

This keeps selective repair and the existing authenticated UDP wire format, but changes the hot path to operate on batches rather than individual datagrams. The current gated prototype supplies the platform-specific primitives, telemetry, and many failure tests. The missing work is the queue geometry: concurrent lane writers, batch-shaped decrypt results, batch-shaped receive accounting, and a bounded capacity probe.

This is the recommended approach. It has the largest controllable efficiency surface without requiring a new wire protocol.

### Introduce a new bulk wire protocol

A new mode could negotiate AES-GCM, FEC, different packet headers, or batch-level acknowledgements. It also creates compatibility, security-review, and recovery work before we know the existing wire format is the limiter. The current evidence points at syscalls and per-packet coordination first. A new protocol is a later design if the batch-native `bulk-packets-v1` path reaches a measured crypto or wire-format ceiling below the goal.

## Architecture

### Capability and selection

Add `BlockPacketBatchCapable` to the v2 claim and accept messages. Peers that both advertise it may provisionally select optimized bulk for a large normal file regardless of the old candidate-count heuristic. An old peer keeps today's policy and wire behavior. For a capable pair, the native batch engine becomes the normal path; `DERPHOLE_TEST_BULK_BATCHED_IO` is no longer required to enable it. The capability changes engine selection, not the existing authenticated `bulk-packets-v1` wire format.

Final production selection order for a capable large-file pair is:

1. Establish and validate the raw public UDP lanes through the existing DERP rendezvous and hole-punching flow.
2. Run the bounded UDP capacity probe.
3. Confirm optimized `bulk-packets-v1` when at least one probe train is clean.
4. Fall back before the first payload byte when raw UDP validation or the probe fails.

The transfer-mode exchange records optimized bulk as provisional until the probe result is authenticated. Direct TCP and QUIC remain fallbacks for reachability and old-peer compatibility. There is no mid-payload fallback. Once a file byte is committed on one data plane, failure terminates the transfer rather than quietly duplicating the file across another transport.

### Sender pipeline

The sender operates in four bounded stages:

1. Two preparation workers read large contiguous slabs and seal each datagram into reusable storage.
2. Prepared datagrams are partitioned by raw UDP lane into persistent per-lane queues.
3. One writer per active lane preserves ordering for that lane while lanes write concurrently.
4. A shared pacer charges aggregate IPv4 wire bytes per batch. Counters and metrics update once per completed batch.

Linux writers use UDP GSO when eligible and `sendmmsg` otherwise. Darwin gains a real `sendmsg_x` backend instead of looping through `WriteTo`. Portable systems retain the one-datagram fallback, but the Mac/Linux acceptance pair must prove their native backends in the trace.

Queue depths are fixed and small. When preparation outruns the network, the lane queues apply backpressure to the slab workers. The sender does not grow a 3 GiB memory queue merely because the fiber is feeling optimistic.

### Receiver pipeline

Linux `recvmmsg` and Darwin `recvmsg_x` readers keep datagrams in reusable batch storage. Decrypt workers authenticate a batch and emit one receive-batch object containing validated headers, payload slices, and aggregate counts. They do not send one Go channel message per datagram.

The receive coordinator processes each batch in a tight loop:

- reject invalid run, total, index, or payload-length values;
- resolve duplicates and update the seen bitmap;
- update the incremental missing tracker;
- copy payloads into larger assembly groups;
- enqueue completed extents to the asynchronous file writer;
- update rate and trace metrics once for the batch timestamp.

Repair generation stays on its 100 ms cadence and remains selective. The reorder allowance continues to derive from measured packet rate. Batch processing may change when the tracker is called, but not which missing indexes it is allowed to request.

### Capacity probe and pacing

The sender performs a short authenticated probe after direct lanes are validated and before the first file byte. It tests aggregate wire rates of 128, 512, 1,000, 1,600, and 2,400 Mbps in order. Each train lasts at most 50 ms and carries at most 16 MiB. The sender stops increasing after the first pressured train.

The receiver returns authenticated sent, received, and overflow counts for each train. A train is clean when at least 90 percent of its datagrams arrive, neither peer reports local buffer pressure or overflow, and the result arrives within the bounded probe timeout. The file pacer starts at 90 percent of the highest clean rate, clamped to the controller's 128 to 2,400 Mbps range. If no train is clean, the optimized path is rejected before payload.

This costs a high-capacity path roughly a quarter second of setup rather than several seconds of payload ramp. A constrained path stops after its first pressured step. Candidate count is no longer asked to impersonate a bandwidth measurement.

The existing progress-and-repair controller then adjusts during the transfer. Clean high-capacity paths reach their starting rate before the canonical transfer clock begins; constrained paths keep a lower target without relying on candidate count as a bandwidth oracle.

Probe packets use authenticated control framing and a distinct packet kind. Peers that do not advertise the capability never receive them.

### Telemetry

Existing trace fields remain, with these additions or strengthened requirements:

- probe rates, delivered bytes, loss, selected seed, and probe duration;
- native send and receive backend per peer;
- batch syscall and datagram counts;
- send-lane queue and receive-batch queue peaks;
- decrypt batches and datagrams per batch;
- assembly extents and asynchronous writer queue peak;
- payload transport mode, including an explicit assertion that no TCP payload path was selected.

The benchmark summary copies these fields into CSV. A fast number without the backend and queue evidence is not an accepted result; it is just a flattering screenshot.

## Failure Handling

- Unsupported GSO, `sendmsg_x`, `recvmsg_x`, `sendmmsg`, or `recvmmsg` falls back to the next safe backend and records the reason.
- `ENOBUFS` remains retryable with bounded waits and cumulative pressure telemetry.
- Invalid batch counts, short writes, truncated datagrams, authentication failures, queue cancellation, and writer failures terminate the transfer with the original cause preserved.
- The capacity probe has a hard byte/time budget. Timeout, excessive loss, or mismatched authentication rejects the optimized path before payload.
- Cancellation closes or deadlines every blocked reader and writer. No worker may outlive the transfer context.
- Repair and completion remain idempotent under duplicated or reordered control packets.

## Test Strategy

Implementation follows red-green-refactor steps. Focused tests precede each production change:

- Darwin `sendmsg_x` batches multiple queued datagrams and falls back safely.
- Concurrent lane writers preserve per-lane ordering, account exact bytes once, stop on the first error, and release all slabs on cancellation.
- Batch decryption emits one batch result, rejects malformed members, reuses buffers, and drains cleanly on cancellation.
- Batch receive accounting handles duplicates, reordering, loss, final short packets, repair, and large files without changing integrity.
- The capacity probe chooses the highest clean rate, respects byte/time caps, rejects forged results, and seeds the controller without an environment override.
- Capability negotiation prefers optimized UDP only when both peers support it and retains old-peer fallback.
- Deterministic Linux tests cover GSO, `sendmmsg`, `recvmmsg`, loss, repair, `ENOBUFS`, cancellation, and no-leak cleanup.
- Darwin tests cover `sendmsg_x`, `recvmsg_x`, cancellation, and portable fallback.

Verification then expands in stages:

1. Focused package tests and race tests for changed components.
2. Full `mise run check`, local smoke, and Linux cross-platform lint/static analysis.
3. A 1 GiB forced-bulk proof in each Hetzner direction with CPU profiles. Continue only when the profile shows no single serial stage consuming the target's CPU budget.
4. Three 3 GiB unoverridden final runs in each direction under the acceptance contract.
5. Three 1 GiB runs in both directions on every reachable canonical test host. Lower-capacity hosts are judged against same-run capacity and prior stable behavior, not against 2 Gbps. Integrity, repair, stability, no-leak, and no-host-failure gates still apply everywhere.

The final harness retains traces, logs, resource summaries, hashes, and normalized results, but removes each exact harness-owned receive payload after its size and SHA-256 digest are verified. It checks free space before staging the 3 GiB source and before every run. This keeps the gate safe on the actual Hetzner disk without deleting unrelated data or weakening integrity evidence.

Eric receives conservative monitoring before, during, and after its cell: uptime, OOM count, process count, memory, disk, and kernel log deltas. A host or VM disappearance stops that cell immediately; it is not retried as though rebooting were a benchmark variance problem.

## Scope Boundaries

- This work changes normal file send/receive, not the pipe workload.
- DERP rendezvous, UDP hole punching, Tailscale candidate discovery in production, and relay fallback remain.
- The final Hetzner acceptance uses public non-Tailscale addresses.
- Direct TCP is not removed in this change. It remains a fallback, but its throughput cannot satisfy or mask the UDP goal.
- A new bulk wire version, FEC, or cipher change requires separate evidence that the batch-native v1 wire is the limiter.

The practical rule is simple: batch the work at every boundary, then measure the queue that remains. The network already proved it can carry the bits. The implementation now has to stop charging two CPUs an administrative fee for every datagram.
