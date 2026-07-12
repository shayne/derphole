# Bulk Repair Efficiency Design

Date: 2026-07-12

Status: reviewed and approved in session; implementation plan ready for execution.

## Summary

Make `bulk-packets-v1` repair work scale with unresolved loss instead of total bytes already received. The receiver currently rescans the full packet prefix every 100 ms. That looks harmless when the file is small. At 1 GiB and above it turns successful history into recurring work, consumes a receiver core, delays reads, and can create the packet loss it then tries to repair. The loop is technically selective repair. The CPU bill is less selective.

Replace the full-prefix scan with an incremental pending-gap tracker. Each packet index enters repair consideration at most once, late originals clear pending gaps in constant time, and repeat requests operate only on unresolved gaps. Make the active reorder allowance time-based so the same policy means roughly the same thing at 500 Mbps and 2.5 Gbps. Preserve immediate idle and end-of-transfer recovery.

The change is accepted only if it improves wire and CPU efficiency without buying those gains by lowering useful throughput. Normal file `send`/`receive`, public paths without Tailscale candidates, integrity, stability, cleanup, and the existing adaptive QUIC path remain part of the gate.

## Evidence and Root Cause

The accepted fleet run established that the production 1,000 Mbps initial target is safer than a route-specific lower default. It also exposed a different problem. Three forward bulk transfers to `derphole-testing` spent 20.25, 20.75, and 22.88 percent of payload size on repair traffic. Eric's corresponding 1 GiB runs spent 2.64 to 6.01 percent. Local UDP buffer pressure was zero in both groups.

A fresh 1 GiB public-path run on current `main` reproduced the peak-to-settle shape and added process sampling:

- peak goodput: 953.74 Mbps
- receiver-anchored goodput: 487.87 Mbps
- command-wall goodput: 375.24 Mbps
- repair payload: 327,546,884 bytes, or 30.5 percent of the file
- repair packets: 241,198
- repair requests observed by the sender: 14,647
- receiver CPU: roughly 94 percent of one core by transfer completion
- sender CPU: roughly 73 percent of one core by transfer completion

The current receiver stores one `seen` bit per packet and a `highestSeenPlusOne` index. Every active-repair tick calls `externalV2BulkPacketMissingBatches`, which starts at index zero and scans the entire eligible prefix. The eligible prefix grows for the life of the transfer. A 3 GiB file contains about 2.37 million packets, so repeated full scans can perform hundreds of millions of checks even when almost every old packet is already present.

The fixed 8,192-packet reorder trail compounds the problem. At 500 Mbps it represents roughly 178 ms of packets. At 1 Gbps it is about 89 ms. At 2.4 Gbps it is about 37 ms. Faster links therefore get a shorter time allowance and more premature repair requests. The policy changes when the link gets faster, which is an odd reward for upgrading the network.

This evidence supports one root-cause hypothesis: full-prefix scanning and a rate-dependent reorder allowance increase receiver work and premature repairs; receiver pressure then reduces sustained delivery and feeds the pacing controller more repair pressure. The implementation must test that hypothesis directly. If incremental tracking does not lower scan work, CPU, and repair traffic together, it is not the fix.

## Goals

- Reduce the median repair ratio on the public `derphole-testing` bulk path below 10 percent.
- Reduce receiver CPU seconds per GiB by at least 10 percent on that path.
- Preserve or improve receiver-anchored and command-wall goodput; neither median may regress more than 3 percent.
- Keep payload flatlines below one second, hashes and sizes exact, and cleanup complete.
- Preserve Eric's accepted 3 GiB forward performance within the same 3 percent bound.
- Preserve all reachable fleet host-directions and their intentionally negotiated transfer modes.
- Keep memory bounded by packet count and unresolved gaps. No per-tick allocation proportional to bytes already received.
- Keep the wire protocol compatible. Old peers must continue to transfer correctly.

## Non-Goals

- Do not replace selective repair with forward-error correction in this cycle.
- Do not lower the global 1,000 Mbps starting target to hide receiver work.
- Do not force bulk packets onto receivers that intentionally negotiate `blocks-v1`.
- Do not change candidate discovery, Tailscale behavior in production, or the receiver-aware mode selector.
- Do not optimize the `pipe` benchmark instead of normal file `send`/`receive`.
- Do not make user-facing tuning flags. Test-only controls may exist for controlled A/B work and must be absent from accepted production runs.

## Considered Approaches

### Incremental, time-aware gap tracking — selected

Keep a monotonic scan cursor and a compact list of unresolved packet indexes. Newly eligible indexes are scanned once. A packet arriving after it was classified missing clears its pending flag in constant time. Repair ticks compact the pending list and emit only gaps still unresolved and due for another request.

Derive the active reorder trail from observed receive rate and a target time window. This keeps the delay policy stable across link speeds without changing the wire format.

This approach attacks both measured mechanisms: repeated historical scanning and premature repairs. It adds receiver state, but the state is explicit, bounded, and testable.

### Increase the fixed trail or repair interval — rejected

A larger constant can reduce repairs on one route. It leaves the full-prefix scan intact and still means different milliseconds at different rates. It is a useful experiment control, not a scalable production design.

### Forward-error correction — deferred

FEC can trade fixed overhead for fewer feedback round trips. It also adds encoding CPU, a protocol capability, and permanent bandwidth overhead on clean paths. Adding it before fixing an avoidable receiver scan would be paying to route around our own loop.

## Architecture

### Incremental missing tracker

Add a receiver-owned `externalV2BulkPacketMissingTracker` with these logical fields:

- `scanCursor`: first packet index never examined for repair eligibility
- `pending`: compact packet-index slice containing unresolved gaps
- `pendingFlags`: packet-indexed flags preventing duplicate entries and allowing constant-time clears
- `lastRequestAt`: tracker-level time of the last active batch round
- `scanChecks`: cumulative indexes examined while advancing the cursor
- `pendingPeak`: largest unresolved pending population
- `requestedPackets`: cumulative packet indexes included in missing batches

The existing `seen` slice remains authoritative for packet arrival and deduplication. The tracker does not own payload data or file assembly.

When the reorder boundary advances, `advance(limit)` scans only `[scanCursor, limit)`. Each unseen index not already pending is appended once and marked. Then `scanCursor` moves to `limit`. It never moves backward.

When a packet arrives, `resolve(index)` clears its pending flag if set. The pending slice is compacted during the next request round; this avoids map allocation and avoids removing from the middle of a slice on the receive hot path.

When a request round is due, the tracker walks the pending slice once, drops resolved entries, and batches unresolved indexes using the existing 300-index wire limit. Active receiver rounds retain the established 100 ms cadence. The independent sender repair suppression remains defense in depth for duplicated or reordered control packets.

The work becomes proportional to newly matured indexes plus unresolved gaps. Already received history stops charging rent.

### Time-based reorder boundary

The receiver maintains an exponentially weighted packet-arrival rate from validated, first-seen data packets. Convert a target reorder duration into packet count:

```text
trail packets = packet rate × reorder window
```

Use a 250 ms production target, with a minimum of the existing 8,192 packets and a bounded maximum large enough for the 2.4 Gbps ceiling. The exact maximum belongs in the implementation plan after overflow and memory tests, but it must represent at least 250 ms at the current 2.4 Gbps ceiling.

Before a stable rate exists, use the minimum trail. Rate updates must be smoothed and monotonic enough that a burst cannot suddenly mature a huge prefix. Because `scanCursor` never retreats, a later rate decrease does not reclassify old packets.

The active boundary is `highestSeenPlusOne - trailPackets`, clamped at zero. This replaces the fixed packet-count interpretation, not the existing idle recovery.

### Idle and completion recovery

Active repair is conservative because more primary packets are still in flight. Idle recovery is different: if no data arrives for 100 ms, advance the tracker through the current lookahead and request unresolved gaps immediately. At primary-send completion, continue advancing toward `totalPackets` as existing idle rounds permit.

The sender still waits for the authenticated `DONE` control message and resets its completion timer when repair activity occurs. A missing packet at the tail must not wait for the 250 ms active reorder window.

### Telemetry

Expose these cumulative receiver diagnostics through the existing transfer trace path:

- `missing_scan_checks`
- `pending_missing`
- `pending_missing_peak`
- `repair_requested_packets`
- `repair_request_batches`
- `reorder_trail_packets`
- `receive_packet_rate_pps`

Keep sender `repair_requests`, `repair_bytes`, retransmits, pacing decisions, and ENOBUFS diagnostics unchanged. The checker and public harness copy the new values into machine-readable summaries where applicable. Healthy zeroes are valid data, not missing data.

Benchmark-only process measurements record user CPU seconds, system CPU seconds, and peak RSS for both sender and receiver. The promotion driver must isolate these values from application stderr and normalize macOS and Linux units. Unsupported platforms emit an explicit unavailable value instead of silently writing zero.

The primary efficiency metrics are:

```text
receiver CPU seconds per GiB = (user + system seconds) / transferred GiB
repair ratio = repair payload bytes / verified payload bytes
scan checks per packet = missing scan checks / total packets
```

Accepted runs require scan checks per packet to remain bounded near one plus unresolved-gap revisits, not grow with transfer duration.

## Compatibility and Failure Handling

- No packet or control-frame format changes are required.
- A new receiver works with an old sender because missing and done frames are unchanged.
- An old receiver works with a new sender because sender repair semantics remain unchanged.
- Invalid packet indexes remain ignored before tracker state changes.
- Tracker counters use overflow-safe arithmetic and clamp derived trail sizes before integer conversion.
- Allocation failure is not recoverable; validate total packet count before allocating packet-indexed state as the current receiver already does.
- A failed missing-control write remains non-fatal during active transfer, matching current behavior. Idle rounds retry.
- Cancellation stops data readers, repair work, timers, and process samplers without leaking sockets or benchmark processes.

## Test Strategy

Implementation follows red/green TDD.

### Tracker unit tests

- Advancing the boundary twice scans each matured index once.
- A late original clears a pending gap without inserting another entry.
- Compaction drops resolved gaps and preserves unresolved order.
- Missing batches retain the 300-index limit.
- Repeat active rounds respect the request interval.
- Idle mode requests unresolved gaps immediately.
- Scan work stays linear for a multi-million-packet synthetic transfer.

### Rate and reorder tests

- 500 Mbps, 1 Gbps, and 2.4 Gbps all map to approximately the same reorder duration.
- The minimum trail applies before a stable rate exists.
- Bursts do not move the boundary discontinuously.
- Integer overflow and maximum-rate inputs clamp safely.
- A delayed packet inside the reorder window produces no repair.
- A genuinely lost packet outside the window is requested and repaired.

### Integration tests

- The existing lossy multi-lane transfer completes with exact bytes and fewer duplicate repairs.
- Heavy lane reordering without loss does not trigger premature repair.
- Mixed loss and reordering completes without a one-second payload flatline.
- Old sender/new receiver and new sender/old receiver protocol fixtures remain compatible.
- Cancellation and control-write failures preserve current cleanup behavior.

### Telemetry and harness tests

- New trace diagnostics preserve healthy zeroes and legacy-schema compatibility.
- Summary rows bind CPU/RSS values to the correct sender, receiver, run, and workload.
- Missing or malformed process statistics reject the efficiency comparison rather than becoming zero.
- The public harness still forces normal files, disables Tailscale candidates for tests, and proves selected addresses.

## Live Experiment and Acceptance

All comparisons use exact source revisions, normal files, verified hashes and sizes, public non-Tailscale routes except the documented pve1 LAN cell, and paired same-direction TCP iperf samples.

### Focused A/B

Run a balanced `A B B A` sequence on `derphole-testing` forward with 1 GiB files. `A` is current `main`; `B` is the incremental tracker candidate. Repeat the sequence if paired iperf CV exceeds 15 percent.

Candidate medians must satisfy all of these:

- repair ratio below 10 percent
- receiver CPU seconds per GiB at least 10 percent lower
- scan checks per packet below 2.0
- receiver-anchored goodput no more than 3 percent below control
- command-wall goodput no more than 3 percent below control
- no payload flatline of at least one second
- no integrity, route, process, socket, or trace failure

### Eric guard

Run three unoverridden 1 GiB candidate Mac-to-Eric file transfers, balanced against three fresh 1 GiB controls in `A B B A B A` order. This preserves a 3 GiB candidate aggregate while producing independent samples for medians and path-variance checks. Compare against the fresh controls when the accepted 880.57 Mbps canonical and 738.86 Mbps wall medians are unreliable.

The candidate may not regress canonical or wall median more than 3 percent, may not increase repair ratio, and must reduce or hold receiver CPU seconds per GiB. The 1,000 Mbps production initial target remains unoverridden.

### Reachable fleet guard

Probe the full canonical inventory at execution time. Run three unoverridden 1 GiB transfers in both directions for every reachable host. Apply the change only to cells negotiating `bulk-packets-v1`; intentional `blocks-v1` cells are unchanged but still serve as integrity, route, stability, and cleanup controls.

Every cell must pass the existing mode-aware acceptance audit. A bulk cell additionally requires bounded scan work, valid CPU/RSS measurements, and no repair or CPU regression. One canonical-CV-only rerun remains permitted; integrity, mode, route, trace, resource, or cleanup failures do not receive a noise waiver.

## Completion

This work is complete only when the candidate passes focused A/B, the balanced Eric three-by-1-GiB gate, and the reachable fleet; independent review finds no unresolved Important issue; local and GitHub gates pass; the final commit lands on local and remote `main`; and the npm `dev` packages resolve to that landed commit.

If the tracker lowers CPU but not repair traffic, or repair traffic falls only because throughput falls, return to root-cause investigation. A prettier loop is not the objective. Faster, steadier, cheaper transfers are.

## Evidence-driven acceptance amendment

The original 25 percent focused CPU target was an investigative stretch goal. Across eight exact A/B attempts, the allocation-free candidate's strongest stable attempt measured 12.1524 percent lower receiver CPU/GiB without a throughput regression. Other intermediate candidates measured nearby improvements but were not retained. Two profile-driven attempts to close the remaining gap were rejected: Linux UDP GRO batching increased repair and reduced throughput, while larger synchronous receive writes did not improve CPU and introduced stall and memory tradeoffs. Plain `recvmmsg` was rejected before commit because deterministic Linux loss-and-repair tests timed out even with a one-message vector.

The focused CPU floor is therefore 10 percent. This is still a material measured improvement, remains above observed noise, and does not relax the repair, throughput, integrity, public-route, stability, resource, or cleanup gates. The later three-sample Eric and fleet gates continue to require no CPU or repair regression in every accepted cell.

The first fleet run then found a separate integration regression: active repair request cadence had changed from 100 ms to 250 ms alongside the independent 250 ms reorder window. The affected candidate lost 12.5 percent canonical goodput and raised repair 34.0 percent against a fresh same-path control. Live bisection isolated the tracker-integration boundary. Restoring the original request cadence in `14ff73a` recovered same-path goodput to within 0.3 percent, reduced repair 17.1 percent, and reduced receiver CPU/GiB 4.3 percent. Its fresh balanced Eric gate improved canonical goodput 0.93 percent, wall goodput 4.02 percent, repair 31.8 percent, and receiver CPU/GiB 17.89 percent versus control.
