# Public Transport Rewrite Design

Date: 2026-05-15

## Summary

Rewrite derphole's public transfer protocol around one clean session model with two data modes:

- a reliable QUIC baseline for correctness, relay, cancellation, and flaky links
- a new measured raw UDP fast path for large transfers on healthy direct paths

This is a breaking protocol change. Backward compatibility with existing tokens, wire messages, and direct UDP handoff behavior is not a goal. The priority is to remove the current fragile handoff/progress protocol, replace it with clear boundaries, and prove the replacement across relay, slow WAN, flaky direct UDP, and multi-gig LAN cases without leaking UDP sockets.

## Problem

The current protocol has accumulated too many interacting state machines:

- DERP relay/control
- relay-prefix file transfer
- direct UDP handoff
- custom reliable UDP repair/progress
- receiver-anchored progress ACKs
- direct/relay status reporting
- socket and process cleanup logic spread across command paths

Recent fixes have repeatedly touched direct UDP rate selection, relay-prefix handoff, progress accounting, peer aborts, and trace anchoring. That pattern indicates an architectural problem, not one isolated bug.

Observed failures include:

- receiver cancellation can leave the sender waiting until manually interrupted
- direct UDP can validate but then transfer at less than 1 Mbps
- sender and receiver progress can diverge when sender-side counters get ahead of receiver-committed bytes
- harness runs can leave UDP sockets or processes behind
- high-speed paths that used to perform well have regressed

The replacement must make correctness boring first, then earn fast-path status with measured evidence.

## Goals

- Support relay-only, slow direct, flaky direct, and multi-gig direct paths with one session protocol.
- Achieve at least 90% of measured viable path potential where direct networking allows it.
- Approach local `pve1` LAN line rate on the 2.5 Gbit path.
- Use `iperf3` as the independent capacity baseline for each host pair.
- Start transfers promptly without waiting for direct UDP to prove itself.
- Anchor user-visible sender progress to receiver-committed bytes.
- Treat direct UDP as a continuously validated path, not a one-time promotion.
- Finish over reliable mode or relay when fast UDP degrades.
- Make Ctrl-C and peer disconnects terminate both sides quickly.
- Prove every test run leaves zero derphole processes and zero derphole UDP sockets on both endpoints.
- Delete the obsolete public transport paths after the replacement passes gates.

## Non-Goals

- Preserve protocol compatibility with prior derphole releases.
- Keep the current relay-prefix/direct-UDP handoff code as a product path.
- Build a general VPN or mesh product.
- Require users to configure port forwarding.
- Require OS-level socket/sysctl tuning for normal use.
- Report throughput numbers from runs that do not also prove integrity and cleanup.

## Approaches Considered

### Approach 1: QUIC-only rewrite

Use QUIC streams over a path-switching UDP/DERP packet substrate for all payloads.

Pros:

- mature reliability, flow control, cancellation, and stream close semantics
- much less custom protocol code
- good baseline for relay and flaky links

Cons:

- may not reach 90%+ of multi-gig or best-WAN potential without significant tuning
- does not directly reuse the raw UDP performance work already proven in probe paths

### Approach 2: WireGuard/TCP overlay

Run an in-process WireGuard/netstack overlay and carry TCP streams over it.

Pros:

- clean stream semantics
- similar conceptual model to Tailscale
- one encrypted packet substrate for direct and relay

Cons:

- previous in-repo WG tunnel direction regressed throughput in benchmark notes
- userspace TCP/netstack tuning may be harder than QUIC tuning
- still does not directly use the highest-performing raw packet path

### Approach 3: Custom raw UDP stream only

Replace everything with a new reliable UDP stream protocol.

Pros:

- maximum control over packet size, batching, pacing, ACKs, repair, and striping
- best chance at peak throughput

Cons:

- highest correctness risk
- repeats the category of complexity that caused the current instability
- relay/flaky-link behavior would require substantial custom fallback logic

### Recommendation

Use a hybrid architecture:

- QUIC is the reliable correctness baseline.
- A new raw UDP fast path is used only when policy and telemetry prove it is the right mode.
- Both modes sit behind one public transport API and one path selector.
- Raw UDP must be demotable to QUIC or relay without corrupting progress or hanging.

This gives derphole a stable floor and a credible path to 90%+ of measured potential.

## Architecture

### Package Boundaries

`pkg/session` owns command semantics only:

- token issuance and validation
- claim, decision, accept, and reject
- file metadata
- command-level stream open and close
- user-facing progress and final status

It must not own transport handoff logic, UDP lane selection, repair state, or socket lifecycle.

`pkg/publictransport` is the single transport API used by public commands:

- `Open(ctx)`
- `DialStream(ctx)`
- `AcceptStream(ctx)`
- `CloseWithError(ctx, reason)`
- `Stats()`

The API hides whether the current payload is riding QUIC, fast UDP, direct UDP packets, or DERP relay packets.

`pkg/pathselect` owns path discovery and packet routing:

- DERP relay availability
- candidate exchange
- STUN and local endpoint candidates
- direct UDP validation
- direct path health
- fallback to relay
- UDP socket lifecycle

It exposes explicit cleanup and stats so harnesses can prove no socket leaks.

`pkg/reliable` owns QUIC reliable mode:

- QUIC streams over the selected packet path
- relay-only and flaky-link operation
- stream cancellation and close-with-error behavior
- fallback completion when fast UDP degrades

`pkg/fastudp` owns the raw UDP bulk engine:

- receiver-committed offset as source of truth
- bounded sender replay
- bounded receiver reorder
- ACK/SACK repair
- adaptive pacing
- packet batching where supported
- explicit abort and terminal verification

It is not a continuation of the current relay-prefix handoff code. Existing probe lessons can be reused, but the product API and state machine must be clean.

### Control Plane

DERP remains the control plane:

- token claim
- peer identity exchange
- protocol version and capability negotiation
- candidate exchange
- mode selection
- authenticated aborts
- final integrity and completion messages

DERP control messages stay small. Bulk payload should only ride DERP as transport packets through `pkg/pathselect`, not as a separate file-transfer protocol.

### Data Plane

Every transfer has one session identity and one receiver commit frontier.

The reliable mode starts first. This means relay-only and slow/flaky paths are valid from the beginning, and direct UDP probing cannot block time-to-first-byte.

The fast UDP path can take over only after policy allows it. It starts from an agreed receiver-committed offset and reports progress through the same receiver commit model. It may finish the transfer or be demoted back to reliable mode.

## Runtime Policy

1. Start reliable mode immediately.
2. Gather and validate direct UDP candidates in parallel.
3. Keep validating direct path health while data flows.
4. Enable fast UDP only for transfers large enough to benefit.
5. Promote to fast UDP only when direct path telemetry is healthy.
6. Demote fast UDP when committed progress stalls, loss grows, replay pressure exceeds budget, or receiver reorder pressure exceeds budget.
7. Finish over reliable mode or relay after demotion.
8. Report sender progress from receiver-committed bytes.
9. Close all streams, sockets, goroutines, and DERP subscriptions on success, failure, or cancellation.

## Data Flow

1. Receiver creates an offer token and opens DERP control.
2. Sender claims the token over DERP with identity, capabilities, candidates, and file metadata.
3. Receiver accepts or rejects with its identity, capabilities, and candidates.
4. Both sides start `publictransport`.
5. QUIC reliable mode becomes available first.
6. Payload starts on reliable mode.
7. `pathselect` validates direct UDP continuously.
8. For large transfers on healthy direct paths, both sides agree on a receiver commit offset for fast UDP.
9. `fastudp` sends from that offset with bounded replay and receiver-committed ACKs.
10. If fast UDP remains healthy, it completes the payload.
11. If fast UDP degrades, reliable mode resumes from the latest receiver-committed offset.
12. Final completion verifies byte count and SHA-256 before success is reported.

## Failure Handling

Peer cancellation is a protocol event, not a local-only context state.

Receiver Ctrl-C:

- send authenticated abort
- close QUIC streams with error
- close direct UDP sockets
- stop DERP subscriptions
- sender exits quickly with a peer-aborted error

Sender Ctrl-C follows the same rules in reverse.

Direct path failure:

- slow path below threshold stays on reliable mode
- stalled fast UDP demotes within a bounded window
- missing committed progress demotes or fails explicitly
- replay window exhaustion demotes or fails explicitly
- missing terminal ACK fails explicitly

Cleanup failure:

- test harness fails if any derphole process remains
- test harness fails if any derphole UDP socket remains
- throughput numbers from that run are invalid

Integrity failure:

- byte count mismatch fails
- SHA-256 mismatch fails
- no performance result is reported for failed integrity

## Telemetry

Both endpoints emit 500 ms CSV rows from a shared transfer epoch.

Required fields:

- role
- protocol version
- transfer id
- elapsed milliseconds from shared transfer start
- current mode: reliable, fastudp, relay
- current path: relay, direct, fallback
- receiver-committed bytes
- local bytes read from source
- local bytes written to socket
- local bytes received from socket
- local bytes written to destination
- interval committed byte rate
- active UDP socket count
- active goroutine count
- loss and missing packet counters
- retransmit counters
- receiver reorder bytes
- sender replay bytes
- active fast UDP lane count
- direct path validation state
- fallback reason
- terminal error

Trace analysis must align sender and receiver rows by the shared epoch and flag:

- sender progress ahead of receiver commit
- committed-byte stalls
- direct path validation without payload progress
- unrealistic sender-only throughput
- mode flapping
- socket/process leaks

## Harness And Benchmarks

The harness must be part of the design, not an afterthought.

Every live run must:

- collect sender and receiver CSV telemetry
- collect stdout and stderr logs
- collect pre-run and post-run UDP socket/process counts
- collect byte count and SHA-256
- fail if cleanup is incomplete
- fail if integrity is not proven
- avoid starting a new run while old derphole processes or sockets exist

Required hosts:

- local Mac to `pve1` on the 2.5 Gbit LAN
- `canlxc`
- `pouffe-rasp.exe.xyz`

Required baselines:

- `iperf3` direct TCP where possible
- `iperf3` UDP where useful for packet-loss and pacing ceilings
- configurable `iperf3` host and port parameters for forwarded or non-default endpoints
- current derphole before replacement
- replacement reliable mode
- replacement fast UDP mode

Performance goals:

- relay and flaky paths complete correctly even when slow
- LAN direct transfer approaches at least 90% of measured `iperf3` potential
- WAN direct transfer approaches at least 90% of viable direct-path potential
- fast UDP must beat reliable mode before it can become default for a host/path class

## Rollout

### Phase 1: Baseline And Harness

Build the leak-proof live harness first. It must reproduce and measure current behavior before replacement work claims improvement.

Exit criteria:

- pre/post process and UDP socket gates work locally and remotely
- 500 ms CSV traces exist for both sides
- current failures are classified by telemetry instead of manual terminal inspection

### Phase 2: Reliable Baseline

Implement `pkg/publictransport`, `pkg/pathselect`, and QUIC reliable mode for public `send/receive`.

Exit criteria:

- relay-only transfer passes
- slow/flaky direct transfer passes or falls back cleanly
- receiver Ctrl-C terminates sender
- sender Ctrl-C terminates receiver
- no socket/process leaks

### Phase 3: Fast UDP Engine

Implement `pkg/fastudp` behind an explicit policy flag or dev gate.

Exit criteria:

- bounded replay and reorder tests pass
- loss/repair tests pass
- cancellation tests pass
- demotion to reliable mode works
- live fast UDP beats reliable mode on at least one viable direct path

### Phase 4: Promotion Policy

Enable fast UDP by policy for large transfers on healthy direct paths.

Exit criteria:

- pve1 LAN reaches the performance target
- canlxc direct paths reach the viable WAN target or fall back clearly
- pouffe-rasp relay/limited paths remain stable
- repeated runs prove no leaks

### Phase 5: Delete Old Paths

Remove obsolete public transport code after the replacement passes:

- relay-prefix direct UDP handoff path
- old product raw UDP transfer path
- public native QUIC mode negotiation not used by the new transport
- stale token fields
- stale docs and harness paths that refer to old behavior

Exit criteria:

- one public transport API remains for public commands
- `mise run check` passes
- live promotion gate passes
- CI passes

## Test Strategy

Unit tests:

- public transport lifecycle cleanup
- path selection direct-to-relay fallback
- peer abort propagation in both directions
- QUIC stream close-with-error propagation
- fast UDP ACK/SACK behavior
- fast UDP replay and reorder bounds
- fast UDP demotion decisions
- telemetry row generation

Package tests:

- public `send/receive` over reliable relay
- public `send/receive` over direct reliable mode
- fast UDP takeover from a receiver commit offset
- reliable fallback from fast UDP
- cancellation while probing
- cancellation while transferring
- cancellation during terminal ACK
- cleanup after every failure path

Live tests:

- Mac to `pve1`, both directions, 1 GiB and larger
- Mac to `canlxc`, both directions, 1 GiB
- Mac to `pouffe-rasp.exe.xyz`, both directions where available
- relay-forced transfer
- constrained or slow-path transfer
- repeated-run socket leak test

## Success Criteria

The rewrite is successful when:

- public transfers no longer depend on the current relay-prefix/direct-UDP handoff protocol
- Ctrl-C on either endpoint terminates both endpoints quickly
- sender progress never exceeds receiver-committed progress
- slow and flaky paths complete or fail explicitly with diagnostics
- direct fast paths reach at least 90% of measured viable potential
- no live or harness run leaves UDP sockets or derphole processes behind
- old public transport code is deleted, not left as a competing default path
