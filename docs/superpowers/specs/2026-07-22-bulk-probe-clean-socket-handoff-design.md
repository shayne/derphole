# Bulk Probe Clean Socket Handoff Design

Date: 2026-07-22

Status: approved for planning

## Context

The bulk decision barrier fixes the protocol disagreement that caused one peer
to wait for bulk packets while the other opened QUIC. It does not yet make the
raw UDP sockets safe to reuse.

The frozen-head live run at `37f9183d` exposed the remaining gap. The sender
completed five acknowledged probe trains, then sent all 9,628 datagrams in the
2.2 Gbps train. Its three end frames did not produce an acknowledgement. The
sender therefore chose QUIC, the receiver acknowledged the exact decision, and
both peers logged `fallback-before-payload`. No QUIC handshake completed. Ten
seconds later the receiver reported `peer disconnected`, the sender reported
the matching peer abort, and both payload counters were still zero.

The decision was correct. The socket handoff was not.

When the receiver cancels its probe readers, those readers stop owning the
sockets, but unread probe datagrams remain in the kernel receive queues. The
decision acknowledgement currently means "I stopped the probe goroutines." It
does not mean "these sockets are ready for a different protocol." QUIC inherits
the queues anyway. At low backlog this often works. At 2.2 Gbps it becomes a
ten-second experiment in whether stale encrypted probe packets can crowd out a
new handshake. That is not a protocol boundary; it is wishful scheduling.

This design makes clean socket ownership part of the decision barrier.

## Goals

- Hand raw-direct sockets to QUIC only after all bulk readers and writers have
  stopped and every receive queue has reached a bounded quiet state.
- Make the receiver's QUIC decision acknowledgement prove that its socket
  cleanup finished successfully.
- Apply the same cleanup rule to the sender before it opens QUIC.
- Abort instead of opening QUIC when socket cleanup cannot be proved.
- Keep the real probe traffic and diagnostics when the deterministic
  `sender-reject` test outcome is enabled.
- Make early probe rejection, including acknowledgement timeout, deterministic
  and observable under the approved test outcome.
- Preserve normal probe selection when the test outcome is unset while making
  unsafe operational and cleanup failures abort explicitly.

## Non-goals

- Mid-payload fallback.
- Replacing raw-direct sockets after every probe.
- Adding a user-facing transport or drain flag.
- Supporting old clients that do not implement this handoff contract.
- Changing probe rates, selection thresholds, pacing, repair, grouping, or
  encryption.
- Treating cleanup failure as an ordinary capacity rejection.

## Decision

Add a bounded socket-drain step between bulk probe shutdown and QUIC startup.
The drain runs on every raw-direct lane concurrently. Each lane repeatedly
reads queued datagrams in batches until one short read window observes no
packet. A separate hard deadline bounds the whole lane drain. Success means
all lanes observed that quiet window before the hard deadline and all socket
deadlines were restored.

The quiet window is evidence of an empty queue, not a sleep. Waiting for 20
milliseconds without reading proves only that the queue enjoyed the break.

The receiver performs this drain after its probe readers have joined and
before it returns the probe outcome to the decision coordinator. The existing
coordinator already waits for that return before acknowledging an early QUIC
decision. The wire order therefore becomes:

```text
sender                         receiver
  |---- final probe train -------->|
  |<--- probe ACK lost ------------X
  |---- decision: QUIC ----------->|
  |                                | stop probe readers
  |                                | drain raw socket queues
  |                                | restore socket deadlines
  |<--- decision ACK: QUIC --------|
  | stop bulk readers/writers      |
  | drain local raw queues         |
  | restore socket deadlines       |
  |========= QUIC handshake ======>|
```

The sender opens QUIC only after it receives the decision ACK and completes its
own bulk cleanup. The receiver may create the QUIC listener after sending the
ACK because the peer cannot send a QUIC Initial before that ACK reaches it and
its local drain finishes. The barrier supplies the ordering; the drain supplies
the clean state.

## Drain semantics

The drain helper consumes an `externalV2BulkPacketPath` and returns structured
per-handoff diagnostics plus an error. It does not close sockets.

For each lane:

1. Create a fresh bulk batch reader over the existing packet connection.
2. Read batches under a short per-attempt context.
3. Count every discarded datagram.
4. After each successful batch, check the hard handoff deadline.
5. Treat a per-attempt deadline with no packet as the required quiet state.
6. Treat any other read error or the hard deadline as cleanup failure.
7. Restore zero read and write deadlines before returning.

All lanes drain concurrently. A noisy lane must not make seven quiet lanes wait
in series, and a fixed per-lane deadline must not accidentally become eight
times larger because the path has eight sockets.

The production quiet window is 10 milliseconds per read attempt. The hard
handoff deadline is 500 milliseconds from the start of the concurrent drain,
shared by every lane. That is long enough to consume the configured receive
queues in batches and remains comfortably inside the existing ten-second
decision barrier. Tests use injected durations and readers rather than
sleeping for production timeouts.

Late packets are handled by the quiet window. A peer that keeps sending beyond
the hard deadline produces a cleanup error. QUIC is not attempted on that path.

## Error boundary

Capacity rejection and cleanup failure remain different things.

- A lost probe acknowledgement and a completed selector rejection are ordinary
  capacity rejections. The sender may choose QUIC after the authenticated
  decision exchange.
- Packet encoding, packet write, context cancellation, peer abort, and
  authentication errors are operational failures. They abort rather than
  being relabeled as ordinary capacity rejection.
- Failure to stop a reader, drain a lane, or restore a deadline is a socket
  cleanup failure. Both peers abort. The outer runtime must not collapse it
  into the ordinary fallback sentinel.
- A decision or acknowledgement mismatch remains a protocol error.
- Context cancellation and peer abort keep their current priority.

This distinction matters because fallback is safe only after cleanup. Calling
cleanup failure "probe rejected" would make the log shorter and the bug more
patient.

## Deterministic test outcome

`DERPHOLE_TEST_BULK_PROBE_OUTCOME=sender-reject` still runs the real probe. Its
scope expands from successful selector returns to every completed sender probe
attempt that produced an ordinary capacity rejection, including an
acknowledgement timeout after one or more trains.

The controlled outcome:

- preserves the real run ID, duration, completed trains, sent and received
  counts, pressure, and the underlying rejection stage;
- clears the selected rate;
- carries the forced-outcome identity through the exact decision and cleanup
  path;
- emits exactly one sender-only
  `v2-bulk-probe-test-outcome=sender-reject` marker after the decision ACK and
  before `fallback-before-payload`;
- never converts cancellation, peer abort, protocol failure, or socket cleanup
  failure into a controlled rejection.

An explicit empty or unknown value remains fatal. The promotion driver still
removes the ambient variable and injects it only into the actual payload sender.

## Diagnostics

Verbose output records the local rejection stage before the stable wire reason:

```text
v2-bulk-probe-rejected=stage:ack-timeout train:5 rate_mbps:2200
v2-bulk-handoff-drain=lanes:8 datagrams:<count> duration_ms:<ms>
```

The rejection stage is local diagnostic state, not a new wire value. The wire
decision remains `quic/sender-probe-rejected` so both peers agree on a small,
stable protocol vocabulary.

Transfer traces retain the existing probe counters and decision tuple. They add
`bulk_probe_reject_stage`, `bulk_handoff_drained_datagrams`, and
`bulk_handoff_drain_duration_ms` so a failed acceptance run does not require
reconstructing the cause from batch syscall counters. Both sender and receiver
emit one successful `v2-bulk-handoff-drain` marker before opening their QUIC
endpoint.

Cleanup errors include the lane and operation. They must not include local
paths, addresses, tokens, or machine-specific details.

## Code boundaries

- `pkg/session/external_v2_bulk_packet_probe.go` owns probe rejection metadata,
  receiver probe shutdown, and the deterministic sender outcome.
- A focused session helper owns bounded concurrent queue draining and deadline
  restoration. It uses the existing batch abstraction rather than adding a
  second platform-specific receive stack.
- `pkg/session/external_v2_bulk_packet.go` owns sender pre-payload cleanup and
  keeps cleanup failures out of the negotiated fallback sentinel.
- `pkg/session/external_transfer_metrics.go` and `pkg/transfertrace` carry the
  new rejection and drain diagnostics.
- `scripts/promotion-benchmark-driver.sh` keeps its existing sender-only
  injection and exact marker gate. No new benchmark flag is added.

## Tests

Unit tests must prove:

1. A lane with queued probe datagrams is drained until a quiet read.
2. Multiple lanes drain concurrently and report the total discarded count.
3. A continuously noisy lane hits the hard deadline and fails the handoff.
4. A read or deadline-restoration error remains fatal and names its lane.
5. Receiver decision acknowledgement is not sent before probe readers join and
   the socket drain completes.
6. Sender QUIC open is not reached before sender cleanup and drain complete.
7. An early sender acknowledgement timeout keeps its real probe diagnostics,
   applies `sender-reject`, and emits the marker exactly once.
8. Cancellation, protocol error, peer abort, and cleanup failure are never
   converted by the test outcome.
9. The existing full in-process fallback test succeeds with stale datagrams
   queued before QUIC handoff and payload remains byte-exact.
10. The unset path preserves current selection and error identity.

Focused tests run normally and under `-race`. The normal implementation loop
ends with `mise run check:fast` and the repository quality baseline.

## Live acceptance

The final candidate is frozen before live work. It gets one exhaustive
`mise run check`, exact archived-tree Darwin and Linux binaries, and three fresh
3 GiB forward transfers against the configured remote host. Each sample must
show:

- eight-lane public raw-direct establishment;
- real probe traffic and the deterministic sender marker;
- identical QUIC decision and ACK tuples on both peers;
- a successful socket-drain marker before QUIC payload;
- `quic-blocks-v1`, exact byte count, SHA-256 parity, and no flatline;
- no disconnect, process, socket, output, or cleanup leak.

The batch uses a capacity-checked home or data filesystem. `/tmp` is used only
when its measured free space covers the payload and working overhead. Every
task-owned staging and output path is removed after evidence capture.

No failed sample is retried under the same head. A failure freezes that ordinal,
stops the remaining batch, and returns the work to diagnosis.

## Alternatives rejected

### Renegotiate fresh raw-direct sockets

Fresh sockets avoid stale queues, but they add a second candidate exchange,
another NAT-punching phase, more port-map state, and another failure boundary
after the peers already agreed on a mode. It is a reasonable escape hatch if a
bounded drain proves unreliable. It is not the smallest fix for state we can
remove in place.

### Fall back through the transport manager

Manager QUIC avoids raw socket reuse entirely. It can also move a public direct
transfer back through relay or a lower-performance path. The original failure
is in handoff hygiene, not reachability, so paying a permanent throughput tax
would fix the wrong layer.

### Sleep before opening QUIC

A sleep lets packets remain queued with greater dignity. It does not empty the
queue or prove ownership changed. Rejected.

## Success criteria

The change is complete when a lost high-rate probe acknowledgement cannot hand
dirty sockets to QUIC, the controlled sender outcome covers that real rejection
path without hiding fatal errors, diagnostics name the rejection and drain,
all focused and repository gates pass, independent review is clean, and three
exact-head live transfers complete with byte parity and full cleanup.
