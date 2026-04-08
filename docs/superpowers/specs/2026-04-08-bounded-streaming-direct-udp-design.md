# Bounded streaming direct UDP design

Date: 2026-04-08

## Goal

Make the default direct-UDP transfer path a bounded-memory byte stream. It must work for regular files, pipes, `pv`, and unknown-length stdin without first reading the full input into RAM or a temp file. It should keep the low-overhead/high-throughput behavior of the current direct UDP blast path, but add backpressure, ACK/SACK-driven repair, receiver-ordering, and explicit memory budgets.

Target behavior:

- Time to first byte is driven by direct path setup plus the first stdin read, not by total input length.
- Sender memory is bounded by a replay/in-flight byte budget.
- Receiver memory is bounded by a reorder byte budget.
- Receiver writes contiguous bytes to `stdout` as soon as they are available, so `derpcat listen | pv > file` shows real network delivery.
- Sender-side `pv | derpcat send` is accepted, but it measures producer-to-derpcat ingest. Network progress belongs in derpcat stats or listener-side `pv`.
- No Tailscale endpoints are required or used in regression tests. DERP coordinates the UDP candidate exchange.
- No forwarded port is required for derpcat. Mac port 8321 is a test-only iperf3 baseline.

## Non-goals

- Do not make full-input temp spooling part of the default direct-UDP data path.
- Do not require user-provided size, rate, lane count, window, or NAT settings.
- Do not promise throughput above the current WAN ceiling. Use iperf3 over port 8321 to estimate that ceiling.
- Do not clone iperf3's test protocol. Use iperf as a reference for pacing, counters, syscall batching, and measurement discipline.

## Reference lessons

From `~/code/iperf`:

- Keep per-stream interval counters (`bytes_sent_this_interval`, `bytes_received_this_interval`) separate from cumulative counters. This makes control-loop feedback and reports comparable.
- Pace from actual delivered time and bytes. iperf throttles against elapsed test time instead of sleeping a fixed amount per packet.
- Prefer multi-send / batched UDP writes when unpaced; prefer smaller pacing decisions when actively rate-limiting.
- UDP receivers should account for highest sequence seen, loss/gaps, out-of-order packets, interval bytes, and first-packet timing.
- Socket send/receive buffers are part of the test surface. Set/check them once and report transport capability.

From the current derpcat code:

- `probe.Send` already has a bounded reliable packet sender with cumulative ACK, ACK mask, extended ACK payload, in-flight map, and receiver reorder map.
- `sendBlast`/`SendBlastParallel` have the syscall batching and adaptive rate-control machinery needed for high throughput.
- `externalDirectUDPSendDiscard` currently calls `externalDirectUDPSpoolDiscardLanes` before signaling start. This must stop being the default for streaming send.
- `externalDirectUDPReceiveSectionTarget` currently spools receiver output when the destination is not a regular file. This must stop being the default for streaming receive.

## Protocol shape

Add a direct UDP stream mode, logically `direct_udp_stream_v1`.

Each stream uses one transfer RunID shared by all data lanes. Packets carry:

- stream byte offset
- packet sequence number
- payload length
- packet type: data, done, ack/control
- lane/stripe identifier when useful for diagnostics

The sender assigns monotonically increasing stream offsets before distributing packets to UDP lanes. The receiver merges lanes by byte offset and writes only the contiguous prefix to `dst`.

Done is a terminal control packet carrying the final byte length. It is retransmitted until ACKed, and the receiver completes only after all bytes below that final length have been written.

## Sender algorithm

The sender owns a replay window keyed by sequence and byte offset.

Loop:

1. Drain ACK/control packets from all UDP lanes.
2. Mark acknowledged packets free. Drop replay payloads below the cumulative ACK floor.
3. Process SACK/repair requests by scheduling missing packets already in the replay window.
4. If replay bytes and in-flight bytes are below the advertised/effective window, read the next stdin chunk.
5. Copy that chunk into a replay slab, create one or more data packets, and enqueue writes.
6. Send batches with the existing packet batcher and adaptive pacer.
7. If stdin returns EOF, enqueue and retransmit Done until acknowledged.

Hard invariant: the sender never reads more bytes from stdin when doing so would exceed the replay byte budget. Backpressure propagates to the source pipe naturally.

Initial budgets should be conservative enough for slower hosts and high enough for ktzlxc:

- start replay/window around one bandwidth-delay product estimate or a safe default
- grow when receiver ACKs cleanly and reorder backlog remains low
- shrink rate/window on repair storms, old outstanding bytes, receiver backlog pressure, or delivery gaps
- keep an absolute default memory ceiling; make it visible in verbose/debug stats

## Receiver algorithm

The receiver owns a reorder buffer keyed by stream byte offset.

For every valid data packet:

1. If offset matches `nextWriteOffset`, write payload to `dst`.
2. After each write, flush any buffered contiguous packets.
3. If offset is above `nextWriteOffset`, buffer it only while inside the reorder byte budget.
4. If offset is below `nextWriteOffset`, treat it as duplicate repair and ignore payload.
5. Emit ACK/control at short intervals or after enough packets/bytes.

ACK/control carries:

- cumulative byte write offset
- cumulative packet ACK floor where applicable
- compact SACK / missing range information inside the live window
- receiver interval bytes
- received packet count
- duplicate/out-of-order/drop counters
- reorder buffered bytes
- advertised receive window
- Done ACK when final byte has been written

Hard invariant: receiver writes to `dst` during transfer. It does not wait for full file completion unless the transport falls back to an explicit file-assembly mode.

## Rate, window, and recovery

Use a combined control loop:

- bytes ACKed controls sender window/replay freeing
- receiver interval bytes controls rate ramp
- missing/repair counters control multiplicative decrease
- receiver reorder buffered bytes control pressure
- sender age of oldest unacked packet controls retransmit urgency

Rate control should remain dynamic. ktzlxc should ramp toward roughly the current iperf3 baseline; canlxc and lower-WAN hosts should converge below their ceiling rather than time out.

Repair must be bounded:

- Receiver requests repairs for holes inside its live window.
- Sender retransmits only packets still inside replay history.
- If a hole ages out of sender replay, fail explicitly with a diagnostic instead of hanging or reporting impossible throughput.

## Benchmarks and profiling

Add Go benchmarks before or with the implementation:

- sender replay window insert/ack/free/lookup, with `-benchmem`
- receiver reorder contiguous-write and hole-fill paths, with `-benchmem`
- ACK/control encode/decode and apply path, with `-benchmem`
- loopback UDP stream throughput to `io.Discard`
- loopback UDP stream pipe path to prove time-to-first-byte and bounded read-ahead

Keep the benchmark functions pprof-compatible:

```sh
go test ./pkg/probe -run '^$' -bench 'Benchmark.*Stream' -benchmem
go test ./pkg/probe -run '^$' -bench 'Benchmark.*StreamUDP' -cpuprofile /tmp/derpcat.cpu.pprof -memprofile /tmp/derpcat.mem.pprof
```

## Acceptance

Local verification:

- `mise run test`
- `mise run vet`
- `mise run check`
- streaming unit tests with unknown-length readers and slow writers
- streaming benchmarks with allocation counts recorded in the PR / final notes

Live verification:

- start with local loopback transfer
- test canlxc for stability before optimizing ktzlxc
- test ktzlxc both directions with `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1`
- run iperf3 through forwarded Mac port 8321 as the independent WAN baseline
- verify listener-side `pv` advances during the transfer
- run 10x ktzlxc back-and-forth once single runs are stable

Release/CI:

- commit on main
- push main
- wait for GitHub CI/CD to pass

