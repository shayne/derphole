# Direct UDP Diagnostic Telemetry Design

Date: 2026-05-17

## Summary

Add a focused diagnostic layer for the direct UDP data phase before making more controller changes.

Recent live runs show direct UDP promotion working and completing, but the sustained file-transfer rate is much lower than the direct probe path suggests. One representative run showed probe goodput around `530-580 Mbps`, while the full 1 GiB transfer settled near `198 Mbps`. The same run showed high peer receive queue depth and a controller that started around `263 Mbps` and did not climb toward the observed probe ceiling.

This phase should answer where throughput falls off: network delivery, packet engine, stream/replay/repair, sender pacing, receiver commit, or transport queue pressure.

## Goals

- Extend the existing transfer CSV with direct UDP data-phase diagnostics at the existing 500 ms cadence.
- Capture controller target rate, actual goodput, lane counts, lane limits, replay pressure, retransmits, repair activity, and peer receive queue depth over time.
- Keep the change observational: no rate, lane, handoff, or packet scheduling behavior changes in this phase.
- Add a benchmark comparison path that records iperf3 baseline, direct UDP probe results, and full derphole transfer traces for the same host pair.
- Make the output machine-readable enough to explain low throughput without relying on terminal progress bars.

## Non-Goals

- Do not tune the dynamic rate controller in this phase.
- Do not replace the direct UDP protocol.
- Do not add a UI or dashboard.
- Do not gate releases on a fixed throughput target yet.
- Do not make host-specific assumptions or commit local hostnames, usernames, paths, or private addresses into repository defaults.

## Measurement Target

The trace should explain the gap between probe capacity and sustained file-transfer capacity.

Each 500 ms sample should make it possible to correlate:

- controller target rate versus actual sender goodput
- receiver committed goodput versus received packet bytes
- active lanes, available lanes, lane cap, and lane floor
- replay window pressure and retransmit growth
- repair request and repair byte activity
- peer receive queue depth and backpressure
- ramp and exploration decisions: hold, increase, decrease, cap, or refuse to increase
- relay/direct byte split and phase transitions

Success for this phase is a trace that can identify the limiting layer. It is not expected to make transfers faster by itself.

## Architecture

### Runtime Snapshot Model

Extend the current transfer metrics path with a diagnostic snapshot that sender and receiver update as state changes. The CSV recorder should continue to sample from this state on its normal interval.

The snapshot should be read-only diagnostic state. It must not be part of the control path and must not block packet send or receive loops.

The snapshot should include:

- current phase and last state
- application bytes, relay bytes, and direct bytes
- selected rate, start rate, current target rate, rate ceiling, and exploration ceiling
- active lanes, available lanes, lane minimum, and lane cap
- replay window size, replay bytes held, and retransmit count
- repair request count and repair bytes
- current and max peer receive queue depth
- last controller decision and reason
- last error

### Probe And Data-Path Instrumentation

Probe results already explain short probe performance. The missing signal is the data-phase controller over time.

The data path should publish controller snapshots when:

- direct execution starts
- active rate changes
- active lane count changes
- the controller holds because of a ceiling, queue pressure, loss, replay pressure, or missing progress
- replay or retransmit counters change materially
- direct execution completes or fails

Final stats are still useful, but they are not enough. The diagnostic row stream must show whether the controller tried to ramp, why it stopped, and whether receiver progress or queue pressure caused it.

### Benchmark Comparison Mode

Extend the harness with a comparison mode that runs three measurements for the same host pair:

1. iperf3 baseline
2. direct UDP probe
3. full derphole transfer with CSV traces

The comparison does not need to be a release gate yet. It should produce a compact summary and preserve raw logs in the run directory.

Interpretation:

- iperf3 high and direct UDP probe low means the packet engine or UDP socket path is suspect.
- direct UDP probe high and full transfer low means stream, replay, repair, or controller behavior is suspect.
- sender target high and receiver committed low means receiver output, ordering, or backpressure is suspect.
- peer receive queue depth high while controller target is low means transport manager backpressure is suspect.
- retransmits or replay bytes rising rapidly means loss, repair, or replay-window behavior is suspect.

## CSV Schema Additions

Extend the existing transfer trace CSV instead of adding a second log.

Add these optional fields:

- `rate_target_mbps`
- `rate_ceiling_mbps`
- `rate_exploration_ceiling_mbps`
- `rate_selected_mbps`
- `active_lanes`
- `available_lanes`
- `lane_min`
- `lane_cap`
- `controller_decision`
- `controller_reason`
- `send_goodput_mbps`
- `receive_goodput_mbps`
- `receiver_committed_mbps`
- `replay_window_bytes`
- `replay_bytes`
- `retransmits`
- `repair_requests`
- `repair_bytes`
- `peer_recv_queue_depth`
- `peer_recv_queue_depth_max`
- `direct_packet_bytes`
- `direct_committed_bytes`

Role-specific unknowns should be empty. The sender should not invent receiver committed throughput unless it has peer progress evidence. The receiver should not invent sender pacing decisions.

The trace checker should continue to fail on integrity, terminal error, and stall conditions. Low throughput should be reported as a diagnostic summary, not treated as a gate in this phase.

## Error Handling

Diagnostic collection must be best-effort. If a CSV writer fails, the transfer should continue and verbose output should include the trace error.

The recorder should flush promptly enough that failed runs retain recent rows. Terminal errors such as `message too long`, `broken pipe`, `context canceled`, and `peer disconnected` should appear in the final trace state when available.

## Testing

Unit tests should cover:

- CSV header stability and row compatibility with older fields
- empty role-specific fields
- per-interval goodput math
- controller snapshot updates without sleeping
- peer receive queue depth snapshotting
- terminal error row behavior

Package tests should cover:

- rate target changes appearing in snapshots
- lane count and lane cap changes appearing in snapshots
- replay bytes and retransmits appearing in snapshots
- repair request and repair byte counters appearing in snapshots
- receiver committed progress producing receiver committed Mbps
- trace checker reporting throughput diagnostics without failing solely because throughput is low

Live validation should run:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh <sender-host> <receiver-host> 1024
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh <receiver-host> <sender-host> 1024
```

When iperf3 is available for the pair, also run the comparison mode and preserve the iperf3, probe, and full-transfer logs in the local run directory.

## Success Criteria

This phase succeeds when:

- sender and receiver traces include the new diagnostic fields
- a full transfer trace can show controller target, actual goodput, committed receiver goodput, lane counts, replay pressure, retransmits, and queue depth over time
- the harness can compare iperf3, direct UDP probe, and full derphole transfer for one host pair
- low throughput produces a clear diagnostic summary rather than only a progress-bar symptom
- `mise run check` passes
- at least one live direct transfer completes with the expanded traces captured

## Rollout

1. Extend the transfer metrics snapshot model.
2. Wire direct UDP sender and receiver data-phase state into the snapshot.
3. Extend CSV schema and checker diagnostics.
4. Add the benchmark comparison harness path.
5. Run local tests.
6. Run one live direct transfer with expanded traces.
7. Use the trace to decide the next behavior-changing design.
