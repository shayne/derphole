# Transfer Telemetry And Smooth Direct Handoff Design

Date: 2026-05-10

## Summary

Add first-class transfer telemetry before changing handoff behavior, then use that telemetry to prove and fix the relay-to-direct stall.

The current live harness can write a CSV, but it samples from outside the process over SSH. In the latest bidirectional `canlxc` and `hetz` runs, the requested `500 ms` interval produced about `1.2s` rows because each sample shells into both hosts. That is useful for coarse failures, but it is not good enough to explain sub-second transport state, rate probing, replay pressure, or a smooth handoff target.

The better design is two-phase:

1. Add in-process sender and receiver CSV telemetry. Use it to verify the existing stall precisely.
2. Change relay-prefix handoff so relay continues carrying data until direct data is executing and receiver progress is advancing. Use the same telemetry to verify the stall is gone.

## Observed Behavior

Recent live traces show successful transfers with a real pause during promotion:

- relay starts and transfers a small prefix
- direct connects around the `2s` mark
- rate probing runs for about `3.4s`
- direct payload execution starts only after probing completes
- application bytes are flat during that transition window

The transfer now completes correctly, but the handoff is not smooth. The protocol treats direct readiness and rate probing as a transition point where relay can stop contributing before direct payload is actually flowing. That creates the visible stall.

## Goals

- Emit true in-process transfer telemetry at `500 ms` cadence.
- Make telemetry available for both CLI sender and receiver without relying on SSH polling.
- Capture enough per-row state to explain relay, direct preparation, probing, execution, progress, stalls, rate changes, and errors.
- Use telemetry to prove the current relay-to-direct flatline before changing behavior.
- Keep relay active during direct preparation and probing.
- Retire relay only after direct execution proves receiver progress.
- Preserve payload correctness through offset-based overlap and deduplication.
- Validate the fix with bidirectional 1 GiB live tests against `canlxc` and `hetz`.

## Non-Goals

- Do not replace the direct UDP transport.
- Do not make relay the preferred steady-state path.
- Do not add a UI or dashboard in this phase.
- Do not depend on external SSH sampling for the proof signal.
- Do not redesign the full runtime guardrail controller from the direct UDP guardrails spec.
- Do not tune every host profile before the telemetry and handoff behavior are correct.

## Phase 1: In-Process Transfer Telemetry

Add an optional telemetry recorder that can be enabled independently on sender and receiver.

Recommended activation:

```bash
DERPHOLE_TRANSFER_TRACE_CSV=/path/to/transfer.csv derphole send ...
DERPHOLE_TRANSFER_TRACE_CSV=/path/to/transfer.csv derphole receive ...
```

The recorder writes CSV rows from inside the process on a monotonic `500 ms` ticker. It should flush rows promptly so a failed run still leaves useful evidence.

### Row Schema

Each row should include:

- `timestamp_unix_ms`
- `elapsed_ms`
- `role`: `send` or `receive`
- `phase`: `claim`, `relay`, `direct_prepare`, `direct_probe`, `direct_execute`, `overlap`, `complete`, or `error`
- `relay_bytes`
- `direct_bytes`
- `app_bytes`
- `delta_app_bytes`
- `app_mbps`
- `direct_rate_selected_mbps`
- `direct_rate_active_mbps`
- `direct_lanes_active`
- `direct_lanes_available`
- `direct_probe_state`
- `direct_probe_summary`
- `replay_window_bytes`
- `repair_queue_bytes`
- `retransmit_count`
- `out_of_order_bytes`
- `last_state`
- `last_error`

Fields that are not meaningful for a role or phase should be empty, not invented.

### Data Sources

Use existing state where possible:

- session layer phases and handoff events
- relay-prefix byte counts
- direct UDP selected and active rate
- direct UDP lane counts
- probe `TransferStats` for replay, repair, retransmit, and committed progress counters
- receiver committed output watermark for `app_bytes`
- sender progress for bytes read or scheduled, plus direct/relay carrier bytes

The receiver's `app_bytes` must mean committed contiguous output bytes. Packet receipt alone is not enough because the failure mode is "packets or setup activity may exist while committed output is flat."

### Required Phase 1 Proof

Before changing handoff behavior, run live transfers with telemetry enabled. The expected pre-fix evidence is:

- relay bytes advance initially
- phase moves to `direct_probe`
- receiver `app_bytes` is flat for more than one sample
- direct bytes begin advancing only after `direct_execute`

This proof should be kept as a benchmark artifact in the local run log, not committed.

## Phase 2: Smooth Relay-To-Direct Handoff

Change relay-prefix handoff so relay remains a live payload carrier until direct has proven useful data flow.

### Target Behavior

1. Relay begins sending payload immediately after claim acceptance.
2. Direct setup, address selection, and rate probing run in parallel with relay.
3. Sender starts direct execution from a safe overlap boundary once direct is ready.
4. Receiver deduplicates overlap using existing offsets and committed watermark logic.
5. Relay keeps sending while direct ramps up.
6. Relay retires only after direct has advanced committed receiver bytes beyond the handoff boundary, or after another explicit progress proof that direct is carrying payload successfully.
7. If direct fails to advance progress within the configured window, relay keeps the transfer moving.

### Handoff Boundary

Use the receiver's committed watermark and the existing relay-prefix spool to choose a safe overlap point. The direct carrier may resend a bounded range already covered by relay. The receiver must deduplicate these chunks and write each byte once.

The duplicate overlap cost is acceptable. A few duplicate packets are cheaper than a visible application-level stall.

### Relay Retirement

Relay retirement should be based on progress, not just direct readiness.

Relay can stop when all of the following are true:

- direct execution has started
- receiver committed bytes have advanced after direct execution started
- the committed watermark is past the selected handoff boundary
- no relay-only chunk remains required to preserve output order

If those conditions do not happen within the progress window, keep relay active and log the reason.

### Failure Behavior

Direct failure during setup, probing, or execution must not strand the transfer. The sender should continue relay, emit telemetry showing the direct failure, and either retry a safe direct profile later or finish on relay according to the existing fallback policy.

Errors such as `message too long`, late `context canceled`, and `peer disconnected` must appear in telemetry rows before process exit.

## CSV Stall Checker

Add a checker that can validate one sender CSV and one receiver CSV.

It should fail when:

- receiver `app_bytes` does not advance for more than the configured stall window while the transfer is active
- phases regress unexpectedly
- sender and receiver final byte counts disagree
- terminal phase is not `complete`
- `last_error` contains known failure strings such as `message too long`, `context canceled`, or `peer disconnected`

Default windows:

- telemetry interval: `500 ms`
- warning flatline threshold: `500 ms`
- failure flatline threshold: `1000 ms`

The checker should be used by the live harness and can also be run manually on captured CSVs.

## Harness Updates

Keep the existing stall harness, but change its role.

The harness should:

- enable in-process telemetry on both hosts
- copy telemetry CSVs back into the run log
- run the CSV stall checker
- still verify payload size and SHA-256
- still collect before and after kernel counters for packet-level context

The harness-side `samples.csv` can remain as an outer process watchdog, but it is no longer the primary performance proof.

## Testing

### Unit Tests

Add focused tests for:

- CSV escaping and header stability
- recorder cadence snapshot logic without sleeping in tests
- empty optional fields
- phase transitions
- per-interval Mbps math
- terminal error rows
- stall checker pass and fail cases

### Package Tests

Add tests around transfer state aggregation:

- relay bytes and direct bytes accumulate independently
- receiver committed watermark drives `app_bytes`
- direct probe phase can be represented without payload progress
- overlap bytes do not double count application progress
- relay retirement waits for direct committed progress
- relay remains active when direct probe or execute fails

### Live Tests

Required live validation:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh canlxc hetz 1024
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh hetz canlxc 1024
```

For Phase 1, these runs should demonstrate the existing stall in telemetry.

For Phase 2, these runs must complete with:

- matching source and sink sizes
- matching SHA-256
- sender and receiver exit status `0`
- telemetry checker passing
- no application-byte flatline longer than the configured failure threshold during promotion
- no `message too long`, `context canceled`, or `peer disconnected` terminal errors

## Success Criteria

Phase 1 succeeds when:

- sender and receiver write in-process CSV rows at about `500 ms`
- the telemetry captures relay, direct probe, direct execute, and completion phases
- a current live run shows the existing application-byte flatline during direct probing

Phase 2 succeeds when:

- relay continues during direct preparation and probing
- receiver application bytes continue advancing during promotion
- direct still takes over for the bulk of a healthy transfer
- bidirectional `canlxc` and `hetz` 1 GiB runs pass payload verification
- the CSV stall checker passes on both directions
- `mise run check` and `mise run quality:goal` pass

## Rollout

1. Implement telemetry recorder and CSV checker.
2. Wire sender and receiver state snapshots into telemetry.
3. Run live Phase 1 validation and save the failing/stalling traces locally.
4. Implement progress-based relay retirement and overlap handoff.
5. Rerun the same live validation.
6. Commit only after local gates and live validation pass.

## Open Tuning Values

These values may be tuned from benchmark evidence without changing the design:

- overlap byte window
- relay retirement grace period
- direct progress proof threshold
- warning and failure stall thresholds
- whether relay retirement requires one or two positive telemetry samples
