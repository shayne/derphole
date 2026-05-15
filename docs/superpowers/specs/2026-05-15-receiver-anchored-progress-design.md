# Receiver-Anchored Progress And Direct Status Design

## Context

Recent relay-prefix transfers exposed two misleading signals:

- Sender and receiver progress bars can diverge because the sender counts bytes accepted into the local send pipeline, while the receiver counts payload bytes written from the transport.
- The CLI can print `connected-direct` after direct UDP handoff activation even when direct UDP never proves packet delivery and the transfer finishes over relay.

The project already has transfer trace CSVs, relay/direct byte accounting, and stall checking. This design tightens the semantics so user-facing progress and throughput reflect delivered payload, while preserving local sender pipeline metrics for debugging.

## Goals

- Make sender and receiver user-facing progress align around receiver-confirmed payload bytes.
- Make throughput rates comparable by using a shared receiver-anchored transfer clock.
- Prevent `connected-direct` from appearing until direct UDP is validated by successful probes or payload delivery.
- Preserve local sender enqueue/spool metrics in verbose logs and trace CSVs for diagnosing buffering and stalls.
- Extend tests and live harness checks so misleading direct status and divergent progress regressions fail early.

## Non-Goals

- Do not remove existing local sender byte accounting.
- Do not make progress depend on synchronized host clocks.
- Do not require direct UDP for successful transfer completion. Relay fallback remains a valid path.
- Do not change the final payload verification model: size and SHA remain the correctness proof.

## Progress Semantics

Normal CLI progress should mean payload delivered, not payload accepted into a local buffer.

Receiver progress remains payload bytes consumed and written by the receiver. Sender progress should use receiver-confirmed payload bytes when available. Local sender enqueue progress remains available as diagnostic telemetry.

Telemetry should expose separate byte counters:

- `app_bytes`: user-facing delivered payload progress.
- `peer_received_bytes`: latest receiver-confirmed payload bytes known by the sender.
- `local_sent_bytes`: sender-side local enqueue, spool, or transport pipeline progress.
- `relay_bytes`: bytes carried by relay transport.
- `direct_bytes`: bytes carried by direct transport.

For the sender, `app_bytes` should follow `peer_received_bytes` once receiver progress ACKs are active. Before the first receiver progress ACK, sender `app_bytes` remains zero and the trace stays in setup or relay/direct preparation phases; it must not imply payload delivery.

## Transfer Clocks

Telemetry should separate setup time from data transfer time:

- `session_elapsed_ms`: command/session start to now.
- `setup_elapsed_ms`: command/session start to receiver first payload byte.
- `transfer_elapsed_ms`: receiver first payload byte to now.

User-facing throughput should use `transfer_elapsed_ms`. Setup delays still matter, but they should be reported separately so throughput is not diluted by claim wait, receiver startup, candidate gathering, failed direct probing, or handoff preparation.

The receiver should be the source of the shared transfer clock. Progress ACKs should include `transfer_elapsed_ms` so sender and receiver rates use the same basis without assuming synchronized wall clocks.

## Status And Path Semantics

Status should distinguish direct attempts from validated direct delivery:

- `connected-relay`: relay path is carrying payload or is the active fallback.
- `trying-direct`: direct UDP handoff or probing has started, but payload delivery is not proven.
- `connected-direct`: direct UDP has received successful rate-probe packets or delivered direct payload bytes.
- `direct-fallback-relay`: direct attempt failed or produced zero payload, and relay remains active.
- `stream-complete`: final receiver-confirmed byte count matches expected bytes.

The key rule is that `connected-direct` must not be emitted just because a direct handoff path was activated, remote addresses were selected, or advertised fallback addresses were used. A trace with empty observed addresses and zero delivered rate-probe packets should report `trying-direct`, then `direct-fallback-relay`, while continuing on relay.

Trace CSV should add explicit status evidence:

- `direct_validated`: true only after positive direct probe delivery or direct payload delivery.
- `fallback_reason`: non-empty when direct was abandoned or skipped after an attempt.

## Protocol And Data Flow

Receiver becomes the source of truth for user-facing transfer progress.

The expected flow:

1. Sender starts the session and may read/enqueue bytes locally.
2. Receiver starts consuming payload bytes.
3. On first receiver payload byte, receiver starts the transfer data clock.
4. Receiver sends periodic progress ACKs, approximately every 500 ms, carrying:
   - payload bytes received
   - transfer elapsed milliseconds
   - current path state when known
5. Sender stores the latest progress ACK.
6. Sender renders its main progress and throughput from receiver-confirmed bytes and receiver transfer elapsed time.
7. Sender trace records both local enqueue progress and peer-confirmed progress.

Add a dedicated authenticated progress ACK envelope. It can reuse existing peer-control authentication helpers, but it must be distinct from liveness heartbeats and final ACKs so progress, liveness, and completion semantics do not overlap.

Completion should continue to verify final receiver-confirmed bytes against the expected payload or session stream bytes where the protocol supports that check.

## Trace And Harness Changes

Transfer traces should add these columns:

- `local_sent_bytes`
- `peer_received_bytes`
- `setup_elapsed_ms`
- `transfer_elapsed_ms`
- `direct_validated`
- `fallback_reason`

`transfertracecheck` should gain checks for:

- sender `peer_received_bytes` matching receiver `app_bytes` within 1 MiB or two trace intervals after progress ACKs start
- sender and receiver user-facing transfer rates staying within 10 percent after at least five active transfer samples
- no `connected-direct` state unless `direct_validated=true`
- expected fallback state and reason when direct probes receive zero packets

The live harness should keep SHA and size verification as the final correctness gate. It should treat relay-only or direct-fallback transfers as valid when explicitly expected, but should not let those runs masquerade as successful direct transfers.

## Testing

Unit coverage:

- Progress reporter can render from an externally supplied progress source.
- Sender progress can use receiver ACK progress instead of local read progress.
- Status emission does not print `connected-direct` until direct validation.
- Direct fallback emits a fallback reason when rate probes receive zero packets.

Session coverage:

- Relay-prefix transfer where sender drains local input ahead of receiver; sender user-facing progress follows receiver ACKs, while trace still records local sent bytes.
- Failed direct UDP rate probes; statuses are `trying-direct` then `direct-fallback-relay`, never `connected-direct`.
- Successful direct probe or direct payload transfer; `connected-direct` appears only after validation.

Live coverage:

- Run 1 GiB end-to-end transfers against `canlxc` and `hetz`.
- Use the relay endpoint when DERP resolution works there.
- Check trace alignment, status validation, payload size, SHA, and post-run cleanup.

## Rollout

Implement this in small slices:

1. Add trace fields and internal progress model without changing normal CLI output.
2. Add receiver progress ACKs and sender-side peer progress tracking.
3. Switch sender normal progress and transfer-rate display to receiver-confirmed progress.
4. Tighten direct status emission and fallback reasons.
5. Extend trace checker and live harness gates.

This sequencing preserves diagnostics during the transition and makes each behavior change testable on its own.
