# Reliable Bulk Capacity Probe Design

Date: 2026-07-22

Status: approved for implementation

## Summary

The bulk decision barrier fixed the split-brain failure where the payload sender
opened QUIC while the payload receiver waited for bulk packets. Live acceptance
then exposed a second problem: the capacity probe still treats a missing UDP
train acknowledgement as proof that bulk is unusable. That discards valid lower
rate evidence and makes otherwise healthy transfers use the much slower QUIC
block engine.

The probe must separate lossy measurement traffic from reliable protocol
coordination. UDP will carry only authenticated capacity samples. The existing
authenticated DERP control path will carry each train boundary, each measured
result, and the final probe outcome. A dirty higher-rate train stops escalation
without erasing earlier clean trains. The decision barrier and clean socket
handoff remain unchanged.

This is a greenfield wire change. Mixed old and new clients are not supported.

## Evidence and Root Cause

The candidate selected `bulk-packets-v1` at the capability-policy layer in every
acceptance run. Four natural runs later selected QUIC because the sender did not
receive a UDP acknowledgement within 250 milliseconds. The timeouts occurred at
the 1.0, 2.0, and 2.2 Gbps probe tiers with no local socket-pressure signal.

The 1.0 Gbps timeout followed exact delivery of all 2,800 datagrams in the 128
and 512 Mbps trains. The existing selector therefore had enough evidence to
start bulk at 460 Mbps, but the acknowledgement timeout bypassed the selector
and rejected the entire bulk mode. Separate successful runs started bulk at 460
and 900 Mbps and sustained about 790 to 801 Mbps.

The release and candidate use the same ladder, clean threshold, seed percentage,
and acknowledgement timeout. The decision barrier did not create the heuristic.
It made both peers safely agree on the result of an unreliable heuristic instead
of choosing different payload engines.

## Goals

- Preserve the decision barrier and bounded clean socket handoff.
- Make capacity loss, rather than control-message loss, determine probe quality.
- Preserve every completed lower-rate clean train when a higher tier is dirty.
- Stop escalation at the first dirty or pressured train.
- Start bulk at 90 percent of the highest clean rate reported by both peers.
- Use QUIC only when there is no clean minimum-rate result or a peer explicitly
  reports probe rejection.
- Treat DERP control failure, malformed control, cancellation, and socket cleanup
  failure as fatal session errors rather than capacity rejection.
- Keep probe data authenticated and keep file payload counters at zero until the
  final decision is acknowledged.
- Record enough diagnostics to distinguish clean selection, dirty-tier stop,
  control failure, and socket handoff behavior.

## Non-Goals

- Mid-payload switching between bulk and QUIC.
- Compatibility with the current UDP-ack probe protocol.
- Changes to the bulk payload format, lane count, grouping, encryption, repair
  controller, or steady-state pacing controller.
- A user-facing transport-selection flag.
- Replacing the public-path capability policy for small files, direct TCP, or
  peers without native packet batching.

## Approaches Considered

### Recommended: reliable per-train coordination over DERP

Send authenticated probe datagrams over UDP, then publish the train boundary
over the authenticated DERP control channel. The receiver settles, computes the
train result, and returns that result over the same control channel. The sender
does not send the next train until it receives the matching result.

This keeps UDP loss as the measured signal while making train completion and
result delivery reliable. It also supplies a natural pacing gap between trains
and gives both peers an identical ordered result list.

### Rejected: treat UDP acknowledgement timeout as a dirty train

The sender could run the selector over earlier acknowledged trains after a UDP
timeout. That preserves local evidence, but the receiver may still be waiting
for another train or may have computed a different result. Selecting bulk before
the receiver publishes matching readiness weakens the decision barrier and can
recreate disagreement in a subtler form.

### Rejected: increase timeout or repeat UDP acknowledgements

Longer waits and more copies reduce the probability of failure but do not change
the semantics. A missing measurement acknowledgement would still be treated as
negative capacity evidence, and there would always be a final UDP control packet
whose loss could force a needless fallback.

## Control Protocol

Extend the existing authenticated `externalV2BulkControl` envelope with two new
phases:

- `probe-end`: sender to receiver, after one UDP train has been transmitted.
- `probe-result`: receiver to sender, after the settle window and measurement.

The envelope adds one optional nested probe value so presence can be validated
without confusing an omitted field with train zero:

```go
Probe *externalV2BulkProbeControl `json:"probe,omitempty"`

type externalV2BulkProbeControl struct {
	Train     int    `json:"train"`
	RateMbps  int    `json:"rate_mbps"`
	Sent      uint32 `json:"sent"`
	Received  uint32 `json:"received"`
	Pressure  bool   `json:"pressure"`
	Final     bool   `json:"final"`
}
```

`probe-end` carries the non-zero probe run ID, zero-based train index, exact
configured rate, sender datagram count, and sender pressure. `probe-result`
repeats those values and adds the receiver's unique authenticated datagram count.
The receiver sets `Final` when the train is dirty, pressured, or the final
configured tier. `probe-end` sets `Final` only for sender pressure or the final
configured tier. Probe phases use mode `bulk-packets-v1`, zero selected rate,
and an empty reason. Readiness, decision, and acknowledgement phases must have a
nil `Probe`; probe phases must have a non-nil `Probe`.

Probe messages use the existing peer-control authentication, DERP peer-key
filter, lossless subscription, and absolute decision-barrier context. The sender
and receiver subscribe before any probe data is sent. Failure to send or receive
a required control message before the barrier deadline is a control-plane error,
not ordinary capacity rejection.

The sender retries the current `probe-end` every 250 milliseconds until it
receives the matching result. The receiver retries the current `probe-result`
at the same cadence until it sees the next train boundary. After the final
result, it keeps an idempotent responder alive through the decision barrier so a
repeated final boundary receives the same result. Retries never change fields.

Unknown phases, unexpected train ordering, mismatched run IDs, mismatched rates,
received counts greater than sent counts, impossible final flags, and probe
fields on non-probe phases are protocol errors. Duplicate identical messages are
idempotent; contradictory duplicates are protocol errors.

Delete the existing UDP probe-end and probe-ack frame writers, readers, packet
kinds, and acknowledgement channel. Mixed-client compatibility is explicitly
out of scope, so there is no dormant legacy probe path.

## Probe State Machines

### Sender

For each configured rate in ascending order:

1. Send one 50 millisecond authenticated UDP data train, bounded by 16 MiB.
2. Send `probe-end` over DERP with the actual sent count and pressure flag.
3. Wait for the matching `probe-result` under the absolute barrier deadline.
4. Append the returned result to the ordered probe result list.
5. Stop if the result is dirty, pressured, or final; otherwise send the next
   configured train.

After the final result, run the existing selector over the completed trains. A
clean train requires non-zero sent count, at least 95 percent received, and no
pressure. Select 90 percent of the highest clean rate, clamped to 128 through
2,400 Mbps. If there is no clean train, produce ordinary probe rejection.

### Receiver

The receiver starts UDP readers and the DERP control subscriber before the first
train. It records authenticated UDP data by run ID, train, rate, and sequence.
For each ordered `probe-end` message:

1. Validate the run ID, train index, rate, sent count, and pressure flag.
2. Wait the existing 10 millisecond settle window while continuing to collect
   matching UDP data.
3. Compute the unique received count and clean/dirty state.
4. Send the matching `probe-result` over DERP.
5. Stop on dirty, pressure, or the last configured rate; otherwise wait for the
   next train.

After stopping, run the same selector, stop probe readers, drain the raw socket
queues to a bounded quiet state, and publish the existing `ready` message. The
receiver's selected rate must equal the rate implied by its published train
results.

### Final decision

The payload sender remains the sole decision owner. It chooses bulk only when
its completed probe result is clean and the receiver publishes matching bulk
readiness. The initial rate is the lower of the sender and receiver selected
rates. It chooses QUIC when either peer has no clean train. The immutable
`decision` and exact `ack` exchange remains the payload barrier.

## Dirty, Pressure, and Failure Semantics

- `received * 100 < sent * 95` is a dirty train. Stop escalation and retain all
  earlier clean trains.
- Sender or receiver pressure stops escalation. Earlier clean trains remain
  eligible; pressure on the first train without clean evidence rejects bulk.
- A missing UDP data packet lowers the measured result. It is not a protocol
  error.
- Missing or malformed DERP probe control is fatal because measurement agreement
  cannot be established safely.
- Probe encoding, authentication, write, cancellation, peer disconnect, and
  socket cleanup errors remain fatal.
- Ordinary QUIC fallback is reserved for a completed, agreed probe with no clean
  train, not uncertainty about whether a control packet arrived.

## Diagnostics

Verbose output adds stable per-train markers:

```text
v2-bulk-probe-result=train:<n> rate_mbps:<rate> sent:<n> received:<n> pressure:<bool> final:<bool>
v2-bulk-probe-selected=selected_mbps:<rate> highest_clean_mbps:<rate> trains:<n>
```

Existing decision, rejection-stage, handoff-drain, selected-rate, train-count,
sent, received, loss, and pressure trace fields remain. Add the final stop reason
(`dirty`, `pressure`, or `ladder-complete`) so live evidence does not infer probe
control behavior from aggregate counters. Do not log addresses, tokens, or
machine-specific paths.

Add a receiver-only live-test seam:

```text
DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS=<configured-rate>
```

When set to one exact configured rate, the receiver excludes every tenth valid
datagram at that rate from probe accounting while still reading it from the
socket. This deterministically reports 90 percent delivery and stops escalation.
The value is injected only into the intended receiver by the benchmark driver,
is unset for ordinary runs, emits one explicit test marker, and is fatal when
empty, unknown, or set on the payload sender.

## Test Strategy

Pure policy tests prove:

- a dirty higher tier preserves and selects the highest earlier clean tier;
- a dirty first tier rejects bulk;
- pressure after a clean tier preserves that tier;
- selected rate remains 90 percent of the highest clean tier and stays clamped;
- final flags and train ordering are validated exactly.

Coordinator tests prove:

- `probe-end` and `probe-result` round-trip with exact fields;
- duplicate identical messages are idempotent;
- contradictory duplicates, wrong run IDs, wrong rates, impossible counts, and
  probe fields on other phases fail as protocol errors;
- control timeout and peer disconnect abort instead of negotiating fallback.

End-to-end tests prove:

- exact delivery at 128 and 512 Mbps followed by a dirty 1,000 Mbps train selects
  bulk at 460 Mbps on both peers;
- loss of UDP data changes the measured count but does not lose train completion;
- no-clean rejection still negotiates QUIC and completes with exact payload hash;
- successful bulk starts only after matching readiness, decision, and ack;
- fallback starts QUIC only after both raw socket queues are drained;
- no file payload counter advances before the decision acknowledgement;
- cancellation and control failure leave no goroutine or socket leak.

Focused package tests run normally and under the race detector. The normal coding
loop ends with `mise run check:fast`; the final candidate runs `mise run check`
once after the final commit stack is stable.

## Live Acceptance

Freeze one exact candidate and compare it with npm release `v0.17.0` using the
public-path performance harness against the configured remote host. Disable
Tailscale candidates and use the same payload, direction, binaries, stream count,
and paired path-capacity control.

Run one receiver-injected dirty-1,000-Mbps transfer and three ordinary 1 GiB
candidate transfers. Every candidate run must:

- negotiate eight-lane public raw-direct and initially select bulk policy;
- emit reliable per-train results and an exact decision/ack tuple;
- retain bulk after a dirty higher tier when an earlier clean tier exists;
- complete with `bulk-packets-v1`, exact size and SHA-256 parity, and valid traces;
- show no disconnect, flatline, process, socket, output, or cleanup leak.

Compare three adjacent interleaved release/candidate 1 GiB pairs. The candidate
must select bulk in all three ordinary runs. Its median canonical goodput must be
at least 95 percent of the release median. Each pair is valid only when its
paired path-capacity controls differ by at most 15 percent; an invalid pair makes
the gate inconclusive and stops the batch rather than starting an unbounded
retry loop. Candidate median repair-byte ratio and receiver CPU per GiB must each
be at most 110 percent of the release median.

Preflight remote storage against payload plus working overhead, use a home or
data filesystem rather than assuming `/tmp`, and remove every task-owned remote
output, staging path, local payload, and temporary build tree after evidence is
captured.

## Success Criteria

The change is complete when a higher-rate probe loss cannot erase earlier clean
capacity evidence, all probe boundaries and results use authenticated DERP
control, both peers retain the decision barrier and clean handoff contract,
focused/race/repository tests pass, three ordinary live candidate runs stay on
bulk with byte parity, and controlled performance is not worse than the current
release by more than the accepted five-percent gate.
