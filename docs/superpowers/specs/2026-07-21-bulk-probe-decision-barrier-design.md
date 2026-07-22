# Bulk Probe Decision Barrier Design

## Summary

The bulk capacity probe currently measures a path and accidentally decides a
protocol at the same time. That works while every UDP acknowledgement arrives.
When the receiver accepts the probe but the sender misses the final
acknowledgement, the receiver starts waiting for bulk packets while the sender
falls back to QUIC. Both choices are locally reasonable. Together they produce
a transfer where each side waits for a different protocol.

The fix is to separate measurement from agreement. The payload sender remains
the authority for the final mode, but it may choose bulk only after the payload
receiver reports that its probe side is ready. The sender publishes one
immutable decision over the authenticated DERP control path. The receiver
acknowledges that exact decision. Neither side starts payload until the decision
barrier completes.

This is a greenfield wire change. Mixed old and new clients are not supported,
and the design does not add capability gates or a legacy decision path.

## Failure Being Fixed

The existing sender waits 250 milliseconds for each authenticated UDP probe
acknowledgement. A missing acknowledgement returns
`errExternalV2BulkPacketProbeRejected`, which the outer runtime interprets as a
local instruction to open QUIC. The receiver independently selects the probe
result, sends the final UDP acknowledgement, and enters the bulk receive loop.
There is no message that says both peers committed to the same payload engine.

The observed failure has exactly that shape:

- both peers validate the same eight raw-direct lanes;
- both peers announce `bulk-packets` and `grouped-v1`;
- the sender announces `fallback-before-payload` and opens QUIC;
- the receiver does not announce fallback and waits for bulk payload;
- no file payload is committed.

Longer timeouts and more repeated UDP acknowledgements make this less likely.
They do not make it impossible. Agreement cannot be inferred from silence on a
lossy channel. The protocol needs an agreement step.

## Goals

- Ensure both peers select the same payload engine before the first file byte.
- Preserve pre-payload QUIC fallback when either side rejects the bulk probe.
- Preserve successful bulk probe results and the selected initial pacing rate.
- Keep the final mode decision authenticated and bound to the current probe.
- Bound every decision wait and exit both processes on control-plane failure.
- Make the local outcome, peer readiness, final decision, and acknowledgement
  visible in verbose output and transfer traces.
- Keep duplicate and retried control messages idempotent.

## Non-Goals

- Mid-payload fallback between bulk and QUIC.
- Compatibility with clients that do not implement the decision barrier.
- Changes to bulk pacing, repair policy, grouping, encryption, or lane count.
- Changes to direct TCP, relay-only transfers, or non-file sessions.
- A user-facing transport-selection flag.

## Approaches Considered

### Recommended: sender decision with receiver readiness and acknowledgement

The payload receiver reports whether its half of the probe is ready. The
payload sender combines that with its own result, publishes one final decision,
and waits for the receiver to acknowledge it. The decision is immutable once
sent.

This gives each state one owner. The receiver owns receiver readiness. The
sender owns the final mode. The acknowledgement proves that the receiver saw
the decision. If the acknowledgement is lost, the sender retransmits the same
decision; it never invents a new one because a timer fired.

### Rejected: symmetric local votes

Both peers could publish independent votes and select bulk only when both vote
for it. This can be correct, but it duplicates selection policy and creates
more combinations to reconcile. The receiver does not need to choose the
initial pace or interpret sender-side pressure. It needs a veto, not a second
copy of the decision engine.

### Rejected: more UDP retries or a longer timeout

More retries help probability, not correctness. There is always a final packet
whose loss leaves one peer unsure whether the other peer moved on. Turning 250
milliseconds into two seconds just makes the same bug take longer to admit what
it is.

### Rejected: abort whenever the probe is uncertain

Aborting avoids split-brain, but throws away the existing QUIC fallback even
when the relay and raw packet path are healthy. The control path already exists
and already carries authenticated, retried session messages. Use it.

## Control Protocol

Add one authenticated envelope payload for bulk coordination:

```go
type externalV2BulkControl struct {
	Protocol     string `json:"protocol"`
	Phase        string `json:"phase"`
	ProbeRunID   uint64 `json:"probe_run_id"`
	Mode         string `json:"mode"`
	SelectedMbps int    `json:"selected_mbps,omitempty"`
	Reason       string `json:"reason,omitempty"`
}
```

The phases are `ready`, `decision`, and `ack`. The modes are
`bulk-packets-v1` and `quic`. Reasons are stable protocol values, not raw error
strings. Raw local errors remain local telemetry.

Every control envelope uses the existing peer-control authentication, DERP
peer-key filter, lossless subscription, and 250 millisecond retry interval. A
single absolute barrier deadline, created before probing, bounds probe cleanup,
readiness, decision delivery, and acknowledgement. This prevents one peer's
per-phase timer from expiring while the other peer is still legitimately in an
earlier phase. The deadline must cover the probe's existing worst-case bound
plus the existing five-second control exchange bound.

The payload sender creates the probe run ID before probing and includes that
non-zero ID in every decision. The receiver includes the observed ID in bulk
readiness and in QUIC readiness when it authenticated any probe train. It may
use zero only for QUIC readiness when it rejected the probe before learning the
ID. An acknowledgement repeats the decision's ID and mode exactly. Bulk
readiness and a bulk decision must have matching non-zero IDs and an initial
rate inside the bulk controller's supported range. A non-zero readiness ID that
differs from the decision ID is always a protocol error, including for QUIC.

Unknown phases, invalid modes, impossible rates, zero decision IDs, and invalid
run-ID combinations are protocol errors. Unauthenticated packets are ignored
by the existing envelope authentication path.

## State Machines

### Payload receiver

The receiver subscribes to bulk control before starting the UDP probe. It then
runs these states:

1. `probing`: collect and authenticate probe trains.
2. `ready`: publish `bulk-packets-v1` after local probe success, or `quic`
   after local probe rejection or cleanup failure.
3. `awaiting-decision`: keep readiness messages reinforced while waiting for
   the sender's immutable decision.
4. `acknowledging`: validate and acknowledge the exact decision.
5. `executing`: start the selected bulk or QUIC payload engine.

The control subscriber runs while the receiver is probing. A QUIC decision can
therefore cancel a receiver probe that is waiting for a train the sender will
never send. A bulk decision is valid only after this receiver has published
bulk readiness with the same run ID. Receiving bulk before readiness is a
protocol error, not an invitation to guess.

The receiver starts the selected payload engine after sending the first valid
acknowledgement. It keeps an idempotent acknowledgement responder alive until
it observes the sender start the selected payload engine or the barrier
deadline expires. A lost acknowledgement therefore cannot strand the sender
while the receiver has already stopped listening for a retry.

### Payload sender

The sender subscribes to receiver readiness and decision acknowledgements
before starting the UDP probe. It then runs these states:

1. `probing`: send probe trains and collect authenticated UDP results.
2. `deciding`: choose QUIC immediately after local probe rejection. After local
   success, wait for receiver readiness. Choose bulk only for matching bulk
   readiness; choose QUIC for receiver rejection or readiness timeout.
3. `publishing`: send one immutable decision and retry it until acknowledged.
4. `executing`: start the selected bulk or QUIC payload engine.

Once the sender publishes a decision, no timeout or later packet may change its
mode. If acknowledgement never arrives, the session aborts. It does not fall
back again. A failed agreement is an error; a second unilateral decision would
recreate the original bug with nicer structs.

## Data Flow

The successful bulk path is:

```text
sender                     receiver
  |---- UDP probe trains ---->|
  |<--- UDP train acks --------|
  |<--- DERP ready: bulk ------|
  |---- DERP decision: bulk -->|
  |<--- DERP ack: bulk --------|
  |====== bulk payload =======>|
```

The lost-final-UDP-ack path is:

```text
sender                     receiver
  |---- UDP probe trains ---->|
  |<--- final UDP ack --X      |
  |<--- DERP ready: bulk ------|
  |---- DERP decision: QUIC -->|
  |<--- DERP ack: QUIC --------|
  |======= QUIC payload ======>|
```

The receiver may believe bulk is usable. That is useful readiness information,
not authority to start bulk. The sender missed evidence it requires, so it
chooses QUIC and says so explicitly.

## Code Structure

Add a focused `externalV2BulkDecisionCoordinator` in a new session file. It
owns the DERP subscription, authenticated control parsing, retries,
reinforcement, probe cancellation signal, and role-specific state transition.
It does not read files, send bulk datagrams, or open QUIC streams.

The existing bulk send and receive functions remain responsible for probe and
payload mechanics, but they receive the coordinator and stop at the new
barrier:

- probe setup and cleanup finish first;
- the coordinator resolves the final mode;
- bulk workers start only after a bulk decision is acknowledged;
- a QUIC decision returns the existing pre-payload fallback sentinel after all
  bulk readers, deadlines, and workers are drained;
- transfer metrics select `bulk-packets-v1` or QUIC only after the barrier.

The four runtime paths in `external_v2.go`, `external_v2_offer.go`, and
`external_v2_block.go` construct the same coordinator using their existing DERP
client, peer key, token-derived control authentication, and abort context. The
coordination policy stays in one component even though either side of an offer
can be the payload sender.

The existing receiver-side probe selector may continue producing diagnostics,
but it no longer selects the payload engine. Its result becomes receiver
readiness. The sender remains the only final decision owner.

## Failure Handling

| Failure | Required result |
| --- | --- |
| Final UDP acknowledgement lost | Sender decides QUIC; receiver acknowledges; both use QUIC |
| Receiver probe rejects | Receiver reports QUIC readiness; sender decides QUIC |
| Receiver probe waits after sender rejection | Sender's QUIC decision cancels the receiver probe |
| Readiness message lost | Receiver retries and reinforces it |
| Decision message lost | Sender retries the same immutable decision |
| Decision acknowledgement lost | Receiver repeats the same acknowledgement |
| Non-zero run IDs disagree | Abort with a protocol error |
| DERP decision exchange times out | Abort both sides; do not choose locally |
| Peer disconnects during the barrier | Use the existing peer-abort/disconnect path |
| Payload fails after the barrier | End the transfer; do not switch engines |

All failure exits must drain probe readers, clear packet deadlines, stop retry
goroutines, close subscriptions, and preserve the existing no-process/no-socket
leak contract.

## Telemetry

Verbose output adds stable markers for:

```text
v2-bulk-ready=mode:<mode> run_id:<id> reason:<reason>
v2-bulk-decision=mode:<mode> run_id:<id> selected_mbps:<rate> reason:<reason>
v2-bulk-decision-ack=mode:<mode> run_id:<id>
```

Transfer traces retain probe train and loss diagnostics even when the final
engine is QUIC. Add final decision and reason fields so a fallback is visible
without reconstructing it from two terminal windows. Raw probe errors should
also appear in the local verbose log before their stable reason is sent.

No payload counter may advance before `v2-bulk-decision-ack`. File payload
engine selection occurs at the same boundary.

## Test Strategy

### Coordinator tests

Table-driven tests cover all valid state transitions, duplicate readiness,
duplicate decisions, duplicate acknowledgements, invalid phases and modes,
run-ID mismatch, timeout, cancellation, and peer disconnect. The tests assert
that a published decision never changes.

### Probe integration tests

The in-process external-v2 round trip gains deterministic packet hooks for the
control edge cases:

- drop every final UDP probe acknowledgement and prove both peers select QUIC;
- reject the receiver probe after the sender may have received an
  acknowledgement and prove the receiver veto prevents bulk;
- drop the first DERP readiness, decision, and acknowledgement messages and
  prove retries complete exactly once;
- withhold every decision acknowledgement and prove both processes exit within
  the bound without a goroutine, process, or socket leak;
- preserve the normal bulk success path and selected probe rate;
- assert exact payload digest and zero bulk-committed bytes on QUIC fallback;
- assert no file payload byte or payload-engine metric appears before the
  decision acknowledgement.

Tests run with the race detector for the coordinator, probe, and external-v2
round-trip packages.

### Live acceptance

Run three normal 3 GiB macOS-to-Ubuntu public-path file transfers against the
configured remote test host with Tailscale candidates disabled. Every run must
either complete through bulk or complete through the negotiated pre-payload
QUIC fallback. No run may leave one peer in bulk while the other opens QUIC,
report `peer disconnected`, flatline without a bounded error, fail integrity,
or leave a process/socket behind.

Before publication, run focused package tests, `mise run check:fast`, and the
final exhaustive `mise run check` gate required by the repository.

## Scope Boundaries

This change fixes agreement around `bulk-packets-v1`. It does not redesign the
probe's rate ladder, grouped record format, repair controller, QUIC transport,
or file sink. Those parts can still fail independently. They may no longer
cause peers to start different payload protocols.
