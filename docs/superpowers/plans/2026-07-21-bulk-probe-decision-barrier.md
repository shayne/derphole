# Bulk Probe Decision Barrier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent sender/receiver payload-engine split-brain by turning the UDP capacity probe into evidence and committing both peers to one sender-authoritative bulk-or-QUIC decision over authenticated DERP control.

**Architecture:** Add a focused `externalV2BulkDecisionCoordinator` with an authenticated `ready`/`decision`/`ack` protocol and a DERP adapter behind a deterministic in-memory test seam. Construct it before probing in all four file-transfer topologies, pass it through the bulk probe boundary, and keep it alive until bulk starts or negotiated QUIC fallback opens. The sender publishes one immutable decision; the receiver may veto bulk, but never starts a payload engine from its local probe result alone.

**Tech Stack:** Go 1.26.5 through `mise`, authenticated JSON envelopes, `derpbind.Client.SubscribeLossless`, contexts, timers, `net.PacketConn`, transfer-trace CSV, and GitButler.

## Global Constraints

- This is a greenfield wire change. Do not add capability negotiation, a legacy exchange, or mixed-client compatibility.
- The payload sender is the only final decision owner. The receiver publishes readiness and may veto bulk.
- Select `bulk-packets-v1` only when both probes succeeded with the same non-zero probe run ID.
- Use the lower of the sender and receiver selected rates as the initial bulk pace; both must remain inside the existing 128-2400 Mbps bounds.
- A sender probe rejection, receiver QUIC readiness, or five-second receiver-readiness timeout produces one explicit QUIC decision.
- After the sender publishes a decision, timeout aborts the session. It must never change the published mode or make another local fallback decision.
- Use a ten-second total barrier deadline created before the UDP probe, a five-second readiness wait inside that deadline, and a 250 millisecond retry interval.
- Every decision has a non-zero sender-created run ID. Receiver QUIC readiness may use zero only when it rejected before authenticating a run ID.
- The receiver acknowledges the decision's mode, run ID, selected rate, and reason exactly. Duplicate messages are idempotent.
- Keep the receiver subscriber and duplicate-ack responder alive across QUIC fallback until the outer transfer exits or the barrier deadline expires.
- Do not select a payload engine, read a source payload byte, write a sink payload byte, or advance a payload counter before acknowledgement.
- Mid-payload fallback remains unsupported. Pacing, repair, grouping, encryption, lane count, direct TCP, relay-only sessions, and non-file sessions stay unchanged.
- Stable reasons are `probe-accepted`, `sender-probe-rejected`, `receiver-probe-rejected`, `receiver-readiness-timeout`, and `both-probes-accepted`. Raw errors remain local.
- Every production change follows red-green-refactor. Run each named test and observe the expected failure before implementation.
- Use GitButler for all version-control writes. Before each checkpoint run `but pull --check` and `but diff`; stop if the diff contains unrelated work.

---

## File Structure

### Create

- `pkg/session/external_v2_bulk_decision.go` — wire constants, validation, DERP adapter, coordination, retries, deadlines, and verbose markers.
- `pkg/session/external_v2_bulk_decision_test.go` — codec, state-machine, retry, timeout, disconnect, cancellation, and idempotence coverage.

### Modify

- `pkg/session/external.go` — register the `v2_bulk_control` envelope.
- `pkg/session/external_v2_protocol.go` — add its subscription predicate.
- `pkg/session/external_v2_bulk_packet.go` — require coordination when probing and stop before payload workers.
- `pkg/session/external_v2_bulk_packet_probe.go` — retain the sender run ID on failures.
- `pkg/session/external_v2_bulk_packet_probe_test.go` — cover sender and receiver run IDs on failed probes.
- `pkg/session/external_v2_bulk_packet_test.go` — migrate payload-only calls and reproduce asymmetric final-ack loss.
- `pkg/session/external_v2_bulk_packet_batched_receiver_test.go` — pass paired coordinators to probe-enabled tests.
- `pkg/session/external_v2.go` — wire claimant-sender and listener-receiver paths.
- `pkg/session/external_v2_offer.go` — wire offerer-sender paths.
- `pkg/session/external_v2_block.go` — wire both receiver topologies and remove unilateral fallback.
- `pkg/session/external_v2_block_test.go` — verify negotiated QUIC fallback end to end.
- `pkg/session/external_transfer_metrics.go` and `pkg/session/external_transfer_metrics_test.go` — retain the final decision independently of the engine.
- `pkg/transfertrace/trace.go` and `pkg/transfertrace/trace_test.go` — append decision columns.
- `pkg/transfertrace/checker.go` and `pkg/transfertrace/checker_test.go` — reject contradictory decision/engine evidence.
- `scripts/promotion-benchmark-driver.sh` and `scripts/promotion_scripts_test.go` — classify an acknowledged QUIC decision as the actual file-transfer mode during live acceptance.

### Do Not Modify

- Do not change the bulk header, grouped format, AEAD derivation, repair controller, or rate ladder.
- Do not change npm packaging, public CLI flags, direct-TCP policy, or generated `dist/` files.

---

### Task 1: Add the authenticated bulk-control wire contract

**Files:**

- Create: `pkg/session/external_v2_bulk_decision.go`
- Create: `pkg/session/external_v2_bulk_decision_test.go`
- Modify: `pkg/session/external.go:33-47,88-104`
- Modify: `pkg/session/external_v2_protocol.go:150-170`

**Interfaces:**

- Consumes: `externalV2Protocol`, `envelope`, `marshalAuthenticatedEnvelope`, `externalV2EnvelopeFromPayload`, and `decodeExternalV2Payload`.
- Produces: `externalV2BulkControl`, `externalV2BulkDecision`, `validateExternalV2BulkControl`, `externalV2BulkControlFromPayload`, and `isV2BulkControlPayload`.

- [ ] **Step 1: Write failing authenticated codec and validation tests**

Create `pkg/session/external_v2_bulk_decision_test.go` with:

```go
package session

import (
	"errors"
	"testing"
)

func TestExternalV2BulkControlAuthenticatedRoundTrip(t *testing.T) {
	auth := externalPeerControlAuth{EnvelopeKey: [32]byte{1}}
	want := externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseDecision,
		ProbeRunID: 77, Mode: externalV2BulkModeBulk,
		SelectedMbps: 900, Reason: externalV2BulkReasonBothAccepted,
	}
	payload, err := marshalAuthenticatedEnvelope(envelope{Type: envelopeV2BulkControl, V2BulkControl: &want}, auth)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := externalV2BulkControlFromPayload(payload, auth)
	if err != nil || !ok || got != want {
		t.Fatalf("decode = (%+v, %t, %v), want %+v", got, ok, err, want)
	}
	forgedAuth := externalPeerControlAuth{EnvelopeKey: [32]byte{2}}
	forgedPayload, err := marshalAuthenticatedEnvelope(envelope{Type: envelopeV2BulkControl, V2BulkControl: &want}, forgedAuth)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := externalV2BulkControlFromPayload(forgedPayload, auth); err != nil || ok {
		t.Fatalf("forged control = (ok=%t, err=%v), want ignored", ok, err)
	}
}

func TestValidateExternalV2BulkControl(t *testing.T) {
	valid := externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseDecision,
		ProbeRunID: 77, Mode: externalV2BulkModeBulk,
		SelectedMbps: 900, Reason: externalV2BulkReasonBothAccepted,
	}
	tests := []struct {
		name string
		edit func(*externalV2BulkControl)
	}{
		{"protocol", func(m *externalV2BulkControl) { m.Protocol = "old" }},
		{"phase", func(m *externalV2BulkControl) { m.Phase = "maybe" }},
		{"mode", func(m *externalV2BulkControl) { m.Mode = "guess" }},
		{"zero-decision-run", func(m *externalV2BulkControl) { m.ProbeRunID = 0 }},
		{"bulk-rate-low", func(m *externalV2BulkControl) { m.SelectedMbps = 127 }},
		{"bulk-rate-high", func(m *externalV2BulkControl) { m.SelectedMbps = 2401 }},
		{"reason", func(m *externalV2BulkControl) { m.Reason = "raw error text" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := valid
			tt.edit(&message)
			if err := validateExternalV2BulkControl(message); !errors.Is(err, errExternalV2BulkDecisionProtocol) {
				t.Fatalf("validation error = %v, want protocol error", err)
			}
		})
	}
}
```

- [ ] **Step 2: Run the codec tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkControlAuthenticatedRoundTrip|TestValidateExternalV2BulkControl' -count=1
```

Expected: build failure because the bulk-control types and envelope field do not exist.

- [ ] **Step 3: Add the envelope and message declarations**

In `pkg/session/external.go`, add `envelopeV2BulkControl = "v2_bulk_control"` and:

```go
	V2BulkControl *externalV2BulkControl `json:"v2_bulk_control,omitempty"`
```

Start `pkg/session/external_v2_bulk_decision.go` with:

```go
package session

import (
	"errors"
	"fmt"
)

const (
	externalV2BulkPhaseReady    = "ready"
	externalV2BulkPhaseDecision = "decision"
	externalV2BulkPhaseAck      = "ack"
	externalV2BulkModeBulk      = externalV2TransferModeBulkPackets
	externalV2BulkModeQUIC      = "quic"
	externalV2BulkReasonProbeAccepted         = "probe-accepted"
	externalV2BulkReasonSenderProbeRejected   = "sender-probe-rejected"
	externalV2BulkReasonReceiverProbeRejected = "receiver-probe-rejected"
	externalV2BulkReasonReadinessTimeout      = "receiver-readiness-timeout"
	externalV2BulkReasonBothAccepted          = "both-probes-accepted"
)

var errExternalV2BulkDecisionProtocol = errors.New("bulk decision protocol error")

type externalV2BulkControl struct {
	Protocol string `json:"protocol"`
	Phase string `json:"phase"`
	ProbeRunID uint64 `json:"probe_run_id"`
	Mode string `json:"mode"`
	SelectedMbps int `json:"selected_mbps,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type externalV2BulkDecision struct {
	Mode string
	ProbeRunID uint64
	SelectedMbps int
	Reason string
}

func (d externalV2BulkDecision) control(phase string) externalV2BulkControl {
	return externalV2BulkControl{Protocol: externalV2Protocol, Phase: phase, ProbeRunID: d.ProbeRunID, Mode: d.Mode, SelectedMbps: d.SelectedMbps, Reason: d.Reason}
}
```

- [ ] **Step 4: Implement exact validation and decoding**

`validateExternalV2BulkControl` must reject an unsupported protocol, unknown phase/mode/reason, zero decision/ack run ID, zero bulk-readiness run ID, bulk rate outside 128-2400 Mbps, and any non-zero rate on QUIC. A `ready/quic` message may use run ID zero; no other message may.

Implement it with phase-aware reason validation:

```go
func validateExternalV2BulkControl(message externalV2BulkControl) error {
	if message.Protocol != externalV2Protocol {
		return fmt.Errorf("%w: protocol %q", errExternalV2BulkDecisionProtocol, message.Protocol)
	}
	if message.Phase != externalV2BulkPhaseReady && message.Phase != externalV2BulkPhaseDecision && message.Phase != externalV2BulkPhaseAck {
		return fmt.Errorf("%w: phase %q", errExternalV2BulkDecisionProtocol, message.Phase)
	}
	if message.Mode != externalV2BulkModeBulk && message.Mode != externalV2BulkModeQUIC {
		return fmt.Errorf("%w: mode %q", errExternalV2BulkDecisionProtocol, message.Mode)
	}
	if message.Phase != externalV2BulkPhaseReady && message.ProbeRunID == 0 {
		return fmt.Errorf("%w: zero run ID", errExternalV2BulkDecisionProtocol)
	}
	if message.Mode == externalV2BulkModeBulk {
		if message.ProbeRunID == 0 || message.SelectedMbps < externalV2BulkPacketMinimumWireMbps || message.SelectedMbps > externalV2BulkPacketCeilingWireMbps {
			return fmt.Errorf("%w: invalid bulk run/rate", errExternalV2BulkDecisionProtocol)
		}
	} else if message.SelectedMbps != 0 {
		return fmt.Errorf("%w: QUIC rate %d", errExternalV2BulkDecisionProtocol, message.SelectedMbps)
	}
	if message.Phase == externalV2BulkPhaseReady {
		valid := message.Mode == externalV2BulkModeBulk && message.Reason == externalV2BulkReasonProbeAccepted ||
			message.Mode == externalV2BulkModeQUIC && message.Reason == externalV2BulkReasonReceiverProbeRejected
		if !valid {
			return fmt.Errorf("%w: readiness reason %q", errExternalV2BulkDecisionProtocol, message.Reason)
		}
		return nil
	}
	valid := message.Reason == externalV2BulkReasonBothAccepted ||
		message.Reason == externalV2BulkReasonSenderProbeRejected ||
		message.Reason == externalV2BulkReasonReceiverProbeRejected ||
		message.Reason == externalV2BulkReasonReadinessTimeout
	if !valid {
		return fmt.Errorf("%w: decision reason %q", errExternalV2BulkDecisionProtocol, message.Reason)
	}
	return nil
}
```

Add:

```go
func externalV2BulkControlFromPayload(payload []byte, auth externalPeerControlAuth) (externalV2BulkControl, bool, error) {
	env, ok, err := externalV2EnvelopeFromPayload(payload, auth)
	if err != nil || !ok || env.Type != envelopeV2BulkControl || env.V2BulkControl == nil {
		return externalV2BulkControl{}, false, err
	}
	if err := validateExternalV2BulkControl(*env.V2BulkControl); err != nil {
		return externalV2BulkControl{}, false, err
	}
	return *env.V2BulkControl, true, nil
}
```

In `pkg/session/external_v2_protocol.go`, add:

```go
func isV2BulkControlPayload(payload []byte) bool {
	env, ok := decodeExternalV2Payload(payload, envelopeV2BulkControl)
	return ok && env.V2BulkControl != nil
}
```

- [ ] **Step 5: Run focused tests and checkpoint**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkControlAuthenticatedRoundTrip|TestValidateExternalV2BulkControl' -count=1
mise run check:fast
but pull --check
but diff
but commit codex/bulk-probe-decision-barrier -m "protocol: add bulk decision control messages"
```

Expected: tests pass, all products build, the diff contains only Task 1 files, and GitButler creates one checkpoint.

---

### Task 2: Implement sender-authoritative coordination and retries

**Files:**

- Modify: `pkg/session/external_v2_bulk_decision.go`
- Modify: `pkg/session/external_v2_bulk_decision_test.go`

**Interfaces:**

- Consumes: Task 1 control messages and existing DERP/authentication primitives.
- Produces:
  - `newExternalV2BulkDecisionCoordinator(ctx, client, peerDERP, auth, emitter) *externalV2BulkDecisionCoordinator`
  - `(*externalV2BulkDecisionCoordinator).ResolveSender(ctx, runID, probeResult, probeErr) (externalV2BulkDecision, error)`
  - `(*externalV2BulkDecisionCoordinator).ResolveReceiver(ctx, probe) (externalV2BulkPacketProbeResult, externalV2BulkDecision, error)`
  - `(*externalV2BulkDecisionCoordinator).Close()`

- [ ] **Step 1: Write failing paired-state-machine tests**

Extend the test import block with `context`, `sync`, and `time`, then add this in-memory wire to `pkg/session/external_v2_bulk_decision_test.go`:

```go
type externalV2BulkTestWire struct {
	send   func(context.Context, externalV2BulkControl) error
	events <-chan externalV2BulkControlEvent
	close  func()
}

func (w externalV2BulkTestWire) Send(ctx context.Context, message externalV2BulkControl) error {
	return w.send(ctx, message)
}
func (w externalV2BulkTestWire) Events() <-chan externalV2BulkControlEvent { return w.events }
func (w externalV2BulkTestWire) Close()                                  { w.close() }

func newExternalV2BulkTestWirePair(t *testing.T, drop func(bool, externalV2BulkControl) bool) (externalV2BulkControlWire, externalV2BulkControlWire) {
	t.Helper()
	left := make(chan externalV2BulkControlEvent, 32)
	right := make(chan externalV2BulkControlEvent, 32)
	makeWire := func(fromSender bool, outbound chan<- externalV2BulkControlEvent, inbound <-chan externalV2BulkControlEvent) externalV2BulkControlWire {
		return externalV2BulkTestWire{
			send: func(ctx context.Context, message externalV2BulkControl) error {
				if drop != nil && drop(fromSender, message) {
					return nil
				}
				select {
				case outbound <- externalV2BulkControlEvent{Control: message}:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
			events: inbound,
			close: func() {},
		}
	}
	return makeWire(true, right, left), makeWire(false, left, right)
}
```

Add `TestExternalV2BulkDecisionCoordinatorSelectsBulkAfterBothReady`. Run receiver and sender concurrently with run ID 77, sender rate 900, and receiver rate 800. Assert both return the same `bulk-packets-v1` decision at 800 Mbps with reason `both-probes-accepted`.

Add table cases with exact expected modes/reasons for:

```go
[]struct {
	name          string
	senderErr     error
	receiverErr   error
	wantMode      string
	wantReason    string
}{
	{"sender-rejects", errExternalV2BulkPacketProbeRejected, nil, externalV2BulkModeQUIC, externalV2BulkReasonSenderProbeRejected},
	{"receiver-rejects", nil, errExternalV2BulkPacketProbeRejected, externalV2BulkModeQUIC, externalV2BulkReasonReceiverProbeRejected},
}
```

Add these independent tests:

- drop the first `ready`, `decision`, and `ack` and prove retries finish once;
- inject exact duplicate `ready`, `decision`, and `ack` messages and prove they are idempotent;
- drop every acknowledgement, record every sender decision, prove all decisions are equal, then require `context.DeadlineExceeded`;
- send conflicting non-zero run IDs and require `errExternalV2BulkDecisionProtocol` on both peers;
- close the event channel and require `ErrPeerDisconnected`;
- block the receiver probe callback, make the sender reject locally, and prove the QUIC decision cancels and drains that callback.
- call `Close` after receiver acknowledgement, wait two retry intervals, and prove the fake wire observes no later send.

Use test-only values `retry=25*time.Millisecond`, `readyWait=75*time.Millisecond`, and a 250 millisecond total deadline so failure tests stay deterministic.

- [ ] **Step 2: Run coordinator tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkDecisionCoordinator' -count=1
```

Expected: build failure because the wire and coordinator do not exist.

- [ ] **Step 3: Add the wire seam and DERP adapter**

Add to `pkg/session/external_v2_bulk_decision.go`:

```go
const (
	externalV2BulkDecisionBarrierWait = 10 * time.Second
	externalV2BulkDecisionReadyWait   = 5 * time.Second
	externalV2BulkDecisionRetry       = 250 * time.Millisecond
)

type externalV2BulkControlEvent struct {
	Control externalV2BulkControl
	Err     error
}

type externalV2BulkControlWire interface {
	Send(context.Context, externalV2BulkControl) error
	Events() <-chan externalV2BulkControlEvent
	Close()
}
```

Implement `externalV2BulkDERPControlWire` with these exact production behaviors:

1. Subscribe with `SubscribeLossless` before returning from its constructor.
2. Filter on `pkt.From == peerDERP && isV2BulkControlPayload(pkt.Payload)`.
3. Decode with `externalV2BulkControlFromPayload`, preserving authenticated protocol errors.
4. Convert a closed subscription into `ErrPeerDisconnected`.
5. Send with `sendAuthenticatedEnvelope` and `envelopeV2BulkControl`.
6. Make `Close` idempotently cancel its read loop and unsubscribe.
7. Never block while reporting a terminal read error after the consumer exits.

The production constructor signature is:

```go
func newExternalV2BulkDERPControlWire(
	ctx context.Context,
	client *derpbind.Client,
	peerDERP key.NodePublic,
	auth externalPeerControlAuth,
) externalV2BulkControlWire
```

- [ ] **Step 4: Implement the coordinator state machines**

Use this state holder and constructors:

```go
type externalV2BulkDecisionCoordinator struct {
	ctx       context.Context
	cancel    context.CancelFunc
	wire      externalV2BulkControlWire
	emitter   *telemetry.Emitter
	retry     time.Duration
	readyWait time.Duration
	deadline  time.Time
	closeOnce sync.Once
}

func newExternalV2BulkDecisionCoordinator(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, auth externalPeerControlAuth, emitter *telemetry.Emitter) *externalV2BulkDecisionCoordinator {
	barrierCtx, cancel := context.WithTimeout(ctx, externalV2BulkDecisionBarrierWait)
	deadline, _ := barrierCtx.Deadline()
	return &externalV2BulkDecisionCoordinator{
		ctx: barrierCtx, cancel: cancel,
		wire: newExternalV2BulkDERPControlWire(barrierCtx, client, peerDERP, auth),
		emitter: emitter, retry: externalV2BulkDecisionRetry,
		readyWait: externalV2BulkDecisionReadyWait,
		deadline: deadline,
	}
}

func (c *externalV2BulkDecisionCoordinator) Close() {
	c.closeOnce.Do(func() {
		c.cancel()
		c.wire.Close()
	})
}
```

Provide `newExternalV2BulkDecisionCoordinatorWithWire` for tests; it accepts the same context plus a wire and emitter, and tests overwrite `retry`, `readyWait`, and `deadline` before starting either role.

Implement `ResolveSender` with this exact policy:

1. Reject zero `runID` as a protocol error.
2. If `probeErr != nil`, choose QUIC with `sender-probe-rejected` immediately.
3. Otherwise wait at most `readyWait`. Ignore exact duplicate readiness, but reject contradictory readiness or mismatched non-zero run IDs.
4. Choose QUIC for receiver QUIC readiness or readiness timeout.
5. Choose bulk only for matching bulk readiness, at `min(probeResult.SelectedMbps, readiness.SelectedMbps)`.
6. Freeze the decision, send it immediately and every `retry`, and return only after an exact acknowledgement.
7. Return the barrier context error on timeout; never replace the frozen decision.

Implement `ResolveReceiver` with this exact policy:

1. Run the supplied probe callback in a goroutine with a child context.
2. While it runs, accept only a valid QUIC decision. Cancel and drain the callback, acknowledge that decision, start the duplicate-decision responder, and return.
3. After the probe finishes, publish bulk readiness with run ID/rate on success or QUIC readiness with observed run ID (possibly zero) on rejection.
4. Send readiness immediately and every `retry` until a decision arrives.
5. Accept bulk only after bulk readiness with the same non-zero run ID. Accept QUIC regardless of local readiness unless both messages carry different non-zero run IDs.
6. Send an exact acknowledgement and respond to exact duplicate decisions until `Close` or the barrier deadline.
7. Reject a second different decision as `errExternalV2BulkDecisionProtocol`.

Emit each logical transition once, not once per retry:

```text
v2-bulk-ready=mode:bulk-packets-v1 run_id:77 selected_mbps:800 reason:probe-accepted
v2-bulk-decision=mode:quic run_id:77 selected_mbps:0 reason:sender-probe-rejected
v2-bulk-decision-ack=mode:quic run_id:77 selected_mbps:0 reason:sender-probe-rejected
```

- [ ] **Step 5: Run coordinator tests under normal and race builds**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkDecisionCoordinator' -count=1
mise exec -- go test -race ./pkg/session -run 'TestExternalV2BulkDecisionCoordinator' -count=1
mise run check:fast
```

Expected: bulk, both QUIC vetoes, readiness timeout, loss/retry, immutable decision, mismatch, disconnect, and cancellation all pass without races.

- [ ] **Step 6: Checkpoint the coordinator**

Run:

```bash
but pull --check
but diff
but commit codex/bulk-probe-decision-barrier -m "session: coordinate bulk probe decisions"
```

Expected: the diff contains only Task 2 files and GitButler creates one checkpoint.

---

### Task 3: Stop the bulk engine at the decision barrier

**Files:**

- Modify: `pkg/session/external_v2_bulk_packet.go:260-333,823-883`
- Modify: `pkg/session/external_v2_bulk_packet_probe.go:160-195,305-360`
- Modify: `pkg/session/external_v2_bulk_packet_probe_test.go`
- Modify: `pkg/session/external_v2_bulk_packet_test.go`
- Modify: `pkg/session/external_v2_bulk_packet_batched_receiver_test.go`

**Interfaces:**

- Consumes: Task 2 coordinator methods.
- Produces: `externalV2BulkPacketTransferOptions` and send/receive functions that cannot run a capacity probe without a coordinator.

- [ ] **Step 1: Write the asymmetric final-ack regression**

In `pkg/session/external_v2_bulk_packet_test.go`, add:

```go
type dropFinalBulkProbeAckConn struct {
	net.PacketConn
	auth    externalV2BulkPacketAuth
	dropped atomic.Bool
}

func (c *dropFinalBulkProbeAckConn) WriteTo(packet []byte, addr net.Addr) (int, error) {
	header, payload, ok := openExternalV2BulkPacket(c.auth.control, packet)
	if ok && header.kind == externalV2BulkPacketProbeAck {
		prefix, decoded := decodeExternalV2BulkPacketProbePrefix(payload)
		final := decoded && (prefix.pressure() || int(prefix.Train) == len(externalV2BulkPacketProbeRatesMbps)-1)
		if final {
			c.dropped.Store(true)
			return len(packet), nil
		}
	}
	return c.PacketConn.WriteTo(packet, addr)
}
```

Add `TestExternalV2BulkPacketFinalProbeAckLossNegotiatesQUIC`. Use real paired UDP connections and paired in-memory coordinators. Wrap each receiver-to-sender lane with `dropFinalBulkProbeAckConn`, which drops all three repeated final acknowledgements on every lane. Use the test-wire observer to capture the sender's `decision` and receiver's `ack`, then run both low-level roles concurrently and assert:

```go
if !errors.Is(sendErr, errExternalV2BulkPacketProbeRejected) || !errors.Is(receiveErr, errExternalV2BulkPacketProbeRejected) {
	t.Fatalf("fallback errors = (send=%v receive=%v), want both negotiated QUIC", sendErr, receiveErr)
}
if got := sink.bytes(); len(got) != 0 {
	t.Fatalf("bulk committed %d bytes before QUIC fallback", len(got))
}
if senderDecision.Mode != externalV2BulkModeQUIC || receiverAck.Mode != senderDecision.Mode ||
	receiverAck.ProbeRunID != senderDecision.ProbeRunID ||
	receiverAck.SelectedMbps != senderDecision.SelectedMbps || receiverAck.Reason != senderDecision.Reason {
	t.Fatalf("decision/ack differ: sender=%+v receiver_ack=%+v", senderDecision, receiverAck)
}
```

Add `TestExternalV2BulkPacketMissingDecisionAckCommitsNoPayload`: drop every decision acknowledgement and require both calls to return within the test deadline, both metrics objects to retain an empty file engine, sender `fileSourceReadCalls`/`fileSourceReadBytes` to remain zero, receiver committed/bulk/QUIC byte counters to remain zero, and the sink to remain empty.

- [ ] **Step 2: Run both regressions and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(FinalProbeAckLossNegotiatesQUIC|MissingDecisionAckCommitsNoPayload)$' -count=1
```

Expected: asymmetric loss fails because the receiver enters bulk while the sender returns a local fallback sentinel.

- [ ] **Step 3: Replace the boolean probe argument with explicit options**

In `pkg/session/external_v2_bulk_packet.go`, add:

```go
type externalV2BulkPacketTransferOptions struct {
	CapacityProbe bool
	Decision      *externalV2BulkDecisionCoordinator
}

func (o externalV2BulkPacketTransferOptions) validate() error {
	if o.CapacityProbe && o.Decision == nil {
		return errors.New("bulk capacity probe requires decision coordinator")
	}
	return nil
}
```

Collapse each wrapper/`WithProbe` pair into one `sendExternalV2BulkBlockPackets` and one `receiveExternalV2BulkBlockPackets` function that accepts `options externalV2BulkPacketTransferOptions`. Update every caller; do not leave a second entry point whose name hides whether agreement is required. Validate options before metrics or workers. Payload-only unit tests pass `externalV2BulkPacketTransferOptions{}`. Probe-enabled tests pass:

```go
externalV2BulkPacketTransferOptions{CapacityProbe: true, Decision: coordinator}
```

Do not retain a probing path that accepts a nil coordinator.

- [ ] **Step 4: Preserve known run IDs on every probe result**

Initialize the sender result before its train loop:

```go
	result := externalV2BulkPacketProbeResult{RunID: sender.runID}
```

Append completed train evidence and duration to that value before every return. Add `TestExternalV2BulkPacketProbeFailurePreservesRunID` in `external_v2_bulk_packet_probe_test.go`; force the first acknowledgement wait to time out and assert the returned result contains the sender's non-zero run ID.

On the receiver, assign a non-zero `runID` returned by `receiveExternalV2BulkPacketProbeTrain` before checking that train's error, and include `RunID: probeRunID` in every error result. Add `TestExternalV2BulkPacketReceiverProbeFailurePreservesObservedRunID`: deliver one authenticated probe event, cancel before the train completes, and require the failure result to retain that observed ID. A receiver that never authenticated an event still returns zero, as required for early QUIC readiness.

Replace the shared probe selector with role-local variables so integration tests can reject one side without changing the other:

```go
var externalV2BulkPacketSenderProbeSelector = selectExternalV2BulkPacketProbe
var externalV2BulkPacketReceiverProbeSelector = selectExternalV2BulkPacketProbe
```

Use the sender selector after sender trains and the receiver selector after receiver trains. Update the one existing test override to restore both variables in `t.Cleanup`.

- [ ] **Step 5: Gate sender payload setup on an acknowledged decision**

Replace the local probe-return branch with:

```go
	if options.CapacityProbe {
		probeResult, probeErr := sendExternalV2BulkPacketProbe(sendCtx, sender, probeAckCh)
		sender.probeResult = probeResult
		decision, decisionErr := options.Decision.ResolveSender(sendCtx, sender.runID, probeResult, probeErr)
		if decisionErr != nil {
			return cleanupExternalV2BulkPacketSenderBeforePayload(sender, cancel, writeDeadlineDone, controlDone, path, decisionErr)
		}
		if decision.Mode == externalV2BulkModeQUIC {
			return cleanupExternalV2BulkPacketSenderBeforePayload(sender, cancel, writeDeadlineDone, controlDone, path, errExternalV2BulkPacketProbeRejected)
		}
		sender.setInitialPaceMbps(decision.SelectedMbps)
		for lane := range sender.batchConns {
			sender.batchConns[lane] = newExternalV2BulkPacketBatchConn(path.Conns[lane])
		}
	}
```

Extract the repeated cancellation/deadline/control-reader cleanup into the named helper. Select the bulk file engine only after acknowledged bulk. No source read may happen before that point.

The cleanup helper signature is:

```go
func cleanupExternalV2BulkPacketSenderBeforePayload(
	sender *externalV2BulkPacketSender,
	cancel context.CancelFunc,
	writeDeadlineDone <-chan error,
	controlDone <-chan struct{},
	path externalV2BulkPacketPath,
	cause error,
) (externalDirectTransferStats, error)
```

- [ ] **Step 6: Run receiver probing under coordinator control**

Replace the receiver's local probe selection with:

```go
	if options.CapacityProbe {
		probeResult, decision, decisionErr := options.Decision.ResolveReceiver(recvCtx, func(probeCtx context.Context) (externalV2BulkPacketProbeResult, error) {
			return receiveExternalV2BulkPacketProbe(probeCtx, path, auth, receiver.totalPackets)
		})
		receiver.probeResult = probeResult
		if decisionErr != nil {
			return receiver.result(decisionErr)
		}
		if decision.Mode == externalV2BulkModeQUIC {
			return receiver.result(errExternalV2BulkPacketProbeRejected)
		}
		receiver.probeResult.SelectedMbps = decision.SelectedMbps
		if receiver.grouped && !receiver.groupAssembler.setExpectedRunID(decision.ProbeRunID) {
			return receiver.result(errors.New("bulk packet grouped decision did not authenticate a run ID"))
		}
		metrics.SelectFilePayloadEngine(transfertrace.FilePayloadEngineBulk, time.Now())
	}
```

Do not start data readers, assemblers, or sink writers before acknowledged bulk.

- [ ] **Step 7: Run boundary tests under the race detector**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(FinalProbeAckLossNegotiatesQUIC|MissingDecisionAckCommitsNoPayload|ProbeFailurePreservesRunID|ReceiverProbeFailurePreservesObservedRunID|Transfer)' -count=1
mise exec -- go test -race ./pkg/session -run 'TestExternalV2BulkPacket(FinalProbeAckLossNegotiatesQUIC|MissingDecisionAckCommitsNoPayload)' -count=1
mise run check:fast
```

Expected: both peers negotiate QUIC under asymmetric loss, missing acknowledgement commits zero payload, existing packet tests pass with explicit options, and the race detector is clean.

- [ ] **Step 8: Checkpoint the gated engine**

Run:

```bash
but pull --check
but diff
but commit codex/bulk-probe-decision-barrier -m "session: gate bulk payload on peer decision"
```

Expected: the diff contains only Task 3 files and GitButler creates one checkpoint.

---

### Task 4: Wire all four runtime topologies through one barrier

**Files:**

- Modify: `pkg/session/external_v2.go:315-433,846-930`
- Modify: `pkg/session/external_v2_offer.go:270-360`
- Modify: `pkg/session/external_v2_block.go:268-490`
- Modify: `pkg/session/external_v2_block_test.go:699-760`

**Interfaces:**

- Consumes: Task 3 transfer options and Task 2 production constructor.
- Produces: claimant/offerer sender/receiver paths that subscribe before probe and retain the same coordinator across QUIC fallback.

- [ ] **Step 1: Strengthen the full fallback test before runtime edits**

Update `TestExternalV2ProbeFallbackCompletesThroughQUICBeforePayload` so only the sender probe selector rejects. In Task 3, replace the shared selector variable with two variables that both default to `selectExternalV2BulkPacketProbe`:

```go
var externalV2BulkPacketSenderProbeSelector = selectExternalV2BulkPacketProbe
var externalV2BulkPacketReceiverProbeSelector = selectExternalV2BulkPacketProbe
```

Call the sender variable from `sendExternalV2BulkPacketProbe` and the receiver variable from `receiveExternalV2BulkPacketProbe`. In this test, override only `externalV2BulkPacketSenderProbeSelector` and restore it with `t.Cleanup`. The receiver must publish bulk readiness while the sender publishes QUIC.

Retain exact payload equality and require both status buffers to contain:

```go
for role, status := range map[string]string{"offer": offerStatus.String(), "receive": receiveStatus.String()} {
	for _, marker := range []string{
		"v2-bulk-ready=mode:bulk-packets-v1",
		"v2-bulk-decision=mode:quic",
		"v2-bulk-decision-ack=mode:quic",
		"v2-bulk-probe=fallback-before-payload",
	} {
		if !strings.Contains(status, marker) {
			t.Fatalf("%s status missing %q: %q", role, marker, status)
		}
	}
}
```

After both calls return, wait 250 milliseconds and assert no status growth. Task 2's `Close` test owns the goroutine/retry shutdown assertion; the live harness owns process/socket leak checks.

- [ ] **Step 2: Run the full fallback test and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run '^TestExternalV2ProbeFallbackCompletesThroughQUICBeforePayload$' -count=1
```

Expected: failure because no runtime coordinator or negotiated markers exist.

- [ ] **Step 3: Construct sender coordinators before probing**

In `externalV2SendRuntime.sendStream`, when the raw path selected bulk packets, create:

```go
decision := newExternalV2BulkDecisionCoordinator(
	streamCtx, rt.derp, rt.listenerDERP, rt.auth, rt.cfg.Emitter,
)
defer decision.Close()
```

Pass it through `sendBulkPacketBlock` as:

```go
externalV2BulkPacketTransferOptions{CapacityProbe: true, Decision: decision}
```

Every runtime-selected bulk path sets `CapacityProbe: true`, including the non-batch record path; only payload-mechanics unit tests may disable it. Keep the defer at `sendStream` scope so QUIC fallback remains subscribed while `copySendStreamWithClient` opens and starts streams.

In `externalV2OfferRuntime.sendQUIC`, construct the sender coordinator with `rt.session.derp`, `accepted.peerDERP`, `rt.auth`, and `rt.cfg.Emitter`. Retain it through `openOfferQUICStreams` and `sendQUICStreams`; do not defer it inside `tryOfferSendBulkPacketBlock`.

- [ ] **Step 4: Construct receiver coordinators before probing**

In `externalV2ListenRuntime.receiveQUICBlock`, construct the receiver coordinator with `rt.session.derp`, `accepted.peerDERP`, `rt.auth`, and `rt.cfg.Emitter` before `tryReceiveBulkPacketBlock`. Retain it until bulk completes or `finishQUICBlockReceive` returns.

In `externalV2OfferReceiveRuntime.receiveQUICBlock`, use `rt.derp`, `rt.listenerDERP`, `rt.auth`, and `rt.cfg.Emitter`, retaining it through `openOfferReceiveQUICBlockStreams` and stream completion.

Pass the coordinator into both `receiveBulkPacketBlock` methods via the same options type. The existing `errExternalV2BulkPacketProbeRejected` sentinel now means “both peers acknowledged QUIC,” never “this peer timed out locally.”

- [ ] **Step 5: Remove unilateral outer fallback decisions**

For all four `try*BulkPacketBlock` paths:

- return `(true, err)` for protocol errors, barrier timeouts, disconnects, and cleanup failures;
- return `(false, nil)` only for the negotiated QUIC sentinel;
- do not inspect or translate raw probe errors outside the coordinator;
- emit `v2-bulk-probe=fallback-before-payload` only for negotiated QUIC;
- finish packet-reader and deadline cleanup before opening QUIC on the same raw sockets.

- [ ] **Step 6: Run topology and session coverage**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2(ProbeFallbackCompletesThroughQUICBeforePayload|OfferReceiveBlock|BlockTransfer|BulkPacket)' -count=1
mise exec -- go test -race ./pkg/session -run '^TestExternalV2ProbeFallbackCompletesThroughQUICBeforePayload$' -count=1
mise run smoke-local
mise run check:fast
```

Expected: all four topology paths pass; asymmetric fallback finishes through QUIC with identical markers; local smoke passes; and every product builds.

- [ ] **Step 7: Checkpoint runtime integration**

Run:

```bash
but pull --check
but diff
but commit codex/bulk-probe-decision-barrier -m "session: negotiate bulk fallback across runtimes"
```

Expected: the diff contains only Task 4 files and GitButler creates one checkpoint.

---

### Task 5: Trace the final decision independently of the payload engine

**Files:**

- Modify: `pkg/session/external_transfer_metrics.go:25-130,263-335,960-1040`
- Modify: `pkg/session/external_transfer_metrics_test.go`
- Modify: `pkg/transfertrace/trace.go:120-180,285-305,570-675`
- Modify: `pkg/transfertrace/trace_test.go:180-315`
- Modify: `pkg/transfertrace/checker.go:420-445,930-975`
- Modify: `pkg/transfertrace/checker_test.go:650-790`
- Modify: `pkg/session/external_v2_bulk_packet.go`
- Modify: `scripts/promotion-benchmark-driver.sh:1485-1500`
- Modify: `scripts/promotion_scripts_test.go`

**Interfaces:**

- Consumes: `externalV2BulkDecision` returned at the barrier.
- Produces: `SetBulkDecision`, snapshot fields `BulkDecisionMode`, `BulkDecisionReason`, `BulkDecisionRunID`, and appended CSV columns `bulk_decision_mode`, `bulk_decision_reason`, `bulk_decision_run_id`.

- [ ] **Step 1: Write failing metrics and trace tests**

Add to `pkg/session/external_transfer_metrics_test.go`:

```go
func TestExternalTransferMetricsRecordsBulkDecisionBeforeEngine(t *testing.T) {
	metrics := newExternalTransferMetricsWithTrace(time.Unix(300, 0), nil, transfertrace.RoleReceive)
	decision := externalV2BulkDecision{
		Mode: externalV2BulkModeQUIC, ProbeRunID: 77,
		Reason: externalV2BulkReasonSenderProbeRejected,
	}
	metrics.SetBulkDecision(decision, time.Unix(300, 1))

	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if metrics.bulkDecisionMode != externalV2BulkModeQUIC ||
		metrics.bulkDecisionReason != externalV2BulkReasonSenderProbeRejected ||
		metrics.bulkDecisionRunID != 77 || metrics.filePayloadEngine != "" ||
		metrics.filePayloadBytesCommitted != 0 {
		t.Fatalf("unexpected decision metrics: mode=%q reason=%q run=%d engine=%q bytes=%d",
			metrics.bulkDecisionMode, metrics.bulkDecisionReason, metrics.bulkDecisionRunID,
			metrics.filePayloadEngine, metrics.filePayloadBytesCommitted)
	}
}
```

Extend `trace_test.go` so `Header` ends with the three new columns and a QUIC decision serializes `quic,sender-probe-rejected,77` before `FilePayloadEngine` is valid.

Add checker table rows that reject:

- final bulk engine with decision mode `quic`;
- final QUIC block engine with decision mode `bulk-packets-v1`;
- decision evidence with zero run ID;
- bulk decision with zero selected probe rate;
- a reason outside the stable reason set.

- [ ] **Step 2: Run telemetry tests and verify RED**

Run:

```bash
mise exec -- go test ./pkg/session -run '^TestExternalTransferMetricsRecordsBulkDecisionBeforeEngine$' -count=1
mise exec -- go test ./pkg/transfertrace -run 'TestTrace|TestChecker' -count=1
```

Expected: build/assertion failures because decision metrics and columns do not exist.

- [ ] **Step 3: Add monotonic decision storage**

Add to `externalTransferMetrics`:

```go
	bulkDecisionMode   string
	bulkDecisionReason string
	bulkDecisionRunID  uint64
```

Add:

```go
func (m *externalTransferMetrics) SetBulkDecision(decision externalV2BulkDecision, at time.Time) {
	if m == nil || decision.ProbeRunID == 0 {
		return
	}
	m.mu.Lock()
	if m.bulkDecisionRunID == 0 {
		m.bulkDecisionMode = decision.Mode
		m.bulkDecisionReason = decision.Reason
		m.bulkDecisionRunID = decision.ProbeRunID
	}
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}
```

The first decision is immutable; a later differing value must not overwrite it. Project all three values into `transfertrace.Snapshot`. Call `SetBulkDecision` immediately after sender or receiver resolution and before returning the QUIC sentinel or selecting bulk.

- [ ] **Step 4: Append trace columns without reordering the schema**

Append after `bulk_probe_pressure`:

```go
	"bulk_decision_mode",
	"bulk_decision_reason",
	"bulk_decision_run_id",
```

Add matching `Snapshot` fields. Keep `bulkBatchTraceColumns` at its existing width of 30; decision evidence must not depend on `BulkBatchPresent`, because negotiated QUIC fallback happens before batch payload setup. Append the decision values unconditionally after the existing bulk columns:

```go
	row = append(row, bulkBatchTraceColumns(snap)...)
	return append(row,
		snap.BulkDecisionMode,
		snap.BulkDecisionReason,
		formatOptionalUint64(snap.BulkDecisionRunID),
	)
```

Serialize an unset run ID as an empty field, not `0`, so transfers that never attempted bulk remain distinguishable from invalid decision evidence. Do not rename or reorder existing columns.

In `checker.go`, require non-zero run ID whenever a decision mode is present. Final bulk rows require `bulk-packets-v1` plus `both-probes-accepted`. Final QUIC block rows with decision evidence require `quic` plus `sender-probe-rejected`, `receiver-probe-rejected`, or `receiver-readiness-timeout`. Transfers that never attempted bulk may leave all three fields empty.

Update `promotion-benchmark-driver.sh` so its transfer-mode detection checks for `v2-bulk-decision=mode:quic` on both peers before treating the earlier `v2-block-transfer=bulk-packets` attempt marker as the final mode:

```bash
elif grep -Fq 'v2-bulk-decision=mode:quic' "${sender_log}" &&
     grep -Fq 'v2-bulk-decision=mode:quic' "${receiver_log}"; then
  transfer_mode="blocks-v1"
elif grep -Fq 'v2-block-transfer=bulk-packets' "${sender_log}" &&
     grep -Fq 'v2-block-transfer=bulk-packets' "${receiver_log}"; then
  transfer_mode="bulk-packets-v1"
```

Add a script test fixture containing both the attempted-bulk marker and the QUIC decision marker; require `benchmark-transfer-mode=blocks-v1`. Keep direct TCP as the first/highest-priority branch.

- [ ] **Step 5: Run telemetry and session regression suites**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalTransferMetrics|TestExternalV2ProbeFallback' -count=1
mise exec -- go test ./pkg/transfertrace -count=1
mise exec -- go test ./scripts -run 'TestPromotion' -count=1
mise run check:fast
```

Expected: decision evidence precedes engine/payload evidence, contradictory rows fail validation, and old columns retain their order.

- [ ] **Step 6: Checkpoint telemetry**

Run:

```bash
but pull --check
but diff
but commit codex/bulk-probe-decision-barrier -m "telemetry: trace bulk probe decisions"
```

Expected: the diff contains only Task 5 files and GitButler creates one checkpoint.

---

### Task 6: Prove the fix locally and on the public path

**Files:**

- Verify only; do not commit benchmark artifacts.

**Interfaces:**

- Consumes: the complete Task 1-5 implementation.
- Produces: deterministic regression evidence, repository gate evidence, and three normal 3 GiB public-path results with integrity and cleanup checks.

- [ ] **Step 1: Repeat focused protocol and asymmetric-loss tests**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2(Bulk(Control|Decision|PacketFinalProbeAckLoss|PacketMissingDecisionAck)|ProbeFallback)' -count=20
mise exec -- go test -race ./pkg/session -run 'TestExternalV2BulkDecisionCoordinator|TestExternalV2BulkPacketFinalProbeAckLoss|TestExternalV2ProbeFallback' -count=1
```

Expected: every repetition passes, race output is clean, lost final UDP acknowledgement always yields one acknowledged QUIC decision, and bulk commits zero bytes before fallback.

- [ ] **Step 2: Run the complete iteration gates**

Run:

```bash
mise exec -- go test ./... -count=1
mise run check:fast
```

Expected: the full Go suite passes once and every product builds.

- [ ] **Step 3: Run three normal 3 GiB forward public-path transfers**

Use the checked-in safe harness from `docs/benchmarks.md`:

```bash
DERPHOLE_PUBLIC_PATH_HOSTS="${REMOTE_HOST:?set REMOTE_HOST}" \
DERPHOLE_PUBLIC_PATH_DIRECTION=forward \
DERPHOLE_PUBLIC_PATH_SIZE_MIB=3072 \
DERPHOLE_PUBLIC_PATH_RUNS=3 \
DERPHOLE_PUBLIC_IPERF_PORT=8123 \
DERPHOLE_BENCH_LOG_DIR=.tmp/bulk-probe-decision-barrier \
./scripts/public-path-performance-harness.sh
```

Set `REMOTE_HOST` to the configured Ubuntu SSH target first. The harness builds both peers from the current revision, disables Tailscale candidates, verifies SHA-256 and byte count, captures both logs/traces, and checks surviving processes/sockets.

Each row must complete with integrity, no one-second flatline, no `peer disconnected`, and no leak. It must show either:

- `bulk_decision_mode=bulk-packets-v1` with `file_payload_engine=bulk-packets-v1`; or
- `bulk_decision_mode=quic` with `file_payload_engine=quic-blocks-v1` and a stable fallback reason.

Sender and receiver decision mode/run ID must match in every run.

- [ ] **Step 4: Run the final repository gate before publication**

Run:

```bash
but pull --check
mise run check
```

Expected: the base is current and the exhaustive gate passes against the final stack. If hooks change tracked content, absorb it into the owning unpublished checkpoint and rerun `mise run check`.

- [ ] **Step 5: Snapshot and review the unpublished stack**

Run:

```bash
but status
but oplog snapshot -m "before bulk decision history cleanup"
```

Expected: only this session's branch is in scope. Use GitButler to squash/reword Task 1-5 checkpoints into a clean final commit if requested during execution. Do not push or land on `main` without explicit authorization.
