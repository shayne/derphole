# Receiver-Anchored Progress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make sender and receiver progress/rate use receiver-confirmed payload progress, and prevent `connected-direct` from being reported before direct UDP is validated.

**Architecture:** Add a dedicated authenticated progress ACK envelope at the session layer. Receivers emit periodic session-stream byte progress with receiver-side transfer elapsed time; senders store that progress in transfer metrics and map session-stream bytes back to payload bytes for CLI progress. Direct status emission is split into attempted direct and validated direct states, with trace fields and harness checks proving the distinction.

**Tech Stack:** Go, DERP peer-control envelopes, existing `transfertrace` CSV recorder/checker, existing CLI `ProgressReporter`, shell live harnesses.

---

## File Structure

- Modify `pkg/transfertrace/trace.go`: add trace columns and snapshot fields.
- Modify `pkg/transfertrace/checker.go`: parse optional new columns and validate direct status and peer progress alignment.
- Modify `pkg/transfertrace/trace_test.go` and `pkg/transfertrace/checker_test.go`: schema/checker regression tests.
- Modify `pkg/session/external.go`: add progress ACK envelope type, send/wait helpers, and payload classifiers.
- Modify `pkg/session/external_control_security.go`: reuse envelope MAC for progress ACKs; no new key is required.
- Create `pkg/session/external_progress_ack_test.go`: progress ACK auth and replay tests.
- Modify `pkg/session/types.go`: add strict path states and progress callback fields on send/offer configs.
- Modify `pkg/session/external_transfer_metrics.go`: track local sent bytes, peer received bytes, setup/transfer elapsed, direct validation, and fallback reason.
- Modify `pkg/session/external_direct_udp.go`: wire progress subscriptions, receiver progress emitters, sender progress consumers, and strict direct status transitions.
- Modify `pkg/session/counting.go`: expose receiver first-byte timestamp for progress ACK elapsed time.
- Modify `pkg/session/external_direct_udp_test.go` and `pkg/session/external_transfer_metrics_test.go`: session-level regressions.
- Modify `pkg/derphole/progress.go`: add externally settable progress and receiver-anchored rate rendering.
- Modify `pkg/derphole/progress_test.go`: progress reporter regression tests.
- Modify `pkg/derphole/transfer.go`: map session-stream receiver progress to payload progress for sender CLI.
- Modify `pkg/derphole/transfer_test.go`: sender progress follows peer progress, not local read progress.
- Modify `scripts/transfer-stall-harness.sh`: run the stricter checker and report fallback/direct-validation evidence.
- Modify `docs/benchmarks.md`: document receiver-anchored progress and trace interpretation.

---

### Task 1: Extend Transfer Trace Schema

**Files:**
- Modify: `pkg/transfertrace/trace.go`
- Modify: `pkg/transfertrace/trace_test.go`

- [ ] **Step 1: Write failing trace schema test**

Add this test to `pkg/transfertrace/trace_test.go`:

```go
func TestRecorderWritesReceiverAnchoredProgressColumns(t *testing.T) {
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleSend, time.Unix(900, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Observe(Snapshot{
		At:                time.Unix(900, int64(500*time.Millisecond)),
		Phase:             PhaseRelay,
		AppBytes:          1024,
		LocalSentBytes:    4096,
		PeerReceivedBytes: 1024,
		SetupElapsedMS:    250,
		TransferElapsedMS: 250,
		DirectValidated:   false,
		FallbackReason:    "direct UDP rate probes received no packets",
		LastState:         "direct-fallback-relay",
	})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	records, indexes := readTraceCSV(t, out.String())
	row := records[1]
	assertColumn(t, row, indexes, "local_sent_bytes", "4096")
	assertColumn(t, row, indexes, "peer_received_bytes", "1024")
	assertColumn(t, row, indexes, "setup_elapsed_ms", "250")
	assertColumn(t, row, indexes, "transfer_elapsed_ms", "250")
	assertColumn(t, row, indexes, "direct_validated", "false")
	assertColumn(t, row, indexes, "fallback_reason", "direct UDP rate probes received no packets")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./pkg/transfertrace -run TestRecorderWritesReceiverAnchoredProgressColumns -count=1
```

Expected: FAIL because the new `Snapshot` fields and CSV columns do not exist.

- [ ] **Step 3: Add trace fields and columns**

In `pkg/transfertrace/trace.go`, extend `header`, `HeaderLine`, `Snapshot`, and `row`:

```go
var header = [...]string{
	"timestamp_unix_ms",
	"elapsed_ms",
	"role",
	"phase",
	"relay_bytes",
	"direct_bytes",
	"app_bytes",
	"delta_app_bytes",
	"app_mbps",
	"local_sent_bytes",
	"peer_received_bytes",
	"setup_elapsed_ms",
	"transfer_elapsed_ms",
	"direct_validated",
	"fallback_reason",
	"direct_rate_selected_mbps",
	"direct_rate_active_mbps",
	"direct_lanes_active",
	"direct_lanes_available",
	"direct_probe_state",
	"direct_probe_summary",
	"replay_window_bytes",
	"repair_queue_bytes",
	"retransmit_count",
	"out_of_order_bytes",
	"last_state",
	"last_error",
}

type Snapshot struct {
	At                     time.Time
	Phase                  Phase
	RelayBytes             int64
	DirectBytes            int64
	AppBytes               int64
	LocalSentBytes         int64
	PeerReceivedBytes      int64
	SetupElapsedMS         int64
	TransferElapsedMS      int64
	DirectValidated        bool
	FallbackReason         string
	DirectRateSelectedMbps int
	DirectRateActiveMbps   int
	DirectLanesActive      int
	DirectLanesAvailable   int
	DirectProbeState       string
	DirectProbeSummary     string
	ReplayWindowBytes      uint64
	RepairQueueBytes       uint64
	RetransmitCount        int64
	OutOfOrderBytes        uint64
	LastState              string
	LastError              string
}
```

Add the new row fields immediately after `app_mbps`:

```go
strconv.FormatInt(snap.LocalSentBytes, 10),
strconv.FormatInt(snap.PeerReceivedBytes, 10),
formatOptionalInt64(snap.SetupElapsedMS),
formatOptionalInt64(snap.TransferElapsedMS),
strconv.FormatBool(snap.DirectValidated),
snap.FallbackReason,
```

Update `HeaderLine` to exactly match `strings.Join(header[:], ",")`.

- [ ] **Step 4: Run trace tests**

Run:

```bash
go test ./pkg/transfertrace -run 'TestRecorderWritesReceiverAnchoredProgressColumns|TestRecorderWritesHeaderAndEscapedRows|TestRecorderHeaderUnaffectedByExportedHeaderMutation' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/transfertrace/trace.go pkg/transfertrace/trace_test.go
git commit -m "trace: add receiver-anchored progress fields"
```

---

### Task 2: Add Transfer Metrics State

**Files:**
- Modify: `pkg/session/external_transfer_metrics.go`
- Modify: `pkg/session/external_transfer_metrics_test.go`

- [ ] **Step 1: Write failing metrics test**

Add this test to `pkg/session/external_transfer_metrics_test.go`:

```go
func TestExternalTransferMetricsUsesPeerProgressForSenderAppBytes(t *testing.T) {
	var out bytes.Buffer
	trace, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, time.Unix(50, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(50, 0), trace, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))
	metrics.RecordLocalSent(10<<20, time.Unix(50, int64(100*time.Millisecond)))
	metrics.RecordPeerProgress(1<<20, 500, time.Unix(51, 0))
	if err := trace.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	body := out.String()
	if !strings.Contains(body, ",10485760,1048576,500,500,false,") {
		t.Fatalf("trace body = %q, want local_sent=10MiB peer_received=1MiB setup/transfer elapsed", body)
	}
	if strings.Contains(body, ",10485760,10485760,") {
		t.Fatalf("trace body = %q, sender app_bytes should not follow local sent bytes", body)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./pkg/session -run TestExternalTransferMetricsUsesPeerProgressForSenderAppBytes -count=1
```

Expected: FAIL because `RecordLocalSent` and `RecordPeerProgress` do not exist.

- [ ] **Step 3: Implement metrics fields and methods**

In `externalTransferMetrics`, add:

```go
localSentBytes        int64
peerReceivedBytes     int64
transferStartedAt     time.Time
receiverTransferMS    int64
directValidated       bool
fallbackReason        string
```

Add methods:

```go
func (m *externalTransferMetrics) RecordLocalSent(n int64, at time.Time) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	m.localSentBytes += n
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	observeExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) RecordPeerProgress(bytesReceived int64, transferElapsedMS int64, at time.Time) {
	if m == nil || bytesReceived < 0 {
		return
	}
	m.mu.Lock()
	if bytesReceived > m.peerReceivedBytes {
		m.peerReceivedBytes = bytesReceived
	}
	if transferElapsedMS > m.receiverTransferMS {
		m.receiverTransferMS = transferElapsedMS
	}
	if m.transferStartedAt.IsZero() && !at.IsZero() && transferElapsedMS >= 0 {
		m.transferStartedAt = at.Add(-time.Duration(transferElapsedMS) * time.Millisecond)
	}
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	observeExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) MarkDirectValidated(at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.directValidated = true
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	observeExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) SetFallbackReason(reason string, at time.Time) {
	if m == nil || reason == "" {
		return
	}
	m.mu.Lock()
	m.fallbackReason = reason
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	observeExternalTransferTrace(trace, snap, ok)
}

func nonZeroTime(at time.Time) time.Time {
	if at.IsZero() {
		return time.Now()
	}
	return at
}
```

Update `appBytesLocked`:

```go
func (m *externalTransferMetrics) appBytesLocked() int64 {
	if m.role == transfertrace.RoleSend && m.peerReceivedBytes > 0 {
		return m.peerReceivedBytes
	}
	if !m.directAppProgressSet {
		return m.relayBytes + m.directBytes
	}
	directProgress := m.directAppProgressBase + m.directBytes
	if directProgress > m.relayBytes {
		return directProgress
	}
	return m.relayBytes
}
```

Update `updateTraceLocked` to populate the new snapshot fields. Compute setup and transfer elapsed like this:

```go
setupMS := int64(0)
transferMS := m.receiverTransferMS
if !m.transferStartedAt.IsZero() {
	setupMS = m.transferStartedAt.Sub(m.startedAt).Milliseconds()
	if setupMS < 0 {
		setupMS = 0
	}
	if transferMS == 0 && at.After(m.transferStartedAt) {
		transferMS = at.Sub(m.transferStartedAt).Milliseconds()
	}
}
```

- [ ] **Step 4: Run metrics tests**

Run:

```bash
go test ./pkg/session -run 'TestExternalTransferMetricsUsesPeerProgressForSenderAppBytes|TestExternalTransferMetricsTrackRelayAndDirectBytes|TestExternalTransferMetricsTraceRows' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/session/external_transfer_metrics.go pkg/session/external_transfer_metrics_test.go
git commit -m "session: track receiver-anchored transfer metrics"
```

---

### Task 3: Add Authenticated Progress ACK Envelope

**Files:**
- Modify: `pkg/session/external.go`
- Create: `pkg/session/external_progress_ack_test.go`

- [ ] **Step 1: Write failing progress ACK tests**

Create `pkg/session/external_progress_ack_test.go`:

```go
package session

import (
	"context"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/token"
	"tailscale.com/types/key"
)

func TestVerifyPeerProgressPacketAcceptsAuthenticatedProgress(t *testing.T) {
	tok := token.Token{Version: token.SupportedVersion}
	tok.SessionID[0] = 1
	tok.BearerSecret[0] = 2
	auth := externalPeerControlAuthForToken(tok)
	payload, err := marshalAuthenticatedEnvelope(envelope{
		Type: envelopeProgress,
		Progress: newPeerProgress(1234, 500, 7),
	}, auth)
	if err != nil {
		t.Fatalf("marshalAuthenticatedEnvelope() error = %v", err)
	}
	progress, handled, err := verifyPeerProgressPacket(derpbind.Packet{Payload: payload}, auth, nil)
	if err != nil || handled {
		t.Fatalf("verifyPeerProgressPacket() = progress=%#v handled=%v err=%v", progress, handled, err)
	}
	if progress.BytesReceived != 1234 || progress.TransferElapsedMS != 500 || progress.Sequence != 7 {
		t.Fatalf("progress = %#v", progress)
	}
}

func TestVerifyPeerProgressPacketIgnoresUnauthenticatedProgress(t *testing.T) {
	tok := token.Token{Version: token.SupportedVersion}
	tok.SessionID[0] = 1
	tok.BearerSecret[0] = 2
	auth := externalPeerControlAuthForToken(tok)
	payload, err := marshalAuthenticatedEnvelope(envelope{
		Type: envelopeProgress,
		Progress: newPeerProgress(1234, 500, 7),
	}, externalPeerControlAuth{})
	if err != nil {
		t.Fatalf("marshalAuthenticatedEnvelope() error = %v", err)
	}
	_, handled, err := verifyPeerProgressPacket(derpbind.Packet{Payload: payload}, auth, nil)
	if !handled || err != nil {
		t.Fatalf("verifyPeerProgressPacket() handled=%v err=%v, want handled unauthenticated packet", handled, err)
	}
}

func TestVerifyPeerProgressPacketRejectsReplay(t *testing.T) {
	progress := newPeerProgress(1024, 250, 9)
	last := uint64(9)
	if !peerProgressReplayed(progress, &last) {
		t.Fatal("peerProgressReplayed = false, want true for same sequence")
	}
	progress.Sequence = 10
	if peerProgressReplayed(progress, &last) {
		t.Fatal("peerProgressReplayed = true, want false for newer sequence")
	}
	if last != 10 {
		t.Fatalf("last = %d, want 10", last)
	}
}

func TestSendPeerProgressSkipsNilClient(t *testing.T) {
	err := sendPeerProgress(context.Background(), nil, key.NodePublic{}, 1, 1, 1, externalPeerControlAuth{})
	if err != nil {
		t.Fatalf("sendPeerProgress() error = %v, want nil for nil client", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./pkg/session -run 'TestVerifyPeerProgressPacket|TestSendPeerProgress' -count=1
```

Expected: FAIL because `envelopeProgress`, `peerProgress`, and helper functions do not exist.

- [ ] **Step 3: Add envelope type and helpers**

In `pkg/session/external.go`, add the constant and envelope field:

```go
envelopeProgress = "progress"
```

```go
Progress *peerProgress `json:"progress,omitempty"`
```

Add type and constructor:

```go
type peerProgress struct {
	BytesReceived    int64  `json:"bytes_received"`
	TransferElapsedMS int64 `json:"transfer_elapsed_ms"`
	Sequence         uint64 `json:"sequence,omitempty"`
}

func newPeerProgress(bytesReceived int64, transferElapsedMS int64, sequence uint64) *peerProgress {
	if bytesReceived < 0 {
		bytesReceived = 0
	}
	if transferElapsedMS < 0 {
		transferElapsedMS = 0
	}
	return &peerProgress{
		BytesReceived:     bytesReceived,
		TransferElapsedMS: transferElapsedMS,
		Sequence:          sequence,
	}
}
```

Add classifier:

```go
func isProgressPayload(payload []byte) bool {
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeProgress
}
```

Add sender and verifier helpers near the ACK helpers:

```go
func sendPeerProgress(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesReceived int64, transferElapsedMS int64, sequence uint64, auth externalPeerControlAuth) error {
	if client == nil || peerDERP.IsZero() {
		return nil
	}
	return sendAuthenticatedEnvelope(ctx, client, peerDERP, envelope{
		Type:     envelopeProgress,
		Progress: newPeerProgress(bytesReceived, transferElapsedMS, sequence),
	}, auth)
}

func verifyPeerProgressPacket(pkt derpbind.Packet, auth externalPeerControlAuth, lastSequence *uint64) (peerProgress, bool, error) {
	env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
	if ignoreAuthenticatedEnvelopeError(err, auth) {
		return peerProgress{}, true, nil
	}
	if err == nil && env.Type == envelopeAbort {
		return peerProgress{}, false, ErrPeerAborted
	}
	if err != nil || env.Type != envelopeProgress {
		return peerProgress{}, false, errors.New("unexpected peer progress payload")
	}
	if env.Progress == nil {
		return peerProgress{}, false, errors.New("peer progress missing body")
	}
	if peerProgressReplayed(env.Progress, lastSequence) {
		return peerProgress{}, true, nil
	}
	return *env.Progress, false, nil
}

func peerProgressReplayed(progress *peerProgress, lastSequence *uint64) bool {
	if progress == nil || lastSequence == nil {
		return false
	}
	if progress.Sequence <= *lastSequence {
		return true
	}
	*lastSequence = progress.Sequence
	return false
}
```

- [ ] **Step 4: Run progress ACK tests**

Run:

```bash
go test ./pkg/session -run 'TestVerifyPeerProgressPacket|TestSendPeerProgress' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/session/external.go pkg/session/external_progress_ack_test.go
git commit -m "session: add authenticated progress acknowledgements"
```

---

### Task 4: Wire Receiver Progress ACKs To Sender Metrics

**Files:**
- Modify: `pkg/session/types.go`
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Write failing subscription and progress tests**

Add tests to `pkg/session/external_direct_udp_test.go`:

```go
func TestSendSubscriptionsIncludeProgressPackets(t *testing.T) {
	progressPayload, err := marshalAuthenticatedEnvelope(envelope{Type: envelopeProgress, Progress: newPeerProgress(1, 1, 1)}, externalPeerControlAuth{})
	if err != nil {
		t.Fatal(err)
	}
	if !isProgressPayload(progressPayload) {
		t.Fatal("isProgressPayload = false")
	}
}

func TestSenderProgressCallbackReceivesPeerProgress(t *testing.T) {
	metrics := newExternalTransferMetrics(time.Unix(60, 0))
	var gotBytes int64
	var gotElapsed int64
	consume := externalPeerProgressConsumer(metrics, func(bytesReceived int64, transferElapsedMS int64) {
		gotBytes = bytesReceived
		gotElapsed = transferElapsedMS
	})
	consume(peerProgress{BytesReceived: 4096, TransferElapsedMS: 700, Sequence: 1}, time.Unix(61, 0))
	if gotBytes != 4096 || gotElapsed != 700 {
		t.Fatalf("progress callback got bytes=%d elapsed=%d", gotBytes, gotElapsed)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./pkg/session -run 'TestSendSubscriptionsIncludeProgressPackets|TestSenderProgressCallbackReceivesPeerProgress' -count=1
```

Expected: FAIL because sender progress subscription and consumer do not exist.

- [ ] **Step 3: Add session progress callback fields**

In `pkg/session/types.go`, add to `SendConfig` and `OfferConfig`:

```go
Progress func(bytesReceived int64, transferElapsedMS int64)
```

- [ ] **Step 4: Subscribe sender to progress packets**

In `externalDirectUDPSendSubscriptions`, add:

```go
progressCh          <-chan derpbind.Packet
unsubscribeProgress func()
```

Close it in `Close()`:

```go
if s.unsubscribeProgress != nil {
	s.unsubscribeProgress()
}
```

In `subscribeExternalDirectUDPSend`, add:

```go
progressCh, unsubscribeProgress := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
	return pkt.From == listenerDERP && isProgressPayload(pkt.Payload)
})
```

Return it in the struct.

- [ ] **Step 5: Add sender progress consumer**

Add helper in `pkg/session/external_direct_udp.go`:

```go
func externalPeerProgressConsumer(metrics *externalTransferMetrics, callback func(int64, int64)) func(peerProgress, time.Time) {
	return func(progress peerProgress, at time.Time) {
		if metrics != nil {
			metrics.RecordPeerProgress(progress.BytesReceived, progress.TransferElapsedMS, at)
		}
		if callback != nil {
			callback(progress.BytesReceived, progress.TransferElapsedMS)
		}
	}
}

func watchPeerProgress(ctx context.Context, ch <-chan derpbind.Packet, auth externalPeerControlAuth, consume func(peerProgress, time.Time)) error {
	var lastSequence uint64
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				return net.ErrClosed
			}
			progress, handled, err := verifyPeerProgressPacket(pkt, auth, &lastSequence)
			if handled {
				continue
			}
			if err != nil {
				return err
			}
			if consume != nil {
				consume(progress, time.Now())
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
```

Start the watcher in `externalDirectUDPSendRuntime.run` after `withPeerControl` is active. Use the current metrics from context:

```go
progressCtx, stopProgress := context.WithCancel(ctx)
defer stopProgress()
progressErrCh := make(chan error, 1)
go func() {
	progressErrCh <- watchPeerProgress(progressCtx, rt.subs.progressCh, rt.auth, externalPeerProgressConsumer(externalTransferMetricsFromContext(ctx), rt.cfg.Progress))
}()
defer func() {
	stopProgress()
	select {
	case <-progressErrCh:
	case <-time.After(time.Second):
	}
}()
```

- [ ] **Step 6: Run tests**

Run:

```bash
go test ./pkg/session -run 'TestSendSubscriptionsIncludeProgressPackets|TestSenderProgressCallbackReceivesPeerProgress' -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/session/types.go pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go
git commit -m "session: consume receiver progress acknowledgements"
```

---

### Task 5: Emit Receiver Progress ACKs

**Files:**
- Modify: `pkg/session/counting.go`
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Write failing progress emitter test**

Add this test to `pkg/session/external_direct_udp_test.go`:

```go
func TestPeerProgressTickerPayloadUsesFirstByteElapsed(t *testing.T) {
	start := time.Unix(70, 0)
	firstByte := start.Add(2 * time.Second)
	progress := peerProgressForTransfer(4096, firstByte, firstByte.Add(750*time.Millisecond), 3)
	if progress.BytesReceived != 4096 {
		t.Fatalf("BytesReceived = %d, want 4096", progress.BytesReceived)
	}
	if progress.TransferElapsedMS != 750 {
		t.Fatalf("TransferElapsedMS = %d, want 750", progress.TransferElapsedMS)
	}
	if progress.Sequence != 3 {
		t.Fatalf("Sequence = %d, want 3", progress.Sequence)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./pkg/session -run TestPeerProgressTickerPayloadUsesFirstByteElapsed -count=1
```

Expected: FAIL because `peerProgressForTransfer` does not exist.

- [ ] **Step 3: Add receiver progress ticker helper**

Add helpers:

```go
var peerProgressInterval = 500 * time.Millisecond

func peerProgressForTransfer(bytesReceived int64, firstByteAt time.Time, now time.Time, sequence uint64) peerProgress {
	elapsed := int64(0)
	if !firstByteAt.IsZero() && now.After(firstByteAt) {
		elapsed = now.Sub(firstByteAt).Milliseconds()
	}
	return *newPeerProgress(bytesReceived, elapsed, sequence)
}

func sendPeerProgressLoop(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesReceived func() int64, firstByteAt func() time.Time, auth externalPeerControlAuth) {
	ticker := time.NewTicker(peerProgressInterval)
	defer ticker.Stop()
	var sequence uint64
	for {
		select {
		case now := <-ticker.C:
			if firstByteAt == nil || firstByteAt().IsZero() {
				continue
			}
			sequence++
			progress := peerProgressForTransfer(bytesReceived(), firstByteAt(), now, sequence)
			_ = sendPeerProgress(ctx, client, peerDERP, progress.BytesReceived, progress.TransferElapsedMS, progress.Sequence, auth)
		case <-ctx.Done():
			return
		}
	}
}
```

- [ ] **Step 4: Add first-byte timestamp to counted receiver writes**

In `pkg/session/counting.go`, add `time` to imports and extend the writer:

```go
type byteCountingWriteCloser struct {
	dst               io.WriteCloser
	n                 atomic.Int64
	firstByteUnixNano atomic.Int64
}
```

Update `Write`:

```go
func (w *byteCountingWriteCloser) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n > 0 {
		w.firstByteUnixNano.CompareAndSwap(0, time.Now().UnixNano())
		w.n.Add(int64(n))
	}
	return n, err
}
```

Add:

```go
func (w *byteCountingWriteCloser) FirstByteAt() time.Time {
	if w == nil {
		return time.Time{}
	}
	nanos := w.firstByteUnixNano.Load()
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos)
}
```

- [ ] **Step 5: Wire receiver runtime to send progress**

In `externalDirectUDPListenRuntime.receiveAccepted`, start the loop after `countedDst` is created:

```go
progressCtx, stopProgress := context.WithCancel(ctx)
defer stopProgress()
go sendPeerProgressLoop(progressCtx, rt.session.derp, accepted.peerDERP, countedDst.Count, countedDst.FirstByteAt, rt.auth)
```

- [ ] **Step 6: Run focused tests**

Run:

```bash
go test ./pkg/session -run 'TestPeerProgressTickerPayloadUsesFirstByteElapsed|TestExternalTransferMetricsUsesPeerProgressForSenderAppBytes' -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/session/counting.go pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go
git commit -m "session: emit receiver transfer progress"
```

---

### Task 6: Make Sender CLI Progress Receiver-Anchored

**Files:**
- Modify: `pkg/derphole/progress.go`
- Modify: `pkg/derphole/progress_test.go`
- Modify: `pkg/derphole/transfer.go`
- Modify: `pkg/derphole/transfer_test.go`

- [ ] **Step 1: Write failing progress reporter test**

Add this test to `pkg/derphole/progress_test.go`:

```go
func TestProgressReporterSetUsesExternalElapsedForRate(t *testing.T) {
	start := time.Unix(0, 0)
	now := start
	prevProgressNow := progressNow
	progressNow = func() time.Time { return now }
	t.Cleanup(func() { progressNow = prevProgressNow })

	var out bytes.Buffer
	progress := NewProgressReporter(&out, 1000*1024*1024)
	progress.SetWithElapsed(100*1024*1024, 10*time.Second)
	got := out.String()
	if !strings.Contains(got, "10.0MiB/s") {
		t.Fatalf("progress output = %q, want receiver-anchored rate 10.0MiB/s", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./pkg/derphole -run TestProgressReporterSetUsesExternalElapsedForRate -count=1
```

Expected: FAIL because `SetWithElapsed` does not exist.

- [ ] **Step 3: Add externally settable progress**

In `ProgressReporter`, add:

```go
externalElapsed time.Duration
externalRate    bool
```

Add method:

```go
func (p *ProgressReporter) SetWithElapsed(current int64, elapsed time.Duration) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if current < 0 {
		current = 0
	}
	if current > p.total {
		current = p.total
	}
	p.current = current
	p.externalElapsed = elapsed
	p.externalRate = elapsed > 0
	now := progressNow()
	callback := p.callbackLocked(now)
	if p.shouldRenderLocked(now) {
		p.lastRender = now
		p.renderLocked(false, now)
	}
	p.mu.Unlock()
	callback.emit()
}
```

Update `rateLocked`:

```go
if p.externalRate && p.externalElapsed > 0 {
	return float64(p.current) / p.externalElapsed.Seconds()
}
```

Keep the existing local smoothed rate path for local progress mode.

- [ ] **Step 4: Write failing sender transfer test**

Add to `pkg/derphole/transfer_test.go`:

```go
func TestSendSessionProgressFollowsPeerReceivedPayloadBytes(t *testing.T) {
	prev := derpholeSessionSend
	t.Cleanup(func() { derpholeSessionSend = prev })

	derpholeSessionSend = func(_ context.Context, cfg session.SendConfig) error {
		if cfg.Progress == nil {
			t.Fatal("session SendConfig.Progress = nil")
		}
		_, _ = io.Copy(io.Discard, cfg.StdioIn)
		header := protocol.Header{
			Version: 1,
			Kind:    protocol.KindFile,
			Name:    "payload.bin",
			Size:    1024 * 1024,
			Verify:  VerificationString(cfg.Token),
		}
		headerBytes, err := protocol.HeaderWireSize(header)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Progress(headerBytes+512*1024, 1000)
		return context.DeadlineExceeded
	}

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "payload.bin")
	if err := os.WriteFile(srcPath, bytes.Repeat([]byte("z"), 1024*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err := token.Encode(token.Token{
		Version:      token.SupportedVersion,
		ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
		Capabilities: token.CapabilityStdio,
	})
	if err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	_ = Send(context.Background(), SendConfig{
		Token:          tok,
		What:           srcPath,
		Stderr:         &stderr,
		ProgressOutput: &stderr,
	})
	if strings.Contains(stderr.String(), "100%|") {
		t.Fatalf("stderr = %q, want sender progress not to finish from local drain", stderr.String())
	}
	if !strings.Contains(stderr.String(), "50%|") {
		t.Fatalf("stderr = %q, want peer-received payload progress near 50%%", stderr.String())
	}
}
```

- [ ] **Step 5: Run sender transfer test to verify it fails**

Run:

```bash
go test ./pkg/derphole -run TestSendSessionProgressFollowsPeerReceivedPayloadBytes -count=1
```

Expected: FAIL because sender progress is still local-read based and `session.SendConfig.Progress` is unset.

- [ ] **Step 6: Pass session progress callback from sender**

In `sendViaSession` and `offerTransfer`, after `tx.header.Verify` is set, compute:

```go
headerBytes, err := protocol.HeaderWireSize(tx.header)
if err != nil {
	return err
}
progress := NewProgressReporter(cfg.ProgressOutput, tx.progressTotal)
sessionProgress := senderPeerPayloadProgress(progress, headerBytes, tx.progressTotal)
```

Add helper:

```go
func senderPeerPayloadProgress(progress *ProgressReporter, headerBytes int64, total int64) func(int64, int64) {
	return func(sessionBytes int64, transferElapsedMS int64) {
		if progress == nil || total < 0 {
			return
		}
		payloadBytes := sessionBytes - headerBytes
		if payloadBytes < 0 {
			payloadBytes = 0
		}
		if payloadBytes > total {
			payloadBytes = total
		}
		progress.SetWithElapsed(payloadBytes, time.Duration(transferElapsedMS)*time.Millisecond)
	}
}
```

Replace `writeTransferWithProgress` usage in session-backed send paths with a variant that writes the header and body without wrapping the body in local progress. Keep local progress wrapping for non-session paths if any existing path still relies on it.

In session config:

```go
Progress: sessionProgress,
```

- [ ] **Step 7: Run derphole tests**

Run:

```bash
go test ./pkg/derphole -run 'TestProgressReporterSetUsesExternalElapsedForRate|TestSendSessionProgressFollowsPeerReceivedPayloadBytes|TestSendDoesNotFinishProgressWhenSessionFailsAfterDrainingInput' -count=1
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add pkg/derphole/progress.go pkg/derphole/progress_test.go pkg/derphole/transfer.go pkg/derphole/transfer_test.go
git commit -m "derphole: anchor sender progress to receiver"
```

---

### Task 7: Tighten Direct Status Semantics

**Files:**
- Modify: `pkg/session/types.go`
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_direct_udp_test.go`
- Modify: `pkg/session/session_test.go`

- [ ] **Step 1: Write failing direct-status tests**

Add tests:

```go
func TestDirectFallbackDoesNotEmitConnectedDirect(t *testing.T) {
	var status bytes.Buffer
	emitter := telemetry.New(&status, telemetry.LevelVerbose)
	pathEmitter := newTransportPathEmitter(emitter)
	pathEmitter.Emit(StateRelay)
	pathEmitter.Emit(StateTryingDirect)
	pathEmitter.Emit(StateDirectFallbackRelay)
	got := status.String()
	if strings.Contains(got, string(StateDirect)+"\n") {
		t.Fatalf("status = %q, want no connected-direct", got)
	}
	if !strings.Contains(got, string(StateTryingDirect)) || !strings.Contains(got, string(StateDirectFallbackRelay)) {
		t.Fatalf("status = %q, want trying-direct and direct-fallback-relay", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./pkg/session -run TestDirectFallbackDoesNotEmitConnectedDirect -count=1
```

Expected: FAIL because new states do not exist or direct status is emitted too early.

- [ ] **Step 3: Add strict states**

In `pkg/session/types.go`, add:

```go
StateTryingDirect        State = "trying-direct"
StateDirectFallbackRelay State = "direct-fallback-relay"
```

Add `Emit` use cases through `transportPathEmitter.Emit`.

- [ ] **Step 4: Move `connected-direct` emission to validation points**

In direct UDP send/receive paths:

- Emit `StateTryingDirect` before ready/start/rate probing begins.
- Call `metrics.MarkDirectValidated(time.Now())` and emit `StateDirect` only when:
  - rate probe result contains at least one sample with `BytesReceived > 0`, or
  - direct send/receive progress stats report `BytesSent > 0` or `BytesReceived > 0`.
- On `errExternalDirectUDPNoRateProbePackets` or any relay fallback from direct prep, call:

```go
metrics.SetFallbackReason(err.Error(), time.Now())
pathEmitter.Emit(StateDirectFallbackRelay)
```

Keep transport manager path watching from emitting `StateDirect` prematurely by leaving watcher direct suppressed until validation.

- [ ] **Step 5: Run direct status tests**

Run:

```bash
go test ./pkg/session -run 'TestDirectFallbackDoesNotEmitConnectedDirect|TestDirectUDPHandshakePayloadsAreControl|TestSendExternalViaRelayPrefixThenDirectUDPFallsBackToRelayWhenPostHandoffPrepareFails' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/session/types.go pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go pkg/session/session_test.go
git commit -m "session: report direct only after validation"
```

---

### Task 8: Add Trace Checker Gates

**Files:**
- Modify: `pkg/transfertrace/checker.go`
- Modify: `pkg/transfertrace/checker_test.go`
- Modify: `tools/transfertracecheck/main.go`

- [ ] **Step 1: Write failing checker tests**

Add to `pkg/transfertrace/checker_test.go`:

```go
func TestCheckFailsConnectedDirectWithoutValidation(t *testing.T) {
	csvText := HeaderLine + "\n" +
		"1000,0,send,relay,1024,0,1024,1024,0.00,2048,1024,500,500,false,,,"
	csvText += ",,,,,,,,,connected-direct,\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleSend})
	if err == nil || !strings.Contains(err.Error(), "connected-direct without direct validation") {
		t.Fatalf("Check() error = %v, want direct validation failure", err)
	}
}

func TestCheckAllowsDirectFallbackRelayReason(t *testing.T) {
	row := "1000,0,send,complete,1048576,0,1048576,1048576,0.00,1048576,1048576,100,100,false,direct UDP rate probes received no packets,,,,,,,,,,stream-complete,\n"
	_, err := Check(strings.NewReader(HeaderLine+"\n"+row), Options{Role: RoleSend, ExpectedBytes: 1048576})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./pkg/transfertrace -run 'TestCheckFailsConnectedDirectWithoutValidation|TestCheckAllowsDirectFallbackRelayReason' -count=1
```

Expected: FAIL until checker parses new columns and applies direct validation logic.

- [ ] **Step 3: Parse new columns and validate**

In `checkerIndexes`, add optional indexes:

```go
peerReceivedBytes int
directValidated   int
fallbackReason    int
```

Use optional lookup so old timestamp alias tests still pass:

```go
optional := func(name string) int {
	if i, ok := positions[name]; ok {
		return i
	}
	return -1
}
```

In `checkerRow`, add:

```go
peerReceivedBytes int64
directValidated   bool
fallbackReason    string
lastState         string
```

In `consume`, reject:

```go
if row.lastState == "connected-direct" && !row.directValidated {
	return fmt.Errorf("row %d: connected-direct without direct validation", row.rowNo)
}
if row.lastState == "direct-fallback-relay" && row.fallbackReason == "" {
	return fmt.Errorf("row %d: direct-fallback-relay missing fallback reason", row.rowNo)
}
```

Add CLI flags in `tools/transfertracecheck/main.go` for later pairwise checks:

```go
peerTrace := flag.String("peer-trace", "", "optional peer trace CSV for sender peer_received_bytes to receiver app_bytes comparison")
rateTolerance := flag.Float64("rate-tolerance", 0.10, "allowed sender/receiver transfer rate divergence")
```

Implement pairwise checks after single-trace `Check` if `-peer-trace` is set.

- [ ] **Step 4: Run checker tests**

Run:

```bash
go test ./pkg/transfertrace ./tools/transfertracecheck -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/transfertrace/checker.go pkg/transfertrace/checker_test.go tools/transfertracecheck/main.go
git commit -m "tracecheck: require validated direct status"
```

---

### Task 9: Extend Harness And Docs

**Files:**
- Modify: `scripts/transfer-stall-harness.sh`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Update harness checker calls**

In `scripts/transfer-stall-harness.sh`, replace separate final checker calls with paired checks:

```bash
mise exec -- go run ./tools/transfertracecheck -role send -stall-window "${trace_stall_window}" -peer-trace "${log_dir}/receiver/receive.trace.csv" "${log_dir}/sender/send.trace.csv"
mise exec -- go run ./tools/transfertracecheck -role receive -stall-window "${trace_stall_window}" "${log_dir}/receiver/receive.trace.csv"
```

Make the same change in the expected-stall integrity path, keeping the larger integrity stall window.

- [ ] **Step 2: Add harness output evidence**

After checker success, add:

```bash
sender_direct_validated="$(awk -F, 'NR>1 && $0 ~ /connected-direct/ && $0 ~ /,true,/ { found=1 } END { print found+0 }' "${log_dir}/sender/send.trace.csv")"
sender_fallback_reason="$(awk -F, 'NR>1 && $0 ~ /direct-fallback-relay/ { print; exit }' "${log_dir}/sender/send.trace.csv")"
echo "sender-direct-validated=${sender_direct_validated}"
if [[ -n "${sender_fallback_reason}" ]]; then
  echo "sender-direct-fallback-seen=true"
fi
```

- [ ] **Step 3: Document new trace semantics**

In `docs/benchmarks.md`, update “Transfer Stall Traces” with:

```markdown
Sender `app_bytes` are receiver-confirmed session stream bytes once progress ACKs start. `local_sent_bytes` records sender-side enqueue/spool progress and can be ahead of receiver progress. Use `transfer_elapsed_ms` for throughput comparisons; `session_elapsed_ms` includes setup and direct probing time.

`connected-direct` means direct UDP has delivered probe or payload bytes. A run that attempts direct but falls back to relay records `direct-fallback-relay` and a non-empty `fallback_reason`.
```

- [ ] **Step 4: Run shell syntax and checker tests**

Run:

```bash
bash -n scripts/transfer-stall-harness.sh
go test ./pkg/transfertrace ./tools/transfertracecheck -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/transfer-stall-harness.sh docs/benchmarks.md
git commit -m "scripts: gate receiver-anchored transfer traces"
```

---

### Task 10: Full Verification And Live Tests

**Files:**
- No source edits unless a previous task fails and reveals a bug.

- [ ] **Step 1: Run focused package tests**

Run:

```bash
go test ./pkg/transfertrace ./pkg/session ./pkg/derphole -count=1
```

Expected: PASS.

- [ ] **Step 2: Run repository gate**

Run:

```bash
mise run check
```

Expected: PASS.

- [ ] **Step 3: Run 1 GiB live test to `hetz`**

Run:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh local root@hetz 1024
```

Expected:

- SHA and size match.
- `transfertracecheck` passes sender and receiver traces.
- Sender `peer_received_bytes` tracks receiver `app_bytes`.
- `connected-direct` appears only if `direct_validated=true`.
- If direct fails, trace shows `direct-fallback-relay` with non-empty `fallback_reason`.

- [ ] **Step 4: Run 1 GiB live test to `canlxc`**

Run:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh local root@canlxc 1024
```

Expected: same as `hetz`.

- [ ] **Step 5: Probe relay endpoint if DERP DNS works**

Run:

```bash
ssh exedev@ion-rain.exe.xyz 'getent hosts derp1c.tailscale.com && curl -m 5 -I https://derp1c.tailscale.com/derp/probe'
```

Expected: DNS and HTTPS probe succeed. If they fail, record the failure and skip relay-endpoint live validation.

- [ ] **Step 6: Check cleanup**

Run:

```bash
pgrep -x derphole || true
ssh root@hetz 'pgrep -x derphole || true'
ssh root@canlxc 'pgrep -x derphole || true'
```

Expected: no benchmark `derphole` processes remain.

- [ ] **Step 7: Confirm branch state**

Run:

```bash
git status --short --branch
```

Expected: branch is ahead of `origin/main` by the implementation commits and has no uncommitted files.

- [ ] **Step 8: Push and watch CI**

Run:

```bash
git status --short --branch
git push
gh run list --branch main --limit 5
```

Expected: push succeeds and latest `Checks`, `Release`, and `Pages` workflows complete successfully.

---

## Plan Self-Review

- Spec coverage: progress semantics are covered by Tasks 2, 4, 5, and 6; transfer clocks by Tasks 1, 2, 5, and 6; direct status semantics by Tasks 7 and 8; trace/harness gates by Tasks 8 and 9; live validation by Task 10.
- Placeholder scan: no placeholder sections remain. Each code-changing task includes concrete tests, implementation snippets, commands, and expected results.
- Type consistency: progress ACK fields use `BytesReceived`, `TransferElapsedMS`, and `Sequence` consistently across envelope, metrics, sender consumer, and receiver emitter. Trace fields use `LocalSentBytes`, `PeerReceivedBytes`, `SetupElapsedMS`, `TransferElapsedMS`, `DirectValidated`, and `FallbackReason` consistently with CSV column names.
