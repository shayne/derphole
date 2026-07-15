# Public UDP Peak Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make derphole prove exactly three 3 GiB normal-file transfers in each direction over public UDP, with every accepted run above 2.0 Gbps on the exact two-vCPU Hetzner VM and every payload byte attributed to QUIC or custom bulk.

**Architecture:** Preserve DERP rendezvous and the existing authenticated UDP formats. Add receiver-owned carrier accounting, reduce grouped source reads, move Linux bulk data sockets to a verified connected native `sendmmsg`/GSO path, and select one production default through a deterministic capacity-bracketed campaign. A checked-in decision tool and staged harness enforce the 1 GiB prerequisites, fleet guard, disk-safe 3 GiB ordering, and hard-ceiling alternative without allowing TCP to satisfy acceptance.

**Tech Stack:** Go 1.26, `net.PacketConn`, `syscall.RawConn`, Linux `connect(2)`, `sendmmsg(2)`, UDP GSO, quic-go qlog and connection statistics, CSV transfer traces, JSON decision artifacts, Bash, Python 3, `iperf3`, `mise`, and GitButler.

## Global Constraints

- Use ordinary files through `send FILE` and `receive TOKEN`.
- Acceptance requires exactly three accepted 3 GiB transfers in each direction; every run must exceed 2.0 Gbps receiver-anchored goodput.
- Every accepted file byte must be committed by `bulk-packets-v1` or `quic-blocks-v1` over public UDP. TCP port 8123 is capacity control only.
- Use the exact Hetzner VM with exactly two online CPUs and make no kernel, sysctl, NIC, qdisc, service, package, CPU, memory, swap, or other host changes.
- Preserve DERP rendezvous, NAT traversal, hole punching, and production Tailscale candidate discovery. Benchmark runs may reject Tailscale-selected payload addresses.
- Do not start a 3 GiB transfer until the exact production binaries have three fresh capacity-valid 1 GiB samples above 2.0 Gbps in both directions.
- A started capacity-valid transfer is never discarded or replaced as an outlier.
- Keep queues bounded, verify exact size and SHA-256, and remove only harness-owned payloads, processes, sockets, and directories.
- Probe every canonical test host without installing anything. Run Eric last, sequentially, and stop using it for the session after disappearance, reboot, OOM, severe pressure, kernel error, or cleanup failure.
- If the 1 GiB gate cannot pass, do not run 3 GiB acceptance. Produce the approved hard-ceiling evidence while leaving the acceptance objective explicitly unmet.
- Use GitButler for branch, commit, and history writes. Before each checkpoint, run `but diff` and commit only the task's file IDs to `codex/framed-file-acceptance`.

## File Structure

### Existing files to modify

- `pkg/transfertrace/trace.go`: authoritative CSV schema for engine, committed payload, selected lanes, bulk-native counters, and QUIC recovery counters.
- `pkg/transfertrace/checker.go`: exact per-trace and paired-trace carrier validation.
- `tools/transfertracecheck/main.go`: CLI operands used by the campaign harness.
- `pkg/session/external_transfer_metrics.go`: session-to-trace state and receiver-owned file commit accounting.
- `pkg/session/external_v2_block.go`: QUIC and bulk file-engine selection and per-sink-write committed-byte publication.
- `pkg/session/external_v2_bulk_packet_grouped.go`: sixteen-group coalesced source reads.
- `pkg/session/external_v2_bulk_packet_batch.go`: platform-neutral batch contract and aggregate mechanism counters.
- `pkg/session/external_v2_bulk_packet_batch_linux.go`: Linux receive path and addressed fallback.
- `pkg/session/external_v2_bulk_packet_batch_darwin.go`: compatible expected-peer method signature.
- `pkg/session/external_v2_bulk_packet.go`: spare-control-socket activation and sender diagnostics.
- `pkg/directquic/endpoint.go`, `pkg/dataplane/types.go`, `pkg/dataplane/quic.go`, and `pkg/quicpath/metrics_tracer.go`: in-process QUIC transport evidence.
- `scripts/promotion-benchmark-driver.sh`: one normal-file transfer with exact artifacts and optional harness-owned output retention.
- `scripts/udp-file-acceptance.sh`: production-prerequisite binding and disk-safe six-run acceptance.
- `.mise.toml` and `docs/benchmarks.md`: stable entrypoints and operator contract.

### New focused files

- `pkg/session/external_v2_bulk_packet_candidate.go`: linker-injected benchmark candidate identity; no CLI or environment tuning.
- `pkg/session/external_v2_bulk_packet_peer_linux.go`: binary peer conversion, connect, getpeername verification, and disconnect.
- `pkg/session/external_v2_bulk_packet_send_linux.go`: connected native non-GSO and GSO send preparation/syscalls.
- `pkg/udpbenchproof/artifact.go`: immutable no-replace JSON writes, SHA-256 identities, and artifact verification.
- `pkg/udpbenchproof/model.go`: manifest, sample, schedule, health, identity, fleet, prerequisite, and acceptance schemas.
- `pkg/udpbenchproof/schedule.go`: deterministic screening, preliminary, finalist, production, fleet, ceiling, and acceptance schedules.
- `pkg/udpbenchproof/decision.go`: stage gates, statistics, pairwise comparison, artifact binding, and prerequisite validation.
- `pkg/udpbenchproof/scc.go`: deterministic strongly connected peak frontier.
- `tools/udppeak/main.go`: `manifest-create`, `validate`, `schedule`, `sample-validate`, `evaluate`, `verify-prerequisite`, and `artifact-verify` commands.
- `scripts/udp-peak-candidates.sh`: immutable candidate-pair builder and registry.
- `scripts/udp-peak-performance.sh`: safe staged campaign orchestrator.
- `scripts/udp-file-production-gate.sh`: exact six-sample fresh 1 GiB production prerequisite.
- `scripts/public-path-hosts.json`: checked-in canonical host names and Eric watchdog ordering, without addresses or private metadata.

---

### Task 1: Bind file bytes to the negotiated UDP engine and selected public lanes

**Files:**
- Modify: `pkg/transfertrace/trace.go`
- Modify: `pkg/transfertrace/trace_test.go`
- Modify: `pkg/transfertrace/checker.go`
- Modify: `pkg/transfertrace/checker_test.go`
- Modify: `tools/transfertracecheck/main.go`
- Modify: `tools/transfertracecheck/main_test.go`
- Modify: `pkg/session/external_transfer_metrics.go`
- Modify: `pkg/session/external_transfer_metrics_test.go`
- Modify: `pkg/session/external_v2_block.go`
- Modify: `pkg/session/external_v2_block_test.go`
- Modify: `pkg/session/external_v2_bulk_packet.go`
- Modify: `pkg/session/external_v2_bulk_packet_test.go`
- Modify: `pkg/session/external_v2_bulk_packet_async_writer.go`
- Modify: `pkg/session/external_v2_bulk_packet_batched_receiver_test.go`
- Modify: `pkg/session/external_v2_bulk_packet_grouped_test.go`

**Interfaces:**
- Consumes: existing `transfertrace.Snapshot`, `externalTransferMetrics`, `receiveExternalV2BlockStreams`, `receiveExternalV2BulkBlockPacketsWithProbe`, and selected `externalV2DirectPacketPath.addrs`.
- Produces: receiver-owned exact file counters, sender/receiver engine agreement, and literal selected-lane verification used by every later harness task.

- [ ] **Step 1: Write failing trace and checker tests**

Add `FilePayloadEngine` and table tests that require a receiver's chosen engine counter to equal the expected file size, require the other engine counter to remain zero, reject a private or unexpected selected address, and reject sender/receiver engine disagreement:

Required cases are `TestTraceRecordsFilePayloadEngineCounters`, `TestExternalTransferMetricsRecordsReceiverOwnedBulkPayload`, `TestExternalTransferMetricsRecordsReceiverOwnedQUICPayload`, `TestExternalTransferMetricsSenderDoesNotSynthesizeCommittedPayload`, `TestExternalV2BlockReceiveCountsOnlyCommittedQUICPayload`, `TestExternalV2BulkPacketReceiverCountsOnlyAuthenticatedCommittedPayload`, `TestExternalV2BulkPacketAsyncWriterDoesNotCountFailedWrite`, `TestCheckPairRejectsEngineDisagreement`, `TestCheckRejectsUnexpectedOrNonPublicLane`, and `TestRunPairedSenderAppliesExpectedPayloadToReceiver`.

```go
func TestCheckRequiresExactReceiverFilePayloadAccounting(t *testing.T) {
	trace := testTraceWithFilePayload(RoleReceive, "bulk-packets-v1", 3<<30, 3<<30, 0, `["203.0.113.10:41000"]`)
	result, err := Check(strings.NewReader(trace), Options{
		Role: RoleReceive, ExpectedPayloadBytes: 3 << 30, ExpectedPayloadBytesSet: true,
		RequireFilePayloadEngine: FilePayloadEngineBulk, ExpectedSelectedPublicIPv4: "203.0.113.10",
	})
	if err != nil || result.FinalFilePayloadBytes != 3<<30 {
		t.Fatalf("result=%+v error=%v", result, err)
	}
}

func TestCheckPairRejectsFilePayloadEngineDisagreement(t *testing.T) {
	send := testTraceWithFilePayload(RoleSend, "quic-blocks-v1", 0, 0, 0, `["203.0.113.10:41000"]`)
	receive := testTraceWithFilePayload(RoleReceive, "bulk-packets-v1", 4096, 4096, 0, `["198.51.100.20:42000"]`)
	if _, err := CheckPair(strings.NewReader(send), strings.NewReader(receive), PairOptions{Role: RoleSend}); err == nil {
		t.Fatal("engine disagreement accepted")
	}
}
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```bash
mise exec -- go test ./pkg/transfertrace ./tools/transfertracecheck \
  -run 'Test.*(FilePayload|PayloadPublic|EngineDisagreement)' -count=1
```

Expected: FAIL because the file-payload columns, options, and CLI operands do not exist.

- [ ] **Step 3: Add the trace schema and exact validation**

Add these definitions and columns to `pkg/transfertrace/trace.go`:

```go
type FilePayloadEngine string

const (
	FilePayloadEngineBulk FilePayloadEngine = "bulk-packets-v1"
	FilePayloadEngineQUIC FilePayloadEngine = "quic-blocks-v1"
)

func (e FilePayloadEngine) Valid() bool {
	return e == FilePayloadEngineBulk || e == FilePayloadEngineQUIC
}

func ParseFilePayloadEngine(string) (FilePayloadEngine, error)

// Snapshot fields, emitted as ordinary non-optional decimal counters.
FilePayloadEngine         FilePayloadEngine
FilePayloadBytesCommitted int64
FilePayloadBytesBulk      int64
FilePayloadBytesQUIC      int64
FilePayloadLaneAddresses string // JSON array, never a delimiter-joined address list
```

Extend checker options and result:

```go
type Options struct {
	Role                     Role
	StallWindow              time.Duration
	ExpectedBytes            int64
	ExpectedBytesSet         bool
	ExpectedPayloadBytes     int64
	ExpectedPayloadBytesSet  bool
	RequireDirectTransport   string
	RequireFilePayloadEngine FilePayloadEngine
	RequireEngineTelemetry   bool
	ExpectedSelectedPublicIPv4 string
	ForbidRelayPayload       bool
}

type Result struct {
	Rows                  int
	FinalAppBytes         int64
	FinalFilePayloadBytes int64
	FinalFilePayloadEngine FilePayloadEngine
	FinalFilePayloadBytesBulk int64
	FinalFilePayloadBytesQUIC int64
	FinalFilePayloadLaneAddresses []string
	FinalPhase            Phase
	MaxFlatline           time.Duration
	Diagnostics           DiagnosticsSummary
}
```

Track an explicit observed-column set so a present healthy zero is distinct from a missing field. At `finish`, require a valid engine when an engine is requested. For receive traces require `bulk+quic == committed == ExpectedPayloadBytes`; require exactly the selected engine counter to equal the expected value. Sender traces require the selected engine but require all three receiver-owned counters to remain exactly zero. Decode `file_payload_lane_addrs` as a JSON array, parse every entry with `netip.ParseAddrPort`, require at least one unique lane, and require every lane IP to equal `ExpectedSelectedPublicIPv4`; reject malformed, duplicate, private, link-local, CGNAT/Tailscale, ULA, multicast, or unexpected values. In `CheckPair`, require identical valid engine values.

Expose matching CLI flags:

```text
-expected-payload-bytes N
-require-file-payload-engine bulk-packets-v1|quic-blocks-v1
-require-engine-telemetry
-expected-selected-public-ipv4 A.B.C.D
-peer-expected-selected-public-ipv4 A.B.C.D
```

Keep `-expected-bytes` exclusively for framed application bytes. In paired CLI mode, propagate `-expected-payload-bytes`, the required engine/telemetry policy, and the peer-specific public IPv4 to the receiver check; never reuse the sender's address expectation for its peer.

- [ ] **Step 4: Publish receiver-owned counters only after authenticated sink commits**

Add these methods to `externalTransferMetrics`:

```go
func (m *externalTransferMetrics) SelectFilePayloadEngine(engine transfertrace.FilePayloadEngine, at time.Time)
func (m *externalTransferMetrics) SetFilePayloadLaneAddrs(addrs []net.Addr, at time.Time) error
func (m *externalTransferMetrics) RecordFilePayloadCommit(engine transfertrace.FilePayloadEngine, n int64, at time.Time)
```

Select bulk on the sender immediately after its capacity probe succeeds (or immediately before payload when no probe is used), and on the receiver after authenticated run-ID/probe acceptance but before payload readers start. Select QUIC in `copyExternalV2SendBlockStreams` and `receiveExternalV2BlockStreams` only after the streams open successfully. This ordering guarantees fallback-before-payload records QUIC rather than bulk.

Increment QUIC committed bytes in `externalV2BlockReceiveTracker.writeChunk` only after `sink.WriteAt` returns the exact plaintext length. Increment bulk committed bytes only after authenticated decrypt and successful sink commit in `handleDataResult`, `handleDataBatch`, `handleGroupedDataResultAt`, `handleDataResultAt`, and, for queued extents, only inside `externalV2BulkPacketAsyncWriter.run` after `WriteAt` succeeds. Failed, short, duplicate, unauthenticated, queued-but-unwritten, framing, ACK, repair-control, and session-control bytes do not count.

Remove `diagnosticsForDirectStatsLocked` as a source for these fields: its generic `stats.BytesReceived` may remain a progress diagnostic but must never synthesize file-sink commit. Sender traces set engine and lane addresses but all receiver-owned counters remain zero.

- [ ] **Step 5: Run proof tests and commit**

Run:

```bash
mise exec -- go test ./pkg/transfertrace ./tools/transfertracecheck -count=1
mise exec -- go test ./pkg/session -run 'Test.*(FilePayload|PayloadLane|CommittedQUIC|AuthenticatedCommitted|AsyncWriterDoesNotCount)' -count=1
```

Expected: PASS with receiver ownership, engine agreement, and literal-lane rejection covered.

Commit:

```text
trace: bind file payload bytes to UDP engines
```

### Task 2: Add in-process QUIC transport and recovery evidence

**Files:**
- Modify: `pkg/quicpath/metrics_tracer.go`
- Modify: `pkg/quicpath/metrics_tracer_test.go`
- Modify: `pkg/quicpath/config.go`
- Modify: `pkg/directquic/endpoint.go`
- Modify: `pkg/directquic/endpoint_test.go`
- Modify: `pkg/dataplane/types.go`
- Modify: `pkg/dataplane/quic.go`
- Modify: `pkg/dataplane/quic_test.go`
- Modify: `pkg/session/external_transfer_metrics.go`
- Modify: `pkg/session/external_transfer_metrics_test.go`
- Modify: `pkg/session/external_v2.go`
- Modify: `pkg/session/external_v2_offer.go`
- Modify: `pkg/session/external_v2_block.go`
- Modify: `pkg/session/external_v2_bulk_packet_batch.go`
- Modify: `pkg/session/external_v2_bulk_packet_batch_linux.go`
- Modify: `pkg/session/external_v2_bulk_packet_batch_darwin.go`
- Modify: `pkg/session/external_v2_bulk_packet_batch_other.go`
- Modify: `pkg/session/external_v2_bulk_packet_batched_sender.go`
- Modify: `pkg/transfertrace/trace.go`
- Modify: `pkg/transfertrace/trace_test.go`
- Modify: `pkg/transfertrace/checker.go`
- Modify: `pkg/transfertrace/checker_test.go`

**Interfaces:**
- Consumes: quic-go `qlog.PacketSent`, `qlog.PacketLost`, `qlog.MetricsUpdated`, and `quic.Conn.ConnectionStats()`.
- Produces: complete, present selected-engine telemetry for both QUIC and bulk, including generic file-source reads, selected lane addresses, connection/stream count, RTT, packets, loss, recovery wire bytes, stream bytes, backend identity, and close reason.

- [ ] **Step 1: Write failing QUIC aggregate tests**

Add tests that feed qlog stream frames with repeated offsets and prove only packets containing previously sent stream ranges on the same connection contribute to recovery wire bytes. Include two producers/connections that reuse the same stream ID and offset; the first packet on connection two must remain initial wire bytes:

```go
func TestQUICMechanismTraceCountsRecoveryPackets(t *testing.T) {
	trace := newQUICMechanismTrace()
	recorder := trace.AddProducer()
	recorder.RecordEvent(qlog.PacketSent{Raw: qlog.RawInfo{Length: 1200}, Frames: []qlog.Frame{{Frame: &qlog.StreamFrame{StreamID: 1, Offset: 0, Length: 1000}}}})
	recorder.RecordEvent(qlog.PacketSent{Raw: qlog.RawInfo{Length: 1200}, Frames: []qlog.Frame{{Frame: &qlog.StreamFrame{StreamID: 1, Offset: 0, Length: 1000}}}})
	got := trace.Snapshot()
	if got.PacketsSent != 2 || got.RecoveryWireBytes != 1200 {
		t.Fatalf("snapshot=%+v", got)
	}
}
```

Extend endpoint/dataplane tests to assert aggregation across multiple connections and add `TestQUICMechanismTraceDoesNotConflateStreamIDsAcrossConnections`.

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```bash
mise exec -- go test ./pkg/quicpath ./pkg/directquic ./pkg/dataplane \
  -run 'Test.*(Mechanism|Recovery|StatsAggregate)' -count=1
```

Expected: FAIL because mechanism snapshots are not attached to endpoints.

- [ ] **Step 3: Implement the in-memory qlog trace and endpoint aggregation**

Add this stable snapshot shape:

```go
type MechanismSnapshot struct {
	Connections       uint32
	Streams           uint32
	PacketsSent       uint64
	PacketsReceived   uint64
	PacketsLost       uint64
	WireBytesSent     uint64
	RecoveryWireBytes uint64
	SmoothedRTT       time.Duration
	HandshakeDuration time.Duration
	FirstByteDuration time.Duration
	StreamBytesSent   uint64
	StreamBytesReceived uint64
	Version           string
	RawSocketBackend  string
	NativeSendBackend string
	NativeReceiveBackend string
	CloseReason       string
	NativeGSO          string // true, false, or unsupported
	NativeReceiveBatch string // true, false, or unsupported
}
```

`quicMechanismTrace.RecordEvent` records packet counts and wire lengths. Track non-overlapping stream intervals per stream ID; a sent packet whose stream frame overlaps an interval already recorded contributes its full `Raw.Length` once to `RecoveryWireBytes`. Keep the existing optional JSON tracer by returning a small multiplex trace that forwards every qlog event to both recorders.

Store the mechanism trace on each `directquic.Endpoint`, add current `ConnectionStats()` values at `Stats()`, and aggregate every endpoint in `dataplane.convertStats`. Extend `directquic.Stats` and `dataplane.Stats` with QUIC version, connection/stream counts, sent/lost packets, initial and retransmitted wire bytes, smoothed RTT, raw socket backend, native send backend, native receive backend, and explicit `true|false|unsupported` native GSO/receive-batch tri-states. `unsupported` is valid only where the platform cannot expose the fact; an empty selected-QUIC field remains invalid.

Preserve existing qlog output by multiplexing rather than replacing it. Feed `PacketSent.Raw.Length` into wire bytes, assign every producer a stable connection identity, and track first-seen stream ranges by `(connection identity, stream ID)` so only repeated ranges on the same QUIC connection count as retransmitted wire bytes. Take loss from `PacketLost` and retain the maximum observed smoothed RTT.

- [ ] **Step 4: Flow QUIC evidence through transfer metrics and trace**

Add trace columns:

```text
quic_connections
quic_streams
quic_telemetry_present
quic_version
quic_raw_socket_backend
quic_native_send_backend
quic_native_receive_backend
quic_handshake_ms
quic_first_byte_ms
quic_smoothed_rtt_ms
quic_packets_sent
quic_packets_received
quic_packets_lost
quic_wire_bytes_sent
quic_recovery_wire_bytes
quic_recovery_ratio
quic_stream_bytes_sent
quic_stream_bytes_received
quic_close_reason
quic_native_gso
quic_native_receive_batch
file_source_read_calls
file_source_read_bytes
file_payload_lane_addrs
```

Add:

```go
func (m *externalTransferMetrics) RecordFileSourceRead(n int, at time.Time)
func (m *externalTransferMetrics) RecordQUICEvidence(stats dataplane.Stats, streamCount int, rawDirect bool, at time.Time)
```

Route every `BlockSource.Payload.ReadAt` used by QUIC and bulk—QUIC block reads, grouped and legacy initial sends, and repair reads—through one recording helper so source read calls and bytes cannot be missed. Record final endpoint evidence immediately before every normal and abnormal endpoint close and before `metrics.Complete`; adding columns alone is insufficient because production currently never reliably publishes `dataplane.Stats` to `externalTransferMetrics`.

`quic_recovery_ratio` is `retransmitted_wire_bytes / max(1, initial_wire_bytes)`. Add an internal presence bit so healthy numeric zeroes serialize when QUIC telemetry is present. Missing selected-QUIC fields are invalid evidence; bulk traces may leave them empty. Require version, raw/native backend, connection and stream counts, handshake/first-byte timing, RTT, sent/lost packets, wire/retransmitted bytes, role-appropriate stream bytes, normal close reason, and native GSO/batch tri-states. Enforce `lost<=sent`, `retransmitted<=wire`, positive connection/stream counts, and role stream bytes at least the expected payload.

- [ ] **Step 5: Run QUIC and trace tests and commit**

Run:

```bash
mise exec -- go test ./pkg/quicpath ./pkg/directquic ./pkg/dataplane -count=1
mise exec -- go test ./pkg/session ./pkg/transfertrace -run 'Test.*QUIC' -count=1
```

Expected: PASS, including normal close, abnormal close, multi-connection aggregation, and healthy zero-loss output.

Commit:

```text
trace: record in-process QUIC recovery evidence
```

### Task 3: Coalesce sixteen grouped source reads

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet_grouped.go`
- Modify: `pkg/session/external_v2_bulk_packet_grouped_test.go`
- Modify: `pkg/session/external_v2_bulk_packet_batched_sender.go`

**Interfaces:**
- Consumes: `externalV2BulkPacketPrepareJob`, `externalV2BulkPacketGroupedPlaintextRange`, and the existing 1,042,944-byte slab input.
- Produces: `externalV2BulkPacketGroupedSlabRange` and one exact `ReadAt` per sixteen-group preparation job.

- [ ] **Step 1: Add failing range/read-count tests**

Add a recording `io.ReaderAt` and these tests:

```go
func TestExternalV2BulkPacketGroupedPrepareSlabReadsFullRangeOnce(t *testing.T) {
	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes*16)
	reader := &recordingReaderAt{ReaderAt: bytes.NewReader(payload)}
	sender := newGroupedSlabTestSender(t, reader, int64(len(payload)))
	result := sender.prepareGroupedPacketSlab(context.Background(), externalV2BulkPacketPrepareJob{start: 0, count: 16}, newExternalV2BulkPacketSlab())
	if result.err != nil || len(reader.reads) != 1 || reader.reads[0].length != 989024 {
		t.Fatalf("result=%v reads=%+v", result.err, reader.reads)
	}
}
```

Also add partial-final, nonzero-start, short-read, and pre-canceled-context cases.

- [ ] **Step 2: Run the tests and confirm RED**

Run:

```bash
mise exec -- go test ./pkg/session \
  -run 'TestExternalV2BulkPacketGroupedPrepareSlab' -count=1
```

Expected: FAIL because the current implementation issues one read per group.

- [ ] **Step 3: Add the exact range helper and one-read implementation**

Add:

```go
func externalV2BulkPacketGroupedSlabRange(startGroup, groupCount uint32, payloadSize int64) (int64, int) {
	if groupCount == 0 || payloadSize <= 0 { return 0, 0 }
	start, _ := externalV2BulkPacketGroupedPlaintextRange(startGroup, payloadSize)
	lastStart, lastLength := externalV2BulkPacketGroupedPlaintextRange(startGroup+groupCount-1, payloadSize)
	if lastLength == 0 { return start, 0 }
	return start, int(lastStart + int64(lastLength) - start)
}
```

Check `ctx.Err()` before the read, perform exactly one `s.readSourceAt(slab.input[:length], start)`, validate with `externalV2BlockReadError`, then seal each group from the corresponding input slice. Preserve per-group cancellation checks and existing packet output.

- [ ] **Step 4: Run characterization and stress tests**

Run:

```bash
mise exec -- go test ./pkg/session \
  -run 'TestExternalV2BulkPacketGrouped(PrepareSlab|BatchedSenderRoundTrip)' -count=20
```

Expected: PASS with byte-identical authenticated fragments and exact primary accounting.

- [ ] **Step 5: Commit**

Commit:

```text
perf: coalesce grouped source reads
```

### Task 4: Carry expected peers into platform batch backends and verify Linux peers in binary form

**Files:**
- Create: `pkg/session/external_v2_bulk_packet_peer_linux.go`
- Create: `pkg/session/external_v2_bulk_packet_peer_linux_test.go`
- Modify: `pkg/session/external_v2_bulk_packet_batch.go`
- Modify: `pkg/session/external_v2_bulk_packet_batch_darwin.go`
- Modify: `pkg/session/external_v2_bulk_packet_batch_darwin_test.go`
- Modify: `pkg/session/external_v2_bulk_packet_batch_linux.go`
- Modify: `pkg/session/external_v2_bulk_packet.go`

**Interfaces:**
- Consumes: selected `path.Addrs[lane]`, `syscall.RawConn`, and the existing spare-socket rule `len(path.Conns) > laneCount`.
- Produces: verified fixed-peer state for data lanes while leaving at least one unconnected control socket.

- [ ] **Step 1: Write failing peer and control-socket tests**

Cover IPv4, IPv6 zone, mismatch/disconnect, invalid peer, and five-socket control preservation:

```go
func TestExternalV2BulkPacketFixedPeersRequireSpareControlSocket(t *testing.T) {
	path, batches := fixedPeerFixture(t, 4)
	if err := enableExternalV2BulkPacketFixedPeers(path, batches, 4); err != nil { t.Fatal(err) }
	for _, batch := range batches {
		if batch.(*recordingFixedPeerBatch).peer != nil { t.Fatal("peer enabled without spare socket") }
	}
}
```

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```bash
mise exec -- go test ./pkg/session \
  -run 'TestExternalV2BulkPacket(FixedPeers|LinuxPeer|LinuxFixedPeer)' -count=1
```

Expected: FAIL because the optional connector does not receive the expected peer and Linux has no fixed-peer implementation.

- [ ] **Step 3: Change the contract and add binary peer conversion**

Add:

```go
type externalV2BulkPacketFixedPeerConnector interface { enableFixedPeerConnect(net.Addr) error }

func enableExternalV2BulkPacketFixedPeerConnect(conn externalV2BulkPacketBatchConn, peer net.Addr) error {
	connector, ok := conn.(externalV2BulkPacketFixedPeerConnector)
	if !ok { return nil }
	return connector.enableFixedPeerConnect(peer)
}

func enableExternalV2BulkPacketFixedPeers(path externalV2BulkPacketPath, conns []externalV2BulkPacketBatchConn, laneCount int) error {
	if len(path.Conns) <= laneCount { return nil }
	for lane := 0; lane < laneCount; lane++ {
		if err := enableExternalV2BulkPacketFixedPeerConnect(conns[lane], path.Addrs[lane]); err != nil { return err }
	}
	return nil
}
```

Use a comparable key:

```go
type externalV2BulkPacketLinuxPeer struct { family uint16; port uint16; zone uint32; addr [16]byte }
func externalV2BulkPacketLinuxPeerFromAddr(net.Addr) (externalV2BulkPacketLinuxPeer, unix.Sockaddr, bool)
func externalV2BulkPacketLinuxPeerFromSockaddr(unix.Sockaddr) (externalV2BulkPacketLinuxPeer, bool)
```

Connect through `RawConn.Control`, call `unix.Getpeername`, compare keys, and disconnect with an `AF_UNSPEC` sockaddr before returning any verification failure. Never compare `Addr.String()` in this activation path.

- [ ] **Step 4: Preserve Darwin behavior and verify the spare socket**

Change Darwin `enableFixedPeerConnect()` to `enableFixedPeerConnect(net.Addr) error`, store the expected peer, and keep its lazy connect behavior. In the Linux integration test, connect four data sockets and prove a sealed hello/ACK frame still travels through the fifth unconnected socket.

Run:

```bash
mise exec -- go test ./pkg/session \
  -run 'TestExternalV2BulkPacket(FixedPeers|LinuxPeer|LinuxFixedPeer|DarwinSendmsgXWritesBatch)' -count=1
mise exec -- env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c ./pkg/session -o .tmp/session-linux.test
```

Expected: PASS and a successful Linux cross-compile.

- [ ] **Step 5: Commit**

Commit:

```text
net: verify fixed bulk peers in binary form
```

### Task 5: Add raw connected non-GSO Linux `sendmmsg`

**Files:**
- Create: `pkg/session/external_v2_bulk_packet_send_linux.go`
- Create: `pkg/session/external_v2_bulk_packet_send_linux_test.go`
- Modify: `pkg/session/external_v2_bulk_packet_batch_linux.go`
- Modify: `pkg/session/external_v2_bulk_packet_batched_sender_test.go`

**Interfaces:**
- Consumes: verified fixed-peer state and `externalV2BulkPacketBatchMessage`.
- Produces: allocation-bounded `msg_name=nil` sendmmsg with exact partial completion, deadline, cancellation, `EAGAIN`, and `ENOBUFS` semantics.

- [ ] **Step 1: Write failing syscall-state tests**

Add tests named:

```text
TestExternalV2BulkPacketLinuxConnectedSendMMsgRoundTrip
TestExternalV2BulkPacketLinuxConnectedSendMMsgUsesNilNames
TestExternalV2BulkPacketLinuxConnectedSendMMsgResumesAfterPartial
TestExternalV2BulkPacketLinuxConnectedSendMMsgRetriesEAGAIN
TestExternalV2BulkPacketLinuxConnectedSendMMsgReturnsENOBUFS
TestExternalV2BulkPacketLinuxConnectedSendMMsgHonorsDeadline
TestExternalV2BulkPacketLinuxConnectedSendMMsgHonorsCancellation
TestExternalV2BulkPacketLinuxConnectedSendMMsgRejectsZeroProgress
TestExternalV2BulkPacketLinuxBatchFallsBackAddressedBeforeConnect
TestExternalV2BulkPacketLinuxBatchFailsCleanlyAfterConnectedFatalError
```

The injected syscall must inspect every `Msghdr.Name` and fail unless it is nil.

- [ ] **Step 2: Run the focused tests and confirm RED**

Run on Linux:

```bash
mise exec -- go test ./pkg/session \
  -run 'TestExternalV2BulkPacketLinuxConnectedSendMMsg|TestExternalV2BulkPacketLinuxBatch(FallsBack|FailsCleanly)' -count=1
```

Expected: FAIL because the connected native writer does not exist.

- [ ] **Step 3: Implement exact scratch and raw callback behavior**

Add:

```go
type externalV2BulkPacketLinuxSendScratch struct {
	headers   [externalV2BulkPacketMaxBatch]externalV2BulkPacketMMsgHdr
	iovecs    [externalV2BulkPacketMaxBatch]unix.Iovec
	groupEnds [externalV2BulkPacketMaxBatch]int
	control   []byte // constructor allocates maxBatch*unix.CmsgSpace(2) once
}

type externalV2BulkPacketLinuxSendSyscall func(uintptr, []externalV2BulkPacketMMsgHdr) (int, syscall.Errno)

func externalV2BulkPacketPrepareLinuxConnectedSend(messages []externalV2BulkPacketBatchMessage, scratch *externalV2BulkPacketLinuxSendScratch) ([]externalV2BulkPacketMMsgHdr, error)
func externalV2BulkPacketSendMMsg(raw syscall.RawConn, headers []externalV2BulkPacketMMsgHdr, send externalV2BulkPacketLinuxSendSyscall, onAttempt func()) (int, error)
```

Preparation accepts one nonempty buffer per message, sets `Iov`/`Iovlen`, and always leaves `Name=nil`/`Namelen=0`. `externalV2BulkPacketSendMMsg` calls `RawConn.Write`; increments `onAttempt` immediately before every real syscall; returns false only on `EAGAIN`/`EWOULDBLOCK`; returns true with `ENOBUFS` or any fatal errno; validates `0 <= written <= len(headers)`; and calls `runtime.KeepAlive` for scratch, messages, headers, iovecs, and payload buffers.

- [ ] **Step 4: Integrate connected and addressed states**

Add `connected bool`, `sendMMsg externalV2BulkPacketLinuxSendSyscall`, and reusable scratch to `externalV2BulkPacketLinuxBatchConn`. Before connect, retain the existing addressed `ipv4.PacketConn.WriteBatch`. After connect, use only raw connected `sendmmsg`; a fatal raw error returns cleanly and never attempts an addressed write on the connected socket. Preserve `writeExternalV2BulkPacketBatchAll`'s exact unsent suffix behavior and the existing `ENOBUFS` retry test.

- [ ] **Step 5: Run tests and commit**

Run:

```bash
GODEBUG=checkptr=2 mise exec -- go test ./pkg/session \
  -run 'TestExternalV2BulkPacketLinuxConnectedSendMMsg|TestExternalV2BulkPacketLinuxBatch(FallsBack|FailsCleanly)|TestExternalV2BulkPacketBatchedSenderRetriesENOBUFSFromFirstUnsent' -count=20
```

Expected: PASS without races, pointer failures, duplicate payload, or wrong retry positions.

Commit:

```text
perf: send connected Linux bulk batches natively
```

### Task 6: Add bounded native GSO candidates and safe connected fallback

**Files:**
- Create: `pkg/session/external_v2_bulk_packet_candidate.go`
- Create: `pkg/session/external_v2_bulk_packet_candidate_test.go`
- Modify: `pkg/session/external_v2_bulk_packet_send_linux.go`
- Modify: `pkg/session/external_v2_bulk_packet_send_linux_test.go`
- Modify: `pkg/session/external_v2_bulk_packet_batch_linux.go`
- Modify: `pkg/session/external_v2_bulk_packet_batch_linux_test.go`
- Modify: `pkg/session/external_v2_block.go`

**Interfaces:**
- Consumes: connected non-GSO sender from Task 5.
- Produces: immutable linker-selected candidates `1,2,3,4,6,8,12`, a QUIC control, and production default selection without user knobs.

- [ ] **Step 1: Write failing candidate and GSO tests**

Add table cases for every allowed candidate, invalid candidate rejection, odd group count, a short final segment, maximum batch scratch, partial logical completion, GSO feature fallback to connected non-GSO, and fatal error rejection.

```go
func TestExternalV2BulkPacketLinuxConnectedGSOCandidates(t *testing.T) {
	for _, segments := range []int{1, 2, 3, 4, 6, 8, 12} {
		t.Run(strconv.Itoa(segments), func(t *testing.T) {
			headers, ends, err := externalV2BulkPacketPrepareLinuxConnectedGSO(testBatchMessages(45), segments, new(externalV2BulkPacketLinuxSendScratch))
			if err != nil || len(headers) != (45+segments-1)/segments || ends[len(ends)-1] != 45 {
				t.Fatalf("headers=%d ends=%v error=%v", len(headers), ends, err)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests and confirm RED**

Run:

```bash
mise exec -- go test ./pkg/session \
  -run 'TestExternalV2BulkPacket.*(Candidate|ConnectedGSO|ConfiguredGSO)' -count=1
```

Expected: FAIL because GSO3 is compile-time fixed and uses the addressed `x/net` batch path.

- [ ] **Step 3: Add linker-only candidate identity**

Add:

```go
var externalV2BulkPacketBenchmarkCandidate string

type externalV2BulkPacketCandidateConfig struct {
	ID                  string
	CoalescedReads      bool
	NativeConnectedSend bool
	GSOSegments         int
	ForceQUICControl    bool
}

func externalV2BulkPacketCandidateConfigFor(value string) (externalV2BulkPacketCandidateConfig, error)
```

Accepted nonempty values are exactly `coalesced-gso3`, `connected-gso3`, `combined-gso1`, `combined-gso2`, `combined-gso3`, `combined-gso4`, `combined-gso6`, `combined-gso8`, `combined-gso12`, and `quic-control`. Empty selects source-controlled production constants. No CLI flag or environment variable controls these fields. Invalid linker values make the batch connection return an initialization error rather than silently substituting GSO3.

- [ ] **Step 4: Prepare native GSO messages and connected fallback**

Add:

```go
func externalV2BulkPacketPrepareLinuxConnectedGSO(messages []externalV2BulkPacketBatchMessage, segments int, scratch *externalV2BulkPacketLinuxSendScratch) ([]externalV2BulkPacketMMsgHdr, []int, error)
```

Group consecutive equal-sized logical datagrams by `segments`, give each top-level header one `UDP_SEGMENT` control message and no destination, retain logical group-end indexes, and allow only the final logical segment to be short. `segments==1` bypasses UDP GSO and calls connected non-GSO. On `EINVAL`, `ENOPROTOOPT`, `EOPNOTSUPP`, `ENOSYS`, or `EIO`, retry the same unsent logical suffix using connected non-GSO. All other errors fail; no post-connect addressed fallback is permitted.

- [ ] **Step 5: Run Linux stress gates and commit**

Run:

```bash
GODEBUG=checkptr=2 mise exec -- go test ./pkg/session \
  -run 'TestExternalV2BulkPacket.*(Candidate|ConnectedGSO|ConnectedSendMMsg)' -count=20
mise exec -- env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c ./pkg/session -o .tmp/session-linux.test
mise exec -- env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/derphole
```

Expected: PASS for all seven group sizes and both fallback states.

Commit:

```text
perf: add bounded GSO candidates to connected bulk sends
```

### Task 7: Record bulk mechanism efficiency and prove pointer lifetime

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet.go`
- Modify: `pkg/session/external_v2_bulk_packet_grouped.go`
- Modify: `pkg/session/external_v2_bulk_packet_batched_sender.go`
- Modify: `pkg/session/external_v2_bulk_packet_batch.go`
- Modify: `pkg/session/external_v2_bulk_packet_send_linux.go`
- Modify: `pkg/session/external_transfer_metrics.go`
- Modify: `pkg/session/external_transfer_metrics_test.go`
- Modify: `pkg/transfertrace/trace.go`
- Modify: `pkg/transfertrace/trace_test.go`
- Modify: `pkg/transfertrace/checker.go`
- Modify: `pkg/transfertrace/checker_test.go`

**Interfaces:**
- Consumes: native connected sender and coalesced reads.
- Produces: source-read/syscall/GSO/logical-datagram/accepted-payload evidence required to explain any ceiling.

- [ ] **Step 1: Add failing counter and lifetime tests**

Add source primary-plus-repair accounting, callback-attempt/partial-acceptance tests, aggregate-lane trace tests, and:

```go
func TestExternalV2BulkPacketLinuxConnectedWriterRetainsBuffersAcrossRawWrite(t *testing.T) {
	messages := testBatchMessages(45)
	raw := rawConnThatRunsGCBeforeCallback()
	_, err := externalV2BulkPacketSendMMsg(raw, prepareHeaders(t, messages), syscallThatChecksEveryIovec(messages), func(){})
	if err != nil { t.Fatal(err) }
}
```

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```bash
GODEBUG=checkptr=2 mise exec -- go test ./pkg/session ./pkg/transfertrace \
  -run 'Test.*(SourceReadDiagnostics|NativeTelemetry|RetainsBuffers|BulkBatchDiagnostics)' -count=1
```

Expected: FAIL because the counters and columns do not exist.

- [ ] **Step 3: Add exact counters at the native boundary**

Add to batch stats, direct diagnostics, metrics, and snapshots. `NativeSendAttempts` is an actual syscall attempt from inside the raw callback, not a count of successful high-level writes:

```go
NativeSendAttempts         uint64
NativeSendSyscalls         uint64
NativeGSOMessages          uint64
LogicalDatagrams           uint64
NativeAcceptedPayloadBytes uint64
GSOSegmentsPerMessage      uint32
CandidateID                string
```

Task 2 already routes all source reads through the generic recorder. Here set `PayloadBytes` on every batch message. Count `NativeSendAttempts` inside `RawConn.Write` immediately before each syscall; count `NativeSendSyscalls` only after a syscall returns; count accepted top-level GSO messages, logical datagrams, and only payload bytes represented by kernel-accepted logical messages. Portable and Darwin backends count attempts/syscalls at their closest native call boundary and mark that backend explicitly.

- [ ] **Step 4: Add trace columns and selected-engine requirements**

Add:

```text
bulk_candidate_id
bulk_native_send_attempts
bulk_native_send_syscalls
bulk_gso_messages
bulk_logical_datagrams
bulk_accepted_payload_bytes
bulk_gso_segments_per_message
```

Healthy zeroes must be numeric when bulk is selected. Missing bulk fields reject bulk evidence; QUIC evidence may leave them empty.

Implement `validateFilePayloadEvidence`, `validateBulkEngineTelemetry`, `validateQUICEngineTelemetry`, and `validateSelectedPayloadLanes` in the checker. A bulk sender requires present generic source-read/backend fields plus actual attempts, syscalls, accepted bytes, send/GSO/batch/queue/probe/`ENOBUFS`/repair fields. A bulk receiver requires backend, receive/decrypt/batch/writer/receive-queue, probe, repair/missing-scan/reorder/PPS fields. Enforce `attempts >= syscalls >= successful calls`, accepted payload at least expected payload, logical datagrams at least successful calls, active GSO with positive messages/segments, and nonnegative queue/probe/repair relations. Add a table-driven test that blanks every required selected-engine field one at a time, plus a healthy-zero test.

- [ ] **Step 5: Run stress and package gates and commit**

Run:

```bash
GODEBUG=checkptr=2 mise exec -- go test ./pkg/session \
  -run 'TestExternalV2BulkPacket.*(SourceReadDiagnostics|NativeTelemetry|RetainsBuffers|ConnectedGSO|ConnectedSendMMsg)' -count=20
mise exec -- go test ./pkg/transfertrace -count=1
mise exec -- go test ./pkg/session -count=1
```

Expected: PASS with no checkptr failure, missing field, or counter double-count.

Commit:

```text
trace: record native bulk send efficiency
```

### Task 8A: Add immutable manifest and artifact primitives

**Files:**
- Create: `pkg/udpbenchproof/artifact.go`
- Create: `pkg/udpbenchproof/artifact_test.go`
- Create: `pkg/udpbenchproof/manifest.go`
- Create: `pkg/udpbenchproof/manifest_test.go`
- Create: `pkg/udpbenchproof/testdata/manifest-valid.json`
- Create: `pkg/udpbenchproof/testdata/manifest-invalid-duplicate-candidate.json`
- Create: `tools/udppeak/main.go`
- Create: `tools/udppeak/main_test.go`

**Interfaces:**
- Consumes: exact endpoint facts, source identity, predeclared candidates/schedules/rules, inventory, health baseline, and binary identities.
- Produces: an immutable manifest whose exact bytes and SHA-256 bind every later schedule, sample, and decision.

- [ ] **Step 1: Write failing immutable-artifact and manifest tests**

Add `TestWriteImmutableJSONCannotOverwrite`, `TestWriteImmutableJSONDigestMatchesExactBytes`, `TestVerifyArtifactRejectsMutation`, `TestNewManifestRejectsUnfrozenSchedule`, `TestManifestRejectsExperimentOverrideInProductionEnvironment`, `TestManifestRequiresExactHetznerCPUs`, `TestProductionManifestRequiresParentDecisionAndNewBinaryHashes`, `TestAcceptanceManifestRequiresBoundThreeGiBPayload`, `TestManifestTransitionRejectsPayloadOrBinarySubstitution`, and duplicate candidate/schedule tests.

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```bash
mise exec -- go test ./pkg/udpbenchproof ./tools/udppeak -run 'Artifact|Immutable|Manifest' -count=1
```

Expected: FAIL because the package and CLI do not exist.

- [ ] **Step 3: Implement exact identities and no-replace writes**

Add:

```go
type SHA256Digest string
type BinaryIdentity struct { Platform, SHA256, VCSRevision string }
type CandidateIdentity struct { ID, Commit string; Darwin, Linux BinaryIdentity; Config map[string]string }
type ManifestKind string // experiment, production, acceptance, or ceiling
type ArtifactRef struct { Path string; SHA256 SHA256Digest }
type PayloadIdentity struct { Bytes int64; SHA256 SHA256Digest }
type FrozenSchedule struct { Stage string; RunIDs, CandidateOrder, DirectionOrder []string }
type FrozenRules struct { CapacityMinimumMbps, FileMinimumMbps, MaxCV, MaterialDelta, ScreenDominance, FinalistDelta, MaxRecovery, MaxScanPerPacket, MaxCPUSecondsPerGiB, MinCeilingCPUSaturation, MinCeilingKernelSaturation, RequiredProfileAgreement float64; CapacityAttempts, MinRepeatedCeilingProfiles int }
type HostIdentity struct { ID, SSH, PublicIPv4 string; EricWatchdog bool }
type ManifestInput struct {
	Kind ManifestKind
	ParentManifest *ArtifactRef
	ParentDecisionRefs []ArtifactRef
	LocalPublicIPv4, RemotePublicIPv4 string
	RemoteKernel, RemoteArch, RemoteBootID string
	RemoteOnlineCPUs int
	Payload PayloadIdentity
	Candidates []CandidateIdentity
	Schedules []FrozenSchedule
	Rules FrozenRules
	ProductionEnvironment map[string]string
	FleetInventory []HostIdentity
	BaselineHealthCounters map[string]uint64
	CapacityTCPPort int
}
type Manifest struct { SchemaVersion int; ManifestInput ManifestInput }

func NewManifest(ManifestInput) (Manifest, error)
func ValidateManifest(Manifest) error
func VerifyManifestTransition(parent Manifest, parentDigest SHA256Digest, child Manifest) error
func DigestBytes([]byte) SHA256Digest
func FileDigest(string) (SHA256Digest, error)
func WriteImmutableBytes(path string, data []byte) (SHA256Digest, error)
func WriteImmutableJSON(path string, value any) (SHA256Digest, error)
func VerifyArtifact(path string, want SHA256Digest) error
```

`WriteImmutableBytes` writes and fsyncs a same-directory `O_EXCL` temporary, hard-links it to the absent final path for atomic no-replace publication, fsyncs the directory, and removes the temporary. `WriteImmutableJSON` canonicalizes JSON then delegates to it. Neither calls `os.Rename` or `os.Replace` over the final path. Digest sidecars use the same no-replace byte primitive.

Manifest validation requires Mac/Hetz public IPv4 literals, Hetz kernel/arch/boot ID and exactly two CPUs, exact payload size/hash, candidate commits/hashes/config, predeclared schedules and thresholds, checked-in plus explicit fleet inventory, baseline health, and a production environment with no benchmark override. Port 8123 is capacity control only. An experiment manifest is a root and binds the reusable 1 GiB screening payload plus candidate binaries. A production manifest must hash-bind the experiment manifest and finalist decision, bind the newly committed override-free production binary pair, and bind its fresh 1 GiB payload. An acceptance manifest must hash-bind the production manifest, prerequisite decision, fleet decision, and the newly created 3 GiB source identity. A ceiling manifest must hash-bind the production manifest, peak decision, fleet decision, exact sweep/profile schedule, and diagnostic binary pair. Child manifests may not silently inherit or substitute a parent's payload or binary identity.

- [ ] **Step 4: Add manifest/artifact CLI and verify deterministic bytes**

Support:

```bash
udppeak manifest-create -input manifest-input.json -out manifest.json
udppeak artifact-verify -path manifest.json -sha256 SHA256
udppeak validate -manifest manifest.json -sha256 SHA256
```

Run the same fixture twice in separate directories and require byte-identical JSON and digests. Commit after:

```bash
mise exec -- go test ./pkg/udpbenchproof ./tools/udppeak -run 'Artifact|Immutable|Manifest' -count=20
```

Commit: `bench: add immutable UDP proof artifacts`.

### Task 8B: Add mechanical samples, schedules, peak decisions, and binary prerequisites

**Files:**
- Create: `pkg/udpbenchproof/model.go`
- Create: `pkg/udpbenchproof/sample.go`
- Create: `pkg/udpbenchproof/sample_test.go`
- Create: `pkg/udpbenchproof/schedule.go`
- Create: `pkg/udpbenchproof/schedule_test.go`
- Create: `pkg/udpbenchproof/decision.go`
- Create: `pkg/udpbenchproof/decision_test.go`
- Create: `pkg/udpbenchproof/ceiling.go`
- Create: `pkg/udpbenchproof/ceiling_test.go`
- Create: `pkg/udpbenchproof/scc.go`
- Create: `pkg/udpbenchproof/scc_test.go`
- Modify: `tools/udppeak/main.go`
- Modify: `tools/udppeak/main_test.go`
- Create: `pkg/udpbenchproof/testdata/screening-dominated.json`
- Create: `pkg/udpbenchproof/testdata/screening-unstable-brackets.json`
- Create: `pkg/udpbenchproof/testdata/preliminary-five-percent-frontier.json`
- Create: `pkg/udpbenchproof/testdata/finalist-three-candidate-rotation.json`
- Create: `pkg/udpbenchproof/testdata/scc-cycle-frontier.json`
- Create: `pkg/udpbenchproof/testdata/scc-incoming-component.json`
- Create: `pkg/udpbenchproof/testdata/sample-missing-sha.json`
- Create: `pkg/udpbenchproof/testdata/prerequisite-wrong-binary.json`
- Create: `pkg/udpbenchproof/testdata/fleet-unavailable-at-second-probe.json`
- Create: `pkg/udpbenchproof/testdata/ceiling-plateau-pass.json`
- Create: `pkg/udpbenchproof/testdata/ceiling-offered-load-still-scales.json`
- Create: `pkg/udpbenchproof/testdata/ceiling-profile-mechanism-mismatch.json`
- Create: `pkg/udpbenchproof/testdata/acceptance-six-run-pass.json`
- Create: `pkg/udpbenchproof/testdata/acceptance-replacement-attempt.json`

**Interfaces:**
- Consumes: an exact manifest digest plus normalized capacity, file, trace, resource, health, cleanup, and binary evidence.
- Produces: deterministic schedules and immutable hash-bound stage decisions that mechanically authorize the next stage.

- [ ] **Step 1: Write fixture-first validation and decision tests**

Create fixtures for dominated and unstable screening, five-percent preliminary frontier, three-candidate and Latin finalist rotations, SCC cycles/incoming components, missing or duplicate SHA reports, wrong binary prerequisite, capacity-valid started failure, unavailable fleet recheck, passing/failed ceiling, six-run acceptance, and a replacement-run attempt. Each test loads its fixture twice and requires byte-identical schedule or decision JSON.

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```bash
mise exec -- go test ./pkg/udpbenchproof ./tools/udppeak -run 'Sample|Schedule|Decision|Prerequisite|Acceptance|SCC' -count=1
```

Expected: FAIL because samples and decisions do not exist.

- [ ] **Step 3: Define the complete decision API**

Add:

```go
type Direction string // local-to-remote or remote-to-local
type Stage string
const (
	StageScreening Stage = "screening"
	StagePreliminary Stage = "preliminary"
	StageFinalist Stage = "finalist"
	StageProduction Stage = "production"
	StageFleet Stage = "fleet"
	StageCeiling Stage = "ceiling"
	StageAcceptance Stage = "acceptance"
)
type BinarySet struct { Darwin, Linux BinaryIdentity }
type ScheduledRun struct { ID string; Stage Stage; CandidateID, HostID string; Direction Direction; SizeBytes int64; Order int; CapacityRequired bool }
type PayloadEvidence struct { SourceHashArtifact, SinkHashArtifact, SinkSizeArtifact ArtifactRef; SourceSHA256, SinkSHA256 SHA256Digest; SourceSHAReports, SinkSHAReports int; SinkSizeBytes int64 }
type CapacityEvidence struct { Artifact ArtifactRef; Direction Direction; Mbps float64; Valid bool }
type TraceEvidence struct { Sender, Receiver ArtifactRef; Engine string; PublicUDP, StrictValid bool }
type ResourceEvidence struct { Sender, Receiver ArtifactRef; SenderUserSeconds, SenderSystemSeconds, ReceiverUserSeconds, ReceiverSystemSeconds float64 }
type HealthEvidence struct { Before, After ArtifactRef; Healthy bool }
type CleanupEvidence struct { Artifact ArtifactRef; ScopedRootRemoved, ProcessesRemoved, SocketsRemoved, PayloadsRemoved bool }
type Sample struct { ManifestSHA256 SHA256Digest; CandidateID string; BinarySet BinarySet; Run ScheduledRun; Payload PayloadEvidence; Capacity CapacityEvidence; Trace TraceEvidence; Resource ResourceEvidence; Health HealthEvidence; Cleanup CleanupEvidence; Started bool }
type SampleVerdict struct { Status string; Reasons []string }
type MaterialEdge struct { From, To string }
type Decision struct { ManifestSHA256 SHA256Digest; Stage Stage; Passed, AcceptanceMet bool; SelectedCandidate string; PeakFrontier []string; Reasons []string; BinarySet BinarySet; InputDecisionRefs, SampleRefs []ArtifactRef }
type PrerequisiteDecision struct { ManifestSHA256 SHA256Digest; CandidateID string; BinarySet BinarySet; InputDecisionRefs, Samples []ArtifactRef; Passed bool; Reasons []string }
type CeilingSweepPoint struct { Direction Direction; Order string; OfferedGbps, DeliveredGbps, LossRatio, QueuePressure float64; Capacity ArtifactRef; UDPResult ArtifactRef; Health ArtifactRef }
type CeilingProfile struct { Direction Direction; Artifact ArtifactRef; HetzCPUUtilization, KernelPacketCPUUtilization float64; LimitingMechanism string }
type CeilingDecision struct { ManifestSHA256 SHA256Digest; InputDecisionRefs, SweepRefs, ProfileRefs, WinnerSampleRefs []ArtifactRef; PlateauStartGbps, PlateauEndGbps float64; LimitingMechanism string; Passed, AcceptanceMet bool; Reasons []string }
type AcceptanceInputs struct { Manifest Manifest; ManifestRef ArtifactRef; Prerequisite PrerequisiteDecision; PrerequisiteRef ArtifactRef; Fleet Decision; FleetRef ArtifactRef; Samples []Sample }

func ValidateSample(Manifest, Sample) SampleVerdict
func BuildSchedule(Manifest, Stage, Decision) ([]ScheduledRun, error)
func Evaluate(Manifest, []Sample, Stage) (Decision, error)
func PeakFrontier([]string, []MaterialEdge) []string
func DecidePrerequisite(Manifest, []Sample) PrerequisiteDecision
func VerifyPrerequisite(Manifest, SHA256Digest, PrerequisiteDecision, SHA256Digest, BinarySet) error
func DecideAcceptance(AcceptanceInputs) Decision
func DecideCeiling(Manifest, []CeilingSweepPoint, []CeilingProfile, []Sample) CeilingDecision
```

Sample validation opens and digest-verifies the immutable source-hash, sink-hash, and sink-size/promotion artifacts; it requires exactly one independently observed source SHA, one independently observed sink SHA, equality to the current stage manifest's payload identity, and exact sink size. It also requires strict paired trace result, resource evidence, same-direction capacity, health, and cleanup. Missing or non-reproducible raw evidence is invalid and never defaults to expected data. Capacity-invalid rows before start are `postponed`; a capacity-valid started failure remains and cannot be replaced.

- [ ] **Step 4: Implement the approved deterministic statistics and gates**

Screen only under frozen controls within 3 percent; eliminate on one sample only for strict greater-than-10-percent domination in raw, normalized, and CPU efficiency. Give every survivor three preliminary samples per direction, advance all candidates within 5 percent of a direction or bottleneck leader, and always advance at least two. Use `A B C / C B A / B C A` for three finalists and a candidate-ID-sorted Latin rotation otherwise.

Match samples by nearest timestamp without reuse. Add `X -> Y` only when raw and normalized bottleneck improve more than 3 percent, no direction regresses more than 3 percent, and X wins at least four of six in each direction. Collapse SCCs, select zero-incoming components, then rank raw bottleneck, normalized bottleneck, maximum Hetz-role CPU, recovery, and wall goodput in that order.

For raw and capacity-normalized goodput report mean, median, minimum, maximum, population standard deviation, coefficient of variation, nearest-time comparisons, and bootstrap confidence intervals. Finalist raw and normalized CV must each be at most 0.10. If capacity CV exceeds 0.10, allow exactly one full balanced schedule rerun after complete cleanup; preserve both schedules and require the pooled decision to retain the same winner.

The prerequisite requires exactly six fresh 1 GiB production samples, three per direction, using the exact same production manifest, candidate, Darwin/Linux hashes, and override-free environment; every sample must be capacity-valid, healthy, integrity/route/telemetry clean, above 2.0 Gbps, and direction CV at most 0.10. Acceptance samples validate against the child acceptance manifest's 3 GiB identity and require its exact prerequisite and fleet decision artifact digests plus exactly six nonreplaceable samples, three per direction. Every dependent decision serializes the exact input decision references/digests it consumed and verification rejects a decoded-but-differently-encoded or mutated input. A hard-ceiling decision always sets `AcceptanceMet=false`.

Ceiling evaluation requires both ascending and descending 1,400-byte public-UDP points at exactly 1.2, 1.5, 1.8, 2.1, and 2.4 Gbps in both directions, with qualifying TCP brackets, strict health, and immutable raw result refs. Freeze `MinCeilingCPUSaturation=0.90`, `MinCeilingKernelSaturation=0.90`, `RequiredProfileAgreement=1.0`, and `MinRepeatedCeilingProfiles=2` in the ceiling manifest before any sweep. It passes only when a 20-percent-or-greater offered-load increase yields at most 3 percent additional delivered goodput while loss or queue pressure rises; at least two independent plateau profiles per direction meet either the total Hetz CPU or kernel packet-processing saturation threshold; every profile names the same limiting mechanism; every candidate has a closed outcome; no candidate sits outside the retained 3-percent peak frontier; and the exact nine winner samples per direction are stable, capacity-valid, integrity/route verified, and CV at most 0.10. `CeilingDecision.WinnerSampleRefs` records every exact sample digest and verification requires its experiment/production manifest ancestry. Missing sweep points, profile refs, counter families, winner refs, ancestry, or mechanism agreement reject the decision.

- [ ] **Step 5: Add commands and commit**

Support:

```bash
udppeak schedule -stage STAGE -manifest manifest.json -manifest-sha256 SHA256 [-prior decision.json] -out schedule.json
udppeak sample-validate -manifest manifest.json -sample sample.json
udppeak evaluate -stage STAGE -manifest manifest.json -results results.jsonl -out decision.json
udppeak prerequisite-decide -manifest manifest.json -results production.jsonl -out prerequisite.json
udppeak verify-prerequisite -manifest manifest.json -manifest-sha256 SHA256 -decision prerequisite.json -decision-sha256 SHA256 -local-bin BIN -linux-bin BIN
udppeak acceptance-decide -manifest manifest.json -prerequisite prerequisite.json -fleet fleet.json -results acceptance.jsonl -out decision.json
udppeak ceiling-decide -manifest ceiling-manifest.json -sweeps ceiling-sweeps.jsonl -profiles ceiling-profiles.jsonl -winner-samples winner.jsonl -out ceiling-decision.json
```

The first stage omits `-prior`; later stages require it. Every decision uses `WriteImmutableJSON` and prints its exact digest. Run `mise exec -- go test ./pkg/udpbenchproof ./tools/udppeak -count=20`, then commit `bench: bind UDP decisions to exact binaries and samples`.

### Task 8C: Add read-only health, disk-capacity, and cleanup verdicts

**Files:**
- Create: `pkg/udpbenchproof/health.go`
- Create: `pkg/udpbenchproof/health_linux.go`
- Create: `pkg/udpbenchproof/health_darwin.go`
- Create: `pkg/udpbenchproof/health_test.go`
- Create: `pkg/udpbenchproof/capacity.go`
- Create: `pkg/udpbenchproof/capacity_test.go`
- Modify: `tools/udppeak/main.go`
- Modify: `tools/udppeak/main_test.go`

**Interfaces:**
- Consumes: read-only host state and an explicit harness-owned process/socket/root set.
- Produces: complete before/after health verdicts and conservative disk requirements without any host mutation.

- [ ] **Step 1: Write failing health/capacity tests**

Add `TestCompareHealthRejectsRebootOOMKernelAndLeak`, `TestHealthSnapshotRequiresEveryCounterFamily`, `TestDiskCapacityModelsOnlyConcurrentPayloadCopies`, and fixtures for reboot, OOM, kernel error, CPU-count change, interface/UDP/softnet failure, exact PID/socket leak, and low disk.

- [ ] **Step 2: Implement capture and comparison APIs**

Add:

```go
type ProcessRef struct { Name string; PID int }
type HealthCaptureOptions struct { WorkDir, Interface string; OwnedProcesses []ProcessRef }
type SocketRef struct { Network, Local, Remote string; PID int }
type HealthSnapshot struct {
	BootID string
	UptimeSeconds float64
	OnlineCPUs int
	GlobalOOMKills, CgroupOOMKills uint64
	AvailableMemoryBytes, SwapUsedBytes, DiskFreeBytes uint64
	KernelErrors []string
	InterfaceDrops, UDPErrors, SoftnetDrops uint64
	Processes []ProcessRef
	Sockets []SocketRef
}
type HealthPolicy struct { ExpectedOnlineCPUs int; MinAvailableMemoryBytes, MinDiskAvailableBytes int64 }
type HealthVerdict struct { Healthy bool; Reasons []string }
func CaptureHealth(context.Context, HealthCaptureOptions) (HealthSnapshot, error)
func CompareHealth(before, after HealthSnapshot, p HealthPolicy) HealthVerdict
type DiskRequirement struct { PayloadBytes, BinaryBytes, EvidenceReserveBytes int64; AdditionalPayloadCopies int }
func RequiredFreeBytes(DiskRequirement) (int64, error)
func CheckDiskCapacity(free int64, req DiskRequirement) error
```

Linux reads boot ID, uptime, global and cgroup-v2 OOM, meminfo, statfs, filtered new kernel errors, interface, SNMP UDP, softnet, and exact process/socket state. Darwin records read-only equivalents. A missing required family is invalid. Comparison rejects reboot, OOM, CPU-count change, severe memory pressure, new kernel error, interface/UDP/softnet failure deltas, exact PID/socket leaks, and disk below policy.

- [ ] **Step 3: Add CLI, Linux cross-build, and commit**

Support `health-snapshot`, `health-watch`, `health-compare`, and `capacity-check`. Run:

```bash
mise exec -- go test ./pkg/udpbenchproof ./tools/udppeak -run 'Health|Capacity' -count=20
mise exec -- env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o .tmp/udppeak-linux ./tools/udppeak
```

Commit: `bench: enforce health capacity and cleanup gates`.

### Task 9: Build immutable benchmark candidate pairs

**Files:**
- Create: `scripts/udp-peak-candidates.sh`
- Create: `scripts/udp_peak_candidates_test.go`
- Modify: `.mise.toml`

**Interfaces:**
- Consumes: one frozen control pair and the current source revision.
- Produces: Darwin/Linux binary pairs and `candidates.json`, each bound to exact linker value, SHA-256, revision, engine, and GSO size.

- [ ] **Step 1: Write failing shell-contract tests**

Assert the script requires explicit root and control binaries, enumerates the exact ten candidate IDs, hashes both outputs, uses `-ldflags "-X github.com/shayne/derphole/pkg/session.externalV2BulkPacketBenchmarkCandidate=<id>"`, and never runs checkout, package install, or host mutation commands.

- [ ] **Step 2: Run the tests and confirm RED**

Run:

```bash
mise exec -- go test ./scripts -run 'TestUDPPeakCandidates' -count=1
```

Expected: FAIL because the candidate builder does not exist.

- [ ] **Step 3: Add strict argument parsing and candidate build loop**

The interface is:

```bash
./scripts/udp-peak-candidates.sh \
  --root ROOT \
  --control-local FROZEN_DARWIN_BIN \
  --control-linux FROZEN_LINUX_BIN \
  --revision "$(git rev-parse HEAD)"
```

Use an explicit array:

```bash
candidates=(coalesced-gso3 connected-gso3 combined-gso1 combined-gso2 combined-gso3 combined-gso4 combined-gso6 combined-gso8 combined-gso12 quic-control)
```

Build each local and `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` binary into `ROOT/bin/<candidate>/`, calculate hashes locally, and write one JSON registry entry through Python's `json` module. Copy the frozen control pair without changing it. Never change Git state.

- [ ] **Step 4: Validate the registry and reproducibility**

Build the same candidate twice into two temporary roots and assert equal binary SHA-256 values when `-trimpath -buildvcs=true` and the same revision are used. Invoke `udppeak validate` on the generated manifest/registry boundary.

- [ ] **Step 5: Run tests and commit**

Run:

```bash
bash -n scripts/udp-peak-candidates.sh
mise exec -- go test ./scripts -run 'TestUDPPeakCandidates' -count=1
```

Commit:

```text
bench: build immutable UDP peak candidates
```

### Task 10: Add the staged, host-safe campaign harness

**Files:**
- Create: `scripts/udp-peak-performance.sh`
- Create: `scripts/udp_peak_performance_test.go`
- Create: `scripts/public-path-hosts.json`
- Modify: `scripts/public-path-performance-harness.sh`
- Modify: `scripts/promotion-benchmark-driver.sh`
- Modify: `scripts/promotion_scripts_test.go`
- Modify: `.mise.toml`

**Interfaces:**
- Consumes: candidate registry and `udppeak` schedules.
- Produces: normalized samples, immutable health/cleanup evidence, and stage decisions without installing or tuning anything.

- [ ] **Step 1: Write failing stubbed-harness tests**

Use fake `ssh`, `scp`, `iperf3`, `df`, and promotion binaries to cover: low capacity starts no transfer; three low controls postpone the block; a changed manifest hash rejects the stage; missing telemetry rejects the sample; host boot/OOM/kernel/cleanup change invalidates the whole host block; started failures remain in results; only recorded PIDs receive TERM/KILL; missing prerequisites never invoke package managers; source and sink SHA/size are each emitted exactly once; explicit retention preserves only a verified forward output; a failed retention removes its partial; remote cleanup failure is visible; canonical inventory gets one bounded recheck; and Eric runs last, serially, with no retry after a watchdog failure.

- [ ] **Step 2: Run tests and confirm RED**

Run:

```bash
mise exec -- go test ./scripts -run 'TestUDPPeakPerformance' -count=1
```

Expected: FAIL because the staged driver does not exist.

- [ ] **Step 3: Tighten the one-transfer executor**

Emit `benchmark-source-sha256`, `benchmark-sink-sha256`, and `benchmark-sink-size-bytes` exactly once from independently observed data; never substitute the expected hash when a footer is absent. Add paired controls `DERPHOLE_BENCH_RETAIN_REMOTE_RESULT=1` and `DERPHOLE_BENCH_REMOTE_RESULT_PATH`; both must be present, only a forward file run may use them, and the path must be inside the caller's scoped remote root. After verified success atomically move `${remote_base}.out` to that path. On failure remove the exact partial. Never retain sidecars, binaries, or unverified bytes.

Copy exact trace, resource, selected-lane, engine, wrapper PID, child PID, exit status, and cleanup status into the run directory. Reject partial binary pairs. Preserve the existing bounded wrapper/child PID TERM/KILL logic and leak checks, but make any exact scoped-root cleanup failure observable to the caller. Start remote commands with `env -i` plus an explicit allowlist; ambient TCP or experiment variables never cross the boundary.

- [ ] **Step 4: Implement staged orchestration and health snapshots**

Support:

```bash
mise run udp:peak -- prepare --root ROOT --registry ROOT/candidates.json --remote root@host --remote-public A.B.C.D --local-public W.X.Y.Z --tcp-port 8123 --fleet-hosts HOSTS_FILE
mise run udp:peak -- run --root ROOT --stage screening
mise run udp:peak -- run --root ROOT --stage preliminary
mise run udp:peak -- run --root ROOT --stage finalist
mise run udp:peak -- run --root ROOT --stage production
mise run udp:peak -- run --root ROOT --stage fleet
mise run udp:peak -- run --root ROOT --stage ceiling
```

Build `scripts/public-path-hosts.json` from the four targets already checked into the existing harness; record names, roles, and Eric's watchdog marker only, with no new address/private metadata. Merge that inventory with the explicitly supplied JSON list. Probe every member initially plus exactly one bounded recheck; available at either probe becomes mandatory, while failure at both is recorded unavailable and never silently omitted. Remove `ensure_iperf3` and every package-install path from `public-path-performance-harness.sh`; a missing prerequisite skips/fails the cell.

Before every scheduled file run, perform a 20-second eight-flow same-direction TCP control; authorize only `>=2050` Mbps and retry capacity at most three times. Run the transfer through an `env -i` allowlist containing only HOME/PATH/TMPDIR, SSH auth, exact binary/payload/log roots, the linker candidate identity already recorded in its binary, and the benchmark-only Tailscale-address guard.

Capture boot ID, uptime, global and cgroup OOM counters, available memory, swap, disk, kernel tail, interface counters, UDP counters, softnet counters, and exact process/socket state before and after. A host-state failure stops the host session and remains evidence; it never becomes a candidate loss. Run Eric last and one sample at a time. Start `udppeak health-watch` under exact wrapper/child PIDs at a 1–2 second cadence. SSH loss, boot-ID change, OOM, severe pressure, new kernel error, interface failure, or cleanup failure stops Eric for the session, cleans the watcher by exact PID/stop file, and is never retried after restart.

Write:

```text
ROOT/manifest.json
ROOT/manifest.sha256
ROOT/candidates.json
ROOT/schedules/ (one immutable JSON file per stage)
ROOT/results/<stage>/<run-id>.json (one immutable normalized sample)
ROOT/results/<stage>.jsonl (immutable deterministic stage index)
ROOT/results.csv (immutable deterministic final index)
ROOT/decisions/ (one immutable JSON file plus digest per stage)
ROOT/runs/<stage>/<run-id>/
ROOT/health/<run-id>/{before,after}.json
ROOT/cleanup/<run-id>.json
```

Never append into an already published artifact. Write each normalized sample once, then derive and immutably publish the stage JSONL index after that stage closes; derive the final CSV from the verified per-sample artifacts. Decisions bind the exact digests of the per-sample inputs, not an unverified mutable aggregate.

- [ ] **Step 5: Require engine-specific trace validation and commit**

For each run call `transfertracecheck` separately on sender and receiver with exact expected payload bytes, expected engine, `-require-engine-telemetry`, and the opposite endpoint's literal public IPv4. Call paired validation with both peer-specific IPv4 operands for engine agreement. Normalize bulk recovery from repair bytes and QUIC recovery from `quic_recovery_ratio`; require only the selected engine's telemetry.

Run:

```bash
bash -n scripts/udp-peak-performance.sh scripts/promotion-benchmark-driver.sh
mise exec -- go test ./scripts -run 'Test(UDPPeakPerformance|PromotionBenchmark)' -count=1
```

Expected: PASS for every stubbed safety and no-retry fixture.

Commit:

```text
bench: add staged UDP peak campaign
```

### Task 11: Add the fresh production gate and bind disk-safe acceptance

**Files:**
- Create: `scripts/udp-file-production-gate.sh`
- Create: `scripts/udp_file_production_gate_test.go`
- Modify: `scripts/udp-file-acceptance.sh`
- Modify: `scripts/udp_file_acceptance_test.go`
- Modify: `.mise.toml`
- Modify: `docs/benchmarks.md`

**Interfaces:**
- Consumes: exact manifest/candidate/fleet identities and selected production binary pair.
- Produces: a fresh immutable six-sample 1 GiB prerequisite followed, only when all gates pass, by exactly six nonreplaceable 3 GiB results with remote peak disk near one 3 GiB file.

- [ ] **Step 1: Write failing fresh-gate, prerequisite, and ordering tests**

For the production gate, assert exact binary hashes are verified locally and remotely before a run, three low controls never start UDP, exactly three 1 GiB samples run per direction, only production environment variables are allowed, cleanup/health failure rejects the gate, and the immutable decision binds manifest plus all six samples. For acceptance, assert no 3 GiB allocation before manifest/prerequisite/fleet digest and current binary verification, forward runs all precede reverse runs, outputs one/two are removed, only forward output three becomes the remote reverse source, no second remote source is staged, disk is rechecked before every run, and every local/remote payload is removed after size/hash evidence.

- [ ] **Step 2: Run tests and confirm RED**

Run:

```bash
mise exec -- go test ./scripts -run 'TestUDPFile(ProductionGate|Acceptance)' -count=1
```

Expected: FAIL because the fresh production-gate script does not exist and the current acceptance script stages a second remote source and is not bound to all proof artifacts.

- [ ] **Step 3: Add the exact fresh 1 GiB production gate**

Require explicit production-manifest path/digest, exact Darwin/Linux binary paths, local/remote public IPv4s, remote SSH target, TCP port, and output root. Verify the production manifest is a valid child of the experiment manifest/finalist decision and verify both override-free binary hashes against it before upload and again on the remote. Use its exact 1024 MiB payload identity. Run three capacity-valid production samples per direction with no linker/env transport override; each capacity control gets at most three attempts and three controls below 2050 Mbps postpone without starting UDP. Every started result is immutable and nonreplaceable. Validate each structured sample and immutably write `${campaign_root}/decisions/prerequisite.json` plus `${campaign_root}/decisions/prerequisite.sha256` through `udppeak prerequisite-decide` even on failure/postponement.

Run:

```bash
bash -n scripts/udp-file-production-gate.sh
mise exec -- go test ./scripts -run 'TestUDPFileProductionGate' -count=1
```

- [ ] **Step 4: Bind acceptance before any payload allocation**

Require:

```text
DERPHOLE_UDP_ACCEPT_CAMPAIGN_ROOT
DERPHOLE_UDP_ACCEPT_REMOTE
DERPHOLE_UDP_ACCEPT_REMOTE_PUBLIC_ADDR
DERPHOLE_UDP_ACCEPT_LOCAL_PUBLIC_ADDR
DERPHOLE_UDP_ACCEPT_TCP_PORT
```

Select the exact production binaries first, then verify the manifest, fresh prerequisite, fleet decision, and current hashes:

```bash
udppeak verify-prerequisite \
  -manifest "${campaign_root}/production-manifest.json" \
  -manifest-sha256 "$(cat "${campaign_root}/production-manifest.sha256")" \
  -decision "${campaign_root}/decisions/prerequisite.json" \
  -decision-sha256 "$(cat "${campaign_root}/decisions/prerequisite.sha256")" \
  -local-bin "${local_derphole}" \
  -linux-bin "${linux_derphole}"
udppeak artifact-verify -path "${campaign_root}/decisions/fleet.json" -sha256 "$(cat "${campaign_root}/decisions/fleet.sha256")"
```

The fleet decision must itself bind the same production manifest, prerequisite, production candidate, and binary pair. All verification occurs before 3 GiB source allocation, remote directory creation, or file transfer; the acceptance script never builds a replacement binary.

- [ ] **Step 5: Replace interleaving with exact disk-safe sequence**

Use this fixed sequence:

```text
forward-1 -> verify -> remove remote output
forward-2 -> verify -> remove remote output
forward-3 -> verify -> retain remote output as reverse source
reverse-1 -> verify -> remove local output
reverse-2 -> verify -> remove local output
reverse-3 -> verify -> remove local output
cleanup -> remove exact retained remote source and scoped directory
```

After the prerequisite/fleet verification succeeds, allocate the one local 3 GiB ordinary source, compute its exact size/hash, and immutably create `acceptance-manifest.json` as a child of the production manifest that also binds the prerequisite and fleet decision digests plus this payload identity. Verify that child before starting any file transfer. Run health, disk, and a qualifying same-direction TCP control before every file. Rehash/remove the local source after forward run three; rehash the retained remote source after reverse run three. A capacity-valid failed file remains in the immutable result set and is never replaced. Every sample binds and validates against the acceptance manifest and uses the Task 1 engine/payload/lane checks and selected-engine recovery checks. `udppeak acceptance-decide` writes a decision even on failure/postponement and requires direction CV at most 0.10.

- [ ] **Step 6: Document and commit**

Document preparation, stage commands, no-host-modification rule, 1 GiB prerequisite, Eric-last fleet rule, and the difference between acceptance and hard ceiling.

Run:

```bash
bash -n scripts/udp-file-production-gate.sh scripts/udp-file-acceptance.sh
mise exec -- go test ./scripts -run 'TestUDPFile(ProductionGate|Acceptance)' -count=1
```

Commit:

```text
bench: gate disk-safe UDP acceptance on fresh proof
```

### Task 12: Run full local verification and independent code review

**Files:**
- Modify only files required by verified failures from the commands below.

**Interfaces:**
- Consumes: Tasks 1-11.
- Produces: reviewed candidate/harness code safe enough to begin bounded live 1 GiB work.

- [ ] **Step 1: Run formatting, shell, and focused tests**

Run:

```bash
bash -n scripts/udp-peak-candidates.sh scripts/udp-peak-performance.sh scripts/udp-file-production-gate.sh scripts/udp-file-acceptance.sh scripts/promotion-benchmark-driver.sh
mise exec -- go test ./scripts ./pkg/udpbenchproof ./tools/udppeak ./pkg/transfertrace ./tools/transfertracecheck -count=1
```

Expected: PASS.

- [ ] **Step 2: Run pointer, race, Linux-build, and package gates**

Run:

```bash
GODEBUG=checkptr=2 mise exec -- go test ./pkg/session -count=1
mise exec -- go test -race ./pkg/session ./pkg/transfertrace ./pkg/udpbenchproof ./tools/udppeak -count=1
mise exec -- env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c ./pkg/session -o .tmp/session-linux.test
mise exec -- env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o .tmp/derphole-linux ./cmd/derphole
mise exec -- env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o .tmp/udppeak-linux ./tools/udppeak
```

Expected: PASS with no race, checkptr, or cross-build errors.

- [ ] **Step 3: Run repository gates**

Run:

```bash
mise run test
mise run smoke-local
mise run check
```

Expected: PASS, including govulncheck and the quality gate.

- [ ] **Step 4: Request two-stage independent review**

First review spec compliance and acceptance mechanics. Second review code quality, syscall state, pointer lifetime, host safety, and exact cleanup. Fix every approved finding with its focused RED/GREEN test, rerun affected gates, and absorb fixes into the owning unpublished commit instead of creating micro-fix commits. No candidate, fleet, 1 GiB, or 3 GiB live host test starts until all preceding proof code, full gates, and both reviews pass.

- [ ] **Step 5: Create a reviewed implementation checkpoint**

Run `but pull --check`, inspect `but diff`, and ensure the branch contains only the framing checkpoint, design, plan, and implementation commits. Do not push or land without explicit user instruction.

### Task 13: Run the bounded candidate campaign and select the production default

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet_candidate.go` only after the finalist decision identifies a winner.
- Test: `pkg/session/external_v2_bulk_packet_candidate_test.go`
- Artifacts: immutable `production-manifest.json` and digest after the source-controlled winner commit.
- Artifacts: `.tmp/udp-peak/<campaign-id>/` (not committed).

**Interfaces:**
- Consumes: reviewed implementation and frozen control pair.
- Produces: deterministic winner or complete hard-ceiling candidate evidence.

- [ ] **Step 1: Resolve the conditional zero-copy gate, then freeze identities**

Using the reviewed harness, run one bounded capacity-valid combined-GSO3 profiling diagnostic before the manifest is frozen. If a fresh optimized sender profile attributes at least 10 percent of CPU to copy, memmove, or buffer movement, stop and write/approve a focused TDD sub-plan for a synchronous `MSG_ZEROCOPY` candidate, then add that exact candidate before rebuilding the registry. If the share is below 10 percent, record the profile and closed gate in the manifest; do not implement zero-copy. io_uring remains closed. Index the recent exact one-owner and two-owner io_uring artifacts as rejected evidence. Historical lane, GRO, and related artifacts count only when identity and conditions are demonstrably comparable; otherwise allow one bounded fresh diagnostic and label it non-acceptance evidence.

Build the final registry, run `prepare`, verify two online Hetz CPUs, bind boot ID/public IPs/kernel/source hash/inventory and the zero-copy-gate artifact, and confirm disk margin. Install and tune nothing. If any prerequisite is missing, stop before a transfer.

- [ ] **Step 2: Run reverse screening under capacity brackets**

Execute the generated screening schedule. Every candidate receives one 1 GiB Hetz-to-Mac file bracketed by the frozen GSO3 control. Low capacity starts no file; a started failure stays in evidence. Stop all Hetz use for the session after reboot, OOM, severe pressure, kernel error, or cleanup failure.

- [ ] **Step 3: Run preliminary and finalist schedules**

Run three capacity-valid 1 GiB samples per surviving candidate in each direction, then the generated finalist rotation for three more per direction. Let `udppeak evaluate` build the complete pairwise graph, SCC frontier, and deterministic retained winner. Do not manually promote a prettier run.

- [ ] **Step 4: Select the winner as source-controlled production default**

Change only the source-controlled engine/policy and, for bulk, coalescing, connected native send, and GSO constants to the exact retained winner. Keep linker candidate values benchmark-only. Add/update the production-default test and run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacketProductionCandidate' -count=1
mise run check
```

Commit:

```text
perf: select peak UDP file default
```

- [ ] **Step 5: Rebuild, freeze the production child manifest, and run the fresh gate**

Build clean binaries with no benchmark transport override. Create an immutable production manifest that hash-links the experiment manifest and finalist decision, records the new winner commit and rebuilt Darwin/Linux hashes, binds a fresh exact 1 GiB payload identity, and records the override-free environment. Verify the transition and both local/remote hashes before any production sample. Run exactly three fresh capacity-valid 1 GiB normal files in each direction. Every sample must exceed 2.0 Gbps, have exact carrier accounting, repair or QUIC recovery below 2 percent, flatline below one second, Hetz-role CPU below 8 seconds/GiB, CV at most 0.10, unchanged OOM state, and complete cleanup.

If only Hetz-to-Mac passes, stop and write the separately reviewed bounded Linux receive-side design required by the specification. If either direction misses, do not run 3 GiB.

### Task 14: Run the fleet guard, final acceptance, or hard-ceiling proof

**Files:**
- Artifacts: `.tmp/udp-peak/<campaign-id>/` (not committed).

**Interfaces:**
- Consumes: passed production decision or retained winner with nine samples per direction.
- Produces: exact six-run acceptance, or hard evidence that acceptance remains unmet at the measured ceiling.

- [ ] **Step 1: Run the mandatory reachable-fleet guard on either conclusion path**

Probe the bound inventory without mutation. Run three unoverridden 1 GiB normal files in both directions on every mandatory reachable host. Judge lower-capacity hosts against paired capacity and stable behavior while still requiring exact integrity, intended UDP or compatible production fallback, bounded selected-engine recovery and CPU, no flatline, complete trace/resource evidence, and zero leaks. Run Eric last, one sample at a time; stop it permanently for the session on disappearance, reboot, OOM, pressure, kernel error, or cleanup failure. Write and hash the fleet decision whether the production gate passed or the campaign is headed to hard-ceiling evidence; a hard-ceiling fleet pass never authorizes 3 GiB.

- [ ] **Step 2: If production and fleet pass, run exact 3 GiB acceptance**

Invoke the disk-safe acceptance driver. Run exactly three Mac-to-Hetz files followed by exactly three Hetz-to-Mac files. Every file must exceed 2.0 Gbps and pass all proof gates. A capacity-valid failure fails acceptance and is not replaced.

- [ ] **Step 3: If production misses 2.0 Gbps, run the bounded ceiling sweep**

Do not run 3 GiB. Preserve the three production samples plus six finalist samples per direction. Create and verify an immutable ceiling child manifest binding the production manifest, peak and fleet decisions, exact diagnostic binaries, fixed sweep schedule, profile schedule, and thresholds. Run public UDP iperf with 1,400-byte datagrams at `1.2,1.5,1.8,2.1,2.4` Gbps ascending and descending in both directions, bracketed by qualifying TCP controls. Capture repeated CPU profiles and kernel/network counters as typed immutable `CeilingSweepPoint` and `CeilingProfile` artifacts.

- [ ] **Step 4: Evaluate and audit the final decision**

Acceptance requires `AcceptanceMet=true`, exactly six accepted 3 GiB sample IDs, three per direction, and every goodput above 2.0 Gbps. Run `udppeak ceiling-decide` for the alternative path; it mechanically requires the approved plateau, saturation, repeated mechanism, complete candidate registry, nine stable winner samples per direction, and `AcceptanceMet=false`. Independent review must reproduce the verdict from the referenced raw sweep/profile/sample artifacts before the conclusion is reported.

- [ ] **Step 5: Preserve evidence and report exact status**

Keep manifests, hashes, schedules, normalized results, decisions, traces, profiles, health, and cleanup artifacts. Remove multi-gigabyte payloads. Report local code state separately from any branch push or landing. Mark the active goal complete only for exact six-run acceptance; a hard-ceiling decision leaves the acceptance goal unmet.
