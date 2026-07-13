# UDP File Transfers Above 2 Gbps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make normal large-file transfers use derphole's optimized public-UDP bulk data plane efficiently enough that three 3 GiB runs in each Hetzner direction all exceed 2.0 Gbps on the exact two-vCPU VM, with hashes, traces, resources, and payload transport independently verified.

**Architecture:** Keep the authenticated `bulk-packets-v1` wire format, but negotiate a batch-native capability that lets capable peers prefer it for large normal files. Run one bounded authenticated capacity probe before payload, seed the existing controller from the highest clean train, then move file data through persistent concurrent lane writers and batch-shaped receive/decrypt/accounting stages. Preserve QUIC and direct TCP as pre-payload compatibility fallbacks, but never count TCP toward this gate.

**Tech Stack:** Go 1.26, `net.PacketConn`, XChaCha20-Poly1305, `golang.org/x/net/ipv4`, Linux UDP GSO/`sendmmsg`/`recvmmsg`, Darwin `sendmsg_x`/`recvmsg_x`, GitButler, Bash benchmark drivers, Python 3 result normalization, `mise` verification.

## Global Constraints

- Final acceptance is three ordinary 3 GiB `send FILE` / `receive TOKEN` transfers in each direction between this Mac and `root@hetz`.
- Every accepted run must exceed 2.0 Gbps receiver-anchored verified-file goodput; the mean is not a substitute.
- Every accepted payload byte must use public UDP. Reject direct TCP, TLS-over-TCP, relay payload, or mid-payload fallback evidence.
- Set `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` only to isolate the public path. Leave batch, force-mode, and pacing overrides unset in final runs.
- Keep the three-run coefficient of variation at or below 10 percent per direction; rerun only a complete three-run cell after cooldown.
- Match exact size and SHA-256, preserve zero peer/application byte delta, record no one-second flatline, keep repair below 2 percent, and keep `scan_checks_per_packet` below 2.0.
- Keep the Hetzner role below 8.0 total CPU seconds per verified GiB and verify its online CPU count remains exactly two.
- Do not stop resident services, add swap, change the CPU allocation, or tune the host solely for the benchmark.
- The live harness may remove only its own exact run directory and verified receive payloads. It must not use broad process-kill or filesystem cleanup commands.
- Batch queues and buffer pools stay bounded under the Hetzner VM's observed low-memory background load.
- Do not change the authenticated `bulk-packets-v1` data format, cipher, DERP rendezvous, hole punching, production Tailscale discovery, or pipe workload in this plan.
- Use GitButler for branch, commit, and history writes. At each commit step, run `but diff`, pass only the CLI IDs shown for that task's listed files to `but commit codex/udp-file-2gbps`, use the exact commit subject printed in the task, and leave unrelated changes untouched.

---

### Task 1: Negotiate and select the production batch-native UDP file mode

**Files:**
- Modify: `pkg/session/external_v2_protocol.go:21-60`
- Modify: `pkg/session/external_v2_block.go:64-188`
- Modify: `pkg/session/external_v2.go:1010-1040`
- Modify: `pkg/session/external_v2_offer.go:430-465,860-885`
- Modify: `pkg/session/external_v2_bulk_packet_batch.go:5-130`
- Test: `pkg/session/external_v2_protocol_test.go:130-290`
- Test: `pkg/session/external_v2_bulk_packet_batch_test.go:1-40`
- Test: `pkg/session/external_v2_test.go`
- Test: `pkg/session/external_v2_offer_test.go`

**Interfaces:**
- Consumes: existing `BlockPacketCapable`, `externalV2AcceptedBlockTransferPolicy`, `externalV2SelectFileTransferMode`, and the unchanged `bulk-packets-v1` wire mode.
- Produces: `BlockPacketBatchCapable bool` on claim and accept, `BatchNative bool` on `externalV2BlockTransferPolicy`, and `externalV2BatchNativeBulk(claimCapable, acceptCapable bool) bool` for later probe plumbing.

- [ ] **Step 1: Write failing capability and production-selection tests**

Add table cases that prove a capable large-file pair selects bulk even with eight public receiver candidates and an available direct-TCP advertisement, while either missing capability preserves the current candidate policy and old-peer behavior:

```go
func TestExternalV2BatchNativePeersPreferBulkForLargeFiles(t *testing.T) {
	claim := externalV2Claim{
		BlockCapable:            true,
		BlockPacketCapable:      true,
		BlockPacketBatchCapable: true,
		BlockSize:               3 << 30,
	}
	for port := 10000; port < 10008; port++ {
		claim.Candidates = append(claim.Candidates, fmt.Sprintf("203.0.113.10:%d", port))
	}
	policy := externalV2AcceptedBlockTransferPolicy(claim, true, true, nil)
	if policy.Mode != externalV2TransferModeBulkPackets || !policy.BatchNative {
		t.Fatalf("policy = %#v, want batch-native bulk", policy)
	}
}

func TestExternalV2BatchNativeSelectionRequiresBothPeers(t *testing.T) {
	for _, tt := range []struct {
		name, want string
		claim, accept bool
	}{
		{name: "both", claim: true, accept: true, want: externalV2TransferModeBulkPackets},
		{name: "old claimant", claim: false, accept: true, want: externalV2TransferModeBlocks},
		{name: "old acceptor", claim: true, accept: false, want: externalV2TransferModeBlocks},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := externalV2SelectOptimizedFileTransferMode(externalV2TransferModeBlocks, 3<<30, tt.claim, tt.accept)
			if got != tt.want { t.Fatalf("mode = %q, want %q", got, tt.want) }
		})
	}
}
```

Replace the environment-gate test with a constructor test proving every bulk sender and receiver receives a platform batch backend without `DERPHOLE_TEST_BULK_BATCHED_IO`.

- [ ] **Step 2: Run the focused tests and verify the intended failures**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2(BatchNative|BulkPacketBatchBackend)' -count=1
```

Expected: FAIL because `BlockPacketBatchCapable`, `BatchNative`, and `externalV2SelectOptimizedFileTransferMode` do not exist and batching is still environment-gated.

- [ ] **Step 3: Add the capability, selection rule, and unconditional local batch backend**

Add the negotiated fields without changing old JSON field meanings:

```go
type externalV2Claim struct {
	// existing fields
	BlockPacketCapable      bool `json:"block_packet_capable,omitempty"`
	BlockPacketBatchCapable bool `json:"block_packet_batch_capable,omitempty"`
}

type externalV2Accept struct {
	// existing fields
	BlockPacketBatchCapable bool `json:"block_packet_batch_capable,omitempty"`
}

func externalV2BatchNativeBulk(claimCapable, acceptCapable bool) bool {
	return claimCapable && acceptCapable
}

func externalV2SelectOptimizedFileTransferMode(policy string, size int64, claimBatch, acceptBatch bool) string {
	if policy == externalV2TransferModeBlocks && size >= externalV2DirectTCPMinFileSize && externalV2BatchNativeBulk(claimBatch, acceptBatch) {
		return externalV2TransferModeBulkPackets
	}
	return policy
}
```

Set the claim field wherever `BlockPacketCapable` is set, set the accept field whenever the local side has a valid block source or receiver, run optimized selection before direct-TCP selection, and include `batch_native:%t` in `v2-block-policy` and `v2-file-transfer-selection` debug lines. Change the policy signature to:

```go
func externalV2AcceptedBlockTransferPolicy(
	claim externalV2Claim,
	blockTransfer bool,
	acceptBatchCapable bool,
	acceptCandidates []string,
) externalV2BlockTransferPolicy
```

Delete `externalV2BulkPacketBatchedIOEnabled`. Always construct `newExternalV2BulkPacketBatchConn` for every active bulk lane. The portable implementation remains the safe fallback, so this is an engine promotion rather than a platform requirement.

- [ ] **Step 4: Run focused negotiation, protocol, and bulk tests**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2(BatchNative|BlockTransferPolicy|DirectTCPFileSelection|BulkPacket)' -count=1
```

Expected: PASS. Existing old-peer, compact-candidate, Tailscale-ignore, invalid-candidate, direct-TCP, and wire-compatibility cases must remain green.

- [ ] **Step 5: Commit the production selection unit**

Run `but diff`, select only the Task 1 file and hunk IDs, then commit with:

```text
perf: select batch-native UDP for large files
```

### Task 2: Replace serial slab draining with persistent concurrent lane writers

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet_batched_sender.go:14-319`
- Modify: `pkg/session/external_v2_bulk_packet_batch.go:20-120`
- Test: `pkg/session/external_v2_bulk_packet_batched_sender_test.go:1-220`

**Interfaces:**
- Consumes: existing slab preparation, per-lane packet partitioning, `writeDataBatch`, the shared thread-safe `rate.Limiter`, and platform `WriteBatch` backends.
- Produces: `externalV2BulkPacketLaneJob`, `externalV2BulkPacketSlabLease.release`, `startExternalV2BulkPacketLaneWriters`, exact per-lane ordering, bounded `BulkLaneQueuePeak`, and first-error cancellation.

- [ ] **Step 1: Add failing concurrency, ordering, cancellation, and slab-release tests**

Use one blocking capture backend per lane. Hold lane 0 after it accepts its first batch and assert lane 1 writes before lane 0 is released; then assert every lane's indexes remain increasing and every slab returns to a counting pool exactly once:

```go
func TestExternalV2BulkPacketSenderWritesLanesConcurrently(t *testing.T) {
	sender, lanes := newConcurrentLaneSenderFixture(t, 4, externalV2BulkPacketSlabPackets*2)
	lanes[0].blockFirst = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- sender.sendInitialPacketsBatched() }()
	<-lanes[0].started
	select {
	case <-lanes[1].started:
	case <-time.After(time.Second):
		t.Fatal("lane 1 did not progress while lane 0 was blocked")
	}
	close(lanes[0].blockFirst)
	if err := <-done; err != nil { t.Fatal(err) }
	assertLaneIndexesStrictlyIncrease(t, lanes)
}

func TestExternalV2BulkPacketLaneWritersCancelAndReleaseEverySlab(t *testing.T) {
	sender, pool := newFailingLaneSenderFixture(t, 3)
	err := sender.sendInitialPacketsBatched()
	if !errors.Is(err, errInjectedLaneWrite) { t.Fatalf("error = %v", err) }
	if got, want := pool.gets.Load(), pool.puts.Load(); got != want {
		t.Fatalf("slab pool gets=%d puts=%d", got, want)
	}
}
```

- [ ] **Step 2: Run the sender tests and verify serial draining fails the concurrency assertion**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(SenderWritesLanesConcurrently|LaneWriters|BatchedSender)' -count=1
```

Expected: FAIL because the current consumer drains each slab and lane synchronously.

- [ ] **Step 3: Implement bounded per-lane queues with a shared slab lease**

Add these types and keep queue depth at two jobs per lane:

```go
const externalV2BulkPacketLaneQueueDepth = 2

type externalV2BulkPacketSlabLease struct {
	slab      *externalV2BulkPacketSlab
	pool      *sync.Pool
	remaining atomic.Int32
}

func (l *externalV2BulkPacketSlabLease) release() {
	if l != nil && l.remaining.Add(-1) == 0 {
		l.pool.Put(l.slab)
	}
}

type externalV2BulkPacketLaneJob struct {
	sequence int
	messages []externalV2BulkPacketBatchMessage
	lease    *externalV2BulkPacketSlabLease
}
```

Start one writer for each active lane. The ordered slab consumer dispatches non-empty lane jobs in slab-sequence order; the lane channel preserves per-lane order. Every accepted or canceled job calls `release` exactly once. Writers report one first error through a buffered channel and cancel the shared context. `rate.Limiter.WaitN`, packet counters, and batch metrics remain aggregate and atomic. Record the maximum lane channel depth in `batchLaneQueuePeak`.

- [ ] **Step 4: Run sender tests and the race detector**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(SenderWritesLanesConcurrently|LaneWriters|BatchedSender)' -race -count=1
```

Expected: PASS with no race report, no duplicate packet index, no ordering regression, and balanced slab-pool accounting.

- [ ] **Step 5: Commit the concurrent sender pipeline**

Commit only Task 2 changes with:

```text
perf: write bulk UDP lanes concurrently
```

### Task 3: Carry receive work as batches through decrypt and accounting

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet_batched_receiver.go:13-184`
- Modify: `pkg/session/external_v2_bulk_packet.go:121-140,640-905`
- Modify: `pkg/session/external_v2_bulk_packet_missing.go:21-64`
- Modify: `pkg/session/external_v2_bulk_packet_batch.go:20-120`
- Test: `pkg/session/external_v2_bulk_packet_batched_receiver_test.go:1-190`
- Test: `pkg/session/external_v2_bulk_packet_test.go`
- Test: `pkg/session/external_v2_bulk_packet_missing_test.go`

**Interfaces:**
- Consumes: native receive batches, reusable sealed and payload pools, receive assembler, missing tracker, and async writer.
- Produces: `externalV2BulkPacketReceiveBatch`, `observeN(at time.Time, packets uint32)`, one coordinator timestamp and repair update per batch, `BulkDecryptBatches`, `BulkDecryptDatagrams`, and `BulkReceiveQueuePeak`.

- [ ] **Step 1: Write failing batch-shape and accounting-equivalence tests**

Change the reader test to require one channel receive containing 64 authenticated results, not 64 channel receives. Add a deterministic reordered/loss/repaired fixture and compare its final byte count, missing-tracker stats, and digest to the existing single-result coordinator:

```go
func TestExternalV2BulkPacketDecryptEmitsOneReceiveBatch(t *testing.T) {
	auth, packets := sealedBulkPacketFixture(t, 64)
	conn := &scriptedReceiveExternalV2BulkPacketBatchConn{packets: packets, delivered: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	batches := make(chan externalV2BulkPacketReceiveBatch, 1)
	errs := make(chan error, 1)
	done := startExternalV2BulkPacketBatchedDataReaders(ctx, []externalV2BulkPacketBatchConn{conn}, auth, batches, errs)
	batch := <-batches
	defer batch.release()
	if len(batch.results) != 64 { t.Fatalf("batch size = %d, want 64", len(batch.results)) }
	cancel()
	<-done
}

func TestExternalV2BulkPacketBatchAccountingMatchesSinglePacketAccounting(t *testing.T) {
	want := runBulkReceiveSequence(t, false, []uint32{0, 2, 1, 4, 3, 4})
	got := runBulkReceiveSequence(t, true, []uint32{0, 2, 1, 4, 3, 4})
	if diff := cmp.Diff(want, got); diff != "" { t.Fatalf("accounting mismatch (-want +got):\n%s", diff) }
}
```

- [ ] **Step 2: Run focused tests and verify the channel-shape failure**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(DecryptEmitsOneReceiveBatch|BatchAccounting|BatchedReceiver|ReceiveRate)' -count=1
```

Expected: FAIL because decrypt workers currently emit one `externalV2BulkPacketReceiveResult` per channel operation and `observe` accepts only one packet.

- [ ] **Step 3: Implement pooled decrypt batches and batch coordinator accounting**

Use these core interfaces:

```go
type externalV2BulkPacketDecryptBatchJob struct {
	buffers []*externalV2BulkPacketSealedBuffer
	lengths []int
}

type externalV2BulkPacketReceiveBatch struct {
	results []externalV2BulkPacketReceiveResult
}

func (b *externalV2BulkPacketReceiveBatch) release() {
	for i := range b.results { b.results[i].release() }
	b.results = b.results[:0]
}

func (r *externalV2BulkPacketReceiveRate) observeN(at time.Time, packets uint32) {
	if at.IsZero() || packets == 0 { return }
	if r.sampleStarted.IsZero() { r.sampleStarted = at }
	r.samplePackets += packets
	if elapsed := at.Sub(r.sampleStarted); elapsed >= externalV2BulkPacketRateSampleInterval {
		r.update(r.samplePackets, elapsed)
		r.sampleStarted, r.samplePackets = at, 0
	}
}
```

Readers copy one native batch into one pooled decrypt job. A decrypt worker authenticates the whole job and emits one receive batch. The coordinator calls `time.Now()` once, loops results with `handleDataResultAt(result, now)`, calls `receiveRate.observeN` once with the accepted count, and calls `sendActiveMissing(now)` once. Invalid authentication remains non-fatal; invalid authenticated payload length remains fatal. Release every buffer on success, cancellation, and partial failure.

- [ ] **Step 4: Run batch receiver, missing-tracker, integrity, and race tests**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(DecryptEmitsOneReceiveBatch|BatchAccounting|BatchedReceiver|ReceiveRate|Missing|Transfer)' -race -count=1
```

Expected: PASS with unchanged integrity, duplicate handling, 100 ms repair cadence, and `scan_checks_per_packet` behavior.

- [ ] **Step 5: Commit the batch-shaped receive pipeline**

Commit only Task 3 changes with:

```text
perf: account bulk UDP receives by batch
```

### Task 4: Add a real Darwin `sendmsg_x` batch backend

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet_batch_darwin.go:10-206`
- Test: `pkg/session/external_v2_bulk_packet_batch_darwin_test.go:1-150`
- Test: `pkg/session/external_v2_bulk_packet_batch_test.go:50-120`

**Interfaces:**
- Consumes: `externalV2BulkPacketDarwinMsgHdr`, `syscall.RawConn`, one-buffer messages, and IPv4/IPv6 UDP destinations.
- Produces: `externalV2BulkPacketDarwinSendmsgX`, `prepareSendmsgX`, `sendmsgX`, backend trace value `darwin-sendmsg-x`, and portable fallback for unsupported address or syscall cases.

- [ ] **Step 1: Add a Darwin-only multi-datagram send test**

Create two loopback UDP sockets, send 32 distinct datagrams in one `WriteBatch`, receive all 32, and require one send call and backend `darwin-sendmsg-x`:

```go
func TestExternalV2BulkPacketDarwinSendmsgXWritesBatch(t *testing.T) {
	sender, receiver := listenDarwinBulkBatchPair(t)
	messages := make([]externalV2BulkPacketBatchMessage, 32)
	for i := range messages {
		messages[i] = externalV2BulkPacketBatchMessage{Buffers: [][]byte{{byte(i), 0xaa}}, Addr: receiver.LocalAddr()}
	}
	written, err := sender.WriteBatch(context.Background(), messages)
	if err != nil { t.Fatal(err) }
	if written != len(messages) { t.Fatalf("written=%d want=%d", written, len(messages)) }
	stats := sender.Stats()
	if stats.Backend != "darwin-sendmsg-x" || stats.SendCalls != 1 || stats.SendDatagrams != 32 {
		t.Fatalf("stats = %+v", stats)
	}
}
```

- [ ] **Step 2: Run the Darwin test and verify the current loop fails the syscall-count assertion**

Run on this Mac:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacketDarwin(SendmsgX|Batch)' -count=1
```

Expected: FAIL because `WriteBatch` loops through `PacketConn.WriteTo` and reports `portable-single` with 32 calls.

- [ ] **Step 3: Implement `sendmsg_x` with exact raw sockaddr storage**

Add the syscall constant and per-message destination storage:

```go
//lint:ignore SA1019 x/sys has no sendmsg_x wrapper; Darwin batching requires this stable XNU syscall.
const externalV2BulkPacketDarwinSendmsgX = unix.SYS_SENDMSG_X

type externalV2BulkPacketDarwinSockaddr struct {
	storage unix.RawSockaddrStorage
}
```

Populate one `Iovec`, one `externalV2BulkPacketDarwinMsgHdr`, and one raw sockaddr per message. Support `*net.UDPAddr` with IPv4 or IPv6; preserve IPv6 zone indexes through `net.InterfaceByName`. Call `unix.Syscall6(SYS_SENDMSG_X, fd, &headers[0], count, MSG_DONTWAIT, 0, 0)` inside `RawConn.Write`, retry `EINTR`, return `false` for `EAGAIN`, and fall back to the existing portable loop for unsupported destinations or `ENOSYS`/`EOPNOTSUPP`. Set each completed message's `N`, record one call with all accepted datagrams, and retain buffers, headers, iovecs, and sockaddr storage with `runtime.KeepAlive`.

- [ ] **Step 4: Run Darwin, portable, and race tests**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(Darwin|PortableBatch|BatchWriteAll)' -race -count=1
```

Expected: PASS. The sender backend must be `darwin-sendmsg-x`; receive remains `darwin-recvmsg-x`; cancellation and portable fallback remain green.

- [ ] **Step 5: Commit the Darwin batch sender**

Commit only Task 4 changes with:

```text
perf: batch Darwin bulk UDP sends
```

### Task 5: Probe public UDP capacity before payload and seed the controller

**Files:**
- Create: `pkg/session/external_v2_bulk_packet_probe.go`
- Create: `pkg/session/external_v2_bulk_packet_probe_test.go`
- Modify: `pkg/session/external_v2_bulk_packet.go:20-55,140-360,640-905,1130-1260`
- Modify: `pkg/session/external_v2_block.go:220-370`
- Modify: `pkg/session/external_v2.go:320-425`
- Modify: `pkg/session/external_v2_offer.go:275-335`
- Test: `pkg/session/external_v2_bulk_packet_test.go`
- Test: `pkg/session/external_v2_test.go`
- Test: `pkg/session/external_v2_offer_test.go`

**Interfaces:**
- Consumes: validated raw UDP lanes, data/control AEADs, native batch backends, the existing controller and pacer, and the negotiated batch capability.
- Produces: authenticated probe data/end/ack packet kinds, `externalV2BulkPacketProbeResult`, `setInitialPaceMbps`, and sentinel `errExternalV2BulkPacketProbeRejected` that both sides convert to QUIC before any file byte.

- [ ] **Step 1: Write failing pure probe-policy tests**

Define exact constants and test clean-rate selection, pressure stop, caps, and no-clean rejection:

```go
func TestExternalV2BulkPacketProbeSelectsNinetyPercentOfHighestCleanTrain(t *testing.T) {
	result, err := selectExternalV2BulkPacketProbe([]externalV2BulkPacketProbeTrainResult{
		{RateMbps: 128, Sent: 560, Received: 560},
		{RateMbps: 512, Sent: 2241, Received: 2200},
		{RateMbps: 1000, Sent: 4377, Received: 4230},
		{RateMbps: 1600, Sent: 7003, Received: 6400, Pressure: true},
	})
	if err != nil { t.Fatal(err) }
	if result.SelectedMbps != 900 { t.Fatalf("selected=%d want=900", result.SelectedMbps) }
}

func TestExternalV2BulkPacketProbeRejectsWithoutCleanTrain(t *testing.T) {
	_, err := selectExternalV2BulkPacketProbe([]externalV2BulkPacketProbeTrainResult{{RateMbps: 128, Sent: 560, Received: 400}})
	if !errors.Is(err, errExternalV2BulkPacketProbeRejected) { t.Fatalf("error=%v", err) }
}
```

Also test that each train is at most 50 ms and 16 MiB, rates are exactly `128, 512, 1000, 1600, 2400`, forged acknowledgements fail authentication, repeated end frames use distinct nonces, and probe bytes never increment file payload counters.

- [ ] **Step 2: Run probe tests and verify missing symbols fail**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacketProbe' -count=1
```

Expected: FAIL because probe types, packet kinds, encoding, and selection do not exist.

- [ ] **Step 3: Implement the bounded authenticated probe protocol**

Create these exact public-to-package interfaces:

```go
var errExternalV2BulkPacketProbeRejected = errors.New("bulk packet capacity probe rejected")

var externalV2BulkPacketProbeRatesMbps = [...]int{128, 512, 1000, 1600, 2400}

const (
	externalV2BulkPacketProbeDuration   = 50 * time.Millisecond
	externalV2BulkPacketProbeMaxBytes   = 16 << 20
	externalV2BulkPacketProbeAckTimeout = 250 * time.Millisecond
	externalV2BulkPacketProbeSettle     = 10 * time.Millisecond

	externalV2BulkPacketProbeData byte = 5
	externalV2BulkPacketProbeEnd  byte = 6
	externalV2BulkPacketProbeAck  byte = 7
)

type externalV2BulkPacketProbeTrainResult struct {
	RateMbps int
	Sent     uint32
	Received uint32
	Pressure bool
}

type externalV2BulkPacketProbeResult struct {
	SelectedMbps int
	Duration     time.Duration
	Trains       []externalV2BulkPacketProbeTrainResult
}
```

Encode train, sequence, expected count, and target rate in a fixed 16-byte big-endian probe prefix. Seal probe data, end, and acknowledgement frames with the control AEAD; the visible packet kind selects which AEAD to attempt, but no probe field is trusted before authentication. Fill probe datagrams to normal data size. Send three uniquely indexed end frames, settle for 10 ms on the receiver, then return an authenticated acknowledgement with sent, received, and pressure fields. A train is clean only when `received*100 >= sent*90` and neither side observed `ENOBUFS`, full bounded queues, truncation, or local overflow. Stop after the first pressured train. Seed at `clamp(highestClean*90/100, 128, 2400)`.

Add:

```go
func (s *externalV2BulkPacketSender) setInitialPaceMbps(mbps int) {
	mbps = min(externalV2BulkPacketCeilingWireMbps, max(externalV2BulkPacketMinimumWireMbps, mbps))
	s.initialPaceMbps = mbps
	s.currentPaceMbps.Store(int64(mbps))
	s.pacer.SetLimitAt(time.Now(), externalV2BulkPacketRateLimit(mbps))
	s.controller = newExternalV2BulkPacketController(mbps)
}
```

Run the probe after hello and before starting the controller, repair worker, or initial file sender. The receiver keeps hello active through probe traffic and assigns `runID` only on the first real data packet.

- [ ] **Step 4: Implement symmetric pre-payload QUIC fallback**

Pass `batchNative bool` from negotiated claim/accept state into bulk send/receive. When either side returns `errExternalV2BulkPacketProbeRejected`, cancel and drain all bulk workers, clear socket deadlines, emit `v2-bulk-probe=fallback-before-payload`, and continue through the existing QUIC-on-raw-conns branch. Any non-probe bulk error remains fatal. Add an end-to-end test that drops 20 percent of the 128 Mbps train, asserts zero sink/file bytes before fallback, then completes through QUIC with an exact digest.

- [ ] **Step 5: Run probe, fallback, controller, and end-to-end tests with race detection**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2(BulkPacketProbe|BulkPacketBatchedTransfer|BulkPacketController|ProbeFallback)' -race -count=1
```

Expected: PASS with exact probe caps, authenticated results, zero pre-fallback payload, and no leaked worker.

- [ ] **Step 6: Commit the capacity probe and fallback**

Commit only Task 5 changes with:

```text
perf: seed bulk UDP from a capacity probe
```

### Task 6: Expose enough trace evidence to prove efficiency and payload transport

**Files:**
- Modify: `pkg/session/external_v2_bulk_packet_batch.go:20-120`
- Modify: `pkg/session/external_transfer_metrics.go:123-175,700-850`
- Modify: `pkg/transfertrace/trace.go:70-210,430-510`
- Modify: `tools/transfertracecheck/main.go`
- Modify: `cmd/derphole/main.go:12-18`
- Create: `cmd/derphole/test_cpu_profile.go`
- Test: `pkg/session/external_transfer_metrics_test.go`
- Test: `pkg/transfertrace/trace_test.go`
- Test: `tools/transfertracecheck/main_test.go`
- Test: `cmd/derphole/main_test.go`

**Interfaces:**
- Consumes: sender lane depth, receive batch depth, decrypt counts, probe result, platform backend counters, and existing `DirectTransport`.
- Produces: trace/CSV columns `bulk_lane_queue_peak`, `bulk_receive_queue_peak`, `bulk_decrypt_batches`, `bulk_decrypt_datagrams`, `bulk_probe_selected_mbps`, `bulk_probe_duration_ms`, `bulk_probe_trains`, `bulk_probe_sent_datagrams`, `bulk_probe_received_datagrams`, `bulk_probe_loss_ppm`, and `bulk_probe_pressure`.

- [ ] **Step 1: Write failing recorder and checker tests for all new fields**

Construct one `transfertrace.Snapshot` with healthy non-zero batch/probe fields and assert exact CSV values. Construct a second with `DirectTransport="tcp"` and assert UDP-only checking rejects it:

```go
func TestRecorderWritesBulkPipelineAndProbeDiagnostics(t *testing.T) {
	snap := Snapshot{
		DirectTransport: "udp", BulkBatchPresent: true,
		BulkLaneQueuePeak: 2, BulkReceiveQueuePeak: 3,
		BulkDecryptBatches: 100, BulkDecryptDatagrams: 6400,
		BulkProbeSelectedMbps: 2160, BulkProbeDurationMS: 250,
		BulkProbeTrains: 5, BulkProbeSentDatagrams: 30000,
		BulkProbeReceivedDatagrams: 29800, BulkProbeLossPPM: 6666,
	}
	row := recordOneSnapshot(t, snap)
	assertColumn(t, row, traceColumnIndexes(t), "bulk_probe_selected_mbps", "2160")
	assertColumn(t, row, traceColumnIndexes(t), "bulk_decrypt_datagrams", "6400")
}
```

- [ ] **Step 2: Run trace and metrics tests and verify missing columns fail**

Run:

```bash
mise exec -- go test ./pkg/transfertrace ./tools/transfertracecheck ./pkg/session -run 'Test(RecorderWritesBulkPipeline|TransferTraceCheckUDP|ExternalTransferMetricsBulk)' -count=1
```

Expected: FAIL because the new snapshot, diagnostics, CSV columns, and UDP-only assertion do not exist.

- [ ] **Step 3: Thread batch/probe diagnostics through metrics and trace output**

Extend `externalV2BulkPacketBatchStats`, `externalDirectTransferDiagnostics`, `externalTransferMetrics`, and `transfertrace.Snapshot` with the exact fields listed above. Aggregate counters by sum, queue depths by maximum, probe selected rate/duration by final value, and loss as integer parts per million:

```go
func externalV2BulkPacketProbeLossPPM(sent, received uint64) uint64 {
	if sent == 0 || received >= sent { return 0 }
	return (sent - received) * 1_000_000 / sent
}
```

Emit empty optional columns for non-bulk traces and numeric healthy zeroes when bulk diagnostics are present. Extend `transfertracecheck` with `-require-direct-transport udp` and `-forbid-relay-payload`; make either mismatch a non-zero exit.

- [ ] **Step 4: Run metrics, trace, and checker tests**

Run:

```bash
mise exec -- go test ./pkg/transfertrace ./tools/transfertracecheck ./pkg/session -run 'Test(RecorderWritesBulk|TransferTraceCheck|ExternalTransferMetricsBulk)' -count=1
```

Expected: PASS with exact headers, stable optional-field behavior, UDP enforcement, and no regression in existing trace parsing.

- [ ] **Step 5: Add a test-only live CPU-profile hook**

Wrap `runMain` with a helper that starts `runtime/pprof` only when `DERPHOLE_TEST_CPU_PROFILE` names a file. Return a startup or close error through the existing stderr/exit-code path, and leave production behavior unchanged when the variable is empty:

```go
const derpholeTestCPUProfileEnv = "DERPHOLE_TEST_CPU_PROFILE"

func startDerpholeTestCPUProfile(path string) (func() error, error) {
	if strings.TrimSpace(path) == "" { return func() error { return nil }, nil }
	file, err := os.Create(path)
	if err != nil { return nil, err }
	if err := pprof.StartCPUProfile(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() error {
		pprof.StopCPUProfile()
		return file.Close()
	}, nil
}
```

Add `TestRunMainWritesTestCPUProfile`, point the variable at `t.TempDir()`, run `version`, and assert a non-empty profile file and exit code zero. Final acceptance never sets this variable; it exists only for the 1 GiB diagnostic gate.

- [ ] **Step 6: Run the CLI profile test**

Run:

```bash
mise exec -- go test ./cmd/derphole -run TestRunMainWritesTestCPUProfile -count=1
```

Expected: PASS and a non-empty pprof file in the test temporary directory.

- [ ] **Step 7: Commit the trace and profile evidence**

Commit only Task 6 changes with:

```text
telemetry: prove bulk UDP pipeline efficiency
```

### Task 7: Add the unoverridden UDP-only acceptance harness

**Files:**
- Create: `scripts/udp-file-acceptance.sh`
- Create: `scripts/udp_file_acceptance_test.go`
- Modify: `.mise.toml:251-255`
- Modify: `docs/benchmarks.md:1-40`
- Reuse without modification: `scripts/promotion-benchmark-driver.sh`
- Reuse: `tools/runstats`
- Reuse: `tools/transfertracecheck`

**Interfaces:**
- Consumes: exact local/Linux candidate builds, ordinary 3 GiB source, public endpoint validation, same-direction eight-flow iperf control on TCP port 8123, promotion driver output, resource JSON, sender/receiver traces, and SHA-256.
- Produces: `mise run udp:file-acceptance`, per-run CSV/JSON, one `decision.json`, exact cleanup, and a strict exit status matching the goal.

- [ ] **Step 1: Write failing static safety and acceptance-policy tests**

The script test must require these literals and forbid transport overrides:

```go
func TestUDPFileAcceptanceHasStrictPublicUDPContract(t *testing.T) {
	body := readScript(t, "udp-file-acceptance.sh")
	for _, want := range []string{
		`size_mib=3072`, `runs=3`, `getconf _NPROCESSORS_ONLN`,
		`DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`,
		`DERPHOLE_BENCH_EXPECT_TRANSFER_MODE=bulk-packets-v1`,
		`-require-direct-transport udp`, `-forbid-relay-payload`,
		`benchmark-goodput-mbps`, `sender_cpu_seconds_per_gib`,
		`receiver_cpu_seconds_per_gib`, `oom_kill`, `sha256`,
	} {
		if !strings.Contains(body, want) { t.Fatalf("script missing %q", want) }
	}
	for _, forbidden := range []string{
		`DERPHOLE_TEST_BULK_BATCHED_IO`, `DERPHOLE_TEST_FORCE_BULK_PACKET_TRANSFER`,
		`DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS`, `pkill`, `killall`, `rm -rf /`,
	} {
		if strings.Contains(body, forbidden) { t.Fatalf("script contains forbidden %q", forbidden) }
	}
}
```

- [ ] **Step 2: Run script tests and verify the missing harness fails**

Run:

```bash
mise exec -- go test ./scripts -run TestUDPFileAcceptance -count=1
```

Expected: FAIL because `scripts/udp-file-acceptance.sh` does not exist.

- [ ] **Step 3: Implement the safe six-run gate**

Adapt the proven helpers from `encrypted-transport-feasibility.sh`, but run only the production `derphole` file path in interleaved order:

```bash
orders=(
  "local-to-remote remote-to-local"
  "remote-to-local local-to-remote"
  "local-to-remote remote-to-local"
)
```

Require explicit SSH target, literal public IPv4 addresses, and TCP port 8123. Build both peers from `git rev-parse HEAD`, verify binary hashes, require exactly two remote CPUs, record preflight OOM/memory/disk/process state, and create one 3 GiB random file. Before each transfer, run a same-direction 20-second `iperf3 -P 8` control; retry the whole sample at most three times until capacity is at least 2.05 Gbps. Run the normal file workload with only the public-path Tailscale test guard and expected-mode assertion.

After each transfer: verify exact size and SHA-256, run sender and receiver trace checks with `-stall-window 999ms -require-direct-transport udp -forbid-relay-payload`, reject any direct-TCP/TLS/relay-payload log marker, require canonical goodput above 2000.0 Mbps, repair below 0.02, scan checks below 2.0, Hetzner role CPU below 8.0 seconds/GiB, and no OOM increment. Remove only that run's exact verified receive payload. Retain logs, traces, hashes, resource JSON, health snapshots, and normalized result rows.

At cell end, calculate population mean, standard deviation, and coefficient of variation for each direction. Require three valid rows and CV at most 0.10. Write `decision.json` atomically with revision, per-direction rates, means, CVs, CPU, repair, trace transport, and pass/fail reasons.

- [ ] **Step 4: Run static harness tests and a no-network argument validation**

Run:

```bash
mise exec -- go test ./scripts -run TestUDPFileAcceptance -count=1
bash ./scripts/udp-file-acceptance.sh
```

Expected: Go tests PASS; the bare script exits 2 and lists every required environment variable without creating local or remote artifacts.

- [ ] **Step 5: Document the exact final command and commit the harness**

Document:

```bash
HETZNER_PUBLIC_IPV4="$(ssh -o BatchMode=yes root@hetz 'curl -4fsS https://api.ipify.org')"
MAC_PUBLIC_IPV4="$(curl -4fsS https://api.ipify.org)"
DERPHOLE_UDP_ACCEPT_REMOTE=root@hetz \
DERPHOLE_UDP_ACCEPT_REMOTE_PUBLIC_ADDR="${HETZNER_PUBLIC_IPV4}" \
DERPHOLE_UDP_ACCEPT_LOCAL_PUBLIC_ADDR="${MAC_PUBLIC_IPV4}" \
DERPHOLE_UDP_ACCEPT_TCP_PORT=8123 \
mise run udp:file-acceptance
```

The discovered values are passed explicitly and validated as public IPv4 addresses; they are not repository defaults. Commit only Task 7 files with:

```text
test: gate 2gbps public UDP file transfers
```

### Task 8: Verify locally, profile live UDP, and run the final acceptance matrix

**Files:**
- No planned repository modification; a failed gate opens a new focused TDD task before verification resumes.
- Generate, do not commit: `.tmp/udp-file-2gbps/${UTC_RUN_ID}/`

**Interfaces:**
- Consumes: exact candidate revision, focused tests, race tests, full checks, two-vCPU Hetzner, all reachable canonical test hosts, and the UDP acceptance harness.
- Produces: fresh verification output, pprof evidence, six accepted Hetzner rows, fleet stability evidence, and a requirement-by-requirement completion audit.

- [ ] **Step 1: Run focused platform and protocol verification**

Run:

```bash
mise exec -- go test ./pkg/session ./pkg/transfertrace ./tools/transfertracecheck ./scripts -race -count=1
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 mise exec -- go test ./pkg/session ./pkg/transfertrace ./tools/transfertracecheck ./scripts -run '^$'
mise run vet
```

Expected: all Darwin tests and race tests PASS; Linux cross-build PASS; vet exits 0.

- [ ] **Step 2: Run full repository verification**

Run:

```bash
mise run check
mise run smoke-local
```

Expected: both exit 0. If the expensive pre-commit hook updates generated metadata, inspect it and commit only when it belongs to this objective.

- [ ] **Step 3: Run one 1 GiB public-UDP proof in each Hetzner direction with CPU profiles**

Use the promotion driver with exact candidate binaries, `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`, file workload, expected `bulk-packets-v1`, and no batch/force/pacing override. Set `DERPHOLE_TEST_CPU_PROFILE` only on the active Hetzner command for this diagnostic, store the result under the run directory, and run:

```bash
profile_path="$(find .tmp/udp-file-2gbps -type f -name 'hetz-*.pprof' -print | sort | tail -n 1)"
test -n "${profile_path}"
mise exec -- go tool pprof -top -cum "${profile_path}"
mise exec -- go tool pprof -top "${profile_path}"
```

Expected before advancing: public addresses in logs; `direct_transport=udp`; native Linux and Darwin batch backends; no TCP/relay payload; exact hash; canonical goodput at least 1.8 Gbps; Hetzner role CPU below 8.0 seconds/GiB; no single serial queue, syscall wrapper, or coordinator consumes enough cumulative CPU to make 2.0 Gbps impossible.

If this gate fails, do not tune a benchmark override. Use the fresh profile and queue telemetry to name the dominant serial stage, add one failing focused test for that mechanism, fix it in the owning file, rerun Steps 1-3, and amend the owning unpublished task commit.

- [ ] **Step 4: Run cautious bidirectional 1 GiB fleet cells**

For every reachable canonical host, run three normal 1 GiB files each direction over public non-Tailscale candidates. Record integrity, mode, repair, CPU, queue, leak, OOM, uptime, and kernel deltas. Judge lower-capacity hosts against same-run iperf and prior stable behavior rather than 2 Gbps. For Eric, snapshot uptime/OOM/memory/processes/disk/kernel before and after every sample and stop immediately if SSH or VM health disappears.

Expected: exact hashes, no leaks or host failures, no catastrophic same-run efficiency regression, and safe bounded queues on every reachable network class.

- [ ] **Step 5: Run the exact six-transfer Hetzner acceptance gate**

After a cooldown and a fresh `but pull --check`, run `mise run udp:file-acceptance` with the literal public endpoints and port 8123. Do not set any other transport or pacing variable.

Expected: `decision.json` passes; three 3 GiB rows per direction; every canonical rate above 2000.0 Mbps; CV at most 0.10; exact hashes and byte counts; public UDP and `bulk-packets-v1` in every trace; repair below 2 percent; scan checks below 2.0; no one-second flatline; Hetzner CPU below 8.0 seconds/GiB; two CPUs; unchanged OOM count; no leaks.

- [ ] **Step 6: Run the completion audit and commit any evidence documentation**

Inspect the exact candidate revision, `decision.json`, every normalized row, both endpoint traces/logs/resources, iperf controls, hashes, health snapshots, and current GitButler status. For each global constraint, record the authoritative artifact path and verdict. Do not call the goal complete if any row is missing, invalid, under 2.0 Gbps, TCP-carried, relayed, hash-inexact, resource-incomplete, or noisy beyond the gate.

If only documentation changed after the last implementation commit, commit it with:

```text
docs: record public UDP acceptance results
```

Keep benchmark payloads and `.tmp` artifacts out of version control.
