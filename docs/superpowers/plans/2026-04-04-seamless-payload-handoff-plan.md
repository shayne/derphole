# Seamless Payload Handoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `send/listen` start payload transfer immediately over relay and seamlessly continue on native direct carriers without duplicate, missing, or reordered bytes.

**Architecture:** Add an application-level chunk/ACK layer above the current carriers. Relay QUIC starts immediately, direct carriers join later from the receiver's committed watermark, and the sender keeps a bounded replay spool so non-seekable stdin can survive handoff without re-reading the source.

**Tech Stack:** Go, quic-go, existing DERP rendezvous/control path, existing route-local native TCP and native QUIC implementations, temp-file-backed sender spooling, package tests plus live remote smoke/perf runs.

---

### Task 1: Add Chunk Framing And Receiver Reassembly

**Files:**
- Create: `pkg/session/external_handoff.go`
- Create: `pkg/session/external_handoff_test.go`

- [ ] **Step 1: Write failing tests for ordered delivery, dedupe, and bounded out-of-order buffering**

Create `pkg/session/external_handoff_test.go` with tests in this shape:

```go
func TestExternalHandoffReceiverWritesContiguousChunksInOrderAndDedupes(t *testing.T) {
	var out bytes.Buffer
	rx := newExternalHandoffReceiver(&out, 2<<20)

	if err := rx.AcceptChunk(externalHandoffChunk{TransferID: 7, Offset: 5, Payload: []byte("world")}); err != nil {
		t.Fatal(err)
	}
	if err := rx.AcceptChunk(externalHandoffChunk{TransferID: 7, Offset: 0, Payload: []byte("hello")}); err != nil {
		t.Fatal(err)
	}
	if err := rx.AcceptChunk(externalHandoffChunk{TransferID: 7, Offset: 0, Payload: []byte("hello")}); err != nil {
		t.Fatal(err)
	}

	if got := out.String(); got != "helloworld" {
		t.Fatalf("output = %q, want %q", got, "helloworld")
	}
	if got := rx.Watermark(); got != 10 {
		t.Fatalf("watermark = %d, want 10", got)
	}
}

func TestExternalHandoffReceiverRejectsWindowOverflow(t *testing.T) {
	var out bytes.Buffer
	rx := newExternalHandoffReceiver(&out, 8)

	err := rx.AcceptChunk(externalHandoffChunk{TransferID: 7, Offset: 1024, Payload: []byte("overflow")})
	if err == nil {
		t.Fatal("AcceptChunk() error = nil, want overflow rejection")
	}
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
go test ./pkg/session -run '^TestExternalHandoffReceiver' -count=1
```

Expected: compile/test failure because `externalHandoffChunk`, `newExternalHandoffReceiver`, `AcceptChunk`, and `Watermark` do not exist yet.

- [ ] **Step 3: Implement minimal receiver/chunk types**

Create `pkg/session/external_handoff.go` with a receiver that only writes contiguous bytes and buffers out-of-order chunks within a fixed byte budget:

```go
type externalHandoffChunk struct {
	TransferID uint64
	Offset     int64
	Payload    []byte
}

type externalHandoffReceiver struct {
	out       io.Writer
	maxWindow int64
	watermark int64
	pending   map[int64][]byte
	buffered  int64
}

func newExternalHandoffReceiver(out io.Writer, maxWindow int64) *externalHandoffReceiver {
	return &externalHandoffReceiver{out: out, maxWindow: maxWindow, pending: map[int64][]byte{}}
}

func (r *externalHandoffReceiver) Watermark() int64 {
	return r.watermark
}
```

Then add `AcceptChunk` logic that ignores already-committed duplicates, rejects negative offsets and excessive forward gaps, stores copied payload bytes keyed by offset, and drains contiguous pending chunks in order.

- [ ] **Step 4: Run tests and verify GREEN**

Run:

```bash
go test ./pkg/session -run '^TestExternalHandoffReceiver' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/session/external_handoff.go pkg/session/external_handoff_test.go
git commit -m "feat: add external payload handoff reassembly"
```

### Task 2: Add Sender Replay Spool And Watermark ACK Handling

**Files:**
- Modify: `pkg/session/external_handoff.go`
- Modify: `pkg/session/external_handoff_test.go`

- [ ] **Step 1: Write failing tests for replay from a non-seekable source and ACK-based truncation**

Extend `pkg/session/external_handoff_test.go` with tests in this shape:

```go
func TestExternalHandoffSenderReplaysFromAckedWatermark(t *testing.T) {
	spool, err := newExternalHandoffSpool(strings.NewReader("abcdefghijklmnopqrstuvwxyz"), 4, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	chunk, err := spool.NextChunk()
	if err != nil {
		t.Fatal(err)
	}
	if string(chunk.Payload) != "abcd" {
		t.Fatalf("chunk = %q, want %q", chunk.Payload, "abcd")
	}

	if err := spool.AckTo(4); err != nil {
		t.Fatal(err)
	}
	if err := spool.RewindTo(4); err != nil {
		t.Fatal(err)
	}

	chunk, err = spool.NextChunk()
	if err != nil {
		t.Fatal(err)
	}
	if chunk.Offset != 4 || string(chunk.Payload) != "efgh" {
		t.Fatalf("chunk = {%d %q}, want {4 %q}", chunk.Offset, chunk.Payload, "efgh")
	}
}

func TestExternalHandoffSenderBackpressuresWhenUnackedWindowExceedsLimit(t *testing.T) {
	spool, err := newExternalHandoffSpool(strings.NewReader("abcdefghijklmnopqrstuvwxyz"), 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	if _, err := spool.NextChunk(); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.NextChunk(); err == nil {
		t.Fatal("NextChunk() error = nil, want unacked window limit")
	}
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
go test ./pkg/session -run '^TestExternalHandoffSender' -count=1
```

Expected: compile/test failure because `newExternalHandoffSpool`, `NextChunk`, `AckTo`, and `RewindTo` do not exist yet.

- [ ] **Step 3: Implement a temp-file-backed sender spool**

Add a sender spool that copies bytes from the source into a temp file, emits fixed-size chunks with monotonically increasing offsets, tracks highest ACKed watermark, allows rewinding to the committed watermark for a new carrier, and refuses to read beyond `maxUnackedBytes` until ACKs advance:

```go
type externalHandoffSpool struct {
	src            io.Reader
	file           *os.File
	chunkSize      int
	maxUnacked     int64
	readOffset     int64
	ackedWatermark int64
}

func newExternalHandoffSpool(src io.Reader, chunkSize int, maxUnackedBytes int64) (*externalHandoffSpool, error)
func (s *externalHandoffSpool) NextChunk() (externalHandoffChunk, error)
func (s *externalHandoffSpool) AckTo(watermark int64) error
func (s *externalHandoffSpool) RewindTo(offset int64) error
func (s *externalHandoffSpool) Close() error
```

Use a temp file under the OS temp directory, not repo `dist/`.

- [ ] **Step 4: Run tests and verify GREEN**

Run:

```bash
go test ./pkg/session -run '^TestExternalHandoffSender' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/session/external_handoff.go pkg/session/external_handoff_test.go
git commit -m "feat: add external payload handoff sender spool"
```

### Task 3: Carry Chunk/ACK Frames Over Existing Streams

**Files:**
- Modify: `pkg/session/external_handoff.go`
- Modify: `pkg/session/external_handoff_test.go`

- [ ] **Step 1: Write failing tests for chunk frame round-trip and watermark frame parsing**

Add tests that encode a chunk frame into a `bytes.Buffer`, decode it back, and verify malformed lengths are rejected:

```go
func TestExternalHandoffChunkFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := externalHandoffChunk{TransferID: 42, Offset: 9, Payload: []byte("payload")}

	if err := writeExternalHandoffChunkFrame(&buf, want); err != nil {
		t.Fatal(err)
	}
	got, err := readExternalHandoffChunkFrame(&buf, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got.TransferID != want.TransferID || got.Offset != want.Offset || string(got.Payload) != string(want.Payload) {
		t.Fatalf("decoded chunk = %+v, want %+v", got, want)
	}
}

func TestExternalHandoffWatermarkFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeExternalHandoffWatermarkFrame(&buf, 99); err != nil {
		t.Fatal(err)
	}
	got, err := readExternalHandoffWatermarkFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != 99 {
		t.Fatalf("watermark = %d, want 99", got)
	}
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
go test ./pkg/session -run '^TestExternalHandoff(ChunkFrame|WatermarkFrame)' -count=1
```

Expected: compile/test failure because frame helpers do not exist yet.

- [ ] **Step 3: Implement compact binary frame helpers**

Add binary encoding helpers with explicit max payload limits:

```go
const externalHandoffMaxChunkPayload = 1 << 20

func writeExternalHandoffChunkFrame(w io.Writer, chunk externalHandoffChunk) error
func readExternalHandoffChunkFrame(r io.Reader, maxPayload int) (externalHandoffChunk, error)
func writeExternalHandoffWatermarkFrame(w io.Writer, watermark int64) error
func readExternalHandoffWatermarkFrame(r io.Reader) (int64, error)
```

Keep framing local to `pkg/session`; do not change the public token format.

- [ ] **Step 4: Run tests and verify GREEN**

Run:

```bash
go test ./pkg/session -run '^TestExternalHandoff(ChunkFrame|WatermarkFrame)' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/session/external_handoff.go pkg/session/external_handoff_test.go
git commit -m "feat: add external payload handoff framing"
```

### Task 4: Use Relay-First Chunk Streaming In `send/listen` And Add Direct Carrier Handoff

**Files:**
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/external_handoff.go`
- Modify: `pkg/session/session_test.go`
- Modify: `pkg/session/external_quic_mode_test.go`

- [ ] **Step 1: Write failing integration tests for relay-first chunk streaming and seamless direct handoff**

Add a test that forces delayed direct availability, asserts payload starts flowing before direct negotiation completes, and verifies the final output has no duplicated or missing bytes:

```go
func TestExternalListenSendStartsOnRelayAndHandsOffToDirectWithoutDataLoss(t *testing.T) {
	// Arrange a fake or delayed direct carrier so relay carries the first chunks.
	// Send a deterministic payload larger than one chunk.
	// Assert the receiver output equals the original payload exactly once.
	// Assert telemetry saw connected-relay before connected-direct.
}
```

Also add a regression that a failed native TCP handoff resumes on relay from the latest ACKed watermark instead of restarting at byte 0.

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
go test ./pkg/session -run '^TestExternalListenSendStartsOnRelayAndHandsOffToDirectWithoutDataLoss$' -count=1
```

Expected: FAIL because the current sender does not stream payload chunks on relay before native-direct negotiation.

- [ ] **Step 3: Refactor one-shot send/listen into a carrier scheduler with a stable chunk stream**

In `sendExternal`, start the relay QUIC stream as soon as the decision is accepted, wrap that stream in the chunk sender, and run native-direct negotiation concurrently. When native TCP or native QUIC becomes ready, request the receiver watermark, rewind the sender spool to that offset, and continue on the new carrier while leaving relay active for a short overlap window.

In `listenExternal`, consume chunk frames from the relay stream immediately, maintain the receiver watermark, and accept chunk frames from the new direct carrier once it appears. Only write contiguous bytes to `cfg.StdioOut`.

Preserve the current control path and security checks; this is a payload scheduling change, not a token or peer-auth change.

- [ ] **Step 4: Run package tests and verify GREEN**

Run:

```bash
go test ./pkg/session -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/session/external.go pkg/session/external_handoff.go pkg/session/session_test.go pkg/session/external_quic_mode_test.go
git commit -m "feat: stream external payloads relay-first with direct handoff"
```

### Task 5: Add Throughput And No-Tailscale Live Verification Gates

**Files:**
- Modify: `scripts/promotion-test.sh`
- Modify: `scripts/promotion-test-reverse.sh`
- Create: `scripts/promotion-matrix-no-tailscale.sh`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Write a failing script-level check for no-Tailscale candidate mode**

Create `scripts/promotion-matrix-no-tailscale.sh` that runs both directions for `hetz`, `ktzlxc`, and `pve1` with `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1`, and prints a failure if any sender or listener log contains `100.64.` or `fd7a:115c:a1e0::`.

Use this structure:

```bash
#!/usr/bin/env bash
set -euo pipefail

hosts=(hetz ktzlxc pve1)
for host in "${hosts[@]}"; do
  DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh "$host" 1024
  DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test-reverse.sh "$host" 1024
done
```

Then extend the promotion scripts so they emit enough verbose logs for this checker to validate route selection.

- [ ] **Step 2: Run the script and verify RED before code wiring is finished**

Run:

```bash
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-matrix-no-tailscale.sh
```

Expected: FAIL until the scripts and sender/listener flow emit and preserve the expected no-Tailscale route evidence in a machine-checkable way.

- [ ] **Step 3: Implement the no-Tailscale benchmark matrix and preserve throughput baselines**

Update the benchmark docs to require 3x averaged 1 GiB runs for:

- Mac -> `ktzlxc`
- `ktzlxc` -> Mac
- Mac -> `hetz`
- `hetz` -> Mac
- Mac -> `pve1`
- `pve1` -> Mac

For `pve1`, note that same-LAN private routing is expected with Tailscale candidates disabled because `pve1` and this Mac are on the same LAN.

- [ ] **Step 4: Run full local and live verification**

Run:

```bash
mise run check
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-matrix-no-tailscale.sh
./scripts/promotion-test.sh ktzlxc 1024
./scripts/promotion-test-reverse.sh ktzlxc 1024
./scripts/promotion-test.sh hetz 1024
./scripts/promotion-test-reverse.sh hetz 1024
./scripts/promotion-test.sh pve1 1024
./scripts/promotion-test-reverse.sh pve1 1024
```

Expected:

- all transfers complete and verify SHA-256
- no no-Tailscale run uses `100.64.0.0/10` or `fd7a:115c:a1e0::/48`
- `connected-relay` appears first and `connected-direct` appears once a direct carrier is established
- throughput is not materially worse than current `main` for the native fast paths

- [ ] **Step 5: Commit**

```bash
git add scripts/promotion-test.sh scripts/promotion-test-reverse.sh scripts/promotion-matrix-no-tailscale.sh docs/benchmarks.md
git commit -m "test: add no-tailscale promotion benchmark matrix"
```

---

## Self-Review Notes

- Spec coverage: Tasks 1-4 cover chunk framing, receiver ordering, sender replay spool, and carrier handoff. Task 5 covers the no-Tailscale and no-throughput-regression verification requirement.
- Placeholder scan: no `TBD` or open-ended "handle edge cases" steps remain; each task has concrete files, code shape, and commands.
- Type consistency: all new helpers are namespaced under `externalHandoff*`, and later tasks only call symbols introduced in Tasks 1-3 or existing session symbols.
