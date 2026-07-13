# Encrypted File Transport Feasibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Determine, with real encrypted 3 GiB file transfers on the exact two-vCPU Hetzner VM, whether a batched wire-compatible bulk UDP engine or an eight-connection TLS 1.3 engine can exceed 2.0 Gbps canonical goodput in both directions.

**Architecture:** Add a reusable feasibility-result contract and a private benchmark command for the TLS candidate. Exercise the UDP candidate through the normal production file path behind an internal test-only batching gate, preserving the `bulk-packets-v1` wire format and independent repair clock. A checked-in driver builds both endpoints, performs safe public-path setup, runs paired eight-flow TCP controls, records 100 ms samples plus endpoint resource usage, and applies one machine-readable pass/fail/selection rule. This plan ends at a measured winner or a measured root cause; it does not add product negotiation or a user-facing direct-TCP transport.

**Tech Stack:** Go 1.26, Go TLS 1.3, `golang.org/x/net/ipv4`, `golang.org/x/sys/unix`, existing derphole file transfer/session code, existing `runstats` and transfer-trace tooling, Bash, SSH, iperf3.

**Execution outcome (2026-07-13):** The eight-connection TLS candidate won the feasibility gate. Static per-lane ranges left a slow-lane tail, so the successful engine used a shared 1 MiB dynamic chunk scheduler across the eight pinned TLS connections. Valid production-path samples reached 2.28 to 2.33 Gbps Mac-to-Hetz and 2.08 Gbps Hetz-to-Mac. The winner is now integrated as negotiated `direct-tcp-files-v1`; the remaining work is the exact-current-revision three-run acceptance in both directions, not more phase-zero prototyping.

## Global Constraints

- Benchmark normal encrypted file I/O, not `pipe`, generated zeros over a socket, `/dev/null`, or an in-memory sink.
- Use the exact two-vCPU Hetzner VM and this Mac. Do not satisfy the gate with a larger VM.
- Use public-internet addresses. Disable Tailscale candidates and prove the selected route in every accepted run.
- Use exactly 3 GiB and three valid runs in each direction for each candidate.
- Pair every candidate run with same-direction eight-flow TCP iperf. Capacity below 2.05 Gbps invalidates and reruns the sample; it does not count as a candidate failure.
- Require greater than 2.0 Gbps receiver-anchored canonical goodput in every valid run, exact size and SHA-256, no one-second payload flatline, complete telemetry, and clean process/listener teardown.
- Preserve the `bulk-packets-v1` authenticated packet format. Do not enable UDP GRO by default.
- Keep the bulk repair scheduler independent of primary send/receive work and runnable at least every 100 ms.
- Bound all slabs, crypto queues, receive batches, and writer queues. The benchmark must report their peaks.
- Do not hard-code hostnames, usernames, addresses, ports, or local filesystem paths into code defaults. The live driver receives them through required environment variables.
- Do not expose feasibility knobs as supported product flags. The UDP experiment gate is named with `DERPHOLE_TEST_`; the TLS command is explicitly diagnostic.
- Stop after phase zero. Direct-TCP candidate discovery, claim/accept fields, selection policy, and normal `send`/`receive` integration belong in a second plan after a winner is selected.
- Before live work, read and follow `docs/benchmarks.md`. On any host-health failure, stop immediately and preserve diagnostics; never use broad `pkill` cleanup.

---

## File Map

### Create

- `pkg/transportbench/result.go` — common engine, direction, endpoint-resource, integrity, capacity, trace-health, and verdict types.
- `pkg/transportbench/result_test.go` — result validation, invalid-capacity, strict-threshold, and winner-selection tests.
- `pkg/transportbench/ranges.go` — exact eight-lane disjoint file-range calculation.
- `pkg/transportbench/ranges_test.go` — zero, boundary, ordinary, and 3 GiB range coverage.
- `pkg/transportbench/tls.go` — pinned TLS 1.3 listener, lane framing, sender, receiver, real file I/O, and transfer sampling.
- `pkg/transportbench/tls_test.go` — pinning, framing, lane ownership, failure, cancellation, and file-integrity tests.
- `pkg/transportbench/tcpinfo_linux.go` — Linux `TCP_INFO` retransmit/cwnd sampling.
- `pkg/transportbench/tcpinfo_other.go` — explicit unsupported TCP-info result.
- `cmd/derphole-transport-bench/main.go` — diagnostic `tls-receive`, `tls-send`, `ingest-bulk`, and `decide` commands.
- `cmd/derphole-transport-bench/main_test.go` — CLI validation, JSON/CSV output, and exit-code tests.
- `pkg/session/external_v2_bulk_packet_batch.go` — packet-batch abstraction, pooled message/slab types, counters, and test-only gate.
- `pkg/session/external_v2_bulk_packet_batch_linux.go` — Linux `sendmmsg`/`recvmmsg` and sender-only UDP GSO without UDP GRO.
- `pkg/session/external_v2_bulk_packet_batch_other.go` — correct one-datagram portable fallback.
- `pkg/session/external_v2_bulk_packet_batch_test.go` — common batching, short-send, counter, and fallback tests.
- `pkg/session/external_v2_bulk_packet_batch_linux_test.go` — Linux loopback GSO, `sendmmsg`, `recvmmsg`, truncation, deadline, and cancellation tests.
- `scripts/encrypted-transport-feasibility.sh` — safe two-engine, two-direction, three-run orchestration and artifact collection.
- `scripts/encrypted_transport_feasibility_test.go` — static safety, required-input, cleanup-scope, command-shape, and artifact-contract tests.

### Modify

- `pkg/session/external_v2_bulk_packet.go` — gated slab/crypto/batched primary sender, batched receiver/decrypt queue, bounded asynchronous writer, and batch diagnostics; retain existing repair path.
- `pkg/session/external_v2_bulk_packet_test.go` — old/new interoperability, loss/reorder/repair timing, stalled sink, and goroutine cleanup coverage.
- `pkg/session/external_transfer_metrics.go` — carry bulk batching counters into trace snapshots.
- `pkg/session/external_transfer_metrics_test.go` — assert new counters remain monotonic and present.
- `pkg/transfertrace/trace.go` — append namespaced UDP batch fields to the CSV schema.
- `pkg/transfertrace/trace_test.go` — lock header order and round trips for the new fields.
- `scripts/public-path-performance-harness.sh` — allow only the named batching experiment gate and use eight iperf flows for this gate.
- `scripts/promotion-benchmark-driver.sh` — accept explicit caller-owned local/remote benchmark payloads so both candidates use identical bytes without regenerating them.
- `scripts/promotion_scripts_test.go` — prove experiment propagation, public-path route enforcement, and eight-flow control.
- `.mise.toml` — build the diagnostic binary and add a convenience feasibility task without machine-specific defaults.
- `docs/benchmarks.md` — document prerequisites, environment, artifact layout, strict decision rule, and safe rerun behavior.

---

## Task 1: Define the machine-readable feasibility contract

**Files:**

- Create `pkg/transportbench/result.go`
- Create `pkg/transportbench/result_test.go`

- [ ] Write `TestEvaluateRunRejectsMissingEvidence`, `TestEvaluateRunInvalidatesLowCapacity`, `TestEvaluateRunRequiresStrictlyGreaterThanTwoGbps`, `TestEvaluateCandidateRequiresSixPassingRuns`, and `TestSelectWinnerUsesCPUThenGoodputThenRSS` first.
- [ ] Make the tests construct complete results and delete one required field at a time. A healthy zero must be represented by a present value, not confused with a missing value.
- [ ] Run the focused tests and confirm they fail because the result types and evaluator do not exist:

```bash
mise exec -- go test ./pkg/transportbench -run 'Test(Evaluate|Select)' -count=1
```

Expected failure: `stat .../pkg/transportbench: directory not found` or undefined result/evaluator symbols.

- [ ] Implement these public package contracts exactly, using pointers for measurements where zero is valid:

```go
package transportbench

type Engine string
type Direction string
type RunDisposition string

const (
	EngineBulkUDP Engine = "bulk-udp-batched-v1"
	EngineTLS8    Engine = "tls-stream-8-v1"

	DirectionLocalToRemote Direction = "local-to-remote"
	DirectionRemoteToLocal Direction = "remote-to-local"

	DispositionPass    RunDisposition = "pass"
	DispositionFail    RunDisposition = "fail"
	DispositionInvalid RunDisposition = "invalid"
)

type EndpointResources struct {
	UserCPUSeconds      *float64 `json:"user_cpu_seconds"`
	SystemCPUSeconds    *float64 `json:"system_cpu_seconds"`
	CPUSecondsPerGiB    *float64 `json:"cpu_seconds_per_gib"`
	PeakRSSBytes        *int64   `json:"peak_rss_bytes"`
}

type RunResult struct {
	SchemaVersion             int               `json:"schema_version"`
	Revision                  string            `json:"revision"`
	Engine                    Engine            `json:"engine"`
	Direction                 Direction         `json:"direction"`
	Run                       int               `json:"run"`
	SizeBytes                 int64             `json:"size_bytes"`
	ExpectedSHA256            string            `json:"expected_sha256"`
	ActualSHA256              string            `json:"actual_sha256"`
	CanonicalGoodputMbps      *float64          `json:"canonical_goodput_mbps"`
	WallGoodputMbps           *float64          `json:"wall_goodput_mbps"`
	CapacityMbps              *float64          `json:"capacity_mbps"`
	MaxFlatlineMS             *int64            `json:"max_flatline_ms"`
	TraceComplete             *bool             `json:"trace_complete"`
	PublicRouteProven         *bool             `json:"public_route_proven"`
	TailscaleCandidates       *int               `json:"tailscale_candidates"`
	Sender                    EndpointResources `json:"sender"`
	Receiver                  EndpointResources `json:"receiver"`
	Transport                 map[string]any    `json:"transport"`
	Failure                   string            `json:"failure,omitempty"`
	Disposition               RunDisposition    `json:"disposition"`
	DispositionReason         string            `json:"disposition_reason"`
}

type CandidateVerdict struct {
	Engine                  Engine         `json:"engine"`
	Pass                    bool           `json:"pass"`
	Runs                    []RunResult    `json:"runs"`
	MaxEndpointCPUPerGiB    float64        `json:"max_endpoint_cpu_seconds_per_gib"`
	MedianCanonicalGoodput  float64        `json:"median_canonical_goodput_mbps"`
	MedianWallGoodput       float64        `json:"median_wall_goodput_mbps"`
	MaxPeakRSSBytes         int64          `json:"max_peak_rss_bytes"`
	Reasons                 []string       `json:"reasons,omitempty"`
}

type Decision struct {
	SchemaVersion int                `json:"schema_version"`
	Selected      Engine             `json:"selected,omitempty"`
	Reason        string             `json:"reason"`
	Candidates    []CandidateVerdict `json:"candidates"`
}

func EvaluateRun(result RunResult) RunResult
func EvaluateCandidate(engine Engine, runs []RunResult) CandidateVerdict
func SelectWinner(candidates ...CandidateVerdict) Decision
```

- [ ] Encode the approved rule in one place: capacity `< 2050` is invalid; canonical goodput must be `> 2000`; size must equal `3*1024*1024*1024`; hashes must match; maximum flatline must be `< 1000`; trace, public-route proof, zero Tailscale candidates, and all resource values must be present.
- [ ] Validate engine-specific evidence instead of trusting an opaque non-empty transport map. Bulk requires backend, GSO attempted/active, send/receive calls and datagrams, maximum batch sizes, queue peaks, ENOBUFS, repair bytes, repair ratio, retransmits, and packet counters. TLS requires TLS version/cipher/ALPN, eight connections, pin verification, eight lane byte counts, read/write call sizes, and retransmit/cwnd support state.
- [ ] Require exactly runs 1–3 for both directions with no duplicates. Invalid samples prevent a verdict and instruct the driver to rerun; they never become passes or candidate failures.
- [ ] If both candidates pass, choose lower maximum endpoint CPU seconds/GiB, then higher median wall goodput, then lower maximum RSS. If all metrics tie, prefer bulk UDP. If only one passes, select it. If neither passes, leave `Selected` empty and list the failed gates.
- [ ] Run:

```bash
mise exec -- go test ./pkg/transportbench -run 'Test(Evaluate|Select)' -count=1
```

Expected result: PASS.

---

## Task 2: Specify eight-lane file ranges and authenticated TLS framing

**Files:**

- Create `pkg/transportbench/ranges.go`
- Create `pkg/transportbench/ranges_test.go`
- Create `pkg/transportbench/tls.go`
- Create `pkg/transportbench/tls_test.go`

- [ ] Write table-driven tests for `SplitRanges` with sizes 0, 1, 7, 8, 9, 1 MiB, and 3 GiB. Assert each byte belongs to exactly one lane, ranges are contiguous, and the largest/smallest ranges differ by at most one byte.
- [ ] Write frame tests that reject wrong magic/version/transfer ID, lane indices outside `[0,8)`, a lane count other than eight, duplicate lanes, overlaps, gaps, range overflow, size disagreement, malformed hash, and truncated headers before any payload write.
- [ ] Run and observe undefined symbols:

```bash
mise exec -- go test ./pkg/transportbench -run 'Test(SplitRanges|LaneHeader)' -count=1
```

- [ ] Implement the fixed protocol surface:

```go
const (
	TLSLaneCount      = 8
	TLSProtocol       = "derphole-transport-bench-v1"
	TLSLaneHeaderSize = 84
)

type ByteRange struct {
	Offset int64
	Length int64
}

type LaneHeader struct {
	TransferID [16]byte
	Lane       uint16
	Lanes      uint16
	TotalSize  uint64
	Offset     uint64
	Length     uint64
	SHA256     [32]byte
}

func SplitRanges(size int64, lanes int) ([]ByteRange, error)
func EncodeLaneHeader(header LaneHeader) [TLSLaneHeaderSize]byte
func DecodeLaneHeader(raw []byte) (LaneHeader, error)
func ValidateLaneHeaders(headers []LaneHeader) error
```

- [ ] Use a four-byte `DHTB` magic, version 1, and three zero reserved bytes before the fields shown above. Keep all integers network byte order; decode must reject nonzero reserved bytes.
- [ ] Run:

```bash
mise exec -- go test ./pkg/transportbench -run 'Test(SplitRanges|LaneHeader)' -count=1
```

Expected result: PASS.

---

## Task 3: Implement the pinned eight-connection TLS file engine

**Files:**

- Modify `pkg/transportbench/tls.go`
- Modify `pkg/transportbench/tls_test.go`
- Create `pkg/transportbench/tcpinfo_linux.go`
- Create `pkg/transportbench/tcpinfo_other.go`

- [ ] Add failing end-to-end loopback tests for an ordinary multi-megabyte file, exact receiver hash, wrong fingerprint, one lane disconnecting, stalled writer cancellation, sibling cancellation, no successful partial result, and listener/goroutine cleanup.
- [ ] Add a short-read reader and short-write `WriterAt` test double. Require the engine to complete correct short operations or return `io.ErrShortWrite`; never silently truncate.
- [ ] Run and confirm failure before implementation:

```bash
mise exec -- go test ./pkg/transportbench -run 'TestTLS' -count=1
```

- [ ] Implement these entry points:

```go
type TLSReceiveConfig struct {
	ListenAddr string
	OutputPath string
	ReadyFile  string
	TracePath  string
	Timeout    time.Duration
}

type TLSSendConfig struct {
	PeerAddr          string
	FingerprintSHA256 string
	TransferID        [16]byte
	InputPath         string
	TracePath         string
	Timeout           time.Duration
}

type Ready struct {
	SchemaVersion     int    `json:"schema_version"`
	Address           string `json:"address"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	TransferID        string `json:"transfer_id"`
}

type TransferSummary struct {
	SchemaVersion        int               `json:"schema_version"`
	Engine               Engine            `json:"engine"`
	Role                 string            `json:"role"`
	SizeBytes            int64             `json:"size_bytes"`
	SHA256               string            `json:"sha256"`
	TransferElapsedMS    int64              `json:"transfer_elapsed_ms"`
	CommandElapsedMS     int64              `json:"command_elapsed_ms"`
	CanonicalGoodputMbps float64            `json:"canonical_goodput_mbps"`
	WallGoodputMbps      float64            `json:"wall_goodput_mbps"`
	Connections          int                `json:"connections"`
	TLSCipher            string             `json:"tls_cipher"`
	TCPRetransmits       *uint64             `json:"tcp_retransmits"`
	TCPCwndSegments      *uint32             `json:"tcp_cwnd_segments"`
	ReadCalls            uint64              `json:"read_calls"`
	WriteCalls           uint64              `json:"write_calls"`
	BytesPerReadCall     float64             `json:"bytes_per_read_call"`
	BytesPerWriteCall    float64             `json:"bytes_per_write_call"`
	LaneBytes            [TLSLaneCount]int64 `json:"lane_bytes"`
}

func ReceiveTLS(ctx context.Context, cfg TLSReceiveConfig) (TransferSummary, error)
func SendTLS(ctx context.Context, cfg TLSSendConfig) (TransferSummary, error)
```

- [ ] Generate an ephemeral Ed25519 certificate per receive invocation. Write `Ready` atomically with mode `0600` only after the listener is bound. Pin SHA-256 of `RawSubjectPublicKeyInfo` in `tls.Config.VerifyConnection`; set TLS minimum and maximum to TLS 1.3 and ALPN to `TLSProtocol`.
- [ ] Open exactly eight connections. Each lane sends its validated fixed header, then its disjoint contiguous range using pooled 1 MiB buffers and `io.NewSectionReader`. The receiver writes with `WriteAt` to a pre-sized ordinary file.
- [ ] Hash the source before transfer and hash the receiver output after all lanes close. Do not include pre-hashing or post-transfer verification in receiver-anchored transfer time, but do include both in command-wall time. Start canonical time at the receiver's first committed payload byte and stop it at the final committed payload byte.
- [ ] Sample per-lane committed bytes every 100 ms and write a final sample. The CSV columns are `timestamp_unix_ms,elapsed_ms,role,lane_0_bytes,...,lane_7_bytes,total_bytes,delta_bytes,mbps,tcp_retransmits,tcp_cwnd_segments,last_error`.
- [ ] On the first lane error, cancel the shared context, set deadlines on all listeners/connections, wait for every worker, close the output, and return failure. Do not unlink a path the caller did not create.
- [ ] On Linux, extract `unix.TCPInfo` through `SyscallConn`; aggregate retransmits and record minimum cwnd across lanes. On other platforms, return nil TCP metrics rather than fabricated zeroes.
- [ ] Run:

```bash
mise exec -- go test ./pkg/transportbench -run 'TestTLS' -count=1
mise exec -- go test -race ./pkg/transportbench -run 'TestTLS' -count=1
```

Expected result: PASS with no race report.

---

## Task 4: Add the diagnostic CLI and result ingestion

**Files:**

- Create `cmd/derphole-transport-bench/main.go`
- Create `cmd/derphole-transport-bench/main_test.go`
- Modify `.mise.toml`

- [ ] Write CLI tests first for required arguments, invalid fingerprints, non-eight lane requests, atomic ready-file creation, exactly one JSON summary on stdout, `ingest-bulk` rejecting incomplete promotion rows, `decide` returning nonzero for invalid/incomplete evidence, and `decide` returning the selected engine only for a complete passing set.
- [ ] Run and observe the missing command failure:

```bash
mise exec -- go test ./cmd/derphole-transport-bench -count=1
```

- [ ] Implement a thin CLI with these forms:

```text
derphole-transport-bench tls-receive --listen ADDR --out FILE --ready-file FILE --trace FILE --timeout 5m
derphole-transport-bench tls-send --peer ADDR --fingerprint HEX --transfer-id HEX --in FILE --trace FILE --timeout 5m
derphole-transport-bench ingest-bulk --summary-csv FILE --direction local-to-remote --run 1 --out FILE
derphole-transport-bench decide --results FILE --out FILE
```

- [ ] `tls-send` and `tls-receive` each write one `TransferSummary` JSON value to stdout and errors to stderr. They never print secrets, certificate private material, or file contents.
- [ ] `ingest-bulk` reads the named derphole row from the existing summary CSV plus its trace-check artifacts and emits one `RunResult`. Require `workload=file`, exact size, complete trace, path evidence, resource fields, and batching diagnostics.
- [ ] `decide` reads JSON Lines, calls only the package evaluator, writes the full `Decision`, and exits: 0 for a selected winner, 1 when no candidate passes, 2 for malformed or incomplete/invalid evidence that must be rerun.
- [ ] Add the diagnostic binary to `mise run build` and add:

```toml
[tasks."transport:feasibility"]
description = "Run the encrypted file transport feasibility gate"
run = "bash ./scripts/encrypted-transport-feasibility.sh"
```

- [ ] Run:

```bash
mise exec -- go test ./cmd/derphole-transport-bench ./pkg/transportbench -count=1
mise run build
```

Expected result: PASS and `dist/derphole-transport-bench` exists.

---

## Task 5: Introduce a portable bulk packet-batch seam

**Files:**

- Create `pkg/session/external_v2_bulk_packet_batch.go`
- Create `pkg/session/external_v2_bulk_packet_batch_other.go`
- Create `pkg/session/external_v2_bulk_packet_batch_test.go`

- [ ] Write failing tests for disabled-by-default behavior, explicit test-gate enablement, 64-message splitting, partial writes resuming at the first unsent message, ENOBUFS retry accounting, receive truncation rejection, and portable one-datagram fallback correctness.
- [ ] Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacketBatch' -count=1
```

- [ ] Add the private seam:

```go
const externalV2BulkPacketMaxBatch = 64

type externalV2BulkPacketBatchMessage struct {
	Buffers [][]byte
	Addr    net.Addr
	OOB     []byte
	N       int
	NN      int
	Flags   int
}

type externalV2BulkPacketBatchStats struct {
	Backend              string
	GSOAttempted          bool
	GSOActive             bool
	GSOSegments           uint64
	SendCalls             uint64
	SendDatagrams         uint64
	ReceiveCalls          uint64
	ReceiveDatagrams      uint64
	MaxSendBatch          uint32
	MaxReceiveBatch       uint32
	CryptoQueuePeak       uint32
	WriterQueuePeak       uint32
}

type externalV2BulkPacketBatchConn interface {
	WriteBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error)
	ReadBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error)
	Stats() externalV2BulkPacketBatchStats
}

func externalV2BulkPacketBatchedIOEnabled() bool
func newExternalV2BulkPacketBatchConn(net.PacketConn) externalV2BulkPacketBatchConn
```

- [ ] The gate reads only `DERPHOLE_TEST_BULK_BATCHED_IO=1`; all other values are false. Normal transfers retain the current code until a candidate wins and a later plan removes the experiment seam.
- [ ] Keep message buffers owned by the caller until `WriteBatch` returns. Document that a positive count means exactly the first `n` datagrams were accepted.
- [ ] Implement the non-Linux version with `WriteTo`/`ReadFrom`, deadlines for context cancellation, the same validation, and truthful `Backend: "portable-single"` counters.
- [ ] Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacketBatch' -count=1
```

Expected result: PASS on macOS using the portable fallback tests.

---

## Task 6: Implement Linux sendmmsg, recvmmsg, and sender-only UDP GSO

**Files:**

- Create `pkg/session/external_v2_bulk_packet_batch_linux.go`
- Create `pkg/session/external_v2_bulk_packet_batch_linux_test.go`

- [ ] Write Linux tests in a build-tagged file. Cover a 64-datagram loopback batch, mixed short final datagram, sendmmsg partial progress, recvmmsg deadline expiry, prompt context cancellation, truncated-message rejection, GSO success when supported, and clean fallback when `UDP_SEGMENT` returns an unsupported error.
- [ ] Assert that receiver construction never sets `UDP_GRO`. This is a regression guard, not just an omitted experiment.
- [ ] Run on the Linux VM before implementation and confirm undefined Linux batch functions:

```bash
ssh "$DERPHOLE_FEASIBILITY_REMOTE" 'cd "$HOME/derphole-feasibility-src" && mise exec -- go test ./pkg/session -run "TestExternalV2BulkPacketLinuxBatch" -count=1'
```

- [ ] Implement `sendmmsg`/`recvmmsg` through `ipv4.NewPacketConn(udpConn).WriteBatch` and `.ReadBatch`. Arm a 100 ms read deadline before each blocking receive so cancellation and repair scheduling cannot hang behind `recvmmsg`.
- [ ] Attempt UDP GSO only for same-size, same-destination primary data packets on a connected or destination-stable socket. Construct `UDP_SEGMENT` ancillary data with `unix.SOL_UDP`/`unix.UDP_SEGMENT`; cap at 64 segments and the IPv4 maximum payload.
- [ ] Treat `EINVAL`, `ENOPROTOOPT`, `EOPNOTSUPP`, and `ENOSYS` as per-socket GSO rejection: record the error class once, disable GSO for that wrapper, and retry the same unsent datagrams with `sendmmsg`. All other errors propagate.
- [ ] Never retry already accepted datagrams. Never combine repair packets with a GSO super-packet.
- [ ] Inspect `ipv4.Message.Flags` for truncation before decryption and fail the transfer on `MSG_TRUNC`.
- [ ] Run on Linux:

```bash
ssh "$DERPHOLE_FEASIBILITY_REMOTE" 'cd "$HOME/derphole-feasibility-src" && mise exec -- go test ./pkg/session -run "TestExternalV2BulkPacketLinuxBatch" -count=1'
```

Expected result: PASS whether the VM reports GSO active or rejected; the test log records which path ran.

---

## Task 7: Replace the gated bulk primary sender with slabs and bounded crypto workers

**Files:**

- Modify `pkg/session/external_v2_bulk_packet.go`
- Modify `pkg/session/external_v2_bulk_packet_test.go`
- Modify `pkg/session/external_v2_bulk_packet_batch.go`

- [ ] Add a failing test that enables `DERPHOLE_TEST_BULK_BATCHED_IO=1`, transfers a deterministic payload through fake batch connections, and asserts byte-for-byte equality with packets produced by the legacy `sealExternalV2BulkPacket` path.
- [ ] Add tests for two-worker maximum, bounded slab count under a blocked socket, cancellation while workers are full, stable per-lane packet ordering, final short packet, and repair still using the existing `sendPacket` path.
- [ ] Add a timing test with a blocked primary batch writer and injected missing requests. Assert repair processing is scheduled within 100 ms plus a small test-only scheduler tolerance.
- [ ] Run and confirm the fake batch connection is unused before implementation:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(BatchedSender|RepairIndependent)' -count=1
```

- [ ] Refactor only primary sends behind the gate:

```go
const (
	externalV2BulkPacketSlabBytes       = 1 << 20
	externalV2BulkPacketCryptoWorkers   = 2
	externalV2BulkPacketPreparedBatches = 4
)

type externalV2BulkPacketPreparedBatch struct {
	Lane     int
	Messages []externalV2BulkPacketBatchMessage
	Payload  int64
	Wire     int64
	Release  func()
}

func (s *externalV2BulkPacketSender) sendInitialPacketsBatched() error
```

- [ ] Read 1 MiB source slabs with `ReadAt`, split them into existing 1,358-byte payloads, and seal into reusable packet storage. Use at most `min(2, runtime.GOMAXPROCS(0))` crypto workers, because the accepted VM has two vCPUs.
- [ ] Assign packet indices to their existing primary lanes. Preserve increasing packet-index order within each lane. Pace the sum of IPv4 wire bytes immediately before handing a prepared batch to its lane.
- [ ] Bound ownership to four prepared batches plus two active worker slabs. When the socket stage is full, workers stop taking slabs; the reader stops reading the file.
- [ ] Keep control readers, repair requests, the rate controller, and `sendPacket(..., repair=true)` independent. Repairs remain individually authenticated and individually sent until a later measured change proves safe.
- [ ] Update payload, wire, ENOBUFS, and batching counters from accepted datagrams only.
- [ ] Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(BatchedSender|RepairIndependent)' -count=1
```

Expected result: PASS.

---

## Task 8: Add the gated batched receiver, decrypt pool, and asynchronous writer

**Files:**

- Modify `pkg/session/external_v2_bulk_packet.go`
- Modify `pkg/session/external_v2_bulk_packet_test.go`
- Modify `pkg/session/external_v2_bulk_packet_batch.go`

- [ ] Write failing tests for 64-message receive batches, two-worker maximum, out-of-order decrypt completion, duplicate datagrams, loss followed by repair, a sink stalled after one write, bounded memory, sink error cancellation, and all pooled buffers returned after failure.
- [ ] Retain the deterministic repair regression test. Assert the idle repair scan still fires every 100 ms even while decrypt and writer queues are occupied.
- [ ] Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(BatchedReceiver|AsyncWriter|RepairCadence)' -count=1
```

- [ ] Add bounded stages behind the same experiment gate:

```go
const (
	externalV2BulkPacketDecryptWorkers = 2
	externalV2BulkPacketDecryptQueue   = 256
	externalV2BulkPacketWriterQueue    = 8
	externalV2BulkPacketWriteGroup     = 256 << 10
)

type externalV2BulkPacketWriteExtent struct {
	Offset  int64
	Data    []byte
	Release func()
}
```

- [ ] Each lane reader owns one 64-message receive array and packet storage. It validates length/truncation, then submits sealed packets to the shared bounded decrypt queue.
- [ ] Use at most `min(2, runtime.GOMAXPROCS(0))` decrypt workers. Decrypt into pooled payload buffers and send indexed results to the existing missing/seen state owner; do not mutate `seen` concurrently.
- [ ] Change the gated assembler to form complete extents up to 256 KiB and enqueue at most eight to a single writer goroutine. Count bytes as committed only after successful `WriteAt`, then release the extent.
- [ ] The receiver state loop owns a ticker created once at startup. It services missing detection from that independent ticker rather than constructing a timer after each packet.
- [ ] First fatal read/decrypt/write error cancels every stage, interrupts socket deadlines, drains only buffers already owned, waits for all workers, and returns the original error joined with cleanup errors.
- [ ] Run:

```bash
mise exec -- go test ./pkg/session -run 'TestExternalV2BulkPacket(BatchedReceiver|AsyncWriter|RepairCadence)' -count=1
mise exec -- go test -race ./pkg/session -run 'TestExternalV2BulkPacket(Batched|Repair)' -count=1
```

Expected result: PASS with no race report.

---

## Task 9: Make batching effectiveness and queue health observable

**Files:**

- Modify `pkg/session/external_transfer_metrics.go`
- Modify `pkg/session/external_transfer_metrics_test.go`
- Modify `pkg/transfertrace/trace.go`
- Modify `pkg/transfertrace/trace_test.go`
- Modify `pkg/session/external_v2_bulk_packet.go`

- [ ] Add failing trace round-trip tests for appended fields. Preserve every existing header position and append only:

```text
bulk_batch_backend
bulk_gso_attempted
bulk_gso_active
bulk_gso_segments
bulk_send_calls
bulk_send_datagrams
bulk_receive_calls
bulk_receive_datagrams
bulk_max_send_batch
bulk_max_receive_batch
bulk_crypto_queue_peak
bulk_writer_queue_peak
```

- [ ] Add metrics tests proving counters are monotonic, maximums never decrease, and absent transport fields serialize as empty rather than plausible zero.
- [ ] Run and observe missing CSV columns:

```bash
mise exec -- go test ./pkg/transfertrace ./pkg/session -run 'Test.*(BulkBatch|Trace)' -count=1
```

- [ ] Extend `externalDirectTransferDiagnostics`, `externalTransferMetrics`, and `transfertrace.Snapshot` with the fields above. Add one setter that merges a batch snapshot without overwriting controller/repair diagnostics.
- [ ] Publish sender batching stats after each accepted batch and receiver stats after each receive batch/committed write. Emit a final snapshot during success and failure cleanup.
- [ ] Ensure `bulk_batch_backend` distinguishes `linux-gso`, `linux-sendmmsg`, and `portable-single`; `gso_attempted=true` plus `gso_active=false` is a valid measured result.
- [ ] Run:

```bash
mise exec -- go test ./pkg/transfertrace ./pkg/session -run 'Test.*(BulkBatch|Trace)' -count=1
```

Expected result: PASS.

---

## Task 10: Build the safe public-path feasibility driver

**Files:**

- Create `scripts/encrypted-transport-feasibility.sh`
- Create `scripts/encrypted_transport_feasibility_test.go`
- Modify `scripts/public-path-performance-harness.sh`
- Modify `scripts/promotion-benchmark-driver.sh`
- Modify `scripts/promotion_scripts_test.go`
- Modify `docs/benchmarks.md`

- [ ] Write script tests first. Require explicit `DERPHOLE_FEASIBILITY_REMOTE`, `DERPHOLE_FEASIBILITY_REMOTE_PUBLIC_ADDR`, `DERPHOLE_FEASIBILITY_LOCAL_PUBLIC_ADDR`, and `DERPHOLE_FEASIBILITY_TCP_PORT`. Reject loopback, RFC1918, link-local, multicast, and Tailscale CGNAT addresses as public endpoints.
- [ ] Assert the script uses unique per-invocation local and remote roots, records exact PIDs, traps cleanup, removes only its own roots/PIDs/listeners, never uses `killall`/`pkill`, never installs packages, and stops immediately on endpoint health failure.
- [ ] Assert every accepted iperf command contains `-P 8`, every file size is 3072 MiB, every bulk process receives both `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` and `DERPHOLE_TEST_BULK_BATCHED_IO=1`, and no normal environment inherits the batching gate.
- [ ] Run and observe the missing script failure:

```bash
mise exec -- go test ./scripts -run 'TestEncryptedTransportFeasibility' -count=1
```

- [ ] Implement this artifact layout:

```text
.tmp/encrypted-transport-feasibility/20260712T210000Z-12345/
  manifest.json
  source.bin
  source.sha256
  results.jsonl
  decision.json
  bulk-udp-batched-v1/local-to-remote/run-1/...
  tls-stream-8-v1/remote-to-local/run-1/...
```

- [ ] Build Mac and `linux/amd64` derphole, runstats, transfertracecheck, and transport-bench binaries from the same revision. Upload into a unique remote directory and record local/remote `sha256sum` values before running anything.
- [ ] Create one ordinary 3 GiB source file locally with cryptographically random content. Reuse its exact bytes in both directions by copying it once to the remote staging directory before timed runs. Record SHA-256 once; do not time staging.
- [ ] Preflight CPU count (`getconf _NPROCESSORS_ONLN` must equal 2), disk free space, public TCP reachability in both receiver topologies, UDP candidate route evidence, no pre-existing listener on the selected port, and endpoint kernel/OOM/interface counters. A failed preflight exits without starting a candidate.
- [ ] Interleave candidates and directions to reduce route bias:

```text
bulk local-to-remote run 1
tls remote-to-local run 1
tls local-to-remote run 1
bulk remote-to-local run 1
... rotate the starting engine/direction for runs 2 and 3
```

- [ ] Immediately before every candidate run, execute same-direction 20-second iperf3 with eight flows and JSON output. If receiver capacity is below 2.05 Gbps, mark the sample invalid, wait for a clean process check, and retry up to three times. After three invalid controls, exit 2 without judging the candidate.
- [ ] Extend `promotion-benchmark-driver.sh` with `DERPHOLE_BENCH_LOCAL_PAYLOAD` and `DERPHOLE_BENCH_REMOTE_PAYLOAD`. Validate that an explicitly supplied path is a regular file of `expected_size`, never regenerate it, never mutate it, and never remove it during cleanup. Require the matching side's explicit payload for each feasibility run so bulk and TLS use the exact pre-staged bytes.
- [ ] For bulk, call the existing promotion file harness with one host/one run, 3072 MiB, public/Tailscale-disabled route, gated batching on both endpoints, the explicit source payload, runstats, exact hash, and 100 ms transfer trace. Use `ingest-bulk` to normalize the artifacts.
- [ ] For TLS, start the receiver under runstats, wait for its atomic ready file, translate only the listener host portion to the explicitly supplied public address while preserving the bound port, then start the pinned sender. Collect both summaries, both resource reports, the receiver trace, SHA, route proof, and socket state.
- [ ] After each run, verify output hash/size, trace health with a 999 ms stall window, endpoint PIDs exited, selected listener is gone, no new OOM/kernel fault appeared, and interface error/drop counters did not jump without being recorded. Append exactly one evaluated `RunResult` to `results.jsonl`.
- [ ] Extend `public-path-performance-harness.sh` with a single allowlisted experiment propagation variable, not arbitrary environment forwarding:

```bash
bulk_batched_io="${DERPHOLE_TEST_BULK_BATCHED_IO:-}"
if [[ -n "${bulk_batched_io}" && "${bulk_batched_io}" != "1" ]]; then
  echo "DERPHOLE_TEST_BULK_BATCHED_IO must be empty or 1" >&2
  exit 2
fi
```

- [ ] Change the feasibility invocation to eight iperf flows while leaving ordinary harness defaults unchanged unless `DERPHOLE_PUBLIC_IPERF_STREAMS=8` is explicitly supplied and validated.
- [ ] Finish by running `decide`. Preserve all artifacts on pass, candidate failure, invalid capacity, or interruption. Cleanup remote processes and transient staging files, but never delete local evidence.
- [ ] Document the exact environment and command in `docs/benchmarks.md`:

```bash
DERPHOLE_FEASIBILITY_REMOTE="${DERPHOLE_FEASIBILITY_REMOTE:?set SSH target}" \
DERPHOLE_FEASIBILITY_REMOTE_PUBLIC_ADDR="${DERPHOLE_FEASIBILITY_REMOTE_PUBLIC_ADDR:?set remote public address}" \
DERPHOLE_FEASIBILITY_LOCAL_PUBLIC_ADDR="${DERPHOLE_FEASIBILITY_LOCAL_PUBLIC_ADDR:?set local public address}" \
DERPHOLE_FEASIBILITY_TCP_PORT="${DERPHOLE_FEASIBILITY_TCP_PORT:?set forwarded TCP port}" \
mise run transport:feasibility
```

- [ ] Run:

```bash
mise exec -- go test ./scripts -run 'Test(EncryptedTransportFeasibility|Promotion)' -count=1
bash -n scripts/encrypted-transport-feasibility.sh scripts/public-path-performance-harness.sh
```

Expected result: PASS.

---

## Task 11: Run local and Linux correctness gates

**Files:** All files changed by Tasks 1–10.

- [ ] Run focused packages on the Mac:

```bash
mise exec -- go test ./pkg/transportbench ./cmd/derphole-transport-bench ./pkg/session ./pkg/transfertrace ./scripts -count=1
mise exec -- go test -race ./pkg/transportbench ./pkg/session -run 'Test.*(TLS|BulkPacketBatch|Batched|Repair)' -count=1
```

- [ ] Run the full project gates:

```bash
mise run test
mise run vet
mise run check:hooks
mise run smoke-local
mise run build
```

- [ ] If `govulncheck` fails because the pinned Go/tool version is stale, update `.mise.toml` to the smallest compatible non-vulnerable Go/tool version, run `mise install`, then rerun `mise run vuln` and the full gates. Do not suppress a finding or exclude a package.
- [ ] Build the Linux test binary from the exact revision and run the focused batching/TLS suite on the two-vCPU VM with no live traffic:

```bash
remote_tmp="${DERPHOLE_FEASIBILITY_REMOTE_TMP:?set remote temporary directory}"
GOOS=linux GOARCH=amd64 mise exec -- go test -c -o .tmp/transportbench-linux.test ./pkg/transportbench
GOOS=linux GOARCH=amd64 mise exec -- go test -c -o .tmp/session-linux.test ./pkg/session
scp .tmp/transportbench-linux.test .tmp/session-linux.test "${DERPHOLE_FEASIBILITY_REMOTE}:${remote_tmp}/"
ssh "$DERPHOLE_FEASIBILITY_REMOTE" \
  "${remote_tmp}/transportbench-linux.test -test.v -test.run 'TestTLS|TestTCPInfo' && ${remote_tmp}/session-linux.test -test.v -test.run 'TestExternalV2BulkPacketLinuxBatch|TestExternalV2BulkPacketRepair'"
```

- [ ] Record `go test`, race, hooks, smoke, Linux test output, kernel version, CPU count, and NIC feature output under the feasibility run's `preflight/` directory.
- [ ] Proceed to live testing only if every correctness gate passes and the VM is healthy.

---

## Task 12: Execute the exact two-way decision gate

**Files:** Runtime artifacts only under `.tmp/encrypted-transport-feasibility/`; do not hand-edit results.

- [ ] Run the checked-in driver with the user-supplied public endpoints and TCP port:

```bash
DERPHOLE_FEASIBILITY_REMOTE="${DERPHOLE_FEASIBILITY_REMOTE:?set SSH target}" \
DERPHOLE_FEASIBILITY_REMOTE_PUBLIC_ADDR="${DERPHOLE_FEASIBILITY_REMOTE_PUBLIC_ADDR:?set remote public address}" \
DERPHOLE_FEASIBILITY_LOCAL_PUBLIC_ADDR="${DERPHOLE_FEASIBILITY_LOCAL_PUBLIC_ADDR:?set local public address}" \
DERPHOLE_FEASIBILITY_TCP_PORT="${DERPHOLE_FEASIBILITY_TCP_PORT:?set forwarded TCP port}" \
mise run transport:feasibility
```

- [ ] Confirm `results.jsonl` contains 12 valid runs: three per direction for each of two engines. Invalid capacity attempts remain in per-run logs but are not silently substituted into the six required results.
- [ ] Confirm every valid run has:
  - 3,221,225,472 bytes and matching SHA-256
  - `canonical_goodput_mbps > 2000`
  - `capacity_mbps >= 2050`
  - `max_flatline_ms < 1000`
  - complete sender/receiver CPU, CPU/GiB, RSS, wall, route, trace, and transport-specific metrics
  - zero Tailscale candidates and public selected addresses
  - no remaining endpoint process or listener
- [ ] For UDP, require a truthful effective backend. If it says `portable-single`, the run may be correct but cannot be described as proof of Linux batching. Report GSO attempted/active, datagrams per syscall, max batch sizes, repair ratio, ENOBUFS, crypto queue peak, and writer queue peak.
- [ ] For TLS, require exactly eight connections, TLS 1.3, the expected ALPN, pinned fingerprint, per-lane byte totals, syscall sizes, retransmits/cwnd where supported, and exact output hash.
- [ ] Run the decision checker independently after the driver:

```bash
run_dir="$(ls -dt .tmp/encrypted-transport-feasibility/*/ | head -n 1)"
mise exec -- go run ./cmd/derphole-transport-bench decide \
  --results "${run_dir}/results.jsonl" \
  --out "${run_dir}/decision-recheck.json"
cmp "${run_dir}/decision.json" "${run_dir}/decision-recheck.json"
```

- [ ] Stop with one of exactly three outcomes:
  1. `bulk-udp-batched-v1` selected: write the product-integration plan that removes the experiment gate and makes the optimized wire-compatible path normal.
  2. `tls-stream-8-v1` selected: write the product-integration plan for authenticated TCP candidates, `--direct-tcp-port`, negotiation, selection, and fallback.
  3. no candidate selected: preserve profiles and write a root-cause report; do not start product integration or lower the target.
- [ ] Do not run Eric or the wider fleet in this phase-zero plan. Those gates test the selected product implementation and belong in the follow-on integration plan.

---

## Task 13: Review, record the decision, and checkpoint the phase-zero work

**Files:**

- Modify `docs/benchmarks.md` only if the live run exposes an instruction correction.
- Create a UTC-named result note under `docs/benchmarks/results/` only if benchmark result records are intentionally checked in by current repository convention; otherwise keep machine-specific evidence under `.tmp` and summarize it in the commit message/final handoff.

- [ ] Use `superpowers:requesting-code-review` for independent review of correctness, resource bounds, authentication, cleanup safety, and whether the measurement contract can be gamed.
- [ ] Resolve every Important issue and rerun the affected focused/full gates.
- [ ] Run `but pull --check`. If another active branch overlaps these files, stop and coordinate rather than absorbing unrelated work.
- [ ] Inspect `but diff` and commit only this session's feasibility implementation and documentation to its dedicated GitButler branch with a scoped subject such as:

```text
bench: gate encrypted file transport feasibility
```

- [ ] Do not push, land on `main`, tag, publish npm, or start a release unless the user explicitly asks after reviewing the decision.
- [ ] Hand off the selected engine, all twelve valid run results, invalid capacity reruns, maximum endpoint CPU/GiB, median canonical/wall goodput, peak RSS, route proof, repair/retransmit data, and exact artifact directory.

## Phase-Zero Completion Criteria

- The feasibility command and tests are reproducible from a clean checkout without machine-specific defaults.
- The UDP candidate remains wire-compatible, bounded, cancellable, repair-safe, and disabled during normal transfers.
- The TLS candidate uses real files, TLS 1.3, certificate fingerprint pinning, exact eight-lane coverage, and bounded reusable buffers.
- The exact two-vCPU VM produces six valid 3 GiB results for each candidate, or the run stops with explicit invalid-capacity/health evidence.
- The decision JSON applies the approved strict thresholds and either selects one candidate or records why neither qualifies.
- No product transport or negotiation behavior changes until the measured winner receives its own implementation plan.
