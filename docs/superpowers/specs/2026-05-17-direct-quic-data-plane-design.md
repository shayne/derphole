# Direct QUIC Data Plane Design

## Summary

Replace the custom reliable direct UDP transfer path with a QUIC-first direct data plane.

The existing token, claim, DERP rendezvous, candidate gathering, and relay fallback flow remains. Direct transfer changes from derphole's custom UDP blast stream to a QUIC connection over the selected UDP path. QUIC becomes responsible for congestion control, pacing, retransmission, stream ordering, flow control, FIN, and connection close. Derphole remains responsible for rendezvous, path selection, relay overlap, progress reporting, cancellation, telemetry, and fallback.

Breaking protocol changes are acceptable. The goal is a simpler, proven direct transport that approaches the available path ceiling instead of maintaining a fragile partial transport stack.

## Problem

Recent live benchmarks show raw network capacity far above derphole's sustained direct transfer throughput. The new transfer diagnostics made the gap visible, but they did not close it.

The current direct UDP stream has too many transport responsibilities:

- rate probing and controller ramping
- lane selection and active lane scaling
- replay windows
- repair requests
- packet ordering and committed-byte accounting
- fallback and promotion coordination

These pieces interact in ways that are difficult to reason about and have produced stalls, unrealistic sender progress, slow direct transfers, and fragile cancellation behavior. Continuing to tune this stack risks spending more time on symptoms than on the underlying transport design.

## Goals

- Make QUIC the primary direct data plane for file and stream transfers.
- Keep relay-first behavior so transfers work immediately and continue when direct cannot be established.
- Promote to direct only after QUIC proves that real receiver-committed bytes are flowing.
- Preserve prompt peer abort behavior on local cancellation.
- Reach at least 75% of the lower clean iperf baseline on fast direct paths as the first acceptance gate, then tune toward 90%.
- Avoid UDP socket and process leaks in all benchmark and cancellation paths.
- Keep enough telemetry to distinguish path capacity, QUIC behavior, application copy overhead, relay fallback, and cancellation.

## Non-Goals

- Do not clone iperf's protocol.
- Do not build another custom TCP-like reliable UDP protocol unless QUIC cannot meet the benchmark gate.
- Do not add permanent relay-plus-direct multipath striping in the first implementation.
- Do not preserve compatibility with old dev tokens or old direct UDP protocol messages.
- Do not commit machine-specific hostnames, usernames, local filesystem paths, or private benchmark defaults.

## Architecture

Add a new focused package, likely `pkg/directquic`, for the direct data plane. Reuse `pkg/quicpath` primitives where they fit, but do not revive the older native QUIC session code wholesale.

The package should expose a small API:

```go
type Endpoint struct {
	// implementation-private fields
}

func Listen(ctx context.Context, cfg ListenConfig) (*Endpoint, error)
func Dial(ctx context.Context, cfg DialConfig) (*Endpoint, error)
func (e *Endpoint) OpenSendStream(ctx context.Context) (io.WriteCloser, error)
func (e *Endpoint) AcceptReceiveStream(ctx context.Context) (io.ReadCloser, error)
func (e *Endpoint) Stats() Stats
func (e *Endpoint) CloseWithError(code uint64, msg string) error
```

`ListenConfig` and `DialConfig` should include:

- the selected UDP socket or packet connection
- selected peer address
- local session identity
- expected peer identity
- buffer sizes
- telemetry hooks
- qlog or metrics hooks enabled only by configuration or environment

The receiver acts as the QUIC server and the sender acts as the QUIC client. If live NAT cases prove that this role split fails, add a tie-breaker for simultaneous-open behavior later. Start simple.

QUIC TLS identity must be pinned to session identity material exchanged through the existing claim/decision flow. A direct UDP packet from the right address is not enough to trust the peer.

## Session Flow

1. Sender creates an offer token and starts relay availability.
2. Receiver claims the token and sends direct candidates as it does today.
3. Sender accepts the claim and starts relay data.
4. Both peers attempt direct QUIC setup over candidate-selected UDP paths.
5. QUIC handshake completes with pinned peer identity.
6. Peers run a small direct readiness exchange over QUIC.
7. Sender opens a QUIC stream and starts a direct proof transfer.
8. Receiver reports committed direct progress.
9. Session promotes from relay to direct only after committed direct bytes advance.
10. Relay overlap drains and closes once direct is the active path.

The important rule is that "handshake succeeded" is not the same as "promote." Promotion requires receiver-committed byte progress.

## Promotion And Fallback

Relay is the initial active path. Direct QUIC is attempted in parallel.

Promotion requires:

- QUIC handshake with the expected peer identity.
- Direct readiness exchange over QUIC.
- Real stream bytes received and committed by the receiver.
- Direct observed throughput better than relay by a configurable threshold, unless direct is the only viable upgrade path.

Fallback cases:

- If direct QUIC handshake fails, keep relay and emit `direct-fallback-relay`.
- If direct handshakes but stream progress stalls, close QUIC, keep relay, and emit `direct-quic-stalled`.
- If direct is slower than relay for a sustained window and is not improving, close direct and stay on relay.
- If peer aborts or local cancellation occurs, send an authenticated abort immediately, close QUIC, close relay, and close sockets.
- If direct succeeds, relay remains active only until overlap has drained and direct committed progress is stable.

Telemetry states:

- `connected-relay`
- `trying-direct-quic`
- `direct-quic-handshake`
- `direct-quic-validating`
- `direct-quic-promoting`
- `connected-direct-quic`
- `direct-fallback-relay`

## Performance Strategy

Start with one QUIC connection and one QUIC stream. Do not introduce multiple QUIC connections or permanent striping until a single connection is proven insufficient.

Initial performance work:

- use one UDP socket per side
- set large UDP read and write buffers where supported
- prefer connected UDP sockets after path selection when possible
- keep initial packet size conservative, likely 1200 bytes
- avoid verbose per-packet logging on benchmark paths
- keep qlog and detailed QUIC metrics behind explicit opt-in
- copy file/stdin data with large buffers
- keep progress accounting out of the hot write path as much as practical

If the full transfer is slow but a QUIC microbenchmark is fast, focus on session copy, progress, relay overlap, and file I/O. If the QUIC microbenchmark is also slow while iperf is fast, focus on packet connection integration, socket buffers, address selection, and QUIC config. If QUIC itself cannot approach the target after those fixes, evaluate multiple QUIC streams or multiple QUIC connections.

## Telemetry

Keep the existing transfer CSV. Add QUIC fields while leaving old direct UDP fields blank for QUIC sessions where appropriate.

Required QUIC telemetry:

- direct transport: `quic`
- handshake duration
- direct first-byte duration
- direct committed bytes
- direct stream bytes sent and received
- stream goodput
- smoothed RTT if exposed
- loss and retransmit counters if exposed
- congestion or bytes-in-flight data if exposed
- receive flow-control stalls if exposed
- fallback reason
- close reason
- qlog path when enabled

Do not make qlog mandatory for benchmark runs. It is too heavy for default performance measurements.

## Benchmark Gate

Add or extend a benchmark script that captures, for the same host pair and direction:

- iperf TCP baseline
- iperf UDP baseline
- direct QUIC microbenchmark over the same selected UDP path where possible
- full derphole transfer
- sender and receiver transfer traces
- leak checks before and after
- payload size and SHA verification

Acceptance gate for fast direct paths:

- full derphole QUIC goodput is at least 75% of the lower clean iperf baseline
- no transfer stalls
- sender and receiver byte counts agree
- payload SHA matches
- cancellation is prompt in both directions
- post-run process and UDP socket leak checks are clean

After the first gate passes, tune toward 90% of the lower clean iperf baseline.

Relay-only paths should not regress from the current relay behavior.

## Migration Plan

### Phase 1: QUIC Spike Behind A Flag

Add `direct_quic_v1` behind an explicit selector such as `DERPHOLE_DIRECT_TRANSPORT=quic`.

Proof:

- local loopback transfer
- one remote transfer
- no leaked sockets
- clean local cancellation

### Phase 2: Telemetry Parity

Wire QUIC metrics into the existing transfer trace system. Ensure the trace checker can summarize QUIC runs without depending on old UDP blast fields.

Proof:

- trace checker passes sender and receiver traces
- QUIC fallback reason appears in failed direct runs
- qlog can be enabled without changing default benchmark behavior

### Phase 3: Relay Overlap Promotion

Integrate QUIC with relay-prefix handoff. Relay remains active until QUIC commits receiver progress.

Proof:

- handshake success with stream stall falls back to relay
- direct commit promotes cleanly
- receiver Ctrl-C aborts sender promptly

### Phase 4: Benchmark Gate

Run the benchmark matrix against configured fast direct and relay-only host pairs.

Proof:

- fast direct path reaches the initial 75% gate
- relay-only path completes or fails with explicit fallback diagnostics
- no benchmark run leaks UDP sockets or processes

### Phase 5: Make QUIC Default

Switch direct transport default to QUIC. Keep the old blast path available for one dev release behind `DERPHOLE_DIRECT_TRANSPORT=blast`.

### Phase 6: Delete Old Reliable UDP Transfer

Remove custom reliable UDP transfer code that is no longer used by production. Keep lower-level probes only if they remain useful for diagnostics.

## Risks

- QUIC over the selected packet connection may underperform iperf. Mitigate with a direct QUIC microbenchmark before full session integration.
- QUIC flow-control defaults may cap throughput. Mitigate with explicit config and telemetry.
- Receiver-as-server may not cover all NAT cases. Mitigate by adding simultaneous-open only after evidence shows it is needed.
- Integrating QUIC with existing session code could inherit old complexity. Mitigate with a small package boundary and a narrow session adapter.
- qlog and verbose tracing can distort benchmark results. Mitigate by keeping them opt-in.

## Open Decisions

- Exact environment variable and CLI flag names for selecting the direct transport.
- Exact QUIC buffer and flow-control defaults.
- Whether direct QUIC microbench should live in `scripts/` only or also as a Go benchmark.
- How much of `pkg/quicpath` should be reused versus simplified into `pkg/directquic`.

These decisions should be resolved in the implementation plan, not by ad hoc edits.
