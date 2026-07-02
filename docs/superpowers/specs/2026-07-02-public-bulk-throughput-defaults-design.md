# Public Bulk Throughput Defaults Design

Date: 2026-07-02

Status: design approved in session. Implementation planning starts only after this spec is reviewed.

## Summary

Make normal derphole bulk transfers approach same-path `iperf3` throughput without requiring users to know or tune performance flags.

The default product behavior must stay automatic:

- no required `--parallel`, transport, or tuning flags for good throughput
- no user-visible choice between raw-direct, manager QUIC, relay, or future fast paths
- public-only testing can disable Tailscale candidates with `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`, but production defaults continue to allow Tailscale and choose the best available path
- diagnostic flags may remain for experiments and regression isolation, not for expected user performance

The current public raw-direct path is correct but underperforms the network. It selects public direct QUIC, transfers zero relay bytes, and verifies size and hash, yet it still falls well below `iperf3` on several hosts and shows repeated one-to-six second ordered progress stalls. That points at derphole's transfer pipeline, not route selection or relay fallback.

## Evidence

All runs below sent 1 GiB from this Mac to the remote host. The remote wrote to its main disk, not `/tmp`. `iperf3` used this Mac's public WAN address on port `8123`. derphole runs used public raw-direct with `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`. Traces reported `v2-data-plane=raw-direct`, `transport-direct-path-class=public`, `relay_bytes=0`, `direct_transport=quic`, and `v2-raw-direct-active=4`.

| Remote | iperf3 avg Mbps | derphole wall avg Mbps | derphole trace avg Mbps | wall ratio | Key trace symptom |
| --- | ---: | ---: | ---: | ---: | --- |
| `ubuntu@derphole-testing` | 349.23 | 284.14 | 292.38 | 0.814 | sender stalls on all runs, max app gap 3.5-6.0s |
| `ubuntu@eric-nuc` | 600.07 | 128.07 | 130.13 | 0.213 | sender and receiver stalls on all runs, recv queue depth up to 3578 |
| `root@hetz` | 2147.73 | 786.98 | 805.21 | 0.366 | high-capacity path limited to roughly 0.8 Gbps |
| `root@canlxc` | 865.06 | 577.49 | 594.00 | 0.668 | variable throughput and receiver stalls |

Common observations:

- The public path is selected correctly, so this is not a Tailscale or relay-selection artifact.
- QUIC/raw-direct can burst high, but sustained ordered application progress is lower than the path can carry.
- Sender and receiver trace checks often fail with ordered progress stalls even when integrity succeeds.
- `peer_recv_queue_depth` and `local_sent_bytes` ahead of receiver-confirmed progress suggest the application striping and reorder layer can build backlog instead of translating available network capacity into smooth output.
- The sender-side UX feels sluggish because sender-visible progress is tied to receiver-confirmed app progress; changing redraw cadence alone cannot fix backend transfer stalls.

## Goals

- Make no-flag derphole bulk send/receive choose a high-throughput policy automatically.
- Reach within 10-15 percent of same-run `iperf3` average on the Mac -> `eric-nuc` direction unless packet loss, CPU, disk, or path diagnostics prove a real external limit.
- Avoid regressions on `derphole-testing`, `hetz`, and `canlxc`.
- Eliminate sender and receiver `transfertracecheck` progress stalls over one second in the steady direct-transfer phase.
- Preserve correctness: byte count, SHA-256, clean close, peer abort, Ctrl-C, and process/socket cleanup remain required for any performance claim.
- Keep public-only benchmark mode explicit and test-scoped with `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`.
- Make diagnostics explain the bottleneck before any large protocol replacement is attempted.

## Non-Goals

- Do not require users to pass performance flags for normal fast transfers.
- Do not disable Tailscale candidates in production defaults.
- Do not tune the sender progress interval as the primary fix for throughput.
- Do not commit to a custom UDP bulk protocol before proving optimized QUIC cannot meet the target.
- Do not report benchmark wins from runs that skip integrity, trace, path-class, or cleanup checks.
- Do not optimize derpssh interactive latency in this work; it is related context, not this transfer target.

## Proposed Approach

Use a measured, staged rewrite of the bulk transfer path.

First, make the benchmark matrix first-class. A single harness should run same-direction `iperf3` and derphole trials across the target hosts, force public-only candidates for test runs, write remote outputs to the main disk, collect traces, run trace checks, verify hashes, and clean up local and remote artifacts. This prevents future changes from optimizing one route while regressing another.

Second, instrument the current pipeline enough to identify the limiting stage. The existing trace already shows path class, relay bytes, direct bytes, data plane, and queue depth. Add focused counters for stripe write blocking, stripe read blocking, reorder wait time, receiver output write time, sender source-read pressure, QUIC blocked state where available, CPU profile hooks, and optional qlog collection. The point is to separate network congestion from app-level head-of-line blocking, disk pressure, CPU saturation, and flow-control limits.

Third, change the default transfer strategy based on the measurements. The leading hypothesis is that the current fixed four-stripe, ordered 1 MiB application striping layer creates avoidable head-of-line blocking over QUIC. The implementation plan should test and then promote the simplest policy that wins by default:

- prefer one optimized QUIC stream when it matches or beats striped mode
- if striping is still useful, replace fixed round-robin ordered chunks with a backpressure-aware policy that avoids unbounded local-ahead and reorder backlog
- make `auto` the no-flag product behavior, not a user requirement
- keep explicit parallel flags only as diagnostic overrides

Fourth, tune QUIC and buffering only after the application pipeline is proven not to be the bottleneck. QUIC stream and connection windows are already sizeable, so window tuning should be evidence-driven rather than the first move.

Fifth, design a v3 custom bulk data plane only if optimized QUIC cannot get close to `iperf3` after the above steps. A custom protocol is allowed because breaking changes are on the table, but it must be justified by data from the simplified QUIC path.

## Architecture

### Benchmark Matrix Harness

Add or extend a script under `scripts/` that treats `iperf3` as the external capacity baseline and derphole as the product under test.

The harness owns:

- host list: `ubuntu@derphole-testing`, `ubuntu@eric-nuc`, `root@hetz`, and `root@canlxc`
- same-run `iperf3` and derphole sequencing
- three-run default sample count
- public-only test env propagation
- remote main-disk output directories under `$HOME` or an explicit remote bench root
- trace collection, trace checking, SHA verification, and leak cleanup
- machine-readable summary with Mbps, ratios, selected path, trace failures, max stall, max queue depth, and max local-ahead bytes

The harness must not assume `/tmp` has enough space.

### Transfer Policy

Move the default from "fixed four stripes" toward an automatic policy selected by the active side and acknowledged by the passive side.

The policy should describe intent rather than expose implementation details:

- `auto` for default product transfers
- `single` for one-stream diagnostic trials
- `fixed-N` for controlled experiments and regression isolation

No normal user should need to pass these controls. CLI flags can exist as debug overrides, but the no-flag path must use the automatic policy.

### Copy Pipeline

Treat `pkg/session/external_striped.go` as suspect until proven otherwise.

The current structure writes 1 MiB sequenced chunks across multiple QUIC streams and requires the receiver to write global sequence order. If one stripe is delayed, later chunks wait even when the network and output file are ready. The replacement should keep the receiver's output order correct while bounding head-of-line damage:

- start with a single-stream baseline for clarity
- measure whether multiple streams improve throughput after queueing is visible
- if multiple streams remain, schedule chunks to writers by observed backpressure, not blind round-robin
- cap local-ahead and receiver reorder bytes so fast local reads cannot hide stalled network or receiver output
- expose blocked time and reorder wait time in trace summaries

### QUIC Data Plane

Keep QUIC as the default reliable data plane during this effort.

QUIC already provides congestion control, retransmission, stream flow control, and close semantics. The design should simplify the application layer before replacing QUIC. QUIC tuning is still in scope when metrics show flow-control blocking, packet loss recovery, socket buffer pressure, or CPU overhead.

### Public-Only Test Guard

Keep `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` as a test-only guard.

Public-route benchmarks need this guard to avoid measuring an existing VPN path, but product defaults should continue to allow Tailscale candidates because users want derphole to work well automatically on whatever good path is available.

## Data Flow

1. The active side creates or claims a transfer as it does today.
2. The active side resolves transfer policy to `auto` when no diagnostic override is set.
3. The peers negotiate the effective policy and data-plane capability.
4. Public-route test runs filter Tailscale candidates only when `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` is set.
5. The selected direct QUIC path starts payload transfer.
6. The copy pipeline uses the selected automatic strategy: single stream or measured multi-stream scheduling.
7. Receiver output progress remains the authoritative committed byte count.
8. Sender progress displays receiver-confirmed progress while also recording local source-read and local-sent counters for diagnostics.
9. Completion verifies byte count and hash, sends the normal completion signal, and closes all streams and sockets.

## Error Handling

- Any policy negotiation mismatch fails early with a clear protocol error.
- If the automatic policy cannot open the preferred stream layout, it falls back to the simpler reliable layout rather than hanging.
- If direct QUIC fails before payload starts, existing relay or fallback behavior may proceed, but traces must identify that the run is no longer a public raw-direct throughput sample.
- If sender local-ahead or receiver reorder backlog exceeds the configured safety bound, the transfer should slow source reads or scheduling instead of building unbounded memory pressure.
- Peer abort and local cancellation must close all copy goroutines, QUIC streams, packet conns, and DERP subscriptions promptly.
- Benchmark harness failures must preserve enough logs and traces to diagnose the failed phase, then clean remote files and processes unless explicitly told to retain them.

## Testing And Verification

### Unit And Package Tests

Add focused tests for:

- automatic policy resolution with no flags
- diagnostic override parsing
- active-side policy authority and passive-side acknowledgement
- single-stream and multi-stream copy correctness
- bounded local-ahead and bounded receiver reorder behavior
- fallback from a failed multi-stream setup to a simpler reliable setup
- public-only test candidate filtering remains scoped to `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`

### Local Regression Tests

Run:

- focused `go test` for touched packages
- `mise run test`
- `mise run smoke-local` when transport behavior changes

### Live Performance Gate

Before claiming the goal is met, run three 1 GiB Mac -> remote trials for each host:

- `ubuntu@derphole-testing`
- `ubuntu@eric-nuc`
- `root@hetz`
- `root@canlxc`

Each host needs:

- three same-direction `iperf3` baseline runs
- three derphole no-flag product runs using the automatic default policy
- public-only benchmark env set for derphole candidate gathering
- remote output on the main disk
- SHA and byte-count verification
- trace path proof showing public direct path for public-path claims
- no `transfertracecheck` app-progress stalls over one second in steady direct phase
- cleanup proof for processes, sockets, and bench files

The primary pass condition is `eric-nuc` Mac -> remote derphole average within 10-15 percent of same-run `iperf3`. The secondary condition is no average throughput regression on the other three hosts relative to the current matrix.

## Risks And Mitigations

- Risk: one stream improves smoothness but loses peak capacity on high-BDP paths. Mitigation: make the matrix compare single, fixed four, fixed eight, and automatic policies before changing defaults.
- Risk: multi-stream scheduling keeps throughput but still creates ordered head-of-line blocking. Mitigation: instrument reorder wait time and cap reorder backlog; prefer simpler single-stream default if it wins.
- Risk: disk write speed contaminates remote download results. Mitigation: include a discard-mode diagnostic run when disk pressure is suspected, but keep main-disk file output in the product-style gate.
- Risk: verbose tracing changes performance. Mitigation: use quiet benchmark runs for throughput claims and separate diagnostic runs for heavier qlog or pprof captures.
- Risk: public Internet variance hides regressions. Mitigation: pair every derphole sample with same-run `iperf3`, use ratios, and require all hosts to avoid regressions.
- Risk: production behavior accidentally disables Tailscale candidates. Mitigation: keep explicit tests proving Tailscale is allowed by default and filtered only under the test env var.

## Implementation Plan Boundary

The implementation plan should decompose this into:

1. benchmark matrix harness and summaries
2. pipeline instrumentation
3. single-stream and fixed-parallel experimental comparisons
4. automatic default policy implementation
5. QUIC or buffer tuning driven by diagnostics
6. final four-host performance gate

Custom UDP bulk transfer should not enter the first implementation plan unless the experimental comparison proves that the simplified QUIC path cannot approach the target.
