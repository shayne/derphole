# V2 QUIC Transfer Protocol Design

Date: 2026-05-18

## Summary

Replace the default external transfer protocol with a v2 QUIC-first data plane.

The current implementation has too many protocol layers competing for ownership of reliability, pacing, progress, handoff, and fallback. Live runs show this clearly: iperf3 can reach much higher host-to-host throughput, while derphole can stall or fall back to a slow relay path because direct setup, relay-prefix handoff, replay windows, and custom UDP rate control interact badly.

The v2 design makes the file transfer layer simple:

- DERP remains the rendezvous, control, and relay packet path.
- QUIC owns reliability, congestion control, stream flow control, loss recovery, and connection close.
- The lower packet path starts relay-capable and adds validated direct UDP paths underneath the same QUIC session.
- Application payload does not switch from one logical stream to another during promotion.

Breaking protocol compatibility is acceptable for this change.

## Problem

The existing default path can be fast in selected cases, but it is fragile.

Observed issues:

- Direct setup can pause or starve relay progress.
- Relay-prefix fallback can stall after direct setup fails.
- Sender and receiver progress can diverge because sender-side enqueue progress is not the same as receiver-committed progress.
- The UDP blast path has custom pacing, replay, repair, lane selection, and relay fallback behavior that overlaps with functionality QUIC already provides.
- Live runs can leave the user with a transfer that is neither fast direct nor reliable relay.
- Throughput can stay far below iperf3 even when the raw network path is healthy.

The core design issue is carrier handoff at the application-transfer layer. The application must copy bytes to one reliable stream and receive committed bytes from one reliable stream. Path promotion belongs below that stream.

## Goals

- Make v2 the default transfer protocol for `send` and `receive`.
- Use QUIC as the default reliable payload data plane.
- Keep DERP relay usable from the start of the transfer.
- Add direct UDP paths under the same QUIC session when they are validated.
- Never stop relay progress merely because direct probing has started.
- Complete cleanly on relay when direct cannot be established.
- Propagate peer aborts and local cancels immediately.
- Keep telemetry good enough to explain setup time, first byte, direct validation, fallback, goodput, and teardown.
- Keep live harnesses strict: size, SHA-256, trace checks, and process/socket leak checks must pass.
- Treat iperf3 as the performance ceiling and use the gap to guide optimization after correctness is stable.

## Non-Goals

- Do not preserve wire compatibility with the legacy direct UDP transfer protocol.
- Do not tune the old UDP blast path into the default path.
- Do not make a browser protocol change in this phase.
- Do not remove lower-level diagnostic benchmarks immediately.
- Do not block the first v2 correctness milestone on reaching 90% of iperf3.

## Architecture

### Control Plane

Keep DERP-backed offer, claim, accept, abort, progress, and complete messages.

The v2 control plane must be explicit about protocol version and selected data plane:

- offer advertises v2 support, QUIC identity, direct candidates, and relay capability
- claim confirms v2 support, QUIC identity, direct candidates, and receiver constraints
- accept authorizes a single QUIC transfer session
- abort terminates the session immediately with authenticated peer-abort semantics
- complete confirms the receiver-committed payload byte count and hash result where available

Control messages must be versioned independently from legacy envelopes so v2 failures are diagnosed as v2 failures instead of falling through legacy direct UDP behavior.

### Data Plane

Create a small data-plane boundary under `pkg/dataplane`, with one default implementation:

```go
type DataPlane interface {
    Open(ctx context.Context) (TransferConn, error)
    Stats() Stats
    CloseWithError(code uint64, reason string) error
}
```

`TransferConn` must expose the QUIC stream or a narrow `io.Reader` / `io.Writer` abstraction, not the legacy handoff machinery.

The default implementation is QUIC over `transport.Manager.PeerDatagramConn`. The manager can use DERP relay packets immediately and direct UDP packets when available. QUIC sees one packet connection and one connection identity.

### Path Manager

Use the existing `transport.Manager` concept, but make its contract simpler for transfers:

- relay path is available at session start
- direct candidates are added asynchronously
- path validation emits state and metrics
- failed direct validation does not cancel relay
- closing the transfer closes all direct sockets and relay subscriptions

The path manager must report whether the active QUIC connection is using relay, direct, or both, but the file-transfer layer must not make correctness decisions from that detail.

### Legacy Transport

Move the legacy UDP blast/replay path out of the default transfer path.

It can remain temporarily as:

- a diagnostic benchmark backend
- an explicit opt-in debug transport
- a source of candidate-gathering and path-measurement code where still useful

Normal `send` / `receive` must not enter relay-prefix data mode or UDP blast handoff once v2 is enabled by default.

## Transfer Flow

### Sender

1. Create a v2 offer token with QUIC identity and local candidate metadata.
2. Wait for a v2 claim.
3. Start the transport manager with relay enabled.
4. Start direct candidate punching and validation asynchronously.
5. Dial QUIC over the manager packet connection.
6. Copy payload bytes into one QUIC stream.
7. Close the stream and wait for receiver complete / peer ACK.
8. Close the QUIC connection and transport manager.

### Receiver

1. Decode a v2 offer token.
2. Gather local candidates.
3. Send a v2 claim.
4. Start the transport manager with relay enabled.
5. Start direct candidate punching and validation asynchronously.
6. Accept QUIC over the manager packet connection.
7. Copy one QUIC stream to the output file.
8. Verify byte count and complete the transfer.
9. Send receiver complete / peer ACK.
10. Close the QUIC connection and transport manager.

### Fallback Behavior

Fallback is not a separate payload protocol in v2.

If direct never validates, QUIC continues over relay. If direct validates late, QUIC can use it late. If direct later becomes bad, QUIC and the path manager can fall back to relay or another path without changing application stream semantics.

If relay itself fails, the transfer fails explicitly with diagnostics. It must not spin waiting for a direct path that was never validated.

## Performance Strategy

The first v2 milestone is correctness. Once correctness is stable, optimize one path instead of several:

- collect iperf3 TCP and UDP baselines for the same host pair and direction
- collect QUIC qlog or equivalent connection stats
- record relay bytes, direct bytes, RTT, congestion window, loss, retransmits, stream blocked time, and socket buffer pressure
- use pprof where CPU or copy overhead is suspected
- compare quiet runs only; verbose logging must not be used for throughput claims

The expected performance target is eventually 90% or better of the feasible iperf3 ceiling for direct-capable paths. If a host pair cannot reach that, the run must explain why with transport metrics rather than guesswork.

## Telemetry

Keep the existing transfer trace concept and add v2-specific fields where needed:

- protocol version
- selected data plane
- relay bytes
- direct bytes
- QUIC bytes sent / received
- QUIC handshake duration
- first application byte duration
- direct validation start and finish times
- active path state
- RTT, loss, retransmit count, congestion window, and blocked state when available
- abort source and close reason

Sender progress must continue to distinguish local source-read bytes from receiver-confirmed bytes. Receiver progress remains the authoritative committed-output byte count.

## Error Handling

Local cancellation must close QUIC with an application close code and send an authenticated abort envelope if the control plane is still available.

Peer abort must cancel the active transfer context immediately and close QUIC / sockets. The user-facing error must say peer aborted, not generic timeout.

Direct path failures are non-fatal while relay is healthy. Relay failure is fatal unless another already-validated path is active.

Timeouts must be phase-specific:

- claim wait timeout
- QUIC handshake timeout
- first-byte timeout
- idle progress timeout
- close ACK timeout

Each timeout must identify the phase that failed.

## Testing

### Unit Tests

Add focused tests for:

- v2 offer / claim / accept validation
- protocol version rejection
- abort propagation
- QUIC stream copy success
- receiver complete ACK success
- relay-only success with no direct candidate
- direct validation failure while relay continues
- cleanup closes packet conns and subscriptions

### Integration Tests

Use in-process packet conns or local loopback harnesses to prove:

- QUIC completes over relay-only manager
- QUIC completes after direct path appears late
- direct failure does not stall stream progress
- peer cancel interrupts the opposite side promptly
- metrics report final bytes and close reason

### Live Tests

Required live gates before flipping v2 into the normal release path:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh pve1 canlxc 1024
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh canlxc pve1 1024
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh canlxc lotus-stalemate.exe.xyz 1024
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh lotus-stalemate.exe.xyz canlxc 1024
```

Every accepted live result must include:

- `stall-harness-success=true`
- matching payload SHA-256
- sender and receiver transfer traces
- trace checker success
- no leaked `derphole` process
- no leaked derphole UDP socket
- clear final transport state

Do not report a throughput result from a failed live gate.

## Migration

Use a staged implementation but an intentionally breaking protocol boundary.

1. Add v2 protocol messages and data-plane interfaces.
2. Implement relay-capable QUIC data plane.
3. Wire `send` / `receive` through v2 behind an internal selector.
4. Make v2 the default once local and remote harnesses pass.
5. Keep legacy blast only behind an explicit diagnostic selector.
6. Remove legacy relay-prefix transfer code from the default path after v2 passes repeated live tests.

The old `DERPHOLE_DIRECT_TRANSPORT=quic` experiment must be replaced by a clearer selector during transition, then removed once v2 is default.

## Risks

- QUIC over the current manager packet connection may still inherit packet-engine bottlenecks.
- Relay-over-DERP packet framing may cap throughput on relay-only transfers.
- qlog and detailed QUIC metrics may require additional plumbing from quic-go.
- Some existing tests assume legacy direct UDP behavior and will need to move to diagnostic-specific coverage.

These risks are manageable because v2 reduces the number of interacting reliability layers. If performance is still below iperf3, the remaining bottleneck must be localized to QUIC configuration, packet connection behavior, DERP relay framing, or socket buffers.

## Acceptance Criteria

The v2 project is complete when:

- v2 is the default `send` / `receive` protocol
- legacy UDP blast is not used by default transfers
- relay-only transfers complete without stalling
- direct-capable transfers complete without app-layer handoff stalls
- receiver Ctrl-C terminates the sender promptly
- live pve1 / canlxc / lotus gates pass in both directions
- release checks pass
- throughput gaps are either improved or explained with recorded benchmark logs and diagnostics
