# V2 Core Transport Cleanup Design

Date: 2026-05-22

## Summary

Derphole should use one core transport architecture across the product: the v2-derived QUIC transport that starts relay-capable through DERP, validates direct UDP paths underneath the same session, and keeps application protocols on top of stable QUIC streams.

This is a breaking cleanup. The goal is to retire inferior legacy implementations rather than preserve compatibility with them.

## Problem

The codebase still contains several older transfer and tunnel paths:

- legacy direct UDP blast, replay, FEC, repair, rate probe, and spool logic
- old direct QUIC selector paths
- native TCP upgrade paths
- WireGuard/netstack-based derptun tunnel runtime
- application-layer handoff machinery
- environment selectors such as `DERPHOLE_DIRECT_TRANSPORT`

Those paths make the code difficult to reason about and keep obsolete behavior alive. The recent v2 work has shown a better model: one reliable QUIC session over a relay-first path that can promote to direct without changing application stream semantics.

## Goals

- Make the v2-derived QUIC transport the only core product transport for `derphole` and `derptun`.
- Delete old implementations rather than hiding them behind debug flags.
- Keep DERP as rendezvous, control plane, and relay packet path.
- Keep direct UDP promotion below the app layer.
- Keep app protocols simple: file transfer and TCP tunnels use QUIC streams.
- Preserve current user-facing capabilities for `derphole send/receive/offer/listen` and `derptun serve/connect/open`.
- Use E2E tests as the proof that the rewrite works.
- Keep telemetry sufficient to explain direct selection, fallback, performance, aborts, and cleanup.

## Non-Goals

- Do not preserve wire compatibility with legacy transfer protocols.
- Do not keep legacy UDP blast as a product path.
- Do not keep WireGuard/netstack derptun as a fallback runtime.
- Do not carry old transport selectors forward.
- Do not optimize old code while removing it.

## Architecture

### Core Session Transport

Create or consolidate a shared core layer that owns:

- DERP connection setup
- peer identity and QUIC identity
- authenticated control envelope handling
- v2 claim, accept, data-plane-ready, abort, and complete messages
- candidate exchange and direct nudges
- transport manager startup
- raw-direct packet path selection
- QUIC endpoint creation
- abort and close semantics
- telemetry and cleanup

This layer is reused by file transfer and derptun. It must not contain file metadata handling or TCP target bridging.

### Low-Level Path Manager

`pkg/transport` remains the low-level relay/direct path manager:

- relay is available at session start
- direct candidates can be seeded and validated asynchronously
- direct failure does not stop relay progress
- path state is observable through telemetry
- all sockets and subscriptions close with the session

The path manager is a packet substrate. Application protocols must not reason about UDP lanes, replay windows, relay prefixes, or native TCP upgrade races.

### QUIC Stream Carrier

The shared carrier exposes QUIC streams:

- one or more unidirectional or bidirectional streams for file transfer
- one bidirectional stream per derptun TCP connection
- clean close with reason
- peer abort propagation
- idle timeout and first-byte timeout
- stats for bytes, duration, relay/direct path use, and close reason

The carrier can use raw-direct packet conns when both peers agree. Otherwise it uses the manager-backed relay/direct packet path.

### File Transfer Protocol

`derphole send/receive/offer/listen` becomes a file-transfer protocol over the shared carrier.

It owns:

- file metadata
- payload byte copy
- progress display
- receiver committed-byte completion
- trace output
- optional hash verification where already supported

It does not own:

- UDP rate control
- direct path selection
- replay or repair
- native TCP upgrade
- app-layer handoff

### Tunnel Protocol

`derptun` uses the same shared transport and QUIC carrier.

- `derptun serve --tcp` accepts QUIC streams and bridges each stream to the configured local TCP target.
- `derptun connect --stdio` opens one bidirectional QUIC stream and bridges stdin/stdout.
- `derptun open` accepts local TCP connections and opens one QUIC stream per connection.

The WireGuard/netstack runtime is removed after this QUIC stream tunnel preserves the current behavior in tests.

## Data Flow

### File Transfer

1. The offering side creates a v2-capable token with DERP public key and QUIC public key.
2. The peer claims through DERP using authenticated v2 control.
3. Both sides start the shared transport session.
4. Relay is available immediately.
5. Direct candidate exchange and raw-direct validation run under the session.
6. QUIC is established over the selected carrier.
7. File metadata is sent on the transfer protocol stream.
8. Payload bytes are copied once through QUIC streams.
9. The receiver sends authenticated complete with committed bytes.
10. The sender exits after complete or peer abort.

### Derptun

1. Server and client tokens keep the current conceptual model.
2. Client claims through DERP.
3. Both sides start the shared transport session.
4. QUIC becomes the tunnel carrier.
5. Each tunnel connection maps to a QUIC bidirectional stream.
6. Local TCP close maps to QUIC stream close.
7. Peer close maps to local TCP half-close where possible.
8. Ctrl-C or fatal transport close tears down the session promptly.

## Removed Code

The cleanup removes production use of:

- `external_direct_udp*`
- UDP blast/replay/FEC/repair/rate-probe transfer machinery
- relay-prefix transfer framing
- direct UDP spool and handoff code
- old direct QUIC transfer selector path
- native TCP transfer upgrade code
- WireGuard/netstack derptun runtime
- old WG tunnel transfer path
- `DERPHOLE_DIRECT_TRANSPORT`
- tests that exist only to preserve removed behavior

Diagnostic code may remain only when it supports the new transport or E2E gates. It must not keep an old product path alive.

## Error Handling

Failures must name the phase:

- claim timeout: `claim timed out`
- QUIC handshake timeout: `quic handshake timed out`
- first stream timeout: `first stream timed out`
- idle timeout: `timeout: no recent network activity`
- peer abort: `peer aborted transfer`
- peer disconnect: `peer disconnected`

Direct failure while relay is healthy is telemetry, not a fatal application error.

Raw-direct failure before consensus falls back to manager-backed QUIC. Raw-direct failure after selection closes QUIC and fails explicitly. This cleanup does not add mid-session raw-direct-to-manager migration because that would reintroduce handoff complexity at a different layer.

Cleanup rules:

- unsubscribe all DERP subscriptions
- close all UDP sockets
- close portmaps
- close QUIC with a reason when possible
- send authenticated abort on local cancel while DERP control is still available
- do not wait indefinitely after the peer exits

## Telemetry

Shared trace output should include:

- protocol version
- application protocol
- data plane
- relay bytes
- direct bytes
- raw-direct selected or fallback
- first-byte timing
- QUIC handshake timing
- stream duration
- close reason
- abort source
- path state summary

Blast-specific fields disappear from product telemetry.

## Testing

### Unit Tests

Cover:

- v2 control auth and validation
- candidate filtering and raw-direct consensus
- manager-backed QUIC fallback
- abort propagation
- stream close behavior
- cleanup of sockets and subscriptions
- file transfer metadata and completion
- derptun stream bridging

### Integration Tests

Cover:

- relay-only QUIC transfer
- direct QUIC transfer
- raw-direct success
- raw-direct failure fallback
- peer cancel interrupting the other side
- derptun `connect --stdio`
- derptun `open` bridging multiple local TCP connections

### E2E Gates

Before this cleanup is complete:

- `mise run check`
- `mise run smoke-local`
- file transfer direct and force-relay
- derptun stdio bridge through a local TCP echo target
- derptun open/serve bridge through a local TCP echo target
- live Mac <-> pve1 direct transfer
- live pve1 <-> canlxc transfer compared with iperf3
- live current exe host relay/direct behavior check
- receiver Ctrl-C terminates sender promptly
- sender Ctrl-C terminates receiver promptly
- no leaked `derphole` or `derptun` processes
- no leaked UDP sockets from the tested process

Throughput claims must come from successful E2E runs, not failed or manually interrupted runs.

## Migration

This is a big-bang cleanup in the sense that the final integration removes old implementations and does not preserve legacy wire compatibility. The implementation can use local checkpoint commits, but the release result is one coherent transport replacement:

1. Introduce the shared v2 core transport boundary.
2. Move file transfer onto that shared boundary.
3. Move derptun onto QUIC stream tunneling over that shared boundary.
4. Delete legacy file-transfer implementations and selectors.
5. Delete WireGuard/netstack derptun runtime and dependencies if no supported command still imports them.
6. Remove obsolete tests and update E2E gates.
7. Run full local and live verification before release.

## Acceptance Criteria

The cleanup is complete when:

- `derphole` and `derptun` use the same v2-derived core transport.
- Legacy transfer/tunnel implementations are removed from production code.
- Obsolete env selectors are removed.
- File transfer succeeds over relay and direct.
- Derptun stdio/open/serve succeed over relay and direct where available.
- Peer abort and Ctrl-C propagate promptly.
- E2E gates pass locally and against live hosts.
- The codebase is smaller and the remaining transport path is explainable from the shared core down to the app protocol.
