# Unified WireGuard Transport Design

## Summary

Replace derphole's split public transport stack with one transport substrate:

- DERP for rendezvous, control, and relay fallback
- direct UDP for NAT traversal and fast-path data transfer
- the in-repo WireGuard packet engine in `pkg/wg` as the only direct and relay data plane

The proof work already established the important fact: derphole can reach the WAN ceiling when it uses the faster packet path. This refactor promotes that winning path into the product and removes the older QUIC and public-native-TCP branches.

## Goals

- Make the fast path the default public derphole transport.
- Remove the public-native-TCP bootstrap path entirely.
- Remove the direct QUIC path entirely.
- Keep DERP as the rendezvous and relay fallback mechanism.
- Preserve no-open-ports behavior as the default operating model.
- Achieve direct no-Tailscale transfers that stay near the proven WAN ceiling on the best host pair, especially this Mac and `ktzlxc`.
- Keep derphole semantics intact for:
  - `send` / `listen`
  - `share` / `open`
- Use live-host testing, not only unit tests, as the completion gate.

## Non-Goals

- Adding a second transport family alongside the new one.
- Preserving the public-native-TCP bootstrap path behind feature flags.
- Keeping QUIC as an alternate direct path.
- Requiring manual port forwarding or any OS-level system modifications.
- Turning derphole into a general mesh VPN product.

## Context

Today derphole's public path is fragmented:

- DERP handles rendezvous and relay.
- direct QUIC over UDP handles the normal direct fast path.
- a later public-native-TCP bootstrap path exists as an optimization branch.

That structure creates three problems:

1. More than one transport state machine is active in the public session flow.
2. The path that proved the highest throughput is not the same path derphole leads with by default.
3. The code is harder to reason about because direct promotion, relay fallback, and transfer semantics are spread across multiple transport implementations.

The repo already contains the better substrate:

- `pkg/wg` provides an in-process WireGuard node backed by `wireguard-go`.
- `pkg/wg/bind.go` already knows how to carry the same encrypted packets either directly over UDP or through DERP.
- `pkg/probe/wg.go` and related proof code already used this substrate to establish the performance ceiling.

The right move is to productize that path instead of tuning the older QUIC path further.

## Approaches Considered

### Approach 1: Keep QUIC and tune it more

Pros:

- smallest code churn
- lowest immediate risk

Cons:

- does not simplify the architecture
- keeps the split transport model
- does not make the proven fast path the product path

### Approach 2: Replace public transport with one WireGuard-based substrate

Pros:

- one packet engine for direct and relay
- one session state machine
- reuses the proven fast path already in the repo
- matches the no-open-ports target naturally

Cons:

- broader refactor across `pkg/session`
- requires migrating both `send/listen` and `share/open`

### Approach 3: Build a brand-new custom reliability protocol

Pros:

- maximum control

Cons:

- unnecessary given the existing `pkg/wg` substrate
- highest implementation risk
- longest path to production

## Recommendation

Use approach 2.

The direct and relay data plane should be the existing in-repo WireGuard substrate. DERP remains for coordination and relay fallback. `pkg/session` should stop selecting between transport families and instead create one tunnel-backed session, then run derphole behavior over that tunnel.

## Architecture

### Control Plane

DERP remains the control channel. It is responsible for:

- claim / accept / reject
- peer identity exchange
- candidate exchange
- path coordination
- relay fallback coordination
- candidate refresh when NAT mappings change

DERP control messages stay small. They do not carry bulk transfer payloads except when the session is explicitly in relay mode and `pkg/wg/bind.go` is using DERP as the packet carrier.

### Data Plane

The data plane is unified:

- one UDP socket per public session
- one WireGuard overlay per claimed session
- one path selector that prefers direct UDP and falls back to DERP relay

The same encrypted WireGuard packets are used in both cases:

- direct UDP path when NAT traversal succeeds
- DERP relay path when direct UDP is unavailable

That means there is no transport handoff from DERP to QUIC or from QUIC to public TCP. There is only path selection inside one transport substrate.

### Session Adapters

Derphole behaviors run above the overlay:

- `send/listen`
  - open one or more TCP streams inside the per-session netstack
  - stream bytes from stdin/file to receiver sink
- `share/open`
  - map each accepted local TCP connection to one overlay TCP stream
  - bridge overlay stream to backend or local listener as appropriate

This preserves the CLI model while replacing the underlying transport.

## Handshake And Path Flow

1. Listener starts:
   - binds a UDP socket
   - gathers local traversal candidates
   - opens DERP control subscription
   - creates WireGuard session material for the session

2. Sender claims token over DERP:
   - sends sender identity
   - sends sender traversal candidates
   - sends sender WireGuard public material needed to form the overlay

3. Listener accepts:
   - sends listener traversal candidates
   - sends listener WireGuard public material

4. Both sides start discovery:
   - `pkg/transport.Manager` sends direct probes to peer candidates
   - both sides keep DERP control alive during discovery

5. Both sides start the WireGuard node:
   - `pkg/wg.Bind` is configured with the shared session packet socket, DERP client, peer DERP key, and path selector
   - until direct path is confirmed, packets may flow via DERP

6. Direct promotion:
   - when `pkg/transport.Manager` confirms direct peer activity, `pkg/wg.Bind` starts preferring the direct UDP endpoint
   - the overlay session stays the same; only the packet path changes

7. Data transfer:
   - derphole opens overlay TCP streams inside the session netstack
   - all user payloads ride those overlay streams

8. Path recovery:
   - if the direct path goes stale, control stays on DERP
   - packet carriage falls back to DERP until direct UDP becomes usable again
   - the overlay session and stream semantics remain unchanged

## Code Structure

### Keep And Expand

- `pkg/traversal`
  - candidate gathering
  - STUN-derived endpoint discovery
  - punch support

- `pkg/transport`
  - direct path discovery and promotion
  - candidate refresh
  - stale-path demotion

- `pkg/wg`
  - packet engine
  - direct-vs-DERP packet carriage
  - in-process TCP overlay

### Remove

- `pkg/quicpath`
- `pkg/session/external_native_quic.go`
- `pkg/session/external_native_tcp.go`
- `pkg/session/external_bootstrap.go`
- QUIC-specific mode negotiation envelopes in `pkg/session/external.go`

### Reshape

- `pkg/session/external.go`
  - stop negotiating QUIC/TCP modes
  - create one public session tunnel backed by `pkg/wg`
  - expose a small internal surface for:
    - open tunnel
    - dial overlay stream
    - listen on overlay stream

- `pkg/session/external_share.go`
  - reuse the same public tunnel path as `send/listen`
  - remove QUIC-specific listener/dial logic

- `pkg/token`
  - remove public-native-TCP bootstrap fields once the old path is deleted

## Security Model

Security remains end-to-end:

- session tokens still authenticate the claim path
- DERP only coordinates and relays encrypted packets
- overlay data confidentiality and integrity come from the per-session WireGuard keys

This is stronger and simpler than maintaining separate QUIC TLS state and bootstrap TCP branches.

## Testing Strategy

### Package Tests

Add and update tests to cover:

- public session setup using `pkg/wg` instead of QUIC
- direct path promotion still driving the transport manager correctly
- DERP relay fallback still carrying overlay traffic
- `send/listen` over the new tunnel
- `share/open` over the new tunnel
- token compatibility after removing bootstrap fields

### Live Tests

Live validation is mandatory. The refactor is not done if only package tests pass.

Required live checks:

1. This Mac <-> `ktzlxc`
   - both directions
   - no dedicated port forward
   - `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`
   - automatic direct promotion
   - throughput near the proven WAN ceiling

2. Additional hosts:
   - `canlxc`
   - `uklxc`
   - `orange-india.exe.xyz`

3. Relay fallback validation
   - disable or break direct path in a controlled run
   - confirm the same session continues via DERP relay

4. Feature validation
   - file send with `send/listen`
   - local service forwarding with `share/open`

## Completion Criteria

The refactor is complete only when all of the following are true:

- the public direct path uses the unified WireGuard transport by default
- QUIC direct transport is gone
- public-native-TCP bootstrap is gone
- DERP still handles rendezvous, control, and relay fallback
- no-open-ports direct transfers work on the required hosts
- this Mac and `ktzlxc` stay near the proven WAN ceiling in both directions
- `send/listen` and `share/open` both work on the new path
- CI passes
- the npm dev build includes the refactor

## Risks And Guardrails

### Risk: Integration regresses the ceiling

Guardrail:

- keep live `ktzlxc` throughput runs as the acceptance gate for each major milestone
- if a refactor step drops direct performance badly, stop and fix before widening scope

### Risk: Session code grows another abstraction pile

Guardrail:

- keep `pkg/session` as the orchestration layer only
- do not re-implement reliability there
- let `pkg/wg` own transport semantics

### Risk: Relay and direct paths diverge again

Guardrail:

- same overlay session in both cases
- same stream adapters in both cases
- only packet carriage changes
