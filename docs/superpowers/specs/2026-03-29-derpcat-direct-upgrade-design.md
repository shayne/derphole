# derpcat Direct Upgrade Design

## Summary

`derpcat` currently decides between direct UDP and DERP relay only once during
session establishment. That model is materially weaker than Tailscale's
`magicsock` behavior: if direct NAT traversal does not succeed during the short
initial probe window, the session stays on relay for its entire lifetime.

This design replaces the current one-shot probing model with a long-lived
transport manager that keeps discovering, coordinating, and re-evaluating paths
for the full lifetime of a peer session. The transport should be able to start
on DERP relay immediately, continue carrying traffic, and later upgrade the same
active session to direct UDP when the network allows it.

The goal is to make `derpcat` behave like the free and open source Tailscale
runtime in the cases that matter here: relay-first bootstrap, background disco
pinging, DERP-delivered `CallMeMaybe` signaling, best-path tracking, and
promotion from relay to direct without restarting the session.

## Goals

- Allow active `derpcat` sessions to start on DERP relay and later upgrade to
  direct UDP.
- Apply the new behavior to all session types: `listen`/`send` and
  `share`/`open`.
- Reuse or adapt as much of Tailscale's proven traversal machinery as practical.
- Keep the no-login, bearer-token, one-peer `derpcat` product model.
- Preserve DERP relay as a stable fallback path.
- Report path state truthfully during live sessions.

## Non-Goals

- Preserving the current internal transport structure.
- Maintaining backward compatibility for transport internals.
- Recreating all of Tailscale's tailnet or control-plane behavior.
- Supporting more than one remote peer per token.
- Turning `derpcat` into a general VPN or multi-peer mesh.

## Current Problem

Today the direct path logic is intentionally simple:

- the sender probes the peer's candidates once after claim acceptance
- the listener only responds to direct probes during a short pre-decision window
- the session then chooses its transport and proceeds

That means:

- if simultaneous hole punching is required after the session starts, current
  `derpcat` cannot do it
- if the network needs more time than the initial probe window, the session does
  not keep trying
- long-running sessions do not get better over time the way Tailscale sessions
  do

The existing behavior is good enough for easy cases such as same-LAN peers or
publicly reachable listeners, but it is not good enough for the harder
relay-first then direct-upgrade cases.

## Recommended Approach

Adopt Tailscale's runtime behavior pattern by extracting and adapting the
relevant `magicsock` traversal concepts into a `derpcat`-owned transport layer.

### Why this approach

A minimal retry loop on top of the current design would still be bespoke and
fragile. The gap is not merely timing. The gap is the absence of a long-lived
runtime model for:

- endpoint state
- repeated discovery pings
- DERP-based `CallMeMaybe` coordination
- best-path trust and expiry
- continuous path re-evaluation while traffic is already flowing

Tailscale already solved those problems in the open. `derpcat` should borrow the
transport behavior, not continue iterating on a one-shot approximation.

## Architecture

### High-Level Split

`derpcat` should separate session orchestration from transport path management.

- `pkg/session`
  - token issuance and claim
  - CLI-mode orchestration for `listen`, `send`, `share`, and `open`
  - local stream or forwarded-listener attachment
- `pkg/transport`
  - long-lived peer transport manager
  - DERP bootstrap and DERP control channel
  - STUN endpoint gathering and refresh
  - disco ping scheduling
  - `CallMeMaybe` sending and handling
  - endpoint registry and path scoring
  - relay/direct promotion and fallback decisions
- `pkg/wg`
  - userspace WireGuard device and overlay/netstack support
  - thin data-plane adapter that follows the active best path

The `pkg/session` layer should stop deciding transport outcome itself. It should
bring up the transport manager, start the overlay as soon as any working path is
available, and let the transport layer improve the path over time.

### Tailscale Concepts To Adapt

The new transport layer should port or closely mirror these Tailscale concepts:

- endpoint-state tracking
- repeated disco pings to known peer candidates
- DERP-based `CallMeMaybe` messages
- best-path trust windows and expiry
- periodic path discovery while current transport is relay or stale
- direct-path promotion during an already-active session
- fallback from direct back to relay when direct breaks

The transport layer does not need all of `magicsock`'s multi-peer and netmap
machinery. `derpcat` has exactly one remote peer per session, so the adapted
implementation should strip away tailnet-specific complexity while preserving
runtime behavior.

## Session Flow

The new session model is relay-first, upgrade-opportunistically.

1. The token claim still happens over DERP.
2. Both sides create the long-lived transport manager immediately after claim.
3. The overlay starts as soon as the transport manager has any viable path.
4. If the current best path is DERP relay, the session still proceeds.
5. While traffic is flowing, the transport manager continues:
   - refreshing local endpoints when needed
   - sending discovery pings to peer candidates
   - sending `CallMeMaybe` over DERP
   - reacting to new peer endpoints
   - re-evaluating the best active path
6. When a validated direct path becomes better than relay, outbound traffic
   shifts to that path without restarting the overlay session.
7. If the direct path later degrades or fails, traffic falls back to relay and
   the manager continues trying to recover a direct path.

This applies equally to:

- one-shot stdio sessions (`listen` / `send`)
- long-lived forwarding sessions (`share` / `open`)

For very short one-shot sessions, upgrade may never occur before the session
finishes. That is acceptable. The important property is that longer sessions are
no longer stuck on relay merely because the first probe window failed.

## Path State And Reporting

Current path reporting is too optimistic because it treats any inbound UDP as
proof of direct success. The new transport layer should own path truth.

### Internal state model

The transport manager should track states such as:

- `relay-active`
- `direct-active`
- `upgrading`
- `degraded`

These are internal transport states, not necessarily all exposed verbatim to the
CLI.

### CLI-facing states

For normal CLI output, keep the simple user-facing messages:

- `connected-relay`
- `connected-direct`

In verbose mode, add runtime transitions:

- `upgraded-direct`
- `fell-back-relay`

The rule is strict: only report `direct` when the transport manager considers
direct UDP the active best path. Passive receipt of some UDP packet is not
sufficient.

### Debug counters

Verbose or debug output should include lightweight runtime counters such as:

- number of direct discovery attempts
- number of successful direct upgrades
- number of direct-to-relay fallbacks
- current best endpoint
- last endpoint refresh time

These are important for live verification and field debugging.

## Code Changes

### Replace

- the one-shot direct probing in `pkg/session/external.go`
- the mirrored one-shot probing in `pkg/session/external_share.go`
- the current direct-confirmation logic in `pkg/wg/bind.go`
- the narrow traversal model in `pkg/traversal`

### Add

- `pkg/transport` as the owner of long-lived path discovery and path state
- adapted Tailscale-style endpoint and disco management
- ongoing relay-to-direct and direct-to-relay path transition handling
- runtime status emission for path transitions

### Keep

- bearer-token session model
- no-login public DERP bootstrap
- one claimant per token
- userspace WireGuard overlay
- current CLI command surfaces unless transport-facing flags require cleanup

## Error Handling

The transport manager should handle path changes as runtime events instead of
fatal connect-time failures where possible.

- Failure to establish direct immediately is not fatal if relay works.
- Failure of a current direct path is not fatal if relay still works.
- DERP failure is fatal only when there is no currently working direct path.
- If both direct and relay are unavailable, the session fails.
- Endpoint refresh or `CallMeMaybe` failures should be treated as degraded-path
  signals, not immediate process-fatal conditions, unless they imply the whole
  session is unrecoverable.

## Testing

### Automated coverage

Add focused tests for:

- endpoint-state updates and best-path selection
- relay-first then direct-upgrade transitions
- direct-to-relay fallback transitions
- `CallMeMaybe`-driven candidate refresh
- preservation of existing stdio behavior
- preservation of `share`/`open` forwarding behavior on top of the new
  transport

### Live validation

The live matrix is mandatory and should be treated as release-blocking for this
change:

1. local sender -> `hetz` listener
2. `hetz` sender -> local listener
3. `pve1` sender -> `hetz` listener
4. `hetz` sender -> `pve1` listener
5. same-LAN cases where applicable
6. long-running relay-first sessions that remain alive for more than 10 seconds
7. 1 GiB transfers with path-state observation during the run

### Success criteria

- Existing CLI modes still function correctly.
- Relay remains a stable fallback path.
- At least some previously relay-stuck sessions now upgrade to direct during an
  active session.
- Path reporting is truthful and reflects actual active transport state.
- If a network cannot punch through, the session remains stable on relay rather
  than flapping or misreporting.

## Rollout Notes

This is a transport rewrite under a greenfield-compatible product. Internal
breaking changes are expected and acceptable.

The right implementation bias is correctness over minimal diff. The existing
transport code should not be preserved merely to reduce churn if it prevents
`derpcat` from behaving like Tailscale in the relay-first then direct-upgrade
cases.
