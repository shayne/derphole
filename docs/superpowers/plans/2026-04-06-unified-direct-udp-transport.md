# Unified Direct UDP Transport Plan

> For implementation in this repository on 2026-04-06.

## Goal

Replace derphole's current public WireGuard-over-TCP default with one direct UDP data plane that:

- uses DERP for rendezvous, coordination, and relay fallback
- uses direct UDP between peers whenever possible, without requiring forwarded ports
- restores at least the old healthy `ktzlxc` public-session baseline of about `955 Mbps`
- creates a credible path toward the forwarded-port TCP ceiling of about `1.9-2.2 Gbps`

## Facts Established

- The forwarded-port baseline is real, but it is only a ceiling:
  - `ktzlxc -> Mac`: about `1.94-1.96 Gbps`
  - `Mac -> ktzlxc`: about `2.22-2.23 Gbps`
- The current default dev build is not close:
  - user run: about `27-44 MiB/s`
  - current live proof on `main`: `promotion-test.sh ktzlxc 1024` completed in `51s`, about `160 Mbps`
- The regression aligns with `8786f15 session: switch public transport to wg tunnel`
- Current WG-backed probe results on `main` are also too slow:
  - `wgiperf P4`: about `296 Mbps`
  - `wgiperf P8`: about `268 Mbps`
  - `wgos P4`: about `454 Mbps`
- The best no-forwarded-port evidence in-repo is not the WG tunnel. It is the tuned raw packet probe:
  - `raw batched P12/W320`: up to `1121.8 Mbps`
- Therefore the WG tunnel cutover is the wrong default architecture for the throughput target.

## Decision

Do not continue optimizing the current public WG tunnel as the primary transport.

Instead:

1. Keep DERP rendezvous and relay fallback.
2. Keep NAT traversal and direct-path promotion.
3. Replace the public data plane with a direct UDP stream transport derived from the proven probe packet engine.
4. Remove the old public QUIC path and the new WG-tunnel detour once the replacement is live and verified.

## Architecture

### Control Plane

- Token issuance and validation stay in `pkg/session` and `pkg/token`.
- Claim, decision, and control envelopes stay DERP-backed.
- `pkg/transport.Manager` remains the authoritative path selector for relay vs direct UDP.

### Data Plane

- New package: `pkg/directudp` or equivalent extracted from `pkg/probe/session.go` and `pkg/probe/batching.go`
- Data plane properties:
  - packetized stream protocol over UDP
  - hello/hello-ack session gating
  - run IDs to isolate concurrent sessions
  - reliable ordered mode for `send/listen`, `share/open`
  - optional striped mode above the base session, but only after the single-session path is healthy
  - DERP relay fallback carries the same encrypted/session-scoped packets when direct UDP is unavailable

### Scope Cut

Phase 1:

- public `send/listen` migrate to direct UDP stream transport
- remove default dependency on `external_wg.go`
- preserve current CLI and token UX

Phase 2:

- public `share/open` migrate to the same transport
- delete obsolete public QUIC and WG-tunnel transport code

## Implementation Tasks

### Task 1: Lock a reproducible proof target

- Reproduce the last healthy old-public-path throughput on `ktzlxc`
- Reproduce the best current raw-probe throughput on `main`
- Fix or retire the probe striped-orchestrate cases that no longer reproduce cleanly
- Record only clean runs in `KTZLXC_BENCHMARKS.md`

Exit criterion:

- one clean no-forwarded-port benchmark on current code that is demonstrably better than the current WG-tunnel default

### Task 2: Extract the raw packet engine into a reusable package

- Move reusable pieces out of `pkg/probe`:
  - batching capability detection
  - packet framing
  - hello handshake
  - ACK/window logic
  - ordered receive buffering
- Remove probe-only reporting types from the core transport surface
- Keep a small adapter layer in `pkg/probe` so the benchmark harness still works

Exit criterion:

- package-level tests pass for the extracted engine without importing probe orchestration logic

### Task 3: Replace public `send/listen` default transport

- Update `sendExternal` and `listenExternal` to use the new direct UDP stream transport
- Use `transport.Manager` path selection for direct promotion and DERP fallback
- Keep the active side authoritative for any striping or tuning decisions
- Keep verbose path reporting honest:
  - `connected-relay`
  - `connected-direct`
  - stripe count only if stripes are actually active

Exit criterion:

- `send/listen` works with no forwarded ports on `ktzlxc`, `canlxc`, `uklxc`, and `orange-india.exe.xyz`

### Task 4: Recover performance before adding complexity

- First optimize the single-session direct UDP path
- Only add striping after the base session stops being the bottleneck
- Focus on:
  - socket batching behavior
  - ACK pacing and retransmit timing
  - receive queue pressure
  - packet sizing and in-flight window control

Exit criterion:

- `ktzlxc` no-forwarded-port direct transfer clearly beats the current WG-tunnel implementation and reaches or exceeds the old ~`955 Mbps` derphole baseline

### Task 5: Migrate `share/open`

- Replace the remaining public session QUIC/WG-tunnel plumbing with the same transport
- Keep one public transport model for all public commands

Exit criterion:

- `share/open` and `send/listen` use the same direct UDP transport family

### Task 6: Delete dead transport code

- Delete the public WG tunnel default path if no longer used
- Delete retired public QUIC/bootstrap helpers
- Update token fields if any no longer make sense
- Remove stale docs that describe the WG-tunnel cutover as the final state

Exit criterion:

- no dead public transport path remains in the default command flow

## Verification Matrix

Local correctness:

- `mise run test`
- `mise run vet`
- `mise run smoke-local`

Live correctness:

- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh ktzlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test-reverse.sh ktzlxc 1024`
- same pair for `canlxc`
- same pair for `uklxc`
- at least one manual public-path verification against `orange-india.exe.xyz`

Live throughput:

- compare current `main` vs replacement path on `ktzlxc`
- compare against forwarded-port `iperf3` ceiling, but do not confuse the ceiling with achieved no-forwarded-port throughput

Release readiness:

- `mise run check`
- CI `Checks` green
- CI `Release` green
- npm dev publish green

## Non-Goals

- Requiring any user to set up port forwarding
- Requiring OS-level sysctl tuning as a product requirement
- Keeping multiple public transport families alive long-term

## Current Status

As of this plan revision:

- current default public transport does not meet the target
- forwarded-port throughput ceiling is proven
- no-forwarded-port >1 Gbps proof exists only in the raw probe history and must be revalidated cleanly on current head
- the next correct move is to promote the direct UDP packet engine, not to keep layering more work onto the WG tunnel
