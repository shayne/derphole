# Dynamic direct UDP rate control design

Date: 2026-04-09

## Goal

Make derphole's default DERP-coordinated direct UDP stream dynamically scale to each WAN path. It should work without user configuration from sub-1 MB/s links through multi-gigabit links, keep relay-first time-to-first-byte behavior, and avoid transfer failures caused by excessive retransmit or replay pressure.

Target behavior:

- DERP relay starts streaming immediately while direct UDP is negotiated.
- Direct UDP treats 10 Gbps as a guarded ceiling, not as the initial send rate.
- Direct UDP reaches the practical WAN ceiling within a few seconds on stable paths.
- Slower paths such as `uklxc` select and maintain their own sustainable rate instead of being driven at a `ktzlxc`-class rate.
- Fast paths such as this Mac to `ktzlxc` still reach roughly the measured WAN ceiling, currently near 2 Gbps under good conditions.
- Retransmits are allowed, but they must remain bounded and recoverable. They must not cause timeouts, corrupt output, impossible throughput reports, unbounded memory growth, or sender OOM kills.
- The same algorithm must cover regular files, `pv`, stdin of unknown length, and theoretically very large streams.

## Non-goals

- Do not add host-specific settings for `uklxc`, `ktzlxc`, or this Mac.
- Do not require the user to provide a rate, payload size, lane count, replay window, or NAT setting.
- Do not route derphole tests over Tailscale candidates. Use `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` for regression tests.
- Do not use the forwarded Mac port 8321 in derphole itself. It remains a test-only iperf3 baseline.
- Do not promise throughput above the current WAN ceiling measured at test time.

## Evidence and current failure mode

The `uklxc` reverse run, from `uklxc` to this Mac, failed before completing 1 GiB. The sender reached `connected-direct`, then the remote shell reported the derphole sender was killed with exit 137 after about 55 seconds. The Mac listener received only about 3.4 MiB. On `uklxc`, swap was full and cgroup `memory.events` showed `oom_kill=2`.

The `uklxc` forward run, from this Mac to `uklxc`, completed 10 out of 10, but only around 400 Mbps p50 and with very high replay and retransmit pressure. Replay nearly pegged the 256 MiB window. This proves the path can transfer, but the current default direct UDP behavior is too aggressive for that path.

The `ktzlxc` runs completed 10 out of 10 in both directions. `ktzlxc` reverse reached about 1.57 Gbps p50 and about 1.90 Gbps max. This proves the high-speed path still matters and must not be flattened to a conservative global default.

The key code clue is that `pkg/session/external_direct_udp.go` already contains direct UDP rate-probe helpers and tests, but the stream path currently sends `DirectUDPStart{Stream: true}` without `ProbeRates`, then starts direct UDP at `externalDirectUDPRateMbps`, currently 2250 Mbps. The available capacity detector is not active on the default stream path.

## Approach considered

The simplest option is a conservative static default followed by slow adaptive ramp-up. This would protect `uklxc`, but it would make `ktzlxc` and future 10 Gbps hosts spend too much wall time below capacity.

A second option is a host/path cache. This can improve repeated transfers, but it is unsafe as the primary fix because WAN paths change and stale cached rates can recreate the failure.

The recommended option is startup probing plus live adaptive control. Each transfer keeps DERP relay streaming while direct UDP probes the real path, picks an initial rate from measured delivery, then adjusts during the stream based on receiver stats, ack progress, replay pressure, and repair pressure. This is dynamic per connection and requires no user configuration.

## Protocol and control flow

The stream handoff flow stays relay-first:

1. The sender starts reading source bytes into the relay-prefix handoff spool.
2. The sender sends prefix data over DERP immediately.
3. Direct UDP NAT traversal runs concurrently.
4. When direct UDP becomes available, the sender keeps DERP relay active while it performs a short synthetic direct UDP rate probe.
5. The receiver records probe delivery for each requested rate tier and reports those samples over DERP.
6. The sender chooses a safe initial direct rate and only then sends the DERP handoff boundary.
7. Source payload continues on direct UDP from the acknowledged handoff point.

The rate-probe envelope should reuse existing `directUDPStart.ProbeRates`, `directUDPRateProbeSample`, `envelopeDirectUDPRateProbe`, `externalDirectUDPRateProbeRates`, and `externalDirectUDPSelectRateFromProbeSamples` concepts. Probe packets must be synthetic and must not consume source bytes, so probing never corrupts or delays the payload stream beyond the short direct-path measurement interval.

## Rate selection

The default ceiling should be raised from 2250 Mbps to 10 Gbps. That ceiling only bounds exploration and socket pacing; it must not mean "start at 10 Gbps".

Initial probe tiers should cover slow and fast WAN paths. A reasonable first table is:

- 8 Mbps
- 25 Mbps
- 75 Mbps
- 150 Mbps
- 350 Mbps
- 700 Mbps
- 1200 Mbps
- 2250 Mbps
- 5000 Mbps
- 10000 Mbps

The implementation can stop early when a tier clearly collapses. Clean delivery at a high tier should select an initial rate near the observed goodput with modest headroom. Lossy or collapsed delivery should back off to the last stable tier, not to the maximum attempted tier.

For small payloads, the relay prefix can complete before direct UDP is worth probing. The existing short-tail behavior should win in that case: finish over DERP rather than delay a tiny transfer.

For unknown-length streams, the direct path should still probe. Unknown length is exactly where bounded memory and safe startup matter most.

## Live adaptation

After direct UDP starts, the live controller should converge to WAN capacity within a few seconds on stable paths. It should ramp quickly when delivery is clean, and cut quickly when pressure appears.

Inputs:

- receiver interval bytes
- receiver packet count
- highest sequence seen
- ack floor movement
- missing packet delta
- repair request rate
- sender replay retained bytes
- replay-window-full waits
- age of oldest unacknowledged packet
- receiver queue/reorder pressure where available

Control behavior:

- Increase rate while interval delivery is clean and replay retention drains.
- Decrease rate immediately when missing packets grow faster than the repair budget, ack floor stalls, or replay retained bytes approach the configured budget.
- Hold increases briefly after a decrease to avoid oscillation.
- If replay pressure remains high after a decrease, decrease again instead of waiting for the window to fill.
- Keep an absolute minimum rate for liveness, but allow operation below 1 MB/s.
- Keep the 10 Gbps ceiling for future high-speed tests, but only use it when measurements show the path can carry it.

This can be implemented as AIMD with additional backpressure signals. It does not need a complex congestion-control clone on the first pass, but it must use replay pressure as a first-class signal, not just receiver byte deltas.

## Memory and backpressure

Replay memory is a transport budget, not a function of total stream length. The sender must never read unbounded stdin data just because the stream has no declared size.

Invariants:

- The replay window has a hard byte cap.
- When replay is full, sender reads from stdin stop until ack progress frees space.
- Repair payload retention is bounded by the same budget.
- Sender stats report max replay bytes and replay-window-full wait count.
- Slow paths fail fast with a clear diagnostic only if the path cannot make forward progress at the minimum rate. They must not OOM the process.

The initial effective replay budget should scale from rate and estimated path delay where possible, but it must also have safe minimum and maximum bounds. The existing 256 MiB maximum can remain a hard default budget while the dynamic controller prevents sitting at that ceiling for long periods.

## Observability

Verbose output should make rate behavior explainable:

- `udp-rate-ceiling-mbps=10000`
- `udp-rate-probe-rates=...`
- `udp-rate-probe-samples=...`
- `udp-rate-selected-mbps=...`
- `udp-rate-mbps=...`
- rate update events when the controller changes rate
- `udp-send-max-replay-bytes=...`
- replay-window-full wait count and duration
- retransmit counts
- first-byte timing and data goodput

These fields should let us compare `uklxc` and `ktzlxc` without guessing whether the sender overran the path, the receiver fell behind, or direct UDP never became stable.

## Testing and validation

Unit and integration tests should cover:

- stream handoff sends probe rates for unknown-length streams
- small relay-completed payloads skip direct probing
- synthetic rate samples select a safe lower initial rate when high tiers collapse
- clean high-rate samples select a near-ceiling initial rate
- replay retention stays below budget while ack progress is delayed
- sender read-ahead stops when replay is full
- live rate control decreases on replay pressure even before the process approaches memory pressure
- live rate control increases on clean delivery

Live validation should use:

```sh
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test-reverse.sh uklxc 1024
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh uklxc 1024
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test-reverse.sh ktzlxc 1024
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh ktzlxc 1024
```

Run 10 iterations in each direction for `uklxc` and `ktzlxc`. Before interpreting throughput, measure the WAN ceiling with iperf3 over the dedicated forwarded test port where available, using `nix run` for iperf3. derphole passes if it completes 10 out of 10 runs without OOM kills, timeouts, leaked derphole UDP sockets, or replay pressure pegged at the hard budget, and if its goodput approaches the measured WAN ceiling within a few seconds of direct UDP handoff.

Release validation remains:

```sh
mise run test
mise run check
```

If packaging behavior changes, also run:

```sh
mise run release:npm-dry-run
```

