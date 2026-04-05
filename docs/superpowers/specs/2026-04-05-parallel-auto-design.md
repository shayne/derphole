# Parallel Striping And Auto-Growth Design

Date: 2026-04-05

## Summary

Add a user-facing parallelism control for derpcat direct fast paths:

- default with no flag: fixed `4`
- fixed override: `-P N` / `--parallel=N`
- adaptive override: `--parallel=auto`

The active side (`send` / `open`) is authoritative for the session policy. The flag applies to both striped native QUIC and striped native TCP, so users do not need to care which direct fast path won.

`--parallel=auto` is a sender-driven, live growth controller:

- start at `4`
- move payload immediately
- add `2` stripes at a time during the transfer
- stop when growth no longer helps
- cap at `16`

This design is intended to make `auto` a candidate for the eventual default, but only after it passes a benchmark gate on both `ktzlxc` and `canlxc`.

## Why This Work Is Worth Doing

Recent live benchmarks showed that `4` is not the steady-state optimum on the public-Internet native-QUIC path.

From [CANLXC_BENCHMARKS.md](/Users/shayne/code/derpcat/CANLXC_BENCHMARKS.md):

- `1024 MiB`, fixed `4 -> 8`, Mac -> host: `408 -> 486 Mbps` avg
- `1024 MiB`, fixed `4 -> 8`, host -> Mac: `489 -> 588 Mbps` avg

From [KTZLXC_BENCHMARKS.md](/Users/shayne/code/derpcat/KTZLXC_BENCHMARKS.md):

- `1024 MiB`, fixed `4 -> 8`, Mac -> host: `741 -> 994 Mbps` avg
- `1024 MiB`, fixed `4 -> 8`, host -> Mac: `573 -> 807 Mbps` avg

Those results justify both a fixed user override and a real adaptive mode.

## Goals

- Give users a predictable fixed stripe control similar to `iperf3 -P`
- Make `--parallel=auto` chase large-transfer throughput without stalling startup
- Keep the user model independent of whether the direct fast path is native QUIC or native TCP
- Preserve existing relay-first, bytes-flow-immediately behavior
- Make `auto` measurable enough that it can eventually replace fixed `4` as the default if it earns that promotion

## Non-Goals

- Do not add shrink-and-grow oscillation logic in v1
- Do not wait for the final stripe count before starting payload transfer
- Do not redesign the entire direct-mode handshake
- Do not make the passive side (`listen` / `share`) expose its own user-facing policy for normal use

## CLI Surface

### Default behavior

No new flag means:

- fixed parallel policy
- target stripe count `4`

This matches current behavior and keeps the no-flag path stable during rollout.

### Fixed override

Add:

- `-P N`
- `--parallel=N`

Accepted range:

- integer `1..16`

Examples:

- `derpcat send -P 8 <token>`
- `derpcat open --parallel=6 <token>`

Meaning:

- use up to `N` direct stripes on the chosen direct fast path
- if the direct path is native QUIC, stripes mean multiple direct QUIC connections
- if the direct path is native TCP, stripes mean multiple direct TCP connections

### Adaptive override

Add:

- `--parallel=auto`

Meaning:

- start with `4`
- grow live in `+2` steps while the transfer is active
- stop when gains become too small
- never exceed `16`

## Session Policy And Authority

The active side is authoritative:

- `send` controls the session for `listen/send`
- `open` controls the session for `share/open`

The passive side mirrors the session policy and participates in setup and growth, but does not choose a competing user policy.

This keeps the user model simple:

- the operator on the initiating side decides how aggressive the session should be
- the passive side follows the resolved session policy

## Wire Protocol Changes

### Initial mode negotiation

Extend the existing direct-mode request so the active side can carry session striping policy before native setup begins.

Add fields conceptually equivalent to:

- `parallel_mode`: `fixed` or `auto`
- `parallel_initial`: initial stripe target
- `parallel_cap`: hard upper bound

Resolved values:

- no flag: `fixed`, `parallel_initial=4`, `parallel_cap=4`
- `-P 8`: `fixed`, `parallel_initial=8`, `parallel_cap=8`
- `--parallel=auto`: `auto`, `parallel_initial=4`, `parallel_cap=16`

The passive side acknowledges the policy and uses it as the starting budget when preparing the direct fast path.

### Live growth control

Reuse the session control plane over DERP rather than inventing a transport-specific side channel.

Add monotonic, idempotent growth messages conceptually equivalent to:

- `parallel_grow_request { target: 6 }`
- `parallel_grow_ready { target: 6 }`
- `parallel_grow_result { target: 6, ok: true|false }`

Rules:

- growth is monotonic only
- duplicate growth messages are safe
- if a growth step fails, both peers keep the previous working stripe set
- the transfer must continue even if growth fails

Why DERP control is the right place:

- works regardless of whether direct fast path is native QUIC or native TCP
- avoids putting stripe-growth control traffic on the data path
- fits the existing session coordination model

## Auto Control Loop

### Startup

`auto` starts at `4` stripes and payload begins immediately. The transfer must not block on future stripe growth.

### Sampling cadence

The sender runs the controller every `1s`.

That cadence is long enough to avoid reacting to tiny bursts and short enough to find a better steady state during `50 MiB+` transfers.

### Preconditions for growth

The sender only considers growth if all of these are true:

- transfer is still active
- direct fast path is already active
- sender still has data to send
- sender appears network-limited rather than idle on stdin
- current stripes are healthy enough to trust the measurement
- current target is below `16`

This prevents pointless growth on tiny or already-draining transfers.

### Growth step

When preconditions hold:

- request `+2` stripes
- examples: `4 -> 6 -> 8 -> 10 -> 12 -> 14 -> 16`

Growing by `2` is preferred over doubling because it gives cleaner diminishing-return detection and avoids large overshoot.

### Detecting improvement

For each growth step, compare throughput before and after the increase using a short EWMA or similar moving average.

Require both:

- relative gain of at least `10%`
- absolute gain of at least `50 Mbps`

If either threshold fails, stop growing and hold the current stripe count for the rest of the session.

These numbers are strong enough to reject noise and weak enough to capture the benchmark wins already observed on `canlxc` and `ktzlxc`.

### Tail behavior

If the transfer appears to be in its tail, stop attempting growth.

The sender may not know tail state perfectly, so v1 should use conservative heuristics such as:

- explicit EOF observed and only a small amount of buffered data remains
- sender is no longer backlog-limited
- recent windows show falling send pressure rather than rising throughput pressure

The key property is simple: do not spend setup work on stripes that cannot repay their cost before the session ends.

### Failure behavior

If any growth step fails:

- keep the current working stripe set
- mark the session capped
- stop future growth attempts
- keep the transfer alive

This makes `auto` opportunistic rather than risky.

## Transport-Specific Behavior

## Native QUIC

Native QUIC is the primary target for live `auto` growth in v1.

Rationale:

- it already has a structured setup and striping protocol
- the current benchmark wins are strongest on the public-Internet native-QUIC path
- it is the most obvious place to recover more WAN throughput automatically

Implementation shape:

- initial QUIC striped setup honors the resolved initial stripe target
- later growth opens additional direct QUIC connections and merges them into the striping pool once both peers report ready

## Native TCP

`-P N` must apply to native TCP as well. A user who asks for `-P 8` should get up to `8` direct stripes on whichever direct fast path wins.

For `auto`, native TCP should follow the same session policy, but the first implementation may be simpler than QUIC:

- initial native TCP setup honors the resolved initial stripe target
- live growth support is desirable
- if live growth on TCP materially complicates v1, it is acceptable to land live growth for QUIC first and keep TCP on setup-time growth only, as long as the session policy remains unified and the behavior is documented

The eventual user contract remains the same:

- one flag
- one session policy
- transport chooses the implementation details

## Observability

Add enough telemetry to understand growth behavior in live tests and verbose runs.

Recommended event names:

- `parallel-mode=fixed|auto`
- `parallel-target-initial=N`
- `parallel-grow-request=N`
- `parallel-grow-ready=N`
- `parallel-grow-applied=N`
- `parallel-grow-stop=reason`
- `parallel-grow-failed=reason`

Recommended stop reasons:

- `diminishing-return`
- `tail`
- `input-idle`
- `cap-reached`
- `growth-failed`

This telemetry is needed for benchmark validation and future tuning.

## Testing Strategy

### Package tests

Add focused tests for:

- CLI parsing and validation for `-P N` and `--parallel=auto`
- initial mode-request propagation of parallel policy
- monotonic growth requests
- duplicate growth idempotence
- growth failure fallback to last working stripe set
- no payload stall during growth
- diminishing-return stop condition
- tail stop condition

### Benchmarks and live tests

Live testing is required during implementation, not only at the end.

Use both hosts because they expose different network conditions:

- `ktzlxc`: healthy high-bandwidth WAN path
- `canlxc`: slower and more variable WAN path

Required matrix before claiming the feature works:

- sizes: `10 KB`, `1 MB`, `10 MB`, `50 MB`, `128 MB`, `1 GB`
- both directions
- both hosts
- `3x` each
- compare:
  - default fixed `4`
  - fixed `8`
  - `auto`

### Promotion gate for making `auto` default

Do not make `auto` the default until it passes this bar:

- `10 KB` and `1 MB`: no more than `10%` worse than fixed `4`
- `10 MB`: no more than `5%` worse than fixed `4`
- `50 MB` and larger: should be equal or better on average
- `128 MB` and `1 GB`: should show a meaningful improvement on at least one path class without causing a serious regression on the other
- no stalls
- no progress freezes
- no relay/direct status churn
- no cleanup leaks

If the bar passes, flipping the default to `auto` becomes justified.

## Rollout Plan

Phase 1:

- add CLI and session-policy plumbing
- implement fixed `-P N`
- keep default fixed at `4`

Phase 2:

- implement QUIC live growth for `auto`
- benchmark on `ktzlxc` and `canlxc`

Phase 3:

- extend `auto` behavior to native TCP if needed
- rerun full benchmark gate

Phase 4:

- if benchmark gate passes, make `auto` the default

## Design Choice Summary

- default remains fixed `4` initially
- `-P N` is a fixed explicit override
- `--parallel=auto` is a live growth controller, not a one-shot heuristic
- active side is authoritative
- one user-facing knob covers both native QUIC and native TCP
- growth uses DERP control messages, not a transport-specific side channel
- growth is monotonic in v1
- default promotion to `auto` is benchmark-gated, not intuition-gated
