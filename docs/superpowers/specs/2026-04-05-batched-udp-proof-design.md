# Batched UDP Proof Design

## Summary

Extend the standalone `derpcat-probe` experiment with the core UDP transport techniques Tailscale uses for throughput: batched send/receive, Linux UDP offload support, larger effective socket buffers, and queue-overflow visibility. The goal is not to copy Tailscale wholesale. The goal is to prove whether those specific techniques let a simpler direct UDP probe materially outperform current no-Tailscale derpcat on the same host pairs.

## Goal

Produce a probe variant that clearly beats the current tuned derpcat baseline on large transfers to `ktzlxc`, then validate the result against `canlxc`, `uklxc`, and `orange-india.exe.xyz` to separate transport wins from path-quality limits.

## Non-Goals

- Replacing derpcat's production transport in this phase
- Reimplementing WireGuard
- Porting Tailscale's full magicsock stack
- Making the probe feature-complete with derpcat

## What Tailscale Is Doing That Matters

The throughput-relevant pieces in `~/code/tailscale` are:

- batched UDP send/receive instead of one syscall per packet
- Linux `sendmmsg` / `recvmmsg` via `x/net` batch APIs
- Linux UDP GSO/GRO via `UDP_SEGMENT` and `UDP_GRO`
- aggressive socket buffer sizing, including forced buffer attempts on Linux
- RX queue overflow telemetry
- heavy buffer reuse to reduce allocation and copy overhead

The current probe does not do those things. It still uses per-packet `WriteTo` / `ReadFrom`, which makes it a weak comparison against Tailscale's direct path.

## Approaches Considered

### Approach 1: Add Tailscale-style batching/offload to the existing probe

Pros:

- fastest route to evidence
- isolates the impact of UDP plumbing improvements
- keeps the existing proof harness and benchmark scripts

Cons:

- still not a production transport
- some Linux-only gains will not appear on macOS

### Approach 2: Jump straight to a production derpcat refactor

Pros:

- no intermediate experiment layer

Cons:

- wrong order
- hard to separate control-plane and data-plane effects
- higher risk of large churn without proof

## Recommendation

Use approach 1. Port the throughput-relevant UDP mechanics first, not the entire Tailscale architecture.

## Design

### Transport Shape

Keep the current probe protocol and orchestration model. Replace the hot-path UDP I/O with a new batching abstraction:

- portable fallback: current one-packet `net.UDPConn` path
- Linux fast path: `ReadBatch` / `WriteBatch`
- optional Linux GSO/GRO when the kernel and socket allow it
- shared packet/message pools to reduce allocation churn

This keeps the proof focused on the actual throughput question.

### Socket Policy

The probe should:

- keep requesting large read/write buffers
- on Linux, attempt forced buffer sizing before falling back
- log the effective result in probe reports
- enable RX queue overflow reporting where supported

This is necessary because host/container socket caps were already a suspect in earlier benchmarks.

### Proof Gates

The experiment only justifies a future refactor if all of the following are true:

1. On `ktzlxc`, the new probe materially beats current tuned derpcat for `1 GiB`.
2. The win remains after adding basic encryption back into the probe, or the raw result is large enough to justify that follow-up.
3. Results on `canlxc`, `uklxc`, and `orange-india.exe.xyz` show where path quality, not transport overhead, becomes the limiter.

If the probe still cannot beat tuned derpcat on `ktzlxc`, stop the refactor path and redirect effort into improving derpcat's current transport.
