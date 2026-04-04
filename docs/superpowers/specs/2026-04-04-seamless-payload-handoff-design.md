# Seamless Payload Handoff For `send/listen`

## Problem

`send/listen` should begin transferring user payload bytes as soon as the claim is accepted, but still upgrade to native direct paths when they become available. Today the fallback QUIC path can naturally start relayed and later promote to direct because it stays on one logical transport manager, but the native TCP fast path is selected before payload starts. That creates a startup tradeoff between "wait for direct" and "start immediately."

The goal is to remove that tradeoff without regressing throughput, correctness, or the current token UX.

## Design

Introduce a transport-agnostic payload protocol above DERP-QUIC, native QUIC, and native TCP.

The sender splits the input byte stream into framed chunks:

```text
chunk {
  transfer_id
  offset
  length
  payload
}
```

The relay QUIC stream starts immediately after claim acceptance and carries these chunks first. In parallel, both sides continue negotiating native direct options. When a faster direct carrier becomes ready, the sender asks the receiver for its committed watermark, starts transmitting from that offset on the new carrier, and keeps relay open briefly so in-flight chunks can still arrive. Once direct has caught up and relay stops contributing new data for a short grace period, the relay carrier is retired.

The receiver writes only the next contiguous offset to stdout, buffers a bounded out-of-order window, and deduplicates chunks that were already received on another carrier. This preserves byte order and allows safe overlap during handoff.

## Sender Spooling

For seekable input files, retransmission can reopen and seek the source.

For non-seekable stdin, the sender needs a bounded replay spool so chunks sent on relay remain available until the receiver acknowledges them. The implementation should prefer a temp-file-backed spool with a capped in-memory window and apply backpressure if the unacked window grows beyond the configured bound. That avoids unbounded RAM while still supporting seamless migration for piped stdin.

## Control Flow

Keep DERP for rendezvous and control:

- claim
- accept/reject
- candidate updates
- direct-path mode negotiation
- payload carrier switch requests
- receiver watermark acknowledgements

Payload carriers may be:

- relay QUIC stream
- native QUIC
- native TCP on route-local addresses

Carrier choice becomes a runtime scheduling decision; stream correctness is enforced by offsets and ACKed watermarks, not by assuming one connection owns the whole byte stream forever.

## Security

The token remains the bearer capability.

DERP still only sees encrypted transport payloads and control messages; it does not get the session secret needed to authenticate as a peer. Public/native QUIC paths stay pinned to the expected peer identity from the token. Route-local native TCP keeps the existing per-session authentication model for Tailscale/private candidates, and public Internet direct paths remain on authenticated QUIC.

Chunk metadata must not weaken this model: offsets and transfer IDs are transport-internal framing, and carrier-switch control messages must remain authenticated under the existing session/control path.

## `share/open`

Do not attempt transparent mid-connection migration for an already-open proxied TCP stream in this phase. For `share/open`, keep the current per-connection transport selection model and apply new direct carriers to newly accepted proxied connections only. Trying to migrate a live arbitrary TCP stream is a larger correctness problem and should be designed separately.

## Throughput Gates

This feature is only acceptable if it preserves or improves current throughput on the fast paths we already validated.

Before shipping:

- Run 3x Mac -> `ktzlxc` and 3x `ktzlxc` -> Mac with 1 GiB transfers and compare against current `main`.
- Run 3x Mac -> `hetz` and 3x `hetz` -> Mac with 1 GiB transfers and compare against current `main`.
- Run `iperf3` over the existing Tailscale route as an upper-bar reference where available, but do not require system tuning changes on either host.
- Fail the change if native TCP fast-path throughput regresses materially or if fallback QUIC relay->direct promotion becomes slower than the current baseline.

Benchmark output must record:

- total transfer duration
- effective throughput
- whether payload began on relay or direct
- whether and when carrier handoff occurred
- sender and listener final path state

## Test Strategy

Add focused package tests first:

- chunk ordering, deduplication, and bounded out-of-order buffering
- watermark ACK handling
- sender replay from temp-file spool for non-seekable stdin
- carrier handoff with overlap and no duplicate stdout bytes
- fallback from a failed direct carrier back to relay without restarting the transfer

Then add live verification:

- `mise run check`
- Mac <-> `ktzlxc` with Tailscale candidates disabled
- Mac <-> `ktzlxc` with default candidate behavior
- Mac <-> `hetz`
- existing `share/open` smoke tests to confirm no regression outside `send/listen`

## Open Implementation Choices

Two details can be tuned during implementation without changing the design:

- chunk size and max in-flight replay window
- relay retirement grace period after direct catches up

These should be chosen from benchmark evidence, not guesswork, and captured in code comments/tests once the winning values are known.
