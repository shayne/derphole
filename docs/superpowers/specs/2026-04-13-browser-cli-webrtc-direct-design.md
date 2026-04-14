# Browser CLI WebRTC Direct Design

## Purpose

Browser-originated `derphole` transfers currently work through the DERP web relay path, but browser-to-CLI transfers can be limited by relay round trips and small frames. The target behavior is relay-first and direct-target: begin transferring immediately through DERP, negotiate WebRTC direct transport in parallel, and switch to direct transfer only after both sides have proved the direct path is ready and byte offsets are synchronized.

The relay path is the safety net, not the goal. It must stay correct and reasonably fast when WebRTC is blocked, but successful browser-to-CLI and CLI-to-browser transfers should prefer a WebRTC DataChannel direct path.

## Current State

`derphole-web` already has browser-side WebRTC support through JavaScript `RTCPeerConnection`, and the Go WASM bridge exposes that browser transport through the existing `webrelay.DirectTransport` interface. Browser-to-browser can therefore attempt a WebRTC direct upgrade.

Native CLI receives browser web-file tokens through `pkg/derphole/transfer.go`, then uses `receiveViaWebRelay`. That path does not currently provide a native direct transport, so browser-to-CLI remains relay-only. The web relay protocol also uses small browser-safe frames and per-frame acknowledgement behavior, which makes relay fallback throughput roughly proportional to frame size divided by RTT.

The existing `webrelay.DirectTransport` seam is the correct integration point. The design should preserve this seam and add a native implementation rather than creating a separate browser-to-CLI transfer engine.

## External References

Tailscale's DERP model is the right architectural reference. DERP carries discovery traffic and fallback packets, while direct paths are attempted separately. Tailscale's disco and magicsock code also reinforce that candidate paths should be exchanged over the relay side channel and trusted only after an explicit handshake.

Magic-wormhole is useful for its connection-state model, not for reusable WebRTC code. Its dilation layer exchanges direct and relay hints, races candidate connections, selects a winner, and shuts down losers. The part not to copy is delaying relay traffic while direct candidates are attempted; derphole should stream over relay immediately and upgrade asynchronously.

Neither project provides a ready-made CLI WebRTC implementation for this repository. Native CLI WebRTC should use a Go WebRTC stack, with Pion as the likely implementation library.

## Goals

- Start payload transfer immediately over DERP relay after metadata exchange.
- Negotiate WebRTC direct transport in parallel for browser-to-CLI, CLI-to-browser, and browser-to-browser web-token transfers.
- Use the same relay/direct state machine for browser and native CLI paths.
- Keep relay fallback correct, bounded, and materially faster than current stop-and-wait behavior.
- Avoid transfer stalls during direct negotiation and direct handoff.
- Preserve support for unknown-length streams without unbounded memory growth.
- Surface path, timing, and throughput trace points that make early-transfer stalls diagnosable.
- Keep default user behavior zero configuration.

## Non-Goals

- Matching native derpcat UDP throughput from browser WebRTC. Browser DataChannel and SCTP overhead may cap below native UDP on multi-gigabit links.
- Replacing the native CLI-to-CLI direct UDP engine.
- Implementing custom browser UDP, raw sockets, or non-standard browser APIs.
- Adding user-required configuration for STUN, ICE, relay windows, or path selection.

## Architecture

The web relay engine owns transfer ordering, metadata, EOF, cancellation, and path switching. DERP relay is always available first. A direct transport is optional and opportunistic.

The sender sends metadata over DERP, begins streaming data over relay, and starts direct negotiation concurrently if a direct transport is configured. The receiver writes relay data in order and sends cumulative acknowledgements. When the direct transport reaches a ready state, the sender sends a direct path probe and switch request. The receiver replies with the highest committed byte offset. The sender starts direct data from that offset, and duplicate relay bytes below that offset are ignored.

The direct transport interface remains small: start negotiation, exchange signaling frames, report readiness/failure, send frames, receive frames, and close. Browser JavaScript implements the interface through the existing WASM bridge. Native CLI implements the same interface with Pion.

## Relay Fallback

Relay fallback should use a bounded sliding window instead of one frame per acknowledgement. The sender may keep multiple data frames in flight up to configured byte and frame limits. The receiver sends cumulative byte acknowledgements. The sender retires acknowledged frames and retransmits only when required by deadline or path-switch recovery.

The window must be bounded by memory, not by total transfer size. Unknown-length streams therefore remain safe: the sender buffers only the in-flight relay window plus the existing direct handoff replay budget.

The relay path remains active during direct negotiation. It may be slowed or paused only after direct transfer is confirmed and the receiver has acknowledged the switch offset.

## Native CLI WebRTC

Add a native WebRTC direct transport using Pion. The CLI transport should implement the existing `webrelay.DirectTransport` interface and use DERP web protocol frames for offer, answer, ICE candidate, ICE complete, direct ready, and direct failed messages.

The browser and CLI should use compatible roles:

- The sender creates the DataChannel when it is the WebRTC offerer.
- The receiver accepts `OnDataChannel` and begins reading only after protocol-level direct-ready exchange.
- ICE candidates are sent over DERP as they are gathered.
- STUN server defaults should match the browser demo defaults unless repository configuration already defines better values.
- The DataChannel should be ordered and reliable for the first implementation.

If Pion fails to gather candidates, connect ICE, open the DataChannel, or sustain the direct path, the transfer remains on relay unless the relay has already been explicitly abandoned. A direct failure before switch is informational. A direct failure after switch falls back only if the relay path is still healthy and has enough replay state to resume; otherwise it is a transfer error.

## Path Switching

Path switching must be offset-based and idempotent. The receiver tracks committed bytes. The sender tracks bytes sent by relay, bytes acknowledged by relay, and bytes sent by direct. Switching to direct uses the receiver's committed byte offset, not the sender's optimistic send offset.

The sender may transmit a small direct probe before switching payload data. The receiver acknowledges the probe and committed byte offset. Only then does the sender send direct payload frames. This avoids the observed stall class where relay pauses before direct is actually usable.

Duplicate data below the committed offset is discarded. Data above the next expected offset is either buffered within a strict bound or rejected with a repair request. The first implementation should prefer simple ordered reliable DataChannel semantics and avoid large out-of-order buffers.

## Cancellation And EOF

Both clean and hard exits must propagate. Ctrl-C, browser close, DataChannel close, DERP close, local read error, and local write error should map to one of these outcomes:

- Clean complete: sender sends done, receiver confirms committed final byte count, both sides exit success.
- Local cancel: side sends cancel when possible, closes direct and relay, exits non-zero if transfer was incomplete.
- Remote cancel: peer receives cancel or detects keepalive/read deadline failure, closes local outputs, exits non-zero if transfer was incomplete.
- Direct failure before switch: log or trace the failure, continue relay.
- Relay failure before direct ready: fail transfer.
- Relay failure after direct ready: continue direct if direct is healthy.

EOF for known-size files requires both final byte count and done acknowledgement. EOF for unknown-size streams requires an explicit done frame and receiver confirmation. Neither side should infer transfer success from a closed pipe alone.

## Tracing And Diagnostics

Verbose output should expose enough timing to diagnose early stalls without overwhelming normal users. Trace events should include:

- metadata sent and received
- first relay data byte sent and received
- relay window size and cumulative ACK progress
- WebRTC offer, answer, ICE candidate, ICE complete, DataChannel open
- direct probe sent and acknowledged
- path switch offset
- first direct data byte sent and received
- direct failure reason
- relay fallback reason
- final committed byte count and duration

Non-verbose CLI output remains quiet except for the existing derphole progress UI and required token instructions.

## Browser Demo

The browser demo remains a static GitHub Pages app. It should continue to work from a zip artifact and from Pages. The UI should describe the transport honestly: relay starts immediately, WebRTC direct is attempted automatically, and relay remains fallback.

Browser-to-CLI compatibility is a primary use case. A token generated by the browser must be accepted by the CLI, and a token generated by the CLI web send path must be accepted by the browser when that mode exists.

## Testing

Unit tests should cover:

- sliding-window relay ACK accounting
- bounded in-flight memory for unknown-size streams
- direct signaling frame round trips
- native direct transport lifecycle using a fake transport
- path switch offset correctness
- relay fallback on direct failure before switch
- cancel propagation in both directions
- done acknowledgement for known and unknown-size payloads

Integration tests should cover:

- browser-to-browser WebRTC direct path with local headless Chrome
- browser-to-CLI transfer with local headless Chrome and native CLI
- CLI-to-browser transfer if supported by the same web-token protocol
- direct failure fallback by injecting a failing direct transport
- no-hang behavior when either side is interrupted

Remote benchmarks should cover:

- this Mac to `ktzlxc`, because it is the high-throughput reference path
- this Mac to `eric-nuc`, because it represents asymmetric residential WAN behavior
- relay-only forced mode, to verify fallback is correct and improved
- direct-enabled mode, to verify direct negotiation removes the RTT-limited relay cap

Benchmark reporting should include wall-clock time, time to first byte, path-switch time, average throughput, peak moving-window throughput, and final path used.

## Rollout

This can break old web-token compatibility if needed. The repository should fix forward rather than preserve old browser proof-of-concept tokens.

Implementation should land in small commits:

1. Relay sliding-window tests and implementation.
2. Shared path-state and handoff tests.
3. Native Pion direct transport behind `webrelay.DirectTransport`.
4. CLI wiring for browser web-file tokens.
5. Browser compatibility and docs.
6. Local and remote benchmark harness updates.

## Success Criteria

- Browser-to-CLI no longer remains relay-only when WebRTC direct can connect.
- Browser-to-CLI relay fallback is significantly faster than stop-and-wait and does not freeze during direct negotiation.
- Transfers begin sending payload bytes immediately over relay.
- Direct upgrade does not create a visible stall in the first five seconds.
- Unknown-size streams remain bounded in memory.
- Interrupting either side causes the other side to exit promptly with the correct success or failure status.
- Existing CLI-to-CLI derpcat performance is not regressed.
- CI passes, release packaging includes the browser demo assets, and GitHub Pages continues to deploy.
