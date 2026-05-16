# Peer Cancel Abort Hardening Design

## Context

`derphole receive` can be interrupted with Ctrl-C while the sender keeps running for several seconds before reporting `peer disconnected`. The existing protocol already has authenticated `abort`, `ack`, `progress`, and heartbeat envelopes. The bug is in peer-control behavior: some receive/listen paths install peer-control watchers but only notify the peer for non-cancel errors. Local user cancellation is filtered out, so the sender often learns about the receiver exit through heartbeat timeout or a later control-path error instead of an immediate abort.

Recent telemetry work also made sender completion receiver-ACK anchored, so the sender can legitimately wait after it has written local bytes. That makes immediate cancellation signaling more important: waiting for final ACK should be interrupted by explicit peer abort, not by a disconnect timeout.

## Goals

- Ctrl-C or local context cancellation on either side sends a best-effort authenticated `abort` envelope before teardown.
- The peer exits quickly with explicit peer-abort semantics when an abort envelope arrives.
- `peer disconnected` remains reserved for heartbeat timeout, transport drop, or hard peer loss where no abort was received.
- Final ACK waits remain interruptible by peer abort.
- The behavior is covered by unit tests and at least one live end-to-end cancel validation.
- No new wire format or compatibility layer is introduced.

## Non-Goals

- Redesigning the full transfer protocol.
- Adding an ACKed close handshake.
- Changing heartbeat interval or disconnect timeout defaults.
- Reworking direct UDP reliability, rate control, or fallback behavior.

## Behavior Contract

If either side exits because its local context is canceled, it sends a best-effort `abort` envelope to the peer using the existing authenticated peer-control channel. The abort should include the current byte count where that count is available.

If a peer receives an abort envelope, the active transfer context is canceled with `ErrPeerAborted`. User-facing output should distinguish this from `ErrPeerDisconnected`. Heartbeat timeout remains the fallback for missed abort envelopes, crashes, or network loss.

If a sender has finished local reads and is waiting for a receiver ACK, an incoming abort must interrupt that wait. If the abort is missed, the existing ACK wait and heartbeat timeout behavior remain safety nets.

## Implementation Shape

Use the existing `notifyPeerAbortOnLocalCancel` helper for receive/listen paths that currently only defer `notifyPeerAbortOnError`. This should include the offer receive path and direct UDP listen/receive path. Check WG listen paths for the same asymmetry and apply the same rule if present.

Preserve teardown ordering so the local-cancel notification runs while the DERP client and peer subscriptions are still usable. The implementation should avoid closing the signaling client before the best-effort abort send has a chance to run.

Keep the existing `sendPeerAbortBestEffort` timeout and envelope shape. If later data shows 750 ms is too short under real DERP latency, that can be tuned separately, but this change should not bundle timeout policy changes with semantic fixes.

## Testing Strategy

Unit tests should prove:

- Receive-side local cancel sends an abort envelope.
- Direct UDP listen/receive local cancel sends an abort envelope.
- Existing sender-side local cancel behavior remains intact.
- Final ACK wait returns `ErrPeerAborted` when an abort envelope arrives.
- Local cancellation is not converted into `ErrPeerDisconnected`.

End-to-end validation should prove:

- Start a real transfer, cancel the receiver, and verify the sender exits quickly with peer-abort behavior rather than waiting for heartbeat timeout.
- Run at least one relay-ish path and one direct-capable path where practical.
- Verify no leftover `derphole` processes or UDP sockets remain after the cancel scenario.

Trace or verbose logs should make explicit aborts visible enough to distinguish them from heartbeat disconnects during debugging.

## Risks

Best-effort abort delivery can still fail if the process is killed hard, the DERP client is already closed, or the network drops at the same time. That is acceptable because heartbeat timeout remains the fallback.

Adding local-cancel abort notification to receive paths must not cause both sides to recursively report aborts after receiving a peer abort. Existing `peerAbortErrorShouldNotify` and local-cancel filtering should continue to prevent echo storms.

The main implementation risk is missing one receive/listen path. The tests should cover the common offer receive path and direct UDP receive path, and code review should explicitly check WG and attach/share variants for the same pattern.

## Acceptance Criteria

- Ctrl-C on the receiver causes the sender to stop promptly with peer-abort semantics in a live run.
- The sender no longer sits idle until heartbeat timeout for normal receiver Ctrl-C.
- Unit tests cover local-cancel abort notification on both send and receive sides.
- Full `mise run check` passes.
- Live cancel validation includes cleanup checks for processes and UDP sockets.
