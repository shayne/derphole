# Deterministic Bulk Probe Outcome Design

Date: 2026-07-22

Status: approved for planning

## Context

The bulk decision barrier is working in live tests, but the promotion harness
cannot deterministically exercise its QUIC fallback branch. The real sender and
receiver probes may both pass, in which case the correct negotiated result is
`bulk-packets-v1`. Repeating large transfers until a probe happens to fail would
make acceptance probabilistic and could conceal retries as evidence.

The existing Go tests can replace the unexported sender probe selector, but the
release binary and promotion driver have no equivalent controlled seam. Network
shaping is not suitable because it is privileged, difficult to reproduce, and
can also distort the QUIC payload path that the acceptance run is meant to
validate.

## Decision

Add one test-only environment variable:

```text
DERPHOLE_TEST_BULK_PROBE_OUTCOME=sender-reject
```

When unset, probe selection and all production behavior remain unchanged. The
initial supported value is deliberately narrow: `sender-reject`. Unknown or
empty explicit values are rejected with a clear error rather than ignored.

The override is applied only after the real sender probe trains finish. It does
not skip raw-direct candidate selection, socket setup, authentication, probe
traffic, or measurement. It converts the completed sender probe result into a
rejected result while preserving its run ID, train observations, loss,
duration, and other diagnostic fields; it clears the selected rate because a
rejected probe cannot select a bulk payload rate.

This causes the ordinary sender-authoritative state machine to publish:

```text
mode=quic reason=sender-probe-rejected run_id=<real probe run ID>
```

The receiver must acknowledge that exact tuple before either peer opens the
QUIC payload engine. Payload then runs over the real public raw-direct sockets.

## Boundaries

### Release binary

The session package reads and validates the test override at the sender probe
selection boundary. The normal selector still performs the real probe first.
Only the returned selection is transformed.

The binary emits an explicit verbose marker when the override is applied. This
lets preserved live evidence prove that the deterministic seam was active and
prevents a naturally rejected probe from being mistaken for a controlled run.

The override does not apply to the receiver probe, readiness messages, decision
validation, acknowledgements, QUIC setup, or payload transfer.

### Promotion driver

The promotion benchmark driver accepts the variable from its environment,
validates the same supported value, and propagates it only to the derphole
sender process. It records the requested outcome in preflight metadata and
requires the corresponding verbose marker when the override is set.

The driver continues to enforce the expected final mode separately. A forced
sender rejection with an unexpected bulk selection, missing marker, mismatched
decision tuple, or missing ACK/fallback ordering remains a failed sample.

### Scope exclusions

- No general-purpose command-line flag or user configuration.
- No receiver-reject mode in this change.
- No shortcut around real probe trains or raw-direct establishment.
- No changes to wire values, authentication, production selection thresholds,
  or behavior when the variable is unset.
- No privileged traffic shaping.

## Error handling

- The release binary fails the sender probe selection with an explicit error
  for an unsupported non-empty value.
- The promotion driver rejects unsupported values before starting a live run.
- A requested override without its application marker fails evidence
  validation.
- Cancellation and genuine probe errors keep their existing priority; the
  override transforms only a completed, otherwise selectable probe result.

## Testing

Unit tests will prove:

1. Unset environment preserves the selector result exactly.
2. `sender-reject` runs the underlying selector, preserves the real diagnostic
   fields and run ID, marks the result rejected, and clears the selected rate.
3. Unsupported values fail with an exact error.
4. Cancellation and underlying probe errors are not converted into controlled
   rejection.
5. The normal decision coordinator turns the controlled result into the exact
   QUIC decision and still requires the matching ACK before payload work.

Promotion-driver tests will prove validation, sender-only propagation,
preflight recording, required marker checking, and unchanged unset behavior.

Final acceptance will run the exhaustive repository gate and then three fresh
3 GiB transfers against `ubuntu@eric-nuc`, with the override enabled and both
peers pinned to the exact candidate build. Every run must show:

- real public eight-lane raw-direct establishment and real sender probe trains;
- the override application marker;
- identical sender/receiver QUIC decision mode, reason, and real run ID;
- decision, exact ACK, and fallback ordering before payload progress;
- `quic-blocks-v1`, exact byte count, SHA-256 parity, and zero flatline;
- no disconnect, terminal error, process, socket, or cleanup leak.

Naturally selected bulk runs remain valid transport evidence but do not count
toward this deterministic QUIC-fallback acceptance batch.

## Alternatives rejected

### Retry until three natural rejections

This requires no code, but it is unbounded and makes acceptance dependent on
ambient network conditions. It also invites accidental cherry-picking of
successful samples.

### External packet shaping

Traffic shaping can make probe loss deterministic, but it requires privileged
host changes and can interfere with the QUIC payload using the same network
path. It is harder to audit and reproduce than a narrow in-process test seam.

## Success criteria

The change is complete when the unset path is unchanged, the controlled sender
rejection is unit-tested and observable, driver propagation is validated, all
repository gates pass without baseline changes, independent review is clean,
and three exact-head live transfers deterministically exercise and pass the
original decision-barrier QUIC fallback path.
