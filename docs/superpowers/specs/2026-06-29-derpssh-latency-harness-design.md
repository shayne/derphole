# derpssh latency harness design

## Summary

`derpssh` needs a repeatable latency harness that lets an agent compare interactive terminal latency against standard SSH and then iterate on the derptun transport until the gap is small and explainable.

The initial benchmark host is:

```sh
ssh ubuntu@derphole-testing
```

The local operator is in New York City and the remote host is in the UK. Standard SSH to the same host is the baseline.

## Goals

- Measure end-to-end interactive latency: local input to visible remote echo.
- Measure an SSH baseline and a derpssh path in the same run.
- Collect derptun diagnostics that explain latency regressions.
- Produce machine-readable artifacts so future agents can compare before and after changes without relying on screenshots.
- Keep the harness standalone under `cmd/` so it can be run with `go run` or built into `dist/`.
- Exercise the same derptun mux path used by derpssh, not a synthetic-only protocol.

## Non-goals

- Throughput benchmarking. Existing promotion and transfer harnesses own that.
- Browser UI testing.
- Long-duration soak testing.
- Release tagging or publishing.

## Metrics

The primary score is interactive round-trip latency:

- p50, p90, p95, p99, max, mean, and standard deviation
- per-sample timestamp, sequence, payload, duration, and scenario
- baseline ratio: derpssh p50 divided by SSH p50

Diagnostic metrics:

- derptun mux ping latency
- derptun stream echo latency
- open-stream setup latency
- active path state when available: relay, direct, or unknown
- QUIC metric snapshots when `DERPHOLE_QUIC_METRICS_DIR` is enabled

## Command shape

The primary command should be:

```sh
go run ./cmd/derpssh-latency run \
  --remote ubuntu@derphole-testing \
  --samples 200 \
  --warmup 20 \
  --out .tmp/latency/latest
```

The run writes:

- `summary.json`
- `samples.jsonl`
- `events.jsonl`
- per-side logs under `logs/`

Comparison command:

```sh
go run ./cmd/derpssh-latency compare .tmp/latency/before .tmp/latency/after
```

## First transport target

The current derptun mux sends one data frame and waits for the cumulative ACK before reading and sending the next chunk on that stream. That stop-and-wait behavior adds at least one transport round trip between consecutive small writes. Interactive terminal input should not require that; SSH does not wait for an application ACK before sending the next keystroke.

The mux should allow multiple in-flight data frames per stream while retaining cumulative ACK cleanup and reconnect replay for unacked payloads.

## Acceptance criteria

- A mux regression test proves consecutive small writes do not wait for the first ACK.
- Existing reconnect replay tests still pass.
- The standalone latency command can run against `ubuntu@derphole-testing` and write JSON artifacts.
- A live run reports SSH and derptun or derpssh latency in one summary.
- Local tests and relevant remote smoke tests pass before landing.
