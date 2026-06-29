# Benchmarking Derphole

Use this runbook when comparing `derphole` throughput, relay-to-direct promotion latency, or baseline host-to-host performance. The goal is repeatable measurements without leaking UDP sockets, orphaning processes, or exhausting ephemeral ports on either host.

## Preferred Benchmark Paths

Use the checked-in harnesses first:

- `REMOTE_HOST=my-server.example.com mise run promotion-1g`
- `./scripts/promotion-test.sh my-server.example.com 1024`
- `./scripts/promotion-test-reverse.sh my-server.example.com 1024`
- `./scripts/promotion-matrix-no-tailscale.sh 1024`
- `./scripts/smoke-remote.sh my-server.example.com`
- `./scripts/smoke-remote-share.sh my-server.example.com`

`promotion-test.sh` is the main throughput benchmark for one-shot `listen/pipe`. It verifies byte count, SHA-256, path transition logs, and now fails if any `derphole` process or UDP socket survives after cleanup.

When comparing direct-path striping, forward the same CLI flag family used by `pipe` and `open` through the harness with `DERPHOLE_PARALLEL_ARGS`. The harness passes those args to the active side only: local `pipe/open` in forward runs and remote `pipe/open` in reverse runs. The passive side follows the active side's negotiated request.

## Baseline Comparisons

Measure raw network capacity separately before blaming tunnel overhead.

- `iperf3` between the same two hosts for a TCP baseline
- `nc` plus `pv` for a simple streaming baseline
- then the matching `derphole listen/pipe` or `share/open` path

Keep source payload size, host pair, and direction fixed when comparing variants. Record duration, throughput, final path state, and whether the session upgraded from `connected-relay` to `connected-direct`.

## Interactive Latency Harness

Use `cmd/derpssh-latency` when tuning interactive terminal latency. It compares a standard SSH line-echo baseline against derptun mux echo over the same SSH carrier, then writes machine-readable artifacts for agent feedback loops.

```bash
mise exec -- go run ./cmd/derpssh-latency run \
  --remote ubuntu@derphole-testing \
  --samples 200 \
  --warmup 20 \
  --out .tmp/latency/latest
```

Artifacts:

- `summary.json` has per-scenario p50/p90/p95/p99/max latency and derptun-vs-SSH ratios
- `samples.jsonl` has each measured and warmup sample
- `events.jsonl` records setup and scenario boundaries
- `logs/*.stderr.log` keeps helper stderr from each scenario

Use `compare` to check a change against a previous run:

```bash
mise exec -- go run ./cmd/derpssh-latency compare .tmp/latency/before .tmp/latency/after
```

The baseline scenario is `ssh-stdio`. The first derptun diagnostic scenario is `derptun-mux-over-ssh`, which isolates mux framing and stream scheduling without changing the underlying network route. If `derptun-mux-over-ssh` is much slower than `ssh-stdio`, inspect mux ACK/write scheduling before tuning higher-level `derpssh` UI code.

## V2 Transport Diagnostic Comparison

Use `scripts/transfer-stall-harness.sh` when a transfer completes below expected line rate or stalls. Pair it with `iperf3` between the same endpoints when you need a raw network baseline.

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh <sender-host> <receiver-host> 1024
```

The harness writes per-side logs, transfer traces, `samples.csv`, SHA checks, and leak snapshots. Key fields to compare are:

- sender and receiver trace `app_bytes`
- `local_sent_bytes` versus receiver-confirmed progress
- `v2-data-plane`
- direct and relay byte counters
- `transport-max-peer-recv-queue-depth`
- preflight and postrun process/socket leak checks

Interpretation:

- high iperf and low transfer goodput points at packet engine, stream, replay, queue, or controller behavior
- sender-side enqueue progress ahead of receiver progress indicates buffering or backpressure
- low sender and receiver goodput with high queue depth points at receiver or stream backpressure

## Phase 1 Public Transport Gate

Before changing the public transport protocol, capture a baseline for each host pair and direction:

```bash
DERPHOLE_IPERF_PORT=8123 DERPHOLE_IPERF_SERVER_HOST="${DERPHOLE_IPERF_SERVER_HOST:?set forwarded Mac iperf host}" ./scripts/iperf-benchmark.sh canlxc 1024
DERPHOLE_IPERF_PORT=8123 DERPHOLE_IPERF_SERVER_HOST="${DERPHOLE_IPERF_SERVER_HOST:?set forwarded Mac iperf host}" ./scripts/iperf-benchmark-reverse.sh canlxc 1024
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh canlxc pouffe-rasp.exe.xyz 1024
```

Use `DERPHOLE_IPERF_PORT=8123` when testing through the Mac port-forwarded iperf endpoint. Use the default `8321` only when both endpoints can reach the local iperf server directly on that port.

Every accepted result must include:

- `stall-harness-success=true`
- matching source and sink SHA-256
- sender and receiver `send.trace.csv` / `receive.trace.csv`
- `transfertracecheck` success for sender and receiver traces
- `leak-check ... processes=0 udp_sockets=0` for preflight and postrun checks
- iperf TCP baseline in both directions, when routing allows it

Do not report a derphole throughput number if any leak check, trace check, or integrity check fails.

### Transfer Stall Traces

Use in-process transfer traces when proving stalls. SSH polling in `samples.csv` is useful as an outer process watchdog, but application-byte progress should come from the sender and receiver trace files.

```bash
DERPHOLE_TRANSFER_TRACE_CSV=/tmp/send.csv derphole send payload.bin
DERPHOLE_TRANSFER_TRACE_CSV=/tmp/receive.csv derphole receive -o received.bin '<token>'
mise exec -- go run ./tools/transfertracecheck -role send -stall-window 1s -peer-trace /tmp/receive.csv /tmp/send.csv
mise exec -- go run ./tools/transfertracecheck -role receive -stall-window 1s /tmp/receive.csv
```

`scripts/transfer-stall-harness.sh` enables sender and receiver traces automatically, copies them back as `sender/send.trace.csv` and `receiver/receive.trace.csv`, and runs `tools/transfertracecheck` after payload SHA verification.
Trace `app_bytes` are session stream bytes and include derphole framing, so payload byte counts should be verified with the transferred file size and SHA. Use `-expected-bytes` only when checking an exact session stream byte count.

Sender `app_bytes` are receiver-confirmed session stream bytes once progress ACKs start. `local_sent_bytes` records sender-side enqueue/spool progress and can be ahead of receiver progress. Use `transfer_elapsed_ms` for throughput comparisons; `elapsed_ms` includes setup and direct probing time.

`connected-direct` means a direct path has delivered probe or payload bytes. A run that attempts direct but falls back to relay records `direct-fallback-relay` and a non-empty `fallback_reason`.
Relay fallback should continue making trace progress after a direct setup failure; v2 keeps the application stream on one QUIC path instead of reviving the retired split-stream protocol.

Use v2 trace and verbose telemetry to explain path selection:

- `v2-data-plane=raw-direct` means both peers agreed on raw UDP packet conns before QUIC started.
- `v2-data-plane=manager` means QUIC is running over the manager-backed relay/direct packet substrate.
- `v2-raw-direct-active` and `v2-raw-direct-selected-addrs` show the raw-direct lane set.
- `direct_bytes` and `relay_bytes` in the trace show actual byte movement by path.
- `fallback_reason` explains direct setup failures that continued over relay.
- `peer_recv_queue_depth` and `peer_recv_queue_depth_max` show receiver-side backpressure inside the packet manager.

A healthy LAN/VLAN run should either use raw-direct or show direct byte growth through the manager path. If verbose logs show `v2-raw-direct-no-observed-addrs`, inspect candidate reachability and routing before treating throughput as a transport regression.

For no-Tailscale route verification, run 3x averaged 1 GiB transfers in both directions for:

- Mac -> `ktzlxc`
- `ktzlxc` -> Mac
- Mac -> `hetz`
- `hetz` -> Mac
- Mac -> `pve1`
- `pve1` -> Mac

Default production runs allow Tailscale CGNAT/ULA candidates, because those routes can be the best path for real users. Set `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` for public-Internet/private-LAN benchmarks when you need to avoid conflating derphole transport performance with an already-encapsulated Tailscale tunnel. For `pve1`, same-LAN private routing is expected because `pve1` and this Mac are on the same LAN.

Examples:

- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPHOLE_PARALLEL_ARGS='--parallel=8' ./scripts/promotion-test.sh ktzlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPHOLE_PARALLEL_ARGS='--parallel=auto' ./scripts/promotion-test.sh canlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPHOLE_PARALLEL_ARGS='--parallel=8' ./scripts/promotion-test-reverse.sh ktzlxc 1024`

## Production Matrix Runner

The old raw/blast packet-engine probe harness has been retired. Use production promotion scripts for transport validation, because they exercise the same v2 session path as `listen/pipe`, `send/receive`, and `share/open`.

Use these harnesses for proof runs:

- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh ktzlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test-reverse.sh ktzlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-matrix-no-tailscale.sh 1024`

Useful production tuning knobs:

- `DERPHOLE_PARALLEL_ARGS='--parallel=auto'` lets the active side choose direct-path striping.
- `DERPHOLE_PARALLEL_ARGS='--parallel=<n>'` forces a specific striping request for controlled comparisons.
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` removes Tailscale CGNAT/ULA candidates from test runs only.

The matrix runner covers:

- `ktzlxc`
- `canlxc`
- `uklxc`
- `november-oscar.exe.xyz`
- `eric@eric-nuc`

`eric@eric-nuc` is the asymmetric long-haul residential host in the standard matrix. As of April 12, 2026, a fresh Ookla run from that machine measured about `409.8 Mbps` download and `33.0 Mbps` upload, so reverse and forward expectations should be judged against that ceiling instead of the `ktzlxc` class hosts.

The baseline commands should continue to use the no-Tailscale guardrail when measuring public-Internet or private-LAN paths without encapsulated Tailscale routes:

- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh ktzlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh canlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh uklxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh november-oscar.exe.xyz 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh eric@eric-nuc 1024`

### Browser to CLI WebRTC

Use this after changing `pkg/derphole/webrelay`, `pkg/derphole/webrtcdirect`, `cmd/derphole-web`, or `web/derphole`.

For repeatable browser-send to CLI-receive measurements, use the automated Playwright harness. It builds the web bundle, writes a real temporary input file, drives Chrome on this Mac, copies a native `derphole` receive binary to the remote, verifies received byte count, and reports browser-side wall time plus direct DataChannel stats.

```bash
SIZE_MB=1024 REMOTE_HOST=root@ktzlxc ./scripts/smoke-web-cli-browser.sh
```

The harness runs the remote receiver without `--verbose` by default because verbose direct-frame traces distort throughput. Use `VERBOSE=1` only when diagnosing direct-path setup or frame ordering. Use `DIRECT=0` only for relay-only comparisons.

For manual testing:

1. Build and serve the browser demo locally:

```bash
./scripts/smoke-web-cli.sh
python3 -m http.server --directory "${TMPDIR:-/tmp}/derphole-web-cli-smoke" 8765
```

2. Open `http://127.0.0.1:8765/`, select a file, and copy the receive command.

3. Receive with native CLI:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 go run ./cmd/derphole receive '<token>'
```

Record time to first byte, path-switch time, average throughput, final path, and whether relay fallback was used. Do not compare manual verbose runs against quiet harness throughput.

## Cleanup Guardrails

Never start the next benchmark iteration until the previous one has fully exited and both hosts are clean.

For one-off loops or custom scripts:

- run one `derphole` sender/listener or `share/open` pair per iteration
- wrap each process in a hard timeout
- register a `trap` that kills child PIDs and removes temp files
- `wait` for child processes before the next iteration
- assert local and remote `pgrep -x derphole` return zero benchmark processes
- if `pgrep -x derphole` returns PIDs, assert `lsof -nP -a -p <pid-list> -iUDP` returns zero UDP sockets after cleanup

If either assertion fails, stop immediately and inspect the leaked process before continuing.

## What To Avoid

Do not run long-lived custom loops that repeatedly create new sessions in one process unless the harness proves every socket is closed. Avoid reusing ad hoc temp binaries from `/tmp` after the code has moved on. Do not use `lsof -c derphole` on macOS for leak checks because it can match unrelated command names; derive exact PIDs with `pgrep -x derphole` first. Do not report throughput numbers unless the run also proves payload integrity and post-run cleanup.
