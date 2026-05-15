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

`connected-direct` means direct UDP has delivered probe or payload bytes. A run that attempts direct but falls back to relay records `direct-fallback-relay` and a non-empty `fallback_reason`.

For no-Tailscale route verification, run 3x averaged 1 GiB transfers in both directions for:

- Mac -> `ktzlxc`
- `ktzlxc` -> Mac
- Mac -> `hetz`
- `hetz` -> Mac
- Mac -> `pve1`
- `pve1` -> Mac

Default production runs already skip `100.64.0.0/10` and `fd7a:115c:a1e0::/48` candidates so transport stays independent from Tailscale routes. Use `./scripts/promotion-matrix-no-tailscale.sh 1024` for the public-Internet/private-LAN matrix, and use `DERPHOLE_ENABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh <host> 1024` only when you intentionally want to compare the old over-Tailscale route. `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` remains available as an explicit guardrail for internet-only tests. For `pve1`, same-LAN private routing is expected because `pve1` and this Mac are on the same LAN.

Examples:

- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPHOLE_PARALLEL_ARGS='--parallel=8' ./scripts/promotion-test.sh ktzlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPHOLE_PARALLEL_ARGS='--parallel=auto' ./scripts/promotion-test.sh canlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPHOLE_PARALLEL_ARGS='--parallel=8' ./scripts/promotion-test-reverse.sh ktzlxc 1024`

## Direct UDP Probe Harness

The raw-mode direct UDP probe harness is a microbenchmark for packet-engine experiments. Production `listen/pipe` now uses DERP-coordinated direct UDP by default, so treat this harness as a lower-level comparison tool rather than the proof of the default transport.

Every derphole baseline command in this validation path must set `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`.

Use the promotion scripts above for end-to-end default-transport validation. Use the raw probe harnesses when you need to isolate packet-engine throughput, pacing, repair, or batching behavior outside the full DERP coordination path.

Use these harnesses for the proof run:

- `./scripts/probe-benchmark.sh ktzlxc 1073741824`
- `DERPHOLE_PROBE_PEER_HOST=<reachable-local-host> DERPHOLE_PROBE_PEER_USER=<ssh-user-on-that-host> ./scripts/probe-benchmark-reverse.sh ktzlxc 1073741824`
- `./scripts/probe-matrix.sh`

Useful probe tuning knobs:

- `DERPHOLE_PROBE_PARALLEL=<n>` controls raw/blast stripe count.
- `DERPHOLE_PROBE_WINDOW_SIZE=<n>` controls the reliable raw-mode in-flight window.
- `DERPHOLE_PROBE_WINDOW=<n>` is accepted as a shorthand alias for `DERPHOLE_PROBE_WINDOW_SIZE`.
- `DERPHOLE_PROBE_CHUNK_SIZE=<bytes>` controls raw/blast payload size per packet.

The matrix runner covers:

- `ktzlxc`
- `canlxc`
- `uklxc`
- `november-oscar.exe.xyz`
- `eric@eric-nuc`

`eric@eric-nuc` is the asymmetric long-haul residential host in the standard matrix. As of April 12, 2026, a fresh Ookla run from that machine measured about `409.8 Mbps` download and `33.0 Mbps` upload, so reverse and forward expectations should be judged against that ceiling instead of the `ktzlxc` class hosts.

Keep the raw probe comparison separate from the derphole baseline runs. The baseline commands should continue to use the no-Tailscale guardrail, for example:

- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh ktzlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh canlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh uklxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh november-oscar.exe.xyz 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh eric@eric-nuc 1024`

The reverse probe harness is only valid when the remote host can actually SSH to the peer host and user you supply. Do not rely on the local hostname unless that name is resolvable and reachable from the remote side.

### Browser to CLI WebRTC

Use this after changing `pkg/derphole/webrelay`, `pkg/derphole/webrtcdirect`, `cmd/derphole-web`, or `web/derphole`.

For repeatable browser-send to CLI-receive measurements, use the automated Playwright harness. It builds the web bundle, writes a real temporary input file, drives Chrome on this Mac, copies a native `derphole` receive binary to the remote, verifies received byte count, and reports browser-side wall time plus direct DataChannel stats.

```bash
SIZE_MB=1024 REMOTE_HOST=root@ktzlxc ./scripts/smoke-web-cli-browser.sh
```

The harness runs the remote receiver without `--verbose` by default because verbose out-of-order direct-frame traces distort throughput. Use `VERBOSE=1` only when diagnosing direct handoff or frame ordering. Use `DIRECT=0` only for relay-only comparisons.

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
