# Benchmarking Derpcat

Use this runbook when comparing `derpcat` throughput, relay-to-direct promotion latency, or baseline host-to-host performance. The goal is repeatable measurements without leaking UDP sockets, orphaning processes, or exhausting ephemeral ports on either host.

## Preferred Benchmark Paths

Use the checked-in harnesses first:

- `REMOTE_HOST=my-server.example.com mise run promotion-1g`
- `./scripts/promotion-test.sh my-server.example.com 1024`
- `./scripts/promotion-test-reverse.sh my-server.example.com 1024`
- `./scripts/promotion-matrix-no-tailscale.sh 1024`
- `./scripts/smoke-remote.sh my-server.example.com`
- `./scripts/smoke-remote-share.sh my-server.example.com`

`promotion-test.sh` is the main throughput benchmark for one-shot `listen/send`. It verifies byte count, SHA-256, path transition logs, and now fails if any `derpcat` process or UDP socket survives after cleanup.

When comparing direct-path striping, forward the same CLI flag family used by `send` and `open` through the harness with `DERPCAT_PARALLEL_ARGS`. The harness passes those args to the active side only: local `send/open` in forward runs and remote `send/open` in reverse runs. The passive side follows the active side's negotiated request.

## Baseline Comparisons

Measure raw network capacity separately before blaming tunnel overhead.

- `iperf3` between the same two hosts for a TCP baseline
- `nc` plus `pv` for a simple streaming baseline
- then the matching `derpcat listen/send` or `share/open` path

Keep source payload size, host pair, and direction fixed when comparing variants. Record duration, throughput, final path state, and whether the session upgraded from `connected-relay` to `connected-direct`.

For no-Tailscale route verification, run 3x averaged 1 GiB transfers in both directions for:

- Mac -> `ktzlxc`
- `ktzlxc` -> Mac
- Mac -> `hetz`
- `hetz` -> Mac
- Mac -> `pve1`
- `pve1` -> Mac

Default production runs already skip `100.64.0.0/10` and `fd7a:115c:a1e0::/48` candidates so transport stays independent from Tailscale routes. Use `./scripts/promotion-matrix-no-tailscale.sh 1024` for the public-Internet/private-LAN matrix, and use `DERPCAT_ENABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh <host> 1024` only when you intentionally want to compare the old over-Tailscale route. `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1` remains available as an explicit guardrail for internet-only tests. For `pve1`, same-LAN private routing is expected because `pve1` and this Mac are on the same LAN.

Examples:

- `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPCAT_PARALLEL_ARGS='--parallel=8' ./scripts/promotion-test.sh ktzlxc 1024`
- `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPCAT_PARALLEL_ARGS='--parallel=auto' ./scripts/promotion-test.sh canlxc 1024`
- `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPCAT_PARALLEL_ARGS='--parallel=8' ./scripts/promotion-test-reverse.sh ktzlxc 1024`

## Direct UDP Probe Harness

The raw-mode direct UDP probe harness is a microbenchmark for packet-engine experiments. Production `listen/send` now uses DERP-coordinated direct UDP by default, so treat this harness as a lower-level comparison tool rather than the proof of the default transport.

Every derpcat baseline command in this validation path must set `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1`.

Use the promotion scripts above for end-to-end default-transport validation. Use the raw probe harnesses when you need to isolate packet-engine throughput, pacing, repair, or batching behavior outside the full DERP coordination path.

Use these harnesses for the proof run:

- `./scripts/probe-benchmark.sh ktzlxc 1073741824`
- `DERPCAT_PROBE_PEER_HOST=<reachable-local-host> DERPCAT_PROBE_PEER_USER=<ssh-user-on-that-host> ./scripts/probe-benchmark-reverse.sh ktzlxc 1073741824`
- `./scripts/probe-matrix.sh`

Useful probe tuning knobs:

- `DERPCAT_PROBE_PARALLEL=<n>` controls raw/blast stripe count.
- `DERPCAT_PROBE_WINDOW_SIZE=<n>` controls the reliable raw-mode in-flight window.
- `DERPCAT_PROBE_WINDOW=<n>` is accepted as a shorthand alias for `DERPCAT_PROBE_WINDOW_SIZE`.
- `DERPCAT_PROBE_CHUNK_SIZE=<bytes>` controls raw/blast payload size per packet.

The matrix runner covers:

- `ktzlxc`
- `canlxc`
- `uklxc`
- `november-oscar.exe.xyz`
- `eric@eric-nuc`

`eric@eric-nuc` is the asymmetric long-haul residential host in the standard matrix. As of April 12, 2026, a fresh Ookla run from that machine measured about `409.8 Mbps` download and `33.0 Mbps` upload, so reverse and forward expectations should be judged against that ceiling instead of the `ktzlxc` class hosts.

Keep the raw probe comparison separate from the derpcat baseline runs. The baseline commands should continue to use the no-Tailscale guardrail, for example:

- `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh ktzlxc 1024`
- `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh canlxc 1024`
- `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh uklxc 1024`
- `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh november-oscar.exe.xyz 1024`
- `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh eric@eric-nuc 1024`

The reverse probe harness is only valid when the remote host can actually SSH to the peer host and user you supply. Do not rely on the local hostname unless that name is resolvable and reachable from the remote side.

### Browser to CLI WebRTC

Use this after changing `pkg/derphole/webrelay`, `pkg/derphole/webrtcdirect`, `cmd/derphole-web`, or `web/derphole`.

1. Build and serve the browser demo locally:

```bash
./scripts/smoke-web-cli.sh
python3 -m http.server --directory "${TMPDIR:-/tmp}/derphole-web-cli-smoke" 8765
```

2. Open `http://127.0.0.1:8765/`, select a file, and copy the receive command.

3. Receive with native CLI:

```bash
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 go run ./cmd/derpcat derphole receive '<token>'
```

Record time to first byte, path-switch time, average throughput, final path, and whether relay fallback was used.

## Cleanup Guardrails

Never start the next benchmark iteration until the previous one has fully exited and both hosts are clean.

For one-off loops or custom scripts:

- run one `derpcat` sender/listener or `share/open` pair per iteration
- wrap each process in a hard timeout
- register a `trap` that kills child PIDs and removes temp files
- `wait` for child processes before the next iteration
- assert local and remote `pgrep -x derpcat` return zero benchmark processes
- if `pgrep -x derpcat` returns PIDs, assert `lsof -nP -a -p <pid-list> -iUDP` returns zero UDP sockets after cleanup

If either assertion fails, stop immediately and inspect the leaked process before continuing.

## What To Avoid

Do not run long-lived custom loops that repeatedly create new sessions in one process unless the harness proves every socket is closed. Avoid reusing ad hoc temp binaries from `/tmp` after the code has moved on. Do not use `lsof -c derpcat` on macOS for leak checks because it can match unrelated command names; derive exact PIDs with `pgrep -x derpcat` first. Do not report throughput numbers unless the run also proves payload integrity and post-run cleanup.
