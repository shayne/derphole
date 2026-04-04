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
