# Benchmarking Derphole

Use this runbook when comparing `derphole` throughput, relay-to-direct promotion latency, or baseline host-to-host performance. The goal is repeatable measurements without leaking UDP sockets, orphaning processes, or exhausting ephemeral ports on either host.

## Encrypted transport feasibility gate

Use the feasibility gate only for the Mac-to-exact-two-vCPU-Hetzner comparison. It builds both endpoints from the same revision, creates one ordinary 3 GiB random file, stages identical bytes on both hosts, and interleaves three file transfers in each direction for the batched bulk UDP and eight-lane TLS 1.3 candidates. Every transfer is paired with a same-direction 20-second, eight-flow iperf3 control.

The TCP port must be reachable through the public internet in both directions. On a NATed local endpoint, forward that TCP port to the Mac before starting. The two address variables must be literal public IPv4 addresses; loopback, private, link-local, multicast, and Tailscale CGNAT addresses are rejected.

```bash
DERPHOLE_FEASIBILITY_REMOTE="${DERPHOLE_FEASIBILITY_REMOTE:?set SSH target}" \
DERPHOLE_FEASIBILITY_REMOTE_PUBLIC_ADDR="${DERPHOLE_FEASIBILITY_REMOTE_PUBLIC_ADDR:?set remote public address}" \
DERPHOLE_FEASIBILITY_LOCAL_PUBLIC_ADDR="${DERPHOLE_FEASIBILITY_LOCAL_PUBLIC_ADDR:?set local public address}" \
DERPHOLE_FEASIBILITY_TCP_PORT="${DERPHOLE_FEASIBILITY_TCP_PORT:?set forwarded TCP port}" \
mise run transport:feasibility
```

The gate does not install packages. `iperf3`, Python 3, SSH/SCP, and the repository's `mise` toolchain must already exist locally; `iperf3`, Python 3, and standard Linux inspection tools must exist remotely. The remote must report exactly two online CPUs and both endpoints must have at least 16 GiB free for the source and retained receiver outputs.

Artifacts are kept under `.tmp/encrypted-transport-feasibility/<UTC timestamp>-<PID>/`. `results.jsonl` contains the normalized runs and `decision.json` contains the strict verdict. A sample is invalid and retried when the paired capacity control is below 2.05 Gbps. A candidate passes only when every valid 3 GiB run exceeds 2.0 Gbps receiver-anchored goodput, hashes match, payload progress never stalls for one second, the public route is proven, and resource/transport evidence is complete. Interruptions preserve local evidence and remove only the exact remote directory and recorded process IDs created by that invocation.

## Preferred Benchmark Paths

Use the checked-in harnesses first:

- `REMOTE_HOST=my-server.example.com mise run promotion-1g`
- `./scripts/promotion-test.sh my-server.example.com 1024`
- `./scripts/promotion-test-reverse.sh my-server.example.com 1024`
- `./scripts/promotion-matrix-no-tailscale.sh 1024`
- `./scripts/smoke-remote.sh my-server.example.com`
- `./scripts/smoke-remote-share.sh my-server.example.com`

`promotion-test.sh` defaults to the primary product file workload: one-shot `send FILE` followed by `receive -o FILE TOKEN`. It verifies byte count, SHA-256, path transition logs, and now fails if any `derphole` process or UDP socket survives after cleanup. Set `DERPHOLE_BENCH_WORKLOAD=stream` only when running the explicit `listen/pipe` control.

For `DERPHOLE_BENCH_WORKLOAD=stream` direct-path striping diagnostics, set `DERPHOLE_BENCH_PARALLEL` to the value that would be passed to `--parallel`. The harness passes that diagnostic override to the active side only: local `pipe/open` in forward runs and remote `pipe/open` in reverse runs. `DERPHOLE_BENCH_PARALLEL` is not valid for the file workload; leave it unset for product-default runs.

## Baseline Comparisons

Measure raw network capacity separately before blaming tunnel overhead.

- `iperf3` between the same two hosts for a TCP baseline
- `nc` plus `pv` for a simple streaming baseline
- then the matching default `derphole send/receive` file workload; use `listen/pipe` only as an explicit stream control

Keep source payload size, host pair, and direction fixed when comparing variants. Record duration, throughput, final path state, and whether the session upgraded from `connected-relay` to `connected-direct`.

## Public Path Performance Harness

Use the file workload for primary product acceptance:

```bash
# Primary product file benchmark.
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
DERPHOLE_BENCH_WORKLOAD=file \
./scripts/promotion-test.sh ubuntu@eric-nuc 3072
```

Use the stream workload only as an explicit control. Never report it as file validation:

```bash
# Explicit stream control; never report this as file validation.
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
DERPHOLE_BENCH_WORKLOAD=stream \
./scripts/promotion-test.sh ubuntu@eric-nuc 3072
```

Production leaves `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES` unset so route discovery can use Tailscale candidates. The primary public harness defaults to the file workload, and benchmark summaries always record the workload and negotiated transfer mode.

The public-path throughput gate is Mac -> remote by default:

```bash
DERPHOLE_PUBLIC_PATH_HOSTS='ubuntu@derphole-testing ubuntu@eric-nuc root@hetz root@canlxc' \
DERPHOLE_PUBLIC_PATH_SIZE_MIB=1024 \
DERPHOLE_PUBLIC_PATH_RUNS=3 \
DERPHOLE_PUBLIC_IPERF_PORT=8123 \
./scripts/public-path-performance-harness.sh
```

The harness sets `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` for derphole runs so the measurement stays on the public Internet path. This is a test-only guard; production defaults still allow Tailscale candidates.

Normal public-path runs use the file workload and leave `DERPHOLE_BENCH_PARALLEL` unset. For an explicit stream diagnostic, set both controls, for example `DERPHOLE_BENCH_WORKLOAD=stream DERPHOLE_BENCH_PARALLEL=auto ./scripts/public-path-performance-harness.sh`.

For a large-file direct-TCP acceptance run, set `DERPHOLE_BENCH_DIRECT_TCP_PORT` to an existing same-port TCP forward on the local endpoint. The driver passes `--direct-tcp-port` only to the local active file endpoint in each direction; the remote peer dials that advertisement. Keep `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` for public-path evidence and set `DERPHOLE_BENCH_EXPECT_TRANSFER_MODE=direct-tcp-files-v1` when the run must reject fallback:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 \
DERPHOLE_BENCH_DIRECT_TCP_PORT=8123 \
DERPHOLE_BENCH_EXPECT_TRANSFER_MODE=direct-tcp-files-v1 \
DERPHOLE_BENCH_WORKLOAD=file \
./scripts/promotion-test.sh root@remote.example 3072
```

The July 2 baseline expected eric-nuc Mac -> remote derphole average within 10-15 percent of same-run `iperf3`, with zero steady direct-phase `transfertracecheck` stalls over 1s. Keep that result as historical context. Use the bulk-pacing decision gate below when selecting an initial rate; the old average is not the selection rule.

### Throughput clocks

The promotion footer separates three clocks:

- `benchmark-transfer-elapsed-ms` is the receiver-anchored interval from first payload byte through committed completion. `benchmark-goodput-mbps` and summary `mbps` are verified payload bytes divided by this clock.
- `benchmark-command-duration-ms` starts immediately before the active sender command and stops after both transfer processes exit. `benchmark-wall-goodput-mbps` uses this clock and includes command setup and teardown, but excludes postflight.
- `benchmark-total-duration-ms` continues through log and trace collection, SHA and size checks, direct-path checks, and leak validation. It is operational duration, not a throughput denominator.

Accepted derphole rows require the rounded `benchmark-goodput-mbps` footer to equal `transfertracecheck sender_mbps`. The public summary records canonical and wall rates, their same-run iperf ratios, all three timing operands, trace status, maximum peer queue depth, and maximum flatline.

Benchmark binaries are installed under a unique remote run directory. `DERPHOLE_REMOTE_BIN_DIR` selects a writable executable root; the harness still appends a unique run directory and removes it during cleanup. The benchmark must never replace a managed binary at a stable path.

### Bulk-packet pacing diagnostics

Bulk-packet pace targets are aggregate IPv4-wire Mbps. A full packet carries 1,358 payload bytes in a 1,400-byte UDP datagram and costs 1,428 bytes after IPv4 and UDP headers. `rate_target_mbps` is the current target; `direct_rate_selected_mbps` is the 1,000 Mbps starting policy.

The controller samples every 500 ms. An accepted primary sample contains at least 8 MiB of primary wire traffic. Backoff requires usable peer progress, repair of at least 2 percent, and receiver-confirmed delivery below 90 percent of the current target in two consecutive accepted pressure samples. The first holds with `repair-pressure-pending`; above the 128 Mbps floor, the second sets the target to integer 85 percent of its current value. That second sample chooses the exact decrease reason: `hard-repair-pressure` when its repair ratio is at least 8 percent, otherwise `repair-and-delivery-drop`. At the floor it holds as `minimum`.

The pending-pressure count clears after a counter reset, after an accepted sample without usable peer progress, after an accepted peer-ready sample with repair below 2 percent or delivery at least 90 percent of the target, and after a decrease. An `insufficient-wire-sample` observation neither advances nor clears the count; its primary traffic continues accumulating toward the next accepted sample.

A decrease loads a four-window cooldown. Repair of at least 2 percent with healthy delivery always holds as `repair-hold`, consuming one cooldown window when one remains. With repair below 2 percent, an active cooldown holds as `backoff-cooldown` and consumes one window. A pending pressure sample does not consume cooldown, and a second consecutive pressure sample may decrease the target again before cooldown expires. Once cooldown is clear, clean delivery below 2 percent repair increases the target by 64 Mbps up to the ceiling; low-repair delivery below 90 percent holds as `receiver-limited`.

The controller also uses the exact guard reasons `initial-target`, `counter-reset`, `insufficient-wire-sample`, `awaiting-peer-progress`, `ceiling`, and `minimum`. Repair percentage is repair IPv4-wire bytes divided by primary plus repair IPv4-wire bytes for the accepted sample.

Use the cumulative `retransmits`, `repair_requests`, and `repair_bytes` counters with the target and reason. Do not infer a decision from the final trace row alone; controller state must be present in non-terminal rows.

Verbose `v2-raw-direct-socket-buffer` lines report the 8 MiB request and, for each opened lane, the raw receive and write values returned by `getsockopt(SO_RCVBUF)` and `getsockopt(SO_SNDBUF)`. The line also reports whether either set operation or the inspection failed. Linux may report a doubled kernel accounting value; preserve the returned number when comparing hosts.

### Bulk repair efficiency

The bulk receiver tracks unresolved packet gaps incrementally. It does not rescan the successful packet prefix on every repair tick. A cursor scans each newly eligible packet index once. Unseen indexes enter a bounded pending tracker, and only later packet arrival or seen-state compaction removes them. Active repair requests retain the established 100 ms cadence. The reorder allowance is separate: a 250 ms observation window is converted from the measured receive packet rate and clamped between 8,192 and 65,536 packets. That keeps the wait stable across fast and slow paths instead of making it an accidental function of throughput.

Bulk traces and `summary.csv` expose seven repair-efficiency fields:

- `missing_scan_checks`: packet positions examined by the incremental tracker.
- `pending_missing`: unresolved gaps at the final sample.
- `pending_missing_peak`: largest unresolved-gap set during the transfer.
- `repair_requested_packets`: packet indexes included in repair requests.
- `repair_request_batches`: repair request batches generated by the receiver.
- `reorder_trail_packets`: final rate-derived reorder allowance.
- `receive_packet_rate_pps`: final receive-rate estimate used for that allowance.

`scan_checks_per_packet` is `missing_scan_checks / ceil(size_bytes / 1358)`. A bulk acceptance row requires it to remain below 2.0. Empty values mean the field was not produced, while numeric zero is a valid healthy result. Intentional `blocks-v1` rows leave all bulk-only fields empty.

The benchmark driver runs both processes through `tools/runstats`. It records user CPU seconds, system CPU seconds, peak RSS, and CPU seconds per verified GiB for the sender and receiver. Missing or malformed resource JSON rejects the sample on Darwin and Linux. `DERPHOLE_BENCH_LOCAL_BIN` and `DERPHOLE_BENCH_LINUX_BIN` select an exact prebuilt candidate or control pair; set both or neither. `DERPHOLE_BENCH_REVISION_LABEL` binds every derphole result row to the tested revision.

The focused comparison uses fresh control and candidate binaries in `A B B A` order. It requires stable paired iperf samples, repair below 10 percent, at least 10 percent lower receiver CPU/GiB, scan work below 2.0 checks per packet, and no canonical or wall regression above 3 percent. The 10 percent CPU floor is evidence-driven: the final candidate measured 17.89 percent lower receiver CPU/GiB in the fresh three-control/three-candidate Eric gate, while GRO batching, plain `recvmmsg`, and larger synchronous receive writes were rejected by WAN or deterministic Linux repair evidence. No throughput, repair, integrity, route, trace, resource, flatline, or cleanup requirement was relaxed.

The first fleet pass exposed a cadence regression in the earlier candidate: incremental tracking had accidentally changed active repair requests from 100 ms to 250 ms. On `derphole-testing` forward, that candidate lost 12.5 percent canonical goodput and raised repair 34.0 percent against a fresh same-path control. A live milestone bisection isolated the tracker-integration boundary. Restoring 100 ms in `14ff73a` recovered canonical goodput to within 0.3 percent of control, reduced median repair 17.1 percent, and reduced receiver CPU/GiB 4.3 percent on the same public path.

Full acceptance is stricter and broader. Eric gets three fresh control and three candidate 1 GiB forward files. Every reachable canonical host then gets three unoverridden candidate files in both directions. Bulk cells require the fields above, the 1,000 Mbps production policy, and no CPU or repair regression. `blocks-v1` cells use the mode-aware QUIC checks. Canonical CV above 0.15 permits one same-cell three-run rerun; integrity, route, mode, trace, resource, cleanup, or repeated stability failures do not get a noise waiver.

The 1,000 Mbps target remains an internal production default. There is no user-facing pacing flag to tune around a bad path. Benchmark-only overrides exist to test a hypothesis, not to transfer the tuning burden to users.

### Eric bulk-pacing experiment

Run the tuning matrix against Eric separately from the fleet gate:

```bash
DERPHOLE_PUBLIC_PATH_HOSTS='ubuntu@eric-nuc' \
DERPHOLE_PUBLIC_PATH_SIZE_MIB=3072 \
DERPHOLE_PUBLIC_PATH_INITIAL_RATES='1000 900 800 800 1000 900 900 800 1000' \
DERPHOLE_PUBLIC_IPERF_PORT=8123 \
DERPHOLE_BENCH_LOG_DIR=.tmp/bulk-pacing-ab-20260712 \
./scripts/public-path-performance-harness.sh
```

The order rotates all three rates through early, middle, and late path conditions. Each derphole row in `summary.csv` is paired with its same-run iperf sample. The useful columns are:

- `mbps`: canonical goodput, calculated from verified payload bytes and the receiver-anchored `benchmark-transfer-elapsed-ms` clock.
- `ratio_to_iperf`: canonical goodput divided by the same run's iperf result.
- `repair_bytes`: the trace checker's `final_repair_bytes`, copied into `summary.csv` under the shorter name. It is the final cumulative repair payload-byte count.
- `repair_ratio`: `repair_bytes` divided by `benchmark-size-bytes`.
- `retransmits`: the trace checker's `max_retransmits`, copied into `summary.csv` under the shorter name. It is the maximum cumulative retransmit count observed in the sender trace.
- `min_rate_target_mbps`: the lowest non-zero pacing target observed in the sender trace.
- `final_rate_target_mbps`: the last non-zero pacing target observed in the sender trace.
- `controller_decreases`: the number of distinct downward pacing-target transitions made by the controller.
- `receiver_rate_p10_mbps`, `receiver_rate_p50_mbps`, and `receiver_rate_p90_mbps`: the p10, median, and p90 of the receiver's direct-execute rate samples after payload progress begins. Zero-throughput windows after progress are included; setup windows before the first payload byte are excluded.
- `receiver_rate_cv`: the coefficient of variation across those post-progress receiver direct-execute rate samples, including zero-throughput windows.
- `receiver_windows_below_500_mbps`: the number of post-progress receiver direct-execute samples below 500 Mbps, including zero-throughput windows.
- `local_enobufs_retries`: cumulative UDP writes retried after the local kernel returned `ENOBUFS`.
- `local_enobufs_wait_us`: cumulative microseconds spent in those retry waits.
- `local_enobufs_max_consecutive`: the largest consecutive `ENOBUFS` run before a write succeeded or the transfer stopped.

For the wait ratio, the CSV `transfer_elapsed_ms` column is the `benchmark-transfer-elapsed-ms` footer value. `local_enobufs_wait_us / 1000 / benchmark-transfer-elapsed-ms >= 0.01` means local buffer waiting consumed at least one percent of transfer time.

This command defines the experiment; it does not claim the live matrix has run or that a candidate has won.

The July 12 fleet disproof rejected the 900 Mbps Eric candidate: on the completed `derphole-testing` forward bulk cell, its median ratio to same-run iperf regressed 7.278 percent. The fleet-safe production selection therefore remains 1,000 Mbps.

The reverse cell then negotiated `blocks-v1` because the Mac receiver advertised 16 non-Tailscale policy candidates. That is intentional adaptive policy, not removable legacy. Receivers with five or more non-Tailscale policy candidates retain QUIC because it measured faster on high-capacity paths, and QUIC remains the compatibility fallback for peers without bulk-packet capability. Bulk-rate A/B rules apply only when the host-direction negotiates `bulk-packets-v1`; `blocks-v1` never runs the bulk controller or exercises `DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS`, so judge it only from unoverridden QUIC evidence.

### Reachable-fleet bidirectional gate

Run this only after the Eric matrix selects a candidate `C` other than 1,000 Mbps. Put every reachable canonical host in `.tmp/bulk-pacing-fleet-20260712/reachable-hosts.txt`, one SSH target per line, and run a 1 GiB normal file in both directions. The candidate-versus-control order is `1000 C C 1000`:

```bash
candidate="$(cat .tmp/bulk-pacing-ab-20260712/candidate-rate.txt)"
while IFS= read -r host; do
  host_label="${host//[^A-Za-z0-9_.-]/_}"
  iperf_host_env=()
  if [[ "${host}" == "root@pve1" ]]; then
    lan_interface="$(route -n get pve1 | awk '/interface:/{print $2; exit}')"
    lan_address="$(ipconfig getifaddr "${lan_interface}")"
    iperf_host_env+=(DERPHOLE_PUBLIC_IPERF_SERVER_HOST="${lan_address}")
  fi
  for direction in forward reverse; do
    env "${iperf_host_env[@]}" \
      DERPHOLE_PUBLIC_PATH_HOSTS="${host}" \
      DERPHOLE_PUBLIC_PATH_DIRECTION="${direction}" \
      DERPHOLE_PUBLIC_PATH_SIZE_MIB=1024 \
      DERPHOLE_PUBLIC_PATH_INITIAL_RATES="1000 ${candidate} ${candidate} 1000" \
      DERPHOLE_PUBLIC_IPERF_PORT=8123 \
      DERPHOLE_BENCH_LOG_DIR=".tmp/bulk-pacing-fleet-20260712/${host_label}/${direction}" \
      ./scripts/public-path-performance-harness.sh
  done
done < .tmp/bulk-pacing-fleet-20260712/reachable-hosts.txt
```

`pve1` is the same-LAN topology. Every other host must remain on a public, non-Tailscale path. The harness disables Tailscale candidates, but the result still has to prove the selected route; an environment variable is not a packet path.

After selecting the fleet-safe default, run three unoverridden normal 1 GiB file transfers in both directions on every reachable host. Each host-direction must produce exactly three derphole rows and three paired iperf rows, and all three derphole rows must negotiate one consistent mode:

```bash
while IFS= read -r host; do
  host_label="${host//[^A-Za-z0-9_.-]/_}"
  iperf_host_env=()
  if [[ "${host}" == "root@pve1" ]]; then
    lan_interface="$(route -n get pve1 | awk '/interface:/{print $2; exit}')"
    lan_address="$(ipconfig getifaddr "${lan_interface}")"
    iperf_host_env+=(DERPHOLE_PUBLIC_IPERF_SERVER_HOST="${lan_address}")
  fi
  for direction in forward reverse; do
    env -u DERPHOLE_PUBLIC_PATH_INITIAL_RATES "${iperf_host_env[@]}" \
      DERPHOLE_PUBLIC_PATH_HOSTS="${host}" \
      DERPHOLE_PUBLIC_PATH_DIRECTION="${direction}" \
      DERPHOLE_PUBLIC_PATH_SIZE_MIB=1024 \
      DERPHOLE_PUBLIC_PATH_RUNS=3 \
      DERPHOLE_PUBLIC_IPERF_PORT=8123 \
      DERPHOLE_BENCH_LOG_DIR=".tmp/bulk-pacing-default-acceptance-20260712/${host_label}/${direction}" \
      ./scripts/public-path-performance-harness.sh
  done
done < .tmp/bulk-pacing-fleet-20260712/reachable-hosts.txt
```

The exact acceptance audit requires empty `initial_rate_mbps` values on every derphole row. For `pve1`, it also requires private, non-Tailscale selected transport addresses and verifies that the paired iperf endpoints are the same two LAN endpoints seen in the transfer logs. Merely exempting `pve1` from the public-address check is not sufficient.

- For `bulk-packets-v1`, every non-empty sender-trace `rate_selected_mbps` value must equal the selected production default of 1,000 Mbps. Repair, retransmit, controller, receiver-rate, and local-pressure fields must be numeric, including healthy zeroes.
- For `blocks-v1`, require QUIC direct transport and successful direct progress. Do not require a bulk selected rate or bulk-only health fields because the controller did not run.

Both modes require matching SHA and size, `trace_ok=true`, no flatline of at least one second, no process or socket leak, and public non-Tailscale selected addresses except for the labeled `pve1` LAN path. Report canonical and wall median/CV, paired iperf median/CV, and derphole-to-iperf ratios. Canonical goodput CV above 15 percent triggers one same-host-direction three-run rerun; a second result above 15 percent fails stability rather than being waived.

### Bulk-pacing decision gate

Rules 1-6 select a candidate on Eric's public path. Rules 7-9 are the separate fleet gate; `pve1` is its explicit same-LAN exception to the public-path requirement.

1. For Eric candidate selection and fleet A/B cells that exercise the bulk controller, reject any rate with a failed SHA, non-public path, transfer mode other than `bulk-packets-v1`, trace failure, flatline of at least one second, or process/socket leak. Final unoverridden fleet acceptance evaluates intentional `blocks-v1` cells under the mode-aware rules above.
2. Group the three accepted rows per rate and compare median canonical goodput first.
3. A median difference above 3 percent selects the faster rate.
4. Within 3 percent, select the rate with at least 20 percent lower median repair ratio and no lower receiver p10 rate.
5. If neither rule separates the top two and same-run iperf coefficient of variation exceeds 15 percent, rerun only those two rates in `A B B A` order.
6. Keep 1,000 Mbps when no alternative wins. Do not lower the default merely because one run had lower repair traffic.
7. On a host-direction that negotiates `bulk-packets-v1`, a non-1,000 candidate may not regress median canonical goodput or median iperf ratio more than 5 percent from that host-direction's 1,000-control median. An intentional `blocks-v1` cell does not exercise the bulk candidate and moves to the unoverridden mode-aware gate.
8. On each bulk A/B cell, the candidate must have no flatline of at least one second, no higher median receiver-rate CV by more than 0.05, no greater median local `ENOBUFS` wait ratio, and no greater median repair ratio by more than 20 percent relative to the 1,000-control rows.
9. If a bulk A/B cell has iperf CV above 15 percent or only one accepted row at either rate, rerun that host-direction as `1000 C C 1000`; do not waive it from the candidate decision. Final acceptance still requires three unoverridden runs on every reachable host-direction in its intentionally negotiated mode.

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

When a sender trace is checked with `-peer-trace`, payload-stall health comes from the peer receiver's `app_bytes`. Sender `app_bytes` are receiver-confirmed ACK progress and may arrive in batches even while the receiver commits bytes every sample. The paired summary reports that cadence separately as `sender_ack_max_flatline`; it does not call it a payload stall while receiver progress continues. A standalone sender check has no peer evidence and retains the original sender-flatline behavior. Failed `transfertrace.Check` calls on a standalone trace or either trace in paired sender mode include their observed `max_flatline` so summary tooling does not turn a threshold failure into `0s`; pair-consistency errors do not promise that field.

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

- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPHOLE_BENCH_WORKLOAD=stream DERPHOLE_BENCH_PARALLEL=8 ./scripts/promotion-test.sh ktzlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPHOLE_BENCH_WORKLOAD=stream DERPHOLE_BENCH_PARALLEL=auto ./scripts/promotion-test.sh canlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPHOLE_BENCH_WORKLOAD=stream DERPHOLE_BENCH_PARALLEL=8 ./scripts/promotion-test-reverse.sh ktzlxc 1024`

## Production Matrix Runner

The old raw/blast packet-engine probe harness has been retired. Use production promotion scripts for transport validation. Their default file workload exercises normal `send/receive`; the explicit stream workload exercises `listen/pipe` over the same v2 session path.

Use these harnesses for proof runs:

- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh ktzlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test-reverse.sh ktzlxc 1024`
- `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-matrix-no-tailscale.sh 1024`

Useful diagnostic override knobs:

- With `DERPHOLE_BENCH_WORKLOAD=stream`, `DERPHOLE_BENCH_PARALLEL=auto` lets the active side choose direct-path striping.
- With `DERPHOLE_BENCH_WORKLOAD=stream`, `DERPHOLE_BENCH_PARALLEL=<n>` forces a specific striping request for controlled comparisons.
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
