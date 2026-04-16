# Relay-First Regression Baseline

Date: 2026-04-09

Baseline revision: `7138654 transport: stream direct UDP with bounded replay`

Host pair: this Mac -> `ktzlxc`

Guardrail: `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`

## Baseline Finding

Default stdio transfer no longer starts payload over the relay path. It waits for direct-UDP readiness, then starts reading stdin into `probe.Send`. This makes small payloads and total wall-clock throughput much worse than the post-upgrade UDP goodput logs suggest.

## Small Payload Wall Clock

Command shape:

```sh
dd if=/dev/zero bs="$size" count=1 |
  DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./dist/derphole --verbose send "$token"
```

Listener stdout was written to a remote temp file and byte-counted after the listener process exited.

| Size | Sender wall | Total wall | Received | Receiver direct first byte | Sender UDP data-goodput | Receiver UDP data-goodput |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 KiB | 11.526s | 11.875s | 1024 | 45ms | 0.13 Mbps | 16.03 Mbps |
| 1 MiB | 12.107s | 12.461s | 1048576 | 44ms | 94.50 Mbps | 308.46 Mbps |
| 5 MiB | 11.589s | 11.929s | 5242880 | 42ms | 332.17 Mbps | 628.21 Mbps |

Control measurement:

| Mode | Size | Total wall | Received |
| --- | ---: | ---: | ---: |
| `send --force-relay` | 1 MiB | 4.424s | 1048576 |

## 1 GiB Checked Promotion

Command:

```sh
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh ktzlxc 1024
```

Result:

| Direction | Sender wall | Size | SHA/size verified | Sender UDP data-goodput | Receiver UDP data-goodput | Path |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| Mac -> ktzlxc | 18s | 1 GiB | yes | 1409.02 Mbps | 1418.95 Mbps | relay -> direct |

Interpretation: the default path can sustain >1 Gbps after direct UDP starts, but total wall-clock goodput for this 1 GiB run is roughly 477 Mbps because payload transfer starts after direct-UDP coordination.

## Current WAN Ceiling Sample

Command shape:

```sh
# Mac, using the dedicated forwarded validation port:
nix run nixpkgs#iperf3 -- -s -p 8321 -1

# ktzlxc:
/usr/bin/iperf3 -c 108.18.210.19 -p 8321 -t 10
/usr/bin/iperf3 -c 108.18.210.19 -p 8321 -t 10 -R
```

| Direction | Tool | Bitrate |
| --- | --- | ---: |
| ktzlxc -> Mac | iperf3 TCP | 1.12 Gbps |
| Mac -> ktzlxc | iperf3 TCP `-R` | 1.50 Gbps |

## Current Relay-First Result

Revision under test: relay prefix over DERP with a 512 KiB startup ACK window, 64 KiB sustained ACK window, and direct UDP handoff at a contiguous received relay boundary.

| Size | Sender wall | Total wall | Received | Path |
| ---: | ---: | ---: | ---: | --- |
| 1 KiB | 0.685s | 0.973s | 1024 | relay |
| 1 MiB | 0.551s | 0.829s | 1048576 | relay |
| 5 MiB | 0.961s | 1.242s | 5242880 | relay; listener observed direct after EOF |

Checked promotion:

| Direction | Script duration | Size | SHA/size verified | Sender UDP data-goodput | Receiver UDP data-goodput | Path |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| Mac -> ktzlxc | 7s | 1 GiB | yes | 1770.27 Mbps | 1792.95 Mbps | relay -> direct |

Interpretation: 1 KiB, 1 MiB, and 5 MiB transfer wall-clock durations improved across the board. The 1 GiB checked transfer now starts immediately on relay, upgrades to direct UDP, verifies SHA/size, and is near the measured forwarded-port iperf3 ceiling for this test window.

## Success Criteria For The Fix

- Small stdin/stdout payloads complete over the relay path when they finish before direct UDP is ready.
- Large stdin/stdout payloads write a relay prefix immediately, hand off after the listener has written a contiguous relay prefix, and continue the suffix over direct UDP.
- Total wall-clock duration improves versus this file, not just `udp-*-data-goodput-mbps`.
- Mac <-> `ktzlxc` retains direct-UDP sustained goodput near the current WAN ceiling.
- Stdio streams remain bounded: relay prefix may spool to a temp file; stdin is not retained in RAM.
