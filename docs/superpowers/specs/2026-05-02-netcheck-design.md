# Netcheck Design

## Summary

Add a local-only `netcheck` command to both published CLIs:

```bash
derphole netcheck
derptun netcheck
```

The command explains whether the current machine looks like a plausible direct UDP peer. It does not test a specific remote peer and does not attempt a transfer.

## Goals

- Report whether outbound UDP and STUN work from this host.
- Report the public UDP endpoint discovered by STUN.
- Classify mapping stability across multiple STUN destinations.
- Classify whether the NAT appears port-preserving.
- List local LAN, overlay, and public candidates.
- Emit a short human-readable report by default.
- Emit a stable JSON report with `--json`.
- Share one implementation between `derphole` and `derptun`.

## Non-Goals

- No SSH or remote execution.
- No pairwise direct-connect proof. That belongs in a later topology command.
- No transfer benchmark.
- No port forwarding setup.
- No UPnP, NAT-PMP, or PCP changes in the first version.

## CLI

Both CLIs expose the same interface:

```bash
derphole netcheck
derphole netcheck --json
derphole netcheck --timeout 5s

derptun netcheck
derptun netcheck --json
derptun netcheck --timeout 5s
```

Flags:

- `--json`: print JSON instead of the human report.
- `--timeout`: total diagnostic timeout. Default: `5s`.

## Human Output

Example direct-friendly output:

```text
Network check: direct-friendly

UDP:
  Outbound UDP: yes
  STUN: yes
  Public endpoint: 203.0.113.10:57179
  Mapping: stable across STUN servers
  Port preservation: yes

Candidates:
  LAN: 192.168.1.20
  Overlay: 100.64.10.20
  Public: 203.0.113.10:57179

Direct-connect readiness:
  This side looks capable of direct UDP.
  Use topology later to test a specific peer.
```

Example limited output:

```text
Network check: direct-limited

UDP:
  Outbound UDP: yes
  STUN: yes
  Public endpoint: 198.51.100.20:51433
  Mapping: changes by STUN destination
  Port preservation: no

Direct-connect readiness:
  Direct UDP may fail with ordinary hole punching.
  Use a forwarded UDP port, routable overlay address, or relay fallback.
```

## JSON Output

JSON output is stable and machine-readable:

```json
{
  "verdict": "direct-friendly",
  "udp": {
    "outbound": true,
    "stun": true,
    "public_endpoints": ["203.0.113.10:57179"],
    "mapping_stable": true,
    "port_preserving": true
  },
  "candidates": {
    "lan": ["192.168.1.20"],
    "overlay": ["100.64.10.20"],
    "public": ["203.0.113.10:57179"]
  },
  "stun": {
    "servers": [
      {
        "server": "stun.l.google.com:19302",
        "mapped_endpoint": "203.0.113.10:57179",
        "error": ""
      }
    ]
  },
  "recommendation": "This side looks capable of direct UDP. Use topology to test a specific peer."
}
```

## Verdicts

- `direct-friendly`: UDP and STUN work, mapping is stable across STUN servers, and the mapped port preserves the local port.
- `direct-limited`: UDP and STUN work, but mapping changes by destination or does not preserve the local port.
- `relay-only-likely`: UDP or STUN is blocked.
- `unknown`: the check was incomplete or contradictory.

These verdicts are local-side claims only. They must not promise connectivity to a specific peer.

## Architecture

Add a shared package for the diagnostic implementation. The package owns:

- report types
- STUN probe execution
- local interface candidate discovery
- candidate categorization
- verdict classification
- human and JSON formatting helpers

The `derphole` and `derptun` commands each add thin `netcheck` subcommands that parse flags, call the shared package, and print output.

## Probe Algorithm

1. Open one UDP socket.
2. Send STUN binding requests from that socket to multiple STUN servers.
3. Record the mapped endpoint for each response.
4. Classify mapping stability by comparing mapped endpoints across STUN servers.
5. Classify port preservation by comparing the local UDP port with mapped ports.
6. Repeat one STUN request with a few fresh sockets to confirm port preservation is not a one-off.
7. Enumerate local interface addresses and categorize candidates:
   - LAN/private
   - overlay, including Tailscale ranges
   - public/STUN
8. Produce the verdict and recommendation.

## Error Handling

- If all STUN requests fail, report `relay-only-likely` when UDP appears blocked, or `unknown` when the reason is unclear.
- If some STUN servers fail but at least one succeeds, include failures in JSON and continue.
- If interface enumeration fails, still report STUN results and include the interface error.
- Human output should stay short; detailed per-server errors belong in `--json` or `--verbose` in a later version.

## Testing

Unit tests cover:

- verdict classification
- port preservation classification
- mapping stability classification
- candidate categorization
- human output for each verdict
- JSON shape
- CLI flag parsing in both `derphole` and `derptun`

Network-dependent live checks are not required for normal unit tests. STUN probing should be dependency-injected so tests can use deterministic fake results.

## Rollout

First release:

- `derphole netcheck`
- `derptun netcheck`
- `--json`
- `--timeout`

Later:

- pairwise `topology`
- relay latency checks
- port mapping checks
- richer `--verbose` output
