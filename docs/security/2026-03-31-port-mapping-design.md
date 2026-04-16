# Port Mapping Design

## Goal

Improve `derphole`'s direct-connection success rate on residential and other consumer NATs by integrating Tailscale's port mapping support (UPnP, NAT-PMP, PCP) into the core direct transport. The feature should be enabled by default, require no CLI changes for normal use, and preserve the existing relay-first/direct-upgrade behavior.

## Current State

`derphole` currently relies on:
- public DERP bootstrap
- bearer-token session claim over DERP
- candidate exchange over DERP control messages
- UDP hole punching using locally discovered and STUN-discovered candidates

This works for many ordinary UDP-capable networks, but it leaves performance and direct-connect success on the table when routers offer port mapping services that could expose a stable external UDP endpoint.

## Approach Options

### 1. Core transport integration with Tailscale portmapper
Attach a long-lived `tailscale.com/net/portmapper` client to each live direct UDP path. Use the real session UDP port, advertise mapped external endpoints as candidates, and trigger candidate refresh plus `call-me-maybe` whenever mappings appear, renew, change, or expire.

Pros:
- Best practical improvement for double-NAT and residential networks
- Faithful to how Tailscale improves direct connectivity
- Keeps the current `derphole` session and transport architecture intact

Cons:
- Requires deeper transport-manager integration
- Adds background mapping lifecycle handling

### 2. Candidate-source-only integration
Use Tailscale's portmapper only during candidate gathering, append one mapped endpoint if present, and do not keep a long-lived client bound to the transport.

Pros:
- Smaller change

Cons:
- Weaker than Tailscale's behavior
- Mapping changes and renewals are not tracked
- Long-lived `share/open` sessions benefit less

### 3. Broader magicsock reuse
Pull more of Tailscale's portmap and endpoint-refresh machinery into `derphole`.

Pros:
- Potentially closest to Tailscale parity

Cons:
- Larger and riskier refactor than necessary for this gap

## Recommended Design

Use option 1.

## Architecture

Port mapping becomes a core transport capability, not a session-side helper. Each session already owns one real direct UDP socket. A new port-mapping adapter will attach to that socket's local port and feed mapped external endpoints into the transport manager.

The transport manager will own:
- relay transport state
- direct UDP socket
- candidate refresh and `call-me-maybe`
- mapped external endpoint state
- mapping-change-driven rediscovery

Candidate sources become:
- local interface candidates
- STUN-discovered candidates
- mapped external endpoint, when available

Whenever a mapped external endpoint is obtained, renewed, changed, or lost, the transport manager should:
- refresh the remote candidate set it advertises
- send a `call-me-maybe`
- start a fresh direct probe cycle

## Tailscale Reuse Boundary

Reuse `tailscale.com/net/portmapper` directly.

Use:
- `SetLocalPort`
- `Probe`
- `GetCachedMappingOrStartCreatingOne`
- `HaveMapping`

Optionally pass the same portmapper client into `netcheck.Client` so discovery and port mapping share a consistent view of the network.

Do not import more of `magicsock` than necessary. `derphole` still owns:
- session claim and token logic
- candidate exchange over DERP
- path selection and state transitions
- QUIC data transport

## Runtime Behavior

Enabled by default whenever direct UDP is enabled.

Flow:
1. Session starts as today with DERP bootstrap and relay/direct transport manager creation.
2. Transport manager attaches a portmapper client to the live UDP port.
3. If port mapping services are available, the mapped external endpoint becomes a candidate.
4. The manager sends candidate updates and `call-me-maybe`, then reprobes.
5. If the mapping changes or expires, the manager updates candidates and retries discovery.
6. If no mapping is available, behavior falls back to current STUN/local candidate logic.

No new required user steps.

## CLI And Telemetry

No new required flags. Port mapping is enabled by default.

With `--verbose`, emit debug-only diagnostics such as:
- `portmap=probing`
- `portmap=none`
- `portmap=upnp external=198.51.100.10:54321`
- `portmap=pmp external=...`
- `portmap=pcp external=...`
- `portmap=changed external=...`
- `portmap=expired`

These are debug lines only; normal status output stays limited to the current status model like `connected-relay` and `connected-direct`.

Yargs wiring remains unchanged: root `-v/-q/-s` still resolve once to a `telemetry.Level` and flow into subcommands.

## Components

### `pkg/portmap`
A thin adapter layer over Tailscale's portmapper.

Responsibilities:
- create and own the portmapper client
- set the live local UDP port
- expose current mapped external endpoint
- surface change notifications
- emit verbose diagnostics

### `pkg/transport`
Integrate mapped external endpoints into transport state and rediscovery.

Responsibilities:
- merge mapped candidates with existing candidate sources
- trigger candidate update plus `call-me-maybe` on changes
- preserve existing relay/direct state behavior

### `pkg/traversal`
Update candidate gathering so `netcheck` can use the same portmapper client when available.

## Error Handling

Port mapping must fail soft.

Rules:
- if UPnP / NAT-PMP / PCP are unavailable, continue with current STUN/local candidate behavior
- if a mapping cannot be renewed, remove it and keep the session alive
- if portmapper probing fails transiently, log in verbose mode and continue
- do not let port mapping failures block session establishment or cause data-path teardown

## Testing

### Unit / integration
- adapter lifecycle and mapped endpoint reporting
- candidate list includes mapped endpoint when present
- mapping change triggers candidate refresh and `call-me-maybe`
- mapping loss removes mapped endpoint without breaking session
- verbose diagnostics only appear in verbose mode

### Live validation
Run against:
- this host and `hetz`
- this host and `pve1`

Success criteria:
- no regression in current direct/relay behavior
- mapped external endpoint enters the candidate pipeline when available
- verbose diagnostics clearly report mapping availability
- live checks still pass with both remote hosts

## Out of Scope

- IPv6 direct transport rework
- broader magicsock import beyond portmapper reuse
- any CLI breaking change for this feature
