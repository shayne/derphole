# DERP Documentation Library

This directory is a source-backed technical library for DERP: what it is, how it works, how clients and servers behave at runtime, how Tailscale models regions and nodes, how Headscale integrates and embeds DERP, and how to operate or test a deployment.

The material here is based on the current upstream source trees:

- `tailscale`
- `headscale`

The documents are intentionally implementation-oriented. Where possible, they cite exact source files and include short code excerpts so the reader can pivot directly into the code.

## Reading Order

1. [`architecture.md`](./architecture.md) for the system model and component boundaries.
2. [`protocol.md`](./protocol.md) for framing, handshake, control frames, and transport behavior.
3. [`derp-map-control-plane.md`](./derp-map-control-plane.md) for the map schema and control-plane responsibilities.
4. [`client-runtime.md`](./client-runtime.md) for netcheck, home DERP selection, dialing, and reconnect behavior.
5. [`server-runtime.md`](./server-runtime.md) for server internals, packet routing, queues, and admission control.
6. [`headscale.md`](./headscale.md) for embedded DERP, map assembly, verification, and runtime differences.
7. [`operations.md`](./operations.md) for deployment constraints, observability, and troubleshooting.
8. [`testing.md`](./testing.md) for integration coverage and concrete validation patterns.

## Scope

This library treats DERP as a complete subsystem, not just a relay binary:

- Protocol: binary framing, TLS upgrade, fast-start, websocket support.
- Control plane: DERP map construction, region/node semantics, home-region selection signals.
- Client runtime: netcheck, sticky preferred DERP logic, region fallback, reverse-path learning.
- Server runtime: authentication, connection registration, duplicate handling, forwarding, queue policy.
- Operations: STUN, captive-portal behavior, mesh topology, metrics, diagnostics.
- Headscale: embedded DERP server, auto-generated region injection, verify endpoint, limitations.

## DERP In One Page

DERP is Tailscale's encrypted TCP relay path for cases where direct peer-to-peer connectivity is unavailable or still being established. It relays:

- Discovery traffic used to bootstrap NAT traversal.
- End-to-end encrypted WireGuard packets as a fallback path.

It is addressed by node public key, not by IP address. Clients receive a DERP map from the control plane, choose a "home" DERP region based primarily on measured latency, and keep that home connection alive. Additional DERP connections are opened on demand when talking to peers whose home region differs.

```text
Source: tailscale/derp/README.md:6-15
DERP is a packet relay system (client and servers) where peers are addressed
using WireGuard public keys instead of IP addresses.

It relays two types of packets:
* "Disco" discovery messages
* Encrypted WireGuard packets as the fallback of last resort
```

```text
Source: tailscale/derp/README.md:23-32
The client picks its home "DERP home" based on latency.
Clients pick their DERP home and report it to the coordination server.
The client will make connections to multiple DERP regions as needed.
Only the DERP home region connection needs to be alive forever.
```

## What DERP Is Not

DERP is not a general-purpose proxy tier and not a replacement for normal direct connectivity:

- It is a fallback path, not the primary steady-state transport.
- DERP servers do not decrypt WireGuard payloads and are not useful for packet-level debugging.
- Cross-region packet routing is not the design center; routing exists within a region mesh, not across regions.
- Global load balancers and generic HTTP proxying conflict with how DERP clients select and upgrade connections.

```text
Source: tailscale/cmd/derper/README.md:37-47
The DERP protocol does a protocol switch inside TLS from HTTP to a custom
bidirectional binary protocol. It is thus incompatible with many HTTP proxies.
Do not put derper behind another HTTP proxy.

The tailscaled client does its own selection of the fastest/nearest DERP
server based on latency measurements. Do not put derper behind a global load
balancer.
```

## Primary Source Roots

The most important implementation files used throughout this library are:

- `tailscale/derp/derp.go`
- `tailscale/derp/derp_client.go`
- `tailscale/derp/derphttp/derphttp_client.go`
- `tailscale/derp/derpserver/derpserver.go`
- `tailscale/derp/derpserver/handler.go`
- `tailscale/tailcfg/derpmap.go`
- `tailscale/net/netcheck/netcheck.go`
- `tailscale/wgengine/magicsock/derp.go`
- `tailscale/wgengine/magicsock/magicsock.go`
- `tailscale/cmd/derper/derper.go`
- `tailscale/cmd/derper/mesh.go`
- `headscale/hscontrol/derp/server/derp_server.go`
- `headscale/hscontrol/derp/derp.go`
- `headscale/hscontrol/app.go`
- `headscale/hscontrol/types/config.go`
- `headscale/hscontrol/handlers.go`
- `headscale/hscontrol/state/state.go`
- `headscale/hscontrol/types/node.go`

## Design Themes

Several design decisions recur across the implementation:

- Key-addressed routing: DERP uses node public keys as logical destination addresses.
- Regionality: clients pick a home region; mesh forwarding is an intra-region redundancy mechanism.
- Stickiness over flapping: both netcheck and magicsock try hard to avoid unnecessary home-DERP changes.
- Limited trust elevation: only mesh peers or explicitly trusted clients may watch peer presence or forward packets.
- Fast path bias: direct UDP is preferred; DERP is the safety net when direct paths fail.

The remaining documents unpack those themes in more detail.
